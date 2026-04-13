//! High-level sync orchestration with auto-sync, retry, and event emission.
//!
//! `SyncService` wraps [`SyncEngine`] with:
//! - Retry logic (configurable max retries + backoff delay)
//! - Event emission via `broadcast::Sender<SyncEvent>`
//! - Catch-up-if-stale support for app resume
//! - Auto-sync debounce: mutation signals are coalesced via a quiet-period
//!   timer before triggering a sync cycle
//! - WebSocket notification handler: relay notifications (NewData,
//!   DeviceRevoked, EpochRotated) are translated into sync triggers or
//!   events

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::JoinHandle;

use rand::Rng;

use crate::client::PrismSync;
use crate::engine::{SyncEngine, SyncResult};
use crate::epoch::EpochManager;
use crate::error::{CoreError, RelayErrorCategory, Result};
use crate::events::{ChangeSet, EntityChange, SyncError, SyncErrorKind, SyncEvent};
use crate::relay::traits::SyncNotification;
use crate::relay::SyncRelay;
use crate::runtime::background_runtime;

/// Why a sync cycle was triggered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncTrigger {
    /// Local mutations were debounced and are ready to push.
    MutationDebounce,
    /// The relay signalled new data via WebSocket.
    WebSocketNewData,
    /// The caller explicitly requested a sync.
    ManualSync,
}

/// Configuration for automatic sync behaviour.
pub struct AutoSyncConfig {
    /// Whether auto-sync is enabled.
    pub enabled: bool,
    /// Debounce delay: how long to wait after a mutation before pushing.
    pub debounce: Duration,
    /// Delay between retry attempts on transient failure.
    pub retry_delay: Duration,
    /// Maximum number of retry attempts before giving up.
    pub max_retries: u32,
    /// Whether to run tombstone pruning after sync.
    pub enable_pruning: bool,
}

impl Default for AutoSyncConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            debounce: Duration::from_millis(400),
            retry_delay: Duration::from_secs(2),
            max_retries: 3,
            enable_pruning: false,
        }
    }
}

/// Tight retry loop parameters for `SyncService::sync_now`.
///
/// These compose deliberately with the outer auto-sync driver in
/// `crates/prism-sync-ffi/src/api.rs` (the `spawn` call at line ~1344).
/// The driver runs exponential backoff (`30s -> 60s -> 120s -> 240s -> 300s`,
/// 10-minute cumulative cap) across sync *cycles*. This inner loop handles
/// tight transient hiccups inside a *single* cycle (e.g. a 15-second pull
/// timeout that recovers in a few seconds). Keep both tiers in place:
/// the inner loop protects against one-off backgrounding hiccups without
/// escalating to the driver; the driver protects against sustained outages.
///
/// `INNER_RETRY_MAX` is the number of *additional* retries after the first
/// failure, matching `AutoSyncConfig::max_retries` semantics.
const INNER_RETRY_DELAY: Duration = Duration::from_secs(2);
const INNER_RETRY_MAX: u32 = 3;

/// Apply "full jitter" to a base delay: the actual delay is uniformly
/// distributed between `base/2` and `base`. This prevents thundering-herd
/// synchronisation when multiple devices retry after the same outage, while
/// keeping the average delay close to the nominal value.
pub fn jittered_delay(base: Duration) -> Duration {
    let half_ms = base.as_millis() as u64 / 2;
    let jitter_ms = rand::thread_rng().gen_range(0..=half_ms);
    Duration::from_millis(half_ms + jitter_ms)
}

fn relay_error_retryable(kind: &RelayErrorCategory) -> bool {
    matches!(
        kind,
        RelayErrorCategory::Network | RelayErrorCategory::Server
    )
}

fn sync_error_kind_retryable(kind: &SyncErrorKind) -> bool {
    matches!(
        kind,
        SyncErrorKind::Network | SyncErrorKind::Server | SyncErrorKind::Timeout
    )
}

fn sync_error_kind_to_relay_category(kind: &SyncErrorKind) -> RelayErrorCategory {
    match kind {
        SyncErrorKind::Network | SyncErrorKind::Timeout => RelayErrorCategory::Network,
        SyncErrorKind::Auth => RelayErrorCategory::Auth,
        SyncErrorKind::DeviceIdentityMismatch => RelayErrorCategory::DeviceIdentityMismatch,
        SyncErrorKind::Server => RelayErrorCategory::Server,
        SyncErrorKind::Protocol
        | SyncErrorKind::EpochRotation
        | SyncErrorKind::ClockSkew
        | SyncErrorKind::KeyChanged => RelayErrorCategory::Protocol,
    }
}

#[allow(dead_code)]
fn relay_error_kind_to_sync_error_kind(kind: &RelayErrorCategory) -> SyncErrorKind {
    match kind {
        RelayErrorCategory::Network => SyncErrorKind::Network,
        RelayErrorCategory::Auth => SyncErrorKind::Auth,
        RelayErrorCategory::DeviceIdentityMismatch => SyncErrorKind::DeviceIdentityMismatch,
        RelayErrorCategory::Server => SyncErrorKind::Server,
        RelayErrorCategory::Protocol => SyncErrorKind::Protocol,
        RelayErrorCategory::Other => SyncErrorKind::Network,
    }
}

/// Extract the RELAY response code + remote_wipe flag from a `CoreError`.
///
/// Only `CoreError::Relay` carries these fields — they are server-sent
/// markers like `device_revoked`. Local errors (`DeviceKeyChanged`,
/// `Engine`, `Storage`, etc.) do NOT populate `error_code`: their
/// classification flows through `SyncErrorKind` instead. Mirrors the
/// invariant in `engine/mod.rs::populate_result_error`.
fn relay_error_details(error: &CoreError) -> (Option<String>, Option<bool>) {
    if let CoreError::Relay {
        code, remote_wipe, ..
    } = error
    {
        (code.clone(), *remote_wipe)
    } else {
        (None, None)
    }
}

/// Spawn the auto-sync debounce background task.
///
/// Waits for the first mutation signal on `rx`, then absorbs further signals
/// until a quiet period of `debounce` elapses. Once the debounce expires,
/// sends [`SyncTrigger::MutationDebounce`] on `sync_trigger` and loops.
///
/// The task exits when the `rx` channel is closed (all senders dropped).
pub fn spawn_auto_sync_task(
    mut rx: mpsc::Receiver<()>,
    debounce: Duration,
    sync_trigger: mpsc::Sender<SyncTrigger>,
) -> JoinHandle<()> {
    // Spawn on the background runtime so the task persists on mobile (iOS/Android)
    // where FRB's async executor is not a Tokio runtime.
    background_runtime().spawn(async move {
        loop {
            // Wait for first mutation signal
            if rx.recv().await.is_none() {
                break;
            }
            // Debounce: absorb rapid signals until quiet period expires
            loop {
                match tokio::time::timeout(debounce, rx.recv()).await {
                    Ok(Some(())) => continue, // another signal, reset timer
                    Ok(None) => return,       // channel closed
                    Err(_) => break,          // timeout = debounce complete
                }
            }
            // Trigger sync
            let _ = sync_trigger.send(SyncTrigger::MutationDebounce).await;
        }
    })
}

/// Spawn a background task that translates relay WebSocket notifications
/// into sync triggers and events.
///
/// - `NewData` → sends [`SyncTrigger::WebSocketNewData`]
/// - `DeviceRevoked` → emits [`SyncEvent::DeviceRevoked`] if this device
///   was revoked, or attempts epoch recovery + [`SyncEvent::EpochRotated`]
///   for other devices
/// - `EpochRotated` → attempts epoch recovery, emits [`SyncEvent::EpochRotated`],
///   then triggers sync
/// - `TokenRotated` → ignored (handled internally by the relay)
///
/// When `inner` and `relay` are provided, epoch recovery is attempted on
/// `EpochRotated` and `DeviceRevoked` (other device) notifications. The
/// handler fetches the rekey artifact from the relay, unwraps it via X25519
/// DH, stores the epoch key, and updates `sync_metadata.current_epoch`
/// before triggering a sync cycle.
///
/// The task exits when the notification stream ends.
pub fn spawn_notification_handler(
    notifications: std::pin::Pin<Box<dyn futures_util::Stream<Item = SyncNotification> + Send>>,
    my_device_id: String,
    sync_trigger: mpsc::Sender<SyncTrigger>,
    event_tx: broadcast::Sender<SyncEvent>,
    inner: Option<Arc<Mutex<PrismSync>>>,
    relay: Option<Arc<dyn SyncRelay>>,
) -> JoinHandle<()> {
    // Spawn on the background runtime so the task persists on mobile (iOS/Android)
    // where FRB's async executor is not a Tokio runtime.
    background_runtime().spawn(async move {
        let mut stream = notifications;
        while let Some(notification) = stream.next().await {
            match notification {
                SyncNotification::NewData { .. } => {
                    let _ = sync_trigger.send(SyncTrigger::WebSocketNewData).await;
                }
                SyncNotification::DeviceRevoked {
                    device_id,
                    new_epoch: _,
                    remote_wipe,
                } => {
                    // Emit DeviceRevoked for both self and other-device cases.
                    // When another device is revoked, the epoch update will
                    // arrive later via a separate "epoch_rotated" notification
                    // from the rekey endpoint.
                    let _ = event_tx.send(SyncEvent::DeviceRevoked {
                        device_id,
                        remote_wipe,
                    });
                }
                SyncNotification::EpochRotated { new_epoch } => {
                    // Recover the new epoch key before triggering sync.
                    recover_epoch_key(
                        new_epoch as u32,
                        &my_device_id,
                        inner.as_ref(),
                        relay.as_ref(),
                    )
                    .await;
                    let _ = event_tx.send(SyncEvent::EpochRotated(new_epoch as u32));
                    let _ = sync_trigger.send(SyncTrigger::WebSocketNewData).await;
                }
                SyncNotification::TokenRotated { .. } => {
                    // Handled internally by the relay transport layer
                }
                SyncNotification::ConnectionStateChanged { connected } => {
                    let _ = event_tx.send(SyncEvent::WebSocketStateChanged { connected });
                }
            }
        }
    })
}

/// Attempt to recover the epoch key for a new epoch after rotation.
///
/// Fetches the device's own X-Wing decapsulation key, then calls
/// `handle_rotation` to fetch and decapsulate the rekey artifact from the
/// relay. On success, stores the epoch key in the key hierarchy, persists it
/// to the secure store, and updates the current epoch in storage.
///
/// Logs warnings on failure but never panics or crashes — the device will
/// be unable to sync at the new epoch until the key is recovered through
/// another mechanism (e.g. manual unlock or re-pairing).
async fn recover_epoch_key(
    new_epoch: u32,
    my_device_id: &str,
    inner: Option<&Arc<Mutex<PrismSync>>>,
    relay: Option<&Arc<dyn SyncRelay>>,
) {
    let (inner, relay) = match (inner, relay) {
        (Some(i), Some(r)) => (i, r),
        _ => return, // No PrismSync handle or relay — cannot recover
    };

    let guard = inner.lock().await;

    // Already have this epoch key — nothing to do
    if guard.key_hierarchy().has_epoch_key(new_epoch) {
        return;
    }

    // Derive own X-Wing decapsulation key — needed to unwrap the artifact
    let xwing_key = match guard.device_secret() {
        Some(ds) => match ds.xwing_keypair(my_device_id) {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(
                    epoch = new_epoch,
                    error = %e,
                    "epoch recovery: failed to derive X-Wing keypair"
                );
                return;
            }
        },
        None => {
            tracing::warn!(
                epoch = new_epoch,
                "epoch recovery: no device secret available"
            );
            return;
        }
    };

    // Drop the lock before network I/O. We'll re-acquire it for
    // handle_rotation which mutates key_hierarchy.
    drop(guard);

    // Re-acquire the lock for key_hierarchy mutation
    let mut guard = inner.lock().await;

    // Re-check in case another task recovered while we were waiting
    if guard.key_hierarchy().has_epoch_key(new_epoch) {
        return;
    }

    // With X-Wing KEM the artifact is self-contained — no need to loop over
    // active devices to find the sender. The receiver just decapsulates with
    // its own DK.
    let recovered = match EpochManager::handle_rotation(
        relay.as_ref(),
        guard.key_hierarchy_mut(),
        new_epoch,
        my_device_id,
        &xwing_key,
    )
    .await
    {
        Ok(()) => {
            tracing::info!(
                epoch = new_epoch,
                "epoch recovery: successfully recovered epoch key"
            );
            true
        }
        Err(e) => {
            tracing::warn!(
                epoch = new_epoch,
                error = %e,
                "epoch recovery: failed to recover epoch key"
            );
            false
        }
    };

    if !recovered {
        return;
    }

    // Persist the epoch key to the secure store
    if let Ok(epoch_key) = guard.key_hierarchy().epoch_key(new_epoch) {
        let store_key = format!("epoch_key_{}", new_epoch);
        if let Err(e) = guard.secure_store().set(&store_key, epoch_key) {
            tracing::warn!(
                epoch = new_epoch,
                error = %e,
                "epoch recovery: failed to persist epoch key to secure store"
            );
        }
    }

    // Update current_epoch in sync_metadata via storage transaction
    if let Some(sync_id) = guard.sync_service().sync_id().map(|s| s.to_string()) {
        let storage = guard.storage().clone();
        // Drop the lock before spawn_blocking to avoid holding it across
        // the blocking task boundary.
        drop(guard);
        let update_result = tokio::task::spawn_blocking(move || {
            let mut tx = storage.begin_tx()?;
            tx.update_current_epoch(&sync_id, new_epoch as i32)?;
            tx.commit()
        })
        .await;

        match update_result {
            Ok(Ok(())) => {
                tracing::info!(
                    epoch = new_epoch,
                    "epoch recovery: updated current_epoch in storage"
                );
                // Advance the runtime epoch so new mutations use the recovered epoch.
                // Guard against concurrent advancement — only advance if we're
                // still behind (another task may have advanced further already).
                let mut guard = inner.lock().await;
                if guard.epoch().unwrap_or(0) < new_epoch as i32 {
                    guard.advance_epoch(new_epoch as i32);
                }
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    epoch = new_epoch,
                    error = %e,
                    "epoch recovery: failed to update current_epoch in storage"
                );
            }
            Err(e) => {
                tracing::warn!(
                    epoch = new_epoch,
                    error = %e,
                    "epoch recovery: spawn_blocking panicked"
                );
            }
        }
    }
}

/// Build a `ChangeSet` from a list of `EntityChange` entries.
///
/// Populates the legacy `created`/`updated`/`deleted` summary vectors
/// alongside the full `entity_changes` list. Since we cannot distinguish
/// "created" from "updated" at the engine level (both are field writes),
/// non-delete changes go into `updated` with their field names listed.
fn build_changeset(entity_changes: &[EntityChange]) -> ChangeSet {
    let created = Vec::new();
    let mut updated = Vec::new();
    let mut deleted = Vec::new();

    for ec in entity_changes {
        if ec.is_delete {
            deleted.push((ec.table.clone(), ec.entity_id.clone()));
        } else {
            let field_names: Vec<String> = ec.fields.keys().cloned().collect();
            updated.push((ec.table.clone(), ec.entity_id.clone(), field_names));
        }
    }

    ChangeSet {
        created,
        updated,
        deleted,
        entity_changes: entity_changes.to_vec(),
    }
}

/// High-level sync orchestration service.
///
/// Manages the sync lifecycle: engine configuration, sync execution with
/// retry, event emission, and catch-up-if-stale for app resume.
pub struct SyncService {
    engine: Option<SyncEngine>,
    event_tx: broadcast::Sender<SyncEvent>,
    auto_sync_config: AutoSyncConfig,
    sync_id: Option<String>,
    last_sync_time: Option<Instant>,
    /// Sender for mutation signals into the auto-sync debounce task.
    /// `None` when auto-sync is disabled.
    auto_sync_tx: Option<mpsc::Sender<()>>,
    /// Handle for the running auto-sync debounce task, if any.
    auto_sync_handle: Option<JoinHandle<()>>,
    /// Sender for WebSocket notification triggers (shared with the debounce
    /// task). Used by the notification handler to signal incoming relay data.
    /// `None` when auto-sync is disabled.
    notification_trigger_tx: Option<mpsc::Sender<SyncTrigger>>,
}

impl SyncService {
    /// Create a new `SyncService` with the given event channel sender.
    pub fn new(event_tx: broadcast::Sender<SyncEvent>) -> Self {
        Self {
            engine: None,
            event_tx,
            auto_sync_config: AutoSyncConfig::default(),
            sync_id: None,
            last_sync_time: None,
            auto_sync_tx: None,
            auto_sync_handle: None,
            notification_trigger_tx: None,
        }
    }

    /// Configure the sync engine and sync group ID.
    ///
    /// Must be called before `sync_now` or `catch_up_if_stale`.
    pub fn set_engine(&mut self, engine: SyncEngine, sync_id: String) {
        self.engine = Some(engine);
        self.sync_id = Some(sync_id);
    }

    /// Borrow the configured relay, if any.
    ///
    /// Exposed so `PrismSync` can perform epoch-key catch-up recovery
    /// without having to reconstruct a relay client.
    pub fn relay(&self) -> Option<&Arc<dyn crate::relay::traits::SyncRelay>> {
        self.engine.as_ref().map(|e| e.relay())
    }

    /// Update the auto-sync configuration, spawning or stopping the
    /// debounce background task as needed.
    ///
    /// When `config.enabled` is `true`, spawns the debounce task and
    /// returns the [`SyncTrigger`] receiver that the caller should use
    /// to drive the actual sync loop. When `false`, aborts the debounce
    /// task and returns `None`.
    pub fn set_auto_sync(&mut self, config: AutoSyncConfig) -> Option<mpsc::Receiver<SyncTrigger>> {
        // Abort any existing debounce task
        if let Some(handle) = self.auto_sync_handle.take() {
            handle.abort();
        }
        self.auto_sync_tx = None;

        let result = if config.enabled {
            let (mutation_tx, mutation_rx) = mpsc::channel::<()>(32);
            let (trigger_tx, trigger_rx) = mpsc::channel::<SyncTrigger>(16);

            // Clone trigger_tx so the notification handler can share the same
            // trigger channel as the debounce task.
            let handle = spawn_auto_sync_task(mutation_rx, config.debounce, trigger_tx.clone());

            self.auto_sync_tx = Some(mutation_tx);
            self.auto_sync_handle = Some(handle);
            self.notification_trigger_tx = Some(trigger_tx);
            Some(trigger_rx)
        } else {
            self.notification_trigger_tx = None;
            None
        };

        self.auto_sync_config = config;
        result
    }

    /// Returns whether an engine has been configured.
    pub fn has_engine(&self) -> bool {
        self.engine.is_some()
    }

    /// Returns the configured sync_id, if any.
    pub fn sync_id(&self) -> Option<&str> {
        self.sync_id.as_deref()
    }

    /// Access the event sender for external emission.
    pub fn event_tx(&self) -> &broadcast::Sender<SyncEvent> {
        &self.event_tx
    }

    /// Returns the last time a sync cycle completed successfully, if any.
    pub fn last_sync_time(&self) -> Option<Instant> {
        self.last_sync_time
    }

    /// Returns a clone of the auto-sync mutation sender, if auto-sync is
    /// enabled. Callers (e.g. `PrismSync`) use this to notify the debounce
    /// task after recording mutations.
    pub fn auto_sync_sender(&self) -> Option<mpsc::Sender<()>> {
        self.auto_sync_tx.clone()
    }

    /// Returns a clone of the notification trigger sender, if auto-sync is
    /// enabled. Used by the WebSocket notification handler to feed relay
    /// `new_data` signals into the same trigger channel as the debounce task.
    pub fn notification_trigger_sender(&self) -> Option<mpsc::Sender<SyncTrigger>> {
        self.notification_trigger_tx.clone()
    }

    /// Upload an encrypted pairing snapshot to the relay.
    ///
    /// Delegates to [`SyncEngine::upload_pairing_snapshot`]. Requires
    /// the engine to be configured.
    #[allow(clippy::too_many_arguments)]
    pub async fn upload_pairing_snapshot(
        &self,
        key_hierarchy: &prism_sync_crypto::KeyHierarchy,
        epoch: i32,
        device_id: &str,
        signing_key: &ed25519_dalek::SigningKey,
        ml_dsa_signing_key: &prism_sync_crypto::DevicePqSigningKey,
        ml_dsa_key_generation: u32,
        ttl_secs: Option<u64>,
        for_device_id: Option<String>,
    ) -> Result<()> {
        let engine = self
            .engine
            .as_ref()
            .ok_or_else(|| CoreError::Storage("sync engine not configured".into()))?;
        let sync_id = self
            .sync_id
            .as_ref()
            .ok_or_else(|| CoreError::Storage("sync_id not set".into()))?;
        engine
            .upload_pairing_snapshot(
                sync_id,
                key_hierarchy,
                epoch,
                device_id,
                signing_key,
                ml_dsa_signing_key,
                ml_dsa_key_generation,
                ttl_secs,
                for_device_id,
            )
            .await
    }

    /// Download and apply a bootstrap snapshot from the relay.
    ///
    /// Delegates to [`SyncEngine::bootstrap_from_snapshot`]. Requires
    /// the engine to be configured. Emits `SyncEvent::RemoteChanges` if
    /// entities were restored.
    pub async fn bootstrap_from_snapshot(
        &self,
        key_hierarchy: &prism_sync_crypto::KeyHierarchy,
    ) -> Result<(u64, Vec<EntityChange>)> {
        let engine = self
            .engine
            .as_ref()
            .ok_or_else(|| CoreError::Storage("sync engine not configured".into()))?;
        let sync_id = self
            .sync_id
            .as_ref()
            .ok_or_else(|| CoreError::Storage("sync_id not set".into()))?;

        let (count, entity_changes) = engine
            .bootstrap_from_snapshot(sync_id, key_hierarchy)
            .await?;

        // Emit RemoteChanges event so Dart's drift sync adapter populates
        // the consumer database from the snapshot data.
        if !entity_changes.is_empty() {
            let changeset = build_changeset(&entity_changes);
            let _ = self.event_tx.send(SyncEvent::RemoteChanges(changeset));
        }

        Ok((count, entity_changes))
    }

    /// Execute a full sync cycle with retry.
    ///
    /// Emits `SyncEvent::SyncStarted` before the first attempt and
    /// `SyncEvent::SyncCompleted` on every terminal attempt (success or
    /// final failure). On exhausted retries, also emits `SyncEvent::Error`
    /// and returns `Err(synthetic_core_error)`.
    ///
    /// **Critical event ordering:** on a final failure, `SyncCompleted` is
    /// emitted BEFORE `Error`. The Dart `SyncStatusNotifier` resets
    /// `isSyncing: false` only on the `SyncCompleted` branch, so reversing
    /// the order would leave the UI stuck showing "syncing..." until a
    /// subsequent successful cycle.
    ///
    /// **Two-tier retry architecture:** this inner loop runs 3 tight
    /// `INNER_RETRY_DELAY` retries to absorb single-cycle transient
    /// hiccups (short TLS resets, iOS-backgrounded tokio timer overdue,
    /// etc.) without involving the outer auto-sync driver. Sustained
    /// outages escalate to the driver's exponential backoff via the
    /// returned `Err`.
    pub async fn sync_now(
        &mut self,
        key_hierarchy: &prism_sync_crypto::KeyHierarchy,
        signing_key: &ed25519_dalek::SigningKey,
        ml_dsa_signing_key: Option<&prism_sync_crypto::DevicePqSigningKey>,
        device_id: &str,
        ml_dsa_key_generation: u32,
    ) -> Result<SyncResult> {
        let engine = self
            .engine
            .as_ref()
            .ok_or_else(|| CoreError::Storage("sync engine not configured".into()))?;
        let sync_id = self
            .sync_id
            .as_ref()
            .ok_or_else(|| CoreError::Storage("sync_id not set".into()))?;

        let _ = self.event_tx.send(SyncEvent::SyncStarted);

        let mut attempts = 0u32;

        // Holds the last observed failure from an `Ok(result_with_error)`
        // so we can surface a synthetic `Err` on exhausted retries.
        let mut last_result_with_error: Option<SyncResult> = None;

        loop {
            let outcome = engine
                .sync(sync_id, key_hierarchy, signing_key, ml_dsa_signing_key, device_id, ml_dsa_key_generation)
                .await;

            // Compute a shared (retryable, error_kind) signal from either
            // `Ok(result_with_error)` or `Err(e)`, so both arms flow
            // through the same retry decision and event emission paths.
            match outcome {
                Ok(result) => {
                    if let Some(err_kind) = result.error_kind.clone() {
                        // Engine converted a transport error into a populated
                        // SyncResult. Decide whether to retry based on the
                        // structured kind.
                        let retryable = sync_error_kind_retryable(&err_kind);
                        attempts += 1;
                        if retryable && attempts <= INNER_RETRY_MAX {
                            tokio::time::sleep(jittered_delay(INNER_RETRY_DELAY)).await;
                            last_result_with_error = Some(result);
                            continue;
                        }

                        // Exhausted — route through the shared terminal
                        // failure helper. Synthetic `CoreError::Relay` is
                        // built from the fields the engine already copied
                        // onto the result via `populate_result_error`.
                        let message = result
                            .error
                            .clone()
                            .unwrap_or_else(|| format!("sync failed ({err_kind:?})"));
                        let synthetic_err = CoreError::Relay {
                            message: message.clone(),
                            kind: sync_error_kind_to_relay_category(&err_kind),
                            status: None,
                            code: result.error_code.clone(),
                            min_signature_version: None,
                            remote_wipe: result.remote_wipe,
                            source: None,
                        };
                        return self.emit_final_failure(
                            result,
                            err_kind,
                            retryable,
                            message,
                            synthetic_err,
                            device_id,
                        );
                    }

                    // Genuine success — no error in the result.
                    self.last_sync_time = Some(Instant::now());

                    // Emit RemoteChanges event with full entity data if
                    // any remote changes were merged during this cycle.
                    if !result.entity_changes.is_empty() {
                        let changeset = build_changeset(&result.entity_changes);
                        let _ = self.event_tx.send(SyncEvent::RemoteChanges(changeset));
                    }

                    let _ = self.event_tx.send(SyncEvent::SyncCompleted(result.clone()));
                    return Ok(result);
                }
                Err(e) => {
                    let retryable = match &e {
                        CoreError::Relay { kind, .. } => relay_error_retryable(kind),
                        _ => false,
                    };

                    attempts += 1;
                    if retryable && attempts <= INNER_RETRY_MAX {
                        // Stash a synthesized result-with-error so that on
                        // final failure we still emit a SyncCompleted event
                        // if all subsequent attempts also return Err. This
                        // keeps the UI's isSyncing flag in sync even when
                        // the engine hard-errors. Copy the structured
                        // error code / remote_wipe too so the final
                        // SyncCompleted/Error pair carries them.
                        let (stash_code, stash_wipe) = relay_error_details(&e);
                        last_result_with_error = Some(SyncResult {
                            error_kind: Some(crate::events::classify_core_error(&e)),
                            error: Some(e.to_string()),
                            error_code: stash_code,
                            remote_wipe: stash_wipe,
                            ..SyncResult::default()
                        });
                        tokio::time::sleep(jittered_delay(INNER_RETRY_DELAY)).await;
                        continue;
                    }

                    // ALL terminal Err paths — including `device_revoked` —
                    // go through the shared `emit_final_failure` helper so
                    // the `SyncCompleted -> Error -> DeviceRevoked`
                    // ordering is enforced by construction. Previously the
                    // `device_revoked` path returned early without emitting
                    // `SyncCompleted`, which left the Dart UI stuck in
                    // `isSyncing: true` on the Err branch (Fix 3 of the
                    // 2026-04-11 robustness plan).
                    let error_kind = crate::events::classify_core_error(&e);
                    let (code, remote_wipe) = relay_error_details(&e);
                    let message = e.to_string();
                    let synthetic_result = last_result_with_error
                        .take()
                        .unwrap_or_else(|| SyncResult {
                            error_kind: Some(error_kind.clone()),
                            error: Some(message.clone()),
                            error_code: code.clone(),
                            remote_wipe,
                            ..SyncResult::default()
                        });
                    return self.emit_final_failure(
                        synthetic_result,
                        error_kind,
                        retryable,
                        message,
                        e,
                        device_id,
                    );
                }
            }
        }
    }

    /// Shared terminal-failure emission helper for `sync_now`.
    ///
    /// Enforces the `SyncCompleted -> Error -> (DeviceRevoked) -> return`
    /// ordering required by Appendix B.1 of the 2026-04-11 sync robustness
    /// plan. Both the `Ok(result_with_error)` and `Err(e)` branches of
    /// `sync_now` route through this helper so the ordering is guaranteed
    /// by construction instead of being duplicated at two call sites.
    ///
    /// - `result`: the final SyncResult snapshot. For the `Err(e)` branch
    ///   this may be a stashed synthetic (from a prior retry).
    /// - `error_kind`: structured classification used for the `SyncError`.
    /// - `retryable`: whether the underlying error was classified as
    ///   retryable (informational, for the emitted `SyncError`).
    /// - `message`: human-readable error message.
    /// - `err_to_return`: the `CoreError` that will be returned via `Err`.
    /// - `device_id`: this device's ID, used for the `DeviceRevoked` event.
    ///
    /// **Round 4 Fix 3:** the `device_revoked` check inspects BOTH
    /// `err_to_return` (the terminal error) AND `result.error_code` (the
    /// stashed/synthetic snapshot). The terminal error takes precedence:
    /// if a retryable failure was stashed and then a terminal
    /// `device_revoked` arrives, the stashed result won't have the
    /// revocation code, but `err_to_return` will.
    fn emit_final_failure(
        &mut self,
        result: SyncResult,
        error_kind: SyncErrorKind,
        retryable: bool,
        message: String,
        err_to_return: CoreError,
        device_id: &str,
    ) -> Result<SyncResult> {
        // Derive revocation metadata from the terminal error first (fresh),
        // then from the result (may be stashed from a prior retry iteration).
        let (err_code, err_wipe) = relay_error_details(&err_to_return);
        let is_revoked = err_code
            .as_deref()
            .or(result.error_code.as_deref())
            == Some("device_revoked");
        let remote_wipe_flag = err_wipe
            .or(result.remote_wipe)
            .unwrap_or(false);
        // For the Error event payload, prefer the terminal error's code and
        // wipe, falling back to the result's values.
        let code_for_error = err_code.or(result.error_code.clone());
        let remote_wipe_for_error = err_wipe.or(result.remote_wipe);

        // 1. SyncCompleted FIRST — Dart flips isSyncing=false on this event.
        let _ = self.event_tx.send(SyncEvent::SyncCompleted(result));

        // 2. Error event — structured classification for the UI to surface.
        let sync_err = SyncError {
            kind: error_kind,
            message,
            retryable,
            code: code_for_error,
            remote_wipe: remote_wipe_for_error,
        };
        let _ = self.event_tx.send(SyncEvent::Error(sync_err));

        // 3. DeviceRevoked (only when the underlying error says so). This
        //    event triggers the dedicated Dart cleanup path that wipes
        //    credentials and stops auto-sync.
        if is_revoked {
            let _ = self.event_tx.send(SyncEvent::DeviceRevoked {
                device_id: device_id.to_string(),
                remote_wipe: remote_wipe_flag,
            });
        }

        Err(err_to_return)
    }

    /// Catch-up sync if stale.
    ///
    /// Skips sync if the last successful sync was less than 5 seconds ago.
    /// Otherwise triggers a full sync cycle.
    pub async fn catch_up_if_stale(
        &mut self,
        key_hierarchy: &prism_sync_crypto::KeyHierarchy,
        signing_key: &ed25519_dalek::SigningKey,
        ml_dsa_signing_key: Option<&prism_sync_crypto::DevicePqSigningKey>,
        device_id: &str,
        ml_dsa_key_generation: u32,
    ) -> Result<()> {
        if let Some(last) = self.last_sync_time {
            if last.elapsed() < Duration::from_secs(5) {
                return Ok(());
            }
        }
        let _ = self
            .sync_now(key_hierarchy, signing_key, ml_dsa_signing_key, device_id, ml_dsa_key_generation)
            .await?;
        Ok(())
    }
}

impl Drop for SyncService {
    fn drop(&mut self) {
        if let Some(handle) = self.auto_sync_handle.take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn debounce_coalesces_rapid_signals() {
        let (mutation_tx, mutation_rx) = mpsc::channel::<()>(32);
        let (trigger_tx, mut trigger_rx) = mpsc::channel::<SyncTrigger>(16);

        let _handle = spawn_auto_sync_task(mutation_rx, Duration::from_millis(50), trigger_tx);

        // Send 5 rapid mutation signals
        for _ in 0..5 {
            mutation_tx.send(()).await.unwrap();
        }

        // Should receive exactly one debounced trigger
        let trigger = tokio::time::timeout(Duration::from_millis(200), trigger_rx.recv())
            .await
            .expect("should receive trigger within timeout")
            .expect("channel should not be closed");

        assert_eq!(trigger, SyncTrigger::MutationDebounce);

        // No second trigger should arrive
        let result = tokio::time::timeout(Duration::from_millis(100), trigger_rx.recv()).await;
        assert!(result.is_err(), "should not receive a second trigger");
    }

    #[tokio::test]
    async fn debounce_triggers_separately_for_spaced_signals() {
        let (mutation_tx, mutation_rx) = mpsc::channel::<()>(32);
        let (trigger_tx, mut trigger_rx) = mpsc::channel::<SyncTrigger>(16);

        let _handle = spawn_auto_sync_task(mutation_rx, Duration::from_millis(30), trigger_tx);

        // First burst
        mutation_tx.send(()).await.unwrap();
        let trigger = tokio::time::timeout(Duration::from_millis(200), trigger_rx.recv())
            .await
            .expect("first trigger")
            .expect("not closed");
        assert_eq!(trigger, SyncTrigger::MutationDebounce);

        // Wait well past debounce, then send second burst
        tokio::time::sleep(Duration::from_millis(50)).await;
        mutation_tx.send(()).await.unwrap();

        let trigger = tokio::time::timeout(Duration::from_millis(200), trigger_rx.recv())
            .await
            .expect("second trigger")
            .expect("not closed");
        assert_eq!(trigger, SyncTrigger::MutationDebounce);
    }

    #[tokio::test]
    async fn debounce_exits_when_sender_dropped() {
        let (mutation_tx, mutation_rx) = mpsc::channel::<()>(32);
        let (trigger_tx, _trigger_rx) = mpsc::channel::<SyncTrigger>(16);

        let handle = spawn_auto_sync_task(mutation_rx, Duration::from_millis(30), trigger_tx);

        // Drop sender — task should exit
        drop(mutation_tx);
        let result = tokio::time::timeout(Duration::from_millis(200), handle).await;
        assert!(result.is_ok(), "task should exit when sender is dropped");
    }

    #[tokio::test]
    async fn notification_handler_new_data_sends_trigger() {
        let (trigger_tx, mut trigger_rx) = mpsc::channel::<SyncTrigger>(16);
        let (event_tx, _event_rx) = broadcast::channel::<SyncEvent>(16);

        let notifications =
            futures_util::stream::iter(vec![SyncNotification::NewData { server_seq: 42 }]);
        let pinned: std::pin::Pin<Box<dyn futures_util::Stream<Item = SyncNotification> + Send>> =
            Box::pin(notifications);

        let handle = spawn_notification_handler(
            pinned,
            "my-device".to_string(),
            trigger_tx,
            event_tx,
            None,
            None,
        );

        let trigger = tokio::time::timeout(Duration::from_millis(200), trigger_rx.recv())
            .await
            .expect("should receive trigger")
            .expect("not closed");
        assert_eq!(trigger, SyncTrigger::WebSocketNewData);

        let _ = handle.await;
    }

    #[tokio::test]
    async fn notification_handler_device_revoked_self() {
        let (trigger_tx, _trigger_rx) = mpsc::channel::<SyncTrigger>(16);
        let (event_tx, mut event_rx) = broadcast::channel::<SyncEvent>(16);

        let notifications = futures_util::stream::iter(vec![SyncNotification::DeviceRevoked {
            device_id: "my-device".to_string(),
            new_epoch: 2,
            remote_wipe: false,
        }]);
        let pinned: std::pin::Pin<Box<dyn futures_util::Stream<Item = SyncNotification> + Send>> =
            Box::pin(notifications);

        let handle = spawn_notification_handler(
            pinned,
            "my-device".to_string(),
            trigger_tx,
            event_tx,
            None,
            None,
        );

        let event = tokio::time::timeout(Duration::from_millis(200), event_rx.recv())
            .await
            .expect("should receive event")
            .expect("not lagged");
        assert!(
            matches!(event, SyncEvent::DeviceRevoked { device_id: ref id, .. } if id == "my-device")
        );

        let _ = handle.await;
    }

    #[tokio::test]
    async fn notification_handler_device_revoked_other() {
        let (trigger_tx, _trigger_rx) = mpsc::channel::<SyncTrigger>(16);
        let (event_tx, mut event_rx) = broadcast::channel::<SyncEvent>(16);

        let notifications = futures_util::stream::iter(vec![SyncNotification::DeviceRevoked {
            device_id: "other-device".to_string(),
            new_epoch: 3,
            remote_wipe: false,
        }]);
        let pinned: std::pin::Pin<Box<dyn futures_util::Stream<Item = SyncNotification> + Send>> =
            Box::pin(notifications);

        let handle = spawn_notification_handler(
            pinned,
            "my-device".to_string(),
            trigger_tx,
            event_tx,
            None,
            None,
        );

        let event = tokio::time::timeout(Duration::from_millis(200), event_rx.recv())
            .await
            .expect("should receive event")
            .expect("not lagged");
        assert!(
            matches!(event, SyncEvent::DeviceRevoked { device_id: ref id, .. } if id == "other-device"),
            "expected DeviceRevoked with device_id \"other-device\", got {:?}",
            event
        );

        let _ = handle.await;
    }

    #[tokio::test]
    async fn notification_handler_epoch_rotated() {
        let (trigger_tx, _trigger_rx) = mpsc::channel::<SyncTrigger>(16);
        let (event_tx, mut event_rx) = broadcast::channel::<SyncEvent>(16);

        let notifications =
            futures_util::stream::iter(vec![SyncNotification::EpochRotated { new_epoch: 5 }]);
        let pinned: std::pin::Pin<Box<dyn futures_util::Stream<Item = SyncNotification> + Send>> =
            Box::pin(notifications);

        let handle = spawn_notification_handler(
            pinned,
            "my-device".to_string(),
            trigger_tx,
            event_tx,
            None,
            None,
        );

        let event = tokio::time::timeout(Duration::from_millis(200), event_rx.recv())
            .await
            .expect("should receive event")
            .expect("not lagged");
        assert!(matches!(event, SyncEvent::EpochRotated(5)));

        let _ = handle.await;
    }

    #[tokio::test]
    async fn set_auto_sync_enabled_returns_trigger_rx() {
        let (event_tx, _) = broadcast::channel::<SyncEvent>(16);
        let mut service = SyncService::new(event_tx);

        let trigger_rx = service.set_auto_sync(AutoSyncConfig {
            enabled: true,
            debounce: Duration::from_millis(50),
            ..Default::default()
        });
        assert!(trigger_rx.is_some());
        assert!(service.auto_sync_tx.is_some());

        // Sending a mutation signal should work
        let tx = service.auto_sync_sender().unwrap();
        tx.send(()).await.unwrap();
    }

    #[tokio::test]
    async fn set_auto_sync_disabled_returns_none() {
        let (event_tx, _) = broadcast::channel::<SyncEvent>(16);
        let mut service = SyncService::new(event_tx);

        let trigger_rx = service.set_auto_sync(AutoSyncConfig {
            enabled: false,
            ..Default::default()
        });
        assert!(trigger_rx.is_none());
        assert!(service.auto_sync_tx.is_none());
    }

    #[test]
    fn relay_error_category_maps_device_identity_mismatch() {
        assert_eq!(
            relay_error_kind_to_sync_error_kind(&RelayErrorCategory::DeviceIdentityMismatch),
            SyncErrorKind::DeviceIdentityMismatch
        );
    }

    #[test]
    fn relay_error_category_device_identity_mismatch_is_not_retryable() {
        assert!(!relay_error_retryable(
            &RelayErrorCategory::DeviceIdentityMismatch
        ));
    }

    #[test]
    fn relay_error_details_extracts_revocation_metadata() {
        let error = CoreError::Relay {
            message: "device revoked".into(),
            kind: RelayErrorCategory::Auth,
            status: None,
            code: Some("device_revoked".into()),
            min_signature_version: None,
            remote_wipe: Some(true),
            source: None,
        };

        assert_eq!(
            relay_error_details(&error),
            (Some("device_revoked".into()), Some(true))
        );
    }

    /// `DeviceKeyChanged` is a LOCAL engine error, not a relay response.
    /// It must NOT populate `error_code` / `remote_wipe` because those
    /// fields carry relay-sent markers (e.g. `device_revoked`). The
    /// cleanup routing in Dart keys off `SyncErrorKind::KeyChanged`
    /// instead. Regression guard for Fix 4 of the 2026-04-11 plan.
    #[test]
    fn relay_error_details_returns_none_for_device_key_changed() {
        let error = CoreError::DeviceKeyChanged {
            device_id: "dev-a".into(),
        };

        assert_eq!(relay_error_details(&error), (None, None));
    }

    /// Local engine and storage errors must also leave `error_code` and
    /// `remote_wipe` as `None`.
    #[test]
    fn relay_error_details_returns_none_for_local_errors() {
        let engine_err = CoreError::Engine("missing epoch key".into());
        assert_eq!(relay_error_details(&engine_err), (None, None));

        let storage_err = CoreError::Storage("tx aborted".into());
        assert_eq!(relay_error_details(&storage_err), (None, None));
    }

    /// Drain all currently available events from a broadcast receiver.
    fn drain_events(rx: &mut broadcast::Receiver<SyncEvent>) -> Vec<SyncEvent> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            out.push(ev);
        }
        out
    }

    /// `emit_final_failure` enforces the `SyncCompleted -> Error` event
    /// ordering required by Appendix B.1. A Dart UI that resets
    /// `isSyncing: false` only on `SyncCompleted` depends on this.
    #[tokio::test]
    async fn emit_final_failure_emits_sync_completed_before_error() {
        let (event_tx, mut event_rx) = broadcast::channel::<SyncEvent>(16);
        let mut service = SyncService::new(event_tx);

        let result = SyncResult {
            error_kind: Some(SyncErrorKind::Protocol),
            error: Some("simulated hard failure".into()),
            ..SyncResult::default()
        };
        let err = CoreError::Storage("simulated hard failure".into());
        let ret = service.emit_final_failure(
            result,
            SyncErrorKind::Protocol,
            false,
            "simulated hard failure".into(),
            err,
            "device-42",
        );
        assert!(ret.is_err(), "emit_final_failure always returns Err");

        let events = drain_events(&mut event_rx);
        let completed_idx = events
            .iter()
            .position(|e| matches!(e, SyncEvent::SyncCompleted(_)))
            .expect("must emit SyncCompleted");
        let error_idx = events
            .iter()
            .position(|e| matches!(e, SyncEvent::Error(_)))
            .expect("must emit Error");
        assert!(
            completed_idx < error_idx,
            "SyncCompleted must precede Error (isSyncing reset): events={events:?}"
        );
    }

    /// When the failure carries `error_code = "device_revoked"`,
    /// `emit_final_failure` also fires the dedicated `DeviceRevoked`
    /// event AFTER `Error`, so Dart's cleanup path runs. All three
    /// events must be emitted in the order `SyncCompleted -> Error
    /// -> DeviceRevoked`. Regression guard for Fix 3 of the 2026-04-11
    /// plan.
    #[tokio::test]
    async fn emit_final_failure_emits_device_revoked_on_revoked_code() {
        let (event_tx, mut event_rx) = broadcast::channel::<SyncEvent>(16);
        let mut service = SyncService::new(event_tx);

        let result = SyncResult {
            error_kind: Some(SyncErrorKind::Auth),
            error: Some("device revoked".into()),
            error_code: Some("device_revoked".into()),
            remote_wipe: Some(true),
            ..SyncResult::default()
        };
        let err = CoreError::Relay {
            message: "device revoked".into(),
            kind: RelayErrorCategory::Auth,
            status: Some(401),
            code: Some("device_revoked".into()),
            min_signature_version: None,
            remote_wipe: Some(true),
            source: None,
        };
        let _ = service.emit_final_failure(
            result,
            SyncErrorKind::Auth,
            false,
            "device revoked".into(),
            err,
            "device-42",
        );

        let events = drain_events(&mut event_rx);
        // Positions of the three expected events.
        let completed_idx = events
            .iter()
            .position(|e| matches!(e, SyncEvent::SyncCompleted(_)))
            .expect("must emit SyncCompleted");
        let error_idx = events
            .iter()
            .position(|e| matches!(e, SyncEvent::Error(_)))
            .expect("must emit Error");
        let revoked_idx = events
            .iter()
            .position(|e| matches!(e, SyncEvent::DeviceRevoked { .. }))
            .expect("must emit DeviceRevoked for device_revoked code");

        // Ordering: SyncCompleted -> Error -> DeviceRevoked.
        assert!(
            completed_idx < error_idx,
            "SyncCompleted must precede Error: events={events:?}"
        );
        assert!(
            error_idx < revoked_idx,
            "Error must precede DeviceRevoked: events={events:?}"
        );

        // Payload checks.
        if let SyncEvent::Error(err) = &events[error_idx] {
            assert_eq!(err.kind, SyncErrorKind::Auth);
            assert_eq!(err.code.as_deref(), Some("device_revoked"));
            assert_eq!(err.remote_wipe, Some(true));
        }
        if let SyncEvent::DeviceRevoked {
            device_id,
            remote_wipe,
        } = &events[revoked_idx]
        {
            assert_eq!(device_id, "device-42");
            assert!(*remote_wipe);
        }
    }

    /// When the failure is NOT a revocation, no `DeviceRevoked` event
    /// is emitted. Just `SyncCompleted -> Error`.
    #[tokio::test]
    async fn emit_final_failure_does_not_emit_device_revoked_on_other_codes() {
        let (event_tx, mut event_rx) = broadcast::channel::<SyncEvent>(16);
        let mut service = SyncService::new(event_tx);

        let result = SyncResult {
            error_kind: Some(SyncErrorKind::Network),
            error: Some("timeout".into()),
            error_code: None,
            remote_wipe: None,
            ..SyncResult::default()
        };
        let err = CoreError::Relay {
            message: "timeout".into(),
            kind: RelayErrorCategory::Network,
            status: None,
            code: None,
            min_signature_version: None,
            remote_wipe: None,
            source: None,
        };
        let _ = service.emit_final_failure(
            result,
            SyncErrorKind::Network,
            true,
            "timeout".into(),
            err,
            "device-42",
        );

        let events = drain_events(&mut event_rx);
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, SyncEvent::DeviceRevoked { .. })),
            "no DeviceRevoked event for non-revoked codes: {events:?}"
        );
    }

    /// Round 4 Fix 3 regression: when a retryable error is stashed and
    /// then a terminal `device_revoked` arrives, the stashed result's
    /// `error_code` won't have the revocation code. `emit_final_failure`
    /// must derive the revocation decision from the terminal error
    /// (`err_to_return`), not (only) from the possibly-stale
    /// `result.error_code`.
    #[tokio::test]
    async fn emit_final_failure_terminal_err_takes_precedence_over_stashed_result() {
        let (event_tx, mut event_rx) = broadcast::channel::<SyncEvent>(16);
        let mut service = SyncService::new(event_tx);

        // Stashed result from a prior retryable failure — no revocation code.
        let stashed = SyncResult {
            error_kind: Some(SyncErrorKind::Network),
            error: Some("retryable timeout".into()),
            error_code: None,
            remote_wipe: None,
            ..SyncResult::default()
        };
        // Terminal error IS a device_revoked, e.g. the server just revoked us.
        let terminal_err = CoreError::Relay {
            message: "device revoked".into(),
            kind: RelayErrorCategory::Auth,
            status: Some(401),
            code: Some("device_revoked".into()),
            min_signature_version: None,
            remote_wipe: Some(true),
            source: None,
        };

        let _ = service.emit_final_failure(
            stashed,
            SyncErrorKind::Auth,
            false,
            "device revoked".into(),
            terminal_err,
            "device-42",
        );

        let events = drain_events(&mut event_rx);

        // The DeviceRevoked event must fire even though the stashed
        // result had no error_code.
        let revoked = events
            .iter()
            .find(|e| matches!(e, SyncEvent::DeviceRevoked { .. }))
            .expect(
                "must emit DeviceRevoked even when stashed result lacks code: {events:?}"
            );
        if let SyncEvent::DeviceRevoked {
            device_id,
            remote_wipe,
        } = revoked
        {
            assert_eq!(device_id, "device-42");
            assert!(*remote_wipe, "remote_wipe from terminal error must propagate");
        }

        // The Error event should also carry the terminal error's code.
        let err_ev = events
            .iter()
            .find_map(|e| match e {
                SyncEvent::Error(err) => Some(err),
                _ => None,
            })
            .expect("must emit Error");
        assert_eq!(
            err_ev.code.as_deref(),
            Some("device_revoked"),
            "Error event code must come from terminal error, not stashed result"
        );
    }
}
