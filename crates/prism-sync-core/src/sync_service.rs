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

fn relay_error_retryable(kind: &RelayErrorCategory) -> bool {
    matches!(
        kind,
        RelayErrorCategory::Network | RelayErrorCategory::Server
    )
}

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

fn relay_error_details(error: &CoreError) -> (Option<String>, Option<bool>) {
    match error {
        CoreError::Relay {
            code, remote_wipe, ..
        } => (code.clone(), *remote_wipe),
        _ => (None, None),
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
/// Lists active devices from the relay and tries each one's X25519 public
/// key to unwrap the rekey artifact. On success, stores the epoch key in
/// the key hierarchy, persists it to the secure store, and updates the
/// current epoch in storage.
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

    let exchange_key = match guard.device_secret() {
        Some(ds) => match ds.x25519_keypair(my_device_id) {
            Ok(xk) => xk,
            Err(e) => {
                tracing::warn!(
                    epoch = new_epoch,
                    error = %e,
                    "epoch recovery: failed to derive X25519 keypair"
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

    // Drop the lock before network I/O (list_devices). We'll re-acquire
    // it for handle_rotation which mutates key_hierarchy.
    drop(guard);

    let devices = match relay.list_devices().await {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(
                epoch = new_epoch,
                error = %e,
                "epoch recovery: failed to list devices"
            );
            return;
        }
    };

    // Re-acquire the lock for key_hierarchy mutation
    let mut guard = inner.lock().await;

    // Re-check in case another task recovered while we were waiting
    if guard.key_hierarchy().has_epoch_key(new_epoch) {
        return;
    }

    let mut recovered = false;
    for device in &devices {
        if device.device_id == my_device_id || device.status != "active" {
            continue;
        }
        if device.x25519_public_key.len() != 32 {
            continue;
        }
        let sender_pk: [u8; 32] = match device.x25519_public_key.as_slice().try_into() {
            Ok(pk) => pk,
            Err(_) => continue,
        };

        match EpochManager::handle_rotation(
            relay.as_ref(),
            guard.key_hierarchy_mut(),
            new_epoch,
            my_device_id,
            &exchange_key,
            &sender_pk,
        )
        .await
        {
            Ok(()) => {
                tracing::info!(
                    epoch = new_epoch,
                    sender = %device.device_id,
                    "epoch recovery: successfully recovered epoch key"
                );
                recovered = true;
                break;
            }
            Err(e) => {
                tracing::debug!(
                    epoch = new_epoch,
                    sender = %device.device_id,
                    error = %e,
                    "epoch recovery: failed with this sender, trying next"
                );
                continue;
            }
        }
    }

    if !recovered {
        tracing::warn!(
            epoch = new_epoch,
            "epoch recovery: failed to recover epoch key from any active device"
        );
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
    pub async fn upload_pairing_snapshot(
        &self,
        key_hierarchy: &prism_sync_crypto::KeyHierarchy,
        epoch: i32,
        device_id: &str,
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
    /// `SyncEvent::SyncCompleted` on success. On exhausted retries, emits
    /// `SyncEvent::Error` and returns the underlying error.
    pub async fn sync_now(
        &mut self,
        key_hierarchy: &prism_sync_crypto::KeyHierarchy,
        signing_key: &ed25519_dalek::SigningKey,
        device_id: &str,
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

        loop {
            match engine
                .sync(sync_id, key_hierarchy, signing_key, device_id)
                .await
            {
                Ok(result) => {
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
                    if !retryable || attempts > self.auto_sync_config.max_retries {
                        let error_kind = match &e {
                            CoreError::Relay { kind, .. } => {
                                relay_error_kind_to_sync_error_kind(kind)
                            }
                            CoreError::Engine(_) => SyncErrorKind::Network,
                            CoreError::Storage(_) => SyncErrorKind::Network,
                            _ => SyncErrorKind::Network,
                        };
                        let (code, remote_wipe) = relay_error_details(&e);

                        if code.as_deref() == Some("device_revoked") {
                            let _ = self.event_tx.send(SyncEvent::DeviceRevoked {
                                device_id: device_id.to_string(),
                                remote_wipe: remote_wipe.unwrap_or(false),
                            });
                            return Err(e);
                        }

                        let sync_err = SyncError {
                            kind: error_kind,
                            message: e.to_string(),
                            retryable,
                            code,
                            remote_wipe,
                        };
                        let _ = self.event_tx.send(SyncEvent::Error(sync_err));
                        return Err(e);
                    }
                    tokio::time::sleep(self.auto_sync_config.retry_delay).await;
                }
            }
        }
    }

    /// Catch-up sync if stale.
    ///
    /// Skips sync if the last successful sync was less than 5 seconds ago.
    /// Otherwise triggers a full sync cycle.
    pub async fn catch_up_if_stale(
        &mut self,
        key_hierarchy: &prism_sync_crypto::KeyHierarchy,
        signing_key: &ed25519_dalek::SigningKey,
        device_id: &str,
    ) -> Result<()> {
        if let Some(last) = self.last_sync_time {
            if last.elapsed() < Duration::from_secs(5) {
                return Ok(());
            }
        }
        let _ = self.sync_now(key_hierarchy, signing_key, device_id).await?;
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
            remote_wipe: Some(true),
        };

        assert_eq!(
            relay_error_details(&error),
            (Some("device_revoked".into()), Some(true))
        );
    }
}
