//! Consumer-facing `PrismSync` builder and API.
//!
//! `PrismSync` is the single entry point for consumers. It wraps key
//! lifecycle, sync orchestration, and event streaming behind a cohesive API.
//!
//! # Example
//! ```ignore
//! let sync = PrismSync::builder()
//!     .schema(my_schema)
//!     .storage(my_storage)
//!     .secure_store(my_store)
//!     .relay_url("https://relay.example.com")
//!     .build()?;
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::broadcast;

use crate::device_registry::DeviceRegistryManager;
use crate::engine::{BootstrapReport, SeedRecord, SyncConfig, SyncEngine};
use crate::epoch::EpochManager;
use crate::error::{CoreError, Result};
use crate::events::{event_channel, EntityChange, SyncEvent};
use crate::hlc::Hlc;
use crate::op_emitter::OpEmitter;
use crate::pairing::SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING;
use crate::recovery::{commit_recovered_epoch_material, KeyHierarchyRecoverer};
use crate::relay::SyncRelay;
use crate::schema::{SyncSchema, SyncType, SyncValue};
use crate::secure_store::SecureStore;
use crate::storage::{StorageError, SyncStorage};
use crate::sync_service::{AutoSyncConfig, SyncService};
use crate::syncable_entity::SyncableEntity;
use prism_sync_crypto::{mnemonic, DeviceSecret, KeyHierarchy};

/// How encryption keys are managed.
pub enum KeyMode {
    /// Keys are fully managed by `PrismSync` (password + secret key).
    Managed,
    /// Master key material provided externally (e.g. from a parent app).
    ExternalMaster(Vec<u8>),
    /// Individual encryption keys provided externally.
    ExternalKeys {
        /// The raw encryption key used for sync payloads.
        encryption_key: Vec<u8>,
    },
}

/// Snapshot of the current sync status.
pub struct SyncStatus {
    /// Whether a sync engine is configured and ready.
    pub syncing: bool,
    /// Timestamp of the last successful sync, if any.
    pub last_sync: Option<chrono::DateTime<chrono::Utc>>,
    /// Number of pending (unpushed) operations.
    pub pending_ops: u64,
}

/// Builder for constructing a [`PrismSync`] instance.
pub struct PrismSyncBuilder {
    schema: Option<SyncSchema>,
    key_mode: KeyMode,
    storage: Option<Arc<dyn SyncStorage>>,
    secure_store: Option<Arc<dyn SecureStore>>,
    relay_url: Option<String>,
    allow_insecure: bool,
    entities: Vec<Arc<dyn SyncableEntity>>,
}

impl PrismSyncBuilder {
    /// Set the sync schema (required).
    pub fn schema(mut self, schema: SyncSchema) -> Self {
        self.schema = Some(schema);
        self
    }

    /// Set the key management mode. Default: `KeyMode::Managed`.
    pub fn key_mode(mut self, mode: KeyMode) -> Self {
        self.key_mode = mode;
        self
    }

    /// Set the sync storage backend (required).
    pub fn storage(mut self, storage: Arc<dyn SyncStorage>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Set the secure store backend (required).
    pub fn secure_store(mut self, store: Arc<dyn SecureStore>) -> Self {
        self.secure_store = Some(store);
        self
    }

    /// Set the relay server URL. Must be `https://` unless
    /// [`allow_insecure_transport`](Self::allow_insecure_transport) is called.
    pub fn relay_url(mut self, url: &str) -> Self {
        self.relay_url = Some(url.to_string());
        self
    }

    /// Allow `http://` and `ws://` relay URLs (for local development only).
    pub fn allow_insecure_transport(mut self) -> Self {
        self.allow_insecure = true;
        self
    }

    /// Register a syncable entity implementation.
    pub fn entity(mut self, entity: Arc<dyn SyncableEntity>) -> Self {
        self.entities.push(entity);
        self
    }

    /// Build the [`PrismSync`] instance.
    ///
    /// Validates that all required fields are set and that the relay URL
    /// uses HTTPS (unless insecure transport is explicitly allowed).
    pub fn build(self) -> Result<PrismSync> {
        let schema = self.schema.ok_or_else(|| CoreError::Schema("schema is required".into()))?;
        let storage = self
            .storage
            .ok_or_else(|| CoreError::Storage(StorageError::Logic("storage is required".into())))?;
        let secure_store = self.secure_store.ok_or_else(|| {
            CoreError::Storage(StorageError::Logic("secure_store is required".into()))
        })?;

        // Validate relay URL transport security
        if let Some(ref url) = self.relay_url {
            if !self.allow_insecure && !url.starts_with("https://") && !url.starts_with("wss://") {
                return Err(CoreError::Storage(StorageError::Logic(
                    "relay URL must use HTTPS/WSS (use allow_insecure_transport() for development)"
                        .into(),
                )));
            }
        }

        let (event_tx, _) = event_channel();
        let sync_service = SyncService::new(event_tx.clone());

        Ok(PrismSync {
            schema,
            _key_mode: self.key_mode,
            storage,
            secure_store,
            relay_url: self.relay_url,
            entities: self.entities,
            key_hierarchy: KeyHierarchy::new(),
            device_secret: None,
            sync_service,
            event_tx,
            op_emitter: None,
            device_signing_key: None,
            device_ml_dsa_signing_key: None,
            ml_dsa_key_generation: None,
            device_id: None,
            epoch: None,
        })
    }
}

/// The primary consumer-facing API for prism-sync.
///
/// Manages key lifecycle, sync orchestration, and event streaming.
/// Obtain an instance via [`PrismSync::builder()`].
pub struct PrismSync {
    schema: SyncSchema,
    _key_mode: KeyMode,
    storage: Arc<dyn SyncStorage>,
    secure_store: Arc<dyn SecureStore>,
    relay_url: Option<String>,
    entities: Vec<Arc<dyn SyncableEntity>>,
    key_hierarchy: KeyHierarchy,
    device_secret: Option<DeviceSecret>,
    sync_service: SyncService,
    event_tx: broadcast::Sender<SyncEvent>,
    op_emitter: Option<OpEmitter>,
    device_signing_key: Option<ed25519_dalek::SigningKey>,
    device_ml_dsa_signing_key: Option<prism_sync_crypto::DevicePqSigningKey>,
    ml_dsa_key_generation: Option<u32>,
    device_id: Option<String>,
    epoch: Option<i32>,
}

impl PrismSync {
    /// Create a new builder.
    pub fn builder() -> PrismSyncBuilder {
        PrismSyncBuilder {
            schema: None,
            key_mode: KeyMode::Managed,
            storage: None,
            secure_store: None,
            relay_url: None,
            allow_insecure: false,
            entities: Vec::new(),
        }
    }

    // ── Key lifecycle ──

    /// Initialize the key hierarchy with a password and BIP39 secret key.
    ///
    /// **Password policy:** This library does not enforce password strength.
    /// The consumer application is responsible for password validation
    /// (minimum length, complexity, etc.) before calling this method.
    /// All devices in a sync group must use the same password.
    ///
    /// Generates the DEK, wraps it under `Argon2id(password + secret_key)`,
    /// and persists the wrapped DEK and salt to the secure store. Also
    /// generates a device secret if none exists.
    pub fn initialize(&mut self, password: &str, secret_key: &[u8]) -> Result<()> {
        let (wrapped_dek, salt) =
            self.key_hierarchy.initialize(password, secret_key).map_err(CoreError::Crypto)?;

        self.secure_store.set("wrapped_dek", &wrapped_dek)?;
        self.secure_store.set("dek_salt", &salt)?;

        // Generate device secret if none exists
        if self.device_secret.is_none() {
            let ds = DeviceSecret::generate();
            self.secure_store.set("device_secret", ds.as_bytes())?;
            self.device_secret = Some(ds);
        }

        Ok(())
    }

    /// Unlock an existing key hierarchy from persisted credentials.
    ///
    /// Reads the wrapped DEK and salt from the secure store, then derives
    /// the DEK using `Argon2id(password + secret_key)`.
    pub fn unlock(&mut self, password: &str, secret_key: &[u8]) -> Result<()> {
        let wrapped_dek = self.secure_store.get("wrapped_dek")?.ok_or_else(|| {
            CoreError::Storage(StorageError::Logic("no wrapped DEK found".into()))
        })?;
        let salt = self
            .secure_store
            .get("dek_salt")?
            .ok_or_else(|| CoreError::Storage(StorageError::Logic("no salt found".into())))?;

        self.key_hierarchy
            .unlock(password, secret_key, &wrapped_dek, &salt)
            .map_err(CoreError::Crypto)?;

        // Restore device secret
        if let Some(ds_bytes) = self.secure_store.get("device_secret")? {
            self.device_secret =
                Some(DeviceSecret::from_bytes(ds_bytes).map_err(CoreError::Crypto)?);
        }

        Ok(())
    }

    /// Restore the unlocked state directly from raw key material.
    ///
    /// Bypasses Argon2id password derivation. Use when the raw DEK has been
    /// persisted in the platform keychain (Signal-style key management).
    pub fn restore_runtime_keys(
        &mut self,
        dek_bytes: &[u8],
        device_secret_bytes: &[u8],
    ) -> Result<()> {
        self.key_hierarchy.restore_from_dek(dek_bytes).map_err(CoreError::Crypto)?;

        self.device_secret = Some(
            DeviceSecret::from_bytes(device_secret_bytes.to_vec()).map_err(CoreError::Crypto)?,
        );

        Ok(())
    }

    /// Only available when unlocked (after `initialize` or `unlock`).
    /// Cache in the platform keychain for `restore_runtime_keys` on relaunch.
    pub fn export_dek(&self) -> Result<Vec<u8>> {
        Ok(self.key_hierarchy.dek()?.to_vec())
    }

    /// Lock the key hierarchy, zeroizing all key material from memory.
    pub fn lock(&mut self) {
        self.key_hierarchy.lock();
    }

    /// Returns whether the key hierarchy is unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.key_hierarchy.is_unlocked()
    }

    /// Generate a new BIP39 secret key (mnemonic).
    pub fn generate_secret_key() -> Result<String> {
        Ok(mnemonic::generate())
    }

    /// Derive the database encryption key from the current key hierarchy.
    ///
    /// Returns an error if the hierarchy is locked.
    pub fn database_key(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        self.key_hierarchy.database_key().map_err(CoreError::Crypto)
    }

    /// Derive local storage key: HKDF(DEK, DeviceSecret, "prism_local_storage_v2").
    ///
    /// Requires the key hierarchy to be unlocked and a DeviceSecret to be loaded
    /// (set by `initialize` or `unlock`).
    pub fn local_storage_key(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let dek = self.key_hierarchy.dek().map_err(CoreError::Crypto)?;
        let device_secret = self
            .device_secret
            .as_ref()
            .ok_or_else(|| CoreError::Engine("device secret not loaded".into()))?;
        prism_sync_crypto::kdf::derive_local_storage_key(dek, device_secret.as_bytes())
            .map_err(CoreError::Crypto)
    }

    /// Re-encrypt the Rust sync SQLite with a new 32-byte key.
    pub fn rekey_db(&self, new_key: &[u8; 32]) -> Result<()> {
        self.storage.rekey(new_key)
    }

    // ── Sync engine ──

    /// Configure the sync engine with a relay, enabling sync operations.
    ///
    /// Call this after `initialize` or `unlock` and after obtaining a relay
    /// connection. The `node_id` is this device's unique identifier (12-char
    /// hex), `epoch` is the current sync epoch number, and
    /// `ml_dsa_key_generation` is the current ML-DSA key generation for this
    /// device (0 for initial key, increments on each rotation).
    ///
    /// If a `DeviceSecret` is available (set by `initialize` or `unlock`),
    /// the device's Ed25519 and ML-DSA signing keys are derived and stored
    /// for use by `sync_now`, `on_resume`, and hybrid batch signing.
    pub fn configure_engine(
        &mut self,
        relay: Arc<dyn SyncRelay>,
        sync_id: String,
        node_id: String,
        epoch: i32,
        ml_dsa_key_generation: u32,
    ) {
        let engine = SyncEngine::new(
            self.storage.clone(),
            relay.clone(),
            self.entities.clone(),
            self.schema.clone(),
            SyncConfig::default(),
        );

        // Seed the OpEmitter's HLC watermark from the max HLC across all
        // currently-stored `field_versions`. Without this, a freshly
        // configured engine starts its emitter at `Hlc::zero`, which can
        // produce a smaller HLC than rows imported from a snapshot or
        // seeded via `bootstrap_existing_state` — the first local mutation
        // then races the seeded row and loses on the HLC tiebreaker.
        let max_hlc =
            match self.storage.list_all_field_version_hlcs(&sync_id) {
                Ok(hlcs) => match Hlc::parse_many_and_max(&hlcs) {
                    Ok(max) => max,
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "configure_engine: failed to parse stored HLCs — starting emitter at zero"
                        );
                        None
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "configure_engine: failed to list field_version HLCs — starting emitter at zero"
                    );
                    None
                }
            };
        self.op_emitter = Some(OpEmitter::new(node_id.clone(), sync_id.clone(), epoch, max_hlc));

        // Derive and store the device signing keys if a DeviceSecret is available.
        if let Some(ref device_secret) = self.device_secret {
            if let Ok(dsk) = device_secret.ed25519_keypair(&node_id) {
                self.device_signing_key = Some(dsk.into_signing_key());
            }
            // Derive ML-DSA signing key at current generation
            if let Ok(pq_sk) = device_secret.ml_dsa_65_keypair_v(&node_id, ml_dsa_key_generation) {
                self.device_ml_dsa_signing_key = Some(pq_sk);
                self.ml_dsa_key_generation = Some(ml_dsa_key_generation);
            }
        }
        self.device_id = Some(node_id);
        self.epoch = Some(epoch);

        self.sync_service.set_engine(engine, sync_id.clone());
        self.sync_service.clear_recoverer();
        if let Some(device_secret) = self.device_secret.as_ref() {
            if let Ok(recoverer) = KeyHierarchyRecoverer::new(
                relay,
                self.storage.clone(),
                self.secure_store.clone(),
                device_secret,
                sync_id,
                self.device_id.as_ref().expect("device_id set above").clone(),
            ) {
                self.sync_service.set_recoverer(Arc::new(recoverer));
            }
        }
    }

    /// Update the auto-sync configuration.
    ///
    /// Returns the [`SyncTrigger`] receiver that the caller must use to drive
    /// the actual sync loop: spawn a task that calls [`sync_now`](Self::sync_now)
    /// each time a trigger is received. Returns `None` when auto-sync is
    /// disabled.
    pub fn set_auto_sync(
        &mut self,
        config: AutoSyncConfig,
    ) -> Option<tokio::sync::mpsc::Receiver<crate::sync_service::SyncTrigger>> {
        self.sync_service.set_auto_sync(config)
    }

    /// Trigger a full sync cycle (pull + merge + push).
    ///
    /// Requires [`configure_engine`](Self::configure_engine) to have been
    /// called and a `DeviceSecret` to be available (set by `initialize` or
    /// `unlock`). Returns the [`SyncResult`](crate::engine::SyncResult) on
    /// success.
    pub async fn sync_now(&mut self) -> Result<crate::engine::SyncResult> {
        // Best-effort: recover any epoch keys we might be missing before we
        // attempt a pull. Joiners that registered moments after the
        // initiator's post_rekey (or any device that was offline when an
        // epoch rotation happened) would otherwise surface a pull-time
        // `CoreError::MissingEpochKey { epoch: N }` as soon as the engine
        // encountered a batch at the rotated epoch, with no preflight path
        // to fill in the missing key first.
        // Ignoring the return value is intentional — the method already
        // logs and swallows transient relay/crypto failures so a bad
        // network doesn't block the actual sync.
        let _ = self.catch_up_epoch_keys().await;

        let signing_key = self.device_signing_key.as_ref().ok_or_else(|| {
            CoreError::Engine(
                "sync not configured — call configure_engine after initialize/unlock".into(),
            )
        })?;
        let device_id = self.device_id.as_ref().ok_or_else(|| {
            CoreError::Engine("device_id not set — call configure_engine first".into())
        })?;
        let result = self
            .sync_service
            .sync_now_with_recovery(
                &mut self.key_hierarchy,
                signing_key,
                self.device_ml_dsa_signing_key.as_ref(),
                device_id,
                self.ml_dsa_key_generation.unwrap_or(0),
            )
            .await;
        self.apply_recovered_epoch_high_water();
        result
    }

    /// Recover any epoch keys we might be missing from the relay.
    ///
    /// Uses the relay's latest signed registry as the authority for the
    /// target epoch and per-epoch key commitments, then asks the relay for
    /// each missing per-device rekey artifact. A recovered key is accepted
    /// only after it matches the hash committed by that verified registry.
    ///
    /// This covers the "missed EpochRotated notification" case. The normal
    /// recovery path in sync_service::spawn_notification_handler only fires
    /// for live WebSocket events, so a device that was offline when the
    /// rotation happened (or a joiner whose WebSocket hadn't connected yet
    /// when the initiator's post_rekey fired) would otherwise stay stuck
    /// at the pre-rotation epoch and fail the next pull with a typed
    /// `CoreError::MissingEpochKey { epoch: N }`.
    ///
    /// Best-effort: logs and returns `Ok(())` on any relay, registry,
    /// crypto, or storage failure. Sync still proceeds and the normal error
    /// surface reports the underlying problem if recovery didn't fix it.
    async fn catch_up_epoch_keys(&mut self) -> Result<()> {
        let relay = match self.sync_service.relay() {
            Some(r) => r.clone(),
            None => {
                tracing::debug!("catch_up_epoch_keys: skipped (no relay configured)");
                return Ok(());
            }
        };
        let device_id = match self.device_id.as_deref() {
            Some(d) => d.to_string(),
            None => {
                tracing::debug!("catch_up_epoch_keys: skipped (no device_id)");
                return Ok(());
            }
        };
        let sync_id = match self.sync_service.sync_id() {
            Some(s) => s.to_string(),
            None => {
                tracing::debug!("catch_up_epoch_keys: skipped (no sync_id)");
                return Ok(());
            }
        };
        let Some(device_secret) = self.device_secret.as_ref() else {
            tracing::debug!("catch_up_epoch_keys: skipped (no device_secret)");
            return Ok(());
        };

        let local_epoch = self.epoch.unwrap_or(0).max(0) as u32;
        let devices = match relay.list_devices().await {
            Ok(devices) => devices,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "catch_up_epoch_keys: failed to list devices"
                );
                return Ok(());
            }
        };
        let Some(current_device) = devices.iter().find(|device| device.device_id == device_id)
        else {
            tracing::warn!(
                device_id = %device_id,
                "catch_up_epoch_keys: current device missing from relay device list"
            );
            return Ok(());
        };
        if current_device.status != "active" {
            tracing::warn!(
                device_id = %device_id,
                status = %current_device.status,
                "catch_up_epoch_keys: current device is not active"
            );
            return Ok(());
        }
        let relay_epoch = current_device.epoch.max(0) as u32;
        if relay_epoch <= local_epoch {
            tracing::debug!(
                local_epoch,
                relay_epoch,
                "catch_up_epoch_keys: skipped (local epoch is current)"
            );
            return Ok(());
        }

        tracing::info!(
            local_epoch,
            relay_epoch,
            known_epochs = ?self.key_hierarchy.known_epochs(),
            sync_id = %sync_id,
            device_id = %device_id,
            "catch_up_epoch_keys: entering preflight"
        );

        let registry_response = match relay.get_signed_registry().await {
            Ok(Some(response)) => response,
            Ok(None) => {
                tracing::warn!(
                    local_epoch,
                    relay_epoch,
                    "catch_up_epoch_keys: relay is ahead but no signed registry is available"
                );
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "catch_up_epoch_keys: failed to fetch signed registry"
                );
                return Ok(());
            }
        };
        let storage = self.storage.clone();
        let sid = sync_id.clone();
        let blob = registry_response.artifact_blob.clone();
        let snapshot = match tokio::task::spawn_blocking(move || {
            DeviceRegistryManager::verify_signed_registry_snapshot(&*storage, &sid, &blob)
        })
        .await
        {
            Ok(Ok(snapshot)) => snapshot,
            Ok(Err(e)) => {
                tracing::warn!(
                    error = %e,
                    "catch_up_epoch_keys: signed registry verification failed"
                );
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "catch_up_epoch_keys: signed registry verification task failed"
                );
                return Ok(());
            }
        };

        if snapshot.registry_version < SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING {
            tracing::warn!(
                registry_version = snapshot.registry_version,
                "catch_up_epoch_keys: signed registry version cannot prove epoch keys"
            );
            return Ok(());
        }
        if snapshot.current_epoch < relay_epoch {
            tracing::warn!(
                registry_epoch = snapshot.current_epoch,
                relay_epoch,
                "catch_up_epoch_keys: signed registry lags relay epoch"
            );
            return Ok(());
        }
        let Some(current_entry) =
            snapshot.entries.iter().find(|entry| entry.device_id == device_id)
        else {
            tracing::warn!(
                device_id = %device_id,
                "catch_up_epoch_keys: signed registry missing current device"
            );
            return Ok(());
        };
        if current_entry.status != "active" {
            tracing::warn!(
                device_id = %device_id,
                status = %current_entry.status,
                "catch_up_epoch_keys: signed registry marks current device non-active"
            );
            return Ok(());
        }

        let target_epoch = snapshot.current_epoch.max(relay_epoch);
        let catch_up = EpochManager::catch_up_epoch_keys(
            relay.as_ref(),
            &mut self.key_hierarchy,
            self.secure_store.as_ref(),
            device_secret,
            &device_id,
            local_epoch,
            target_epoch,
            &snapshot.epoch_key_hashes,
        )
        .await;
        let recovered_through = match catch_up {
            Ok(result) => result.recovered_through,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "catch_up_epoch_keys: verified catch-up failed"
                );
                self.secure_store
                    .get("epoch")
                    .ok()
                    .flatten()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .and_then(|value| value.parse::<u32>().ok())
                    .filter(|epoch| *epoch > local_epoch)
                    .unwrap_or(local_epoch)
            }
        };

        tracing::info!(
            local_epoch,
            relay_epoch,
            registry_epoch = snapshot.current_epoch,
            recovered_through,
            final_known_epochs = ?self.key_hierarchy.known_epochs(),
            "catch_up_epoch_keys: exit"
        );

        if recovered_through > local_epoch {
            let storage = self.storage.clone();
            let sid = sync_id;
            let ne = recovered_through as i32;
            let update_result = tokio::task::spawn_blocking(move || {
                let mut tx = storage.begin_tx()?;
                tx.update_current_epoch(&sid, ne)?;
                tx.commit()
            })
            .await;
            let mut persisted = false;
            match update_result {
                Ok(Ok(())) => {
                    persisted = true;
                }
                Ok(Err(e)) => {
                    tracing::warn!(
                        error = %e,
                        "catch_up_epoch_keys: sync_metadata update failed"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "catch_up_epoch_keys: join error on sync_metadata update"
                    );
                }
            }
            if persisted {
                self.advance_epoch(recovered_through as i32);
            }
        }

        Ok(())
    }

    /// App lifecycle hook: catch up sync if stale (>5 s since last sync).
    ///
    /// Requires [`configure_engine`](Self::configure_engine) to have been
    /// called and a `DeviceSecret` to be available. Skips the sync if the
    /// last successful sync was recent.
    pub async fn on_resume(&mut self) -> Result<()> {
        let signing_key = self.device_signing_key.as_ref().ok_or_else(|| {
            CoreError::Engine(
                "sync not configured — call configure_engine after initialize/unlock".into(),
            )
        })?;
        let device_id = self.device_id.as_ref().ok_or_else(|| {
            CoreError::Engine("device_id not set — call configure_engine first".into())
        })?;
        let result = self
            .sync_service
            .catch_up_if_stale_with_recovery(
                &mut self.key_hierarchy,
                signing_key,
                self.device_ml_dsa_signing_key.as_ref(),
                device_id,
                self.ml_dsa_key_generation.unwrap_or(0),
            )
            .await;
        self.apply_recovered_epoch_high_water();
        result
    }

    // ── Snapshot operations ──

    /// Upload an encrypted pairing snapshot to the relay for a new device.
    ///
    /// Call this on the existing device after generating an invite. The
    /// snapshot is encrypted with the current epoch key and uploaded with
    /// an optional TTL (auto-deleted after expiry). If `for_device_id` is
    /// provided, the snapshot is targeted to that specific device.
    ///
    /// Requires [`configure_engine`](Self::configure_engine) to have been
    /// called.
    pub async fn upload_pairing_snapshot(
        &self,
        ttl_secs: Option<u64>,
        for_device_id: Option<String>,
    ) -> Result<()> {
        let device_id = self.device_id.as_ref().ok_or_else(|| {
            CoreError::Engine("device_id not set — call configure_engine first".into())
        })?;
        let epoch = self.epoch.ok_or_else(|| {
            CoreError::Engine("epoch not set — call configure_engine first".into())
        })?;
        let signing_key = self.device_signing_key.as_ref().ok_or_else(|| {
            CoreError::Engine("signing key not set — call configure_engine first".into())
        })?;
        let ml_dsa_signing_key = self.device_ml_dsa_signing_key.as_ref().ok_or_else(|| {
            CoreError::Engine("ML-DSA signing key not set — call configure_engine first".into())
        })?;
        self.sync_service
            .upload_pairing_snapshot(
                &self.key_hierarchy,
                epoch,
                device_id,
                signing_key,
                ml_dsa_signing_key,
                self.ml_dsa_key_generation.unwrap_or(0),
                ttl_secs,
                for_device_id,
            )
            .await
    }

    /// Download and apply a bootstrap snapshot from the relay.
    ///
    /// Call this on a new device after pairing to populate local state from
    /// the existing device's snapshot. Returns `(entity_count, entity_changes)`
    /// where `entity_count` is the number of unique entities restored, and
    /// `entity_changes` contains the full field data for consumer DB application.
    ///
    /// Returns `(0, [])` if no snapshot is available.
    ///
    /// Requires [`configure_engine`](Self::configure_engine) to have been
    /// called.
    pub async fn bootstrap_from_snapshot(&mut self) -> Result<(u64, Vec<EntityChange>)> {
        self.sync_service.bootstrap_from_snapshot(&self.key_hierarchy).await
    }

    /// Seed `field_versions` from pre-existing local data (first-device
    /// bootstrap). No relay traffic; no `pending_ops` produced.
    ///
    /// See [`SyncEngine::bootstrap_existing_state`] for semantics and guards.
    /// Also re-seeds the live `OpEmitter`'s HLC watermark after seeding so
    /// subsequent `record_create` calls stamp strictly greater HLCs.
    pub async fn bootstrap_existing_state(
        &mut self,
        records: Vec<SeedRecord>,
    ) -> Result<BootstrapReport> {
        let report = self.sync_service.bootstrap_existing_state(records).await?;

        // Re-read the max HLC from storage and update the live emitter so
        // that any subsequent record_create/record_update uses a strictly
        // greater HLC than anything that was just seeded.
        if let (Some(sync_id), Some(emitter)) =
            (self.sync_service.sync_id(), self.op_emitter.as_mut())
        {
            match self.storage.list_all_field_version_hlcs(sync_id) {
                Ok(hlcs) => match Hlc::parse_many_and_max(&hlcs) {
                    Ok(Some(max)) => {
                        if &max > emitter.last_hlc() {
                            emitter.set_last_hlc(max);
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "bootstrap_existing_state: failed to parse stored HLCs after seeding"
                        );
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "bootstrap_existing_state: failed to read stored HLCs after seeding"
                    );
                }
            }
        }

        Ok(report)
    }

    /// Acknowledge that the downloaded snapshot has been applied locally.
    ///
    /// Instructs the relay to delete the snapshot via
    /// `DELETE /v1/sync/{id}/snapshot`. Idempotent: a relay-side 404 is
    /// mapped to `Ok(())` so concurrent joiners and expired-TTL cases don't
    /// surface as errors.
    pub async fn acknowledge_snapshot_applied(&self) -> Result<()> {
        self.sync_service.acknowledge_snapshot_applied().await
    }

    // ── Consumer mutation API ──

    /// Record a newly created entity for sync.
    ///
    /// Each field in `fields` becomes a pending op. Returns an error if the
    /// sync engine has not been configured via [`configure_engine`](Self::configure_engine).
    pub fn record_create(
        &mut self,
        table: &str,
        entity_id: &str,
        fields: &HashMap<String, SyncValue>,
    ) -> Result<()> {
        if self.op_emitter.is_none() {
            return Err(CoreError::Engine("sync not configured".into()));
        }
        self.validate_mutation_fields(table, fields)?;
        let emitter = self
            .op_emitter
            .as_mut()
            .ok_or_else(|| CoreError::Engine("sync not configured".into()))?;
        let batch_id = uuid::Uuid::new_v4().to_string();
        let result = emitter.emit_create(&*self.storage, table, entity_id, fields, &batch_id);
        if result.is_ok() {
            if let Some(tx) = self.sync_service.auto_sync_sender() {
                let _ = tx.try_send(());
            }
        }
        result
    }

    /// Record changed fields on an existing entity for sync.
    ///
    /// Only pass the fields that actually changed. Returns an error if the
    /// sync engine has not been configured.
    pub fn record_update(
        &mut self,
        table: &str,
        entity_id: &str,
        changed_fields: &HashMap<String, SyncValue>,
    ) -> Result<()> {
        if self.op_emitter.is_none() {
            return Err(CoreError::Engine("sync not configured".into()));
        }
        if changed_fields.is_empty() {
            return Ok(());
        }
        self.validate_mutation_fields(table, changed_fields)?;
        let emitter = self
            .op_emitter
            .as_mut()
            .ok_or_else(|| CoreError::Engine("sync not configured".into()))?;
        let batch_id = uuid::Uuid::new_v4().to_string();
        let result =
            emitter.emit_update(&*self.storage, table, entity_id, changed_fields, &batch_id);
        if result.is_ok() {
            if let Some(tx) = self.sync_service.auto_sync_sender() {
                let _ = tx.try_send(());
            }
        }
        result
    }

    /// Record a soft-delete for an entity.
    ///
    /// Creates a tombstone op (`is_deleted = true`). Returns an error if the
    /// sync engine has not been configured.
    pub fn record_delete(&mut self, table: &str, entity_id: &str) -> Result<()> {
        if self.op_emitter.is_none() {
            return Err(CoreError::Engine("sync not configured".into()));
        }
        self.schema.entity(table).ok_or_else(|| CoreError::UnknownTable(table.to_string()))?;
        let emitter = self
            .op_emitter
            .as_mut()
            .ok_or_else(|| CoreError::Engine("sync not configured".into()))?;
        let batch_id = uuid::Uuid::new_v4().to_string();
        let result = emitter.emit_delete(&*self.storage, table, entity_id, &batch_id);
        if result.is_ok() {
            if let Some(tx) = self.sync_service.auto_sync_sender() {
                let _ = tx.try_send(());
            }
        }
        result
    }

    fn validate_mutation_fields(
        &self,
        table: &str,
        fields: &HashMap<String, SyncValue>,
    ) -> Result<()> {
        let entity =
            self.schema.entity(table).ok_or_else(|| CoreError::UnknownTable(table.to_string()))?;

        for (field_name, value) in fields {
            let field = entity.field_by_name(field_name).ok_or_else(|| {
                CoreError::UnknownField { table: table.to_string(), field: field_name.clone() }
            })?;
            validate_sync_value_type(table, field_name, field.sync_type, value)?;
        }

        Ok(())
    }

    // ── Epoch rotation ──

    /// Revoke a device and rotate to a new epoch with a fresh epoch key.
    ///
    /// 1. Revokes `target_device_id` on the relay (bumps epoch server-side).
    /// 2. Generates a new epoch key and posts per-device wrapped keys for all
    ///    remaining active devices.
    /// 3. Persists the new epoch key to the secure store.
    /// 4. Updates the local sync metadata with the new epoch number.
    ///
    /// Requires [`configure_engine`](Self::configure_engine) to have been called
    /// and a `DeviceSecret` to be available.
    pub async fn revoke_and_rekey(
        &mut self,
        relay: Arc<dyn SyncRelay>,
        target_device_id: &str,
        remote_wipe: bool,
    ) -> Result<u32> {
        // Get required state
        let sync_id = self
            .sync_service()
            .sync_id()
            .ok_or_else(|| CoreError::Engine("sync_id not set".into()))?
            .to_string();
        let self_device_id = self
            .device_id()
            .ok_or_else(|| {
                CoreError::Engine("device_id not set — call configure_engine first".into())
            })?
            .to_string();

        // 1. Get current epoch from local metadata
        let storage = self.storage().clone();
        let sid = sync_id.clone();
        let meta = tokio::task::spawn_blocking(move || storage.get_sync_metadata(&sid))
            .await
            .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
        let current_epoch = meta.map(|m| m.current_epoch).unwrap_or(0);
        let new_epoch = (current_epoch + 1) as u32;

        // 2. Generate wrapped keys for surviving devices, then perform the
        //    atomic revoke+epoch-rotation request against the relay.
        let (epoch_key, wrapped_keys) = crate::epoch::EpochManager::prepare_wrapped_keys(
            relay.as_ref(),
            new_epoch,
            Some(target_device_id),
        )
        .await?;

        let committed_epoch = match relay
            .revoke_device(target_device_id, remote_wipe, new_epoch as i32, wrapped_keys)
            .await
        {
            Ok(epoch) => epoch as u32,
            Err(relay_error) => {
                let error = CoreError::from_relay(relay_error);
                if !error.is_retryable() {
                    return Err(error);
                }

                if !self
                    .reconcile_revoke_and_rekey_commit(
                        relay.as_ref(),
                        &self_device_id,
                        target_device_id,
                        new_epoch,
                    )
                    .await
                {
                    return Err(error);
                }

                tracing::info!(
                    device_id = %self_device_id,
                    target_device_id = %target_device_id,
                    epoch = new_epoch,
                    "revoke_and_rekey: reconciled ambiguous relay failure after remote commit"
                );
                new_epoch
            }
        };

        self.commit_local_epoch_rotation(&sync_id, committed_epoch, epoch_key.as_ref()).await?;

        Ok(committed_epoch)
    }

    async fn reconcile_revoke_and_rekey_commit(
        &self,
        relay: &dyn SyncRelay,
        self_device_id: &str,
        target_device_id: &str,
        expected_epoch: u32,
    ) -> bool {
        let devices = match relay.list_devices().await {
            Ok(devices) => devices,
            Err(error) => {
                tracing::warn!(
                    device_id = %self_device_id,
                    target_device_id = %target_device_id,
                    epoch = expected_epoch,
                    error = %error,
                    "revoke_and_rekey: reconciliation failed to list devices"
                );
                return false;
            }
        };

        let Some(self_device) = devices.iter().find(|device| device.device_id == self_device_id)
        else {
            tracing::warn!(
                device_id = %self_device_id,
                target_device_id = %target_device_id,
                epoch = expected_epoch,
                "revoke_and_rekey: reconciliation could not find local device in relay registry"
            );
            return false;
        };

        if self_device.status != "active" || self_device.epoch != expected_epoch as i32 {
            tracing::info!(
                device_id = %self_device_id,
                target_device_id = %target_device_id,
                epoch = expected_epoch,
                relay_status = %self_device.status,
                relay_epoch = self_device.epoch,
                "revoke_and_rekey: reconciliation did not prove survivor advanced to new epoch"
            );
            return false;
        }

        let target_not_active = devices
            .iter()
            .find(|device| device.device_id == target_device_id)
            .map(|device| device.status != "active")
            .unwrap_or(true);
        if !target_not_active {
            tracing::info!(
                device_id = %self_device_id,
                target_device_id = %target_device_id,
                epoch = expected_epoch,
                "revoke_and_rekey: reconciliation did not prove target device was revoked"
            );
            return false;
        }

        match relay.get_rekey_artifact(expected_epoch as i32, self_device_id).await {
            Ok(Some(_)) => true,
            Ok(None) => {
                tracing::info!(
                    device_id = %self_device_id,
                    target_device_id = %target_device_id,
                    epoch = expected_epoch,
                    "revoke_and_rekey: reconciliation found no local rekey artifact"
                );
                false
            }
            Err(error) => {
                tracing::warn!(
                    device_id = %self_device_id,
                    target_device_id = %target_device_id,
                    epoch = expected_epoch,
                    error = %error,
                    "revoke_and_rekey: reconciliation failed to fetch local rekey artifact"
                );
                false
            }
        }
    }

    async fn commit_local_epoch_rotation(
        &mut self,
        sync_id: &str,
        epoch: u32,
        epoch_key: &[u8],
    ) -> Result<()> {
        commit_recovered_epoch_material(
            self.storage().clone(),
            self.secure_store().clone(),
            sync_id,
            epoch,
            epoch_key,
        )
        .await?;

        self.key_hierarchy_mut()
            .store_epoch_key(epoch, zeroize::Zeroizing::new(epoch_key.to_vec()));
        self.advance_epoch(epoch as i32);
        Ok(())
    }

    fn apply_recovered_epoch_high_water(&mut self) {
        let Some(recovered_epoch) = self.sync_service.take_recovered_epoch_high_water() else {
            return;
        };
        if self.epoch.unwrap_or(0) < recovered_epoch as i32 {
            self.advance_epoch(recovered_epoch as i32);
        }
    }

    /// Advance the runtime epoch after a successful rotation or recovery.
    /// Updates both the in-memory epoch and the live OpEmitter so new
    /// mutations are stamped at the correct epoch.
    pub fn advance_epoch(&mut self, new_epoch: i32) {
        self.epoch = Some(new_epoch);
        let epoch_bytes = new_epoch.to_string();
        let _ = self.secure_store.set("epoch", epoch_bytes.as_bytes());
        if let Some(ref mut emitter) = self.op_emitter {
            emitter.set_epoch(new_epoch);
        }
    }

    // ── Events ──

    /// Subscribe to sync events.
    pub fn events(&self) -> broadcast::Receiver<SyncEvent> {
        self.event_tx.subscribe()
    }

    /// Get the current sync status snapshot.
    pub fn status(&self) -> SyncStatus {
        let sync_id = self.sync_service.sync_id();

        let pending_ops = sync_id
            .and_then(|sid| self.storage.get_unpushed_batch_ids(sid).ok())
            .map(|ids| ids.len() as u64)
            .unwrap_or(0);

        let last_sync = sync_id
            .and_then(|sid| self.storage.get_sync_metadata(sid).ok().flatten())
            .and_then(|meta| meta.last_successful_sync_at);

        SyncStatus { syncing: self.sync_service.has_engine(), last_sync, pending_ops }
    }

    // ── Accessors ──

    /// Access the sync schema.
    pub fn schema(&self) -> &SyncSchema {
        &self.schema
    }

    /// Access the key hierarchy (for advanced use / engine calls).
    pub fn key_hierarchy(&self) -> &KeyHierarchy {
        &self.key_hierarchy
    }

    /// Access the mutable key hierarchy.
    pub fn key_hierarchy_mut(&mut self) -> &mut KeyHierarchy {
        &mut self.key_hierarchy
    }

    /// Access the sync service.
    pub fn sync_service(&self) -> &SyncService {
        &self.sync_service
    }

    /// Access the storage.
    pub fn storage(&self) -> &Arc<dyn SyncStorage> {
        &self.storage
    }

    /// Access the secure store.
    pub fn secure_store(&self) -> &Arc<dyn SecureStore> {
        &self.secure_store
    }

    /// Access the current runtime epoch, if set.
    pub fn epoch(&self) -> Option<i32> {
        self.epoch
    }

    /// Access the ML-DSA signing key, if derived.
    pub fn ml_dsa_signing_key(&self) -> Option<&prism_sync_crypto::DevicePqSigningKey> {
        self.device_ml_dsa_signing_key.as_ref()
    }

    /// Access the ML-DSA key generation, if set.
    pub fn ml_dsa_key_generation(&self) -> Option<u32> {
        self.ml_dsa_key_generation
    }

    /// Re-derive the ML-DSA signing key after a local rotation.
    pub fn refresh_ml_dsa_key(&mut self, new_generation: u32) -> Result<()> {
        // Enforce monotonicity: generation must increase
        if let Some(current) = self.ml_dsa_key_generation {
            if new_generation <= current {
                return Err(CoreError::Engine(format!(
                    "ML-DSA generation must increase: current={current}, requested={new_generation}"
                )));
            }
        }
        let device_secret = self.device_secret.as_ref().ok_or_else(|| {
            CoreError::Engine("device_secret not set — call initialize first".into())
        })?;
        let device_id = self.device_id.as_ref().ok_or_else(|| {
            CoreError::Engine("device_id not set — call configure_engine first".into())
        })?;
        let pq_sk = device_secret
            .ml_dsa_65_keypair_v(device_id, new_generation)
            .map_err(CoreError::Crypto)?;
        self.device_ml_dsa_signing_key = Some(pq_sk);
        self.ml_dsa_key_generation = Some(new_generation);
        Ok(())
    }

    /// Access the configured relay URL, if any.
    pub fn relay_url(&self) -> Option<&str> {
        self.relay_url.as_deref()
    }

    /// Access the device ID set by [`configure_engine`](Self::configure_engine), if any.
    pub fn device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }

    /// Access the device secret, if initialized.
    pub fn device_secret(&self) -> Option<&DeviceSecret> {
        self.device_secret.as_ref()
    }
}

fn validate_sync_value_type(
    table: &str,
    field: &str,
    expected: SyncType,
    value: &SyncValue,
) -> Result<()> {
    if let SyncValue::Real(value) = value {
        if !value.is_finite() {
            return Err(CoreError::Schema(format!(
                "field '{table}.{field}' received non-finite Real value"
            )));
        }
    }

    if value.is_null() {
        return Ok(());
    }

    let matches = match (expected, value) {
        (SyncType::String, SyncValue::String(_)) => true,
        (SyncType::Int, SyncValue::Int(_)) => true,
        (SyncType::Real, SyncValue::Real(_)) => true,
        (SyncType::Real, SyncValue::Int(_)) => true,
        (SyncType::Bool, SyncValue::Bool(_)) => true,
        (SyncType::DateTime, SyncValue::DateTime(_)) => true,
        (SyncType::Blob, SyncValue::Blob(_)) => true,
        _ => false,
    };

    if matches {
        Ok(())
    } else {
        Err(CoreError::Schema(format!(
            "field '{table}.{field}' expects {expected:?}, got {}",
            sync_value_type_name(value)
        )))
    }
}

fn sync_value_type_name(value: &SyncValue) -> &'static str {
    match value {
        SyncValue::Null => "Null",
        SyncValue::String(_) => "String",
        SyncValue::Int(_) => "Int",
        SyncValue::Real(_) => "Real",
        SyncValue::Bool(_) => "Bool",
        SyncValue::DateTime(_) => "DateTime",
        SyncValue::Blob(_) => "Blob",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::op_emitter::DELETED_FIELD;
    use crate::pairing::{compute_epoch_key_hash, RegistrySnapshotEntry, SignedRegistrySnapshot};
    use crate::relay::traits::*;
    use crate::schema::SyncType;
    use crate::secure_store::SecureStore;
    use crate::storage::{DeviceRecord, RusqliteSyncStorage};
    use async_trait::async_trait;
    use futures_util::Stream;
    use std::collections::HashMap;
    use std::pin::Pin;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemStore(Mutex<HashMap<String, Vec<u8>>>);

    impl SecureStore for MemStore {
        fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.0.lock().unwrap().get(key).cloned())
        }
        fn set(&self, key: &str, value: &[u8]) -> Result<()> {
            self.0.lock().unwrap().insert(key.to_string(), value.to_vec());
            Ok(())
        }
        fn delete(&self, key: &str) -> Result<()> {
            self.0.lock().unwrap().remove(key);
            Ok(())
        }
        fn clear(&self) -> Result<()> {
            self.0.lock().unwrap().clear();
            Ok(())
        }
    }

    struct NoopRelay;

    #[async_trait]
    impl SyncTransport for NoopRelay {
        async fn pull_changes(&self, _: i64) -> std::result::Result<PullResponse, RelayError> {
            unimplemented!()
        }
        async fn push_changes(&self, _: OutgoingBatch) -> std::result::Result<i64, RelayError> {
            unimplemented!()
        }
        async fn ack(&self, _: i64) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl DeviceRegistry for NoopRelay {
        async fn get_registration_nonce(
            &self,
        ) -> std::result::Result<crate::relay::traits::RegistrationNonceResponse, RelayError>
        {
            Ok(crate::relay::traits::RegistrationNonceResponse {
                nonce: "nonce".to_string(),
                pow_challenge: None,
                min_signature_version: None,
            })
        }
        async fn register_device(
            &self,
            _: RegisterRequest,
        ) -> std::result::Result<RegisterResponse, RelayError> {
            unimplemented!()
        }
        async fn list_devices(&self) -> std::result::Result<Vec<DeviceInfo>, RelayError> {
            unimplemented!()
        }
        async fn revoke_device(
            &self,
            _: &str,
            _: bool,
            _: i32,
            _: HashMap<String, Vec<u8>>,
        ) -> std::result::Result<i32, RelayError> {
            unimplemented!()
        }
        async fn deregister(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn rotate_ml_dsa(
            &self,
            _: &str,
            _: &[u8],
            _: u32,
            _: &prism_sync_crypto::pq::continuity_proof::MlDsaContinuityProof,
            _: Option<&[u8]>,
        ) -> std::result::Result<RotateMlDsaResponse, RelayError> {
            unimplemented!()
        }
        async fn get_signed_registry(
            &self,
        ) -> std::result::Result<Option<SignedRegistryResponse>, RelayError> {
            Ok(None)
        }
    }

    #[async_trait]
    impl EpochManagement for NoopRelay {
        async fn post_rekey_artifacts(
            &self,
            _: i32,
            _: HashMap<String, Vec<u8>>,
        ) -> std::result::Result<i32, RelayError> {
            unimplemented!()
        }
        async fn get_rekey_artifact(
            &self,
            _: i32,
            _: &str,
        ) -> std::result::Result<Option<Vec<u8>>, RelayError> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl SnapshotExchange for NoopRelay {
        async fn get_snapshot(&self) -> std::result::Result<Option<SnapshotResponse>, RelayError> {
            unimplemented!()
        }
        async fn put_snapshot(
            &self,
            _: i32,
            _: i64,
            _: Vec<u8>,
            _: Option<u64>,
            _: Option<String>,
            _: String,
            _: Option<SnapshotUploadProgress>,
        ) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn delete_snapshot(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl MediaRelay for NoopRelay {
        async fn upload_media(
            &self,
            _: &str,
            _: &str,
            _: Vec<u8>,
        ) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn download_media(&self, _: &str) -> std::result::Result<Vec<u8>, RelayError> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl SyncRelay for NoopRelay {
        async fn delete_sync_group(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn connect_websocket(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn disconnect_websocket(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        fn notifications(&self) -> Pin<Box<dyn Stream<Item = SyncNotification> + Send>> {
            unimplemented!()
        }
        async fn dispose(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
    }

    #[derive(Clone, Copy)]
    enum RevokeBehavior {
        Success,
        CommitThenTimeout,
        TimeoutBeforeCommit,
    }

    struct RevokeTestRelayState {
        devices: Vec<DeviceInfo>,
        artifacts: HashMap<(i32, String), Vec<u8>>,
        signed_registry: Option<SignedRegistryResponse>,
        behavior: RevokeBehavior,
        revoke_calls: u32,
    }

    struct RevokeTestRelay {
        state: Mutex<RevokeTestRelayState>,
    }

    impl RevokeTestRelay {
        fn new(devices: Vec<DeviceInfo>, behavior: RevokeBehavior) -> Self {
            Self {
                state: Mutex::new(RevokeTestRelayState {
                    devices,
                    artifacts: HashMap::new(),
                    signed_registry: None,
                    behavior,
                    revoke_calls: 0,
                }),
            }
        }

        fn revoke_calls(&self) -> u32 {
            self.state.lock().unwrap().revoke_calls
        }

        fn insert_artifact(&self, epoch: i32, device_id: &str, artifact: Vec<u8>) {
            self.state.lock().unwrap().artifacts.insert((epoch, device_id.to_string()), artifact);
        }

        fn set_signed_registry(&self, signed_registry: SignedRegistryResponse) {
            self.state.lock().unwrap().signed_registry = Some(signed_registry);
        }

        fn commit_revoke(
            state: &mut RevokeTestRelayState,
            target_device_id: &str,
            new_epoch: i32,
            wrapped_keys: HashMap<String, Vec<u8>>,
        ) {
            for device in &mut state.devices {
                if device.device_id == target_device_id {
                    device.status = "revoked".to_string();
                    continue;
                }
                if device.status == "active" {
                    device.epoch = new_epoch;
                }
            }

            for (device_id, artifact) in wrapped_keys {
                state.artifacts.insert((new_epoch, device_id), artifact);
            }
        }
    }

    #[async_trait]
    impl SyncTransport for RevokeTestRelay {
        async fn pull_changes(&self, _: i64) -> std::result::Result<PullResponse, RelayError> {
            unimplemented!()
        }
        async fn push_changes(&self, _: OutgoingBatch) -> std::result::Result<i64, RelayError> {
            unimplemented!()
        }
        async fn ack(&self, _: i64) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl DeviceRegistry for RevokeTestRelay {
        async fn get_registration_nonce(
            &self,
        ) -> std::result::Result<crate::relay::traits::RegistrationNonceResponse, RelayError>
        {
            Ok(crate::relay::traits::RegistrationNonceResponse {
                nonce: "nonce".to_string(),
                pow_challenge: None,
                min_signature_version: None,
            })
        }

        async fn register_device(
            &self,
            _: RegisterRequest,
        ) -> std::result::Result<RegisterResponse, RelayError> {
            unimplemented!()
        }

        async fn list_devices(&self) -> std::result::Result<Vec<DeviceInfo>, RelayError> {
            Ok(self.state.lock().unwrap().devices.clone())
        }

        async fn revoke_device(
            &self,
            device_id: &str,
            _: bool,
            new_epoch: i32,
            wrapped_keys: HashMap<String, Vec<u8>>,
        ) -> std::result::Result<i32, RelayError> {
            let mut state = self.state.lock().unwrap();
            state.revoke_calls += 1;

            match state.behavior {
                RevokeBehavior::Success => {
                    Self::commit_revoke(&mut state, device_id, new_epoch, wrapped_keys);
                    Ok(new_epoch)
                }
                RevokeBehavior::CommitThenTimeout => {
                    Self::commit_revoke(&mut state, device_id, new_epoch, wrapped_keys);
                    Err(RelayError::Timeout { message: "response lost after commit".to_string() })
                }
                RevokeBehavior::TimeoutBeforeCommit => Err(RelayError::Timeout {
                    message: "request timed out before commit".to_string(),
                }),
            }
        }

        async fn deregister(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }

        async fn rotate_ml_dsa(
            &self,
            _: &str,
            _: &[u8],
            _: u32,
            _: &prism_sync_crypto::pq::continuity_proof::MlDsaContinuityProof,
            _: Option<&[u8]>,
        ) -> std::result::Result<RotateMlDsaResponse, RelayError> {
            unimplemented!()
        }

        async fn get_signed_registry(
            &self,
        ) -> std::result::Result<Option<SignedRegistryResponse>, RelayError> {
            Ok(self.state.lock().unwrap().signed_registry.clone())
        }
    }

    #[async_trait]
    impl EpochManagement for RevokeTestRelay {
        async fn post_rekey_artifacts(
            &self,
            _: i32,
            _: HashMap<String, Vec<u8>>,
        ) -> std::result::Result<i32, RelayError> {
            unimplemented!()
        }

        async fn get_rekey_artifact(
            &self,
            epoch: i32,
            device_id: &str,
        ) -> std::result::Result<Option<Vec<u8>>, RelayError> {
            Ok(self.state.lock().unwrap().artifacts.get(&(epoch, device_id.to_string())).cloned())
        }
    }

    #[async_trait]
    impl SnapshotExchange for RevokeTestRelay {
        async fn get_snapshot(&self) -> std::result::Result<Option<SnapshotResponse>, RelayError> {
            unimplemented!()
        }

        async fn put_snapshot(
            &self,
            _: i32,
            _: i64,
            _: Vec<u8>,
            _: Option<u64>,
            _: Option<String>,
            _: String,
            _: Option<SnapshotUploadProgress>,
        ) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }

        async fn delete_snapshot(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl MediaRelay for RevokeTestRelay {
        async fn upload_media(
            &self,
            _: &str,
            _: &str,
            _: Vec<u8>,
        ) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }

        async fn download_media(&self, _: &str) -> std::result::Result<Vec<u8>, RelayError> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl SyncRelay for RevokeTestRelay {
        async fn delete_sync_group(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }

        async fn connect_websocket(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }

        async fn disconnect_websocket(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }

        fn notifications(&self) -> Pin<Box<dyn Stream<Item = SyncNotification> + Send>> {
            unimplemented!()
        }

        async fn dispose(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
    }

    fn make_device_info(
        device_id: &str,
        secret: &DeviceSecret,
        epoch: i32,
        status: &str,
    ) -> DeviceInfo {
        DeviceInfo {
            device_id: device_id.to_string(),
            epoch,
            status: status.to_string(),
            ed25519_public_key: secret
                .ed25519_keypair(device_id)
                .unwrap()
                .public_key_bytes()
                .to_vec(),
            x25519_public_key: secret
                .x25519_keypair(device_id)
                .unwrap()
                .public_key_bytes()
                .to_vec(),
            ml_dsa_65_public_key: secret.ml_dsa_65_keypair(device_id).unwrap().public_key_bytes(),
            ml_kem_768_public_key: secret.ml_kem_768_keypair(device_id).unwrap().public_key_bytes(),
            x_wing_public_key: secret.xwing_keypair(device_id).unwrap().encapsulation_key_bytes(),
            permission: None,
            ml_dsa_key_generation: 0,
        }
    }

    fn make_device_record(sync_id: &str, info: &DeviceInfo) -> DeviceRecord {
        let now = chrono::Utc::now();
        DeviceRecord {
            sync_id: sync_id.to_string(),
            device_id: info.device_id.clone(),
            ed25519_public_key: info.ed25519_public_key.clone(),
            x25519_public_key: info.x25519_public_key.clone(),
            ml_dsa_65_public_key: info.ml_dsa_65_public_key.clone(),
            ml_kem_768_public_key: info.ml_kem_768_public_key.clone(),
            x_wing_public_key: info.x_wing_public_key.clone(),
            status: info.status.clone(),
            registered_at: now,
            revoked_at: None,
            ml_dsa_key_generation: info.ml_dsa_key_generation,
        }
    }

    fn make_registry_entry(sync_id: &str, info: &DeviceInfo) -> RegistrySnapshotEntry {
        RegistrySnapshotEntry {
            sync_id: sync_id.to_string(),
            device_id: info.device_id.clone(),
            ed25519_public_key: info.ed25519_public_key.clone(),
            x25519_public_key: info.x25519_public_key.clone(),
            ml_dsa_65_public_key: info.ml_dsa_65_public_key.clone(),
            ml_kem_768_public_key: info.ml_kem_768_public_key.clone(),
            x_wing_public_key: info.x_wing_public_key.clone(),
            status: info.status.clone(),
            ml_dsa_key_generation: info.ml_dsa_key_generation,
        }
    }

    fn build_v2_artifact(
        receiver_xwing: &prism_sync_crypto::DeviceXWingKey,
        epoch_key: &[u8],
        epoch: u32,
        device_id: &str,
    ) -> Vec<u8> {
        use prism_sync_crypto::pq::hybrid_kem::XWingKem;

        let ek_bytes = receiver_xwing.encapsulation_key_bytes();
        let ek = XWingKem::encapsulation_key_from_bytes(&ek_bytes).unwrap();
        let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
        let (ciphertext, shared_secret_raw) = XWingKem::encapsulate(&ek, &mut rng);
        let shared_secret = zeroize::Zeroizing::new(shared_secret_raw);

        let mut salt = Vec::with_capacity(4 + device_id.len());
        salt.extend_from_slice(&epoch.to_le_bytes());
        salt.extend_from_slice(device_id.as_bytes());
        let wrap_key =
            prism_sync_crypto::kdf::derive_subkey(&shared_secret, &salt, b"prism_epoch_rekey_v2")
                .unwrap();
        let encrypted_epoch_key =
            prism_sync_crypto::aead::xchacha_encrypt(&wrap_key, epoch_key).unwrap();

        let mut artifact = Vec::with_capacity(1 + ciphertext.len() + encrypted_epoch_key.len());
        artifact.push(0x02);
        artifact.extend_from_slice(&ciphertext);
        artifact.extend_from_slice(&encrypted_epoch_key);
        artifact
    }

    fn signed_registry_response(
        sync_id: &str,
        signer_secret: &DeviceSecret,
        signer_device_id: &str,
        device_info: &DeviceInfo,
        current_epoch: u32,
        epoch_keys: &[(u32, [u8; 32])],
    ) -> SignedRegistryResponse {
        let signing_key = signer_secret.ed25519_keypair(signer_device_id).unwrap();
        let pq_signing_key = signer_secret.ml_dsa_65_keypair(signer_device_id).unwrap();
        let epoch_key_hashes =
            epoch_keys.iter().map(|(epoch, key)| (*epoch, compute_epoch_key_hash(key))).collect();
        let snapshot = SignedRegistrySnapshot::new_with_epoch_binding(
            vec![make_registry_entry(sync_id, device_info)],
            SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
            current_epoch,
            epoch_key_hashes,
        );
        SignedRegistryResponse {
            registry_version: SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
            artifact_blob: snapshot.sign_hybrid(&signing_key, &pq_signing_key),
            artifact_kind: "signed_registry_snapshot".to_string(),
        }
    }

    fn make_sync() -> PrismSync {
        let schema = SyncSchema::builder()
            .entity("members", |e| {
                e.field("name", SyncType::String)
                    .field("age", SyncType::Int)
                    .field("active", SyncType::Bool)
                    .field("score", SyncType::Real)
            })
            .build();
        let storage = RusqliteSyncStorage::in_memory().expect("in-memory storage");
        let secure_store = Arc::new(MemStore::default());

        PrismSync::builder()
            .schema(schema)
            .storage(Arc::new(storage))
            .secure_store(secure_store)
            .build()
            .expect("build should succeed")
    }

    fn configure(sync: &mut PrismSync) {
        sync.configure_engine(
            Arc::new(NoopRelay),
            "sync-1".to_string(),
            "a1b2c3d4e5f6".to_string(),
            1,
            0, // ml_dsa_key_generation
        );
    }

    fn prepare_verified_epoch_catch_up(
        include_epoch_2_artifact: bool,
    ) -> (PrismSync, Arc<RevokeTestRelay>, String, [u8; 32], [u8; 32]) {
        let mut sync = make_sync();
        sync.initialize("test-password", &[1u8; 16]).unwrap();

        let sync_id = "sync-1";
        let self_device_id = "a1b2c3d4e5f6";
        let device_secret =
            DeviceSecret::from_bytes(sync.device_secret().unwrap().as_bytes().to_vec()).unwrap();
        let device_info = make_device_info(self_device_id, &device_secret, 2, "active");
        DeviceRegistryManager::pin_device(
            sync.storage().as_ref(),
            sync_id,
            &make_device_record(sync_id, &device_info),
        )
        .unwrap();

        let epoch_0_key: [u8; 32] = sync.key_hierarchy().epoch_key(0).unwrap().try_into().unwrap();
        let epoch_1_key = [0x11u8; 32];
        let epoch_2_key = [0x22u8; 32];
        let xwing_key = device_secret.xwing_keypair(self_device_id).unwrap();

        let relay =
            Arc::new(RevokeTestRelay::new(vec![device_info.clone()], RevokeBehavior::Success));
        relay.insert_artifact(
            1,
            self_device_id,
            build_v2_artifact(&xwing_key, &epoch_1_key, 1, self_device_id),
        );
        if include_epoch_2_artifact {
            relay.insert_artifact(
                2,
                self_device_id,
                build_v2_artifact(&xwing_key, &epoch_2_key, 2, self_device_id),
            );
        }
        relay.set_signed_registry(signed_registry_response(
            sync_id,
            &device_secret,
            self_device_id,
            &device_info,
            2,
            &[(0, epoch_0_key), (1, epoch_1_key), (2, epoch_2_key)],
        ));

        sync.configure_engine(relay.clone(), sync_id.to_string(), self_device_id.to_string(), 0, 0);

        (sync, relay, self_device_id.to_string(), epoch_1_key, epoch_2_key)
    }

    #[tokio::test]
    async fn sync_preflight_catches_up_epoch_keys_from_verified_registry() {
        let (mut sync, _relay, _device_id, epoch_1_key, epoch_2_key) =
            prepare_verified_epoch_catch_up(true);

        sync.catch_up_epoch_keys().await.unwrap();

        assert_eq!(sync.epoch(), Some(2));
        assert_eq!(sync.key_hierarchy().epoch_key(1).unwrap(), &epoch_1_key);
        assert_eq!(sync.key_hierarchy().epoch_key(2).unwrap(), &epoch_2_key);
        assert!(sync.secure_store().get("epoch_key_1").unwrap().is_some());
        assert!(sync.secure_store().get("epoch_key_2").unwrap().is_some());
        assert_eq!(sync.storage().get_sync_metadata("sync-1").unwrap().unwrap().current_epoch, 2);
    }

    #[tokio::test]
    async fn sync_preflight_advances_only_verified_prefix_when_artifact_missing() {
        let (mut sync, _relay, _device_id, epoch_1_key, _epoch_2_key) =
            prepare_verified_epoch_catch_up(false);

        sync.catch_up_epoch_keys().await.unwrap();

        assert_eq!(sync.epoch(), Some(1));
        assert_eq!(sync.key_hierarchy().epoch_key(1).unwrap(), &epoch_1_key);
        assert!(!sync.key_hierarchy().has_epoch_key(2));
        assert!(sync.secure_store().get("epoch_key_1").unwrap().is_some());
        assert!(sync.secure_store().get("epoch_key_2").unwrap().is_none());
        assert_eq!(sync.secure_store().get("epoch").unwrap().unwrap().as_slice(), b"1");
        assert_eq!(sync.storage().get_sync_metadata("sync-1").unwrap().unwrap().current_epoch, 1);
    }

    #[test]
    fn configure_engine_sets_engine() {
        let mut sync = make_sync();
        assert!(!sync.sync_service.has_engine());
        configure(&mut sync);
        assert!(sync.sync_service.has_engine());
    }

    /// Regression guard for the HLC-init bug: if `field_versions` contains a
    /// pre-existing row (e.g. from a snapshot import or a prior
    /// `bootstrap_existing_state`), `configure_engine` must seed the live
    /// `OpEmitter`'s `last_hlc` from the max across those rows. Otherwise the
    /// first local mutation stamps a smaller HLC and loses the CRDT
    /// tiebreaker against remote state.
    #[test]
    fn configure_engine_seeds_hlc_from_existing_field_versions() {
        use crate::hlc::Hlc;
        use crate::storage::FieldVersion;

        let schema = SyncSchema::builder()
            .entity("members", |e| e.field("name", SyncType::String))
            .build();
        let storage = RusqliteSyncStorage::in_memory().expect("in-memory storage");

        // Pre-populate field_versions with a high-counter HLC to make the
        // :9/:10 ordering bug easy to catch.
        let pre_hlc = "1234567890:99:preseeddev001";
        {
            use crate::storage::SyncStorage;
            let mut tx = storage.begin_tx().unwrap();
            tx.upsert_field_version(&FieldVersion {
                sync_id: "sync-1".to_string(),
                entity_table: "members".to_string(),
                entity_id: "pre-1".to_string(),
                field_name: "name".to_string(),
                winning_op_id: "op-pre".to_string(),
                winning_device_id: "preseeddev001".to_string(),
                winning_hlc: pre_hlc.to_string(),
                winning_encoded_value: Some("\"Pre\"".to_string()),
                updated_at: chrono::Utc::now(),
            })
            .unwrap();
            tx.commit().unwrap();
        }

        let secure_store = Arc::new(MemStore::default());
        let mut sync = PrismSync::builder()
            .schema(schema)
            .storage(Arc::new(storage))
            .secure_store(secure_store)
            .build()
            .expect("build should succeed");

        configure(&mut sync);

        let pre_parsed = Hlc::from_string(pre_hlc).unwrap();
        let emitter_hlc = sync.op_emitter.as_ref().expect("emitter").last_hlc().clone();
        assert!(
            emitter_hlc >= pre_parsed,
            "emitter HLC {emitter_hlc:?} must be >= pre-seeded HLC {pre_parsed:?}"
        );

        // A subsequent record_create must mint an HLC strictly greater than
        // the pre-existing one.
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), SyncValue::String("Post".to_string()));
        sync.record_create("members", "post-1", &fields).unwrap();
        let fv = sync
            .storage
            .get_field_version("sync-1", "members", "post-1", "name")
            .unwrap()
            .unwrap();
        let post_hlc = Hlc::from_string(&fv.winning_hlc).unwrap();
        assert!(
            post_hlc > pre_parsed,
            "post-configure HLC {post_hlc:?} must exceed pre-seeded HLC {pre_parsed:?}"
        );
    }

    #[test]
    fn record_create_populates_pending_ops() {
        let mut sync = make_sync();
        configure(&mut sync);

        let mut fields = HashMap::new();
        fields.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        fields.insert("age".to_string(), SyncValue::Int(25));
        fields.insert("active".to_string(), SyncValue::Bool(true));

        sync.record_create("members", "ent-1", &fields).unwrap();

        let batch_ids = sync.storage.get_unpushed_batch_ids("sync-1").unwrap();
        assert_eq!(batch_ids.len(), 1);

        let ops = sync.storage.load_batch_ops(&batch_ids[0]).unwrap();
        assert_eq!(ops.len(), 3);

        let field_names: Vec<&str> = ops.iter().map(|o| o.field_name.as_str()).collect();
        assert!(field_names.contains(&"name"));
        assert!(field_names.contains(&"age"));
        assert!(field_names.contains(&"active"));
    }

    #[test]
    fn record_update_only_stores_changed_fields() {
        let mut sync = make_sync();
        configure(&mut sync);

        // First create the entity
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        fields.insert("age".to_string(), SyncValue::Int(25));
        sync.record_create("members", "ent-1", &fields).unwrap();

        // Now update only one field
        let mut changed = HashMap::new();
        changed.insert("name".to_string(), SyncValue::String("Bob".to_string()));
        sync.record_update("members", "ent-1", &changed).unwrap();

        let batch_ids = sync.storage.get_unpushed_batch_ids("sync-1").unwrap();
        assert_eq!(batch_ids.len(), 2); // create + update

        // The second batch should have exactly 1 op
        let update_ops = sync.storage.load_batch_ops(&batch_ids[1]).unwrap();
        assert_eq!(update_ops.len(), 1);
        assert_eq!(update_ops[0].field_name, "name");
    }

    #[test]
    fn record_create_rejects_real_for_int_field() {
        let mut sync = make_sync();
        configure(&mut sync);

        let mut fields = HashMap::new();
        fields.insert("age".to_string(), SyncValue::Real(25.5));

        let err = sync.record_create("members", "ent-1", &fields).unwrap_err();
        assert!(err.to_string().contains("expects Int, got Real"), "unexpected error: {err}");
        assert!(sync.storage.get_unpushed_batch_ids("sync-1").unwrap().is_empty());
    }

    #[test]
    fn record_create_allows_int_for_real_field() {
        let mut sync = make_sync();
        configure(&mut sync);

        let mut fields = HashMap::new();
        fields.insert("score".to_string(), SyncValue::Int(8));

        sync.record_create("members", "ent-1", &fields).unwrap();

        let batch_ids = sync.storage.get_unpushed_batch_ids("sync-1").unwrap();
        let ops = sync.storage.load_batch_ops(&batch_ids[0]).unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].field_name, "score");
        assert_eq!(ops[0].encoded_value, "8");
    }

    #[test]
    fn record_create_rejects_non_finite_real() {
        let mut sync = make_sync();
        configure(&mut sync);

        let mut fields = HashMap::new();
        fields.insert("score".to_string(), SyncValue::Real(f64::NAN));

        let err = sync.record_create("members", "ent-1", &fields).unwrap_err();
        assert!(err.to_string().contains("non-finite Real"), "unexpected error: {err}");
        assert!(sync.storage.get_unpushed_batch_ids("sync-1").unwrap().is_empty());
    }

    #[test]
    fn record_update_rejects_unknown_field() {
        let mut sync = make_sync();
        configure(&mut sync);

        let mut changed = HashMap::new();
        changed.insert("unknown".to_string(), SyncValue::String("value".to_string()));

        let err = sync.record_update("members", "ent-1", &changed).unwrap_err();
        assert!(
            err.to_string().contains("unknown field: members.unknown"),
            "unexpected error: {err}"
        );
        assert!(sync.storage.get_unpushed_batch_ids("sync-1").unwrap().is_empty());
    }

    #[test]
    fn record_delete_creates_tombstone_op() {
        let mut sync = make_sync();
        configure(&mut sync);

        sync.record_delete("members", "ent-1").unwrap();

        let batch_ids = sync.storage.get_unpushed_batch_ids("sync-1").unwrap();
        assert_eq!(batch_ids.len(), 1);

        let ops = sync.storage.load_batch_ops(&batch_ids[0]).unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].field_name, DELETED_FIELD);
        assert_eq!(ops[0].encoded_value, "true");
        assert!(ops[0].is_delete);
    }

    #[test]
    fn mutation_without_configure_returns_error() {
        let mut sync = make_sync();

        let fields = HashMap::new();
        let err = sync.record_create("members", "ent-1", &fields);
        assert!(err.is_err());
        assert!(
            err.unwrap_err().to_string().contains("sync not configured"),
            "expected 'sync not configured' error"
        );
    }

    #[test]
    fn configure_engine_derives_ml_dsa_key() {
        let mut sync = make_sync();

        // Initialize with a password so a DeviceSecret is generated
        sync.initialize("test-password", &[1u8; 16]).unwrap();

        // Configure engine with ML-DSA generation 1
        sync.configure_engine(
            Arc::new(NoopRelay),
            "sync-1".to_string(),
            "a1b2c3d4e5f6".to_string(),
            1,
            1, // ml_dsa_key_generation
        );

        // Verify ML-DSA signing key was derived
        assert!(
            sync.ml_dsa_signing_key().is_some(),
            "ML-DSA signing key should be derived after configure_engine"
        );
        assert_eq!(sync.ml_dsa_key_generation(), Some(1), "ML-DSA key generation should be 1");

        // Test refresh to generation 2
        sync.refresh_ml_dsa_key(2).unwrap();
        assert_eq!(
            sync.ml_dsa_key_generation(),
            Some(2),
            "ML-DSA key generation should be updated to 2 after refresh"
        );
    }

    #[test]
    fn local_storage_key_fails_without_device_secret() {
        let mut sync = make_sync();
        // Unlock the key hierarchy without setting a device secret by using restore_from_dek
        sync.key_hierarchy_mut().restore_from_dek(&[0u8; 32]).unwrap();
        // device_secret is still None — local_storage_key should return an error about it
        let result = sync.local_storage_key();
        assert!(result.is_err(), "local_storage_key should fail without device secret");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("device secret"), "error should mention device secret, got: {msg}");
    }

    #[test]
    fn local_storage_key_succeeds_after_initialize() {
        let mut sync = make_sync();
        sync.initialize("test-password", &[1u8; 16]).unwrap();
        let result = sync.local_storage_key();
        assert!(
            result.is_ok(),
            "local_storage_key should succeed after initialize: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn rekey_db_delegates_to_storage() {
        let mut sync = make_sync();
        sync.initialize("test-password", &[1u8; 16]).unwrap();
        // In-memory storage — rekey is a no-op and should succeed
        let new_key = [0xaau8; 32];
        let result = sync.rekey_db(&new_key);
        assert!(result.is_ok(), "rekey_db should succeed on in-memory storage: {:?}", result.err());
    }

    #[tokio::test]
    async fn revoke_and_rekey_reconciles_ambiguous_failure_after_remote_commit() {
        let mut sync = make_sync();
        sync.initialize("test-password", &[1u8; 16]).unwrap();

        let self_device_id = "a1b2c3d4e5f6";
        let target_device_id = "b7c8d9e0f1a2";
        let target_secret = DeviceSecret::generate();
        let relay = Arc::new(RevokeTestRelay::new(
            vec![
                make_device_info(self_device_id, sync.device_secret().unwrap(), 0, "active"),
                make_device_info(target_device_id, &target_secret, 0, "active"),
            ],
            RevokeBehavior::CommitThenTimeout,
        ));

        sync.configure_engine(
            relay.clone(),
            "sync-1".to_string(),
            self_device_id.to_string(),
            0,
            0,
        );

        let committed_epoch =
            sync.revoke_and_rekey(relay.clone(), target_device_id, false).await.unwrap();

        assert_eq!(committed_epoch, 1);
        assert_eq!(relay.revoke_calls(), 1);
        assert_eq!(sync.epoch(), Some(1));
        assert!(sync.key_hierarchy().has_epoch_key(1));
        assert_eq!(sync.storage().get_sync_metadata("sync-1").unwrap().unwrap().current_epoch, 1);
        assert_eq!(
            String::from_utf8(sync.secure_store().get("epoch").unwrap().unwrap()).unwrap(),
            "1"
        );
        assert!(sync.secure_store().get("epoch_key_1").unwrap().is_some());
    }

    #[tokio::test]
    async fn revoke_and_rekey_commits_local_state_on_immediate_success() {
        let mut sync = make_sync();
        sync.initialize("test-password", &[1u8; 16]).unwrap();

        let self_device_id = "a1b2c3d4e5f6";
        let target_device_id = "b7c8d9e0f1a2";
        let target_secret = DeviceSecret::generate();
        let relay = Arc::new(RevokeTestRelay::new(
            vec![
                make_device_info(self_device_id, sync.device_secret().unwrap(), 0, "active"),
                make_device_info(target_device_id, &target_secret, 0, "active"),
            ],
            RevokeBehavior::Success,
        ));

        sync.configure_engine(
            relay.clone(),
            "sync-1".to_string(),
            self_device_id.to_string(),
            0,
            0,
        );

        let committed_epoch =
            sync.revoke_and_rekey(relay.clone(), target_device_id, false).await.unwrap();

        assert_eq!(committed_epoch, 1);
        assert_eq!(relay.revoke_calls(), 1);
        assert_eq!(sync.epoch(), Some(1));
        assert!(sync.key_hierarchy().has_epoch_key(1));
        assert_eq!(sync.storage().get_sync_metadata("sync-1").unwrap().unwrap().current_epoch, 1);
        assert!(sync.secure_store().get("epoch_key_1").unwrap().is_some());
    }

    #[tokio::test]
    async fn revoke_and_rekey_returns_original_error_when_ambiguous_failure_did_not_commit() {
        let mut sync = make_sync();
        sync.initialize("test-password", &[1u8; 16]).unwrap();

        let self_device_id = "a1b2c3d4e5f6";
        let target_device_id = "b7c8d9e0f1a2";
        let target_secret = DeviceSecret::generate();
        let relay = Arc::new(RevokeTestRelay::new(
            vec![
                make_device_info(self_device_id, sync.device_secret().unwrap(), 0, "active"),
                make_device_info(target_device_id, &target_secret, 0, "active"),
            ],
            RevokeBehavior::TimeoutBeforeCommit,
        ));

        sync.configure_engine(
            relay.clone(),
            "sync-1".to_string(),
            self_device_id.to_string(),
            0,
            0,
        );

        let error =
            sync.revoke_and_rekey(relay.clone(), target_device_id, false).await.unwrap_err();

        assert!(error.is_retryable(), "timeout should remain classified as retryable");
        assert_eq!(relay.revoke_calls(), 1);
        assert_eq!(sync.epoch(), Some(0));
        assert!(!sync.key_hierarchy().has_epoch_key(1));
        assert!(sync.storage().get_sync_metadata("sync-1").unwrap().is_none());
        assert!(sync.secure_store().get("epoch").unwrap().is_none());
        assert!(sync.secure_store().get("epoch_key_1").unwrap().is_none());
    }
}
