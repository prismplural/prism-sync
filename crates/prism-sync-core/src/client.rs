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

use crate::engine::{SyncConfig, SyncEngine};
use crate::error::{CoreError, Result};
use crate::events::{event_channel, SyncEvent};
use crate::op_emitter::OpEmitter;
use crate::relay::SyncRelay;
use crate::schema::{SyncSchema, SyncValue};
use crate::secure_store::SecureStore;
use crate::storage::SyncStorage;
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
        let schema = self
            .schema
            .ok_or_else(|| CoreError::Schema("schema is required".into()))?;
        let storage = self
            .storage
            .ok_or_else(|| CoreError::Storage("storage is required".into()))?;
        let secure_store = self
            .secure_store
            .ok_or_else(|| CoreError::Storage("secure_store is required".into()))?;

        // Validate relay URL transport security
        if let Some(ref url) = self.relay_url {
            if !self.allow_insecure && !url.starts_with("https://") && !url.starts_with("wss://") {
                return Err(CoreError::Storage(
                    "relay URL must use HTTPS/WSS (use allow_insecure_transport() for development)"
                        .into(),
                ));
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
        let (wrapped_dek, salt) = self
            .key_hierarchy
            .initialize(password, secret_key)
            .map_err(CoreError::Crypto)?;

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
        let wrapped_dek = self
            .secure_store
            .get("wrapped_dek")?
            .ok_or_else(|| CoreError::Storage("no wrapped DEK found".into()))?;
        let salt = self
            .secure_store
            .get("dek_salt")?
            .ok_or_else(|| CoreError::Storage("no salt found".into()))?;

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
        self.key_hierarchy
            .restore_from_dek(dek_bytes)
            .map_err(CoreError::Crypto)?;

        self.device_secret = Some(
            DeviceSecret::from_bytes(device_secret_bytes.to_vec()).map_err(CoreError::Crypto)?,
        );

        Ok(())
    }

    /// Export the raw DEK bytes for keychain persistence.
    ///
    /// Returns the raw 32-byte DEK. Only works when unlocked.
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

    // ── Sync engine ──

    /// Configure the sync engine with a relay, enabling sync operations.
    ///
    /// Call this after `initialize` or `unlock` and after obtaining a relay
    /// connection. The `node_id` is this device's unique identifier (12-char
    /// hex), and `epoch` is the current sync epoch number.
    ///
    /// If a `DeviceSecret` is available (set by `initialize` or `unlock`),
    /// the device's Ed25519 signing key is derived and stored for use by
    /// `sync_now` and `on_resume`.
    pub fn configure_engine(
        &mut self,
        relay: Arc<dyn SyncRelay>,
        sync_id: String,
        node_id: String,
        epoch: i32,
    ) {
        let engine = SyncEngine::new(
            self.storage.clone(),
            relay,
            self.entities.clone(),
            self.schema.clone(),
            SyncConfig::default(),
        );
        self.op_emitter = Some(OpEmitter::new(
            node_id.clone(),
            sync_id.clone(),
            epoch,
            None,
        ));

        // Derive and store the device signing key if a DeviceSecret is available.
        if let Some(ref device_secret) = self.device_secret {
            if let Ok(dsk) = device_secret.ed25519_keypair(&node_id) {
                self.device_signing_key = Some(dsk.into_signing_key());
            }
        }
        self.device_id = Some(node_id);
        self.epoch = Some(epoch);

        self.sync_service.set_engine(engine, sync_id);
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
        let signing_key = self.device_signing_key.as_ref().ok_or_else(|| {
            CoreError::Engine(
                "sync not configured — call configure_engine after initialize/unlock".into(),
            )
        })?;
        let device_id = self.device_id.as_ref().ok_or_else(|| {
            CoreError::Engine("device_id not set — call configure_engine first".into())
        })?;
        self.sync_service
            .sync_now(&self.key_hierarchy, signing_key, device_id)
            .await
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
        self.sync_service
            .catch_up_if_stale(&self.key_hierarchy, signing_key, device_id)
            .await
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
        self.sync_service
            .upload_pairing_snapshot(
                &self.key_hierarchy,
                epoch,
                device_id,
                signing_key,
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
    pub async fn bootstrap_from_snapshot(
        &mut self,
    ) -> Result<(u64, Vec<crate::events::EntityChange>)> {
        self.sync_service
            .bootstrap_from_snapshot(&self.key_hierarchy)
            .await
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

        // 1. Get current epoch from local metadata
        let storage = self.storage().clone();
        let sid = sync_id.clone();
        let meta = tokio::task::spawn_blocking(move || storage.get_sync_metadata(&sid))
            .await
            .map_err(|e| CoreError::Storage(e.to_string()))??;
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

        let committed_epoch = relay
            .revoke_device(
                target_device_id,
                remote_wipe,
                new_epoch as i32,
                wrapped_keys,
            )
            .await
            .map_err(CoreError::from_relay)? as u32;

        self.key_hierarchy_mut()
            .store_epoch_key(committed_epoch, zeroize::Zeroizing::new(epoch_key.to_vec()));

        // 3. Persist new epoch key to secure store
        if let Ok(epoch_key) = self.key_hierarchy().epoch_key(committed_epoch) {
            use base64::{engine::general_purpose::STANDARD, Engine};
            let encoded = STANDARD.encode(epoch_key);
            self.secure_store()
                .set(&format!("epoch_key_{committed_epoch}"), encoded.as_bytes())
                .map_err(|e| CoreError::Storage(format!("failed to persist epoch key: {e}")))?;
        }
        self.secure_store()
            .set("epoch", committed_epoch.to_string().as_bytes())
            .map_err(|e| CoreError::Storage(format!("failed to persist epoch: {e}")))?;

        // 4. Update local epoch in sync metadata
        let storage = self.storage().clone();
        let sid = sync_id.clone();
        let ne = committed_epoch as i32;
        tokio::task::spawn_blocking(move || {
            let mut tx = storage.begin_tx()?;
            tx.update_current_epoch(&sid, ne)?;
            tx.commit()
        })
        .await
        .map_err(|e| CoreError::Storage(e.to_string()))??;

        // 5. Advance runtime epoch so new mutations use the rotated epoch
        self.advance_epoch(committed_epoch as i32);

        Ok(committed_epoch)
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

        SyncStatus {
            syncing: self.sync_service.has_engine(),
            last_sync,
            pending_ops,
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::op_emitter::DELETED_FIELD;
    use crate::relay::traits::*;
    use crate::schema::SyncType;
    use crate::secure_store::SecureStore;
    use crate::storage::RusqliteSyncStorage;
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
            self.0
                .lock()
                .unwrap()
                .insert(key.to_string(), value.to_vec());
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
    impl SyncRelay for NoopRelay {
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
        async fn pull_changes(&self, _: i64) -> std::result::Result<PullResponse, RelayError> {
            unimplemented!()
        }
        async fn push_changes(&self, _: OutgoingBatch) -> std::result::Result<i64, RelayError> {
            unimplemented!()
        }
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
        ) -> std::result::Result<(), RelayError> {
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
        async fn deregister(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn delete_sync_group(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn ack(&self, _: i64) -> std::result::Result<(), RelayError> {
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
        async fn dispose(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn get_signed_registry(&self) -> std::result::Result<Option<SignedRegistryResponse>, RelayError> {
            Ok(None)
        }
    }

    fn make_sync() -> PrismSync {
        let schema = SyncSchema::builder()
            .entity("members", |e| {
                e.field("name", SyncType::String)
                    .field("age", SyncType::Int)
                    .field("active", SyncType::Bool)
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
        );
    }

    #[test]
    fn configure_engine_sets_engine() {
        let mut sync = make_sync();
        assert!(!sync.sync_service.has_engine());
        configure(&mut sync);
        assert!(sync.sync_service.has_engine());
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
}
