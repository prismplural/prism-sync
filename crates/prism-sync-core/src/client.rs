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

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use tokio::sync::broadcast;

use crate::crdt_change::{estimate_envelope_body_size, CrdtChange};
use crate::device_registry::DeviceRegistryManager;
use crate::engine::{BootstrapReport, SeedRecord, SyncConfig, SyncEngine};
use crate::epoch::EpochManager;
use crate::error::{CoreError, Result};
use crate::events::{event_channel, EntityChange, SyncEvent};
use crate::hlc::Hlc;
use crate::op_emitter::{OpEmitter, DELETED_FIELD};
use crate::pairing::{
    compute_epoch_key_hash, RegistrySnapshotEntry, SignedRegistrySnapshot,
    SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
};
use crate::recovery::{commit_recovered_epoch_material, KeyHierarchyRecoverer};
use crate::relay::SyncRelay;
use crate::schema::{SyncSchema, SyncType, SyncValue};
use crate::secure_store::SecureStore;
use crate::storage::{PendingOp, StorageError, SyncStorage};
use crate::sync_service::{AutoSyncConfig, SyncService};
use crate::syncable_entity::SyncableEntity;
use prism_sync_crypto::{mnemonic, DeviceSecret, KeyHierarchy};

/// Wire-format size in bytes of a single Ed25519 + ML-DSA-65 hybrid signature
/// as produced by `HybridSignature::to_bytes`: a 4-byte LE length, the
/// 64-byte Ed25519 signature, another 4-byte LE length, then the 3309-byte
/// ML-DSA-65 signature.
pub(crate) const HYBRID_SIGNATURE_WIRE_BYTES: usize = 4 + 64 + 4 + 3309;

/// Target serialized body size (in bytes) for a pushed batch envelope.
///
/// The relay's hard `MAX_CHANGESET_SIZE` is 1 MiB (1,048,576 bytes). 950 KB
/// leaves ~100 KB of headroom for the unaccounted envelope variability the
/// estimator does not model (oversized `sync_id`, longer-than-expected
/// device ids, future schema additions) and still accommodates a banner-only
/// batch (~925 KB body) as a single partition.
pub(crate) const BATCH_BODY_TARGET_BYTES: usize = 950 * 1024;

/// Maximum delete tombstones packed into one batch by `record_delete_multi`.
/// The partitioner also enforces a conservative byte bound, so this count is
/// the cap for normal (short) entity ids; long ids hit the byte bound first.
const DELETE_BATCH_OP_CAP: usize = 500;

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

    /// Read-only credential check. Derives the MEK from `password` + `secret_key`
    /// and attempts the wrapped DEK AEAD unwrap. Returns `Ok(true)` on success,
    /// `Ok(false)` on AEAD authentication failure (wrong password or secret key),
    /// and `Err` on infrastructure problems (missing wrapped_dek, missing salt, IO).
    ///
    /// **Does NOT modify engine state**: does not touch `self.key_hierarchy`,
    /// `self.device_secret`, or call `restore_persisted_epoch_keys`. The engine
    /// remains in exactly the same locked/unlocked state it was in before the
    /// call.
    ///
    /// Both `password` and `secret_key` must be valid UTF-8 and raw bytes
    /// respectively. `password` is treated as a UTF-8 string before KDF; if it
    /// is not valid UTF-8, an `Err` is returned.
    pub fn verify_credentials(&self, password: &[u8], secret_key: &[u8]) -> Result<bool> {
        let wrapped_dek = self.secure_store.get("wrapped_dek")?.ok_or_else(|| {
            CoreError::Storage(StorageError::Logic("no wrapped DEK found".into()))
        })?;
        let salt = self
            .secure_store
            .get("dek_salt")?
            .ok_or_else(|| CoreError::Storage(StorageError::Logic("no salt found".into())))?;

        let password_str = std::str::from_utf8(password)
            .map_err(|_| CoreError::Engine("password must be valid UTF-8".into()))?;

        // Attempt the unlock on a fresh, throwaway key hierarchy. This runs
        // Argon2id + AEAD unwrap exactly as `unlock` does, but writes nothing
        // to `self`. The temporary hierarchy and its DEK are zeroized on drop.
        let mut temp = KeyHierarchy::new();
        match temp.unlock(password_str, secret_key, &wrapped_dek, &salt) {
            Ok(()) => Ok(true),
            Err(prism_sync_crypto::CryptoError::DecryptionFailed(_)) => Ok(false),
            Err(e) => Err(CoreError::Crypto(e)),
        }
    }

    /// Restore the unlocked state directly from raw key material.
    ///
    /// Bypasses Argon2id password derivation. Use when the host has recovered
    /// the DEK from a platform-protected runtime cache.
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
    /// The host should wrap this before persistence and feed the unwrapped key
    /// back to `restore_runtime_keys` on relaunch.
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
        let max_hlc = match self.storage.list_all_field_version_hlcs(&sync_id) {
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
        self.refresh_op_emitter_hlc_from_storage("sync_now");
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
        if relay_epoch == local_epoch {
            if let Err(error) = self
                .repair_signed_registry_epoch_if_needed(
                    relay.as_ref(),
                    &sync_id,
                    &device_id,
                    relay_epoch,
                    &devices,
                )
                .await
            {
                tracing::warn!(
                    error = %error,
                    relay_epoch,
                    local_epoch,
                    "catch_up_epoch_keys: signed registry epoch repair failed"
                );
            }
        }
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

    async fn repair_signed_registry_epoch_if_needed(
        &self,
        relay: &dyn SyncRelay,
        sync_id: &str,
        device_id: &str,
        target_epoch: u32,
        devices: &[crate::relay::traits::DeviceInfo],
    ) -> Result<()> {
        if !self.key_hierarchy.has_epoch_key(target_epoch) {
            return Ok(());
        }

        let device_secret = self.device_secret.as_ref().ok_or_else(|| {
            CoreError::Engine("device secret not set — call configure_engine first".into())
        })?;
        let signing_key = device_secret.ed25519_keypair(device_id).map_err(CoreError::Crypto)?;
        let pq_signing_key = self.device_ml_dsa_signing_key.as_ref().ok_or_else(|| {
            CoreError::Engine("ML-DSA signing key not set — call configure_engine first".into())
        })?;

        let registry_version = match relay.get_signed_registry().await {
            Ok(Some(response)) => {
                let current_snapshot = DeviceRegistryManager::verify_signed_registry_snapshot(
                    self.storage.as_ref(),
                    sync_id,
                    &response.artifact_blob,
                )
                .map_err(|e| {
                    CoreError::Engine(format!(
                        "signed registry verification failed before epoch repair: {e}"
                    ))
                })?;
                if current_snapshot.current_epoch >= target_epoch {
                    return Ok(());
                }
                (current_snapshot.registry_version + 1)
                    .max(SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING)
            }
            Ok(None) => SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
            Err(error) => return Err(CoreError::from_relay(error)),
        };

        let epoch_key_hashes = Self::build_epoch_key_hashes_for_registry(&self.key_hierarchy)?;
        if !epoch_key_hashes.contains_key(&target_epoch) {
            return Ok(());
        }

        let entries: Vec<RegistrySnapshotEntry> = devices
            .iter()
            .filter(|device| device.status == "active")
            .map(|device| RegistrySnapshotEntry {
                sync_id: sync_id.to_string(),
                device_id: device.device_id.clone(),
                ed25519_public_key: device.ed25519_public_key.clone(),
                x25519_public_key: device.x25519_public_key.clone(),
                ml_dsa_65_public_key: device.ml_dsa_65_public_key.clone(),
                ml_kem_768_public_key: device.ml_kem_768_public_key.clone(),
                x_wing_public_key: device.x_wing_public_key.clone(),
                status: device.status.clone(),
                ml_dsa_key_generation: device.ml_dsa_key_generation,
            })
            .collect();

        if !entries.iter().any(|entry| entry.device_id == device_id) {
            return Err(CoreError::Engine(
                "cannot repair signed registry: current device missing from active relay list"
                    .into(),
            ));
        }

        let snapshot = SignedRegistrySnapshot::new_with_epoch_binding(
            entries,
            registry_version,
            target_epoch,
            epoch_key_hashes,
        );
        let signed = snapshot.sign_hybrid(&signing_key, pq_signing_key);
        let _ = relay.put_signed_registry(&signed).await.map_err(CoreError::from_relay)?;

        tracing::info!(
            epoch = target_epoch,
            sync_id = %sync_id,
            device_id = %device_id,
            "catch_up_epoch_keys: repaired signed registry epoch binding"
        );

        Ok(())
    }

    fn build_epoch_key_hashes_for_registry(
        key_hierarchy: &KeyHierarchy,
    ) -> Result<BTreeMap<u32, [u8; 32]>> {
        let entries = key_hierarchy.epoch_keys_iter().map_err(CoreError::Crypto)?;
        let mut out = BTreeMap::new();
        for (epoch, key) in entries {
            out.insert(epoch, compute_epoch_key_hash(key));
        }
        Ok(out)
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
        self.refresh_op_emitter_hlc_from_storage("on_resume");
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
        let result = self.sync_service.bootstrap_from_snapshot(&self.key_hierarchy).await;
        self.refresh_op_emitter_hlc_from_storage("bootstrap_from_snapshot");
        result
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

        self.refresh_op_emitter_hlc_from_storage("bootstrap_existing_state");

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
    /// Each field in `fields` becomes a pending op. Large entities (e.g.
    /// members with avatars + banners) are partitioned across multiple
    /// batches so each batch's serialized envelope stays under the relay's
    /// 1 MB cap. All partitions commit in one storage transaction so a
    /// partial failure does not leave a half-written entity in
    /// `pending_ops` / `field_versions`. Returns an error if the sync engine
    /// has not been configured via [`configure_engine`](Self::configure_engine).
    pub fn record_create(
        &mut self,
        table: &str,
        entity_id: &str,
        fields: &HashMap<String, SyncValue>,
    ) -> Result<()> {
        if self.op_emitter.is_none() {
            return Err(CoreError::Engine("sync not configured".into()));
        }
        // Strip a phantom `is_deleted = false` (would resurrect a re-created
        // deleted id; see [`without_phantom_undelete`]).
        let stripped = Self::without_phantom_undelete(fields);
        let fields = stripped.as_ref().unwrap_or(fields);
        self.validate_mutation_fields(table, fields)?;
        let (device_id, epoch) = {
            let emitter = self
                .op_emitter
                .as_ref()
                .ok_or_else(|| CoreError::Engine("sync not configured".into()))?;
            (emitter.last_hlc().node_id.clone(), emitter.epoch())
        };
        let partitions =
            Self::partition_fields_into_batches(fields, table, entity_id, &device_id, epoch);
        let emitter = self
            .op_emitter
            .as_mut()
            .ok_or_else(|| CoreError::Engine("sync not configured".into()))?;
        let result = emitter.emit_create_multi(&*self.storage, table, entity_id, &partitions);
        if result.is_ok() {
            if let Some(tx) = self.sync_service.auto_sync_sender() {
                let _ = tx.try_send(());
            }
        }
        result
    }

    /// Record changed fields on an existing entity for sync.
    ///
    /// Only pass the fields that actually changed. The change set is
    /// partitioned across multiple size-bounded batches if needed (see
    /// [`record_create`](Self::record_create)). Returns an error if the
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
        // Strip before the empty check so an update of only `is_deleted = false`
        // is a no-op (see [`without_phantom_undelete`]).
        let stripped = Self::without_phantom_undelete(changed_fields);
        let changed_fields = stripped.as_ref().unwrap_or(changed_fields);
        if changed_fields.is_empty() {
            return Ok(());
        }
        self.validate_mutation_fields(table, changed_fields)?;
        let (device_id, epoch) = {
            let emitter = self
                .op_emitter
                .as_ref()
                .ok_or_else(|| CoreError::Engine("sync not configured".into()))?;
            (emitter.last_hlc().node_id.clone(), emitter.epoch())
        };
        let partitions = Self::partition_fields_into_batches(
            changed_fields,
            table,
            entity_id,
            &device_id,
            epoch,
        );
        let emitter = self
            .op_emitter
            .as_mut()
            .ok_or_else(|| CoreError::Engine("sync not configured".into()))?;
        let result = emitter.emit_update_multi(&*self.storage, table, entity_id, &partitions);
        if result.is_ok() {
            if let Some(tx) = self.sync_service.auto_sync_sender() {
                let _ = tx.try_send(());
            }
        }
        result
    }

    /// Drop a phantom `is_deleted = false` from a mutation's fields.
    ///
    /// `is_deleted` is write-once-true: a create/update carrying `false` stamps a
    /// fresh-HLC live-marker that, on a re-create of a deleted id, beats the older
    /// tombstone under per-field LWW and resurrects the entity.
    /// [`MergeEngine`](crate::engine::merge) enforces the same on receive. Returns
    /// `Some` only when a strip was needed (otherwise allocation-free).
    fn without_phantom_undelete(
        fields: &HashMap<String, SyncValue>,
    ) -> Option<HashMap<String, SyncValue>> {
        if !matches!(fields.get(DELETED_FIELD), Some(SyncValue::Bool(false))) {
            return None;
        }
        Some(
            fields
                .iter()
                .filter(|(k, v)| {
                    !(k.as_str() == DELETED_FIELD && matches!(v, SyncValue::Bool(false)))
                })
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        )
    }

    /// Record a soft-delete for an entity.
    ///
    /// Creates a tombstone op (`is_deleted = true`). Returns an error if the
    /// sync engine has not been configured.
    pub fn record_delete(&mut self, table: &str, entity_id: &str) -> Result<()> {
        self.record_delete_multi(table, &[entity_id.to_string()])
    }

    /// Delete many entities at once, packing their tombstones into a few
    /// batches instead of one batch (and one push round-trip) per row. All
    /// entity ids must belong to `table`. Empty input is a no-op.
    pub fn record_delete_multi(&mut self, table: &str, entity_ids: &[String]) -> Result<()> {
        if self.op_emitter.is_none() {
            return Err(CoreError::Engine("sync not configured".into()));
        }
        self.schema.entity(table).ok_or_else(|| CoreError::UnknownTable(table.to_string()))?;
        if entity_ids.is_empty() {
            return Ok(());
        }
        let partitions = Self::partition_deletes_into_batches(entity_ids);
        let emitter = self
            .op_emitter
            .as_mut()
            .ok_or_else(|| CoreError::Engine("sync not configured".into()))?;
        let result = emitter.emit_delete_multi(&*self.storage, table, &partitions);
        if result.is_ok() {
            if let Some(tx) = self.sync_service.auto_sync_sender() {
                let _ = tx.try_send(());
            }
        }
        result
    }

    /// Split delete tombstones into batches bounded by BOTH a count
    /// ([`DELETE_BATCH_OP_CAP`]) and a conservative byte estimate, each with its
    /// own `batch_id`. The byte bound keeps the public/FFI `record_delete_multi`
    /// safe even for pathologically long entity ids (without the per-op
    /// re-encoding the field-write partitioner needs for multi-MB blobs).
    fn partition_deletes_into_batches(entity_ids: &[String]) -> Vec<(Vec<String>, String)> {
        // Conservative per-op envelope cost: ~280 B of fixed JSON (op_id,
        // batch_id, device id, hlc, keys) plus the entity id, doubled to cover
        // AEAD tag + base64 expansion of the ciphertext. Over-estimating only
        // makes batches smaller — never over the relay cap.
        const OP_ENVELOPE_OVERHEAD: usize = 640;

        let mut partitions: Vec<(Vec<String>, String)> = Vec::new();
        let mut current: Vec<String> = Vec::new();
        let mut current_bytes = 0usize;
        for id in entity_ids {
            let op_bytes = OP_ENVELOPE_OVERHEAD + 2 * id.len();
            let would_overflow = current.len() >= DELETE_BATCH_OP_CAP
                || current_bytes + op_bytes > BATCH_BODY_TARGET_BYTES;
            if would_overflow && !current.is_empty() {
                partitions.push((std::mem::take(&mut current), uuid::Uuid::new_v4().to_string()));
                current_bytes = 0;
            }
            current.push(id.clone());
            current_bytes += op_bytes;
        }
        if !current.is_empty() {
            partitions.push((current, uuid::Uuid::new_v4().to_string()));
        }
        partitions
    }

    // ── Sync state reset ──

    /// Atomically wipe all local sync engine state for the configured sync
    /// group, leaving the device unpaired and ready to re-pair from scratch.
    ///
    /// Clears, in a single `BEGIN IMMEDIATE` transaction:
    /// - `pending_ops` (unpushed local mutations)
    /// - `applied_ops` (history of remote ops we've merged)
    /// - `field_versions` (per-field LWW winners — CRDT merge state)
    /// - `sync_metadata` (HLC bookkeeping, last-sync timestamps, epoch, etc.)
    /// - `device_registry` (the paired-devices list)
    ///
    /// The transaction is all-or-nothing: a failure rolls back leaving the
    /// engine state intact. After a successful wipe the device must call
    /// [`configure_engine`](Self::configure_engine) again as part of a fresh
    /// pairing flow before any sync operation will succeed.
    ///
    /// This also clears Rust's `quarantined_ops` table. Host-side quarantine
    /// tables, if any, still live outside the Rust sync engine and must be
    /// cleared by the host alongside this call.
    ///
    /// Returns `Err(CoreError::Engine)` if no sync group is currently
    /// configured (i.e. `configure_engine` has not been called).
    ///
    /// Used as the "Approach A" cutover hook by app-layer migrations that need
    /// to reshape synced entities incompatibly — the device is severed from
    /// its old sync group and re-pairs against the migrated peer.
    ///
    /// In addition to wiping the persistent engine tables, this nulls out the
    /// in-memory runtime state that `configure_engine` populated: the
    /// `OpEmitter`, the device signing keys (Ed25519 + ML-DSA), the device
    /// id, the epoch, and the `SyncService` engine + auto-sync task. Without
    /// this, a host that re-seeded credentials from its own keychain on next
    /// launch could re-attach to the OLD sync group with the in-memory
    /// state still pointing at it. Host-side quarantine tables are NOT
    /// touched by this call (see method-level note above).
    pub async fn reset_sync_state(&mut self) -> Result<()> {
        let sync_id = self
            .sync_service
            .sync_id()
            .ok_or_else(|| {
                CoreError::Engine("sync_id not set — call configure_engine first".into())
            })?
            .to_string();

        let storage = self.storage.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut tx = storage.begin_tx()?;
            tx.clear_sync_state(&sync_id)?;
            tx.commit()?;
            Ok(())
        })
        .await
        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;

        // Tear down in-memory runtime state. Order matters only insofar as
        // `clear_engine` aborts the auto-sync task before we drop key
        // material — any in-flight sync cycle will fail cleanly with
        // "sync not configured" rather than racing against half-cleared
        // state.
        self.sync_service.clear_engine();
        self.op_emitter = None;
        self.device_signing_key = None;
        self.device_ml_dsa_signing_key = None;
        self.ml_dsa_key_generation = None;
        self.device_id = None;
        self.epoch = None;

        Ok(())
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

    /// Split `fields` into one or more partitions whose serialized envelope
    /// stays under `BATCH_BODY_TARGET_BYTES` (and therefore under the relay's
    /// 1 MB cap).
    ///
    /// Each entry in the returned vector is `(field_map, batch_id)`. Empty
    /// `fields` maps are skipped; an empty `fields` argument returns an empty
    /// `Vec`.
    ///
    /// Algorithm: sort fields by encoded-value length **ascending**, then
    /// pack greedily into envelope-size-measured buckets. Small fields are
    /// placed first, so partition 0 accumulates every non-blob field of an
    /// entity create before a large blob is ever attempted; oversized blobs
    /// then naturally spill into their own subsequent buckets. A field
    /// whose own measured envelope already exceeds the target is placed
    /// alone in its bucket — the push path will surface a more precise size
    /// error if it actually exceeds the relay cap on the wire.
    ///
    /// **Why small-first matters:** receivers apply each pushed batch as a
    /// single UPSERT against their local schema. If the first partition for
    /// a member create contained only an avatar blob, the receiver's
    /// `name`/`created_at` NOT NULL columns would be empty and the insert
    /// would fail, silently dropping the row on the non-strict apply path.
    /// Small-first packing keeps partition 0 carrying every required
    /// column so the initial UPSERT is always a valid insert.
    ///
    /// **Important:** sizes are computed by serializing tentative
    /// `CrdtChange` ops and asking `estimate_envelope_body_size`, NOT by
    /// summing `encoded_value` lengths. Plaintext-only estimates ignore the
    /// AEAD padding buckets and the base64/JSON envelope overhead and so
    /// underestimate large batches.
    fn partition_fields_into_batches(
        fields: &HashMap<String, SyncValue>,
        table: &str,
        entity_id: &str,
        device_id: &str,
        epoch: i32,
    ) -> Vec<(HashMap<String, SyncValue>, String)> {
        if fields.is_empty() {
            return Vec::new();
        }

        // Pre-encode every value once so we can use the same plaintext both
        // for size estimation and for sorting. Sort ascending by encoded
        // length so the smallest values are placed first — this guarantees
        // every NOT NULL column lands in partition 0 before any blob is
        // tried, preventing receivers from UPSERTing a row that lacks
        // required fields and gets silently dropped on constraint violation.
        let mut entries: Vec<(String, SyncValue, String)> = fields
            .iter()
            .map(|(name, value)| {
                let encoded = crate::schema::encode_value(value);
                (name.clone(), value.clone(), encoded)
            })
            .collect();
        entries.sort_by_key(|a| a.2.len());

        // Each bucket carries the partition's field map plus its tentative
        // CrdtChange list (rebuilt as fields are added) for re-measuring.
        struct Bucket {
            fields: HashMap<String, SyncValue>,
            // Tentative ops shaped the same way the push path will reshape
            // them — values are the actual encoded JSON strings. The
            // estimator uses these to compute exact plaintext length.
            ops: Vec<CrdtChange>,
            batch_id: String,
        }

        let make_bucket = || Bucket {
            fields: HashMap::new(),
            ops: Vec::new(),
            batch_id: uuid::Uuid::new_v4().to_string(),
        };

        // Build a CrdtChange placeholder shaped like the ops the push path
        // will encode. The HLC string uses a worst-case length so the
        // plaintext-size estimate is an upper bound: 13-digit ms timestamp,
        // 10-digit counter (max u32), and the device id verbatim — this
        // never under-counts vs the real HLC the push path stamps later.
        let placeholder_hlc =
            format!("{:013}:{:010}:{}", u64::MAX % 10_000_000_000_000u64, u32::MAX, device_id);
        let make_change =
            |field_name: &str, encoded: &str, batch_id: &str, device: &str, ep: i32| CrdtChange {
                op_id: uuid::Uuid::new_v4().to_string(),
                batch_id: Some(batch_id.to_string()),
                entity_id: entity_id.to_string(),
                entity_table: table.to_string(),
                field_name: field_name.to_string(),
                encoded_value: encoded.to_string(),
                client_hlc: placeholder_hlc.clone(),
                is_delete: false,
                device_id: device.to_string(),
                epoch: ep,
                server_seq: None,
            };

        let mut buckets: Vec<Bucket> = Vec::new();

        for (name, value, encoded) in entries {
            let mut placed = false;

            for bucket in buckets.iter_mut() {
                // Build the candidate op list for this bucket if we add the
                // new field to it.
                let mut candidate_ops = bucket.ops.clone();
                candidate_ops.push(make_change(
                    &name,
                    &encoded,
                    &bucket.batch_id,
                    device_id,
                    epoch,
                ));

                let body = estimate_envelope_body_size(&candidate_ops, HYBRID_SIGNATURE_WIRE_BYTES);
                if body <= BATCH_BODY_TARGET_BYTES {
                    bucket.fields.insert(name.clone(), value.clone());
                    bucket.ops = candidate_ops;
                    placed = true;
                    break;
                }
            }

            if !placed {
                // No existing bucket can fit this field. Start a fresh one.
                // If this single field alone overshoots the target it still
                // gets its own bucket — the push path's pre-flight guard
                // (Phase 1B) will catch any batch that genuinely exceeds the
                // 1 MB relay cap on the wire.
                let mut bucket = make_bucket();
                bucket.ops.push(make_change(&name, &encoded, &bucket.batch_id, device_id, epoch));
                bucket.fields.insert(name, value);
                buckets.push(bucket);
            }
        }

        buckets
            .into_iter()
            .filter(|b| !b.fields.is_empty())
            .map(|b| (b.fields, b.batch_id))
            .collect()
    }

    /// Partition pre-existing `PendingOp` rows into one or more sub-batches
    /// whose serialized envelope stays under `BATCH_BODY_TARGET_BYTES` (and
    /// therefore under the relay's 1 MB cap).
    ///
    /// Used by Phase 1C recovery to repartition a quarantined batch without
    /// re-emitting ops — the returned `op_ids` keep their `op_id`,
    /// `client_hlc`, `device_id`, `epoch`, `encoded_value`, `created_at`,
    /// `entity_table`, `entity_id`, `field_name`, `is_delete`, `pushed_at`
    /// fields intact; only `local_batch_id` is rewritten by the caller.
    ///
    /// Each entry in the returned vector is `(op_ids, batch_id)` — every
    /// `op_id` in `op_ids` belongs to the same new `batch_id`. Empty input
    /// returns an empty Vec.
    ///
    /// Algorithm mirrors `partition_fields_into_batches`: sort by
    /// `encoded_value` length descending, then first-fit-decreasing into
    /// envelope-size-measured buckets. A single op whose own envelope already
    /// overshoots the target still gets its own bucket — the push path's
    /// pre-flight guard re-quarantines it on the next cycle with an
    /// irreparable-oversized-op diagnostic, which is the correct surface for
    /// the caller (Phase 1C UI / future Phase 1D handling).
    fn partition_pending_ops_into_batches(ops: &[PendingOp]) -> Vec<(Vec<String>, String)> {
        if ops.is_empty() {
            return Vec::new();
        }

        // Sort op references by encoded_value length descending so the largest
        // ops are placed first (classic FFD).
        let mut entries: Vec<&PendingOp> = ops.iter().collect();
        entries.sort_by_key(|b| std::cmp::Reverse(b.encoded_value.len()));

        // Each bucket carries the partition's op_ids list plus its tentative
        // CrdtChange list for re-measuring envelope size.
        struct Bucket {
            op_ids: Vec<String>,
            ops: Vec<CrdtChange>,
            batch_id: String,
        }

        let make_bucket = || Bucket {
            op_ids: Vec::new(),
            ops: Vec::new(),
            batch_id: uuid::Uuid::new_v4().to_string(),
        };

        // Build a CrdtChange from a PendingOp tagged with the candidate
        // `batch_id`. The shape matches what the push path actually
        // serializes (`engine::mod::push_phase` builds CrdtChange instances
        // from the same fields), so the envelope-size estimate is faithful.
        let make_change = Self::pending_op_to_change;

        let mut buckets: Vec<Bucket> = Vec::new();

        for op in entries {
            let mut placed = false;

            for bucket in buckets.iter_mut() {
                let mut candidate_ops = bucket.ops.clone();
                candidate_ops.push(make_change(op, &bucket.batch_id));

                let body = estimate_envelope_body_size(&candidate_ops, HYBRID_SIGNATURE_WIRE_BYTES);
                if body <= BATCH_BODY_TARGET_BYTES {
                    bucket.op_ids.push(op.op_id.clone());
                    bucket.ops = candidate_ops;
                    placed = true;
                    break;
                }
            }

            if !placed {
                let mut bucket = make_bucket();
                bucket.ops.push(make_change(op, &bucket.batch_id));
                bucket.op_ids.push(op.op_id.clone());
                buckets.push(bucket);
            }
        }

        buckets
            .into_iter()
            .filter(|b| !b.op_ids.is_empty())
            .map(|b| (b.op_ids, b.batch_id))
            .collect()
    }

    /// Build a `CrdtChange` from a `PendingOp` tagged with `batch_id`. The shape
    /// matches what `engine::push_phase` serializes, so envelope-size estimates
    /// off this are faithful to the wire.
    fn pending_op_to_change(op: &PendingOp, batch_id: &str) -> CrdtChange {
        CrdtChange {
            op_id: op.op_id.clone(),
            batch_id: Some(batch_id.to_string()),
            entity_id: op.entity_id.clone(),
            entity_table: op.entity_table.clone(),
            field_name: op.field_name.clone(),
            encoded_value: op.encoded_value.clone(),
            client_hlc: op.client_hlc.clone(),
            is_delete: op.is_delete,
            device_id: op.device_id.clone(),
            epoch: op.epoch,
            server_seq: None,
        }
    }

    /// Whether a single op's own push envelope exceeds the relay body cap, so it
    /// can't be made pushable by repartitioning (nothing to split off).
    fn op_alone_exceeds_wire_cap(op: &PendingOp) -> bool {
        let change = Self::pending_op_to_change(op, &op.local_batch_id);
        estimate_envelope_body_size(&[change], HYBRID_SIGNATURE_WIRE_BYTES)
            > crate::engine::RELAY_BODY_GUARD_BYTES
    }

    /// Repartition every push-quarantined batch into one or more smaller
    /// sub-batches sized to fit under the relay's 1 MB envelope cap, and
    /// clear the matching `push_quarantine` row so the next sync cycle picks
    /// the new batches up via `get_unpushed_batch_ids`.
    ///
    /// Runs in a single `BEGIN IMMEDIATE` transaction so the entire recovery
    /// either commits as one atomic step or rolls back leaving the
    /// pre-existing quarantined batches exactly as they were.
    ///
    /// Returns the number of `push_quarantine` rows successfully repaired.
    ///
    /// **Critical safety property:** every `pending_ops` field other than
    /// `local_batch_id` is preserved exactly — `op_id`, `client_hlc`,
    /// `device_id`, `epoch`, `encoded_value`, `created_at`, `entity_table`,
    /// `entity_id`, `field_name`, `is_delete`, `pushed_at` are NEVER
    /// touched. Repartitioning is a pure CRDT-no-op: the resulting ops have
    /// the same field-level LWW outcomes as the originals.
    ///
    /// Idempotent: a second call when there are no quarantined batches is a
    /// cheap no-op returning 0. Re-running on an already-repaired DB returns
    /// 0 because nothing remains in `push_quarantine` to repair.
    ///
    /// Errors with `CoreError::Engine("sync_id not set …")` if the engine
    /// has not been configured.
    pub fn repair_quarantined_batches(&mut self) -> Result<i64> {
        let sync_id = self
            .sync_service
            .sync_id()
            .ok_or_else(|| {
                CoreError::Engine("sync_id not set — call configure_engine first".into())
            })?
            .to_string();

        let infos = self.storage.list_quarantined_batches(&sync_id)?;
        if infos.is_empty() {
            return Ok(0);
        }

        // One transaction wrapping ALL repairs. If any step fails we roll
        // back the whole thing, leaving the quarantined batches untouched.
        let mut tx = self.storage.begin_tx()?;
        let mut repaired = 0i64;

        for info in &infos {
            let original_batch_id = info.batch_id.as_str();
            let existing_ops = tx.load_batch_ops(original_batch_id)?;

            // Orphan quarantine row: the underlying pending_ops are gone.
            // Cleanest fix is to remove the dangling quarantine row so the
            // banner clears and the user isn't stuck looking at a count
            // they can't act on.
            if existing_ops.is_empty() {
                tx.unquarantine_batch(&sync_id, original_batch_id)?;
                repaired += 1;
                continue;
            }

            // Drop ops the field has already moved past: if the winning version
            // is a different op, this one lost LWW and would lose on every peer,
            // so pushing it only re-quarantines. Keyed off the field version, not
            // pending ops, so it holds even after the newer op has pushed.
            let mut live_ops = Vec::with_capacity(existing_ops.len());
            for op in existing_ops {
                let fv = tx.get_field_version(
                    &sync_id,
                    &op.entity_table,
                    &op.entity_id,
                    &op.field_name,
                )?;
                let superseded = fv.is_some_and(|fv| fv.winning_op_id != op.op_id);
                if superseded {
                    tx.delete_pending_op(&op.op_id)?;
                } else {
                    live_ops.push(op);
                }
            }

            // Every op was superseded → nothing left to push; clear the row.
            if live_ops.is_empty() {
                tx.unquarantine_batch(&sync_id, original_batch_id)?;
                repaired += 1;
                continue;
            }

            // An op whose own envelope still exceeds the cap can't be split
            // smaller. Leave it quarantined rather than unquarantine it for the
            // next push to re-quarantine — that loop made "Repair" a no-op.
            if live_ops.iter().any(Self::op_alone_exceeds_wire_cap) {
                continue;
            }

            let partitions = Self::partition_pending_ops_into_batches(&live_ops);

            // Defensive: the partitioner must produce at least one bucket if
            // we got here with non-empty ops. Treat anything else as a bug.
            if partitions.is_empty() {
                let _ = tx.rollback();
                return Err(CoreError::Engine(format!(
                    "repair_quarantined_batches: partitioner produced no buckets \
                     for batch_id={original_batch_id} with {} ops",
                    live_ops.len(),
                )));
            }

            // Decide whether we actually need to rewrite local_batch_id:
            // if the partitioner produces a single bucket that covers every
            // live op, the "new" batch_id is just a fresh UUID for the
            // same set of ops — rewriting is unnecessary, but we still must
            // clear the quarantine row.
            let single_bucket = partitions.len() == 1;
            let same_size = single_bucket && partitions[0].0.len() == live_ops.len();

            if !same_size {
                for (op_ids, new_batch_id) in &partitions {
                    for op_id in op_ids {
                        tx.update_pending_op_batch_id(op_id, new_batch_id)?;
                    }
                }
            }

            tx.unquarantine_batch(&sync_id, original_batch_id)?;
            repaired += 1;
        }

        tx.commit()?;
        Ok(repaired)
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

        // 1. Use the relay registry epoch for the atomic revoke precondition.
        //    Local metadata can lag after this device recovers from another
        //    device's earlier rekey, but the relay is authoritative here.
        let devices = relay.list_devices().await?;
        let self_device =
            devices.iter().find(|device| device.device_id == self_device_id).ok_or_else(|| {
                CoreError::Engine("current device missing from relay device list".into())
            })?;
        if self_device.status != "active" {
            return Err(CoreError::Engine(format!(
                "current device is not active in relay device list: {}",
                self_device.status
            )));
        }
        let new_epoch = self_device.epoch.max(0) as u32 + 1;

        // 2. Generate wrapped keys for surviving devices, then perform the
        //    atomic revoke+epoch-rotation request against the relay.
        let (epoch_key, wrapped_keys) =
            crate::epoch::EpochManager::prepare_wrapped_keys_for_devices(
                &devices,
                new_epoch,
                Some(target_device_id),
            )?;

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

    fn refresh_op_emitter_hlc_from_storage(&mut self, context: &'static str) {
        let Some(sync_id) = self.sync_service.sync_id().map(str::to_owned) else {
            return;
        };
        let Some(emitter) = self.op_emitter.as_mut() else {
            return;
        };

        match self.storage.list_all_field_version_hlcs(&sync_id) {
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
                        context,
                        "failed to parse stored HLCs while refreshing local emitter"
                    );
                }
            },
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    context,
                    "failed to read stored HLCs while refreshing local emitter"
                );
            }
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

    let matches = matches!(
        (expected, value),
        (SyncType::String, SyncValue::String(_))
            | (SyncType::Int, SyncValue::Int(_))
            | (SyncType::Real, SyncValue::Real(_))
            | (SyncType::Real, SyncValue::Int(_))
            | (SyncType::Bool, SyncValue::Bool(_))
            | (SyncType::DateTime, SyncValue::DateTime(_))
            | (SyncType::Blob, SyncValue::Blob(_))
    );

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
        async fn put_signed_registry(&self, _: &[u8]) -> std::result::Result<i64, RelayError> {
            Ok(0)
        }
    }

    #[async_trait]
    impl EpochManagement for NoopRelay {
        async fn post_rekey_artifacts(
            &self,
            _: i32,
            _: HashMap<String, Vec<u8>>,
            _: Option<&[u8]>,
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
            _: Option<u64>,
        ) -> std::result::Result<MediaUploadOutcome, RelayError> {
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
        SuccessWithEpochCheck,
        AdvanceBeforeEpochCheck,
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
                RevokeBehavior::Success
                | RevokeBehavior::SuccessWithEpochCheck
                | RevokeBehavior::AdvanceBeforeEpochCheck => {
                    if matches!(state.behavior, RevokeBehavior::AdvanceBeforeEpochCheck) {
                        for device in &mut state.devices {
                            if device.status == "active" {
                                device.epoch += 1;
                            }
                        }
                    }
                    if matches!(
                        state.behavior,
                        RevokeBehavior::SuccessWithEpochCheck
                            | RevokeBehavior::AdvanceBeforeEpochCheck
                    ) {
                        let current_epoch = state
                            .devices
                            .iter()
                            .filter(|device| device.status == "active")
                            .map(|device| device.epoch)
                            .max()
                            .unwrap_or(0);
                        if new_epoch != current_epoch + 1 {
                            return Err(RelayError::Protocol {
                                message: format!(
                                    "new_epoch must be current_epoch + 1 (current={current_epoch}, got={new_epoch})"
                                ),
                            });
                        }
                    }
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
        async fn put_signed_registry(
            &self,
            signed_registry_snapshot: &[u8],
        ) -> std::result::Result<i64, RelayError> {
            let mut state = self.state.lock().unwrap();
            let registry_version = state
                .signed_registry
                .as_ref()
                .map(|registry| registry.registry_version + 1)
                .unwrap_or(SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING);
            state.signed_registry = Some(SignedRegistryResponse {
                registry_version,
                artifact_blob: signed_registry_snapshot.to_vec(),
                artifact_kind: "signed_registry_snapshot".to_string(),
            });
            Ok(registry_version)
        }
    }

    #[async_trait]
    impl EpochManagement for RevokeTestRelay {
        async fn post_rekey_artifacts(
            &self,
            _: i32,
            _: HashMap<String, Vec<u8>>,
            _: Option<&[u8]>,
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
            _: Option<u64>,
        ) -> std::result::Result<MediaUploadOutcome, RelayError> {
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
        let aad = crate::epoch::build_rekey_artifact_aad(epoch, device_id);
        let encrypted_epoch_key =
            prism_sync_crypto::aead::xchacha_encrypt_aead(&wrap_key, epoch_key, &aad).unwrap();

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
                    // Registered so the phantom-undelete strip tests exercise the
                    // real path (is_deleted is a valid Bool field in prod schema),
                    // not an incidental UnknownField rejection.
                    .field("is_deleted", SyncType::Bool)
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
    async fn sync_preflight_repairs_lagging_signed_registry_when_local_epoch_is_current() {
        let (mut sync, relay, device_id, epoch_1_key, _epoch_2_key) =
            prepare_verified_epoch_catch_up(true);

        sync.catch_up_epoch_keys().await.unwrap();
        assert_eq!(sync.epoch(), Some(2));

        let device_secret =
            DeviceSecret::from_bytes(sync.device_secret().unwrap().as_bytes().to_vec()).unwrap();
        let device_info = relay.state.lock().unwrap().devices[0].clone();
        let epoch_0_key: [u8; 32] = sync.key_hierarchy().epoch_key(0).unwrap().try_into().unwrap();
        relay.set_signed_registry(signed_registry_response(
            "sync-1",
            &device_secret,
            &device_id,
            &device_info,
            1,
            &[(0, epoch_0_key), (1, epoch_1_key)],
        ));

        sync.catch_up_epoch_keys().await.unwrap();

        let repaired = relay.state.lock().unwrap().signed_registry.clone().unwrap();
        let signing_key = device_secret.ed25519_keypair(&device_id).unwrap();
        let pq_signing_key = device_secret.ml_dsa_65_keypair(&device_id).unwrap();
        let snapshot = SignedRegistrySnapshot::verify_and_decode_hybrid(
            &repaired.artifact_blob,
            &signing_key.public_key_bytes(),
            &pq_signing_key.public_key_bytes(),
        )
        .unwrap();
        assert_eq!(snapshot.current_epoch, 2);
        assert_eq!(snapshot.registry_version, 2);
        assert!(snapshot.epoch_key_hashes.contains_key(&2));
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

        let schema =
            SyncSchema::builder().entity("members", |e| e.field("name", SyncType::String)).build();
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
        let fv =
            sync.storage.get_field_version("sync-1", "members", "post-1", "name").unwrap().unwrap();
        let post_hlc = Hlc::from_string(&fv.winning_hlc).unwrap();
        assert!(
            post_hlc > pre_parsed,
            "post-configure HLC {post_hlc:?} must exceed pre-seeded HLC {pre_parsed:?}"
        );
    }

    #[test]
    fn refresh_op_emitter_hlc_preserves_causality_after_near_future_remote_pull() {
        use crate::hlc::Hlc;
        use crate::storage::FieldVersion;

        let mut sync = make_sync();
        configure(&mut sync);

        let remote_hlc = Hlc::new(Hlc::now_ms() + 5_000, 0, "remote-device");
        {
            let mut tx = sync.storage.begin_tx().unwrap();
            tx.upsert_field_version(&FieldVersion {
                sync_id: "sync-1".to_string(),
                entity_table: "members".to_string(),
                entity_id: "ent-1".to_string(),
                field_name: "name".to_string(),
                winning_op_id: "remote-op".to_string(),
                winning_device_id: "remote-device".to_string(),
                winning_hlc: remote_hlc.to_string(),
                winning_encoded_value: Some("\"Remote\"".to_string()),
                updated_at: chrono::Utc::now(),
            })
            .unwrap();
            tx.commit().unwrap();
        }

        sync.refresh_op_emitter_hlc_from_storage("test");

        let mut fields = HashMap::new();
        fields.insert("name".to_string(), SyncValue::String("Local".to_string()));
        sync.record_update("members", "ent-1", &fields).unwrap();

        let fv =
            sync.storage.get_field_version("sync-1", "members", "ent-1", "name").unwrap().unwrap();
        let local_hlc = Hlc::from_string(&fv.winning_hlc).unwrap();
        assert!(
            local_hlc > remote_hlc,
            "local mutation HLC {local_hlc:?} must be causally after pulled HLC {remote_hlc:?}"
        );
        assert_eq!(local_hlc.node_id, "a1b2c3d4e5f6");
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
    fn record_create_strips_phantom_is_deleted_false() {
        // Regression: a create carrying is_deleted=false must NOT emit an
        // is_deleted op. On a re-create of a deleted id that fresh-HLC `false`
        // beats the older tombstone under per-field LWW and resurrects the
        // entity on every peer. See prism-app
        // test/e2e/board_post_delete_resurrection_test.dart.
        let mut sync = make_sync();
        configure(&mut sync);

        let mut fields = HashMap::new();
        fields.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        fields.insert(DELETED_FIELD.to_string(), SyncValue::Bool(false));

        sync.record_create("members", "ent-1", &fields).unwrap();

        // Only the real field was emitted; the phantom is_deleted=false is gone.
        let batch_ids = sync.storage.get_unpushed_batch_ids("sync-1").unwrap();
        let ops = sync.storage.load_batch_ops(&batch_ids[0]).unwrap();
        assert_eq!(ops.len(), 1, "only the name op should be emitted, not is_deleted");
        assert_eq!(ops[0].field_name, "name");
        assert!(
            sync.storage
                .get_field_version("sync-1", "members", "ent-1", DELETED_FIELD)
                .unwrap()
                .is_none(),
            "create must not write an is_deleted=false field version"
        );
    }

    #[test]
    fn record_update_strips_phantom_is_deleted_false() {
        // A field update carrying is_deleted=false must also drop it; an update
        // of ONLY is_deleted=false becomes a no-op rather than a phantom
        // un-delete that would resurrect a tombstoned entity.
        let mut sync = make_sync();
        configure(&mut sync);

        let mut create = HashMap::new();
        create.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        sync.record_create("members", "ent-1", &create).unwrap();
        let batches_after_create = sync.storage.get_unpushed_batch_ids("sync-1").unwrap().len();

        let mut changed = HashMap::new();
        changed.insert(DELETED_FIELD.to_string(), SyncValue::Bool(false));
        sync.record_update("members", "ent-1", &changed).unwrap();

        assert_eq!(
            sync.storage.get_unpushed_batch_ids("sync-1").unwrap().len(),
            batches_after_create,
            "an update of only is_deleted=false must emit nothing"
        );
        assert!(
            sync.storage
                .get_field_version("sync-1", "members", "ent-1", DELETED_FIELD)
                .unwrap()
                .is_none(),
            "a phantom un-delete must not write an is_deleted field version"
        );
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
    fn record_delete_multi_packs_many_deletes_into_one_batch() {
        let mut sync = make_sync();
        configure(&mut sync);

        let ids: Vec<String> = (0..5).map(|i| format!("ent-{i}")).collect();
        sync.record_delete_multi("members", &ids).unwrap();

        // 5 deletes (< DELETE_BATCH_OP_CAP) coalesce into a single batch.
        let batch_ids = sync.storage.get_unpushed_batch_ids("sync-1").unwrap();
        assert_eq!(batch_ids.len(), 1, "5 deletes should be one batch, not five");

        let ops = sync.storage.load_batch_ops(&batch_ids[0]).unwrap();
        assert_eq!(ops.len(), 5);
        for op in &ops {
            assert!(op.is_delete);
            assert_eq!(op.field_name, DELETED_FIELD);
            assert_eq!(op.encoded_value, "true");
        }
        let mut entities: Vec<&str> = ops.iter().map(|o| o.entity_id.as_str()).collect();
        entities.sort_unstable();
        assert_eq!(entities, vec!["ent-0", "ent-1", "ent-2", "ent-3", "ent-4"]);
    }

    #[test]
    fn record_delete_multi_splits_beyond_cap() {
        let mut sync = make_sync();
        configure(&mut sync);

        // One past the cap spans two batches (cap, then 1) covering every id.
        let ids: Vec<String> = (0..DELETE_BATCH_OP_CAP + 1).map(|i| format!("ent-{i}")).collect();
        sync.record_delete_multi("members", &ids).unwrap();

        let batch_ids = sync.storage.get_unpushed_batch_ids("sync-1").unwrap();
        assert_eq!(batch_ids.len(), 2, "cap+1 deletes should span two batches");

        let total: usize =
            batch_ids.iter().map(|b| sync.storage.load_batch_ops(b).unwrap().len()).sum();
        assert_eq!(total, DELETE_BATCH_OP_CAP + 1);
    }

    #[test]
    fn record_delete_multi_splits_on_byte_budget_for_long_ids() {
        let mut sync = make_sync();
        configure(&mut sync);

        // 5 KB ids blow the byte budget long before the count cap, so batches
        // stay small and well under DELETE_BATCH_OP_CAP — the public/FFI API
        // can't produce an over-relay-cap batch even with pathological ids.
        let long = "x".repeat(5000);
        let ids: Vec<String> = (0..200).map(|i| format!("{long}-{i}")).collect();
        sync.record_delete_multi("members", &ids).unwrap();

        let batch_ids = sync.storage.get_unpushed_batch_ids("sync-1").unwrap();
        assert!(batch_ids.len() > 1, "long ids must split into multiple batches");

        let mut total = 0usize;
        for b in &batch_ids {
            let n = sync.storage.load_batch_ops(b).unwrap().len();
            assert!(n < DELETE_BATCH_OP_CAP, "byte bound should cap below the count cap");
            total += n;
        }
        assert_eq!(total, 200, "every id must be tombstoned exactly once");
    }

    #[test]
    fn record_delete_multi_empty_is_noop() {
        let mut sync = make_sync();
        configure(&mut sync);
        sync.record_delete_multi("members", &[]).unwrap();
        assert!(sync.storage.get_unpushed_batch_ids("sync-1").unwrap().is_empty());
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
    async fn revoke_and_rekey_uses_relay_epoch_when_local_metadata_is_stale() {
        let mut sync = make_sync();
        sync.initialize("test-password", &[1u8; 16]).unwrap();

        let self_device_id = "a1b2c3d4e5f6";
        let target_device_id = "b7c8d9e0f1a2";
        let target_secret = DeviceSecret::generate();
        let relay = Arc::new(RevokeTestRelay::new(
            vec![
                make_device_info(self_device_id, sync.device_secret().unwrap(), 6, "active"),
                make_device_info(target_device_id, &target_secret, 6, "active"),
            ],
            RevokeBehavior::SuccessWithEpochCheck,
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

        assert_eq!(committed_epoch, 7);
        assert_eq!(relay.revoke_calls(), 1);
        assert_eq!(sync.epoch(), Some(7));
        assert!(sync.key_hierarchy().has_epoch_key(7));
        assert_eq!(sync.storage().get_sync_metadata("sync-1").unwrap().unwrap().current_epoch, 7);
        assert!(sync.secure_store().get("epoch_key_7").unwrap().is_some());
    }

    #[tokio::test]
    async fn revoke_and_rekey_uses_relay_epoch_when_persisted_metadata_is_stale() {
        let mut sync = make_sync();
        sync.initialize("test-password", &[1u8; 16]).unwrap();

        let self_device_id = "a1b2c3d4e5f6";
        let target_device_id = "b7c8d9e0f1a2";
        let target_secret = DeviceSecret::generate();
        let relay = Arc::new(RevokeTestRelay::new(
            vec![
                make_device_info(self_device_id, sync.device_secret().unwrap(), 6, "active"),
                make_device_info(target_device_id, &target_secret, 6, "active"),
            ],
            RevokeBehavior::SuccessWithEpochCheck,
        ));

        {
            let mut tx = sync.storage().begin_tx().unwrap();
            tx.update_current_epoch("sync-1", 3).unwrap();
            tx.commit().unwrap();
        }
        sync.secure_store().set("epoch", b"3").unwrap();

        sync.configure_engine(
            relay.clone(),
            "sync-1".to_string(),
            self_device_id.to_string(),
            3,
            0,
        );

        let committed_epoch =
            sync.revoke_and_rekey(relay.clone(), target_device_id, false).await.unwrap();

        assert_eq!(committed_epoch, 7);
        assert_eq!(relay.revoke_calls(), 1);
        assert_eq!(sync.epoch(), Some(7));
        assert!(sync.key_hierarchy().has_epoch_key(7));
        assert_eq!(sync.storage().get_sync_metadata("sync-1").unwrap().unwrap().current_epoch, 7);
        assert!(sync.secure_store().get("epoch_key_7").unwrap().is_some());
    }

    #[tokio::test]
    async fn revoke_and_rekey_does_not_commit_local_epoch_after_relay_epoch_race() {
        let mut sync = make_sync();
        sync.initialize("test-password", &[1u8; 16]).unwrap();

        let self_device_id = "a1b2c3d4e5f6";
        let target_device_id = "b7c8d9e0f1a2";
        let target_secret = DeviceSecret::generate();
        let relay = Arc::new(RevokeTestRelay::new(
            vec![
                make_device_info(self_device_id, sync.device_secret().unwrap(), 6, "active"),
                make_device_info(target_device_id, &target_secret, 6, "active"),
            ],
            RevokeBehavior::AdvanceBeforeEpochCheck,
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

        assert!(error.to_string().contains("new_epoch must be current_epoch + 1"));
        assert_eq!(relay.revoke_calls(), 1);
        assert_eq!(sync.epoch(), Some(0));
        assert!(!sync.key_hierarchy().has_epoch_key(7));
        assert!(sync.storage().get_sync_metadata("sync-1").unwrap().is_none());
        assert!(sync.secure_store().get("epoch_key_7").unwrap().is_none());
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

    // ── reset_sync_state ──

    fn seed_all_tables(storage: &Arc<dyn SyncStorage>, sync_id: &str) {
        use crate::storage::{AppliedOp, DeviceRecord, FieldVersion, PendingOp, SyncMetadata};
        use chrono::Utc;

        let now = Utc::now();
        // Op ids are PRIMARY KEY across the whole table (not per sync_id), so
        // include sync_id in derived ids to keep multi-group seeding from
        // colliding.
        let pending_op_id = format!("op-pending-{sync_id}");
        let applied_op_id = format!("op-applied-{sync_id}");
        let batch_id = format!("batch-{sync_id}");
        let metadata = SyncMetadata {
            sync_id: sync_id.to_string(),
            local_device_id: "device-abc".to_string(),
            current_epoch: 1,
            last_pulled_server_seq: 42,
            last_pushed_at: Some(now),
            last_successful_sync_at: Some(now),
            registered_at: Some(now),
            needs_rekey: false,
            last_imported_registry_version: Some(7),
            created_at: now,
            updated_at: now,
        };
        let pending = PendingOp {
            op_id: pending_op_id,
            sync_id: sync_id.to_string(),
            epoch: 1,
            device_id: "dev1".to_string(),
            local_batch_id: batch_id,
            entity_table: "members".to_string(),
            entity_id: "ent-1".to_string(),
            field_name: "name".to_string(),
            encoded_value: "\"Alice\"".to_string(),
            is_delete: false,
            client_hlc: "2026-01-01T00:00:00.000Z:0000:dev1".to_string(),
            created_at: now,
            pushed_at: None,
        };
        let applied = AppliedOp {
            op_id: applied_op_id.clone(),
            sync_id: sync_id.to_string(),
            epoch: 1,
            device_id: "dev1".to_string(),
            client_hlc: "2026-01-01T00:00:00.000Z:0000:dev1".to_string(),
            server_seq: 10,
            applied_at: now,
        };
        let fv = FieldVersion {
            sync_id: sync_id.to_string(),
            entity_table: "members".to_string(),
            entity_id: "ent-1".to_string(),
            field_name: "name".to_string(),
            winning_op_id: applied_op_id,
            winning_device_id: "dev1".to_string(),
            winning_hlc: "2026-01-01T00:00:00.000Z:0000:dev1".to_string(),
            winning_encoded_value: Some("\"Alice\"".to_string()),
            updated_at: now,
        };
        let device = DeviceRecord {
            sync_id: sync_id.to_string(),
            device_id: "dev1".to_string(),
            ed25519_public_key: vec![1, 2, 3, 4],
            x25519_public_key: vec![5, 6, 7, 8],
            ml_dsa_65_public_key: vec![9u8; 1952],
            ml_kem_768_public_key: vec![10u8; 1184],
            x_wing_public_key: vec![],
            status: "active".to_string(),
            registered_at: now,
            revoked_at: None,
            ml_dsa_key_generation: 0,
        };

        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_sync_metadata(&metadata).unwrap();
        tx.insert_pending_op(&pending).unwrap();
        tx.insert_applied_op(&applied).unwrap();
        tx.upsert_field_version(&fv).unwrap();
        tx.upsert_device_record(&device).unwrap();
        tx.commit().unwrap();
    }

    #[tokio::test]
    async fn reset_sync_state_wipes_all_engine_tables() {
        let mut sync = make_sync();
        configure(&mut sync);
        seed_all_tables(sync.storage(), "sync-1");

        // Sanity: every table has data before the wipe.
        assert!(sync.storage().get_sync_metadata("sync-1").unwrap().is_some());
        assert!(!sync.storage().get_unpushed_batch_ids("sync-1").unwrap().is_empty());
        assert!(sync.storage().is_op_applied("op-applied-sync-1").unwrap());
        assert!(sync
            .storage()
            .get_field_version("sync-1", "members", "ent-1", "name")
            .unwrap()
            .is_some());
        assert!(!sync.storage().list_device_records("sync-1").unwrap().is_empty());

        sync.reset_sync_state().await.unwrap();

        // Every table is empty after the wipe.
        assert!(sync.storage().get_sync_metadata("sync-1").unwrap().is_none());
        assert!(sync.storage().get_unpushed_batch_ids("sync-1").unwrap().is_empty());
        assert!(!sync.storage().is_op_applied("op-applied-sync-1").unwrap());
        assert!(sync
            .storage()
            .get_field_version("sync-1", "members", "ent-1", "name")
            .unwrap()
            .is_none());
        assert!(sync.storage().list_device_records("sync-1").unwrap().is_empty());
    }

    /// `reset_sync_state` must also tear down the in-memory runtime state
    /// that `configure_engine` populated. Previously it only wiped the
    /// engine's persistent tables, leaving `op_emitter`, the device id,
    /// epoch, and the `SyncService` engine intact — so a host that
    /// re-seeded credentials from its own keychain on next launch could
    /// silently re-attach to the OLD sync group with the in-memory state
    /// still pointing at it.
    #[tokio::test]
    async fn reset_sync_state_clears_runtime_engine_and_keys() {
        let mut sync = make_sync();
        configure(&mut sync);
        seed_all_tables(sync.storage(), "sync-1");

        // Pre-conditions established by `configure_engine`.
        assert!(sync.op_emitter.is_some(), "op_emitter set by configure");
        assert!(sync.device_id.is_some(), "device_id set by configure");
        assert!(sync.epoch.is_some(), "epoch set by configure");
        assert!(sync.sync_service.has_engine(), "engine set by configure");
        assert_eq!(sync.sync_service.sync_id(), Some("sync-1"));

        sync.reset_sync_state().await.unwrap();

        // In-memory runtime state torn down — device is in the same shape
        // as immediately after `PrismSync::builder().build()`.
        assert!(sync.op_emitter.is_none(), "op_emitter cleared");
        assert!(sync.device_signing_key.is_none(), "Ed25519 signing key cleared");
        assert!(sync.device_ml_dsa_signing_key.is_none(), "ML-DSA signing key cleared");
        assert!(sync.ml_dsa_key_generation.is_none(), "ML-DSA generation cleared");
        assert!(sync.device_id.is_none(), "device_id cleared");
        assert!(sync.epoch.is_none(), "epoch cleared");
        assert!(!sync.sync_service.has_engine(), "engine cleared");
        assert!(sync.sync_service.sync_id().is_none(), "sync_id cleared");
    }

    /// After reset, the standard mutation entry points must fail closed
    /// rather than silently accepting writes that would never sync.
    #[tokio::test]
    async fn record_create_after_reset_returns_engine_error() {
        let mut sync = make_sync();
        configure(&mut sync);

        // Sanity: writes succeed pre-reset.
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        sync.record_create("members", "ent-pre", &fields).unwrap();

        sync.reset_sync_state().await.unwrap();

        let err = sync
            .record_create("members", "ent-post", &fields)
            .expect_err("record_create must fail after reset");
        assert!(
            err.to_string().to_lowercase().contains("not configured"),
            "expected 'sync not configured' style error, got: {err}"
        );
    }

    /// With auto-sync enabled, reset must abort the debounce task and
    /// drop the mutation sender so no further sync cycles fire against
    /// the (now-cleared) old sync group.
    #[tokio::test]
    async fn reset_sync_state_disables_auto_sync() {
        let mut sync = make_sync();
        configure(&mut sync);

        // Enable auto-sync; verify the sender is live before reset.
        let _trigger_rx = sync.sync_service.set_auto_sync(crate::sync_service::AutoSyncConfig {
            enabled: true,
            debounce: std::time::Duration::from_millis(50),
            ..Default::default()
        });
        assert!(
            sync.sync_service.auto_sync_sender().is_some(),
            "auto-sync sender should be live after set_auto_sync(enabled=true)"
        );

        sync.reset_sync_state().await.unwrap();

        assert!(
            sync.sync_service.auto_sync_sender().is_none(),
            "auto-sync sender must be None after reset"
        );
        assert!(
            sync.sync_service.notification_trigger_sender().is_none(),
            "notification trigger sender must be None after reset"
        );
    }

    #[tokio::test]
    async fn reset_sync_state_errors_when_sync_not_configured() {
        let mut sync = make_sync();
        let err = sync.reset_sync_state().await.unwrap_err();
        assert!(
            err.to_string().contains("sync_id not set"),
            "expected 'sync_id not set' error, got: {err}"
        );
    }

    #[tokio::test]
    async fn reset_sync_state_only_clears_configured_sync_group() {
        let mut sync = make_sync();
        configure(&mut sync);
        // Seed both the configured group ("sync-1") and a foreign group.
        seed_all_tables(sync.storage(), "sync-1");
        seed_all_tables(sync.storage(), "sync-other");

        sync.reset_sync_state().await.unwrap();

        // Configured group is gone; foreign group is untouched.
        assert!(sync.storage().get_sync_metadata("sync-1").unwrap().is_none());
        assert!(sync.storage().list_device_records("sync-1").unwrap().is_empty());

        assert!(sync.storage().get_sync_metadata("sync-other").unwrap().is_some());
        assert!(!sync.storage().list_device_records("sync-other").unwrap().is_empty());
    }

    // ── partition_fields_into_batches ──

    /// Build a `SyncValue::String` whose `encode_value` form roughly matches a
    /// real base64-encoded image blob of `raw_bytes` raw bytes. (Encoded form
    /// adds JSON quotes; the test only relies on relative magnitudes so this
    /// approximation is fine.)
    fn image_value(raw_bytes: usize) -> SyncValue {
        // Real avatars/banners are base64-encoded by Dart before crossing
        // FFI, so the value is a ~4/3 expansion of the raw image. Build a
        // string of approximately the same size for the test.
        let expanded = (raw_bytes * 4).div_ceil(3);
        SyncValue::String("A".repeat(expanded))
    }

    #[test]
    fn partition_small_entity_returns_one_bucket() {
        let mut fields: HashMap<String, SyncValue> = HashMap::new();
        fields.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        fields.insert("pronouns".to_string(), SyncValue::String("she/her".to_string()));
        fields.insert("is_active".to_string(), SyncValue::Bool(true));

        let buckets = PrismSync::partition_fields_into_batches(
            &fields,
            "members",
            "ent-small",
            "a1b2c3d4e5f6",
            0,
        );

        assert_eq!(buckets.len(), 1);
        // All fields landed in the single bucket.
        let (only, batch_id) = &buckets[0];
        assert_eq!(only.len(), 3);
        for key in ["name", "pronouns", "is_active"] {
            assert!(only.contains_key(key), "missing {key}");
        }
        // Batch ID is a valid UUID.
        uuid::Uuid::parse_str(batch_id).expect("batch_id should be a UUID");
    }

    #[test]
    fn partition_empty_fields_returns_empty_vec() {
        let fields: HashMap<String, SyncValue> = HashMap::new();
        let buckets = PrismSync::partition_fields_into_batches(
            &fields,
            "members",
            "ent-empty",
            "device-empty",
            0,
        );
        assert!(buckets.is_empty());
    }

    #[test]
    fn partition_avatar_plus_banner_splits_into_multiple_buckets_each_under_target() {
        // Real-world worst case: avatar (256 KB raw) + banner (512 KB raw).
        // Combined plaintext exceeds 1 MB → must be split.
        let mut fields: HashMap<String, SyncValue> = HashMap::new();
        fields.insert("name".to_string(), SyncValue::String("Big System".to_string()));
        fields.insert("avatar".to_string(), image_value(256 * 1024));
        fields.insert("banner".to_string(), image_value(512 * 1024));

        let buckets = PrismSync::partition_fields_into_batches(
            &fields,
            "members",
            "ent-big",
            "a1b2c3d4e5f6",
            0,
        );

        assert!(
            buckets.len() >= 2,
            "avatar+banner should split into 2 or more buckets, got {}",
            buckets.len()
        );

        // Every produced bucket must measure under the target on its own.
        // Use the same placeholder HLC the partitioner uses so this is a
        // faithful re-measure of what the partitioner saw.
        let placeholder_hlc =
            format!("{:013}:{:010}:{}", u64::MAX % 10_000_000_000_000u64, u32::MAX, "a1b2c3d4e5f6");
        for (i, (bucket_fields, batch_id)) in buckets.iter().enumerate() {
            let ops: Vec<CrdtChange> = bucket_fields
                .iter()
                .map(|(name, value)| CrdtChange {
                    op_id: uuid::Uuid::new_v4().to_string(),
                    batch_id: Some(batch_id.clone()),
                    entity_id: "ent-big".to_string(),
                    entity_table: "members".to_string(),
                    field_name: name.clone(),
                    encoded_value: crate::schema::encode_value(value),
                    client_hlc: placeholder_hlc.clone(),
                    is_delete: false,
                    device_id: "a1b2c3d4e5f6".to_string(),
                    epoch: 0,
                    server_seq: None,
                })
                .collect();
            let body = estimate_envelope_body_size(&ops, HYBRID_SIGNATURE_WIRE_BYTES);
            assert!(
                body <= BATCH_BODY_TARGET_BYTES,
                "bucket {i} measured {body} > target {BATCH_BODY_TARGET_BYTES}",
            );
        }

        // The combined field set is preserved across all buckets — no field
        // is dropped or duplicated.
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for (bucket_fields, _) in &buckets {
            for key in bucket_fields.keys() {
                assert!(seen.insert(key), "field {key} appears in more than one bucket");
            }
        }
        assert_eq!(seen.len(), 3);
        for key in ["name", "avatar", "banner"] {
            assert!(seen.contains(key), "missing field {key} after partitioning");
        }
    }

    #[test]
    fn partition_single_oversized_field_gets_its_own_bucket() {
        // One field whose encoded value alone overflows the target. Greedy
        // packing places it in its own bucket; downstream guards decide
        // whether it actually fits on the wire.
        let mut fields: HashMap<String, SyncValue> = HashMap::new();
        // 950 KB raw -> ~1.25 MB JSON-encoded -> single-field envelope
        // estimate is well over BATCH_BODY_TARGET_BYTES.
        fields.insert("banner".to_string(), image_value(950 * 1024));
        fields.insert("name".to_string(), SyncValue::String("Megabig".to_string()));

        let buckets = PrismSync::partition_fields_into_batches(
            &fields,
            "members",
            "ent-mega",
            "a1b2c3d4e5f6",
            0,
        );

        // The oversized field must be alone in one bucket; the small field
        // gets its own bucket too (cannot be packed alongside oversize).
        assert!(
            buckets.len() >= 2,
            "expected 2 buckets (oversized alone + remainder), got {}",
            buckets.len(),
        );

        // The banner bucket has exactly one field.
        let banner_bucket =
            buckets.iter().find(|(b, _)| b.contains_key("banner")).expect("banner bucket present");
        assert_eq!(banner_bucket.0.len(), 1, "banner must be in a bucket alone");
        assert!(banner_bucket.0.contains_key("banner"));
    }

    #[test]
    fn partition_packs_all_small_fields_into_first_bucket_when_blob_present() {
        // Regression: with FFD-descending the first emitted partition for a
        // member create contained only the avatar blob, so the receiver's
        // UPSERT had NULL name/created_at and the row was silently dropped
        // by the non-strict apply path. Ascending order must land every
        // required NOT NULL column in partition 0 before the blob spills
        // into its own subsequent bucket.
        let mut fields: HashMap<String, SyncValue> = HashMap::new();
        // Small fields shaped like a real member create — all of these are
        // NOT NULL on the receiver's Drift schema.
        fields.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        fields.insert(
            "created_at".to_string(),
            SyncValue::String("2026-05-10T00:00:00Z".to_string()),
        );
        fields.insert("emoji".to_string(), SyncValue::String("\u{1F33C}".to_string()));
        fields.insert("is_active".to_string(), SyncValue::Bool(true));
        fields.insert("pronouns".to_string(), SyncValue::String("she/her".to_string()));
        fields.insert("custom_color".to_string(), SyncValue::String("#AF8EE9".to_string()));
        // One synthetic ~600 KB blob forces multi-partition splitting.
        fields.insert("avatar_image_data".to_string(), image_value(600 * 1024));

        let buckets = PrismSync::partition_fields_into_batches(
            &fields,
            "members",
            "ent-mem-1",
            "a1b2c3d4e5f6",
            0,
        );

        assert!(
            buckets.len() >= 2,
            "blob + small fields should split into 2+ buckets, got {}",
            buckets.len()
        );

        // Partition 0 (the one the relay receives first, since push order
        // is FIFO by created_at) must carry every small / NOT NULL field
        // so the receiver's initial UPSERT is a valid insert.
        let (first_fields, _) = &buckets[0];
        for required in ["name", "created_at", "emoji", "is_active", "pronouns", "custom_color"] {
            assert!(
                first_fields.contains_key(required),
                "partition 0 must contain required field {required} so receivers can insert \
                 the row without violating NOT NULL constraints; partition 0 = {:?}",
                first_fields.keys().collect::<Vec<_>>(),
            );
        }
        // The blob must NOT be in partition 0 — it spills to a later bucket.
        assert!(
            !first_fields.contains_key("avatar_image_data"),
            "the large blob must not occupy partition 0; partition 0 = {:?}",
            first_fields.keys().collect::<Vec<_>>(),
        );

        // The blob still ends up in *some* partition.
        let blob_bucket = buckets
            .iter()
            .find(|(b, _)| b.contains_key("avatar_image_data"))
            .expect("avatar_image_data must be present in some bucket");
        assert_eq!(
            blob_bucket.0.len(),
            1,
            "the large blob should be alone in its bucket; got {:?}",
            blob_bucket.0.keys().collect::<Vec<_>>(),
        );
    }

    #[test]
    fn partition_emits_unique_batch_ids_per_bucket() {
        let mut fields: HashMap<String, SyncValue> = HashMap::new();
        fields.insert("avatar".to_string(), image_value(256 * 1024));
        fields.insert("banner".to_string(), image_value(512 * 1024));

        let buckets = PrismSync::partition_fields_into_batches(
            &fields,
            "members",
            "ent-uuid",
            "deviceXYZ",
            3,
        );

        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (_, batch_id) in &buckets {
            assert!(seen.insert(batch_id.clone()), "duplicate batch_id detected: {batch_id}");
            uuid::Uuid::parse_str(batch_id).expect("batch_id should be a UUID");
        }
    }

    // ── Phase 1C: repair_quarantined_batches ──

    /// Construct a `PendingOp` with predictable defaults. The `encoded_value`
    /// is what drives partitioning size, so the test passes the bytes
    /// inline.
    fn pending_op(
        op_id: &str,
        sync_id: &str,
        local_batch_id: &str,
        field_name: &str,
        encoded_value: String,
    ) -> PendingOp {
        PendingOp {
            op_id: op_id.to_string(),
            sync_id: sync_id.to_string(),
            epoch: 1,
            device_id: "dev-c1".to_string(),
            local_batch_id: local_batch_id.to_string(),
            entity_table: "members".to_string(),
            entity_id: "ent-1c".to_string(),
            field_name: field_name.to_string(),
            encoded_value,
            is_delete: false,
            client_hlc: format!("{:013}:{:010}:dev-c1", 1_700_000_000_000u64, 42u32),
            created_at: chrono::Utc::now(),
            pushed_at: None,
        }
    }

    /// Insert pending ops + a matching push_quarantine row directly into the
    /// configured sync's storage, bypassing the consumer API. Mirrors what
    /// the user's DB looks like after the broken sync attempts in the bug
    /// report.
    fn seed_quarantined_batch(
        sync: &PrismSync,
        sync_id: &str,
        batch_id: &str,
        ops: &[PendingOp],
        body_bytes: i64,
    ) {
        let mut tx = sync.storage().begin_tx().unwrap();
        for op in ops {
            tx.insert_pending_op(op).unwrap();
        }
        tx.quarantine_batch(
            sync_id,
            batch_id,
            "members",
            "ent-1c",
            body_bytes,
            "payload_too_large",
            "envelope exceeded relay cap",
        )
        .unwrap();
        tx.commit().unwrap();
    }

    /// Build an `encoded_value` shaped like a base64 image blob (`\"AAAA…\"`)
    /// whose total length matches `raw_bytes * 4 / 3 + 2` (for the surrounding
    /// JSON quotes).
    fn image_encoded(raw_bytes: usize) -> String {
        let expanded = (raw_bytes * 4).div_ceil(3);
        format!("\"{}\"", "A".repeat(expanded))
    }

    /// A field_version marking `winning_op_id` as the current LWW winner for
    /// `field`. Mirrors what `emit_update` writes alongside a local op.
    fn field_version(sync_id: &str, field: &str, winning_op_id: &str) -> crate::storage::FieldVersion {
        crate::storage::FieldVersion {
            sync_id: sync_id.to_string(),
            entity_table: "members".to_string(),
            entity_id: "ent-1c".to_string(),
            field_name: field.to_string(),
            winning_op_id: winning_op_id.to_string(),
            winning_device_id: "dev-c1".to_string(),
            winning_hlc: format!("{:013}:{:010}:dev-c1", 1_700_000_000_000u64, 42u32),
            winning_encoded_value: None,
            updated_at: chrono::Utc::now(),
        }
    }

    /// Every still-unpushed op id, across all (repartitioned) batches.
    fn unpushed_op_ids(sync: &PrismSync, sync_id: &str) -> std::collections::HashSet<String> {
        let mut ids = std::collections::HashSet::new();
        for bid in sync.storage().get_unpushed_batch_ids(sync_id).unwrap() {
            let tx = sync.storage().begin_tx().unwrap();
            for op in tx.load_batch_ops(&bid).unwrap() {
                ids.insert(op.op_id);
            }
        }
        ids
    }

    #[test]
    fn repair_quarantined_batches_repartitions_oversized_batch_preserving_op_fields() {
        let mut sync = make_sync();
        configure(&mut sync);

        // One oversized batch: small name op + two huge image-blob ops that
        // together overshoot the 950 KB partition target.
        let sync_id = "sync-1";
        let original_batch_id = "stuck-batch";
        let op_name =
            pending_op("op-name", sync_id, original_batch_id, "name", "\"Big System\"".to_string());
        let op_avatar = pending_op(
            "op-avatar",
            sync_id,
            original_batch_id,
            "avatar",
            image_encoded(500 * 1024),
        );
        let op_banner = pending_op(
            "op-banner",
            sync_id,
            original_batch_id,
            "banner",
            image_encoded(500 * 1024),
        );
        let ops = vec![op_name.clone(), op_avatar.clone(), op_banner.clone()];

        seed_quarantined_batch(&sync, sync_id, original_batch_id, &ops, 1_400_000);

        // Sanity: pre-repair, the batch is hidden from the unpushed-batch query
        // and the quarantine count is 1.
        assert!(sync.storage().get_unpushed_batch_ids(sync_id).unwrap().is_empty());
        assert_eq!(sync.storage().quarantined_batch_count(sync_id).unwrap(), 1);

        let repaired = sync.repair_quarantined_batches().expect("repair ok");
        assert_eq!(repaired, 1);

        // The quarantine row is gone.
        assert_eq!(sync.storage().quarantined_batch_count(sync_id).unwrap(), 0);

        // The pending_ops rows now appear under at least two different
        // local_batch_ids — the partitioner split the oversized batch.
        let post_ops_name = sync.storage().load_batch_ops(original_batch_id).unwrap_or_default();
        assert!(
            post_ops_name.is_empty(),
            "ops should have been moved off the original batch_id, found {post_ops_name:?}"
        );

        // The post-repair unpushed-batch list contains at least one batch_id
        // distinct from the quarantined original.
        let post_batches = sync.storage().get_unpushed_batch_ids(sync_id).unwrap();
        assert!(
            !post_batches.is_empty(),
            "unpushed batches should resurface after repair, got {post_batches:?}"
        );
        assert!(
            post_batches.iter().all(|b| b != original_batch_id),
            "no surviving op should still carry the original batch_id, got {post_batches:?}"
        );

        // Every op preserves every field except `local_batch_id`. Verify by
        // looking up each op in its new batch and comparing the immutable
        // columns.
        let mut new_ops_by_id: std::collections::HashMap<String, PendingOp> =
            std::collections::HashMap::new();
        for bid in &post_batches {
            for op in sync.storage().load_batch_ops(bid).unwrap() {
                new_ops_by_id.insert(op.op_id.clone(), op);
            }
        }
        assert_eq!(new_ops_by_id.len(), 3, "all three ops must survive");

        for original in [&op_name, &op_avatar, &op_banner] {
            let post = new_ops_by_id.remove(&original.op_id).expect("op preserved");
            assert_eq!(post.op_id, original.op_id);
            assert_eq!(post.sync_id, original.sync_id);
            assert_eq!(post.epoch, original.epoch);
            assert_eq!(post.device_id, original.device_id);
            assert_eq!(post.entity_table, original.entity_table);
            assert_eq!(post.entity_id, original.entity_id);
            assert_eq!(post.field_name, original.field_name);
            assert_eq!(post.encoded_value, original.encoded_value);
            assert_eq!(post.is_delete, original.is_delete);
            assert_eq!(post.client_hlc, original.client_hlc);
            assert_eq!(post.created_at, original.created_at);
            assert_eq!(post.pushed_at, original.pushed_at);
            assert_ne!(
                post.local_batch_id, original.local_batch_id,
                "local_batch_id should have been rewritten"
            );
        }
    }

    #[test]
    fn repair_quarantined_batches_idempotent_no_op_when_empty() {
        let mut sync = make_sync();
        configure(&mut sync);

        // First call with nothing quarantined: returns 0.
        assert_eq!(sync.repair_quarantined_batches().unwrap(), 0);
        // Second call still 0.
        assert_eq!(sync.repair_quarantined_batches().unwrap(), 0);
    }

    #[test]
    fn repair_quarantined_batches_second_run_is_noop_after_successful_repair() {
        let mut sync = make_sync();
        configure(&mut sync);

        let sync_id = "sync-1";
        let original_batch_id = "stuck-batch-2";
        // Each op is individually pushable (its own envelope is under the cap),
        // so the batch is genuinely repairable — repartitioning yields pushable
        // sub-batches and the quarantine clears.
        let ops = vec![
            pending_op("op-name-2", sync_id, original_batch_id, "name", "\"Sys2\"".to_string()),
            pending_op(
                "op-banner-2",
                sync_id,
                original_batch_id,
                "banner",
                image_encoded(400 * 1024),
            ),
        ];
        seed_quarantined_batch(&sync, sync_id, original_batch_id, &ops, 1_200_000);

        assert_eq!(sync.repair_quarantined_batches().unwrap(), 1);
        // Second call: nothing in push_quarantine, returns 0.
        assert_eq!(sync.repair_quarantined_batches().unwrap(), 0);
        assert_eq!(sync.storage().quarantined_batch_count(sync_id).unwrap(), 0);
    }

    #[test]
    fn repair_drops_a_superseded_quarantined_op_and_clears_the_banner() {
        let mut sync = make_sync();
        configure(&mut sync);

        let sync_id = "sync-1";
        let stuck_batch = "stuck-avatar-batch";
        // A stuck oversized avatar op (won't fit one envelope on its own).
        let stuck = vec![pending_op(
            "op-avatar-old",
            sync_id,
            stuck_batch,
            "avatar_image_data",
            image_encoded(900 * 1024),
        )];
        seed_quarantined_batch(&sync, sync_id, stuck_batch, &stuck, 1_400_000);

        // A later re-emit of the SAME field (e.g. the re-normalized avatar) with
        // a newer HLC, in its own un-quarantined batch.
        let mut newer = pending_op(
            "op-avatar-new",
            sync_id,
            "fresh-batch",
            "avatar_image_data",
            image_encoded(200 * 1024),
        );
        newer.client_hlc = format!("{:013}:{:010}:dev-c1", 1_700_000_009_000u64, 0u32);
        // The re-emit also moves the field's winning version to the new op —
        // which is what repair keys off (record_update upserts this locally).
        let fv = crate::storage::FieldVersion {
            sync_id: sync_id.to_string(),
            entity_table: "members".to_string(),
            entity_id: "ent-1c".to_string(),
            field_name: "avatar_image_data".to_string(),
            winning_op_id: "op-avatar-new".to_string(),
            winning_device_id: "dev-c1".to_string(),
            winning_hlc: newer.client_hlc.clone(),
            winning_encoded_value: Some(image_encoded(200 * 1024)),
            updated_at: chrono::Utc::now(),
        };
        {
            let mut tx = sync.storage().begin_tx().unwrap();
            tx.insert_pending_op(&newer).unwrap();
            tx.upsert_field_version(&fv).unwrap();
            tx.commit().unwrap();
        }

        // Repair drops the superseded oversized op and clears the quarantine.
        assert_eq!(sync.repair_quarantined_batches().unwrap(), 1);
        assert_eq!(sync.storage().quarantined_batch_count(sync_id).unwrap(), 0);

        // The newer op survives and is unpushed (it will push normally).
        let unpushed = sync.storage().get_unpushed_batch_ids(sync_id).unwrap();
        assert!(
            unpushed.contains(&"fresh-batch".to_string()),
            "the re-normalized op should remain pushable (was: {unpushed:?})"
        );
        // The superseded op is gone.
        assert!(sync.storage().begin_tx().unwrap().load_batch_ops(stuck_batch).unwrap().is_empty());
    }

    #[test]
    fn repair_leaves_a_single_unsplittable_op_quarantined() {
        let mut sync = make_sync();
        configure(&mut sync);

        let sync_id = "sync-1";
        let stuck_batch = "stuck-unsplittable";
        // One op whose own envelope exceeds the cap and nothing supersedes it —
        // repair can't fix it, so it must stay quarantined (no oscillation) and
        // not be counted as repaired.
        let ops = vec![pending_op(
            "op-huge",
            sync_id,
            stuck_batch,
            "avatar_image_data",
            image_encoded(900 * 1024),
        )];
        seed_quarantined_batch(&sync, sync_id, stuck_batch, &ops, 1_400_000);
        // This op is still the field's winner (nothing superseded it), so repair
        // must not drop it — it just can't be made to fit.
        {
            let mut tx = sync.storage().begin_tx().unwrap();
            tx.upsert_field_version(&crate::storage::FieldVersion {
                sync_id: sync_id.to_string(),
                entity_table: "members".to_string(),
                entity_id: "ent-1c".to_string(),
                field_name: "avatar_image_data".to_string(),
                winning_op_id: "op-huge".to_string(),
                winning_device_id: "dev-c1".to_string(),
                winning_hlc: format!("{:013}:{:010}:dev-c1", 1_700_000_000_000u64, 42u32),
                winning_encoded_value: Some(image_encoded(900 * 1024)),
                updated_at: chrono::Utc::now(),
            })
            .unwrap();
            tx.commit().unwrap();
        }

        assert_eq!(sync.repair_quarantined_batches().unwrap(), 0);
        assert_eq!(sync.storage().quarantined_batch_count(sync_id).unwrap(), 1);
        // Still excluded from the push set, so it doesn't churn.
        let unpushed = sync.storage().get_unpushed_batch_ids(sync_id).unwrap();
        assert!(!unpushed.contains(&stuck_batch.to_string()));
        // And it was NOT deleted — a stuck winner stays in its quarantined
        // batch (excluded from the push set, but never lost).
        let still_there =
            sync.storage().begin_tx().unwrap().load_batch_ops(stuck_batch).unwrap();
        assert!(still_there.iter().any(|o| o.op_id == "op-huge"));
    }

    #[test]
    fn repair_preserves_winner_ops_when_repartitioning_a_splittable_batch() {
        // The dangerous regression: repair must NEVER drop an op that is still
        // the field's winner. Two winner ops, each individually pushable but
        // together over the cap, must both SURVIVE the repartition.
        let mut sync = make_sync();
        configure(&mut sync);

        let sync_id = "sync-1";
        let stuck_batch = "splittable-winners";
        let ops = vec![
            pending_op("op-a", sync_id, stuck_batch, "field_a", image_encoded(400 * 1024)),
            pending_op("op-b", sync_id, stuck_batch, "field_b", image_encoded(400 * 1024)),
        ];
        seed_quarantined_batch(&sync, sync_id, stuck_batch, &ops, 1_300_000);
        {
            let mut tx = sync.storage().begin_tx().unwrap();
            tx.upsert_field_version(&field_version(sync_id, "field_a", "op-a")).unwrap();
            tx.upsert_field_version(&field_version(sync_id, "field_b", "op-b")).unwrap();
            tx.commit().unwrap();
        }

        assert_eq!(sync.repair_quarantined_batches().unwrap(), 1);
        assert_eq!(sync.storage().quarantined_batch_count(sync_id).unwrap(), 0);
        // Both winners survive (repartitioned, never deleted) and are pushable.
        let survivors = unpushed_op_ids(&sync, sync_id);
        assert!(survivors.contains("op-a"), "op-a must survive repair");
        assert!(survivors.contains("op-b"), "op-b must survive repair");
    }

    #[test]
    fn repair_drops_only_the_superseded_op_in_a_mixed_batch() {
        // A batch holding one stale (superseded) op and one still-winning op:
        // only the superseded one is dropped; the winner is preserved and pushed.
        let mut sync = make_sync();
        configure(&mut sync);

        let sync_id = "sync-1";
        let stuck_batch = "mixed-batch";
        let ops = vec![
            pending_op("op-keep", sync_id, stuck_batch, "name", "\"Sys\"".to_string()),
            pending_op(
                "op-drop",
                sync_id,
                stuck_batch,
                "avatar_image_data",
                image_encoded(900 * 1024),
            ),
        ];
        seed_quarantined_batch(&sync, sync_id, stuck_batch, &ops, 1_400_000);
        {
            let mut tx = sync.storage().begin_tx().unwrap();
            // `name` winner is op-keep itself; `avatar` has moved on to a newer op.
            tx.upsert_field_version(&field_version(sync_id, "name", "op-keep")).unwrap();
            tx.upsert_field_version(&field_version(sync_id, "avatar_image_data", "op-newer"))
                .unwrap();
            tx.commit().unwrap();
        }

        assert_eq!(sync.repair_quarantined_batches().unwrap(), 1);
        assert_eq!(sync.storage().quarantined_batch_count(sync_id).unwrap(), 0);
        let remaining = unpushed_op_ids(&sync, sync_id);
        assert!(remaining.contains("op-keep"), "the winning op must be preserved");
        assert!(!remaining.contains("op-drop"), "the superseded op must be dropped");
    }

    #[test]
    fn repair_quarantined_batches_handles_orphan_quarantine_row_without_panic() {
        let mut sync = make_sync();
        configure(&mut sync);

        let sync_id = "sync-1";
        let orphan_batch_id = "orphan-batch";
        // Insert ONLY a quarantine row — no pending_ops. This models the
        // case where ops were pushed-and-deleted by an earlier sync cycle
        // but the quarantine row slipped past cleanup.
        {
            let mut tx = sync.storage().begin_tx().unwrap();
            tx.quarantine_batch(
                sync_id,
                orphan_batch_id,
                "members",
                "ent-orphan",
                500_000,
                "payload_too_large",
                "orphan diagnostics",
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let repaired = sync.repair_quarantined_batches().expect("orphan handling ok");
        assert_eq!(repaired, 1, "orphan row should count as repaired");
        assert_eq!(sync.storage().quarantined_batch_count(sync_id).unwrap(), 0);
    }

    #[test]
    fn repair_quarantined_batches_rolls_back_when_storage_errors_midflight() {
        // Mirror the FailingStorage pattern from op_emitter tests: wrap the
        // real storage in a test-only `SyncStorage` that injects a failure
        // on the Nth call to `update_pending_op_batch_id`. We then verify
        // the transaction rolled back — the quarantine row is still there
        // and the pending_ops rows still carry the original local_batch_id.
        let schema = SyncSchema::builder()
            .entity("members", |e| {
                e.field("name", SyncType::String)
                    .field("avatar", SyncType::String)
                    .field("banner", SyncType::String)
            })
            .build();
        let real_storage = RusqliteSyncStorage::in_memory().expect("in-memory storage");
        let failing = Arc::new(RepairFailingStorage::new(real_storage));
        let secure_store = Arc::new(MemStore::default());

        let mut sync = PrismSync::builder()
            .schema(schema)
            .storage(failing.clone())
            .secure_store(secure_store)
            .build()
            .expect("build ok");
        configure(&mut sync);

        let sync_id = "sync-1";
        let original_batch_id = "stuck-batch-3";
        let op_name =
            pending_op("op-name-3", sync_id, original_batch_id, "name", "\"Sys3\"".to_string());
        let op_avatar = pending_op(
            "op-avatar-3",
            sync_id,
            original_batch_id,
            "avatar",
            image_encoded(500 * 1024),
        );
        let op_banner = pending_op(
            "op-banner-3",
            sync_id,
            original_batch_id,
            "banner",
            image_encoded(500 * 1024),
        );
        let ops = vec![op_name.clone(), op_avatar.clone(), op_banner.clone()];

        // Use a fresh tx through the real storage to seed (the wrapper
        // forwards `begin_tx` and the wrapper's update-counter only trips
        // during the repair call below).
        {
            let mut tx = failing.begin_tx().unwrap();
            for op in &ops {
                tx.insert_pending_op(op).unwrap();
            }
            tx.quarantine_batch(
                sync_id,
                original_batch_id,
                "members",
                "ent-1c",
                1_400_000,
                "payload_too_large",
                "trip-mid-repair",
            )
            .unwrap();
            tx.commit().unwrap();
        }

        // Fail on the second `update_pending_op_batch_id` call so the
        // first one succeeds (proving the rollback actually undoes a
        // partial mutation, not a no-op).
        failing.fail_on_update_at(2);

        let err =
            sync.repair_quarantined_batches().expect_err("repair must propagate the storage error");
        assert!(err.to_string().contains("repair-failure"), "unexpected error: {err}");

        // The quarantine row survives untouched — rollback restored it.
        assert_eq!(failing.quarantined_batch_count(sync_id).unwrap(), 1);

        // The pending_ops rows still belong to the original batch_id.
        let still_in_orig = failing.load_batch_ops(original_batch_id).unwrap();
        assert_eq!(
            still_in_orig.len(),
            3,
            "all 3 ops must remain under the original batch_id after rollback"
        );
        let mut by_id: std::collections::HashMap<&str, &PendingOp> =
            std::collections::HashMap::new();
        for op in &still_in_orig {
            by_id.insert(op.op_id.as_str(), op);
        }
        for original in [&op_name, &op_avatar, &op_banner] {
            let post = by_id.remove(original.op_id.as_str()).expect("op present");
            assert_eq!(post.local_batch_id, original_batch_id);
            assert_eq!(post.encoded_value, original.encoded_value);
            assert_eq!(post.client_hlc, original.client_hlc);
            assert_eq!(post.device_id, original.device_id);
            assert_eq!(post.epoch, original.epoch);
        }
    }

    // Test-only wrapper that injects a failure on the Nth call to
    // `update_pending_op_batch_id`, to verify Phase 1C rollback semantics.
    struct RepairFailingStorage {
        inner: std::sync::Arc<RusqliteSyncStorage>,
        fail_at: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        seen: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl RepairFailingStorage {
        fn new(inner: RusqliteSyncStorage) -> Self {
            Self {
                inner: std::sync::Arc::new(inner),
                fail_at: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                seen: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }
        }

        fn fail_on_update_at(&self, ordinal: usize) {
            self.fail_at.store(ordinal, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl SyncStorage for RepairFailingStorage {
        fn begin_tx(&self) -> Result<Box<dyn crate::storage::SyncStorageTx + '_>> {
            let inner_tx = self.inner.begin_tx()?;
            Ok(Box::new(RepairFailingTx {
                inner: inner_tx,
                fail_at: self.fail_at.clone(),
                seen: self.seen.clone(),
            }))
        }

        fn get_sync_metadata(&self, sync_id: &str) -> Result<Option<crate::storage::SyncMetadata>> {
            self.inner.get_sync_metadata(sync_id)
        }

        fn get_unpushed_batch_ids(&self, sync_id: &str) -> Result<Vec<String>> {
            self.inner.get_unpushed_batch_ids(sync_id)
        }

        fn load_batch_ops(&self, batch_id: &str) -> Result<Vec<PendingOp>> {
            self.inner.load_batch_ops(batch_id)
        }

        fn is_op_applied(&self, op_id: &str) -> Result<bool> {
            self.inner.is_op_applied(op_id)
        }

        fn get_field_version(
            &self,
            sync_id: &str,
            table: &str,
            entity_id: &str,
            field: &str,
        ) -> Result<Option<crate::storage::FieldVersion>> {
            self.inner.get_field_version(sync_id, table, entity_id, field)
        }

        fn list_quarantined_batches(
            &self,
            sync_id: &str,
        ) -> Result<Vec<crate::storage::QuarantinedBatchInfo>> {
            self.inner.list_quarantined_batches(sync_id)
        }

        fn quarantined_batch_count(&self, sync_id: &str) -> Result<i64> {
            self.inner.quarantined_batch_count(sync_id)
        }

        fn get_device_record(
            &self,
            sync_id: &str,
            device_id: &str,
        ) -> Result<Option<crate::storage::DeviceRecord>> {
            self.inner.get_device_record(sync_id, device_id)
        }

        fn list_device_records(&self, sync_id: &str) -> Result<Vec<crate::storage::DeviceRecord>> {
            self.inner.list_device_records(sync_id)
        }

        fn export_snapshot(&self, sync_id: &str) -> Result<Vec<u8>> {
            self.inner.export_snapshot(sync_id)
        }

        fn rekey(&self, new_key: &[u8; 32]) -> Result<()> {
            self.inner.rekey(new_key)
        }
    }

    struct RepairFailingTx<'a> {
        inner: Box<dyn crate::storage::SyncStorageTx + 'a>,
        fail_at: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        seen: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl crate::storage::SyncStorageTx for RepairFailingTx<'_> {
        fn is_op_applied(&self, op_id: &str) -> Result<bool> {
            self.inner.is_op_applied(op_id)
        }

        fn get_field_version(
            &self,
            sync_id: &str,
            table: &str,
            entity_id: &str,
            field: &str,
        ) -> Result<Option<crate::storage::FieldVersion>> {
            self.inner.get_field_version(sync_id, table, entity_id, field)
        }

        fn get_device_record(
            &self,
            sync_id: &str,
            device_id: &str,
        ) -> Result<Option<crate::storage::DeviceRecord>> {
            self.inner.get_device_record(sync_id, device_id)
        }

        fn upsert_sync_metadata(&mut self, meta: &crate::storage::SyncMetadata) -> Result<()> {
            self.inner.upsert_sync_metadata(meta)
        }

        fn update_last_pulled_seq(&mut self, sync_id: &str, seq: i64) -> Result<()> {
            self.inner.update_last_pulled_seq(sync_id, seq)
        }

        fn update_last_successful_sync(&mut self, sync_id: &str) -> Result<()> {
            self.inner.update_last_successful_sync(sync_id)
        }

        fn update_current_epoch(&mut self, sync_id: &str, epoch: i32) -> Result<()> {
            self.inner.update_current_epoch(sync_id, epoch)
        }

        fn update_last_imported_registry_version(
            &mut self,
            sync_id: &str,
            version: i64,
        ) -> Result<()> {
            self.inner.update_last_imported_registry_version(sync_id, version)
        }

        fn insert_pending_op(&mut self, op: &PendingOp) -> Result<()> {
            self.inner.insert_pending_op(op)
        }

        fn mark_batch_pushed(&mut self, batch_id: &str) -> Result<()> {
            self.inner.mark_batch_pushed(batch_id)
        }

        fn delete_pushed_ops(&mut self, sync_id: &str, batch_id: &str) -> Result<()> {
            self.inner.delete_pushed_ops(sync_id, batch_id)
        }

        fn load_batch_ops(&self, batch_id: &str) -> Result<Vec<PendingOp>> {
            self.inner.load_batch_ops(batch_id)
        }

        fn update_pending_op_batch_id(&mut self, op_id: &str, new_batch_id: &str) -> Result<()> {
            let next = self.seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            let trip = self.fail_at.load(std::sync::atomic::Ordering::SeqCst);
            if trip != 0 && next == trip {
                return Err(CoreError::Storage(crate::storage::StorageError::Logic(
                    "repair-failure injected".to_string(),
                )));
            }
            self.inner.update_pending_op_batch_id(op_id, new_batch_id)
        }

        fn insert_applied_op(&mut self, op: &crate::storage::AppliedOp) -> Result<()> {
            self.inner.insert_applied_op(op)
        }

        fn upsert_field_version(&mut self, fv: &crate::storage::FieldVersion) -> Result<()> {
            self.inner.upsert_field_version(fv)
        }

        fn quarantine_batch(
            &mut self,
            sync_id: &str,
            batch_id: &str,
            entity_table: &str,
            entity_id: &str,
            body_bytes: i64,
            error_code: &str,
            error_message: &str,
        ) -> Result<()> {
            self.inner.quarantine_batch(
                sync_id,
                batch_id,
                entity_table,
                entity_id,
                body_bytes,
                error_code,
                error_message,
            )
        }

        fn unquarantine_batch(&mut self, sync_id: &str, batch_id: &str) -> Result<()> {
            self.inner.unquarantine_batch(sync_id, batch_id)
        }

        fn upsert_device_record(&mut self, device: &crate::storage::DeviceRecord) -> Result<()> {
            self.inner.upsert_device_record(device)
        }

        fn remove_device_record(&mut self, sync_id: &str, device_id: &str) -> Result<()> {
            self.inner.remove_device_record(sync_id, device_id)
        }

        fn clear_sync_state(&mut self, sync_id: &str) -> Result<()> {
            self.inner.clear_sync_state(sync_id)
        }

        fn import_snapshot(&mut self, sync_id: &str, data: &[u8]) -> Result<u64> {
            self.inner.import_snapshot(sync_id, data)
        }

        fn commit(self: Box<Self>) -> Result<()> {
            self.inner.commit()
        }

        fn rollback(self: Box<Self>) -> Result<()> {
            self.inner.rollback()
        }
    }
}
