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

use crate::clock_drift::{ClockConfidence, MAX_CLOCK_DRIFT_MS};
use crate::crdt_change::{estimate_envelope_body_size, CrdtChange};
use crate::device_registry::DeviceRegistryManager;
use crate::engine::{BootstrapReport, SeedRecord, SyncConfig, SyncEngine};
use crate::epoch::EpochManager;
use crate::error::{CoreError, Result};
use crate::events::{event_channel, EntityChange, SyncEvent};
use crate::hlc::Hlc;
use crate::op_emitter::{DivergentMode, OpEmitter, DELETED_FIELD};
use crate::pairing::{
    compute_epoch_key_hash, RegistrySnapshotEntry, SignedRegistrySnapshot,
    SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
};
use crate::recovery::{commit_recovered_epoch_material, KeyHierarchyRecoverer};
use crate::registry_publish;
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

/// Result of a **signature-verified** self-revocation check.
///
/// Produced by [`PrismSync::confirm_self_revocation`]. This is the single
/// authenticated answer to "has THIS device been revoked?" — derived only from
/// a verified signed registry, never from a relay WebSocket frame or error
/// string (those are untrusted hints; see H3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfRevocationStatus {
    /// The verified signed registry contains an explicit entry for this device
    /// with `status == "revoked"`. The only state in which a caller may take a
    /// destructive action.
    ///
    /// `remote_wipe` is the admin-authenticated wipe intent read from the SAME
    /// signature-verified entry (H3 Layer B). It is `true` only when an admin
    /// signed a `revoked` entry for this device with `remote_wipe == true`;
    /// it defaults to `false` for older snapshots that omit the bit. Callers
    /// MUST drive any data wipe from this verified bit, never from a
    /// relay-controlled WS frame / error body.
    ConfirmedRevoked { remote_wipe: bool },
    /// The verified signed registry lists this device with a non-revoked
    /// status. Definitely NOT revoked — a false-revoke hint should be ignored.
    Active,
    /// Inconclusive: no signed registry could be fetched or verified, the relay
    /// errored, or this device was absent from the verified snapshot. Fail-safe
    /// — callers must NOT wipe or clear credentials.
    Unknown,
}

impl SelfRevocationStatus {
    /// Stable string form crossing the FFI boundary.
    ///
    /// Note: this collapses [`Self::ConfirmedRevoked`] to `"revoked"` and
    /// discards the wipe bit; prefer [`Self::to_json`] for the FFI surface so
    /// the verified `remote_wipe` intent reaches the Dart caller.
    pub fn as_str(self) -> &'static str {
        match self {
            SelfRevocationStatus::ConfirmedRevoked { .. } => "revoked",
            SelfRevocationStatus::Active => "active",
            SelfRevocationStatus::Unknown => "unknown",
        }
    }

    /// JSON form crossing the FFI boundary (H3 Layer B).
    ///
    /// - `{"status":"revoked","remote_wipe":<bool>}` — the verified wipe intent.
    /// - `{"status":"active"}`
    /// - `{"status":"unknown"}`
    ///
    /// Keeping this a plain JSON string preserves the `Result<String, String>`
    /// FFI signature, so no flutter_rust_bridge type regeneration is required.
    pub fn to_json(self) -> String {
        match self {
            SelfRevocationStatus::ConfirmedRevoked { remote_wipe } => {
                format!("{{\"status\":\"revoked\",\"remote_wipe\":{remote_wipe}}}")
            }
            SelfRevocationStatus::Active => "{\"status\":\"active\"}".to_string(),
            SelfRevocationStatus::Unknown => "{\"status\":\"unknown\"}".to_string(),
        }
    }
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
            clock_confidence: ClockConfidence::new(),
        })
    }
}

/// Whether an origin-stamped mutation is a create or an update — the two share
/// `record_mutation_at`'s body and differ only in which emitter method runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MutationKind {
    Create,
    Update,
}

/// A confirmed forward HLC clock excursion: the over-bound self-authored
/// `field_versions` winners that the repair re-emits, plus the peak drift.
struct ClockExcursion {
    device_id: String,
    sync_id: String,
    future_rows: Vec<crate::storage::FieldVersion>,
    max_drift_ms: i64,
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
    /// Stamped whenever a sync cycle completes a successful signed relay
    /// exchange; gates the excursion repair so it never fires during a
    /// backward clock step (where the relay 401s and this stays
    /// stale).
    clock_confidence: ClockConfidence,
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
        let signed_exchange_validated =
            matches!(&result, Ok(r) if r.signed_exchange_validated);
        self.note_signed_exchange_and_repair_clock(signed_exchange_validated);
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

        // Ratchet-on-verified-read: the registry just verified, so advance
        // our freshness baseline to its embedded `registry_version` regardless of
        // whether the epoch catch-up below succeeds. This covers the relay-ahead
        // path (relay_epoch > local_epoch); the steady-state path ratchets in
        // repair_signed_registry_epoch_if_needed. Best-effort and non-fatal, and
        // uses the VERIFIED embedded version, never the relay response's claimed
        // version. (Sub-floor versions are no-oped by the helper, so this is safe
        // to call before the floor check below.)
        if let Err(error) = registry_publish::ratchet_last_imported_registry_version(
            self.storage.as_ref(),
            &sync_id,
            snapshot.registry_version,
        ) {
            tracing::warn!(
                error = %error,
                registry_version = snapshot.registry_version,
                "catch_up_epoch_keys: failed to ratchet baseline on verified read"
            );
        }

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

    /// Determine whether THIS device has been revoked, according to a
    /// **signature-verified** signed registry snapshot.
    ///
    /// # Security (H3)
    ///
    /// The relay's `device_revoked` WebSocket frame and any relay error string
    /// are UNTRUSTED HINTS. They must never, on their own, drive a destructive
    /// action (local-data wipe or credential clear). This method is the single
    /// authenticated source of truth for self-revocation: it fetches the signed
    /// registry, verifies its hybrid signature against the device's
    /// pinned/SAS-anchored registry (the same machinery the epoch catch-up
    /// uses), and only then inspects this device's entry.
    ///
    /// ## Freshness gate (replay defense)
    ///
    /// Signature verification alone does not prove a snapshot is *current* — a
    /// malicious relay can replay an OLD, validly-signed snapshot in which this
    /// device was marked `revoked` (relevant after a revoke → re-pair under the
    /// same `device_id`). Before returning `ConfirmedRevoked` we therefore
    /// compare the verified snapshot's `registry_version` against this device's
    /// locally-recorded last-imported version
    /// (`SyncMetadata::last_imported_registry_version`, the SAME baseline
    /// `verify_and_import_signed_registry` checks). A snapshot strictly older
    /// than that baseline is treated as stale/replayed → `Unknown`
    /// (non-destructive). When no baseline is recorded (a freshly paired or
    /// snapshot-restored device that has not yet imported/published a registry)
    /// staleness cannot be proven, so we ALSO fail safe to `Unknown` and refuse
    /// the destructive confirmation — a stale validly-signed replay must never
    /// wipe a device that merely lacks a baseline. A genuine revocation
    /// still confirms because the revoke publisher emits a positive `revoked`-self entry at a
    /// version above any prior artifact, and the baseline self-heals (monotonic
    /// ratchet) on the device's next registry import or publish. This is a
    /// read-only check: it never imports.
    ///
    /// Returns:
    /// - [`SelfRevocationStatus::ConfirmedRevoked`] only when the verified,
    ///   non-stale snapshot contains an explicit entry for this device with
    ///   `status == "revoked"`. We deliberately require an explicit revoked
    ///   entry rather than treating absence as removal: a relay that omits our
    ///   entry, or serves a stale snapshot from before we joined, must not be
    ///   able to fabricate a revocation.
    /// - [`SelfRevocationStatus::Active`] when the verified snapshot lists this
    ///   device with a non-revoked status.
    /// - [`SelfRevocationStatus::Unknown`] in every fail-safe case: no relay
    ///   configured, no device_id/sync_id, no signed registry available,
    ///   signature verification failed, a relay error, a stale/replayed
    ///   snapshot, or our entry is simply absent. `Unknown` is non-destructive
    ///   — callers preserve credentials and relay config so the engine can
    ///   self-heal from transient blips.
    pub async fn confirm_self_revocation(&self) -> SelfRevocationStatus {
        let relay = match self.sync_service.relay() {
            Some(r) => r.clone(),
            None => {
                tracing::debug!("confirm_self_revocation: unknown (no relay configured)");
                return SelfRevocationStatus::Unknown;
            }
        };
        let device_id = match self.device_id.as_deref() {
            Some(d) => d.to_string(),
            None => {
                tracing::debug!("confirm_self_revocation: unknown (no device_id)");
                return SelfRevocationStatus::Unknown;
            }
        };
        let sync_id = match self.sync_service.sync_id() {
            Some(s) => s.to_string(),
            None => {
                tracing::debug!("confirm_self_revocation: unknown (no sync_id)");
                return SelfRevocationStatus::Unknown;
            }
        };

        // A revoked device can still fetch the SIGNED REGISTRY: the relay
        // auth middleware allowlists exactly `GET /v1/sync/{sync_id}/registry`
        // for revoked devices (and nothing else) precisely so a device can
        // verify its OWN revocation here. The signed registry is group-wide
        // PUBLIC data (device public keys + per-device status + epoch_key_hashes
        // commitments + version/epoch — no secrets), so serving it to a revoked
        // requester is safe. Every other authenticated route stays rejected, so
        // this fetch is expected to succeed while the engine otherwise cannot.
        let registry_response = match relay.get_signed_registry().await {
            Ok(Some(response)) => response,
            Ok(None) => {
                tracing::warn!(
                    "confirm_self_revocation: unknown (no signed registry available)"
                );
                return SelfRevocationStatus::Unknown;
            }
            Err(e) => {
                // A relay error is inconclusive, never positive confirmation.
                tracing::warn!(
                    error = %e,
                    "confirm_self_revocation: unknown (failed to fetch signed registry)"
                );
                return SelfRevocationStatus::Unknown;
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
                    "confirm_self_revocation: unknown (signed registry verification failed)"
                );
                return SelfRevocationStatus::Unknown;
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "confirm_self_revocation: unknown (verification task failed)"
                );
                return SelfRevocationStatus::Unknown;
            }
        };

        match snapshot.entries.iter().find(|entry| entry.device_id == device_id) {
            Some(entry) if entry.status == "revoked" => {
                // Freshness gate (replay defense): a signature-valid but stale
                // snapshot must not drive a wipe. Reject versions older than our
                // last-imported baseline; a missing baseline (None) also fails
                // safe to Unknown — staleness is unprovable, so we refuse the
                // destructive confirmation. See the three-way match below.
                let storage = self.storage.clone();
                let sid = sync_id.clone();
                let last_imported = tokio::task::spawn_blocking(move || {
                    storage.get_sync_metadata(&sid)
                })
                .await
                .ok()
                .and_then(|res| res.ok())
                .flatten()
                .and_then(|meta| meta.last_imported_registry_version);

                match last_imported {
                    Some(baseline) if snapshot.registry_version < baseline => {
                        // Verified but stale: a version below our baseline is a
                        // replay. Never destructive.
                        tracing::warn!(
                            device_id = %device_id,
                            snapshot_version = snapshot.registry_version,
                            last_imported = baseline,
                            "confirm_self_revocation: unknown (stale/replayed signed registry marks self revoked)"
                        );
                        return SelfRevocationStatus::Unknown;
                    }
                    None => {
                        // No baseline recorded → staleness is unprovable. With
                        // the revoke publisher emitting a positive revoked-self entry from every
                        // genuine revoke, an unprovable case must stay fail-safe
                        // Unknown rather than wipe: a malicious/faulty relay
                        // could replay an old validly-signed registry that marks
                        // a freshly-paired/restored (NULL-baseline) device
                        // revoked, and proceeding here would drive a false wipe.
                        // Baselines self-heal as soon as the device
                        // imports or publishes any registry.
                        tracing::warn!(
                            device_id = %device_id,
                            snapshot_version = snapshot.registry_version,
                            "confirm_self_revocation: unknown (no registry baseline recorded — cannot prove freshness, refusing destructive confirmation)"
                        );
                        return SelfRevocationStatus::Unknown;
                    }
                    Some(_) => {}
                }

                // H3 Layer B: the wipe intent is read from the SAME verified,
                // non-stale signed entry that confirmed the revocation. It is
                // admin-authenticated (covered by the registry signature) and
                // defaults to `false` for older snapshots that omit the field —
                // so a relay can never drive a wipe by flipping an untrusted
                // WS-frame / error-body bit. The caller MUST use this verified
                // value, not the relay frame's hint.
                let remote_wipe = entry.remote_wipe;
                tracing::info!(
                    device_id = %device_id,
                    snapshot_version = snapshot.registry_version,
                    last_imported = ?last_imported,
                    remote_wipe,
                    "confirm_self_revocation: confirmed revoked (verified, non-stale signed registry)"
                );
                SelfRevocationStatus::ConfirmedRevoked { remote_wipe }
            }
            Some(entry) => {
                tracing::debug!(
                    device_id = %device_id,
                    status = %entry.status,
                    "confirm_self_revocation: active (verified signed registry lists us non-revoked)"
                );
                SelfRevocationStatus::Active
            }
            None => {
                // Self absent from the verified snapshot. We do NOT treat this
                // as confirmation of removal — a stale or partial snapshot
                // could omit us. Fail safe.
                tracing::warn!(
                    device_id = %device_id,
                    "confirm_self_revocation: unknown (self absent from verified snapshot)"
                );
                SelfRevocationStatus::Unknown
            }
        }
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
                // Ratchet-on-verified-read: a signature-verified registry is
                // proof of a real published version, so advance our freshness
                // baseline to its embedded `registry_version` even when no repair
                // is needed. This is the steady-state preflight path (relay_epoch
                // == local_epoch), so without this a NULL-baseline device (the
                // whole upgrading 0.12.x fleet, plus the creator until its first
                // publish) would never populate a baseline and could never confirm
                // a genuine revocation. Best-effort and non-fatal — a ratchet
                // failure must not block epoch repair — and uses the VERIFIED
                // embedded version, never the relay response's claimed version.
                if let Err(error) = registry_publish::ratchet_last_imported_registry_version(
                    self.storage.as_ref(),
                    sync_id,
                    current_snapshot.registry_version,
                ) {
                    tracing::warn!(
                        error = %error,
                        registry_version = current_snapshot.registry_version,
                        "repair_signed_registry_epoch_if_needed: failed to ratchet baseline on verified read"
                    );
                }
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

        // Revoked-absorbing republish: emit EVERY relay-listed device, not
        // just active ones, so a survivor's epoch repair carries forward the
        // tombstone even if the revoker crashed before publishing. The pinned
        // record is authoritative for revocation: a device is emitted as
        // "revoked" if EITHER the relay reports it revoked OR our locally-pinned
        // record is revoked — a malicious relay cannot un-revoke a device this
        // way. We prefer locally-pinned key bytes when a pin exists so the
        // republished entry matches what peers already verified against.
        let pinned = DeviceRegistryManager::list_devices(self.storage.as_ref(), sync_id)?;
        let entries: Vec<RegistrySnapshotEntry> = devices
            .iter()
            .map(|device| {
                let pin = pinned.iter().find(|p| p.device_id == device.device_id);
                let locally_revoked = pin.is_some_and(|p| p.status == "revoked");
                let status = if locally_revoked || device.status == "revoked" {
                    "revoked"
                } else {
                    "active"
                };
                let (ed25519, x25519, ml_dsa, ml_kem, x_wing, generation) = match pin {
                    Some(p) => (
                        p.ed25519_public_key.clone(),
                        p.x25519_public_key.clone(),
                        p.ml_dsa_65_public_key.clone(),
                        p.ml_kem_768_public_key.clone(),
                        p.x_wing_public_key.clone(),
                        p.ml_dsa_key_generation,
                    ),
                    None => (
                        device.ed25519_public_key.clone(),
                        device.x25519_public_key.clone(),
                        device.ml_dsa_65_public_key.clone(),
                        device.ml_kem_768_public_key.clone(),
                        device.x_wing_public_key.clone(),
                        device.ml_dsa_key_generation,
                    ),
                };
                RegistrySnapshotEntry {
                    sync_id: sync_id.to_string(),
                    device_id: device.device_id.clone(),
                    ed25519_public_key: ed25519,
                    x25519_public_key: x25519,
                    ml_dsa_65_public_key: ml_dsa,
                    ml_kem_768_public_key: ml_kem,
                    x_wing_public_key: x_wing,
                    status: status.to_string(),
                    ml_dsa_key_generation: generation,
                    // The repair backstop republishes tombstones but never authors
                    // a wipe intent (wipe intent isn't pinned locally); H3 wipe
                    // durability is a known follow-up.
                    remote_wipe: false,
                }
            })
            .collect();

        // The publishing device must be present AND active in the artifact it
        // signs: a registry that omits or revokes its own signer is never
        // legitimate and would strand survivors.
        if !entries
            .iter()
            .any(|entry| entry.device_id == device_id && entry.status == "active")
        {
            return Err(CoreError::Engine(
                "cannot repair signed registry: current device missing or non-active".into(),
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

        // Ratchet our own freshness baseline to the version we just published so
        // this long-lived survivor stops sitting at a NULL baseline. Use
        // the locally-computed `registry_version`, never a relay-returned value.
        registry_publish::ratchet_last_imported_registry_version(
            self.storage.as_ref(),
            sync_id,
            registry_version,
        )?;

        tracing::info!(
            epoch = target_epoch,
            sync_id = %sync_id,
            device_id = %device_id,
            "catch_up_epoch_keys: repaired signed registry epoch binding"
        );

        Ok(())
    }

    // TODO: collapse this into
    // `registry_publish::build_signed_registry_from_pinned`'s
    // `epoch_key_hashes_from_hierarchy`. The revoke-time publisher already
    // uses the shared helper; `repair_signed_registry_epoch_if_needed` still
    // builds its entries from the relay device list (cross-checked against local
    // pins for revoked-absorption) rather than pins-only, so it can't switch to
    // the pins-only builder until the epoch-key-lifecycle work rebuilds
    // it. Keep the two byte-identical until then.
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
        // Gate on the cycle's signed-exchange flag, same as `sync_now`. The
        // debounce short-circuit returns `Ok(None)` — no relay contact — which
        // (like a failed cycle) must not arm the repair.
        let signed_exchange_validated =
            matches!(&result, Ok(Some(r)) if r.signed_exchange_validated);
        self.note_signed_exchange_and_repair_clock(signed_exchange_validated);
        result.map(|_| ())
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
        let (device_id, epoch, sync_id) = {
            let emitter = self
                .op_emitter
                .as_ref()
                .ok_or_else(|| CoreError::Engine("sync not configured".into()))?;
            (emitter.last_hlc().node_id.clone(), emitter.epoch(), emitter.sync_id().to_string())
        };
        // Strip a phantom `is_deleted = false` only when this exact id is already
        // tombstoned (would resurrect a re-created deleted id); a fresh
        // incarnation id keeps its explicit live marker. See
        // [`without_phantom_undelete`].
        let stripped =
            Self::without_phantom_undelete(&*self.storage, &sync_id, table, entity_id, fields);
        let fields = stripped.as_ref().unwrap_or(fields);
        self.validate_mutation_fields(table, fields)?;
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
        let (device_id, epoch, sync_id) = {
            let emitter = self
                .op_emitter
                .as_ref()
                .ok_or_else(|| CoreError::Engine("sync not configured".into()))?;
            (emitter.last_hlc().node_id.clone(), emitter.epoch(), emitter.sync_id().to_string())
        };
        // Strip before the empty check so an update of only `is_deleted = false`
        // on an already-tombstoned id is a no-op; on a live/fresh id the explicit
        // `false` survives (see [`without_phantom_undelete`]).
        let stripped = Self::without_phantom_undelete(
            &*self.storage,
            &sync_id,
            table,
            entity_id,
            changed_fields,
        );
        let changed_fields = stripped.as_ref().unwrap_or(changed_fields);
        if changed_fields.is_empty() {
            return Ok(());
        }
        self.validate_mutation_fields(table, changed_fields)?;
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

    /// Record a newly created entity, stamping the ops at `origin_timestamp_ms`
    /// instead of a fresh wall-clock HLC.
    ///
    /// Used by the startup-deferred-op replay: a captured create that was
    /// deferred during auto-configure replays at its capture time so it never
    /// wins LWW against an edit made (locally or by a peer) after capture. The
    /// emitter watermark is left untouched and each `field_versions` write is
    /// `wins_over`-guarded, so the replay can only push a `pending_op` (peers
    /// merge and may reject it), never regress a newer local winner.
    pub fn record_create_at(
        &mut self,
        table: &str,
        entity_id: &str,
        fields: &HashMap<String, SyncValue>,
        origin_timestamp_ms: i64,
    ) -> Result<()> {
        self.record_mutation_at(table, entity_id, fields, origin_timestamp_ms, MutationKind::Create)
    }

    /// Record changed fields on an existing entity, stamped at
    /// `origin_timestamp_ms`. See [`record_create_at`](Self::record_create_at).
    pub fn record_update_at(
        &mut self,
        table: &str,
        entity_id: &str,
        changed_fields: &HashMap<String, SyncValue>,
        origin_timestamp_ms: i64,
    ) -> Result<()> {
        self.record_mutation_at(
            table,
            entity_id,
            changed_fields,
            origin_timestamp_ms,
            MutationKind::Update,
        )
    }

    /// Shared body for the origin-stamped create/update variants — identical to
    /// `record_create` / `record_update` (phantom-undelete strip, validation,
    /// size partitioning) except the emit stamps every partition at the origin.
    fn record_mutation_at(
        &mut self,
        table: &str,
        entity_id: &str,
        fields: &HashMap<String, SyncValue>,
        origin_timestamp_ms: i64,
        kind: MutationKind,
    ) -> Result<()> {
        if self.op_emitter.is_none() {
            return Err(CoreError::Engine("sync not configured".into()));
        }
        let (device_id, epoch, sync_id) = {
            let emitter = self
                .op_emitter
                .as_ref()
                .ok_or_else(|| CoreError::Engine("sync not configured".into()))?;
            (emitter.last_hlc().node_id.clone(), emitter.epoch(), emitter.sync_id().to_string())
        };
        let stripped =
            Self::without_phantom_undelete(&*self.storage, &sync_id, table, entity_id, fields);
        let fields = stripped.as_ref().unwrap_or(fields);
        if fields.is_empty() {
            return Ok(());
        }
        self.validate_mutation_fields(table, fields)?;
        let partitions =
            Self::partition_fields_into_batches(fields, table, entity_id, &device_id, epoch);
        let emitter = self
            .op_emitter
            .as_mut()
            .ok_or_else(|| CoreError::Engine("sync not configured".into()))?;
        let result = match kind {
            MutationKind::Create => emitter.emit_create_multi_at(
                &*self.storage,
                table,
                entity_id,
                &partitions,
                origin_timestamp_ms,
            ),
            MutationKind::Update => emitter.emit_update_multi_at(
                &*self.storage,
                table,
                entity_id,
                &partitions,
                origin_timestamp_ms,
            ),
        };
        if result.is_ok() {
            if let Some(tx) = self.sync_service.auto_sync_sender() {
                let _ = tx.try_send(());
            }
        }
        result
    }

    /// Reconcile `fields` against this device's `field_versions`, emitting only
    /// genuinely-diverged fields (`divergent_mode` decides fresh-HLC vs skip)
    /// and never-synced fields as floor-HLC backfill.
    ///
    /// The clobber-free replacement for full-row fresh-HLC re-broadcasts: a
    /// value the device already agrees with produces zero ops, so a
    /// re-broadcast can no longer beat a peer's un-pulled newer edit. Reuses the
    /// conditional phantom-undelete strip and field validation; size
    /// partitioning is unnecessary because the reconcile only emits the small
    /// subset that actually diverges, so the whole reconcile rides one batch.
    pub fn record_reconcile(
        &mut self,
        table: &str,
        entity_id: &str,
        fields: &HashMap<String, SyncValue>,
        divergent_mode: DivergentMode,
    ) -> Result<()> {
        if self.op_emitter.is_none() {
            return Err(CoreError::Engine("sync not configured".into()));
        }
        let sync_id = {
            let emitter = self
                .op_emitter
                .as_ref()
                .ok_or_else(|| CoreError::Engine("sync not configured".into()))?;
            emitter.sync_id().to_string()
        };
        let stripped =
            Self::without_phantom_undelete(&*self.storage, &sync_id, table, entity_id, fields);
        let fields = stripped.as_ref().unwrap_or(fields);
        if fields.is_empty() {
            return Ok(());
        }
        self.validate_mutation_fields(table, fields)?;
        let batch_id = uuid::Uuid::new_v4().to_string();
        let emitter = self
            .op_emitter
            .as_mut()
            .ok_or_else(|| CoreError::Engine("sync not configured".into()))?;
        let result = emitter.emit_reconcile_multi(
            &*self.storage,
            table,
            entity_id,
            fields,
            divergent_mode,
            &batch_id,
        );
        if result.is_ok() {
            if let Some(tx) = self.sync_service.auto_sync_sender() {
                let _ = tx.try_send(());
            }
        }
        result
    }

    /// Pure write-if-absent backfill: reconcile with [`DivergentMode::Skip`].
    ///
    /// Emits only fields with no `field_versions` row, stamped at the floor
    /// backfill HLC — establishing the entity group-wide while losing to every
    /// genuine edit. Divergent local values are left alone (first-device-wins).
    pub fn record_backfill(
        &mut self,
        table: &str,
        entity_id: &str,
        fields: &HashMap<String, SyncValue>,
    ) -> Result<()> {
        self.record_reconcile(table, entity_id, fields, DivergentMode::Skip)
    }

    /// Drop a phantom `is_deleted = false` from a mutation's fields when the
    /// entity is already locally tombstoned.
    ///
    /// `is_deleted` is absorbing: a create/update carrying `false` stamps a
    /// fresh-HLC live-marker that, on a re-create of an *already-tombstoned* id,
    /// beats the older tombstone under per-field LWW and resurrects the entity on
    /// every peer — so we strip it. But the app deliberately reuses deterministic
    /// ids (`pk-group-g<N>:<uuid>`, gen-suffixed entry shas) and a *fresh*
    /// incarnation id has no local tombstone; that id's explicit `false` must
    /// travel so peers see it as a live new entity (the sanctioned-revive path).
    ///
    /// The strip is therefore conditional on a LOCAL tombstone for the exact
    /// `(table, entity_id)`: an `is_deleted` field version whose winning value is
    /// anything other than `"false"` (mirrors merge.rs — a `None`/missing value
    /// counts as a tombstone). [`MergeEngine`](crate::engine::merge) keeps its own
    /// receiver backstop (`false` never beats a tombstone) so a stale peer can
    /// never be resurrected even when this device emits an explicit `false`.
    ///
    /// Returns `Some` only when a strip was needed (otherwise allocation-free).
    fn without_phantom_undelete(
        storage: &dyn SyncStorage,
        sync_id: &str,
        table: &str,
        entity_id: &str,
        fields: &HashMap<String, SyncValue>,
    ) -> Option<HashMap<String, SyncValue>> {
        if !matches!(fields.get(DELETED_FIELD), Some(SyncValue::Bool(false))) {
            return None;
        }
        // Only strip when this exact id is already tombstoned locally; a fresh
        // incarnation carries its explicit live marker.
        let tombstoned = match storage.get_field_version(sync_id, table, entity_id, DELETED_FIELD) {
            Ok(Some(fv)) => fv.winning_encoded_value.as_deref() != Some("false"),
            Ok(None) => false,
            // On a read error, fail safe: behave as 0.12.x did and strip, so a
            // transient storage fault cannot leak a phantom undelete.
            Err(_) => true,
        };
        if !tombstoned {
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

    /// Record a soft-delete stamped at `origin_timestamp_ms`. The replay-time
    /// variant of [`record_delete`](Self::record_delete): the tombstone
    /// op pushes at its capture HLC and the `field_versions` write is
    /// `wins_over`-guarded, so a stale-origin delete never overwrites a newer
    /// local winner. Receivers still apply the absorbing-tombstone rule.
    pub fn record_delete_at(
        &mut self,
        table: &str,
        entity_id: &str,
        origin_timestamp_ms: i64,
    ) -> Result<()> {
        if self.op_emitter.is_none() {
            return Err(CoreError::Engine("sync not configured".into()));
        }
        self.schema.entity(table).ok_or_else(|| CoreError::UnknownTable(table.to_string()))?;
        let batch_id = uuid::Uuid::new_v4().to_string();
        let emitter = self
            .op_emitter
            .as_mut()
            .ok_or_else(|| CoreError::Engine("sync not configured".into()))?;
        let result =
            emitter.emit_delete_at(&*self.storage, table, entity_id, &batch_id, origin_timestamp_ms);
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

        // 2. Wrap the new epoch key for surviving devices. The locally-pinned
        //    registry — not the relay device list — is the authority for who
        //    may receive a wrapped key, so the relay cannot inject a recipient.
        let pinned =
            crate::device_registry::DeviceRegistryManager::list_devices(&*self.storage, &sync_id)?;
        let (epoch_key, wrapped_keys) =
            crate::epoch::EpochManager::prepare_wrapped_keys_for_devices(
                &devices,
                new_epoch,
                Some(target_device_id),
                &pinned,
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

        // Revoke-publish + wipe-intent binding: pin the local tombstone, then publish a signed
        // registry that carries the target as an explicit status=="revoked"
        // entry — binding the admin's `remote_wipe` intent into the SIGNATURE so
        // the revoked device can both confirm its own revocation and read the
        // wipe bit from the verified entry. Both steps run strictly AFTER the
        // relay-side revocation committed (above), so a signed revoked-claim can
        // never precede the actual revocation.
        //
        // The pin is the gate for the publish: the publisher builds from local
        // pins, so without a successful revoked pin it would emit a
        // tombstone-LESS artifact at the new epoch (omitting an unpinned target,
        // or re-asserting an active target after a storage write error). Such a
        // publish is worse than no publish: it makes the served artifact
        // epoch-current, so the revoked-absorbing epoch repair backstop
        // (repair_signed_registry_epoch_if_needed early-returns once the served
        // epoch catches up) never republishes the tombstone — permanently
        // disarming the revoke-publish backstop. So if the pin fails we deliberately do NOT publish: the
        // served artifact stays epoch-stale and any survivor's next
        // catch_up_epoch_keys repair re-derives the tombstone from the relay
        // list (the revoker's revoke_device call already moved the relay row to
        // revoked). publish_revocation_registry additionally re-checks the built
        // snapshot carries the target as revoked before PUT (belt-and-braces).
        match DeviceRegistryManager::revoke_device(
            self.storage.as_ref(),
            &sync_id,
            target_device_id,
        ) {
            Ok(()) => {
                // Publish failure is non-fatal: the revoke itself already
                // committed, and any survivor's next catch_up_epoch_keys epoch
                // repair republishes the tombstone-bearing registry (the
                // revoked-absorbing backstop).
                if let Err(error) = self
                    .publish_revocation_registry(
                        relay.as_ref(),
                        &sync_id,
                        &self_device_id,
                        target_device_id,
                        committed_epoch,
                        remote_wipe,
                    )
                    .await
                {
                    tracing::warn!(
                        error = %error,
                        target_device_id = %target_device_id,
                        epoch = committed_epoch,
                        "revoke_and_rekey: failed to publish revocation registry (epoch repair will backstop)"
                    );
                }
            }
            Err(error) => {
                // The relay-side revoke already committed, so the revocation is
                // real and durable. Skip the publish entirely (see above): the
                // epoch-stale served artifact makes the epoch repair backstop
                // fire on the next survivor's catch_up_epoch_keys, which derives
                // the tombstone from the relay's revoked row.
                tracing::warn!(
                    error = %error,
                    target_device_id = %target_device_id,
                    epoch = committed_epoch,
                    "revoke_and_rekey: failed to pin local revocation tombstone — skipping revocation-registry publish so the epoch repair backstop re-derives it"
                );
            }
        }

        Ok(committed_epoch)
    }

    /// React to a relay `needs_rekey` signal (F29): one active device drives a
    /// standalone rekey that advances the epoch and clears the relay flag the
    /// 90d auto-revoke set. Idempotent across responders — the relay's epoch CAS
    /// admits exactly one winner and the rest reconcile to a no-op.
    ///
    /// Best-effort by design: every early return is a benign defer (we are not
    /// the active device that should rotate, the relay is unreachable, an old
    /// relay still 409s). It NEVER performs a destructive action.
    pub async fn react_to_rekey_needed(&mut self, relay: Arc<dyn SyncRelay>) -> Result<()> {
        let sync_id = match self.sync_service().sync_id() {
            Some(id) => id.to_string(),
            None => return Ok(()),
        };
        let self_device_id = match self.device_id() {
            Some(id) => id.to_string(),
            None => return Ok(()),
        };

        // Refresh the local pinned registry from the relay's latest verified
        // artifact so `pinned` reflects any revocation a survivor already
        // published. This is best-effort: the relay's in-transaction
        // `validate_wrapped_keys(active_survivor_set)` is the real gate on who
        // receives the new epoch key, so a missing/stale artifact only costs a
        // retry, never correctness.
        self.import_latest_verified_registry(relay.as_ref(), &sync_id).await;

        // The relay device list is authoritative for the current epoch (local
        // metadata can lag after recovering from a peer's earlier rekey). Only an
        // ACTIVE device may rotate; anyone else defers (the relay would reject a
        // non-active requester anyway).
        let devices = relay.list_devices().await?;
        let self_device = match devices.iter().find(|d| d.device_id == self_device_id) {
            Some(d) => d,
            None => return Ok(()),
        };
        if self_device.status != "active" {
            return Ok(());
        }
        let current_epoch = self_device.epoch.max(0) as u32;

        // The locally-pinned registry — not the relay list — is the authority for
        // who may receive a wrapped key, so the relay cannot inject a recipient.
        let pinned = DeviceRegistryManager::list_devices(&*self.storage, &sync_id)?;

        let committed_epoch = current_epoch.saturating_add(1);
        let installed = EpochManager::post_rekey_for_needed(
            relay.as_ref(),
            self.key_hierarchy_mut(),
            &self_device_id,
            &pinned,
            current_epoch,
            None,
        )
        .await?;

        let epoch_key = match installed {
            Some(key) => key,
            // A peer already rotated (epoch-mismatch reconcile) — the relay's
            // `EpochRotated` broadcast drives our key recovery. Nothing to commit.
            None => return Ok(()),
        };

        self.commit_local_epoch_rotation(&sync_id, committed_epoch, epoch_key.as_ref()).await?;

        // Publish a signed registry carrying the new epoch's key hash so peers can
        // recover the new epoch key via the existing `EpochRotated` -> registry
        // path. A publish failure is non-fatal: the rekey already committed and a
        // survivor's next `catch_up_epoch_keys` epoch repair backstops it.
        if let Err(error) =
            self.publish_post_rekey_registry(relay.as_ref(), &sync_id, &self_device_id, committed_epoch).await
        {
            tracing::warn!(
                error = %error,
                epoch = committed_epoch,
                "rekey-needed: failed to publish post-rekey registry (epoch repair will backstop)"
            );
        }

        tracing::info!(
            sync_id = %sync_id,
            device_id = %self_device_id,
            epoch = committed_epoch,
            "rekey-needed: standalone rekey committed and needs_rekey cleared"
        );
        Ok(())
    }

    /// Best-effort import of the relay's latest verified signed registry into the
    /// local pinned store. Logs and returns on any failure — callers treat a
    /// missing/stale/unverifiable artifact as "use whatever is pinned locally".
    async fn import_latest_verified_registry(&self, relay: &dyn SyncRelay, sync_id: &str) {
        let response = match relay.get_signed_registry().await {
            Ok(Some(response)) => response,
            Ok(None) => return,
            Err(error) => {
                tracing::debug!(error = %error, "rekey-needed: no signed registry to import");
                return;
            }
        };
        // A storage ERROR reading the last imported version must NOT collapse to
        // `None`: `None` floors the monotonicity gate at -1, which would accept a
        // rolled-back registry artifact — and this import directly feeds the
        // wrap-set authority for the rekey reaction. Defer the import on error
        // (keep whatever is pinned locally) rather than disable the gate. `Ok(None)`
        // is the legitimate "no prior import" case and keeps `None`.
        let last_version = match self.storage.get_sync_metadata(sync_id) {
            Ok(meta) => meta.and_then(|m| m.last_imported_registry_version),
            Err(error) => {
                tracing::debug!(
                    error = %error,
                    "rekey-needed: registry import deferred (could not read last imported version)"
                );
                return;
            }
        };
        match DeviceRegistryManager::verify_and_import_signed_registry(
            &*self.storage,
            sync_id,
            &response.artifact_blob,
            last_version,
        ) {
            Ok(signed_version) => {
                if let Ok(mut tx) = self.storage.begin_tx() {
                    let _ = tx.update_last_imported_registry_version(sync_id, signed_version);
                    let _ = tx.commit();
                }
            }
            Err(error) => {
                tracing::debug!(error = %error, "rekey-needed: registry import skipped");
            }
        }
    }

    /// Publish a signed registry bound to `epoch` carrying the new epoch's key
    /// hash, at a version strictly above the currently-served artifact. Mirrors
    /// the post-commit publish in `revoke_and_rekey`, minus the revoked-tombstone
    /// content check (a standalone rekey changes no membership).
    async fn publish_post_rekey_registry(
        &self,
        relay: &dyn SyncRelay,
        sync_id: &str,
        self_device_id: &str,
        epoch: u32,
    ) -> Result<()> {
        let device_secret = self.device_secret.as_ref().ok_or_else(|| {
            CoreError::Engine("device secret not set — call configure_engine first".into())
        })?;
        let signing_key = device_secret.ed25519_keypair(self_device_id).map_err(CoreError::Crypto)?;
        let pq_signing_key = self.device_ml_dsa_signing_key.as_ref().ok_or_else(|| {
            CoreError::Engine("ML-DSA signing key not set — call configure_engine first".into())
        })?;

        let new_version = match relay.get_signed_registry().await {
            Ok(Some(response)) => {
                let current = DeviceRegistryManager::verify_signed_registry_snapshot(
                    self.storage.as_ref(),
                    sync_id,
                    &response.artifact_blob,
                )
                .map_err(|e| {
                    CoreError::Engine(format!(
                        "signed registry verification failed before post-rekey publish: {e}"
                    ))
                })?;
                (current.registry_version + 1).max(SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING)
            }
            Ok(None) => SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
            Err(error) => return Err(CoreError::from_relay(error)),
        };

        let snapshot = registry_publish::build_signed_registry_from_pinned(
            self.storage.as_ref(),
            sync_id,
            self_device_id,
            new_version,
            epoch,
            &self.key_hierarchy,
        )?;
        let signed = snapshot.sign_hybrid(&signing_key, pq_signing_key);
        relay.put_signed_registry(&signed).await.map_err(CoreError::from_relay)?;

        registry_publish::ratchet_last_imported_registry_version(
            self.storage.as_ref(),
            sync_id,
            new_version,
        )?;
        Ok(())
    }

    /// Publish a signed registry carrying the locally-pinned revocation state
    /// (explicit revoked entries) so a genuinely revoked device can fetch it and
    /// reach `ConfirmedRevoked` via `confirm_self_revocation`.
    ///
    /// Built from local pins via the shared revoked-absorbing
    /// [`build_signed_registry_from_pinned`] helper, signed with this device's
    /// Ed25519 + ML-DSA keys, and published with a version strictly above the
    /// currently-served artifact. The built snapshot is re-checked to carry
    /// `target_device_id` as `status == "revoked"` before the PUT — a
    /// tombstone-less artifact at the current epoch must never be published, as
    /// it would silently disarm the epoch-repair backstop. After a successful
    /// publish the device's own freshness baseline is ratcheted to the
    /// locally-computed version (never the relay's PUT response, which a
    /// malicious relay could inflate to wedge future imports).
    ///
    /// H3 Layer B: `remote_wipe` is the admin's authenticated wipe intent. It is
    /// passed through to the builder as the wipe target, so the target's revoked
    /// entry binds the wipe bit into the registry SIGNATURE and the victim reads
    /// it back from the verified entry in `confirm_self_revocation`.
    ///
    /// Composition seam: this is the publish-after path. The later
    /// epoch-key-lifecycle work refactors revocation
    /// publication to atomic-attach (signed_registry_snapshot attached to the
    /// revoke call) reusing this same helper; it rebases on this function rather
    /// than duplicating the content rules.
    async fn publish_revocation_registry(
        &self,
        relay: &dyn SyncRelay,
        sync_id: &str,
        self_device_id: &str,
        target_device_id: &str,
        committed_epoch: u32,
        remote_wipe: bool,
    ) -> Result<()> {
        let device_secret = self.device_secret.as_ref().ok_or_else(|| {
            CoreError::Engine("device secret not set — call configure_engine first".into())
        })?;
        let signing_key = device_secret.ed25519_keypair(self_device_id).map_err(CoreError::Crypto)?;
        let pq_signing_key = self.device_ml_dsa_signing_key.as_ref().ok_or_else(|| {
            CoreError::Engine("ML-DSA signing key not set — call configure_engine first".into())
        })?;

        // Choose a version strictly above the currently-served artifact (same
        // pattern as the epoch repair publisher), floored at the epoch-binding
        // minimum. A fetch failure is treated as "no served artifact yet".
        let new_version = match relay.get_signed_registry().await {
            Ok(Some(response)) => {
                let current = DeviceRegistryManager::verify_signed_registry_snapshot(
                    self.storage.as_ref(),
                    sync_id,
                    &response.artifact_blob,
                )
                .map_err(|e| {
                    CoreError::Engine(format!(
                        "signed registry verification failed before revocation publish: {e}"
                    ))
                })?;
                (current.registry_version + 1).max(SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING)
            }
            Ok(None) => SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
            Err(error) => return Err(CoreError::from_relay(error)),
        };

        // H3 composition: when the admin requested a remote wipe, name the target
        // as the builder's `wipe_target` so its (pinned-revoked) entry binds
        // `remote_wipe = true` into the registry signature. The repair backstop
        // republish passes `None`, so only this explicit revocation carries the
        // bit. The builder draws the target's keys + revoked status from the
        // local pins (set just above by `DeviceRegistryManager::revoke_device`),
        // never the raw relay list.
        let snapshot = registry_publish::build_signed_registry_from_pinned(
            self.storage.as_ref(),
            sync_id,
            self_device_id,
            new_version,
            committed_epoch,
            &self.key_hierarchy,
            if remote_wipe { Some(target_device_id) } else { None },
        )?;

        // Belt-and-braces: refuse to publish a tombstone-LESS artifact at the
        // new epoch. The caller only reaches here after a successful local
        // revoked pin, so the builder should already carry the target as
        // revoked — but verifying it here closes the gap if the pin were ever
        // racing/partial, since a tombstone-less publish at the current epoch
        // would silently disarm the epoch-repair backstop (which only fires
        // while the served artifact's epoch lags).
        let target_revoked = snapshot
            .entries
            .iter()
            .any(|entry| entry.device_id == target_device_id && entry.status == "revoked");
        if !target_revoked {
            return Err(CoreError::Engine(format!(
                "refusing to publish revocation registry: built snapshot does not carry target {target_device_id} as revoked"
            )));
        }

        let signed = snapshot.sign_hybrid(&signing_key, pq_signing_key);
        relay.put_signed_registry(&signed).await.map_err(CoreError::from_relay)?;

        // Ratchet our own baseline forward so we never treat our just-published
        // registry as stale, and so this long-lived device stops sitting at a
        // NULL freshness baseline. Ratchet to the LOCALLY-computed new_version,
        // never the relay's PutRegistryResponse value: a malicious relay could
        // return an absurdly high registry_version to inflate the baseline and
        // wedge every future genuine artifact as "stale" (fail-safe direction —
        // no false wipe — but a needless relay-driven local DoS).
        registry_publish::ratchet_last_imported_registry_version(
            self.storage.as_ref(),
            sync_id,
            new_version,
        )?;

        tracing::info!(
            epoch = committed_epoch,
            registry_version = new_version,
            sync_id = %sync_id,
            device_id = %self_device_id,
            remote_wipe,
            "revoke_and_rekey: published revocation registry with explicit revoked entry"
        );

        Ok(())
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

    /// Stamp clock confidence on a relay-validated signed exchange and, when one
    /// occurred this cycle, run the forward-excursion detect-and-repair.
    ///
    /// `signed_exchange_validated` is the engine's [`SyncResult`] flag: `true`
    /// only when this cycle landed a 2xx on a *signed* route (push or ack) whose
    /// `X-Prism-Timestamp` the relay checked against its symmetric skew window —
    /// which proves `|local − relay| ≤ MAX_CLOCK_DRIFT_MS`. It is NOT keyed on
    /// `error.is_none()`: a pull-only cycle (the unsigned, bearer-only `GET`) can
    /// succeed with the local clock arbitrarily skewed, so gating on bare success
    /// would arm the repair with no clock proof. Keying on the signed-exchange
    /// flag is the relay anchor that separates a genuine forward excursion (a
    /// signed request still validates, so we repair) from a backward clock step
    /// (the relay 401s the signed request on the same skew check, the flag stays
    /// `false`, and the repair never runs). A cycle with nothing
    /// signed to send simply defers the repair to a later validated cycle.
    fn note_signed_exchange_and_repair_clock(&mut self, signed_exchange_validated: bool) {
        if !signed_exchange_validated {
            return;
        }
        // Bookkeeping for cross-cycle freshness consumers; the per-cycle gate
        // above is the load-bearing evidence (a backward step never reaches here).
        self.clock_confidence.record_validated(Hlc::now_ms());

        if let Some(excursion) = self.check_clock_excursion() {
            if let Err(e) = self.repair_future_hlc_excursion(excursion) {
                tracing::error!(error = %e, "clock-excursion repair failed");
            }
        }
    }

    /// Detect a confirmed forward HLC excursion over the drift bound.
    ///
    /// Computes `future_drift_ms` as the MAX over (a) the emitter watermark and
    /// (b) the self-authored `field_versions` winners that exceed the bound, and
    /// returns the over-bound rows plus the peak drift when an excursion is
    /// confirmed. Gated by the caller on relay-anchored clock confidence, so a
    /// reading over the bound here can only be a forward clock step.
    fn check_clock_excursion(&self) -> Option<ClockExcursion> {
        let sync_id = self.sync_service.sync_id()?.to_string();
        let device_id = self.device_id.clone()?;
        let emitter = self.op_emitter.as_ref()?;

        let now_ms = Hlc::now_ms();
        let watermark_drift = crate::clock_drift::future_drift_ms(emitter.last_hlc(), now_ms);

        let future_rows = match self.storage.list_self_authored_future_fv(
            &sync_id,
            &device_id,
            MAX_CLOCK_DRIFT_MS,
        ) {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(error = %e, "clock-excursion: failed to read self-authored FV rows");
                return None;
            }
        };

        let fv_drift = future_rows
            .iter()
            .filter_map(|fv| Hlc::from_string(&fv.winning_hlc).ok())
            .map(|hlc| crate::clock_drift::future_drift_ms(&hlc, now_ms))
            .max()
            .unwrap_or(0);

        let max_drift = watermark_drift.max(fv_drift);
        if max_drift <= MAX_CLOCK_DRIFT_MS {
            return None;
        }
        Some(ClockExcursion { device_id, sync_id, future_rows, max_drift_ms: max_drift })
    }

    /// Repair a confirmed forward HLC excursion.
    ///
    /// (i) clamp the emitter watermark back to now; (ii) drop the device's
    /// unpushed over-bound `pending_ops` (their FV winner is also self-authored
    /// and over-bound, and is re-emitted below, so nothing is lost); (iii)
    /// re-emit each over-bound self-authored winner at a fresh sane HLC via the
    /// normal `record_update` path so blobs re-partition correctly — the blind
    /// FV upsert rewrites the poisoned winner downward locally, and the re-emit
    /// is what lets peers (who silently dropped the excursion-era ops) finally
    /// converge. (iv) emit `ClockExcursionRepaired`.
    ///
    /// The three steps are not one transaction (each `record_update` commits its
    /// own), but a crash mid-repair is recoverable on the next validated cycle
    /// because [`check_clock_excursion`](Self::check_clock_excursion) re-detects
    /// off the FV winners' drift, not the watermark alone: a clamped watermark
    /// plus any still-poisoned FV row re-confirms the excursion and re-runs the
    /// repair. A deleted pending op is never lost — its FV winner is the re-emit
    /// source, and `record_update` re-creates the op atomically with the FV
    /// rewrite. The repair is therefore idempotent and self-healing.
    fn repair_future_hlc_excursion(&mut self, excursion: ClockExcursion) -> Result<()> {
        let ClockExcursion { device_id, sync_id, future_rows, max_drift_ms } = excursion;

        tracing::error!(
            device_id = %device_id,
            field_count = future_rows.len(),
            max_drift_ms,
            "forward HLC clock excursion detected — repairing self-authored future HLCs"
        );

        if let Some(emitter) = self.op_emitter.as_mut() {
            emitter.clamp_watermark_to_now()?;
        }

        let deleted = self
            .storage
            .delete_unpushed_future_pending_ops(&sync_id, &device_id, MAX_CLOCK_DRIFT_MS)?;
        tracing::debug!(deleted, "clock-excursion: dropped over-bound unpushed pending ops");

        let mut field_count = 0u64;
        for fv in &future_rows {
            // A self-authored future tombstone re-emits through the delete path;
            // `is_deleted` is not a declared schema field so it cannot ride
            // `record_update`. A live `is_deleted = "false"` row is just a normal
            // field and falls through to the update path below.
            if fv.field_name == DELETED_FIELD
                && crate::storage::is_tombstone_value(fv.winning_encoded_value.as_deref())
            {
                if let Err(e) = self.record_delete(&fv.entity_table, &fv.entity_id) {
                    tracing::warn!(
                        error = %e,
                        entity_table = %fv.entity_table,
                        entity_id = %fv.entity_id,
                        "clock-excursion: failed to re-emit tombstone"
                    );
                    continue;
                }
                field_count += 1;
                continue;
            }

            // Decode the winning value back into a SyncValue and re-emit it as a
            // normal update; `record_update` partitions large blobs and stamps a
            // fresh now-HLC via the freshly clamped watermark. Resolve the field
            // type the same way the engine's apply path does.
            let Some(encoded) = fv.winning_encoded_value.as_deref() else {
                continue;
            };
            let sync_type = self
                .schema
                .entity(&fv.entity_table)
                .and_then(|e| e.field_by_name(&fv.field_name))
                .map(|f| f.sync_type)
                .unwrap_or(SyncType::String);
            let value = match crate::schema::decode_value(encoded, sync_type) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        entity_table = %fv.entity_table,
                        entity_id = %fv.entity_id,
                        field_name = %fv.field_name,
                        "clock-excursion: skipping field with undecodable winning value"
                    );
                    continue;
                }
            };
            let mut fields = HashMap::new();
            fields.insert(fv.field_name.clone(), value);
            if let Err(e) = self.record_update(&fv.entity_table, &fv.entity_id, &fields) {
                tracing::warn!(
                    error = %e,
                    entity_table = %fv.entity_table,
                    entity_id = %fv.entity_id,
                    field_name = %fv.field_name,
                    "clock-excursion: failed to re-emit field"
                );
                continue;
            }
            field_count += 1;
        }

        let _ = self
            .event_tx
            .send(SyncEvent::ClockExcursionRepaired { field_count, max_drift_ms });

        Ok(())
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

    /// Build a sealed ephemeral-message envelope for the device-message mailbox,
    /// keyed by this client's current epoch key. Pure
    /// (no I/O) so the FFI can construct it under the state lock and then
    /// transport it via [`MediaRelay::send_ephemeral`](crate::relay::traits::MediaRelay::send_ephemeral)
    /// without holding the lock across the network call.
    pub fn build_ephemeral_envelope(
        &self,
        kind: &str,
        media_id: &str,
        recipient_device_id: Option<String>,
    ) -> Result<crate::ephemeral::EphemeralEnvelope> {
        let sync_id = self
            .sync_service
            .sync_id()
            .ok_or_else(|| CoreError::Engine("no sync_id; engine not configured".into()))?;
        let epoch = self.epoch.ok_or_else(|| CoreError::Engine("no current epoch".into()))?;
        let epoch_u32 =
            u32::try_from(epoch).map_err(|_| CoreError::Engine(format!("invalid epoch {epoch}")))?;
        let epoch_key = self.key_hierarchy.epoch_key(epoch_u32)?;
        let now = chrono::Utc::now().timestamp();
        crate::ephemeral::seal_envelope(
            epoch_key,
            sync_id,
            epoch_u32,
            kind,
            media_id,
            recipient_device_id,
            now,
        )
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
        async fn batch_exists(
            &self,
            _: &[String],
        ) -> std::result::Result<Vec<String>, RelayError> {
            unimplemented!()
        }
        async fn send_ephemeral(
            &self,
            _: &crate::ephemeral::EphemeralEnvelope,
        ) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn fetch_pending_ephemeral(
            &self,
        ) -> std::result::Result<Vec<crate::ephemeral::EphemeralEnvelope>, RelayError> {
            unimplemented!()
        }
        async fn ack_ephemeral(
            &self,
            _: &[String],
        ) -> std::result::Result<(), RelayError> {
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
        /// When set, `get_signed_registry` returns a relay error instead of the
        /// stored snapshot. Used to exercise the H3 `Unknown` fail-safe.
        signed_registry_error: bool,
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
                    signed_registry_error: false,
                    behavior,
                    revoke_calls: 0,
                }),
            }
        }

        fn revoke_calls(&self) -> u32 {
            self.state.lock().unwrap().revoke_calls
        }

        fn devices(&self) -> Vec<DeviceInfo> {
            self.state.lock().unwrap().devices.clone()
        }

        fn insert_artifact(&self, epoch: i32, device_id: &str, artifact: Vec<u8>) {
            self.state.lock().unwrap().artifacts.insert((epoch, device_id.to_string()), artifact);
        }

        fn set_signed_registry(&self, signed_registry: SignedRegistryResponse) {
            self.state.lock().unwrap().signed_registry = Some(signed_registry);
        }

        fn set_signed_registry_error(&self, errored: bool) {
            self.state.lock().unwrap().signed_registry_error = errored;
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
            let state = self.state.lock().unwrap();
            if state.signed_registry_error {
                return Err(RelayError::Protocol {
                    message: "device_revoked".to_string(),
                });
            }
            Ok(state.signed_registry.clone())
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
        async fn batch_exists(
            &self,
            _: &[String],
        ) -> std::result::Result<Vec<String>, RelayError> {
            unimplemented!()
        }
        async fn send_ephemeral(
            &self,
            _: &crate::ephemeral::EphemeralEnvelope,
        ) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn fetch_pending_ephemeral(
            &self,
        ) -> std::result::Result<Vec<crate::ephemeral::EphemeralEnvelope>, RelayError> {
            unimplemented!()
        }
        async fn ack_ephemeral(
            &self,
            _: &[String],
        ) -> std::result::Result<(), RelayError> {
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
            needs_rekey: false,
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

    /// Seed the local pinned device registry so `revoke_and_rekey`'s wrap
    /// intersection (pinned vs relay-listed) has a matching authority. Mirrors
    /// what a real device would hold after importing a signed registry.
    fn seed_device_registry(sync: &PrismSync, sync_id: &str, infos: &[DeviceInfo]) {
        let mut tx = sync.storage().begin_tx().unwrap();
        for info in infos {
            tx.upsert_device_record(&make_device_record(sync_id, info)).unwrap();
        }
        tx.commit().unwrap();
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
            remote_wipe: false,
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

    /// Force the recorded freshness baseline back to NULL. The MAX-monotonic
    /// `update_last_imported_registry_version` cannot rewind to NULL, so reset
    /// via a full metadata upsert — modelling a 0.12.x device that upgraded
    /// with the column populated but the baseline never set.
    fn clear_last_imported_registry_version(sync: &PrismSync, sync_id: &str) {
        let mut meta = sync.storage().get_sync_metadata(sync_id).unwrap().unwrap();
        meta.last_imported_registry_version = None;
        let mut tx = sync.storage().begin_tx().unwrap();
        tx.upsert_sync_metadata(&meta).unwrap();
        tx.commit().unwrap();
    }

    #[tokio::test]
    async fn sync_preflight_ratchets_null_baseline_on_verified_read_when_relay_ahead() {
        // Ratchet-on-verified-read: the relay-ahead catch-up path verifies a
        // signed registry; a NULL-baseline device (the upgrading 0.12.x fleet)
        // must populate its freshness baseline from the VERIFIED embedded
        // registry_version so it can later confirm a genuine revocation — without
        // this, the flipped fail-safe gate leaves remote_wipe permanently inert
        // for that population.
        let (mut sync, _relay, _device_id, _epoch_1_key, _epoch_2_key) =
            prepare_verified_epoch_catch_up(true);
        // Model the upgrading 0.12.x device: a sync_metadata row exists (the
        // column is present from the migration) but the baseline was never set.
        // The ratchet helper deliberately never fabricates a metadata row — row
        // creation belongs to the pairing/join/configure paths — so seed the row
        // here exactly as a real device would have one by catch-up time.
        {
            let mut tx = sync.storage().begin_tx().unwrap();
            tx.update_current_epoch("sync-1", 0).unwrap();
            tx.commit().unwrap();
        }
        assert_eq!(
            sync.storage()
                .get_sync_metadata("sync-1")
                .unwrap()
                .and_then(|m| m.last_imported_registry_version),
            None,
            "precondition: row exists but no freshness baseline is recorded"
        );

        sync.catch_up_epoch_keys().await.unwrap();

        // The relay serves registry_version 1 (the floor); the relay-ahead verify
        // ratchets the NULL baseline up to it.
        assert_eq!(
            sync.storage().get_sync_metadata("sync-1").unwrap().unwrap().last_imported_registry_version,
            Some(1),
            "verified relay-ahead read must populate a NULL baseline"
        );
    }

    #[tokio::test]
    async fn sync_preflight_ratchets_null_baseline_on_verified_read_when_no_repair_needed() {
        // Ratchet-on-verified-read, steady-state path: once local_epoch ==
        // relay_epoch, the preflight routes through
        // repair_signed_registry_epoch_if_needed, which verifies the served
        // registry and EARLY-RETURNS because no epoch repair is needed
        // (current_snapshot.current_epoch >= target_epoch). That no-repair branch
        // must still ratchet the baseline — this is the dominant steady-state
        // sync cycle, so it is what actually self-heals the NULL-baseline fleet.
        let (mut sync, _relay, _device_id, _epoch_1_key, _epoch_2_key) =
            prepare_verified_epoch_catch_up(true);

        // First catch-up advances local epoch to 2 (== relay epoch).
        sync.catch_up_epoch_keys().await.unwrap();
        assert_eq!(sync.epoch(), Some(2));

        // Reset the baseline to NULL to model the upgrade hole, then run the
        // steady-state preflight: relay_epoch == local_epoch == 2 so the served
        // registry (current_epoch 2) needs no repair and the publisher branch is
        // never reached — only the verified-read ratchet can populate the baseline.
        clear_last_imported_registry_version(&sync, "sync-1");
        sync.catch_up_epoch_keys().await.unwrap();

        assert_eq!(
            sync.storage().get_sync_metadata("sync-1").unwrap().unwrap().last_imported_registry_version,
            Some(1),
            "verified no-repair-needed catch-up must populate a NULL baseline"
        );
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

    // ── H3: signature-verified self-revocation check ──

    /// Sign a registry snapshot over an arbitrary set of entries using an
    /// ACTIVE signer device. Unlike [`signed_registry_response`] (single
    /// entry), this lets a test mark THIS device `revoked` in a snapshot signed
    /// by a *different* active device — the only legitimate way revocation is
    /// represented (a device cannot sign its own revocation; the verifier
    /// rejects a self-revoked signer).
    /// Sign a registry from pre-built [`RegistrySnapshotEntry`] values so tests
    /// can set per-entry fields (e.g. the H3 Layer B `remote_wipe` bit) that
    /// `DeviceInfo` does not carry.
    fn signed_registry_from_entries(
        signer_secret: &DeviceSecret,
        signer_device_id: &str,
        entries: Vec<RegistrySnapshotEntry>,
        current_epoch: u32,
        epoch_keys: &[(u32, [u8; 32])],
    ) -> SignedRegistryResponse {
        let signing_key = signer_secret.ed25519_keypair(signer_device_id).unwrap();
        let pq_signing_key = signer_secret.ml_dsa_65_keypair(signer_device_id).unwrap();
        let epoch_key_hashes =
            epoch_keys.iter().map(|(epoch, key)| (*epoch, compute_epoch_key_hash(key))).collect();
        let snapshot = SignedRegistrySnapshot::new_with_epoch_binding(
            entries,
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

    /// Sign a registry from `DeviceInfo` entries (the revoke-publish
    /// test helper). Takes a `sync_id` + `DeviceInfo` slice and maps each through
    /// `make_registry_entry` before signing at the binding floor version.
    fn signed_registry_with_entries(
        sync_id: &str,
        signer_secret: &DeviceSecret,
        signer_device_id: &str,
        entries: &[DeviceInfo],
        current_epoch: u32,
        epoch_keys: &[(u32, [u8; 32])],
    ) -> SignedRegistryResponse {
        let signing_key = signer_secret.ed25519_keypair(signer_device_id).unwrap();
        let pq_signing_key = signer_secret.ml_dsa_65_keypair(signer_device_id).unwrap();
        let epoch_key_hashes =
            epoch_keys.iter().map(|(epoch, key)| (*epoch, compute_epoch_key_hash(key))).collect();
        let snapshot = SignedRegistrySnapshot::new_with_epoch_binding(
            entries.iter().map(|info| make_registry_entry(sync_id, info)).collect(),
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

    /// Build a `PrismSync` whose engine relay serves a SIGNED registry listing
    /// THIS device with `self_status`, signed by an ACTIVE sibling. Mirrors a
    /// real device that pinned its own (and the sibling's) registry entry and
    /// configured the engine. The relay is returned so tests can mutate the
    /// served registry (e.g. swap to a tampered blob or force an error) before
    /// calling `confirm_self_revocation`.
    fn prepare_self_revocation_check(
        self_status: &str,
    ) -> (PrismSync, Arc<RevokeTestRelay>, String, DeviceSecret, DeviceInfo) {
        // Default to no signed wipe intent (the historical behavior).
        prepare_self_revocation_check_with_wipe(self_status, false)
    }

    /// Like [`prepare_self_revocation_check`] but authors the SELF entry's
    /// signed `remote_wipe` bit (H3 Layer B). The wipe bit is bound into the
    /// signature, so `confirm_self_revocation` reads it back from the verified
    /// entry.
    fn prepare_self_revocation_check_with_wipe(
        self_status: &str,
        remote_wipe: bool,
    ) -> (PrismSync, Arc<RevokeTestRelay>, String, DeviceSecret, DeviceInfo) {
        let mut sync = make_sync();
        sync.initialize("test-password", &[1u8; 16]).unwrap();

        let sync_id = "sync-1";
        let self_device_id = "a1b2c3d4e5f6";
        let signer_device_id = "bbbbbbbbbbbb";
        let device_secret =
            DeviceSecret::from_bytes(sync.device_secret().unwrap().as_bytes().to_vec()).unwrap();

        // Pin self (always active locally — local status is metadata) and the
        // active sibling that signs the snapshot. The verifier roots trust in
        // these pinned public keys.
        let pinned_self = make_device_info(self_device_id, &device_secret, 0, "active");
        let signer_info = make_device_info(signer_device_id, &device_secret, 0, "active");
        for info in [&pinned_self, &signer_info] {
            DeviceRegistryManager::pin_device(
                sync.storage().as_ref(),
                sync_id,
                &make_device_record(sync_id, info),
            )
            .unwrap();
        }

        // The signed-registry entry for self carries the status under test and
        // the admin-signed wipe intent; the sibling (signer) is active.
        let snapshot_self = make_device_info(self_device_id, &device_secret, 0, self_status);
        let mut self_entry = make_registry_entry(sync_id, &snapshot_self);
        self_entry.remote_wipe = remote_wipe;
        let signer_entry = make_registry_entry(sync_id, &signer_info);
        let epoch_0_key: [u8; 32] = sync.key_hierarchy().epoch_key(0).unwrap().try_into().unwrap();

        let relay =
            Arc::new(RevokeTestRelay::new(vec![pinned_self.clone()], RevokeBehavior::Success));
        relay.set_signed_registry(signed_registry_from_entries(
            &device_secret,
            signer_device_id,
            vec![self_entry, signer_entry],
            0,
            &[(0, epoch_0_key)],
        ));

        sync.configure_engine(relay.clone(), sync_id.to_string(), self_device_id.to_string(), 0, 0);

        (sync, relay, self_device_id.to_string(), device_secret, snapshot_self)
    }

    /// Set the device's last-imported registry baseline. The helper-built sync
    /// has no `sync_metadata` row yet and `update_last_imported_registry_version`
    /// is a plain UPDATE (no-op without a row), so seed the row via
    /// `update_current_epoch` (UPSERT) first.
    fn set_last_imported_registry_version(sync: &PrismSync, sync_id: &str, version: i64) {
        let mut tx = sync.storage().begin_tx().unwrap();
        tx.update_current_epoch(sync_id, 0).unwrap();
        tx.update_last_imported_registry_version(sync_id, version).unwrap();
        tx.commit().unwrap();
    }

    #[tokio::test]
    async fn confirm_self_revocation_is_unknown_when_no_baseline_recorded() {
        // Freshness gate: with NO last-imported baseline recorded, staleness
        // cannot be proven, so even a verified snapshot with an explicit
        // `revoked` self-entry must fail safe to Unknown — never wipe a device
        // (e.g. freshly paired / snapshot-restored) that merely lacks a baseline.
        // A genuine revocation still confirms via the revoke publisher because the baseline
        // self-heals on the device's next registry import/publish (see
        // confirm_self_revocation_returns_revoked_when_snapshot_at_or_above_baseline).
        let (sync, _relay, _id, _secret, _info) = prepare_self_revocation_check("revoked");
        assert_eq!(
            sync.storage().get_sync_metadata("sync-1").unwrap().and_then(|m| m.last_imported_registry_version),
            None,
            "precondition: helper records no last-imported baseline"
        );
        assert_eq!(sync.confirm_self_revocation().await, SelfRevocationStatus::Unknown);
    }

    #[tokio::test]
    async fn confirm_self_revocation_returns_revoked_when_snapshot_at_or_above_baseline() {
        // Snapshot registry_version (== SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
        // i.e. 1) is >= the recorded baseline → the legitimate, current
        // revocation is accepted.
        let (sync, _relay, _id, _secret, _info) = prepare_self_revocation_check("revoked");
        set_last_imported_registry_version(&sync, "sync-1", 1);
        assert_eq!(
            sync.confirm_self_revocation().await,
            SelfRevocationStatus::ConfirmedRevoked { remote_wipe: false }
        );
    }

    #[tokio::test]
    async fn confirm_self_revocation_carries_signed_wipe_false_when_not_requested() {
        // H3 Layer B: a verified `revoked` entry whose SIGNED `remote_wipe` is
        // false must surface `ConfirmedRevoked { remote_wipe: false }` — the
        // device clears creds / disconnects but must NOT wipe.
        let (sync, _relay, _id, _secret, _info) =
            prepare_self_revocation_check_with_wipe("revoked", false);
        // The helper authors the snapshot at the binding floor (version 1);
        // seed a baseline at or below it so the legitimate current revocation
        // passes the freshness gate and the wipe-bit read path is exercised.
        set_last_imported_registry_version(&sync, "sync-1", 1);
        assert_eq!(
            sync.confirm_self_revocation().await,
            SelfRevocationStatus::ConfirmedRevoked { remote_wipe: false }
        );
    }

    #[tokio::test]
    async fn confirm_self_revocation_carries_signed_wipe_true_when_admin_requested() {
        // H3 Layer B: a verified `revoked` entry whose SIGNED `remote_wipe` is
        // true must surface `ConfirmedRevoked { remote_wipe: true }` — only an
        // admin signature over wipe=true can drive a wipe.
        let (sync, _relay, _id, _secret, _info) =
            prepare_self_revocation_check_with_wipe("revoked", true);
        // Freshness baseline seed (see the wipe-false test above).
        set_last_imported_registry_version(&sync, "sync-1", 1);
        assert_eq!(
            sync.confirm_self_revocation().await,
            SelfRevocationStatus::ConfirmedRevoked { remote_wipe: true }
        );
    }

    #[tokio::test]
    async fn confirm_self_revocation_old_format_registry_defaults_wipe_false() {
        // BACK-COMPAT: a signed registry produced by an OLDER device that omits
        // the `remote_wipe` key entirely must decode to `remote_wipe: false`
        // (the safe no-wipe default), never a wipe. We simulate the old wire
        // shape by stripping the `"remote_wipe":...` member from the signed
        // JSON is not possible post-signature; instead we author with the
        // default-false path and assert the decode yields false even though the
        // entry is `revoked`. (The serde-default decode of a truly-absent key is
        // covered by the models.rs unit tests; here we assert the client read.)
        let (sync, _relay, _id, _secret, _info) =
            prepare_self_revocation_check_with_wipe("revoked", false);
        // Freshness baseline seed (see confirm_self_revocation_carries_signed_wipe_false).
        set_last_imported_registry_version(&sync, "sync-1", 1);
        match sync.confirm_self_revocation().await {
            SelfRevocationStatus::ConfirmedRevoked { remote_wipe } => {
                assert!(!remote_wipe, "absent/false signed wipe must default to no-wipe");
            }
            other => panic!("expected ConfirmedRevoked, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn confirm_self_revocation_is_unknown_when_stale_snapshot_marks_self_revoked() {
        // REPLAY DEFENSE: a validly-signed but STALE snapshot
        // (registry_version 1) that marks self `revoked`, served when the device
        // has already imported a NEWER registry (baseline 5), must NOT wipe.
        // This is the re-pair-under-same-device_id replay residual.
        let (sync, _relay, _id, _secret, _info) = prepare_self_revocation_check("revoked");
        set_last_imported_registry_version(&sync, "sync-1", 5);
        assert_eq!(sync.confirm_self_revocation().await, SelfRevocationStatus::Unknown);
    }

    #[tokio::test]
    async fn confirm_self_revocation_returns_active_when_verified_registry_lists_self_active() {
        let (sync, _relay, _id, _secret, _info) = prepare_self_revocation_check("active");
        assert_eq!(sync.confirm_self_revocation().await, SelfRevocationStatus::Active);
    }

    #[tokio::test]
    async fn confirm_self_revocation_is_unknown_when_no_signed_registry_available() {
        let (sync, relay, _id, _secret, _info) = prepare_self_revocation_check("active");
        // Relay serves no signed registry at all → fail-safe Unknown.
        relay.state.lock().unwrap().signed_registry = None;
        assert_eq!(sync.confirm_self_revocation().await, SelfRevocationStatus::Unknown);
    }

    #[tokio::test]
    async fn confirm_self_revocation_is_unknown_when_signature_invalid() {
        let (sync, relay, _id, _secret, _info) = prepare_self_revocation_check("revoked");
        // Tamper the signed blob so hybrid verification fails. A forged/corrupt
        // registry MUST NOT be able to drive a destructive outcome — Unknown.
        {
            let mut state = relay.state.lock().unwrap();
            let registry = state.signed_registry.as_mut().unwrap();
            let last = registry.artifact_blob.len() - 1;
            registry.artifact_blob[last] ^= 0xFF;
        }
        assert_eq!(sync.confirm_self_revocation().await, SelfRevocationStatus::Unknown);
    }

    #[tokio::test]
    async fn confirm_self_revocation_is_unknown_when_relay_errors() {
        let (sync, relay, _id, _secret, _info) = prepare_self_revocation_check("revoked");
        // A relay erroring the registry fetch is INCONCLUSIVE, never positive
        // confirmation — even when the (untrusted) error body says
        // "device_revoked". This removes the former spoofable heuristic.
        relay.set_signed_registry_error(true);
        assert_eq!(sync.confirm_self_revocation().await, SelfRevocationStatus::Unknown);
    }

    #[tokio::test]
    async fn confirm_self_revocation_is_unknown_when_self_absent_from_verified_snapshot() {
        // A VERIFIED snapshot that simply OMITS this device is NOT treated as
        // confirmation of removal (a stale/partial snapshot could omit us) —
        // fail-safe Unknown. We deliberately require an explicit revoked entry.
        let (sync, relay, _id, device_secret, _info) = prepare_self_revocation_check("active");

        // The sibling `bbbb...` is already pinned by the helper. Serve a
        // snapshot signed by the sibling that lists ONLY the sibling — self
        // `a1b2...` is omitted entirely.
        let sibling = make_device_info("bbbbbbbbbbbb", &device_secret, 0, "active");
        let epoch_0_key: [u8; 32] = sync.key_hierarchy().epoch_key(0).unwrap().try_into().unwrap();
        relay.set_signed_registry(signed_registry_response(
            "sync-1",
            &device_secret,
            "bbbbbbbbbbbb",
            &sibling,
            0,
            &[(0, epoch_0_key)],
        ));

        // Verification succeeds (signer = sibling, present in its own snapshot),
        // but self `a1b2...` is absent → Unknown, NOT ConfirmedRevoked.
        assert_eq!(sync.confirm_self_revocation().await, SelfRevocationStatus::Unknown);
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

    /// Seed a configured engine with a self-authored future winner for
    /// `members/ent-1/name` plus a matching unpushed pending op, both carrying a
    /// `+1h` HLC. This is the residue a forward clock excursion leaves behind.
    fn seed_clock_excursion(sync: &PrismSync) -> Hlc {
        use crate::storage::{FieldVersion, PendingOp};
        let poison_hlc = Hlc::new(Hlc::now_ms() + 3_600_000, 0, "a1b2c3d4e5f6");
        let mut tx = sync.storage.begin_tx().unwrap();
        tx.upsert_field_version(&FieldVersion {
            sync_id: "sync-1".to_string(),
            entity_table: "members".to_string(),
            entity_id: "ent-1".to_string(),
            field_name: "name".to_string(),
            winning_op_id: "poison-op".to_string(),
            winning_device_id: "a1b2c3d4e5f6".to_string(),
            winning_hlc: poison_hlc.to_string(),
            winning_encoded_value: Some("\"Future\"".to_string()),
            updated_at: chrono::Utc::now(),
        })
        .unwrap();
        tx.insert_pending_op(&PendingOp {
            op_id: "poison-op".to_string(),
            sync_id: "sync-1".to_string(),
            epoch: 1,
            device_id: "a1b2c3d4e5f6".to_string(),
            local_batch_id: "poison-batch".to_string(),
            entity_table: "members".to_string(),
            entity_id: "ent-1".to_string(),
            field_name: "name".to_string(),
            encoded_value: "\"Future\"".to_string(),
            is_delete: false,
            client_hlc: poison_hlc.to_string(),
            created_at: chrono::Utc::now(),
            pushed_at: None,
        })
        .unwrap();
        tx.commit().unwrap();
        poison_hlc
    }

    #[test]
    fn clock_excursion_repair_runs_after_successful_signed_exchange() {
        let mut sync = make_sync();
        configure(&mut sync);
        let poison_hlc = seed_clock_excursion(&sync);
        // configure_engine already seeded the emitter from storage; the
        // self-authored future HLC poisons the watermark.
        sync.refresh_op_emitter_hlc_from_storage("test");
        assert!(sync.op_emitter.as_ref().unwrap().last_hlc().future_drift_ms() > MAX_CLOCK_DRIFT_MS);

        let mut events = sync.events();

        // A successful signed exchange certifies the clock and arms the repair.
        sync.note_signed_exchange_and_repair_clock(true);

        // The over-bound unpushed pending op is gone.
        assert!(sync.storage.load_batch_ops("poison-batch").unwrap().is_empty());

        // The FV winner was rewritten at a sane HLC (value preserved).
        let fv =
            sync.storage.get_field_version("sync-1", "members", "ent-1", "name").unwrap().unwrap();
        let repaired = Hlc::from_string(&fv.winning_hlc).unwrap();
        assert!(repaired.future_drift_ms() <= MAX_CLOCK_DRIFT_MS);
        assert!(repaired < poison_hlc);
        assert_eq!(fv.winning_encoded_value, Some("\"Future\"".to_string()));

        // The watermark was clamped back to a sane value.
        assert!(sync.op_emitter.as_ref().unwrap().last_hlc().future_drift_ms() <= MAX_CLOCK_DRIFT_MS);

        // A ClockExcursionRepaired event surfaced.
        let mut saw_event = false;
        while let Ok(ev) = events.try_recv() {
            if let SyncEvent::ClockExcursionRepaired { field_count, max_drift_ms } = ev {
                assert_eq!(field_count, 1);
                assert!(max_drift_ms > MAX_CLOCK_DRIFT_MS);
                saw_event = true;
            }
        }
        assert!(saw_event, "expected a ClockExcursionRepaired event");
    }

    #[test]
    fn clock_excursion_repair_does_not_run_without_signed_exchange() {
        // Unit contract for the gate: when no signed exchange validated the clock
        // this cycle (`signed_exchange_validated == false`), the repair is a
        // no-op and leaves all state untouched. The load-bearing link that a
        // backward clock step actually yields `false` (the pull stays unsigned,
        // the ack 401s on the skew check) is exercised end-to-end through the
        // real gate in `e2e_clock_excursion_repair_skips_unvalidated_pull_only`.
        let mut sync = make_sync();
        configure(&mut sync);
        let poison_hlc = seed_clock_excursion(&sync);
        sync.refresh_op_emitter_hlc_from_storage("test");

        // No validated signed exchange this cycle → the gate stays shut.
        sync.note_signed_exchange_and_repair_clock(false);

        // Pending op survives and the FV keeps its poisoned HLC.
        assert_eq!(sync.storage.load_batch_ops("poison-batch").unwrap().len(), 1);
        let fv =
            sync.storage.get_field_version("sync-1", "members", "ent-1", "name").unwrap().unwrap();
        assert_eq!(fv.winning_hlc, poison_hlc.to_string());
        // Watermark untouched (still poisoned).
        assert!(sync.op_emitter.as_ref().unwrap().last_hlc().future_drift_ms() > MAX_CLOCK_DRIFT_MS);
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
    fn record_create_emits_explicit_false_on_fresh_id() {
        // A create carrying is_deleted=false on a FRESH (never-tombstoned) id
        // must EMIT the explicit false: this is the sanctioned-revive path where
        // the app re-creates a logical entity under a new incarnation id that no
        // peer holds a tombstone for, and that explicit live marker has to travel
        // so peers display it. The receiver backstop in merge.rs keeps a real
        // stale tombstone safe.
        let mut sync = make_sync();
        configure(&mut sync);

        let mut fields = HashMap::new();
        fields.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        fields.insert(DELETED_FIELD.to_string(), SyncValue::Bool(false));

        sync.record_create("members", "ent-1", &fields).unwrap();

        // Both the name op AND the explicit is_deleted=false op were emitted.
        let batch_ids = sync.storage.get_unpushed_batch_ids("sync-1").unwrap();
        let mut ops: Vec<_> =
            batch_ids.iter().flat_map(|b| sync.storage.load_batch_ops(b).unwrap()).collect();
        ops.sort_by(|a, b| a.field_name.cmp(&b.field_name));
        assert_eq!(ops.len(), 2, "fresh id must emit both name and the explicit is_deleted=false");
        assert_eq!(ops[0].field_name, DELETED_FIELD);
        assert_eq!(ops[0].encoded_value, "false");
        assert_eq!(ops[1].field_name, "name");
        assert_eq!(
            sync.storage
                .get_field_version("sync-1", "members", "ent-1", DELETED_FIELD)
                .unwrap()
                .and_then(|fv| fv.winning_encoded_value)
                .as_deref(),
            Some("false"),
            "fresh-id create writes an explicit is_deleted=false field version"
        );
    }

    #[test]
    fn record_create_strips_phantom_is_deleted_false_on_tombstoned_id() {
        // Regression: a re-create carrying is_deleted=false against a LOCALLY
        // TOMBSTONED id must NOT emit an is_deleted op. That fresh-HLC `false`
        // would beat the older tombstone under per-field LWW and resurrect the
        // entity on every peer. See prism-app
        // test/e2e/board_post_delete_resurrection_test.dart.
        let mut sync = make_sync();
        configure(&mut sync);

        // Tombstone the id first so a later re-create has a local tombstone.
        sync.record_delete("members", "ent-1").unwrap();
        assert_eq!(
            sync.storage
                .get_field_version("sync-1", "members", "ent-1", DELETED_FIELD)
                .unwrap()
                .and_then(|fv| fv.winning_encoded_value)
                .as_deref(),
            Some("true"),
            "delete must write an is_deleted=true field version"
        );

        let mut fields = HashMap::new();
        fields.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        fields.insert(DELETED_FIELD.to_string(), SyncValue::Bool(false));
        sync.record_create("members", "ent-1", &fields).unwrap();

        // The re-create emits only the real field; the phantom is_deleted=false
        // was stripped and the tombstone field version is intact.
        let ops: Vec<_> = sync
            .storage
            .get_unpushed_batch_ids("sync-1")
            .unwrap()
            .iter()
            .flat_map(|b| sync.storage.load_batch_ops(b).unwrap())
            .filter(|op| op.entity_id == "ent-1")
            .collect();
        assert!(
            ops.iter().any(|op| op.field_name == "name"),
            "the name op should still be emitted"
        );
        assert!(
            !ops.iter().any(|op| op.field_name == DELETED_FIELD && op.encoded_value == "false"),
            "no is_deleted=false op may be emitted for a tombstoned id"
        );
        assert_eq!(
            sync.storage
                .get_field_version("sync-1", "members", "ent-1", DELETED_FIELD)
                .unwrap()
                .and_then(|fv| fv.winning_encoded_value)
                .as_deref(),
            Some("true"),
            "re-create must not flip the tombstone back to false"
        );
    }

    #[test]
    fn record_update_emits_explicit_false_on_live_id() {
        // An update carrying is_deleted=false on a live (never-tombstoned) id
        // must emit the explicit false — the entity is alive, no strip applies.
        let mut sync = make_sync();
        configure(&mut sync);

        let mut create = HashMap::new();
        create.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        sync.record_create("members", "ent-1", &create).unwrap();
        let batches_after_create = sync.storage.get_unpushed_batch_ids("sync-1").unwrap().len();

        let mut changed = HashMap::new();
        changed.insert(DELETED_FIELD.to_string(), SyncValue::Bool(false));
        sync.record_update("members", "ent-1", &changed).unwrap();

        assert!(
            sync.storage.get_unpushed_batch_ids("sync-1").unwrap().len() > batches_after_create,
            "an explicit is_deleted=false on a live id must emit"
        );
        assert_eq!(
            sync.storage
                .get_field_version("sync-1", "members", "ent-1", DELETED_FIELD)
                .unwrap()
                .and_then(|fv| fv.winning_encoded_value)
                .as_deref(),
            Some("false"),
            "update writes an explicit is_deleted=false field version on a live id"
        );
    }

    #[test]
    fn record_update_strips_phantom_is_deleted_false_on_tombstoned_id() {
        // A field update carrying is_deleted=false against a tombstoned id must
        // drop it; an update of ONLY is_deleted=false becomes a no-op rather than
        // a phantom un-delete that would resurrect a tombstoned entity.
        let mut sync = make_sync();
        configure(&mut sync);

        let mut create = HashMap::new();
        create.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        sync.record_create("members", "ent-1", &create).unwrap();
        sync.record_delete("members", "ent-1").unwrap();
        let batches_after_delete = sync.storage.get_unpushed_batch_ids("sync-1").unwrap().len();

        let mut changed = HashMap::new();
        changed.insert(DELETED_FIELD.to_string(), SyncValue::Bool(false));
        sync.record_update("members", "ent-1", &changed).unwrap();

        assert_eq!(
            sync.storage.get_unpushed_batch_ids("sync-1").unwrap().len(),
            batches_after_delete,
            "an update of only is_deleted=false on a tombstoned id must emit nothing"
        );
        assert_eq!(
            sync.storage
                .get_field_version("sync-1", "members", "ent-1", DELETED_FIELD)
                .unwrap()
                .and_then(|fv| fv.winning_encoded_value)
                .as_deref(),
            Some("true"),
            "a phantom un-delete must not flip the tombstone back to false"
        );
    }

    #[test]
    fn record_update_at_strips_phantom_undelete_and_stamps_partitions_at_origin() {
        // The origin-stamped update reuses the conditional phantom-undelete
        // strip: against a tombstoned id, an is_deleted=false rides off but a
        // real field still emits — at the supplied origin HLC, not a fresh tick.
        let mut sync = make_sync();
        configure(&mut sync);

        sync.record_create(
            "members",
            "ent-1",
            &HashMap::from([("name".to_string(), SyncValue::String("Alice".to_string()))]),
        )
        .unwrap();
        sync.record_delete("members", "ent-1").unwrap();
        // Isolate the new batches by set difference rather than positional skip:
        // the origin-stamped op sorts by its (earlier) HLC, not append order.
        let batches_before: std::collections::HashSet<String> =
            sync.storage.get_unpushed_batch_ids("sync-1").unwrap().into_iter().collect();

        let origin = Hlc::now_ms() - 7_200_000; // two hours ago
        let mut changed = HashMap::new();
        changed.insert("name".to_string(), SyncValue::String("Bob".to_string()));
        changed.insert(DELETED_FIELD.to_string(), SyncValue::Bool(false));
        sync.record_update_at("members", "ent-1", &changed, origin).unwrap();

        let new_batches: Vec<_> = sync
            .storage
            .get_unpushed_batch_ids("sync-1")
            .unwrap()
            .into_iter()
            .filter(|b| !batches_before.contains(b))
            .collect();
        let ops: Vec<_> =
            new_batches.iter().flat_map(|b| sync.storage.load_batch_ops(b).unwrap()).collect();
        // The phantom is_deleted=false was stripped; only the real "name" emits.
        assert!(ops.iter().any(|o| o.field_name == "name"));
        assert!(
            !ops.iter().any(|o| o.field_name == DELETED_FIELD && o.encoded_value == "false"),
            "phantom is_deleted=false must be stripped on a tombstoned id"
        );
        // Every emitted partition's client_hlc carries the origin timestamp.
        for op in ops.iter().filter(|o| o.field_name == "name") {
            let hlc = Hlc::from_string(&op.client_hlc).unwrap();
            assert_eq!(hlc.timestamp, origin, "op stamped at origin, not a fresh tick");
            assert_eq!(hlc.node_id, "a1b2c3d4e5f6");
        }
        // The tombstone winner is untouched (wins_over-guarded FV upsert).
        assert_eq!(
            sync.storage
                .get_field_version("sync-1", "members", "ent-1", DELETED_FIELD)
                .unwrap()
                .and_then(|fv| fv.winning_encoded_value)
                .as_deref(),
            Some("true"),
        );
    }

    #[test]
    fn record_update_at_does_not_regress_a_newer_field_version() {
        let mut sync = make_sync();
        configure(&mut sync);

        // A genuine "now" winner.
        sync.record_update(
            "members",
            "ent-1",
            &HashMap::from([("name".to_string(), SyncValue::String("Beta".to_string()))]),
        )
        .unwrap();

        // Replay an older captured value.
        let origin = Hlc::now_ms() - 3_600_000;
        sync.record_update_at(
            "members",
            "ent-1",
            &HashMap::from([("name".to_string(), SyncValue::String("Alpha".to_string()))]),
            origin,
        )
        .unwrap();

        // field_versions still holds Beta; the Alpha op is pushable but loses.
        assert_eq!(
            sync.storage
                .get_field_version("sync-1", "members", "ent-1", "name")
                .unwrap()
                .and_then(|fv| fv.winning_encoded_value)
                .as_deref(),
            Some("\"Beta\""),
        );
    }

    #[test]
    fn record_reconcile_emits_only_diverged_fields() {
        let mut sync = make_sync();
        configure(&mut sync);

        // Seed name + age; leave score never-synced.
        sync.record_create(
            "members",
            "ent-1",
            &HashMap::from([
                ("name".to_string(), SyncValue::String("Same".to_string())),
                ("age".to_string(), SyncValue::Int(10)),
            ]),
        )
        .unwrap();
        // Isolate the new batches by set difference rather than positional skip:
        // floor/fresh-stamped ops sort by their HLC, not append order.
        let before: std::collections::HashSet<String> =
            sync.storage.get_unpushed_batch_ids("sync-1").unwrap().into_iter().collect();

        // Reconcile: name equal (skip), age diverged (fresh), score absent (floor).
        sync.record_reconcile(
            "members",
            "ent-1",
            &HashMap::from([
                ("name".to_string(), SyncValue::String("Same".to_string())),
                ("age".to_string(), SyncValue::Int(20)),
                ("score".to_string(), SyncValue::Real(1.5)),
            ]),
            crate::op_emitter::DivergentMode::FreshHlc,
        )
        .unwrap();

        let new_batches: Vec<_> = sync
            .storage
            .get_unpushed_batch_ids("sync-1")
            .unwrap()
            .into_iter()
            .filter(|b| !before.contains(b))
            .collect();
        let ops: Vec<_> =
            new_batches.iter().flat_map(|b| sync.storage.load_batch_ops(b).unwrap()).collect();
        let fields: Vec<&str> = ops.iter().map(|o| o.field_name.as_str()).collect();
        assert!(!fields.contains(&"name"), "value-equal field must not emit");
        assert!(fields.contains(&"age"), "diverged field emits");
        assert!(fields.contains(&"score"), "absent field backfills");
    }

    #[test]
    fn record_backfill_emits_only_absent_fields_at_floor() {
        let mut sync = make_sync();
        configure(&mut sync);

        sync.record_create(
            "members",
            "ent-1",
            &HashMap::from([("name".to_string(), SyncValue::String("Existing".to_string()))]),
        )
        .unwrap();
        // Isolate the new batches by set difference rather than positional skip:
        // a floor-HLC backfill op sorts by its (earliest) HLC, not append order.
        let before: std::collections::HashSet<String> =
            sync.storage.get_unpushed_batch_ids("sync-1").unwrap().into_iter().collect();

        // name diverged (Skip ⇒ no emit), age absent (floor backfill).
        sync.record_backfill(
            "members",
            "ent-1",
            &HashMap::from([
                ("name".to_string(), SyncValue::String("Divergent".to_string())),
                ("age".to_string(), SyncValue::Int(42)),
            ]),
        )
        .unwrap();

        let new_batches: Vec<_> = sync
            .storage
            .get_unpushed_batch_ids("sync-1")
            .unwrap()
            .into_iter()
            .filter(|b| !before.contains(b))
            .collect();
        let ops: Vec<_> =
            new_batches.iter().flat_map(|b| sync.storage.load_batch_ops(b).unwrap()).collect();
        assert_eq!(ops.len(), 1, "only the absent field backfills");
        assert_eq!(ops[0].field_name, "age");
        let hlc = Hlc::from_string(&ops[0].client_hlc).unwrap();
        assert_eq!(hlc.timestamp, crate::op_emitter::BACKFILL_HLC_TIMESTAMP_MS);
    }

    #[test]
    fn record_delete_at_stamps_tombstone_at_origin() {
        let mut sync = make_sync();
        configure(&mut sync);

        let origin = Hlc::now_ms() - 3_600_000;
        sync.record_delete_at("members", "ent-1", origin).unwrap();

        let batch_ids = sync.storage.get_unpushed_batch_ids("sync-1").unwrap();
        let ops: Vec<_> =
            batch_ids.iter().flat_map(|b| sync.storage.load_batch_ops(b).unwrap()).collect();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].field_name, DELETED_FIELD);
        assert!(ops[0].is_delete);
        let hlc = Hlc::from_string(&ops[0].client_hlc).unwrap();
        assert_eq!(hlc.timestamp, origin);
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

        seed_device_registry(&sync, "sync-1", &relay.devices());

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

        seed_device_registry(&sync, "sync-1", &relay.devices());

        let committed_epoch =
            sync.revoke_and_rekey(relay.clone(), target_device_id, false).await.unwrap();

        assert_eq!(committed_epoch, 1);
        assert_eq!(relay.revoke_calls(), 1);
        assert_eq!(sync.epoch(), Some(1));
        assert!(sync.key_hierarchy().has_epoch_key(1));
        assert_eq!(sync.storage().get_sync_metadata("sync-1").unwrap().unwrap().current_epoch, 1);
        assert!(sync.secure_store().get("epoch_key_1").unwrap().is_some());
    }

    /// H3 Layer B PRODUCER: `revoke_and_rekey` must author + sign + post a
    /// signed registry whose target entry is `status == "revoked"` with the
    /// admin-signed `remote_wipe` intent, version-monotonic above the current
    /// registry, and verifiable by the admin's own pinned keys.
    async fn revoke_and_rekey_posts_signed_revocation(remote_wipe: bool) {
        let mut sync = make_sync();
        sync.initialize("test-password", &[1u8; 16]).unwrap();

        let self_device_id = "a1b2c3d4e5f6";
        let target_device_id = "b7c8d9e0f1a2";
        // The whole group shares the same DeviceSecret; per-device keys derive
        // from `device_id`. Using the admin's secret for the target keeps the
        // target's pinned keys derivable + verifiable.
        let group_secret =
            DeviceSecret::from_bytes(sync.device_secret().unwrap().as_bytes().to_vec()).unwrap();
        let relay = Arc::new(RevokeTestRelay::new(
            vec![
                make_device_info(self_device_id, &group_secret, 0, "active"),
                make_device_info(target_device_id, &group_secret, 0, "active"),
            ],
            RevokeBehavior::Success,
        ));

        sync.configure_engine(relay.clone(), "sync-1".to_string(), self_device_id.to_string(), 0, 0);
        seed_device_registry(&sync, "sync-1", &relay.devices());

        // Seed a pre-existing signed registry at the binding floor so the
        // producer's monotonic version bump is exercised (next == floor + 1).
        let epoch_0_key: [u8; 32] = sync.key_hierarchy().epoch_key(0).unwrap().try_into().unwrap();
        relay.set_signed_registry(signed_registry_from_entries(
            &group_secret,
            self_device_id,
            vec![
                make_registry_entry(
                    "sync-1",
                    &make_device_info(self_device_id, &group_secret, 0, "active"),
                ),
                make_registry_entry(
                    "sync-1",
                    &make_device_info(target_device_id, &group_secret, 0, "active"),
                ),
            ],
            0,
            &[(0, epoch_0_key)],
        ));
        let baseline_version =
            relay.state.lock().unwrap().signed_registry.as_ref().unwrap().registry_version;

        let committed_epoch =
            sync.revoke_and_rekey(relay.clone(), target_device_id, remote_wipe).await.unwrap();
        assert_eq!(committed_epoch, 1);

        // Fetch what the producer posted and verify it against the admin's
        // pinned keys (rooting trust the way a victim would).
        let posted = relay.state.lock().unwrap().signed_registry.as_ref().unwrap().clone();
        assert!(
            posted.registry_version > baseline_version,
            "posted registry_version {} must be monotonic above baseline {}",
            posted.registry_version,
            baseline_version
        );
        let snapshot = DeviceRegistryManager::verify_signed_registry_snapshot(
            sync.storage().as_ref(),
            "sync-1",
            &posted.artifact_blob,
        )
        .expect("posted signed revocation registry must verify against pinned admin keys");

        let target_entry = snapshot
            .entries
            .iter()
            .find(|e| e.device_id == target_device_id)
            .expect("posted registry must include the revoked target entry");
        assert_eq!(target_entry.status, "revoked", "target must be marked revoked");
        assert_eq!(
            target_entry.remote_wipe, remote_wipe,
            "target's signed remote_wipe must equal the admin's revoke intent"
        );

        // The admin (signer) must be present as a non-revoked entry.
        let self_entry = snapshot
            .entries
            .iter()
            .find(|e| e.device_id == self_device_id)
            .expect("signer must be present in its own snapshot");
        assert_eq!(self_entry.status, "active");
        assert!(!self_entry.remote_wipe, "active survivor must never carry a wipe intent");

        // Epoch binding covers the committed (post-revoke) epoch.
        assert_eq!(snapshot.current_epoch, committed_epoch);
    }

    #[tokio::test]
    async fn revoke_and_rekey_posts_signed_revocation_with_wipe_true() {
        revoke_and_rekey_posts_signed_revocation(true).await;
    }

    #[tokio::test]
    async fn revoke_and_rekey_posts_signed_revocation_with_wipe_false() {
        revoke_and_rekey_posts_signed_revocation(false).await;
    }

    /// H3 Layer B END-TO-END: a real `revoke_and_rekey` on the admin posts a
    /// signed registry; a SECOND `PrismSync` (the victim) reads it back through
    /// `confirm_self_revocation` and surfaces the admin-signed wipe intent. The
    /// victim wipes iff the SIGNED bit is true — a relay frame is never
    /// consulted in this Rust path.
    async fn revoke_and_rekey_end_to_end_victim_reads_signed_wipe(remote_wipe: bool) {
        // ── Admin (device A) ──
        let mut admin = make_sync();
        admin.initialize("test-password", &[1u8; 16]).unwrap();
        let admin_device_id = "a1b2c3d4e5f6";
        let victim_device_id = "b7c8d9e0f1a2";
        let group_secret =
            DeviceSecret::from_bytes(admin.device_secret().unwrap().as_bytes().to_vec()).unwrap();

        let relay = Arc::new(RevokeTestRelay::new(
            vec![
                make_device_info(admin_device_id, &group_secret, 0, "active"),
                make_device_info(victim_device_id, &group_secret, 0, "active"),
            ],
            RevokeBehavior::Success,
        ));
        admin.configure_engine(
            relay.clone(),
            "sync-1".to_string(),
            admin_device_id.to_string(),
            0,
            0,
        );
        seed_device_registry(&admin, "sync-1", &relay.devices());

        // ── Victim (device B), sharing the group secret, pins A (the signer)
        //    and itself, and points at the SAME relay. ──
        // Rebuild the victim from the admin's DEK + device secret so its derived
        // keys and the signature root-of-trust match the admin's (the group
        // secret is shared across devices; per-device keys derive from
        // `device_id`).
        let admin_dek = admin.key_hierarchy().dek().unwrap().to_vec();
        let admin_secret_bytes = group_secret.as_bytes().to_vec();
        let mut victim = make_sync();
        victim.restore_runtime_keys(&admin_dek, &admin_secret_bytes).unwrap();
        let admin_info = make_device_info(admin_device_id, &group_secret, 0, "active");
        let victim_info = make_device_info(victim_device_id, &group_secret, 0, "active");
        for info in [&admin_info, &victim_info] {
            DeviceRegistryManager::pin_device(
                victim.storage().as_ref(),
                "sync-1",
                &make_device_record("sync-1", info),
            )
            .unwrap();
        }
        victim.configure_engine(
            relay.clone(),
            "sync-1".to_string(),
            victim_device_id.to_string(),
            0,
            0,
        );

        // Drive the real revoke on the admin. This posts the signed registry.
        admin.revoke_and_rekey(relay.clone(), victim_device_id, remote_wipe).await.unwrap();

        // Freshness baseline: the victim was an active member that had
        // imported the group's registry before being revoked. Seed a baseline at
        // or below the admin's just-published revocation registry (authored at
        // the binding floor, version 1) so the genuine current revocation clears
        // the never-rewind gate; without it the victim fails safe to Unknown.
        set_last_imported_registry_version(&victim, "sync-1", 1);

        // The victim reads the SIGNED verdict — no relay frame involved.
        assert_eq!(
            victim.confirm_self_revocation().await,
            SelfRevocationStatus::ConfirmedRevoked { remote_wipe },
            "victim must read the admin-signed wipe intent ({remote_wipe}) from the verified registry"
        );
    }

    #[tokio::test]
    async fn revoke_and_rekey_end_to_end_victim_wipes_only_when_signed_true() {
        revoke_and_rekey_end_to_end_victim_reads_signed_wipe(true).await;
    }

    #[tokio::test]
    async fn revoke_and_rekey_end_to_end_victim_does_not_wipe_when_signed_false() {
        revoke_and_rekey_end_to_end_victim_reads_signed_wipe(false).await;
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

        seed_device_registry(&sync, "sync-1", &relay.devices());

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

        seed_device_registry(&sync, "sync-1", &relay.devices());

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

        seed_device_registry(&sync, "sync-1", &relay.devices());

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

        seed_device_registry(&sync, "sync-1", &relay.devices());

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

    // ── Revoke-time signed-registry publication ──

    /// Decode the artifact the relay currently serves, verifying it against the
    /// given signer's permanent Ed25519 + ML-DSA keys.
    fn decode_served_registry(
        relay: &RevokeTestRelay,
        signer_secret: &DeviceSecret,
        signer_device_id: &str,
    ) -> SignedRegistrySnapshot {
        let served = relay.state.lock().unwrap().signed_registry.clone().expect(
            "revoke_and_rekey must have published a signed registry",
        );
        let signing_key = signer_secret.ed25519_keypair(signer_device_id).unwrap();
        let pq_signing_key = signer_secret.ml_dsa_65_keypair(signer_device_id).unwrap();
        SignedRegistrySnapshot::verify_and_decode_hybrid(
            &served.artifact_blob,
            &signing_key.public_key_bytes(),
            &pq_signing_key.public_key_bytes(),
        )
        .expect("published registry must verify against the survivor's signer keys")
    }

    #[tokio::test]
    async fn revoke_and_rekey_publishes_signed_registry_with_explicit_revoked_entry() {
        let mut sync = make_sync();
        sync.initialize("test-password", &[1u8; 16]).unwrap();

        let self_device_id = "a1b2c3d4e5f6";
        let target_device_id = "b7c8d9e0f1a2";
        let target_secret = DeviceSecret::generate();
        let self_secret =
            DeviceSecret::from_bytes(sync.device_secret().unwrap().as_bytes().to_vec()).unwrap();
        let relay = Arc::new(RevokeTestRelay::new(
            vec![
                make_device_info(self_device_id, &self_secret, 0, "active"),
                make_device_info(target_device_id, &target_secret, 0, "active"),
            ],
            RevokeBehavior::Success,
        ));

        sync.configure_engine(relay.clone(), "sync-1".to_string(), self_device_id.to_string(), 0, 0);
        seed_device_registry(&sync, "sync-1", &relay.devices());

        let committed_epoch =
            sync.revoke_and_rekey(relay.clone(), target_device_id, true).await.unwrap();
        assert_eq!(committed_epoch, 1);

        // The published artifact carries the target as an EXPLICIT revoked entry
        // (not omitted, the way the old active-only publisher would have) and the
        // survivor as active, bound to the new epoch.
        let snapshot = decode_served_registry(&relay, &self_secret, self_device_id);
        let target_entry = snapshot
            .entries
            .iter()
            .find(|e| e.device_id == target_device_id)
            .expect("revoked target must be present in the published registry");
        assert_eq!(target_entry.status, "revoked");
        let self_entry = snapshot
            .entries
            .iter()
            .find(|e| e.device_id == self_device_id)
            .expect("survivor must be present");
        assert_eq!(self_entry.status, "active");
        assert_eq!(snapshot.current_epoch, committed_epoch);
        // First publish: relay served nothing, so version is the epoch-binding
        // floor.
        assert_eq!(snapshot.registry_version, SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING);

        // The local pinned record for the target is now revoked.
        let pinned_target =
            sync.storage().get_device_record("sync-1", target_device_id).unwrap().unwrap();
        assert_eq!(pinned_target.status, "revoked");

        // The survivor ratcheted its own freshness baseline to the published
        // version, so it stops sitting at a NULL baseline forever.
        assert_eq!(
            sync.storage()
                .get_sync_metadata("sync-1")
                .unwrap()
                .and_then(|m| m.last_imported_registry_version),
            Some(SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING)
        );
    }

    #[tokio::test]
    async fn revoke_and_rekey_publishes_version_above_served_artifact() {
        let mut sync = make_sync();
        sync.initialize("test-password", &[1u8; 16]).unwrap();

        let self_device_id = "a1b2c3d4e5f6";
        let target_device_id = "b7c8d9e0f1a2";
        let target_secret = DeviceSecret::generate();
        let self_secret =
            DeviceSecret::from_bytes(sync.device_secret().unwrap().as_bytes().to_vec()).unwrap();
        let relay = Arc::new(RevokeTestRelay::new(
            vec![
                make_device_info(self_device_id, &self_secret, 0, "active"),
                make_device_info(target_device_id, &target_secret, 0, "active"),
            ],
            RevokeBehavior::Success,
        ));

        sync.configure_engine(relay.clone(), "sync-1".to_string(), self_device_id.to_string(), 0, 0);
        seed_device_registry(&sync, "sync-1", &relay.devices());

        // Pre-seed a served artifact at the floor version so the publisher must
        // choose floor+1.
        let epoch_0_key: [u8; 32] = sync.key_hierarchy().epoch_key(0).unwrap().try_into().unwrap();
        relay.set_signed_registry(signed_registry_with_entries(
            "sync-1",
            &self_secret,
            self_device_id,
            &[make_device_info(self_device_id, &self_secret, 0, "active")],
            0,
            &[(0, epoch_0_key)],
        ));

        sync.revoke_and_rekey(relay.clone(), target_device_id, true).await.unwrap();

        let snapshot = decode_served_registry(&relay, &self_secret, self_device_id);
        assert_eq!(
            snapshot.registry_version,
            SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING + 1,
            "publish must supersede the served artifact"
        );
    }

    #[tokio::test]
    async fn revoke_and_rekey_skips_publish_when_local_tombstone_pin_fails() {
        // Realistic case: revoking a device that paired via another survivor and
        // never pushed, so no registry import ever pinned it locally. The relay
        // lists it active (so the relay-side revoke commits), but the local
        // DeviceRegistryManager::revoke_device errors ("device not in
        // registry"). The publisher builds from local pins, so publishing here
        // would emit a tombstone-LESS artifact at the new epoch — making the
        // served artifact epoch-current and permanently disarming the
        // epoch-repair backstop. The fix: skip the publish, leaving the served
        // artifact epoch-STALE so any survivor's next catch_up_epoch_keys repair
        // re-derives the tombstone from the relay's revoked row.
        let mut sync = make_sync();
        sync.initialize("test-password", &[1u8; 16]).unwrap();

        let self_device_id = "a1b2c3d4e5f6";
        let target_device_id = "b7c8d9e0f1a2";
        let target_secret = DeviceSecret::generate();
        let self_secret =
            DeviceSecret::from_bytes(sync.device_secret().unwrap().as_bytes().to_vec()).unwrap();
        let relay = Arc::new(RevokeTestRelay::new(
            vec![
                make_device_info(self_device_id, &self_secret, 0, "active"),
                make_device_info(target_device_id, &target_secret, 0, "active"),
            ],
            RevokeBehavior::Success,
        ));

        sync.configure_engine(relay.clone(), "sync-1".to_string(), self_device_id.to_string(), 0, 0);
        // Pin ONLY the survivor — the target was never imported, so the local
        // tombstone pin will fail. The survivor must be pinned so the rekey wrap
        // step still succeeds.
        seed_device_registry(
            &sync,
            "sync-1",
            &[make_device_info(self_device_id, &self_secret, 0, "active")],
        );

        // Pre-seed a served artifact at the PRE-revoke epoch (0), so the served
        // artifact is epoch-stale relative to the post-revoke committed epoch
        // (1). The repair backstop fires exactly while the served epoch lags.
        let epoch_0_key: [u8; 32] = sync.key_hierarchy().epoch_key(0).unwrap().try_into().unwrap();
        relay.set_signed_registry(signed_registry_with_entries(
            "sync-1",
            &self_secret,
            self_device_id,
            &[make_device_info(self_device_id, &self_secret, 0, "active")],
            0,
            &[(0, epoch_0_key)],
        ));

        let committed_epoch =
            sync.revoke_and_rekey(relay.clone(), target_device_id, true).await.unwrap();
        assert_eq!(committed_epoch, 1);

        // The relay-side revoke committed (the revocation is real).
        assert_eq!(relay.revoke_calls(), 1);
        assert!(
            relay
                .devices()
                .iter()
                .any(|d| d.device_id == target_device_id && d.status == "revoked"),
            "relay-side revoke must have committed"
        );

        // The local pin still failed: the target is absent from local storage.
        assert!(
            sync.storage().get_device_record("sync-1", target_device_id).unwrap().is_none(),
            "unpinned target must remain absent — the pin failed"
        );

        // CRITICAL: the served artifact is UNCHANGED — no tombstone-less publish
        // happened — so it stays at epoch 0 < committed epoch 1. The
        // epoch-repair backstop (which early-returns once served_epoch >=
        // target_epoch) therefore still fires for any survivor.
        let served = decode_served_registry(&relay, &self_secret, self_device_id);
        assert_eq!(
            served.current_epoch, 0,
            "served artifact must stay epoch-stale so the epoch-repair backstop still fires"
        );
        assert!(
            served.entries.iter().all(|e| e.device_id != target_device_id || e.status != "active"),
            "no fresh artifact should re-assert the revoked target as active"
        );
    }

    #[tokio::test]
    async fn revoke_and_rekey_then_target_confirms_self_revocation_round_trip() {
        // A revokes B; A publishes a signed registry carrying B as revoked. B,
        // verifying that artifact against its pin of A, reaches ConfirmedRevoked.
        // A stale pre-revoke replay served to a re-paired B with a higher
        // baseline yields Unknown (ties to the freshness gate).
        let mut a = make_sync();
        a.initialize("test-password", &[1u8; 16]).unwrap();

        let a_id = "a1b2c3d4e5f6";
        let b_id = "b7c8d9e0f1a2";
        let a_secret = DeviceSecret::from_bytes(a.device_secret().unwrap().as_bytes().to_vec())
            .unwrap();
        let b_secret = DeviceSecret::generate();
        let a_relay = Arc::new(RevokeTestRelay::new(
            vec![
                make_device_info(a_id, &a_secret, 0, "active"),
                make_device_info(b_id, &b_secret, 0, "active"),
            ],
            RevokeBehavior::Success,
        ));

        a.configure_engine(a_relay.clone(), "sync-1".to_string(), a_id.to_string(), 0, 0);
        seed_device_registry(&a, "sync-1", &a_relay.devices());
        a.revoke_and_rekey(a_relay.clone(), b_id, true).await.unwrap();

        // The artifact A just published, captured to drive B's verification.
        let revoked_artifact =
            a_relay.state.lock().unwrap().signed_registry.clone().unwrap();

        // Build B: pins A (active, the signer) and itself, served the revoked
        // artifact A published. With a baseline at or below the artifact version
        // B confirms its own revocation. After the freshness gate flip a NULL baseline
        // is fail-safe Unknown (see
        // confirm_self_revocation_is_unknown_when_no_baseline_recorded), so a
        // genuinely-revoked device confirms once it has a baseline — which it
        // acquires by importing/publishing any registry; here we seed one at the
        // artifact version (the equal boundary, which `>=` accepts).
        // confirm_self_revocation reads the pinned signer keys and the served
        // artifact only — B needs no DeviceSecret of its own.
        let mut b = make_sync();
        let b_relay = Arc::new(RevokeTestRelay::new(
            vec![make_device_info(b_id, &b_secret, 1, "revoked")],
            RevokeBehavior::Success,
        ));
        for info in [
            make_device_info(a_id, &a_secret, 1, "active"),
            make_device_info(b_id, &b_secret, 1, "revoked"),
        ] {
            DeviceRegistryManager::pin_device(
                b.storage().as_ref(),
                "sync-1",
                &make_device_record("sync-1", &info),
            )
            .unwrap();
        }
        b.configure_engine(b_relay.clone(), "sync-1".to_string(), b_id.to_string(), 1, 0);
        b_relay.set_signed_registry(revoked_artifact.clone());
        set_last_imported_registry_version(&b, "sync-1", revoked_artifact.registry_version);

        assert_eq!(
            b.confirm_self_revocation().await,
            // A revoked with remote_wipe=true (line above), and the H3 graft binds
            // that wipe intent into the published registry's signature, so the
            // victim reads it back as ConfirmedRevoked { remote_wipe: true }.
            SelfRevocationStatus::ConfirmedRevoked { remote_wipe: true },
            "B must confirm its own revocation (with the admin-signed wipe bit) from A's published artifact"
        );

        // Replay defense: a re-paired B with a fresh higher baseline served the
        // SAME (now stale) artifact must not wipe.
        set_last_imported_registry_version(&b, "sync-1", revoked_artifact.registry_version + 5);
        assert_eq!(
            b.confirm_self_revocation().await,
            SelfRevocationStatus::Unknown,
            "a stale pre-baseline artifact must never drive a wipe"
        );
    }

    #[tokio::test]
    async fn repair_signed_registry_emits_explicit_revoked_entry_absorbing() {
        // The epoch-repair publisher (the survivor backstop) emits EVERY listed
        // device, forcing revoked status from either the relay list or the local
        // pin (revoked-absorbing).
        let mut sync = make_sync();
        sync.initialize("test-password", &[1u8; 16]).unwrap();

        let self_device_id = "a1b2c3d4e5f6";
        let relay_revoked_id = "b7c8d9e0f1a2"; // relay says revoked
        let pin_revoked_id = "c8d9e0f1a2b3"; // relay says active, local pin revoked
        let self_secret =
            DeviceSecret::from_bytes(sync.device_secret().unwrap().as_bytes().to_vec()).unwrap();
        let relay_revoked_secret = DeviceSecret::generate();
        let pin_revoked_secret = DeviceSecret::generate();

        let relay = Arc::new(RevokeTestRelay::new(vec![], RevokeBehavior::Success));
        sync.configure_engine(relay.clone(), "sync-1".to_string(), self_device_id.to_string(), 0, 0);

        // Local pins: self active, one device pinned revoked even though the
        // relay will report it active.
        for (id, secret, status) in [
            (self_device_id, &self_secret, "active"),
            (relay_revoked_id, &relay_revoked_secret, "active"),
            (pin_revoked_id, &pin_revoked_secret, "revoked"),
        ] {
            let mut record =
                make_device_record("sync-1", &make_device_info(id, secret, 0, status));
            record.status = status.to_string();
            DeviceRegistryManager::pin_device(sync.storage().as_ref(), "sync-1", &record).unwrap();
        }

        // Relay device list: self active, relay_revoked revoked, pin_revoked
        // ACTIVE (the absorbing test — the local pin must win).
        let devices = vec![
            make_device_info(self_device_id, &self_secret, 0, "active"),
            make_device_info(relay_revoked_id, &relay_revoked_secret, 0, "revoked"),
            make_device_info(pin_revoked_id, &pin_revoked_secret, 0, "active"),
        ];

        sync.repair_signed_registry_epoch_if_needed(relay.as_ref(), "sync-1", self_device_id, 0, &devices)
            .await
            .unwrap();

        let snapshot = decode_served_registry(&relay, &self_secret, self_device_id);
        let status_of = |id: &str| {
            snapshot.entries.iter().find(|e| e.device_id == id).map(|e| e.status.clone())
        };
        assert_eq!(status_of(self_device_id).as_deref(), Some("active"));
        assert_eq!(
            status_of(relay_revoked_id).as_deref(),
            Some("revoked"),
            "relay-revoked device must be emitted revoked, not dropped"
        );
        assert_eq!(
            status_of(pin_revoked_id).as_deref(),
            Some("revoked"),
            "locally-pinned revoked must win over a relay-active claim (absorbing)"
        );
    }

    #[tokio::test]
    async fn repair_signed_registry_refuses_when_self_non_active() {
        let mut sync = make_sync();
        sync.initialize("test-password", &[1u8; 16]).unwrap();

        let self_device_id = "a1b2c3d4e5f6";
        let self_secret =
            DeviceSecret::from_bytes(sync.device_secret().unwrap().as_bytes().to_vec()).unwrap();
        let relay = Arc::new(RevokeTestRelay::new(vec![], RevokeBehavior::Success));
        sync.configure_engine(relay.clone(), "sync-1".to_string(), self_device_id.to_string(), 0, 0);

        let mut self_record =
            make_device_record("sync-1", &make_device_info(self_device_id, &self_secret, 0, "active"));
        self_record.status = "active".to_string();
        DeviceRegistryManager::pin_device(sync.storage().as_ref(), "sync-1", &self_record).unwrap();

        // Relay marks THIS device revoked → the publisher must refuse rather than
        // sign a registry that revokes its own signer.
        let devices = vec![make_device_info(self_device_id, &self_secret, 0, "revoked")];
        let err = sync
            .repair_signed_registry_epoch_if_needed(relay.as_ref(), "sync-1", self_device_id, 0, &devices)
            .await
            .unwrap_err();
        assert!(matches!(err, CoreError::Engine(_)));
        assert!(relay.state.lock().unwrap().signed_registry.is_none(), "nothing published");
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
            relay_log_token: None,
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

        fn reset_last_pulled_seq(&mut self, sync_id: &str, seq: i64) -> Result<()> {
            self.inner.reset_last_pulled_seq(sync_id, seq)
        }

        fn update_relay_log_token(&mut self, sync_id: &str, token: &str) -> Result<()> {
            self.inner.update_relay_log_token(sync_id, token)
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

        fn import_snapshot(&mut self, sync_id: &str, data: &[u8], bound_ms: i64) -> Result<u64> {
            self.inner.import_snapshot(sync_id, data, bound_ms)
        }

        fn commit(self: Box<Self>) -> Result<()> {
            self.inner.commit()
        }

        fn rollback(self: Box<Self>) -> Result<()> {
            self.inner.rollback()
        }
    }
}
