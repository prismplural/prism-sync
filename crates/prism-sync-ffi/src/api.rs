use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use prism_sync_core::client::PrismSync;
use prism_sync_core::pairing::models::{Invite, PairingResponse};
use prism_sync_core::pairing::service::PairingService;
use prism_sync_core::relay::traits::{FirstDeviceAdmissionProof, RegistrationNonceResponse};
use prism_sync_core::relay::ServerRelay;
// Import the trait for method resolution only — NOT exposed in any public FFI signature.
use prism_sync_core::relay::SyncRelay as _;
use prism_sync_core::schema::{SyncSchema, SyncValue};
use prism_sync_core::storage::RusqliteSyncStorage;
use prism_sync_core::sync_service::AutoSyncConfig;
use prism_sync_core::{background_runtime, spawn_notification_handler, DeviceRegistryManager};
use prism_sync_crypto::DeviceSecret;

/// Opaque handle wrapping PrismSync for FFI.
/// Uses tokio::sync::Mutex so async methods can hold the lock across .await.
/// MUST be Send + Sync for flutter_rust_bridge.
///
/// Stores `relay_url` and `allow_insecure` so that relay connections can be
/// constructed on the Rust side — Dart never passes trait objects across FFI.
pub struct PrismSyncHandle {
    inner: Arc<Mutex<PrismSync>>,
    relay_url: String,
    allow_insecure: bool,
    /// The active relay after `configure_engine` is called. Stored here so
    /// `set_auto_sync` can connect the WebSocket notification handler.
    relay: std::sync::Mutex<Option<Arc<ServerRelay>>>,
    /// Background task that drives the sync loop: receives `SyncTrigger`
    /// signals and calls `sync_now()` for each one.
    driver_handle: std::sync::Mutex<Option<JoinHandle<()>>>,
    /// Background task that translates WebSocket relay notifications into
    /// `SyncTrigger` signals.
    notification_handle: std::sync::Mutex<Option<JoinHandle<()>>>,
    /// Abort handle for the pending backoff delay task (if any).
    backoff_handle: Arc<std::sync::Mutex<Option<tokio::task::AbortHandle>>>,
}

impl std::fmt::Debug for PrismSyncHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrismSyncHandle").finish_non_exhaustive()
    }
}

impl Drop for PrismSyncHandle {
    fn drop(&mut self) {
        // Abort background tasks eagerly on drop. try_lock() is safe here
        // because no concurrent access exists once the last reference is gone.
        if let Ok(mut g) = self.driver_handle.try_lock() {
            if let Some(h) = g.take() {
                h.abort();
            }
        }
        if let Ok(mut g) = self.notification_handle.try_lock() {
            if let Some(h) = g.take() {
                h.abort();
            }
        }
        if let Ok(mut g) = self.backoff_handle.try_lock() {
            if let Some(h) = g.take() {
                h.abort();
            }
        }
    }
}

// Compile-time proof that PrismSyncHandle is Send + Sync
#[allow(dead_code)]
const _: () = {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    fn check() {
        assert_send::<PrismSyncHandle>();
        assert_sync::<PrismSyncHandle>();
    }
};

// ══════════════════════════════════════════════════════════════════════
// Internal helpers
// ══════════════════════════════════════════════════════════════════════

// ── Schema parsing ──

/// Parse a JSON schema definition into a `SyncSchema`.
///
/// Expected format:
/// ```json
/// {
///   "entities": {
///     "members": {
///       "fields": {
///         "name": "String",
///         "age": "Int",
///         "active": "Bool",
///         "avatar": "Blob",
///         "created_at": "DateTime"
///       }
///     }
///   }
/// }
/// ```
fn parse_schema_json(json: &str) -> Result<SyncSchema, String> {
    SyncSchema::from_json(json).map_err(|e| e.to_string())
}

// ── Helper: Parse fields JSON to HashMap<String, SyncValue> ──

fn parse_fields_json(json: &str) -> Result<HashMap<String, SyncValue>, String> {
    let map: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(json).map_err(|e| format!("Invalid fields JSON: {e}"))?;
    let mut result = HashMap::new();
    for (key, value) in map {
        let sv = json_value_to_sync_value(&key, &value)?;
        result.insert(key, sv);
    }
    Ok(result)
}

fn json_value_to_sync_value(key: &str, value: &serde_json::Value) -> Result<SyncValue, String> {
    match value {
        serde_json::Value::Null => Ok(SyncValue::Null),
        serde_json::Value::String(s) => Ok(SyncValue::String(s.clone())),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(SyncValue::Int(i))
            } else if let Some(f) = n.as_f64() {
                if f.fract() == 0.0 && f >= i64::MIN as f64 && f <= i64::MAX as f64 {
                    Ok(SyncValue::Int(f as i64))
                } else {
                    Err(format!("Unsupported float value for field '{key}'"))
                }
            } else {
                Err(format!("Unsupported number type for field '{key}'"))
            }
        }
        serde_json::Value::Bool(b) => Ok(SyncValue::Bool(*b)),
        _ => Err(format!("Unsupported value type for field '{key}'")),
    }
}

// ── SyncValue JSON round-trip helper ──

/// Convert an encoded_value string (from the sync engine wire format) back
/// to a natural JSON value matching the `parse_fields_json` input format.
///
/// This ensures round-trip consistency:
/// - `parse_fields_json` input: `{"name": "Alice", "age": 42, "active": true}`
/// - `encoded_value_to_json` output: same natural JSON types
///
/// Encoding rules (see `encode_value` in prism-sync-core):
/// - `"null"` -> JSON null
/// - `"42"` / `"-100"` -> JSON number (Int)
/// - `"true"` / `"false"` -> JSON boolean (Bool)
/// - `"\"hello\""` -> JSON string `"hello"` (String)
/// - `"\"2026-03-15T12:00:00.000Z\""` -> JSON string (DateTime as ISO-8601)
/// - `"\"3q2+7w==\""` -> JSON string (Blob as base64)
fn encoded_value_to_json(encoded: &str) -> serde_json::Value {
    // Try parsing as JSON -- this handles strings (quoted), numbers, bools, null
    match serde_json::from_str(encoded) {
        Ok(v) => v,
        // Fallback: treat as raw string if it doesn't parse
        Err(_) => serde_json::Value::String(encoded.to_string()),
    }
}

// ── JSON serialization helpers for types without Serialize ──

fn sync_status_to_json(status: &prism_sync_core::client::SyncStatus) -> serde_json::Value {
    serde_json::json!({
        "syncing": status.syncing,
        "last_sync": status.last_sync.map(|dt| dt.to_rfc3339()),
        "pending_ops": status.pending_ops,
    })
}

fn sync_result_to_json(result: &prism_sync_core::engine::SyncResult) -> serde_json::Value {
    serde_json::json!({
        "pulled": result.pulled,
        "merged": result.merged,
        "pushed": result.pushed,
        "pruned": result.pruned,
        "duration_ms": result.duration.as_millis() as u64,
        "error": result.error,
    })
}

const STRUCTURED_ERROR_PREFIX: &str = "PRISM_SYNC_ERROR_JSON:";

fn relay_error_category_to_json(kind: prism_sync_core::RelayErrorCategory) -> &'static str {
    match kind {
        prism_sync_core::RelayErrorCategory::Network => "network",
        prism_sync_core::RelayErrorCategory::Auth => "auth",
        prism_sync_core::RelayErrorCategory::DeviceIdentityMismatch => "device_identity_mismatch",
        prism_sync_core::RelayErrorCategory::Server => "server",
        prism_sync_core::RelayErrorCategory::Protocol => "protocol",
        prism_sync_core::RelayErrorCategory::Other => "other",
    }
}

fn encode_core_error(operation: &str, error: prism_sync_core::CoreError) -> String {
    let mut payload = serde_json::json!({
        "operation": operation,
        "message": error.to_string(),
    });

    if let prism_sync_core::CoreError::Relay {
        kind,
        status,
        code,
        remote_wipe,
        ..
    } = &error
    {
        payload["error_type"] = serde_json::json!("relay");
        payload["relay_kind"] = serde_json::json!(relay_error_category_to_json(kind.clone()));
        if let Some(status) = status {
            payload["status"] = serde_json::json!(status);
        }
        if let Some(code) = code {
            payload["code"] = serde_json::json!(code);
        }
        if let Some(remote_wipe) = remote_wipe {
            payload["remote_wipe"] = serde_json::json!(remote_wipe);
        }
    } else {
        payload["error_type"] = serde_json::json!("core");
    }

    format!("{STRUCTURED_ERROR_PREFIX}{payload}")
}

fn sync_event_to_json(event: &prism_sync_core::events::SyncEvent) -> serde_json::Value {
    use prism_sync_core::events::SyncEvent;
    match event {
        SyncEvent::SyncStarted => serde_json::json!({"type": "SyncStarted"}),
        SyncEvent::SyncCompleted(result) => serde_json::json!({
            "type": "SyncCompleted",
            "result": sync_result_to_json(result),
        }),
        SyncEvent::SnapshotProgress { received, total } => serde_json::json!({
            "type": "SnapshotProgress",
            "received": received,
            "total": total,
        }),
        SyncEvent::Error(err) => serde_json::json!({
            "type": "Error",
            "kind": format!("{:?}", err.kind),
            "message": err.message,
            "retryable": err.retryable,
            "code": err.code,
            "remote_wipe": err.remote_wipe,
        }),
        SyncEvent::RemoteChanges(changeset) => {
            let changes: Vec<serde_json::Value> = changeset
                .entity_changes
                .iter()
                .map(|c| {
                    // Convert encoded field values to natural JSON types for
                    // round-trip consistency with parse_fields_json input format.
                    let fields: serde_json::Map<String, serde_json::Value> = c
                        .fields
                        .iter()
                        .map(|(k, v)| (k.clone(), encoded_value_to_json(v)))
                        .collect();
                    serde_json::json!({
                        "table": c.table,
                        "entity_id": c.entity_id,
                        "is_delete": c.is_delete,
                        "fields": fields,
                    })
                })
                .collect();
            serde_json::json!({
                "type": "RemoteChanges",
                "changes": changes,
            })
        }
        SyncEvent::DeviceJoined(info) => serde_json::json!({
            "type": "DeviceJoined",
            "device_id": info.device_id,
            "epoch": info.epoch,
            "status": info.status,
        }),
        SyncEvent::DeviceRevoked {
            ref device_id,
            remote_wipe,
        } => serde_json::json!({
            "type": "DeviceRevoked",
            "device_id": device_id,
            "remote_wipe": remote_wipe,
        }),
        SyncEvent::EpochRotated(epoch) => serde_json::json!({
            "type": "EpochRotated",
            "epoch": epoch,
        }),
        SyncEvent::WebSocketStateChanged { connected } => serde_json::json!({
            "type": "WebSocketStateChanged",
            "connected": connected,
        }),
        SyncEvent::BackoffScheduled {
            attempt,
            delay_secs,
        } => serde_json::json!({
            "type": "BackoffScheduled",
            "attempt": attempt,
            "delay_secs": delay_secs,
        }),
    }
}

fn device_info_to_json(info: &prism_sync_core::relay::traits::DeviceInfo) -> serde_json::Value {
    serde_json::json!({
        "device_id": info.device_id,
        "epoch": info.epoch,
        "status": info.status,
        "permission": info.permission,
    })
}

// ══════════════════════════════════════════════════════════════════════
// MemorySecureStore — in-memory SecureStore for testing
// ══════════════════════════════════════════════════════════════════════

/// A SecureStore backed by an in-memory HashMap, suitable for testing.
/// Real Dart callbacks will be wired later via FRB.
pub struct MemorySecureStore {
    data: std::sync::Mutex<HashMap<String, Vec<u8>>>,
}

impl MemorySecureStore {
    pub fn new() -> Self {
        Self {
            data: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Return a copy of all stored entries (for draining back to Dart).
    pub fn snapshot(&self) -> HashMap<String, Vec<u8>> {
        self.data.lock().unwrap().clone()
    }
}

impl Default for MemorySecureStore {
    fn default() -> Self {
        Self::new()
    }
}

impl prism_sync_core::secure_store::SecureStore for MemorySecureStore {
    fn get(&self, key: &str) -> prism_sync_core::Result<Option<Vec<u8>>> {
        Ok(self.data.lock().unwrap().get(key).cloned())
    }
    fn set(&self, key: &str, value: &[u8]) -> prism_sync_core::Result<()> {
        self.data
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_vec());
        Ok(())
    }
    fn delete(&self, key: &str) -> prism_sync_core::Result<()> {
        self.data.lock().unwrap().remove(key);
        Ok(())
    }
    fn clear(&self) -> prism_sync_core::Result<()> {
        self.data.lock().unwrap().clear();
        Ok(())
    }
}

// ══════════════════════════════════════════════════════════════════════
// Public FFI API
// ══════════════════════════════════════════════════════════════════════

// ── Construction ──

/// Build and configure a PrismSync instance.
///
/// - `relay_url`: The relay server URL.
/// - `db_path`: SQLite database path, or ":memory:" for in-memory.
/// - `allow_insecure`: Allow http:// relay URLs (dev only).
/// - `schema_json`: JSON schema definition (see `parse_schema_json` docs).
///   Pass an empty string or "{}" to use an empty schema.
///
/// Always uses an in-memory `MemorySecureStore`. Seed it after creation via
/// `seed_secure_store` (from Dart's platform keychain) and drain it via
/// `drain_secure_store` after state-changing operations.
pub fn create_prism_sync(
    relay_url: String,
    db_path: String,
    allow_insecure: bool,
    schema_json: String,
    database_key: Option<Vec<u8>>,
) -> Result<PrismSyncHandle, String> {
    let schema = if schema_json.is_empty() || schema_json == "{}" {
        SyncSchema::builder().build()
    } else {
        parse_schema_json(&schema_json)?
    };

    let storage = if db_path == ":memory:" {
        RusqliteSyncStorage::in_memory()
    } else if let Some(ref key) = database_key {
        // If the DB file exists, try opening encrypted first; if that fails
        // assume it is a plaintext DB and migrate it in-place.
        let path = std::path::Path::new(&db_path);
        if path.exists() {
            let conn = rusqlite::Connection::open(&db_path)
                .map_err(|e| format!("Failed to open database: {e}"))?;
            match RusqliteSyncStorage::new_encrypted(conn, key) {
                Ok(s) => Ok(s),
                Err(_) => {
                    // Plaintext DB detected — migrate to encrypted with backup safety.
                    let enc_path = format!("{db_path}.enc");
                    let bak_path = format!("{db_path}.bak");
                    RusqliteSyncStorage::migrate_to_encrypted(
                        path,
                        std::path::Path::new(&enc_path),
                        key,
                    )
                    .map_err(|e| format!("Encryption migration failed: {e}"))?;

                    // Keep the plaintext DB as a backup until we verify the encrypted copy.
                    std::fs::rename(&db_path, &bak_path)
                        .map_err(|e| format!("Failed to backup plaintext DB: {e}"))?;
                    std::fs::rename(&enc_path, &db_path)
                        .map_err(|e| format!("Failed to replace DB with encrypted copy: {e}"))?;

                    let conn = rusqlite::Connection::open(&db_path)
                        .map_err(|e| format!("Failed to open migrated database: {e}"))?;
                    let storage = RusqliteSyncStorage::new_encrypted(conn, key)
                        .map_err(|e| format!("Encrypted DB verification failed: {e}"))?;

                    // Encrypted copy verified — remove the plaintext backup.
                    let _ = std::fs::remove_file(&bak_path);
                    Ok(storage)
                }
            }
        } else {
            let conn = rusqlite::Connection::open(&db_path)
                .map_err(|e| format!("Failed to open database: {e}"))?;
            RusqliteSyncStorage::new_encrypted(conn, key)
        }
    } else {
        let conn = rusqlite::Connection::open(&db_path)
            .map_err(|e| format!("Failed to open database: {e}"))?;
        RusqliteSyncStorage::new(conn)
    }
    .map_err(|e| format!("Failed to create storage: {e}"))?;

    let mut builder = PrismSync::builder()
        .schema(schema)
        .storage(Arc::new(storage))
        .relay_url(&relay_url);

    if allow_insecure {
        builder = builder.allow_insecure_transport();
    }

    let secure_store: Arc<dyn prism_sync_core::secure_store::SecureStore> =
        Arc::new(MemorySecureStore::new());
    builder = builder.secure_store(secure_store);

    let prism_sync = builder.build().map_err(|e| format!("Build failed: {e}"))?;

    Ok(PrismSyncHandle {
        inner: Arc::new(Mutex::new(prism_sync)),
        relay_url,
        allow_insecure,
        relay: std::sync::Mutex::new(None),
        driver_handle: std::sync::Mutex::new(None),
        notification_handle: std::sync::Mutex::new(None),
        backoff_handle: Arc::new(std::sync::Mutex::new(None)),
    })
}

// ── Key lifecycle ──

/// Initialize (first-time setup).
pub async fn initialize(
    handle: &PrismSyncHandle,
    password: String,
    secret_key: Vec<u8>,
) -> Result<(), String> {
    let mut inner = handle.inner.lock().await;
    inner
        .initialize(&password, &secret_key)
        .map_err(|e| e.to_string())
}

/// Unlock (subsequent launches).
pub async fn unlock(
    handle: &PrismSyncHandle,
    password: String,
    secret_key: Vec<u8>,
) -> Result<(), String> {
    let mut inner = handle.inner.lock().await;
    inner
        .unlock(&password, &secret_key)
        .map_err(|e| e.to_string())
}

/// Restore the unlocked state directly from raw key material.
///
/// Bypasses Argon2id password derivation entirely. Use when the raw DEK
/// has been persisted in the platform keychain (Signal-style approach).
/// This is the fast path for subsequent app launches.
///
/// - `dek`: The raw 32-byte Data Encryption Key.
/// - `device_secret`: The raw 32-byte device secret.
pub async fn restore_runtime_keys(
    handle: &PrismSyncHandle,
    dek: Vec<u8>,
    device_secret: Vec<u8>,
) -> Result<(), String> {
    let mut inner = handle.inner.lock().await;
    inner
        .restore_runtime_keys(&dek, &device_secret)
        .map_err(|e| e.to_string())?;

    // Restore persisted epoch keys (epoch 1+, generated during rekey).
    // Epoch 0 is derived from the DEK by restore_from_dek, but higher epochs
    // are generated fresh during rekey and only live in the secure store.
    // Try sequential epoch numbers and stop at the first gap.
    use base64::{engine::general_purpose::STANDARD, Engine};
    for epoch in 1u32.. {
        let key_name = format!("epoch_key_{epoch}");
        match inner.secure_store().get(&key_name) {
            Ok(Some(stored_bytes)) => {
                // The key may have been stored as base64 (client.rs path) or
                // raw bytes (sync_service.rs path). Try base64 decode first;
                // if that yields exactly 32 bytes use it, otherwise treat the
                // stored value as raw key material.
                let key_bytes = if let Ok(decoded) = STANDARD.decode(&stored_bytes) {
                    if decoded.len() == 32 {
                        decoded
                    } else {
                        stored_bytes
                    }
                } else {
                    stored_bytes
                };

                if key_bytes.len() == 32 {
                    inner
                        .key_hierarchy_mut()
                        .store_epoch_key(epoch, zeroize::Zeroizing::new(key_bytes));
                } else {
                    // Unexpected key length — stop restoring further epochs.
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }

    Ok(())
}

/// Export the raw DEK bytes for keychain persistence.
///
/// Returns the raw 32-byte DEK. Only works when unlocked (after
/// `initialize` or `unlock`). Store in the platform keychain so
/// `restore_runtime_keys` can be used on subsequent launches.
pub async fn export_dek(handle: &PrismSyncHandle) -> Result<Vec<u8>, String> {
    let inner = handle.inner.lock().await;
    inner.export_dek().map_err(|e| e.to_string())
}

/// Lock (zero keys from memory).
pub async fn lock(handle: &PrismSyncHandle) {
    let mut inner = handle.inner.lock().await;
    inner.lock();
}

/// Check if unlocked.
pub async fn is_unlocked(handle: &PrismSyncHandle) -> bool {
    let inner = handle.inner.lock().await;
    inner.is_unlocked()
}

/// Generate a new BIP39 secret key.
pub fn generate_secret_key() -> Result<String, String> {
    PrismSync::generate_secret_key().map_err(|e| e.to_string())
}

/// Get database encryption key (for consumer's encrypted SQLite).
pub async fn database_key(handle: &PrismSyncHandle) -> Result<Vec<u8>, String> {
    let inner = handle.inner.lock().await;
    inner
        .database_key()
        .map(|k| k.to_vec())
        .map_err(|e| e.to_string())
}

// ── Engine configuration ──

/// Configure the sync engine after initialize/unlock.
///
/// Reads `sync_id`, `device_id`, and `session_token` from SecureStore,
/// constructs a `ServerRelay`, and calls `PrismSync::configure_engine()`.
/// Must be called before `sync_now()` or `on_resume()` will work.
///
/// The `epoch` defaults to 0 (the starting epoch for new sync groups).
/// If the secure store contains an `epoch` key, that value is used instead.
pub async fn configure_engine(handle: &PrismSyncHandle) -> Result<(), String> {
    let mut inner = handle.inner.lock().await;

    // Read credentials from secure store
    let sync_id = inner
        .secure_store()
        .get("sync_id")
        .map_err(|e| e.to_string())?
        .map(|b| String::from_utf8(b).unwrap_or_default())
        .ok_or("No sync_id found — pair first")?;
    let device_id = inner
        .secure_store()
        .get("device_id")
        .map_err(|e| e.to_string())?
        .map(|b| String::from_utf8(b).unwrap_or_default())
        .ok_or("No device_id found — pair first")?;
    let session_token = inner
        .secure_store()
        .get("session_token")
        .map_err(|e| e.to_string())?
        .map(|b| String::from_utf8(b).unwrap_or_default())
        .unwrap_or_default();

    // Read authoritative epoch from sync_metadata (storage), falling back
    // to secure_store cache, then 0 for brand-new groups.
    let epoch = {
        let storage = inner.storage().clone();
        let sid = sync_id.clone();
        let meta_epoch = tokio::task::spawn_blocking(move || storage.get_sync_metadata(&sid))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?
            .map(|m| m.current_epoch);

        meta_epoch.unwrap_or_else(|| {
            // Fallback to secure_store cache (e.g. before first sync creates metadata)
            inner
                .secure_store()
                .get("epoch")
                .ok()
                .flatten()
                .and_then(|b| String::from_utf8(b).ok())
                .and_then(|s| s.parse::<i32>().ok())
                .unwrap_or(0)
        })
    };

    // Prefer relay_url from secure store (set by joinFromUrl / createSyncGroup)
    // over handle.relay_url (set at handle creation, may be stale default).
    let relay_url = inner
        .secure_store()
        .get("relay_url")
        .map_err(|e| e.to_string())?
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| handle.relay_url.clone());
    let device_secret = inner
        .secure_store()
        .get("device_secret")
        .map_err(|e| e.to_string())?;

    // Construct relay
    let relay = build_relay(
        &relay_url,
        &sync_id,
        &device_id,
        &session_token,
        device_secret,
        handle.allow_insecure,
        None,
    )?;

    // Connect WebSocket for real-time relay notifications (best-effort;
    // connect() spawns a background reconnect loop and never blocks).
    if let Err(e) = relay.connect_websocket().await {
        // Non-fatal: WebSocket will reconnect automatically with backoff.
        eprintln!("[prism_sync_ffi] WebSocket connect failed (non-fatal): {e}");
    }

    // Store relay so set_auto_sync can wire up the notification handler.
    *handle.relay.lock().unwrap() = Some(relay.clone());

    // Configure engine
    inner.configure_engine(relay, sync_id, device_id, epoch);

    Ok(())
}

// ── Password management ──

/// Change password (re-wraps DEK, no data re-encryption).
///
/// The `old_password` parameter is accepted for API symmetry but is not
/// used — `change_password` operates on the already-unlocked key hierarchy.
/// The secret key is required to derive the new wrapping key.
pub async fn change_password(
    handle: &PrismSyncHandle,
    _old_password: String,
    new_password: String,
    secret_key: Vec<u8>,
) -> Result<(), String> {
    let inner = handle.inner.lock().await;
    let (new_wrapped_dek, new_salt) = inner
        .key_hierarchy()
        .change_password(&new_password, &secret_key)
        .map_err(|e| format!("change_password failed: {e}"))?;

    inner
        .secure_store()
        .set("wrapped_dek", &new_wrapped_dek)
        .map_err(|e| format!("Failed to persist wrapped_dek: {e}"))?;
    inner
        .secure_store()
        .set("dek_salt", &new_salt)
        .map_err(|e| format!("Failed to persist dek_salt: {e}"))?;

    Ok(())
}

// ── Mutation recording ──

/// Record a new entity creation.
///
/// `fields_json` is a JSON object: `{"field_name": value, ...}`.
/// Supported value types: null, string, integer, boolean.
pub async fn record_create(
    handle: &PrismSyncHandle,
    table: String,
    entity_id: String,
    fields_json: String,
) -> Result<(), String> {
    let mut inner = handle.inner.lock().await;
    let fields = parse_fields_json(&fields_json)?;
    inner
        .record_create(&table, &entity_id, &fields)
        .map_err(|e| e.to_string())
}

/// Record field updates on an existing entity.
///
/// `changed_fields_json` is a JSON object with only the changed fields.
pub async fn record_update(
    handle: &PrismSyncHandle,
    table: String,
    entity_id: String,
    changed_fields_json: String,
) -> Result<(), String> {
    let mut inner = handle.inner.lock().await;
    let fields = parse_fields_json(&changed_fields_json)?;
    inner
        .record_update(&table, &entity_id, &fields)
        .map_err(|e| e.to_string())
}

/// Record entity deletion (soft delete / tombstone).
pub async fn record_delete(
    handle: &PrismSyncHandle,
    table: String,
    entity_id: String,
) -> Result<(), String> {
    let mut inner = handle.inner.lock().await;
    inner
        .record_delete(&table, &entity_id)
        .map_err(|e| e.to_string())
}

// ── Sync control ──

/// Configure auto-sync (debounced push after mutations + WebSocket pull).
///
/// When `enabled` is true:
/// - Mutations are coalesced via a debounce timer and pushed after
///   `debounce_ms` of quiet time.
/// - A driver task listens on the trigger channel and calls `sync_now()`
///   for each `SyncTrigger` received (mutation debounce or WebSocket).
/// - If a relay is connected, a notification handler translates relay
///   `new_data` WebSocket messages into sync triggers so Device B pulls
///   immediately when Device A pushes.
pub async fn set_auto_sync(
    handle: &PrismSyncHandle,
    enabled: bool,
    debounce_ms: u64,
    retry_delay_ms: u64,
    max_retries: u32,
) -> Result<(), String> {
    // Abort any existing driver / notification / backoff tasks before reconfiguring.
    if let Some(h) = handle.driver_handle.lock().unwrap().take() {
        h.abort();
    }
    if let Some(h) = handle.notification_handle.lock().unwrap().take() {
        h.abort();
    }
    if let Some(h) = handle.backoff_handle.lock().unwrap().take() {
        h.abort();
    }

    let config = AutoSyncConfig {
        enabled,
        debounce: std::time::Duration::from_millis(debounce_ms),
        retry_delay: std::time::Duration::from_millis(retry_delay_ms),
        max_retries,
        enable_pruning: false,
    };

    // Configure auto-sync inside the lock, capturing what we need to spawn tasks.
    let (trigger_rx, event_tx, device_id, notification_trigger_tx) = {
        let mut inner = handle.inner.lock().await;
        let trigger_rx = inner.set_auto_sync(config);
        let event_tx = inner.sync_service().event_tx().clone();
        let device_id = inner.device_id().unwrap_or("").to_string();
        let notification_trigger_tx = inner.sync_service().notification_trigger_sender();
        (trigger_rx, event_tx, device_id, notification_trigger_tx)
    };

    if let Some(mut trigger_rx) = trigger_rx {
        // Spawn driver loop on the background runtime so it persists on mobile
        // (iOS/Android) where FRB's async executor is not a Tokio runtime.
        let inner = handle.inner.clone();
        let backoff_abort = handle.backoff_handle.clone();
        let event_tx_clone = event_tx.clone();
        // Clone the notification trigger sender for backoff retriggers.
        // It feeds the same mpsc channel as the debounce + notification tasks.
        let backoff_tx = notification_trigger_tx.clone();

        let driver = background_runtime().spawn(async move {
            use prism_sync_core::sync_service::SyncTrigger;

            let mut backoff_secs: u64 = 0;
            let mut backoff_attempt: u32 = 0;
            let mut cumulative_backoff_secs: u64 = 0;
            const MAX_CUMULATIVE_SECS: u64 = 600; // 10 minutes

            while trigger_rx.recv().await.is_some() {
                // Cancel any pending backoff delay task
                {
                    let mut guard = backoff_abort.lock().unwrap();
                    if let Some(abort) = guard.take() {
                        abort.abort();
                    }
                }

                match inner.lock().await.sync_now().await {
                    Ok(_) => {
                        backoff_secs = 0;
                        backoff_attempt = 0;
                        cumulative_backoff_secs = 0;
                    }
                    Err(_) => {
                        backoff_secs = if backoff_secs == 0 {
                            30
                        } else {
                            (backoff_secs * 2).min(300)
                        };
                        backoff_attempt += 1;
                        cumulative_backoff_secs += backoff_secs;

                        // After ~10min of cumulative backoff, emit a terminal
                        // error. Dart side can show a permanent error state.
                        if cumulative_backoff_secs >= MAX_CUMULATIVE_SECS {
                            let _ = event_tx_clone.send(prism_sync_core::events::SyncEvent::Error(
                                prism_sync_core::events::SyncError {
                                    kind: prism_sync_core::events::SyncErrorKind::Network,
                                    message: "Sync failed repeatedly for over 10 minutes".into(),
                                    retryable: false,
                                    code: None,
                                    remote_wipe: None,
                                },
                            ));
                            // Reset so a future manual trigger starts fresh
                            backoff_secs = 0;
                            backoff_attempt = 0;
                            cumulative_backoff_secs = 0;
                            continue;
                        }

                        let _ = event_tx_clone.send(
                            prism_sync_core::events::SyncEvent::BackoffScheduled {
                                attempt: backoff_attempt,
                                delay_secs: backoff_secs,
                            },
                        );

                        if let Some(ref tx) = backoff_tx {
                            let tx = tx.clone();
                            let delay = backoff_secs;
                            let task = tokio::spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                                let _ = tx.send(SyncTrigger::ManualSync).await;
                            });
                            if let Ok(mut guard) = backoff_abort.lock() {
                                *guard = Some(task.abort_handle());
                            }
                        }
                    }
                }
            }
        });
        *handle.driver_handle.lock().unwrap() = Some(driver);

        // Spawn notification handler if relay is connected, so WebSocket
        // new_data messages trigger auto-pull on this device. Pass the
        // PrismSync handle and relay so epoch rotation can be recovered
        // inline before triggering sync.
        let relay = handle.relay.lock().unwrap().clone();
        if let (Some(trigger_tx), Some(relay)) = (notification_trigger_tx, relay) {
            let notifications = relay.notifications();
            let inner_for_notif = Some(handle.inner.clone());
            let relay_for_notif: Option<Arc<dyn prism_sync_core::relay::SyncRelay>> =
                Some(relay.clone() as Arc<dyn prism_sync_core::relay::SyncRelay>);
            let notif = spawn_notification_handler(
                notifications,
                device_id,
                trigger_tx,
                event_tx,
                inner_for_notif,
                relay_for_notif,
            );
            *handle.notification_handle.lock().unwrap() = Some(notif);
        }
    }

    Ok(())
}

/// Trigger a manual sync cycle (pull + merge + push).
///
/// Returns the sync result as a JSON string:
/// `{"pulled": int, "merged": int, "pushed": int, "pruned": int, "duration_ms": int, "error": string|null}`
///
/// Requires `configure_engine` to have been called after `initialize`/`unlock`.
pub async fn sync_now(handle: &PrismSyncHandle) -> Result<String, String> {
    let mut inner = handle.inner.lock().await;
    let result = inner
        .sync_now()
        .await
        .map_err(|e| encode_core_error("sync_now", e))?;
    Ok(sync_result_to_json(&result).to_string())
}

/// Whether the WebSocket is currently authenticated and receiving notifications.
///
/// Returns `false` if no relay is configured, the WebSocket hasn't connected
/// yet, or the connection was lost (reconnecting in the background).
pub fn is_websocket_connected(handle: &PrismSyncHandle) -> bool {
    handle
        .relay
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().map(|r| r.is_websocket_connected()))
        .unwrap_or(false)
}

/// Reconnect the WebSocket if it is currently disconnected.
///
/// Tears down any existing (stale) WebSocket connection and starts a fresh one,
/// resetting the exponential backoff. No-op if no relay is configured.
/// Non-fatal: errors are logged but not propagated.
pub async fn reconnect_websocket(handle: &PrismSyncHandle) -> Result<(), String> {
    let relay = handle.relay.lock().ok().and_then(|g| g.clone());
    if let Some(relay) = relay {
        if !relay.is_websocket_connected() {
            // disconnect drops the old client (and its stale backoff loop),
            // then connect starts fresh with attempt=0.
            let _ = relay.disconnect_websocket().await;
            relay.connect_websocket().await.map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// App lifecycle hook — catch up sync if stale (>5 s since last sync).
///
/// Triggers a full sync cycle only when the last successful sync was more
/// than 5 seconds ago. Safe to call on every app resume.
///
/// Requires `configure_engine` to have been called after `initialize`/`unlock`.
pub async fn on_resume(handle: &PrismSyncHandle) -> Result<(), String> {
    let mut inner = handle.inner.lock().await;
    inner.on_resume().await.map_err(|e| e.to_string())
}

/// Upload an ephemeral snapshot for device pairing.
///
/// Called by the existing device after generating an invite. The snapshot
/// is encrypted and uploaded with a TTL. The new device downloads it to
/// bootstrap, and the relay auto-deletes it afterwards.
pub async fn upload_pairing_snapshot(
    handle: &PrismSyncHandle,
    ttl_secs: u64,
    for_device_id: Option<String>,
) -> Result<(), String> {
    let inner = handle.inner.lock().await;
    inner
        .upload_pairing_snapshot(Some(ttl_secs), for_device_id)
        .await
        .map_err(|e| e.to_string())
}

/// Download and apply a snapshot for initial device bootstrap.
///
/// Called by the new device after joining. Returns the number of entities
/// restored, or 0 if no snapshot was available. Emits a RemoteChanges
/// SyncEvent so Dart can populate its local database.
pub async fn bootstrap_from_snapshot(handle: &PrismSyncHandle) -> Result<u64, String> {
    let mut inner = handle.inner.lock().await;
    let (count, _changes) = inner
        .bootstrap_from_snapshot()
        .await
        .map_err(|e| e.to_string())?;
    Ok(count)
}

/// Get current sync status as JSON.
///
/// Returns: `{"syncing": bool, "last_sync": string|null, "pending_ops": int}`
pub async fn status(handle: &PrismSyncHandle) -> Result<String, String> {
    let inner = handle.inner.lock().await;
    let s = inner.status();
    let json = sync_status_to_json(&s);
    Ok(json.to_string())
}

// ── Events stream ──

/// Subscribe to sync events as a continuous stream.
///
/// Returns a Dart `Stream<String>` that receives JSON-encoded sync events
/// pushed directly from the Rust sync engine. Events are delivered the
/// instant they occur — no polling delay.
///
/// Each event is a JSON object with a `"type"` field. See `sync_event_to_json`
/// for the full format. `RemoteChanges` events include field-level data:
/// ```json
/// {"type": "RemoteChanges", "changes": [{"table": "members", "entity_id": "...", "fields": {...}}]}
/// ```
///
/// The stream stays open until the handle is dropped or `lock()` is called.
/// Multiple subscribers are supported (each gets its own broadcast receiver).
pub async fn sync_event_stream(
    handle: &PrismSyncHandle,
    sink: crate::frb_generated::StreamSink<String>,
) {
    // Acquire lock briefly to get a broadcast receiver, then drop the lock.
    let mut rx = {
        let guard = handle.inner.lock().await;
        guard.events()
    };
    // Lock is dropped — receive loop runs without holding it.
    // Runs directly in FRB's async executor (not tokio::spawn, which requires
    // a Tokio runtime that FRB doesn't provide on mobile platforms).
    loop {
        match rx.recv().await {
            Ok(event) => {
                let json = sync_event_to_json(&event).to_string();
                if sink.add(json).is_err() {
                    break; // Dart side closed the stream
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                let warning = serde_json::json!({
                    "type": "Warning",
                    "message": format!("Event receiver lagged by {n} events"),
                })
                .to_string();
                if sink.add(warning).is_err() {
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                break; // Channel closed (handle dropped)
            }
        }
    }
}

/// Poll for the next sync event. Returns a JSON string if an event is
/// available, or None if no events are pending.
///
/// **Prefer `sync_event_stream` for production use.** This polling API
/// is kept for testing and non-streaming integrations.
pub async fn poll_event(handle: &PrismSyncHandle) -> Result<Option<String>, String> {
    let inner = handle.inner.lock().await;
    let mut rx = inner.events();
    match rx.try_recv() {
        Ok(event) => {
            let json = sync_event_to_json(&event);
            Ok(Some(json.to_string()))
        }
        Err(tokio::sync::broadcast::error::TryRecvError::Empty) => Ok(None),
        Err(tokio::sync::broadcast::error::TryRecvError::Lagged(n)) => {
            Err(format!("Event receiver lagged by {n} events"))
        }
        Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
            Err("Event channel closed".to_string())
        }
    }
}

// ── Pairing ──

/// Build a `ServerRelay` from primitive parameters.
///
/// Used internally by pairing and device-management functions so that Dart
/// never needs to pass trait objects across FFI.  For `allow_insecure` URLs
/// (non-localhost HTTP), the URL check in `ServerRelay::new` is bypassed by
/// temporarily rewriting the scheme — callers must opt in via the handle's
/// `allow_insecure` flag.
fn build_relay(
    relay_url: &str,
    sync_id: &str,
    device_id: &str,
    session_token: &str,
    device_secret: Option<Vec<u8>>,
    allow_insecure: bool,
    registration_token: Option<String>,
) -> Result<Arc<ServerRelay>, String> {
    // ServerRelay::new only accepts https:// or http://localhost.
    // When allow_insecure is set we permit arbitrary http:// URLs by
    // converting to http://localhost temporarily is not feasible, so we
    // skip the check by using the URL as-is and relying on the caller.
    let url = relay_url.to_string();
    if !allow_insecure && !url.starts_with("https://") && !url.starts_with("http://localhost") {
        return Err(format!(
            "Relay URL must use https:// (got {url:?}). \
             Set allow_insecure=true for development."
        ));
    }
    let signing_key = device_secret
        .and_then(|bytes| DeviceSecret::from_bytes(bytes).ok())
        .and_then(|secret| secret.ed25519_keypair(device_id).ok())
        .map(|kp| kp.into_signing_key())
        .unwrap_or_else(|| {
            // No device_secret available (pre-registration or corrupted store).
            // Use a random ephemeral key — signing will fail-closed at the relay
            // because the derived pubkey won't match the registered one.
            DeviceSecret::generate()
                .ed25519_keypair(device_id)
                .expect("ephemeral signing key")
                .into_signing_key()
        });
    let relay = ServerRelay::new(
        url,
        sync_id.to_string(),
        device_id.to_string(),
        session_token.to_string(),
        signing_key,
        registration_token,
    )
    .map_err(|e| format!("Failed to create ServerRelay: {e}"))?;
    Ok(Arc::new(relay))
}

/// Create a new sync group (first device).
///
/// Returns JSON with `qr_payload` (byte array), `words` (string array),
/// `url` (deep link string), `sync_id`, and `relay_url`.
///
/// The relay is constructed internally from the handle's `relay_url`.
/// A placeholder `sync_id` is used for the registration call because the
/// real `sync_id` is generated inside `PairingService::create_sync_group`.
/// The relay server must accept registration at any sync-group path.
pub async fn create_sync_group(
    handle: &PrismSyncHandle,
    password: String,
    relay_url: String,
    mnemonic: Option<String>,
) -> Result<String, String> {
    const PENDING_SYNC_ID_KEY: &str = "pending_sync_id";
    const PENDING_NONCE_RESPONSE_KEY: &str = "pending_registration_nonce_response";
    const PENDING_ADMISSION_PROOF_KEY: &str = "pending_first_device_admission_proof";
    const PENDING_DEVICE_SECRET_KEY: &str = "pending_device_secret";
    const PENDING_DEVICE_ID_KEY: &str = "pending_device_id";
    const PENDING_REGISTRATION_TOKEN_KEY: &str = "pending_registration_token";

    let pending = {
        let inner = handle.inner.lock().await;
        let store = inner.secure_store();

        let pending_sync_id = store
            .get(PENDING_SYNC_ID_KEY)
            .map_err(|e| e.to_string())?
            .map(String::from_utf8)
            .transpose()
            .map_err(|e| format!("invalid pending sync id: {e}"))?;

        let pending_nonce_response = store
            .get(PENDING_NONCE_RESPONSE_KEY)
            .map_err(|e| e.to_string())?
            .map(|bytes| serde_json::from_slice::<RegistrationNonceResponse>(&bytes))
            .transpose()
            .map_err(|e| format!("invalid pending nonce response: {e}"))?;

        let pending_admission_proof = store
            .get(PENDING_ADMISSION_PROOF_KEY)
            .map_err(|e| e.to_string())?
            .map(|bytes| serde_json::from_slice::<FirstDeviceAdmissionProof>(&bytes))
            .transpose()
            .map_err(|e| format!("invalid pending admission proof: {e}"))?;

        let pending_registration_token = store
            .get(PENDING_REGISTRATION_TOKEN_KEY)
            .map_err(|e| e.to_string())?
            .map(String::from_utf8)
            .transpose()
            .map_err(|e| format!("invalid pending registration token: {e}"))?;

        (
            pending_sync_id,
            pending_nonce_response,
            pending_admission_proof,
            pending_registration_token,
        )
    };

    // Generate the sync_id BEFORE constructing the relay, because
    // ServerRelay requires a valid 64-char hex sync_id at construction
    // and the relay validates it on every request.
    let sync_id = pending
        .0
        .clone()
        .unwrap_or_else(prism_sync_core::epoch::EpochManager::generate_sync_id);
    let device_id = prism_sync_core::node_id::generate_node_id();

    let relay = build_relay(
        &relay_url,
        &sync_id,
        &device_id,
        "", // no session token yet — registration will return one
        None,
        handle.allow_insecure,
        pending.3.clone(),
    )?;

    let mut inner = handle.inner.lock().await;
    let pairing = PairingService::new(relay, inner.secure_store().clone());

    let create_result = pairing
        .create_sync_group(
            &password,
            &relay_url,
            mnemonic,
            Some(sync_id),
            pending.1.clone(),
            pending.2.clone(),
            pending.3.clone(),
        )
        .await;

    for key in [
        PENDING_SYNC_ID_KEY,
        PENDING_NONCE_RESPONSE_KEY,
        PENDING_ADMISSION_PROOF_KEY,
        PENDING_DEVICE_SECRET_KEY,
        PENDING_DEVICE_ID_KEY,
        PENDING_REGISTRATION_TOKEN_KEY,
    ] {
        let _ = inner.secure_store().delete(key);
    }

    let (creds, invite) = create_result.map_err(|e| encode_core_error("create_sync_group", e))?;

    // Unlock the handle's key hierarchy using the credentials that
    // create_sync_group just produced, and restore the device_secret.
    // This ensures configureEngine can derive the signing key and
    // the epoch key matches what's in the invite for other devices.
    let secret_key = prism_sync_crypto::mnemonic::to_bytes(&creds.mnemonic)
        .map_err(|e| format!("mnemonic conversion failed: {e}"))?;
    inner
        .unlock(&password, &secret_key)
        .map_err(|e| format!("unlock after create failed: {e}"))?;

    let device_secret_bytes = inner
        .secure_store()
        .get("device_secret")
        .map_err(|e| e.to_string())?
        .ok_or("device_secret not found after create_sync_group")?;
    let dek = inner.export_dek().map_err(|e| e.to_string())?;
    inner
        .restore_runtime_keys(&dek, &device_secret_bytes)
        .map_err(|e| e.to_string())?;

    let result = serde_json::json!({
        "qr_payload": invite.qr_payload(),
        "words": invite.words(),
        "url": invite.url(),
        "sync_id": invite.response().sync_id,
        "relay_url": invite.response().relay_url,
    });

    Ok(result.to_string())
}

/// Generate a pairing request for a new device wanting to join a sync group.
///
/// The joiner device calls this to create a PairingRequest containing its
/// device identity. The request is encoded as a QR code payload and JSON
/// for flexible transport.
///
/// Returns JSON: `{ "qr_payload": [...], "request_json": "...", "device_id": "..." }`
pub async fn generate_pairing_request(_handle: &PrismSyncHandle) -> Result<String, String> {
    // Generate a fresh device identity for the joiner
    let device_secret = prism_sync_crypto::DeviceSecret::generate();
    let device_id = prism_sync_core::node_id::generate_node_id();
    let signing_key = device_secret
        .ed25519_keypair(&device_id)
        .map_err(|e| format!("Key derivation failed: {e}"))?;
    let exchange_key = device_secret
        .x25519_keypair(&device_id)
        .map_err(|e| format!("Key derivation failed: {e}"))?;

    let request = prism_sync_core::pairing::models::PairingRequest {
        device_id: device_id.clone(),
        ed25519_public_key: signing_key.public_key_bytes().to_vec(),
        x25519_public_key: exchange_key.public_key_bytes().to_vec(),
    };

    let qr_payload = request
        .to_compact_bytes()
        .ok_or("Failed to encode pairing request")?;
    let request_json = serde_json::to_string(&request)
        .map_err(|e| format!("Failed to serialize pairing request: {e}"))?;

    // Persist the device secret so that complete_join can use it later.
    // The handle is not locked here because we only need to stash the
    // pre-generated identity for the join step.
    let handle_inner = _handle.inner.lock().await;
    let store = handle_inner.secure_store();
    store
        .set("pending_device_secret", device_secret.as_bytes())
        .map_err(|e| format!("Failed to persist pending device secret: {e}"))?;
    store
        .set("pending_device_id", device_id.as_bytes())
        .map_err(|e| format!("Failed to persist pending device id: {e}"))?;

    let result = serde_json::json!({
        "qr_payload": qr_payload,
        "request_json": request_json,
        "device_id": device_id,
    });

    Ok(result.to_string())
}

/// Approve a pairing request from a joining device.
///
/// Called by an existing trusted device after scanning a joiner's QR code.
/// Reads the current sync group credentials from SecureStore, builds a
/// PairingResponse targeting the joiner's device, and returns it for
/// transport back to the joiner (e.g. via QR, NFC, or paste).
///
/// Accepts the pairing request as either compact bytes (from QR scan) or JSON.
///
/// Returns JSON: `{ "qr_payload": [...], "response_json": "...", "url": "..." }`
pub async fn approve_pairing_request(
    handle: &PrismSyncHandle,
    request_bytes: Option<Vec<u8>>,
    request_json: Option<String>,
) -> Result<String, String> {
    // Parse the PairingRequest from whichever format was provided
    let request = if let Some(bytes) = request_bytes {
        prism_sync_core::pairing::models::PairingRequest::from_compact_bytes(&bytes)
            .ok_or("Failed to parse pairing request QR payload")?
    } else if let Some(json) = request_json {
        serde_json::from_str(&json)
            .map_err(|e| format!("Failed to parse pairing request JSON: {e}"))?
    } else {
        return Err("Either request_bytes or request_json must be provided".into());
    };

    let inner = handle.inner.lock().await;
    let store = inner.secure_store();

    // Read existing credentials from SecureStore (same as create_invite)
    let sync_id = store
        .get("sync_id")
        .map_err(|e| e.to_string())?
        .map(|b| String::from_utf8(b).unwrap_or_default())
        .ok_or("No sync_id — set up sync first")?;
    let relay_url = store
        .get("relay_url")
        .map_err(|e| e.to_string())?
        .map(|b| String::from_utf8(b).unwrap_or_default())
        .ok_or("No relay_url — set up sync first")?;
    let mnemonic = store
        .get("mnemonic")
        .map_err(|e| e.to_string())?
        .map(|b| String::from_utf8(b).unwrap_or_default())
        .ok_or("No mnemonic — set up sync first")?;
    let wrapped_dek = store
        .get("wrapped_dek")
        .map_err(|e| e.to_string())?
        .ok_or("No wrapped_dek — set up sync first")?;
    let salt = store
        .get("dek_salt")
        .map_err(|e| e.to_string())?
        .ok_or("No salt — set up sync first")?;
    let device_id = store
        .get("device_id")
        .map_err(|e| e.to_string())?
        .map(|b| String::from_utf8(b).unwrap_or_default())
        .ok_or("No device_id — set up sync first")?;
    let device_secret_bytes = store
        .get("device_secret")
        .map_err(|e| e.to_string())?
        .ok_or("No device_secret — set up sync first")?;

    let device_secret = prism_sync_crypto::DeviceSecret::from_bytes(device_secret_bytes)
        .map_err(|e| format!("Invalid device secret: {e}"))?;
    let signing_key = device_secret
        .ed25519_keypair(&device_id)
        .map_err(|e| format!("Key derivation failed: {e}"))?;
    let exchange_key = device_secret
        .x25519_keypair(&device_id)
        .map_err(|e| format!("Key derivation failed: {e}"))?;

    // Use the joiner's device_id from their PairingRequest
    let joiner_device_id = request.device_id.clone();

    // Read epoch state
    let epoch: i32 = inner
        .epoch()
        .ok_or("Cannot approve: sync engine not configured (epoch unknown)".to_string())?;
    let epoch_key_data: Vec<u8> = if epoch > 0 {
        inner
            .key_hierarchy()
            .epoch_key(epoch as u32)
            .map(|k| k.to_vec())
            .map_err(|_| format!("Cannot approve: missing epoch {epoch} key"))?
    } else {
        vec![]
    };

    // Sign the invitation
    let signing_data = prism_sync_core::pairing::models::build_invitation_signing_data(
        &sync_id,
        &relay_url,
        &wrapped_dek,
        &salt,
        &device_id,
        &signing_key.public_key_bytes(),
        Some(joiner_device_id.as_str()),
        epoch as u32,
        &epoch_key_data,
    );
    let signature = signing_key.sign(&signing_data);

    let mut registry_entries: Vec<prism_sync_core::pairing::models::RegistrySnapshotEntry> = inner
        .storage()
        .list_device_records(&sync_id)
        .map_err(|e| format!("Failed to read local device registry: {e}"))?
        .into_iter()
        .map(
            |device| prism_sync_core::pairing::models::RegistrySnapshotEntry {
                sync_id: device.sync_id,
                device_id: device.device_id,
                ed25519_public_key: device.ed25519_public_key,
                x25519_public_key: device.x25519_public_key,
                status: device.status,
            },
        )
        .collect();
    registry_entries
        .retain(|entry| entry.device_id != device_id && entry.device_id != joiner_device_id);
    registry_entries.push(prism_sync_core::pairing::models::RegistrySnapshotEntry {
        sync_id: sync_id.clone(),
        device_id: device_id.clone(),
        ed25519_public_key: signing_key.public_key_bytes().to_vec(),
        x25519_public_key: exchange_key.public_key_bytes().to_vec(),
        status: "active".into(),
    });
    registry_entries.push(prism_sync_core::pairing::models::RegistrySnapshotEntry {
        sync_id: sync_id.clone(),
        device_id: joiner_device_id.clone(),
        ed25519_public_key: request.ed25519_public_key.clone(),
        x25519_public_key: request.x25519_public_key.clone(),
        status: "active".into(),
    });

    // Build signed registry snapshot for current membership plus the approved joiner.
    let registry_snapshot =
        prism_sync_core::pairing::models::SignedRegistrySnapshot::new(registry_entries);
    let signed_keyring = registry_snapshot.sign(&signing_key);
    let approval_signature = signing_key.sign(
        &prism_sync_core::pairing::models::build_registry_approval_signing_data(
            &sync_id,
            &device_id,
            &signed_keyring,
        ),
    );

    // Build PairingResponse
    let response = prism_sync_core::pairing::models::PairingResponse {
        relay_url: relay_url.clone(),
        sync_id: sync_id.clone(),
        mnemonic,
        wrapped_dek: wrapped_dek.to_vec(),
        salt: salt.to_vec(),
        signed_invitation: prism_sync_crypto::hex::encode(&signature),
        signed_keyring,
        inviter_device_id: device_id,
        inviter_ed25519_pk: signing_key.public_key_bytes().to_vec(),
        joiner_device_id: Some(joiner_device_id),
        current_epoch: epoch as u32,
        epoch_key: epoch_key_data,
        registry_approval_signature: Some(prism_sync_crypto::hex::encode(&approval_signature)),
        registration_token: None,
    };

    let invite = prism_sync_core::pairing::models::Invite::new(response);

    let result = serde_json::json!({
        "qr_payload": invite.qr_payload(),
        "response_json": serde_json::to_string(invite.response()).unwrap_or_default(),
        "url": invite.url(),
        "sync_id": sync_id,
        "relay_url": relay_url,
    });

    Ok(result.to_string())
}

/// Join an existing sync group from QR payload bytes.
///
/// The relay is constructed on the Rust side from the invite's `relay_url`.
pub async fn join_from_qr(
    handle: &PrismSyncHandle,
    qr_bytes: Vec<u8>,
    password: String,
) -> Result<(), String> {
    let invite = Invite::from_qr_payload(&qr_bytes)
        .ok_or_else(|| "Failed to parse QR payload".to_string())?;
    join_with_response(handle, invite.response(), &password).await
}

/// Join an existing sync group from a deep link URL.
///
/// The relay is constructed on the Rust side from the invite's `relay_url`.
pub async fn join_from_url(
    handle: &PrismSyncHandle,
    url: String,
    password: String,
) -> Result<(), String> {
    let invite = Invite::from_url(&url).ok_or_else(|| "Failed to parse invite URL".to_string())?;
    join_with_response(handle, invite.response(), &password).await
}

/// Join from a raw PairingResponse JSON string.
///
/// This is the most flexible join method — use it when you have the full
/// pairing response (e.g. from a word-list lookup or manual entry).
/// The relay is constructed on the Rust side from the response's `relay_url`.
pub async fn join_from_response_json(
    handle: &PrismSyncHandle,
    response_json: String,
    password: String,
) -> Result<(), String> {
    let response: PairingResponse = serde_json::from_str(&response_json)
        .map_err(|e| format!("Failed to parse PairingResponse JSON: {e}"))?;
    join_with_response(handle, &response, &password).await
}

/// Internal helper for all join flows.
///
/// Constructs a `ServerRelay` from the pairing response's `relay_url` and
/// `sync_id`, then delegates to `PairingService::join_sync_group`.
async fn join_with_response(
    handle: &PrismSyncHandle,
    response: &PairingResponse,
    password: &str,
) -> Result<(), String> {
    let relay = build_relay(
        &response.relay_url,
        &response.sync_id,
        "pending", // device_id not known yet — generated by PairingService
        "",        // no session token yet
        None,
        handle.allow_insecure,
        response.registration_token.clone(),
    )?;

    let mut inner = handle.inner.lock().await;
    let pairing = PairingService::new(relay, inner.secure_store().clone());

    let (key_hierarchy, registry_snapshot) = pairing
        .join_sync_group(response, password)
        .await
        .map_err(|e| encode_core_error("join_sync_group", e))?;

    DeviceRegistryManager::import_keyring(
        inner.storage().as_ref(),
        &response.sync_id,
        &registry_snapshot.to_device_records(),
    )
    .map_err(|e| e.to_string())?;

    // Restore the unlocked key hierarchy and device secret into the handle
    // so subsequent calls (configureEngine, exportDek, etc.) work.
    let dek = key_hierarchy.dek().map_err(|e| e.to_string())?;
    let device_secret_bytes = inner
        .secure_store()
        .get("device_secret")
        .map_err(|e| e.to_string())?
        .ok_or("device_secret not found after join")?;
    inner
        .restore_runtime_keys(dek, &device_secret_bytes)
        .map_err(|e| e.to_string())?;

    // Restore epoch keys that were stored during join into the live handle's
    // key hierarchy so configureEngine / bootstrapFromSnapshot / syncNow see them.
    let epoch_val = inner
        .secure_store()
        .get("epoch")
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    if epoch_val > 0 {
        let key_name = format!("epoch_key_{}", epoch_val);
        match inner.secure_store().get(&key_name) {
            Ok(Some(stored)) => {
                use base64::{engine::general_purpose::STANDARD, Engine};
                match STANDARD.decode(&stored) {
                    Ok(decoded) if decoded.len() == 32 => {
                        inner
                            .key_hierarchy_mut()
                            .store_epoch_key(epoch_val, zeroize::Zeroizing::new(decoded));
                    }
                    Ok(decoded) => {
                        return Err(format!(
                            "epoch_key_{} has wrong length ({}, expected 32) — device cannot decrypt at epoch {}",
                            epoch_val, decoded.len(), epoch_val,
                        ));
                    }
                    Err(e) => {
                        return Err(format!(
                            "epoch_key_{} base64 decode failed: {e} — device cannot decrypt at epoch {}",
                            epoch_val, epoch_val,
                        ));
                    }
                }
            }
            Ok(None) => {
                return Err(format!(
                    "epoch_key_{} not found in secure store — device cannot decrypt at epoch {}",
                    epoch_val, epoch_val,
                ));
            }
            Err(e) => {
                return Err(format!("Failed to read epoch_key_{}: {e}", epoch_val,));
            }
        }
    }

    inner
        .secure_store()
        .delete("pending_device_secret")
        .map_err(|e| e.to_string())?;
    inner
        .secure_store()
        .delete("pending_device_id")
        .map_err(|e| e.to_string())?;

    Ok(())
}

// ── Device management ──

/// List devices in the sync group. Returns JSON array.
///
/// Each element: `{"device_id", "epoch", "status", "permission"}`.
///
/// Takes primitive connection parameters instead of a relay trait object.
/// The `ServerRelay` is constructed internally.
pub async fn list_devices(
    handle: &PrismSyncHandle,
    sync_id: String,
    device_id: String,
    session_token: String,
) -> Result<String, String> {
    let device_secret = handle
        .inner
        .lock()
        .await
        .secure_store()
        .get("device_secret")
        .map_err(|e| e.to_string())?;
    let relay = build_relay(
        &handle.relay_url,
        &sync_id,
        &device_id,
        &session_token,
        device_secret,
        handle.allow_insecure,
        None,
    )?;

    let devices = relay
        .list_devices()
        .await
        .map_err(|e| format!("list_devices failed: {e}"))?;

    let json: Vec<serde_json::Value> = devices.iter().map(device_info_to_json).collect();
    serde_json::to_string(&json).map_err(|e| format!("JSON serialization failed: {e}"))
}

/// Revoke a device (owner only).
///
/// Takes primitive connection parameters instead of a relay trait object.
/// The `ServerRelay` is constructed internally.
pub async fn revoke_device(
    handle: &PrismSyncHandle,
    sync_id: String,
    device_id: String,
    session_token: String,
    target_device_id: String,
) -> Result<(), String> {
    let device_secret = handle
        .inner
        .lock()
        .await
        .secure_store()
        .get("device_secret")
        .map_err(|e| e.to_string())?;
    let relay = build_relay(
        &handle.relay_url,
        &sync_id,
        &device_id,
        &session_token,
        device_secret,
        handle.allow_insecure,
        None,
    )?;
    let mut inner = handle.inner.lock().await;
    inner
        .revoke_and_rekey(
            relay as std::sync::Arc<dyn prism_sync_core::relay::SyncRelay>,
            &target_device_id,
            false,
        )
        .await
        .map(|_| ())
        .map_err(|e| format!("revoke_device failed: {e}"))
}

/// Revoke a device and perform epoch key rotation.
///
/// This is the correct way to revoke a device — it:
/// 1. Revokes the device on the relay (bumps epoch)
/// 2. Generates a new epoch key
/// 3. Wraps the key for each remaining device via X25519 DH
/// 4. Posts wrapped keys to the relay
/// 5. Persists the new epoch key locally
/// 6. Updates local epoch metadata
///
/// Returns the new epoch number.
pub async fn revoke_and_rekey(
    handle: &PrismSyncHandle,
    sync_id: String,
    device_id: String,
    session_token: String,
    target_device_id: String,
    remote_wipe: bool,
) -> Result<u32, String> {
    let device_secret = handle
        .inner
        .lock()
        .await
        .secure_store()
        .get("device_secret")
        .map_err(|e| e.to_string())?;
    let relay = build_relay(
        &handle.relay_url,
        &sync_id,
        &device_id,
        &session_token,
        device_secret,
        handle.allow_insecure,
        None,
    )?;
    let mut inner = handle.inner.lock().await;
    inner
        .revoke_and_rekey(
            relay as std::sync::Arc<dyn prism_sync_core::relay::SyncRelay>,
            &target_device_id,
            remote_wipe,
        )
        .await
        .map_err(|e| format!("revoke_and_rekey failed: {e}"))
}

/// Deprecated: wipe status is now embedded in the 401 response from the relay.
/// This stub is kept only for FFI binding compatibility until bindings are regenerated.
pub async fn check_wipe_status(
    _relay_url: String,
    _sync_id: String,
    _device_id: String,
) -> Result<Option<bool>, String> {
    Err("check_wipe_status is deprecated: wipe status is now embedded in 401 auth responses".into())
}

// ── Mnemonic utilities ──

/// Convert a BIP39 mnemonic string to its 16-byte entropy.
///
/// This is needed because `initialize()` and `unlock()` take `secret_key: Vec<u8>`,
/// but the user sees/enters a 12-word mnemonic. This bridges the two.
pub fn mnemonic_to_bytes(mnemonic: String) -> Result<Vec<u8>, String> {
    prism_sync_crypto::mnemonic::to_bytes(&mnemonic).map_err(|e| e.to_string())
}

/// Convert 16-byte entropy back to a BIP39 mnemonic string.
pub fn bytes_to_mnemonic(bytes: Vec<u8>) -> Result<String, String> {
    prism_sync_crypto::mnemonic::from_bytes(&bytes).map_err(|e| e.to_string())
}

// ── Sync group management ──

/// Deregister this device from the sync group (self-removal).
///
/// The device is removed from the relay and can no longer sync.
/// Local data is preserved — only the relay registration is removed.
pub async fn deregister_device(
    handle: &PrismSyncHandle,
    sync_id: String,
    device_id: String,
    session_token: String,
) -> Result<(), String> {
    let device_secret = handle
        .inner
        .lock()
        .await
        .secure_store()
        .get("device_secret")
        .map_err(|e| e.to_string())?;
    let relay = build_relay(
        &handle.relay_url,
        &sync_id,
        &device_id,
        &session_token,
        device_secret,
        handle.allow_insecure,
        None,
    )?;
    relay
        .deregister()
        .await
        .map_err(|e| format!("deregister failed: {e}"))
}

/// Delete the entire sync group and all data on the relay.
///
/// Only allowed if this device is the sole active device in the group.
/// All relay data (batches, snapshots, device records) is permanently deleted.
pub async fn delete_sync_group(
    handle: &PrismSyncHandle,
    sync_id: String,
    device_id: String,
    session_token: String,
) -> Result<(), String> {
    let device_secret = handle
        .inner
        .lock()
        .await
        .secure_store()
        .get("device_secret")
        .map_err(|e| e.to_string())?;
    let relay = build_relay(
        &handle.relay_url,
        &sync_id,
        &device_id,
        &session_token,
        device_secret,
        handle.allow_insecure,
        None,
    )?;
    relay
        .delete_sync_group()
        .await
        .map_err(|e| format!("delete_sync_group failed: {e}"))
}

// ── Device info ──

/// Get this device's node ID (12-char hex identifier).
///
/// Reads from SecureStore. Returns None if no device_id has been generated yet
/// (i.e., before pairing).
pub async fn get_node_id(handle: &PrismSyncHandle) -> Result<Option<String>, String> {
    let inner = handle.inner.lock().await;
    inner
        .secure_store()
        .get("device_id")
        .map(|opt| opt.map(|b| String::from_utf8(b).unwrap_or_default()))
        .map_err(|e| e.to_string())
}

// ── SecureStore bridge ──

/// Seed the in-memory secure store with values from the platform keychain.
/// Call this after `create_prism_sync`, before `initialize`/`unlock`/`configure_engine`.
///
/// `entries_json` is a JSON object: `{"key": "base64value", ...}`
pub async fn seed_secure_store(
    handle: &PrismSyncHandle,
    entries_json: String,
) -> Result<(), String> {
    let entries: std::collections::HashMap<String, String> =
        serde_json::from_str(&entries_json).map_err(|e| format!("Invalid entries JSON: {e}"))?;
    let inner = handle.inner.lock().await;
    let store = inner.secure_store();
    for (key, b64_value) in entries {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&b64_value)
            .map_err(|e| format!("Invalid base64 for key '{key}': {e}"))?;
        store.set(&key, &bytes).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Drain all values from the secure store so Dart can persist them
/// back to the platform keychain.
///
/// Returns a JSON object: `{"key": "base64value", ...}`
/// Call this after state-changing operations (initialize, change_password,
/// create_sync_group, join_*).
pub async fn drain_secure_store(handle: &PrismSyncHandle) -> Result<String, String> {
    let (store, storage, sync_id, cached_epoch) = {
        let inner = handle.inner.lock().await;
        let cached_epoch = inner
            .secure_store()
            .get("epoch")
            .ok()
            .flatten()
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        (
            inner.secure_store().clone(),
            inner.storage().clone(),
            inner.sync_service().sync_id().map(|s| s.to_string()),
            cached_epoch,
        )
    };

    let current_epoch = if let Some(sync_id) = sync_id {
        let meta_epoch = tokio::task::spawn_blocking(move || storage.get_sync_metadata(&sync_id))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?
            .map(|m| m.current_epoch.max(0) as u32);
        meta_epoch.unwrap_or(cached_epoch)
    } else {
        cached_epoch
    };

    let known_keys = [
        "wrapped_dek",
        "dek_salt",
        "device_secret",
        "device_id",
        "sync_id",
        "session_token",
        "epoch",
        "relay_url",
        "mnemonic",
        "setup_rollback_marker",
    ];
    let mut entries = serde_json::Map::new();
    for key in known_keys {
        if let Ok(Some(value)) = store.get(key) {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&value);
            entries.insert(key.to_string(), serde_json::Value::String(b64));
        }
    }
    for epoch in 1..=current_epoch {
        let key = format!("epoch_key_{epoch}");
        if let Ok(Some(value)) = store.get(&key) {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&value);
            entries.insert(key, serde_json::Value::String(b64));
        }
    }
    Ok(serde_json::Value::Object(entries).to_string())
}

// ── Sharing crypto primitives ──

/// Returns the 32-byte X25519 public key for this device's identity.
/// Used by the sharing/friend-invite system to exchange public keys.
pub async fn get_identity_public_key(handle: &PrismSyncHandle) -> Result<Vec<u8>, String> {
    let inner = handle.inner.lock().await;
    let device_secret = inner
        .device_secret()
        .ok_or("Device secret not initialized")?;
    let device_id = inner.device_id().ok_or("Device ID not configured")?;
    let exchange_key = device_secret
        .x25519_keypair(device_id)
        .map_err(|e| e.to_string())?;
    Ok(exchange_key.public_key_bytes().to_vec())
}

/// Perform X25519 ECDH key agreement with a peer's public key.
/// Returns the 32-byte shared secret.
pub async fn perform_ecdh(
    handle: &PrismSyncHandle,
    peer_public_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    if peer_public_key.len() != 32 {
        return Err(format!(
            "peer public key must be 32 bytes, got {}",
            peer_public_key.len()
        ));
    }
    let inner = handle.inner.lock().await;
    let device_secret = inner
        .device_secret()
        .ok_or("Device secret not initialized")?;
    let device_id = inner.device_id().ok_or("Device ID not configured")?;
    let exchange_key = device_secret
        .x25519_keypair(device_id)
        .map_err(|e| e.to_string())?;
    let mut peer_arr = [0u8; 32];
    peer_arr.copy_from_slice(&peer_public_key);
    Ok(exchange_key.diffie_hellman(&peer_arr))
}

/// Encrypt plaintext with XChaCha20-Poly1305. Returns `nonce || ciphertext+MAC`.
pub fn encrypt_xchacha(key: Vec<u8>, plaintext: Vec<u8>) -> Result<Vec<u8>, String> {
    prism_sync_crypto::aead::xchacha_encrypt(&key, &plaintext).map_err(|e| e.to_string())
}

/// Decrypt `nonce || ciphertext+MAC` with XChaCha20-Poly1305.
pub fn decrypt_xchacha(key: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, String> {
    prism_sync_crypto::aead::xchacha_decrypt(&key, &ciphertext).map_err(|e| e.to_string())
}

/// Generate cryptographically secure random bytes.
pub fn random_bytes(len: u32) -> Vec<u8> {
    prism_sync_crypto::random_bytes(len as usize)
}

/// Hex-encode bytes.
pub fn hex_encode(bytes: Vec<u8>) -> String {
    prism_sync_crypto::hex::encode(&bytes)
}

/// Hex-decode a string to bytes.
pub fn hex_decode(hex_str: String) -> Result<Vec<u8>, String> {
    prism_sync_crypto::hex::decode(&hex_str).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_and_caps() {
        // Simulate the backoff progression: 0 → 30 → 60 → 120 → 240 → 300 → 300
        let mut backoff_secs: u64 = 0;
        let expected = [30, 60, 120, 240, 300, 300];
        for &exp in &expected {
            backoff_secs = if backoff_secs == 0 {
                30
            } else {
                (backoff_secs * 2).min(300)
            };
            assert_eq!(backoff_secs, exp);
        }
    }

    #[test]
    fn backoff_resets_on_success() {
        let mut backoff_secs: u64 = 0;
        let mut backoff_attempt: u32 = 0;
        let mut cumulative_backoff_secs: u64 = 0;

        // Simulate two failures
        for _ in 0..2 {
            backoff_secs = if backoff_secs == 0 {
                30
            } else {
                (backoff_secs * 2).min(300)
            };
            backoff_attempt += 1;
            cumulative_backoff_secs += backoff_secs;
        }
        assert_eq!(backoff_secs, 60);
        assert_eq!(backoff_attempt, 2);
        assert_eq!(cumulative_backoff_secs, 90);

        // Simulate success
        backoff_secs = 0;
        backoff_attempt = 0;
        cumulative_backoff_secs = 0;
        assert_eq!(backoff_secs, 0);
        assert_eq!(backoff_attempt, 0);
        assert_eq!(cumulative_backoff_secs, 0);

        // Next failure starts fresh at 30
        backoff_secs = if backoff_secs == 0 {
            30
        } else {
            (backoff_secs * 2).min(300)
        };
        assert_eq!(backoff_secs, 30);
    }

    #[test]
    fn cumulative_backoff_exceeds_max() {
        let mut backoff_secs: u64 = 0;
        let mut cumulative_backoff_secs: u64 = 0;
        let mut attempts = 0u32;
        const MAX_CUMULATIVE_SECS: u64 = 600;

        loop {
            backoff_secs = if backoff_secs == 0 {
                30
            } else {
                (backoff_secs * 2).min(300)
            };
            attempts += 1;
            cumulative_backoff_secs += backoff_secs;

            if cumulative_backoff_secs >= MAX_CUMULATIVE_SECS {
                break;
            }
        }

        // Should hit the cap after: 30+60+120+240+300 = 750 ≥ 600, so 5 attempts
        assert_eq!(attempts, 5);
        assert!(cumulative_backoff_secs >= MAX_CUMULATIVE_SECS);
    }

    #[test]
    fn backoff_scheduled_event_json() {
        let event = prism_sync_core::events::SyncEvent::BackoffScheduled {
            attempt: 3,
            delay_secs: 120,
        };
        let json = sync_event_to_json(&event);
        assert_eq!(json["type"], "BackoffScheduled");
        assert_eq!(json["attempt"], 3);
        assert_eq!(json["delay_secs"], 120);
    }
}
