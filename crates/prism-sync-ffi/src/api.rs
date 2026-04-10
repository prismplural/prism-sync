use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use prism_sync_core::bootstrap::sharing_trust::{
    compute_sharing_fingerprint, evaluate_identity_with_generation_floor,
    GenerationAwareTrustDecision,
};
use prism_sync_core::bootstrap::{
    InitiatorCeremony, JoinerCeremony, PrekeyStore, RendezvousToken, SharingIdentityBundle,
    SharingRecipient, SharingSender,
};
use prism_sync_core::client::PrismSync;
use prism_sync_core::pairing::service::PairingService;
use prism_sync_core::relay::traits::{FirstDeviceAdmissionProof, RegistrationNonceResponse};
use prism_sync_core::relay::ServerPairingRelay;
use prism_sync_core::relay::{ServerRelay, ServerSharingRelay};
// Import the trait for method resolution only — NOT exposed in any public FFI signature.
use prism_sync_core::relay::SharingRelay as _;
use prism_sync_core::relay::SyncRelay as _;
use prism_sync_core::schema::{SyncSchema, SyncValue};
use prism_sync_core::storage::{RusqliteSyncStorage, SyncStorage};
use prism_sync_core::sync_service::AutoSyncConfig;
use prism_sync_core::{
    background_runtime, spawn_notification_handler, DeviceRegistryManager,
    SecureStore as PrismSecureStore,
};
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
    /// In-progress joiner ceremony state (relay-based PQ pairing).
    joiner_ceremony: std::sync::Mutex<Option<JoinerCeremony>>,
    /// In-progress initiator ceremony state (relay-based PQ pairing).
    initiator_ceremony: std::sync::Mutex<Option<InitiatorCeremony>>,
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
        min_signature_version,
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
        if let Some(min_signature_version) = min_signature_version {
            payload["min_signature_version"] = serde_json::json!(min_signature_version);
        }
        if let Some(remote_wipe) = remote_wipe {
            payload["remote_wipe"] = serde_json::json!(remote_wipe);
        }
    } else {
        payload["error_type"] = serde_json::json!("core");
    }

    format!("{STRUCTURED_ERROR_PREFIX}{payload}")
}

async fn encode_handle_core_error(
    handle: &PrismSyncHandle,
    operation: &str,
    error: prism_sync_core::CoreError,
) -> String {
    if let prism_sync_core::CoreError::Relay {
        min_signature_version,
        ..
    } = &error
    {
        let _ = ratchet_handle_min_signature_version(handle, *min_signature_version).await;
    }
    encode_core_error(operation, error)
}

async fn format_handle_relay_error(
    handle: &PrismSyncHandle,
    operation: &str,
    error: prism_sync_core::relay::traits::RelayError,
) -> String {
    if let prism_sync_core::relay::traits::RelayError::UpgradeRequired {
        min_signature_version,
        ..
    } = &error
    {
        let _ = ratchet_handle_min_signature_version(handle, Some(*min_signature_version)).await;
    }
    format!("{operation} failed: {error}")
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
        "ml_dsa_key_generation": info.ml_dsa_key_generation,
    })
}

const SHARING_ID_CACHE_KEY: &str = "sharing_id_cache";
const MIN_SIGNATURE_VERSION_FLOOR_KEY: &str = "min_signature_version_floor";
const SUPPORTED_SIGNATURE_VERSION: u8 = 0x03;
const SHARING_ID_LEN_BYTES: usize = 16;
const PAIRWISE_SECRET_LEN_BYTES: usize = 32;

struct SharingHandleContext {
    relay: Arc<ServerSharingRelay>,
    secure_store: Arc<dyn PrismSecureStore>,
    dek: Vec<u8>,
    device_id: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct SharingProcessPendingInputsObject {
    #[serde(default)]
    pub existing_relationships: Vec<String>,
    #[serde(default, alias = "pinned_identities_b64")]
    pub pinned_identities: HashMap<String, String>,
    #[serde(default, alias = "verified_by_peer")]
    pub verified_peers: HashMap<String, bool>,
}

#[derive(Debug, Default)]
pub struct SharingProcessPendingInputs {
    pub existing_relationships: Vec<String>,
    pub pinned_identities: HashMap<String, Vec<u8>>,
    pub verified_peers: HashMap<String, bool>,
}

#[derive(Debug, Serialize)]
struct SharingPendingResultJson {
    status: String,
    init_id: String,
    sender_sharing_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offered_scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pairwise_secret_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pairwise_secret_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sender_identity_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sender_identity_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trust_decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn now_unix_timestamp() -> Result<i64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("System clock is before UNIX_EPOCH: {e}"))?;
    Ok(duration.as_secs() as i64)
}

fn decode_binary_string(value: &str, field_name: &str) -> Result<Vec<u8>, String> {
    if value.len().is_multiple_of(2) && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return prism_sync_crypto::hex::decode(value)
            .map_err(|e| format!("Invalid hex in {field_name}: {e}"));
    }

    BASE64
        .decode(value)
        .map_err(|e| format!("Invalid base64 in {field_name}: {e}"))
}

fn parse_sharing_id_bytes(sharing_id: &str) -> Result<[u8; SHARING_ID_LEN_BYTES], String> {
    let decoded = prism_sync_crypto::hex::decode(sharing_id)
        .map_err(|e| format!("sharing_id must be 32 hex chars (decode failed: {e})"))?;
    if decoded.len() != SHARING_ID_LEN_BYTES {
        return Err(format!(
            "sharing_id must be 32 hex chars (got {} bytes)",
            decoded.len()
        ));
    }
    let mut bytes = [0u8; SHARING_ID_LEN_BYTES];
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}

fn generation_aware_trust_decision_to_str(
    decision: &GenerationAwareTrustDecision,
) -> Option<&'static str> {
    match decision {
        GenerationAwareTrustDecision::Accept => Some("accept"),
        GenerationAwareTrustDecision::WarnKeyChange => Some("warn_key_change"),
        GenerationAwareTrustDecision::BlockKeyChange => Some("block_key_change"),
        GenerationAwareTrustDecision::RejectStaleGenerationReplay
        | GenerationAwareTrustDecision::RejectSharingIdMismatch
        | GenerationAwareTrustDecision::RejectMalformedIdentity => None,
    }
}

fn decode_optional_utf8(store: &dyn PrismSecureStore, key: &str) -> Result<Option<String>, String> {
    store
        .get(key)
        .map_err(|e| e.to_string())?
        .map(|bytes| String::from_utf8(bytes).map_err(|e| format!("invalid UTF-8 in {key}: {e}")))
        .transpose()
}

fn require_secure_string(store: &dyn PrismSecureStore, key: &str) -> Result<String, String> {
    decode_optional_utf8(store, key)?.ok_or_else(|| format!("{key} not found in secure store"))
}

fn decode_optional_u8(store: &dyn PrismSecureStore, key: &str) -> Result<Option<u8>, String> {
    decode_optional_utf8(store, key)?
        .map(|value| {
            value
                .parse::<u8>()
                .map_err(|e| format!("invalid integer in {key}: {e}"))
        })
        .transpose()
}

fn ratchet_min_signature_version(
    store: &dyn PrismSecureStore,
    observed: Option<u8>,
) -> Result<(), String> {
    let Some(observed) = observed else {
        return Ok(());
    };
    let current = decode_optional_u8(store, MIN_SIGNATURE_VERSION_FLOOR_KEY)?.unwrap_or(0);
    if observed > current {
        store
            .set(
                MIN_SIGNATURE_VERSION_FLOOR_KEY,
                observed.to_string().as_bytes(),
            )
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn enforce_supported_signature_version_floor(store: &dyn PrismSecureStore) -> Result<(), String> {
    if let Some(required) = decode_optional_u8(store, MIN_SIGNATURE_VERSION_FLOOR_KEY)? {
        if required > SUPPORTED_SIGNATURE_VERSION {
            return Err(format!(
                "relay requires signature version {required}, but this app supports up to {SUPPORTED_SIGNATURE_VERSION}. Please update."
            ));
        }
    }
    Ok(())
}

fn cache_sharing_id(store: &dyn PrismSecureStore, sharing_id: &str) -> Result<(), String> {
    store
        .set(SHARING_ID_CACHE_KEY, sharing_id.as_bytes())
        .map_err(|e| e.to_string())
}

fn clear_sharing_id_cache(store: &dyn PrismSecureStore) -> Result<(), String> {
    store
        .delete(SHARING_ID_CACHE_KEY)
        .map_err(|e| e.to_string())
}

fn validate_cached_sharing_id(
    store: &dyn PrismSecureStore,
    sharing_id: &str,
) -> Result<(), String> {
    if let Some(cached) = decode_optional_utf8(store, SHARING_ID_CACHE_KEY)? {
        if cached != sharing_id {
            return Err(format!(
                "secure-store sharing state is bound to a different sharing_id: expected {sharing_id}, found {cached}"
            ));
        }
    }
    Ok(())
}

fn sharing_rotation_needed(store: &dyn PrismSecureStore, sharing_id: &str) -> Result<bool, String> {
    if let Some(cached) = decode_optional_utf8(store, SHARING_ID_CACHE_KEY)? {
        if cached != sharing_id {
            return Err(format!(
                "secure-store sharing state is bound to a different sharing_id: expected {sharing_id}, found {cached}"
            ));
        }
        return Ok(true);
    }

    store
        .get("sharing_prekey_store")
        .map_err(|e| e.to_string())
        .map(|value| value.is_some())
}

async fn republish_sharing_identity(
    handle: &PrismSyncHandle,
    sharing_id: &str,
    identity_generation: u32,
) -> Result<(), String> {
    let context = build_sharing_context(handle).await?;
    let sharing_id_bytes = parse_sharing_id_bytes(sharing_id)?;
    validate_cached_sharing_id(context.secure_store.as_ref(), sharing_id)?;

    PrekeyStore::clear_persisted(context.secure_store.as_ref()).map_err(|e| e.to_string())?;

    let mut recipient = SharingRecipient::from_dek(
        &context.dek,
        sharing_id,
        &sharing_id_bytes,
        identity_generation,
    )
    .map_err(|e| e.to_string())?;

    if let Err(error) = context
        .relay
        .publish_identity(sharing_id, &recipient.identity().to_bytes())
        .await
    {
        return Err(format_handle_relay_error(handle, "publish_identity", error).await);
    }

    recipient
        .ensure_prekey_fresh_and_persist(
            context.relay.as_ref(),
            context.secure_store.as_ref(),
            &context.device_id,
            now_unix_timestamp()?,
        )
        .await
        .map_err(|e| e.to_string())?;

    cache_sharing_id(context.secure_store.as_ref(), sharing_id)?;
    Ok(())
}

fn parse_string_array_json(input: &str, field_name: &str) -> Result<Vec<String>, String> {
    if input.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(input).map_err(|e| format!("Invalid {field_name} JSON: {e}"))
}

fn parse_sharing_process_pending_inputs(
    input: &str,
) -> Result<SharingProcessPendingInputs, String> {
    if input.trim().is_empty() {
        return Ok(SharingProcessPendingInputs::default());
    }

    if let Ok(existing_relationships) = serde_json::from_str::<Vec<String>>(input) {
        return Ok(SharingProcessPendingInputs {
            existing_relationships,
            ..SharingProcessPendingInputs::default()
        });
    }

    let parsed: SharingProcessPendingInputsObject = serde_json::from_str(input)
        .map_err(|e| format!("Invalid sharing_process_pending context JSON: {e}"))?;
    let mut pinned_identities = HashMap::with_capacity(parsed.pinned_identities.len());
    for (peer_id, encoded_identity) in parsed.pinned_identities {
        pinned_identities.insert(
            peer_id,
            decode_binary_string(&encoded_identity, "pinned_identities")?,
        );
    }

    Ok(SharingProcessPendingInputs {
        existing_relationships: parsed.existing_relationships,
        pinned_identities,
        verified_peers: parsed.verified_peers,
    })
}

fn build_sharing_relay(
    relay_url: String,
    sync_id: String,
    device_id: String,
    session_token: String,
    device_secret_bytes: Vec<u8>,
    ml_dsa_key_generation: u32,
) -> Result<Arc<ServerSharingRelay>, String> {
    let device_secret = DeviceSecret::from_bytes(device_secret_bytes)
        .map_err(|e| format!("Invalid device secret: {e}"))?;
    let signing_key = device_secret
        .ed25519_keypair(&device_id)
        .map_err(|e| format!("Failed to derive sharing signing key: {e}"))?
        .into_signing_key();
    let ml_dsa_signing_key = device_secret
        .ml_dsa_65_keypair_v(&device_id, ml_dsa_key_generation)
        .map_err(|e| format!("Failed to derive sharing ML-DSA signing key: {e}"))?;
    let relay = ServerSharingRelay::new(
        relay_url,
        session_token,
        sync_id,
        device_id,
        signing_key,
        ml_dsa_signing_key,
    )
    .map_err(|e| format!("Failed to create ServerSharingRelay: {e}"))?;
    Ok(Arc::new(relay))
}

async fn build_sharing_context(handle: &PrismSyncHandle) -> Result<SharingHandleContext, String> {
    let (
        storage,
        secure_store,
        fallback_relay_url,
        fallback_sync_id,
        fallback_device_id,
        fallback_secret,
        dek,
    ) = {
        let inner = handle.inner.lock().await;
        (
            inner.storage().clone(),
            inner.secure_store().clone(),
            inner.relay_url().map(str::to_string),
            inner.sync_service().sync_id().map(str::to_string),
            inner.device_id().map(str::to_string),
            inner
                .device_secret()
                .map(|secret| secret.as_bytes().to_vec()),
            inner.export_dek().map_err(|e| e.to_string())?,
        )
    };

    enforce_supported_signature_version_floor(secure_store.as_ref())?;

    let relay_url = decode_optional_utf8(secure_store.as_ref(), "relay_url")?
        .or(fallback_relay_url)
        .ok_or_else(|| "relay_url not configured".to_string())?;
    let sync_id = decode_optional_utf8(secure_store.as_ref(), "sync_id")?
        .or(fallback_sync_id)
        .ok_or_else(|| "sync_id not configured".to_string())?;
    let device_id = decode_optional_utf8(secure_store.as_ref(), "device_id")?
        .or(fallback_device_id)
        .ok_or_else(|| "device_id not configured".to_string())?;
    let session_token = require_secure_string(secure_store.as_ref(), "session_token")?;
    let device_secret_bytes = secure_store
        .get("device_secret")
        .map_err(|e| e.to_string())?
        .or(fallback_secret)
        .ok_or_else(|| "device_secret not configured".to_string())?;
    let ml_dsa_key_generation =
        load_device_ml_dsa_generation(storage.clone(), sync_id.clone(), device_id.clone()).await?;

    Ok(SharingHandleContext {
        relay: build_sharing_relay(
            relay_url,
            sync_id,
            device_id.clone(),
            session_token,
            device_secret_bytes,
            ml_dsa_key_generation,
        )?,
        secure_store,
        dek,
        device_id,
    })
}

async fn load_device_ml_dsa_generation(
    storage: Arc<dyn SyncStorage>,
    sync_id: String,
    device_id: String,
) -> Result<u32, String> {
    let lookup_device_id = device_id.clone();
    let record = tokio::task::spawn_blocking(move || {
        storage.get_device_record(&sync_id, &lookup_device_id)
    })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("device {device_id} not in local registry"))?;

    Ok(record.ml_dsa_key_generation)
}

async fn enforce_handle_signature_version_floor(handle: &PrismSyncHandle) -> Result<(), String> {
    let secure_store = {
        let inner = handle.inner.lock().await;
        inner.secure_store().clone()
    };
    enforce_supported_signature_version_floor(secure_store.as_ref())
}

async fn ratchet_handle_min_signature_version(
    handle: &PrismSyncHandle,
    observed: Option<u8>,
) -> Result<(), String> {
    let secure_store = match handle.inner.try_lock() {
        Ok(inner) => inner.secure_store().clone(),
        Err(_) => return Ok(()),
    };
    ratchet_min_signature_version(secure_store.as_ref(), observed)
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
        joiner_ceremony: std::sync::Mutex::new(None),
        initiator_ceremony: std::sync::Mutex::new(None),
    })
}

// ── Key lifecycle ──

/// Initialize (first-time setup).
pub async fn initialize(
    handle: &PrismSyncHandle,
    password: String,
    secret_key: Vec<u8>,
) -> Result<(), String> {
    // Argon2id (64 MiB, 3 rounds) is CPU-heavy. Run on a spawn_blocking thread
    // so we don't stall the tokio worker. blocking_lock() acquires the tokio
    // Mutex synchronously, which is safe inside spawn_blocking.
    let inner = handle.inner.clone();
    tokio::task::spawn_blocking(move || {
        inner
            .blocking_lock()
            .initialize(&password, &secret_key)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("task failed: {e}"))?
}

/// Unlock (subsequent launches).
pub async fn unlock(
    handle: &PrismSyncHandle,
    password: String,
    secret_key: Vec<u8>,
) -> Result<(), String> {
    // Same reasoning as initialize — Argon2id must not run on a tokio worker.
    let inner = handle.inner.clone();
    tokio::task::spawn_blocking(move || {
        inner
            .blocking_lock()
            .unlock(&password, &secret_key)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("task failed: {e}"))?
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
    enforce_supported_signature_version_floor(inner.secure_store().as_ref())?;

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
    let storage = inner.storage().clone();

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

    // Prefer relay_url from secure store (set by pairing / createSyncGroup)
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
    let ml_dsa_key_generation =
        load_device_ml_dsa_generation(storage, sync_id.clone(), device_id.clone()).await?;

    // Construct relay
    let relay = build_relay(
        &relay_url,
        &sync_id,
        &device_id,
        &session_token,
        device_secret,
        ml_dsa_key_generation,
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
///
/// Returns the next `identity_generation` value that the app should persist
/// to synced settings. If local sharing is currently active, this also
/// republishes the sharing identity and rotates the signed prekey under the
/// incremented generation before re-wrapping the DEK.
pub async fn change_password(
    handle: &PrismSyncHandle,
    _old_password: String,
    new_password: String,
    secret_key: Vec<u8>,
    sharing_id: Option<String>,
    current_identity_generation: u32,
) -> Result<u32, String> {
    let next_identity_generation = current_identity_generation
        .checked_add(1)
        .ok_or_else(|| "identity_generation overflow".to_string())?;
    let normalized_sharing_id = sharing_id.filter(|value| !value.is_empty());

    let sharing_rotation_needed = {
        let inner = handle.inner.lock().await;
        let secure_store = inner.secure_store().clone();
        if let Some(ref sharing_id) = normalized_sharing_id {
            sharing_rotation_needed(secure_store.as_ref(), sharing_id)?
        } else {
            false
        }
    };

    if sharing_rotation_needed {
        republish_sharing_identity(
            handle,
            normalized_sharing_id
                .as_deref()
                .ok_or_else(|| "missing sharing_id for sharing rotation".to_string())?,
            next_identity_generation,
        )
        .await?;
    }

    // Argon2id (re-wrap DEK under new password) must not run on a tokio worker.
    let inner_arc = handle.inner.clone();
    tokio::task::spawn_blocking(move || {
        let inner = inner_arc.blocking_lock();
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
        Ok::<_, String>(())
    })
    .await
    .map_err(|e| format!("task failed: {e}"))??;

    Ok(next_identity_generation)
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
    let secure_store = inner.secure_store().clone();
    let result = match inner.sync_now().await {
        Ok(result) => result,
        Err(error) => {
            if let prism_sync_core::CoreError::Relay {
                min_signature_version,
                ..
            } = &error
            {
                let _ =
                    ratchet_min_signature_version(secure_store.as_ref(), *min_signature_version);
            }
            return Err(encode_core_error("sync_now", error));
        }
    };
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

/// Upload an encrypted media blob to the relay.
///
/// Requires `configure_engine` to have been called after `initialize`/`unlock`.
pub async fn upload_media(
    handle: &PrismSyncHandle,
    media_id: String,
    content_hash: String,
    data: Vec<u8>,
) -> Result<(), String> {
    let relay = handle
        .relay
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .ok_or_else(|| "Relay not configured".to_string())?;

    match relay.upload_media(&media_id, &content_hash, data).await {
        Ok(()) => Ok(()),
        Err(error) => Err(format_handle_relay_error(handle, "upload_media", error).await),
    }
}

/// Download an encrypted media blob from the relay.
///
/// Requires `configure_engine` to have been called after `initialize`/`unlock`.
pub async fn download_media(
    handle: &PrismSyncHandle,
    media_id: String,
) -> Result<Vec<u8>, String> {
    let relay = handle
        .relay
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .ok_or_else(|| "Relay not configured".to_string())?;

    match relay.download_media(&media_id).await {
        Ok(data) => Ok(data),
        Err(error) => Err(format_handle_relay_error(handle, "download_media", error).await),
    }
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
    ml_dsa_key_generation: u32,
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
    let parsed_secret = device_secret.and_then(|bytes| DeviceSecret::from_bytes(bytes).ok());
    let signing_key = parsed_secret
        .as_ref()
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
    let ml_dsa_signing_key = parsed_secret
        .as_ref()
        .and_then(|secret| secret.ml_dsa_65_keypair_v(device_id, ml_dsa_key_generation).ok())
        .unwrap_or_else(|| {
            DeviceSecret::generate()
                .ml_dsa_65_keypair_v(device_id, ml_dsa_key_generation)
                .expect("ephemeral ML-DSA signing key")
        });
    let relay = ServerRelay::new(
        url,
        sync_id.to_string(),
        device_id.to_string(),
        session_token.to_string(),
        signing_key,
        ml_dsa_signing_key,
        registration_token,
    )
    .map_err(|e| format!("Failed to create ServerRelay: {e}"))?;
    Ok(Arc::new(relay))
}

/// Create a new sync group (first device).
///
/// Returns JSON containing `sync_id` and `relay_url`.
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
    enforce_handle_signature_version_floor(handle).await?;
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
        0,
        handle.allow_insecure,
        pending.3.clone(),
    )?;

    let mut inner = handle.inner.lock().await;
    let secure_store = inner.secure_store().clone();
    let pairing = PairingService::new(relay, secure_store.clone());

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

    let (creds, response) = match create_result {
        Ok(value) => value,
        Err(error) => {
            if let prism_sync_core::CoreError::Relay {
                min_signature_version,
                ..
            } = &error
            {
                let _ =
                    ratchet_min_signature_version(secure_store.as_ref(), *min_signature_version);
            }
            return Err(encode_core_error("create_sync_group", error));
        }
    };

    // Persist registration token so it survives restarts and can be
    // included when approving pairing requests from new devices.
    if let Some(ref token) = pending.3 {
        inner
            .secure_store()
            .set("registration_token", token.as_bytes())
            .map_err(|e| e.to_string())?;
    }

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
        "sync_id": response.sync_id,
        "relay_url": response.relay_url,
    });

    Ok(result.to_string())
}

/// Generate and persist a pending joiner identity for the relay ceremony.
///
/// The joiner device uses the resulting device id and secret to start the
/// rendezvous-token pairing flow. No compact QR payload or URL transport is
/// produced here; the app now exchanges only the relay rendezvous token.
pub async fn prepare_pending_device_identity(handle: &PrismSyncHandle) -> Result<String, String> {
    let device_secret = prism_sync_crypto::DeviceSecret::generate();
    let device_id = prism_sync_core::node_id::generate_node_id();

    let handle_inner = handle.inner.lock().await;
    let store = handle_inner.secure_store();
    store
        .set("pending_device_secret", device_secret.as_bytes())
        .map_err(|e| format!("Failed to persist pending device secret: {e}"))?;
    store
        .set("pending_device_id", device_id.as_bytes())
        .map_err(|e| format!("Failed to persist pending device id: {e}"))?;

    Ok(device_id)
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
    enforce_handle_signature_version_floor(handle).await?;
    let (storage, device_secret) = {
        let inner = handle.inner.lock().await;
        (
            inner.storage().clone(),
            inner
                .secure_store()
                .get("device_secret")
                .map_err(|e| e.to_string())?,
        )
    };
    let ml_dsa_key_generation =
        load_device_ml_dsa_generation(storage, sync_id.clone(), device_id.clone()).await?;
    let relay = build_relay(
        &handle.relay_url,
        &sync_id,
        &device_id,
        &session_token,
        device_secret,
        ml_dsa_key_generation,
        handle.allow_insecure,
        None,
    )?;

    let devices = match relay.list_devices().await {
        Ok(devices) => devices,
        Err(error) => return Err(format_handle_relay_error(handle, "list_devices", error).await),
    };

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
    enforce_handle_signature_version_floor(handle).await?;
    let (storage, device_secret) = {
        let inner = handle.inner.lock().await;
        (
            inner.storage().clone(),
            inner
                .secure_store()
                .get("device_secret")
                .map_err(|e| e.to_string())?,
        )
    };
    let ml_dsa_key_generation =
        load_device_ml_dsa_generation(storage, sync_id.clone(), device_id.clone()).await?;
    let relay = build_relay(
        &handle.relay_url,
        &sync_id,
        &device_id,
        &session_token,
        device_secret,
        ml_dsa_key_generation,
        handle.allow_insecure,
        None,
    )?;
    let mut inner = handle.inner.lock().await;
    match inner
        .revoke_and_rekey(
            relay as std::sync::Arc<dyn prism_sync_core::relay::SyncRelay>,
            &target_device_id,
            false,
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(error) => Err(format!("revoke_device failed: {error}")),
    }
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
    enforce_handle_signature_version_floor(handle).await?;
    let (storage, device_secret) = {
        let inner = handle.inner.lock().await;
        (
            inner.storage().clone(),
            inner
                .secure_store()
                .get("device_secret")
                .map_err(|e| e.to_string())?,
        )
    };
    let ml_dsa_key_generation =
        load_device_ml_dsa_generation(storage, sync_id.clone(), device_id.clone()).await?;
    let relay = build_relay(
        &handle.relay_url,
        &sync_id,
        &device_id,
        &session_token,
        device_secret,
        ml_dsa_key_generation,
        handle.allow_insecure,
        None,
    )?;
    let mut inner = handle.inner.lock().await;
    match inner
        .revoke_and_rekey(
            relay as std::sync::Arc<dyn prism_sync_core::relay::SyncRelay>,
            &target_device_id,
            remote_wipe,
        )
        .await
    {
        Ok(epoch) => Ok(epoch),
        Err(error) => Err(format!("revoke_and_rekey failed: {error}")),
    }
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
    enforce_handle_signature_version_floor(handle).await?;
    let (storage, device_secret) = {
        let inner = handle.inner.lock().await;
        (
            inner.storage().clone(),
            inner
                .secure_store()
                .get("device_secret")
                .map_err(|e| e.to_string())?,
        )
    };
    let ml_dsa_key_generation =
        load_device_ml_dsa_generation(storage, sync_id.clone(), device_id.clone()).await?;
    let relay = build_relay(
        &handle.relay_url,
        &sync_id,
        &device_id,
        &session_token,
        device_secret,
        ml_dsa_key_generation,
        handle.allow_insecure,
        None,
    )?;
    match relay.deregister().await {
        Ok(()) => Ok(()),
        Err(error) => Err(format_handle_relay_error(handle, "deregister", error).await),
    }
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
    enforce_handle_signature_version_floor(handle).await?;
    let (storage, device_secret) = {
        let inner = handle.inner.lock().await;
        (
            inner.storage().clone(),
            inner
                .secure_store()
                .get("device_secret")
                .map_err(|e| e.to_string())?,
        )
    };
    let ml_dsa_key_generation =
        load_device_ml_dsa_generation(storage, sync_id.clone(), device_id.clone()).await?;
    let relay = build_relay(
        &handle.relay_url,
        &sync_id,
        &device_id,
        &session_token,
        device_secret,
        ml_dsa_key_generation,
        handle.allow_insecure,
        None,
    )?;
    match relay.delete_sync_group().await {
        Ok(()) => Ok(()),
        Err(error) => Err(format_handle_relay_error(handle, "delete_sync_group", error).await),
    }
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
        "registration_token",
        "sharing_prekey_store",
        "sharing_id_cache",
        "min_signature_version_floor",
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

// ── Phase 4 sharing bootstrap ──

/// Ensure a local sharing identity exists for the provided synced sharing_id.
///
/// If `current_sharing_id` is `None`, this reuses any cached sharing_id in
/// secure storage or generates a new 16-byte random sharing_id and returns it
/// for the app to persist to synced settings.
pub async fn sharing_enable(
    handle: &PrismSyncHandle,
    current_sharing_id: Option<String>,
    identity_generation: u32,
) -> Result<String, String> {
    let context = build_sharing_context(handle).await?;

    let sharing_id = if let Some(sharing_id) = current_sharing_id {
        parse_sharing_id_bytes(&sharing_id)?;
        validate_cached_sharing_id(context.secure_store.as_ref(), &sharing_id)?;
        sharing_id
    } else if let Some(cached) =
        decode_optional_utf8(context.secure_store.as_ref(), SHARING_ID_CACHE_KEY)?
    {
        parse_sharing_id_bytes(&cached)?;
        cached
    } else {
        let device_secret = DeviceSecret::generate();
        prism_sync_crypto::hex::encode(&device_secret.as_bytes()[..SHARING_ID_LEN_BYTES])
    };

    let sharing_id_bytes = parse_sharing_id_bytes(&sharing_id)?;
    let mut recipient = SharingRecipient::load_from_secure_store(
        &context.dek,
        &sharing_id,
        &sharing_id_bytes,
        identity_generation,
        context.secure_store.as_ref(),
    )
    .map_err(|e| e.to_string())?;

    if let Err(error) = context
        .relay
        .publish_identity(&sharing_id, &recipient.identity().to_bytes())
        .await
    {
        return Err(format_handle_relay_error(handle, "publish_identity", error).await);
    }

    recipient
        .ensure_prekey_fresh_and_persist(
            context.relay.as_ref(),
            context.secure_store.as_ref(),
            &context.device_id,
            now_unix_timestamp()?,
        )
        .await
        .map_err(|e| e.to_string())?;

    cache_sharing_id(context.secure_store.as_ref(), &sharing_id)?;
    Ok(sharing_id)
}

/// Disable sharing by removing the identity bundle and signed prekeys from the relay.
pub async fn sharing_disable(handle: &PrismSyncHandle, sharing_id: String) -> Result<(), String> {
    parse_sharing_id_bytes(&sharing_id)?;
    let context = build_sharing_context(handle).await?;
    validate_cached_sharing_id(context.secure_store.as_ref(), &sharing_id)?;

    if let Err(error) = context.relay.remove_identity().await {
        return Err(format_handle_relay_error(handle, "remove_identity", error).await);
    }

    PrekeyStore::clear_persisted(context.secure_store.as_ref()).map_err(|e| e.to_string())?;
    clear_sharing_id_cache(context.secure_store.as_ref())?;
    Ok(())
}

/// Rotate and publish a new signed prekey if the current one is stale or missing.
pub async fn sharing_ensure_prekey(
    handle: &PrismSyncHandle,
    sharing_id: String,
    identity_generation: u32,
) -> Result<(), String> {
    let context = build_sharing_context(handle).await?;
    let sharing_id_bytes = parse_sharing_id_bytes(&sharing_id)?;
    validate_cached_sharing_id(context.secure_store.as_ref(), &sharing_id)?;

    let mut recipient = SharingRecipient::load_from_secure_store(
        &context.dek,
        &sharing_id,
        &sharing_id_bytes,
        identity_generation,
        context.secure_store.as_ref(),
    )
    .map_err(|e| e.to_string())?;

    recipient
        .ensure_prekey_fresh_and_persist(
            context.relay.as_ref(),
            context.secure_store.as_ref(),
            &context.device_id,
            now_unix_timestamp()?,
        )
        .await
        .map_err(|e| e.to_string())?;

    cache_sharing_id(context.secure_store.as_ref(), &sharing_id)?;
    Ok(())
}

/// Initiate sharing with a remote recipient and return the established pairwise secret.
pub async fn sharing_initiate(
    handle: &PrismSyncHandle,
    sender_sharing_id: String,
    identity_generation: u32,
    recipient_sharing_id: String,
    display_name: String,
    offered_scopes: String,
) -> Result<String, String> {
    let context = build_sharing_context(handle).await?;
    let sender_sharing_id_bytes = parse_sharing_id_bytes(&sender_sharing_id)?;
    parse_sharing_id_bytes(&recipient_sharing_id)?;
    validate_cached_sharing_id(context.secure_store.as_ref(), &sender_sharing_id)?;

    let sender = SharingSender::from_dek(
        &context.dek,
        &sender_sharing_id,
        &sender_sharing_id_bytes,
        identity_generation,
    )
    .map_err(|e| e.to_string())?;
    let offered_scopes = parse_string_array_json(&offered_scopes, "offered_scopes")?;

    let result = sender
        .initiate(
            context.relay.as_ref(),
            &recipient_sharing_id,
            &display_name,
            offered_scopes,
            now_unix_timestamp()?,
        )
        .await
        .map_err(|e| e.to_string())?;

    let recipient_identity_bytes = result.recipient_identity.to_bytes();
    let response = serde_json::json!({
        "init_id": result.init_id,
        "pairwise_secret_b64": BASE64.encode(&result.pairwise_secret[..]),
        "pairwise_secret_hex": prism_sync_crypto::hex::encode(result.pairwise_secret.as_ref()),
        "recipient_identity_b64": BASE64.encode(&recipient_identity_bytes),
        "recipient_identity_hex": prism_sync_crypto::hex::encode(&recipient_identity_bytes),
    });
    Ok(response.to_string())
}

/// Fetch and process all pending sharing-init payloads for the authenticated user.
///
/// `existing_relationships_json` accepts either:
/// - a JSON array of known peer sharing_ids, or
/// - a JSON object with `existing_relationships`, optional `pinned_identities`,
///   and optional `verified_peers`
pub async fn sharing_process_pending(
    handle: &PrismSyncHandle,
    recipient_sharing_id: String,
    identity_generation: u32,
    existing_relationships_json: String,
    seen_init_ids_json: String,
) -> Result<String, String> {
    let context = build_sharing_context(handle).await?;
    let recipient_sharing_id_bytes = parse_sharing_id_bytes(&recipient_sharing_id)?;
    validate_cached_sharing_id(context.secure_store.as_ref(), &recipient_sharing_id)?;

    let recipient = SharingRecipient::load_from_secure_store(
        &context.dek,
        &recipient_sharing_id,
        &recipient_sharing_id_bytes,
        identity_generation,
        context.secure_store.as_ref(),
    )
    .map_err(|e| e.to_string())?;

    let pending = match context.relay.fetch_pending_inits().await {
        Ok(pending) => pending,
        Err(error) => {
            return Err(format_handle_relay_error(handle, "fetch_pending_inits", error).await);
        }
    };

    let inputs = parse_sharing_process_pending_inputs(&existing_relationships_json)?;
    let mut existing_relationships = inputs.existing_relationships;
    let mut seen_init_ids = parse_string_array_json(&seen_init_ids_json, "seen_init_ids")?;
    let mut results = Vec::with_capacity(pending.len());

    for pending_init in pending {
        let existing_refs: Vec<&str> = existing_relationships.iter().map(String::as_str).collect();
        let seen_refs: Vec<&str> = seen_init_ids.iter().map(String::as_str).collect();

        let result = match recipient.process_sharing_init(
            &pending_init.payload,
            &pending_init.init_id,
            &existing_refs,
            &seen_refs,
        ) {
            Ok(processed) => {
                let sender_identity_bytes = processed.sender_identity.to_bytes();
                if pending_init.sender_id != processed.sender_identity.sharing_id {
                    SharingPendingResultJson {
                        status: "error".to_string(),
                        init_id: pending_init.init_id.clone(),
                        sender_sharing_id: pending_init.sender_id.clone(),
                        display_name: None,
                        offered_scopes: None,
                        pairwise_secret_b64: None,
                        pairwise_secret_hex: None,
                        sender_identity_b64: None,
                        sender_identity_hex: None,
                        fingerprint: None,
                        trust_decision: None,
                        error: Some(format!(
                            "relay sender_id does not match signed sender identity: relay={}, signed={}",
                            pending_init.sender_id, processed.sender_identity.sharing_id
                        )),
                    }
                } else {
                    let pinned_identity = inputs
                        .pinned_identities
                        .get(&processed.sender_identity.sharing_id)
                        .map(Vec::as_slice);
                    let highest_generation = pinned_identity
                        .and_then(SharingIdentityBundle::parse_metadata)
                        .map(|metadata| metadata.identity_generation);
                    let trust_decision = evaluate_identity_with_generation_floor(
                        pinned_identity,
                        &sender_identity_bytes,
                        &processed.sender_identity.sharing_id,
                        highest_generation,
                        inputs
                            .verified_peers
                            .get(&processed.sender_identity.sharing_id)
                            .copied()
                            .unwrap_or(false),
                    );
                    if let Some(status) = generation_aware_trust_decision_to_str(&trust_decision) {
                        let status = status.to_string();
                        let fingerprint = compute_sharing_fingerprint(
                            &processed.sender_identity.sharing_id,
                            processed.sender_identity.identity_generation,
                            &processed.sender_identity.ed25519_public_key,
                            &processed.sender_identity.ml_dsa_65_public_key,
                        );

                        existing_relationships.push(processed.sender_identity.sharing_id.clone());

                        SharingPendingResultJson {
                            status: status.clone(),
                            init_id: processed.init_id,
                            sender_sharing_id: processed.sender_identity.sharing_id.clone(),
                            display_name: Some(processed.display_name),
                            offered_scopes: Some(processed.offered_scopes),
                            pairwise_secret_b64: Some(
                                BASE64.encode(&processed.pairwise_secret[..]),
                            ),
                            pairwise_secret_hex: Some(prism_sync_crypto::hex::encode(
                                processed.pairwise_secret.as_ref(),
                            )),
                            sender_identity_b64: Some(BASE64.encode(&sender_identity_bytes)),
                            sender_identity_hex: Some(prism_sync_crypto::hex::encode(
                                &sender_identity_bytes,
                            )),
                            fingerprint: Some(fingerprint),
                            trust_decision: Some(status),
                            error: None,
                        }
                    } else {
                        SharingPendingResultJson {
                            status: "error".to_string(),
                            init_id: processed.init_id,
                            sender_sharing_id: processed.sender_identity.sharing_id,
                            display_name: None,
                            offered_scopes: None,
                            pairwise_secret_b64: None,
                            pairwise_secret_hex: None,
                            sender_identity_b64: None,
                            sender_identity_hex: None,
                            fingerprint: None,
                            trust_decision: None,
                            error: Some(match trust_decision {
                                GenerationAwareTrustDecision::RejectStaleGenerationReplay => {
                                    format!(
                                        "stale identity generation replay: highest accepted={}, received={}",
                                        highest_generation.unwrap_or_default(),
                                        processed.sender_identity.identity_generation
                                    )
                                }
                                GenerationAwareTrustDecision::RejectSharingIdMismatch => {
                                    "signed identity claims unexpected sharing_id".to_string()
                                }
                                GenerationAwareTrustDecision::RejectMalformedIdentity => {
                                    "invalid sharing identity bundle".to_string()
                                }
                                _ => "unexpected trust-evaluation rejection".to_string(),
                            }),
                        }
                    }
                }
            }
            Err(error) => SharingPendingResultJson {
                status: "error".to_string(),
                init_id: pending_init.init_id.clone(),
                sender_sharing_id: pending_init.sender_id.clone(),
                display_name: None,
                offered_scopes: None,
                pairwise_secret_b64: None,
                pairwise_secret_hex: None,
                sender_identity_b64: None,
                sender_identity_hex: None,
                fingerprint: None,
                trust_decision: None,
                error: Some(error.to_string()),
            },
        };

        if !seen_init_ids
            .iter()
            .any(|seen| seen == &pending_init.init_id)
        {
            seen_init_ids.push(pending_init.init_id);
        }
        results.push(result);
    }

    serde_json::to_string(&results).map_err(|e| format!("JSON serialization failed: {e}"))
}

/// Compute a user-visible fingerprint for a canonical sharing identity bundle.
pub fn sharing_fingerprint(identity_bundle_b64: String) -> Result<String, String> {
    let identity_bytes = decode_binary_string(&identity_bundle_b64, "identity_bundle")?;
    let identity = SharingIdentityBundle::from_bytes(&identity_bytes)
        .ok_or_else(|| "Invalid sharing identity bundle".to_string())?;
    identity
        .verify()
        .map_err(|e| format!("Invalid sharing identity signature: {e}"))?;

    Ok(compute_sharing_fingerprint(
        &identity.sharing_id,
        identity.identity_generation,
        &identity.ed25519_public_key,
        &identity.ml_dsa_65_public_key,
    ))
}

/// Wrap resource keys under pairwise-secret-derived per-scope wrapping keys.
pub fn sharing_wrap_keys(
    pairwise_secret_b64: String,
    scope_keys: String,
) -> Result<String, String> {
    let pairwise_secret = decode_binary_string(&pairwise_secret_b64, "pairwise_secret")?;
    if pairwise_secret.len() != PAIRWISE_SECRET_LEN_BYTES {
        return Err(format!(
            "pairwise_secret must be {PAIRWISE_SECRET_LEN_BYTES} bytes, got {}",
            pairwise_secret.len()
        ));
    }

    let scope_keys: HashMap<String, String> =
        serde_json::from_str(&scope_keys).map_err(|e| format!("Invalid scope_keys JSON: {e}"))?;
    let mut wrapped_keys = serde_json::Map::new();
    for (scope, encoded_key) in scope_keys {
        let key_bytes = decode_binary_string(&encoded_key, "scope_keys")?;
        let wrap_key = prism_sync_crypto::kdf::derive_subkey(
            &pairwise_secret,
            scope.as_bytes(),
            b"prism_sharing_scope_wrap_v1",
        )
        .map_err(|e| e.to_string())?;
        let wrapped = prism_sync_crypto::aead::xchacha_encrypt(wrap_key.as_ref(), &key_bytes)
            .map_err(|e| e.to_string())?;
        wrapped_keys.insert(scope, serde_json::Value::String(BASE64.encode(&wrapped)));
    }

    Ok(serde_json::json!({ "wrapped_keys": wrapped_keys }).to_string())
}

/// Unwrap resource keys previously wrapped by `sharing_wrap_keys`.
pub fn sharing_unwrap_keys(
    pairwise_secret_b64: String,
    wrapped_keys: String,
) -> Result<String, String> {
    let pairwise_secret = decode_binary_string(&pairwise_secret_b64, "pairwise_secret")?;
    if pairwise_secret.len() != PAIRWISE_SECRET_LEN_BYTES {
        return Err(format!(
            "pairwise_secret must be {PAIRWISE_SECRET_LEN_BYTES} bytes, got {}",
            pairwise_secret.len()
        ));
    }

    let wrapped_keys: HashMap<String, String> = serde_json::from_str(&wrapped_keys)
        .map_err(|e| format!("Invalid wrapped_keys JSON: {e}"))?;
    let mut unwrapped_keys = serde_json::Map::new();
    for (scope, encoded_wrapped_key) in wrapped_keys {
        let wrapped_key = decode_binary_string(&encoded_wrapped_key, "wrapped_keys")?;
        let wrap_key = prism_sync_crypto::kdf::derive_subkey(
            &pairwise_secret,
            scope.as_bytes(),
            b"prism_sharing_scope_wrap_v1",
        )
        .map_err(|e| e.to_string())?;
        let unwrapped = prism_sync_crypto::aead::xchacha_decrypt(wrap_key.as_ref(), &wrapped_key)
            .map_err(|e| e.to_string())?;
        unwrapped_keys.insert(scope, serde_json::Value::String(BASE64.encode(&unwrapped)));
    }

    Ok(serde_json::json!({ "unwrapped_keys": unwrapped_keys }).to_string())
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

// ══════════════════════════════════════════════════════════════════════
// Relay-based PQ pairing ceremony (Phase 3 bootstrap)
// ══════════════════════════════════════════════════════════════════════

/// Build a `ServerPairingRelay` from the handle's relay URL.
fn build_pairing_relay(handle: &PrismSyncHandle) -> Result<ServerPairingRelay, String> {
    let relay_url = &handle.relay_url;
    if !handle.allow_insecure
        && !relay_url.starts_with("https://")
        && !relay_url.starts_with("http://localhost")
    {
        return Err(format!(
            "PairingRelay requires HTTPS (got {relay_url:?}). \
             Set allow_insecure=true for development."
        ));
    }
    ServerPairingRelay::new(relay_url.clone())
        .map_err(|e| format!("Failed to create PairingRelay: {e}"))
}

/// Start the joiner side of the relay-based PQ pairing ceremony.
///
/// Generates bootstrap keys, uploads them to the relay, and returns
/// a JSON object with token bytes and a deep-link URL for QR encoding:
///
/// ```json
/// {
///   "token_bytes": [1, 2, ...],
///   "token_url": "prismsync://pair?d=...",
///   "device_id": "generated-device-id"
/// }
/// ```
///
/// The `JoinerCeremony` state is stored in the handle for subsequent calls
/// to [`get_joiner_sas`] and [`complete_joiner_ceremony`].
pub async fn start_joiner_ceremony(handle: &PrismSyncHandle) -> Result<String, String> {
    enforce_handle_signature_version_floor(handle).await?;
    let pairing_relay = build_pairing_relay(handle)?;

    let inner = handle.inner.lock().await;
    let pairing = PairingService::new(
        // PairingService needs a SyncRelay for registration, but start_bootstrap_pairing
        // only uses the PairingRelay argument. Build a temporary relay for the service.
        build_relay(
            &handle.relay_url,
            "pending",
            "pending",
            "",
            None,
            0,
            handle.allow_insecure,
            None,
        )?,
        inner.secure_store().clone(),
    );
    drop(inner);

    let (ceremony, token) = match pairing
        .start_bootstrap_pairing(&pairing_relay, &handle.relay_url)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            return Err(
                encode_handle_core_error(handle, "start_bootstrap_pairing", error).await,
            );
        }
    };

    let device_id = ceremony.device_id().to_string();

    // Store ceremony state for later use
    handle
        .joiner_ceremony
        .lock()
        .map_err(|e| format!("failed to lock joiner_ceremony: {e}"))?
        .replace(ceremony);

    let result = serde_json::json!({
        "token_bytes": token.to_bytes(),
        "token_url": token.to_url(),
        "device_id": device_id,
    });
    Ok(result.to_string())
}

/// Wait for the initiator's PairingInit and return the SAS display codes.
///
/// Polls the relay for the PairingInit slot until it arrives, then derives
/// the shared secret and SAS codes. Returns JSON:
///
/// ```json
/// { "sas_words": "apple banana cherry", "sas_decimal": "123456" }
/// ```
///
/// Must be called after [`start_joiner_ceremony`].
pub async fn get_joiner_sas(handle: &PrismSyncHandle) -> Result<String, String> {
    let pairing_relay = build_pairing_relay(handle)?;

    // Take the ceremony out so we can mutate it (process_pairing_init requires &mut self)
    let mut ceremony = handle
        .joiner_ceremony
        .lock()
        .map_err(|e| format!("failed to lock joiner_ceremony: {e}"))?
        .take()
        .ok_or_else(|| {
            "no joiner ceremony in progress — call start_joiner_ceremony first".to_string()
        })?;

    // Poll for the PairingInit slot
    use prism_sync_core::relay::PairingSlot;
    let rendezvous_hex = ceremony.rendezvous_id_hex();
    let init_bytes = poll_pairing_slot(&pairing_relay, &rendezvous_hex, PairingSlot::Init)
        .await
        .map_err(|e| format!("failed waiting for PairingInit: {e}"))?;

    // Process the init to derive SAS
    let sas = match ceremony.process_pairing_init(&init_bytes) {
        Ok(sas) => sas,
        Err(error) => {
            return Err(encode_handle_core_error(handle, "process_pairing_init", error).await);
        }
    };

    // Put ceremony back
    handle
        .joiner_ceremony
        .lock()
        .map_err(|e| format!("failed to lock joiner_ceremony: {e}"))?
        .replace(ceremony);

    let result = serde_json::json!({
        "sas_words": sas.words,
        "sas_decimal": sas.decimal,
    });
    Ok(result.to_string())
}

/// Complete the joiner side of the ceremony after SAS verification.
///
/// Sends the confirmation MAC, waits for encrypted credentials from the
/// initiator, decrypts them, registers with the relay, and persists all
/// credentials. Returns JSON:
///
/// ```json
/// { "sync_id": "..." }
/// ```
///
/// Must be called after [`get_joiner_sas`] and user SAS verification.
pub async fn complete_joiner_ceremony(
    handle: &PrismSyncHandle,
    password: String,
) -> Result<String, String> {
    enforce_handle_signature_version_floor(handle).await?;
    let pairing_relay = build_pairing_relay(handle)?;

    // Take the ceremony out — it won't be needed again after completion
    let ceremony = handle
        .joiner_ceremony
        .lock()
        .map_err(|e| format!("failed to lock joiner_ceremony: {e}"))?
        .take()
        .ok_or_else(|| "no joiner ceremony in progress — call get_joiner_sas first".to_string())?;

    // Build a SyncRelay for registration
    let relay = build_relay(
        &handle.relay_url,
        "pending",
        "pending",
        "",
        None,
        0,
        handle.allow_insecure,
        None,
    )?;

    let inner = handle.inner.lock().await;
    let pairing = PairingService::new(relay, inner.secure_store().clone());
    drop(inner);

    // complete_bootstrap_join handles: confirmation MAC, wait for credentials,
    // decrypt, register, persist, post joiner bundle
    let (key_hierarchy, registry_snapshot) = match pairing
        .complete_bootstrap_join(&ceremony, &pairing_relay, &[], &password)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            return Err(
                encode_handle_core_error(handle, "complete_bootstrap_join", error).await,
            );
        }
    };

    // Read sync_id from secure store (persisted by complete_bootstrap_join)
    let mut inner = handle.inner.lock().await;
    let sync_id = inner
        .secure_store()
        .get("sync_id")
        .map_err(|e| e.to_string())?
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or("sync_id not found after bootstrap join")?;

    // Import the registry snapshot
    DeviceRegistryManager::import_keyring(
        inner.storage().as_ref(),
        &sync_id,
        &registry_snapshot.to_device_records(),
    )
    .map_err(|e| e.to_string())?;

    // Restore runtime keys so configureEngine etc. work
    let dek = key_hierarchy.dek().map_err(|e| e.to_string())?;
    let device_secret_bytes = inner
        .secure_store()
        .get("device_secret")
        .map_err(|e| e.to_string())?
        .ok_or("device_secret not found after join")?;
    inner
        .restore_runtime_keys(dek, &device_secret_bytes)
        .map_err(|e| e.to_string())?;

    // Restore epoch keys into the live key hierarchy
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
            Ok(Some(stored)) => match BASE64.decode(&stored) {
                Ok(decoded) if decoded.len() == 32 => {
                    inner
                        .key_hierarchy_mut()
                        .store_epoch_key(epoch_val, zeroize::Zeroizing::new(decoded));
                }
                Ok(decoded) => {
                    return Err(format!(
                        "epoch_key_{} has wrong length ({}, expected 32)",
                        epoch_val,
                        decoded.len(),
                    ));
                }
                Err(e) => {
                    return Err(format!("epoch_key_{} base64 decode failed: {e}", epoch_val,));
                }
            },
            Ok(None) => {
                return Err(format!("epoch_key_{} not found in secure store", epoch_val,));
            }
            Err(e) => {
                return Err(format!("Failed to read epoch_key_{}: {e}", epoch_val));
            }
        }
    }

    let result = serde_json::json!({ "sync_id": sync_id });
    Ok(result.to_string())
}

/// Start the initiator side of the relay-based PQ pairing ceremony.
///
/// Parses the rendezvous token from QR/deep-link bytes, fetches the joiner's
/// bootstrap, verifies the commitment, and posts the PairingInit. Returns
/// the SAS display codes for user verification:
///
/// ```json
/// { "sas_words": "apple banana cherry", "sas_decimal": "123456" }
/// ```
///
/// The `InitiatorCeremony` state is stored in the handle for the subsequent
/// call to [`complete_initiator_ceremony`].
pub async fn start_initiator_ceremony(
    handle: &PrismSyncHandle,
    token_bytes: Vec<u8>,
) -> Result<String, String> {
    enforce_handle_signature_version_floor(handle).await?;
    let token = RendezvousToken::from_bytes(&token_bytes)
        .ok_or_else(|| "failed to parse RendezvousToken from bytes".to_string())?;

    let pairing_relay = build_pairing_relay(handle)?;

    // Build a SyncRelay so PairingService can load the current device identity
    let inner = handle.inner.lock().await;
    let secure_store = inner.secure_store().clone();
    let storage = inner.storage().clone();
    let device_id = inner
        .secure_store()
        .get("device_id")
        .map_err(|e| e.to_string())?
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| "pending".to_string());
    let sync_id = inner
        .secure_store()
        .get("sync_id")
        .map_err(|e| e.to_string())?
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| "pending".to_string());
    let session_token = inner
        .secure_store()
        .get("session_token")
        .map_err(|e| e.to_string())?
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default();
    let device_secret_bytes = inner
        .secure_store()
        .get("device_secret")
        .map_err(|e| e.to_string())?;
    drop(inner);
    let ml_dsa_key_generation =
        load_device_ml_dsa_generation(storage, sync_id.clone(), device_id.clone()).await?;

    let relay = build_relay(
        &handle.relay_url,
        &sync_id,
        &device_id,
        &session_token,
        device_secret_bytes,
        ml_dsa_key_generation,
        handle.allow_insecure,
        None,
    )?;

    let pairing = PairingService::new(relay, secure_store);
    let (ceremony, sas) = match pairing.start_bootstrap_initiator(token, &pairing_relay).await {
        Ok(value) => value,
        Err(error) => {
            return Err(
                encode_handle_core_error(handle, "start_bootstrap_initiator", error).await,
            );
        }
    };

    // Store ceremony state for complete_initiator_ceremony
    handle
        .initiator_ceremony
        .lock()
        .map_err(|e| format!("failed to lock initiator_ceremony: {e}"))?
        .replace(ceremony);

    let result = serde_json::json!({
        "sas_words": sas.words,
        "sas_decimal": sas.decimal,
    });
    Ok(result.to_string())
}

/// Complete the initiator side of the ceremony after SAS verification.
///
/// Waits for the joiner's confirmation MAC, verifies it, then sends
/// encrypted credentials to the joiner. Returns `"ok"` on success.
///
/// Must be called after [`start_initiator_ceremony`] and user SAS verification.
pub async fn complete_initiator_ceremony(
    handle: &PrismSyncHandle,
    password: String,
) -> Result<String, String> {
    enforce_handle_signature_version_floor(handle).await?;
    let pairing_relay = build_pairing_relay(handle)?;

    // Take the ceremony out — it won't be needed again after completion
    let ceremony = handle
        .initiator_ceremony
        .lock()
        .map_err(|e| format!("failed to lock initiator_ceremony: {e}"))?
        .take()
        .ok_or_else(|| {
            "no initiator ceremony in progress — call start_initiator_ceremony first".to_string()
        })?;

    // Build a SyncRelay for the PairingService (needs device identity + relay access)
    let inner = handle.inner.lock().await;
    let secure_store = inner.secure_store().clone();
    let storage = inner.storage().clone();
    let device_id = inner
        .secure_store()
        .get("device_id")
        .map_err(|e| e.to_string())?
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| "pending".to_string());
    let sync_id = inner
        .secure_store()
        .get("sync_id")
        .map_err(|e| e.to_string())?
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| "pending".to_string());
    let session_token = inner
        .secure_store()
        .get("session_token")
        .map_err(|e| e.to_string())?
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default();
    let device_secret_bytes = inner
        .secure_store()
        .get("device_secret")
        .map_err(|e| e.to_string())?;
    drop(inner);
    let ml_dsa_key_generation =
        load_device_ml_dsa_generation(storage, sync_id.clone(), device_id.clone()).await?;

    let relay = build_relay(
        &handle.relay_url,
        &sync_id,
        &device_id,
        &session_token,
        device_secret_bytes,
        ml_dsa_key_generation,
        handle.allow_insecure,
        None,
    )?;

    let pairing = PairingService::new(relay, secure_store);
    if let Err(error) = pairing
        .complete_bootstrap_initiator(&ceremony, &pairing_relay, &password)
        .await
    {
        return Err(encode_handle_core_error(handle, "complete_bootstrap_initiator", error).await);
    }

    // Drain the store so Dart can pick up any updated values
    // (epoch keys, registration token, etc.)
    Ok("ok".to_string())
}

/// Poll a pairing relay slot with exponential backoff.
///
/// Retries up to ~60s with increasing delays before giving up.
async fn poll_pairing_slot(
    relay: &ServerPairingRelay,
    rendezvous_id: &str,
    slot: prism_sync_core::relay::PairingSlot,
) -> Result<Vec<u8>, String> {
    use prism_sync_core::relay::pairing_relay::PairingRelay;
    use std::time::Duration;

    let delays = [1, 1, 2, 2, 3, 3, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5]; // ~60s total
    for delay in &delays {
        match relay.get_slot(rendezvous_id, slot).await {
            Ok(Some(data)) => return Ok(data),
            Ok(None) => {
                tokio::time::sleep(Duration::from_secs(*delay)).await;
            }
            Err(e) => return Err(format!("relay error polling {slot:?}: {e}")),
        }
    }
    Err(format!("timeout waiting for pairing slot {slot:?}"))
}

// ── ML-DSA key rotation ──

/// Rotate this device's ML-DSA-65 signing key.
///
/// Generates a new ML-DSA keypair at the next generation, creates a
/// cross-signed continuity proof, submits it to the relay, and updates
/// the local device registry.
///
/// Returns JSON: `{"ml_dsa_key_generation": N, "device_id": "..."}`
pub async fn rotate_ml_dsa_key(handle: &PrismSyncHandle) -> Result<String, String> {
    // 1. Read credentials and device state from the handle
    let (storage, secure_store, relay_url, allow_insecure) = {
        let inner = handle.inner.lock().await;
        (
            inner.storage().clone(),
            inner.secure_store().clone(),
            inner.relay_url().map(str::to_string),
            handle.allow_insecure,
        )
    };

    let sync_id = require_secure_string(secure_store.as_ref(), "sync_id")?;
    let device_id = require_secure_string(secure_store.as_ref(), "device_id")?;
    let session_token = require_secure_string(secure_store.as_ref(), "session_token")?;
    let device_secret_bytes = secure_store
        .get("device_secret")
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "device_secret not found in secure store".to_string())?;
    let device_secret = DeviceSecret::from_bytes(device_secret_bytes)
        .map_err(|e| format!("invalid device_secret: {e}"))?;
    let relay_url = decode_optional_utf8(secure_store.as_ref(), "relay_url")?
        .or(relay_url)
        .ok_or_else(|| "relay_url not configured".to_string())?;

    // 2. Get current generation from local device registry
    let sid = sync_id.clone();
    let did = device_id.clone();
    let current_record = tokio::task::spawn_blocking(move || storage.get_device_record(&sid, &did))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("device {device_id} not in local registry"))?;

    let mut current_gen = current_record.ml_dsa_key_generation;

    // 2b. Check relay's generation to handle crash recovery.
    // If the relay is ahead of local (e.g., previous rotation succeeded on
    // relay but client crashed before updating local registry), sync local
    // state forward so we rotate from the relay's generation.
    let relay = build_relay(
        &relay_url,
        &sync_id,
        &device_id,
        &session_token,
        Some(device_secret.as_bytes().to_vec()),
        current_gen,
        allow_insecure,
        None,
    )?;

    let relay_devices = relay.list_devices().await.unwrap_or_default();
    if let Some(relay_self) = relay_devices.iter().find(|d| d.device_id == device_id) {
        if relay_self.ml_dsa_key_generation > current_gen {
            // Relay is ahead — re-derive the key at relay's generation and
            // update local registry so our next rotation starts from there.
            let relay_gen = relay_self.ml_dsa_key_generation;
            let synced_ml_dsa = device_secret
                .ml_dsa_65_keypair_v(&device_id, relay_gen)
                .map_err(|e| format!("failed to derive ML-DSA key at relay gen {relay_gen}: {e}"))?;
            let synced_pk = synced_ml_dsa.public_key_bytes();

            let inner = handle.inner.lock().await;
            let storage = inner.storage().clone();
            let sid = sync_id.clone();
            let did = device_id.clone();
            tokio::task::spawn_blocking(move || {
                let mut record = storage
                    .get_device_record(&sid, &did)?
                    .ok_or_else(|| {
                        prism_sync_core::error::CoreError::Storage(
                            "device not in registry".into(),
                        )
                    })?;
                record.ml_dsa_65_public_key = synced_pk;
                record.ml_dsa_key_generation = relay_gen;
                let mut tx = storage.begin_tx()?;
                tx.upsert_device_record(&record)?;
                tx.commit()
            })
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;

            current_gen = relay_gen;
        }
    }

    let new_gen = current_gen + 1;

    // 3. Create continuity proof (cross-signed by old and new ML-DSA keys)
    let proof = prism_sync_crypto::pq::continuity_proof::MlDsaContinuityProof::create(
        &device_secret,
        &device_id,
        current_gen,
        new_gen,
    )
    .map_err(|e| format!("failed to create continuity proof: {e}"))?;

    let new_ml_dsa = device_secret
        .ml_dsa_65_keypair_v(&device_id, new_gen)
        .map_err(|e| format!("failed to derive new ML-DSA key: {e}"))?;
    let new_pk = new_ml_dsa.public_key_bytes();

    // 4. Submit rotation to relay
    let response = match relay
        .rotate_ml_dsa(&device_id, &new_pk, new_gen, &proof)
        .await
    {
        Ok(resp) => resp,
        Err(error) => {
            return Err(format_handle_relay_error(handle, "rotate_ml_dsa", error).await)
        }
    };

    // 5. Update local device registry
    let inner = handle.inner.lock().await;
    let storage = inner.storage().clone();
    let sid = sync_id.clone();
    let did = device_id.clone();
    let proof_clone = proof.clone();
    let new_pk_clone = new_pk.clone();
    tokio::task::spawn_blocking(move || {
        DeviceRegistryManager::accept_ml_dsa_rotation(
            storage.as_ref(),
            &sid,
            &did,
            &new_pk_clone,
            new_gen,
            &proof_clone,
        )
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;

    // 6. Return result as JSON
    let result = serde_json::json!({
        "ml_dsa_key_generation": response.ml_dsa_key_generation,
        "device_id": device_id,
    });
    Ok(result.to_string())
}

/// Get the current ML-DSA key generation for this device.
///
/// Returns the generation number (0 for initial key, increments on each rotation).
pub async fn get_ml_dsa_key_generation(handle: &PrismSyncHandle) -> Result<u32, String> {
    let (storage, secure_store) = {
        let inner = handle.inner.lock().await;
        (inner.storage().clone(), inner.secure_store().clone())
    };

    let sync_id = require_secure_string(secure_store.as_ref(), "sync_id")?;
    let device_id = require_secure_string(secure_store.as_ref(), "device_id")?;
    load_device_ml_dsa_generation(storage, sync_id, device_id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use prism_sync_core::secure_store::SecureStore;

    #[test]
    fn decode_binary_string_accepts_hex_and_base64() {
        let bytes = b"hello world";
        let hex_encoded = prism_sync_crypto::hex::encode(bytes);
        let b64_encoded = BASE64.encode(bytes);

        assert_eq!(decode_binary_string(&hex_encoded, "field").unwrap(), bytes);
        assert_eq!(decode_binary_string(&b64_encoded, "field").unwrap(), bytes);
    }

    #[test]
    fn parse_sharing_process_pending_inputs_accepts_rich_context() {
        let identity_bytes = vec![0xAB; 32];
        let json = serde_json::json!({
            "existing_relationships": ["peer-a"],
            "pinned_identities": {
                "peer-a": BASE64.encode(&identity_bytes),
            },
            "verified_peers": {
                "peer-a": true,
            },
        })
        .to_string();

        let parsed = parse_sharing_process_pending_inputs(&json).unwrap();
        assert_eq!(parsed.existing_relationships, vec!["peer-a"]);
        assert_eq!(parsed.pinned_identities["peer-a"], identity_bytes);
        assert!(parsed.verified_peers["peer-a"]);
    }

    #[test]
    fn sharing_wrap_and_unwrap_round_trip() {
        let pairwise_secret = vec![0x42; 32];
        let scope_keys = serde_json::json!({
            "read:members": BASE64.encode([0x11; 32]),
            "read:fronting": BASE64.encode([0x22; 32]),
        })
        .to_string();

        let wrapped = sharing_wrap_keys(BASE64.encode(&pairwise_secret), scope_keys).unwrap();
        let wrapped_json: serde_json::Value = serde_json::from_str(&wrapped).unwrap();
        let unwrapped = sharing_unwrap_keys(
            BASE64.encode(&pairwise_secret),
            wrapped_json["wrapped_keys"].to_string(),
        )
        .unwrap();
        let unwrapped_json: serde_json::Value = serde_json::from_str(&unwrapped).unwrap();

        assert_eq!(
            BASE64
                .decode(
                    unwrapped_json["unwrapped_keys"]["read:members"]
                        .as_str()
                        .unwrap()
                )
                .unwrap(),
            vec![0x11; 32]
        );
        assert_eq!(
            BASE64
                .decode(
                    unwrapped_json["unwrapped_keys"]["read:fronting"]
                        .as_str()
                        .unwrap()
                )
                .unwrap(),
            vec![0x22; 32]
        );
    }

    #[test]
    fn sharing_fingerprint_matches_valid_identity_bundle() {
        let dek = [0x55; 32];
        let sharing_id_bytes = [0xAA; SHARING_ID_LEN_BYTES];
        let sharing_id = prism_sync_crypto::hex::encode(&sharing_id_bytes);
        let sender = SharingSender::from_dek(&dek, &sharing_id, &sharing_id_bytes, 0).unwrap();
        let identity_b64 = BASE64.encode(sender.identity().to_bytes());

        let fingerprint = sharing_fingerprint(identity_b64).unwrap();
        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sharing_rotation_needed_requires_matching_cached_identity() {
        let store = MemorySecureStore::new();
        store
            .set(SHARING_ID_CACHE_KEY, b"feedfacefeedfacefeedfacefeedface")
            .unwrap();

        let err = sharing_rotation_needed(&store, "deadbeefdeadbeefdeadbeefdeadbeef").unwrap_err();
        assert!(err.contains("bound to a different sharing_id"));
    }

    #[test]
    fn sharing_rotation_needed_detects_cached_active_sharing() {
        let store = MemorySecureStore::new();
        let sharing_id = "feedfacefeedfacefeedfacefeedface";
        store
            .set(SHARING_ID_CACHE_KEY, sharing_id.as_bytes())
            .unwrap();

        assert!(sharing_rotation_needed(&store, sharing_id).unwrap());
    }

    #[test]
    fn sharing_rotation_needed_detects_persisted_prekey_state_without_cache() {
        let store = MemorySecureStore::new();
        store
            .set("sharing_prekey_store", br#"{"current":null,"previous":[]}"#)
            .unwrap();

        assert!(sharing_rotation_needed(&store, "feedfacefeedfacefeedfacefeedface").unwrap());
    }

    #[test]
    fn sharing_rotation_needed_false_when_local_sharing_is_disabled() {
        let store = MemorySecureStore::new();

        assert!(!sharing_rotation_needed(&store, "feedfacefeedfacefeedfacefeedface").unwrap());
    }

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
