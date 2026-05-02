use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use zeroize::Zeroize;

use prism_sync_core::bootstrap::sharing_trust::{
    compute_sharing_fingerprint, evaluate_identity_with_generation_floor,
    GenerationAwareTrustDecision,
};
use prism_sync_core::bootstrap::{
    InitiatorCeremony, JoinerCeremony, PrekeyStore, RendezvousToken, SasDisplay,
    SharingIdentityBundle, SharingRecipient, SharingSender,
};
use prism_sync_core::client::PrismSync;
use prism_sync_core::pairing::service::PairingService;
use prism_sync_core::pairing::{
    compute_epoch_key_hash, RegistrySnapshotEntry, SignedRegistrySnapshot,
};
use prism_sync_core::relay::traits::{FirstDeviceAdmissionProof, RegistrationNonceResponse};
use prism_sync_core::relay::PairingRelay as _;
use prism_sync_core::relay::ServerPairingRelay;
use prism_sync_core::relay::{ServerRelay, ServerSharingRelay};
// Import the trait for method resolution only — NOT exposed in any public FFI signature.
use prism_sync_core::relay::SharingRelay as _;
use prism_sync_core::relay::{DeviceRegistry, MediaRelay, SyncRelay};
use prism_sync_core::schema::{parse_datetime_utc, SyncSchema, SyncType, SyncValue};
use prism_sync_core::storage::{RusqliteSyncStorage, SyncMetadata, SyncStorage};
use prism_sync_core::sync_service::AutoSyncConfig;
use prism_sync_core::{
    background_runtime, spawn_notification_handler, DeviceRegistryManager,
    SecureStore as PrismSecureStore,
};
use prism_sync_crypto::DeviceSecret;

/// Initialize a `tracing` subscriber once per process, writing to stderr.
///
/// Opt-in via the `PRISM_SYNC_TRACE` env var (treated as an `EnvFilter`
/// directive). In debug builds, defaults to `prism_sync_core=debug,
/// prism_sync_ffi=debug` when the var is unset so developers see FFI logs
/// by default. Release builds stay silent unless the env var is explicitly
/// set. Calling this more than once is a no-op thanks to `Once`.
///
/// Diagnostic-only — do NOT ship production users into a tracing subscriber.
fn install_trace_subscriber_once() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let directive = std::env::var("PRISM_SYNC_TRACE").ok();
        let filter = match directive {
            Some(d) if !d.is_empty() => d,
            _ => {
                if cfg!(debug_assertions) {
                    "prism_sync_core=debug,prism_sync_ffi=debug".to_string()
                } else {
                    return; // release + no env var → stay silent
                }
            }
        };
        let env_filter = match tracing_subscriber::EnvFilter::try_new(&filter) {
            Ok(f) => f,
            Err(_) => tracing_subscriber::EnvFilter::new("prism_sync_core=info"),
        };
        let _ = tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_writer(std::io::stderr)
            .with_target(true)
            .try_init();
    });
}

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
///         "score": "Real",
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

#[cfg(test)]
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

fn parse_fields_json_for_schema(
    json: &str,
    schema: &SyncSchema,
    table: &str,
) -> Result<HashMap<String, SyncValue>, String> {
    let map: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(json).map_err(|e| format!("Invalid fields JSON: {e}"))?;
    let entity = schema.entity(table).ok_or_else(|| format!("Unknown table '{table}'"))?;

    let mut result = HashMap::new();
    for (key, value) in map {
        let field =
            entity.field_by_name(&key).ok_or_else(|| format!("Unknown field '{table}.{key}'"))?;
        let sv = json_value_to_sync_value_for_type(&key, &value, field.sync_type)?;
        result.insert(key, sv);
    }
    Ok(result)
}

fn json_value_to_sync_value_for_type(
    key: &str,
    value: &serde_json::Value,
    sync_type: SyncType,
) -> Result<SyncValue, String> {
    if value.is_null() {
        return Ok(SyncValue::Null);
    }

    match sync_type {
        SyncType::String => value
            .as_str()
            .map(|s| SyncValue::String(s.to_string()))
            .ok_or_else(|| format!("Expected string for field '{key}'")),
        SyncType::Int => json_number_to_i64(key, value).map(SyncValue::Int),
        SyncType::Real => {
            let f =
                value.as_f64().ok_or_else(|| format!("Expected real number for field '{key}'"))?;
            if f.is_finite() {
                Ok(SyncValue::Real(f))
            } else {
                Err(format!("Unsupported float value for field '{key}'"))
            }
        }
        SyncType::Bool => value
            .as_bool()
            .map(SyncValue::Bool)
            .ok_or_else(|| format!("Expected boolean for field '{key}'")),
        SyncType::DateTime => {
            let s =
                value.as_str().ok_or_else(|| format!("Expected date string for field '{key}'"))?;
            let dt = parse_datetime_utc(s)
                .map_err(|e| format!("Invalid date string for field '{key}': {e}"))?;
            Ok(SyncValue::DateTime(dt))
        }
        SyncType::Blob => {
            let s = value
                .as_str()
                .ok_or_else(|| format!("Expected base64 string for field '{key}'"))?;
            let bytes = BASE64
                .decode(s)
                .map_err(|e| format!("Invalid base64 string for field '{key}': {e}"))?;
            Ok(SyncValue::Blob(bytes))
        }
    }
}

fn json_number_to_i64(key: &str, value: &serde_json::Value) -> Result<i64, String> {
    if let Some(i) = value.as_i64() {
        return Ok(i);
    }
    let f = value.as_f64().ok_or_else(|| format!("Expected integer for field '{key}'"))?;
    if f.fract() == 0.0 && f >= i64::MIN as f64 && f <= i64::MAX as f64 {
        Ok(f as i64)
    } else {
        Err(format!("Expected integer for field '{key}'"))
    }
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
                } else if f.is_finite() {
                    Ok(SyncValue::Real(f))
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
/// - `"3.14"` -> JSON number (Real)
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
    // `error_kind` uses the same pascal-case Debug format as
    // `SyncEvent::Error.kind` (see below) so Dart can parse both the same way.
    // Do not switch to kebab-case serde; the existing FFI convention is
    // `format!("{k:?}")` and both surfaces must stay consistent.
    //
    // `error_code` and `remote_wipe` are forwarded verbatim so the Dart
    // `SyncStatusNotifier` can trigger credential cleanup when the engine
    // wraps a `device_revoked` response into an `Ok(result)` branch.
    serde_json::json!({
        "pulled": result.pulled,
        "merged": result.merged,
        "pushed": result.pushed,
        "pruned": result.pruned,
        "duration_ms": result.duration.as_millis() as u64,
        "error": result.error.as_deref().map(redact_sensitive_message),
        "error_kind": result.error_kind.as_ref().map(|k| format!("{k:?}")),
        "error_code": result.error_code,
        "remote_wipe": result.remote_wipe,
    })
}

const STRUCTURED_ERROR_PREFIX: &str = "PRISM_SYNC_ERROR_JSON:";
const REDACTED_ID: &str = "[redacted-id]";
const REDACTED_HEX: &str = "[redacted-hex]";
const REDACTED_TOKEN: &str = "[redacted-token]";
const REDACTED_VALUE: &str = "[redacted]";
const SENSITIVE_MESSAGE_KEYS: &[&str] = &[
    "content_hash",
    "dek",
    "device",
    "device_id",
    "deviceid",
    "identity",
    "init_id",
    "media_id",
    "mnemonic",
    "pairwise_secret",
    "password",
    "recipient_sharing_id",
    "recipientsharingid",
    "relay",
    "sender_id",
    "sender_sharing_id",
    "sendersharingid",
    "session_token",
    "sessiontoken",
    "sharing_id",
    "sharingid",
    "signed",
    "sync_id",
    "syncid",
    "target_device_id",
    "targetdeviceid",
    "token",
    "wrapped_dek",
];

fn redact_sensitive_message(message: &str) -> String {
    let keyed = redact_keyed_values(message);
    redact_unkeyed_fragments(&keyed)
}

fn redact_display(error: &impl std::fmt::Display) -> String {
    redact_sensitive_message(&error.to_string())
}

fn redacted_identifier_for_log(_identifier: &str) -> &'static str {
    REDACTED_ID
}

fn redact_keyed_values(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut last = 0;
    let mut index = 0;

    while index < input.len() {
        let Some((_, ch)) = input[index..].char_indices().next() else {
            break;
        };

        if let Some((value_start, value_end)) =
            SENSITIVE_MESSAGE_KEYS.iter().find_map(|key| keyed_value_range(input, index, key))
        {
            output.push_str(&input[last..value_start]);
            output.push_str(REDACTED_VALUE);
            last = value_end;
            index = value_end;
            continue;
        }

        index += ch.len_utf8();
    }

    output.push_str(&input[last..]);
    output
}

fn keyed_value_range(input: &str, key_start: usize, key: &str) -> Option<(usize, usize)> {
    if !is_sensitive_key_at(input, key_start, key) {
        return None;
    }

    let mut index = key_start + key.len();
    index = skip_ascii_whitespace(input, index);
    if matches!(char_at(input, index), Some('"') | Some('\'')) {
        index += 1;
        index = skip_ascii_whitespace(input, index);
    }
    if !matches!(char_at(input, index), Some(':') | Some('=')) {
        return None;
    }
    index += 1;
    index = skip_ascii_whitespace(input, index);

    let quote = match char_at(input, index) {
        Some('"') | Some('\'') => {
            let quote = char_at(input, index);
            index += 1;
            quote
        }
        _ => None,
    };

    let value_start = index;
    let value_end = if let Some(quote) = quote {
        input[index..]
            .char_indices()
            .find_map(|(offset, ch)| (ch == quote).then_some(index + offset))
            .unwrap_or(input.len())
    } else {
        input[index..]
            .char_indices()
            .find_map(|(offset, ch)| is_unquoted_value_delimiter(ch).then_some(index + offset))
            .unwrap_or(input.len())
    };

    (value_start < value_end).then_some((value_start, value_end))
}

fn is_sensitive_key_at(input: &str, key_start: usize, key: &str) -> bool {
    input
        .get(key_start..key_start + key.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(key))
        && input
            .get(..key_start)
            .and_then(|prefix| prefix.chars().next_back())
            .is_none_or(|ch| !is_key_char(ch))
        && input
            .get(key_start + key.len()..)
            .and_then(|suffix| suffix.chars().next())
            .is_none_or(|ch| !is_key_char(ch))
}

fn is_key_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'
}

fn skip_ascii_whitespace(input: &str, mut index: usize) -> usize {
    while matches!(char_at(input, index), Some(ch) if ch.is_ascii_whitespace()) {
        index += 1;
    }
    index
}

fn char_at(input: &str, index: usize) -> Option<char> {
    input.get(index..)?.chars().next()
}

fn is_unquoted_value_delimiter(ch: char) -> bool {
    ch.is_ascii_whitespace() || matches!(ch, ',' | ')' | ']' | '}' | ';')
}

fn redact_unkeyed_fragments(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut token = String::new();

    for ch in input.chars() {
        if is_fragment_char(ch) {
            token.push(ch);
        } else {
            push_redacted_fragment(&mut output, &token);
            token.clear();
            output.push(ch);
        }
    }
    push_redacted_fragment(&mut output, &token);

    output
}

fn push_redacted_fragment(output: &mut String, token: &str) {
    if token.is_empty() {
        return;
    }

    if is_uuid_like(token) || is_short_hex_identifier(token) {
        output.push_str(REDACTED_HEX);
    } else if is_long_token_like(token) {
        output.push_str(REDACTED_TOKEN);
    } else {
        output.push_str(token);
    }
}

fn is_fragment_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '_' | '-')
}

fn is_uuid_like(token: &str) -> bool {
    let bytes = token.as_bytes();
    bytes.len() == 36
        && matches!(bytes.get(8), Some(b'-'))
        && matches!(bytes.get(13), Some(b'-'))
        && matches!(bytes.get(18), Some(b'-'))
        && matches!(bytes.get(23), Some(b'-'))
        && token.chars().filter(|ch| *ch != '-').all(|ch| ch.is_ascii_hexdigit())
}

fn is_short_hex_identifier(token: &str) -> bool {
    token.len() >= 12
        && token.chars().all(|ch| ch.is_ascii_hexdigit())
        && token.chars().any(|ch| matches!(ch, 'a'..='f' | 'A'..='F'))
}

fn is_long_token_like(token: &str) -> bool {
    token.len() >= 32
        && token.chars().all(is_fragment_char)
        && token.chars().any(|ch| ch.is_ascii_digit() || matches!(ch, '+' | '/' | '=' | '-' | '_'))
}

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
        "message": redact_display(&error),
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
    } else if let prism_sync_core::CoreError::BootstrapNotAllowed(reason) = &error {
        // First-device bootstrap guard failed. Surface a stable `code` so the
        // Dart side can render a user-friendly message without string-matching
        // against the English `message`.
        payload["error_type"] = serde_json::json!("core");
        payload["code"] = serde_json::json!("bootstrap_not_allowed");
        payload["reason"] = serde_json::json!(reason);
    } else if let prism_sync_core::CoreError::SnapshotTooLarge { bytes } = &error {
        payload["error_type"] = serde_json::json!("core");
        payload["code"] = serde_json::json!("snapshot_too_large");
        payload["bytes"] = serde_json::json!(bytes);
        payload["limit_bytes"] =
            serde_json::json!(prism_sync_core::snapshot_limits::MAX_SNAPSHOT_COMPRESSED_BYTES);
    } else if let prism_sync_core::CoreError::EpochMismatch { local_epoch, relay_epoch, .. } =
        &error
    {
        payload["error_type"] = serde_json::json!("core");
        payload["code"] = serde_json::json!("epoch_mismatch");
        payload["local_epoch"] = serde_json::json!(local_epoch);
        payload["relay_epoch"] = serde_json::json!(relay_epoch);
    } else if let prism_sync_core::CoreError::EpochKeyMismatch { epoch, .. } = &error {
        payload["error_type"] = serde_json::json!("core");
        payload["code"] = serde_json::json!("epoch_key_mismatch");
        payload["epoch"] = serde_json::json!(epoch);
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
    if let prism_sync_core::CoreError::Relay { min_signature_version, .. } = &error {
        let _ = ratchet_handle_min_signature_version_floor(handle, *min_signature_version).await;
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
        let _ =
            ratchet_handle_min_signature_version_floor(handle, Some(*min_signature_version)).await;
    }
    format!("{operation} failed: {}", redact_display(&error))
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
            "message": redact_sensitive_message(&err.message),
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
        SyncEvent::DeviceRevoked { ref device_id, remote_wipe } => serde_json::json!({
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
        SyncEvent::BackoffScheduled { attempt, delay_secs } => serde_json::json!({
            "type": "BackoffScheduled",
            "attempt": attempt,
            "delay_secs": delay_secs,
        }),
        SyncEvent::SnapshotUploadProgress { sync_id, bytes_sent, bytes_total } => {
            serde_json::json!({
                "type": "SnapshotUploadProgress",
                "sync_id": sync_id,
                "bytes_sent": bytes_sent,
                "bytes_total": bytes_total,
            })
        }
        SyncEvent::SnapshotUploadFailed { sync_id, reason } => serde_json::json!({
            "type": "SnapshotUploadFailed",
            "sync_id": sync_id,
            "reason": redact_sensitive_message(reason),
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
const SIGNATURE_VERSION_SOURCE_FLOOR: u8 = 0x03;
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

    BASE64.decode(value).map_err(|e| format!("Invalid base64 in {field_name}: {e}"))
}

fn parse_sharing_id_bytes(sharing_id: &str) -> Result<[u8; SHARING_ID_LEN_BYTES], String> {
    let decoded = prism_sync_crypto::hex::decode(sharing_id)
        .map_err(|e| format!("sharing_id must be 32 hex chars (decode failed: {e})"))?;
    if decoded.len() != SHARING_ID_LEN_BYTES {
        return Err(format!("sharing_id must be 32 hex chars (got {} bytes)", decoded.len()));
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
        .map(|value| value.parse::<u8>().map_err(|e| format!("invalid integer in {key}: {e}")))
        .transpose()
}

fn stored_min_signature_version_floor(store: &dyn PrismSecureStore) -> Result<Option<u8>, String> {
    decode_optional_u8(store, MIN_SIGNATURE_VERSION_FLOOR_KEY)
}

fn ratchet_min_signature_version_floor(
    store: &dyn PrismSecureStore,
    observed: Option<u8>,
) -> Result<(), String> {
    let required =
        observed.unwrap_or(SIGNATURE_VERSION_SOURCE_FLOOR).max(SIGNATURE_VERSION_SOURCE_FLOOR);
    let current = stored_min_signature_version_floor(store)?.unwrap_or(0);
    if required > current {
        store
            .set(MIN_SIGNATURE_VERSION_FLOOR_KEY, required.to_string().as_bytes())
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn ensure_app_supports_stored_floor(store: &dyn PrismSecureStore) -> Result<(), String> {
    if let Some(required) = stored_min_signature_version_floor(store)? {
        if required > SUPPORTED_SIGNATURE_VERSION {
            return Err(format!(
                "relay requires signature version {required}, but this app supports up to {SUPPORTED_SIGNATURE_VERSION}. Please update."
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
fn enforce_wire_signature_floor(
    store: &dyn PrismSecureStore,
    wire_signature_version: u8,
) -> Result<(), String> {
    let required =
        stored_min_signature_version_floor(store)?.unwrap_or(0).max(SIGNATURE_VERSION_SOURCE_FLOOR);
    if wire_signature_version < required {
        return Err(format!(
            "wire signature version {wire_signature_version} is below required floor {required}"
        ));
    }
    Ok(())
}

fn cache_sharing_id(store: &dyn PrismSecureStore, sharing_id: &str) -> Result<(), String> {
    store.set(SHARING_ID_CACHE_KEY, sharing_id.as_bytes()).map_err(|e| e.to_string())
}

fn clear_sharing_id_cache(store: &dyn PrismSecureStore) -> Result<(), String> {
    store.delete(SHARING_ID_CACHE_KEY).map_err(|e| e.to_string())
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

    store.get("sharing_prekey_store").map_err(|e| e.to_string()).map(|value| value.is_some())
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

    if let Err(error) =
        context.relay.publish_identity(sharing_id, &recipient.identity().to_bytes()).await
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
        pinned_identities
            .insert(peer_id, decode_binary_string(&encoded_identity, "pinned_identities")?);
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
    let ml_dsa_signing_key =
        device_secret
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
            inner.device_secret().map(|secret| secret.as_bytes().to_vec()),
            inner.export_dek().map_err(|e| e.to_string())?,
        )
    };

    ratchet_min_signature_version_floor(secure_store.as_ref(), None)?;
    ensure_app_supports_stored_floor(secure_store.as_ref())?;

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
    let record =
        tokio::task::spawn_blocking(move || storage.get_device_record(&sync_id, &lookup_device_id))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("device {device_id} not in local registry"))?;

    Ok(record.ml_dsa_key_generation)
}

async fn ensure_handle_supports_signature_version_floor(
    handle: &PrismSyncHandle,
) -> Result<(), String> {
    let secure_store = {
        let inner = handle.inner.lock().await;
        inner.secure_store().clone()
    };
    ratchet_min_signature_version_floor(secure_store.as_ref(), None)?;
    ensure_app_supports_stored_floor(secure_store.as_ref())
}

async fn ratchet_handle_min_signature_version_floor(
    handle: &PrismSyncHandle,
    observed: Option<u8>,
) -> Result<(), String> {
    let secure_store = match handle.inner.try_lock() {
        Ok(inner) => inner.secure_store().clone(),
        Err(_) => return Ok(()),
    };
    ratchet_min_signature_version_floor(secure_store.as_ref(), observed)
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
        Self { data: std::sync::Mutex::new(HashMap::new()) }
    }

    /// Return a copy of all stored entries (for draining back to Dart).
    pub fn snapshot(&self) -> HashMap<String, Vec<u8>> {
        lock_or_recover(&self.data).clone()
    }
}

impl Default for MemorySecureStore {
    fn default() -> Self {
        Self::new()
    }
}

impl prism_sync_core::secure_store::SecureStore for MemorySecureStore {
    fn get(&self, key: &str) -> prism_sync_core::Result<Option<Vec<u8>>> {
        Ok(lock_or_recover(&self.data).get(key).cloned())
    }
    fn set(&self, key: &str, value: &[u8]) -> prism_sync_core::Result<()> {
        lock_or_recover(&self.data).insert(key.to_string(), value.to_vec());
        Ok(())
    }
    fn delete(&self, key: &str) -> prism_sync_core::Result<()> {
        lock_or_recover(&self.data).remove(key);
        Ok(())
    }
    fn clear(&self) -> prism_sync_core::Result<()> {
        lock_or_recover(&self.data).clear();
        Ok(())
    }

    /// Override the default `None` impl so `drain_secure_store` can
    /// enumerate every entry (including dynamic `epoch_key_*` and
    /// `runtime_keys_*` keys) via the trait object. Reuses the existing
    /// inherent `snapshot()` method above.
    fn snapshot(&self) -> prism_sync_core::Result<Option<HashMap<String, Vec<u8>>>> {
        Ok(Some(MemorySecureStore::snapshot(self)))
    }
}

/// Lock a `std::sync::Mutex`, recovering from poisoning instead of panicking.
/// This is critical for FFI safety — a panic across the Dart/Rust boundary is UB.
fn lock_or_recover<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| {
        tracing::warn!("[prism_sync_ffi] mutex poisoned, recovering inner value");
        poisoned.into_inner()
    })
}

/// Stable error prefix returned when an FFI ceremony entry point is invoked
/// while another pairing ceremony is already in flight on the same handle.
///
/// Dart code can match on this prefix to surface a "complete or abandon the
/// existing ceremony" error to the user without crashing the in-progress
/// state. Phase 4E of the sync-pairing-reset hardening plan.
const CEREMONY_IN_PROGRESS_PREFIX: &str = "CEREMONY_IN_PROGRESS";

/// Guard against starting/completing a ceremony while another is in flight.
///
/// `start_*` callers pass `kind = StartGuard::Initiator` or
/// `StartGuard::Joiner` — both ceremony slots must be empty before a fresh
/// start.
///
/// `complete_*` callers pass `kind = StartGuard::CompleteInitiator` or
/// `StartGuard::CompleteJoiner` — only the *opposite* slot is checked
/// (mixing types is nonsensical), the matching slot is consumed by the
/// caller's own `take()`.
fn guard_ceremony_in_progress(
    handle: &PrismSyncHandle,
    kind: CeremonyGuardKind,
) -> Result<(), String> {
    let initiator_present = lock_or_recover(&handle.initiator_ceremony).is_some();
    let joiner_present = lock_or_recover(&handle.joiner_ceremony).is_some();
    match kind {
        CeremonyGuardKind::StartInitiator => {
            if initiator_present {
                return Err(format!(
                    "{CEREMONY_IN_PROGRESS_PREFIX}: an initiator ceremony is already in progress; \
                     complete or abandon the existing one before starting a new one"
                ));
            }
            if joiner_present {
                return Err(format!(
                    "{CEREMONY_IN_PROGRESS_PREFIX}: a joiner ceremony is in progress; \
                     cannot start an initiator ceremony on the same handle"
                ));
            }
        }
        CeremonyGuardKind::StartJoiner => {
            if joiner_present {
                return Err(format!(
                    "{CEREMONY_IN_PROGRESS_PREFIX}: a joiner ceremony is already in progress; \
                     complete or abandon the existing one before starting a new one"
                ));
            }
            if initiator_present {
                return Err(format!(
                    "{CEREMONY_IN_PROGRESS_PREFIX}: an initiator ceremony is in progress; \
                     cannot start a joiner ceremony on the same handle"
                ));
            }
        }
        CeremonyGuardKind::CompleteInitiator => {
            if joiner_present {
                return Err(format!(
                    "{CEREMONY_IN_PROGRESS_PREFIX}: a joiner ceremony is in progress; \
                     cannot complete an initiator ceremony on the same handle"
                ));
            }
        }
        CeremonyGuardKind::CompleteJoiner => {
            if initiator_present {
                return Err(format!(
                    "{CEREMONY_IN_PROGRESS_PREFIX}: an initiator ceremony is in progress; \
                     cannot complete a joiner ceremony on the same handle"
                ));
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum CeremonyGuardKind {
    StartInitiator,
    StartJoiner,
    CompleteInitiator,
    CompleteJoiner,
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
    install_trace_subscriber_once();

    let schema = if schema_json.is_empty() || schema_json == "{}" {
        SyncSchema::builder().build()
    } else {
        parse_schema_json(&schema_json)?
    };

    let storage = if db_path == ":memory:" {
        RusqliteSyncStorage::in_memory()
    } else if let Some(ref key) = database_key {
        let path = std::path::Path::new(&db_path);
        if path.exists() {
            let conn = rusqlite::Connection::open(&db_path)
                .map_err(|e| format!("Failed to open database: {e}"))?;
            RusqliteSyncStorage::new_encrypted(conn, key)
                .map_err(|e| prism_sync_core::CoreError::Storage(
                    prism_sync_core::storage::StorageError::Logic(format!(
                        "existing sync database could not be opened with the configured encryption key; refusing plaintext migration: {e}"
                    )),
                ))
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

    let mut builder =
        PrismSync::builder().schema(schema).storage(Arc::new(storage)).relay_url(&relay_url);

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

fn secret_text<'a>(
    field_name: &str,
    secret: &'a zeroize::Zeroizing<Vec<u8>>,
) -> Result<&'a str, String> {
    std::str::from_utf8(secret.as_slice()).map_err(|_| format!("{field_name} must be valid UTF-8"))
}

/// Initialize (first-time setup).
pub async fn initialize(
    handle: &PrismSyncHandle,
    password: Vec<u8>,
    secret_key: Vec<u8>,
) -> Result<(), String> {
    let password = zeroize::Zeroizing::new(password);
    let secret_key = zeroize::Zeroizing::new(secret_key);
    secret_text("password", &password)?;

    // Argon2id (64 MiB, 3 rounds) is CPU-heavy. Run on a spawn_blocking thread
    // so we don't stall the tokio worker. blocking_lock() acquires the tokio
    // Mutex synchronously, which is safe inside spawn_blocking.
    let inner = handle.inner.clone();
    tokio::task::spawn_blocking(move || {
        let password = secret_text("password", &password)?;
        inner.blocking_lock().initialize(password, secret_key.as_slice()).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("task failed: {e}"))??;
    ratchet_handle_min_signature_version_floor(handle, None).await
}

/// Unlock (subsequent launches).
pub async fn unlock(
    handle: &PrismSyncHandle,
    password: Vec<u8>,
    secret_key: Vec<u8>,
) -> Result<(), String> {
    let password = zeroize::Zeroizing::new(password);
    let secret_key = zeroize::Zeroizing::new(secret_key);
    secret_text("password", &password)?;

    // Same reasoning as initialize — Argon2id must not run on a tokio worker.
    let inner = handle.inner.clone();
    tokio::task::spawn_blocking(move || {
        let password = secret_text("password", &password)?;
        inner.blocking_lock().unlock(password, secret_key.as_slice()).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("task failed: {e}"))??;
    ratchet_handle_min_signature_version_floor(handle, None).await
}

/// Restore the unlocked state directly from raw key material.
///
/// Bypasses Argon2id password derivation entirely. Use when the host has
/// recovered the DEK from a platform-protected runtime cache. This is the
/// fast path for subsequent app launches.
///
/// - `dek`: The raw 32-byte Data Encryption Key.
/// - `device_secret`: The raw 32-byte device secret.
pub async fn restore_runtime_keys(
    handle: &PrismSyncHandle,
    dek: Vec<u8>,
    device_secret: Vec<u8>,
) -> Result<(), String> {
    let mut inner = handle.inner.lock().await;
    inner.restore_runtime_keys(&dek, &device_secret).map_err(|e| e.to_string())?;

    restore_persisted_epoch_keys(&mut inner)?;
    ratchet_min_signature_version_floor(inner.secure_store().as_ref(), None)?;

    Ok(())
}

fn parse_epoch_key_name(key: &str) -> Option<u32> {
    let suffix = key.strip_prefix("epoch_key_")?;
    if suffix.is_empty() {
        return None;
    }
    suffix.parse::<u32>().ok()
}

fn decode_persisted_epoch_key(key_name: &str, stored_bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    // The key may have been stored as base64 (client/pairing paths) or raw
    // bytes (older recovery paths). Try base64 first; if it does not decode
    // to exactly 32 bytes, fall back to raw key material.
    if let Ok(decoded) = BASE64.decode(&stored_bytes) {
        if decoded.len() == 32 {
            return Ok(decoded);
        }
    }

    if stored_bytes.len() == 32 {
        return Ok(stored_bytes);
    }

    Err(format!("{key_name} has wrong length ({}, expected 32)", stored_bytes.len()))
}

fn restore_persisted_epoch_keys(inner: &mut PrismSync) -> Result<(), String> {
    let secure_store = inner.secure_store().clone();
    let mut entries: Vec<(u32, String, Vec<u8>)> = Vec::new();

    if let Some(snapshot) = secure_store.snapshot().map_err(|e| e.to_string())? {
        for (key, value) in snapshot {
            let Some(epoch) = parse_epoch_key_name(&key) else {
                continue;
            };
            entries.push((epoch, key, value));
        }
    } else {
        let current_epoch = secure_store
            .get("epoch")
            .map_err(|e| e.to_string())?
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        for epoch in 1..=current_epoch {
            let key = format!("epoch_key_{epoch}");
            if let Some(value) = secure_store.get(&key).map_err(|e| e.to_string())? {
                entries.push((epoch, key, value));
            }
        }
    }

    entries.sort_by_key(|(epoch, _, _)| *epoch);
    for (epoch, key_name, stored_bytes) in entries {
        let key_bytes = match decode_persisted_epoch_key(&key_name, stored_bytes) {
            Ok(key_bytes) => key_bytes,
            Err(error) => {
                tracing::warn!(
                    epoch,
                    key = %key_name,
                    error = %redact_display(&error),
                    "restore_runtime_keys: skipping invalid persisted epoch key"
                );
                continue;
            }
        };
        inner.key_hierarchy_mut().store_epoch_key(epoch, zeroize::Zeroizing::new(key_bytes));
    }

    Ok(())
}

/// Export the raw DEK bytes for host-side runtime-cache wrapping.
///
/// Returns the raw 32-byte DEK. Only works when unlocked (after
/// `initialize` or `unlock`). The host must wrap the bytes before
/// persistence; the unwrapped bytes can be supplied to `restore_runtime_keys`
/// on subsequent launches.
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
    inner.database_key().map(|k| k.to_vec()).map_err(|e| e.to_string())
}

/// Derive local storage key (HKDF from DEK + DeviceSecret).
/// Requires initialize() or restore_runtime_keys() to have been called.
pub async fn local_storage_key(handle: &PrismSyncHandle) -> Result<Vec<u8>, String> {
    let inner = handle.inner.lock().await;
    inner.local_storage_key().map(|k| k.to_vec()).map_err(|e| e.to_string())
}

/// Re-encrypt the Rust sync SQLite database with a new 32-byte key.
/// Takes Vec<u8> from Dart; validates to exactly 32 bytes.
pub async fn rekey_db(handle: &PrismSyncHandle, new_key: Vec<u8>) -> Result<(), String> {
    let key: [u8; 32] =
        new_key.try_into().map_err(|_| "rekey_db: key must be exactly 32 bytes".to_string())?;
    let inner = handle.inner.lock().await;
    inner.rekey_db(&key).map_err(|e| e.to_string())
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
    ratchet_min_signature_version_floor(inner.secure_store().as_ref(), None)?;
    ensure_app_supports_stored_floor(inner.secure_store().as_ref())?;

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
    let device_secret = inner.secure_store().get("device_secret").map_err(|e| e.to_string())?;
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
        tracing::warn!(
            error = %redact_display(&e),
            "[prism_sync_ffi] WebSocket connect failed (non-fatal)"
        );
    }

    // Store relay so set_auto_sync can wire up the notification handler.
    *lock_or_recover(&handle.relay) = Some(relay.clone());

    // Configure engine
    inner.configure_engine(relay, sync_id, device_id, epoch, ml_dsa_key_generation);

    Ok(())
}

// ── Password management ──

/// Change password (re-wraps DEK, no data re-encryption).
///
/// Operates on the already-unlocked key hierarchy. The new password and
/// secret key are wrapped for zeroization immediately on FFI entry; the new
/// password bytes must be valid UTF-8 for the current crypto API.
///
/// Returns the next `identity_generation` value that the app should persist
/// to synced settings. If local sharing is currently active, this also
/// republishes the sharing identity and rotates the signed prekey under the
/// incremented generation before re-wrapping the DEK.
pub async fn change_password(
    handle: &PrismSyncHandle,
    new_password: Vec<u8>,
    secret_key: Vec<u8>,
    sharing_id: Option<String>,
    current_identity_generation: u32,
) -> Result<u32, String> {
    let new_password = zeroize::Zeroizing::new(new_password);
    let secret_key = zeroize::Zeroizing::new(secret_key);
    std::str::from_utf8(new_password.as_slice())
        .map_err(|_| "new_password must be valid UTF-8".to_string())?;

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
        let new_password = std::str::from_utf8(new_password.as_slice())
            .map_err(|_| "new_password must be valid UTF-8".to_string())?;
        let (new_wrapped_dek, new_salt) = inner
            .key_hierarchy()
            .change_password(new_password, secret_key.as_slice())
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
/// Supported value types: null, string, integer, real number, boolean.
pub async fn record_create(
    handle: &PrismSyncHandle,
    table: String,
    entity_id: String,
    fields_json: String,
) -> Result<(), String> {
    let mut inner = handle.inner.lock().await;
    let fields = parse_fields_json_for_schema(&fields_json, inner.schema(), &table)?;
    inner.record_create(&table, &entity_id, &fields).map_err(|e| e.to_string())
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
    let fields = parse_fields_json_for_schema(&changed_fields_json, inner.schema(), &table)?;
    inner.record_update(&table, &entity_id, &fields).map_err(|e| e.to_string())
}

/// Record entity deletion (soft delete / tombstone).
pub async fn record_delete(
    handle: &PrismSyncHandle,
    table: String,
    entity_id: String,
) -> Result<(), String> {
    let mut inner = handle.inner.lock().await;
    inner.record_delete(&table, &entity_id).map_err(|e| e.to_string())
}

// ── First-device bootstrap ──

/// Seed `field_versions` from pre-existing local data for the first device in
/// a sync group. No relay traffic; no `pending_ops` produced.
///
/// `records_json` is a JSON array of seed records:
///
/// ```json
/// [
///   { "table": "members", "entity_id": "...", "fields": { "name": "Alice", "emoji": "..." } },
///   ...
/// ]
/// ```
///
/// The inner `fields` object follows the same natural-JSON shape as
/// [`record_create`]: `null`, strings, integers, and booleans.
///
/// Returns a JSON object with `entity_count` and `snapshot_bytes`:
/// ```json
/// { "entity_count": 42, "snapshot_bytes": 1234567 }
/// ```
///
/// Errors propagate via the standard structured-error encoding. In particular:
/// - `BootstrapNotAllowed` (a device is already registered, a remote has been
///   pulled, or applied_ops rows exist) carries `code: "bootstrap_not_allowed"`.
/// - `SnapshotTooLarge` carries `code: "snapshot_too_large"`, `bytes`, and
///   `limit_bytes` so the UI can surface the numbers without string parsing.
pub async fn bootstrap_existing_state(
    handle: &PrismSyncHandle,
    records_json: String,
) -> Result<String, String> {
    // Parse the records array.
    let value: serde_json::Value =
        serde_json::from_str(&records_json).map_err(|e| format!("Invalid records JSON: {e}"))?;
    let arr = value.as_array().ok_or_else(|| "records JSON must be an array".to_string())?;

    let mut records: Vec<prism_sync_core::engine::SeedRecord> = Vec::with_capacity(arr.len());
    for (idx, entry) in arr.iter().enumerate() {
        let obj = entry.as_object().ok_or_else(|| format!("records[{idx}] must be an object"))?;
        let table = obj
            .get("table")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("records[{idx}].table must be a string"))?
            .to_string();
        let entity_id = obj
            .get("entity_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("records[{idx}].entity_id must be a string"))?
            .to_string();
        let fields_value =
            obj.get("fields").ok_or_else(|| format!("records[{idx}].fields missing"))?;
        let fields_map = fields_value
            .as_object()
            .ok_or_else(|| format!("records[{idx}].fields must be an object"))?;
        let mut fields = HashMap::with_capacity(fields_map.len());
        for (key, v) in fields_map {
            let sv = json_value_to_sync_value(key, v)
                .map_err(|e| format!("records[{idx}].fields: {e}"))?;
            fields.insert(key.clone(), sv);
        }
        records.push(prism_sync_core::engine::SeedRecord { table, entity_id, fields });
    }

    let mut inner = handle.inner.lock().await;
    match inner.bootstrap_existing_state(records).await {
        Ok(report) => {
            let json = serde_json::json!({
                "entity_count": report.entity_count,
                "snapshot_bytes": report.snapshot_bytes,
            });
            Ok(json.to_string())
        }
        Err(e) => {
            drop(inner);
            Err(encode_handle_core_error(handle, "bootstrap_existing_state", e).await)
        }
    }
}

/// Acknowledge that a downloaded snapshot has been applied locally, telling
/// the relay to delete the stored blob (`DELETE /v1/sync/{id}/snapshot`).
///
/// Idempotent: a `NotFound` response maps to `Ok(())`. Older relays that
/// don't implement `DELETE /snapshot` will return 405 Method Not Allowed;
/// the engine folds that to `Ok(())` too and the snapshot TTL-expires
/// relay-side.
pub async fn acknowledge_snapshot_applied(handle: &PrismSyncHandle) -> Result<(), String> {
    let inner = handle.inner.lock().await;
    match inner.acknowledge_snapshot_applied().await {
        Ok(()) => Ok(()),
        Err(e) => {
            drop(inner);
            Err(encode_handle_core_error(handle, "acknowledge_snapshot_applied", e).await)
        }
    }
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
    if let Some(h) = lock_or_recover(&handle.driver_handle).take() {
        h.abort();
    }
    if let Some(h) = lock_or_recover(&handle.notification_handle).take() {
        h.abort();
    }
    if let Some(h) = lock_or_recover(&handle.backoff_handle).take() {
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

        // Auto-sync driver: outer tier of the two-tier retry architecture.
        //
        // The inner tier lives in `SyncService::sync_now` (prism-sync-core):
        // 3 tight `INNER_RETRY_DELAY` (2s) retries inside a single sync
        // cycle, scoped to transient transport hiccups (pull timeouts,
        // TLS resets, backgrounded tokio timers firing overdue). The inner
        // loop converts exhausted retries into `Err(synthetic_core_error)`.
        //
        // This outer loop receives that `Err` and runs exponential backoff
        // across sync *cycles* (`30s -> 60s -> 120s -> 240s -> 300s`, with
        // a ~10-minute cumulative cap). On success we reset; on final
        // exhaustion we emit a terminal `SyncEvent::Error` and clear the
        // backoff so a manual trigger starts fresh.
        //
        // Do not collapse the two tiers: the inner loop avoids escalating
        // one-off hiccups to multi-minute user-visible delays; the outer
        // loop prevents busy-looping during sustained outages.
        let driver = background_runtime().spawn(async move {
            use prism_sync_core::sync_service::{jittered_delay, SyncTrigger};

            let mut backoff_secs: u64 = 0;
            let mut backoff_attempt: u32 = 0;
            let mut cumulative_backoff_secs: u64 = 0;
            const MAX_CUMULATIVE_SECS: u64 = 600; // 10 minutes

            while trigger_rx.recv().await.is_some() {
                // Cancel any pending backoff delay task
                {
                    let mut guard = lock_or_recover(&backoff_abort);
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
                    Err(e) => {
                        // Non-retryable errors (auth failures, protocol errors,
                        // device revocations) should surface immediately without
                        // scheduling a backoff retry. The inner loop already
                        // emitted SyncCompleted + Error events; don't delay them
                        // behind a 30-second backoff wall.
                        if !e.is_retryable() {
                            backoff_secs = 0;
                            backoff_attempt = 0;
                            cumulative_backoff_secs = 0;
                            continue;
                        }

                        backoff_secs =
                            if backoff_secs == 0 { 30 } else { (backoff_secs * 2).min(300) };
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
                            let delay =
                                jittered_delay(std::time::Duration::from_secs(backoff_secs));
                            let task = tokio::spawn(async move {
                                tokio::time::sleep(delay).await;
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
        *lock_or_recover(&handle.driver_handle) = Some(driver);

        // Spawn notification handler if relay is connected, so WebSocket
        // new_data messages trigger auto-pull on this device. Pass the
        // PrismSync handle and relay so epoch rotation can be recovered
        // inline before triggering sync.
        let relay = lock_or_recover(&handle.relay).clone();
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
            *lock_or_recover(&handle.notification_handle) = Some(notif);
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
            if let prism_sync_core::CoreError::Relay { min_signature_version, .. } = &error {
                let _ = ratchet_min_signature_version_floor(
                    secure_store.as_ref(),
                    *min_signature_version,
                );
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
    let result = {
        let mut inner = handle.inner.lock().await;
        inner.on_resume().await
    };
    match result {
        Ok(()) => Ok(()),
        Err(error) => Err(encode_handle_core_error(handle, "on_resume", error).await),
    }
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
pub async fn download_media(handle: &PrismSyncHandle, media_id: String) -> Result<Vec<u8>, String> {
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
    inner.upload_pairing_snapshot(Some(ttl_secs), for_device_id).await.map_err(|e| e.to_string())
}

/// Download and apply a snapshot for initial device bootstrap.
///
/// Called by the new device after joining. Returns the number of entities
/// restored, or 0 if no snapshot was available. Emits a RemoteChanges
/// SyncEvent so Dart can populate its local database.
pub async fn bootstrap_from_snapshot(handle: &PrismSyncHandle) -> Result<u64, String> {
    let mut inner = handle.inner.lock().await;
    let (count, _changes) = inner.bootstrap_from_snapshot().await.map_err(|e| e.to_string())?;
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
#[allow(clippy::too_many_arguments)]
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
/// The relay is constructed via a builder closure after the sync_id is
/// generated internally, ensuring the registration request uses the real
/// sync_id in the URL path.
pub async fn create_sync_group(
    handle: &PrismSyncHandle,
    password: Vec<u8>,
    relay_url: String,
    mnemonic: Option<Vec<u8>>,
) -> Result<String, String> {
    let password = zeroize::Zeroizing::new(password);
    let mnemonic = mnemonic.map(zeroize::Zeroizing::new);
    let password_text = secret_text("password", &password)?;
    let mnemonic_text =
        mnemonic.as_ref().map(|bytes| secret_text("mnemonic", bytes)).transpose()?;

    ensure_handle_supports_signature_version_floor(handle).await?;
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

    // Generate the sync_id upfront so the pending state can reference it.
    // The relay is built later via the relay_builder closure, after
    // PairingService resolves sync_id + device_id internally.
    let sync_id =
        pending.0.clone().unwrap_or_else(prism_sync_core::epoch::EpochManager::generate_sync_id);

    let mut inner = handle.inner.lock().await;
    let secure_store = inner.secure_store().clone();
    let pairing = PairingService::new(secure_store.clone());

    let ffi_relay_url = relay_url.clone();
    let ffi_allow_insecure = handle.allow_insecure;
    let create_result = pairing
        .create_sync_group(
            password_text,
            &relay_url,
            mnemonic_text,
            Some(sync_id),
            pending.1.clone(),
            pending.2.clone(),
            pending.3.clone(),
            |sync_id, device_id, registration_token| {
                build_relay(
                    &ffi_relay_url,
                    sync_id,
                    device_id,
                    "", // no session token yet — registration will return one
                    None,
                    0,
                    ffi_allow_insecure,
                    registration_token.map(str::to_string),
                )
                .map(|r| r as Arc<dyn SyncRelay>)
                .map_err(prism_sync_core::CoreError::Engine)
            },
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

    let (mut creds, mut response) = match create_result {
        Ok(value) => value,
        Err(error) => {
            if let prism_sync_core::CoreError::Relay { min_signature_version, .. } = &error {
                let _ = ratchet_min_signature_version_floor(
                    secure_store.as_ref(),
                    *min_signature_version,
                );
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
    let secret_key_result = prism_sync_crypto::mnemonic::to_bytes(&creds.mnemonic)
        .map_err(|e| format!("mnemonic conversion failed: {e}"));
    creds.mnemonic.zeroize();
    response.mnemonic.zeroize();
    let secret_key = zeroize::Zeroizing::new(secret_key_result?);
    inner
        .unlock(password_text, secret_key.as_slice())
        .map_err(|e| format!("unlock after create failed: {e}"))?;

    let device_secret_bytes = inner
        .secure_store()
        .get("device_secret")
        .map_err(|e| e.to_string())?
        .ok_or("device_secret not found after create_sync_group")?;
    let dek = inner.export_dek().map_err(|e| e.to_string())?;
    inner.restore_runtime_keys(&dek, &device_secret_bytes).map_err(|e| e.to_string())?;

    // Insert the device's own record into the local registry so that
    // configureEngine (which calls load_device_ml_dsa_generation) can
    // find it. The joiner path does this via import_keyring, but the
    // first-device (initiator) path was missing it.
    let device_id = inner
        .secure_store()
        .get("device_id")
        .map_err(|e| e.to_string())?
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or("device_id not found after create_sync_group")?;
    let device_secret = DeviceSecret::from_bytes(device_secret_bytes.clone())
        .map_err(|e| format!("invalid device_secret: {e}"))?;
    let signing_key = device_secret
        .ed25519_keypair(&device_id)
        .map_err(|e| format!("ed25519 derive failed: {e}"))?;
    let exchange_key = device_secret
        .x25519_keypair(&device_id)
        .map_err(|e| format!("x25519 derive failed: {e}"))?;
    let pq_signing_key = device_secret
        .ml_dsa_65_keypair(&device_id)
        .map_err(|e| format!("ml_dsa derive failed: {e}"))?;
    let pq_kem_key = device_secret
        .ml_kem_768_keypair(&device_id)
        .map_err(|e| format!("ml_kem derive failed: {e}"))?;
    let xwing_key =
        device_secret.xwing_keypair(&device_id).map_err(|e| format!("xwing derive failed: {e}"))?;

    let self_record = prism_sync_core::storage::types::DeviceRecord {
        sync_id: response.sync_id.clone(),
        device_id: device_id.clone(),
        ed25519_public_key: signing_key.public_key_bytes().to_vec(),
        x25519_public_key: exchange_key.public_key_bytes().to_vec(),
        ml_dsa_65_public_key: pq_signing_key.public_key_bytes(),
        ml_kem_768_public_key: pq_kem_key.public_key_bytes(),
        x_wing_public_key: xwing_key.encapsulation_key_bytes(),
        status: "active".to_string(),
        registered_at: chrono::Utc::now(),
        revoked_at: None,
        ml_dsa_key_generation: 0,
    };
    DeviceRegistryManager::import_keyring(
        inner.storage().as_ref(),
        &response.sync_id,
        &[self_record],
    )
    .map_err(|e| format!("failed to seed local device registry: {e}"))?;
    ensure_local_sync_metadata(inner.storage().as_ref(), &response.sync_id, &device_id, 0)
        .map_err(|e| format!("failed to seed local sync metadata: {e}"))?;

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
    let signing_key = device_secret
        .ed25519_keypair(&device_id)
        .map_err(|e| format!("ed25519 derive failed: {e}"))?;
    let x25519_key = device_secret
        .x25519_keypair(&device_id)
        .map_err(|e| format!("x25519 derive failed: {e}"))?;
    let ml_dsa_key = device_secret
        .ml_dsa_65_keypair(&device_id)
        .map_err(|e| format!("ml-dsa derive failed: {e}"))?;
    let ml_kem_key = device_secret
        .ml_kem_768_keypair(&device_id)
        .map_err(|e| format!("ml-kem derive failed: {e}"))?;
    let xwing_key = device_secret
        .xwing_keypair(&device_id)
        .map_err(|e| format!("x-wing derive failed: {e}"))?;

    let signing_pk = signing_key.public_key_bytes();
    let x25519_pk = x25519_key.public_key_bytes();
    let ml_dsa_pk = ml_dsa_key.public_key_bytes();
    let ml_kem_pk = ml_kem_key.public_key_bytes();
    let xwing_pk = xwing_key.encapsulation_key_bytes();
    let registration_key_bundle_hash = compute_registration_key_bundle_hash(
        &signing_pk,
        &x25519_pk,
        &ml_dsa_pk,
        &ml_kem_pk,
        &xwing_pk,
    );

    let handle_inner = handle.inner.lock().await;
    let store = handle_inner.secure_store();
    store
        .set("pending_device_secret", device_secret.as_bytes())
        .map_err(|e| format!("Failed to persist pending device secret: {e}"))?;
    store
        .set("pending_device_id", device_id.as_bytes())
        .map_err(|e| format!("Failed to persist pending device id: {e}"))?;

    Ok(serde_json::json!({
        "device_id": device_id,
        "registration_key_bundle_hash": hex::encode(registration_key_bundle_hash),
    })
    .to_string())
}

fn compute_registration_key_bundle_hash(
    signing_pk: &[u8],
    x25519_pk: &[u8],
    ml_dsa_pk: &[u8],
    ml_kem_pk: &[u8],
    xwing_pk: &[u8],
) -> [u8; 32] {
    fn write_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
    }

    let mut hasher = Sha256::new();
    hasher.update(b"PRISM_SYNC_REGISTRATION_KEY_BUNDLE_V1\x00");
    write_len_prefixed(&mut hasher, signing_pk);
    write_len_prefixed(&mut hasher, x25519_pk);
    write_len_prefixed(&mut hasher, ml_dsa_pk);
    write_len_prefixed(&mut hasher, ml_kem_pk);
    write_len_prefixed(&mut hasher, xwing_pk);
    hasher.finalize().into()
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
    ensure_handle_supports_signature_version_floor(handle).await?;
    let (storage, device_secret) = {
        let inner = handle.inner.lock().await;
        (
            inner.storage().clone(),
            inner.secure_store().get("device_secret").map_err(|e| e.to_string())?,
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

/// Fetch the relay-advertised GIF service configuration for the current sync
/// server. Returns JSON: `{"enabled": bool, "api_base_url": "...", "media_proxy_enabled": bool}`.
pub async fn fetch_gif_service_config(handle: &PrismSyncHandle) -> Result<String, String> {
    ensure_handle_supports_signature_version_floor(handle).await?;
    let (sync_id, device_id, session_token, relay_url, storage, device_secret) = {
        let inner = handle.inner.lock().await;
        let secure_store = inner.secure_store();
        let sync_id = secure_store
            .get("sync_id")
            .map_err(|e| e.to_string())?
            .map(|b| String::from_utf8(b).unwrap_or_default())
            .ok_or("No sync_id found — pair first")?;
        let device_id = secure_store
            .get("device_id")
            .map_err(|e| e.to_string())?
            .map(|b| String::from_utf8(b).unwrap_or_default())
            .ok_or("No device_id found — pair first")?;
        let session_token = secure_store
            .get("session_token")
            .map_err(|e| e.to_string())?
            .map(|b| String::from_utf8(b).unwrap_or_default())
            .ok_or("No session token found — pair first")?;
        let relay_url = secure_store
            .get("relay_url")
            .map_err(|e| e.to_string())?
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| handle.relay_url.clone());
        (
            sync_id,
            device_id,
            session_token,
            relay_url,
            inner.storage().clone(),
            secure_store.get("device_secret").map_err(|e| e.to_string())?,
        )
    };

    let ml_dsa_key_generation =
        load_device_ml_dsa_generation(storage, sync_id.clone(), device_id.clone()).await?;
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

    let config = match relay.fetch_gif_service_config().await {
        Ok(config) => config,
        Err(error) => {
            return Err(format_handle_relay_error(handle, "fetch_gif_service_config", error).await);
        }
    };
    serde_json::to_string(&config).map_err(|e| format!("JSON serialization failed: {e}"))
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
    ensure_handle_supports_signature_version_floor(handle).await?;
    let (storage, device_secret) = {
        let inner = handle.inner.lock().await;
        (
            inner.storage().clone(),
            inner.secure_store().get("device_secret").map_err(|e| e.to_string())?,
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
        Err(error) => Err(format!("revoke_device failed: {}", redact_display(&error))),
    }
}

/// Revoke a device and perform epoch key rotation.
///
/// This is the correct way to revoke a device — it:
/// 1. Revokes the device on the relay (bumps epoch)
/// 2. Generates a new epoch key
/// 3. Wraps the key for each remaining device via X-Wing hybrid key exchange (X25519 + ML-KEM-768)
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
    ensure_handle_supports_signature_version_floor(handle).await?;
    let (storage, device_secret) = {
        let inner = handle.inner.lock().await;
        (
            inner.storage().clone(),
            inner.secure_store().get("device_secret").map_err(|e| e.to_string())?,
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
        Err(error) => Err(format!("revoke_and_rekey failed: {}", redact_display(&error))),
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
pub fn mnemonic_to_bytes(mnemonic: Vec<u8>) -> Result<Vec<u8>, String> {
    let mnemonic = zeroize::Zeroizing::new(mnemonic);
    let mnemonic = secret_text("mnemonic", &mnemonic)?;
    prism_sync_crypto::mnemonic::to_bytes(mnemonic).map_err(|e| e.to_string())
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
    ensure_handle_supports_signature_version_floor(handle).await?;
    let (storage, device_secret) = {
        let inner = handle.inner.lock().await;
        (
            inner.storage().clone(),
            inner.secure_store().get("device_secret").map_err(|e| e.to_string())?,
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
    ensure_handle_supports_signature_version_floor(handle).await?;
    let (storage, device_secret) = {
        let inner = handle.inner.lock().await;
        (
            inner.storage().clone(),
            inner.secure_store().get("device_secret").map_err(|e| e.to_string())?,
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

/// Atomically wipe all local sync engine state for the configured sync group.
///
/// Clears `pending_ops`, `applied_ops`, `field_versions`, `sync_metadata`, and
/// the paired-devices list (`device_registry`) inside a single
/// `BEGIN IMMEDIATE` transaction. After this returns successfully the device
/// is unpaired from its sync group and must re-pair before any further sync
/// operation will succeed.
///
/// The host's Drift-side `sync_quarantine` table (if any) is *not* touched —
/// that lives outside the Rust engine and must be cleared by the host
/// alongside this call.
///
/// Used as the "Approach A" cutover hook by the per-member fronting migration
/// (see `docs/plans/fronting-per-member-sessions.md` §4.2). Performs no relay
/// I/O — purely local. Requires a configured engine (`configure_engine` must
/// have been called) — for the cleanup-resume path that runs without a
/// configured engine, use [`clear_sync_state`] instead.
pub async fn reset_sync_state(handle: &PrismSyncHandle) -> Result<(), String> {
    let mut inner = handle.inner.lock().await;
    inner.reset_sync_state().await.map_err(|e| e.to_string())
}

/// Clear all sync-DB rows for the given `sync_id`.
///
/// Wipes `pending_ops`, `applied_ops`, `field_versions`, `device_registry`,
/// and `sync_metadata` rows scoped to `sync_id`. Used by the reset-data path
/// (Phase 2B) as belt-and-suspenders before deleting the sync DB file, and
/// by any future cleanup of orphaned/abandoned sync_ids — including the
/// fronting-migration cleanup-resume path, which has no live engine to call
/// [`reset_sync_state`] against.
///
/// **Safety guard:** by default, refuses to clear the *currently active*
/// `sync_id` (the one configured on the live engine). Callers that
/// intentionally clear the active sync_id (e.g. the reset path, which then
/// disposes the handle) must pass `force_active=true`.
///
/// The Drift app DB is not touched — only the Rust-managed sync DB.
pub async fn clear_sync_state(
    handle: &PrismSyncHandle,
    sync_id: String,
    force_active: bool,
) -> Result<(), String> {
    let storage = {
        let inner = handle.inner.lock().await;
        if !force_active {
            if let Some(active) = inner.sync_service().sync_id() {
                if active == sync_id {
                    return Err("refusing to clear_sync_state for the active sync_id; pass \
                         force_active=true if intentional"
                        .into());
                }
            }
        }
        inner.storage().clone()
    };
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let mut tx = storage.begin_tx().map_err(|e| e.to_string())?;
        tx.clear_sync_state(&sync_id).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
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
/// Entries are transferred as per-key byte buffers so secret material does not
/// need to be assembled into a JSON string at the FFI boundary.
pub async fn seed_secure_store(
    handle: &PrismSyncHandle,
    entries: std::collections::HashMap<String, Vec<u8>>,
) -> Result<(), String> {
    let inner = handle.inner.lock().await;
    let store = inner.secure_store();
    for (key, bytes) in entries {
        store.set(&key, &bytes).map_err(|e| e.to_string())?;
    }
    ratchet_min_signature_version_floor(store.as_ref(), None)?;
    Ok(())
}

/// Drain all values from the secure store so Dart can persist them
/// back to the platform keychain.
///
/// Returns per-key byte buffers for the app to persist to its keychain.
/// Call this after state-changing operations (initialize, change_password,
/// create_sync_group, join_*).
///
/// **Fast path:** if the underlying store supports enumeration (i.e.
/// `SecureStore::snapshot()` returns `Some`, which `MemorySecureStore`
/// does), every entry is exported verbatim. This covers dynamic keys
/// such as `epoch_key_*` and `runtime_keys_*` without allow-list
/// maintenance.
///
/// **Fallback:** if enumeration is unavailable (keychain-backed impls),
/// drain falls back to the historical fixed `known_keys` list plus
/// `epoch_key_1..=current_epoch`.
pub async fn drain_secure_store(
    handle: &PrismSyncHandle,
) -> Result<std::collections::HashMap<String, Vec<u8>>, String> {
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

    // Fast path: snapshot the entire store.
    if let Some(map) = store.snapshot().map_err(|e| e.to_string())? {
        return Ok(map);
    }

    // Fallback path: keychain-backed store without enumeration. Use the
    // historical allow-list plus a bounded `epoch_key_*` scan so existing
    // consumers keep working with no behavior change.
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

    // The recovery phrase is deliberately not listed: the mnemonic is an
    // offline backup credential and is not persisted to the secure store.
    // The fast-path `snapshot()` above still exports anything present (so
    // legacy entries from earlier builds drain once), but nothing will
    // re-seed it afterwards.
    let known_keys = [
        "wrapped_dek",
        "dek_salt",
        "device_secret",
        "device_id",
        "sync_id",
        "session_token",
        "epoch",
        "relay_url",
        "setup_rollback_marker",
        "registration_token",
        "sharing_prekey_store",
        "sharing_id_cache",
        "min_signature_version_floor",
    ];
    let mut entries = std::collections::HashMap::new();
    for key in known_keys {
        if let Ok(Some(value)) = store.get(key) {
            entries.insert(key.to_string(), value);
        }
    }
    for epoch in 1..=current_epoch {
        let key = format!("epoch_key_{epoch}");
        if let Ok(Some(value)) = store.get(&key) {
            entries.insert(key, value);
        }
    }
    Ok(entries)
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

    if let Err(error) =
        context.relay.publish_identity(&sharing_id, &recipient.identity().to_bytes()).await
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
                        error: Some(redact_sensitive_message(&format!(
                            "relay sender_id does not match signed sender identity: relay={}, signed={}",
                            pending_init.sender_id, processed.sender_identity.sharing_id
                        ))),
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
                error: Some(redact_display(&error)),
            },
        };

        if !seen_init_ids.iter().any(|seen| seen == &pending_init.init_id) {
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
    identity.verify().map_err(|e| format!("Invalid sharing identity signature: {e}"))?;

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
    let device_secret = inner.device_secret().ok_or("Device secret not initialized")?;
    let device_id = inner.device_id().ok_or("Device ID not configured")?;
    let exchange_key = device_secret.x25519_keypair(device_id).map_err(|e| e.to_string())?;
    Ok(exchange_key.public_key_bytes().to_vec())
}

/// Perform X25519 ECDH key agreement with a peer's public key.
/// Returns the 32-byte shared secret.
pub async fn perform_ecdh(
    handle: &PrismSyncHandle,
    peer_public_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    if peer_public_key.len() != 32 {
        return Err(format!("peer public key must be 32 bytes, got {}", peer_public_key.len()));
    }
    let inner = handle.inner.lock().await;
    let device_secret = inner.device_secret().ok_or("Device secret not initialized")?;
    let device_id = inner.device_id().ok_or("Device ID not configured")?;
    let exchange_key = device_secret.x25519_keypair(device_id).map_err(|e| e.to_string())?;
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

fn sas_display_json(sas: &SasDisplay) -> serde_json::Value {
    serde_json::json!({
        "sas_version": sas.version,
        "sas_words": sas.words,
        "sas_word_list": sas.word_list,
    })
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
    ensure_handle_supports_signature_version_floor(handle).await?;
    guard_ceremony_in_progress(handle, CeremonyGuardKind::StartJoiner)?;
    let pairing_relay = build_pairing_relay(handle)?;

    let inner = handle.inner.lock().await;
    let pairing = PairingService::new(inner.secure_store().clone());
    drop(inner);

    let (ceremony, token) = match pairing
        .start_bootstrap_pairing(&pairing_relay, &handle.relay_url)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            return Err(encode_handle_core_error(handle, "start_bootstrap_pairing", error).await);
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

/// Cancel any in-progress relay-based PQ pairing ceremony.
///
/// This clears both in-memory ceremony slots, removes any pending joiner
/// bootstrap identity material, and never sends credentials. If a rendezvous id
/// was already allocated, the relay session is deleted on a best-effort basis
/// after local state is cleared. Relay cleanup errors are intentionally logged
/// and ignored so cancellation remains idempotent and can recover from
/// partially connected/offline states.
pub async fn cancel_pairing_ceremony(handle: &PrismSyncHandle) -> Result<(), String> {
    let mut rendezvous_ids = Vec::new();

    if let Some(ceremony) = handle
        .joiner_ceremony
        .lock()
        .map_err(|e| format!("failed to lock joiner_ceremony: {e}"))?
        .take()
    {
        rendezvous_ids.push(ceremony.rendezvous_id_hex());
    }

    if let Some(ceremony) = handle
        .initiator_ceremony
        .lock()
        .map_err(|e| format!("failed to lock initiator_ceremony: {e}"))?
        .take()
    {
        rendezvous_ids.push(ceremony.rendezvous_id_hex());
    }

    rendezvous_ids.sort();
    rendezvous_ids.dedup();

    {
        let inner = handle.inner.lock().await;
        let secure_store = inner.secure_store();
        if let Err(error) = secure_store.delete("pending_device_secret") {
            tracing::debug!(
                "[prism_sync_ffi] pairing cancel could not delete pending_device_secret: {error}"
            );
        }
        if let Err(error) = secure_store.delete("pending_device_id") {
            tracing::debug!(
                "[prism_sync_ffi] pairing cancel could not delete pending_device_id: {error}"
            );
        }
    }

    if rendezvous_ids.is_empty() {
        return Ok(());
    }

    let pairing_relay = match build_pairing_relay(handle) {
        Ok(pairing_relay) => pairing_relay,
        Err(error) => {
            tracing::debug!(
                "[prism_sync_ffi] skipping best-effort pairing cancel relay cleanup: {error}"
            );
            return Ok(());
        }
    };

    for rendezvous_id in rendezvous_ids {
        let cleanup = pairing_relay.delete_session(&rendezvous_id);
        match tokio::time::timeout(std::time::Duration::from_secs(2), cleanup).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::debug!(
                "[prism_sync_ffi] best-effort pairing cancel relay cleanup failed for {rendezvous_id}: {error}"
            ),
            Err(_) => tracing::debug!(
                "[prism_sync_ffi] best-effort pairing cancel relay cleanup timed out for {rendezvous_id}"
            ),
        }
    }

    Ok(())
}

/// Wait for the initiator's PairingInit and return the SAS display codes.
///
/// Polls the relay for the PairingInit slot until it arrives, then derives
/// the shared secret and SAS phrase. Returns JSON:
///
/// ```json
/// {
///   "sas_version": 2,
///   "sas_words": "apple banana cherry delta ember",
///   "sas_word_list": ["apple", "banana", "cherry", "delta", "ember"]
/// }
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

    let result = sas_display_json(&sas);
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
    password: Vec<u8>,
) -> Result<String, String> {
    let password = zeroize::Zeroizing::new(password);
    let password_text = secret_text("password", &password)?;

    ensure_handle_supports_signature_version_floor(handle).await?;
    guard_ceremony_in_progress(handle, CeremonyGuardKind::CompleteJoiner)?;
    let pairing_relay = build_pairing_relay(handle)?;

    // Take the ceremony out — it won't be needed again after completion
    let ceremony = handle
        .joiner_ceremony
        .lock()
        .map_err(|e| format!("failed to lock joiner_ceremony: {e}"))?
        .take()
        .ok_or_else(|| "no joiner ceremony in progress — call get_joiner_sas first".to_string())?;

    let relay_url = handle.relay_url.clone();
    let allow_insecure = handle.allow_insecure;

    let (pairing, fallback_registration_token) = {
        let inner = handle.inner.lock().await;
        let fallback_registration_token = inner
            .secure_store()
            .get("registration_token")
            .map_err(|e| e.to_string())?
            .map(String::from_utf8)
            .transpose()
            .map_err(|e| format!("invalid registration token: {e}"))?
            .filter(|token| !token.is_empty());
        (PairingService::new(inner.secure_store().clone()), fallback_registration_token)
    };

    // complete_bootstrap_join handles: confirmation MAC, wait for credentials,
    // decrypt, register, persist, post joiner bundle
    let (key_hierarchy, registry_snapshot) = match pairing
        .complete_bootstrap_join(
            &ceremony,
            &pairing_relay,
            &[],
            password_text,
            |sync_id, device_id, registration_token| {
                // Fresh-install onboarding can seed a manual token locally
                // before pairing starts. Use it when the inviter bundle does
                // not already carry a relay registration token.
                let registration_token = registration_token
                    .filter(|token| !token.is_empty())
                    .map(str::to_string)
                    .or_else(|| fallback_registration_token.clone());
                build_relay(
                    &relay_url,
                    sync_id,
                    device_id,
                    "", // no session token yet — registration will return one
                    None,
                    0,
                    allow_insecure,
                    registration_token,
                )
                .map(|r| r as Arc<dyn SyncRelay>)
                .map_err(prism_sync_core::CoreError::Engine)
            },
        )
        .await
    {
        Ok(value) => value,
        Err(error) => {
            return Err(encode_handle_core_error(handle, "complete_bootstrap_join", error).await);
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

    // Seed local metadata before the snapshot import runs. `import_snapshot`
    // preserves an existing `local_device_id`, but falls back to the snapshot's
    // metadata when no row exists. For a joiner that fallback is the inviter's
    // device id, so create/repair the row here with this device's identity.
    let device_id = inner
        .secure_store()
        .get("device_id")
        .map_err(|e| e.to_string())?
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or("device_id not found after bootstrap join")?;
    let current_epoch = i32::try_from(registry_snapshot.current_epoch).map_err(|_| {
        format!(
            "registry current_epoch {} exceeds local storage range",
            registry_snapshot.current_epoch
        )
    })?;
    ensure_local_sync_metadata(inner.storage().as_ref(), &sync_id, &device_id, current_epoch)?;

    // Restore runtime keys so configureEngine etc. work
    let dek = key_hierarchy.dek().map_err(|e| e.to_string())?;
    let device_secret_bytes = inner
        .secure_store()
        .get("device_secret")
        .map_err(|e| e.to_string())?
        .ok_or("device_secret not found after join")?;
    inner.restore_runtime_keys(dek, &device_secret_bytes).map_err(|e| e.to_string())?;

    // Restore epoch keys into the live key hierarchy. Bootstrap join may
    // catch up through multiple epochs before returning, while a bundle that
    // starts at epoch > 1 may only carry the current epoch plus newly recovered
    // keys. Load every stored key, but require the current epoch key to exist.
    let epoch_val = inner
        .secure_store()
        .get("epoch")
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    for epoch in 1..=epoch_val {
        let key_name = format!("epoch_key_{}", epoch);
        match inner.secure_store().get(&key_name) {
            Ok(Some(stored)) => match BASE64.decode(&stored) {
                Ok(decoded) if decoded.len() == 32 => {
                    inner
                        .key_hierarchy_mut()
                        .store_epoch_key(epoch, zeroize::Zeroizing::new(decoded));
                }
                Ok(decoded) => {
                    return Err(format!(
                        "epoch_key_{} has wrong length ({}, expected 32)",
                        epoch,
                        decoded.len(),
                    ));
                }
                Err(e) => {
                    return Err(format!("epoch_key_{} base64 decode failed: {e}", epoch,));
                }
            },
            Ok(None) => {
                if epoch == epoch_val {
                    return Err(format!("epoch_key_{} not found in secure store", epoch,));
                }
            }
            Err(e) => {
                return Err(format!("Failed to read epoch_key_{}: {e}", epoch));
            }
        }
    }

    let result = serde_json::json!({ "sync_id": sync_id });
    Ok(result.to_string())
}

fn ensure_local_sync_metadata(
    storage: &dyn SyncStorage,
    sync_id: &str,
    device_id: &str,
    current_epoch: i32,
) -> Result<(), String> {
    let now = chrono::Utc::now();
    let metadata = match storage.get_sync_metadata(sync_id).map_err(|e| e.to_string())? {
        Some(mut metadata) => {
            metadata.local_device_id = device_id.to_string();
            metadata.current_epoch = metadata.current_epoch.max(current_epoch);
            metadata.updated_at = now;
            metadata
        }
        None => SyncMetadata {
            sync_id: sync_id.to_string(),
            local_device_id: device_id.to_string(),
            current_epoch,
            last_pulled_server_seq: 0,
            last_pushed_at: None,
            last_successful_sync_at: None,
            registered_at: Some(now),
            needs_rekey: false,
            last_imported_registry_version: None,
            created_at: now,
            updated_at: now,
        },
    };
    let mut tx = storage.begin_tx().map_err(|e| e.to_string())?;
    tx.upsert_sync_metadata(&metadata).map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(())
}

/// Start the initiator side of the relay-based PQ pairing ceremony.
///
/// Parses the rendezvous token from QR/deep-link bytes, fetches the joiner's
/// bootstrap, verifies the commitment, and posts the PairingInit. Returns
/// the SAS display codes for user verification plus the joiner's device_id:
///
/// ```json
/// {
///   "sas_version": 2,
///   "sas_words": "apple banana cherry delta ember",
///   "sas_word_list": ["apple", "banana", "cherry", "delta", "ember"],
///   "joiner_device_id": "c3d4..."
/// }
/// ```
///
/// `joiner_device_id` is captured from the bootstrap record fetched at
/// ceremony start and is stable for the remainder of the ceremony. The Dart
/// caller threads it through to `uploadPairingSnapshot(..., forDeviceId:)`
/// so the joiner can later `DELETE /v1/sync/{id}/snapshot` under its own
/// identity.
///
/// The `InitiatorCeremony` state is stored in the handle for the subsequent
/// call to [`complete_initiator_ceremony`].
pub async fn start_initiator_ceremony(
    handle: &PrismSyncHandle,
    token_bytes: Vec<u8>,
) -> Result<String, String> {
    ensure_handle_supports_signature_version_floor(handle).await?;
    guard_ceremony_in_progress(handle, CeremonyGuardKind::StartInitiator)?;
    let token = RendezvousToken::from_bytes(&token_bytes)
        .ok_or_else(|| "failed to parse RendezvousToken from bytes".to_string())?;

    let pairing_relay = build_pairing_relay(handle)?;

    let inner = handle.inner.lock().await;
    let secure_store = inner.secure_store().clone();
    drop(inner);

    let pairing = PairingService::new(secure_store);
    let (ceremony, sas) = match pairing.start_bootstrap_initiator(token, &pairing_relay).await {
        Ok(value) => value,
        Err(error) => {
            return Err(encode_handle_core_error(handle, "start_bootstrap_initiator", error).await);
        }
    };

    let joiner_device_id = ceremony.joiner_device_id().to_string();

    // Store ceremony state for complete_initiator_ceremony
    handle
        .initiator_ceremony
        .lock()
        .map_err(|e| format!("failed to lock initiator_ceremony: {e}"))?
        .replace(ceremony);

    let mut result = sas_display_json(&sas);
    result["joiner_device_id"] = serde_json::Value::String(joiner_device_id);
    Ok(result.to_string())
}

/// Complete the initiator side of the ceremony after SAS verification.
///
/// Waits for the joiner's confirmation MAC, verifies it, then sends
/// encrypted credentials to the joiner. Returns `"ok"` on success.
///
/// `mnemonic` is the inviter's 12-word BIP39 recovery phrase, typed by the
/// user from their offline backup. The recovery phrase is never persisted in
/// the secure store, so the caller must provide it here — it is needed to
/// assemble the credential bundle shipped to the joiner so the joiner can
/// derive the MEK and unlock the wrapped DEK.
///
/// Must be called after [`start_initiator_ceremony`] and user SAS verification.
pub async fn complete_initiator_ceremony(
    handle: &PrismSyncHandle,
    password: Vec<u8>,
    mnemonic: Vec<u8>,
) -> Result<String, String> {
    let password = zeroize::Zeroizing::new(password);
    let mnemonic = zeroize::Zeroizing::new(mnemonic);
    let password_text = secret_text("password", &password)?;
    let mnemonic_text = secret_text("mnemonic", &mnemonic)?;

    ensure_handle_supports_signature_version_floor(handle).await?;
    guard_ceremony_in_progress(handle, CeremonyGuardKind::CompleteInitiator)?;
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
    let device_secret_bytes =
        inner.secure_store().get("device_secret").map_err(|e| e.to_string())?;
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

    let pairing = PairingService::new(secure_store);
    if let Err(error) = pairing
        .complete_bootstrap_initiator(
            &ceremony,
            &pairing_relay,
            password_text,
            mnemonic_text,
            relay.as_ref(),
        )
        .await
    {
        return Err(encode_handle_core_error(handle, "complete_bootstrap_initiator", error).await);
    }

    // Align the live client with the post-rekey epoch. complete_bootstrap_initiator
    // calls EpochManager::post_rekey which writes `epoch` and `epoch_key_{new}`
    // to secure_store, but the pairing service does not own the PrismSync
    // client, so self.epoch, the op_emitter, sync_metadata.current_epoch, and
    // key_hierarchy stay at the pre-rekey value. Leaving them stale breaks the
    // next pairing attempt: upload_pairing_snapshot reads self.epoch (old) while
    // complete_bootstrap_initiator reads secure_store.epoch (new) for the
    // credential bundle, so the joiner receives the new epoch key but the
    // snapshot is encrypted with the old one, and bootstrap_from_snapshot fails.
    // Mirror what commit_epoch_rotation does: load the new epoch key into the
    // live key hierarchy, update sync_metadata, and advance the runtime epoch.
    {
        let mut inner = handle.inner.lock().await;
        let secure_store = inner.secure_store().clone();

        let new_epoch_str = secure_store
            .get("epoch")
            .map_err(|e| format!("read epoch after pairing: {e}"))?
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or_else(|| "epoch missing from secure store after pairing".to_string())?;
        let new_epoch: u32 =
            new_epoch_str.parse().map_err(|e| format!("invalid epoch in secure store: {e}"))?;

        let current_client_epoch = inner.epoch().unwrap_or(0);
        if (new_epoch as i32) > current_client_epoch {
            // Load the rekey epoch key from secure_store into the live key
            // hierarchy. The pairing service base64-encodes it (see
            // pairing/service.rs post_rekey path); fall back to raw bytes to
            // match the tolerant decode in restore_runtime_keys.
            let key_name = format!("epoch_key_{new_epoch}");
            if let Some(stored_bytes) =
                secure_store.get(&key_name).map_err(|e| format!("read {key_name}: {e}"))?
            {
                let key_bytes = if let Ok(decoded) = BASE64.decode(&stored_bytes) {
                    if decoded.len() == 32 {
                        decoded
                    } else {
                        stored_bytes
                    }
                } else {
                    stored_bytes
                };
                if key_bytes.len() != 32 {
                    return Err(format!(
                        "{key_name} has wrong length ({}, expected 32)",
                        key_bytes.len()
                    ));
                }
                inner
                    .key_hierarchy_mut()
                    .store_epoch_key(new_epoch, zeroize::Zeroizing::new(key_bytes));
            } else {
                return Err(format!("{key_name} missing from secure store after post_rekey"));
            }

            // Update sync_metadata.current_epoch so configure_engine on the
            // next launch reads the same epoch we're advancing to. Without
            // this, restart drops self.epoch back to the pre-rekey value
            // (configure_engine prefers sync_metadata over secure_store).
            let ne = new_epoch as i32;
            ensure_local_sync_metadata(inner.storage().as_ref(), &sync_id, &device_id, ne)
                .map_err(|e| format!("update sync_metadata.current_epoch: {e}"))?;

            inner.advance_epoch(new_epoch as i32);
        }
    }

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
    let current_record = {
        let storage = storage.clone();
        tokio::task::spawn_blocking(move || storage.get_device_record(&sid, &did))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("device {device_id} not in local registry"))?
    };

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
            let synced_ml_dsa =
                device_secret.ml_dsa_65_keypair_v(&device_id, relay_gen).map_err(|e| {
                    format!("failed to derive ML-DSA key at relay gen {relay_gen}: {e}")
                })?;
            set_local_device_ml_dsa_state(
                storage.clone(),
                &sync_id,
                &device_id,
                synced_ml_dsa.public_key_bytes(),
                relay_gen,
            )
            .await?;

            current_gen = relay_gen;
        }
    }

    let new_gen = current_gen + 1;
    let last_imported_registry_version = {
        let sid = sync_id.clone();
        let storage = storage.clone();
        tokio::task::spawn_blocking(move || storage.get_sync_metadata(&sid))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?
            .and_then(|meta| meta.last_imported_registry_version)
    };
    let current_epoch = {
        let sid = sync_id.clone();
        let storage = storage.clone();
        tokio::task::spawn_blocking(move || storage.get_sync_metadata(&sid))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?
            .map(|meta| meta.current_epoch.max(0) as u32)
            .unwrap_or(0)
    };
    let relay_registry_version =
        relay.get_signed_registry().await.ok().flatten().map(|response| response.registry_version);
    let next_registry_version = next_registry_snapshot_version(
        relay_registry_version,
        last_imported_registry_version,
        current_gen,
    );

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

    // 3b. Build signed registry snapshot for the relay to store
    //
    // Sign with the OLD ML-DSA key — that's the key peers have pinned.
    // Include the NEW ML-DSA key for the rotating device in the snapshot.
    let signed_snapshot = {
        let (storage, epoch_key_hashes) = {
            let inner = handle.inner.lock().await;
            (inner.storage().clone(), build_epoch_key_hashes_for_registry(inner.key_hierarchy())?)
        };
        if !epoch_key_hashes.contains_key(&current_epoch) {
            return Err(format!(
                "signed registry epoch_key_hashes missing current_epoch {current_epoch}"
            ));
        }
        let sid = sync_id.clone();
        let did = device_id.clone();
        let new_pk_for_snapshot = new_pk.clone();

        let device_records = tokio::task::spawn_blocking(move || storage.list_device_records(&sid))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;

        // Build snapshot entries with the rotating device's NEW key
        let entries: Vec<RegistrySnapshotEntry> = device_records
            .iter()
            .map(|r| {
                let (ml_dsa_pk, ml_dsa_gen) = if r.device_id == did {
                    // Use the NEW key for the rotating device
                    (new_pk_for_snapshot.clone(), new_gen as u32)
                } else {
                    (r.ml_dsa_65_public_key.clone(), r.ml_dsa_key_generation)
                };
                RegistrySnapshotEntry {
                    sync_id: r.sync_id.clone(),
                    device_id: r.device_id.clone(),
                    ed25519_public_key: r.ed25519_public_key.clone(),
                    x25519_public_key: r.x25519_public_key.clone(),
                    ml_dsa_65_public_key: ml_dsa_pk,
                    ml_kem_768_public_key: r.ml_kem_768_public_key.clone(),
                    x_wing_public_key: r.x_wing_public_key.clone(),
                    status: r.status.clone(),
                    ml_dsa_key_generation: ml_dsa_gen,
                }
            })
            .collect();

        let snapshot = SignedRegistrySnapshot::new_with_epoch_binding(
            entries,
            next_registry_version,
            current_epoch,
            epoch_key_hashes,
        );

        // Sign with Ed25519 (unchanged) + OLD ML-DSA key (what peers have pinned)
        let ed25519_key = device_secret
            .ed25519_keypair(&device_id)
            .map_err(|e| format!("failed to derive Ed25519 key for snapshot: {e}"))?;
        let old_ml_dsa_key = device_secret
            .ml_dsa_65_keypair_v(&device_id, current_gen)
            .map_err(|e| format!("failed to derive old ML-DSA key for snapshot: {e}"))?;

        snapshot.sign_hybrid(&ed25519_key, &old_ml_dsa_key)
    };

    // 4. Submit rotation to relay
    let final_generation = match relay
        .rotate_ml_dsa(&device_id, &new_pk, new_gen, &proof, Some(&signed_snapshot))
        .await
    {
        Ok(response) => {
            let storage = storage.clone();
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
            response.ml_dsa_key_generation
        }
        Err(error) => {
            if error.is_retryable()
                && reconcile_ml_dsa_rotation_commit(
                    storage.clone(),
                    relay.as_ref(),
                    &sync_id,
                    &device_id,
                    new_gen,
                    &new_pk,
                )
                .await
            {
                tracing::info!(
                    device_id = %redacted_identifier_for_log(&device_id),
                    generation = new_gen,
                    "rotate_ml_dsa_key: reconciled ambiguous relay failure after remote commit"
                );
                new_gen
            } else {
                return Err(format_handle_relay_error(handle, "rotate_ml_dsa", error).await);
            }
        }
    };

    // After successful rotation, refresh the cached ML-DSA signing key in PrismSync
    // so that subsequent hybrid batch signing uses the new key without requiring
    // a full configure_engine call.
    let mut inner = handle.inner.lock().await;
    inner
        .refresh_ml_dsa_key(final_generation)
        .map_err(|e| format!("Failed to refresh ML-DSA signing key: {e}"))?;

    // 6. Return result as JSON
    let result = serde_json::json!({
        "ml_dsa_key_generation": final_generation,
        "device_id": device_id,
    });
    Ok(result.to_string())
}

async fn set_local_device_ml_dsa_state(
    storage: Arc<dyn SyncStorage>,
    sync_id: &str,
    device_id: &str,
    public_key: Vec<u8>,
    generation: u32,
) -> Result<(), String> {
    let sid = sync_id.to_string();
    let did = device_id.to_string();
    tokio::task::spawn_blocking(move || {
        let mut record = storage.get_device_record(&sid, &did)?.ok_or_else(|| {
            prism_sync_core::error::CoreError::Storage(
                prism_sync_core::storage::StorageError::Logic("device not in registry".into()),
            )
        })?;
        record.ml_dsa_65_public_key = public_key;
        record.ml_dsa_key_generation = generation;
        let mut tx = storage.begin_tx()?;
        tx.upsert_device_record(&record)?;
        tx.commit()
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())
}

async fn import_signed_registry(
    storage: Arc<dyn SyncStorage>,
    sync_id: &str,
    artifact_blob: Vec<u8>,
) -> Result<i64, String> {
    let sid = sync_id.to_string();
    let last_imported_version = {
        let storage = storage.clone();
        tokio::task::spawn_blocking(move || storage.get_sync_metadata(&sid))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?
            .and_then(|meta| meta.last_imported_registry_version)
    };

    let sid = sync_id.to_string();
    let signed_version = {
        let storage = storage.clone();
        tokio::task::spawn_blocking(move || {
            DeviceRegistryManager::verify_and_import_signed_registry(
                storage.as_ref(),
                &sid,
                &artifact_blob,
                last_imported_version,
            )
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?
    };

    let sid = sync_id.to_string();
    let storage = storage.clone();
    tokio::task::spawn_blocking(move || {
        let mut tx = storage.begin_tx()?;
        tx.update_last_imported_registry_version(&sid, signed_version)?;
        tx.commit()
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;

    Ok(signed_version)
}

async fn reconcile_ml_dsa_rotation_commit(
    storage: Arc<dyn SyncStorage>,
    relay: &dyn SyncRelay,
    sync_id: &str,
    device_id: &str,
    expected_new_gen: u32,
    expected_new_pk: &[u8],
) -> bool {
    let redacted_device_id = redacted_identifier_for_log(device_id);
    let relay_devices = match relay.list_devices().await {
        Ok(devices) => devices,
        Err(error) => {
            tracing::warn!(
                device_id = %redacted_device_id,
                generation = expected_new_gen,
                error = %redact_display(&error),
                "rotate_ml_dsa_key: reconciliation failed to list relay devices"
            );
            return false;
        }
    };

    let Some(relay_self) = relay_devices.iter().find(|device| device.device_id == device_id) else {
        tracing::warn!(
            device_id = %redacted_device_id,
            generation = expected_new_gen,
            "rotate_ml_dsa_key: reconciliation could not find local device on relay"
        );
        return false;
    };

    if relay_self.ml_dsa_key_generation != expected_new_gen {
        tracing::info!(
            device_id = %redacted_device_id,
            expected_generation = expected_new_gen,
            relay_generation = relay_self.ml_dsa_key_generation,
            "rotate_ml_dsa_key: reconciliation did not prove relay advanced to target generation"
        );
        return false;
    }

    let signed_registry = match relay.get_signed_registry().await {
        Ok(Some(response)) => response,
        Ok(None) => {
            tracing::info!(
                device_id = %redacted_device_id,
                generation = expected_new_gen,
                "rotate_ml_dsa_key: reconciliation found no signed registry artifact"
            );
            return false;
        }
        Err(error) => {
            tracing::warn!(
                device_id = %redacted_device_id,
                generation = expected_new_gen,
                error = %redact_display(&error),
                "rotate_ml_dsa_key: reconciliation failed to fetch signed registry"
            );
            return false;
        }
    };

    if let Err(error) =
        import_signed_registry(storage.clone(), sync_id, signed_registry.artifact_blob).await
    {
        tracing::warn!(
            device_id = %redacted_device_id,
            generation = expected_new_gen,
            error = %redact_sensitive_message(&error),
            "rotate_ml_dsa_key: reconciliation failed to import signed registry"
        );
        return false;
    }

    let sid = sync_id.to_string();
    let did = device_id.to_string();
    match tokio::task::spawn_blocking(move || storage.get_device_record(&sid, &did)).await {
        Ok(Ok(Some(record))) => {
            if record.ml_dsa_key_generation == expected_new_gen
                && record.ml_dsa_65_public_key == expected_new_pk
            {
                true
            } else {
                tracing::info!(
                    device_id = %redacted_device_id,
                    expected_generation = expected_new_gen,
                    local_generation = record.ml_dsa_key_generation,
                    "rotate_ml_dsa_key: reconciliation imported registry but local record did not match expected key state"
                );
                false
            }
        }
        Ok(Ok(None)) => {
            tracing::warn!(
                device_id = %redacted_device_id,
                generation = expected_new_gen,
                "rotate_ml_dsa_key: reconciliation could not find local device after registry import"
            );
            false
        }
        Ok(Err(error)) => {
            tracing::warn!(
                device_id = %redacted_device_id,
                generation = expected_new_gen,
                error = %redact_display(&error),
                "rotate_ml_dsa_key: reconciliation failed to load local device after registry import"
            );
            false
        }
        Err(error) => {
            tracing::warn!(
                device_id = %redacted_device_id,
                generation = expected_new_gen,
                error = %redact_display(&error),
                "rotate_ml_dsa_key: reconciliation device lookup task failed"
            );
            false
        }
    }
}

fn next_registry_snapshot_version(
    relay_registry_version: Option<i64>,
    last_imported_registry_version: Option<i64>,
    current_ml_dsa_generation: u32,
) -> i64 {
    // Registry version tracks global device-registry state, not this device's
    // ML-DSA generation. Prefer the newest registry version we know about, and
    // only use the local generation as a fallback monotonic floor when no
    // signed registry artifact has been observed yet.
    [
        relay_registry_version,
        last_imported_registry_version,
        Some(i64::from(current_ml_dsa_generation)),
    ]
    .into_iter()
    .flatten()
    .max()
    .unwrap_or(0)
        + 1
}

fn build_epoch_key_hashes_for_registry(
    key_hierarchy: &prism_sync_crypto::KeyHierarchy,
) -> Result<BTreeMap<u32, [u8; 32]>, String> {
    let entries = key_hierarchy
        .epoch_keys_iter()
        .map_err(|e| format!("failed to enumerate epoch keys for signed registry: {e}"))?;
    let mut epoch_key_hashes = BTreeMap::new();
    for (epoch, key) in entries {
        epoch_key_hashes.insert(epoch, compute_epoch_key_hash(key));
    }
    Ok(epoch_key_hashes)
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
    use chrono::Utc;
    use prism_sync_core::relay::{DeviceInfo, MockRelay, SignedRegistryResponse};
    use prism_sync_core::secure_store::SecureStore;
    use prism_sync_core::storage::RusqliteSyncStorage;
    use prism_sync_core::{DeviceRecord, SyncMetadata, SyncStorage};
    use std::sync::Arc;

    #[test]
    fn min_signature_version_omitted_response_ratchets_to_source_floor() {
        let store = MemorySecureStore::new();

        ratchet_min_signature_version_floor(&store, None).unwrap();

        assert_eq!(
            decode_optional_u8(&store, MIN_SIGNATURE_VERSION_FLOOR_KEY).unwrap(),
            Some(SIGNATURE_VERSION_SOURCE_FLOOR)
        );
    }

    #[test]
    fn min_signature_version_omission_does_not_lower_existing_floor() {
        let store = MemorySecureStore::new();
        store.set(MIN_SIGNATURE_VERSION_FLOOR_KEY, b"4").unwrap();

        ratchet_min_signature_version_floor(&store, None).unwrap();

        assert_eq!(decode_optional_u8(&store, MIN_SIGNATURE_VERSION_FLOOR_KEY).unwrap(), Some(4));
    }

    #[test]
    fn min_signature_version_above_app_support_fails_update_required() {
        let store = MemorySecureStore::new();
        store.set(MIN_SIGNATURE_VERSION_FLOOR_KEY, b"4").unwrap();

        let err = ensure_app_supports_stored_floor(&store).unwrap_err();

        assert!(err.contains("supports up to 3"), "unexpected error: {err}");
        assert!(err.contains("Please update"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn min_signature_version_above_app_support_blocks_create_sync_group() {
        let handle = create_prism_sync(
            "https://localhost:8080".into(),
            ":memory:".into(),
            false,
            String::new(),
            None,
        )
        .expect("create_prism_sync");
        seed_secure_store(
            &handle,
            HashMap::from([(MIN_SIGNATURE_VERSION_FLOOR_KEY.to_string(), b"4".to_vec())]),
        )
        .await
        .expect("seed secure store");

        let err = create_sync_group(
            &handle,
            b"pw".to_vec(),
            "https://relay.example.com".to_string(),
            None,
        )
        .await
        .unwrap_err();

        assert!(err.contains("supports up to 3"), "unexpected error: {err}");
        assert!(err.contains("Please update"), "unexpected error: {err}");
    }

    #[test]
    fn min_signature_version_wire_floor_rejects_v2_without_stored_floor() {
        let store = MemorySecureStore::new();

        let err = enforce_wire_signature_floor(&store, 0x02).unwrap_err();

        assert!(err.contains("below required floor 3"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn min_signature_version_seed_secure_store_ratchets_low_floor() {
        let handle = create_prism_sync(
            "https://localhost:8080".into(),
            ":memory:".into(),
            false,
            String::new(),
            None,
        )
        .expect("create_prism_sync");

        seed_secure_store(
            &handle,
            HashMap::from([(MIN_SIGNATURE_VERSION_FLOOR_KEY.to_string(), b"2".to_vec())]),
        )
        .await
        .expect("seed secure store");

        let inner = handle.inner.lock().await;
        assert_eq!(
            decode_optional_u8(inner.secure_store().as_ref(), MIN_SIGNATURE_VERSION_FLOOR_KEY)
                .unwrap(),
            Some(SIGNATURE_VERSION_SOURCE_FLOOR)
        );
    }

    #[test]
    fn parse_schema_json_accepts_real_type() {
        let schema =
            parse_schema_json(r#"{"entities":{"settings":{"fields":{"score":"Real"}}}}"#).unwrap();

        let field = schema.entity("settings").unwrap().field_by_name("score").unwrap();
        assert_eq!(field.sync_type, prism_sync_core::schema::SyncType::Real);
    }

    #[test]
    fn parse_fields_json_accepts_real_numbers() {
        let fields = parse_fields_json(r#"{"score":8.5}"#).unwrap();

        assert_eq!(fields.get("score"), Some(&SyncValue::Real(8.5)));
    }

    #[test]
    fn parse_fields_json_for_schema_coerces_wire_strings_to_typed_values() {
        let schema = parse_schema_json(
            r#"{"entities":{"settings":{"fields":{"score":"Real","created_at":"DateTime","avatar":"Blob"}}}}"#,
        )
        .unwrap();

        let fields = parse_fields_json_for_schema(
            r#"{"score":8,"created_at":"2026-04-27T12:34:56.789Z","avatar":"AAECAw=="}"#,
            &schema,
            "settings",
        )
        .unwrap();

        assert_eq!(fields.get("score"), Some(&SyncValue::Real(8.0)));
        assert!(matches!(fields.get("created_at"), Some(SyncValue::DateTime(_))));
        assert_eq!(fields.get("avatar"), Some(&SyncValue::Blob(vec![0, 1, 2, 3])));
    }

    #[test]
    fn encoded_real_value_round_trips_to_json_number() {
        assert_eq!(encoded_value_to_json("8.5"), serde_json::json!(8.5));
    }

    fn make_device_record(
        sync_id: &str,
        device_id: &str,
        secret: &DeviceSecret,
        generation: u32,
    ) -> DeviceRecord {
        DeviceRecord {
            sync_id: sync_id.to_string(),
            device_id: device_id.to_string(),
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
            ml_dsa_65_public_key: secret
                .ml_dsa_65_keypair_v(device_id, generation)
                .unwrap()
                .public_key_bytes(),
            ml_kem_768_public_key: secret.ml_kem_768_keypair(device_id).unwrap().public_key_bytes(),
            x_wing_public_key: secret.xwing_keypair(device_id).unwrap().encapsulation_key_bytes(),
            status: "active".to_string(),
            registered_at: Utc::now(),
            revoked_at: None,
            ml_dsa_key_generation: generation,
        }
    }

    fn make_device_info(
        sync_id: &str,
        device_id: &str,
        secret: &DeviceSecret,
        generation: u32,
    ) -> DeviceInfo {
        let record = make_device_record(sync_id, device_id, secret, generation);
        DeviceInfo {
            device_id: record.device_id,
            epoch: 0,
            status: record.status,
            ed25519_public_key: record.ed25519_public_key,
            x25519_public_key: record.x25519_public_key,
            ml_dsa_65_public_key: record.ml_dsa_65_public_key,
            ml_kem_768_public_key: record.ml_kem_768_public_key,
            x_wing_public_key: record.x_wing_public_key,
            permission: None,
            ml_dsa_key_generation: record.ml_dsa_key_generation,
        }
    }

    fn seed_rotation_storage(
        storage: &RusqliteSyncStorage,
        sync_id: &str,
        device_id: &str,
        record: &DeviceRecord,
        last_imported_registry_version: Option<i64>,
    ) {
        let now = Utc::now();
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_sync_metadata(&SyncMetadata {
            sync_id: sync_id.to_string(),
            local_device_id: device_id.to_string(),
            current_epoch: 0,
            last_pulled_server_seq: 0,
            last_pushed_at: None,
            last_successful_sync_at: None,
            registered_at: None,
            needs_rekey: false,
            last_imported_registry_version,
            created_at: now,
            updated_at: now,
        })
        .unwrap();
        tx.upsert_device_record(record).unwrap();
        tx.commit().unwrap();
    }

    fn make_signed_registry_artifact(
        sync_id: &str,
        device_id: &str,
        device_secret: &DeviceSecret,
        new_generation: u32,
        registry_version: i64,
    ) -> Vec<u8> {
        let mut epoch_key_hashes = BTreeMap::new();
        epoch_key_hashes.insert(0, compute_epoch_key_hash(&[0x42; 32]));
        let ed25519_key = device_secret.ed25519_keypair(device_id).unwrap();
        let old_ml_dsa_key =
            device_secret.ml_dsa_65_keypair_v(device_id, new_generation - 1).unwrap();
        let new_record = make_device_record(sync_id, device_id, device_secret, new_generation);
        SignedRegistrySnapshot::new_with_epoch_binding(
            vec![RegistrySnapshotEntry {
                sync_id: sync_id.to_string(),
                device_id: device_id.to_string(),
                ed25519_public_key: new_record.ed25519_public_key,
                x25519_public_key: new_record.x25519_public_key,
                ml_dsa_65_public_key: new_record.ml_dsa_65_public_key,
                ml_kem_768_public_key: new_record.ml_kem_768_public_key,
                x_wing_public_key: new_record.x_wing_public_key,
                status: "active".to_string(),
                ml_dsa_key_generation: new_generation,
            }],
            registry_version,
            0,
            epoch_key_hashes,
        )
        .sign_hybrid(&ed25519_key, &old_ml_dsa_key)
    }

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
                .decode(unwrapped_json["unwrapped_keys"]["read:members"].as_str().unwrap())
                .unwrap(),
            vec![0x11; 32]
        );
        assert_eq!(
            BASE64
                .decode(unwrapped_json["unwrapped_keys"]["read:fronting"].as_str().unwrap())
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
        store.set(SHARING_ID_CACHE_KEY, b"feedfacefeedfacefeedfacefeedface").unwrap();

        let err = sharing_rotation_needed(&store, "deadbeefdeadbeefdeadbeefdeadbeef").unwrap_err();
        assert!(err.contains("bound to a different sharing_id"));
    }

    #[test]
    fn sharing_rotation_needed_detects_cached_active_sharing() {
        let store = MemorySecureStore::new();
        let sharing_id = "feedfacefeedfacefeedfacefeedface";
        store.set(SHARING_ID_CACHE_KEY, sharing_id.as_bytes()).unwrap();

        assert!(sharing_rotation_needed(&store, sharing_id).unwrap());
    }

    #[test]
    fn sharing_rotation_needed_detects_persisted_prekey_state_without_cache() {
        let store = MemorySecureStore::new();
        store.set("sharing_prekey_store", br#"{"current":null,"previous":[]}"#).unwrap();

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
            backoff_secs = if backoff_secs == 0 { 30 } else { (backoff_secs * 2).min(300) };
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
            backoff_secs = if backoff_secs == 0 { 30 } else { (backoff_secs * 2).min(300) };
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
        backoff_secs = if backoff_secs == 0 { 30 } else { (backoff_secs * 2).min(300) };
        assert_eq!(backoff_secs, 30);
    }

    #[test]
    fn cumulative_backoff_exceeds_max() {
        let mut backoff_secs: u64 = 0;
        let mut cumulative_backoff_secs: u64 = 0;
        let mut attempts = 0u32;
        const MAX_CUMULATIVE_SECS: u64 = 600;

        loop {
            backoff_secs = if backoff_secs == 0 { 30 } else { (backoff_secs * 2).min(300) };
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
        let event =
            prism_sync_core::events::SyncEvent::BackoffScheduled { attempt: 3, delay_secs: 120 };
        let json = sync_event_to_json(&event);
        assert_eq!(json["type"], "BackoffScheduled");
        assert_eq!(json["attempt"], 3);
        assert_eq!(json["delay_secs"], 120);
    }

    #[test]
    fn lock_or_recover_handles_poisoned_mutex() {
        let mutex = std::sync::Arc::new(std::sync::Mutex::new(42));
        let m = mutex.clone();
        let _ = std::thread::spawn(move || {
            let _guard = m.lock().unwrap();
            panic!("intentional poisoning");
        })
        .join();

        assert!(mutex.is_poisoned());
        let guard = lock_or_recover(&mutex);
        assert_eq!(*guard, 42);
    }

    #[test]
    fn next_registry_snapshot_version_prefers_relay_registry_state() {
        assert_eq!(next_registry_snapshot_version(Some(10), Some(7), 1), 11);
    }

    #[test]
    fn next_registry_snapshot_version_falls_back_to_local_metadata() {
        assert_eq!(next_registry_snapshot_version(None, Some(4), 1), 5);
    }

    #[test]
    fn next_registry_snapshot_version_uses_generation_only_as_floor() {
        assert_eq!(next_registry_snapshot_version(None, None, 3), 4);
    }

    #[tokio::test]
    async fn reconcile_ml_dsa_rotation_commit_imports_signed_registry() {
        let sync_id = "sync-1";
        let device_id = "a1b2c3d4e5f6";
        let device_secret = DeviceSecret::generate();
        let old_record = make_device_record(sync_id, device_id, &device_secret, 0);
        let expected_new_pk =
            device_secret.ml_dsa_65_keypair_v(device_id, 1).unwrap().public_key_bytes();
        let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
        seed_rotation_storage(storage.as_ref(), sync_id, device_id, &old_record, Some(1));

        let relay = MockRelay::new();
        relay.add_device(make_device_info(sync_id, device_id, &device_secret, 1));
        relay.set_signed_registry(SignedRegistryResponse {
            registry_version: 2,
            artifact_blob: make_signed_registry_artifact(sync_id, device_id, &device_secret, 1, 2),
            artifact_kind: "signed_registry_snapshot".to_string(),
        });

        assert!(
            reconcile_ml_dsa_rotation_commit(
                storage.clone(),
                &relay,
                sync_id,
                device_id,
                1,
                &expected_new_pk,
            )
            .await
        );

        let record = storage.get_device_record(sync_id, device_id).unwrap().unwrap();
        assert_eq!(record.ml_dsa_key_generation, 1);
        assert_eq!(record.ml_dsa_65_public_key, expected_new_pk);
        assert_eq!(
            storage.get_sync_metadata(sync_id).unwrap().unwrap().last_imported_registry_version,
            Some(2)
        );
    }

    #[tokio::test]
    async fn reconcile_ml_dsa_rotation_commit_refuses_unadvanced_relay_state() {
        let sync_id = "sync-1";
        let device_id = "a1b2c3d4e5f6";
        let device_secret = DeviceSecret::generate();
        let old_record = make_device_record(sync_id, device_id, &device_secret, 0);
        let expected_new_pk =
            device_secret.ml_dsa_65_keypair_v(device_id, 1).unwrap().public_key_bytes();
        let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
        seed_rotation_storage(storage.as_ref(), sync_id, device_id, &old_record, Some(1));

        let relay = MockRelay::new();
        relay.add_device(make_device_info(sync_id, device_id, &device_secret, 0));
        relay.set_signed_registry(SignedRegistryResponse {
            registry_version: 2,
            artifact_blob: make_signed_registry_artifact(sync_id, device_id, &device_secret, 1, 2),
            artifact_kind: "signed_registry_snapshot".to_string(),
        });

        assert!(
            !reconcile_ml_dsa_rotation_commit(
                storage.clone(),
                &relay,
                sync_id,
                device_id,
                1,
                &expected_new_pk,
            )
            .await
        );

        let record = storage.get_device_record(sync_id, device_id).unwrap().unwrap();
        assert_eq!(record.ml_dsa_key_generation, 0);
        assert_eq!(
            storage.get_sync_metadata(sync_id).unwrap().unwrap().last_imported_registry_version,
            Some(1)
        );
    }

    // ── Phase 1C: clear_sync_state FFI ──

    fn make_pending_op(
        sync_id: &str,
        op_id: &str,
        batch_id: &str,
    ) -> prism_sync_core::storage::PendingOp {
        prism_sync_core::storage::PendingOp {
            op_id: op_id.to_string(),
            sync_id: sync_id.to_string(),
            epoch: 0,
            device_id: "dev-1".to_string(),
            local_batch_id: batch_id.to_string(),
            entity_table: "members".to_string(),
            entity_id: "ent-1".to_string(),
            field_name: "name".to_string(),
            encoded_value: "value".to_string(),
            is_delete: false,
            client_hlc: "0:0:dev-1".to_string(),
            created_at: Utc::now(),
            pushed_at: None,
        }
    }

    fn make_metadata(sync_id: &str) -> SyncMetadata {
        let now = Utc::now();
        SyncMetadata {
            sync_id: sync_id.to_string(),
            local_device_id: "dev-1".to_string(),
            current_epoch: 0,
            last_pulled_server_seq: 0,
            last_pushed_at: None,
            last_successful_sync_at: None,
            registered_at: None,
            needs_rekey: false,
            last_imported_registry_version: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn ensure_local_sync_metadata_creates_missing_row() {
        let storage = RusqliteSyncStorage::in_memory().unwrap();

        ensure_local_sync_metadata(&storage, "sync-join", "joiner-device", 3).unwrap();

        let meta = storage.get_sync_metadata("sync-join").unwrap().unwrap();
        assert_eq!(meta.local_device_id, "joiner-device");
        assert_eq!(meta.current_epoch, 3);
        assert_eq!(meta.last_pulled_server_seq, 0);
    }

    #[test]
    fn ensure_local_sync_metadata_repairs_local_device_id_without_regressing_progress() {
        let storage = RusqliteSyncStorage::in_memory().unwrap();
        let mut metadata = make_metadata("sync-join");
        metadata.local_device_id = "inviter-device".to_string();
        metadata.current_epoch = 5;
        metadata.last_pulled_server_seq = 42;
        {
            let mut tx = storage.begin_tx().unwrap();
            tx.upsert_sync_metadata(&metadata).unwrap();
            tx.commit().unwrap();
        }

        ensure_local_sync_metadata(&storage, "sync-join", "joiner-device", 3).unwrap();

        let meta = storage.get_sync_metadata("sync-join").unwrap().unwrap();
        assert_eq!(meta.local_device_id, "joiner-device");
        assert_eq!(meta.current_epoch, 5);
        assert_eq!(meta.last_pulled_server_seq, 42);
    }

    #[tokio::test]
    async fn restore_runtime_keys_loads_noncontiguous_epoch_keys_from_seeded_store() {
        let handle = create_prism_sync(
            "https://localhost:8080".into(),
            ":memory:".into(),
            false,
            String::new(),
            None,
        )
        .expect("create_prism_sync");

        let epoch_4_key = [0x44u8; 32];
        let entries = HashMap::from([
            ("epoch".to_string(), b"4".to_vec()),
            ("epoch_key_4".to_string(), epoch_4_key.to_vec()),
        ]);
        seed_secure_store(&handle, entries).await.expect("seed secure store");

        restore_runtime_keys(&handle, vec![0xAA; 32], vec![0xBB; 32])
            .await
            .expect("restore runtime keys");

        let inner = handle.inner.lock().await;
        assert_eq!(inner.key_hierarchy().known_epochs(), vec![0, 4]);
        assert_eq!(inner.key_hierarchy().epoch_key(4).unwrap(), epoch_4_key);
    }

    /// Seeds two sync_ids' rows into the handle's storage, then calls the FFI
    /// `clear_sync_state(sid_a, force_active=false)` and asserts only sid_a's
    /// rows are removed.
    #[tokio::test]
    async fn clear_sync_state_drops_only_target_sync_id() {
        let handle = create_prism_sync(
            "https://localhost:8080".into(),
            ":memory:".into(),
            false,
            String::new(),
            None,
        )
        .expect("create_prism_sync");

        let storage = {
            let inner = handle.inner.lock().await;
            inner.storage().clone()
        };

        // Seed metadata + a pending op for two sync_ids.
        {
            let mut tx = storage.begin_tx().unwrap();
            tx.upsert_sync_metadata(&make_metadata("sync-a")).unwrap();
            tx.upsert_sync_metadata(&make_metadata("sync-b")).unwrap();
            tx.insert_pending_op(&make_pending_op("sync-a", "op-a", "batch-a")).unwrap();
            tx.insert_pending_op(&make_pending_op("sync-b", "op-b", "batch-b")).unwrap();
            tx.commit().unwrap();
        }

        assert!(storage.get_sync_metadata("sync-a").unwrap().is_some());
        assert!(storage.get_sync_metadata("sync-b").unwrap().is_some());
        assert!(!storage.get_unpushed_batch_ids("sync-a").unwrap().is_empty());
        assert!(!storage.get_unpushed_batch_ids("sync-b").unwrap().is_empty());

        // No engine configured → sync_service.sync_id() is None → guard does
        // not trip even with force_active=false.
        super::clear_sync_state(&handle, "sync-a".to_string(), false)
            .await
            .expect("clear_sync_state should succeed for non-active sync_id");

        // sync-a rows gone, sync-b rows preserved.
        assert!(storage.get_sync_metadata("sync-a").unwrap().is_none());
        assert!(storage.get_unpushed_batch_ids("sync-a").unwrap().is_empty());
        assert!(storage.get_sync_metadata("sync-b").unwrap().is_some());
        assert!(!storage.get_unpushed_batch_ids("sync-b").unwrap().is_empty());
    }

    /// With the engine configured to a specific sync_id, calling
    /// `clear_sync_state` with that sync_id and `force_active=false` must be
    /// refused with a stable error.
    #[tokio::test]
    async fn clear_sync_state_refuses_active_sync_id_without_force() {
        let handle = create_prism_sync(
            "https://localhost:8080".into(),
            ":memory:".into(),
            false,
            String::new(),
            None,
        )
        .expect("create_prism_sync");

        // Seed rows so we can also assert they're untouched on refusal.
        let storage = {
            let inner = handle.inner.lock().await;
            inner.storage().clone()
        };
        {
            let mut tx = storage.begin_tx().unwrap();
            tx.upsert_sync_metadata(&make_metadata("active-sync")).unwrap();
            tx.commit().unwrap();
        }

        // Configure the engine so sync_service.sync_id() == "active-sync".
        let relay: Arc<dyn prism_sync_core::relay::SyncRelay> = Arc::new(MockRelay::new());
        {
            let mut inner = handle.inner.lock().await;
            inner.configure_engine(relay, "active-sync".to_string(), "dev-1".to_string(), 0, 0);
        }

        let err = super::clear_sync_state(&handle, "active-sync".to_string(), false)
            .await
            .expect_err("must refuse to clear active sync_id without force");
        assert!(
            err.contains("refusing to clear_sync_state for the active sync_id"),
            "unexpected error message: {err}"
        );

        // Rows still present.
        assert!(storage.get_sync_metadata("active-sync").unwrap().is_some());
    }

    /// Same setup as the refusal test, but with `force_active=true` the call
    /// must succeed and remove the rows.
    #[tokio::test]
    async fn clear_sync_state_with_force_active_succeeds() {
        let handle = create_prism_sync(
            "https://localhost:8080".into(),
            ":memory:".into(),
            false,
            String::new(),
            None,
        )
        .expect("create_prism_sync");

        let storage = {
            let inner = handle.inner.lock().await;
            inner.storage().clone()
        };
        {
            let mut tx = storage.begin_tx().unwrap();
            tx.upsert_sync_metadata(&make_metadata("active-sync")).unwrap();
            tx.insert_pending_op(&make_pending_op("active-sync", "op-1", "batch-1")).unwrap();
            tx.commit().unwrap();
        }

        let relay: Arc<dyn prism_sync_core::relay::SyncRelay> = Arc::new(MockRelay::new());
        {
            let mut inner = handle.inner.lock().await;
            inner.configure_engine(relay, "active-sync".to_string(), "dev-1".to_string(), 0, 0);
        }

        super::clear_sync_state(&handle, "active-sync".to_string(), true)
            .await
            .expect("clear_sync_state with force_active should succeed");

        assert!(storage.get_sync_metadata("active-sync").unwrap().is_none());
        assert!(storage.get_unpushed_batch_ids("active-sync").unwrap().is_empty());
    }

    // ── Phase 4E: concurrent-ceremony guard ──
    //
    // The guard inspects `Option::is_some()` on the ceremony slots. We
    // populate those slots with real ceremony values constructed against an
    // in-memory `MockPairingRelay`, then drive the FFI entry points and
    // verify they short-circuit with the `CEREMONY_IN_PROGRESS` prefix
    // before touching any relay or doing any heavy work.

    fn plant_joiner_slot(handle: &PrismSyncHandle, ceremony: JoinerCeremony) {
        *lock_or_recover(&handle.joiner_ceremony) = Some(ceremony);
    }

    fn plant_initiator_slot(handle: &PrismSyncHandle, ceremony: InitiatorCeremony) {
        *lock_or_recover(&handle.initiator_ceremony) = Some(ceremony);
    }

    /// Build a real joiner ceremony against an in-memory `MockPairingRelay`.
    async fn make_real_joiner_ceremony() -> (
        JoinerCeremony,
        prism_sync_core::bootstrap::RendezvousToken,
        Arc<prism_sync_core::relay::MockPairingRelay>,
    ) {
        let relay = Arc::new(prism_sync_core::relay::MockPairingRelay::new());
        let (ceremony, token) = JoinerCeremony::start(relay.as_ref(), "https://relay.example.com")
            .await
            .expect("joiner ceremony start");
        (ceremony, token, relay)
    }

    /// Build a real initiator ceremony by first standing up a joiner side
    /// against the same `MockPairingRelay` and then consuming the token.
    async fn make_real_initiator_ceremony() -> InitiatorCeremony {
        let (_joiner, token, relay) = make_real_joiner_ceremony().await;
        let initiator_secret = prism_sync_crypto::DeviceSecret::generate();
        let initiator_device_id = prism_sync_core::node_id::generate_node_id();
        let (ceremony, _sas) = InitiatorCeremony::start(
            token,
            relay.as_ref(),
            &initiator_secret,
            &initiator_device_id,
        )
        .await
        .expect("initiator ceremony start");
        ceremony
    }

    #[test]
    fn ceremony_guard_emits_stable_error_prefix() {
        // Dart-side error matching keys off this prefix.
        assert_eq!(CEREMONY_IN_PROGRESS_PREFIX, "CEREMONY_IN_PROGRESS");
    }

    #[test]
    fn sas_display_json_has_v2_five_words_and_no_decimal() {
        let sas = SasDisplay {
            version: 2,
            words: "atlas garden signal harbor velvet".to_string(),
            word_list: vec![
                "atlas".to_string(),
                "garden".to_string(),
                "signal".to_string(),
                "harbor".to_string(),
                "velvet".to_string(),
            ],
        };

        let json = sas_display_json(&sas);
        assert_eq!(json["sas_version"], 2);
        assert_eq!(json["sas_words"], "atlas garden signal harbor velvet");
        assert_eq!(json["sas_word_list"].as_array().unwrap().len(), 5);
        assert!(
            json.get("sas_decimal").is_none(),
            "production FFI SAS JSON must not expose a decimal fallback"
        );
    }

    #[tokio::test]
    async fn cancel_pairing_ceremony_is_idempotent_with_no_slots() {
        let handle = create_prism_sync(
            "https://localhost:8080".into(),
            ":memory:".into(),
            false,
            String::new(),
            None,
        )
        .expect("create_prism_sync");

        {
            let inner = handle.inner.lock().await;
            inner
                .secure_store()
                .set("pending_device_secret", b"orphan-pending-secret")
                .expect("seed orphan pending secret");
            inner
                .secure_store()
                .set("pending_device_id", b"orphan-pending-device")
                .expect("seed orphan pending id");
        }

        cancel_pairing_ceremony(&handle).await.expect("empty cancel should succeed");
        {
            let inner = handle.inner.lock().await;
            assert!(inner.secure_store().get("pending_device_secret").unwrap().is_none());
            assert!(inner.secure_store().get("pending_device_id").unwrap().is_none());
        }
        cancel_pairing_ceremony(&handle).await.expect("second empty cancel should succeed");
    }

    #[tokio::test]
    async fn cancel_pairing_ceremony_clears_slots_and_allows_fresh_start_guard() {
        let handle = create_prism_sync(
            "http://127.0.0.1:9".into(),
            ":memory:".into(),
            true,
            String::new(),
            None,
        )
        .expect("create_prism_sync");

        let (ceremony, _token, _relay) = make_real_joiner_ceremony().await;
        plant_joiner_slot(&handle, ceremony);
        {
            let inner = handle.inner.lock().await;
            inner
                .secure_store()
                .set("pending_device_secret", b"stale-pending-secret")
                .expect("seed pending secret");
            inner
                .secure_store()
                .set("pending_device_id", b"stale-pending-device")
                .expect("seed pending id");
        }
        assert!(lock_or_recover(&handle.joiner_ceremony).is_some());

        cancel_pairing_ceremony(&handle).await.expect("cancel should clear local state");

        assert!(lock_or_recover(&handle.joiner_ceremony).is_none());
        assert!(lock_or_recover(&handle.initiator_ceremony).is_none());
        {
            let inner = handle.inner.lock().await;
            assert!(
                inner.secure_store().get("pending_device_secret").unwrap().is_none(),
                "cancel should delete stale pending device secret"
            );
            assert!(
                inner.secure_store().get("pending_device_id").unwrap().is_none(),
                "cancel should delete stale pending device id"
            );
        }
        guard_ceremony_in_progress(&handle, CeremonyGuardKind::StartJoiner)
            .expect("fresh joiner ceremony should no longer be blocked");
        guard_ceremony_in_progress(&handle, CeremonyGuardKind::StartInitiator)
            .expect("fresh initiator ceremony should no longer be blocked");
    }

    #[test]
    fn redact_sensitive_message_masks_keyed_values_and_fragments() {
        let message = concat!(
            "device a1b2c3d4e5f6 rejected sync_id=feedfacefeedface ",
            "session_token=\"abcdefghijklmnopqrstuvwxyzABCDEF012345\" ",
            "fingerprint deadbeefdeadbeefdeadbeefdeadbeef"
        );

        let redacted = redact_sensitive_message(message);

        assert!(!redacted.contains("a1b2c3d4e5f6"));
        assert!(!redacted.contains("feedfacefeedface"));
        assert!(!redacted.contains("abcdefghijklmnopqrstuvwxyzABCDEF012345"));
        assert!(!redacted.contains("deadbeefdeadbeefdeadbeefdeadbeef"));
        assert!(redacted.contains(REDACTED_HEX));
        assert!(redacted.contains(REDACTED_VALUE));
    }

    #[test]
    fn sync_result_to_json_redacts_error_message() {
        let result = prism_sync_core::engine::SyncResult {
            error: Some(
                "device_id=a1b2c3d4e5f6 failed with key deadbeefdeadbeefdeadbeefdeadbeef".into(),
            ),
            ..Default::default()
        };

        let json = sync_result_to_json(&result);
        let error = json["error"].as_str().unwrap();

        assert!(!error.contains("a1b2c3d4e5f6"));
        assert!(!error.contains("deadbeefdeadbeefdeadbeefdeadbeef"));
        assert!(error.contains(REDACTED_VALUE));
        assert!(error.contains(REDACTED_HEX));
    }

    #[test]
    fn sync_event_to_json_redacts_error_message() {
        let event = prism_sync_core::events::SyncEvent::Error(prism_sync_core::events::SyncError {
            kind: prism_sync_core::events::SyncErrorKind::DeviceIdentityMismatch,
            message: "device a1b2c3d4e5f6 mismatched sync_id=feedfacefeedface".into(),
            retryable: false,
            code: Some("device_identity_mismatch".into()),
            remote_wipe: None,
        });

        let json = sync_event_to_json(&event);
        let message = json["message"].as_str().unwrap();

        assert!(!message.contains("a1b2c3d4e5f6"));
        assert!(!message.contains("feedfacefeedface"));
        assert_eq!(json["code"], "device_identity_mismatch");
    }

    #[test]
    fn encode_core_error_surfaces_epoch_mismatch_code_and_epochs() {
        let encoded = encode_core_error(
            "complete_bootstrap_join",
            prism_sync_core::CoreError::EpochMismatch {
                local_epoch: 2,
                relay_epoch: 4,
                message: "relay advanced during pairing".into(),
            },
        );

        let payload: serde_json::Value =
            serde_json::from_str(encoded.strip_prefix(STRUCTURED_ERROR_PREFIX).unwrap()).unwrap();
        assert_eq!(payload["code"], "epoch_mismatch");
        assert_eq!(payload["local_epoch"], 2);
        assert_eq!(payload["relay_epoch"], 4);
    }

    #[test]
    fn encode_core_error_redacts_relay_message_but_keeps_code() {
        let encoded = encode_core_error(
            "sync_now",
            prism_sync_core::CoreError::from_relay(
                prism_sync_core::relay::traits::RelayError::DeviceIdentityMismatch {
                    message: "device_id=a1b2c3d4e5f6 key deadbeefdeadbeefdeadbeefdeadbeef".into(),
                },
            ),
        );

        let payload: serde_json::Value =
            serde_json::from_str(encoded.strip_prefix(STRUCTURED_ERROR_PREFIX).unwrap()).unwrap();
        let message = payload["message"].as_str().unwrap();
        assert_eq!(payload["code"], "device_identity_mismatch");
        assert!(!message.contains("a1b2c3d4e5f6"));
        assert!(!message.contains("deadbeefdeadbeefdeadbeefdeadbeef"));
        assert!(message.contains(REDACTED_VALUE));
        assert!(message.contains(REDACTED_HEX));
    }

    #[test]
    fn encode_core_error_surfaces_epoch_key_mismatch_code() {
        let encoded = encode_core_error(
            "complete_bootstrap_join",
            prism_sync_core::CoreError::EpochKeyMismatch {
                epoch: 3,
                message: "hash mismatch".into(),
            },
        );

        let payload: serde_json::Value =
            serde_json::from_str(encoded.strip_prefix(STRUCTURED_ERROR_PREFIX).unwrap()).unwrap();
        assert_eq!(payload["code"], "epoch_key_mismatch");
        assert_eq!(payload["epoch"], 3);
    }

    #[tokio::test]
    async fn start_initiator_ceremony_refuses_when_initiator_in_progress() {
        let handle = create_prism_sync(
            "https://localhost:8080".into(),
            ":memory:".into(),
            false,
            String::new(),
            None,
        )
        .expect("create_prism_sync");

        let ceremony = make_real_initiator_ceremony().await;
        plant_initiator_slot(&handle, ceremony);

        // Token bytes are irrelevant — guard fires before parsing.
        let err = start_initiator_ceremony(&handle, vec![0xAA; 64])
            .await
            .expect_err("guard must refuse second start_initiator_ceremony");
        assert!(
            err.starts_with(CEREMONY_IN_PROGRESS_PREFIX),
            "expected CEREMONY_IN_PROGRESS prefix, got: {err}"
        );
        assert!(err.contains("initiator ceremony is already in progress"), "got: {err}");
    }

    #[tokio::test]
    async fn start_initiator_ceremony_refuses_when_joiner_in_progress() {
        let handle = create_prism_sync(
            "https://localhost:8080".into(),
            ":memory:".into(),
            false,
            String::new(),
            None,
        )
        .expect("create_prism_sync");

        let (ceremony, _token, _relay) = make_real_joiner_ceremony().await;
        plant_joiner_slot(&handle, ceremony);

        let err = start_initiator_ceremony(&handle, vec![0xAA; 64])
            .await
            .expect_err("guard must refuse start_initiator_ceremony when joiner in flight");
        assert!(
            err.starts_with(CEREMONY_IN_PROGRESS_PREFIX),
            "expected CEREMONY_IN_PROGRESS prefix, got: {err}"
        );
        assert!(err.contains("joiner ceremony is in progress"), "got: {err}");
    }

    #[tokio::test]
    async fn start_joiner_ceremony_refuses_when_joiner_in_progress() {
        let handle = create_prism_sync(
            "https://localhost:8080".into(),
            ":memory:".into(),
            false,
            String::new(),
            None,
        )
        .expect("create_prism_sync");

        let (ceremony, _token, _relay) = make_real_joiner_ceremony().await;
        plant_joiner_slot(&handle, ceremony);

        let err = start_joiner_ceremony(&handle)
            .await
            .expect_err("guard must refuse second start_joiner_ceremony");
        assert!(
            err.starts_with(CEREMONY_IN_PROGRESS_PREFIX),
            "expected CEREMONY_IN_PROGRESS prefix, got: {err}"
        );
        assert!(err.contains("joiner ceremony is already in progress"), "got: {err}");
    }

    #[tokio::test]
    async fn start_joiner_ceremony_refuses_when_initiator_in_progress() {
        let handle = create_prism_sync(
            "https://localhost:8080".into(),
            ":memory:".into(),
            false,
            String::new(),
            None,
        )
        .expect("create_prism_sync");

        let ceremony = make_real_initiator_ceremony().await;
        plant_initiator_slot(&handle, ceremony);

        let err = start_joiner_ceremony(&handle)
            .await
            .expect_err("guard must refuse start_joiner_ceremony when initiator in flight");
        assert!(
            err.starts_with(CEREMONY_IN_PROGRESS_PREFIX),
            "expected CEREMONY_IN_PROGRESS prefix, got: {err}"
        );
        assert!(err.contains("initiator ceremony is in progress"), "got: {err}");
    }

    #[tokio::test]
    async fn complete_initiator_ceremony_refuses_when_joiner_in_progress() {
        let handle = create_prism_sync(
            "https://localhost:8080".into(),
            ":memory:".into(),
            false,
            String::new(),
            None,
        )
        .expect("create_prism_sync");

        let (ceremony, _token, _relay) = make_real_joiner_ceremony().await;
        plant_joiner_slot(&handle, ceremony);

        let err = complete_initiator_ceremony(&handle, b"pw".to_vec(), b"phrase".to_vec())
            .await
            .expect_err("guard must refuse complete_initiator while joiner in flight");
        assert!(
            err.starts_with(CEREMONY_IN_PROGRESS_PREFIX),
            "expected CEREMONY_IN_PROGRESS prefix, got: {err}"
        );
    }

    #[tokio::test]
    async fn complete_initiator_ceremony_rejects_non_utf8_secrets_before_guard() {
        let handle = create_prism_sync(
            "https://localhost:8080".into(),
            ":memory:".into(),
            false,
            String::new(),
            None,
        )
        .expect("create_prism_sync");

        let err = complete_initiator_ceremony(&handle, vec![0xff], b"phrase".to_vec())
            .await
            .expect_err("invalid password should fail before ceremony guard");
        assert_eq!(err, "password must be valid UTF-8");

        let err = complete_initiator_ceremony(&handle, b"pw".to_vec(), vec![0xff])
            .await
            .expect_err("invalid mnemonic should fail before ceremony guard");
        assert_eq!(err, "mnemonic must be valid UTF-8");
    }

    #[tokio::test]
    async fn complete_joiner_ceremony_refuses_when_initiator_in_progress() {
        let handle = create_prism_sync(
            "https://localhost:8080".into(),
            ":memory:".into(),
            false,
            String::new(),
            None,
        )
        .expect("create_prism_sync");

        let ceremony = make_real_initiator_ceremony().await;
        plant_initiator_slot(&handle, ceremony);

        let err = complete_joiner_ceremony(&handle, b"pw".to_vec())
            .await
            .expect_err("guard must refuse complete_joiner while initiator in flight");
        assert!(
            err.starts_with(CEREMONY_IN_PROGRESS_PREFIX),
            "expected CEREMONY_IN_PROGRESS prefix, got: {err}"
        );
    }

    #[tokio::test]
    async fn complete_joiner_ceremony_rejects_non_utf8_password_before_guard() {
        let handle = create_prism_sync(
            "https://localhost:8080".into(),
            ":memory:".into(),
            false,
            String::new(),
            None,
        )
        .expect("create_prism_sync");

        let err = complete_joiner_ceremony(&handle, vec![0xff])
            .await
            .expect_err("invalid password should fail before ceremony guard");
        assert_eq!(err, "password must be valid UTF-8");
    }
}
