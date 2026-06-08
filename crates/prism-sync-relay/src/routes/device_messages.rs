//! Ephemeral signal lane (media re-supply C3): the relay-blind device-message
//! mailbox HTTP surface — send / pending / ack.
//!
//! All three routes are bearer-authenticated **and** request-signed (a stolen
//! session token alone can't post on a device's behalf — signing needs the
//! device key). The `sender_device_id` stored for a send is always the
//! *authenticated* device, never a client-asserted field, so the per-sender
//! rate limit and pending cap can't be evaded by spoofing. Payloads are opaque
//! ciphertext (the relay never decrypts); see `prism_sync_core::ephemeral`.

use axum::{
    body::Bytes,
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine;
use serde::Deserialize;

use crate::{db, errors::AppError, state::AppState};

use super::{verify_signed_request, AuthIdentity};

/// Max ack ids accepted in one request (clients page their drains).
const MAX_ACK_IDS: usize = 1024;

/// A `message_id` is exactly 32 **lowercase** hex chars (a 16-byte HMAC tag from
/// `hex::encode`, which is always lowercase). Uppercase is rejected on purpose:
/// the dedup PK `(sync_id, message_id)` is exact text, so accepting case variants
/// of the same logical id would let a client split it into non-coalescing rows
/// and bypass the in-window dedup the composite PK exists to provide.
fn is_valid_message_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A routing device id is a bounded, non-empty, control-char-free string. The
/// relay never parses it beyond equality routing + parameterised SQL, so this
/// only bounds abuse, not format.
fn is_valid_device_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.chars().all(|c| !c.is_control())
}

// ---------------------------------------------------------------------------
// POST /v1/sync/{sync_id}/device-messages — send
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SendDeviceMessageRequest {
    pub message_id: String,
    pub epoch_id: i64,
    #[serde(default)]
    pub recipient_device_id: Option<String>,
    /// base64-encoded opaque sealed payload.
    pub payload: String,
}

pub async fn send_device_message(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthIdentity>,
    Path(path_sync_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }
    let path = format!("/v1/sync/{}/device-messages", auth.sync_id);
    verify_signed_request(&state, &auth, &headers, "POST", &path, &body)?;

    let req: SendDeviceMessageRequest =
        serde_json::from_slice(&body).map_err(|_| AppError::BadRequest("Invalid JSON"))?;

    if !is_valid_message_id(&req.message_id) {
        return Err(AppError::BadRequest("Invalid message_id (32 hex chars)"));
    }
    if req.epoch_id < 0 || req.epoch_id > u32::MAX as i64 {
        return Err(AppError::BadRequest("Invalid epoch_id"));
    }
    if let Some(ref r) = req.recipient_device_id {
        if !is_valid_device_id(r) {
            return Err(AppError::BadRequest("Invalid recipient_device_id"));
        }
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let payload =
        b64.decode(&req.payload).map_err(|_| AppError::BadRequest("Invalid base64 payload"))?;
    if payload.is_empty() {
        return Err(AppError::BadRequest("Empty payload"));
    }
    if payload.len() > state.config.device_message_max_payload_bytes {
        return Err(AppError::PayloadTooLarge("Device message payload too large"));
    }

    // Per-sender-device send rate limit — the request-storm bound. Note this is
    // consumed before the DB dedup runs, so an in-window re-send of an
    // already-stored message_id (which would coalesce harmlessly at the PK)
    // still costs a token; the limiter is a coarse storm backstop, and the C4
    // requester's per-media cooldown keeps honest senders well under it.
    let rate_key = format!("device_msg_send:{}:{}", auth.sync_id, auth.device_id);
    if !state.device_message_send_rate_limiter.check(
        &rate_key,
        state.config.device_message_send_rate_limit,
        state.config.device_message_send_rate_window_secs,
    ) {
        return Err(AppError::TooManyRequests);
    }

    let sync_id = auth.sync_id.clone();
    let sender_device_id = auth.device_id.clone();
    let message_id = req.message_id.clone();
    let recipient = req.recipient_device_id.clone();
    let epoch_id = req.epoch_id;
    let ttl = state.config.device_message_ttl_secs;
    let max_pending = state.config.device_message_max_pending;
    let db = state.db.clone();

    let outcome = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            db::insert_device_message(
                conn,
                &sync_id,
                &message_id,
                &sender_device_id,
                recipient.as_deref(),
                epoch_id,
                &payload,
                ttl,
                max_pending,
            )
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    use db::DeviceMessageSendOutcome;
    match outcome {
        // Both a new store and a coalesced duplicate are successes for the
        // caller — the dedup key did its job either way.
        DeviceMessageSendOutcome::Stored | DeviceMessageSendOutcome::Coalesced => {
            Ok((StatusCode::CREATED, Json(serde_json::json!({ "message_id": req.message_id })))
                .into_response())
        }
        DeviceMessageSendOutcome::PendingCapExceeded => Err(AppError::TooManyRequests),
    }
}

// ---------------------------------------------------------------------------
// GET /v1/sync/{sync_id}/device-messages/pending — drain
// ---------------------------------------------------------------------------

pub async fn pending_device_messages(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthIdentity>,
    Path(path_sync_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }
    let path = format!("/v1/sync/{}/device-messages/pending", auth.sync_id);
    verify_signed_request(&state, &auth, &headers, "GET", &path, &[])?;

    let sync_id = auth.sync_id.clone();
    let device_id = auth.device_id.clone();
    let limit = state.config.device_message_fetch_limit;
    let db = state.db.clone();

    let messages = tokio::task::spawn_blocking(move || {
        db.with_read_conn(|conn| {
            db::fetch_pending_device_messages(conn, &sync_id, &device_id, limit)
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let b64 = base64::engine::general_purpose::STANDARD;
    let body: Vec<serde_json::Value> = messages
        .into_iter()
        .map(|m| {
            serde_json::json!({
                "message_id": m.message_id,
                "sender_device_id": m.sender_device_id,
                "recipient_device_id": m.recipient_device_id,
                "epoch_id": m.epoch_id,
                "payload": b64.encode(&m.payload),
                "created_at": m.created_at,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({ "messages": body })).into_response())
}

// ---------------------------------------------------------------------------
// POST /v1/sync/{sync_id}/device-messages/ack — acknowledge
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AckDeviceMessagesRequest {
    pub message_ids: Vec<String>,
}

pub async fn ack_device_messages(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthIdentity>,
    Path(path_sync_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }
    let path = format!("/v1/sync/{}/device-messages/ack", auth.sync_id);
    verify_signed_request(&state, &auth, &headers, "POST", &path, &body)?;

    let req: AckDeviceMessagesRequest =
        serde_json::from_slice(&body).map_err(|_| AppError::BadRequest("Invalid JSON"))?;
    if req.message_ids.len() > MAX_ACK_IDS {
        return Err(AppError::BadRequest("Too many message_ids in one ack request"));
    }

    // Drop malformed ids (they can never reference a stored message) and dedup.
    let mut ids: Vec<String> =
        req.message_ids.into_iter().filter(|id| is_valid_message_id(id)).collect();
    ids.sort();
    ids.dedup();

    let acked = if ids.is_empty() {
        0
    } else {
        let sync_id = auth.sync_id.clone();
        let device_id = auth.device_id.clone();
        let db = state.db.clone();
        tokio::task::spawn_blocking(move || {
            db.with_conn(|conn| db::ack_device_messages(conn, &sync_id, &device_id, &ids))
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|e| AppError::Internal(e.to_string()))?
    };

    Ok(Json(serde_json::json!({ "acked": acked })).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_id_validation() {
        assert!(is_valid_message_id(&"a".repeat(32)));
        assert!(is_valid_message_id("0123456789abcdef0123456789abcdef"));
        // Uppercase is rejected — the PK is case-sensitive and ids are lowercase.
        assert!(!is_valid_message_id("0123456789ABCDEF0123456789ABCDEF"));
        assert!(!is_valid_message_id("0123456789abcdef0123456789abcdeF"));
        assert!(!is_valid_message_id(""));
        assert!(!is_valid_message_id(&"a".repeat(31)));
        assert!(!is_valid_message_id(&"a".repeat(33)));
        assert!(!is_valid_message_id(&"g".repeat(32)));
        assert!(!is_valid_message_id("not-hex-padded-to-32-chars-xxxxx"));
    }

    #[test]
    fn device_id_validation() {
        assert!(is_valid_device_id("device-1"));
        assert!(is_valid_device_id(&"d".repeat(128)));
        assert!(!is_valid_device_id(""));
        assert!(!is_valid_device_id(&"d".repeat(129)));
        assert!(!is_valid_device_id("has\nnewline"));
        assert!(!is_valid_device_id("has\0null"));
    }
}
