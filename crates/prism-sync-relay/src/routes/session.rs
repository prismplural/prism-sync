//! Public session-refresh recovery endpoint.
//!
//! `POST /v1/sync/{sync_id}/session/refresh` is the device-initiated exit from
//! the "offline past the session TTL" state. When a device's bearer token
//! has expired it can no longer touch `last_seen_at` through `auth_middleware`,
//! and under default config (`SESSION_EXPIRY_SECS == STALE_DEVICE_SECS`) the
//! session expires exactly when the device goes stale — so without this door a
//! device offline >30 days is permanently locked out with its unpushed ops
//! stranded, contradicting the prune-floor retention design.
//!
//! This route lives on the PUBLIC router (no `auth_middleware`, no bearer token)
//! because the whole point is to recover from an *expired* session. Instead of a
//! session, the request proves identity with a V3 hybrid signed request verified
//! against the device's STORED public keys (plus the ML-DSA grace key during a
//! rotation window). Active/stale devices get a fresh session and are
//! reactivated; revoked devices get a structured 401 carrying the signed
//! registry blob so they can verify their own revocation offline.

use axum::{
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use base64::Engine;
use serde::Deserialize;
use std::net::SocketAddr;

use crate::{auth, db, errors::AppError, state::AppState};

use super::{verify_signed_request, AuthIdentity};

pub fn routes() -> Router<AppState> {
    Router::new().route("/v1/sync/{sync_id}/session/refresh", post(refresh_session))
}

#[derive(Deserialize)]
struct RefreshRequest {
    device_id: String,
}

/// `POST /v1/sync/{sync_id}/session/refresh`
///
/// Body: `{ device_id }`. Headers: the standard V3 hybrid signed-request triple
/// (`X-Prism-Timestamp` / `X-Prism-Nonce` / `X-Prism-Signature`).
async fn refresh_session(
    State(state): State<AppState>,
    Path(path_sync_id): Path<String>,
    ConnectInfo(_peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    if !auth::is_valid_sync_id(&path_sync_id) {
        return Err(AppError::BadRequest("Invalid sync ID"));
    }

    // Rate-limit per sync_id like the registration nonce path: an attacker who
    // does not hold the device's signing keys cannot pass verification anyway,
    // and capping attempts bounds replay/timestamp probing against this public
    // surface. Use a distinct `refresh:` key prefix so a refresh storm (e.g. a
    // revoked device's per-cycle retries, or any party who knows the sync_id)
    // does not starve registration-nonce issuance for the same group, or vice
    // versa — they share `nonce_rate_limiter` but must not share a bucket.
    if !state.nonce_rate_limiter.check(
        &format!("refresh:{path_sync_id}"),
        state.config.nonce_rate_limit,
        state.config.nonce_rate_window_secs,
    ) {
        return Err(AppError::TooManyRequests);
    }

    let req: RefreshRequest =
        serde_json::from_slice(&body).map_err(|_| AppError::BadRequest("Invalid JSON body"))?;
    if !auth::is_valid_device_id(&req.device_id) {
        return Err(AppError::BadRequest("Invalid device_id"));
    }

    let sync_id = path_sync_id.clone();
    let device_id = req.device_id.clone();

    // Phase 1 — look up the device row (read). The signed-request verification
    // and the reactivate/mint write happen in Phase 2.
    let db_read = state.db.clone();
    let (sid, did) = (sync_id.clone(), device_id.clone());
    let device = tokio::task::spawn_blocking(move || {
        db_read.with_read_conn(|conn| db::get_device(conn, &sid, &did))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let Some(device) = device else {
        // No such device: surface a generic 401 (do not leak existence).
        return Err(AppError::Unauthorized);
    };

    // Build the AuthIdentity from the STORED device row — there is no session to
    // derive it from. Include the ML-DSA grace key so a device mid-rotation can
    // still recover. `verify_signed_request` re-checks timestamp skew and the
    // signed-request replay nonce just like every authenticated write.
    let prev_ml_dsa_65_public_key = if !device.prev_ml_dsa_65_public_key.is_empty()
        && device.prev_ml_dsa_65_expires_at.is_some_and(|exp| exp > db::now_secs())
    {
        Some(device.prev_ml_dsa_65_public_key.clone())
    } else {
        None
    };
    let auth_identity = AuthIdentity {
        sync_id: sync_id.clone(),
        device_id: device_id.clone(),
        signing_public_key: device.signing_public_key.clone(),
        ml_dsa_65_public_key: device.ml_dsa_65_public_key.clone(),
        prev_ml_dsa_65_public_key,
    };

    verify_signed_request(
        &state,
        &auth_identity,
        &headers,
        "POST",
        &format!("/v1/sync/{sync_id}/session/refresh"),
        &body,
    )?;

    // Signature verified. A revoked device gets a structured 401 carrying the
    // latest signed registry artifact so it can confirm its own revocation
    // offline (the primary path — the registry GET exemption — also serves
    // this, but bundling it here means a single round-trip on the recovery
    // surface). Active/stale devices are reactivated and minted a fresh session.
    if device.status == "revoked" {
        let db_read = state.db.clone();
        let (sid, did) = (sync_id.clone(), device_id.clone());
        let (wipe, artifact) = tokio::task::spawn_blocking(move || {
            db_read.with_read_conn(|conn| {
                let wipe = db::get_device_wipe_status(conn, &sid, &did)?.unwrap_or(false);
                let artifact = match db::get_registry_state(conn, &sid)? {
                    Some(s) => db::get_registry_artifact(conn, &sid, s.registry_version)?,
                    None => None,
                };
                Ok((wipe, artifact))
            })
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|e| AppError::Internal(e.to_string()))?;

        let b64 = base64::engine::general_purpose::STANDARD;
        let signed_registry = artifact.map(|a| b64.encode(&a.artifact_blob));
        // Dedicated JSON body (not the shared `AppError::DeviceRevoked` one) so
        // the additive `signed_registry` field rides along; the `error`/
        // `remote_wipe` keys match the existing device_revoked contract that
        // `classify_error` already parses, so old clients keep working.
        let body = serde_json::json!({
            "error": "device_revoked",
            "message": "Device has been revoked",
            "remote_wipe": wipe,
            "signed_registry": signed_registry,
        });
        return Ok((StatusCode::UNAUTHORIZED, Json(body)).into_response());
    }

    // Active or stale: reactivate (status guard makes the write safe against a
    // concurrent auto-revoke) and mint a fresh session token.
    let session_expiry = state.config.session_expiry_secs as i64;
    let db_write = state.db.clone();
    let (sid, did) = (sync_id.clone(), device_id.clone());
    let token = tokio::task::spawn_blocking(move || {
        db_write.with_conn(|conn| {
            // If a concurrent auto-revoke beat us to it, this matches no row and
            // we must not hand out a session for a now-revoked device.
            let reactivated = db::touch_and_reactivate_device(conn, &sid, &did)?;
            if reactivated == 0 {
                return Ok(None);
            }
            let token = db::create_session(conn, &sid, &did, session_expiry)?;
            Ok(Some(token))
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let Some(token) = token else {
        // Lost the race to a concurrent auto-revoke; the device is now revoked.
        return Err(AppError::Unauthorized);
    };

    tracing::debug!(
        sync_id = %&sync_id[..16.min(sync_id.len())],
        device_id = %&device_id[..8.min(device_id.len())],
        "Session refreshed; device reactivated"
    );

    Ok(Json(serde_json::json!({ "device_session_token": token })).into_response())
}
