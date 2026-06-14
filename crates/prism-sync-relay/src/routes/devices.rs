use std::collections::HashSet;

use axum::{
    body::Bytes,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::{auth, db, errors::AppError, state::AppState};

use super::{
    register::sync_registry_state_with_current_devices, verify_signed_request, AuthIdentity,
};

const MAX_WRAPPED_KEY_SIZE: usize = 1536; // bumped from 1024 for hybrid X-Wing rekey artifacts (~1193 bytes)
const THIRTY_DAYS_SECS: i64 = 30 * 24 * 3600;

#[derive(Deserialize)]
pub struct RevokeQuery {
    #[serde(default)]
    pub remote_wipe: bool,
}

#[derive(Deserialize)]
pub struct RekeyArtifactQuery {
    /// Optional epoch to fetch. If omitted, uses the device's current epoch.
    pub epoch: Option<i64>,
}

// ---------------------------------------------------------------------------
// list_devices — GET /v1/sync/{sync_id}/devices
// ---------------------------------------------------------------------------

pub async fn list_devices(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthIdentity>,
    Path(path_sync_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }

    let db = state.db.clone();
    let sid = auth.sync_id;

    let (devices, needs_rekey) = tokio::task::spawn_blocking(move || {
        db.with_read_conn(|conn| {
            // Surface the group-level rekey-needed flag so a polling client
            // (no WS) can detect that the 90d auto-revoke left the group owing a
            // forced rotation, and one active device can drive the standalone
            // rekey that clears it. Additive per-device key — 0.12.x clients that
            // don't know the field ignore it.
            let needs_rekey = db::get_needs_rekey(conn, &sid)?.unwrap_or(false);
            Ok((db::list_devices(conn, &sid)?, needs_rekey))
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let b64 = base64::engine::general_purpose::STANDARD;
    let body: Vec<serde_json::Value> = devices
        .into_iter()
        .map(|d| {
            serde_json::json!({
                "device_id": d.device_id,
                "signing_public_key": b64.encode(&d.signing_public_key),
                "x25519_public_key": b64.encode(&d.x25519_public_key),
                "ml_dsa_65_public_key": b64.encode(&d.ml_dsa_65_public_key),
                "ml_kem_768_public_key": b64.encode(&d.ml_kem_768_public_key),
                "x_wing_public_key": b64.encode(&d.x_wing_public_key),
                "epoch": d.epoch,
                "status": d.status,
                "ml_dsa_key_generation": d.ml_dsa_key_generation,
                "needs_rekey": needs_rekey,
            })
        })
        .collect();

    Ok(Json(body))
}

// ---------------------------------------------------------------------------
// delete_device — DELETE /v1/sync/{sync_id}/devices/{device_id}
// ---------------------------------------------------------------------------

pub async fn delete_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(auth): Extension<AuthIdentity>,
    Path((path_sync_id, target_device_id)): Path<(String, String)>,
    Query(_query): Query<RevokeQuery>,
) -> Result<impl IntoResponse, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }
    if !auth::is_valid_device_id(&target_device_id) {
        return Err(AppError::BadRequest("Invalid device ID"));
    }

    let sync_id = auth.sync_id.clone();
    let requester = auth.device_id.clone();
    let is_self = target_device_id == requester;

    if !is_self {
        return Ok((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "use_atomic_revoke",
                "message": "Use POST /v1/sync/{sync_id}/devices/{device_id}/revoke",
            })),
        )
            .into_response());
    }

    let path = format!("/v1/sync/{sync_id}/devices/{target_device_id}");
    verify_signed_request(&state, &auth, &headers, "DELETE", &path, &[])?;

    let db = state.db.clone();
    let sid = sync_id.clone();
    let target = target_device_id.clone();

    tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| Ok(do_self_deregister(conn, &sid, &target)))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))??;

    state
        .notify_devices(
            &sync_id,
            Some(&requester),
            &serde_json::json!({
                "type": "device_deregistered",
                "device_id": target_device_id,
            })
            .to_string(),
        )
        .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

fn do_self_deregister(
    conn: &rusqlite::Connection,
    sync_id: &str,
    _device_id: &str,
) -> Result<(), AppError> {
    let active =
        db::count_active_devices(conn, sync_id).map_err(|e| AppError::Internal(e.to_string()))?;
    if active <= 1 {
        return Err(AppError::Forbidden(
            "Cannot deregister the last active device; delete the sync group instead",
        ));
    }
    Err(AppError::Conflict("Self-deregister with active peers requires atomic revoke"))
}

// ---------------------------------------------------------------------------
// post_atomic_revoke — POST /v1/sync/{sync_id}/devices/{device_id}/revoke
// ---------------------------------------------------------------------------

pub async fn post_atomic_revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(auth): Extension<AuthIdentity>,
    Path((path_sync_id, target_device_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }
    if !auth::is_valid_device_id(&target_device_id) {
        return Err(AppError::BadRequest("Invalid device ID"));
    }

    let path = format!("/v1/sync/{}/devices/{}/revoke", auth.sync_id, target_device_id);
    verify_signed_request(&state, &auth, &headers, "POST", &path, &body)?;

    if !state.revoke_rate_limiter.check(
        &format!("revoke:{}", auth.sync_id),
        state.config.revoke_rate_limit,
        state.config.revoke_rate_window_secs,
    ) {
        return Err(AppError::TooManyRequests);
    }

    let body_json: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| AppError::BadRequest("Invalid JSON"))?;
    let new_epoch =
        body_json["new_epoch"].as_i64().ok_or(AppError::BadRequest("Missing new_epoch"))?;
    let remote_wipe = body_json["remote_wipe"].as_bool().unwrap_or(false);
    let wrapped_keys = parse_wrapped_keys(&body_json)?;
    let signed_registry_snapshot = decode_optional_signed_registry_snapshot(&body_json)?;

    let sync_id = auth.sync_id.clone();
    let requester = auth.device_id.clone();
    let target = target_device_id.clone();
    let db = state.db.clone();
    let session_max_age = state.config.session_max_age_secs as i64;

    tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            Ok(do_atomic_revoke(
                conn,
                &sync_id,
                &requester,
                &target,
                new_epoch,
                remote_wipe,
                &wrapped_keys,
                session_max_age,
                signed_registry_snapshot.as_deref(),
            ))
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))??;

    state
        .notify_devices(
            &auth.sync_id,
            None,
            &serde_json::json!({
                "type": "device_revoked",
                "device_id": target_device_id,
                "remote_wipe": remote_wipe,
            })
            .to_string(),
        )
        .await;
    state
        .notify_devices(
            &auth.sync_id,
            None,
            &serde_json::json!({
                "type": "epoch_rotated",
                "new_epoch": new_epoch,
            })
            .to_string(),
        )
        .await;

    Ok((StatusCode::OK, Json(serde_json::json!({ "new_epoch": new_epoch }))))
}

fn do_atomic_revoke(
    conn: &rusqlite::Connection,
    sync_id: &str,
    requester_device_id: &str,
    target_device_id: &str,
    new_epoch: i64,
    remote_wipe: bool,
    wrapped_keys: &[(String, Vec<u8>)],
    session_max_age_secs: i64,
    signed_registry_snapshot: Option<&[u8]>,
) -> Result<i64, AppError> {
    if target_device_id == requester_device_id {
        return Err(AppError::BadRequest("Self-deregister must use DELETE /devices/{device_id}"));
    }

    let tx = conn.unchecked_transaction().map_err(|e| AppError::Internal(e.to_string()))?;

    let current_epoch = db::get_sync_group_epoch(&tx, sync_id)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or(AppError::NotFound)?;
    if new_epoch != current_epoch + 1 {
        return Err(AppError::BadRequest("new_epoch must be current_epoch + 1"));
    }

    let requester = db::get_device(&tx, sync_id, requester_device_id)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or(AppError::NotFound)?;
    if requester.status != "active" {
        return Err(AppError::Forbidden("Requester device is not active"));
    }

    let target = db::get_device(&tx, sync_id, target_device_id)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or(AppError::NotFound)?;
    // Reject only an already-`revoked` target: a `stale` device (30d idle) must
    // remain revocable for the whole 30–90d window. A stale device can now
    // self-reactivate via the signed `/session/refresh`, so leaving the owner
    // unable to revoke a lost/stolen-but-stale device would open a window
    // strictly weaker than before self-reactivation existed. `stale` is excluded from the active
    // survivor set anyway, so `validate_wrapped_keys` agrees with the client's
    // `status == "active"` wrap set for a stale target.
    if target.status == "revoked" {
        return Err(AppError::Conflict("Target device is already revoked"));
    }

    let expected_survivors = active_survivor_set(&tx, sync_id, Some(target_device_id))?;
    validate_wrapped_keys(&expected_survivors, wrapped_keys)?;

    let changed = db::revoke_device(&tx, sync_id, target_device_id, remote_wipe)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if !changed {
        // Lost a race to a concurrent revoke (the row is no longer
        // active/stale): the target is already revoked.
        return Err(AppError::Conflict("Target device is already revoked"));
    }

    let _ = db::touch_session(&tx, sync_id, target_device_id, THIRTY_DAYS_SECS, session_max_age_secs);
    db::update_sync_group_epoch(&tx, sync_id, new_epoch)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    db::set_needs_rekey(&tx, sync_id, false).map_err(|e| AppError::Internal(e.to_string()))?;
    tx.execute(
        "UPDATE devices SET epoch = ?1 WHERE sync_id = ?2 AND status = 'active'",
        rusqlite::params![new_epoch, sync_id],
    )
    .map_err(|e| AppError::Internal(e.to_string()))?;

    for (device_id, wrapped_key) in wrapped_keys {
        db::store_rekey_artifact(&tx, sync_id, new_epoch, device_id, wrapped_key)
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    // Publish the epoch-N signed registry inside the same transaction as the
    // revoke + epoch bump, so the registry committing hash(K_N) can never lag the
    // relay-visible epoch. The device row is already revoked above, so the rebuilt
    // registry entries exclude the target.
    if let Some(snapshot) = signed_registry_snapshot {
        sync_registry_state_with_current_devices(
            &tx,
            sync_id,
            Some("signed_registry_snapshot"),
            Some(snapshot),
        )?;
    }

    db::insert_revocation_event(
        &tx,
        sync_id,
        requester_device_id,
        target_device_id,
        new_epoch,
        remote_wipe,
    )
    .map_err(|e| AppError::Internal(e.to_string()))?;

    tx.commit().map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(new_epoch)
}

// ---------------------------------------------------------------------------
// post_rekey — POST /v1/sync/{sync_id}/rekey
// ---------------------------------------------------------------------------

pub async fn post_rekey(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(auth): Extension<AuthIdentity>,
    Path(path_sync_id): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }

    let path = format!("/v1/sync/{}/rekey", auth.sync_id);
    verify_signed_request(&state, &auth, &headers, "POST", &path, &body)?;

    let body_json: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| AppError::BadRequest("Invalid JSON"))?;
    if body_json.get("revoked_device_id").is_some() {
        return Ok((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "use_atomic_revoke",
                "message": "Rekey after revocation must use the atomic endpoint",
            })),
        ));
    }

    let epoch = body_json["epoch"].as_i64().ok_or(AppError::BadRequest("Missing epoch"))?;
    let wrapped_keys = parse_wrapped_keys(&body_json)?;
    let signed_registry_snapshot = decode_optional_signed_registry_snapshot(&body_json)?;

    let sync_id = auth.sync_id.clone();
    let device_id = auth.device_id.clone();

    let db = state.db.clone();
    let sid = sync_id.clone();
    let did = device_id.clone();

    let new_epoch = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            Ok(do_rekey(
                conn,
                &sid,
                &did,
                epoch,
                &wrapped_keys,
                signed_registry_snapshot.as_deref(),
            ))
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))??;

    state
        .notify_devices(
            &sync_id,
            None,
            &serde_json::json!({
                "type": "epoch_rotated",
                "new_epoch": new_epoch,
            })
            .to_string(),
        )
        .await;

    Ok((StatusCode::OK, Json(serde_json::json!({ "new_epoch": new_epoch }))))
}

fn do_rekey(
    conn: &rusqlite::Connection,
    sync_id: &str,
    device_id: &str,
    epoch: i64,
    wrapped_keys: &[(String, Vec<u8>)],
    signed_registry_snapshot: Option<&[u8]>,
) -> Result<i64, AppError> {
    let tx = conn.unchecked_transaction().map_err(|e| AppError::Internal(e.to_string()))?;

    // A standalone rekey is allowed to clear `needs_rekey`. The flag is set
    // by the 90d auto-revoke with no epoch bump and can ONLY be cleared by an
    // epoch rotation, but the previous early 409 forced that rotation onto the
    // atomic-revoke endpoint — which requires a still-`active` target and so
    // deadlocked forever once the trigger device was already revoked. The
    // security property the 409 guarded (the new epoch key reaches exactly the
    // current active set, never the auto-revoked device) is enforced in-tx below
    // by `validate_wrapped_keys(active_survivor_set(..))`. The epoch CAS
    // (`epoch == current_epoch + 1`) plus the writer-mutex serialization
    // guarantees at most one rotation commits, so concurrent standalone rekey
    // vs. atomic revoke still resolves to exactly one winner.
    let current_epoch = db::get_sync_group_epoch(&tx, sync_id)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or(AppError::NotFound)?;
    if epoch != current_epoch + 1 {
        return Err(AppError::BadRequest("Rekey epoch must be current_epoch + 1"));
    }

    // Mirror the atomic endpoint's requester gate: a non-active requester (stale,
    // or racing a Phase-2 reactivation) is excluded from `active_survivor_set`,
    // so it would commit a rotation whose wrap set omits itself and self-lock out
    // of the new epoch key with no artifact to recover from.
    let requester = db::get_device(&tx, sync_id, device_id)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or(AppError::NotFound)?;
    if requester.status != "active" {
        return Err(AppError::Forbidden("Requester device is not active"));
    }

    let expected_devices = active_survivor_set(&tx, sync_id, None)?;
    validate_wrapped_keys(&expected_devices, wrapped_keys)?;

    db::update_sync_group_epoch(&tx, sync_id, epoch)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    db::set_needs_rekey(&tx, sync_id, false).map_err(|e| AppError::Internal(e.to_string()))?;
    tx.execute(
        "UPDATE devices SET epoch = ?1 WHERE sync_id = ?2 AND status = 'active'",
        rusqlite::params![epoch, sync_id],
    )
    .map_err(|e| AppError::Internal(e.to_string()))?;

    for (dev_id, key_bytes) in wrapped_keys {
        db::store_rekey_artifact(&tx, sync_id, epoch, dev_id, key_bytes)
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }
    if let Some(snapshot) = signed_registry_snapshot {
        sync_registry_state_with_current_devices(
            &tx,
            sync_id,
            Some("signed_registry_snapshot"),
            Some(snapshot),
        )?;
    }
    db::insert_rekey_event(&tx, sync_id, device_id, epoch)
        .map_err(|e| AppError::Internal(e.to_string()))?;

    tx.commit().map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(epoch)
}

fn active_survivor_set(
    conn: &rusqlite::Connection,
    sync_id: &str,
    excluded_device_id: Option<&str>,
) -> Result<HashSet<String>, AppError> {
    let devices = db::list_devices(conn, sync_id).map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(devices
        .into_iter()
        .filter(|d| d.status == "active")
        .filter(|d| excluded_device_id.is_none_or(|excluded| d.device_id != excluded))
        .map(|d| d.device_id)
        .collect())
}

fn validate_wrapped_keys(
    expected_devices: &HashSet<String>,
    wrapped_keys: &[(String, Vec<u8>)],
) -> Result<(), AppError> {
    let mut seen = HashSet::new();
    for (device_id, wrapped_key) in wrapped_keys {
        if !auth::is_valid_device_id(device_id) {
            return Err(AppError::BadRequest("Invalid wrapped_keys device ID"));
        }
        if wrapped_key.len() > MAX_WRAPPED_KEY_SIZE {
            return Err(AppError::BadRequest("wrapped_key exceeds maximum size"));
        }
        if !seen.insert(device_id.as_str()) {
            return Err(AppError::BadRequest("Duplicate wrapped_key entry"));
        }
    }

    if seen.len() != expected_devices.len()
        || expected_devices.iter().any(|id| !seen.contains(id.as_str()))
    {
        return Err(AppError::BadRequest("wrapped_keys must match the active device set exactly"));
    }

    Ok(())
}

/// Parse wrapped_keys from the rekey body.
/// Accepts `{"wrapped_keys": {"device_id": "base64...", ...}}` (map format)
/// or `{"artifacts": [{"device_id": "...", "wrapped_key": "base64..."}, ...]}` (array format).
fn parse_wrapped_keys(body: &serde_json::Value) -> Result<Vec<(String, Vec<u8>)>, AppError> {
    let b64 = base64::engine::general_purpose::STANDARD;

    if let Some(map) = body["wrapped_keys"].as_object() {
        let mut result = Vec::with_capacity(map.len());
        for (device_id, val) in map {
            let b64_str =
                val.as_str().ok_or(AppError::BadRequest("wrapped_keys values must be strings"))?;
            let bytes = b64
                .decode(b64_str)
                .map_err(|_| AppError::BadRequest("Invalid base64 in wrapped_keys"))?;
            result.push((device_id.clone(), bytes));
        }
        return Ok(result);
    }

    if let Some(arr) = body["artifacts"].as_array() {
        let mut result = Vec::with_capacity(arr.len());
        for item in arr {
            let device_id = item["device_id"]
                .as_str()
                .ok_or(AppError::BadRequest("artifact missing device_id"))?
                .to_string();
            let wrapped_key = item["wrapped_key"]
                .as_str()
                .ok_or(AppError::BadRequest("artifact missing wrapped_key"))?;
            let bytes = b64
                .decode(wrapped_key)
                .map_err(|_| AppError::BadRequest("Invalid base64 in wrapped_key"))?;
            result.push((device_id, bytes));
        }
        return Ok(result);
    }

    Err(AppError::BadRequest("Missing wrapped_keys or artifacts"))
}

fn decode_optional_signed_registry_snapshot(
    body: &serde_json::Value,
) -> Result<Option<Vec<u8>>, AppError> {
    let Some(value) = body.get("signed_registry_snapshot") else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let encoded =
        value.as_str().ok_or(AppError::BadRequest("signed_registry_snapshot must be a string"))?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| AppError::BadRequest("Invalid base64 in signed_registry_snapshot"))?;
    if blob.len() > 512 * 1024 {
        return Err(AppError::BadRequest("signed_registry_snapshot too large (max 512KB)"));
    }
    Ok(Some(blob))
}

// ---------------------------------------------------------------------------
// get_rekey_artifact — GET /v1/sync/{sync_id}/rekey/{device_id}
// ---------------------------------------------------------------------------

pub async fn get_rekey_artifact(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthIdentity>,
    Path((path_sync_id, target_device_id)): Path<(String, String)>,
    Query(query): Query<RekeyArtifactQuery>,
) -> Result<impl IntoResponse, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }
    if !auth::is_valid_device_id(&target_device_id) {
        return Err(AppError::BadRequest("Invalid device ID"));
    }

    let db = state.db.clone();
    let sid = auth.sync_id;

    let artifact = tokio::task::spawn_blocking(move || {
        db.with_read_conn(|conn| {
            let epoch = match query.epoch {
                Some(e) => e,
                None => {
                    let device = db::get_device(conn, &sid, &target_device_id)?;
                    match device {
                        Some(d) => d.epoch,
                        None => return Ok(None),
                    }
                }
            };
            db::get_rekey_artifact(conn, &sid, epoch, &target_device_id)
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    match artifact {
        Some(data) => {
            let b64 = base64::engine::general_purpose::STANDARD;
            Ok(Json(serde_json::json!({
                "wrapped_key": b64.encode(data),
            }))
            .into_response())
        }
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

// ---------------------------------------------------------------------------
// post_ack — POST /v1/sync/{sync_id}/ack
// ---------------------------------------------------------------------------

pub async fn post_ack(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthIdentity>,
    Path(path_sync_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }

    let path = format!("/v1/sync/{}/ack", auth.sync_id);
    verify_signed_request(&state, &auth, &headers, "POST", &path, &body)?;

    let body_json: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| AppError::BadRequest("Invalid JSON"))?;
    let server_seq =
        body_json["server_seq"].as_i64().ok_or(AppError::BadRequest("Missing server_seq"))?;
    if server_seq < 0 {
        return Err(AppError::BadRequest("server_seq must be non-negative"));
    }

    let db = state.db.clone();
    let sid = auth.sync_id;
    let did = auth.device_id;

    let accepted = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            let latest_seq = db::get_latest_seq(conn, &sid)?;
            let pruned_floor_seq = db::get_pruned_floor_seq(conn, &sid)?;
            if server_seq > latest_seq && server_seq > pruned_floor_seq {
                return Ok(false);
            }
            db::upsert_device_receipt(conn, &sid, &did, server_seq)?;
            Ok(true)
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    if !accepted {
        return Err(AppError::BadRequest("server_seq exceeds latest server sequence"));
    }

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// post_rotate_ml_dsa — POST /v1/sync/{sync_id}/devices/{device_id}/rotate-ml-dsa
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RotateMlDsaRequest {
    pub new_ml_dsa_pk: String,
    pub ml_dsa_key_generation: i64,
    #[serde(default)]
    pub timestamp: i64,
    pub old_signs_new: String,
    pub new_signs_old: String,
    #[serde(default)]
    pub signed_registry_snapshot: Option<String>,
}

#[derive(Serialize)]
pub struct RotateMlDsaResponse {
    pub ml_dsa_key_generation: i64,
}

/// POST /v1/sync/{sync_id}/devices/{device_id}/rotate-ml-dsa
///
/// Rotates the device's ML-DSA-65 key with a cross-signed continuity proof.
/// The request must be signed with the device's CURRENT key.
pub async fn post_rotate_ml_dsa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(auth_identity): Extension<AuthIdentity>,
    Path((path_sync_id, device_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Json<RotateMlDsaResponse>, AppError> {
    if path_sync_id != auth_identity.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }

    // The authenticated device must match the path device_id
    if auth_identity.device_id != device_id {
        return Err(AppError::Forbidden("device_id mismatch"));
    }

    let path = format!("/v1/sync/{}/devices/{}/rotate-ml-dsa", auth_identity.sync_id, device_id);
    verify_signed_request(&state, &auth_identity, &headers, "POST", &path, &body)?;

    let req: RotateMlDsaRequest =
        serde_json::from_slice(&body).map_err(|_| AppError::BadRequest("Invalid JSON"))?;

    // Look up the current device to get its generation and ML-DSA public key
    let db = state.db.clone();
    let sid = auth_identity.sync_id.clone();
    let did = device_id.clone();
    let device = tokio::task::spawn_blocking(move || {
        db.with_read_conn(|conn| db::get_device(conn, &sid, &did))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?
    .ok_or(AppError::NotFound)?;

    let current_gen = device.ml_dsa_key_generation;
    if req.ml_dsa_key_generation <= current_gen {
        return Err(AppError::Conflict("generation must be greater than current"));
    }

    // Decode base64 fields
    let b64 = base64::engine::general_purpose::STANDARD;
    let new_pk = b64
        .decode(&req.new_ml_dsa_pk)
        .map_err(|_| AppError::BadRequest("invalid base64 in new_ml_dsa_pk"))?;
    let old_signs_new = b64
        .decode(&req.old_signs_new)
        .map_err(|_| AppError::BadRequest("invalid base64 in old_signs_new"))?;
    let new_signs_old = b64
        .decode(&req.new_signs_old)
        .map_err(|_| AppError::BadRequest("invalid base64 in new_signs_old"))?;

    // Build and verify the continuity proof
    let proof = prism_sync_crypto::pq::continuity_proof::MlDsaContinuityProof {
        device_id: device_id.clone(),
        old_generation: u32::try_from(current_gen)
            .map_err(|_| AppError::Internal("invalid generation in database".into()))?,
        new_generation: u32::try_from(req.ml_dsa_key_generation)
            .map_err(|_| AppError::BadRequest("ml_dsa_key_generation out of range"))?,
        timestamp: req.timestamp,
        new_ml_dsa_pk: new_pk.clone(),
        old_signs_new,
        new_signs_old,
    };

    let ed25519_pk: [u8; 32] = auth_identity
        .signing_public_key
        .try_into()
        .map_err(|_| AppError::Internal("invalid ed25519 pk length".into()))?;

    proof.verify(&ed25519_pk, &device.ml_dsa_65_public_key).map_err(|e| {
        tracing::warn!("ML-DSA continuity proof verification failed: {e}");
        AppError::BadRequest("invalid continuity proof")
    })?;

    // Decode optional signed registry snapshot
    let signed_snapshot = req
        .signed_registry_snapshot
        .as_ref()
        .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok());

    // Apply the rotation with a 30-day grace period for the old key
    let grace_expires_at = db::now_secs() + THIRTY_DAYS_SECS;
    let new_gen = req.ml_dsa_key_generation;
    let db = state.db.clone();
    let sid = auth_identity.sync_id.clone();
    let did = device_id.clone();
    let applied = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            Ok(do_rotate_ml_dsa(
                conn,
                &sid,
                &did,
                &new_pk,
                new_gen,
                grace_expires_at,
                signed_snapshot,
            ))
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))??;

    if !applied {
        return Err(AppError::Conflict("rotation was not applied (concurrent rotation?)"));
    }

    Ok(Json(RotateMlDsaResponse { ml_dsa_key_generation: new_gen }))
}

fn do_rotate_ml_dsa(
    conn: &rusqlite::Connection,
    sync_id: &str,
    device_id: &str,
    new_pk: &[u8],
    new_gen: i64,
    grace_expires_at: i64,
    signed_snapshot: Option<Vec<u8>>,
) -> Result<bool, AppError> {
    let applied =
        db::rotate_device_ml_dsa(conn, sync_id, device_id, new_pk, new_gen, grace_expires_at)
            .map_err(|e| AppError::Internal(e.to_string()))?;

    if applied {
        // Update registry state so clients can detect the key change
        let (kind, blob): (Option<&str>, Option<&[u8]>) = match signed_snapshot.as_deref() {
            Some(blob) => (Some("signed_registry_snapshot"), Some(blob)),
            None => (None, None),
        };
        sync_registry_state_with_current_devices(conn, sync_id, kind, blob)?;
    }

    Ok(applied)
}

#[cfg(test)]
mod atomic_revoke_registry_tests {
    use super::*;
    use crate::db::Database;
    use std::collections::HashMap;

    const SYNC_ID: &str = "sg1";
    const REQUESTER: &str = "a1b2c3d4e5f6";
    const TARGET: &str = "b7c8d9e0f1a2";

    fn seed_two_active_devices(conn: &rusqlite::Connection) {
        db::create_sync_group(conn, SYNC_ID, 0).unwrap();
        // Requester needs a non-empty x_wing key so the wrap-set validation has a
        // recipient; the snapshot store path is independent of the key contents.
        db::register_device_with_pq(
            conn, SYNC_ID, REQUESTER, b"sig-r", b"x-r", b"mldsa-r", b"mlkem-r", b"xwing-r", 0,
        )
        .unwrap();
        db::register_device_with_pq(
            conn, SYNC_ID, TARGET, b"sig-t", b"x-t", b"mldsa-t", b"mlkem-t", b"xwing-t", 0,
        )
        .unwrap();
    }

    fn survivor_wrapped_keys() -> HashMap<String, Vec<u8>> {
        // After excluding the revoked target, the requester is the sole survivor.
        let mut keys = HashMap::new();
        keys.insert(REQUESTER.to_string(), vec![0xab; 16]);
        keys
    }

    fn wrapped_pairs() -> Vec<(String, Vec<u8>)> {
        survivor_wrapped_keys().into_iter().collect()
    }

    #[test]
    fn atomic_revoke_with_snapshot_stores_registry_in_same_tx() {
        let db = Database::in_memory().unwrap();
        db.with_conn(|conn| {
            seed_two_active_devices(conn);
            let snapshot = b"signed-registry-epoch-1".to_vec();

            let new_epoch =
                do_atomic_revoke(conn, SYNC_ID, REQUESTER, TARGET, 1, false, &wrapped_pairs(), 7_776_000, Some(&snapshot))
                    .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;
            assert_eq!(new_epoch, 1);

            // The committed registry is visible after the tx commit, and its
            // artifact is the snapshot we attached — committed atomically with the
            // epoch bump.
            let state = db::get_registry_state(conn, SYNC_ID)?.expect("registry state present");
            let artifact = db::get_registry_artifact(conn, SYNC_ID, state.registry_version)?
                .expect("registry artifact present");
            assert_eq!(artifact.artifact_kind, "signed_registry_snapshot");
            assert_eq!(artifact.artifact_blob, snapshot);
            assert_eq!(db::get_sync_group_epoch(conn, SYNC_ID)?, Some(1));
            Ok::<_, rusqlite::Error>(())
        })
        .unwrap();
    }

    #[test]
    fn atomic_revoke_without_snapshot_stores_no_registry_artifact() {
        let db = Database::in_memory().unwrap();
        db.with_conn(|conn| {
            seed_two_active_devices(conn);

            let new_epoch =
                do_atomic_revoke(conn, SYNC_ID, REQUESTER, TARGET, 1, false, &wrapped_pairs(), 7_776_000, None)
                    .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;
            assert_eq!(new_epoch, 1);

            // Without the field, the behavior is exactly as before: the epoch bumps
            // but no registry artifact is stored by the revoke.
            assert_eq!(db::get_sync_group_epoch(conn, SYNC_ID)?, Some(1));
            assert!(db::get_registry_state(conn, SYNC_ID)?.is_none());
            Ok::<_, rusqlite::Error>(())
        })
        .unwrap();
    }

    #[test]
    fn aborted_atomic_revoke_leaves_no_registry() {
        let db = Database::in_memory().unwrap();
        db.with_conn(|conn| {
            seed_two_active_devices(conn);

            // A bad new_epoch (not current+1) aborts the whole tx before commit, so
            // neither the epoch bump nor the attached registry persists.
            let snapshot = b"signed-registry-epoch-9".to_vec();
            let result = do_atomic_revoke(
                conn, SYNC_ID, REQUESTER, TARGET, 9, false, &wrapped_pairs(), 7_776_000, Some(&snapshot),
            );
            assert!(result.is_err());

            assert_eq!(db::get_sync_group_epoch(conn, SYNC_ID)?, Some(0));
            assert!(db::get_registry_state(conn, SYNC_ID)?.is_none());
            // The target is still active — the aborted tx rolled back the revoke.
            assert_eq!(db::get_device(conn, SYNC_ID, TARGET)?.unwrap().status, "active");
            Ok::<_, rusqlite::Error>(())
        })
        .unwrap();
    }
}
