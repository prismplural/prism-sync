use std::collections::HashSet;

use axum::{
    body::Bytes,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::Engine;
use serde::Deserialize;

use crate::{auth, db, errors::AppError, state::AppState};

use super::{verify_signed_request, AuthIdentity};

const MAX_WRAPPED_KEY_SIZE: usize = 1024;
const THIRTY_DAYS_SECS: i64 = 30 * 24 * 3600;

const REVOKED_SESSION_RETENTION_SECS: i64 = 30 * 24 * 3600;

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

    let devices =
        tokio::task::spawn_blocking(move || db.with_read_conn(|conn| db::list_devices(conn, &sid)))
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
                "epoch": d.epoch,
                "status": d.status,
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
    device_id: &str,
) -> Result<(), AppError> {
    let active =
        db::count_active_devices(conn, sync_id).map_err(|e| AppError::Internal(e.to_string()))?;
    if active <= 1 {
        return Err(AppError::Forbidden(
            "Cannot deregister the last active device; delete the sync group instead",
        ));
    }
    let deleted = db::delete_device(conn, sync_id, device_id)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if !deleted {
        return Err(AppError::NotFound);
    }
    Ok(())
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

    let path = format!(
        "/v1/sync/{}/devices/{}/revoke",
        auth.sync_id, target_device_id
    );
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
    let new_epoch = body_json["new_epoch"]
        .as_i64()
        .ok_or(AppError::BadRequest("Missing new_epoch"))?;
    let remote_wipe = body_json["remote_wipe"].as_bool().unwrap_or(false);
    let wrapped_keys = parse_wrapped_keys(&body_json)?;

    let sync_id = auth.sync_id.clone();
    let requester = auth.device_id.clone();
    let target = target_device_id.clone();
    let db = state.db.clone();

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

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "new_epoch": new_epoch })),
    ))
}

fn do_atomic_revoke(
    conn: &rusqlite::Connection,
    sync_id: &str,
    requester_device_id: &str,
    target_device_id: &str,
    new_epoch: i64,
    remote_wipe: bool,
    wrapped_keys: &[(String, Vec<u8>)],
) -> Result<i64, AppError> {
    if target_device_id == requester_device_id {
        return Err(AppError::BadRequest(
            "Self-deregister must use DELETE /devices/{device_id}",
        ));
    }

    let tx = conn
        .unchecked_transaction()
        .map_err(|e| AppError::Internal(e.to_string()))?;

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
    if target.status != "active" {
        return Err(AppError::Conflict("Target device is not active"));
    }

    let expected_survivors = active_survivor_set(&tx, sync_id, Some(target_device_id))?;
    validate_wrapped_keys(&expected_survivors, wrapped_keys)?;

    let changed = db::revoke_device(&tx, sync_id, target_device_id, remote_wipe)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if !changed {
        return Err(AppError::Conflict("Target device is not active"));
    }

    let _ = db::touch_session(&tx, sync_id, target_device_id, THIRTY_DAYS_SECS);
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

    let epoch = body_json["epoch"]
        .as_i64()
        .ok_or(AppError::BadRequest("Missing epoch"))?;
    let wrapped_keys = parse_wrapped_keys(&body_json)?;

    let sync_id = auth.sync_id.clone();
    let device_id = auth.device_id.clone();

    let db = state.db.clone();
    let sid = sync_id.clone();
    let did = device_id.clone();

    let new_epoch = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| Ok(do_rekey(conn, &sid, &did, epoch, &wrapped_keys)))
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

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "new_epoch": new_epoch })),
    ))
}

fn do_rekey(
    conn: &rusqlite::Connection,
    sync_id: &str,
    device_id: &str,
    epoch: i64,
    wrapped_keys: &[(String, Vec<u8>)],
) -> Result<i64, AppError> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let needs_rekey = db::get_needs_rekey(&tx, sync_id)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .unwrap_or(false);
    if needs_rekey {
        return Err(AppError::Conflict(
            "Rekey after revocation must use the atomic endpoint",
        ));
    }

    let current_epoch = db::get_sync_group_epoch(&tx, sync_id)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or(AppError::NotFound)?;
    if epoch != current_epoch + 1 {
        return Err(AppError::BadRequest(
            "Rekey epoch must be current_epoch + 1",
        ));
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
        || expected_devices
            .iter()
            .any(|id| !seen.contains(id.as_str()))
    {
        return Err(AppError::BadRequest(
            "wrapped_keys must match the active device set exactly",
        ));
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
            let b64_str = val
                .as_str()
                .ok_or(AppError::BadRequest("wrapped_keys values must be strings"))?;
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
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }

    let body_json: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| AppError::BadRequest("Invalid JSON"))?;
    let server_seq = body_json["server_seq"]
        .as_i64()
        .ok_or(AppError::BadRequest("Missing server_seq"))?;

    let db = state.db.clone();
    let sid = auth.sync_id;
    let did = auth.device_id;
    let stale_threshold = state.config.stale_device_secs as i64;

    let pruned = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            db::upsert_device_receipt(conn, &sid, &did, server_seq)?;
            match db::get_safe_prune_seq(conn, &sid, stale_threshold)? {
                Some(safe_seq) => db::prune_batches_before(conn, &sid, safe_seq),
                None => Ok(0),
            }
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    if pruned > 0 {
        state
            .metrics
            .changesets_pruned
            .fetch_add(pruned as u64, std::sync::atomic::Ordering::Relaxed);
    }

    Ok(StatusCode::NO_CONTENT)
}
