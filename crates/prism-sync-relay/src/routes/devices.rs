use axum::{
    body::Bytes,
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use base64::Engine;
use serde::Deserialize;

use crate::{db, errors::AppError, state::AppState};

use super::AuthIdentity;

#[derive(Deserialize)]
pub struct RevokeQuery {
    #[serde(default)]
    pub remote_wipe: bool,
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
    Extension(auth): Extension<AuthIdentity>,
    Path((path_sync_id, target_device_id)): Path<(String, String)>,
    Query(query): Query<RevokeQuery>,
) -> Result<impl IntoResponse, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }

    let sync_id = auth.sync_id.clone();
    let requester = auth.device_id.clone();
    let is_self = target_device_id == requester;

    if is_self {
        // Self-deregister: fully remove device row and associated data
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
    } else {
        // Revoke another device
        let db = state.db.clone();
        let sid = sync_id.clone();
        let did = requester.clone();
        let target = target_device_id.clone();

        let remote_wipe = query.remote_wipe;
        tokio::task::spawn_blocking(move || {
            db.with_conn(|conn| Ok(do_revoke_device(conn, &sid, &did, &target, remote_wipe)))
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|e| AppError::Internal(e.to_string()))??;

        state
            .notify_devices(
                &sync_id,
                Some(&requester),
                &serde_json::json!({
                    "type": "device_revoked",
                    "device_id": target_device_id,
                    "remote_wipe": query.remote_wipe,
                })
                .to_string(),
            )
            .await;
    }

    Ok(StatusCode::NO_CONTENT)
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

fn do_revoke_device(
    conn: &rusqlite::Connection,
    sync_id: &str,
    _requester_device_id: &str,
    target_device_id: &str,
    remote_wipe: bool,
) -> Result<(), AppError> {
    let changed = db::revoke_device(conn, sync_id, target_device_id, remote_wipe)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if !changed {
        return Err(AppError::NotFound);
    }

    // Keep the revoked device's session with an extended TTL (30 days) so the
    // auth middleware can look up the device and embed wipe status in the 401
    // response even if the device has been offline for a while.
    let thirty_days: i64 = 30 * 24 * 3600;
    let _ = db::touch_session(conn, sync_id, target_device_id, thirty_days);

    // Mark needs_rekey (epoch bump happens during rekey)
    db::set_needs_rekey(conn, sync_id, true).map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// post_rekey — POST /v1/sync/{sync_id}/rekey
// ---------------------------------------------------------------------------

pub async fn post_rekey(
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

    let epoch = body_json["epoch"]
        .as_i64()
        .ok_or(AppError::BadRequest("Missing epoch"))?;
    let revoked_device_id = body_json["revoked_device_id"].as_str().map(str::to_string);
    let wrapped_keys = parse_wrapped_keys(&body_json)?;

    let sync_id = auth.sync_id.clone();
    let device_id = auth.device_id.clone();

    let db = state.db.clone();
    let sid = sync_id.clone();
    let did = device_id;

    let new_epoch = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            Ok(do_rekey(
                conn,
                &sid,
                &did,
                epoch,
                revoked_device_id.as_deref(),
                &wrapped_keys,
            ))
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))??;

    // Notify all devices
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
    _device_id: &str,
    epoch: i64,
    revoked_device_id: Option<&str>,
    wrapped_keys: &[(String, Vec<u8>)],
) -> Result<i64, AppError> {
    let current_epoch = db::get_sync_group_epoch(conn, sync_id)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or(AppError::NotFound)?;
    if epoch != current_epoch + 1 {
        return Err(AppError::BadRequest(
            "Rekey epoch must be current_epoch + 1",
        ));
    }

    // Revoke device if specified
    if let Some(target) = revoked_device_id {
        let changed = db::revoke_device(conn, sync_id, target, false)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        if changed {
            // Extend session TTL (30 days) so auth middleware can embed wipe
            // status when the revoked device next connects.
            let thirty_days: i64 = 30 * 24 * 3600;
            let _ = db::touch_session(conn, sync_id, target, thirty_days);
        }
        // If already revoked, continue silently — idempotent
    }

    // Verify all active devices are covered
    let active_devices: Vec<String> = db::list_devices(conn, sync_id)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .into_iter()
        .filter(|d| d.status == "active")
        .map(|d| d.device_id)
        .collect();
    let artifact_ids: std::collections::HashSet<&str> =
        wrapped_keys.iter().map(|(id, _)| id.as_str()).collect();
    for active_id in &active_devices {
        if !artifact_ids.contains(active_id.as_str()) {
            return Err(AppError::BadRequest(
                "Missing rekey artifact for active device",
            ));
        }
    }

    // Update epoch, clear needs_rekey
    db::update_sync_group_epoch(conn, sync_id, epoch)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    db::set_needs_rekey(conn, sync_id, false).map_err(|e| AppError::Internal(e.to_string()))?;
    conn.execute(
        "UPDATE devices SET epoch = ?1 WHERE sync_id = ?2 AND status = 'active'",
        rusqlite::params![epoch, sync_id],
    )
    .map_err(|e| AppError::Internal(e.to_string()))?;

    // Store rekey artifacts
    for (dev_id, key_bytes) in wrapped_keys {
        db::store_rekey_artifact(conn, sync_id, epoch, dev_id, key_bytes)
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    Ok(epoch)
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

#[derive(Deserialize)]
pub struct RekeyArtifactQuery {
    /// Optional epoch to fetch. If omitted, uses the device's current epoch.
    pub epoch: Option<i64>,
}

pub async fn get_rekey_artifact(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthIdentity>,
    Path((path_sync_id, target_device_id)): Path<(String, String)>,
    Query(query): Query<RekeyArtifactQuery>,
) -> Result<impl IntoResponse, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }

    let db = state.db.clone();
    let sid = auth.sync_id;

    let artifact = tokio::task::spawn_blocking(move || {
        db.with_read_conn(|conn| {
            // Use client-specified epoch if provided, otherwise look up from device record
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

