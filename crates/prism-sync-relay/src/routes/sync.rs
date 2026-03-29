use axum::{
    body::Bytes,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::Engine;
use serde::Deserialize;

use crate::{db, errors::AppError, state::AppState};

use super::AuthIdentity;

const MAX_CHANGESET_SIZE: usize = 1_024 * 1_024; // 1 MB
const MAX_SNAPSHOT_SIZE: usize = 25 * 1_024 * 1_024; // 25 MB
const DEFAULT_PULL_LIMIT: i64 = 100;

// ---------------------------------------------------------------------------
// push_changes — PUT /v1/sync/{sync_id}/changes
// ---------------------------------------------------------------------------

/// Minimal fields the relay extracts from the opaque `SignedBatchEnvelope`.
#[derive(Deserialize)]
struct EnvelopeHeader {
    batch_id: String,
    epoch: i64,
}

pub async fn push_changes(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthIdentity>,
    Path(path_sync_id): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }

    if body.len() > MAX_CHANGESET_SIZE {
        return Err(AppError::PayloadTooLarge("Batch exceeds 1 MB limit"));
    }

    let header: EnvelopeHeader =
        serde_json::from_slice(&body).map_err(|_| AppError::BadRequest("Invalid JSON body"))?;

    let sync_id = auth.sync_id.clone();
    let device_id = auth.device_id.clone();
    let batch_id = header.batch_id;
    let device_epoch = header.epoch;
    let data = body.to_vec();
    let max_unpruned = state.config.max_unpruned_batches;

    tracing::debug!(
        sync_id = %trunc(&sync_id),
        device_id = %trunc(&device_id),
        batch_id = %trunc(&batch_id),
        epoch = device_epoch,
        body_bytes = data.len(),
        "Push changes request"
    );

    let stale_threshold = state.config.stale_device_secs as i64;

    let db = state.db.clone();
    let sid = sync_id.clone();
    let did = device_id.clone();
    let bid = batch_id;

    let server_seq = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            Ok(do_push(
                conn,
                &sid,
                &did,
                &bid,
                device_epoch,
                &data,
                max_unpruned,
                stale_threshold,
            ))
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))??;

    state.metrics.inc(&state.metrics.changesets_pushed);

    tracing::debug!(
        sync_id = %trunc(&sync_id),
        device_id = %trunc(&device_id),
        server_seq,
        "Push changes stored"
    );

    // Notify other devices via WebSocket
    let notification = serde_json::json!({
        "type": "new_data",
        "server_seq": server_seq,
    })
    .to_string();
    state
        .notify_devices(&sync_id, Some(&device_id), &notification)
        .await;

    Ok(Json(serde_json::json!({ "server_seq": server_seq })))
}

#[allow(clippy::too_many_arguments)]
fn do_push(
    conn: &rusqlite::Connection,
    sync_id: &str,
    device_id: &str,
    batch_id: &str,
    device_epoch: i64,
    data: &[u8],
    max_unpruned: u64,
    stale_threshold: i64,
) -> Result<i64, AppError> {
    // Epoch validation
    let current_epoch = db::get_sync_group_epoch(conn, sync_id)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or(AppError::NotFound)?;
    if device_epoch != current_epoch {
        return Err(AppError::Forbidden(
            "Epoch mismatch; perform epoch recovery first",
        ));
    }

    // Check max unpruned batches
    let prune_floor = db::get_safe_prune_seq(conn, sync_id, stale_threshold)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .unwrap_or(0);
    let unpruned: u64 = conn
        .query_row(
            "SELECT COUNT(*) FROM batches WHERE sync_id = ?1 AND id > ?2",
            rusqlite::params![sync_id, prune_floor],
            |row| row.get(0),
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if unpruned >= max_unpruned {
        return Err(AppError::StorageFull(
            "Too many unpruned batches; all devices must pull or a snapshot is needed",
        ));
    }

    db::insert_batch(conn, sync_id, current_epoch, device_id, batch_id, data)
        .map_err(|e| AppError::Internal(e.to_string()))
}

// ---------------------------------------------------------------------------
// pull_changes — GET /v1/sync/{sync_id}/changes?since=N&limit=100
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct PullQuery {
    since: Option<i64>,
    limit: Option<i64>,
}

pub async fn pull_changes(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthIdentity>,
    Path(path_sync_id): Path<String>,
    Query(query): Query<PullQuery>,
) -> Result<impl IntoResponse, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }

    let since = query.since.unwrap_or(0);
    let limit = query.limit.unwrap_or(DEFAULT_PULL_LIMIT).clamp(1, 1000);
    let sync_id = auth.sync_id.clone();
    let device_id = auth.device_id.clone();
    let stale_threshold = state.config.stale_device_secs as i64;

    tracing::debug!(
        sync_id = %trunc(&sync_id),
        device_id = %trunc(&device_id),
        since,
        limit,
        "Pull changes request"
    );

    let db = state.db.clone();
    let sid = sync_id.clone();

    let (batches, min_acked_seq, password_version) = tokio::task::spawn_blocking(move || {
        db.with_read_conn(|conn| {
            let batches = db::get_batches_since(conn, &sid, since, limit)?;
            let min_acked = db::get_min_acked_seq(conn, &sid, stale_threshold)?;
            let pw_version = db::get_password_version(conn, &sid)?.unwrap_or(0);
            Ok((batches, min_acked, pw_version))
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    state.metrics.inc(&state.metrics.changesets_pulled);

    let max_server_seq = batches.iter().map(|b| b.server_seq).max().unwrap_or(since);

    tracing::debug!(
        sync_id = %trunc(&sync_id),
        batch_count = batches.len(),
        max_server_seq,
        "Pull changes returning"
    );

    // Batch data is the full SignedBatchEnvelope JSON stored as a blob.
    let encoded: Vec<serde_json::Value> = batches
        .iter()
        .map(|batch| {
            let envelope: serde_json::Value =
                serde_json::from_slice(&batch.data).unwrap_or(serde_json::Value::Null);
            serde_json::json!({
                "server_seq": batch.server_seq,
                "received_at": batch.received_at,
                "envelope": envelope,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "batches": encoded,
        "max_server_seq": max_server_seq,
        "min_acked_seq": min_acked_seq,
        "password_version": password_version,
    })))
}

// ---------------------------------------------------------------------------
// get_snapshot — GET /v1/sync/{sync_id}/snapshot
// ---------------------------------------------------------------------------

pub async fn get_snapshot(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthIdentity>,
    Path(path_sync_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }

    let db = state.db.clone();
    let sid = auth.sync_id.clone();

    let snapshot =
        tokio::task::spawn_blocking(move || db.with_read_conn(|conn| db::get_snapshot(conn, &sid)))
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?
            .map_err(|e| AppError::Internal(e.to_string()))?;

    tracing::debug!(
        sync_id = %trunc(&auth.sync_id),
        found = snapshot.is_some(),
        "Get snapshot"
    );

    match snapshot {
        Some(snap) => {
            if let Some(target_device_id) = snap.target_device_id.as_deref() {
                if target_device_id != auth.device_id {
                    return Err(AppError::Forbidden(
                        "Snapshot is targeted at a different device",
                    ));
                }
            }

            // Auto-delete after the intended recipient downloads it. For legacy
            // snapshots without a target, preserve the existing cross-device
            // deletion behavior.
            let should_delete = snap
                .target_device_id
                .as_deref()
                .map(|target| target == auth.device_id)
                .unwrap_or_else(|| {
                    snap.uploaded_by_device_id
                        .as_deref()
                        .is_some_and(|uploader| uploader != auth.device_id)
                });
            if should_delete {
                let db = state.db.clone();
                let sid = auth.sync_id.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    db.with_conn(|conn| db::delete_snapshot(conn, &sid))
                })
                .await;
                tracing::debug!(
                    sync_id = %trunc(&auth.sync_id),
                    device_id = %trunc(&auth.device_id),
                    "Snapshot auto-deleted after cross-device download"
                );
            }

            let b64 = base64::engine::general_purpose::STANDARD;
            Ok(Json(serde_json::json!({
                "epoch": snap.epoch,
                "server_seq_at": snap.server_seq_at,
                "data": b64.encode(&snap.data),
            }))
            .into_response())
        }
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

// ---------------------------------------------------------------------------
// put_snapshot — PUT /v1/sync/{sync_id}/snapshot
// ---------------------------------------------------------------------------

pub async fn put_snapshot(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthIdentity>,
    Path(path_sync_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }

    if body.len() > MAX_SNAPSHOT_SIZE {
        return Err(AppError::PayloadTooLarge("Snapshot exceeds 25 MB limit"));
    }

    let server_seq_at = headers
        .get("X-Server-Seq-At")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i64>().ok())
        .ok_or(AppError::BadRequest(
            "Missing or invalid X-Server-Seq-At header",
        ))?;

    let ttl_secs = headers
        .get("X-Snapshot-TTL")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    let expires_at = ttl_secs.map(|ttl| chrono::Utc::now().timestamp() + ttl as i64);
    let target_device_id = headers
        .get("X-For-Device-Id")
        .and_then(|v| v.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());

    let sync_id = auth.sync_id.clone();
    let device_id = auth.device_id.clone();

    tracing::debug!(
        sync_id = %trunc(&sync_id),
        server_seq_at,
        body_bytes = body.len(),
        ?ttl_secs,
        ?expires_at,
        ?target_device_id,
        "Put snapshot request"
    );

    let db = state.db.clone();
    let sid = sync_id.clone();
    let did = device_id;
    let data = body.to_vec();

    tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            Ok(do_put_snapshot(
                conn,
                &sid,
                &did,
                server_seq_at,
                &data,
                expires_at,
                target_device_id.as_deref(),
            ))
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))??;

    state.metrics.inc(&state.metrics.snapshots_exchanged);
    tracing::debug!(sync_id = %trunc(&sync_id), "Put snapshot stored");
    Ok(StatusCode::NO_CONTENT)
}

fn do_put_snapshot(
    conn: &rusqlite::Connection,
    sync_id: &str,
    device_id: &str,
    server_seq_at: i64,
    data: &[u8],
    expires_at: Option<i64>,
    target_device_id: Option<&str>,
) -> Result<(), AppError> {
    // Look up the device's current epoch from the devices table
    let device = db::get_device(conn, sync_id, device_id)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or(AppError::NotFound)?;
    let epoch = device.epoch;

    db::upsert_snapshot(
        conn,
        sync_id,
        epoch,
        server_seq_at,
        data,
        expires_at,
        target_device_id,
        Some(device_id),
    )
    .map_err(|e| AppError::Internal(e.to_string()))
}

// ---------------------------------------------------------------------------
// delete_account — DELETE /v1/sync/{sync_id}
// ---------------------------------------------------------------------------

pub async fn delete_account(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthIdentity>,
    Path(path_sync_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }

    let sync_id = auth.sync_id.clone();
    let device_id = auth.device_id.clone();

    let db = state.db.clone();
    let sid = sync_id.clone();
    let did = device_id;

    let deleted = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| Ok(do_delete_account(conn, &sid, &did)))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))??;

    if deleted {
        tracing::debug!(sync_id = %trunc(&sync_id), "Sync group deleted");
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::Forbidden(
            "Only the sole active admin can delete the sync group",
        ))
    }
}

fn do_delete_account(
    conn: &rusqlite::Connection,
    sync_id: &str,
    device_id: &str,
) -> Result<bool, AppError> {
    let devices = db::list_devices(conn, sync_id).map_err(|e| AppError::Internal(e.to_string()))?;
    let active: Vec<_> = devices
        .into_iter()
        .filter(|d| d.status == "active")
        .collect();
    if active.len() == 1 && active[0].device_id == device_id {
        db::delete_sync_group(conn, sync_id).map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn trunc(s: &str) -> &str {
    let end = s.len().min(16);
    &s[..end]
}
