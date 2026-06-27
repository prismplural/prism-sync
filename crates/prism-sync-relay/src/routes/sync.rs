use axum::{
    body::Bytes,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::Engine;
use serde::Deserialize;

use crate::{
    db,
    errors::AppError,
    snapshot_limits::{
        DEFAULT_TARGETED_SNAPSHOT_TTL_SECS, MAX_SNAPSHOT_WIRE_BYTES,
        MAX_TARGETED_SNAPSHOTS_PER_GROUP,
    },
    state::AppState,
};

use super::{verify_signed_request, AuthIdentity};

const MAX_CHANGESET_SIZE: usize = 1_024 * 1_024; // 1 MB
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
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }

    let path = format!("/v1/sync/{}/changes", auth.sync_id);
    verify_signed_request(&state, &auth, &headers, "PUT", &path, &body)?;

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
    let brand_new_group_max_unpruned_batches = state.config.brand_new_group_max_unpruned_batches();
    let brand_new_group_age_secs = state.config.brand_new_group_age_secs();

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
                brand_new_group_max_unpruned_batches,
                brand_new_group_age_secs,
                stale_threshold,
            ))
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))??;

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
    state.notify_devices(&sync_id, Some(&device_id), &notification).await;

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
    brand_new_group_max_unpruned_batches: u64,
    brand_new_group_age_secs: u64,
    stale_threshold: i64,
) -> Result<i64, AppError> {
    // Epoch validation
    let current_epoch = db::get_sync_group_epoch(conn, sync_id)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or(AppError::NotFound)?;
    if device_epoch != current_epoch {
        return Err(AppError::EpochMismatch {
            envelope_epoch: device_epoch,
            relay_epoch: current_epoch,
        });
    }

    // Check max unpruned batches
    let prune_floor = db::get_safe_prune_seq(conn, sync_id, stale_threshold)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .unwrap_or(0);
    let created_at = get_sync_group_created_at(conn, sync_id)?.ok_or(AppError::NotFound)?;
    let group_age_secs = (db::now_secs() - created_at).max(0) as u64;
    let max_allowed = if group_age_secs <= brand_new_group_age_secs {
        brand_new_group_max_unpruned_batches.min(max_unpruned)
    } else {
        max_unpruned
    };
    let unpruned: u64 = conn
        .query_row(
            "SELECT COUNT(*) FROM batches WHERE sync_id = ?1 AND id > ?2",
            rusqlite::params![sync_id, prune_floor],
            |row| row.get(0),
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if unpruned >= max_allowed {
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

    let (first_retained_seq, batches, min_acked_seq, password_version, log_head_seq, log_token) =
        tokio::task::spawn_blocking(move || {
            // One read transaction so the floor gate, the batch page, the
            // min-acked seq, the password version, and the log-head accounting
            // all observe the same WAL snapshot. A cleanup prune committing
            // mid-read can no longer slip between the floor read and the batch
            // read, so the must_bootstrap gate provably matches the page it
            // gates, and the log-head gate sees a consistent head.
            db.with_read_tx(|conn| {
                let first_retained = db::get_first_retained_batch_seq(conn, &sid)?;
                let batches = db::get_batches_since(conn, &sid, since, limit)?;
                let min_acked = db::get_min_acked_seq(conn, &sid, stale_threshold)?;
                let pw_version = db::get_password_version(conn, &sid)?.unwrap_or(0);
                // The head is the highest seq the log can ever answer for: the
                // latest issued batch seq, or the pruned floor when every batch
                // for the group has been pruned (MAX(id)=0 but floor>0). A cursor
                // above this came from a different lineage (a restored DB).
                let latest = db::get_latest_seq(conn, &sid)?;
                let floor = db::get_pruned_floor_seq(conn, &sid)?;
                let log_head = latest.max(floor);
                let token = db::get_log_token(conn)?;
                Ok((first_retained, batches, min_acked, pw_version, log_head, token))
            })
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // The cursor must never sit above the log head. If it does, the relay's seq
    // stream regressed (a backup restore re-issued lower seqs) and the empty page
    // an up-to-date client would otherwise read as "in sync" actually masks lost
    // delivery. Force an explicit reset instead.
    if since > log_head_seq {
        tracing::warn!(
            sync_id = %trunc(&sync_id),
            device_id = %trunc(&device_id),
            since,
            log_head_seq,
            "Pull cursor is ahead of the log head — lineage regressed"
        );
        return Err(AppError::CursorAheadOfLog { since_seq: since, log_head_seq });
    }

    if let Some(first_retained_seq) = first_retained_seq {
        // `since` is the last sequence the client says it has applied. The
        // history is incomplete only when the next expected sequence is already
        // below the retained floor; `since == first_retained_seq - 1` can still
        // pull a complete tail starting at the first retained batch.
        if since.saturating_add(1) < first_retained_seq {
            tracing::warn!(
                sync_id = %trunc(&sync_id),
                device_id = %trunc(&device_id),
                since,
                first_retained_seq,
                "Pull cursor predates retained batch history"
            );
            return Err(AppError::MustBootstrapFromSnapshot {
                since_seq: since,
                first_retained_seq,
            });
        }
    }

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
        // Additive: old clients ignore unknown keys. `log_token` identifies
        // the seq lineage so a client can detect a restore-induced reset;
        // `log_head_seq` also closes the max_server_seq-echoes-since blindspot.
        "log_token": log_token,
        "log_head_seq": log_head_seq,
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
    let did = auth.device_id.clone();

    // The query returns the caller's own targeted row, else the group-wide
    // row, so a non-target sees `None` (404 → client maps to `Ok(None)`)
    // rather than a hard 403 — the cross-target 403 path is gone.
    let snapshot = tokio::task::spawn_blocking(move || {
        db.with_read_conn(|conn| db::get_snapshot(conn, &sid, &did))
    })
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
            // Retention is ACK-gated: the target device issues
            // `DELETE /v1/sync/{sync_id}/snapshot` once the snapshot has
            // been applied locally. TTL-based cleanup still fires via
            // `cleanup_expired_snapshots` for snapshots uploaded with an
            // explicit `X-Snapshot-TTL`.
            let b64 = base64::engine::general_purpose::STANDARD;
            Ok(Json(serde_json::json!({
                "epoch": snap.epoch,
                "server_seq_at": snap.server_seq_at,
                "data": b64.encode(&snap.data),
                "sender_device_id": snap.uploaded_by_device_id.unwrap_or_default(),
            }))
            .into_response())
        }
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

// ---------------------------------------------------------------------------
// delete_snapshot — DELETE /v1/sync/{sync_id}/snapshot
// ---------------------------------------------------------------------------

/// Acknowledge-and-delete the caller's own pair-time bootstrap snapshot. The
/// delete is a single conditional writer scoped to the caller's targeted row
/// (`DELETE WHERE sync_id = ? AND target_device_id = caller`), so it can only
/// ever remove the snapshot the caller was the audience for — never another
/// concurrent pairing's row and never the group-wide row (NULL target is not
/// ACK-deletable; it expires via TTL). Folding the target check into the DELETE
/// kills the old read-then-delete TOCTOU structurally. Returns 404 when the
/// caller has no targeted row, 204 on success.
pub async fn delete_snapshot(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthIdentity>,
    Path(path_sync_id): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }

    let path = format!("/v1/sync/{}/snapshot", auth.sync_id);
    verify_signed_request(&state, &auth, &headers, "DELETE", &path, &[])?;

    let db = state.db.clone();
    let sid = auth.sync_id.clone();
    let did = auth.device_id.clone();

    let deleted = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| db::delete_snapshot(conn, &sid, &did))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    if !deleted {
        // No row targeted at the caller: either it never existed, TTL cleanup
        // removed it, another concurrent pairing's row is all that remains, or
        // the group is group-wide-only (NULL target — not ACK-deletable).
        return Err(AppError::NotFound);
    }

    tracing::debug!(
        sync_id = %trunc(&auth.sync_id),
        device_id = %trunc(&auth.device_id),
        "Snapshot ACK-deleted by target device"
    );

    Ok(StatusCode::NO_CONTENT)
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

    if body.len() > MAX_SNAPSHOT_WIRE_BYTES {
        return Err(AppError::PayloadTooLarge("Snapshot exceeds wire size limit"));
    }

    let path = format!("/v1/sync/{}/snapshot", auth.sync_id);
    verify_signed_request(&state, &auth, &headers, "PUT", &path, &body)?;

    let server_seq_at = headers
        .get("X-Server-Seq-At")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i64>().ok())
        .ok_or(AppError::BadRequest("Missing or invalid X-Server-Seq-At header"))?;

    let ttl_secs = headers
        .get("X-Snapshot-TTL")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    let target_device_id = headers
        .get("X-For-Device-Id")
        .and_then(|v| v.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());
    if let Some(target_device_id) = target_device_id.as_deref() {
        if !crate::auth::is_valid_device_id(target_device_id) {
            return Err(AppError::BadRequest("Invalid X-For-Device-Id"));
        }
    }

    // A targeted (pair-time) snapshot must never outlive its pairing window, so
    // give it a relay-default TTL when the client did not set one. Group-wide
    // uploads keep their existing no-default semantics.
    let effective_ttl_secs = match (ttl_secs, target_device_id.is_some()) {
        (Some(ttl), _) => Some(ttl as i64),
        (None, true) => Some(DEFAULT_TARGETED_SNAPSHOT_TTL_SECS),
        (None, false) => None,
    };
    let expires_at = effective_ttl_secs.map(|ttl| chrono::Utc::now().timestamp() + ttl);

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
    // `body` is a `bytes::Bytes` — cheap to move into the blocking task
    // (reference-counted, no allocation). Avoid an extra ~150 MB copy via
    // `body.to_vec()` that the handler used to do.
    let upsert_result = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            Ok(do_put_snapshot(
                conn,
                &sid,
                &did,
                server_seq_at,
                &body,
                expires_at,
                target_device_id.as_deref(),
            ))
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    match &upsert_result {
        Err(AppError::SnapshotStale { .. }) => {
            state.metrics.inc(&state.metrics.snapshots_rejected_stale);
        }
        Err(AppError::TooManyTargetedSnapshots { .. }) => {
            state.metrics.inc(&state.metrics.snapshots_rejected_targeted_cap);
        }
        _ => {}
    }
    upsert_result?;

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

    // Cap concurrent targeted rows. The count excludes the caller's own
    // audience, so re-uploading to an existing audience updates it in place and
    // never trips the cap — and an expired-then-refreshed caller row can't push
    // the live unexpired total to cap+1 (the slack the expiry-agnostic precheck
    // used to leave until hourly cleanup). The whole handler runs under
    // `with_conn`'s writer mutex, so the count and the upsert are atomic.
    if let Some(target) = target_device_id {
        let other_audiences = db::count_unexpired_targeted_snapshots(conn, sync_id, Some(target))
            .map_err(|e| AppError::Internal(e.to_string()))?;
        if other_audiences >= MAX_TARGETED_SNAPSHOTS_PER_GROUP {
            return Err(AppError::TooManyTargetedSnapshots {
                max: MAX_TARGETED_SNAPSHOTS_PER_GROUP,
            });
        }
    }

    let affected = db::upsert_snapshot(
        conn,
        sync_id,
        epoch,
        server_seq_at,
        data,
        expires_at,
        target_device_id,
        Some(device_id),
    )
    .map_err(|e| AppError::Internal(e.to_string()))?;

    if affected == 0 {
        // The upsert's WHERE guard filtered our write: a snapshot with a
        // >= server_seq_at is already stored FOR THIS AUDIENCE (the conflict
        // target is the per-audience index). Report that audience's existing
        // (seq, target) so the client can advance its watermark and route the
        // 409 through the engine's suppression matrix.
        //
        // The lookup is a separate auto-commit statement, not a SQL
        // transaction. Safe because `with_conn` serializes writers
        // behind a single `Mutex<Connection>`, so no other writer can
        // mutate the row between the failed upsert and this read.
        let audience = target_device_id.unwrap_or("");
        let (current_server_seq_at, current_target_device_id) =
            db::get_snapshot_seq_and_target(conn, sync_id, audience)
                .map_err(|e| AppError::Internal(e.to_string()))?
                .unwrap_or((0, None));
        return Err(AppError::SnapshotStale { current_server_seq_at, current_target_device_id });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// delete_account — DELETE /v1/sync/{sync_id}
// ---------------------------------------------------------------------------

pub async fn delete_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(auth): Extension<AuthIdentity>,
    Path(path_sync_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }
    verify_signed_request(
        &state,
        &auth,
        &headers,
        "DELETE",
        &format!("/v1/sync/{}", auth.sync_id),
        &[],
    )?;

    let sync_id = auth.sync_id.clone();
    let device_id = auth.device_id.clone();

    let db = state.db.clone();
    let sid = sync_id.clone();
    let did = device_id;

    let media_storage_path = state.config.media_storage_path.clone();

    let result = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| Ok(do_delete_account(conn, &sid, &did)))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))??;

    match result {
        Some(media_ids) => {
            // Clean up media files from disk
            for media_id in &media_ids {
                let path = std::path::Path::new(&media_storage_path).join(&sync_id).join(media_id);
                let _ = std::fs::remove_file(&path);
            }
            let dir = std::path::Path::new(&media_storage_path).join(&sync_id);
            let _ = std::fs::remove_dir(&dir);

            tracing::debug!(sync_id = %trunc(&sync_id), "Sync group deleted");
            Ok(StatusCode::NO_CONTENT)
        }
        None => Err(AppError::Forbidden("Only the sole active admin can delete the sync group")),
    }
}

fn do_delete_account(
    conn: &rusqlite::Connection,
    sync_id: &str,
    device_id: &str,
) -> Result<Option<Vec<String>>, AppError> {
    let devices = db::list_devices(conn, sync_id).map_err(|e| AppError::Internal(e.to_string()))?;
    let active: Vec<_> = devices.into_iter().filter(|d| d.status == "active").collect();
    if active.len() == 1 && active[0].device_id == device_id {
        let media_ids =
            db::delete_sync_group(conn, sync_id).map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(Some(media_ids))
    } else {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn trunc(s: &str) -> &str {
    let end = s.len().min(16);
    &s[..end]
}

fn get_sync_group_created_at(
    conn: &rusqlite::Connection,
    sync_id: &str,
) -> Result<Option<i64>, AppError> {
    use rusqlite::OptionalExtension;

    conn.query_row(
        "SELECT created_at FROM sync_groups WHERE sync_id = ?1",
        rusqlite::params![sync_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(|e| AppError::Internal(e.to_string()))
}
