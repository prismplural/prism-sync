use axum::{
    body::Bytes,
    extract::{Extension, Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use sha2::{Digest, Sha256};

use crate::{db, errors::AppError, state::AppState};

use super::{verify_signed_request, AuthIdentity};

/// Validate media_id format: alphanumeric + hyphens only, <= 36 chars.
fn is_valid_media_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 36 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Validate content hash format: exactly 64 hex chars.
fn is_valid_content_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit())
}

/// Build the disk path for a media blob: {storage_path}/{sync_id}/{media_id}
fn media_file_path(storage_path: &str, sync_id: &str, media_id: &str) -> std::path::PathBuf {
    std::path::Path::new(storage_path).join(sync_id).join(media_id)
}

/// Build a unique staging path for an in-flight upload:
/// `{storage_path}/{sync_id}/.staging/{media_id}.{nonce}`. Never the final path,
/// so a failed or concurrent writer can only ever touch its own staging file
/// (the final path is shared, keyed by `{sync_id}/{media_id}`). A validated
/// `media_id` is alphanumeric/hyphens, so it can never collide with the
/// `.staging` directory name.
fn staging_file_path(
    storage_path: &str,
    sync_id: &str,
    media_id: &str,
    nonce: &str,
) -> std::path::PathBuf {
    std::path::Path::new(storage_path)
        .join(sync_id)
        .join(".staging")
        .join(format!("{media_id}.{nonce}"))
}

/// Parse the optional `X-Media-TTL` (seconds) header into an absolute
/// `expires_at`, clamped to `[media_resupply_ttl_min_secs, retention]`. Absent
/// or unparseable header ⇒ `None` ⇒ the global retention applies (back-compat:
/// an old relay ignores the header, a new relay treats a missing header as the
/// default 90-day retention). The header is NOT part of the signed request
/// bytes, so old/new client+relay combinations all degrade gracefully.
fn parse_media_ttl(headers: &HeaderMap, config: &crate::config::Config, now: i64) -> Option<i64> {
    let requested = headers
        .get("X-Media-TTL")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())?;
    let min = config.media_resupply_ttl_min_secs;
    let max = config.media_retention_days.saturating_mul(86_400);
    let clamped = requested.clamp(min, max.max(min));
    Some(now + clamped as i64)
}

// ---------------------------------------------------------------------------
// upload_media — POST /v1/sync/{sync_id}/media
// ---------------------------------------------------------------------------

pub async fn upload_media(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthIdentity>,
    Path(path_sync_id): Path<String>,
    headers: HeaderMap,
    // Note: Entire body buffered in memory (max `media_max_file_bytes`, default 10MB).
    // Acceptable at current scale. For high-concurrency deployments, consider
    // streaming to disk via axum::body::Body with incremental SHA-256.
    body: Bytes,
) -> Result<Response, AppError> {
    // 1. Validate path_sync_id == auth.sync_id
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }

    // 2. Extract X-Media-Id and X-Content-Hash from headers
    let media_id = headers
        .get("X-Media-Id")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::BadRequest("Missing X-Media-Id header"))?;
    let content_hash = headers
        .get("X-Content-Hash")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::BadRequest("Missing X-Content-Hash header"))?;

    // 3. Validate media_id format
    if !is_valid_media_id(media_id) {
        return Err(AppError::BadRequest(
            "Invalid X-Media-Id: must be alphanumeric/hyphens, max 36 chars",
        ));
    }

    // 4. Validate content hash format
    if !is_valid_content_hash(content_hash) {
        return Err(AppError::BadRequest(
            "Invalid X-Content-Hash: must be exactly 64 hex characters",
        ));
    }

    // 5. Rate limit
    let rate_key = format!("media_upload:{}", auth.sync_id);
    if !state.media_upload_rate_limiter.check(
        &rate_key,
        state.config.media_upload_rate_limit,
        state.config.media_upload_rate_window_secs,
    ) {
        return Err(AppError::TooManyRequests);
    }

    // 6. Validate body size
    if body.len() > state.config.media_max_file_bytes {
        return Err(AppError::PayloadTooLarge("Media file exceeds size limit"));
    }

    // 7. Verify SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let computed_hash = hex::encode(hasher.finalize());
    if computed_hash != content_hash {
        return Err(AppError::BadRequest("Content hash mismatch"));
    }

    // 8. Verify signed request
    let path = format!("/v1/sync/{}/media", auth.sync_id);
    verify_signed_request(&state, &auth, &headers, "POST", &path, &body)?;

    // 9. Resolve the per-upload TTL (clamped) → absolute expires_at.
    let now = db::now_secs();
    let ttl_expires_at = parse_media_ttl(&headers, &state.config, now);

    let sync_id = auth.sync_id.clone();
    let device_id = auth.device_id.clone();
    let media_id_owned = media_id.to_string();
    let content_hash_owned = content_hash.to_string();
    let size_bytes = body.len() as i64;
    let quota = state.config.media_quota_bytes_per_group as i64;
    let grace = state.config.media_pending_grace_secs as i64;
    let sweep_cap = state.config.media_expired_sweep_cap;
    let storage_path = state.config.media_storage_path.clone();
    let final_path = media_file_path(&storage_path, &sync_id, &media_id_owned);

    // 10. Preflight: always-sweep this group's expired rows (bounded ≤ cap),
    //     then a cheap quota reject *before* staging any bytes. Sweeping every
    //     upload bounds physical disk to ≈ the live quota; the cleanup loop is
    //     the catch-all backstop. The authoritative quota decision is re-checked
    //     inside the reserve txn below, so this preflight only needs to reject
    //     the obvious "would add bytes over quota" case to avoid staging a body
    //     that's doomed. Idempotent/repair re-uploads of an existing committed
    //     blob (Δquota 0) are NOT rejected here.
    {
        let db = state.db.clone();
        let sid = sync_id.clone();
        let mid = media_id_owned.clone();
        let (swept, usage, would_add_bytes) = tokio::task::spawn_blocking(move || {
            db.with_conn(|conn| {
                let tx = rusqlite::Transaction::new_unchecked(
                    conn,
                    rusqlite::TransactionBehavior::Immediate,
                )?;
                let swept = db::sweep_expired_media_for_group(&tx, &sid, now, sweep_cap)?;
                let usage = db::get_group_media_usage_at(&tx, &sid, now, grace)?;
                let would_add_bytes = match db::get_media_metadata(&tx, &mid)? {
                    // No row, or an expired/soft-deleted row (resurrect) adds
                    // its bytes back. A committed-live row (idempotent/repair)
                    // or a pending reserve (→ 202) adds nothing.
                    None => true,
                    Some(row) => !row.is_servable_at(now) && !row.is_pending(),
                };
                tx.commit()?;
                Ok((swept, usage, would_add_bytes))
            })
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|e| AppError::Internal(e.to_string()))?;

        // Unlink swept expired files (best-effort; the cleanup loop backstops).
        for swept_id in &swept {
            let _ = tokio::fs::remove_file(media_file_path(&storage_path, &sync_id, swept_id)).await;
        }

        if would_add_bytes && usage + size_bytes > quota {
            return Err(AppError::StorageFull("Media quota exceeded for sync group"));
        }
    }

    // 11. Stage: write the body to a UNIQUE staging path (never the final path).
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let staging_path = staging_file_path(&storage_path, &sync_id, &media_id_owned, &nonce);
    {
        let staging_path = staging_path.clone();
        tokio::task::spawn_blocking(move || -> Result<(), std::io::Error> {
            if let Some(parent) = staging_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&staging_path, &body)?;
            Ok(())
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|e| AppError::Internal(format!("Failed to stage media file: {e}")))?;
    }

    // 12. Reserve: resolve the upsert case table in an IMMEDIATE txn that
    //     serializes same-media_id writers, writing a PENDING row for an
    //     insert/resurrect. File presence (checked just before the txn to keep
    //     the TOCTOU window tiny) distinguishes idempotent from repair.
    let final_present = tokio::fs::try_exists(&final_path).await.unwrap_or(false);
    let outcome = {
        let db = state.db.clone();
        let sid = sync_id.clone();
        let did = device_id.clone();
        let mid = media_id_owned.clone();
        let chash = content_hash_owned.clone();
        tokio::task::spawn_blocking(move || {
            db.with_conn(|conn| {
                let tx = rusqlite::Transaction::new_unchecked(
                    conn,
                    rusqlite::TransactionBehavior::Immediate,
                )?;
                let oc = db::reserve_media_upload(
                    &tx,
                    &mid,
                    &sid,
                    &did,
                    size_bytes,
                    &chash,
                    ttl_expires_at,
                    quota,
                    now,
                    grace,
                    final_present,
                )?;
                tx.commit()?;
                Ok(oc)
            })
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|e| AppError::Internal(e.to_string()))?
    };

    use db::ReserveOutcome;
    match outcome {
        ReserveOutcome::ReservedPending | ReserveOutcome::RepairCommitted => {
            // 13. Promote: atomically rename staging → final. Same-media_id
            //     content is byte-identical (different hash is rejected in
            //     reserve), so a benign concurrent rename writes identical bytes.
            let promote = {
                let staging_path = staging_path.clone();
                let final_path = final_path.clone();
                tokio::task::spawn_blocking(move || -> Result<(), std::io::Error> {
                    if let Some(parent) = final_path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::rename(&staging_path, &final_path)?;
                    Ok(())
                })
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?
            };

            if let Err(e) = promote {
                let _ = tokio::fs::remove_file(&staging_path).await;
                // Only a fresh reserve owns its row; drop it so it doesn't
                // linger as pending. A repair leaves the pre-existing committed
                // row untouched (the `committed_at IS NULL` guard enforces this).
                if outcome == ReserveOutcome::ReservedPending {
                    let db = state.db.clone();
                    let mid = media_id_owned.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        db.with_conn(|conn| db::delete_pending_media_row(conn, &mid))
                    })
                    .await;
                }
                return Err(AppError::Internal(format!("Failed to promote media file: {e}")));
            }

            // 14. Finalize: mark the row committed (servable).
            let db = state.db.clone();
            let mid = media_id_owned.clone();
            tokio::task::spawn_blocking(move || db.with_conn(|conn| db::finalize_media(conn, &mid, now)))
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?
                .map_err(|e| AppError::Internal(e.to_string()))?;

            state.metrics.inc(&state.metrics.media_uploads);
            state.metrics.inc_by(&state.metrics.media_bytes_uploaded, size_bytes as u64);
            Ok((
                axum::http::StatusCode::OK,
                Json(serde_json::json!({ "media_id": media_id_owned })),
            )
                .into_response())
        }
        ReserveOutcome::AlreadyServable => {
            // Pure idempotent re-upload of a present, committed blob: drop the
            // staged copy, no promote. TTL was already refreshed in reserve.
            let _ = tokio::fs::remove_file(&staging_path).await;
            state.metrics.inc(&state.metrics.media_uploads);
            Ok((
                axum::http::StatusCode::OK,
                Json(serde_json::json!({ "media_id": media_id_owned })),
            )
                .into_response())
        }
        ReserveOutcome::PendingInFlight => {
            // Another writer holds the reserve. 202 ≠ success: no metrics, no
            // side effects. The caller backs off and re-checks batch-exists.
            let _ = tokio::fs::remove_file(&staging_path).await;
            Ok((
                axum::http::StatusCode::ACCEPTED,
                Json(serde_json::json!({ "media_id": media_id_owned, "in_progress": true })),
            )
                .into_response())
        }
        ReserveOutcome::QuotaExceeded => {
            let _ = tokio::fs::remove_file(&staging_path).await;
            Err(AppError::StorageFull("Media quota exceeded for sync group"))
        }
        ReserveOutcome::HashConflict => {
            let _ = tokio::fs::remove_file(&staging_path).await;
            Err(AppError::Conflict("Media with this ID already exists"))
        }
    }
}

// ---------------------------------------------------------------------------
// download_media — GET /v1/sync/{sync_id}/media/{media_id}
// ---------------------------------------------------------------------------

pub async fn download_media(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthIdentity>,
    Path((path_sync_id, media_id)): Path<(String, String)>,
) -> Result<Response, AppError> {
    // 1. Validate path_sync_id == auth.sync_id
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }

    // 2. Validate media_id format
    if !is_valid_media_id(&media_id) {
        return Err(AppError::BadRequest(
            "Invalid media_id: must be alphanumeric/hyphens, max 36 chars",
        ));
    }

    // 3. Look up metadata, verify sync_id matches, deleted_at IS NULL
    let db = state.db.clone();
    let mid = media_id.clone();
    let sync_id = auth.sync_id.clone();

    let metadata = tokio::task::spawn_blocking(move || {
        db.with_read_conn(|conn| db::get_media_metadata(conn, &mid))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    // Servable predicate (metadata level): committed, not soft-deleted, and not
    // past its per-blob TTL. File presence is verified below by the file-open
    // (belt-and-suspenders for the brief promote window / legacy crash rows).
    let now = db::now_secs();
    let metadata = match metadata {
        Some(m) if m.sync_id == sync_id && m.is_servable_at(now) => m,
        _ => return Err(AppError::NotFound),
    };

    // 4. Stream file from disk
    let storage_path = state.config.media_storage_path.clone();
    let file_path = media_file_path(&storage_path, &metadata.sync_id, &metadata.media_id);

    let file = tokio::fs::File::open(&file_path).await.map_err(|_| AppError::NotFound)?;
    let stream = tokio_util::io::ReaderStream::new(file);
    let body = axum::body::Body::from_stream(stream);

    // 5. Increment metrics
    state.metrics.inc(&state.metrics.media_downloads);

    // 6. Return streaming body with appropriate headers
    Ok(Response::builder()
        .status(axum::http::StatusCode::OK)
        .header(axum::http::header::CACHE_CONTROL, "no-store")
        .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
        .body(body)
        .expect("response builder with valid constant headers"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db::{self, Database};
    use crate::state::AppState;

    /// Create a test AppState with a temp dir for media storage.
    fn test_state(media_dir: &std::path::Path) -> AppState {
        let db = Database::in_memory().expect("in-memory db");
        let mut config = Config::from_env();
        config.media_storage_path = media_dir.to_str().unwrap().to_string();
        config.media_max_file_bytes = 1024; // 1KB for tests
        config.media_quota_bytes_per_group = 4096; // 4KB for tests
        config.media_upload_rate_limit = 100;
        config.media_upload_rate_window_secs = 60;

        // Create a sync group and device for testing
        db.with_conn(|conn| {
            db::create_sync_group(conn, "test-sync-id", 0)?;
            db::register_device(conn, "test-sync-id", "test-device-id", &[1; 32], &[2; 32], 0)?;
            Ok(())
        })
        .unwrap();

        AppState::new(db, config)
    }

    #[test]
    fn upload_and_download_roundtrip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let state = test_state(tmp.path());
        let data = b"hello world";

        // Compute hash
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hex::encode(hasher.finalize());

        // Insert metadata
        state
            .db
            .with_conn(|conn| {
                db::insert_media_metadata(
                    conn,
                    "media-001",
                    "test-sync-id",
                    "test-device-id",
                    data.len() as i64,
                    &hash,
                    None,
                )
            })
            .unwrap();

        // Write file to disk
        let file_path = media_file_path(tmp.path().to_str().unwrap(), "test-sync-id", "media-001");
        std::fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        std::fs::write(&file_path, data).unwrap();

        // Verify metadata exists
        let row =
            state.db.with_read_conn(|conn| db::get_media_metadata(conn, "media-001")).unwrap();
        let row = row.expect("metadata should exist");
        assert_eq!(row.media_id, "media-001");
        assert_eq!(row.sync_id, "test-sync-id");
        assert_eq!(row.size_bytes, data.len() as i64);
        assert_eq!(row.content_hash, hash);
        assert!(row.deleted_at.is_none());

        // Verify file on disk
        let disk_data = std::fs::read(&file_path).unwrap();
        assert_eq!(disk_data, data);
    }

    #[test]
    fn download_returns_404_for_nonexistent() {
        let tmp = tempfile::TempDir::new().unwrap();
        let state = test_state(tmp.path());

        let row =
            state.db.with_read_conn(|conn| db::get_media_metadata(conn, "nonexistent")).unwrap();
        assert!(row.is_none());
    }

    #[test]
    fn download_returns_404_for_deleted_media() {
        let tmp = tempfile::TempDir::new().unwrap();
        let state = test_state(tmp.path());

        state
            .db
            .with_conn(|conn| {
                db::insert_media_metadata(
                    conn,
                    "media-del",
                    "test-sync-id",
                    "test-device-id",
                    100,
                    &"a".repeat(64),
                    None,
                )?;
                db::mark_media_deleted(conn, "media-del")
            })
            .unwrap();

        let row = state
            .db
            .with_read_conn(|conn| db::get_media_metadata(conn, "media-del"))
            .unwrap()
            .expect("row should exist");
        assert!(row.deleted_at.is_some(), "deleted_at should be set");
    }

    #[test]
    fn upload_rejected_when_quota_exceeded() {
        let tmp = tempfile::TempDir::new().unwrap();
        let state = test_state(tmp.path());

        // Quota is 4096 in test config. Insert a large existing media entry.
        state
            .db
            .with_conn(|conn| {
                db::insert_media_metadata(
                    conn,
                    "media-big",
                    "test-sync-id",
                    "test-device-id",
                    4000,
                    &"b".repeat(64),
                    None,
                )
            })
            .unwrap();

        let usage = state
            .db
            .with_read_conn(|conn| db::get_group_media_usage(conn, "test-sync-id"))
            .unwrap();
        assert_eq!(usage, 4000);

        // Attempting to insert another 200 bytes should exceed quota (4000 + 200 > 4096)
        let result = state.db.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            let current = db::get_group_media_usage(&tx, "test-sync-id")?;
            if current + 200 > state.config.media_quota_bytes_per_group as i64 {
                tx.rollback()?;
                return Ok(false);
            }
            tx.commit()?;
            Ok(true)
        });
        assert!(!result.unwrap());
    }

    #[test]
    fn invalid_media_id_rejected() {
        // Empty
        assert!(!is_valid_media_id(""));
        // Too long (37 chars)
        assert!(!is_valid_media_id(&"a".repeat(37)));
        // Invalid characters
        assert!(!is_valid_media_id("hello world"));
        assert!(!is_valid_media_id("media/id"));
        assert!(!is_valid_media_id("media..id"));
        // Valid
        assert!(is_valid_media_id("abc-123"));
        assert!(is_valid_media_id("a"));
        assert!(is_valid_media_id(&"a".repeat(36)));
    }

    #[test]
    fn invalid_content_hash_rejected() {
        // Too short
        assert!(!is_valid_content_hash("abc"));
        // Too long
        assert!(!is_valid_content_hash(&"a".repeat(65)));
        // Non-hex chars
        assert!(!is_valid_content_hash(&format!("{}g", "a".repeat(63))));
        // Valid
        assert!(is_valid_content_hash(&"a".repeat(64)));
        assert!(is_valid_content_hash(&"0123456789abcdef".repeat(4)));
    }

    #[test]
    fn cleanup_expired_media_works() {
        let tmp = tempfile::TempDir::new().unwrap();
        let state = test_state(tmp.path());

        state
            .db
            .with_conn(|conn| {
                // Insert media with old created_at by manipulating db directly.
                // committed_at mirrors the legacy backfill (= created_at) so the
                // row is a committed, servable blob past retention.
                conn.execute(
                    "INSERT INTO media_metadata (media_id, sync_id, device_id, size_bytes, content_hash, created_at, committed_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                    rusqlite::params![
                        "old-media",
                        "test-sync-id",
                        "test-device-id",
                        100,
                        "a".repeat(64),
                        db::now_secs() - 100 * 86400, // 100 days old
                    ],
                )?;
                // Insert recent media
                db::insert_media_metadata(
                    conn,
                    "new-media",
                    "test-sync-id",
                    "test-device-id",
                    200,
                    &"b".repeat(64),
                    None,
                )?;

                // Cleanup with 90 day retention
                let expired = db::cleanup_expired_media(conn, 90)?;
                assert_eq!(expired.len(), 1);
                assert_eq!(expired[0].1, "old-media");

                // Verify old media is now marked deleted
                let old = db::get_media_metadata(conn, "old-media")?;
                assert!(old.unwrap().deleted_at.is_some());

                // Verify new media is untouched
                let new = db::get_media_metadata(conn, "new-media")?;
                assert!(new.unwrap().deleted_at.is_none());

                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn delete_media_for_sync_group_works() {
        let tmp = tempfile::TempDir::new().unwrap();
        let state = test_state(tmp.path());

        state
            .db
            .with_conn(|conn| {
                db::insert_media_metadata(
                    conn,
                    "m1",
                    "test-sync-id",
                    "test-device-id",
                    100,
                    &"a".repeat(64),
                    None,
                )?;
                db::insert_media_metadata(
                    conn,
                    "m2",
                    "test-sync-id",
                    "test-device-id",
                    200,
                    &"b".repeat(64),
                    None,
                )?;

                let ids = db::delete_media_for_sync_group(conn, "test-sync-id")?;
                assert_eq!(ids.len(), 2);

                // Verify they're gone
                assert!(db::get_media_metadata(conn, "m1")?.is_none());
                assert!(db::get_media_metadata(conn, "m2")?.is_none());

                Ok(())
            })
            .unwrap();
    }
}
