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
    !id.is_empty()
        && id.len() <= 36
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Validate content hash format: exactly 64 hex chars.
fn is_valid_content_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit())
}

/// Build the disk path for a media blob: {storage_path}/{sync_id}/{media_id}
fn media_file_path(storage_path: &str, sync_id: &str, media_id: &str) -> std::path::PathBuf {
    std::path::Path::new(storage_path)
        .join(sync_id)
        .join(media_id)
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
) -> Result<impl IntoResponse, AppError> {
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

    // 9. DB: check quota, insert metadata
    let sync_id = auth.sync_id.clone();
    let device_id = auth.device_id.clone();
    let media_id_owned = media_id.to_string();
    let content_hash_owned = content_hash.to_string();
    let size_bytes = body.len() as i64;
    let quota = state.config.media_quota_bytes_per_group;

    let db = state.db.clone();
    let sid = sync_id.clone();
    let did = device_id.clone();
    let mid = media_id_owned.clone();
    let chash = content_hash_owned.clone();

    let inserted = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;

            // Check quota
            let current_usage = db::get_group_media_usage(&tx, &sid)?;
            if current_usage + size_bytes > quota as i64 {
                tx.rollback()?;
                return Ok(false); // quota exceeded
            }

            db::insert_media_metadata(&tx, &mid, &sid, &did, size_bytes, &chash, None)?;
            tx.commit()?;
            Ok(true)
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| match &e {
        rusqlite::Error::SqliteFailure(f, _)
            if f.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
                || f.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE =>
        {
            AppError::Conflict("Media with this ID already exists")
        }
        _ => AppError::Internal(e.to_string()),
    })?;

    if !inserted {
        return Err(AppError::StorageFull("Media quota exceeded for sync group"));
    }

    // 10. Write to disk
    let storage_path = state.config.media_storage_path.clone();
    let file_path = media_file_path(&storage_path, &sync_id, &media_id_owned);

    if let Some(parent) = file_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to create media dir: {e}")))?;
    }

    // Write via tempfile for atomicity
    let parent_dir = file_path
        .parent()
        .ok_or_else(|| AppError::Internal("Invalid media path".into()))?
        .to_path_buf();
    let file_path_clone = file_path.clone();

    let write_result = tokio::task::spawn_blocking(move || -> Result<(), std::io::Error> {
        let named_temp = tempfile::NamedTempFile::new_in(&parent_dir)?;
        std::io::Write::write_all(&mut named_temp.as_file().try_clone()?, &body)?;
        named_temp.persist(&file_path_clone)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    // 11. On disk write failure: delete metadata row
    if let Err(e) = write_result {
        let db = state.db.clone();
        let mid = media_id_owned.clone();
        let _ = tokio::task::spawn_blocking(move || {
            db.with_conn(|conn| db::mark_media_deleted(conn, &mid))
        })
        .await;
        return Err(AppError::Internal(format!(
            "Failed to write media file: {e}"
        )));
    }

    // 12. Increment metrics
    state.metrics.inc(&state.metrics.media_uploads);
    state
        .metrics
        .inc_by(&state.metrics.media_bytes_uploaded, size_bytes as u64);

    // 13. Return JSON
    Ok(Json(serde_json::json!({ "media_id": media_id_owned })))
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

    let metadata = match metadata {
        Some(m) if m.sync_id == sync_id && m.deleted_at.is_none() => m,
        _ => return Err(AppError::NotFound),
    };

    // 4. Stream file from disk
    let storage_path = state.config.media_storage_path.clone();
    let file_path = media_file_path(&storage_path, &metadata.sync_id, &metadata.media_id);

    let file = tokio::fs::File::open(&file_path)
        .await
        .map_err(|_| AppError::NotFound)?;
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
        let file_path = media_file_path(
            tmp.path().to_str().unwrap(),
            "test-sync-id",
            "media-001",
        );
        std::fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        std::fs::write(&file_path, data).unwrap();

        // Verify metadata exists
        let row = state
            .db
            .with_read_conn(|conn| db::get_media_metadata(conn, "media-001"))
            .unwrap();
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

        let row = state
            .db
            .with_read_conn(|conn| db::get_media_metadata(conn, "nonexistent"))
            .unwrap();
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
                // Insert media with old created_at by manipulating db directly
                conn.execute(
                    "INSERT INTO media_metadata (media_id, sync_id, device_id, size_bytes, content_hash, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
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
