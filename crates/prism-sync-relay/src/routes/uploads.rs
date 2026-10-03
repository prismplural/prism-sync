//! Resumable snapshot upload routes (lean v1 relay lifecycle).
//!
//! Five authenticated operations under `/v1/sync/{sync_id}/snapshot/uploads`:
//!
//! ```text
//! POST   /                        create or recover a session
//! GET    /{upload_id}             status
//! PUT    /{upload_id}/chunks/{offset}  upload one chunk
//! POST   /{upload_id}/complete    complete and publish
//! DELETE /{upload_id}             abort
//! ```
//!
//! # Authority model
//!
//! Every operation requires the existing bearer session **and** the existing
//! hybrid signed-request headers, whose canonical form already binds method,
//! canonical path, `sync_id`, device ID, body hash, timestamp, and nonce. On top
//! of that, the session owner is re-checked against the immutable row: knowing an
//! `upload_id` is never sufficient authority, and a sibling device in the same
//! group cannot operate another device's upload. Both failure shapes collapse to
//! the same `404 upload_not_found`, so the endpoint is not a state oracle for
//! session existence across devices or groups.
//!
//! # Concurrency model
//!
//! V1 retains the documented **single-relay-writer** contract: one process owns
//! the SQLite database and the snapshot filesystem. Within that process a
//! per-upload process-local mutation lock serializes chunk, complete, abort, and
//! expiry-sensitive mutation. That lock lives **inside** the blocking task and is
//! held through file write, file synchronization, and the conditional DB update,
//! so a timed-out request (whose blocking work keeps running) cannot interleave
//! with a newer one. Every DB update is additionally conditioned on the expected
//! state and expected committed offset, which is what actually rejects a delayed
//! or duplicate task.
//!
//! Horizontal writers are out of scope: neither the process-local lock nor
//! ordinary local-file writes coordinate across processes.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::errors::{AppError, UploadError};
use crate::snapshot_limits::MAX_TARGETED_SNAPSHOTS_PER_GROUP;
use crate::state::AppState;
use crate::uploads;

use super::{auth_middleware, AuthIdentity};

/// The chunk route's body limit is the **protocol** maximum, not the session's
/// persisted `chunk_bytes` and not runtime configuration, so a restart or a
/// config change can never wedge a live v1 session before semantic validation
/// runs. Control requests are bodyless, except create which carries a small
/// JSON body capped independently of the chunk route.
const CHUNK_BODY_LIMIT: usize = crate::uploads::SNAPSHOT_UPLOAD_CHUNK_BYTES;
const CREATE_BODY_LIMIT: usize = crate::uploads::SNAPSHOT_UPLOAD_CREATE_BODY_MAX_BYTES;

// `503 upload_busy` is the transient-shedding answer for chunk/complete
// concurrency. It is deliberately a **retryable** status rather than a
// quota-coded 429, so a client backs off instead of treating it as a policy
// rejection it must not retry.

/// Advertised resumable-upload capability (`snapshot_upload` sibling).
///
/// Kept in one struct so the capabilities response and the config gate cannot
/// describe different shapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotUploadCapability {
    pub version: u16,
    pub chunk_bytes: u64,
    pub max_wire_bytes: u64,
    pub session_idle_ttl_secs: u64,
}

/// Registry of per-upload mutation locks.
///
/// Process-local and bounded: v1 admits at most one nonterminal session per
/// uploader, so the live key space is bounded by active pairings rather than by
/// session creation. Entries are removed when no thread holds them, and
/// [`Self::prune`] drops any leftover idle entry so a long-lived relay cannot
/// accumulate one `Arc` per upload ID ever seen.
#[derive(Clone, Default)]
pub struct UploadLocks {
    inner: Arc<Mutex<std::collections::HashMap<String, Arc<Mutex<()>>>>>,
}

impl UploadLocks {
    /// Acquire (creating if needed) the mutation lock for `upload_id`.
    pub(crate) fn acquire(&self, upload_id: &str) -> Arc<Mutex<()>> {
        let mut map = self.inner.lock().expect("upload lock map poisoned");
        map.entry(upload_id.to_string()).or_default().clone()
    }

    /// Drop entries whose lock is no longer held by any thread.
    pub(crate) fn prune(&self) {
        let mut map = self.inner.lock().expect("upload lock map poisoned");
        map.retain(|_, lock| Arc::strong_count(lock) > 1);
    }

    /// Number of tracked locks, for tests and diagnostics.
    pub fn tracked(&self) -> usize {
        self.inner.lock().expect("upload lock map poisoned").len()
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateUploadRequest {
    pub version: u16,
    /// Client-generated random idempotency key (base64url or standard base64).
    pub upload_key: String,
    pub epoch: i64,
    pub server_seq_at: i64,
    /// v1 requires a targeted snapshot; a group-wide request is rejected.
    pub target_device_id: Option<String>,
    pub ttl_secs: i64,
    pub total_bytes: i64,
    /// Canonical lowercase hex SHA-256 of the exact envelope bytes.
    pub body_sha256: String,
}

/// Wire body for create. Mirrors the spec's field set exactly; unknown fields
/// are tolerated so a newer client can add non-semantic fields.
#[derive(Debug, Serialize)]
pub struct CreateUploadResponse {
    pub upload_id: String,
    pub state: &'static str,
    pub chunk_bytes: i64,
    pub total_bytes: i64,
    pub committed_offset: i64,
    pub idle_expires_at: i64,
    pub absolute_expires_at: i64,
}

#[derive(Debug, Serialize)]
pub struct UploadStatusResponse {
    pub state: &'static str,
    pub total_bytes: i64,
    pub committed_offset: i64,
    pub chunk_bytes: i64,
    pub idle_expires_at: i64,
    pub absolute_expires_at: i64,
}

#[derive(Debug, Serialize)]
pub struct ChunkResponse {
    pub committed_offset: i64,
    pub idle_expires_at: i64,
    pub absolute_expires_at: i64,
}

/// Build the `/v1/sync/{sync_id}/snapshot/uploads` sub-router.
///
/// Deliberately split from the shared authenticated router so each operation can
/// carry its own body limit, timeout, and concurrency layer:
///
/// - `create` gets a small JSON body cap;
/// - `status`/`abort` are bodyless;
/// - `chunk` gets the exact protocol chunk cap plus a dedicated chunk-write
///   concurrency limit that sheds as retryable `503 upload_busy`;
/// - `complete` gets a dedicated completion concurrency limit (it is the heavy
///   hashing/publication step).
///
/// `chunk` needs a *separate* router because `GlobalConcurrencyLimitLayer` cannot
/// be applied per-route with distinct values on one router: applying
/// `route_layer` to a merged router would multiply the caps into a product, so
/// each layer group is a real sub-router that is merged at the root.
pub fn routes(state: AppState) -> Router<AppState> {
    let chunk_concurrency = state.config.snapshot_upload_chunk_concurrency();

    // Chunk: exact protocol body limit + dedicated concurrency + long timeout.
    let chunk_routes = Router::new()
        .route("/v1/sync/{sync_id}/snapshot/uploads/{upload_id}/chunks/{offset}", put(put_chunk))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .layer(DefaultBodyLimit::max(CHUNK_BODY_LIMIT))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(CHUNK_BODY_LIMIT))
        .layer(tower::limit::GlobalConcurrencyLimitLayer::new(chunk_concurrency))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            std::time::Duration::from_secs(crate::uploads::SNAPSHOT_UPLOAD_CHUNK_TIMEOUT_SECS),
        ));

    // Create/status/complete/abort: small bodies, one timeout, shared
    // concurrency through the default authenticated router's outer cap.
    let control_routes = Router::new()
        .route("/v1/sync/{sync_id}/snapshot/uploads", post(create_upload))
        .route("/v1/sync/{sync_id}/snapshot/uploads/{upload_id}", get(upload_status))
        .route("/v1/sync/{sync_id}/snapshot/uploads/{upload_id}", delete(abort_upload))
        .route("/v1/sync/{sync_id}/snapshot/uploads/{upload_id}/complete", post(complete_upload))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        // Create carries a small JSON body; status/abort/complete are bodyless.
        // Using the larger of the two (the create cap) as the shared control
        // limit keeps one layer while still bounding every control request well
        // below the chunk route.
        .layer(DefaultBodyLimit::max(CREATE_BODY_LIMIT))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(CREATE_BODY_LIMIT))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            std::time::Duration::from_secs(crate::uploads::SNAPSHOT_UPLOAD_CONTROL_TIMEOUT_SECS),
        ));

    Router::new().merge(chunk_routes).merge(control_routes)
}

use axum::middleware;

// ───────────────────────────── create ─────────────────────────────

/// `POST /v1/sync/{sync_id}/snapshot/uploads`
///
/// Idempotent on `(sync_id, uploader_device_id, upload_key)`. A **new** key
/// supersedes any other nonterminal session owned by the same uploader, so a
/// lost abort cannot poison later pairing attempts.
pub async fn create_upload(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthIdentity>,
    Path(path_sync_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }

    let root = require_resumable_root(&state)?;
    let path = format!("/v1/sync/{}/snapshot/uploads", auth.sync_id);
    super::verify_signed_request(&state, &auth, &headers, "POST", &path, &body)?;
    let request: CreateUploadRequest = serde_json::from_slice(&body)
        .map_err(|_| AppError::Upload(UploadError::InvalidUpload("malformed create body")))?;

    // ── Validate everything before reserving anything ─────────────────────
    if request.version != crate::uploads::SNAPSHOT_UPLOAD_VERSION_V1 {
        return Err(AppError::Upload(UploadError::InvalidUpload("unsupported version")));
    }
    let upload_key = decode_upload_key(&request.upload_key)
        .ok_or(AppError::Upload(UploadError::InvalidUpload("invalid upload_key encoding")))?;
    // v1 requires a targeted audience; group-wide resumable uploads are refused
    // rather than silently widened.
    let target_device_id = request
        .target_device_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or(AppError::Upload(UploadError::UnsupportedAudience))?;
    if !crate::auth::is_valid_device_id(target_device_id) {
        return Err(AppError::Upload(UploadError::InvalidUpload("invalid target_device_id")));
    }
    // Declared total must be positive and within the advertised maximum.
    let total_bytes = u64::try_from(request.total_bytes)
        .ok()
        .filter(|total| *total > 0)
        .filter(|total| *total <= crate::uploads::SNAPSHOT_UPLOAD_MAX_WIRE_BYTES)
        .ok_or(AppError::Upload(UploadError::SnapshotTooLarge {
            max_wire_bytes: crate::uploads::SNAPSHOT_UPLOAD_MAX_WIRE_BYTES,
        }))?;
    // TTL: validated in the field's own type — never the unchecked `u64 as i64`
    // cast the legacy header path uses, and never a lossy conversion.
    let ttl_secs = request
        .ttl_secs
        .checked_abs()
        .filter(|ttl| (1..=crate::uploads::SNAPSHOT_UPLOAD_MAX_SNAPSHOT_TTL_SECS).contains(ttl))
        .ok_or(AppError::Upload(UploadError::InvalidUpload("invalid snapshot TTL")))?;
    let body_sha256 = uploads::decode_sha256_hex(&request.body_sha256)
        .ok_or(AppError::Upload(UploadError::InvalidUpload("invalid body_sha256")))?;

    // Per-device create rate limit (existing limiter pattern).
    let limiter_key = format!("snapshot-upload-create:{}:{}", auth.sync_id, auth.device_id);
    if !state.snapshot_upload_create_rate_limiter.check(
        &limiter_key,
        state.config.snapshot_upload.create_rate_limit,
        state.config.snapshot_upload_create_rate_window_secs(),
    ) {
        state.metrics.inc(&state.metrics.snapshot_upload_quota_rejections);
        return Err(AppError::Upload(UploadError::QuotaExceeded { scope: "create_rate" }));
    }

    let upload_id = uploads::generate_upload_id();
    let blob_ref = crate::snapshot_store::generate_blob_ref();

    let db = state.db.clone();
    let sid = auth.sync_id.clone();
    let did = auth.device_id.clone();
    let target = target_device_id.to_string();
    let quotas = state.config.snapshot_upload;
    let storage_root = root.clone();
    let epoch = request.epoch;
    let server_seq_at = request.server_seq_at;
    let free_space_reserve = quotas.free_space_reserve_bytes;

    // The whole admission decision — supersession, quota reservation, audience
    // precheck, and insert — is one blocking operation under the writer mutex.
    // The only thing outside it is the free-space probe, which must not run under
    // the writer lock.
    let outcome = tokio::task::spawn_blocking(move || {
        // Free-space probe first: `statvfs` on the snapshot volume is a syscall
        // that must never be taken while holding the SQLite writer mutex.
        let free = uploads::available_bytes(&storage_root)
            .map_err(|_| AppError::Upload(UploadError::InsufficientStorage))?;
        db.with_conn(|conn| {
            crate::db::create_snapshot_upload(
                conn,
                crate::db::CreateSnapshotUpload {
                    upload_id: &upload_id,
                    upload_key: &upload_key,
                    sync_id: &sid,
                    uploader_device_id: &did,
                    target_device_id: &target,
                    epoch,
                    server_seq_at,
                    snapshot_ttl_secs: ttl_secs,
                    total_bytes: total_bytes as i64,
                    chunk_bytes: crate::uploads::SNAPSHOT_UPLOAD_CHUNK_BYTES as i64,
                    body_sha256: &body_sha256,
                    blob_ref: &blob_ref,
                    global_reserved_limit: quotas.global_reserved_bytes,
                    group_reserved_limit: quotas.group_reserved_bytes,
                    audience_cap: MAX_TARGETED_SNAPSHOTS_PER_GROUP,
                    free_bytes: free,
                    free_space_reserve,
                },
            )
        })
        .map_err(AppError::from)
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))??;

    match outcome {
        crate::db::CreateSnapshotUploadOutcome::Created { session, superseded } => {
            if superseded > 0 {
                state.metrics.inc_by(&state.metrics.snapshot_upload_superseded, superseded);
            }
            tracing::debug!(
                sync_id = %trunc(&auth.sync_id),
                device_id = %trunc(&auth.device_id),
                upload = %upload_hash(&session.upload_id),
                total_bytes,
                "snapshot upload session created"
            );
            Ok((StatusCode::CREATED, Json(session_to_response(&session))).into_response())
        }
        crate::db::CreateSnapshotUploadOutcome::Recovered(session) => {
            // Idempotent recovery: same key, same immutable metadata. A
            // `completed` row reports `committed_offset == total_bytes` so a lost
            // create/complete response does not force a re-upload.
            tracing::debug!(
                sync_id = %trunc(&auth.sync_id),
                device_id = %trunc(&auth.device_id),
                upload = %upload_hash(&session.upload_id),
                state = session.state.as_str(),
                committed_offset = session.committed_offset,
                "snapshot upload session recovered"
            );
            Ok((StatusCode::OK, Json(session_to_response(&session))).into_response())
        }
        crate::db::CreateSnapshotUploadOutcome::UploadBusy => {
            // Deterministic and retryable: a completion currently owns this
            // uploader's session. Nothing was created, reserved, or superseded.
            tracing::debug!(
                sync_id = %trunc(&auth.sync_id),
                device_id = %trunc(&auth.device_id),
                "snapshot upload create refused: a completion is in flight"
            );
            Err(AppError::Upload(UploadError::Busy))
        }
        crate::db::CreateSnapshotUploadOutcome::KeyConflict => {
            Err(AppError::Upload(UploadError::KeyConflict))
        }
        crate::db::CreateSnapshotUploadOutcome::QuotaExceeded(scope) => {
            state.metrics.inc(&state.metrics.snapshot_upload_quota_rejections);
            tracing::warn!(
                sync_id = %trunc(&auth.sync_id),
                scope,
                "snapshot upload quota rejected"
            );
            Err(AppError::Upload(UploadError::QuotaExceeded { scope }))
        }
        crate::db::CreateSnapshotUploadOutcome::InsufficientStorage => {
            state.metrics.inc(&state.metrics.snapshot_upload_quota_rejections);
            Err(AppError::Upload(UploadError::InsufficientStorage))
        }
        crate::db::CreateSnapshotUploadOutcome::AudienceCapReached => {
            state.metrics.inc(&state.metrics.snapshots_rejected_targeted_cap);
            Err(AppError::TooManyTargetedSnapshots { max: MAX_TARGETED_SNAPSHOTS_PER_GROUP })
        }
        crate::db::CreateSnapshotUploadOutcome::DeviceInvalid => {
            Err(AppError::Upload(UploadError::OwnerInvalid))
        }
        crate::db::CreateSnapshotUploadOutcome::EpochMismatch { .. } => {
            // Consistent with completion's epoch recheck: the declared epoch no
            // longer matches the relay's, so the upload cannot proceed.
            Err(AppError::Upload(UploadError::EpochInvalid))
        }
    }
}

// ───────────────────────────── status ─────────────────────────────

/// `GET /v1/sync/{sync_id}/snapshot/uploads/{upload_id}`
///
/// Never extends either expiry. Successfully accepted chunks do; status does not.
pub async fn upload_status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthIdentity>,
    Path((path_sync_id, upload_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }
    require_resumable_root(&state)?;
    if !uploads::is_valid_upload_id(&upload_id) {
        // A malformed ID is indistinguishable from an unknown one.
        return Err(AppError::Upload(UploadError::NotFound));
    }
    let path = format!("/v1/sync/{}/snapshot/uploads/{}", auth.sync_id, upload_id);
    super::verify_signed_request(&state, &auth, &headers, "GET", &path, &[])?;

    let db = state.db.clone();
    let sid = auth.sync_id.clone();
    let did = auth.device_id.clone();
    let uid = upload_id.clone();
    let session = tokio::task::spawn_blocking(move || {
        db.with_read_conn(|conn| crate::db::get_snapshot_upload(conn, &uid)).map_err(AppError::from)
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))??;

    let session = owned_session(session, &sid, &did)?;
    Ok(Json(status_to_response(&session)).into_response())
}

// ───────────────────────────── chunk ─────────────────────────────

/// `PUT /v1/sync/{sync_id}/snapshot/uploads/{upload_id}/chunks/{offset}`
///
/// `upload_id` and decimal `offset` are in the **signed canonical path**, and
/// the signature binds the chunk body hash, so neither an unsigned offset nor an
/// unsigned checksum can be authoritative.
pub async fn put_chunk(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthIdentity>,
    Path((path_sync_id, upload_id, offset)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }
    let root = require_resumable_root(&state)?;
    if !uploads::is_valid_upload_id(&upload_id) {
        return Err(AppError::Upload(UploadError::NotFound));
    }
    // The decimal offset is part of the signed path; parse it strictly.
    let offset: u64 = offset
        .parse()
        .map_err(|_| AppError::Upload(UploadError::InvalidUpload("invalid chunk offset")))?;
    let path =
        format!("/v1/sync/{}/snapshot/uploads/{}/chunks/{}", auth.sync_id, upload_id, offset);
    super::verify_signed_request(&state, &auth, &headers, "PUT", &path, &body)?;

    // Body bounds: an oversize body is normally refused by the route's body
    // layer before reaching the handler (with a plain-text 413), which is the
    // correct transport backstop. The semantic check below is what produces the
    // structured `chunk_too_large` machine code for a body the layer let
    // through, and it also rejects the zero-length case the layer cannot.
    let body_len = body.len() as u64;
    if body_len == 0 || body_len > crate::uploads::SNAPSHOT_UPLOAD_CHUNK_BYTES as u64 {
        state.metrics.inc(&state.metrics.snapshot_upload_chunks_rejected);
        return Err(AppError::Upload(UploadError::ChunkTooLarge {
            chunk_bytes: crate::uploads::SNAPSHOT_UPLOAD_CHUNK_BYTES as i64,
        }));
    }

    let lock = state.upload_locks.acquire(&upload_id);
    let db = state.db.clone();
    let sid = auth.sync_id.clone();
    let did = auth.device_id.clone();
    let uid = upload_id.clone();
    let storage_root = root.clone();
    let body = body.to_vec();
    let free_space_reserve = state.config.snapshot_upload.free_space_reserve_bytes;
    let (sid_job, did_job, uid_job, root_job) =
        (sid.clone(), did.clone(), uid.clone(), storage_root.clone());

    let outcome = tokio::task::spawn_blocking(move || {
        // The per-upload lock lives INSIDE the blocking task and is held through
        // the file write, the file sync, and the conditional offset commit. A
        // request timeout cannot stop this work, so the lock is what prevents a
        // still-running stale write from interleaving with a newer one.
        let _guard = lock.lock().expect("upload mutation lock poisoned");
        crate::db::apply_snapshot_upload_chunk(
            &db,
            &root_job,
            &sid_job,
            &did_job,
            &uid_job,
            offset,
            &body,
            free_space_reserve,
        )
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    match outcome {
        Ok(committed) => {
            state.metrics.inc(&state.metrics.snapshot_upload_chunks_accepted);
            state.metrics.inc_by(&state.metrics.snapshot_upload_chunk_bytes, body_len);
            Ok(Json(ChunkResponse {
                committed_offset: committed.committed_offset,
                idle_expires_at: committed.idle_expires_at,
                absolute_expires_at: committed.absolute_expires_at,
            })
            .into_response())
        }
        Err(rejection) => {
            state.metrics.inc(&state.metrics.snapshot_upload_chunks_rejected);
            Err(chunk_rejection_to_error(&state, rejection))
        }
    }
}

/// Map a chunk rejection onto the documented error surface.
///
/// Every one maps to a [`UploadError`], which carries the relay's structured
/// JSON body and stable machine code. `Replayed` is not a rejection at all (it is
/// handled by the success path). The offset and chunk-size fields are echoed so
/// the client can resume from the relay's authoritative value rather than
/// guessing.
fn chunk_rejection_to_error(state: &AppState, rejection: crate::db::ChunkRejection) -> AppError {
    use crate::db::ChunkRejection;
    use crate::errors::UploadError;
    match rejection {
        // Ownership failure is indistinguishable from an unknown ID.
        ChunkRejection::NotFound | ChunkRejection::NotOwned => {
            AppError::Upload(UploadError::NotFound)
        }
        ChunkRejection::Finalizing => AppError::Upload(UploadError::Finalizing),
        ChunkRejection::Completed => AppError::Upload(UploadError::Completed),
        ChunkRejection::Failed => AppError::Upload(UploadError::Failed),
        ChunkRejection::Expired => AppError::Upload(UploadError::Expired),
        ChunkRejection::OffsetMismatch { committed_offset } => {
            AppError::Upload(UploadError::OffsetMismatch { committed_offset })
        }
        ChunkRejection::ChunkTooLarge { chunk_bytes } => {
            AppError::Upload(UploadError::ChunkTooLarge { chunk_bytes })
        }
        ChunkRejection::ShortChunk { chunk_bytes, committed_offset } => {
            AppError::Upload(UploadError::ShortChunk { chunk_bytes, committed_offset })
        }
        ChunkRejection::BeyondTotal { max_wire_bytes } => {
            AppError::Upload(UploadError::SnapshotTooLarge { max_wire_bytes })
        }
        ChunkRejection::StagingCorrupt => {
            state.metrics.inc(&state.metrics.snapshot_upload_staging_corrupt);
            tracing::error!("snapshot upload staging corruption; session failed");
            AppError::Upload(UploadError::Failed)
        }
        ChunkRejection::InsufficientStorage => {
            state.metrics.inc(&state.metrics.snapshot_upload_quota_rejections);
            AppError::Upload(UploadError::InsufficientStorage)
        }
        ChunkRejection::Internal(msg) => AppError::Internal(msg),
    }
}

// ───────────────────────────── complete ─────────────────────────────

/// `POST /v1/sync/{sync_id}/snapshot/uploads/{upload_id}/complete`
///
/// Publishes the staged bytes through the **existing** audience-aware snapshot
/// row. The relay does not verify the inner snapshot signature or AAD — it holds
/// no client snapshot keys — exactly as the existing single PUT does not. The
/// outer SHA-256 detects transport/staging corruption; end-to-end verification
/// remains mandatory on the joiner.
pub async fn complete_upload(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthIdentity>,
    Path((path_sync_id, upload_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }
    let root = require_resumable_root(&state)?;
    if !uploads::is_valid_upload_id(&upload_id) {
        return Err(AppError::NotFound);
    }
    if !body.is_empty() {
        return Err(AppError::Upload(UploadError::InvalidUpload("complete takes no body")));
    }
    let path = format!("/v1/sync/{}/snapshot/uploads/{}/complete", auth.sync_id, upload_id);
    super::verify_signed_request(&state, &auth, &headers, "POST", &path, &[])?;

    let lock = state.upload_locks.acquire(&upload_id);
    let db = state.db.clone();
    let sid = auth.sync_id.clone();
    let did = auth.device_id.clone();
    let uid = upload_id.clone();
    let storage_root = root.clone();
    let audience_cap = MAX_TARGETED_SNAPSHOTS_PER_GROUP;
    let free_space_reserve = state.config.snapshot_upload.free_space_reserve_bytes;
    let (sid_job, did_job, uid_job, root_job) =
        (sid.clone(), did.clone(), uid.clone(), storage_root.clone());

    let outcome = tokio::task::spawn_blocking(move || {
        let _guard = lock.lock().expect("upload mutation lock poisoned");
        crate::db::complete_snapshot_upload(
            &db,
            &root_job,
            &sid_job,
            &did_job,
            &uid_job,
            audience_cap,
            free_space_reserve,
        )
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    match outcome {
        Ok(crate::db::CompletionOutcome::Published { replaced_blob_ref }) => {
            state.metrics.inc(&state.metrics.snapshot_upload_completions);
            state.metrics.inc(&state.metrics.snapshots_exchanged);
            // Delete the replaced snapshot's old blob AFTER the writer lock is
            // released. Best-effort; the orphan sweep backstops a miss.
            if let Some(old) = replaced_blob_ref {
                let root = storage_root.clone();
                let sid = sid.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    uploads::remove_candidate(&root, &sid, &old);
                })
                .await;
            }
            tracing::debug!(
                sync_id = %trunc(&sid),
                device_id = %trunc(&did),
                upload = %upload_hash(&uid),
                "snapshot upload completed and published"
            );
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        // A lost completion response followed by a retry returns the original
        // result and never republishes.
        Ok(crate::db::CompletionOutcome::AlreadyCompleted) => {
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        Ok(crate::db::CompletionOutcome::Succeeded { status, code, stale_detail }) => {
            state.metrics.inc(&state.metrics.snapshot_upload_completions);
            Err(recorded_failure(&state, status, code, stale_detail))
        }
        Err(rejection) => Err(completion_rejection_to_error(&state, rejection)),
    }
}

/// Reproduce a recorded terminal completion failure exactly.
///
/// A retry after a lost response must see the SAME status and body as the
/// original, so this reconstructs from the stored status/code instead of
/// re-deriving it. The two pre-existing snapshot errors keep their original
/// variants (and therefore their original JSON bodies) so the client's existing
/// suppression matrix is untouched; everything else routes through the
/// structured [`UploadError`] table.
fn recorded_failure(
    state: &AppState,
    status: u16,
    code: Option<String>,
    stale_detail: Option<(i64, Option<String>)>,
) -> AppError {
    match code.as_deref() {
        Some("stale_snapshot_seq") => {
            state.metrics.inc(&state.metrics.snapshots_rejected_stale);
            // Replay the competing snapshot's seq/audience exactly as recorded, so
            // the retried 409 carries the same fields as the original. The client's
            // suppression matrix compares those two fields; substituting zeros
            // would turn a real cross-target refusal into a suppressed success.
            // A row written before the detail columns existed has no recorded
            // detail. Keep the conservative shape: a zero seq fails the matrix's
            // `existing_seq < our_seq` guard, so the refusal still propagates
            // rather than being suppressed.
            let (current_server_seq_at, current_target_device_id) =
                stale_detail.unwrap_or((0, None));
            AppError::SnapshotStale { current_server_seq_at, current_target_device_id }
        }
        Some("too_many_targeted_snapshots") => {
            state.metrics.inc(&state.metrics.snapshots_rejected_targeted_cap);
            AppError::TooManyTargetedSnapshots { max: MAX_TARGETED_SNAPSHOTS_PER_GROUP }
        }
        Some("snapshot_hash_mismatch") => {
            state.metrics.inc(&state.metrics.snapshot_upload_hash_mismatch);
            AppError::Upload(UploadError::HashMismatch)
        }
        Some("staging_corrupt") => {
            state.metrics.inc(&state.metrics.snapshot_upload_staging_corrupt);
            AppError::Upload(UploadError::Failed)
        }
        Some(code) => UploadError::from_recorded(status, code)
            .map(AppError::Upload)
            .unwrap_or(AppError::Upload(UploadError::Failed)),
        None => AppError::Upload(UploadError::Failed),
    }
}

fn completion_rejection_to_error(
    state: &AppState,
    rejection: crate::db::CompletionRejection,
) -> AppError {
    use crate::db::CompletionRejection;
    match rejection {
        CompletionRejection::NotFound | CompletionRejection::NotOwned => {
            AppError::Upload(UploadError::NotFound)
        }
        CompletionRejection::Incomplete { committed_offset } => {
            AppError::Upload(UploadError::Incomplete { committed_offset })
        }
        CompletionRejection::Finalizing => AppError::Upload(UploadError::Finalizing),
        CompletionRejection::Failed => AppError::Upload(UploadError::Failed),
        CompletionRejection::Expired => AppError::Upload(UploadError::Expired),
        CompletionRejection::HashMismatch => {
            state.metrics.inc(&state.metrics.snapshot_upload_hash_mismatch);
            AppError::Upload(UploadError::HashMismatch)
        }
        CompletionRejection::EpochInvalid => AppError::Upload(UploadError::EpochInvalid),
        CompletionRejection::OwnerInvalid => AppError::Upload(UploadError::OwnerInvalid),
        CompletionRejection::AudienceCapReached => {
            state.metrics.inc(&state.metrics.snapshots_rejected_targeted_cap);
            AppError::TooManyTargetedSnapshots { max: MAX_TARGETED_SNAPSHOTS_PER_GROUP }
        }
        CompletionRejection::Stale { current_server_seq_at, current_target_device_id } => {
            state.metrics.inc(&state.metrics.snapshots_rejected_stale);
            // Preserve the existing 409 body shape the client's suppression
            // matrix already understands.
            AppError::SnapshotStale { current_server_seq_at, current_target_device_id }
        }
        CompletionRejection::StagingCorrupt => {
            state.metrics.inc(&state.metrics.snapshot_upload_staging_corrupt);
            AppError::Upload(UploadError::Failed)
        }
        CompletionRejection::SessionLost => {
            // The session was aborted, superseded, or expired while publication
            // was in flight. Never answer 204 here: no bytes were published.
            tracing::warn!("snapshot upload publication lost its session");
            AppError::Upload(UploadError::Failed)
        }
        CompletionRejection::InsufficientStorage => {
            state.metrics.inc(&state.metrics.snapshot_upload_quota_rejections);
            AppError::Upload(UploadError::InsufficientStorage)
        }
        CompletionRejection::Internal(msg) => AppError::Internal(msg),
    }
}

// ───────────────────────────── abort ─────────────────────────────

/// `DELETE /v1/sync/{sync_id}/snapshot/uploads/{upload_id}`
///
/// Makes a nonterminal session terminal, releasing its reservation in the same
/// transition, then removes the candidate outside the writer lock. Repeated
/// abort is idempotent. Aborting a completed session never deletes the published
/// snapshot.
pub async fn abort_upload(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthIdentity>,
    Path((path_sync_id, upload_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }
    let root = require_resumable_root(&state)?;
    if !uploads::is_valid_upload_id(&upload_id) {
        return Err(AppError::NotFound);
    }
    let path = format!("/v1/sync/{}/snapshot/uploads/{}", auth.sync_id, upload_id);
    super::verify_signed_request(&state, &auth, &headers, "DELETE", &path, &[])?;

    let lock = state.upload_locks.acquire(&upload_id);
    let db = state.db.clone();
    let sid = auth.sync_id.clone();
    let did = auth.device_id.clone();
    let uid = upload_id.clone();
    let (sid_job, did_job, uid_job) = (sid.clone(), did.clone(), uid.clone());

    let outcome = tokio::task::spawn_blocking(move || {
        let _guard = lock.lock().expect("upload mutation lock poisoned");
        db.with_conn(|conn| crate::db::abort_snapshot_upload(conn, &sid_job, &did_job, &uid_job))
            .map_err(AppError::from)
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))??;

    match outcome {
        crate::db::AbortOutcome::Aborted { blob_ref } => {
            state.metrics.inc(&state.metrics.snapshot_upload_aborted);
            // The row is terminal; unlink the now-unreferenced candidate outside
            // the writer lock. Best-effort: the orphan sweep backstops.
            if let Some(blob_ref) = blob_ref {
                let root = root.clone();
                let sid = sid.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    uploads::remove_candidate(&root, &sid, &blob_ref);
                })
                .await;
            }
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        // Repeated abort is idempotent.
        crate::db::AbortOutcome::AlreadyFailed => Ok(StatusCode::NO_CONTENT.into_response()),
        crate::db::AbortOutcome::Completed => Err(AppError::Upload(UploadError::Completed)),
        // Not-found and not-owned are deliberately the same answer.
        crate::db::AbortOutcome::NotFound | crate::db::AbortOutcome::NotOwned => {
            Err(AppError::Upload(UploadError::NotFound))
        }
    }
}

// ───────────────────────────── helpers ─────────────────────────────

/// Fail closed when the relay is not configured for resumable uploads.
///
/// The capability is withheld in exactly this case, so a client should never
/// call these routes; a direct caller gets the same 404 an old relay would give,
/// which is what makes fallback to single PUT correct.
fn require_resumable_root(state: &AppState) -> Result<PathBuf, AppError> {
    if !state.config.snapshot_upload_supported(&state.snapshot_storage) {
        return Err(AppError::Upload(UploadError::NotFound));
    }
    state
        .snapshot_storage
        .root()
        .map(std::path::Path::to_path_buf)
        .ok_or(AppError::Upload(UploadError::NotFound))
}

/// Enforce session ownership: the authenticated sync group and device must equal
/// the immutable session owner. A cross-device or cross-group probe is
/// indistinguishable from an unknown ID.
fn owned_session(
    session: Option<crate::db::SnapshotUploadRow>,
    sync_id: &str,
    device_id: &str,
) -> Result<crate::db::SnapshotUploadRow, AppError> {
    match session {
        Some(row) if row.sync_id == sync_id && row.uploader_device_id == device_id => Ok(row),
        _ => Err(AppError::Upload(UploadError::NotFound)),
    }
}

fn session_to_response(session: &crate::db::SnapshotUploadRow) -> CreateUploadResponse {
    CreateUploadResponse {
        upload_id: session.upload_id.clone(),
        state: session.state.as_str(),
        chunk_bytes: session.chunk_bytes,
        total_bytes: session.total_bytes,
        committed_offset: session.committed_offset,
        idle_expires_at: session.idle_expires_at,
        absolute_expires_at: session.absolute_expires_at,
    }
}

fn status_to_response(session: &crate::db::SnapshotUploadRow) -> UploadStatusResponse {
    UploadStatusResponse {
        state: session.state.as_str(),
        total_bytes: session.total_bytes,
        committed_offset: session.committed_offset,
        chunk_bytes: session.chunk_bytes,
        idle_expires_at: session.idle_expires_at,
        absolute_expires_at: session.absolute_expires_at,
    }
}

/// Decode the client's `upload_key`.
///
/// Accepts **both** base64 alphabets, padded or unpadded, mirroring the pairing
/// lease's dual-acceptance rule, but requires the decoded value to be exactly
/// [`uploads::SNAPSHOT_UPLOAD_KEY_BYTES`] bytes. The canonical form is stored as
/// lowercase hex so the idempotency uniqueness constraint cannot split one key
/// across two spellings.
fn decode_upload_key(value: &str) -> Option<String> {
    use base64::Engine;
    let trimmed = value.trim();
    if trimmed.len() > 128 {
        return None;
    }
    let standard = base64::engine::general_purpose::STANDARD;
    let standard_nopad = base64::engine::general_purpose::STANDARD_NO_PAD;
    let urlsafe = base64::engine::general_purpose::URL_SAFE;
    let urlsafe_nopad = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let decoded = standard
        .decode(trimmed)
        .or_else(|_| standard_nopad.decode(trimmed))
        .or_else(|_| urlsafe.decode(trimmed))
        .or_else(|_| urlsafe_nopad.decode(trimmed))
        .ok()?;
    if decoded.len() != crate::uploads::SNAPSHOT_UPLOAD_KEY_BYTES {
        return None;
    }
    Some(hex::encode(decoded))
}

/// Short, non-reversible identifier for a log line. Upload IDs are never logged
/// in full: they are opaque and should not become a correlatable logging key.
fn upload_hash(upload_id: &str) -> String {
    use sha2::Digest;
    let digest: [u8; 32] = sha2::Sha256::digest(upload_id.as_bytes()).into();
    hex::encode(&digest[..8])
}

fn trunc(value: &str) -> &str {
    let end = value.len().min(16);
    &value[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uploads::{StagingError, UploadState};

    #[test]
    fn upload_key_accepts_both_alphabets_and_requires_32_bytes() {
        use base64::Engine;
        let raw = [7u8; 32];
        let standard = base64::engine::general_purpose::STANDARD.encode(raw);
        let urlsafe = base64::engine::general_purpose::URL_SAFE.encode(raw);
        assert!(decode_upload_key(&standard).is_some());
        assert!(decode_upload_key(&urlsafe).is_some());
        // Both spellings canonicalize to the same stored key, so the DB
        // uniqueness constraint cannot be split across encodings.
        assert_eq!(decode_upload_key(&standard), decode_upload_key(&urlsafe));
        assert_eq!(decode_upload_key(&standard).unwrap(), hex::encode(raw));

        // Wrong length and garbage are rejected.
        assert!(decode_upload_key(&base64::engine::general_purpose::STANDARD.encode([1u8; 31]))
            .is_none());
        assert!(decode_upload_key("not base64!!").is_none());
        assert!(decode_upload_key("").is_none());
        assert!(decode_upload_key(&"A".repeat(200)).is_none());
    }

    #[test]
    fn upload_hash_is_short_and_not_the_identifier() {
        let id = uploads::generate_upload_id();
        let hashed = upload_hash(&id);
        assert_eq!(hashed.len(), 16);
        assert!(!hashed.contains(&id));
        assert_ne!(hashed, upload_hash(&uploads::generate_upload_id()));
    }

    #[test]
    fn ownership_mismatch_is_indistinguishable_from_unknown() {
        let row = crate::db::SnapshotUploadRow {
            upload_id: "a".repeat(32),
            sync_id: "s1".into(),
            uploader_device_id: "d1".into(),
            target_device_id: "t1".into(),
            epoch: 1,
            server_seq_at: 1,
            snapshot_ttl_secs: 60,
            total_bytes: 10,
            chunk_bytes: 8,
            committed_offset: 0,
            body_sha256: [0u8; 32],
            blob_ref: "b".repeat(32),
            state: UploadState::Active,
            terminal_code: None,
            terminal_status: None,
            terminal_server_seq_at: None,
            terminal_target_device_id: None,
            created_at: 0,
            updated_at: 0,
            idle_expires_at: i64::MAX,
            absolute_expires_at: i64::MAX,
        };
        row_ownership_assertions(&row);
    }

    fn row_ownership_assertions(row: &crate::db::SnapshotUploadRow) {
        assert!(owned_session(Some(row.clone()), "s1", "d1").is_ok());
        // Same group, different device: not found.
        assert!(matches!(
            owned_session(Some(row.clone()), "s1", "other"),
            Err(AppError::Upload(UploadError::NotFound))
        ));
        // Different group: not found, so a cross-sync ID does not leak existence.
        assert!(matches!(
            owned_session(Some(row.clone()), "s2", "d1"),
            Err(AppError::Upload(UploadError::NotFound))
        ));
        // Unknown ID: the same answer.
        assert!(matches!(
            owned_session(None, "s1", "d1"),
            Err(AppError::Upload(UploadError::NotFound))
        ));
    }

    #[test]
    fn upload_locks_prune_only_releases_unheld_entries() {
        let locks = UploadLocks::default();
        let held = locks.acquire("a");
        let _dropped = locks.acquire("b");
        assert_eq!(locks.tracked(), 2);
        drop(_dropped);
        locks.prune();
        assert_eq!(locks.tracked(), 1, "only the held lock survives");
        drop(held);
        locks.prune();
        assert_eq!(locks.tracked(), 0);
    }

    #[test]
    fn staging_error_maps_hash_mismatch_distinctly_from_length() {
        // Both are `StagingCorrupt`, but the message distinguishes them so an
        // operator log can tell an injected/tampered body from a truncated one.
        let a = StagingError::StagingCorrupt("staged file hash mismatch".into());
        let b =
            StagingError::StagingCorrupt("staged file length 3 is below declared total 4".into());
        assert_ne!(a.to_string(), b.to_string());
    }
}
