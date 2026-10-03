use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("BadRequest({0})")]
    BadRequest(&'static str),
    #[error("Unauthorized")]
    Unauthorized,
    #[error("DeviceIdentityMismatch")]
    DeviceIdentityMismatch,
    #[error("DeviceRevoked(remote_wipe={remote_wipe})")]
    DeviceRevoked { remote_wipe: bool },
    #[error("FirstDeviceAdmissionRequired")]
    FirstDeviceAdmissionRequired,
    #[error("FirstDeviceAdmissionInvalid")]
    FirstDeviceAdmissionInvalid,
    #[error("UpgradeRequired(min_signature_version={min_signature_version})")]
    UpgradeRequired { min_signature_version: u8 },
    #[error("EpochMismatch(envelope_epoch={envelope_epoch}, relay_epoch={relay_epoch})")]
    EpochMismatch { envelope_epoch: i64, relay_epoch: i64 },
    #[error("Forbidden({0})")]
    Forbidden(&'static str),
    #[error("NotFound")]
    NotFound,
    #[error("Conflict({0})")]
    Conflict(&'static str),
    #[error("PayloadTooLarge({0})")]
    PayloadTooLarge(&'static str),
    #[error("TooManyRequests")]
    TooManyRequests,
    #[error("StorageFull({0})")]
    StorageFull(&'static str),
    #[error(
        "MustBootstrapFromSnapshot(since_seq={since_seq}, first_retained_seq={first_retained_seq})"
    )]
    MustBootstrapFromSnapshot { since_seq: i64, first_retained_seq: i64 },
    /// A pull cursor sits above the log's head — the relay's seq stream regressed
    /// (a backup restore re-issued lower seqs) so the client holds a cursor from a
    /// no-longer-current lineage. Returned as `409 Conflict` with a structured
    /// `cursor_ahead_of_log` body (mirrors `must_bootstrap_from_snapshot`) so the
    /// client resets its cursor and re-pulls; an old (0.12.x) client classifies it
    /// as a generic loud retry rather than reading the empty page as "in sync".
    #[error("CursorAheadOfLog(since_seq={since_seq}, log_head_seq={log_head_seq})")]
    CursorAheadOfLog { since_seq: i64, log_head_seq: i64 },
    /// A `PUT /snapshot` upload lost the seq-ordering race. Returned
    /// as `409 Conflict` with a structured `stale_snapshot_seq` body
    /// (`current_server_seq_at`, `current_target_device_id`) so the
    /// client can route it to the snapshot-specific recovery path
    /// rather than the generic epoch-rotation one and feed the existing
    /// target into its suppression matrix.
    #[error(
        "SnapshotStale(current_server_seq_at={current_server_seq_at}, \
         current_target_device_id={current_target_device_id:?})"
    )]
    SnapshotStale { current_server_seq_at: i64, current_target_device_id: Option<String> },
    /// A targeted `PUT /snapshot` for a NEW audience was rejected because the
    /// group already holds the maximum unexpired targeted snapshot rows.
    /// Returned as `409 Conflict` with a structured `too_many_targeted_snapshots`
    /// body so an old (0.12.x) client classifies it as a generic loud retry.
    #[error("TooManyTargetedSnapshots(max={max})")]
    TooManyTargetedSnapshots { max: i64 },
    #[error("Internal({0})")]
    Internal(String),
    /// Resumable snapshot upload lifecycle error.
    ///
    /// Wrapped in its own variant so every new error carries the relay's
    /// structured JSON shape and a **stable machine code** the client can branch
    /// on, rather than the plain-text body most legacy variants return. See
    /// [`UploadError`] for the status/code table.
    #[error("Upload({0:?})")]
    Upload(UploadError),
}

/// Machine codes and statuses for the resumable snapshot upload lifecycle.
///
/// These are contract, not decoration: a client decides between "retry with back
///off", "query status", and "abort the ceremony" purely from the code, and a
/// recorded terminal result is reproduced by round-tripping the status and code
/// stored in the session row. Changing a code is a wire change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadError {
    /// 400 `invalid_upload` — malformed or internally inconsistent request.
    InvalidUpload(&'static str),
    /// 400 `unsupported_snapshot_audience` — a v1 request that is not targeted.
    UnsupportedAudience,
    /// 404 `upload_not_found` — no session for this ID, **or** the caller is not
    /// its owner. The two are deliberately the same response so an upload ID is
    /// not a probe for cross-device/cross-group existence.
    NotFound,
    /// 409 `upload_key_conflict` — same idempotency key, different metadata.
    KeyConflict,
    /// 409 `upload_incomplete` — complete called before all bytes are committed.
    Incomplete { committed_offset: i64 },
    /// 409 `upload_finalizing` — a completion operation currently owns the
    /// session.
    Finalizing,
    /// 409 `offset_mismatch` — the client is ahead of, or partially overlaps,
    /// the relay's committed prefix. The relay's offset is authoritative.
    OffsetMismatch { committed_offset: i64 },
    /// 409 `upload_completed` — mutation attempted after completion. The
    /// published snapshot is never deleted by this.
    Completed,
    /// 410 `upload_expired` — the session is known and terminal-by-expiry.
    Expired,
    /// 413 `chunk_too_large` — the request exceeds the session's chunk size.
    ChunkTooLarge { chunk_bytes: i64 },
    /// 400 `chunk_too_short` — a non-final chunk smaller than the chunk size. The
    /// relay's offset is authoritative for resumption, so this echoes it.
    ShortChunk { chunk_bytes: i64, committed_offset: i64 },
    /// 413 `snapshot_too_large` — the declared or requested total exceeds the
    /// server maximum.
    SnapshotTooLarge { max_wire_bytes: u64 },
    /// 429 `upload_quota_exceeded` — a session, rate, or staged-byte quota was
    /// reached. `scope` is a bounded label for metrics only, never a user ID.
    QuotaExceeded { scope: &'static str },
    /// 503 `upload_busy` — transient concurrency shedding; retry with backoff.
    /// Deliberately **not** 429 so a client does not treat it as a policy
    /// rejection.
    Busy,
    /// 422 `snapshot_hash_mismatch` — the final staged file does not match the
    /// create-time SHA-256.
    HashMismatch,
    /// 422 `upload_epoch_invalid` — the uploader's epoch changed.
    EpochInvalid,
    /// 422 `upload_owner_invalid` — the uploader was deleted or revoked.
    OwnerInvalid,
    /// 507 `insufficient_storage` — encrypted storage cannot safely reserve or
    /// write the declared bytes.
    InsufficientStorage,
    /// 409 `upload_failed` — a terminal failure with no more specific public
    /// code (e.g. staging corruption). Details stay in the logs; the client's
    /// correct response is a new upload key.
    Failed,
}

impl UploadError {
    /// The stable machine code returned in the JSON body.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidUpload(_) => "invalid_upload",
            Self::UnsupportedAudience => "unsupported_snapshot_audience",
            Self::NotFound => "upload_not_found",
            Self::KeyConflict => "upload_key_conflict",
            Self::Incomplete { .. } => "upload_incomplete",
            Self::Finalizing => "upload_finalizing",
            Self::OffsetMismatch { .. } => "offset_mismatch",
            Self::Completed => "upload_completed",
            Self::Expired => "upload_expired",
            Self::ChunkTooLarge { .. } => "chunk_too_large",
            Self::ShortChunk { .. } => "chunk_too_short",
            Self::SnapshotTooLarge { .. } => "snapshot_too_large",
            Self::QuotaExceeded { .. } => "upload_quota_exceeded",
            Self::Busy => "upload_busy",
            Self::HashMismatch => "snapshot_hash_mismatch",
            Self::EpochInvalid => "upload_epoch_invalid",
            Self::OwnerInvalid => "upload_owner_invalid",
            Self::InsufficientStorage => "insufficient_storage",
            Self::Failed => "upload_failed",
        }
    }

    /// HTTP status for this code.
    pub fn status(&self) -> StatusCode {
        match self {
            Self::InvalidUpload(_) | Self::UnsupportedAudience | Self::ShortChunk { .. } => {
                StatusCode::BAD_REQUEST
            }
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::KeyConflict
            | Self::Incomplete { .. }
            | Self::Finalizing
            | Self::OffsetMismatch { .. }
            | Self::Completed
            | Self::Failed => StatusCode::CONFLICT,
            Self::Expired => StatusCode::GONE,
            Self::ChunkTooLarge { .. } | Self::SnapshotTooLarge { .. } => {
                StatusCode::PAYLOAD_TOO_LARGE
            }
            Self::QuotaExceeded { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::HashMismatch | Self::EpochInvalid | Self::OwnerInvalid => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
            Self::Busy => StatusCode::SERVICE_UNAVAILABLE,
            Self::InsufficientStorage => StatusCode::INSUFFICIENT_STORAGE,
        }
    }

    /// Rebuild a terminal error from the status/code recorded on a session row,
    /// so a retry after a lost response returns the **same** result instead of
    /// re-running publication.
    ///
    /// `stale_snapshot_seq` and `too_many_targeted_snapshots` are the two
    /// existing snapshot errors the completion path can surface; they are
    /// reconstructed into their original variants by the caller, which is why
    /// this returns `None` for them.
    pub fn from_recorded(status: u16, code: &str) -> Option<Self> {
        let _ = status; // status is recorded for operators/diagnostics
        Some(match code {
            "invalid_upload" => Self::InvalidUpload("recorded"),
            "unsupported_snapshot_audience" => Self::UnsupportedAudience,
            "upload_not_found" => Self::NotFound,
            "upload_key_conflict" => Self::KeyConflict,
            "upload_finalizing" => Self::Finalizing,
            "upload_completed" => Self::Completed,
            "upload_expired" => Self::Expired,
            "snapshot_hash_mismatch" => Self::HashMismatch,
            "upload_epoch_invalid" => Self::EpochInvalid,
            "upload_owner_invalid" => Self::OwnerInvalid,
            "insufficient_storage" => Self::InsufficientStorage,
            // A session ended without publishing. Both are recorded with a 409
            // status, so they reconstruct into the generic terminal failure —
            // whose documented client response (generate a new upload key) is
            // exactly right. Listed explicitly rather than left to the fallback so
            // the round trip is intentional.
            "superseded" | "aborted" => Self::Failed,
            "upload_failed" | "staging_corrupt" => Self::Failed,
            // Reconstructed by the caller into the existing snapshot variants.
            "stale_snapshot_seq" | "too_many_targeted_snapshots" => return None,
            _ => return None,
        })
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::DeviceIdentityMismatch => StatusCode::UNAUTHORIZED,
            AppError::DeviceRevoked { .. } => StatusCode::UNAUTHORIZED,
            AppError::FirstDeviceAdmissionRequired => StatusCode::FORBIDDEN,
            AppError::FirstDeviceAdmissionInvalid => StatusCode::FORBIDDEN,
            AppError::UpgradeRequired { .. } => StatusCode::FORBIDDEN,
            AppError::EpochMismatch { .. } => StatusCode::FORBIDDEN,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            AppError::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            AppError::StorageFull(_) => StatusCode::INSUFFICIENT_STORAGE,
            AppError::MustBootstrapFromSnapshot { .. } => StatusCode::CONFLICT,
            AppError::CursorAheadOfLog { .. } => StatusCode::CONFLICT,
            AppError::SnapshotStale { .. } => StatusCode::CONFLICT,
            AppError::TooManyTargetedSnapshots { .. } => StatusCode::CONFLICT,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Upload(error) => error.status(),
        };
        let response = match &self {
            AppError::BadRequest(msg) => (status, msg.to_string()).into_response(),
            AppError::Unauthorized => (status, "Unauthorized".to_string()).into_response(),
            AppError::DeviceIdentityMismatch => (
                status,
                Json(ErrorBody {
                    error: "device_identity_mismatch",
                    message: Some("Registered device identity does not match stored keys"),
                    min_signature_version: None,
                    remote_wipe: None,
                    since_seq: None,
                    first_retained_seq: None,
                }),
            )
                .into_response(),
            AppError::DeviceRevoked { remote_wipe } => (
                status,
                Json(ErrorBody {
                    error: "device_revoked",
                    message: Some("Device has been revoked"),
                    min_signature_version: None,
                    remote_wipe: Some(*remote_wipe),
                    since_seq: None,
                    first_retained_seq: None,
                }),
            )
                .into_response(),
            AppError::FirstDeviceAdmissionRequired => (
                status,
                Json(ErrorBody {
                    error: "first_device_admission_required",
                    message: Some("First-device admission proof is required"),
                    min_signature_version: None,
                    remote_wipe: None,
                    since_seq: None,
                    first_retained_seq: None,
                }),
            )
                .into_response(),
            AppError::FirstDeviceAdmissionInvalid => (
                status,
                Json(ErrorBody {
                    error: "first_device_admission_invalid",
                    message: Some("First-device admission proof is invalid"),
                    min_signature_version: None,
                    remote_wipe: None,
                    since_seq: None,
                    first_retained_seq: None,
                }),
            )
                .into_response(),
            AppError::UpgradeRequired { min_signature_version } => (
                status,
                Json(ErrorBody {
                    error: "upgrade_required",
                    message: Some(
                        "This app version is too old. Please update to continue syncing.",
                    ),
                    min_signature_version: Some(*min_signature_version),
                    remote_wipe: None,
                    since_seq: None,
                    first_retained_seq: None,
                }),
            )
                .into_response(),
            AppError::EpochMismatch { envelope_epoch, relay_epoch } => {
                let body = serde_json::json!({
                    "error": "epoch_mismatch",
                    "message": "Envelope epoch does not match relay epoch; perform epoch recovery first",
                    "envelope_epoch": envelope_epoch,
                    "relay_epoch": relay_epoch,
                });
                (status, Json(body)).into_response()
            }
            AppError::Forbidden(msg) => (status, msg.to_string()).into_response(),
            AppError::NotFound => (status, "Not Found".to_string()).into_response(),
            AppError::Conflict(msg) => (status, msg.to_string()).into_response(),
            AppError::PayloadTooLarge(msg) => (status, msg.to_string()).into_response(),
            AppError::TooManyRequests => (status, "Too Many Requests".to_string()).into_response(),
            AppError::StorageFull(msg) => (status, msg.to_string()).into_response(),
            AppError::MustBootstrapFromSnapshot { since_seq, first_retained_seq } => (
                status,
                Json(ErrorBody {
                    error: "must_bootstrap_from_snapshot",
                    message: Some("Batch history is no longer complete; bootstrap from snapshot"),
                    min_signature_version: None,
                    remote_wipe: None,
                    since_seq: Some(*since_seq),
                    first_retained_seq: Some(*first_retained_seq),
                }),
            )
                .into_response(),
            AppError::CursorAheadOfLog { since_seq, log_head_seq } => {
                // Local JSON body (mirrors `must_bootstrap_from_snapshot`'s shape
                // with a distinct `error` code and a `log_head_seq` field). A
                // 0.12.x client has no branch for this code, so it falls through to
                // the generic loud-retry path — strictly better than the silent
                // in-sync misread it does today.
                let body = serde_json::json!({
                    "error": "cursor_ahead_of_log",
                    "message": "Pull cursor is ahead of the relay log head; reset and re-pull",
                    "since_seq": since_seq,
                    "log_head_seq": log_head_seq,
                });
                (status, Json(body)).into_response()
            }
            AppError::SnapshotStale { current_server_seq_at, current_target_device_id } => {
                // Local JSON body rather than a field on the shared
                // `ErrorBody` — this variant's payload doesn't overlap
                // any other. `Option::None` serialises as JSON `null`,
                // which is the wire contract the client expects.
                let body = serde_json::json!({
                    "error": "stale_snapshot_seq",
                    "message": "Snapshot upload superseded by a newer server snapshot",
                    "current_server_seq_at": current_server_seq_at,
                    "current_target_device_id": current_target_device_id,
                });
                (status, Json(body)).into_response()
            }
            AppError::TooManyTargetedSnapshots { max } => {
                let body = serde_json::json!({
                    "error": "too_many_targeted_snapshots",
                    "message": "Too many concurrent pair-time snapshots; retry later",
                    "max": max,
                });
                (status, Json(body)).into_response()
            }
            AppError::Internal(msg) => {
                tracing::error!("Internal error: {}", msg);
                (status, "Internal Server Error".to_string()).into_response()
            }
            AppError::Upload(error) => {
                // Structured body, unlike most legacy variants: the client's
                // whole retry/abort decision depends on the machine code, so it
                // must never be flattened into free text. The fields are the
                // response-specific data a client needs (the relay's offset, the
                // chunk size, the declared cap) and never a user identifier.
                let mut body = serde_json::json!({
                    "error": error.code(),
                    "message": upload_error_message(error),
                });
                match error {
                    UploadError::Incomplete { committed_offset }
                    | UploadError::OffsetMismatch { committed_offset } => {
                        body["committed_offset"] = serde_json::json!(committed_offset);
                    }
                    UploadError::ChunkTooLarge { chunk_bytes } => {
                        body["chunk_bytes"] = serde_json::json!(chunk_bytes);
                    }
                    UploadError::ShortChunk { chunk_bytes, committed_offset } => {
                        // Same resumption fields as the offset/size errors: the
                        // relay's offset and chunk size are what the client needs
                        // to resume rather than re-derive.
                        body["chunk_bytes"] = serde_json::json!(chunk_bytes);
                        body["committed_offset"] = serde_json::json!(committed_offset);
                    }
                    UploadError::SnapshotTooLarge { max_wire_bytes } => {
                        body["max_wire_bytes"] = serde_json::json!(max_wire_bytes);
                    }
                    UploadError::QuotaExceeded { scope } => {
                        // `scope` is a bounded, non-user label (e.g. "group").
                        body["scope"] = serde_json::json!(scope);
                    }
                    _ => {}
                }
                (status, Json(body)).into_response()
            }
        };
        tracing::warn!(status = %status, error = %self, "Request error");
        response
    }
}

/// Operator-facing message text for one upload error code.
///
/// Kept server-side (not client-supplied) and deliberately free of identifiers,
/// upload IDs, offsets from other sessions, or any distinguishing detail that
/// would turn a uniform response into an oracle.
fn upload_error_message(error: &UploadError) -> &'static str {
    match error {
        UploadError::InvalidUpload(_) => "Malformed or internally inconsistent upload request",
        UploadError::UnsupportedAudience => {
            "Resumable snapshot uploads require a targeted snapshot audience"
        }
        UploadError::NotFound => "No such upload session",
        UploadError::KeyConflict => "Upload key already used with different metadata",
        UploadError::Incomplete { .. } => "Upload is not fully committed",
        UploadError::Finalizing => "A completion operation currently owns this upload",
        UploadError::OffsetMismatch { .. } => {
            "Chunk offset does not match the relay's committed offset"
        }
        UploadError::Completed => "Upload already completed",
        UploadError::Expired => "Upload session expired",
        UploadError::ChunkTooLarge { .. } => "Chunk exceeds the negotiated chunk size",
        UploadError::ShortChunk { .. } => {
            "A non-final chunk must be exactly the negotiated chunk size"
        }
        UploadError::SnapshotTooLarge { .. } => "Declared snapshot size exceeds the server maximum",
        UploadError::QuotaExceeded { .. } => "Upload quota reached",
        UploadError::Busy => "Upload is busy; retry with backoff",
        UploadError::HashMismatch => "Staged upload does not match create metadata",
        UploadError::EpochInvalid => "Uploader epoch is no longer valid",
        UploadError::OwnerInvalid => "Uploader is no longer valid",
        UploadError::InsufficientStorage => "Encrypted storage cannot reserve the declared bytes",
        UploadError::Failed => "Upload failed; start a new upload",
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    min_signature_version: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_wipe: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    since_seq: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_retained_seq: Option<i64>,
}

impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        AppError::Internal(e.to_string())
    }
}
