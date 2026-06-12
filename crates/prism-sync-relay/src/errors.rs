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
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            AppError::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            AppError::StorageFull(_) => StatusCode::INSUFFICIENT_STORAGE,
            AppError::MustBootstrapFromSnapshot { .. } => StatusCode::CONFLICT,
            AppError::SnapshotStale { .. } => StatusCode::CONFLICT,
            AppError::TooManyTargetedSnapshots { .. } => StatusCode::CONFLICT,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
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
        };
        tracing::warn!(status = %status, error = %self, "Request error");
        response
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
