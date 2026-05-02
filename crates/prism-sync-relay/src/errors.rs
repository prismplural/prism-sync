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
