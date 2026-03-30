use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum AppError {
    BadRequest(&'static str),
    Unauthorized,
    DeviceIdentityMismatch,
    DeviceRevoked { remote_wipe: bool },
    FirstDeviceAdmissionRequired,
    FirstDeviceAdmissionInvalid,
    Forbidden(&'static str),
    NotFound,
    Conflict(&'static str),
    PayloadTooLarge(&'static str),
    TooManyRequests,
    StorageFull(&'static str),
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
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            AppError::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            AppError::StorageFull(_) => StatusCode::INSUFFICIENT_STORAGE,
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
                    remote_wipe: None,
                }),
            )
                .into_response(),
            AppError::DeviceRevoked { remote_wipe } => (
                status,
                Json(ErrorBody {
                    error: "device_revoked",
                    message: Some("Device has been revoked"),
                    remote_wipe: Some(*remote_wipe),
                }),
            )
                .into_response(),
            AppError::FirstDeviceAdmissionRequired => (
                status,
                Json(ErrorBody {
                    error: "first_device_admission_required",
                    message: Some("First-device admission proof is required"),
                    remote_wipe: None,
                }),
            )
                .into_response(),
            AppError::FirstDeviceAdmissionInvalid => (
                status,
                Json(ErrorBody {
                    error: "first_device_admission_invalid",
                    message: Some("First-device admission proof is invalid"),
                    remote_wipe: None,
                }),
            )
                .into_response(),
            AppError::Forbidden(msg) => (status, msg.to_string()).into_response(),
            AppError::NotFound => (status, "Not Found".to_string()).into_response(),
            AppError::Conflict(msg) => (status, msg.to_string()).into_response(),
            AppError::PayloadTooLarge(msg) => (status, msg.to_string()).into_response(),
            AppError::TooManyRequests => (status, "Too Many Requests".to_string()).into_response(),
            AppError::StorageFull(msg) => (status, msg.to_string()).into_response(),
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
    remote_wipe: Option<bool>,
}

impl Display for AppError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::BadRequest(msg) => write!(f, "BadRequest({msg})"),
            AppError::Unauthorized => write!(f, "Unauthorized"),
            AppError::DeviceIdentityMismatch => write!(f, "DeviceIdentityMismatch"),
            AppError::DeviceRevoked { remote_wipe } => {
                write!(f, "DeviceRevoked(remote_wipe={remote_wipe})")
            }
            AppError::FirstDeviceAdmissionRequired => {
                write!(f, "FirstDeviceAdmissionRequired")
            }
            AppError::FirstDeviceAdmissionInvalid => write!(f, "FirstDeviceAdmissionInvalid"),
            AppError::Forbidden(msg) => write!(f, "Forbidden({msg})"),
            AppError::NotFound => write!(f, "NotFound"),
            AppError::Conflict(msg) => write!(f, "Conflict({msg})"),
            AppError::PayloadTooLarge(msg) => write!(f, "PayloadTooLarge({msg})"),
            AppError::TooManyRequests => write!(f, "TooManyRequests"),
            AppError::StorageFull(msg) => write!(f, "StorageFull({msg})"),
            AppError::Internal(msg) => write!(f, "Internal({msg})"),
        }
    }
}

impl std::error::Error for AppError {}

impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        AppError::Internal(e.to_string())
    }
}
