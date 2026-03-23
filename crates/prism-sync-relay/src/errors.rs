use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum AppError {
    BadRequest(&'static str),
    Unauthorized,
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
        let (status, body) = match &self {
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.to_string()),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".into()),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.to_string()),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not Found".into()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg.to_string()),
            AppError::PayloadTooLarge(msg) => (StatusCode::PAYLOAD_TOO_LARGE, msg.to_string()),
            AppError::TooManyRequests => {
                (StatusCode::TOO_MANY_REQUESTS, "Too Many Requests".into())
            }
            AppError::StorageFull(msg) => (StatusCode::INSUFFICIENT_STORAGE, msg.to_string()),
            AppError::Internal(msg) => {
                tracing::error!("Internal error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error".into(),
                )
            }
        };
        tracing::warn!(status = %status, error = %self, "Request error");
        (status, body).into_response()
    }
}

impl Display for AppError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::BadRequest(msg) => write!(f, "BadRequest({msg})"),
            AppError::Unauthorized => write!(f, "Unauthorized"),
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
