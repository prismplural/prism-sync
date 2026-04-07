use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, put},
    Router,
};
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::{db, errors::AppError, state::AppState};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/pairing", axum::routing::post(create_session))
        .route("/v1/pairing/{rendezvous_id}/bootstrap", get(get_bootstrap))
        .route(
            "/v1/pairing/{rendezvous_id}/init",
            put(put_init).get(get_init),
        )
        .route(
            "/v1/pairing/{rendezvous_id}/confirmation",
            put(put_confirmation).get(get_confirmation),
        )
        .route(
            "/v1/pairing/{rendezvous_id}/credentials",
            put(put_credentials).get(get_credentials),
        )
        .route(
            "/v1/pairing/{rendezvous_id}/joiner",
            put(put_joiner).get(get_joiner),
        )
        .route("/v1/pairing/{rendezvous_id}", delete(delete_session))
}

// ---------------------------------------------------------------------------
// POST /v1/pairing — create a new pairing session
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateSessionRequest {
    joiner_bootstrap: String,
}

#[derive(Serialize)]
struct CreateSessionResponse {
    rendezvous_id: String,
}

async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<CreateSessionRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Rate limit by client IP
    if let Some(ip) = client_ip_key(&headers) {
        if !state.pairing_rate_limiter.check(
            &ip,
            state.config.pairing_session_rate_limit,
            300, // 5-minute window
        ) {
            return Err(AppError::TooManyRequests);
        }
    }

    // Decode and validate bootstrap data
    let bootstrap_data = base64::engine::general_purpose::STANDARD
        .decode(&body.joiner_bootstrap)
        .map_err(|_| AppError::BadRequest("Invalid base64 in joiner_bootstrap"))?;

    if bootstrap_data.len() > state.config.pairing_session_max_payload_bytes {
        return Err(AppError::PayloadTooLarge("joiner_bootstrap too large"));
    }

    // Generate rendezvous_id (128-bit CSPRNG, hex-encoded)
    let rendezvous_id = {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
    };

    let db = state.db.clone();
    let rid = rendezvous_id.clone();
    let ttl = state.config.pairing_session_ttl_secs;

    tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| db::create_pairing_session(conn, &rid, &bootstrap_data, ttl))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    tracing::debug!(
        rendezvous_id = %&rendezvous_id[..8],
        "Pairing session created"
    );

    Ok((
        StatusCode::CREATED,
        axum::Json(CreateSessionResponse { rendezvous_id }),
    ))
}

// ---------------------------------------------------------------------------
// GET /v1/pairing/{rendezvous_id}/bootstrap
// ---------------------------------------------------------------------------

async fn get_bootstrap(
    State(state): State<AppState>,
    Path(rendezvous_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let db = state.db.clone();
    let rid = rendezvous_id.clone();

    let bootstrap = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| db::get_pairing_bootstrap(conn, &rid))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    match bootstrap {
        Some(data) => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(&data);
            Ok((StatusCode::OK, encoded).into_response())
        }
        None => Err(AppError::NotFound),
    }
}

// ---------------------------------------------------------------------------
// PUT/GET slot helpers
// ---------------------------------------------------------------------------

async fn put_slot(
    state: AppState,
    rendezvous_id: String,
    slot: &'static str,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    if body.len() > state.config.pairing_session_max_payload_bytes {
        return Err(AppError::PayloadTooLarge("Payload too large"));
    }

    let db = state.db.clone();
    let rid = rendezvous_id.clone();
    let data = body.to_vec();

    // First check if the session exists at all
    let exists = {
        let db = state.db.clone();
        let rid = rid.clone();
        tokio::task::spawn_blocking(move || {
            db.with_conn(|conn| db::pairing_session_exists(conn, &rid))
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|e| AppError::Internal(e.to_string()))?
    };

    if !exists {
        return Err(AppError::NotFound);
    }

    let updated = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| db::set_pairing_slot(conn, &rid, slot, &data))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    if updated {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        // Session exists but slot already set
        Err(AppError::Conflict("Slot already set"))
    }
}

async fn get_slot(
    state: AppState,
    rendezvous_id: String,
    slot: &'static str,
) -> Result<impl IntoResponse, AppError> {
    let db = state.db.clone();
    let rid = rendezvous_id.clone();

    // Check if session exists
    let exists = {
        let db = state.db.clone();
        let rid2 = rid.clone();
        tokio::task::spawn_blocking(move || {
            db.with_conn(|conn| db::pairing_session_exists(conn, &rid2))
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|e| AppError::Internal(e.to_string()))?
    };

    if !exists {
        return Err(AppError::NotFound);
    }

    let value = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| db::get_pairing_slot(conn, &rid, slot))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    match value {
        Some(data) => Ok((StatusCode::OK, data).into_response()),
        None => Ok(StatusCode::NO_CONTENT.into_response()),
    }
}

// ---------------------------------------------------------------------------
// Slot route handlers
// ---------------------------------------------------------------------------

async fn put_init(
    State(state): State<AppState>,
    Path(rendezvous_id): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    put_slot(state, rendezvous_id, "pairing_init", body).await
}

async fn get_init(
    State(state): State<AppState>,
    Path(rendezvous_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    get_slot(state, rendezvous_id, "pairing_init").await
}

async fn put_confirmation(
    State(state): State<AppState>,
    Path(rendezvous_id): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    put_slot(state, rendezvous_id, "joiner_confirmation", body).await
}

async fn get_confirmation(
    State(state): State<AppState>,
    Path(rendezvous_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    get_slot(state, rendezvous_id, "joiner_confirmation").await
}

async fn put_credentials(
    State(state): State<AppState>,
    Path(rendezvous_id): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    put_slot(state, rendezvous_id, "credential_bundle", body).await
}

async fn get_credentials(
    State(state): State<AppState>,
    Path(rendezvous_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    get_slot(state, rendezvous_id, "credential_bundle").await
}

async fn put_joiner(
    State(state): State<AppState>,
    Path(rendezvous_id): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    put_slot(state, rendezvous_id, "joiner_bundle", body).await
}

async fn get_joiner(
    State(state): State<AppState>,
    Path(rendezvous_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    get_slot(state, rendezvous_id, "joiner_bundle").await
}

// ---------------------------------------------------------------------------
// DELETE /v1/pairing/{rendezvous_id}
// ---------------------------------------------------------------------------

async fn delete_session(
    State(state): State<AppState>,
    Path(rendezvous_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let db = state.db.clone();
    let rid = rendezvous_id;

    tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| db::delete_pairing_session(conn, &rid))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn client_ip_key(headers: &HeaderMap) -> Option<String> {
    for header_name in [
        #[cfg(feature = "test-helpers")]
        "x-test-client-ip",
        "cf-connecting-ip",
        "x-forwarded-for",
        "x-real-ip",
        "forwarded",
    ] {
        if let Some(value) = headers.get(header_name).and_then(|v| v.to_str().ok()) {
            let candidate = if header_name == "forwarded" {
                value
                    .split(';')
                    .find_map(|part| part.trim().strip_prefix("for="))
                    .unwrap_or(value)
            } else {
                value.split(',').next().unwrap_or(value)
            };
            let trimmed = candidate.trim().trim_matches('"');
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}
