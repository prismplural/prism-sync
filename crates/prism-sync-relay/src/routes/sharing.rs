use axum::{
    body::Bytes,
    extract::{ConnectInfo, Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::Engine;
use serde::Deserialize;
use std::net::SocketAddr;

use crate::{db, errors::AppError, state::AppState};

use super::{verify_signed_request, AuthIdentity};

/// Validate that a sharing_id is a 32-char hex string (16 bytes).
fn is_valid_sharing_id(sharing_id: &str) -> bool {
    sharing_id.len() == 32 && sharing_id.chars().all(|c| c.is_ascii_hexdigit())
}

fn client_ip_key(peer_addr: SocketAddr) -> String {
    peer_addr.ip().to_string()
}

// ---------------------------------------------------------------------------
// PUT /v1/sharing/identity — publish identity bundle (auth + signed)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct PublishIdentityRequest {
    pub sharing_id: String,
    pub identity_bundle: String, // base64
}

pub async fn put_identity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(auth): Extension<AuthIdentity>,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    verify_signed_request(
        &state,
        &auth,
        &headers,
        "PUT",
        "/v1/sharing/identity",
        &body,
    )?;

    let req: PublishIdentityRequest =
        serde_json::from_slice(&body).map_err(|_| AppError::BadRequest("Invalid JSON"))?;

    if !is_valid_sharing_id(&req.sharing_id) {
        return Err(AppError::BadRequest("Invalid sharing_id (32 hex chars)"));
    }

    let b64 = base64::engine::general_purpose::STANDARD;
    let bundle = b64
        .decode(&req.identity_bundle)
        .map_err(|_| AppError::BadRequest("Invalid base64 identity_bundle"))?;

    if bundle.len() > state.config.sharing_identity_max_bytes {
        return Err(AppError::PayloadTooLarge("identity_bundle too large"));
    }

    let db = state.db.clone();
    let sync_id = auth.sync_id.clone();
    let sharing_id = req.sharing_id;

    tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            // Bind sync_id <-> sharing_id
            let ok = db::upsert_sharing_id_mapping(conn, &sync_id, &sharing_id)?;
            if !ok {
                return Err(rusqlite::Error::QueryReturnedNoRows); // sentinel
            }
            let now = db::now_secs();
            db::upsert_sharing_identity(conn, &sharing_id, &bundle, now)?;
            Ok(true)
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| {
        if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
            AppError::Conflict("sharing_id/sync_id mapping conflict")
        } else {
            AppError::Internal(e.to_string())
        }
    })?;

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// PUT /v1/sharing/prekey — publish signed prekey (auth + signed)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct PublishPrekeyRequest {
    pub sharing_id: String,
    pub device_id: String,
    pub prekey_id: String,
    pub prekey_bundle: String, // base64
}

pub async fn put_prekey(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(auth): Extension<AuthIdentity>,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    verify_signed_request(&state, &auth, &headers, "PUT", "/v1/sharing/prekey", &body)?;

    let req: PublishPrekeyRequest =
        serde_json::from_slice(&body).map_err(|_| AppError::BadRequest("Invalid JSON"))?;

    if req.device_id != auth.device_id {
        return Err(AppError::Forbidden("device_id mismatch"));
    }

    if !is_valid_sharing_id(&req.sharing_id) {
        return Err(AppError::BadRequest("Invalid sharing_id (32 hex chars)"));
    }

    let b64 = base64::engine::general_purpose::STANDARD;
    let bundle = b64
        .decode(&req.prekey_bundle)
        .map_err(|_| AppError::BadRequest("Invalid base64 prekey_bundle"))?;

    if bundle.len() > state.config.sharing_prekey_max_bytes {
        return Err(AppError::PayloadTooLarge("prekey_bundle too large"));
    }

    let db = state.db.clone();
    let sync_id = auth.sync_id.clone();
    let sharing_id = req.sharing_id;
    let device_id = req.device_id;
    let prekey_id = req.prekey_id;

    tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            // Verify caller's sync_id is bound to the claimed sharing_id
            let bound = db::get_sharing_id_for_sync(conn, &sync_id)?;
            match bound {
                Some(ref s) if s == &sharing_id => {}
                _ => return Err(rusqlite::Error::QueryReturnedNoRows), // sentinel
            }
            // Record relay-side upload time as created_at for freshness enforcement.
            // The relay does not parse the opaque prekey bundle — it uses its own
            // clock to timestamp the upload, then enforces upload-age and serve-age
            // limits against that timestamp.
            let now = db::now_secs();
            db::upsert_sharing_prekey(conn, &sharing_id, &device_id, &prekey_id, &bundle, now)?;
            Ok(true)
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| {
        if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
            AppError::Conflict("sharing_id does not match bound mapping")
        } else {
            AppError::Internal(e.to_string())
        }
    })?;

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// GET /v1/sharing/{sharing_id}/bundle — fetch prekey bundle (public, rate-limited)
// ---------------------------------------------------------------------------

pub async fn get_bundle(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    Path(sharing_id): Path<String>,
) -> Result<axum::response::Response, AppError> {
    let key = format!("sharing_fetch:{}", client_ip_key(peer_addr));
    if !state
        .sharing_fetch_rate_limiter
        .check(&key, state.config.sharing_fetch_rate_limit, 300)
    {
        return Err(AppError::TooManyRequests);
    }

    if !is_valid_sharing_id(&sharing_id) {
        return Err(AppError::NotFound);
    }

    let db = state.db.clone();
    let sid = sharing_id.clone();

    let result = tokio::task::spawn_blocking(move || {
        db.with_read_conn(|conn| {
            let identity = db::get_sharing_identity(conn, &sid)?;
            let prekey = db::get_best_sharing_prekey(conn, &sid)?;
            Ok((identity, prekey))
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let (identity, prekey) = result;

    // Return 404 for missing identity OR missing prekey (no presence probing)
    let Some(identity_bundle) = identity else {
        return Err(AppError::NotFound);
    };
    let Some((device_id, prekey_id, prekey_bundle, created_at)) = prekey else {
        return Err(AppError::NotFound);
    };

    // Freshness gate: reject stale prekeys so senders don't encrypt to
    // an abandoned recipient.
    let now = db::now_secs();
    let max_age = state.config.prekey_serve_max_age_secs;
    if created_at < now - max_age {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "recipient_prekey_stale"})),
        )
            .into_response());
    }

    let b64 = base64::engine::general_purpose::STANDARD;
    Ok(Json(serde_json::json!({
        "identity_bundle": b64.encode(&identity_bundle),
        "signed_prekey": b64.encode(&prekey_bundle),
        "device_id": device_id,
        "prekey_id": prekey_id,
    }))
    .into_response())
}

// ---------------------------------------------------------------------------
// POST /v1/sharing/init — upload sharing-init payload (auth + signed)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SharingInitRequest {
    pub init_id: String,
    pub recipient_id: String,
    pub sender_id: String,
    pub payload: String, // base64
}

pub async fn post_init(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(auth): Extension<AuthIdentity>,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    verify_signed_request(&state, &auth, &headers, "POST", "/v1/sharing/init", &body)?;

    let req: SharingInitRequest =
        serde_json::from_slice(&body).map_err(|_| AppError::BadRequest("Invalid JSON"))?;

    if !is_valid_sharing_id(&req.init_id) {
        return Err(AppError::BadRequest("Invalid init_id (32 hex chars)"));
    }
    if !is_valid_sharing_id(&req.recipient_id) {
        return Err(AppError::BadRequest("Invalid recipient_id (32 hex chars)"));
    }
    if !is_valid_sharing_id(&req.sender_id) {
        return Err(AppError::BadRequest("Invalid sender_id (32 hex chars)"));
    }

    let b64 = base64::engine::general_purpose::STANDARD;
    let payload = b64
        .decode(&req.payload)
        .map_err(|_| AppError::BadRequest("Invalid base64 payload"))?;

    if payload.len() > state.config.sharing_init_max_payload_bytes {
        return Err(AppError::PayloadTooLarge("payload too large"));
    }

    let db = state.db.clone();
    let sync_id = auth.sync_id.clone();
    let sender_id = req.sender_id;
    let recipient_id = req.recipient_id;
    let init_id = req.init_id;

    // Verify caller's sharing_id matches sender_id
    let db2 = db.clone();
    let sid = sync_id.clone();
    let sender = sender_id.clone();
    let bound_sharing_id = tokio::task::spawn_blocking(move || {
        db2.with_read_conn(|conn| db::get_sharing_id_for_sync(conn, &sid))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    match bound_sharing_id {
        Some(ref s) if s == &sender => {}
        _ => {
            return Err(AppError::Conflict(
                "sender_id does not match bound sharing_id",
            ))
        }
    }

    // Rate-limit by sync_id
    let rate_key = format!("sharing_init:{sync_id}");
    if !state
        .sharing_init_rate_limiter
        .check(&rate_key, state.config.sharing_init_rate_limit, 3600)
    {
        return Err(AppError::TooManyRequests);
    }

    let ttl = state.config.sharing_init_ttl_secs;
    let max_pending = state.config.sharing_init_max_pending;

    tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            // Check pending count for recipient
            let count = db::count_pending_sharing_inits(conn, &recipient_id)?;
            if count >= max_pending {
                return Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
                    Some("max_pending".to_string()),
                ));
            }

            let inserted =
                db::insert_sharing_init(conn, &init_id, &recipient_id, &sender_id, &payload, ttl)?;
            if !inserted {
                return Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
                    Some("duplicate".to_string()),
                ));
            }
            Ok(())
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| {
        if let rusqlite::Error::SqliteFailure(_, Some(ref msg)) = e {
            if msg == "max_pending" {
                return AppError::TooManyRequests;
            }
            if msg == "duplicate" {
                return AppError::Conflict("init_id already exists");
            }
        }
        AppError::Internal(e.to_string())
    })?;

    Ok(StatusCode::CREATED)
}

// ---------------------------------------------------------------------------
// GET /v1/sharing/init/pending — fetch pending sharing-inits (auth + signed)
// ---------------------------------------------------------------------------

pub async fn get_pending_inits(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(auth): Extension<AuthIdentity>,
) -> Result<impl IntoResponse, AppError> {
    verify_signed_request(
        &state,
        &auth,
        &headers,
        "GET",
        "/v1/sharing/init/pending",
        &[],
    )?;

    let db = state.db.clone();
    let sync_id = auth.sync_id.clone();

    let result = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            let sharing_id = db::get_sharing_id_for_sync(conn, &sync_id)?;
            let Some(sharing_id) = sharing_id else {
                return Ok(Vec::new());
            };
            db::fetch_and_consume_pending_sharing_inits(conn, &sharing_id)
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let b64 = base64::engine::general_purpose::STANDARD;
    let body: Vec<serde_json::Value> = result
        .into_iter()
        .map(|p| {
            serde_json::json!({
                "init_id": p.init_id,
                "sender_id": p.sender_id,
                "payload": b64.encode(&p.payload),
                "created_at": p.created_at,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({"payloads": body})))
}

// ---------------------------------------------------------------------------
// DELETE /v1/sharing/identity — remove identity + prekeys (auth + signed)
// ---------------------------------------------------------------------------

pub async fn delete_identity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(auth): Extension<AuthIdentity>,
) -> Result<impl IntoResponse, AppError> {
    verify_signed_request(
        &state,
        &auth,
        &headers,
        "DELETE",
        "/v1/sharing/identity",
        &[],
    )?;

    let db = state.db.clone();
    let sync_id = auth.sync_id.clone();

    tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            let sharing_id = db::get_sharing_id_for_sync(conn, &sync_id)?;
            if let Some(ref sharing_id) = sharing_id {
                db::delete_sharing_identity(conn, sharing_id)?;
                db::delete_sharing_prekeys(conn, sharing_id)?;
            }
            Ok(())
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}
