pub mod devices;
pub mod metrics;
pub mod register;
pub mod sync;
pub mod ws;

use axum::{
    extract::State,
    http::Request,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use tower_http::cors::CorsLayer;
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::Level;

use crate::{db, errors::AppError, state::AppState};

/// Authenticated identity injected into request extensions by auth middleware.
#[derive(Debug, Clone)]
pub struct AuthIdentity {
    pub sync_id: String,
    pub device_id: String,
}

/// Build the full application router.
pub fn router(state: AppState) -> Router {
    // Routes that require authentication
    let authenticated_routes = Router::new()
        // Sync routes (push/pull/snapshot/delete)
        .route(
            "/v1/sync/{sync_id}/changes",
            put(sync::push_changes).get(sync::pull_changes),
        )
        .route(
            "/v1/sync/{sync_id}/snapshot",
            put(sync::put_snapshot).get(sync::get_snapshot),
        )
        .route("/v1/sync/{sync_id}", delete(sync::delete_account))
        // Device routes (list/revoke/rekey/ack)
        .route("/v1/sync/{sync_id}/devices", get(devices::list_devices))
        .route(
            "/v1/sync/{sync_id}/devices/{device_id}",
            delete(devices::delete_device),
        )
        .route("/v1/sync/{sync_id}/rekey", post(devices::post_rekey))
        .route(
            "/v1/sync/{sync_id}/rekey/{device_id}",
            get(devices::get_rekey_artifact),
        )
        .route("/v1/sync/{sync_id}/ack", post(devices::post_ack))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // Routes that do NOT require authentication
    // (WebSocket does message-based auth after upgrade)
    let public_routes = Router::new()
        .merge(register::routes())
        .route("/v1/sync/{sync_id}/ws", get(ws::ws_upgrade));

    // Relay is accessed only by native clients — no browser origin is expected.
    // Default CorsLayer rejects all cross-origin requests.
    let cors = CorsLayer::new();

    Router::new()
        .merge(public_routes)
        .merge(authenticated_routes)
        .merge(metrics::routes())
        .route(
            "/health",
            axum::routing::get(|| async { axum::Json(serde_json::json!({"status": "ok"})) }),
        )
        .layer(cors)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<axum::body::Body>| {
                    let path = request.uri().path();
                    tracing::debug_span!("http", method = %request.method(), path)
                })
                .on_response(DefaultOnResponse::new().level(Level::DEBUG)),
        )
        .with_state(state)
}

/// Result of auth validation — distinguishes "no session" from "device revoked".
enum AuthResult {
    Ok(AuthIdentity),
    /// Valid session but device is revoked; includes remote_wipe flag.
    DeviceRevoked { remote_wipe: bool },
    /// Session not found, expired, or device missing.
    Invalid,
}

/// Auth middleware: extracts Bearer token, validates session, injects AuthIdentity.
///
/// When a revoked device authenticates, the 401 response includes a JSON body
/// with `{"error": "device_revoked", "remote_wipe": true/false}` so the client
/// can act on it without needing a separate unauthenticated endpoint.
async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, Response> {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let Some(token) = token else {
        return Err(AppError::Unauthorized.into_response());
    };

    if token.len() < 32 {
        state.metrics.inc(&state.metrics.auth_failures);
        return Err(AppError::Unauthorized.into_response());
    }

    let token_owned = token.to_string();
    let session_expiry = state.config.session_expiry_secs as i64;

    // Phase 1 — Read (blocking, must complete): validate session + device status
    let db_read = state.db.clone();
    let auth_result =
        tokio::task::spawn_blocking(move || -> Result<AuthResult, AppError> {
            db_read
                .with_read_conn(|conn| {
                    let Some((sync_id, device_id)) =
                        db::validate_session(conn, &token_owned)?
                    else {
                        return Ok(AuthResult::Invalid);
                    };
                    let Some(device) = db::get_device(conn, &sync_id, &device_id)? else {
                        return Ok(AuthResult::Invalid);
                    };
                    if device.status != "active" {
                        let wipe = db::get_device_wipe_status(conn, &sync_id, &device_id)?
                            .unwrap_or(false);
                        return Ok(AuthResult::DeviceRevoked { remote_wipe: wipe });
                    }
                    Ok(AuthResult::Ok(AuthIdentity { sync_id, device_id }))
                })
                .map_err(|e| AppError::Internal(e.to_string()))
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()).into_response())?
        .map_err(|e| e.into_response())?;

    match auth_result {
        AuthResult::Ok(identity) => {
            // Phase 2 — Write (fire-and-forget): touch session + device timestamps
            let db_write = state.db.clone();
            let sid = identity.sync_id.clone();
            let did = identity.device_id.clone();
            tokio::spawn(async move {
                let _ = tokio::task::spawn_blocking(move || {
                    db_write.with_conn(|conn| {
                        db::touch_session(conn, &sid, &did, session_expiry)?;
                        db::touch_device(conn, &sid, &did)
                    })
                })
                .await;
            });

            tracing::debug!(
                sync_id = %&identity.sync_id[..16.min(identity.sync_id.len())],
                device_id = %&identity.device_id[..8.min(identity.device_id.len())],
                method = %req.method(),
                path = %req.uri().path(),
                "Auth OK"
            );
            req.extensions_mut().insert(identity);
            Ok(next.run(req).await)
        }
        AuthResult::DeviceRevoked { remote_wipe } => {
            tracing::warn!(
                method = %req.method(),
                path = %req.uri().path(),
                remote_wipe,
                "Auth REJECTED: device revoked"
            );
            state.metrics.inc(&state.metrics.auth_failures);
            Err((
                axum::http::StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "device_revoked",
                    "remote_wipe": remote_wipe,
                })),
            )
                .into_response())
        }
        AuthResult::Invalid => {
            tracing::warn!(
                method = %req.method(),
                path = %req.uri().path(),
                "Auth REJECTED: invalid session or inactive device"
            );
            state.metrics.inc(&state.metrics.auth_failures);
            Err(AppError::Unauthorized.into_response())
        }
    }
}
