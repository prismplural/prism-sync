pub mod devices;
pub mod metrics;
pub mod register;
pub mod sync;
pub mod ws;

use axum::{
    extract::State,
    http::Request,
    middleware::{self, Next},
    response::Response,
    routing::{delete, get, post, put},
    Router,
};
use tower_http::cors::CorsLayer;
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::Level;

use crate::{db, errors::AppError, state::AppState};

/// Permission levels, ordered from least to most privileged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permission {
    ReadOnly,
    ReadWrite,
    Admin,
}

impl Permission {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read_only" => Some(Permission::ReadOnly),
            "read_write" => Some(Permission::ReadWrite),
            "admin" => Some(Permission::Admin),
            _ => None,
        }
    }
}

/// Check that a device has at least the required permission level.
pub fn require_permission(device_permission: &str, min_level: Permission) -> Result<(), AppError> {
    let actual = Permission::parse(device_permission)
        .ok_or(AppError::Forbidden("Unknown permission level"))?;
    if actual >= min_level {
        Ok(())
    } else {
        Err(AppError::Forbidden("Insufficient permissions"))
    }
}

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
            "/v1/sync/{sync_id}/rekey/{epoch}/{device_id}",
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
        .route("/v1/sync/{sync_id}/ws", get(ws::ws_upgrade))
        .route(
            "/v1/sync/{sync_id}/devices/{device_id}/wipe-status",
            get(devices::get_wipe_status),
        );

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

/// Auth middleware: extracts Bearer token, validates session, injects AuthIdentity.
async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, AppError> {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;

    if token.len() < 32 {
        state.metrics.inc(&state.metrics.auth_failures);
        return Err(AppError::Unauthorized);
    }

    let token_owned = token.to_string();
    let session_expiry = state.config.session_expiry_secs as i64;

    // Phase 1 — Read (blocking, must complete): validate session + device status
    let db_read = state.db.clone();
    let identity =
        tokio::task::spawn_blocking(move || -> Result<Option<AuthIdentity>, AppError> {
            db_read
                .with_read_conn(|conn| {
                    let Some((sync_id, device_id)) =
                        db::validate_session(conn, &token_owned)?
                    else {
                        return Ok(None);
                    };
                    let Some(device) = db::get_device(conn, &sync_id, &device_id)? else {
                        return Ok(None);
                    };
                    if device.status != "active" {
                        return Ok(None);
                    }
                    Ok(Some(AuthIdentity { sync_id, device_id }))
                })
                .map_err(|e| AppError::Internal(e.to_string()))
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;

    // Phase 2 — Write (fire-and-forget): touch session + device timestamps
    if let Some(ref auth) = identity {
        let db_write = state.db.clone();
        let sid = auth.sync_id.clone();
        let did = auth.device_id.clone();
        tokio::spawn(async move {
            let _ = tokio::task::spawn_blocking(move || {
                db_write.with_conn(|conn| {
                    db::touch_session(conn, &sid, &did, session_expiry)?;
                    db::touch_device(conn, &sid, &did)
                })
            })
            .await;
        });
    }

    match identity {
        Some(identity) => {
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
        None => {
            tracing::warn!(
                method = %req.method(),
                path = %req.uri().path(),
                "Auth REJECTED: invalid session or inactive device"
            );
            state.metrics.inc(&state.metrics.auth_failures);
            Err(AppError::Unauthorized)
        }
    }
}
