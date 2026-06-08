pub mod device_messages;
pub mod devices;
pub mod gifs;
pub mod media;
pub mod metrics;
pub mod pairing;
pub mod register;
pub mod registry;
pub mod sharing;
pub mod sync;
pub mod ws;

use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, State},
    http::{HeaderMap, Method, Request},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Router,
};
use base64::Engine;
use std::net::{IpAddr, SocketAddr};
use tower::limit::GlobalConcurrencyLimitLayer;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{MakeRequestUuid, SetRequestIdLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::Level;

use crate::{
    auth, config::Config, db, errors::AppError, snapshot_limits::MAX_SNAPSHOT_WIRE_BYTES,
    state::AppState,
};

/// Authenticated identity injected into request extensions by auth middleware.
#[derive(Debug, Clone)]
pub struct AuthIdentity {
    pub sync_id: String,
    pub device_id: String,
    pub signing_public_key: Vec<u8>,
    pub ml_dsa_65_public_key: Vec<u8>,
    /// Previous ML-DSA key accepted during a 30-day grace period after rotation.
    /// `None` if no grace key exists or the grace period has expired.
    pub prev_ml_dsa_65_public_key: Option<Vec<u8>>,
}

pub(crate) fn verify_signed_request(
    state: &AppState,
    auth_identity: &AuthIdentity,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<(), AppError> {
    let timestamp = headers
        .get("X-Prism-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::BadRequest("Missing X-Prism-Timestamp"))?;
    let nonce = headers
        .get("X-Prism-Nonce")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::BadRequest("Missing X-Prism-Nonce"))?;
    let signature_b64 = headers
        .get("X-Prism-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::BadRequest("Missing X-Prism-Signature"))?;

    if !auth::is_valid_device_id(&auth_identity.device_id) {
        log_signed_request_rejection(auth_identity, method, path, "invalid_device_id");
        return Err(AppError::Unauthorized);
    }

    let timestamp_i64 =
        timestamp.parse::<i64>().map_err(|_| AppError::BadRequest("Invalid X-Prism-Timestamp"))?;
    let now = db::now_secs();
    let timestamp_drift_secs = (now - timestamp_i64).abs();
    if timestamp_drift_secs > state.config.signed_request_max_skew_secs {
        tracing::warn!(
            sync_id = %trunc_id(&auth_identity.sync_id),
            device_id = %trunc_id(&auth_identity.device_id),
            method,
            route = %redacted_signed_route(path, &auth_identity.sync_id),
            reason = "timestamp_skew",
            drift_secs = timestamp_drift_secs,
            max_skew_secs = state.config.signed_request_max_skew_secs,
            "Signed request rejected"
        );
        return Err(AppError::Unauthorized);
    }

    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|_| AppError::BadRequest("Invalid X-Prism-Signature"))?;

    // Reject devices without PQ keys (should not exist after V1 removal)
    if auth_identity.ml_dsa_65_public_key.is_empty() {
        log_signed_request_rejection(auth_identity, method, path, "missing_pq_public_key");
        return Err(AppError::Unauthorized);
    }

    let Some(&signature_version) = signature.first() else {
        log_signed_request_rejection(auth_identity, method, path, "empty_signature");
        return Err(AppError::Unauthorized);
    };

    // Enforce minimum signature version for downgrade resistance before
    // rejecting unknown older formats generically.
    if signature_version < state.config.min_signature_version {
        return Err(AppError::UpgradeRequired {
            min_signature_version: state.config.min_signature_version,
        });
    }

    let signing_data = auth::build_request_signing_data_v2(
        method,
        path,
        &auth_identity.sync_id,
        &auth_identity.device_id,
        body,
        timestamp,
        nonce,
    );
    let verified = auth::verify_hybrid_request_signature(
        &auth_identity.signing_public_key,
        &auth_identity.ml_dsa_65_public_key,
        &signing_data,
        &signature,
    ) || auth_identity.prev_ml_dsa_65_public_key.as_ref().is_some_and(|prev_pk| {
        auth::verify_hybrid_request_signature(
            &auth_identity.signing_public_key,
            prev_pk,
            &signing_data,
            &signature,
        )
    });

    if !verified {
        log_signed_request_rejection(auth_identity, method, path, "signature_mismatch");
        return Err(AppError::DeviceIdentityMismatch);
    }

    let nonce_window = i64::try_from(state.config.signed_request_nonce_window_secs)
        .map_err(|_| AppError::Internal("signed request nonce window is too large".into()))?;
    let expires_at = now
        .checked_add(nonce_window)
        .ok_or_else(|| AppError::Internal("signed request nonce expiry overflow".into()))?;
    let nonce_accepted = state
        .db
        .with_conn(|conn| {
            db::record_signed_request_nonce(conn, &auth_identity.device_id, nonce, expires_at, now)
        })
        .map_err(AppError::from)?;
    if !nonce_accepted {
        log_signed_request_rejection(auth_identity, method, path, "nonce_replay");
        return Err(AppError::Unauthorized);
    }

    Ok(())
}

fn log_signed_request_rejection(
    auth_identity: &AuthIdentity,
    method: &str,
    path: &str,
    reason: &'static str,
) {
    tracing::warn!(
        sync_id = %trunc_id(&auth_identity.sync_id),
        device_id = %trunc_id(&auth_identity.device_id),
        method,
        route = %redacted_signed_route(path, &auth_identity.sync_id),
        reason,
        "Signed request rejected"
    );
}

fn redacted_signed_route(path: &str, sync_id: &str) -> String {
    let sync_prefix = format!("/v1/sync/{sync_id}");
    if let Some(suffix) = path.strip_prefix(&sync_prefix) {
        return format!("/v1/sync/<sync_id>{suffix}");
    }
    path.to_string()
}

fn trunc_id(value: &str) -> &str {
    let end = value.len().min(16);
    &value[..end]
}

pub(crate) fn client_ip_for_rate_limit(
    headers: &HeaderMap,
    peer_addr: SocketAddr,
    config: &Config,
) -> String {
    #[cfg(feature = "test-helpers")]
    {
        if let Some(value) = headers.get("x-test-client-ip").and_then(|v| v.to_str().ok()) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }

    if is_trusted_proxy(peer_addr.ip(), &config.trusted_proxy_cidrs) {
        if let Some(ip) = forwarded_client_ip(headers) {
            return ip.to_string();
        }
    }

    peer_addr.ip().to_string()
}

fn forwarded_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    header_ip(headers, "cf-connecting-ip")
        .or_else(|| header_ip(headers, "x-forwarded-for"))
        .or_else(|| forwarded_header_ip(headers))
}

fn header_ip(headers: &HeaderMap, header_name: &'static str) -> Option<IpAddr> {
    headers
        .get(header_name)
        .and_then(|v| v.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(parse_ip_candidate)
}

fn forwarded_header_ip(headers: &HeaderMap) -> Option<IpAddr> {
    let value = headers.get("forwarded").and_then(|v| v.to_str().ok())?;
    for element in value.split(',') {
        for part in element.split(';') {
            let Some((name, raw_value)) = part.trim().split_once('=') else {
                continue;
            };
            if name.trim().eq_ignore_ascii_case("for") {
                return parse_ip_candidate(raw_value);
            }
        }
    }
    None
}

fn parse_ip_candidate(raw: &str) -> Option<IpAddr> {
    let candidate = raw.trim().trim_matches('"').trim();
    if candidate.is_empty() || candidate.eq_ignore_ascii_case("unknown") {
        return None;
    }

    if let Ok(ip) = candidate.parse::<IpAddr>() {
        return Some(ip);
    }

    if let Some(rest) = candidate.strip_prefix('[') {
        let end = rest.find(']')?;
        return rest[..end].parse::<IpAddr>().ok();
    }

    if let Some((host, _port)) = candidate.rsplit_once(':') {
        if host.contains('.') {
            return host.parse::<IpAddr>().ok();
        }
    }

    None
}

fn is_trusted_proxy(peer_ip: IpAddr, trusted_proxy_cidrs: &[String]) -> bool {
    trusted_proxy_cidrs.iter().any(|cidr| ip_in_cidr(peer_ip, cidr))
}

fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let cidr = cidr.trim();
    if cidr.is_empty() {
        return false;
    }

    let Some((network, prefix)) = parse_cidr(cidr) else {
        return false;
    };

    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(network)) if prefix <= 32 => {
            let mask = ipv4_prefix_mask(prefix);
            (u32::from(ip) & mask) == (u32::from(network) & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(network)) if prefix <= 128 => {
            let mask = ipv6_prefix_mask(prefix);
            (u128::from(ip) & mask) == (u128::from(network) & mask)
        }
        _ => false,
    }
}

fn parse_cidr(cidr: &str) -> Option<(IpAddr, u8)> {
    let (network, prefix) = match cidr.split_once('/') {
        Some((network, prefix)) => {
            let prefix = prefix.parse::<u8>().ok()?;
            (network, prefix)
        }
        None => {
            let ip = cidr.parse::<IpAddr>().ok()?;
            let prefix = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            return Some((ip, prefix));
        }
    };
    Some((network.parse::<IpAddr>().ok()?, prefix))
}

fn ipv4_prefix_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

fn ipv6_prefix_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    }
}

/// Build the full application router.
pub fn router(state: AppState) -> Router {
    // Snapshot PUT — heavy upload, large body, slow-network tolerant.
    //
    // Layer order (innermost to outermost): handler → auth → body limits →
    // concurrency → timeout. The timeout therefore wraps the entire request
    // including auth and body buffering, matching the previous global
    // timeout's semantics — just with a far higher ceiling because real
    // pair-time snapshots can be 30-150 MB and need minutes on slow mobile
    // links.
    //
    // Known limitation: `TimeoutLayer` cancels by dropping the request
    // future, but `tokio::task::spawn_blocking` inside `put_snapshot`
    // continues to completion. A timed-out blocking write can still commit
    // after the client gives up. The current `upsert_snapshot` SQL uses
    // `ON CONFLICT(sync_id) DO UPDATE`, so a late commit can overwrite a
    // newer snapshot — a pre-existing race not introduced (or fixed) by
    // this scoping. Track separately if it matters in practice.
    //
    // Also note: concurrency-permit acquisition happens in `poll_ready`,
    // which is NOT timed by `TimeoutLayer` (it only times `call`). A
    // saturated route queues, it doesn't fast-fail with 408.
    let snapshot_put_route = Router::new()
        .route("/v1/sync/{sync_id}/snapshot", put(sync::put_snapshot))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .layer(DefaultBodyLimit::max(MAX_SNAPSHOT_WIRE_BYTES))
        .layer(RequestBodyLimitLayer::new(MAX_SNAPSHOT_WIRE_BYTES))
        .layer(GlobalConcurrencyLimitLayer::new(state.config.snapshot_upload_concurrency))
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            std::time::Duration::from_secs(state.config.snapshot_request_timeout_secs),
        ));

    // Media routes — moderate-size upload + streaming download.
    //
    // The timeout only covers request handling through the moment response
    // headers are produced. Streaming response bodies (e.g. `Body::from_stream`
    // returned by `download_media`) continue past this deadline; use a
    // `ResponseBodyTimeoutLayer` if you need to bound total transfer time.
    let media_routes = Router::new()
        .route("/v1/sync/{sync_id}/media", post(media::upload_media))
        .route("/v1/sync/{sync_id}/media/{media_id}", get(media::download_media))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .layer(DefaultBodyLimit::max(state.config.media_max_file_bytes))
        .layer(RequestBodyLimitLayer::new(state.config.media_max_file_bytes))
        .layer(GlobalConcurrencyLimitLayer::new(state.config.media_upload_concurrency))
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            std::time::Duration::from_secs(state.config.media_request_timeout_secs),
        ));

    // Routes that require authentication (small-body — capped at 10 MiB by
    // the global body limit applied below).
    let authenticated_routes = Router::new()
        // Sync routes (push/pull)
        .route("/v1/sync/{sync_id}/changes", put(sync::push_changes).get(sync::pull_changes))
        .route("/v1/sync/{sync_id}", delete(sync::delete_account))
        // Snapshot GET + DELETE: bodyless, so they sit under the normal
        // 10 MiB cap alongside the other authenticated routes.
        .route("/v1/sync/{sync_id}/snapshot", get(sync::get_snapshot).delete(sync::delete_snapshot))
        // Device routes (list/revoke/rekey/ack)
        .route("/v1/sync/{sync_id}/devices", get(devices::list_devices))
        .route("/v1/sync/{sync_id}/devices/{device_id}", delete(devices::delete_device))
        .route("/v1/sync/{sync_id}/devices/{device_id}/revoke", post(devices::post_atomic_revoke))
        .route(
            "/v1/sync/{sync_id}/devices/{device_id}/rotate-ml-dsa",
            post(devices::post_rotate_ml_dsa),
        )
        .route("/v1/sync/{sync_id}/rekey", post(devices::post_rekey))
        .route("/v1/sync/{sync_id}/rekey/{device_id}", get(devices::get_rekey_artifact))
        .route("/v1/sync/{sync_id}/ack", post(devices::post_ack))
        .route("/v1/sync/{sync_id}/capabilities", get(gifs::get_capabilities))
        // Media batch-exists (C2): small JSON read. A tight per-route body cap
        // (≤1024 ids × ≤36 chars ≈ 41 KiB; 64 KiB is ample) overrides the shared
        // 10 MiB authenticated cap, so an authed caller can't force large JSON
        // buffering/parsing here before the id-count check runs.
        .route(
            "/v1/sync/{sync_id}/media/exists",
            post(media::media_exists).layer(DefaultBodyLimit::max(64 * 1024)),
        )
        // Ephemeral signal lane / device-message mailbox (C3). Small bodies:
        // send carries one ≤4 KiB padded payload (base64'd) + envelope, ack a
        // bounded id list. Tight per-route caps override the shared 10 MiB
        // authenticated cap so an authed caller can't force large-body buffering
        // before the field checks run. GET pending is bodyless.
        .route(
            "/v1/sync/{sync_id}/device-messages",
            post(device_messages::send_device_message).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route(
            "/v1/sync/{sync_id}/device-messages/pending",
            get(device_messages::pending_device_messages),
        )
        .route(
            "/v1/sync/{sync_id}/device-messages/ack",
            post(device_messages::ack_device_messages).layer(DefaultBodyLimit::max(64 * 1024)),
        )
        .route("/v1/sync/{sync_id}/ws", get(ws::ws_upgrade))
        // Registry routes (auth + signed)
        .merge(registry::routes())
        // Sharing routes (auth + signed)
        .route("/v1/sharing/identity", put(sharing::put_identity).delete(sharing::delete_identity))
        .route("/v1/sharing/prekey", put(sharing::put_prekey))
        .route("/v1/sharing/init", post(sharing::post_init))
        .route("/v1/sharing/init/pending", get(sharing::get_pending_inits))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        // 10 MiB default body limit for these routes. Snapshot and media
        // routes are merged in below already wearing their own larger
        // limits, so they bypass this cap.
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
        .layer(RequestBodyLimitLayer::new(10 * 1024 * 1024));

    // Routes that do NOT require authentication.
    let public_routes = Router::new()
        .merge(register::routes())
        .merge(pairing::routes())
        .route("/v1/gifs/trending", get(gifs::get_trending))
        .route("/v1/gifs/search", get(gifs::search_gifs))
        // Public sharing route (no auth, rate-limited by IP)
        .route("/v1/sharing/{sharing_id}/bundle", get(sharing::get_bundle))
        // Public surfaces have no large-body requirement. Keep the
        // historical 10 MiB cap as a defensive ceiling.
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
        .layer(RequestBodyLimitLayer::new(10 * 1024 * 1024));

    // Default-timeout routes: everything that's not snapshot PUT or media.
    // Returns 408 on expiry. WebSocket upgrades complete inside this window;
    // the long-lived WS connection runs after upgrade and is unaffected.
    //
    // The default concurrency cap replaces the historical outer
    // `ConcurrencyLimitLayer(512)` and prevents connection exhaustion on
    // light routes. Heavy upload routes have their own (much smaller) caps
    // sized for memory headroom.
    let default_request_timeout_secs = state.config.default_request_timeout_secs;
    let default_request_concurrency = state.config.default_request_concurrency;
    let default_timeout_routes = Router::new()
        .merge(public_routes)
        .merge(authenticated_routes)
        .merge(metrics::routes())
        .route(
            "/health",
            axum::routing::get(|| async { axum::Json(serde_json::json!({"status": "ok"})) }),
        )
        .layer(GlobalConcurrencyLimitLayer::new(default_request_concurrency))
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            std::time::Duration::from_secs(default_request_timeout_secs),
        ));

    // Relay is accessed only by native clients — no browser origin is expected.
    // Default CorsLayer rejects all cross-origin requests.
    let cors = CorsLayer::new();

    // Outer router carries only cross-cutting layers (CORS, request id,
    // tracing). Timeouts and concurrency caps live on each sub-router so
    // heavy upload routes can have their own ceilings without affecting
    // light routes.
    Router::new()
        .merge(default_timeout_routes)
        .merge(snapshot_put_route)
        .merge(media_routes)
        .layer(cors)
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<axum::body::Body>| {
                    let request_id = request
                        .headers()
                        .get("x-request-id")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("-");
                    let path = request.uri().path();
                    tracing::debug_span!(
                        "http",
                        method = %request.method(),
                        path,
                        request_id,
                    )
                })
                .on_response(DefaultOnResponse::new().level(Level::DEBUG)),
        )
        .with_state(state)
}

/// Result of auth validation — distinguishes "no session" from "device revoked".
enum AuthResult {
    Ok(AuthIdentity),
    /// Valid session but device is revoked; includes remote_wipe flag and the
    /// revoked device's identity so the middleware can inject it on the narrow
    /// read-only allowlist (a revoked device may still `GET /registry` to verify
    /// its OWN revocation — see `auth_middleware`).
    DeviceRevoked {
        remote_wipe: bool,
        identity: AuthIdentity,
    },
    /// Session not found, expired, or device missing.
    Invalid,
}

/// Is this request the one read-only call a REVOKED device is still allowed to
/// make: `GET /v1/sync/{sync_id}/registry`?
///
/// SECURITY: the signed registry is the group's device PUBLIC keys + per-device
/// status + epoch_key_hashes (commitments, NOT keys) + registry version/epoch —
/// no secrets, read-only, and rate-limited like any other route. A revoked
/// device already held all of this before revocation. Allowing exactly this one
/// call lets `confirm_self_revocation` fetch the signed registry and
/// signature-verify its OWN revocation (incl. the admin-signed `remote_wipe`
/// intent, H3 Layer B) instead of trusting an unauthenticated relay frame.
///
/// The match is deliberately TIGHT: method == GET AND the path is exactly
/// `/v1/sync/<id>/registry` (three fixed segments around a single id segment,
/// no trailing extra). It must NOT match writes (PUT /registry) or any other
/// authenticated route.
fn is_revoked_device_registry_read(method: &Method, path: &str) -> bool {
    if method != Method::GET {
        return false;
    }
    // Expect exactly: ["v1", "sync", "<id>", "registry"] — no more, no fewer,
    // and a non-empty id segment.
    let mut segments = path.split('/').filter(|s| !s.is_empty());
    matches!(
        (segments.next(), segments.next(), segments.next(), segments.next(), segments.next()),
        (Some("v1"), Some("sync"), Some(id), Some("registry"), None) if !id.is_empty()
    )
}

/// Auth middleware: extracts Bearer token, validates session, injects AuthIdentity.
///
/// When a revoked device authenticates, the 401 response includes a structured
/// JSON body so the client can act on it without needing a separate
/// unauthenticated endpoint.
async fn auth_middleware(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, Response> {
    if req.method() == Method::GET
        && req.uri().path().starts_with("/v1/sync/")
        && req.uri().path().ends_with("/ws")
    {
        let client_ip = client_ip_for_rate_limit(req.headers(), peer_addr, &state.config);
        let rate_key = format!("ws_upgrade:{client_ip}");
        if !state.ws_upgrade_rate_limiter.check(
            &rate_key,
            state.config.ws_upgrade_rate_limit,
            state.config.ws_upgrade_rate_window_secs,
        ) {
            return Err(AppError::TooManyRequests.into_response());
        }
    }

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
    let session_max_age = state.config.session_max_age_secs as i64;

    // Phase 1 — Read (blocking, must complete): validate session + device status
    let db_read = state.db.clone();
    let auth_result = tokio::task::spawn_blocking(move || -> Result<AuthResult, AppError> {
        db_read
            .with_read_conn(|conn| {
                if let Some((sync_id, device_id)) =
                    db::validate_session(conn, &token_owned, session_max_age)?
                {
                    let Some(device) = db::get_device(conn, &sync_id, &device_id)? else {
                        return Ok(AuthResult::Invalid);
                    };
                    if device.status != "active" {
                        let wipe = db::get_device_wipe_status(conn, &sync_id, &device_id)?
                            .unwrap_or(false);
                        return Ok(AuthResult::DeviceRevoked {
                            remote_wipe: wipe,
                            identity: AuthIdentity {
                                sync_id,
                                device_id,
                                signing_public_key: device.signing_public_key,
                                ml_dsa_65_public_key: device.ml_dsa_65_public_key,
                                prev_ml_dsa_65_public_key: None,
                            },
                        });
                    }
                    let prev_ml_dsa_65_public_key = if !device.prev_ml_dsa_65_public_key.is_empty()
                        && device.prev_ml_dsa_65_expires_at.is_some_and(|exp| exp > db::now_secs())
                    {
                        Some(device.prev_ml_dsa_65_public_key)
                    } else {
                        None
                    };
                    return Ok(AuthResult::Ok(AuthIdentity {
                        sync_id,
                        device_id,
                        signing_public_key: device.signing_public_key,
                        ml_dsa_65_public_key: device.ml_dsa_65_public_key,
                        prev_ml_dsa_65_public_key,
                    }));
                }

                if let Some((sync_id, device_id)) =
                    db::validate_revoked_session(conn, &token_owned)?
                {
                    let wipe =
                        db::get_device_wipe_status(conn, &sync_id, &device_id)?.unwrap_or(false);
                    // Build the identity from the (revoked) device record so the
                    // narrow registry-read allowlist can inject it. The registry
                    // GET handler only reads `sync_id`, but we populate the keys
                    // faithfully. If the record is gone, fall back to empty keys
                    // — the read is on group-wide PUBLIC data and the handler
                    // re-checks `path_sync_id == auth.sync_id`.
                    let device = db::get_device(conn, &sync_id, &device_id)?;
                    let identity = AuthIdentity {
                        sync_id: sync_id.clone(),
                        device_id: device_id.clone(),
                        signing_public_key: device
                            .as_ref()
                            .map(|d| d.signing_public_key.clone())
                            .unwrap_or_default(),
                        ml_dsa_65_public_key: device
                            .as_ref()
                            .map(|d| d.ml_dsa_65_public_key.clone())
                            .unwrap_or_default(),
                        prev_ml_dsa_65_public_key: None,
                    };
                    return Ok(AuthResult::DeviceRevoked { remote_wipe: wipe, identity });
                }

                Ok(AuthResult::Invalid)
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
                        db::touch_session(conn, &sid, &did, session_expiry, session_max_age)?;
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
        AuthResult::DeviceRevoked { remote_wipe, identity } => {
            // Narrow read-only allowlist: a revoked device may still issue the
            // single call `GET /v1/sync/{sync_id}/registry` so it can fetch the
            // signed registry and verify its OWN revocation (H3). Every other
            // route/method is rejected exactly as before. The allowed read is on
            // group-wide PUBLIC data (no secrets) and is rate-limited like any
            // other route. See `is_revoked_device_registry_read`.
            if is_revoked_device_registry_read(req.method(), req.uri().path()) {
                tracing::debug!(
                    sync_id = %trunc_id(&identity.sync_id),
                    device_id = %trunc_id(&identity.device_id),
                    method = %req.method(),
                    path = %req.uri().path(),
                    remote_wipe,
                    "Auth OK (revoked device: read-only registry self-revocation check allowed)"
                );
                req.extensions_mut().insert(identity);
                return Ok(next.run(req).await);
            }
            tracing::warn!(
                method = %req.method(),
                path = %req.uri().path(),
                remote_wipe,
                "Auth REJECTED: device revoked"
            );
            state.metrics.inc(&state.metrics.auth_failures);
            Err(AppError::DeviceRevoked { remote_wipe }.into_response())
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

#[cfg(test)]
mod allowlist_tests {
    use super::is_revoked_device_registry_read;
    use axum::http::Method;

    #[test]
    fn allows_only_get_registry_exact_path() {
        // The single allowed read.
        assert!(is_revoked_device_registry_read(
            &Method::GET,
            "/v1/sync/abc123/registry"
        ));
        // Tolerate a trailing slash (router-normalized variant).
        assert!(is_revoked_device_registry_read(
            &Method::GET,
            "/v1/sync/abc123/registry/"
        ));
    }

    #[test]
    fn rejects_non_get_methods_on_registry() {
        for m in [Method::PUT, Method::POST, Method::DELETE, Method::PATCH, Method::HEAD] {
            assert!(
                !is_revoked_device_registry_read(&m, "/v1/sync/abc123/registry"),
                "method {m} on /registry must NOT be allowlisted"
            );
        }
    }

    #[test]
    fn rejects_other_paths_and_subpaths() {
        for path in [
            "/v1/sync/abc123/changes",
            "/v1/sync/abc123/devices",
            "/v1/sync/abc123/ack",
            "/v1/sync/abc123/snapshot",
            // No id segment.
            "/v1/sync/registry",
            // Extra trailing segment after registry.
            "/v1/sync/abc123/registry/extra",
            // registry as the id, wrong shape.
            "/v1/sync/registry/registry/more",
            // Loose substring that must NOT match.
            "/v1/sync/abc123/registry-export",
            "/v1/sync/abc123/devices/registry",
            // Empty id.
            "/v1/sync//registry",
        ] {
            assert!(
                !is_revoked_device_registry_read(&Method::GET, path),
                "path {path} must NOT be allowlisted"
            );
        }
    }
}
