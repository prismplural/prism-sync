use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    response::IntoResponse,
    routing::get,
    Router,
};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use subtle::ConstantTimeEq;

use crate::{errors::AppError, state::AppState};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/metrics", get(prometheus_metrics))
        .route("/metrics/node", get(node_metrics))
}

/// Authorize a metrics request, failing closed when no token is configured.
///
/// * If `METRICS_TOKEN` is set, require a matching `Authorization: Bearer
///   <token>` header (constant-time compare).
/// * If no token is configured, the endpoint is **not** world-readable: it is
///   served only to loopback peers (localhost / same host, e.g. a sidecar
///   Prometheus or `docker exec`). Any non-loopback peer gets 401. This keeps
///   the common internal/firewalled deployment working while closing the
///   default-open hole an empty/unset `METRICS_TOKEN` previously left.
fn authorize_metrics(state: &AppState, headers: &HeaderMap, peer_addr: SocketAddr) -> Result<(), AppError> {
    match state.config.metrics_token.as_deref() {
        Some(expected_token) => {
            let provided = headers
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .unwrap_or("");
            // Hash both sides to fixed 32-byte SHA-256 digests before the
            // constant-time compare, so the token LENGTH is never compared
            // variably. `subtle`'s slice `ct_eq` short-circuits on length
            // mismatch, which would otherwise leak the configured token's
            // length via timing — this mirrors the registration-token path
            // in `routes/register.rs::check_registration_access`.
            let provided_hash = Sha256::digest(provided.as_bytes());
            let expected_hash = Sha256::digest(expected_token.as_bytes());
            if !bool::from(provided_hash.ct_eq(&expected_hash)) {
                return Err(AppError::Unauthorized);
            }
            Ok(())
        }
        None => {
            // Fail closed: no token => loopback only.
            if peer_addr.ip().is_loopback() {
                Ok(())
            } else {
                Err(AppError::Unauthorized)
            }
        }
    }
}

/// Expose Prometheus-format metrics.
///
/// See [`authorize_metrics`] for the access model. When `METRICS_TOKEN` is set
/// a matching bearer token is required; otherwise only loopback peers are
/// served (the endpoint is never world-readable by default).
async fn prometheus_metrics(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    authorize_metrics(&state, &headers, peer_addr)?;

    let m = &state.metrics;
    let connected = state.connected_device_count().await;

    let stored_batches = m.cached_stored_batches.load(Ordering::Relaxed);
    let db_size_bytes = m.cached_db_size_bytes.load(Ordering::Relaxed);
    let freelist_pages = m.cached_freelist_pages.load(Ordering::Relaxed);
    let ws_notifications = m.ws_notifications.load(Ordering::Relaxed);
    let ws_notifications_dropped = m.ws_notifications_dropped.load(Ordering::Relaxed);
    let snapshots_rejected_stale = m.snapshots_rejected_stale.load(Ordering::Relaxed);
    let reconciliation_missing = m.media_reconciliation_missing_files.load(Ordering::Relaxed);

    let output = format!(
        "# HELP prism_connected_devices Current WebSocket connections\n\
         # TYPE prism_connected_devices gauge\n\
         prism_connected_devices {connected}\n\
         # HELP prism_stored_batches Current batch count\n\
         # TYPE prism_stored_batches gauge\n\
         prism_stored_batches {stored_batches}\n\
         # HELP prism_db_size_bytes SQLite database size in bytes\n\
         # TYPE prism_db_size_bytes gauge\n\
         prism_db_size_bytes {db_size_bytes}\n\
         # HELP prism_freelist_pages SQLite freelist pages awaiting vacuum\n\
         # TYPE prism_freelist_pages gauge\n\
         prism_freelist_pages {freelist_pages}\n\
         # HELP prism_last_cleanup_timestamp_seconds Unix timestamp of last successful cleanup cycle\n\
         # TYPE prism_last_cleanup_timestamp_seconds gauge\n\
         prism_last_cleanup_timestamp_seconds {}\n\
         # HELP prism_ws_notifications_total WebSocket notify fan-outs broadcast to sync groups\n\
         # TYPE prism_ws_notifications_total counter\n\
         prism_ws_notifications_total {ws_notifications}\n\
         # HELP prism_ws_notifications_dropped_total WebSocket notifications dropped on a full or closed per-device channel\n\
         # TYPE prism_ws_notifications_dropped_total counter\n\
         prism_ws_notifications_dropped_total {ws_notifications_dropped}\n\
         # HELP prism_snapshots_rejected_stale_total PUT /snapshot rejected with 409 stale_snapshot_seq\n\
         # TYPE prism_snapshots_rejected_stale_total counter\n\
         prism_snapshots_rejected_stale_total {snapshots_rejected_stale}\n\
         # HELP prism_media_reconciliation_missing_files Committed/servable media rows whose on-disk file is missing (count the dry-run reconciliation sweep would delete)\n\
         # TYPE prism_media_reconciliation_missing_files gauge\n\
         prism_media_reconciliation_missing_files {reconciliation_missing}\n",
        m.last_cleanup_epoch_secs.load(Ordering::Relaxed),
    );

    Ok(([("content-type", "text/plain; version=0.0.4; charset=utf-8")], output))
}

/// Reverse-proxy to node-exporter, gated by the same access model as
/// [`prometheus_metrics`] (token if configured, else loopback-only).
/// Returns 404 if NODE_EXPORTER_URL is not configured.
async fn node_metrics(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    authorize_metrics(&state, &headers, peer_addr)?;

    let base_url = state.config.node_exporter_url.as_deref().ok_or(AppError::NotFound)?;

    let url = format!("{base_url}/metrics");
    let body = reqwest::get(&url)
        .await
        .map_err(|e| AppError::Internal(format!("node-exporter fetch failed: {e}")))?
        .text()
        .await
        .map_err(|e| AppError::Internal(format!("node-exporter read failed: {e}")))?;

    Ok(([("content-type", "text/plain; version=0.0.4; charset=utf-8")], body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::localhost_test_config;
    use crate::db::Database;
    use axum::http::HeaderValue;

    fn state_with_token(token: Option<&str>) -> AppState {
        let mut config = localhost_test_config();
        config.metrics_token = token.map(|t| t.to_string());
        let db = Database::in_memory().expect("in-memory db");
        AppState::new(db, config)
    }

    fn loopback() -> SocketAddr {
        "127.0.0.1:54321".parse().unwrap()
    }

    fn external() -> SocketAddr {
        "203.0.113.7:54321".parse().unwrap()
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        h
    }

    #[test]
    fn no_token_allows_loopback() {
        let state = state_with_token(None);
        assert!(authorize_metrics(&state, &HeaderMap::new(), loopback()).is_ok());
    }

    #[test]
    fn no_token_rejects_external_peer_fails_closed() {
        // The key regression: an unset/empty METRICS_TOKEN must NOT leave
        // /metrics world-readable. Off-host peers are refused.
        let state = state_with_token(None);
        assert!(matches!(
            authorize_metrics(&state, &HeaderMap::new(), external()),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn token_required_for_external_peer() {
        let state = state_with_token(Some("s3cr3t"));
        // Correct token from anywhere is accepted.
        assert!(authorize_metrics(&state, &bearer("s3cr3t"), external()).is_ok());
        // Wrong/absent token is rejected even from loopback.
        assert!(matches!(
            authorize_metrics(&state, &bearer("nope"), loopback()),
            Err(AppError::Unauthorized)
        ));
        assert!(matches!(
            authorize_metrics(&state, &HeaderMap::new(), loopback()),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn token_compare_handles_length_mismatch_without_leaking() {
        // The compare hashes both sides to fixed 32-byte SHA-256 digests before
        // the constant-time check, so a token of the WRONG LENGTH is rejected
        // just like any other mismatch — the configured token's length is never
        // compared variably. (Behavioural assertion; the constant-time property
        // lives in the digest-then-`ct_eq` construction.)
        let state = state_with_token(Some("s3cr3t"));
        // Shorter, longer, and empty provided tokens are all rejected.
        assert!(matches!(
            authorize_metrics(&state, &bearer("s3"), external()),
            Err(AppError::Unauthorized)
        ));
        assert!(matches!(
            authorize_metrics(&state, &bearer("s3cr3t-and-then-some-more"), external()),
            Err(AppError::Unauthorized)
        ));
        assert!(matches!(
            authorize_metrics(&state, &bearer(""), external()),
            Err(AppError::Unauthorized)
        ));
        // The exact-length, correct token still passes.
        assert!(authorize_metrics(&state, &bearer("s3cr3t"), external()).is_ok());
    }
}
