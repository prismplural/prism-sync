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
fn authorize_metrics(
    state: &AppState,
    headers: &HeaderMap,
    peer_addr: SocketAddr,
) -> Result<(), AppError> {
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
    let snapshots_rejected_targeted_cap = m.snapshots_rejected_targeted_cap.load(Ordering::Relaxed);
    let snapshots_missing_blob = m.snapshots_missing_blob.load(Ordering::Relaxed);
    let log_token_rotations = m.log_token_rotations.load(Ordering::Relaxed);
    let lineage_companion_unreadable = m.lineage_companion_unreadable.load(Ordering::Relaxed);
    let pairing_lease_renewed = m.pairing_lease_renewed.load(Ordering::Relaxed);
    let pairing_lease_renew_not_found = m.pairing_lease_renew_not_found.load(Ordering::Relaxed);
    let pairing_lease_renew_client_limited =
        m.pairing_lease_renew_client_limited.load(Ordering::Relaxed);
    let pairing_lease_renew_rejected_rate_limited =
        m.pairing_lease_renew_rejected_rate_limited.load(Ordering::Relaxed);
    let leased_pairing_sessions = m.cached_leased_pairing_sessions.load(Ordering::Relaxed);
    let upload_sessions_active = m.cached_snapshot_upload_sessions_active.load(Ordering::Relaxed);
    let upload_reserved_bytes = m.cached_snapshot_upload_reserved_bytes.load(Ordering::Relaxed);
    let upload_chunks_accepted = m.snapshot_upload_chunks_accepted.load(Ordering::Relaxed);
    let upload_chunks_rejected = m.snapshot_upload_chunks_rejected.load(Ordering::Relaxed);
    let upload_chunk_bytes = m.snapshot_upload_chunk_bytes.load(Ordering::Relaxed);
    let upload_completions = m.snapshot_upload_completions.load(Ordering::Relaxed);
    let upload_quota_rejections = m.snapshot_upload_quota_rejections.load(Ordering::Relaxed);
    let upload_hash_mismatch = m.snapshot_upload_hash_mismatch.load(Ordering::Relaxed);
    let upload_staging_corrupt = m.snapshot_upload_staging_corrupt.load(Ordering::Relaxed);
    let upload_expired = m.snapshot_upload_expired.load(Ordering::Relaxed);
    let upload_aborted = m.snapshot_upload_aborted.load(Ordering::Relaxed);
    let upload_superseded = m.snapshot_upload_superseded.load(Ordering::Relaxed);

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
         prism_media_reconciliation_missing_files {reconciliation_missing}\n\
         # HELP prism_snapshots_rejected_targeted_cap_total Targeted PUT /snapshot rejected with 409 too_many_targeted_snapshots\n\
         # TYPE prism_snapshots_rejected_targeted_cap_total counter\n\
         prism_snapshots_rejected_targeted_cap_total {snapshots_rejected_targeted_cap}\n\
         # HELP prism_snapshots_missing_blob_total Published file-backed snapshot rows whose on-disk blob was missing or unreadable; served as snapshot-absent\n\
         # TYPE prism_snapshots_missing_blob_total counter\n\
         prism_snapshots_missing_blob_total {snapshots_missing_blob}\n\
         # HELP prism_log_token_rotations_total Startup lineage checks that detected a regressed batch sequence and rotated log_token\n\
         # TYPE prism_log_token_rotations_total counter\n\
         prism_log_token_rotations_total {log_token_rotations}\n\
         # HELP prism_lineage_companion_unreadable_total Startup lineage checks that could not read the companion file, forfeiting restore detection for that boot\n\
         # TYPE prism_lineage_companion_unreadable_total counter\n\
         prism_lineage_companion_unreadable_total {lineage_companion_unreadable}\n\
         # HELP prism_pairing_lease_renewed_total Pairing lease renewals that extended a lease\n\
         # TYPE prism_pairing_lease_renewed_total counter\n\
         prism_pairing_lease_renewed_total {pairing_lease_renewed}\n\
         # HELP prism_pairing_lease_renew_not_found_total Pairing lease renewals that did not extend a lease (unknown/expired/unsupported/pre-confirmation/consumed/saturated/wrong secret); mirrors the uniform not-found response\n\
         # TYPE prism_pairing_lease_renew_not_found_total counter\n\
         prism_pairing_lease_renew_not_found_total {pairing_lease_renew_not_found}\n\
         # HELP prism_pairing_lease_renew_client_limited_total Pairing lease renewals dropped by the trusted-proxy-derived client-IP limiter\n\
         # TYPE prism_pairing_lease_renew_client_limited_total counter\n\
         prism_pairing_lease_renew_client_limited_total {pairing_lease_renew_client_limited}\n\
         # HELP prism_pairing_lease_renew_rejected_rate_limited_total Pairing lease renewal failures that exhausted the per-rendezvous failure bucket\n\
         # TYPE prism_pairing_lease_renew_rejected_rate_limited_total counter\n\
         prism_pairing_lease_renew_rejected_rate_limited_total {pairing_lease_renew_rejected_rate_limited}\n\
         # HELP prism_leased_pairing_sessions Pairing rows currently holding a live lease (absolute deadline set and in the future), refreshed each cleanup cycle\n\
         # TYPE prism_leased_pairing_sessions gauge\n\
         prism_leased_pairing_sessions {leased_pairing_sessions}\n\
         # HELP prism_snapshot_upload_sessions_active Nonterminal resumable-upload sessions (gauge, refreshed each cleanup cycle)\n\
         # TYPE prism_snapshot_upload_sessions_active gauge\n\
         prism_snapshot_upload_sessions_active {upload_sessions_active}\n\
         # HELP prism_snapshot_upload_reserved_bytes Bytes reserved by nonterminal resumable-upload sessions (gauge, refreshed each cleanup cycle)\n\
         # TYPE prism_snapshot_upload_reserved_bytes gauge\n\
         prism_snapshot_upload_reserved_bytes {upload_reserved_bytes}\n\
         # HELP prism_snapshot_upload_chunks_total Resumable upload chunk requests by outcome\n\
         # TYPE prism_snapshot_upload_chunks_total counter\n\
         prism_snapshot_upload_chunks_total{{result=\"accepted\"}} {upload_chunks_accepted}\n\
         prism_snapshot_upload_chunks_total{{result=\"rejected\"}} {upload_chunks_rejected}\n\
         # HELP prism_snapshot_upload_chunk_bytes_total Bytes durably committed by accepted resumable upload chunks\n\
         # TYPE prism_snapshot_upload_chunk_bytes_total counter\n\
         prism_snapshot_upload_chunk_bytes_total {upload_chunk_bytes}\n\
         # HELP prism_snapshot_upload_completions_total Resumable upload completions that published a snapshot\n\
         # TYPE prism_snapshot_upload_completions_total counter\n\
         prism_snapshot_upload_completions_total {upload_completions}\n\
         # HELP prism_snapshot_upload_quota_rejections_total Resumable upload admission/write rejections from a quota or free-space bound\n\
         # TYPE prism_snapshot_upload_quota_rejections_total counter\n\
         prism_snapshot_upload_quota_rejections_total {upload_quota_rejections}\n\
         # HELP prism_snapshot_upload_hash_mismatch_total Completions rejected because staged bytes did not match the create-time SHA-256\n\
         # TYPE prism_snapshot_upload_hash_mismatch_total counter\n\
         prism_snapshot_upload_hash_mismatch_total {upload_hash_mismatch}\n\
         # HELP prism_snapshot_upload_staging_corrupt_total Sessions failed for staging corruption (missing or short candidate)\n\
         # TYPE prism_snapshot_upload_staging_corrupt_total counter\n\
         prism_snapshot_upload_staging_corrupt_total {upload_staging_corrupt}\n\
         # HELP prism_snapshot_upload_expired_total Resumable upload sessions expired by idle or absolute TTL\n\
         # TYPE prism_snapshot_upload_expired_total counter\n\
         prism_snapshot_upload_expired_total {upload_expired}\n\
         # HELP prism_snapshot_upload_aborted_total Resumable upload sessions ended by an explicit abort\n\
         # TYPE prism_snapshot_upload_aborted_total counter\n\
         prism_snapshot_upload_aborted_total {upload_aborted}\n\
         # HELP prism_snapshot_upload_superseded_total Resumable upload sessions superseded by a newer create from the same uploader\n\
         # TYPE prism_snapshot_upload_superseded_total counter\n\
         prism_snapshot_upload_superseded_total {upload_superseded}\n",
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
        h.insert("Authorization", HeaderValue::from_str(&format!("Bearer {token}")).unwrap());
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
