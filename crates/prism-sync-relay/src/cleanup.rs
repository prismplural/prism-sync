use crate::state::AppState;
use std::sync::Arc;
use tokio::time::{interval, Duration};

/// Spawn the background cleanup task. Runs once immediately on startup,
/// then repeats on the configured interval.
pub fn spawn_cleanup_task(state: Arc<AppState>) {
    let interval_secs = state.config.cleanup_interval_secs;
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(interval_secs));
        ticker.tick().await; // first tick fires immediately
        loop {
            ticker.tick().await;
            run_cleanup(&state).await;
        }
    });
}

async fn run_cleanup(state: &AppState) {
    let db = state.db.clone();
    let config = state.config.clone();

    let result = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            // 1. Expire registration nonces (> nonce_expiry_secs old)
            let nonces = crate::db::cleanup_expired_nonces(conn)?;

            // 2. Mark stale devices (> stale_device_secs no activity).
            //    Stale devices are excluded from min_acked_seq so they don't
            //    block batch pruning for the rest of the sync group.
            let stale = crate::db::mark_stale_devices(conn, config.stale_device_secs as i64)?;

            // 3. Auto-revoke abandoned devices (> sync_inactive_ttl_secs).
            //    Returns sync_ids that had devices revoked and now need a rekey.
            let revoked_groups =
                crate::db::auto_revoke_devices(conn, config.sync_inactive_ttl_secs as i64)?;

            // 4. Prune sync groups where no device has been seen within the
            //    sync_inactive_ttl_secs window.
            let pruned =
                crate::db::prune_stale_sync_groups(conn, config.sync_inactive_ttl_secs as i64)?;

            // 5. Delete expired ephemeral snapshots
            let expired_snapshots = crate::db::cleanup_expired_snapshots(conn)?;

            // 6. Reclaim freed pages (incremental auto_vacuum)
            let freelist_before: i64 = conn
                .query_row("PRAGMA freelist_count;", [], |r| r.get(0))
                .unwrap_or(0);
            conn.execute_batch("PRAGMA incremental_vacuum;")?;
            let freelist_after: i64 = conn
                .query_row("PRAGMA freelist_count;", [], |r| r.get(0))
                .unwrap_or(0);
            let pages_freed = (freelist_before - freelist_after).max(0) as u64;

            Ok::<_, rusqlite::Error>((nonces, stale, revoked_groups, pruned, expired_snapshots, pages_freed))
        })
    })
    .await;

    match result {
        Ok(Ok((nonces, stale, revoked_groups, pruned, expired_snapshots, pages_freed))) => {
            if pages_freed > 0 {
                state.metrics.inc_by(&state.metrics.vacuum_pages_freed, pages_freed);
            }
            if nonces > 0
                || stale > 0
                || !revoked_groups.is_empty()
                || pruned > 0
                || expired_snapshots > 0
                || pages_freed > 0
            {
                tracing::info!(
                    nonces,
                    stale,
                    revoked_groups = revoked_groups.len(),
                    pruned,
                    expired_snapshots,
                    pages_freed,
                    "cleanup cycle complete"
                );
            }

            // Notify active devices in each revoked group that a rekey is needed.
            // Active devices are responsible for generating and posting rekey artifacts
            // (the relay is zero-knowledge and cannot generate epoch keys).
            for sync_id in &revoked_groups {
                let msg = serde_json::json!({
                    "type": "rekey_required",
                    "sync_id": sync_id
                })
                .to_string();
                state.notify_devices(sync_id, None, &msg).await;
            }
        }
        Ok(Err(e)) => tracing::error!("cleanup db error: {e}"),
        Err(e) => tracing::error!("cleanup task panic: {e}"),
    }

    // Prune stale entries from the in-memory nonce rate limiter.
    state
        .nonce_rate_limiter
        .prune_stale(state.config.nonce_rate_window_secs);
}
