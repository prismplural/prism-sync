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

            // 3. Prune sync groups where no device has been seen within the
            //    sync_inactive_ttl_secs window.
            let pruned =
                crate::db::prune_stale_sync_groups(conn, config.sync_inactive_ttl_secs as i64)?;

            // 4. Delete expired ephemeral snapshots
            let expired_snapshots = crate::db::cleanup_expired_snapshots(conn)?;

            // 5. Reclaim freed pages (incremental auto_vacuum)
            let freelist_before: i64 = conn
                .query_row("PRAGMA freelist_count;", [], |r| r.get(0))
                .unwrap_or(0);
            conn.execute_batch("PRAGMA incremental_vacuum;")?;
            let freelist_after: i64 = conn
                .query_row("PRAGMA freelist_count;", [], |r| r.get(0))
                .unwrap_or(0);
            let pages_freed = (freelist_before - freelist_after).max(0) as u64;
            Ok::<_, rusqlite::Error>((nonces, stale, pruned, expired_snapshots, pages_freed))
        })
    })
    .await;

    match result {
        Ok(Ok((nonces, stale, pruned, expired_snapshots, pages_freed))) => {
            state.metrics.last_cleanup_epoch_secs.store(
                crate::db::now_secs() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
            if pages_freed > 0 {
                state
                    .metrics
                    .inc_by(&state.metrics.vacuum_pages_freed, pages_freed);
            }
            if nonces > 0 || stale > 0 || pruned > 0 || expired_snapshots > 0 || pages_freed > 0 {
                tracing::info!(
                    nonces,
                    stale,
                    pruned,
                    expired_snapshots,
                    pages_freed,
                    "cleanup cycle complete"
                );
            }
        }
        Ok(Err(e)) => tracing::error!("cleanup db error: {e}"),
        Err(e) => tracing::error!("cleanup task panic: {e}"),
    }

    // Prune stale entries from the in-memory nonce rate limiter.
    state
        .nonce_rate_limiter
        .prune_stale(state.config.nonce_rate_window_secs);
    state
        .revoke_rate_limiter
        .prune_stale(state.config.revoke_rate_window_secs);
    state
        .signed_request_replay_cache
        .prune_stale(state.config.signed_request_nonce_window_secs);

    // Flush counter values to SQLite so they survive restarts.
    let db = state.db.clone();
    let counters = state.metrics.snapshot_counters();
    let flush_result = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| crate::db::flush_counters(conn, &counters))
    })
    .await;
    match flush_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::error!("counter flush db error: {e}"),
        Err(e) => tracing::error!("counter flush task panic: {e}"),
    }
}
