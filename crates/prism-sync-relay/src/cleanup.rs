use crate::state::AppState;
use std::sync::Arc;
use tokio::time::{interval, Duration};

/// Spawn the background cleanup task. Runs once immediately on startup,
/// then repeats on the configured interval. Returns the [`JoinHandle`] so
/// the caller can abort it during graceful shutdown.
pub fn spawn_cleanup_task(state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
    let interval_secs = state.config.cleanup_interval_secs;
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(interval_secs));
        ticker.tick().await; // first tick fires immediately
        loop {
            ticker.tick().await;
            run_cleanup(&state).await;
        }
    })
}

async fn run_cleanup(state: &AppState) {
    let db = state.db.clone();
    let config = state.config.clone();

    let result = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            // 1. Expire registration nonces (> nonce_expiry_secs old)
            let nonces = crate::db::cleanup_expired_nonces(conn)?;
            let revoked_sessions = crate::db::cleanup_expired_revoked_sessions(conn)?;

            // 2. Mark stale devices (> stale_device_secs no activity).
            //    Stale devices are excluded from min_acked_seq so they don't
            //    block batch pruning for the rest of the sync group.
            let stale = crate::db::mark_stale_devices(conn, config.stale_device_secs as i64)?;

            // 3. Auto-revoke abandoned devices (> sync_inactive_ttl_secs).
            //    Returns sync_ids that had devices revoked and now need a rekey.
            let revoked_groups =
                crate::db::auto_revoke_devices(conn, config.sync_inactive_ttl_secs as i64)?;

            // 4. Prune sync groups where no device has been seen within the
            //    sync_inactive_ttl_secs window. Collect media_ids for disk cleanup.
            let stale_group_media_ids =
                collect_stale_group_media(conn, config.sync_inactive_ttl_secs as i64)?;
            let pruned =
                crate::db::prune_stale_sync_groups(conn, config.sync_inactive_ttl_secs as i64)?;

            // 5. Remove abandoned brand-new groups that never produced any
            //    batches or snapshots and have been idle long enough.
            let abandoned_new_groups = cleanup_abandoned_brand_new_groups(
                conn,
                config.abandoned_brand_new_group_ttl_secs() as i64,
            )?;

            // 6. Delete expired ephemeral snapshots
            let expired_snapshots = crate::db::cleanup_expired_snapshots(conn)?;

            // 7. Remove superseded registry artifacts now that the current
            //    registry state is persisted separately.
            let superseded_registry_artifacts =
                crate::db::cleanup_superseded_registry_state_artifacts(conn)?;

            // 8. Remove expired pairing sessions.
            let expired_pairing_sessions = crate::db::cleanup_expired_pairing_sessions(conn)?;

            // 9. Garbage-collect revoked tombstones only after no retained
            //    history rows still reference them.
            let revoked_tombstones = crate::db::cleanup_revoked_device_tombstones(
                conn,
                config.revoked_tombstone_retention_secs as i64,
            )?;

            // 10. Delete stale sharing prekeys past the serve-age limit.
            let stale_prekeys = crate::db::cleanup_stale_sharing_prekeys(
                conn,
                config.prekey_serve_max_age_secs,
            )?;

            // 11. Delete expired or long-consumed sharing-init payloads.
            let expired_sharing_inits = crate::db::cleanup_expired_sharing_init_payloads(conn)?;

            // 12. Clear expired ML-DSA grace keys (post-rotation old keys).
            let expired_grace_keys =
                crate::db::cleanup_expired_ml_dsa_grace_keys(conn, crate::db::now_secs())?;

            // 13. Expire old media blobs past retention period.
            let expired_media =
                crate::db::cleanup_expired_media(conn, config.media_retention_days)?;

            // 14. Reclaim freed pages (incremental auto_vacuum)
            let freelist_before: i64 = conn
                .query_row("PRAGMA freelist_count;", [], |r| r.get(0))
                .unwrap_or(0);
            conn.execute_batch("PRAGMA incremental_vacuum;")?;
            let freelist_after: i64 = conn
                .query_row("PRAGMA freelist_count;", [], |r| r.get(0))
                .unwrap_or(0);
            let pages_freed = (freelist_before - freelist_after).max(0) as u64;
            Ok::<_, rusqlite::Error>((
                nonces,
                revoked_sessions,
                stale,
                revoked_groups,
                pruned,
                stale_group_media_ids,
                abandoned_new_groups,
                expired_snapshots,
                superseded_registry_artifacts,
                expired_pairing_sessions,
                revoked_tombstones,
                stale_prekeys,
                expired_sharing_inits,
                expired_grace_keys,
                expired_media,
                pages_freed,
            ))
        })
    })
    .await;

    match result {
        Ok(Ok((
            nonces,
            revoked_sessions,
            stale,
            revoked_groups,
            pruned,
            stale_group_media_ids,
            abandoned_new_groups,
            expired_snapshots,
            superseded_registry_artifacts,
            expired_pairing_sessions,
            revoked_tombstones,
            stale_prekeys,
            expired_sharing_inits,
            expired_grace_keys,
            expired_media,
            pages_freed,
        ))) => {
            // Clean up media files from disk for pruned sync groups
            let stale_media_items: Vec<(String, String)> = stale_group_media_ids
                .into_iter()
                .flat_map(|(sync_id, media_ids)| {
                    media_ids
                        .into_iter()
                        .map(move |mid| (sync_id.clone(), mid))
                })
                .collect();
            let stale_media_cleaned =
                cleanup_media_files(&state.config.media_storage_path, &stale_media_items);

            // Clean up expired media files from disk
            let expired_media_cleaned =
                cleanup_media_files(&state.config.media_storage_path, &expired_media);

            // Try to remove empty sync_id directories left after media cleanup
            cleanup_empty_media_dirs(&state.config.media_storage_path, &stale_media_items);
            cleanup_empty_media_dirs(&state.config.media_storage_path, &expired_media);

            state.metrics.last_cleanup_epoch_secs.store(
                crate::db::now_secs() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
            let expired_media_count = expired_media_cleaned + stale_media_cleaned;
            if nonces > 0
                || revoked_sessions > 0
                || stale > 0
                || !revoked_groups.is_empty()
                || pruned > 0
                || abandoned_new_groups > 0
                || expired_snapshots > 0
                || superseded_registry_artifacts > 0
                || expired_pairing_sessions > 0
                || revoked_tombstones > 0
                || stale_prekeys > 0
                || expired_sharing_inits > 0
                || expired_grace_keys > 0
                || expired_media_count > 0
                || pages_freed > 0
            {
                tracing::info!(
                    nonces,
                    revoked_sessions,
                    stale,
                    pruned,
                    abandoned_new_groups,
                    expired_snapshots,
                    superseded_registry_artifacts,
                    expired_pairing_sessions,
                    revoked_tombstones,
                    stale_prekeys,
                    expired_sharing_inits,
                    expired_grace_keys,
                    expired_media_count,
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
    state.pairing_rate_limiter.prune_stale(60);
    state
        .media_upload_rate_limiter
        .prune_stale(state.config.media_upload_rate_window_secs);
}

/// Collect media_ids for sync groups that are about to be pruned.
/// Must be called BEFORE `prune_stale_sync_groups` so the data still exists.
fn collect_stale_group_media(
    conn: &rusqlite::Connection,
    inactive_threshold_secs: i64,
) -> Result<Vec<(String, Vec<String>)>, rusqlite::Error> {
    let cutoff = crate::db::now_secs() - inactive_threshold_secs;
    let mut stmt = conn.prepare(
        "SELECT sg.sync_id
         FROM sync_groups sg
         WHERE NOT EXISTS (
             SELECT 1
             FROM devices d
             WHERE d.sync_id = sg.sync_id AND d.last_seen_at >= ?1
         )",
    )?;
    let stale_ids: Vec<String> = stmt
        .query_map(rusqlite::params![cutoff], |row| row.get(0))?
        .filter_map(|r| r.ok())
        .collect();

    let mut results = Vec::new();
    for sync_id in stale_ids {
        let media_ids = crate::db::delete_media_for_sync_group(conn, &sync_id)?;
        if !media_ids.is_empty() {
            results.push((sync_id, media_ids));
        }
    }
    Ok(results)
}

/// Delete media files from disk. Returns the number of files successfully removed.
fn cleanup_media_files(storage_path: &str, items: &[(String, String)]) -> usize {
    items
        .iter()
        .filter(|(sync_id, media_id)| {
            let path = std::path::Path::new(storage_path)
                .join(sync_id)
                .join(media_id);
            std::fs::remove_file(&path).is_ok()
        })
        .count()
}

/// Try to remove empty sync_id directories after media files have been cleaned up.
fn cleanup_empty_media_dirs(storage_path: &str, items: &[(String, String)]) {
    let mut seen = std::collections::HashSet::new();
    for (sync_id, _) in items {
        if seen.insert(sync_id.clone()) {
            let dir = std::path::Path::new(storage_path).join(sync_id);
            // remove_dir only succeeds if the directory is empty
            let _ = std::fs::remove_dir(&dir);
        }
    }
}

fn cleanup_abandoned_brand_new_groups(
    conn: &rusqlite::Connection,
    abandon_secs: i64,
) -> Result<usize, rusqlite::Error> {
    let cutoff = crate::db::now_secs() - abandon_secs;
    let mut stmt = conn.prepare(
        "SELECT sg.sync_id
         FROM sync_groups sg
         WHERE sg.created_at <= ?1
           AND NOT EXISTS (
               SELECT 1 FROM batches b WHERE b.sync_id = sg.sync_id
           )
           AND NOT EXISTS (
               SELECT 1 FROM snapshots s WHERE s.sync_id = sg.sync_id
           )
           AND NOT EXISTS (
               SELECT 1 FROM devices d
               WHERE d.sync_id = sg.sync_id
                 AND d.status = 'active'
                 AND d.last_seen_at >= ?1
           )",
    )?;

    let sync_ids: Vec<String> = stmt
        .query_map([cutoff], |row| row.get(0))?
        .filter_map(|row| row.ok())
        .collect();

    for sync_id in &sync_ids {
        let _ = crate::db::delete_sync_group(conn, sync_id)?;
    }

    Ok(sync_ids.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{self, Database};
    use rusqlite::params;

    #[test]
    fn abandoned_brand_new_groups_are_removed() {
        let db = Database::in_memory().expect("in-memory db");
        db.with_conn(|conn| {
            db::create_sync_group(conn, "sg1", 0)?;
            db::register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0)?;

            let old = db::now_secs() - 10_000;
            conn.execute(
                "UPDATE sync_groups SET created_at = ?1, updated_at = ?1 WHERE sync_id = ?2",
                params![old, "sg1"],
            )?;
            conn.execute(
                "UPDATE devices SET last_seen_at = ?1 WHERE sync_id = ?2",
                params![old, "sg1"],
            )?;

            let removed = cleanup_abandoned_brand_new_groups(conn, 60)?;
            assert_eq!(removed, 1);
            assert!(db::get_sync_group_epoch(conn, "sg1")?.is_none());

            Ok(())
        })
        .unwrap();
    }
}
