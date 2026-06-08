use crate::state::AppState;
use std::sync::Arc;
use tokio::time::{interval, Duration};

/// Spawn the background cleanup task. Runs on the configured interval
/// (first cycle fires after one full interval, not immediately).
/// Returns the [`JoinHandle`] so the caller can abort it during graceful shutdown.
pub fn spawn_cleanup_task(state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
    let interval_secs = state.config.cleanup_interval_secs;
    tokio::spawn(async move {
        // Run the (dry-run) media reconciliation sweep once at startup so the
        // crash-row count surfaces immediately, not only after the first full
        // cleanup interval.
        run_media_reconciliation(&state).await;
        let mut ticker = interval(Duration::from_secs(interval_secs));
        ticker.tick().await; // consume the immediate first tick; first cleanup fires after one full interval
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
            // 1. Expire registration and signed-request replay nonces.
            let nonces = crate::db::cleanup_expired_nonces(conn)?;
            let signed_request_nonces = crate::db::cleanup_expired_signed_request_nonces(conn)?;
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

            // 6. Delete expired ephemeral snapshots before snapshot-gated
            //    pruning so stale snapshot rows cannot authorize history loss.
            let expired_snapshots = crate::db::cleanup_expired_snapshots(conn)?;

            // 7. Prune acknowledged batch history only when an unexpired
            //    group-wide snapshot exists for the sync group.
            let pruned_batches = crate::db::prune_batches_with_unexpired_snapshots(
                conn,
                config.stale_device_secs as i64,
            )?;

            // 7b. Ack-only pruning for groups with no group-wide snapshot.
            //     Never prunes past a non-revoked device; step 3's revocation
            //     is what lets the floor advance past an abandoned one.
            let pruned_batches_by_acks = crate::db::prune_batches_by_acks(conn)?;

            // 8. Remove superseded registry artifacts now that the current
            //    registry state is persisted separately.
            let superseded_registry_artifacts =
                crate::db::cleanup_superseded_registry_state_artifacts(conn)?;

            // 9. Remove expired pairing sessions.
            let expired_pairing_sessions = crate::db::cleanup_expired_pairing_sessions(conn)?;

            // 10. Garbage-collect revoked tombstones only after no retained
            //    history rows still reference them.
            let revoked_tombstones = crate::db::cleanup_revoked_device_tombstones(
                conn,
                config.revoked_tombstone_retention_secs as i64,
            )?;

            // 11. Delete stale sharing prekeys past the serve-age limit.
            let stale_prekeys =
                crate::db::cleanup_stale_sharing_prekeys(conn, config.prekey_serve_max_age_secs)?;

            // 12. Delete sharing-init payloads after their replay window expires.
            let expired_sharing_inits = crate::db::cleanup_expired_sharing_init_payloads(conn)?;

            // 13. Clear expired ML-DSA grace keys (post-rotation old keys).
            let expired_grace_keys =
                crate::db::cleanup_expired_ml_dsa_grace_keys(conn, crate::db::now_secs())?;

            // 14. Expire old media blobs past retention period.
            let expired_media =
                crate::db::cleanup_expired_media(conn, config.media_retention_days)?;

            // 14b. Sweep the ephemeral device-message mailbox (C3): rows past
            // their short TTL or already fully acked by every eligible recipient.
            let expired_device_messages = crate::db::cleanup_expired_device_messages(conn)?;

            // 15. Reclaim freed pages (incremental auto_vacuum)
            let freelist_before: i64 =
                conn.query_row("PRAGMA freelist_count;", [], |r| r.get(0)).unwrap_or(0);
            conn.execute_batch("PRAGMA incremental_vacuum;")?;
            let freelist_after: i64 =
                conn.query_row("PRAGMA freelist_count;", [], |r| r.get(0)).unwrap_or(0);
            let pages_freed = (freelist_before - freelist_after).max(0) as u64;
            Ok::<_, rusqlite::Error>((
                nonces,
                signed_request_nonces,
                revoked_sessions,
                stale,
                revoked_groups,
                pruned,
                stale_group_media_ids,
                abandoned_new_groups,
                expired_snapshots,
                pruned_batches,
                pruned_batches_by_acks,
                superseded_registry_artifacts,
                expired_pairing_sessions,
                revoked_tombstones,
                stale_prekeys,
                expired_sharing_inits,
                expired_grace_keys,
                expired_media,
                expired_device_messages,
                pages_freed,
            ))
        })
    })
    .await;

    match result {
        Ok(Ok((
            nonces,
            signed_request_nonces,
            revoked_sessions,
            stale,
            revoked_groups,
            pruned,
            stale_group_media_ids,
            abandoned_new_groups,
            expired_snapshots,
            pruned_batches,
            pruned_batches_by_acks,
            superseded_registry_artifacts,
            expired_pairing_sessions,
            revoked_tombstones,
            stale_prekeys,
            expired_sharing_inits,
            expired_grace_keys,
            expired_media,
            expired_device_messages,
            pages_freed,
        ))) => {
            // Clean up media files from disk for pruned sync groups
            let stale_media_items: Vec<(String, String)> = stale_group_media_ids
                .into_iter()
                .flat_map(|(sync_id, media_ids)| {
                    media_ids.into_iter().map(move |mid| (sync_id.clone(), mid))
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

            state
                .metrics
                .last_cleanup_epoch_secs
                .store(crate::db::now_secs() as u64, std::sync::atomic::Ordering::Relaxed);
            let expired_media_count = expired_media_cleaned + stale_media_cleaned;
            if nonces > 0
                || signed_request_nonces > 0
                || revoked_sessions > 0
                || stale > 0
                || !revoked_groups.is_empty()
                || pruned > 0
                || abandoned_new_groups > 0
                || expired_snapshots > 0
                || pruned_batches > 0
                || pruned_batches_by_acks > 0
                || superseded_registry_artifacts > 0
                || expired_pairing_sessions > 0
                || revoked_tombstones > 0
                || stale_prekeys > 0
                || expired_sharing_inits > 0
                || expired_grace_keys > 0
                || expired_media_count > 0
                || expired_device_messages > 0
                || pages_freed > 0
            {
                tracing::info!(
                    nonces,
                    signed_request_nonces,
                    revoked_sessions,
                    stale,
                    pruned,
                    pruned_batches,
                    pruned_batches_by_acks,
                    abandoned_new_groups,
                    expired_snapshots,
                    superseded_registry_artifacts,
                    expired_pairing_sessions,
                    revoked_tombstones,
                    stale_prekeys,
                    expired_sharing_inits,
                    expired_grace_keys,
                    expired_media_count,
                    expired_device_messages,
                    pages_freed,
                    "cleanup cycle complete"
                );
            }
        }
        Ok(Err(e)) => tracing::error!("cleanup db error: {e}"),
        Err(e) => tracing::error!("cleanup task panic: {e}"),
    }

    // Media lifecycle backstops: reap abandoned PENDING reserves (row + files)
    // and sweep orphaned media files. Kept separate from the giant cleanup
    // tuple above for clarity. The stale-pending grace must be ≫ a normal
    // promote so a healthy in-flight upload is never reaped.
    {
        let db = state.db.clone();
        let grace = state.config.media_pending_grace_secs as i64;
        let result = tokio::task::spawn_blocking(move || {
            db.with_conn(|conn| {
                let reaped = crate::db::reap_stale_pending_media(conn, grace)?;
                let known = crate::db::all_media_keys(conn)?;
                Ok::<_, rusqlite::Error>((reaped, known))
            })
        })
        .await;
        match result {
            Ok(Ok((reaped, known))) => {
                let storage = &state.config.media_storage_path;
                // Unlink final files for reaped pending rows, then sweep
                // orphaned finals + abandoned staging files. The orphan sweep
                // age-gates with the dedicated, long `media_orphan_cleanup_secs`
                // (not the 5-min pending grace): `rename` preserves the staging
                // file's mtime, so a lock-delayed upload could be promoted with
                // an "old" mtime just after the known-rows snapshot was taken —
                // a short gate could then delete a healthy just-committed file.
                // A day-long gate closes that race (an upload that old has long
                // since timed out and been reaped).
                let orphan_grace = state.config.media_orphan_cleanup_secs as i64;
                let reaped_cleaned = cleanup_media_files(storage, &reaped);
                cleanup_empty_media_dirs(storage, &reaped);
                let orphans_cleaned = sweep_orphan_media_files(storage, &known, orphan_grace);
                if !reaped.is_empty() || orphans_cleaned > 0 {
                    tracing::info!(
                        reaped_pending = reaped.len(),
                        reaped_cleaned,
                        orphans_cleaned,
                        "media pending/orphan sweep complete"
                    );
                }
            }
            Ok(Err(e)) => tracing::error!("media pending/orphan sweep db error: {e}"),
            Err(e) => tracing::error!("media pending/orphan sweep task panicked: {e}"),
        }
    }

    // Dry-run reconciliation: surface (but do NOT delete) servable rows whose
    // file is missing. See `run_media_reconciliation`.
    run_media_reconciliation(state).await;

    // Refresh DB-state metric cache. Runs after the cleanup block regardless
    // of whether cleanup succeeded, so metrics don't go stale on cleanup errors.
    // Keeps previous cached values on query failure rather than storing 0.
    {
        let db = state.db.clone();
        let prev_sb =
            state.metrics.cached_stored_batches.load(std::sync::atomic::Ordering::Relaxed);
        let prev_ds = state.metrics.cached_db_size_bytes.load(std::sync::atomic::Ordering::Relaxed);
        let prev_fp =
            state.metrics.cached_freelist_pages.load(std::sync::atomic::Ordering::Relaxed);
        match tokio::task::spawn_blocking(move || {
            db.with_read_conn(|conn| {
                let stored_batches: u64 = conn
                    .query_row("SELECT COUNT(*) FROM batches", [], |r| r.get(0))
                    .unwrap_or_else(|e| {
                        tracing::warn!("metrics cache: stored_batches query failed: {e}");
                        prev_sb
                    });
                let db_size_bytes: u64 = conn
                    .query_row(
                        "SELECT page_count * page_size \
                         FROM pragma_page_count(), pragma_page_size()",
                        [],
                        |r| r.get(0),
                    )
                    .unwrap_or_else(|e| {
                        tracing::warn!("metrics cache: db_size_bytes query failed: {e}");
                        prev_ds
                    });
                let freelist_pages: u64 = conn
                    .query_row("PRAGMA freelist_count;", [], |r| r.get(0))
                    .unwrap_or_else(|e| {
                        tracing::warn!("metrics cache: freelist_pages query failed: {e}");
                        prev_fp
                    });
                Ok::<(u64, u64, u64), rusqlite::Error>((
                    stored_batches,
                    db_size_bytes,
                    freelist_pages,
                ))
            })
        })
        .await
        {
            Ok(Ok((sb, ds, fp))) => {
                state.metrics.cached_stored_batches.store(sb, std::sync::atomic::Ordering::Relaxed);
                state.metrics.cached_db_size_bytes.store(ds, std::sync::atomic::Ordering::Relaxed);
                state.metrics.cached_freelist_pages.store(fp, std::sync::atomic::Ordering::Relaxed);
            }
            Ok(Err(e)) => tracing::warn!("metrics cache refresh failed: {e}"),
            Err(e) => tracing::warn!("metrics cache refresh task panicked: {e}"),
        }
    }

    // Prune stale entries from in-memory rate limiters.
    state.ws_upgrade_rate_limiter.prune_stale(state.config.ws_upgrade_rate_window_secs);
    state.nonce_rate_limiter.prune_stale(state.config.nonce_rate_window_secs);
    state.revoke_rate_limiter.prune_stale(state.config.revoke_rate_window_secs);
    state.pairing_rate_limiter.prune_stale(60);
    state.media_upload_rate_limiter.prune_stale(state.config.media_upload_rate_window_secs);
    // Re-supply / pairing-push limiters are scaffolding (enforcement lands with
    // C4/C5) but are pruned here so their windows don't accumulate.
    state.media_resupply_rate_limiter.prune_stale(state.config.media_resupply_rate_window_secs);
    state
        .media_pairing_push_rate_limiter
        .prune_stale(state.config.media_pairing_push_rate_window_secs);
    state
        .device_message_send_rate_limiter
        .prune_stale(state.config.device_message_send_rate_window_secs);
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
            let path = std::path::Path::new(storage_path).join(sync_id).join(media_id);
            std::fs::remove_file(&path).is_ok()
        })
        .count()
}

/// Remove media files with no backing DB row (orphaned final files) and
/// abandoned staging files. Pure disk hygiene — the DB is the source of truth.
///
/// Both removals are age-gated by `staging_grace_secs`: `known` is a snapshot
/// that may be slightly stale relative to the filesystem walk, so a final file
/// younger than the grace window might belong to a just-committed upload not yet
/// in the snapshot. Only files older than the grace are removed, which is safe
/// because a healthy upload commits its row within seconds (≪ grace). Returns
/// the number of files removed.
fn sweep_orphan_media_files(
    storage_path: &str,
    known: &[(String, String)],
    staging_grace_secs: i64,
) -> usize {
    use std::collections::HashSet;
    let known: HashSet<(&str, &str)> =
        known.iter().map(|(s, m)| (s.as_str(), m.as_str())).collect();
    let root = std::path::Path::new(storage_path);
    let Ok(sync_dirs) = std::fs::read_dir(root) else {
        return 0;
    };
    let now = crate::db::now_secs();
    let mut removed = 0usize;

    for sync_entry in sync_dirs.flatten() {
        let sync_path = sync_entry.path();
        if !sync_path.is_dir() {
            continue;
        }
        let Some(sync_id) =
            sync_path.file_name().and_then(|n| n.to_str()).map(str::to_string)
        else {
            continue;
        };
        let Ok(files) = std::fs::read_dir(&sync_path) else {
            continue;
        };
        for file_entry in files.flatten() {
            let path = file_entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()).map(str::to_string) else {
                continue;
            };

            if name == ".staging" {
                // Abandoned staging files older than the grace window. A live
                // upload's staging file is < grace old.
                if let Ok(staging) = std::fs::read_dir(&path) {
                    for st in staging.flatten() {
                        let stp = st.path();
                        if stp.is_file()
                            && file_older_than(&stp, now, staging_grace_secs)
                            && std::fs::remove_file(&stp).is_ok()
                        {
                            removed += 1;
                        }
                    }
                }
                continue;
            }

            // A final file with no backing row is an orphan (age-gated against
            // the snapshot-vs-walk race — see fn doc).
            if path.is_file()
                && !known.contains(&(sync_id.as_str(), name.as_str()))
                && file_older_than(&path, now, staging_grace_secs)
                && std::fs::remove_file(&path).is_ok()
            {
                removed += 1;
            }
        }
    }

    removed
}

/// True if `path`'s mtime is more than `age_secs` before `now` (unix seconds).
/// Errors (missing file / unreadable mtime) conservatively return `false` so a
/// file is never removed on a metadata read failure.
fn file_older_than(path: &std::path::Path, now: i64, age_secs: i64) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|mtime| mtime.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| (now - d.as_secs() as i64) > age_secs)
        .unwrap_or(false)
}

/// Dry-run reconciliation sweep (media re-supply C1 follow-up).
///
/// Scans the rows the relay considers servable (committed, not deleted, not past
/// TTL) and reports how many have **no on-disk file** — legacy "metadata then
/// file" crash rows that would make a metadata-only batch-exists (C2) dishonest.
///
/// **This is intentionally LOG-ONLY: it never marks anything deleted.** The
/// first run of the destructive form against a live relay's legacy crash-rows is
/// risky, so we ship the observation first: the count is published as
/// `prism_media_reconciliation_missing_files` (and logged with a bounded id
/// sample). A later change enables the mark-deleted step only after this count
/// is verified against the known crash-row population. PENDING reserves are
/// excluded by the query, so this can never observe an in-flight upload.
async fn run_media_reconciliation(state: &AppState) {
    let db = state.db.clone();
    let now = crate::db::now_secs();
    let candidates = match tokio::task::spawn_blocking(move || {
        db.with_read_conn(|conn| crate::db::list_servable_committed_media(conn, now))
    })
    .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            tracing::error!("media reconciliation: list query failed: {e}");
            return;
        }
        Err(e) => {
            tracing::error!("media reconciliation task panicked: {e}");
            return;
        }
    };

    let scanned = candidates.len();
    let missing = find_missing_media_files(&state.config.media_storage_path, &candidates);
    state
        .metrics
        .media_reconciliation_missing_files
        .store(missing.len() as u64, std::sync::atomic::Ordering::Relaxed);

    if missing.is_empty() {
        tracing::debug!(scanned, "media reconciliation: all servable rows have files");
    } else {
        // A bounded id sample aids verification without flooding logs if the
        // crash-row population is large.
        let sample: Vec<String> =
            missing.iter().take(20).map(|(s, m)| format!("{s}/{m}")).collect();
        tracing::warn!(
            scanned,
            missing = missing.len(),
            mode = "dry_run",
            ?sample,
            "media reconciliation: servable rows with no on-disk file (LOG-ONLY, nothing deleted)"
        );
    }
}

/// Return the subset of `candidates` (`(sync_id, media_id)`) whose final media
/// file is absent on disk. Pure (filesystem + input) so it is unit-testable.
fn find_missing_media_files(
    storage_path: &str,
    candidates: &[(String, String)],
) -> Vec<(String, String)> {
    candidates
        .iter()
        .filter(|(sync_id, media_id)| {
            !std::path::Path::new(storage_path).join(sync_id).join(media_id).exists()
        })
        .cloned()
        .collect()
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

    let sync_ids: Vec<String> =
        stmt.query_map([cutoff], |row| row.get(0))?.filter_map(|row| row.ok()).collect();

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

    #[test]
    fn orphan_sweep_removes_unbacked_finals_and_staging() {
        let tmp = tempfile::TempDir::new().unwrap();
        let storage = tmp.path().to_str().unwrap();
        let sync_dir = tmp.path().join("sg");
        let staging_dir = sync_dir.join(".staging");
        std::fs::create_dir_all(&staging_dir).unwrap();

        // A final file with a backing row (kept), one without (orphan), and a
        // staging file (abandoned).
        std::fs::write(sync_dir.join("keep"), b"k").unwrap();
        std::fs::write(sync_dir.join("orphan"), b"o").unwrap();
        std::fs::write(staging_dir.join("up.deadbeef"), b"s").unwrap();

        let known = vec![("sg".to_string(), "keep".to_string())];
        // age_secs = -1 forces the age gate true regardless of mtime.
        let removed = sweep_orphan_media_files(storage, &known, -1);
        assert_eq!(removed, 2, "orphan final + staging file removed");
        assert!(sync_dir.join("keep").exists(), "backed final survives");
        assert!(!sync_dir.join("orphan").exists(), "unbacked final removed");
        assert!(!staging_dir.join("up.deadbeef").exists(), "staging removed");
    }

    #[test]
    fn reconciliation_finds_only_rows_with_missing_files() {
        let tmp = tempfile::TempDir::new().unwrap();
        let storage = tmp.path().to_str().unwrap();
        let sync_dir = tmp.path().join("sg");
        std::fs::create_dir_all(&sync_dir).unwrap();
        // "present" has a file on disk; "gone" does not (legacy crash row).
        std::fs::write(sync_dir.join("present"), b"x").unwrap();

        let candidates = vec![
            ("sg".to_string(), "present".to_string()),
            ("sg".to_string(), "gone".to_string()),
        ];
        let missing = find_missing_media_files(storage, &candidates);
        assert_eq!(missing, vec![("sg".to_string(), "gone".to_string())]);
        // Dry-run: the finder never touches the filesystem rows it inspects.
        assert!(sync_dir.join("present").exists());
    }

    #[test]
    fn orphan_sweep_age_gate_spares_fresh_files() {
        let tmp = tempfile::TempDir::new().unwrap();
        let storage = tmp.path().to_str().unwrap();
        let sync_dir = tmp.path().join("sg");
        std::fs::create_dir_all(&sync_dir).unwrap();
        std::fs::write(sync_dir.join("fresh-orphan"), b"x").unwrap();

        // A just-written file is younger than a large grace window, so even
        // though it has no backing row it must NOT be removed (protects the
        // snapshot-vs-walk race against a just-committed upload).
        let removed = sweep_orphan_media_files(storage, &[], 86_400);
        assert_eq!(removed, 0);
        assert!(sync_dir.join("fresh-orphan").exists());
    }
}
