use crate::config::Config;
use crate::db::Database;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};

/// Bounded channel capacity for WebSocket notification senders.
const WS_CHANNEL_CAPACITY: usize = 64;

pub type WsSender = mpsc::Sender<String>;
/// Connection IDs prevent stale teardown from removing a replacement socket.
type WsConnections = HashMap<String, HashMap<String, (u64, WsSender)>>;

#[derive(Debug, Default)]
pub struct Metrics {
    pub changesets_pushed: AtomicU64,
    pub changesets_pulled: AtomicU64,
    pub changesets_pruned: AtomicU64,
    pub ws_notifications: AtomicU64,
    pub ws_notifications_dropped: AtomicU64,
    pub auth_failures: AtomicU64,
    pub snapshots_exchanged: AtomicU64,
    /// `PUT /snapshot` rejected with 409 `stale_snapshot_seq`. Unusual
    /// rates here flag a buggy client or a concurrency regression.
    pub snapshots_rejected_stale: AtomicU64,
    /// Targeted `PUT /snapshot` rejected with 409 `too_many_targeted_snapshots`
    /// because the group already holds the per-group cap of unexpired targeted
    /// rows. Elevated rates flag a pairing storm or stalled pairings.
    pub snapshots_rejected_targeted_cap: AtomicU64,
    pub registrations: AtomicU64,
    pub vacuum_pages_freed: AtomicU64,
    /// Times the startup lineage check detected a regressed batch sequence (a
    /// file-level DB restore) and rotated `log_token`. Any nonzero value here is
    /// an operator-visible signal that clients were forced to reset their cursor.
    pub log_token_rotations: AtomicU64,
    /// Times the startup lineage check could not read the companion file
    /// (truncation, partial write, EACCES). Each one is a boot where shape-A
    /// restore detection was forfeited — operator-visible because the overwrite
    /// that follows destroys the evidence.
    pub lineage_companion_unreadable: AtomicU64,
    pub last_cleanup_epoch_secs: AtomicU64,
    pub media_uploads: AtomicU64,
    pub media_downloads: AtomicU64,
    pub media_bytes_uploaded: AtomicU64,
    /// Gauge (not persisted): committed/servable media rows whose on-disk file
    /// is missing, as found by the most recent reconciliation sweep. While the
    /// sweep is in dry-run/log-only mode this is the count it *would* delete —
    /// watch it to verify against the known crash-row population before enabling
    /// deletion.
    pub media_reconciliation_missing_files: AtomicU64,
    // Cached DB-state values refreshed after each cleanup cycle.
    // Avoids live DB queries on every Prometheus scrape.
    pub cached_stored_batches: AtomicU64,
    pub cached_db_size_bytes: AtomicU64,
    pub cached_freelist_pages: AtomicU64,
}

impl Metrics {
    pub fn inc(&self, field: &AtomicU64) {
        field.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_by(&self, field: &AtomicU64, n: u64) {
        field.fetch_add(n, Ordering::Relaxed);
    }

    /// Restore counter values from a name→value map (loaded from SQLite).
    pub fn restore_from(&self, counters: &std::collections::HashMap<String, u64>) {
        let fields: &[(&str, &AtomicU64)] = &[
            ("changesets_pushed", &self.changesets_pushed),
            ("changesets_pulled", &self.changesets_pulled),
            ("changesets_pruned", &self.changesets_pruned),
            ("ws_notifications", &self.ws_notifications),
            ("ws_notifications_dropped", &self.ws_notifications_dropped),
            ("auth_failures", &self.auth_failures),
            ("snapshots_exchanged", &self.snapshots_exchanged),
            ("snapshots_rejected_stale", &self.snapshots_rejected_stale),
            ("snapshots_rejected_targeted_cap", &self.snapshots_rejected_targeted_cap),
            ("registrations", &self.registrations),
            ("vacuum_pages_freed", &self.vacuum_pages_freed),
            ("log_token_rotations", &self.log_token_rotations),
            ("lineage_companion_unreadable", &self.lineage_companion_unreadable),
            ("media_uploads", &self.media_uploads),
            ("media_downloads", &self.media_downloads),
            ("media_bytes_uploaded", &self.media_bytes_uploaded),
        ];
        for (name, field) in fields {
            if let Some(&value) = counters.get(*name) {
                field.store(value, Ordering::Relaxed);
            }
        }
    }

    /// Snapshot current counter values for flushing to SQLite.
    pub fn snapshot_counters(&self) -> Vec<(&'static str, u64)> {
        vec![
            ("changesets_pushed", self.changesets_pushed.load(Ordering::Relaxed)),
            ("changesets_pulled", self.changesets_pulled.load(Ordering::Relaxed)),
            ("changesets_pruned", self.changesets_pruned.load(Ordering::Relaxed)),
            ("ws_notifications", self.ws_notifications.load(Ordering::Relaxed)),
            ("ws_notifications_dropped", self.ws_notifications_dropped.load(Ordering::Relaxed)),
            ("auth_failures", self.auth_failures.load(Ordering::Relaxed)),
            ("snapshots_exchanged", self.snapshots_exchanged.load(Ordering::Relaxed)),
            ("snapshots_rejected_stale", self.snapshots_rejected_stale.load(Ordering::Relaxed)),
            (
                "snapshots_rejected_targeted_cap",
                self.snapshots_rejected_targeted_cap.load(Ordering::Relaxed),
            ),
            ("registrations", self.registrations.load(Ordering::Relaxed)),
            ("vacuum_pages_freed", self.vacuum_pages_freed.load(Ordering::Relaxed)),
            ("log_token_rotations", self.log_token_rotations.load(Ordering::Relaxed)),
            (
                "lineage_companion_unreadable",
                self.lineage_companion_unreadable.load(Ordering::Relaxed),
            ),
            ("media_uploads", self.media_uploads.load(Ordering::Relaxed)),
            ("media_downloads", self.media_downloads.load(Ordering::Relaxed)),
            ("media_bytes_uploaded", self.media_bytes_uploaded.load(Ordering::Relaxed)),
        ]
    }
}

/// Per-key sliding window rate limiter.
/// Stores timestamps of recent requests per key, pruning on access.
#[derive(Clone, Default)]
pub struct RateLimiter {
    windows: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl RateLimiter {
    /// Maximum number of distinct keys tracked before new keys are rejected.
    /// Prevents unbounded memory growth from attackers using random keys.
    const MAX_TRACKED_KEYS: usize = 100_000;

    /// Check whether a request for `key` is allowed.
    /// Returns `true` if under the limit, `false` if rate-limited.
    /// Automatically prunes timestamps outside the window.
    pub fn check(&self, key: &str, max_requests: u32, window_secs: u64) -> bool {
        self.check_many(&[key], max_requests, window_secs)
    }

    /// Check whether a request for all `keys` is allowed, reserving a slot for
    /// each key atomically if so.
    pub fn check_many(&self, keys: &[&str], max_requests: u32, window_secs: u64) -> bool {
        let mut map = self.windows.lock().expect("rate limiter mutex poisoned");
        let now = Instant::now();
        let cutoff = now - std::time::Duration::from_secs(window_secs);

        let mut missing = 0usize;
        for key in keys {
            if !map.contains_key(*key) {
                missing += 1;
            }
        }
        if map.len() + missing > Self::MAX_TRACKED_KEYS {
            return false;
        }

        let mut candidates = Vec::with_capacity(keys.len());
        for key in keys {
            let timestamps = map.entry((*key).to_string()).or_default();
            timestamps.retain(|t| *t > cutoff);
            if timestamps.len() >= max_requests as usize {
                return false;
            }
            candidates.push(key.to_string());
        }

        for key in candidates {
            map.get_mut(&key).expect("key was just inserted above").push(now);
        }
        true
    }

    /// Remove entries that have no timestamps within the given window.
    /// Called periodically to prevent unbounded growth.
    pub fn prune_stale(&self, window_secs: u64) {
        let mut map = self.windows.lock().expect("rate limiter mutex poisoned");
        let cutoff = Instant::now() - std::time::Duration::from_secs(window_secs);
        map.retain(|_, timestamps| {
            timestamps.retain(|t| *t > cutoff);
            !timestamps.is_empty()
        });
    }
}

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub config: Arc<Config>,
    pub ws_connections: Arc<RwLock<WsConnections>>,
    /// Sequence for connection ownership checks.
    pub ws_conn_seq: Arc<AtomicU64>,
    pub metrics: Arc<Metrics>,
    pub nonce_rate_limiter: RateLimiter,
    pub revoke_rate_limiter: RateLimiter,
    pub first_device_nonce_rate_limiter: RateLimiter,
    pub first_device_registration_rate_limiter: RateLimiter,
    pub first_device_group_rate_limiter: RateLimiter,
    pub pairing_rate_limiter: RateLimiter,
    pub ws_upgrade_rate_limiter: RateLimiter,
    pub sharing_fetch_rate_limiter: RateLimiter,
    pub sharing_init_rate_limiter: RateLimiter,
    pub media_upload_rate_limiter: RateLimiter,
    /// Re-supply/heal upload limiter, separate from fresh sends.
    pub media_resupply_rate_limiter: RateLimiter,
    /// Pairing-push upload limiter, keyed per pairing event/device.
    pub media_pairing_push_rate_limiter: RateLimiter,
    /// Ephemeral mailbox send limiter, keyed per sender device. The real
    /// request-storm bound for the re-supply signal lane.
    pub device_message_send_rate_limiter: RateLimiter,
    pub gif_request_rate_limiter: RateLimiter,
    pub gif_http_client: reqwest::Client,
}

impl AppState {
    pub fn new(db: Database, config: Config) -> Self {
        let metrics = Arc::new(Metrics::default());
        let gif_http_client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .pool_idle_timeout(Some(std::time::Duration::from_secs(90)))
            .tcp_keepalive(Some(std::time::Duration::from_secs(60)))
            .build()
            .expect("gif HTTP client should build");

        // Restore persisted counters so lifetime totals survive restarts.
        match db.with_read_conn(crate::db::load_counters) {
            Ok(counters) => metrics.restore_from(&counters),
            Err(e) => tracing::warn!("failed to load persisted counters: {e}"),
        }

        // Seed DB-state metric cache so the first scrape returns real values.
        // Cleanup runs after one full interval (~1hr), not immediately, so
        // without this the cached fields stay 0 until the first cleanup cycle.
        match db.with_read_conn(|conn| {
            let stored_batches: u64 =
                conn.query_row("SELECT COUNT(*) FROM batches", [], |r| r.get(0)).unwrap_or(0);
            let db_size_bytes: u64 = conn
                .query_row(
                    "SELECT page_count * page_size \
                     FROM pragma_page_count(), pragma_page_size()",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            let freelist_pages: u64 =
                conn.query_row("PRAGMA freelist_count;", [], |r| r.get(0)).unwrap_or(0);
            Ok::<(u64, u64, u64), rusqlite::Error>((stored_batches, db_size_bytes, freelist_pages))
        }) {
            Ok((sb, ds, fp)) => {
                metrics.cached_stored_batches.store(sb, Ordering::Relaxed);
                metrics.cached_db_size_bytes.store(ds, Ordering::Relaxed);
                metrics.cached_freelist_pages.store(fp, Ordering::Relaxed);
            }
            Err(e) => tracing::warn!("failed to seed metrics cache: {e}"),
        }

        Self {
            db: Arc::new(db),
            config: Arc::new(config),
            ws_connections: Arc::new(RwLock::new(HashMap::new())),
            ws_conn_seq: Arc::new(AtomicU64::new(0)),
            metrics,
            nonce_rate_limiter: RateLimiter::default(),
            revoke_rate_limiter: RateLimiter::default(),
            first_device_nonce_rate_limiter: RateLimiter::default(),
            first_device_registration_rate_limiter: RateLimiter::default(),
            first_device_group_rate_limiter: RateLimiter::default(),
            pairing_rate_limiter: RateLimiter::default(),
            ws_upgrade_rate_limiter: RateLimiter::default(),
            sharing_fetch_rate_limiter: RateLimiter::default(),
            sharing_init_rate_limiter: RateLimiter::default(),
            media_upload_rate_limiter: RateLimiter::default(),
            media_resupply_rate_limiter: RateLimiter::default(),
            media_pairing_push_rate_limiter: RateLimiter::default(),
            device_message_send_rate_limiter: RateLimiter::default(),
            gif_request_rate_limiter: RateLimiter::default(),
            gif_http_client,
        }
    }

    /// Broadcast a message to all WS connections for a sync group, excluding one device.
    pub async fn notify_devices(&self, sync_id: &str, exclude_device: Option<&str>, message: &str) {
        // Snapshot senders under the read guard, then drop the guard before
        // sending. A slow consumer with a full 64-slot channel must NOT block
        // the broadcast loop or stall register_ws/unregister_ws (which take
        // the write guard).
        let senders: Vec<(String, WsSender)> = {
            let conns = self.ws_connections.read().await;
            conns
                .get(sync_id)
                .map(|devices| {
                    devices
                        .iter()
                        .filter(|(device_id, _)| exclude_device != Some(device_id.as_str()))
                        .map(|(id, (_conn_id, sender))| (id.clone(), sender.clone()))
                        .collect()
                })
                .unwrap_or_default()
        }; // RwLock guard dropped here.

        if senders.is_empty() {
            return;
        }

        let mut dropped = 0u64;
        for (device_id, sender) in senders {
            match sender.try_send(message.to_string()) {
                Ok(_) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    dropped += 1;
                    tracing::debug!("WS channel full for device {device_id}, dropped notification");
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    dropped += 1;
                    tracing::debug!(
                        "WS channel closed for device {device_id}, dropped notification"
                    );
                }
            }
        }

        self.metrics.inc(&self.metrics.ws_notifications);
        if dropped > 0 {
            self.metrics.inc_by(&self.metrics.ws_notifications_dropped, dropped);
        }
    }

    /// Replace the current sender; pass the returned ID to [`Self::unregister_ws`].
    pub async fn register_ws(
        &self,
        sync_id: &str,
        device_id: &str,
    ) -> (mpsc::Receiver<String>, u64) {
        let conn_id = self.ws_conn_seq.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(WS_CHANNEL_CAPACITY);
        let mut conns = self.ws_connections.write().await;
        conns.entry(sync_id.to_string()).or_default().insert(device_id.to_string(), (conn_id, tx));
        (rx, conn_id)
    }

    /// Remove the sender only if this connection still owns the slot.
    pub async fn unregister_ws(&self, sync_id: &str, device_id: &str, conn_id: u64) {
        let mut conns = self.ws_connections.write().await;
        if let Some(devices) = conns.get_mut(sync_id) {
            if matches!(devices.get(device_id), Some((existing, _)) if *existing == conn_id) {
                devices.remove(device_id);
            }
            if devices.is_empty() {
                conns.remove(sync_id);
            }
        }
    }

    /// Disconnect the current sender regardless of connection ID, for revocation.
    pub async fn disconnect_ws(&self, sync_id: &str, device_id: &str) {
        let mut conns = self.ws_connections.write().await;
        if let Some(devices) = conns.get_mut(sync_id) {
            devices.remove(device_id);
            if devices.is_empty() {
                conns.remove(sync_id);
            }
        }
    }

    /// Count total connected WebSocket devices.
    pub async fn connected_device_count(&self) -> usize {
        let conns = self.ws_connections.read().await;
        conns.values().map(|d| d.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db::Database;

    fn test_app_state() -> AppState {
        let db = Database::in_memory().expect("in-memory db");
        let config = Config::from_env();
        AppState::new(db, config)
    }

    #[tokio::test]
    async fn notify_devices_does_not_block_on_slow_consumer() {
        // The bug this fix targets: a single slow WS consumer with a full
        // channel can stall the broadcast loop for every device in the sync
        // group. The fix is `try_send` + drop-on-full. The right assertions
        // are (a) the broadcast loop never blocks regardless of consumer
        // state, and (b) dropped messages are accounted for. We do NOT
        // assert that any specific receiver gets a specific count, because
        // under bursty load `try_send` can drop on any receiver that
        // briefly fills its channel, even fast ones — that's the deliberate
        // tradeoff (fanout never blocks; clients catch up on next pull).
        let state = test_app_state();
        let sync_id = "sync-1";

        // dev_a registers but never reads — its 64-slot channel will fill up.
        let (_dev_a_rx, _) = state.register_ws(sync_id, "dev-a").await;
        // dev_b registers — we just need it to exist for the fanout loop.
        let (_dev_b_rx, _) = state.register_ws(sync_id, "dev-b").await;

        // Send 80 notifications. Without the fix, calls #65+ block on
        // dev_a's full channel for many seconds (the WS sender's
        // send().await never returns until the consumer drains). With the
        // fix (try_send + drop-on-full), all 80 calls return promptly.
        let send_start = std::time::Instant::now();
        for i in 0..80u32 {
            state.notify_devices(sync_id, None, &format!("msg-{i}")).await;
        }
        let send_elapsed = send_start.elapsed();
        assert!(
            send_elapsed < std::time::Duration::from_millis(500),
            "all 80 notify_devices calls should complete promptly (got {send_elapsed:?}); \
             the slow-consumer bug would stall this for many seconds"
        );

        // dev_a's drop counter must show that try_send dropped messages on
        // dev_a's full channel. Without the fix, the sender would have
        // blocked instead of dropping, so this counter would be 0.
        let dropped = state.metrics.ws_notifications_dropped.load(Ordering::Relaxed);
        assert!(
            dropped >= 16,
            "expected >= 16 dropped notifications for dev_a (80 sends - 64 buffer), got {dropped}"
        );
    }

    #[tokio::test]
    async fn unregister_ws_does_not_evict_a_replacement_connection() {
        let state = test_app_state();
        let sync_id = "sync-1";
        let device_id = "dev-a";

        let (_rx_a, conn_id_a) = state.register_ws(sync_id, device_id).await;
        let (mut rx_b, _conn_id_b) = state.register_ws(sync_id, device_id).await;

        // The old connection finishes after its replacement registers.
        state.unregister_ws(sync_id, device_id, conn_id_a).await;

        state.notify_devices(sync_id, None, "new_data").await;
        let message = tokio::time::timeout(std::time::Duration::from_millis(100), rx_b.recv())
            .await
            .expect("stale connection A's teardown must not remove B's live registration")
            .expect("replacement connection B's channel must remain open");
        assert_eq!(message, "new_data");
    }

    #[tokio::test]
    async fn unregister_ws_removes_the_current_connection() {
        let state = test_app_state();
        let sync_id = "sync-1";
        let device_id = "dev-a";

        let (mut rx, conn_id) = state.register_ws(sync_id, device_id).await;
        state.unregister_ws(sync_id, device_id, conn_id).await;

        assert_eq!(state.connected_device_count().await, 0);
        assert!(
            rx.recv().await.is_none(),
            "the current connection's cleanup must close its notification channel"
        );
    }

    #[tokio::test]
    async fn disconnect_ws_removes_only_the_target_current_connection() {
        let state = test_app_state();
        let sync_id = "sync-1";
        let other_sync_id = "sync-2";
        let target_device_id = "dev-a";

        let (_old_target_rx, _) = state.register_ws(sync_id, target_device_id).await;
        let (mut target_rx, _) = state.register_ws(sync_id, target_device_id).await;
        let (mut peer_rx, _) = state.register_ws(sync_id, "dev-b").await;
        let (mut other_group_rx, _) = state.register_ws(other_sync_id, target_device_id).await;

        state.disconnect_ws(sync_id, target_device_id).await;

        assert_eq!(state.connected_device_count().await, 2);
        assert!(
            target_rx.recv().await.is_none(),
            "forced teardown must close the target's current notification channel"
        );

        state.notify_devices(sync_id, None, "same-group").await;
        assert_eq!(peer_rx.recv().await, Some("same-group".to_string()));

        state.notify_devices(other_sync_id, None, "other-group").await;
        assert_eq!(other_group_rx.recv().await, Some("other-group".to_string()));
    }

    #[test]
    fn rate_limiter_allows_up_to_limit() {
        let limiter = RateLimiter::default();
        for i in 0..5 {
            assert!(limiter.check("key", 5, 60), "request {i} should be allowed");
        }
        assert!(!limiter.check("key", 5, 60), "6th request should be denied");
    }

    #[test]
    fn rate_limiter_tracks_keys_independently() {
        let limiter = RateLimiter::default();
        for _ in 0..3 {
            assert!(limiter.check("a", 3, 60));
        }
        assert!(!limiter.check("a", 3, 60));
        // Different key should still be allowed
        assert!(limiter.check("b", 3, 60));
    }

    #[test]
    fn rate_limiter_allows_after_window_expires() {
        let limiter = RateLimiter::default();
        // Use a 0-second window so timestamps expire immediately
        for _ in 0..5 {
            assert!(limiter.check("key", 5, 0));
        }
        // Window is 0s, so all previous timestamps are expired
        assert!(limiter.check("key", 5, 0));
    }

    #[test]
    fn rate_limiter_check_many_is_atomic_across_keys() {
        let limiter = RateLimiter::default();
        assert!(limiter.check_many(&["global", "ip"], 1, 60));
        assert!(!limiter.check_many(&["global", "ip"], 1, 60));

        let map = limiter.windows.lock().unwrap();
        assert_eq!(map.get("global").map(|v| v.len()), Some(1));
        assert_eq!(map.get("ip").map(|v| v.len()), Some(1));
    }

    #[test]
    fn rate_limiter_prune_stale_removes_expired() {
        let limiter = RateLimiter::default();
        limiter.check("a", 10, 0);
        limiter.check("b", 10, 0);
        // Both entries have timestamps, but with 0s window they're all expired
        limiter.prune_stale(0);
        let map = limiter.windows.lock().unwrap();
        assert!(map.is_empty(), "stale entries should be pruned");
    }

    #[test]
    fn rate_limiter_window_expiry_with_real_sleep() {
        let limiter = RateLimiter::default();
        // Use a 1-second window with a limit of 2
        assert!(limiter.check("key", 2, 1), "1st request should be allowed");
        assert!(limiter.check("key", 2, 1), "2nd request should be allowed");
        assert!(!limiter.check("key", 2, 1), "3rd request should be denied");

        // Sleep just over 1 second so the window expires
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // After window expiry, the next request should be allowed
        assert!(limiter.check("key", 2, 1), "request after window expiry should be allowed");
    }

    #[test]
    fn rate_limiter_rejects_new_keys_at_capacity() {
        let limiter = RateLimiter::default();
        // Fill up to MAX_TRACKED_KEYS — we can't actually fill 100k in a test,
        // so verify the logic by directly inserting into the map.
        {
            let mut map = limiter.windows.lock().unwrap();
            for i in 0..RateLimiter::MAX_TRACKED_KEYS {
                map.insert(format!("key-{i}"), vec![Instant::now()]);
            }
        }
        // New key should be rejected
        assert!(!limiter.check("new-key", 10, 60));
        // Existing key should still work
        assert!(limiter.check("key-0", 10, 60));
    }
}
