use crate::config::Config;
use crate::db::Database;
use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};

/// Bounded channel capacity for WebSocket notification senders.
const WS_CHANNEL_CAPACITY: usize = 64;

pub type WsSender = mpsc::Sender<String>;
type WsConnections = HashMap<String, HashMap<String, WsSender>>;

#[derive(Debug, Default)]
pub struct Metrics {
    pub last_cleanup_epoch_secs: AtomicU64,
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
        let mut map = self.windows.lock().unwrap();
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
            map.get_mut(&key).unwrap().push(now);
        }
        true
    }

    /// Remove entries that have no timestamps within the given window.
    /// Called periodically to prevent unbounded growth.
    pub fn prune_stale(&self, window_secs: u64) {
        let mut map = self.windows.lock().unwrap();
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
    pub metrics: Arc<Metrics>,
    pub nonce_rate_limiter: RateLimiter,
    pub revoke_rate_limiter: RateLimiter,
    pub signed_request_replay_cache: RateLimiter,
    pub first_device_nonce_rate_limiter: RateLimiter,
    pub first_device_registration_rate_limiter: RateLimiter,
    pub first_device_group_rate_limiter: RateLimiter,
}

impl AppState {
    pub fn new(db: Database, config: Config) -> Self {
        Self {
            db: Arc::new(db),
            config: Arc::new(config),
            ws_connections: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(Metrics::default()),
            nonce_rate_limiter: RateLimiter::default(),
            revoke_rate_limiter: RateLimiter::default(),
            signed_request_replay_cache: RateLimiter::default(),
            first_device_nonce_rate_limiter: RateLimiter::default(),
            first_device_registration_rate_limiter: RateLimiter::default(),
            first_device_group_rate_limiter: RateLimiter::default(),
        }
    }

    /// Broadcast a message to all WS connections for a sync group, excluding one device.
    pub async fn notify_devices(&self, sync_id: &str, exclude_device: Option<&str>, message: &str) {
        let conns = self.ws_connections.read().await;
        if let Some(devices) = conns.get(sync_id) {
            for (device_id, sender) in devices {
                if exclude_device == Some(device_id.as_str()) {
                    continue;
                }
                if sender.send(message.to_string()).await.is_err() {
                    tracing::debug!(
                        "Failed to send to device {}, likely disconnected",
                        device_id
                    );
                }
            }
        }
    }

    /// Register a WebSocket connection. Last-connection-wins: if a sender already
    /// exists for this (sync_id, device_id), the old one is replaced (its receiver
    /// will see the channel close).
    pub async fn register_ws(&self, sync_id: &str, device_id: &str) -> mpsc::Receiver<String> {
        let (tx, rx) = mpsc::channel(WS_CHANNEL_CAPACITY);
        let mut conns = self.ws_connections.write().await;
        conns
            .entry(sync_id.to_string())
            .or_default()
            .insert(device_id.to_string(), tx);
        rx
    }

    /// Unregister a WebSocket connection.
    pub async fn unregister_ws(&self, sync_id: &str, device_id: &str) {
        let mut conns = self.ws_connections.write().await;
        if let Some(devices) = conns.get_mut(sync_id) {
            devices.remove(device_id);
            if devices.is_empty() {
                conns.remove(sync_id);
            }
        }
    }

    /// Drop the current WebSocket sender for a device so it stops receiving
    /// future notifications immediately.
    pub async fn disconnect_ws(&self, sync_id: &str, device_id: &str) {
        self.unregister_ws(sync_id, device_id).await;
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
        assert!(
            limiter.check("key", 2, 1),
            "request after window expiry should be allowed"
        );
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
