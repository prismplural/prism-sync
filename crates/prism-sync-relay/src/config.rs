/// Application configuration, loaded from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub db_path: String,
    pub invite_ttl_secs: u64,
    pub sync_inactive_ttl_secs: u64,
    pub stale_device_secs: u64,
    pub cleanup_interval_secs: u64,
    pub max_unpruned_batches: u64,
    pub metrics_token: Option<String>,
    pub session_expiry_secs: u64,
    pub nonce_expiry_secs: u64,
    /// Max nonces per sync_id within the rate limit window.
    pub nonce_rate_limit: u32,
    /// Sliding window duration in seconds for nonce rate limiting.
    pub nonce_rate_window_secs: u64,
    /// Default TTL in seconds for ephemeral snapshots (24 hours).
    pub snapshot_default_ttl_secs: u64,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            port: parse_env("PORT", 8080),
            db_path: std::env::var("DB_PATH").unwrap_or_else(|_| "data/relay.db".into()),
            invite_ttl_secs: parse_env("INVITE_TTL_SECS", 86400),
            sync_inactive_ttl_secs: parse_env("SYNC_INACTIVE_TTL_SECS", 7_776_000),
            stale_device_secs: parse_env("STALE_DEVICE_SECS", 2_592_000),
            cleanup_interval_secs: parse_env("CLEANUP_INTERVAL_SECS", 3600),
            max_unpruned_batches: parse_env("MAX_UNPRUNED_BATCHES", 10_000),
            metrics_token: std::env::var("METRICS_TOKEN")
                .ok()
                .filter(|s| !s.is_empty()),
            session_expiry_secs: parse_env("SESSION_EXPIRY_SECS", 2_592_000),
            nonce_expiry_secs: parse_env("NONCE_EXPIRY_SECS", 60),
            nonce_rate_limit: parse_env("NONCE_RATE_LIMIT", 10),
            nonce_rate_window_secs: parse_env("NONCE_RATE_WINDOW_SECS", 60),
            snapshot_default_ttl_secs: parse_env("SNAPSHOT_DEFAULT_TTL_SECS", 86400),
        }
    }
}

fn parse_env<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
