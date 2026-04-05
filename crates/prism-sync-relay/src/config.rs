/// Application configuration, loaded from environment variables.
#[derive(Clone)]
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
    /// Leading zero bits required for first-device PoW admission.
    /// Set to 0 to disable PoW gating.
    pub first_device_pow_difficulty_bits: u8,
    /// Max nonces per sync_id within the rate limit window.
    pub nonce_rate_limit: u32,
    /// Sliding window duration in seconds for nonce rate limiting.
    pub nonce_rate_window_secs: u64,
    /// Max revoke operations per sync group within revoke_rate_window_secs.
    pub revoke_rate_limit: u32,
    /// Sliding window duration in seconds for revoke rate limiting.
    pub revoke_rate_window_secs: u64,
    /// Max allowed absolute clock skew for signed requests.
    pub signed_request_max_skew_secs: i64,
    /// Replay window (seconds) for signed request nonces.
    pub signed_request_nonce_window_secs: u64,
    /// Default TTL in seconds for ephemeral snapshots (24 hours).
    pub snapshot_default_ttl_secs: u64,
    /// How long revoked device tombstones should be retained before cleanup.
    pub revoked_tombstone_retention_secs: u64,
    /// Number of read-only SQLite connections in the reader pool.
    pub reader_pool_size: usize,
    /// URL of node-exporter for /metrics/node proxy (e.g. http://node-exporter:9100).
    /// If unset, the endpoint returns 404.
    pub node_exporter_url: Option<String>,
    /// Enable Apple App Attest as a first-device admission signal.
    pub first_device_apple_attestation_enabled: bool,
    /// Trust anchors for Apple App Attest verification, PEM-encoded.
    pub first_device_apple_attestation_trust_roots_pem: Vec<String>,
    /// Allowlisted Apple app IDs (TEAMID.bundle_id) that may present App Attest.
    pub first_device_apple_attestation_allowed_app_ids: Vec<String>,
    /// Enable Android hardware-backed attestation as a first-device admission signal.
    pub first_device_android_attestation_enabled: bool,
    /// Trust anchors for Android hardware attestation verification, PEM-encoded.
    pub first_device_android_attestation_trust_roots_pem: Vec<String>,
    /// Allowlisted verified boot keys (hex-encoded) that identify GrapheneOS devices.
    pub grapheneos_verified_boot_key_allowlist: Vec<String>,
    /// Registration token for access control. When set, both registration
    /// endpoints require this token in the X-Registration-Token header.
    ///
    /// Resolution order (handled by [`resolve_registration_token`]):
    /// 1. `REGISTRATION_TOKEN` env var (explicit config, highest priority)
    /// 2. `{db_dir}/.registration-token` file (auto-generated on first boot)
    /// 3. Neither → generate a random token, write it to the file, log it
    ///
    /// To explicitly run open registration, set `REGISTRATION_TOKEN=OPEN`.
    pub registration_token: Option<String>,
    /// Whether registration is enabled at all. When false, all registration
    /// endpoints return 403. Use this to lock down a relay after initial setup.
    pub registration_enabled: bool,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("db_path", &self.db_path)
            .field("port", &self.port)
            .field("registration_token", &self.registration_token.as_ref().map(|_| "[REDACTED]"))
            .field("registration_enabled", &self.registration_enabled)
            .field("metrics_token", &self.metrics_token.as_ref().map(|_| "[REDACTED]"))
            .field("reader_pool_size", &self.reader_pool_size)
            .finish_non_exhaustive()
    }
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
            first_device_pow_difficulty_bits: parse_env("FIRST_DEVICE_POW_DIFFICULTY_BITS", 18),
            nonce_rate_limit: parse_env("NONCE_RATE_LIMIT", 10),
            nonce_rate_window_secs: parse_env("NONCE_RATE_WINDOW_SECS", 60),
            revoke_rate_limit: parse_env("REVOKE_RATE_LIMIT", 2),
            revoke_rate_window_secs: parse_env("REVOKE_RATE_WINDOW_SECS", 3600),
            signed_request_max_skew_secs: parse_env("SIGNED_REQUEST_MAX_SKEW_SECS", 60),
            signed_request_nonce_window_secs: parse_env("SIGNED_REQUEST_NONCE_WINDOW_SECS", 120),
            snapshot_default_ttl_secs: parse_env("SNAPSHOT_DEFAULT_TTL_SECS", 86400),
            revoked_tombstone_retention_secs: parse_env(
                "REVOKED_TOMBSTONE_RETENTION_SECS",
                2_592_000,
            ),
            reader_pool_size: parse_env("READER_POOL_SIZE", 4),
            node_exporter_url: std::env::var("NODE_EXPORTER_URL")
                .ok()
                .filter(|s| !s.is_empty()),
            first_device_apple_attestation_enabled: parse_bool_env(
                "FIRST_DEVICE_APPLE_ATTESTATION_ENABLED",
                false,
            ),
            first_device_apple_attestation_trust_roots_pem: parse_json_vec_env(
                "FIRST_DEVICE_APPLE_ATTESTATION_TRUST_ROOTS_PEM",
                Vec::new(),
            ),
            first_device_apple_attestation_allowed_app_ids: parse_json_vec_env(
                "FIRST_DEVICE_APPLE_ATTESTATION_ALLOWED_APP_IDS",
                Vec::new(),
            ),
            first_device_android_attestation_enabled: parse_bool_env(
                "FIRST_DEVICE_ANDROID_ATTESTATION_ENABLED",
                true,
            ),
            first_device_android_attestation_trust_roots_pem: parse_json_vec_env(
                "FIRST_DEVICE_ANDROID_ATTESTATION_TRUST_ROOTS_PEM",
                default_android_attestation_roots(),
            ),
            grapheneos_verified_boot_key_allowlist: parse_json_vec_env(
                "GRAPHENEOS_VERIFIED_BOOT_KEY_ALLOWLIST",
                Vec::new(),
            ),
            registration_token: std::env::var("REGISTRATION_TOKEN")
                .ok()
                .filter(|s| !s.is_empty()),
            registration_enabled: parse_bool_env("REGISTRATION_ENABLED", true),
        }
    }

    /// Maximum first-device nonce requests permitted per window.
    pub fn first_device_nonce_rate_limit(&self) -> u32 {
        parse_env("FIRST_DEVICE_NONCE_RATE_LIMIT", 3)
    }

    /// Sliding window for first-device nonce rate limiting.
    pub fn first_device_nonce_rate_window_secs(&self) -> u64 {
        parse_env("FIRST_DEVICE_NONCE_RATE_WINDOW_SECS", 60)
    }

    /// Maximum first-device registration attempts permitted per window.
    pub fn first_device_registration_rate_limit(&self) -> u32 {
        parse_env("FIRST_DEVICE_REGISTRATION_RATE_LIMIT", 3)
    }

    /// Sliding window for first-device registration rate limiting.
    pub fn first_device_registration_rate_window_secs(&self) -> u64 {
        parse_env("FIRST_DEVICE_REGISTRATION_RATE_WINDOW_SECS", 60)
    }

    /// Maximum new-group creations permitted per window.
    pub fn first_device_group_rate_limit(&self) -> u32 {
        parse_env("FIRST_DEVICE_GROUP_RATE_LIMIT", 3)
    }

    /// Sliding window for new-group creation rate limiting.
    pub fn first_device_group_rate_window_secs(&self) -> u64 {
        parse_env("FIRST_DEVICE_GROUP_RATE_WINDOW_SECS", 600)
    }

    /// Brand-new groups get a much smaller unpruned batch budget until they age out.
    pub fn brand_new_group_max_unpruned_batches(&self) -> u64 {
        let cap = parse_env(
            "BRAND_NEW_GROUP_MAX_UNPRUNED_BATCHES",
            self.max_unpruned_batches / 10,
        );
        cap.max(10).min(self.max_unpruned_batches.max(1))
    }

    /// Age threshold after which a group is no longer treated as brand-new.
    pub fn brand_new_group_age_secs(&self) -> u64 {
        parse_env("BRAND_NEW_GROUP_AGE_SECS", 86_400)
    }

    /// Abandoned brand-new groups are eligible for cleanup after this long.
    pub fn abandoned_brand_new_group_ttl_secs(&self) -> u64 {
        parse_env(
            "ABANDONED_BRAND_NEW_GROUP_TTL_SECS",
            self.sync_inactive_ttl_secs,
        )
    }

    /// Resolve the registration token using the priority chain:
    /// 1. `REGISTRATION_TOKEN` env var — if "OPEN", clears the token (open mode)
    /// 2. `{db_dir}/.registration-token` file
    /// 3. Generate a random token, write it to the file, log it
    pub fn resolve_registration_token(&mut self) {
        // If env var was set, it's already in self.registration_token from from_env().
        if let Some(ref token) = self.registration_token {
            if token.eq_ignore_ascii_case("OPEN") {
                tracing::warn!(
                    "REGISTRATION_TOKEN=OPEN — registration is open to anyone. \
                     Only use this behind a VPN/firewall."
                );
                self.registration_token = None;
                return;
            }
            tracing::info!("Registration token loaded from environment variable");
            return;
        }

        // No env var — try the file next to the database.
        let db_dir = std::path::Path::new(&self.db_path)
            .parent()
            .unwrap_or(std::path::Path::new("."));
        let token_path = db_dir.join(".registration-token");

        if let Ok(contents) = std::fs::read_to_string(&token_path) {
            let token = contents.trim().to_string();
            if !token.is_empty() {
                tracing::info!(
                    path = %token_path.display(),
                    "Registration token loaded from file"
                );
                self.registration_token = Some(token);
                return;
            }
        }

        // Neither env var nor file — generate, persist, and log.
        let token = generate_random_token();
        if let Some(parent) = token_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::write(&token_path, &token) {
            Ok(()) => {
                tracing::info!(
                    path = %token_path.display(),
                    "Generated and saved registration token to file"
                );
            }
            Err(e) => {
                tracing::error!(
                    path = %token_path.display(),
                    error = %e,
                    "Failed to write registration token file — token will be ephemeral"
                );
            }
        }
        tracing::warn!(
            "\n\n\
             ╔══════════════════════════════════════════════════════════════╗\n\
             ║  AUTO-GENERATED REGISTRATION TOKEN                         ║\n\
             ║                                                            ║\n\
             ║  {token:<52}  ║\n\
             ║                                                            ║\n\
             ║  Enter this token in the Prism app when connecting.        ║\n\
             ║  To use your own token, set the REGISTRATION_TOKEN         ║\n\
             ║  environment variable.                                     ║\n\
             ╚══════════════════════════════════════════════════════════════╝\n"
        );
        self.registration_token = Some(token);
    }
}

fn parse_env<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn parse_bool_env(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
        .unwrap_or(default)
}

fn parse_json_vec_env(key: &str, default: Vec<String>) -> Vec<String> {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .and_then(|value| serde_json::from_str::<Vec<String>>(&value).ok())
        .unwrap_or(default)
}

fn generate_random_token() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    hex::encode(bytes)
}

fn default_android_attestation_roots() -> Vec<String> {
    vec![
        include_str!("android_attestation_roots/root_rsa.pem").to_string(),
        include_str!("android_attestation_roots/root_p384.pem").to_string(),
    ]
}
