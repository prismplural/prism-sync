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
    /// TTL for pairing sessions in seconds. Default: 300 (5 minutes).
    pub pairing_session_ttl_secs: u64,
    /// Maximum pairing session creation rate per IP per minute.
    pub pairing_session_rate_limit: u32,
    /// Maximum payload size for pairing session slots (bytes).
    pub pairing_session_max_payload_bytes: usize,
    /// TTL in seconds for sharing-init payloads (default 7 days).
    pub sharing_init_ttl_secs: u64,
    /// Maximum size in bytes for sharing-init payloads.
    pub sharing_init_max_payload_bytes: usize,
    /// Maximum size in bytes for sharing identity bundles.
    pub sharing_identity_max_bytes: usize,
    /// Maximum size in bytes for sharing signed prekey bundles.
    pub sharing_prekey_max_bytes: usize,
    /// Max fetch-bundle requests per IP within 300s window.
    pub sharing_fetch_rate_limit: u32,
    /// Max sharing-init uploads per sync_id within 3600s window.
    pub sharing_init_rate_limit: u32,
    /// Max pending (unconsumed) sharing-init payloads per recipient.
    pub sharing_init_max_pending: u32,
    /// Maximum age (in seconds) for a prekey upload. Reject prekeys with
    /// `created_at` older than this. Default: 604800 (7 days).
    pub prekey_upload_max_age_secs: i64,
    /// Maximum age (in seconds) for serving a prekey to a sender. Return 404
    /// if the best prekey is older than this. Default: 2592000 (30 days).
    pub prekey_serve_max_age_secs: i64,
    /// Maximum clock skew (in seconds) allowed for prekey timestamps in the
    /// future. Default: 300 (5 minutes).
    pub prekey_max_future_skew_secs: i64,
    /// Minimum accepted signature version byte (default: 3).
    /// Signatures with a version below this are rejected with 403.
    pub min_signature_version: u8,
    /// Directory where uploaded media blobs are stored on disk.
    pub media_storage_path: String,
    /// Maximum size in bytes for a single media upload.
    pub media_max_file_bytes: usize,
    /// Per-sync-group storage quota in bytes.
    pub media_quota_bytes_per_group: u64,
    /// Number of days before unreferenced media is eligible for cleanup.
    pub media_retention_days: u64,
    /// Maximum media uploads per sync group within the rate window.
    pub media_upload_rate_limit: u32,
    /// Sliding window duration in seconds for media upload rate limiting.
    pub media_upload_rate_window_secs: u64,
    /// Interval in seconds for cleaning up orphaned media files.
    pub media_orphan_cleanup_secs: u64,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("db_path", &self.db_path)
            .field("port", &self.port)
            .field(
                "registration_token",
                &self.registration_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("registration_enabled", &self.registration_enabled)
            .field(
                "metrics_token",
                &self.metrics_token.as_ref().map(|_| "[REDACTED]"),
            )
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
            pairing_session_ttl_secs: parse_env("PAIRING_SESSION_TTL_SECS", 300),
            pairing_session_rate_limit: parse_env("PAIRING_SESSION_RATE_LIMIT", 5),
            pairing_session_max_payload_bytes: parse_env(
                "PAIRING_SESSION_MAX_PAYLOAD_BYTES",
                262144, // 256 KB — PQ credential bundles with ML-DSA/ML-KEM/X-Wing keys
            ),
            sharing_init_ttl_secs: parse_env("SHARING_INIT_TTL_SECS", 604800),
            sharing_init_max_payload_bytes: parse_env("SHARING_INIT_MAX_PAYLOAD_BYTES", 65536),
            sharing_identity_max_bytes: parse_env("SHARING_IDENTITY_MAX_BYTES", 8192),
            sharing_prekey_max_bytes: parse_env("SHARING_PREKEY_MAX_BYTES", 4096),
            sharing_fetch_rate_limit: parse_env("SHARING_FETCH_RATE_LIMIT", 20),
            sharing_init_rate_limit: parse_env("SHARING_INIT_RATE_LIMIT", 10),
            sharing_init_max_pending: parse_env("SHARING_INIT_MAX_PENDING", 50),
            prekey_upload_max_age_secs: parse_env("PREKEY_UPLOAD_MAX_AGE_SECS", 604800),
            prekey_serve_max_age_secs: parse_env("PREKEY_SERVE_MAX_AGE_SECS", 2_592_000),
            prekey_max_future_skew_secs: parse_env("PREKEY_MAX_FUTURE_SKEW_SECS", 300),
            min_signature_version: parse_env("MIN_SIGNATURE_VERSION", 3),
            media_storage_path: std::env::var("MEDIA_STORAGE_PATH")
                .unwrap_or_else(|_| "data/media".into()),
            media_max_file_bytes: parse_env("MEDIA_MAX_FILE_BYTES", 10_485_760),
            media_quota_bytes_per_group: parse_env("MEDIA_QUOTA_BYTES_PER_GROUP", 1_073_741_824),
            media_retention_days: parse_env("MEDIA_RETENTION_DAYS", 90),
            media_upload_rate_limit: parse_env("MEDIA_UPLOAD_RATE_LIMIT", 10),
            media_upload_rate_window_secs: parse_env("MEDIA_UPLOAD_RATE_WINDOW_SECS", 60),
            media_orphan_cleanup_secs: parse_env("MEDIA_ORPHAN_CLEANUP_SECS", 86400),
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
