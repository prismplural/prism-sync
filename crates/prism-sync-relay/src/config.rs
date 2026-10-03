pub const MIN_SIGNATURE_VERSION_SOURCE_FLOOR: u8 = 3;
const GENERATED_REGISTRATION_TOKEN_LOG_MESSAGE: &str =
    "Generated registration token. Read it from the token file; the full token is not printed in logs.";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("MIN_SIGNATURE_VERSION={configured} is below source floor {floor}; refusing to start")]
    MinSignatureVersionBelowSourceFloor { configured: u8, floor: u8 },
    #[error(
        "FIRST_DEVICE_APPLE_ATTESTATION_ENABLED=true requires FIRST_DEVICE_APPLE_ATTESTATION_TRUST_ROOTS_PEM"
    )]
    AppleAttestationEnabledWithoutTrustRoots,
    #[error(
        "FIRST_DEVICE_ANDROID_ATTESTATION_ENABLED=true requires FIRST_DEVICE_ANDROID_ATTESTATION_TRUST_ROOTS_PEM"
    )]
    AndroidAttestationEnabledWithoutTrustRoots,
    #[error("{key} must be >= 1 (a zero concurrency cap blocks requests indefinitely)")]
    ConcurrencyLimitZero { key: &'static str },
    /// Snapshot file backing was explicitly requested but the derived snapshot
    /// storage root cannot be trusted (relative path, non-absolute, or not
    /// creatable/writable). Refuse startup rather than risk writing snapshot
    /// blobs to an ephemeral or unwritable location while the DB row still
    /// commits — that would publish rows whose bytes are gone.
    #[error(
        "SNAPSHOT_FILE_BACKING_ENABLED=true but snapshot storage root is unusable ({reason}); \
         set MEDIA_STORAGE_PATH to an absolute path on a writable persistent volume, or set \
         SNAPSHOT_FILE_BACKING_ENABLED=false to retain inline snapshot writes"
    )]
    SnapshotStorageInvalid { reason: String },
}

/// Resolved runtime policy for where `PUT /snapshot` stores its bytes.
///
/// Decided once at startup by [`Config::resolve_snapshot_storage`] and held on
/// `AppState`. The file-backed variant carries the **canonicalized** root, so
/// every subsequent path join starts from a resolved, symlink-free directory
/// rather than re-resolving the raw config string per request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotStorage {
    /// Write snapshot bytes to `<root>/<sync_id>/<blob_ref>`.
    FileBacked(std::path::PathBuf),
    /// Keep snapshot bytes inline in the SQLite `snapshots.data` column — the
    /// legacy behavior, retained when the file-backed root failed validation.
    Inline,
}

impl SnapshotStorage {
    /// True when single PUT should write snapshot bytes to a file.
    pub fn is_file_backed(&self) -> bool {
        matches!(self, Self::FileBacked(_))
    }

    /// The canonical storage root, when file-backed.
    pub fn root(&self) -> Option<&std::path::Path> {
        match self {
            Self::FileBacked(root) => Some(root),
            Self::Inline => None,
        }
    }
}

// ── Pairing lease protocol constants ─────────────────────────────────────────
//
// These mirror `prism_sync_core::pairing::lease` exactly. The relay crate is
// deliberately standalone (it must not depend on core), so the values are
// duplicated here and held in lockstep by
// `tests/relay_pairing_lease_parity.rs`, which imports both crates. That test
// is the drift alarm: changing one side without the other fails CI rather than
// silently splitting the wire contract.

/// Lease protocol version understood by this relay (v1).
pub const PAIRING_LEASE_VERSION_V1: u16 = 1;

/// Length of the random `pairing_lease_secret` (and therefore of
/// `SHA-256(secret)`), in bytes. The renew route accepts an exact-length body.
pub const PAIRING_LEASE_SECRET_LEN: usize = 32;

/// Exact request-body length accepted by `POST /v1/pairing/{id}/lease/renew`.
pub const PAIRING_LEASE_RENEW_REQUEST_BODY_LEN: usize = PAIRING_LEASE_SECRET_LEN;

/// Defensive transport cap for the renewal request body, in bytes.
///
/// Deliberately **larger** than [`PAIRING_LEASE_RENEW_REQUEST_BODY_LEN`]. It
/// bounds how much the handler buffers: `renew_lease` reads the body through a
/// `to_bytes` call capped here and collapses a read failure — including an
/// over-cap body — to the same uniform 404 the semantic length check returns. A
/// layer-imposed limit would instead answer with a *different* status, which is
/// the oracle the uniform response exists to remove, so the bound is applied in
/// the handler rather than as a route layer.
///
/// This is not the only ceiling in practice: the public router still carries the
/// global 10 MiB `RequestBodyLimitLayer`, so a body above that is rejected by the
/// layer before the handler runs. Every size at or below it, which is every
/// request this endpoint could plausibly receive, is answered uniformly.
pub const PAIRING_LEASE_RENEW_MAX_BODY_BYTES: usize = 1024;

/// Idle expiry granted by a valid lease renewal (v1 = 30 minutes). The same
/// constant is enforced in `db::renew_pairing_lease`.
pub const PAIRING_LEASE_IDLE_EXTENSION_SECS: i64 = 1800;

/// Absolute, nonrenewable lease cap measured from the first valid renewal
/// (v1 = 4 hours).
pub const PAIRING_LEASE_ABSOLUTE_CAP_SECS: i64 = 14400;

/// Deployment default cap on concurrently leased pairing rows (v1 = 256).
pub const PAIRING_LEASE_MAX_CONCURRENT_SESSIONS: u32 = 256;

/// Effective default renewal limiter size: per trusted-proxy-derived client IP,
/// per [`PairingLeaseConfig::renew_rate_window_secs`].
///
/// The legitimate maximum is one renewal per active ceremony per five minutes
/// (plus one final renewal immediately before credential release), so 120 per
/// minute leaves room for many concurrent ceremonies behind one client IP — a
/// shared home NAT or an app reconnecting — without ever being reachable by
/// honest traffic. The per-rendezvous failure bucket, not this limiter, is what
/// bounds a single hostile source.
pub const PAIRING_LEASE_DEFAULT_RENEW_RATE_LIMIT: u32 = 120;

/// Default window for [`PairingLeaseConfig::renew_rate_limit`], in seconds.
pub const PAIRING_LEASE_DEFAULT_RENEW_RATE_WINDOW_SECS: u64 = 60;

/// Default bound on *failed* verifier attempts per presented rendezvous ID per
/// [`PairingLeaseConfig::failure_window_secs`].
pub const PAIRING_LEASE_DEFAULT_FAILURE_LIMIT: u32 = 20;

/// Default window for the per-rendezvous failure bucket, in seconds.
pub const PAIRING_LEASE_DEFAULT_FAILURE_WINDOW_SECS: u64 = 60;

/// Opaque pairing-lease (v1) runtime configuration.
///
/// Split out of [`Config`] so it has a `Default` and so `Config` literals stay
/// readable. Every field is bounded by an accessor on [`Config`] that enforces a
/// non-degenerate value, because a `0` cap or a `0`-second window would be a
/// deployment footgun rather than a useful setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairingLeaseConfig {
    /// Whether this relay offers the opaque pairing lease (v1) at all.
    ///
    /// Dark by default. When `false`, a create request offering lease metadata
    /// is accepted as an ordinary fixed-TTL session with no `lease_version`
    /// echo, and the renew route returns the same uniform not-found as an
    /// unknown rendezvous. Withholding the capability is always a safe
    /// downgrade: clients fall back to fixed-TTL pairing.
    pub enabled: bool,
    /// Global cap on concurrently leased pairing rows, passed to
    /// [`crate::db::renew_pairing_lease`]. Accessor-clamped to at least 1.
    pub max_concurrent_sessions: u32,
    /// Max lease renewals per trusted-proxy-derived client IP per
    /// [`Self::renew_rate_window_secs`].
    pub renew_rate_limit: u32,
    /// Sliding window in seconds for the per-client-IP renewal limiter.
    pub renew_rate_window_secs: u64,
    /// Max *failed* verifier attempts per presented rendezvous ID per
    /// [`Self::failure_window_secs`].
    ///
    /// Counts failures only, so a successful renewal can never be starved by
    /// garbage that merely knows the rendezvous ID.
    pub failure_limit: u32,
    /// Sliding window in seconds for the per-rendezvous failure bucket.
    pub failure_window_secs: u64,
}

impl Default for PairingLeaseConfig {
    fn default() -> Self {
        Self {
            // Dark by default: enablement is a deliberate per-deployment act.
            enabled: false,
            max_concurrent_sessions: PAIRING_LEASE_MAX_CONCURRENT_SESSIONS,
            renew_rate_limit: PAIRING_LEASE_DEFAULT_RENEW_RATE_LIMIT,
            renew_rate_window_secs: PAIRING_LEASE_DEFAULT_RENEW_RATE_WINDOW_SECS,
            failure_limit: PAIRING_LEASE_DEFAULT_FAILURE_LIMIT,
            failure_window_secs: PAIRING_LEASE_DEFAULT_FAILURE_WINDOW_SECS,
        }
    }
}

/// Whether `SNAPSHOT_FILE_BACKING_ENABLED` was set in the environment.
///
/// An explicit `true` means an invalid storage root must refuse startup; an
/// unset or explicit `false` allows the inline fallback. Kept separate from
/// [`Config`] because it is a one-time startup decision, not runtime config.
pub fn snapshot_file_backing_explicitly_requested(env: impl Fn(&str) -> Option<String>) -> bool {
    env("SNAPSHOT_FILE_BACKING_ENABLED")
        .map(|v| v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Resource policy for resumable snapshot uploads (lean v1).
///
/// Protocol shape is **not** configurable here: the chunk size, wire maximum,
/// and TTL ceilings live in [`crate::uploads`] as compile-time constants. What a
/// deployment can tune is the resource envelope around them — quotas, free-space
/// reserve, rate limit, and concurrency — plus the single enable switch.
///
/// # Dark by default
///
/// `enabled` defaults to `false`. Even when set, capability is advertised only
/// if file-backed snapshot storage is live, because a resumable session stages
/// bytes on disk and publishing a reference into an inline-only deployment would
/// be unsafe. Withholding the capability is always a safe downgrade: clients
/// fall back to the existing single `PUT /snapshot`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotUploadConfig {
    /// Whether this relay offers resumable snapshot uploads at all.
    ///
    /// Requires `SNAPSHOT_FILE_BACKING_ENABLED`-equivalent storage resolution to
    /// have produced a file-backed root; see [`Config::snapshot_upload_supported`].
    pub enabled: bool,
    /// Ceiling on bytes reserved by nonterminal sessions in one group.
    pub group_reserved_bytes: u64,
    /// Ceiling on bytes reserved by nonterminal sessions across the relay.
    pub global_reserved_bytes: u64,
    /// Free space that must remain after reserving an upload's declared bytes.
    pub free_space_reserve_bytes: u64,
    /// Max create requests per uploader device per `create_rate_window_secs`.
    pub create_rate_limit: u32,
    /// Sliding window for the per-device create limiter, in seconds.
    pub create_rate_window_secs: u64,
    /// Max simultaneous in-flight chunk writes. Exceeding it sheds with a
    /// retryable `503 upload_busy`, never a quota-coded 429.
    pub chunk_concurrency: usize,
}

impl Default for SnapshotUploadConfig {
    fn default() -> Self {
        Self {
            // Dark by default: enablement is a deliberate per-deployment act.
            enabled: false,
            group_reserved_bytes: crate::uploads::SNAPSHOT_UPLOAD_DEFAULT_GROUP_RESERVED_BYTES,
            global_reserved_bytes: crate::uploads::SNAPSHOT_UPLOAD_DEFAULT_GLOBAL_RESERVED_BYTES,
            free_space_reserve_bytes:
                crate::uploads::SNAPSHOT_UPLOAD_DEFAULT_FREE_SPACE_RESERVE_BYTES,
            create_rate_limit: crate::uploads::SNAPSHOT_UPLOAD_DEFAULT_CREATE_RATE_LIMIT,
            create_rate_window_secs:
                crate::uploads::SNAPSHOT_UPLOAD_DEFAULT_CREATE_RATE_WINDOW_SECS,
            chunk_concurrency: crate::uploads::SNAPSHOT_UPLOAD_DEFAULT_CHUNK_CONCURRENCY,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GifProviderMode {
    Disabled,
    PrismHosted,
    SelfHosted,
}

impl GifProviderMode {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "disabled" => Some(Self::Disabled),
            "prism_hosted" | "prism-hosted" => Some(Self::PrismHosted),
            "self_hosted" | "self-hosted" => Some(Self::SelfHosted),
            _ => None,
        }
    }
}

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
    /// Absolute maximum lifetime of a session, measured from `created_at`
    /// (the last full re-authentication), independent of the sliding
    /// `session_expiry_secs` window. Once a session is older than this it is
    /// rejected even if it has been kept warm by activity, forcing a re-auth.
    /// Default: 7,776,000 (90 days).
    pub session_max_age_secs: u64,
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
    /// Max WebSocket upgrade attempts per client IP within ws_upgrade_rate_window_secs.
    pub ws_upgrade_rate_limit: u32,
    /// Sliding window duration in seconds for WebSocket upgrade rate limiting.
    pub ws_upgrade_rate_window_secs: u64,
    /// Reverse proxy CIDR ranges whose forwarded client IP headers are trusted.
    pub trusted_proxy_cidrs: Vec<String>,
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
    /// 3. Neither → generate a random token, write it to the file, log the file path
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
    /// Opaque pairing lease (v1) configuration. Grouped into one value so it
    /// carries a `Default` and so every existing `Config` literal gains exactly
    /// one field rather than six.
    pub pairing_lease: PairingLeaseConfig,
    /// Resumable snapshot upload (lean v1) resource policy. Grouped like
    /// [`Self::pairing_lease`] so existing `Config` literals gain one field.
    /// Dark by default; see [`Config::snapshot_upload_supported`].
    pub snapshot_upload: SnapshotUploadConfig,
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
    /// Minimum accepted signature version byte.
    /// Signatures with a version below this are rejected with 403.
    pub min_signature_version: u8,
    /// Directory where uploaded media blobs are stored on disk.
    ///
    /// Snapshot blobs are derived from this root as a sibling directory
    /// ([`Config::snapshot_storage_path`]) so both trees share one persistent
    /// volume mount and one backup story. Container deployments must set this
    /// to an explicit absolute path (`MEDIA_STORAGE_PATH=/data/media`) on the
    /// writable persistent mount.
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
    /// Minimum per-blob TTL (seconds) an `X-Media-TTL` upload may request. Floors
    /// churny sub-minute TTLs; the relay clamps a requested TTL to
    /// `[media_resupply_ttl_min_secs, media_retention_days]`.
    pub media_resupply_ttl_min_secs: u64,
    /// Grace window (seconds) before an un-finalized PENDING media reserve is
    /// reaped as abandoned. Must be ≫ a normal promote so a healthy in-flight
    /// upload is never reaped.
    pub media_pending_grace_secs: u64,
    /// Maximum expired media rows a single upload's always-sweep reclaims before
    /// the quota preflight. Bounds per-upload work; the cleanup loop is the
    /// catch-all backstop.
    pub media_expired_sweep_cap: u32,
    /// Per-group ceiling, in bytes, on live EPHEMERAL (TTL-bearing) media.
    /// Covers re-supply/heal and pairing-push uploads as a preflight soft cap.
    pub media_resupply_byte_ceiling_bytes: u64,
    /// Re-supply/heal uploads allowed per group within
    /// `media_resupply_rate_window_secs` — a separate lane from fresh-send so
    /// heal can't starve normal sends.
    pub media_resupply_rate_limit: u32,
    /// Sliding window in seconds for the re-supply rate limiter.
    pub media_resupply_rate_window_secs: u64,
    /// Pairing-push uploads allowed per group within
    /// `media_pairing_push_rate_window_secs` — a separate, more generous bucket
    /// (vs re-supply) so a joiner-bootstrap burst can't consume the group's
    /// fresh-send budget and heal/pairing don't contend.
    pub media_pairing_push_rate_limit: u32,
    /// Sliding window in seconds for the pairing-push limiter.
    pub media_pairing_push_rate_window_secs: u64,
    /// Device-message mailbox TTL in seconds for a
    /// stored mailbox message (default 7 days). Short, so the mailbox sheds fast.
    pub device_message_ttl_secs: u64,
    /// Max size in bytes of a mailbox payload BLOB. Clients send a fixed-size
    /// padded payload; this caps it (≤ 4 KiB) as the DoS bound.
    pub device_message_max_payload_bytes: usize,
    /// Per-sender-device mailbox sends allowed within
    /// `device_message_send_rate_window_secs` — the real request-storm bound (the
    /// requester's per-media cooldown is device-local/advisory).
    pub device_message_send_rate_limit: u32,
    /// Sliding window in seconds for the mailbox send rate limiter.
    pub device_message_send_rate_window_secs: u64,
    /// Max non-expired mailbox messages a single sender may hold outstanding
    /// (per-sender pending cap), bounding stored bytes + recipient drain work.
    /// Sized so a few genuinely-missing blobs can retry across the full mailbox
    /// TTL without blocking `media_uploaded` announces.
    pub device_message_max_pending: u32,
    /// Max messages returned by one GET-pending mailbox drain (clients page).
    pub device_message_fetch_limit: u32,
    /// Wall-clock timeout applied to most non-WebSocket routes. Returns 408 on
    /// expiry. Heavy upload routes (snapshot, media) have their own longer
    /// timeouts so large transfers over slow connections don't trip this cap.
    pub default_request_timeout_secs: u64,
    /// Timeout for PUT /v1/sync/{sync_id}/snapshot. Encrypted snapshots up to
    /// `MAX_SNAPSHOT_WIRE_BYTES` (~150 MB) need significantly longer than the
    /// default to upload over slow mobile links.
    pub snapshot_request_timeout_secs: u64,
    /// Timeout for media upload/download. Sized between the default and the
    /// snapshot timeout because `media_max_file_bytes` is smaller. Covers
    /// request handling through response headers only; streaming response
    /// bodies (downloads) continue past this deadline.
    pub media_request_timeout_secs: u64,
    /// Maximum simultaneous in-flight snapshot PUTs. Each upload buffers the
    /// full body in memory before signature verification, so this directly
    /// bounds peak memory. Must be >= 1; zero would deadlock the route.
    pub snapshot_upload_concurrency: usize,
    /// Maximum simultaneous in-flight media upload/download requests. Same
    /// memory-bounding intent as `snapshot_upload_concurrency`. Must be >= 1.
    pub media_upload_concurrency: usize,
    /// Maximum simultaneous in-flight requests on light (non-heavy-upload)
    /// routes. Replaces the historical global concurrency cap. Must be >= 1.
    pub default_request_concurrency: usize,
    /// GIF provider mode for chat GIF search.
    pub gif_provider_mode: GifProviderMode,
    /// Public base URL that clients should use for GIF API calls when this relay
    /// serves the proxy itself. Relative paths are allowed.
    pub gif_public_base_url: Option<String>,
    /// Prism-hosted GIF API base URL advertised to clients when this relay is in
    /// prism-hosted mode. Relative paths are not allowed.
    pub gif_prism_base_url: Option<String>,
    /// Upstream Klipy API base URL used by self-hosted GIF proxy mode.
    pub gif_api_base_url: String,
    /// Klipy API key used by self-hosted GIF proxy mode.
    pub gif_api_key: Option<String>,
    /// Timeout in seconds for upstream GIF API requests.
    pub gif_http_timeout_secs: u64,
    /// Max GIF proxy requests per client IP within the GIF rate limit window.
    pub gif_request_rate_limit: u32,
    /// Sliding window in seconds for GIF proxy rate limiting.
    pub gif_request_rate_window_secs: u64,
    /// Maximum accepted search query length in bytes before truncation.
    pub gif_query_max_len: usize,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("db_path", &self.db_path)
            .field("port", &self.port)
            .field("registration_token", &self.registration_token.as_ref().map(|_| "[REDACTED]"))
            .field("registration_enabled", &self.registration_enabled)
            .field("metrics_token", &self.metrics_token.as_ref().map(|_| "[REDACTED]"))
            .field("ws_upgrade_rate_limit", &self.ws_upgrade_rate_limit)
            .field("ws_upgrade_rate_window_secs", &self.ws_upgrade_rate_window_secs)
            .field("trusted_proxy_cidrs", &self.trusted_proxy_cidrs)
            .field("gif_provider_mode", &self.gif_provider_mode)
            .field("gif_public_base_url", &self.gif_public_base_url)
            .field("gif_prism_base_url", &self.gif_prism_base_url)
            .field("gif_api_base_url", &self.gif_api_base_url)
            .field("gif_api_key", &self.gif_api_key.as_ref().map(|_| "[REDACTED]"))
            .field("reader_pool_size", &self.reader_pool_size)
            .finish_non_exhaustive()
    }
}

impl Config {
    pub fn from_env() -> Self {
        match Self::try_from_env() {
            Ok(config) => config,
            Err(error) => panic!("invalid relay configuration: {error}"),
        }
    }

    /// On-disk root for file-backed snapshot blobs, derived as a sibling of
    /// `media_storage_path` (`<media_storage_path>-snapshots`). Deriving it
    /// rather than adding a separate setting keeps snapshot bytes co-located
    /// with media under the same parent directory, so they inherit media's
    /// volume mount and backup/at-rest story automatically — whatever
    /// `MEDIA_STORAGE_PATH` resolves to (or its `data/media` default), the
    /// snapshot tree follows. Like media, the bytes are stored verbatim (the
    /// already client-encrypted `SignedBatchEnvelope`); the relay adds no
    /// at-rest layer of its own.
    pub fn snapshot_storage_path(&self) -> String {
        format!("{}-snapshots", self.media_storage_path)
    }

    // ── Pairing lease ────────────────────────────────────────────────────────

    /// Whether this relay advertises and enforces the opaque pairing lease.
    ///
    /// This is the **capability gate**. The renew route and the create-time
    /// `lease_version` echo are both conditional on it, so an unconfigured
    /// relay behaves exactly like a pre-lease relay: create succeeds without an
    /// echo and renew returns the uniform not-found. That keeps the feature dark
    /// until a deployment deliberately turns it on.
    pub fn pairing_lease_supported(&self) -> bool {
        self.pairing_lease.enabled
    }

    // ── Resumable snapshot uploads (lean v1) ─────────────────────────────────

    /// Whether this relay advertises and accepts resumable snapshot uploads.
    ///
    /// Two independent gates, both required:
    ///
    /// 1. the operator turned the feature on (`SNAPSHOT_UPLOAD_ENABLED`), and
    /// 2. the resolved storage policy is **file-backed**, so a completed session
    ///    can publish a `blob_ref` rather than forcing a large inline BLOB write
    ///    under the SQLite writer mutex.
    ///
    /// The `storage` argument is the already-resolved
    /// [`SnapshotStorage`] policy, so capability can never disagree with what the
    /// routes will actually do. Withholding capability is always a safe
    /// downgrade: clients fall back to the existing single PUT.
    pub fn snapshot_upload_supported(&self, storage: &SnapshotStorage) -> bool {
        self.snapshot_upload.enabled && storage.is_file_backed()
    }

    /// Effective chunk-write concurrency, clamped to at least 1 so a misconfigured
    /// zero cannot deadlock the chunk route.
    pub fn snapshot_upload_chunk_concurrency(&self) -> usize {
        self.snapshot_upload.chunk_concurrency.max(1)
    }

    /// Effective create-rate window: never zero, so the limiter cannot be turned
    /// into an unbounded counter by a `0`-second window.
    pub fn snapshot_upload_create_rate_window_secs(&self) -> u64 {
        self.snapshot_upload.create_rate_window_secs.max(1)
    }

    /// The capability object this relay advertises, or `None` when withheld.
    ///
    /// Advertised only when every prerequisite holds, including the resource
    /// ceilings being present, positive, and internally valid — the spec makes
    /// that gate unconditional because the binary cannot distinguish hosted from
    /// self-host operation. A deployment may be *stricter* than the protocol
    /// maxima, never looser: `max_wire_bytes` is the minimum of the configured
    /// ceilings and the protocol cap so a client can never be told it may send
    /// more than the relay will accept.
    pub fn snapshot_upload_capability(
        &self,
        storage: &SnapshotStorage,
    ) -> Option<crate::routes::uploads::SnapshotUploadCapability> {
        if !self.snapshot_upload_supported(storage) {
            return None;
        }
        if self.snapshot_upload.global_reserved_bytes == 0
            || self.snapshot_upload.group_reserved_bytes == 0
            || self.snapshot_upload.free_space_reserve_bytes == 0
            || self.snapshot_upload.group_reserved_bytes
                > self.snapshot_upload.global_reserved_bytes
        {
            return None;
        }
        Some(crate::routes::uploads::SnapshotUploadCapability {
            version: crate::uploads::SNAPSHOT_UPLOAD_VERSION_V1,
            chunk_bytes: crate::uploads::SNAPSHOT_UPLOAD_CHUNK_BYTES as u64,
            max_wire_bytes: crate::uploads::SNAPSHOT_UPLOAD_MAX_WIRE_BYTES,
            session_idle_ttl_secs: crate::uploads::SNAPSHOT_UPLOAD_IDLE_TTL_SECS as u64,
        })
    }

    // ── Pairing lease accessors ──────────────────────────────────────────────

    /// Global concurrently-leased cap actually handed to the DB layer.
    ///
    /// Clamped to at least 1: a `0` would make every *new* lease unobtainable
    /// (a row that is already leased still renews, since the cap is only
    /// consulted on the first renewal), which is a deployment footgun rather
    /// than a useful setting.
    pub fn pairing_lease_max_concurrent_sessions(&self) -> u32 {
        self.pairing_lease.max_concurrent_sessions.max(1)
    }

    /// Effective renewal window: never zero, so the limiter cannot be turned
    /// into an unbounded counter by a `0`-second window.
    pub fn pairing_lease_renew_rate_window_secs(&self) -> u64 {
        self.pairing_lease.renew_rate_window_secs.max(1)
    }

    /// Effective failure-bucket window: never zero.
    pub fn pairing_lease_failure_window_secs(&self) -> u64 {
        self.pairing_lease.failure_window_secs.max(1)
    }

    /// Validate that lease enablement has the proxy trust it needs.
    ///
    /// The renew endpoint's front limiter keys on the trusted-proxy-derived
    /// client IP. Behind a reverse proxy (hosted Prism runs behind Cloudflare
    /// Tunnel) with no `TRUSTED_PROXY_CIDRS` allowlist, every request appears to
    /// come from the tunnel peer, so **all** users collapse into one limiter
    /// bucket — a self-inflicted global throttle and a loss of the per-source
    /// bound. Refusing enablement without an allowlist makes that a startup
    /// error instead of a production incident.
    ///
    /// Self-host with direct peers needs no allowlist: the peer address *is* the
    /// client address, so the limiter is already correct. That is why this is a
    /// documented operator obligation rather than an unconditional requirement —
    /// see [`Config::pairing_lease_trusted_proxy_warning`].
    pub fn validate_pairing_lease_proxy_trust(
        &self,
        hosted_deployment: bool,
    ) -> Result<(), String> {
        if self.pairing_lease_supported()
            && hosted_deployment
            && self.trusted_proxy_cidrs.is_empty()
        {
            return Err(
                "PAIRING_LEASE_ENABLED=true in a hosted deployment requires a non-empty \
                 TRUSTED_PROXY_CIDRS allowlist; without it the lease renewal limiter would key \
                 every user on the tunnel peer address and collapse them into one bucket. Set \
                 TRUSTED_PROXY_CIDRS to the ingress ranges, or leave PAIRING_LEASE_ENABLED=false."
                    .to_string(),
            );
        }
        Ok(())
    }

    /// Non-fatal warning text for a lease-enabled relay with no proxy allowlist.
    ///
    /// Emitted at startup so a self-host operator (for whom direct peers are
    /// normal) still sees the tradeoff: if anything does front the relay, the
    /// renewal limiter degrades to one shared bucket.
    pub fn pairing_lease_trusted_proxy_warning(&self) -> Option<&'static str> {
        if self.pairing_lease_supported() && self.trusted_proxy_cidrs.is_empty() {
            return Some(
                "PAIRING_LEASE_ENABLED=true with no TRUSTED_PROXY_CIDRS: pairing lease renewal is \
                 rate limited by the direct peer address. This is correct for a relay reached \
                 directly, but if a reverse proxy or tunnel fronts this deployment, forwarded \
                 client IPs are ignored and all users share one limiter bucket. Set \
                 TRUSTED_PROXY_CIDRS to the ingress ranges in that case.",
            );
        }
        None
    }

    /// Resolve the snapshot storage root and prove it is safe for file-backed
    /// snapshot writes.
    ///
    /// Phase 0 gate: before any file-backed single PUT can run, the relay must
    /// know the derived root is an **absolute**, **writable**, **creatable**
    /// directory that path resolution can trust. A relative default like
    /// `data/media` resolves under the process CWD (in a container, the image
    /// workdir) and may be ephemeral or unwritable, which would let a snapshot
    /// row commit while its bytes were never durably stored. Failing validation
    /// is handled by the caller as either a startup refusal (when file backing
    /// was explicitly requested) or a downgrade to the legacy inline-BLOB write
    /// path — never a silent file-backed write against a bad root.
    ///
    /// Returns the canonicalized root on success. The `reason` on failure is a
    /// short operator-facing string; it never contains client input.
    pub fn validate_snapshot_storage(&self) -> Result<std::path::PathBuf, String> {
        let configured = self.snapshot_storage_path();
        let path = std::path::Path::new(&configured);
        if !path.is_absolute() {
            return Err(format!("{configured:?} is not an absolute path"));
        }
        // Create the root if needed. `create_dir_all` on an existing directory
        // is a no-op, so this both provisions first boot and tolerates the
        // already-mounted case.
        if let Err(e) = std::fs::create_dir_all(path) {
            return Err(format!("{configured:?} is not creatable: {e}"));
        }
        // Canonicalize so callers join against a resolved, symlink-free root.
        // A relative or dangling component would have failed above already.
        let canonical = match std::fs::canonicalize(path) {
            Ok(p) => p,
            Err(e) => return Err(format!("{configured:?} is not resolvable: {e}")),
        };
        // Prove writability with a real create-new probe rather than trusting
        // directory permission bits (they can lie under ACLs, read-only
        // bind-mounts, and full filesystems).
        if let Err(e) = probe_writable_dir(&canonical) {
            return Err(format!("{configured:?} is not writable: {e}"));
        }
        Ok(canonical)
    }

    /// Apply the snapshot storage gate, returning the resolved policy.
    ///
    /// Two acceptable outcomes, per the Phase 0 spec:
    /// - the root validates → [`SnapshotStorage::FileBacked`] with the
    ///   canonical root; or
    /// - the root does not validate and file backing was **not** explicitly
    ///   requested → log loudly and return [`SnapshotStorage::Inline`], so
    ///   single PUT retains the legacy inline-BLOB write path.
    ///
    /// `explicit_file_backing` is true only when the operator set
    /// `SNAPSHOT_FILE_BACKING_ENABLED` in the environment. In that case an
    /// invalid root is a hard [`ConfigError::SnapshotStorageInvalid`] (refuse
    /// startup) rather than a silent downgrade — a deploy that demanded file
    /// backing must not quietly run on ephemeral storage instead.
    pub fn resolve_snapshot_storage(
        &self,
        explicit_file_backing: bool,
    ) -> Result<SnapshotStorage, ConfigError> {
        match self.validate_snapshot_storage() {
            Ok(root) => Ok(SnapshotStorage::FileBacked(root)),
            Err(reason) => {
                if explicit_file_backing {
                    return Err(ConfigError::SnapshotStorageInvalid { reason });
                }
                tracing::warn!(
                    reason = %reason,
                    "snapshot storage root unusable — retaining inline snapshot writes \
                     (set MEDIA_STORAGE_PATH to an absolute persistent path, or set \
                     SNAPSHOT_FILE_BACKING_ENABLED=true to refuse startup instead)"
                );
                Ok(SnapshotStorage::Inline)
            }
        }
    }

    pub fn try_from_env() -> Result<Self, ConfigError> {
        Self::from_env_values(|key| std::env::var(key).ok())
    }

    fn from_env_values<F>(env: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let min_signature_version = parse_min_signature_version_env(
            &env,
            "MIN_SIGNATURE_VERSION",
            MIN_SIGNATURE_VERSION_SOURCE_FLOOR,
        )?;
        let first_device_apple_attestation_enabled =
            parse_bool_env_with(&env, "FIRST_DEVICE_APPLE_ATTESTATION_ENABLED", false);
        let first_device_apple_attestation_trust_roots_pem = parse_json_vec_env_with(
            &env,
            "FIRST_DEVICE_APPLE_ATTESTATION_TRUST_ROOTS_PEM",
            Vec::new(),
        );
        if first_device_apple_attestation_enabled
            && first_device_apple_attestation_trust_roots_pem.is_empty()
        {
            return Err(ConfigError::AppleAttestationEnabledWithoutTrustRoots);
        }
        let first_device_android_attestation_enabled =
            parse_bool_env_with(&env, "FIRST_DEVICE_ANDROID_ATTESTATION_ENABLED", true);
        let first_device_android_attestation_trust_roots_pem = parse_json_vec_env_with(
            &env,
            "FIRST_DEVICE_ANDROID_ATTESTATION_TRUST_ROOTS_PEM",
            default_android_attestation_roots(),
        );
        if first_device_android_attestation_enabled
            && first_device_android_attestation_trust_roots_pem.is_empty()
        {
            return Err(ConfigError::AndroidAttestationEnabledWithoutTrustRoots);
        }

        let snapshot_upload_concurrency: usize =
            parse_env_with(&env, "SNAPSHOT_UPLOAD_CONCURRENCY", 8);
        if snapshot_upload_concurrency == 0 {
            return Err(ConfigError::ConcurrencyLimitZero { key: "SNAPSHOT_UPLOAD_CONCURRENCY" });
        }
        let media_upload_concurrency: usize = parse_env_with(&env, "MEDIA_UPLOAD_CONCURRENCY", 32);
        if media_upload_concurrency == 0 {
            return Err(ConfigError::ConcurrencyLimitZero { key: "MEDIA_UPLOAD_CONCURRENCY" });
        }
        let default_request_concurrency: usize =
            parse_env_with(&env, "DEFAULT_REQUEST_CONCURRENCY", 512);
        if default_request_concurrency == 0 {
            return Err(ConfigError::ConcurrencyLimitZero { key: "DEFAULT_REQUEST_CONCURRENCY" });
        }

        Ok(Self {
            port: parse_env_with(&env, "PORT", 8080),
            db_path: env("DB_PATH").unwrap_or_else(|| "data/relay.db".into()),
            invite_ttl_secs: parse_env_with(&env, "INVITE_TTL_SECS", 86400),
            sync_inactive_ttl_secs: parse_env_with(&env, "SYNC_INACTIVE_TTL_SECS", 7_776_000),
            stale_device_secs: parse_env_with(&env, "STALE_DEVICE_SECS", 2_592_000),
            cleanup_interval_secs: parse_env_with(&env, "CLEANUP_INTERVAL_SECS", 3600),
            max_unpruned_batches: parse_env_with(&env, "MAX_UNPRUNED_BATCHES", 10_000),
            metrics_token: env("METRICS_TOKEN").filter(|s| !s.is_empty()),
            session_expiry_secs: parse_env_with(&env, "SESSION_EXPIRY_SECS", 2_592_000),
            session_max_age_secs: parse_env_with(&env, "SESSION_MAX_AGE_SECS", 7_776_000),
            nonce_expiry_secs: parse_env_with(&env, "NONCE_EXPIRY_SECS", 60),
            first_device_pow_difficulty_bits: parse_env_with(
                &env,
                "FIRST_DEVICE_POW_DIFFICULTY_BITS",
                18,
            ),
            nonce_rate_limit: parse_env_with(&env, "NONCE_RATE_LIMIT", 10),
            nonce_rate_window_secs: parse_env_with(&env, "NONCE_RATE_WINDOW_SECS", 60),
            revoke_rate_limit: parse_env_with(&env, "REVOKE_RATE_LIMIT", 20),
            revoke_rate_window_secs: parse_env_with(&env, "REVOKE_RATE_WINDOW_SECS", 3600),
            ws_upgrade_rate_limit: parse_env_with(&env, "WS_UPGRADE_RATE_LIMIT", 20),
            ws_upgrade_rate_window_secs: parse_env_with(&env, "WS_UPGRADE_RATE_WINDOW_SECS", 60),
            trusted_proxy_cidrs: parse_string_list_env_with(
                &env,
                "TRUSTED_PROXY_CIDRS",
                Vec::new(),
            ),
            signed_request_max_skew_secs: parse_env_with(&env, "SIGNED_REQUEST_MAX_SKEW_SECS", 60),
            signed_request_nonce_window_secs: parse_env_with(
                &env,
                "SIGNED_REQUEST_NONCE_WINDOW_SECS",
                120,
            ),
            snapshot_default_ttl_secs: parse_env_with(&env, "SNAPSHOT_DEFAULT_TTL_SECS", 86400),
            revoked_tombstone_retention_secs: parse_env_with(
                &env,
                "REVOKED_TOMBSTONE_RETENTION_SECS",
                2_592_000,
            ),
            reader_pool_size: parse_env_with(&env, "READER_POOL_SIZE", 4),
            node_exporter_url: env("NODE_EXPORTER_URL").filter(|s| !s.is_empty()),
            first_device_apple_attestation_enabled,
            first_device_apple_attestation_trust_roots_pem,
            first_device_apple_attestation_allowed_app_ids: parse_json_vec_env_with(
                &env,
                "FIRST_DEVICE_APPLE_ATTESTATION_ALLOWED_APP_IDS",
                Vec::new(),
            ),
            first_device_android_attestation_enabled,
            first_device_android_attestation_trust_roots_pem,
            grapheneos_verified_boot_key_allowlist: parse_json_vec_env_with(
                &env,
                "GRAPHENEOS_VERIFIED_BOOT_KEY_ALLOWLIST",
                Vec::new(),
            ),
            registration_token: env("REGISTRATION_TOKEN").filter(|s| !s.is_empty()),
            registration_enabled: parse_bool_env_with(&env, "REGISTRATION_ENABLED", true),
            pairing_session_ttl_secs: parse_env_with(&env, "PAIRING_SESSION_TTL_SECS", 300),
            pairing_session_rate_limit: parse_env_with(&env, "PAIRING_SESSION_RATE_LIMIT", 5),
            pairing_session_max_payload_bytes: parse_env_with(
                &env,
                "PAIRING_SESSION_MAX_PAYLOAD_BYTES",
                262144, // 256 KB — PQ credential bundles with ML-DSA/ML-KEM/X-Wing keys
            ),
            // Dark by default: the lease is opt-in per deployment.
            pairing_lease: PairingLeaseConfig {
                enabled: parse_bool_env_with(&env, "PAIRING_LEASE_ENABLED", false),
                max_concurrent_sessions: parse_env_with(
                    &env,
                    "PAIRING_LEASE_MAX_CONCURRENT_SESSIONS",
                    PAIRING_LEASE_MAX_CONCURRENT_SESSIONS,
                ),
                renew_rate_limit: parse_env_with(
                    &env,
                    "PAIRING_LEASE_RENEW_RATE_LIMIT",
                    PAIRING_LEASE_DEFAULT_RENEW_RATE_LIMIT,
                ),
                renew_rate_window_secs: parse_env_with(
                    &env,
                    "PAIRING_LEASE_RENEW_RATE_WINDOW_SECS",
                    PAIRING_LEASE_DEFAULT_RENEW_RATE_WINDOW_SECS,
                ),
                failure_limit: parse_env_with(
                    &env,
                    "PAIRING_LEASE_FAILURE_LIMIT",
                    PAIRING_LEASE_DEFAULT_FAILURE_LIMIT,
                ),
                failure_window_secs: parse_env_with(
                    &env,
                    "PAIRING_LEASE_FAILURE_WINDOW_SECS",
                    PAIRING_LEASE_DEFAULT_FAILURE_WINDOW_SECS,
                ),
            },
            // Resumable snapshot uploads. Protocol constants are compile-time;
            // only the resource envelope and the enable switch are configurable.
            // Dark by default, and `snapshot_upload_supported` additionally
            // requires file-backed storage.
            snapshot_upload: SnapshotUploadConfig {
                enabled: parse_bool_env_with(&env, "SNAPSHOT_UPLOAD_ENABLED", false),
                group_reserved_bytes: parse_env_with(
                    &env,
                    "SNAPSHOT_UPLOAD_GROUP_RESERVED_BYTES",
                    crate::uploads::SNAPSHOT_UPLOAD_DEFAULT_GROUP_RESERVED_BYTES,
                ),
                global_reserved_bytes: parse_env_with(
                    &env,
                    "SNAPSHOT_UPLOAD_GLOBAL_RESERVED_BYTES",
                    crate::uploads::SNAPSHOT_UPLOAD_DEFAULT_GLOBAL_RESERVED_BYTES,
                ),
                free_space_reserve_bytes: parse_env_with(
                    &env,
                    "SNAPSHOT_UPLOAD_FREE_SPACE_RESERVE_BYTES",
                    crate::uploads::SNAPSHOT_UPLOAD_DEFAULT_FREE_SPACE_RESERVE_BYTES,
                ),
                create_rate_limit: parse_env_with(
                    &env,
                    "SNAPSHOT_UPLOAD_CREATE_RATE_LIMIT",
                    crate::uploads::SNAPSHOT_UPLOAD_DEFAULT_CREATE_RATE_LIMIT,
                ),
                create_rate_window_secs: parse_env_with(
                    &env,
                    "SNAPSHOT_UPLOAD_CREATE_RATE_WINDOW_SECS",
                    crate::uploads::SNAPSHOT_UPLOAD_DEFAULT_CREATE_RATE_WINDOW_SECS,
                ),
                chunk_concurrency: parse_env_with(
                    &env,
                    "SNAPSHOT_UPLOAD_CHUNK_CONCURRENCY",
                    crate::uploads::SNAPSHOT_UPLOAD_DEFAULT_CHUNK_CONCURRENCY,
                ),
            },
            sharing_init_ttl_secs: parse_env_with(&env, "SHARING_INIT_TTL_SECS", 604800),
            sharing_init_max_payload_bytes: parse_env_with(
                &env,
                "SHARING_INIT_MAX_PAYLOAD_BYTES",
                65536,
            ),
            sharing_identity_max_bytes: parse_env_with(&env, "SHARING_IDENTITY_MAX_BYTES", 8192),
            sharing_prekey_max_bytes: parse_env_with(&env, "SHARING_PREKEY_MAX_BYTES", 4096),
            sharing_fetch_rate_limit: parse_env_with(&env, "SHARING_FETCH_RATE_LIMIT", 20),
            sharing_init_rate_limit: parse_env_with(&env, "SHARING_INIT_RATE_LIMIT", 10),
            sharing_init_max_pending: parse_env_with(&env, "SHARING_INIT_MAX_PENDING", 50),
            prekey_upload_max_age_secs: parse_env_with(&env, "PREKEY_UPLOAD_MAX_AGE_SECS", 604800),
            prekey_serve_max_age_secs: parse_env_with(&env, "PREKEY_SERVE_MAX_AGE_SECS", 2_592_000),
            prekey_max_future_skew_secs: parse_env_with(&env, "PREKEY_MAX_FUTURE_SKEW_SECS", 300),
            min_signature_version,
            media_storage_path: env("MEDIA_STORAGE_PATH").unwrap_or_else(|| "data/media".into()),
            media_max_file_bytes: parse_env_with(&env, "MEDIA_MAX_FILE_BYTES", 10_485_760),
            media_quota_bytes_per_group: parse_env_with(
                &env,
                "MEDIA_QUOTA_BYTES_PER_GROUP",
                1_073_741_824,
            ),
            media_retention_days: parse_env_with(&env, "MEDIA_RETENTION_DAYS", 90),
            media_upload_rate_limit: parse_env_with(&env, "MEDIA_UPLOAD_RATE_LIMIT", 10),
            media_upload_rate_window_secs: parse_env_with(
                &env,
                "MEDIA_UPLOAD_RATE_WINDOW_SECS",
                60,
            ),
            media_orphan_cleanup_secs: parse_env_with(&env, "MEDIA_ORPHAN_CLEANUP_SECS", 86400),
            media_resupply_ttl_min_secs: parse_env_with(&env, "MEDIA_RESUPPLY_TTL_MIN", 3600),
            media_pending_grace_secs: parse_env_with(&env, "MEDIA_PENDING_GRACE_SECS", 300),
            media_expired_sweep_cap: parse_env_with(&env, "MEDIA_EXPIRED_SWEEP_CAP", 64),
            media_resupply_byte_ceiling_bytes: parse_env_with(
                &env,
                "MEDIA_RESUPPLY_BYTE_CEILING_BYTES",
                536_870_912, // 512 MiB
            ),
            media_resupply_rate_limit: parse_env_with(&env, "MEDIA_RESUPPLY_RATE_LIMIT", 10),
            media_resupply_rate_window_secs: parse_env_with(
                &env,
                "MEDIA_RESUPPLY_RATE_WINDOW_SECS",
                60,
            ),
            media_pairing_push_rate_limit: parse_env_with(
                &env,
                "MEDIA_PAIRING_PUSH_RATE_LIMIT",
                60,
            ),
            media_pairing_push_rate_window_secs: parse_env_with(
                &env,
                "MEDIA_PAIRING_PUSH_RATE_WINDOW_SECS",
                60,
            ),
            device_message_ttl_secs: parse_env_with(&env, "DEVICE_MESSAGE_TTL_SECS", 604_800), // 7 days
            device_message_max_payload_bytes: parse_env_with(
                &env,
                "DEVICE_MESSAGE_MAX_PAYLOAD_BYTES",
                4096,
            ),
            device_message_send_rate_limit: parse_env_with(
                &env,
                "DEVICE_MESSAGE_SEND_RATE_LIMIT",
                60,
            ),
            device_message_send_rate_window_secs: parse_env_with(
                &env,
                "DEVICE_MESSAGE_SEND_RATE_WINDOW_SECS",
                60,
            ),
            device_message_max_pending: parse_env_with(&env, "DEVICE_MESSAGE_MAX_PENDING", 2048),
            device_message_fetch_limit: parse_env_with(&env, "DEVICE_MESSAGE_FETCH_LIMIT", 256),
            default_request_timeout_secs: parse_env_with(&env, "DEFAULT_REQUEST_TIMEOUT_SECS", 30),
            snapshot_request_timeout_secs: parse_env_with(
                &env,
                "SNAPSHOT_REQUEST_TIMEOUT_SECS",
                300,
            ),
            media_request_timeout_secs: parse_env_with(&env, "MEDIA_REQUEST_TIMEOUT_SECS", 120),
            snapshot_upload_concurrency,
            media_upload_concurrency,
            default_request_concurrency,
            gif_provider_mode: parse_gif_provider_mode_env_with(
                &env,
                "GIF_PROVIDER_MODE",
                GifProviderMode::Disabled,
            ),
            gif_public_base_url: env("GIF_PUBLIC_BASE_URL").filter(|s| !s.trim().is_empty()),
            gif_prism_base_url: env("GIF_PRISM_BASE_URL").filter(|s| !s.trim().is_empty()),
            gif_api_base_url: env("GIF_API_BASE_URL")
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "https://api.klipy.com".into()),
            gif_api_key: env("GIF_API_KEY").filter(|s| !s.trim().is_empty()),
            gif_http_timeout_secs: parse_env_with(&env, "GIF_HTTP_TIMEOUT_SECS", 15),
            gif_request_rate_limit: parse_env_with(&env, "GIF_REQUEST_RATE_LIMIT", 20),
            gif_request_rate_window_secs: parse_env_with(&env, "GIF_REQUEST_RATE_WINDOW_SECS", 60),
            gif_query_max_len: parse_env_with(&env, "GIF_QUERY_MAX_LEN", 200),
        })
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
        let cap = parse_env("BRAND_NEW_GROUP_MAX_UNPRUNED_BATCHES", self.max_unpruned_batches / 10);
        cap.max(10).min(self.max_unpruned_batches.max(1))
    }

    /// Age threshold after which a group is no longer treated as brand-new.
    pub fn brand_new_group_age_secs(&self) -> u64 {
        parse_env("BRAND_NEW_GROUP_AGE_SECS", 86_400)
    }

    /// Abandoned brand-new groups are eligible for cleanup after this long.
    pub fn abandoned_brand_new_group_ttl_secs(&self) -> u64 {
        parse_env("ABANDONED_BRAND_NEW_GROUP_TTL_SECS", self.sync_inactive_ttl_secs)
    }

    /// Resolve the registration token using the priority chain:
    /// 1. `REGISTRATION_TOKEN` env var — if "OPEN", clears the token (open mode)
    /// 2. `{db_dir}/.registration-token` file
    /// 3. Generate a random token, write it to the file, log the file path
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
        let db_dir =
            std::path::Path::new(&self.db_path).parent().unwrap_or(std::path::Path::new("."));
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
        match write_registration_token_file(&token_path, &token) {
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
            path = %token_path.display(),
            "{}",
            GENERATED_REGISTRATION_TOKEN_LOG_MESSAGE
        );
        self.registration_token = Some(token);
    }
}

fn parse_min_signature_version_env<F>(env: &F, key: &str, default: u8) -> Result<u8, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let configured = parse_env_with(env, key, default);
    if configured < MIN_SIGNATURE_VERSION_SOURCE_FLOOR {
        return Err(ConfigError::MinSignatureVersionBelowSourceFloor {
            configured,
            floor: MIN_SIGNATURE_VERSION_SOURCE_FLOOR,
        });
    }
    Ok(configured)
}

fn parse_env_with<T, F>(env: &F, key: &str, default: T) -> T
where
    T: std::str::FromStr,
    F: Fn(&str) -> Option<String>,
{
    env(key).and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn parse_env<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn parse_bool_env_with<F>(env: &F, key: &str, default: bool) -> bool
where
    F: Fn(&str) -> Option<String>,
{
    env(key)
        .and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
        .unwrap_or(default)
}

fn parse_json_vec_env_with<F>(env: &F, key: &str, default: Vec<String>) -> Vec<String>
where
    F: Fn(&str) -> Option<String>,
{
    env(key)
        .filter(|value| !value.trim().is_empty())
        .and_then(|value| serde_json::from_str::<Vec<String>>(&value).ok())
        .unwrap_or(default)
}

fn parse_string_list_env_with<F>(env: &F, key: &str, default: Vec<String>) -> Vec<String>
where
    F: Fn(&str) -> Option<String>,
{
    env(key)
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            serde_json::from_str::<Vec<String>>(&value).unwrap_or_else(|_| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|entry| !entry.is_empty())
                    .map(ToOwned::to_owned)
                    .collect()
            })
        })
        .unwrap_or(default)
}

fn parse_gif_provider_mode_env_with<F>(
    env: &F,
    key: &str,
    default: GifProviderMode,
) -> GifProviderMode
where
    F: Fn(&str) -> Option<String>,
{
    env(key).as_deref().and_then(GifProviderMode::parse).unwrap_or(default)
}

fn generate_random_token() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    hex::encode(bytes)
}

fn write_registration_token_file(path: &std::path::Path, token: &str) -> std::io::Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;
    file.write_all(token.as_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

/// Prove a directory is writable by creating and removing a probe file.
///
/// Directory permission bits are not sufficient evidence: ACLs, read-only
/// bind mounts, and a full filesystem all leave the mode bits looking writable
/// while every real `open` fails. A create-new probe with a random name (so it
/// can never clobber an existing file) is the honest check. The probe file is
/// removed immediately; a failure to remove it is not fatal to startup.
fn probe_writable_dir(dir: &std::path::Path) -> std::io::Result<()> {
    let probe = dir.join(format!(".snapshot-storage-probe-{}", uuid::Uuid::new_v4().simple()));
    {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&probe)?;
        file.write_all(b"probe")?;
        // Durable enough to prove the volume accepts writes, not just buffers.
        file.sync_all()?;
    }
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

fn default_android_attestation_roots() -> Vec<String> {
    vec![
        include_str!("android_attestation_roots/root_rsa.pem").to_string(),
        include_str!("android_attestation_roots/root_p384.pem").to_string(),
    ]
}

/// Config for a throwaway localhost relay: in-memory DB, ephemeral port, OPEN
/// registration, zero PoW, attestation disabled. Used by the `test_relay`
/// example (and any local harness) to bring up a real relay without a deploy
/// environment. NOT for production.
pub fn localhost_test_config() -> Config {
    Config {
        port: 0,
        db_path: ":memory:".into(),
        nonce_expiry_secs: 60,
        session_expiry_secs: 3600,
        session_max_age_secs: 7_776_000,
        first_device_pow_difficulty_bits: 0,
        invite_ttl_secs: 86400,
        sync_inactive_ttl_secs: 7_776_000,
        stale_device_secs: 2_592_000,
        cleanup_interval_secs: 3600,
        max_unpruned_batches: 10_000,
        metrics_token: None,
        nonce_rate_limit: 100,
        nonce_rate_window_secs: 60,
        revoke_rate_limit: 100,
        revoke_rate_window_secs: 60,
        ws_upgrade_rate_limit: 100,
        ws_upgrade_rate_window_secs: 60,
        trusted_proxy_cidrs: vec![],
        signed_request_max_skew_secs: 60,
        signed_request_nonce_window_secs: 120,
        snapshot_default_ttl_secs: 86400,
        revoked_tombstone_retention_secs: 2_592_000,
        reader_pool_size: 2,
        node_exporter_url: None,
        first_device_apple_attestation_enabled: false,
        first_device_apple_attestation_trust_roots_pem: vec![],
        first_device_apple_attestation_allowed_app_ids: vec![],
        first_device_android_attestation_enabled: false,
        first_device_android_attestation_trust_roots_pem: vec![],
        grapheneos_verified_boot_key_allowlist: vec![],
        registration_token: None,
        registration_enabled: true,
        pairing_session_ttl_secs: 300,
        pairing_session_rate_limit: 100,
        // 256 KB to match production — real PQ credential bundles (ML-DSA /
        // ML-KEM / X-Wing keys + signed registry) exceed the relay test
        // harness's 32 KB, which would 413 the pairing credentials PUT.
        pairing_session_max_payload_bytes: 262144,
        // Lease defaults for tests: disabled (matching production default), with
        // the v1 caps and limiter sizes available for tests that enable it.
        pairing_lease: PairingLeaseConfig::default(),
        // Resumable upload defaults for tests: disabled (matching the production
        // default), with the conservative v1 resource ceilings available for
        // tests that deliberately enable it.
        snapshot_upload: SnapshotUploadConfig::default(),
        sharing_init_ttl_secs: 604800,
        sharing_init_max_payload_bytes: 65536,
        sharing_identity_max_bytes: 8192,
        sharing_prekey_max_bytes: 4096,
        sharing_fetch_rate_limit: 100,
        sharing_init_rate_limit: 100,
        sharing_init_max_pending: 50,
        prekey_upload_max_age_secs: 604800,
        prekey_serve_max_age_secs: 2_592_000,
        prekey_max_future_skew_secs: 300,
        min_signature_version: 3,
        media_storage_path: std::env::temp_dir()
            .join(format!("prism_test_media_{}", uuid::Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string(),
        media_max_file_bytes: 10_485_760,
        media_quota_bytes_per_group: 1_073_741_824,
        media_retention_days: 90,
        media_upload_rate_limit: 100,
        media_upload_rate_window_secs: 60,
        media_orphan_cleanup_secs: 86400,
        media_resupply_ttl_min_secs: 3600,
        media_pending_grace_secs: 300,
        media_expired_sweep_cap: 64,
        media_resupply_byte_ceiling_bytes: 536_870_912,
        media_resupply_rate_limit: 10,
        media_resupply_rate_window_secs: 60,
        media_pairing_push_rate_limit: 60,
        media_pairing_push_rate_window_secs: 60,
        device_message_ttl_secs: 604_800,
        device_message_max_payload_bytes: 4096,
        device_message_send_rate_limit: 100,
        device_message_send_rate_window_secs: 60,
        device_message_max_pending: 2048,
        device_message_fetch_limit: 256,
        default_request_timeout_secs: 30,
        snapshot_request_timeout_secs: 300,
        media_request_timeout_secs: 120,
        snapshot_upload_concurrency: 8,
        media_upload_concurrency: 32,
        default_request_concurrency: 512,
        gif_provider_mode: GifProviderMode::Disabled,
        gif_public_base_url: None,
        gif_prism_base_url: None,
        gif_api_base_url: "https://api.klipy.com".into(),
        gif_api_key: None,
        gif_http_timeout_secs: 15,
        gif_request_rate_limit: 20,
        gif_request_rate_window_secs: 60,
        gif_query_max_len: 200,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_from_env_pairs(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        Config::from_env_values(|key| {
            pairs
                .iter()
                .find_map(|(candidate, value)| (*candidate == key).then(|| (*value).to_string()))
        })
    }

    fn default_test_config(db_path: &std::path::Path) -> Config {
        let mut config = config_from_env_pairs(&[]).unwrap();
        config.db_path = db_path.to_string_lossy().into_owned();
        config
    }

    #[test]
    fn rejects_env_min_signature_version_below_source_floor() {
        let low_floor = (MIN_SIGNATURE_VERSION_SOURCE_FLOOR - 1).to_string();
        let err =
            config_from_env_pairs(&[("MIN_SIGNATURE_VERSION", low_floor.as_str())]).unwrap_err();

        assert_eq!(
            err,
            ConfigError::MinSignatureVersionBelowSourceFloor {
                configured: MIN_SIGNATURE_VERSION_SOURCE_FLOOR - 1,
                floor: MIN_SIGNATURE_VERSION_SOURCE_FLOOR,
            }
        );
    }

    #[test]
    fn default_min_signature_version_uses_source_floor() {
        let config = config_from_env_pairs(&[]).unwrap();

        assert_eq!(config.min_signature_version, MIN_SIGNATURE_VERSION_SOURCE_FLOOR);
    }

    #[test]
    fn default_revoke_rate_limit_allows_cleanup_bursts() {
        let config = config_from_env_pairs(&[]).unwrap();

        assert_eq!(config.revoke_rate_limit, 20);
    }

    #[test]
    fn rejects_apple_attestation_enabled_without_trust_roots() {
        let err = config_from_env_pairs(&[("FIRST_DEVICE_APPLE_ATTESTATION_ENABLED", "true")])
            .unwrap_err();

        assert_eq!(err, ConfigError::AppleAttestationEnabledWithoutTrustRoots);
    }

    #[test]
    fn accepts_apple_attestation_enabled_with_trust_roots() {
        let config = config_from_env_pairs(&[
            ("FIRST_DEVICE_APPLE_ATTESTATION_ENABLED", "true"),
            ("FIRST_DEVICE_APPLE_ATTESTATION_TRUST_ROOTS_PEM", r#"["test-root"]"#),
        ])
        .unwrap();

        assert!(config.first_device_apple_attestation_enabled);
        assert_eq!(config.first_device_apple_attestation_trust_roots_pem, vec!["test-root"]);
    }

    #[test]
    fn rejects_android_attestation_enabled_without_trust_roots() {
        let err =
            config_from_env_pairs(&[("FIRST_DEVICE_ANDROID_ATTESTATION_TRUST_ROOTS_PEM", "[]")])
                .unwrap_err();

        assert_eq!(err, ConfigError::AndroidAttestationEnabledWithoutTrustRoots);
    }

    #[test]
    fn accepts_android_attestation_disabled_without_trust_roots() {
        let config = config_from_env_pairs(&[
            ("FIRST_DEVICE_ANDROID_ATTESTATION_ENABLED", "false"),
            ("FIRST_DEVICE_ANDROID_ATTESTATION_TRUST_ROOTS_PEM", "[]"),
        ])
        .unwrap();

        assert!(!config.first_device_android_attestation_enabled);
        assert!(config.first_device_android_attestation_trust_roots_pem.is_empty());
    }

    #[test]
    fn default_android_attestation_enabled_uses_default_trust_roots() {
        let config = config_from_env_pairs(&[]).unwrap();

        assert!(config.first_device_android_attestation_enabled);
        assert!(!config.first_device_android_attestation_trust_roots_pem.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn generated_registration_token_file_mode_is_0600() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("relay.db");
        let mut config = default_test_config(&db_path);

        config.resolve_registration_token();

        let token_path = tmp.path().join(".registration-token");
        let mode = std::fs::metadata(&token_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let token = config.registration_token.as_deref().unwrap();
        let token_file = std::fs::read_to_string(&token_path).unwrap();
        assert_eq!(token_file, token);
    }

    #[test]
    fn generated_registration_token_log_message_does_not_contain_full_token() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("relay.db");
        let mut config = default_test_config(&db_path);
        config.resolve_registration_token();

        let token = config.registration_token.as_deref().unwrap();

        assert!(
            !GENERATED_REGISTRATION_TOKEN_LOG_MESSAGE.contains(token),
            "generated-token log message leaked token"
        );
        assert!(GENERATED_REGISTRATION_TOKEN_LOG_MESSAGE
            .contains("the full token is not printed in logs"));
    }

    #[test]
    fn request_timeout_and_concurrency_defaults_match_documented_values() {
        let config = config_from_env_pairs(&[]).unwrap();

        assert_eq!(config.default_request_timeout_secs, 30);
        assert_eq!(config.snapshot_request_timeout_secs, 300);
        assert_eq!(config.media_request_timeout_secs, 120);
        assert_eq!(config.snapshot_upload_concurrency, 8);
        assert_eq!(config.media_upload_concurrency, 32);
        assert_eq!(config.default_request_concurrency, 512);
    }

    #[test]
    fn request_timeout_and_concurrency_honor_env_overrides() {
        let config = config_from_env_pairs(&[
            ("DEFAULT_REQUEST_TIMEOUT_SECS", "45"),
            ("SNAPSHOT_REQUEST_TIMEOUT_SECS", "600"),
            ("MEDIA_REQUEST_TIMEOUT_SECS", "180"),
            ("SNAPSHOT_UPLOAD_CONCURRENCY", "4"),
            ("MEDIA_UPLOAD_CONCURRENCY", "16"),
            ("DEFAULT_REQUEST_CONCURRENCY", "256"),
        ])
        .unwrap();

        assert_eq!(config.default_request_timeout_secs, 45);
        assert_eq!(config.snapshot_request_timeout_secs, 600);
        assert_eq!(config.media_request_timeout_secs, 180);
        assert_eq!(config.snapshot_upload_concurrency, 4);
        assert_eq!(config.media_upload_concurrency, 16);
        assert_eq!(config.default_request_concurrency, 256);
    }

    #[test]
    fn invalid_request_timeout_env_falls_back_to_default() {
        // `parse_env_with` silently falls back on parse failure (existing
        // convention). A timeout knob with garbage shouldn't crash the relay
        // — it just uses the default.
        let config = config_from_env_pairs(&[
            ("DEFAULT_REQUEST_TIMEOUT_SECS", "not-a-number"),
            ("SNAPSHOT_REQUEST_TIMEOUT_SECS", "abc"),
        ])
        .unwrap();

        assert_eq!(config.default_request_timeout_secs, 30);
        assert_eq!(config.snapshot_request_timeout_secs, 300);
    }

    #[test]
    fn zero_snapshot_upload_concurrency_is_rejected() {
        let err = config_from_env_pairs(&[("SNAPSHOT_UPLOAD_CONCURRENCY", "0")]).unwrap_err();
        assert_eq!(err, ConfigError::ConcurrencyLimitZero { key: "SNAPSHOT_UPLOAD_CONCURRENCY" });
    }

    #[test]
    fn zero_media_upload_concurrency_is_rejected() {
        let err = config_from_env_pairs(&[("MEDIA_UPLOAD_CONCURRENCY", "0")]).unwrap_err();
        assert_eq!(err, ConfigError::ConcurrencyLimitZero { key: "MEDIA_UPLOAD_CONCURRENCY" });
    }

    #[test]
    fn zero_default_request_concurrency_is_rejected() {
        let err = config_from_env_pairs(&[("DEFAULT_REQUEST_CONCURRENCY", "0")]).unwrap_err();
        assert_eq!(err, ConfigError::ConcurrencyLimitZero { key: "DEFAULT_REQUEST_CONCURRENCY" });
    }

    #[test]
    fn snapshot_storage_root_is_derived_from_media_path() {
        let config = config_from_env_pairs(&[("MEDIA_STORAGE_PATH", "/data/media")]).unwrap();
        assert_eq!(config.snapshot_storage_path(), "/data/media-snapshots");
    }

    #[test]
    fn explicit_file_backing_refuses_relative_root_instead_of_degrading() {
        // The bare default `data/media` is relative, so its derived root cannot
        // be trusted. An operator who explicitly demanded file backing must get
        // a refusal, not a silent inline downgrade on ephemeral storage.
        let config = config_from_env_pairs(&[]).unwrap();
        let err = config.resolve_snapshot_storage(true).unwrap_err();
        match err {
            ConfigError::SnapshotStorageInvalid { reason } => {
                assert!(
                    reason.contains("not an absolute path"),
                    "reason should name the relative-path failure: {reason}"
                );
            }
            other => panic!("expected SnapshotStorageInvalid, got {other:?}"),
        }
    }

    #[test]
    fn explicit_file_backing_refuses_uncreatable_root_instead_of_degrading() {
        // The derived root is `<MEDIA_STORAGE_PATH>-snapshots`, so make its
        // PARENT a regular file: `<file>/media` derives
        // `<file>/media-snapshots`, which cannot be created because a path
        // component is not a directory. Explicit file backing must refuse rather
        // than enable a file-backed write that could never durably store a blob.
        let tmp = tempfile::TempDir::new().unwrap();
        let blocker = tmp.path().join("not-a-dir");
        std::fs::write(&blocker, b"x").unwrap();
        let media = blocker.join("media");
        let config =
            config_from_env_pairs(&[("MEDIA_STORAGE_PATH", media.to_str().unwrap())]).unwrap();

        let err = config.resolve_snapshot_storage(true).unwrap_err();
        assert!(
            matches!(err, ConfigError::SnapshotStorageInvalid { .. }),
            "expected SnapshotStorageInvalid, got {err:?}"
        );
    }

    #[test]
    fn unset_file_backing_degrades_to_inline_on_unusable_root() {
        // Same relative root, but without the explicit opt-in: the gate logs and
        // falls back to the legacy inline path so an existing deploy keeps
        // working after upgrade. This is the "silently enabling" hazard only if
        // the fallback were file-backed — it is not.
        let config = config_from_env_pairs(&[]).unwrap();
        assert_eq!(config.resolve_snapshot_storage(false).unwrap(), SnapshotStorage::Inline);
    }

    #[test]
    fn explicit_file_backing_enables_file_backed_for_valid_absolute_root() {
        let tmp = tempfile::TempDir::new().unwrap();
        let media = tmp.path().join("media");
        let config =
            config_from_env_pairs(&[("MEDIA_STORAGE_PATH", media.to_str().unwrap())]).unwrap();

        let storage = config.resolve_snapshot_storage(true).unwrap();
        let root = storage.root().expect("valid root must resolve file-backed");
        assert!(storage.is_file_backed());
        assert!(root.is_absolute(), "resolved root is canonicalized absolute");
        assert_eq!(root.file_name().and_then(|n| n.to_str()), Some("media-snapshots"));
    }

    #[test]
    fn file_backing_opt_in_parses_only_explicit_true() {
        let value_of = |v: Option<&str>| {
            let owned = v.map(str::to_string);
            snapshot_file_backing_explicitly_requested(move |_| owned.clone())
        };
        assert!(value_of(Some("true")));
        assert!(value_of(Some("  TRUE  ")), "case- and whitespace-insensitive");
        assert!(!value_of(Some("false")), "explicit false keeps the inline fallback");
        assert!(!value_of(Some("1")), "only `true` opts in");
        assert!(!value_of(None), "unset keeps the inline fallback");
    }
}
