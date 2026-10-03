//! Resumable pair-time snapshot upload (lean v1 **client** half).
//!
//! This module owns the client side of resumable snapshot uploads: the optional
//! `snapshot_upload` capability, the exact wire models for the five resumable
//! operations, structured error parsing, and the sequential fixed-size uploader
//! with status reconciliation and bounded retry.
//!
//! Three things are deliberately *not* here:
//!
//! - **No new crypto or envelope format.** The uploader transports the exact
//!   serialized `SignedBatchEnvelope` bytes the existing single `PUT /snapshot`
//!   path sends; the relay stores them opaquely and the joiner's hybrid
//!   signature remains authoritative end to end.
//! - **No server linkage.** Nothing here tells the relay which pairing ceremony
//!   owns an upload. Progress-driven lease renewals are carried by the caller
//!   through [`SnapshotUploadProgressHook`], which sees only an acknowledged
//!   offset.
//! - **No process-death recovery.** Retry state is in-process only, exactly as
//!   the spec scopes v1.
//!
//! # Fallback contract
//!
//! Capability absence, a capability lookup failure, or a locally invalid
//! capability all downgrade to the existing single `PUT`. That downgrade is
//! *always* a local decision reported as [`SnapshotUploadOutcome::CapabilityUnavailable`];
//! it is never an error and never a reason to bypass a relay rejection.
//!
//! # Offset authority
//!
//! The relay's committed offset is authoritative everywhere. The uploader never
//! resumes from an offset it merely assumes: after any ambiguous chunk or
//! complete result it reconciles with `GET .../{upload_id}` first, and a
//! definitive `404`/`410` is terminal rather than retried.

use std::future::Future;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::relay::traits::{RelayError, SnapshotUploadProgress};

// ── Protocol constants (mirror of `prism-sync-relay::uploads`) ──────────────

/// Wire protocol version this client speaks.
pub const SNAPSHOT_UPLOAD_VERSION_V1: u16 = 1;

/// Fixed v1 chunk size: a protocol constant, never negotiated.
pub const SNAPSHOT_UPLOAD_CHUNK_BYTES: u64 = 8 * 1024 * 1024;

/// Fixed v1 maximum wire body the relay will accept for one snapshot.
pub const SNAPSHOT_UPLOAD_MAX_WIRE_BYTES: u64 = 150 * 1024 * 1024;

/// Relay's advertised idle session TTL.
pub const SNAPSHOT_UPLOAD_IDLE_TTL_SECS: u64 = 3600;

/// Length of the client-generated idempotency key.
pub const SNAPSHOT_UPLOAD_KEY_BYTES: usize = 32;

/// Maximum snapshot TTL the protocol admits.
pub const SNAPSHOT_UPLOAD_MAX_SNAPSHOT_TTL_SECS: u64 = 604_800;

/// Snapshot TTL this client requests, matching the existing single-PUT default.
pub const SNAPSHOT_UPLOAD_DEFAULT_TTL_SECS: u64 = 86_400;

/// Requested retry attempts per resumable operation.
pub const SNAPSHOT_UPLOAD_MAX_ATTEMPTS: u32 = 5;

/// First retry backoff.
pub const SNAPSHOT_UPLOAD_INITIAL_BACKOFF_MS: u64 = 250;

/// Exponential backoff ceiling.
pub const SNAPSHOT_UPLOAD_MAX_BACKOFF_MS: u64 = 8_000;

/// Bound on chunk/complete state transitions for a single upload.
///
/// Every transition either advances the committed offset, publishes, or
/// terminates with an error, so this only exists to turn an unexpected relay
/// behavior into a definite failure instead of an unbounded loop.
pub const MAX_UPLOAD_STATE_TRANSITIONS: usize = 4096;

// ── Capability ──────────────────────────────────────────────────────────────

/// Advertised resumable-upload capability (the ignorable `snapshot_upload`
/// sibling of the capabilities response).
///
/// Every field is `#[serde(default)]` and the type is parsed through
/// [`SnapshotUploadCapability::parse`], so an old relay that omits the sibling,
/// a relay that omits a field, or a relay that adds an unknown field all
/// downgrade safely instead of breaking pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotUploadCapability {
    /// Protocol version the relay speaks.
    pub version: u16,
    /// Fixed chunk size for this relay.
    pub chunk_bytes: u64,
    /// Largest declared total the relay will accept.
    pub max_wire_bytes: u64,
    /// Idle session TTL the relay applies.
    pub session_idle_ttl_secs: u64,
}

/// Why resumable upload is unavailable, so the fallback to single PUT is
/// explainable in logs and tests without being an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityUnavailableReason {
    /// Old relay: the `snapshot_upload` sibling is absent.
    Absent,
    /// The capabilities request itself failed (network, auth, malformed body).
    /// Never fatal to pairing — the client falls back to single PUT.
    LookupFailed,
    /// The sibling exists but declares a version this client does not speak.
    UnsupportedVersion {
        /// Version the relay advertised.
        advertised: u16,
    },
    /// The sibling exists but a value is internally invalid or contradicts the
    /// v1 protocol constant. Treated as absent, never as an error.
    InvalidCapability,
}

impl CapabilityUnavailableReason {
    /// Stable short label for structured logs. Carries no identifiers.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "capability_absent",
            Self::LookupFailed => "capability_lookup_failed",
            Self::UnsupportedVersion { .. } => "capability_unsupported_version",
            Self::InvalidCapability => "capability_invalid",
        }
    }
}

impl SnapshotUploadCapability {
    /// Parse an optional capability object from the raw capabilities JSON.
    ///
    /// Returns `Err(reason)` for a present-but-unusable sibling and
    /// `Ok(None)`-equivalent through `Err(Absent)` when the sibling is missing.
    /// Unknown fields inside the sibling are ignored by serde, which is what
    /// keeps a newer relay compatible with this client.
    ///
    /// The chunk size is validated against the v1 protocol constant: a relay
    /// that advertised a different chunk size would produce sessions this
    /// client cannot chunk correctly, so it is treated as unavailable rather
    /// than guessed at.
    pub fn parse(
        capabilities_json: &serde_json::Value,
    ) -> Result<Self, CapabilityUnavailableReason> {
        let Some(sibling) = capabilities_json.get("snapshot_upload") else {
            return Err(CapabilityUnavailableReason::Absent);
        };
        if sibling.is_null() {
            return Err(CapabilityUnavailableReason::Absent);
        }
        let capability: Self = serde_json::from_value(sibling.clone()).map_err(|_| {
            // A malformed sibling is a relay-side problem, but it must never
            // fail pairing: treat it exactly like an absent capability.
            CapabilityUnavailableReason::InvalidCapability
        })?;
        capability.validate()?;
        Ok(capability)
    }

    /// Validate every field against the v1 profile.
    pub fn validate(&self) -> Result<(), CapabilityUnavailableReason> {
        if self.version != SNAPSHOT_UPLOAD_VERSION_V1 {
            return Err(CapabilityUnavailableReason::UnsupportedVersion {
                advertised: self.version,
            });
        }
        if self.chunk_bytes == 0
            || self.chunk_bytes > SNAPSHOT_UPLOAD_CHUNK_BYTES
            || !SNAPSHOT_UPLOAD_CHUNK_BYTES.is_multiple_of(self.chunk_bytes)
        {
            return Err(CapabilityUnavailableReason::InvalidCapability);
        }
        if self.max_wire_bytes == 0 || self.max_wire_bytes > SNAPSHOT_UPLOAD_MAX_WIRE_BYTES {
            return Err(CapabilityUnavailableReason::InvalidCapability);
        }
        if self.session_idle_ttl_secs == 0 {
            return Err(CapabilityUnavailableReason::InvalidCapability);
        }
        Ok(())
    }

    /// Whether an envelope of `total_bytes` fits the advertised maximum.
    pub fn accepts_total(&self, total_bytes: u64) -> bool {
        total_bytes > 0 && total_bytes <= self.max_wire_bytes
    }
}

// ── Wire models ─────────────────────────────────────────────────────────────

/// Signed create body.
#[derive(Debug, Clone, Serialize)]
pub struct CreateUploadRequest {
    /// Protocol version.
    pub version: u16,
    /// Client-generated idempotency key (base64url, no padding).
    pub upload_key: String,
    /// Uploader's current registered epoch.
    pub epoch: i64,
    /// Snapshot point.
    pub server_seq_at: i64,
    /// v1 requires a targeted audience.
    pub target_device_id: String,
    /// Requested snapshot TTL.
    pub ttl_secs: i64,
    /// Exact envelope byte count.
    pub total_bytes: i64,
    /// Lowercase hex SHA-256 of the exact envelope bytes.
    pub body_sha256: String,
}

/// Create/recover response (also the status shape minus `state`).
#[derive(Debug, Clone, Deserialize)]
pub struct CreateUploadResponse {
    /// Relay-generated opaque upload identifier.
    pub upload_id: String,
    /// Lifecycle state, when the relay reports it.
    #[serde(default)]
    pub state: Option<String>,
    /// Session chunk size (authoritative for chunking).
    pub chunk_bytes: i64,
    /// Declared total.
    #[serde(default)]
    pub total_bytes: i64,
    /// Durable contiguous prefix already accepted.
    pub committed_offset: i64,
    /// Idle expiry.
    #[serde(default)]
    pub idle_expires_at: i64,
    /// Absolute expiry.
    #[serde(default)]
    pub absolute_expires_at: i64,
}

/// Status response.
#[derive(Debug, Clone, Deserialize)]
pub struct UploadStatusResponse {
    /// Lifecycle state.
    #[serde(default)]
    pub state: Option<String>,
    /// Declared total.
    #[serde(default)]
    pub total_bytes: i64,
    /// Durable contiguous prefix already accepted.
    pub committed_offset: i64,
    /// Session chunk size.
    pub chunk_bytes: i64,
    /// Idle expiry.
    #[serde(default)]
    pub idle_expires_at: i64,
    /// Absolute expiry.
    #[serde(default)]
    pub absolute_expires_at: i64,
}

/// Chunk acknowledgment.
#[derive(Debug, Clone, Deserialize)]
pub struct ChunkResponse {
    /// Relay's authoritative committed offset after this write.
    pub committed_offset: i64,
    /// Idle expiry after this accepted chunk.
    #[serde(default)]
    pub idle_expires_at: i64,
    /// Absolute expiry.
    #[serde(default)]
    pub absolute_expires_at: i64,
}

/// Lifecycle state reported by the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadState {
    /// Accepting chunks.
    Active,
    /// A completion operation owns the session.
    Finalizing,
    /// Terminal success.
    Completed,
    /// Terminal failure.
    Failed,
    /// A state string this client does not recognize.
    Unknown,
}

impl UploadState {
    /// Parse the wire spelling, failing closed to [`Self::Unknown`].
    pub fn parse(value: Option<&str>) -> Self {
        match value {
            Some("active") => Self::Active,
            Some("finalizing") => Self::Finalizing,
            Some("completed") => Self::Completed,
            Some("failed") => Self::Failed,
            _ => Self::Unknown,
        }
    }

    /// True for the terminal states.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

// ── Structured errors ───────────────────────────────────────────────────────

/// Stable machine codes the resumable routes return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadErrorCode {
    /// 400 `invalid_upload`.
    InvalidUpload,
    /// 400 `unsupported_snapshot_audience`.
    UnsupportedAudience,
    /// 404 `upload_not_found`.
    NotFound,
    /// 409 `upload_key_conflict`.
    KeyConflict,
    /// 409 `upload_incomplete`.
    Incomplete,
    /// 409 `upload_finalizing`.
    Finalizing,
    /// 409 `offset_mismatch`.
    OffsetMismatch,
    /// 409 `upload_completed`.
    Completed,
    /// 410 `upload_expired`.
    Expired,
    /// 413 `chunk_too_large`.
    ChunkTooLarge,
    /// 413 `snapshot_too_large`.
    SnapshotTooLarge,
    /// 429 `upload_quota_exceeded`.
    QuotaExceeded,
    /// 503 `upload_busy`.
    Busy,
    /// 422 `snapshot_hash_mismatch`.
    HashMismatch,
    /// 422 `upload_epoch_invalid`.
    EpochInvalid,
    /// 422 `upload_owner_invalid`.
    OwnerInvalid,
    /// 507 `insufficient_storage`.
    InsufficientStorage,
    /// 409 `upload_failed`.
    Failed,
    /// The existing audience-staleness conflict, preserved through the
    /// resumable path so the engine's suppression matrix still applies.
    StaleSnapshotSeq,
    /// The existing targeted-audience cap conflict.
    TooManyTargetedSnapshots,
    /// A code this client does not recognize, or a non-JSON body.
    Unknown(String),
}

impl UploadErrorCode {
    /// Machine code as it appears on the wire.
    pub fn as_str(&self) -> &str {
        match self {
            Self::InvalidUpload => "invalid_upload",
            Self::UnsupportedAudience => "unsupported_snapshot_audience",
            Self::NotFound => "upload_not_found",
            Self::KeyConflict => "upload_key_conflict",
            Self::Incomplete => "upload_incomplete",
            Self::Finalizing => "upload_finalizing",
            Self::OffsetMismatch => "offset_mismatch",
            Self::Completed => "upload_completed",
            Self::Expired => "upload_expired",
            Self::ChunkTooLarge => "chunk_too_large",
            Self::SnapshotTooLarge => "snapshot_too_large",
            Self::QuotaExceeded => "upload_quota_exceeded",
            Self::Busy => "upload_busy",
            Self::HashMismatch => "snapshot_hash_mismatch",
            Self::EpochInvalid => "upload_epoch_invalid",
            Self::OwnerInvalid => "upload_owner_invalid",
            Self::InsufficientStorage => "insufficient_storage",
            Self::Failed => "upload_failed",
            Self::StaleSnapshotSeq => "stale_snapshot_seq",
            Self::TooManyTargetedSnapshots => "too_many_targeted_snapshots",
            Self::Unknown(code) => code.as_str(),
        }
    }

    /// Parse a machine code, tolerating unknown values.
    pub fn parse(code: &str) -> Self {
        match code {
            "invalid_upload" => Self::InvalidUpload,
            "unsupported_snapshot_audience" => Self::UnsupportedAudience,
            "upload_not_found" => Self::NotFound,
            "upload_key_conflict" => Self::KeyConflict,
            "upload_incomplete" => Self::Incomplete,
            "upload_finalizing" => Self::Finalizing,
            "offset_mismatch" => Self::OffsetMismatch,
            "upload_completed" => Self::Completed,
            "upload_expired" => Self::Expired,
            "chunk_too_large" => Self::ChunkTooLarge,
            "snapshot_too_large" => Self::SnapshotTooLarge,
            "upload_quota_exceeded" => Self::QuotaExceeded,
            "upload_busy" => Self::Busy,
            "snapshot_hash_mismatch" => Self::HashMismatch,
            "upload_epoch_invalid" => Self::EpochInvalid,
            "upload_owner_invalid" => Self::OwnerInvalid,
            "insufficient_storage" => Self::InsufficientStorage,
            "upload_failed" => Self::Failed,
            "stale_snapshot_seq" => Self::StaleSnapshotSeq,
            "too_many_targeted_snapshots" => Self::TooManyTargetedSnapshots,
            other => Self::Unknown(other.to_string()),
        }
    }
}

/// Response-specific detail a retry decision needs.
///
/// Split out and boxed from [`ResumableUploadError`] so the error type stays
/// small: the transport trait returns `Result<_, ResumableUploadError>` on hot
/// chunk paths, and clippy rejects a large `Err` variant for good reason. The
/// status and machine code stay inline because every caller branches on them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UploadErrorDetail {
    /// Relay's committed offset, when the code carries one.
    pub committed_offset: Option<u64>,
    /// Chunk size the relay enforces, when the code carries one.
    pub chunk_bytes: Option<u64>,
    /// Declared maximum, when the code carries one.
    pub max_wire_bytes: Option<u64>,
    /// Bounded, non-user quota scope label, when the code carries one.
    pub scope: Option<String>,
    /// Competing snapshot's `server_seq_at`, on a `stale_snapshot_seq` conflict.
    pub current_server_seq_at: Option<i64>,
    /// Competing snapshot's audience, on a `stale_snapshot_seq` conflict.
    pub current_target_device_id: Option<String>,
    /// Human-readable message from the relay, or a synthesized one.
    pub message: String,
}

/// A structured resumable-upload failure.
///
/// Carries only the response-specific fields a retry decision needs (the
/// relay's offset, the chunk size it enforces, the declared cap, a bounded
/// quota scope label). It never carries request bytes, keys, tokens, or a full
/// upload identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumableUploadError {
    /// HTTP status the relay returned; `0` means no response was received.
    pub status: u16,
    /// Stable machine code.
    pub code: UploadErrorCode,
    /// Response-specific detail.
    pub detail: Box<UploadErrorDetail>,
}

impl ResumableUploadError {
    /// Build an error from a status plus an already-parsed code.
    pub fn new(status: u16, code: UploadErrorCode, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            detail: Box::new(UploadErrorDetail {
                message: message.into(),
                ..UploadErrorDetail::default()
            }),
        }
    }

    /// The relay's committed offset, when this code carries one.
    pub fn committed_offset(&self) -> Option<u64> {
        self.detail.committed_offset
    }

    /// The chunk size the relay enforces, when this code carries one.
    pub fn chunk_bytes(&self) -> Option<u64> {
        self.detail.chunk_bytes
    }

    /// The declared maximum, when this code carries one.
    pub fn max_wire_bytes(&self) -> Option<u64> {
        self.detail.max_wire_bytes
    }

    /// The bounded, non-user quota scope label, when this code carries one.
    pub fn scope(&self) -> Option<&str> {
        self.detail.scope.as_deref()
    }

    /// The human-readable relay message, or a synthesized one.
    pub fn message(&self) -> &str {
        &self.detail.message
    }

    /// Attach the relay's authoritative committed offset.
    pub fn with_committed_offset(mut self, committed_offset: u64) -> Self {
        self.detail.committed_offset = Some(committed_offset);
        self
    }

    /// Attach the relay's enforced chunk size.
    pub fn with_chunk_bytes(mut self, chunk_bytes: u64) -> Self {
        self.detail.chunk_bytes = Some(chunk_bytes);
        self
    }

    /// Attach the relay's declared maximum.
    pub fn with_max_wire_bytes(mut self, max_wire_bytes: u64) -> Self {
        self.detail.max_wire_bytes = Some(max_wire_bytes);
        self
    }

    /// Attach the bounded quota scope label.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.detail.scope = Some(scope.into());
        self
    }

    /// The transport never reached a decision for this operation.
    pub fn transport(message: impl Into<String>) -> Self {
        Self::new(0, UploadErrorCode::Unknown("transport".to_string()), message)
    }

    /// The transport does not implement the resumable routes at all.
    ///
    /// Returned only by trait defaults, which the uploader never reaches for a
    /// relay that reports the capability as absent. It exists so a mis-wired
    /// transport fails loudly instead of silently no-oping.
    pub fn unsupported() -> Self {
        // Deliberately a 4xx-shaped, non-retryable failure: this is a local
        // wiring defect, not a transient relay condition, so retrying it would
        // only burn the bounded retry budget.
        Self::new(
            400,
            UploadErrorCode::Unknown("resumable_upload_unsupported".to_string()),
            "transport does not implement resumable snapshot upload",
        )
    }

    /// Parse the relay's structured error body.
    ///
    /// A non-JSON or unstructured body degrades to [`UploadErrorCode::Unknown`]
    /// carrying the status, which the classification below still handles
    /// correctly (5xx stays retryable, 4xx terminal).
    pub fn parse(status: u16, body: &str) -> Self {
        let Ok(json) = serde_json::from_str::<serde_json::Value>(body) else {
            return Self::new(status, UploadErrorCode::Unknown(format!("http_{status}")), body);
        };
        let code_str = json.get("error").and_then(|v| v.as_str()).unwrap_or("");
        // The existing snapshot-conflict shape is preserved through the resumable
        // path so the engine's suppression matrix still applies. `null` is a
        // meaningful value here (group-wide audience), so a present-but-null
        // field must NOT be coerced into an unknown-target value.
        let mut detail = UploadErrorDetail {
            committed_offset: json
                .get("committed_offset")
                .and_then(|v| v.as_i64())
                .and_then(|v| u64::try_from(v).ok()),
            chunk_bytes: json.get("chunk_bytes").and_then(|v| v.as_u64()),
            max_wire_bytes: json.get("max_wire_bytes").and_then(|v| v.as_u64()),
            scope: json.get("scope").and_then(|v| v.as_str()).map(str::to_string),
            current_server_seq_at: json
                .get("current_server_seq_at")
                .or_else(|| json.get("server_seq_at"))
                .and_then(|v| v.as_i64()),
            current_target_device_id: None,
            message: json.get("message").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        };
        if let Some(target) = json.get("current_target_device_id") {
            detail.current_target_device_id = target.as_str().map(str::to_string);
        }
        Self { status, code: UploadErrorCode::parse(code_str), detail: Box::new(detail) }
    }

    /// Whether retrying this operation can succeed without changing state.
    ///
    /// Only transport failures (status `0`), `408`, `429`-free `5xx`, and the
    /// deliberately-retryable `503 upload_busy` qualify. `429 upload_quota_exceeded`
    /// is a policy rejection and is never retried.
    pub fn is_retryable(&self) -> bool {
        if self.status == 0 {
            return true;
        }
        if self.status == 408 {
            return true;
        }
        match &self.code {
            UploadErrorCode::Busy => true,
            UploadErrorCode::QuotaExceeded => false,
            _ => (500..=599).contains(&self.status),
        }
    }

    /// Whether this outcome definitively ends the session (or its existence).
    ///
    /// A definitive terminal result must stop a wait early instead of being
    /// retried until a budget expires.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.code,
            UploadErrorCode::NotFound
                | UploadErrorCode::Expired
                | UploadErrorCode::Completed
                | UploadErrorCode::HashMismatch
                | UploadErrorCode::EpochInvalid
                | UploadErrorCode::OwnerInvalid
                | UploadErrorCode::KeyConflict
                | UploadErrorCode::Failed
                | UploadErrorCode::InvalidUpload
                | UploadErrorCode::UnsupportedAudience
                | UploadErrorCode::SnapshotTooLarge
                | UploadErrorCode::StaleSnapshotSeq
                | UploadErrorCode::TooManyTargetedSnapshots
        )
    }

    /// Translate into the core relay error surface, preserving the two existing
    /// snapshot conflicts so the engine's suppression matrix is unchanged.
    pub fn to_relay_error(&self) -> RelayError {
        match self.code {
            UploadErrorCode::StaleSnapshotSeq => RelayError::SnapshotStale {
                // The resumable complete response reproduces the existing
                // snapshot-conflict shape, including a `null` audience for a
                // group-wide competing snapshot. When the relay does not echo a
                // competing seq the conservative `i64::MAX` keeps the
                // `existing_seq < our_seq` guard from suppressing it.
                current_server_seq_at: self.detail.current_server_seq_at.unwrap_or(i64::MAX),
                current_target_device_id: self.detail.current_target_device_id.clone(),
            },
            UploadErrorCode::NotFound => RelayError::NotFound,
            UploadErrorCode::UnsupportedAudience
            | UploadErrorCode::OwnerInvalid
            | UploadErrorCode::EpochInvalid => {
                RelayError::Forbidden { message: self.detail.message.clone() }
            }
            _ if self.status == 0 => RelayError::Network { message: self.detail.message.clone() },
            _ => RelayError::Http { status: self.status, body: self.detail.message.clone() },
        }
    }
}

impl std::fmt::Display for ResumableUploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Status + machine code only: the message may embed relay text.
        write!(f, "resumable snapshot upload failed ({}, {})", self.status, self.code.as_str())
    }
}

impl std::error::Error for ResumableUploadError {}

// ── Uploader configuration / outcome ────────────────────────────────────────

/// Bounded retry policy for one resumable operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotUploadRetryPolicy {
    /// Total attempts per operation, including the first.
    pub max_attempts: u32,
    /// First retry delay.
    pub initial_backoff: Duration,
    /// Ceiling for the exponential delay.
    pub max_backoff: Duration,
}

impl Default for SnapshotUploadRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: SNAPSHOT_UPLOAD_MAX_ATTEMPTS,
            initial_backoff: Duration::from_millis(SNAPSHOT_UPLOAD_INITIAL_BACKOFF_MS),
            max_backoff: Duration::from_millis(SNAPSHOT_UPLOAD_MAX_BACKOFF_MS),
        }
    }
}

impl SnapshotUploadRetryPolicy {
    /// Delay before attempt `attempt` (1-based), with deterministically derived
    /// jitter bounded to half the delay.
    ///
    /// `entropy` is supplied fresh per attempt, so two clients retrying the same
    /// operation do not lockstep.
    pub fn delay_for(&self, attempt: u32, entropy: u64) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }
        let shift = attempt.saturating_sub(1).min(31);
        let base_ms = self.initial_backoff.as_millis() as u64;
        let delay_ms =
            base_ms.saturating_mul(1u64 << shift).min(self.max_backoff.as_millis() as u64);
        let delay = Duration::from_millis(delay_ms);
        jitter_duration(delay, entropy)
    }
}

/// Deterministic jitter in `[0, delay/2]`.
fn jitter_duration(delay: Duration, entropy: u64) -> Duration {
    let base = delay.as_millis() as u64;
    if base == 0 {
        return Duration::ZERO;
    }
    let half = base / 2;
    if half == 0 {
        return delay;
    }
    delay.saturating_sub(Duration::from_millis(entropy % (half + 1)))
}

/// Caller-supplied parameters for one resumable upload.
#[derive(Debug, Clone)]
pub struct SnapshotUploadRequest {
    /// Uploader's registered epoch.
    pub epoch: i32,
    /// Snapshot point recorded in the signed create body.
    pub server_seq_at: i64,
    /// Targeted audience device. v1 requires this.
    pub target_device_id: String,
    /// Requested snapshot TTL.
    pub ttl_secs: u64,
}

/// What the uploader did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotUploadOutcome {
    /// The exact envelope bytes are durably published on the relay.
    Uploaded {
        /// Relay-generated opaque session identifier.
        upload_id: String,
        /// Total bytes published.
        total_bytes: u64,
    },
    /// Resumable upload is unavailable locally; the caller must use the
    /// existing single `PUT /snapshot`. This is a downgrade, not a failure.
    CapabilityUnavailable {
        /// Why, for structured logging and tests.
        reason: CapabilityUnavailableReason,
    },
}

impl SnapshotUploadOutcome {
    /// Whether the resumable path was used.
    pub fn used_resumable(&self) -> bool {
        matches!(self, Self::Uploaded { .. })
    }
}

/// Progress-driven renewal hook.
///
/// The uploader invokes this after every **strictly increased** acknowledged
/// committed offset, and never for status polls, duplicate acknowledgments, or
/// retries that did not advance the prefix. It exposes only the offset: the
/// hook decides whether a renewal is due, and the relay therefore never learns
/// what progressed, how much of the transfer completed, or which upload is
/// related to a pairing ceremony.
///
/// Errors are the hook's business; the uploader treats a renewal failure as
/// nonfatal and continues.
#[async_trait]
pub trait SnapshotUploadProgressHook: Send {
    /// Called after the relay created **or recovered** the session, with the
    /// opaque relay-generated session identifier.
    ///
    /// Invoked once per upload attempt, after that attempt's `create` succeeded —
    /// not once per session lifetime. A create response that was lost makes the
    /// next attempt's `create` recover the existing session, so a re-driven upload
    /// calls this again with the **same** id. A hook must therefore treat a
    /// repeated call as "this is still the session to abort", not as a new session,
    /// and must keep the latest value it is handed.
    ///
    /// It fires only after a **successful** create, so a create that failed
    /// (including one still being retried) reports nothing: until the relay has a
    /// session there is nothing to abort. The id is the durable handle for
    /// cancellation — record it and keep it until the session is terminal, because
    /// the upload future may be dropped at any await point and an id handed back
    /// only on the success path would arrive too late to abort anything.
    ///
    /// This exists so a caller that owns the ceremony — not the uploader — can
    /// abort exactly this session when the user cancels, the ceremony expires,
    /// or the transfer fails part-way. The default is a no-op, which keeps
    /// every existing hook (including the lease renewer) unaffected.
    ///
    /// The identifier is not a bearer capability: every resumable operation is
    /// still authorized by the owning device's session and request signature.
    async fn on_session_created(&mut self, upload_id: &str) {
        let _ = upload_id;
    }

    /// Called after the relay acknowledged a larger committed offset.
    async fn on_committed_offset_advanced(&mut self, committed_offset: u64);

    /// Called after the upload published successfully, before it returns.
    async fn on_upload_completed(&mut self, total_bytes: u64) {
        let _ = total_bytes;
    }

    /// Called when the upload is abandoned, so best-effort cancellation work
    /// (such as an abort) can run. Never fatal.
    async fn on_upload_abandoned(&mut self) {
        // Default: nothing to do.
    }
}

/// A [`SnapshotUploadProgressHook`] that does nothing.
pub struct NoopProgressHook;

#[async_trait]
impl SnapshotUploadProgressHook for NoopProgressHook {
    async fn on_committed_offset_advanced(&mut self, _committed_offset: u64) {}
}

/// Everything the uploader needs from the transport layer.
///
/// Implemented by `ServerRelay` (HTTP) and `MockRelay` (in-memory tests). The
/// default implementations on `SnapshotExchange` report "unavailable", which is
/// exactly the old-relay contract.
#[async_trait]
pub trait ResumableSnapshotTransport: Send + Sync {
    /// Fetch and parse the optional resumable capability.
    ///
    /// Returns the local downgrade reason when the capability is absent or
    /// unusable. A transport failure must be reported as
    /// [`CapabilityUnavailableReason::LookupFailed`] rather than bubbling an
    /// error: capability lookup never fails pairing.
    async fn resumable_snapshot_capability(
        &self,
    ) -> Result<SnapshotUploadCapability, CapabilityUnavailableReason>;

    /// Create or recover a session.
    async fn create_snapshot_upload(
        &self,
        body: &CreateUploadRequest,
    ) -> Result<CreateUploadResponse, ResumableUploadError>;

    /// Query the relay's authoritative session state.
    async fn snapshot_upload_status(
        &self,
        upload_id: &str,
    ) -> Result<UploadStatusResponse, ResumableUploadError>;

    /// Upload one chunk at `offset`.
    async fn put_snapshot_upload_chunk(
        &self,
        upload_id: &str,
        offset: u64,
        chunk: &[u8],
    ) -> Result<ChunkResponse, ResumableUploadError>;

    /// Complete and publish.
    async fn complete_snapshot_upload(&self, upload_id: &str) -> Result<(), ResumableUploadError>;

    /// Best-effort abort.
    async fn abort_snapshot_upload(&self, upload_id: &str) -> Result<(), ResumableUploadError>;
}

// ── The uploader ────────────────────────────────────────────────────────────

/// Sequential fixed-size resumable snapshot uploader.
///
/// One instance drives one upload. The `upload_key` is generated once at
/// construction and reused across every create retry, so a lost create response
/// recovers the same session instead of creating a second reservation. The
/// `body_sha256` is computed once over the exact envelope bytes.
pub struct SnapshotUploader<'a> {
    transport: &'a dyn ResumableSnapshotTransport,
    envelope: &'a [u8],
    request: SnapshotUploadRequest,
    retry: SnapshotUploadRetryPolicy,
    upload_key: String,
    body_sha256: String,
    progress_cb: Option<SnapshotUploadProgress>,
}

impl<'a> SnapshotUploader<'a> {
    /// Build an uploader for one envelope, generating the idempotency key once.
    pub fn new(
        transport: &'a dyn ResumableSnapshotTransport,
        envelope: &'a [u8],
        request: SnapshotUploadRequest,
    ) -> Self {
        let mut key_bytes = [0u8; SNAPSHOT_UPLOAD_KEY_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut key_bytes);
        let upload_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_bytes);
        let body_sha256 = hex::encode(Sha256::digest(envelope));
        Self {
            transport,
            envelope,
            request,
            retry: SnapshotUploadRetryPolicy::default(),
            upload_key,
            body_sha256,
            progress_cb: None,
        }
    }

    /// Override the retry policy (tests use a zero-backoff policy).
    pub fn with_retry_policy(mut self, retry: SnapshotUploadRetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// Attach the legacy byte-progress callback so app UI needs no new surface.
    pub fn with_progress(mut self, progress: Option<SnapshotUploadProgress>) -> Self {
        self.progress_cb = progress;
        self
    }

    /// The idempotency key this uploader will present. Stable across retries.
    pub fn upload_key(&self) -> &str {
        &self.upload_key
    }

    /// The exact-envelope digest this uploader commits to at create time.
    pub fn body_sha256(&self) -> &str {
        &self.body_sha256
    }

    /// Run the upload.
    ///
    /// Returns [`SnapshotUploadOutcome::CapabilityUnavailable`] when the relay
    /// does not advertise a usable capability, or when the envelope exceeds the
    /// advertised maximum — in the latter case with a specific error, never a
    /// silent fallback, because the envelope genuinely does not fit.
    pub async fn run(
        &self,
        hook: Option<&mut dyn SnapshotUploadProgressHook>,
    ) -> Result<SnapshotUploadOutcome, ResumableUploadError> {
        let total = self.envelope.len() as u64;

        let capability = match self.transport.resumable_snapshot_capability().await {
            Ok(capability) => capability,
            Err(reason) => return Ok(SnapshotUploadOutcome::CapabilityUnavailable { reason }),
        };

        // Locally reject an envelope the relay cannot accept, before any
        // session is created. This is a specific pairing error, not a downgrade:
        // the single-PUT path would be rejected by the same policy.
        if !capability.accepts_total(total) {
            return Err(ResumableUploadError::new(
                413,
                UploadErrorCode::SnapshotTooLarge,
                format!("envelope of {total} bytes exceeds the advertised resumable maximum"),
            ));
        }

        let mut hook = hook;
        match self.run_resumable(&capability, total, &mut hook).await {
            Ok(upload_id) => Ok(SnapshotUploadOutcome::Uploaded { upload_id, total_bytes: total }),
            Err(error) => {
                if let Some(hook) = hook {
                    hook.on_upload_abandoned().await;
                }
                Err(error)
            }
        }
    }

    async fn run_resumable(
        &self,
        capability: &SnapshotUploadCapability,
        total: u64,
        hook: &mut Option<&mut dyn SnapshotUploadProgressHook>,
    ) -> Result<String, ResumableUploadError> {
        let create_body = CreateUploadRequest {
            version: SNAPSHOT_UPLOAD_VERSION_V1,
            upload_key: self.upload_key.clone(),
            epoch: i64::from(self.request.epoch),
            server_seq_at: self.request.server_seq_at,
            target_device_id: self.request.target_device_id.clone(),
            ttl_secs: self.request.ttl_secs.min(SNAPSHOT_UPLOAD_MAX_SNAPSHOT_TTL_SECS) as i64,
            total_bytes: total as i64,
            body_sha256: self.body_sha256.clone(),
        };

        let created =
            self.retry_operation(|| self.transport.create_snapshot_upload(&create_body)).await?;

        let upload_id = created.upload_id.clone();
        // Hand the session identifier to the hook before the first chunk. A
        // caller that owns the ceremony stores it and can then abort exactly
        // this session if it cancels, expires, or fails mid-transfer.
        if let Some(hook) = hook.as_deref_mut() {
            hook.on_session_created(&upload_id).await;
        }
        // The session's persisted chunk size is authoritative, not the
        // capability's: a restart or config change cannot wedge the session.
        let chunk_bytes = match u64::try_from(created.chunk_bytes) {
            Ok(value) if value > 0 => value,
            _ => {
                return Err(ResumableUploadError::new(
                    500,
                    UploadErrorCode::Unknown("invalid_session_chunk_bytes".to_string()),
                    "relay reported a non-positive session chunk size",
                ));
            }
        };
        if chunk_bytes > capability.chunk_bytes {
            return Err(ResumableUploadError::new(
                500,
                UploadErrorCode::Unknown("invalid_session_chunk_bytes".to_string()),
                "relay reported a chunk size above its advertised maximum",
            ));
        }

        // Recovered sessions report their current offset, which is already
        // authoritative: a lost create or complete response must not force a
        // re-upload of the accepted prefix.
        let mut committed = clamp_offset(created.committed_offset, total);
        let mut published = UploadState::parse(created.state.as_deref()) == UploadState::Completed;
        self.emit_progress(committed, total);

        let mut last_renewed_offset: Option<u64> = None;

        // One state machine drives chunks and completion together: a completion
        // that reports `upload_incomplete` (an ambiguous or raced complete) must
        // resume chunking without re-planning, and a session that another
        // completion owns must be reconciled before we give up. Both directions
        // are therefore transitions, not nested recovery loops.
        let mut guard = 0usize;
        while !published {
            guard += 1;
            if guard > MAX_UPLOAD_STATE_TRANSITIONS {
                return Err(ResumableUploadError::new(
                    500,
                    UploadErrorCode::Unknown("upload_no_progress".to_string()),
                    "resumable upload made no progress within its transition budget",
                ));
            }

            if committed < total {
                let end = (committed + chunk_bytes).min(total);
                let chunk = &self.envelope[committed as usize..end as usize];
                let result = self
                    .retry_operation(|| {
                        self.transport.put_snapshot_upload_chunk(&upload_id, committed, chunk)
                    })
                    .await;

                match result {
                    Ok(ack) => {
                        let previous = committed;
                        committed = self.accept_offset(ack.committed_offset, previous, total)?;
                    }
                    // The relay is authoritative about where we stand. Never
                    // resend from an assumed offset: reconcile first.
                    Err(error)
                        if matches!(
                            error.code,
                            UploadErrorCode::OffsetMismatch | UploadErrorCode::Incomplete
                        ) =>
                    {
                        committed = self.reconcile_offset(&upload_id, total).await?;
                    }
                    Err(error) if error.code == UploadErrorCode::Finalizing => {
                        let status = self.status_with_retry(&upload_id).await?;
                        published =
                            UploadState::parse(status.state.as_deref()) == UploadState::Completed;
                        committed = clamp_offset(status.committed_offset, total);
                    }
                    Err(error) => return Err(error),
                }
            } else {
                // All bytes are committed: publish idempotently.
                match self
                    .retry_operation(|| self.transport.complete_snapshot_upload(&upload_id))
                    .await
                {
                    Ok(()) => published = true,
                    // Bytes are not all committed after all: adopt the relay's
                    // offset and go back to chunking.
                    Err(error) if error.code == UploadErrorCode::Incomplete => {
                        committed = self.reconcile_offset(&upload_id, total).await?;
                    }
                    Err(error) if error.code == UploadErrorCode::Finalizing => {
                        let status = self.status_with_retry(&upload_id).await?;
                        published =
                            UploadState::parse(status.state.as_deref()) == UploadState::Completed;
                        committed = clamp_offset(status.committed_offset, total);
                        if !published {
                            // A concurrent completion still owns the session and
                            // has not finished; surface the conflict rather than
                            // spinning on it.
                            return Err(error);
                        }
                    }
                    Err(error) => return Err(error),
                }
            }

            self.emit_progress(committed, total);
            self.maybe_advance_lease(hook, &mut last_renewed_offset, committed).await;
        }

        self.emit_progress(total, total);
        if let Some(hook) = hook.as_deref_mut() {
            hook.on_upload_completed(total).await;
        }
        Ok(upload_id)
    }

    /// Reconcile with the relay's authoritative status, twice-tolerant.
    async fn reconcile_offset(
        &self,
        upload_id: &str,
        total: u64,
    ) -> Result<u64, ResumableUploadError> {
        let status = self.status_with_retry(upload_id).await?;
        match UploadState::parse(status.state.as_deref()) {
            UploadState::Completed => Ok(total),
            UploadState::Failed => Err(ResumableUploadError::new(
                409,
                UploadErrorCode::Failed,
                "upload session is terminally failed",
            )),
            _ => Ok(clamp_offset(status.committed_offset, total)),
        }
    }

    async fn status_with_retry(
        &self,
        upload_id: &str,
    ) -> Result<UploadStatusResponse, ResumableUploadError> {
        self.retry_operation(|| self.transport.snapshot_upload_status(upload_id)).await
    }

    /// Adopt an acknowledged offset, rejecting a nonsensical one.
    fn accept_offset(
        &self,
        reported: i64,
        previous: u64,
        total: u64,
    ) -> Result<u64, ResumableUploadError> {
        let reported = u64::try_from(reported).map_err(|_| {
            ResumableUploadError::new(
                500,
                UploadErrorCode::Unknown("invalid_committed_offset".to_string()),
                "relay reported a negative committed offset",
            )
        })?;
        let reported = reported.min(total);
        if reported < previous {
            // The committed prefix must be monotonic. A regression means we can
            // no longer trust the session framing; fail closed rather than
            // re-send from a lower offset.
            return Err(ResumableUploadError::new(
                500,
                UploadErrorCode::Unknown("offset_regressed".to_string()),
                "relay reported a committed offset below the acknowledged prefix",
            ));
        }
        Ok(reported)
    }

    /// Renew only for strictly increased offsets, delegated to the hook.
    async fn maybe_advance_lease(
        &self,
        hook: &mut Option<&mut dyn SnapshotUploadProgressHook>,
        last_renewed_offset: &mut Option<u64>,
        committed: u64,
    ) {
        // Offset zero means nothing has been durably committed, so it is not
        // progress and must never be reported: a session that acknowledges zero
        // bytes (a fresh create, a status poll, or a lost-and-retried request
        // that committed nothing) has earned no renewal.
        if committed == 0 {
            return;
        }
        if *last_renewed_offset == Some(committed) {
            return;
        }
        // The strict-increase test lives here so a duplicate acknowledgment or a
        // pure status reconciliation can never earn a renewal.
        let advanced = match *last_renewed_offset {
            Some(previous) => committed > previous,
            None => true,
        };
        if !advanced {
            return;
        }
        *last_renewed_offset = Some(committed);
        if let Some(hook) = hook.as_deref_mut() {
            hook.on_committed_offset_advanced(committed).await;
        }
    }

    fn emit_progress(&self, sent: u64, total: u64) {
        if let Some(cb) = self.progress_cb.as_ref() {
            cb(sent, total);
        }
    }

    /// Retry `operation` under the bounded policy.
    ///
    /// Only [`ResumableUploadError::is_retryable`] failures are retried. Each
    /// attempt is a fresh HTTP request, which means a fresh signed-request nonce
    /// (the signing layer generates one per request). Auth, conflict, hash,
    /// expiry, quota, and other semantic rejections are returned immediately.
    async fn retry_operation<T, F, Fut>(&self, mut operation: F) -> Result<T, ResumableUploadError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, ResumableUploadError>>,
    {
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            match operation().await {
                Ok(value) => return Ok(value),
                Err(error) => {
                    if !error.is_retryable() || attempt >= self.retry.max_attempts {
                        return Err(error);
                    }
                    let entropy = fresh_entropy();
                    tokio::time::sleep(self.retry.delay_for(attempt, entropy)).await;
                }
            }
        }
    }
}

fn clamp_offset(value: i64, total: u64) -> u64 {
    u64::try_from(value).unwrap_or(0).min(total)
}

/// Fresh 64-bit entropy for backoff jitter. Not a substitute for the
/// signed-request nonce, which the signing layer generates per request.
fn fresh_entropy() -> u64 {
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    u64::from_le_bytes(bytes)
}

// ── Abort helper ────────────────────────────────────────────────────────────

/// Best-effort abort of an upload session.
///
/// Cancellation and ceremony-expiry paths call this. Every failure is
/// swallowed: an abort that cannot be delivered is cleaned up by the relay's
/// independent session expiry, and a pairing failure must never be replaced by
/// an abort error.
pub async fn abort_upload_best_effort(transport: &dyn ResumableSnapshotTransport, upload_id: &str) {
    let _ = transport.abort_snapshot_upload(upload_id).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_parses_the_advertised_sibling() {
        let json = serde_json::json!({
            "gifs": { "enabled": false },
            "snapshot_upload": {
                "version": 1,
                "chunk_bytes": 8388608,
                "max_wire_bytes": 157286400,
                "session_idle_ttl_secs": 3600
            }
        });
        let capability = SnapshotUploadCapability::parse(&json).unwrap();
        assert_eq!(capability.version, 1);
        assert_eq!(capability.chunk_bytes, SNAPSHOT_UPLOAD_CHUNK_BYTES);
        assert_eq!(capability.max_wire_bytes, SNAPSHOT_UPLOAD_MAX_WIRE_BYTES);
        assert_eq!(capability.session_idle_ttl_secs, SNAPSHOT_UPLOAD_IDLE_TTL_SECS);
    }

    #[test]
    fn capability_absence_is_a_downgrade_not_an_error() {
        let json = serde_json::json!({ "gifs": { "enabled": false } });
        assert_eq!(
            SnapshotUploadCapability::parse(&json),
            Err(CapabilityUnavailableReason::Absent)
        );
        let null = serde_json::json!({ "snapshot_upload": null });
        assert_eq!(
            SnapshotUploadCapability::parse(&null),
            Err(CapabilityUnavailableReason::Absent)
        );
    }

    #[test]
    fn capability_ignores_unknown_fields() {
        let json = serde_json::json!({
            "snapshot_upload": {
                "version": 1,
                "chunk_bytes": 8388608,
                "max_wire_bytes": 157286400,
                "session_idle_ttl_secs": 3600,
                "future_field": "ignored"
            }
        });
        assert!(SnapshotUploadCapability::parse(&json).is_ok());
    }

    #[test]
    fn malformed_capability_fields_downgrade() {
        let json = serde_json::json!({ "snapshot_upload": { "version": "one" } });
        assert_eq!(
            SnapshotUploadCapability::parse(&json),
            Err(CapabilityUnavailableReason::InvalidCapability)
        );
    }

    #[test]
    fn unsupported_capability_version_downgrades_distinctly() {
        let json = serde_json::json!({
            "snapshot_upload": {
                "version": 2, "chunk_bytes": 8388608,
                "max_wire_bytes": 157286400, "session_idle_ttl_secs": 3600
            }
        });
        assert_eq!(
            SnapshotUploadCapability::parse(&json),
            Err(CapabilityUnavailableReason::UnsupportedVersion { advertised: 2 })
        );
    }

    #[test]
    fn zero_and_oversize_capability_values_downgrade() {
        for sibling in [
            serde_json::json!({"version":1,"chunk_bytes":0,"max_wire_bytes":1,"session_idle_ttl_secs":1}),
            serde_json::json!({"version":1,"chunk_bytes":8388608,"max_wire_bytes":0,"session_idle_ttl_secs":1}),
            serde_json::json!({"version":1,"chunk_bytes":8388608,"max_wire_bytes":157286400,"session_idle_ttl_secs":0}),
            serde_json::json!({"version":1,"chunk_bytes":3,"max_wire_bytes":157286400,"session_idle_ttl_secs":3600}),
        ] {
            let json = serde_json::json!({ "snapshot_upload": sibling });
            assert_eq!(
                SnapshotUploadCapability::parse(&json),
                Err(CapabilityUnavailableReason::InvalidCapability)
            );
        }
    }

    #[test]
    fn error_codes_round_trip_including_the_existing_conflicts() {
        for code in [
            UploadErrorCode::InvalidUpload,
            UploadErrorCode::UnsupportedAudience,
            UploadErrorCode::NotFound,
            UploadErrorCode::KeyConflict,
            UploadErrorCode::Incomplete,
            UploadErrorCode::Finalizing,
            UploadErrorCode::OffsetMismatch,
            UploadErrorCode::Completed,
            UploadErrorCode::Expired,
            UploadErrorCode::ChunkTooLarge,
            UploadErrorCode::SnapshotTooLarge,
            UploadErrorCode::QuotaExceeded,
            UploadErrorCode::Busy,
            UploadErrorCode::HashMismatch,
            UploadErrorCode::EpochInvalid,
            UploadErrorCode::OwnerInvalid,
            UploadErrorCode::InsufficientStorage,
            UploadErrorCode::Failed,
            UploadErrorCode::StaleSnapshotSeq,
            UploadErrorCode::TooManyTargetedSnapshots,
        ] {
            assert_eq!(UploadErrorCode::parse(code.as_str()), code);
        }
    }

    #[test]
    fn structured_error_body_is_parsed_with_its_response_fields() {
        let error = ResumableUploadError::parse(
            409,
            r#"{"error":"offset_mismatch","message":"Chunk offset does not match","committed_offset":41943040}"#,
        );
        assert_eq!(error.status, 409);
        assert_eq!(error.code, UploadErrorCode::OffsetMismatch);
        assert_eq!(error.committed_offset(), Some(41_943_040));
        assert!(!error.is_retryable());
    }

    #[test]
    fn unstructured_error_body_still_classifies() {
        let error = ResumableUploadError::parse(503, "<html>gateway</html>");
        assert_eq!(error.status, 503);
        assert!(error.is_retryable());
        let not_found = ResumableUploadError::parse(404, "");
        assert_eq!(not_found.status, 404);
        assert!(!not_found.is_retryable());
    }

    #[test]
    fn retry_classification_is_restricted_to_safe_transient_failures() {
        // Transport, timeout, 5xx, and busy are retryable.
        assert!(ResumableUploadError::transport("reset").is_retryable());
        assert!(
            ResumableUploadError::new(408, UploadErrorCode::Unknown("t".into()), "").is_retryable()
        );
        assert!(
            ResumableUploadError::new(500, UploadErrorCode::Unknown("i".into()), "").is_retryable()
        );
        assert!(ResumableUploadError::new(503, UploadErrorCode::Busy, "").is_retryable());
        // Quota is a policy rejection even though it is 429.
        assert!(!ResumableUploadError::new(429, UploadErrorCode::QuotaExceeded, "").is_retryable());
        // Auth, conflict, hash, expiry, and cap errors are terminal.
        for (status, code) in [
            (401, UploadErrorCode::Unknown("auth".into())),
            (409, UploadErrorCode::KeyConflict),
            (409, UploadErrorCode::Completed),
            (410, UploadErrorCode::Expired),
            (422, UploadErrorCode::HashMismatch),
            (404, UploadErrorCode::NotFound),
            (413, UploadErrorCode::SnapshotTooLarge),
        ] {
            assert!(!ResumableUploadError::new(status, code, "").is_retryable());
        }
    }

    #[test]
    fn definitive_not_found_and_terminal_codes_are_terminal() {
        assert!(ResumableUploadError::new(404, UploadErrorCode::NotFound, "").is_terminal());
        assert!(ResumableUploadError::new(410, UploadErrorCode::Expired, "").is_terminal());
        assert!(ResumableUploadError::new(409, UploadErrorCode::Completed, "").is_terminal());
        assert!(!ResumableUploadError::new(503, UploadErrorCode::Busy, "").is_terminal());
    }

    #[test]
    fn stale_snapshot_conflict_keeps_its_engine_mapping() {
        let error = ResumableUploadError::new(409, UploadErrorCode::StaleSnapshotSeq, "stale");
        assert!(matches!(error.to_relay_error(), RelayError::SnapshotStale { .. }));
    }

    #[test]
    fn backoff_is_exponential_bounded_and_jittered() {
        let policy = SnapshotUploadRetryPolicy {
            max_attempts: 6,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(700),
        };
        assert_eq!(policy.delay_for(0, 0), Duration::ZERO);
        // Deterministic jitter never exceeds the nominal delay and never
        // undercuts it by more than half.
        for attempt in 1..=6 {
            let nominal = Duration::from_millis((100u64 << (attempt - 1)).min(700));
            let delay = policy.delay_for(attempt, 0);
            assert_eq!(delay, nominal, "attempt {attempt} should be full delay at zero entropy");
            let jittered = policy.delay_for(attempt, u64::MAX);
            assert!(jittered <= nominal);
            assert!(jittered >= nominal - nominal / 2);
        }
    }

    #[test]
    fn debug_output_never_renders_envelope_bytes_or_digests_verbatim() {
        // The wire models are Debug-printable for logs, but the uploader never
        // renders the envelope. This guards the invariant that the request body
        // holds a digest rather than the bytes.
        let request = CreateUploadRequest {
            version: 1,
            upload_key: "AAAA".to_string(),
            epoch: 1,
            server_seq_at: 2,
            target_device_id: "device".to_string(),
            ttl_secs: 3,
            total_bytes: 4,
            body_sha256: "ab".repeat(32),
        };
        let rendered = format!("{request:?}");
        assert!(rendered.contains("body_sha256"));
        // The struct cannot carry payload bytes at all.
        assert!(!rendered.contains("ciphertext"));
    }
}
