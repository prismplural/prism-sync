//! Size constants for the pair-time bootstrap snapshot.
//!
//! The snapshot travels as a zstd-compressed blob wrapped in a
//! `SignedBatchEnvelope`: zstd bytes → XChaCha20-Poly1305 ciphertext (+16 B
//! tag + 24 B nonce) → base64 inside JSON with hybrid Ed25519 + ML-DSA-65
//! signatures. Base64 alone is ~1.37×; plus signature fields and headers.
//! We budget 1.5× to go from the compressed payload cap to the wire cap.
//!
//! These values are intentionally duplicated in
//! `prism-sync-core` (`src/snapshot_limits.rs`) because `prism-sync-relay`
//! cannot depend on `prism-sync-core`. A cross-crate parity test enforces
//! they do not drift.

/// Maximum compressed (zstd) snapshot payload the client is allowed to
/// produce. Enforced locally in `bootstrap_existing_state` before any
/// upload is attempted.
pub const MAX_SNAPSHOT_COMPRESSED_BYTES: usize = 100 * 1024 * 1024;

/// Maximum wire-size (post-encryption, post-base64, post-signature) body
/// the relay accepts on `PUT /v1/sync/{id}/snapshot`. Enforced both by a
/// tower `RequestBodyLimitLayer` on the snapshot route and by an explicit
/// `body.len()` check inside the handler.
pub const MAX_SNAPSHOT_WIRE_BYTES: usize = 150 * 1024 * 1024;

/// Concurrent admission is separate from retained-storage limits.
pub const MAX_TARGETED_SNAPSHOTS_PER_GROUP: i64 = 4;

/// Older unregistered targets release slots but retain snapshots and bootstrap tails.
pub const TARGETED_SNAPSHOT_PAIRING_WINDOW_SECS: i64 = 30 * 60;

/// Preserve the previous payload budget while allowing more small abandoned attempts.
pub const MAX_RETAINED_TARGETED_SNAPSHOTS_PER_GROUP: i64 = 32;
pub const MAX_RETAINED_TARGETED_SNAPSHOT_BYTES: u64 =
    MAX_SNAPSHOT_WIRE_BYTES as u64 * MAX_TARGETED_SNAPSHOTS_PER_GROUP as u64;

/// TTL (seconds) the relay applies to a targeted snapshot uploaded without an
/// explicit `X-Snapshot-TTL`. Targeted rows are pair-time bootstrap blobs that
/// must not outlive their pairing window; 24h bounds a stalled pairing while
/// leaving room for a backgrounded joiner to finish. Group-wide (untargeted)
/// uploads keep their existing semantics (no relay-imposed default).
pub const DEFAULT_TARGETED_SNAPSHOT_TTL_SECS: i64 = 86_400;
