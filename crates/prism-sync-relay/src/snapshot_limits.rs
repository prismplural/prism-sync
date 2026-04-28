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
