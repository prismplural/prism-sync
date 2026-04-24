//! Snapshot size limits shared across client and relay code.
//!
//! These constants are duplicated deliberately in `prism-sync-relay` because
//! the relay crate has no dependency on `prism-sync-core`. A cross-crate
//! parity test guards against drift — see
//! `docs/plans/first-device-bootstrap-snapshot.md` (Phase A.4).
//!
//! # Why two numbers?
//!
//! The "compressed" limit gates the raw zstd-compressed snapshot blob we
//! export locally via `SyncStorage::export_snapshot`. The "wire" limit gates
//! the outer HTTP body that actually hits the relay — that body is the
//! compressed blob encrypted with XChaCha20-Poly1305, base64-encoded, and
//! wrapped in a JSON `SignedBatchEnvelope` with hybrid Ed25519 + ML-DSA-65
//! signatures. Base64 alone adds ~37%; signature fields, nonce, and JSON
//! headers account for the rest. 1.5× is a safe wire budget.

/// Maximum size of the raw zstd-compressed snapshot blob as returned by
/// `SyncStorage::export_snapshot`.
///
/// Enforced locally by the first-device bootstrap size probe before the
/// user tries to pair.
pub const MAX_SNAPSHOT_COMPRESSED_BYTES: usize = 100 * 1024 * 1024;

/// Maximum size of the HTTP request body carrying a snapshot to the relay.
///
/// Larger than `MAX_SNAPSHOT_COMPRESSED_BYTES` because the compressed blob
/// is further encrypted, base64-encoded, and wrapped in a signed JSON
/// envelope before transmission.
pub const MAX_SNAPSHOT_WIRE_BYTES: usize = 150 * 1024 * 1024;
