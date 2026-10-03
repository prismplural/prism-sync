//! Resumable pair-time snapshot uploads (lean v1 relay lifecycle).
//!
//! This module owns the relay half of the "Resumable Pair-Time Snapshot Upload"
//! lean v1 contract: the fixed protocol constants, the persisted
//! `snapshot_uploads` schema, and the on-disk **staging** store for a
//! partially-received envelope.
//!
//! Three shapes of state are involved and they must not be confused:
//!
//! - **DB session row** (`snapshot_uploads`) — the authoritative record:
//!   immutable signed create metadata, ownership, the candidate's `blob_ref`,
//!   the committed offset, lifecycle state, and both expiries. It is also the
//!   byte reservation, so there is deliberately **no** separate counter table.
//! - **Staging file** (`<snapshot_root>/<sync_id>/<blob_ref>`) — the exact
//!   envelope bytes written so far, at the unique name the completed snapshot
//!   row will eventually reference. It is invisible to `GET /snapshot` until
//!   publication commits.
//! - **Publication** — the completion transaction that swaps the snapshot row
//!   onto that same `blob_ref`. Reusing the name is what makes a crash between
//!   file write and DB commit self-healing: the file is either an orphan (swept
//!   after the grace period) or the published bytes, never a half-referenced
//!   state.
//!
//! Because the candidate is written directly to its final name and stays
//! invisible until referenced, no cross-filesystem rename is needed and
//! completion only has to publish a small reference. That is the whole reason
//! `PUT /snapshot` file backing had to land first.
//!
//! Deliberately **not** here:
//!
//! - any plaintext or envelope metadata parsing beyond the immutable create
//!   fields the client signs (the relay never decrypts or reserializes);
//! - any pairing-to-upload linkage (see the opaque pairing lease instead);
//! - any per-chunk DB row (one contiguous file + committed offset is enough for
//!   sequential upload and keeps DB writes bounded).
//!
//! # State machine
//!
//! ```text
//! active -> finalizing -> completed
//!    |          |
//!    +----------+-> failed
//! ```
//!
//! `completed` and `failed` are terminal. `finalizing` is retained (rather than
//! jumping straight from `active` to `completed`) so a crash during completion
//! is observable and recoverable: status reports it, chunks answer
//! `409 upload_finalizing`, and abort may fail it only before a publication
//! transaction commits. Terminal rows hold the stable HTTP status and machine
//! code needed to answer a retry identically — no workflow log, no serialized
//! response store.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

// ── Protocol constants (lean v1) ─────────────────────────────────────────────
//
// Lean v1 deliberately keeps this surface tiny: one server-selected chunk size,
// one fixed wire maximum, and a handful of TTLs. Deployments may be *stricter*
// than these ceilings but must not advertise a value the routes cannot honor, so
// the chunk size is a compile-time protocol constant rather than a runtime knob
// (`Config::snapshot_upload` only ever narrows the resource limits around it).

/// Protocol version understood by this relay.
pub const SNAPSHOT_UPLOAD_VERSION_V1: u16 = 1;

/// Fixed server-selected chunk size for v1, in bytes (8 MiB).
///
/// The route's body limit is this value exactly. A restart or a configuration
/// change therefore cannot wedge a live v1 session before semantic validation:
/// the persisted per-session `chunk_bytes` only decides what is *semantically*
/// acceptable, never what the transport will accept.
pub const SNAPSHOT_UPLOAD_CHUNK_BYTES: usize = 8 * 1024 * 1024;

/// Maximum total envelope size accepted for a resumable upload, in bytes
/// (150 MiB). Mirrors the existing single-PUT wire cap in
/// [`crate::snapshot_limits::MAX_SNAPSHOT_WIRE_BYTES`]; a relay's advertised
/// resumable maximum must be at least its single-PUT policy cap so a new client
/// cannot regress relative to an old one. A cross-check in `Config` enforces it.
pub const SNAPSHOT_UPLOAD_MAX_WIRE_BYTES: u64 =
    crate::snapshot_limits::MAX_SNAPSHOT_WIRE_BYTES as u64;

/// Idle session TTL in seconds (1 hour). An accepted **new-offset** chunk
/// refreshes it, capped by the absolute expiry. Status and committed-range
/// retries never do.
pub const SNAPSHOT_UPLOAD_IDLE_TTL_SECS: i64 = 3600;

/// Absolute, nonrenewable session lifetime in seconds (4 hours), measured from
/// `created_at`. Chunk acceptance may never extend it.
pub const SNAPSHOT_UPLOAD_MAX_SESSION_SECS: i64 = 4 * 3600;

/// Retention of a terminal (`completed`/`failed`) session row after it became
/// terminal, in seconds (1 hour). Within this window a lost create/complete
/// response is answered from the recorded terminal result; afterwards the ID is
/// indistinguishable from an unknown one.
pub const SNAPSHOT_UPLOAD_TERMINAL_TTL_SECS: i64 = 3600;

/// Maximum snapshot TTL a create request may declare, in seconds (7 days).
pub const SNAPSHOT_UPLOAD_MAX_SNAPSHOT_TTL_SECS: i64 = 604_800;

/// Grace period (seconds) before a file with no referencing row is swept. Must
/// be comfortably longer than the cleanup interval and than any in-flight
/// upload, so a candidate written just before its row commits is never reaped.
pub const SNAPSHOT_UPLOAD_ORPHAN_GRACE_SECS: i64 = 86_400;

/// Binary-default global ceiling on sum of reserved bytes across all groups:
/// `16 * max_wire_bytes`. Conservative so self-hosting stays operable without
/// configuration; hosted production must set explicit capacity-derived values.
pub const SNAPSHOT_UPLOAD_DEFAULT_GLOBAL_RESERVED_BYTES: u64 = 16 * SNAPSHOT_UPLOAD_MAX_WIRE_BYTES;

/// Binary-default per-group ceiling on reserved bytes: `4 * max_wire_bytes`,
/// matching the targeted-audience cap.
pub const SNAPSHOT_UPLOAD_DEFAULT_GROUP_RESERVED_BYTES: u64 = 4 * SNAPSHOT_UPLOAD_MAX_WIRE_BYTES;

/// Binary-default minimum free-space reserve: `2 * max_wire_bytes`.
pub const SNAPSHOT_UPLOAD_DEFAULT_FREE_SPACE_RESERVE_BYTES: u64 =
    2 * SNAPSHOT_UPLOAD_MAX_WIRE_BYTES;

/// Max create requests per uploader device per rate window (in-process limiter).
pub const SNAPSHOT_UPLOAD_DEFAULT_CREATE_RATE_LIMIT: u32 = 10;

/// Window for the per-device create rate limit, in seconds.
pub const SNAPSHOT_UPLOAD_DEFAULT_CREATE_RATE_WINDOW_SECS: u64 = 60;

/// Maximum simultaneous in-flight chunk writes. Transient shedding returns
/// retryable `503 upload_busy` — never a quota-coded 429.
pub const SNAPSHOT_UPLOAD_DEFAULT_CHUNK_CONCURRENCY: usize = 4;

/// Wall-clock timeout for one chunk request, in seconds. Each request is bounded
/// to [`SNAPSHOT_UPLOAD_CHUNK_BYTES`], so this is generous for a slow link while
/// still bounding a stuck connection.
pub const SNAPSHOT_UPLOAD_CHUNK_TIMEOUT_SECS: u64 = 120;

/// Wall-clock timeout for create/status/complete/abort, in seconds.
pub const SNAPSHOT_UPLOAD_CONTROL_TIMEOUT_SECS: u64 = 120;

/// Maximum accepted JSON create-body size, in bytes. Independent of (and far
/// below) the chunk route's exact body limit.
pub const SNAPSHOT_UPLOAD_CREATE_BODY_MAX_BYTES: usize = 4096;

/// Length of a client-generated `upload_key` (random bytes, base64-encoded on
/// the wire). 32 bytes = 256 bits, matching the spec's "32 random bytes".
pub const SNAPSHOT_UPLOAD_KEY_BYTES: usize = 32;

/// Length of the lowercase hex SHA-256 the create body must carry.
pub const SNAPSHOT_UPLOAD_SHA256_HEX_LEN: usize = 64;

// ── Lifecycle state ─────────────────────────────────────────────────────────

/// Persisted lifecycle state of one upload session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadState {
    /// Accepting chunks at `committed_offset`.
    Active,
    /// A completion operation owns the session (file sync, hash, publication).
    Finalizing,
    /// Terminal success: the snapshot row references this `blob_ref`.
    Completed,
    /// Terminal failure (semantic rejection, expiry, abort, or corruption).
    Failed,
}

impl UploadState {
    /// Wire/DB spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Finalizing => "finalizing",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    /// Parse the DB spelling. Unknown values fail closed to `Failed` so an
    /// unrecognized row can never be treated as writable.
    pub fn from_db(value: &str) -> Self {
        match value {
            "active" => Self::Active,
            "finalizing" => Self::Finalizing,
            "completed" => Self::Completed,
            _ => Self::Failed,
        }
    }

    /// True for states that hold a live byte reservation.
    pub fn is_nonterminal(self) -> bool {
        matches!(self, Self::Active | Self::Finalizing)
    }

    /// True for states that reject all mutation.
    pub fn is_terminal(self) -> bool {
        !self.is_nonterminal()
    }
}

// ── Persisted schema ────────────────────────────────────────────────────────

/// Additive `snapshot_uploads` table plus its expiry index.
///
/// One row per session, and the row **is** the byte reservation: reserved
/// bytes are derived as an indexed `SUM(total_bytes)` over nonterminal rows
/// inside the serialized writer transaction. At this scale an authoritative sum
/// is safer than a second counter table that can drift and needs its own
/// crash-sensitive repair, and the transition that ends a reservation is the
/// same transaction that ends the lifecycle state.
///
/// The `UNIQUE(sync_id, uploader_device_id, upload_key)` constraint is what
/// makes create idempotent; it is database-enforced rather than checked-then-
/// inserted so a race cannot create two sessions for one client key.
///
/// `ON DELETE CASCADE` on the group FK means account deletion removes session
/// rows transactionally (and the route then drops the group's snapshot
/// directory, which the candidate files live in).
pub const SNAPSHOT_UPLOADS_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS snapshot_uploads (
        upload_id             TEXT PRIMARY KEY,
        upload_key            TEXT NOT NULL,
        sync_id               TEXT NOT NULL,
        uploader_device_id    TEXT NOT NULL,
        target_device_id      TEXT NOT NULL,
        epoch                 INTEGER NOT NULL,
        server_seq_at         INTEGER NOT NULL,
        snapshot_ttl_secs     INTEGER NOT NULL,
        total_bytes           INTEGER NOT NULL,
        chunk_bytes           INTEGER NOT NULL,
        committed_offset      INTEGER NOT NULL DEFAULT 0,
        body_sha256           BLOB NOT NULL,
        blob_ref              TEXT NOT NULL,
        state                 TEXT NOT NULL,
        terminal_code         TEXT,
        terminal_status       INTEGER,
        terminal_expires_at   INTEGER,
        created_at            INTEGER NOT NULL,
        updated_at            INTEGER NOT NULL,
        idle_expires_at       INTEGER NOT NULL,
        absolute_expires_at   INTEGER NOT NULL,
        -- Recorded detail of a `stale_snapshot_seq` terminal result: the competing
        -- snapshot's `server_seq_at` and audience. Stored so an idempotent
        -- completion retry reproduces the **same** structured body the original
        -- refusal sent — the client's suppression matrix compares those two
        -- fields, so a zeroed replay would silently flip its verdict. NULL for
        -- every other terminal code.
        terminal_server_seq_at    INTEGER,
        terminal_target_device_id TEXT,
        UNIQUE(sync_id, uploader_device_id, upload_key),
        FOREIGN KEY (sync_id) REFERENCES sync_groups(sync_id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_snapshot_uploads_expiry
        ON snapshot_uploads(state, idle_expires_at, absolute_expires_at);
    CREATE INDEX IF NOT EXISTS idx_snapshot_uploads_owner
        ON snapshot_uploads(sync_id, uploader_device_id, state);
    CREATE INDEX IF NOT EXISTS idx_snapshot_uploads_terminal
        ON snapshot_uploads(state, terminal_expires_at);
";

// ── Validation ──────────────────────────────────────────────────────────────

/// True when `value` is a canonical lowercase hex SHA-256 (exactly 64 chars,
/// no uppercase, no `0x` prefix, no whitespace). Canonical form only — the
/// client signs the string it sends, so accepting a second spelling would let
/// two distinct create bodies describe the same bytes.
pub fn is_canonical_sha256_hex(value: &str) -> bool {
    value.len() == SNAPSHOT_UPLOAD_SHA256_HEX_LEN
        && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Decode the canonical hex SHA-256 into its 32 raw bytes.
pub fn decode_sha256_hex(value: &str) -> Option<[u8; 32]> {
    if !is_canonical_sha256_hex(value) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in value.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// Encode a SHA-256 digest as canonical lowercase hex.
pub fn encode_sha256_hex(digest: &[u8; 32]) -> String {
    hex::encode(digest)
}

/// Generate a fresh opaque upload ID.
///
/// 128 bits from the platform CSPRNG, rendered as 32 lowercase hex characters.
/// Deliberately the same shape as a snapshot `blob_ref`, so `is_valid_blob_ref`
/// doubles as the upload-ID syntax check and neither can ever carry a client
/// path component. Upload IDs are **not** credentials: every operation still
/// requires the owner's bearer session and hybrid signature.
pub fn generate_upload_id() -> String {
    crate::snapshot_store::generate_blob_ref()
}

/// Validate an opaque upload ID from a request path. Opaque, fixed-shape, and
/// never a path — so a crafted segment cannot address another row's storage.
pub fn is_valid_upload_id(upload_id: &str) -> bool {
    crate::snapshot_store::is_valid_blob_ref(upload_id)
}

/// SHA-256 of the exact envelope bytes (used for the staged-file integrity
/// check at completion). This is transport integrity only: it detects staging
/// corruption, and the joiner's signature/AEAD verification remains
/// authoritative for end-to-end authenticity.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(data).into();
    encode_sha256_hex(&digest)
}

// ── Staging store ───────────────────────────────────────────────────────────

/// Why a staging operation could not proceed.
#[derive(Debug)]
pub enum StagingError {
    /// The file is shorter than the committed offset: the DB says bytes are
    /// acknowledged that are not on disk. Unrecoverable — the session must fail
    /// as `staging_corrupt`; the committed offset is never silently lowered.
    StagingCorrupt(String),
    /// The candidate file is missing after a nonzero committed offset, or could
    /// not be created at offset zero.
    Missing(String),
    /// An unexpected I/O failure. The session stays recoverable.
    Io(std::io::Error),
}

impl std::fmt::Display for StagingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StagingCorrupt(msg) => write!(f, "staging corrupt: {msg}"),
            Self::Missing(msg) => write!(f, "staging file missing: {msg}"),
            Self::Io(e) => write!(f, "staging I/O error: {e}"),
        }
    }
}

impl From<std::io::Error> for StagingError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Classify a failure to resolve the per-group directory.
///
/// An `InvalidInput` means the path is unverifiable — the group directory exists
/// as a symlink, or the `sync_id` is not a valid group identifier. Both are
/// permanent, so the session must fail closed as corruption. Collapsing them
/// into the generic I/O case would surface a 500 that a client would retry
/// forever against a condition retrying cannot fix.
fn map_group_dir_error(e: std::io::Error) -> StagingError {
    if e.kind() == std::io::ErrorKind::InvalidInput {
        StagingError::StagingCorrupt(e.to_string())
    } else {
        StagingError::Io(e)
    }
}

/// Open/create a candidate file for an active session and reconcile its actual
/// length with the committed offset **before** any new bytes are written.
///
/// Recovery rules (spec §12), applied under the caller's per-upload lock:
///
/// | actual length          | action                                        |
/// |------------------------|-----------------------------------------------|
/// | `== committed_offset`  | normal; continue                              |
/// | `> committed_offset`   | crash after write, before DB commit → truncate to `committed_offset` and sync |
/// | `< committed_offset`   | committed metadata refers to absent bytes → [`StagingError::StagingCorrupt`] |
/// | missing, offset `0`    | recreate with create-new semantics            |
/// | missing, offset `> 0`  | [`StagingError::StagingCorrupt`] via [`StagingError::Missing`] |
///
/// The file is always opened with create-new (`O_CREAT|O_EXCL`) or, for an
/// existing candidate, with no-follow semantics, so a planted symlink at the
/// path is never traversed. `O_APPEND` is never used — callers write with
/// positioned `write_at`, which confines a delayed duplicate to its intended
/// range.
pub fn open_candidate_reconciled(
    root: &Path,
    sync_id: &str,
    blob_ref: &str,
    committed_offset: u64,
) -> Result<std::fs::File, StagingError> {
    if !crate::snapshot_store::is_valid_blob_ref(blob_ref) {
        return Err(StagingError::StagingCorrupt("invalid blob reference".to_string()));
    }
    let (group_dir, created_dir) = crate::snapshot_store::ensure_snapshot_group_dir(root, sync_id)
        .map_err(map_group_dir_error)?;
    // A group directory created by this call is a new entry in the snapshot root,
    // and the root is the durable anchor for it. Synchronize the root before
    // anything is written inside, mirroring
    // [`crate::snapshot_store::write_blob_durably`], so a power loss cannot leave
    // acknowledged bytes reachable only through a directory entry that never
    // reached stable storage.
    if created_dir {
        crate::snapshot_store::sync_snapshot_dir(root).map_err(StagingError::Io)?;
    }
    let path = group_dir.join(blob_ref);

    // `symlink_metadata` inspects the link itself, so a planted symlink is
    // detected rather than followed. An unreadable/looping path is an error, and
    // the caller fails closed.
    let existing = match std::fs::symlink_metadata(&path) {
        Ok(meta) => Some(meta),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(StagingError::Io(e)),
    };

    let file = match existing {
        Some(meta) => {
            if meta.file_type().is_symlink() {
                return Err(StagingError::StagingCorrupt(
                    "candidate path is a symlink".to_string(),
                ));
            }
            if !meta.is_file() {
                return Err(StagingError::StagingCorrupt(
                    "candidate path is not a regular file".to_string(),
                ));
            }
            open_existing_candidate(&path)?
        }
        None => {
            if committed_offset > 0 {
                // Bytes were acknowledged but the file is gone. Never silently
                // lower the offset: require a new upload.
                return Err(StagingError::Missing(format!(
                    "candidate missing with committed offset {committed_offset}"
                )));
            }
            open_new_candidate(&path)?
        }
    };

    let actual = file.metadata().map_err(StagingError::Io)?.len();
    if actual < committed_offset {
        return Err(StagingError::StagingCorrupt(format!(
            "file length {actual} is below committed offset {committed_offset}"
        )));
    }
    if actual > committed_offset {
        // Crash between the positioned write and the offset commit. Positioned
        // writes plus this truncate keep every acknowledged prefix intact and
        // discard only unacknowledged trailing bytes. `set_len`/`sync_data` take
        // `&self`, so no `mut` binding is needed here.
        file.set_len(committed_offset).map_err(StagingError::Io)?;
        file.sync_data().map_err(StagingError::Io)?;
    }
    Ok(file)
}

/// Open a candidate that already exists, refusing to follow a final symlink.
fn open_existing_candidate(path: &Path) -> Result<std::fs::File, StagingError> {
    // `rustix::fs::open` with `NOFOLLOW` refuses to traverse a symlink swapped in
    // after the metadata probe. The candidate name is relay-generated and unique
    // per upload, so a symlink here can only be an attack or filesystem damage.
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .map_err(StagingError::Io)?;
    Ok(std::fs::File::from(fd))
}

/// Create a brand-new candidate with create-new semantics and restrictive mode.
fn open_new_candidate(path: &Path) -> Result<std::fs::File, StagingError> {
    // `CREATE|EXCL` is `O_CREAT|O_EXCL`, which per POSIX also refuses to follow a
    // symlink at that path and fails if any file already owns the name.
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        // Restrictive mode: snapshot ciphertext is opaque, but the group tree is
        // per-tenant and must not be world-readable.
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map_err(std::io::Error::from)
    .map_err(StagingError::Io)?;
    let file = std::fs::File::from(fd);
    // Synchronize the parent directory so the new entry survives a power loss
    // before the DB ever references it. A candidate lost here is only an orphan,
    // but an entry present in the directory *and* in the DB must be durable in
    // both.
    if let Some(parent) = path.parent() {
        crate::snapshot_store::sync_snapshot_dir(parent).map_err(StagingError::Io)?;
    }
    Ok(file)
}

/// Durably write `data` at `offset` in the already-open candidate.
///
/// Ordering is exactly the spec's: positioned write, flush, `sync_data`. The
/// caller commits the increased offset only after this returns, so an
/// acknowledged offset always refers to bytes that are on stable storage.
/// `O_APPEND` is never used, so a delayed duplicate can only rewrite its own
/// range.
pub fn write_chunk_at(
    file: &mut std::fs::File,
    offset: u64,
    data: &[u8],
) -> Result<(), StagingError> {
    use std::os::unix::fs::FileExt;
    file.seek(SeekFrom::Start(offset)).map_err(StagingError::Io)?;
    file.write_all_at(data, offset).map_err(StagingError::Io)?;
    file.flush().map_err(StagingError::Io)?;
    file.sync_data().map_err(StagingError::Io)?;
    Ok(())
}

/// Verify a completed candidate against the create-time SHA-256 and the
/// declared total length, then make it durable for publication.
///
/// Steps, in order (spec §13): confirm the length matches `total_bytes`, hash the
/// full file, compare against `expected_sha256`, and finally `sync_all` the file
/// plus its parent directory so the directory entry cannot be discarded by a
/// power loss after the publication transaction commits.
///
/// The file is read in bounded windows, so a 150 MiB verification never
/// materializes the whole envelope in memory.
pub fn verify_and_sync_candidate(
    root: &Path,
    sync_id: &str,
    blob_ref: &str,
    total_bytes: u64,
    expected_sha256: &[u8; 32],
) -> Result<(), StagingError> {
    if !crate::snapshot_store::is_valid_blob_ref(blob_ref) {
        return Err(StagingError::StagingCorrupt("invalid blob reference".to_string()));
    }
    let (group_dir, _created) = crate::snapshot_store::ensure_snapshot_group_dir(root, sync_id)
        .map_err(map_group_dir_error)?;
    let path = group_dir.join(blob_ref);

    let mut file = open_existing_candidate(&path)?;
    let actual = file.metadata().map_err(StagingError::Io)?.len();
    if actual < total_bytes {
        return Err(StagingError::StagingCorrupt(format!(
            "staged file length {actual} is below declared total {total_bytes}"
        )));
    }
    if actual > total_bytes {
        // Should be unreachable (chunk rules cap the offset at `total_bytes`),
        // but never publish bytes the sender did not declare.
        return Err(StagingError::StagingCorrupt(format!(
            "staged file length {actual} exceeds declared total {total_bytes}"
        )));
    }

    file.seek(SeekFrom::Start(0)).map_err(StagingError::Io)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    let mut remaining = total_bytes;
    while remaining > 0 {
        let want = buf.len().min(remaining as usize);
        let read = file.read(&mut buf[..want]).map_err(StagingError::Io)?;
        if read == 0 {
            return Err(StagingError::StagingCorrupt(
                "staged file ended before its declared total".to_string(),
            ));
        }
        hasher.update(&buf[..read]);
        remaining -= read as u64;
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if !bool::from(digest_constant_time_eq(&digest, expected_sha256)) {
        return Err(StagingError::StagingCorrupt("staged file hash mismatch".to_string()));
    }

    // Durable ordering: data first, then the directory entry, then publication.
    file.flush().map_err(StagingError::Io)?;
    file.sync_all().map_err(StagingError::Io)?;
    drop(file);
    crate::snapshot_store::sync_snapshot_dir(&group_dir).map_err(StagingError::Io)?;
    Ok(())
}

/// Constant-time comparison of two SHA-256 digests.
fn digest_constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> subtle::Choice {
    use subtle::ConstantTimeEq;
    a.ct_eq(b)
}

/// Unlink a candidate file. Best-effort and never follows a symlink
/// (`remove_file` unlinks the link itself). Missing files are not an error.
pub fn remove_candidate(root: &Path, sync_id: &str, blob_ref: &str) {
    crate::snapshot_store::remove_blob(root, sync_id, blob_ref);
}

/// Resolve the on-disk path of a candidate, for tests and diagnostics.
pub fn candidate_path(root: &Path, sync_id: &str, blob_ref: &str) -> PathBuf {
    crate::snapshot_store::blob_path(root, sync_id, blob_ref)
}

/// Free bytes available to the relay on the filesystem holding `root`.
///
/// Used by the admission and chunk-write free-space gates. `f_bavail` (not
/// `f_bfree`) is the number that matters: it is what an unprivileged writer may
/// actually use, so reserved blocks do not make the relay believe it has room
/// it cannot touch.
pub fn available_bytes(root: &Path) -> std::io::Result<u64> {
    let stat = rustix::fs::statvfs(root).map_err(std::io::Error::from)?;
    Ok(stat.f_bavail.saturating_mul(stat.f_frsize))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNC_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn tmp_root() -> tempfile::TempDir {
        tempfile::TempDir::new().unwrap()
    }

    #[test]
    fn upload_ids_are_opaque_and_fixed_shape() {
        let id = generate_upload_id();
        assert!(is_valid_upload_id(&id));
        assert_eq!(id.len(), 32);
        assert_ne!(id, generate_upload_id(), "IDs must not repeat");
        assert!(!is_valid_upload_id("../../etc/passwd"));
        assert!(!is_valid_upload_id(""));
        assert!(!is_valid_upload_id(&"z".repeat(32)));
    }

    #[test]
    fn sha256_hex_validation_is_canonical_only() {
        let hex = sha256_hex(b"envelope");
        assert!(is_canonical_sha256_hex(&hex));
        assert!(decode_sha256_hex(&hex).is_some());
        assert!(!is_canonical_sha256_hex(&hex.to_uppercase()), "uppercase is not canonical");
        assert!(!is_canonical_sha256_hex(&hex[..63]), "short values are rejected");
        assert!(!is_canonical_sha256_hex(&format!("{hex}0")), "long values are rejected");
        assert!(!is_canonical_sha256_hex(&format!("0x{hex}")), "prefixes are rejected");
    }

    #[test]
    fn round_trips_sha256_hex() {
        let digest: [u8; 32] = Sha256::digest(b"payload").into();
        assert_eq!(decode_sha256_hex(&encode_sha256_hex(&digest)).unwrap(), digest);
        assert_eq!(sha256_hex(b"payload"), encode_sha256_hex(&digest));
    }

    #[test]
    fn state_machine_spellings_and_terminality() {
        for (state, name) in [
            (UploadState::Active, "active"),
            (UploadState::Finalizing, "finalizing"),
            (UploadState::Completed, "completed"),
            (UploadState::Failed, "failed"),
        ] {
            assert_eq!(state.as_str(), name);
            assert_eq!(UploadState::from_db(name), state);
        }
        assert!(UploadState::Active.is_nonterminal());
        assert!(UploadState::Finalizing.is_nonterminal());
        assert!(UploadState::Completed.is_terminal());
        assert!(UploadState::Failed.is_terminal());
        // An unknown DB value must never be treated as writable.
        assert_eq!(UploadState::from_db("surprising"), UploadState::Failed);
    }

    #[test]
    fn create_new_candidate_then_positioned_writes_advance_exactly() {
        let tmp = tmp_root();
        let root = tmp.path();
        let blob_ref = generate_upload_id();

        let mut file = open_candidate_reconciled(root, SYNC_ID, &blob_ref, 0).unwrap();
        write_chunk_at(&mut file, 0, b"hello ").unwrap();
        write_chunk_at(&mut file, 6, b"world").unwrap();
        drop(file);

        let path = candidate_path(root, SYNC_ID, &blob_ref);
        assert_eq!(std::fs::read(&path).unwrap(), b"hello world");
    }

    #[test]
    fn reconciliation_truncates_uncommitted_trailing_bytes() {
        let tmp = tmp_root();
        let root = tmp.path();
        let blob_ref = generate_upload_id();

        // Simulate a crash after the positioned write but before the offset
        // commit: 10 bytes on disk, committed offset 4.
        let mut file = open_candidate_reconciled(root, SYNC_ID, &blob_ref, 0).unwrap();
        write_chunk_at(&mut file, 0, b"0123456789").unwrap();
        drop(file);

        let _file = open_candidate_reconciled(root, SYNC_ID, &blob_ref, 4).unwrap();
        let path = candidate_path(root, SYNC_ID, &blob_ref);
        assert_eq!(std::fs::read(&path).unwrap(), b"0123", "trailing bytes truncated");
    }

    #[test]
    fn reconciliation_fails_closed_when_file_is_short_or_missing() {
        let tmp = tmp_root();
        let root = tmp.path();
        let blob_ref = generate_upload_id();

        let mut file = open_candidate_reconciled(root, SYNC_ID, &blob_ref, 0).unwrap();
        write_chunk_at(&mut file, 0, b"0123").unwrap();
        drop(file);

        // Committed offset above the file length: unrecoverable, never lowered.
        assert!(matches!(
            open_candidate_reconciled(root, SYNC_ID, &blob_ref, 9),
            Err(StagingError::StagingCorrupt(_))
        ));

        // A missing file with a nonzero committed offset is corruption too.
        std::fs::remove_file(candidate_path(root, SYNC_ID, &blob_ref)).unwrap();
        assert!(matches!(
            open_candidate_reconciled(root, SYNC_ID, &blob_ref, 4),
            Err(StagingError::Missing(_))
        ));
    }

    #[test]
    fn missing_file_at_offset_zero_is_recreated() {
        let tmp = tmp_root();
        let root = tmp.path();
        let blob_ref = generate_upload_id();
        let file = open_candidate_reconciled(root, SYNC_ID, &blob_ref, 0).unwrap();
        drop(file);
        std::fs::remove_file(candidate_path(root, SYNC_ID, &blob_ref)).unwrap();

        let file = open_candidate_reconciled(root, SYNC_ID, &blob_ref, 0).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn candidate_symlink_is_refused_not_followed() {
        let tmp = tmp_root();
        let root = tmp.path();
        let blob_ref = generate_upload_id();
        let group = root.join(SYNC_ID);
        std::fs::create_dir_all(&group).unwrap();
        let outside = tmp.path().join("outside");
        std::fs::write(&outside, b"secret").unwrap();
        std::os::unix::fs::symlink(&outside, group.join(&blob_ref)).unwrap();

        assert!(matches!(
            open_candidate_reconciled(root, SYNC_ID, &blob_ref, 0),
            Err(StagingError::StagingCorrupt(_))
        ));
        assert_eq!(std::fs::read(&outside).unwrap(), b"secret", "target untouched");
    }

    #[test]
    fn verify_accepts_exact_bytes_and_rejects_mismatch_or_length_change() {
        let tmp = tmp_root();
        let root = tmp.path();
        let blob_ref = generate_upload_id();
        let expected: [u8; 32] = Sha256::digest(b"the exact envelope").into();

        let mut file = open_candidate_reconciled(root, SYNC_ID, &blob_ref, 0).unwrap();
        write_chunk_at(&mut file, 0, b"the exact envelope").unwrap();
        drop(file);
        assert!(verify_and_sync_candidate(root, SYNC_ID, &blob_ref, 18, &expected).is_ok());

        // Wrong hash never verifies.
        assert!(matches!(
            verify_and_sync_candidate(root, SYNC_ID, &blob_ref, 18, &[0u8; 32]),
            Err(StagingError::StagingCorrupt(_))
        ));
        // A truncated file is below the declared total.
        assert!(matches!(
            verify_and_sync_candidate(root, SYNC_ID, &blob_ref, 19, &expected),
            Err(StagingError::StagingCorrupt(_))
        ));
    }

    #[test]
    fn available_bytes_reports_a_positive_figure_for_a_writable_root() {
        let tmp = tmp_root();
        let free = available_bytes(tmp.path()).unwrap();
        assert!(free > 0, "a writable temp dir should report free space");
    }

    #[test]
    fn schema_ddl_is_idempotent_shape() {
        // The DDL is executed once at migration time; assert the two invariants
        // that matter most and that a syntax error would trip here.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        conn.execute_batch(
            "CREATE TABLE sync_groups (sync_id TEXT PRIMARY KEY, created_at INTEGER NOT NULL);",
        )
        .unwrap();
        conn.execute_batch(SNAPSHOT_UPLOADS_SCHEMA).unwrap();
        conn.execute_batch(SNAPSHOT_UPLOADS_SCHEMA).unwrap();
        // The idempotency constraint is database-enforced.
        conn.execute(
            "INSERT INTO sync_groups (sync_id, created_at) VALUES (?1, 0)",
            rusqlite::params![SYNC_ID],
        )
        .unwrap();
        let insert = "INSERT INTO snapshot_uploads
            (upload_id, upload_key, sync_id, uploader_device_id, target_device_id, epoch,
             server_seq_at, snapshot_ttl_secs, total_bytes, chunk_bytes, committed_offset,
             body_sha256, blob_ref, state, created_at, updated_at, idle_expires_at,
             absolute_expires_at)
            VALUES (?1, 'k', ?2, 'd', 't', 1, 2, 3, 4, 5, 0, X'', 'b', 'active', 1, 1, 1, 1)";
        conn.execute(insert, rusqlite::params!["a".repeat(32), SYNC_ID]).unwrap();
        // Differing upload_id but the same (sync_id, device, upload_key) collides.
        assert!(conn.execute(insert, rusqlite::params!["b".repeat(32), SYNC_ID]).is_err());
        // A cascade delete removes session rows with their group.
        conn.execute("DELETE FROM sync_groups WHERE sync_id = ?1", rusqlite::params![SYNC_ID])
            .unwrap();
        let remaining: i64 =
            conn.query_row("SELECT COUNT(*) FROM snapshot_uploads", [], |r| r.get(0)).unwrap();
        assert_eq!(remaining, 0, "group deletion cascades session rows");
    }
}
