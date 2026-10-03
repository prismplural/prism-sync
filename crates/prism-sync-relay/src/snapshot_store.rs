//! On-disk storage for file-backed snapshot blobs (Phase 0).
//!
//! Snapshot bytes live at `<snapshot_root>/<sync_id>/<blob_ref>`, mirroring the
//! media layout so both trees share one persistent volume mount and one backup
//! story. Unlike media — where `media_id` is content-derived and a shared final
//! path needs a staging+promote dance — each snapshot replacement gets a
//! **unique-per-upload** `blob_ref`, so a file is written straight to its final
//! name and stays invisible until a row references it.
//!
//! Safety properties enforced here, and relied on by the PUT/GET/DELETE routes
//! and the cleanup sweeps:
//!
//! - `blob_ref` and `sync_id` are relay-generated/validated, never client
//!   paths. A malformed reference fails closed to an impossible path.
//! - The leaf file is opened with create-new semantics (`O_CREAT|O_EXCL`),
//!   which per POSIX also refuses to follow a symlink at that path, and only
//!   the relay's own generated name is ever used.
//! - Directories are created explicitly and any existing group directory that
//!   is a symlink is rejected rather than traversed.
//! - The file is `sync_all`'d, then its **parent directory** is synchronized so
//!   the directory entry survives a power loss; the snapshot root is
//!   synchronized too when a new group directory was created this call.

use std::io::Write;
use std::path::{Path, PathBuf};

/// A relay-generated snapshot blob filename is a UUIDv4 in simple (32 hex
/// character) form. Read/unlink paths re-validate against this so a
/// hand-doctored database row can never drive a traversal or symlink open.
pub(crate) fn is_valid_blob_ref(blob_ref: &str) -> bool {
    blob_ref.len() == 32 && blob_ref.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Generate a fresh, unique-per-upload blob reference.
///
/// Unique **per upload**, not per audience: a replacing upload writes a
/// brand-new file and never overwrites bytes a concurrent GET is still reading.
pub(crate) fn generate_blob_ref() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Resolve the on-disk path for a snapshot blob.
///
/// Both components are validated. An invalid `blob_ref` resolves to an
/// impossible reserved leaf (`__invalid__`) rather than propagating a crafted
/// segment, so a bad reference fails closed as snapshot-absent instead of
/// escaping the group directory. An invalid `sync_id` similarly resolves under
/// a reserved directory name that cannot be a real group.
pub(crate) fn blob_path(root: &Path, sync_id: &str, blob_ref: &str) -> PathBuf {
    let group = if crate::auth::is_valid_sync_id(sync_id) { sync_id } else { "__invalid__" };
    let leaf = if is_valid_blob_ref(blob_ref) { blob_ref } else { "__invalid__" };
    root.join(group).join(leaf)
}

/// Open a directory for synchronization, to flush a newly-created directory
/// entry to stable storage.
pub(crate) fn sync_snapshot_dir(dir: &Path) -> std::io::Result<()> {
    // Opening a directory read-only and `sync_all`-ing it is the portable way
    // to force the directory entry itself to disk. On platforms where this is
    // not permitted the open fails and we surface the error — a write we cannot
    // make durable must not be reported as durably stored.
    std::fs::File::open(dir)?.sync_all()
}

/// Symlink probe for a group directory that fails **closed** on an unverifiable
/// path.
///
/// `Ok(true)` means the path exists and is a symlink (checked with
/// `symlink_metadata`, so the link itself is inspected and never followed).
/// `Ok(false)` means it exists as a non-link, or does not exist yet — the
/// first-ever write for a group, which is not a symlink and may be created.
/// `Err` means metadata could not be read at all (EACCES, ELOOP, an unreadable
/// parent), so the caller cannot prove the path is a real directory; it must
/// refuse rather than report "not a symlink" and traverse an unverifiable path.
fn symlink_check(dir: &Path) -> std::io::Result<bool> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => Ok(meta.file_type().is_symlink()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Resolve (creating if needed) the per-group directory under `root`.
///
/// Returns the directory path and whether it was created by this call, so the
/// caller knows a parent-directory sync is required. An existing group
/// directory that is a symlink is refused: the relay must never traverse an
/// attacker-planted link out of the snapshot root.
pub(crate) fn ensure_snapshot_group_dir(
    root: &Path,
    sync_id: &str,
) -> std::io::Result<(PathBuf, bool)> {
    ensure_group_dir(root, sync_id)
}

fn ensure_group_dir(root: &Path, sync_id: &str) -> std::io::Result<(PathBuf, bool)> {
    if !crate::auth::is_valid_sync_id(sync_id) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid sync_id for snapshot storage",
        ));
    }
    let group_dir = root.join(sync_id);
    // Fail closed on an unverifiable path: `symlink_check` errors (rather than
    // reporting "not a symlink") when metadata cannot be read, so an unreadable
    // or looping path is refused instead of traversed.
    if symlink_check(&group_dir)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "snapshot group directory is a symlink",
        ));
    }
    if group_dir.is_dir() {
        return Ok((group_dir, false));
    }
    std::fs::create_dir_all(&group_dir)?;
    Ok((group_dir, true))
}

/// Write snapshot bytes durably to their final path.
///
/// Ordering (matches the spec's publication requirements):
/// 1. create the group directory (refusing a symlinked one);
/// 2. create the leaf file with create-new semantics and restrictive mode, then
///    write and `sync_all` the data;
/// 3. synchronize the **parent directory** so the new entry is durable, and the
///    snapshot root as well when step 1 created a new group directory.
///
/// A failure after the file was opened removes the partial file (best effort)
/// so a rejected upload cannot leave an unattributable blob behind.
///
/// Returns the final path on success.
pub(crate) fn write_blob_durably(
    root: &Path,
    sync_id: &str,
    blob_ref: &str,
    data: &[u8],
) -> std::io::Result<PathBuf> {
    if !is_valid_blob_ref(blob_ref) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid snapshot blob reference",
        ));
    }
    let (group_dir, created_dir) = ensure_group_dir(root, sync_id)?;
    let final_path = group_dir.join(blob_ref);

    let mut options = std::fs::OpenOptions::new();
    // `create_new` is `O_CREAT|O_EXCL`: it fails if the path exists, including
    // when that path is a symlink, so the leaf can never be followed elsewhere.
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Restrictive mode: snapshot ciphertext is opaque, but the group tree
        // is per-tenant and should not be world-readable.
        options.mode(0o600);
    }

    // An open-time `AlreadyExists` means another valid blob owns this name. Do
    // not run partial-file cleanup until this invocation has successfully created
    // the file, or a collision would delete the existing blob.
    let mut file = options.open(&final_path)?;
    let write_result = (|| -> std::io::Result<()> {
        file.write_all(data)?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_result {
        // This invocation created the file, so it is safe to remove its partial
        // contents after a write or synchronization failure.
        drop(file);
        let _ = std::fs::remove_file(&final_path);
        return Err(e);
    }
    drop(file);

    if let Err(e) = sync_snapshot_dir(&group_dir) {
        let _ = std::fs::remove_file(&final_path);
        return Err(e);
    }
    if created_dir {
        if let Err(e) = sync_snapshot_dir(root) {
            let _ = std::fs::remove_file(&final_path);
            return Err(e);
        }
    }

    Ok(final_path)
}

/// Best-effort removal of one blob file. Never follows a symlink: `remove_file`
/// unlinks the link itself, so a planted link cannot make this delete its
/// target. Missing files are not an error.
pub(crate) fn remove_blob(root: &Path, sync_id: &str, blob_ref: &str) {
    let path = blob_path(root, sync_id, blob_ref);
    let _ = std::fs::remove_file(path);
}

/// Remove a whole group's snapshot directory after its rows are gone.
///
/// Refuses to follow a symlinked group directory, so account deletion cannot be
/// tricked into recursively removing an arbitrary target.
pub(crate) fn remove_group_dir(root: &Path, sync_id: &str) {
    if !crate::auth::is_valid_sync_id(sync_id) {
        return;
    }
    let group_dir = root.join(sync_id);
    // Fail closed: on an unverifiable path treat it as unsafe to remove.
    // `remove_dir_all` on a symlink would delete the link, but an unreadable or
    // looping path is not something account deletion should touch at all.
    if symlink_check(&group_dir).unwrap_or(true) {
        tracing::warn!("refusing to remove unverifiable or symlinked snapshot group directory");
        return;
    }
    let _ = std::fs::remove_dir_all(group_dir);
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNC_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn tmp_root() -> tempfile::TempDir {
        tempfile::TempDir::new().unwrap()
    }

    #[test]
    fn rejects_traversal_and_malformed_refs() {
        assert!(!is_valid_blob_ref("../../etc/passwd"));
        assert!(!is_valid_blob_ref("short"));
        assert!(!is_valid_blob_ref(&"g".repeat(32)));
        assert!(is_valid_blob_ref(&"a".repeat(32)));

        let root = Path::new("/snapshot-root");
        // A crafted reference cannot escape the group directory.
        let bad = blob_path(root, SYNC_ID, "../../../etc/passwd");
        assert_eq!(bad, root.join(SYNC_ID).join("__invalid__"));
        // A crafted sync_id cannot escape the root either.
        let bad_group = blob_path(root, "../evil", &"a".repeat(32));
        assert_eq!(bad_group, root.join("__invalid__").join("a".repeat(32)));
    }

    #[test]
    fn write_is_durable_and_create_new() {
        let tmp = tmp_root();
        let root = tmp.path();
        let blob_ref = generate_blob_ref();
        let path = write_blob_durably(root, SYNC_ID, &blob_ref, b"payload").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"payload");
        assert_eq!(path, root.join(SYNC_ID).join(&blob_ref));

        // A second write to the same name fails: create-new semantics.
        let err = write_blob_durably(root, SYNC_ID, &blob_ref, b"other").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"payload", "first bytes survive");
    }

    #[test]
    fn write_refuses_symlinked_group_dir() {
        let tmp = tmp_root();
        let root = tmp.path();
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, root.join(SYNC_ID)).unwrap();
        #[cfg(not(unix))]
        return;

        let err = write_blob_durably(root, SYNC_ID, &generate_blob_ref(), b"x").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none(), "nothing escaped");
    }

    #[test]
    fn remove_group_dir_refuses_symlink_target() {
        let tmp = tmp_root();
        let root = tmp.path();
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("keep"), b"k").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, root.join(SYNC_ID)).unwrap();
        #[cfg(not(unix))]
        return;

        remove_group_dir(root, SYNC_ID);
        assert!(outside.join("keep").exists(), "symlink target untouched");
    }

    #[test]
    fn unix_permissions_are_restrictive() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let tmp = tmp_root();
            let path =
                write_blob_durably(tmp.path(), SYNC_ID, &generate_blob_ref(), b"secret").unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "blob is not group/world readable");
        }
    }
}
