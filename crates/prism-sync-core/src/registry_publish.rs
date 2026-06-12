//! Shared helpers for the revocation-replay gate.
//!
//! Two small, behavior-neutral building blocks consumed by every registry
//! ingress and publish site so the freshness baseline and the published
//! registry content stay consistent across paths:
//!
//! 1. [`ratchet_last_imported_registry_version`] — a monotonic-max upsert of
//!    `SyncMetadata::last_imported_registry_version`. Called wherever verified
//!    registry material enters local storage (pairing-bundle join, signed
//!    registry import) or is published by this device (revoke-time publisher,
//!    epoch repair, pairing initiator, ML-DSA rotation). The baseline is the
//!    replay-freshness anchor for `confirm_self_revocation`; ratcheting it can
//!    only ever move it forward, so a stale-but-validly-signed registry replay
//!    can never satisfy the gate.
//!
//! 2. [`build_signed_registry_from_pinned`] — constructs an unsigned
//!    [`SignedRegistrySnapshot`] from this device's *locally pinned* device
//!    records (not relay-supplied state), with **revoked-absorbing** status: a
//!    locally-revoked record is always emitted as `status == "revoked"`, never
//!    omitted and never re-emitted as active. This is the mandatory replacement
//!    for the old active-only publisher (which dropped revoked devices), so a
//!    genuinely revoked device can read an explicit revoked self-entry and
//!    reach `ConfirmedRevoked`.
//!
//! These helpers do **not** flip any behavior on their own — they are wired
//! into the ingress/publish sites by the freshness-baseline and revoke-publish
//! steps.

use std::collections::BTreeMap;

use prism_sync_crypto::KeyHierarchy;

use crate::error::{CoreError, Result};
use crate::pairing::{
    compute_epoch_key_hash, RegistrySnapshotEntry, SignedRegistrySnapshot,
    SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
};
use crate::storage::{DeviceRecord, SyncStorage};

/// Monotonically advance the locally-recorded
/// `SyncMetadata::last_imported_registry_version` baseline to `version`.
///
/// The baseline is the replay-freshness anchor used by
/// `confirm_self_revocation`: a verified-but-stale signed registry whose
/// version is below the baseline must never drive a destructive confirmation.
/// To keep that guarantee, the baseline may only ever move forward — this
/// helper stores `MAX(current, version)` and is a no-op when `version` is not
/// strictly greater than the current value (including when they are equal).
///
/// Semantics:
/// - `version` below [`SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING`] (i.e.
///   sub-floor / legacy `0`): no-op. Real registries always carry a version at
///   or above the floor, so a sub-floor value is a malformed/legacy artifact
///   that must never become the freshness baseline.
/// - No stored row for `sync_id`: no-op (the underlying UPDATE matches zero
///   rows; we never fabricate a metadata row here — metadata creation belongs
///   to the pairing/join/configure paths).
/// - Stored baseline is `None` (NULL): any at-or-above-floor `version` is
///   written (NULL is treated as "below everything").
/// - Stored baseline is `Some(b)`: written only when `version > b`.
///
/// The read below is only a fast-path early-out; the actual no-rewind
/// guarantee is enforced atomically in SQL by
/// `exec_update_last_imported_registry_version` (a `MAX(COALESCE(...))` clamp),
/// so two ratchets racing outside the engine `Mutex` cannot interleave to land
/// a lower version last.
///
/// Safe to call from any registry ingress (pairing-bundle join, verified
/// signed-registry import) or publish site (revoke publisher, epoch repair,
/// pairing initiator, ML-DSA rotation). It opens its own short transaction.
pub fn ratchet_last_imported_registry_version(
    storage: &dyn SyncStorage,
    sync_id: &str,
    version: i64,
) -> Result<()> {
    // Sub-floor versions are never legitimate baselines (real registries are
    // always >= the epoch-binding floor). Refuse to anchor the gate on one.
    if version < SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING {
        return Ok(());
    }

    let current = storage
        .get_sync_metadata(sync_id)?
        .and_then(|meta| meta.last_imported_registry_version);

    // Strictly-greater early-out: equal or older versions never rewind or
    // rewrite the baseline. A missing row also can't be advanced (no row to
    // UPDATE). This is an optimization only — the SQL MAX clamp is the source
    // of truth under concurrency.
    let should_write = match current {
        Some(existing) => version > existing,
        None => true,
    };
    if !should_write {
        return Ok(());
    }

    let mut tx = storage.begin_tx()?;
    tx.update_last_imported_registry_version(sync_id, version)?;
    tx.commit()?;
    Ok(())
}

/// Build an unsigned [`SignedRegistrySnapshot`] from this device's locally
/// pinned device records, with epoch binding for `epoch`.
///
/// Content rules (binding):
/// - **Source of truth is local pins.** Entries are built from
///   `storage.list_device_records(sync_id)`, not relay-supplied device lists,
///   so a malicious relay cannot inject or rewrite entries through this builder.
/// - **Revoked-absorbing.** A locally-pinned record with `status == "revoked"`
///   is always emitted as an explicit `status == "revoked"` entry — never
///   omitted, never re-emitted as active.
/// - **Status normalized to the registry alphabet.** Only `"active"` and
///   `"revoked"` are valid in a published registry. A pinned `"stale"` record
///   (the relay can mint `stale`, and `DeviceRegistryManager::merge_relay_device`
///   can fold it into a pin) normalizes to `"active"`, mirroring the relay's own
///   pairing-admission validator (`normalize_registry_status`). Any other status
///   fails the build closed rather than emitting an artifact the relay's
///   validator would reject — see the stale-vs-revoked normalization rules.
/// - **Signer must be present and active.** `self_device_id` must have a pinned
///   record that is active; otherwise this returns an error rather than
///   publishing a registry that omits or revokes the signer.
///
/// `version` MUST be at or above
/// [`SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING`]: this builder always
/// attaches epoch binding, and a sub-floor `registry_version` would produce a
/// self-inconsistent artifact (the wire encoding treats sub-floor versions as
/// binding-exempt). Callers compute `max(prev + 1, MIN)`; this is the shared
/// chokepoint so the floor is enforced once here as defense-in-depth.
///
/// The returned snapshot is unsigned; the caller signs it with
/// `SignedRegistrySnapshot::sign_hybrid` using its Ed25519 + ML-DSA keys.
/// Epoch binding is applied via `SignedRegistrySnapshot::new_with_epoch_binding`
/// with per-epoch commitments derived from every epoch key the supplied
/// `key_hierarchy` currently holds; `key_hierarchy` MUST hold the key for
/// `epoch` (the caller's committed/target epoch) or this returns an error.
pub fn build_signed_registry_from_pinned(
    storage: &dyn SyncStorage,
    sync_id: &str,
    self_device_id: &str,
    version: i64,
    epoch: u32,
    key_hierarchy: &KeyHierarchy,
    // H3 composition: when `Some(device_id)` and that device is emitted as a
    // `revoked` tombstone, bind `remote_wipe = true` into its signed entry so the
    // victim reads the admin's wipe intent back from the verified registry. Every
    // other entry (and the repair-backstop republish, which passes `None`) carries
    // `remote_wipe = false`.
    wipe_target: Option<&str>,
) -> Result<SignedRegistrySnapshot> {
    if version < SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING {
        return Err(CoreError::Engine(format!(
            "cannot build signed registry: version {version} is below the epoch-binding floor {SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING}"
        )));
    }

    let records = storage.list_device_records(sync_id)?;

    // Signer-active check: refuse to publish a registry that does not list the
    // publishing device as active. A registry omitting or revoking its own
    // signer is never legitimate and would strand survivors. The signer's own
    // status is normalized first (a `stale` self-pin still counts as active),
    // and an unknown status fails the build closed before we reach it below.
    let signer_active = records.iter().any(|record| {
        record.device_id == self_device_id
            && matches!(normalize_registry_status(&record.status), Ok("active"))
    });
    if !signer_active {
        return Err(CoreError::Engine(format!(
            "cannot build signed registry: signer {self_device_id} missing or non-active in pinned records"
        )));
    }

    let entries: Vec<RegistrySnapshotEntry> = records
        .iter()
        .map(|record| registry_entry_from_record(record, wipe_target))
        .collect::<Result<_>>()?;

    // Per-epoch commitments for every epoch key we currently hold. The binding
    // epoch's key must be present, otherwise the produced snapshot would fail
    // `epoch_key_hashes`-presence validation downstream.
    let epoch_key_hashes = epoch_key_hashes_from_hierarchy(key_hierarchy)?;
    if !epoch_key_hashes.contains_key(&epoch) {
        return Err(CoreError::Engine(format!(
            "cannot build signed registry: missing epoch key for binding epoch {epoch}"
        )));
    }

    Ok(SignedRegistrySnapshot::new_with_epoch_binding(
        entries,
        version,
        epoch,
        epoch_key_hashes,
    ))
}

/// Normalize a locally-pinned device status to the registry alphabet.
///
/// Mirrors the relay's pairing-admission validator
/// (`prism-sync-relay::routes::register::normalize_registry_status`): `active`
/// and `stale` both map to `"active"`, `revoked` stays `"revoked"`, and any
/// other status fails closed. Keeping the two in lockstep means a future
/// stale-merged pin can never produce a registry artifact the relay would 409.
fn normalize_registry_status(status: &str) -> Result<&'static str> {
    match status {
        "active" | "stale" => Ok("active"),
        "revoked" => Ok("revoked"),
        other => Err(CoreError::Engine(format!(
            "cannot build signed registry: pinned device has unsupported status {other:?}"
        ))),
    }
}

/// Map a locally-pinned [`DeviceRecord`] to a [`RegistrySnapshotEntry`].
///
/// Revoked-absorbing by construction — the pinned status is the source of truth
/// and is normalized via [`normalize_registry_status`] (a `revoked` pin always
/// stays `revoked`; a `stale` pin becomes `active`; anything else fails closed).
///
/// H3 composition: `remote_wipe` is bound to `true` only when this record is the
/// `wipe_target` AND it normalizes to a `revoked` tombstone — i.e. only the
/// admin's explicit revocation publish carries the wipe bit; the repair-backstop
/// republish (and every non-target entry) authors `remote_wipe = false`.
fn registry_entry_from_record(
    record: &DeviceRecord,
    wipe_target: Option<&str>,
) -> Result<RegistrySnapshotEntry> {
    let status = normalize_registry_status(&record.status)?;
    let remote_wipe =
        status == "revoked" && wipe_target == Some(record.device_id.as_str());
    Ok(RegistrySnapshotEntry {
        sync_id: record.sync_id.clone(),
        device_id: record.device_id.clone(),
        ed25519_public_key: record.ed25519_public_key.clone(),
        x25519_public_key: record.x25519_public_key.clone(),
        ml_dsa_65_public_key: record.ml_dsa_65_public_key.clone(),
        ml_kem_768_public_key: record.ml_kem_768_public_key.clone(),
        x_wing_public_key: record.x_wing_public_key.clone(),
        status: status.to_string(),
        ml_dsa_key_generation: record.ml_dsa_key_generation,
        remote_wipe,
    })
}

/// Compute per-epoch registry commitments for every epoch key the hierarchy
/// currently holds. Mirrors `PrismSync::build_epoch_key_hashes_for_registry`.
fn epoch_key_hashes_from_hierarchy(
    key_hierarchy: &KeyHierarchy,
) -> Result<BTreeMap<u32, [u8; 32]>> {
    let entries = key_hierarchy.epoch_keys_iter().map_err(CoreError::Crypto)?;
    let mut out = BTreeMap::new();
    for (epoch, key) in entries {
        out.insert(epoch, compute_epoch_key_hash(key));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{DeviceRecord, RusqliteSyncStorage, SyncMetadata, SyncStorage};
    use chrono::Utc;
    use prism_sync_crypto::DeviceSecret;
    use zeroize::Zeroizing;

    const SYNC_ID: &str = "sync-1";

    fn in_memory() -> RusqliteSyncStorage {
        RusqliteSyncStorage::in_memory().expect("in-memory storage")
    }

    fn read_baseline(storage: &dyn SyncStorage) -> Option<i64> {
        storage
            .get_sync_metadata(SYNC_ID)
            .unwrap()
            .and_then(|m| m.last_imported_registry_version)
    }

    fn seed_metadata(storage: &dyn SyncStorage, baseline: Option<i64>) {
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_sync_metadata(&SyncMetadata {
            sync_id: SYNC_ID.to_string(),
            local_device_id: "a1b2c3d4e5f6".to_string(),
            current_epoch: 1,
            last_pulled_server_seq: 0,
            last_pushed_at: None,
            last_successful_sync_at: None,
            registered_at: None,
            needs_rekey: false,
            last_imported_registry_version: baseline,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
        .unwrap();
        tx.commit().unwrap();
    }

    /// Build a `DeviceRecord` and return the `DeviceSecret` it was derived from
    /// so callers that need to *sign* as this device (the round-trip test) can
    /// re-derive its Ed25519 + ML-DSA signing keys.
    fn device_record_with_secret(device_id: &str, status: &str) -> (DeviceRecord, DeviceSecret) {
        let secret = DeviceSecret::generate();
        let record = DeviceRecord {
            sync_id: SYNC_ID.to_string(),
            device_id: device_id.to_string(),
            ed25519_public_key: secret
                .ed25519_keypair(device_id)
                .unwrap()
                .public_key_bytes()
                .to_vec(),
            x25519_public_key: secret
                .x25519_keypair(device_id)
                .unwrap()
                .public_key_bytes()
                .to_vec(),
            ml_dsa_65_public_key: secret.ml_dsa_65_keypair(device_id).unwrap().public_key_bytes(),
            ml_kem_768_public_key: secret.ml_kem_768_keypair(device_id).unwrap().public_key_bytes(),
            x_wing_public_key: secret.xwing_keypair(device_id).unwrap().encapsulation_key_bytes(),
            status: status.to_string(),
            registered_at: Utc::now(),
            revoked_at: if status == "revoked" { Some(Utc::now()) } else { None },
            ml_dsa_key_generation: 0,
        };
        (record, secret)
    }

    fn device_record(device_id: &str, status: &str) -> DeviceRecord {
        device_record_with_secret(device_id, status).0
    }

    fn pin(storage: &dyn SyncStorage, record: &DeviceRecord) {
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_device_record(record).unwrap();
        tx.commit().unwrap();
    }

    /// An unlocked hierarchy holding the supplied epoch's key, so epoch binding
    /// succeeds for that epoch and its per-epoch commitment is present.
    /// `initialize` unlocks the hierarchy and pre-derives the epoch-0 key;
    /// higher epochs are seeded explicitly.
    fn hierarchy_with_epoch(epoch: u32) -> KeyHierarchy {
        let mut h = KeyHierarchy::new();
        h.initialize("test-password", &[1u8; 16]).unwrap();
        if epoch != 0 {
            h.store_epoch_key(epoch, Zeroizing::new(vec![7u8; 32]));
        }
        h
    }

    // ── ratchet monotonicity ──

    #[test]
    fn ratchet_advances_from_null_baseline() {
        let storage = in_memory();
        seed_metadata(&storage, None);

        ratchet_last_imported_registry_version(&storage, SYNC_ID, 5).unwrap();

        assert_eq!(read_baseline(&storage), Some(5));
    }

    #[test]
    fn ratchet_advances_to_higher_version() {
        let storage = in_memory();
        seed_metadata(&storage, Some(5));

        ratchet_last_imported_registry_version(&storage, SYNC_ID, 9).unwrap();

        assert_eq!(read_baseline(&storage), Some(9));
    }

    #[test]
    fn ratchet_never_regresses_on_older_version() {
        let storage = in_memory();
        seed_metadata(&storage, Some(10));

        // Older verified registry must not pull the baseline backward.
        ratchet_last_imported_registry_version(&storage, SYNC_ID, 3).unwrap();

        assert_eq!(read_baseline(&storage), Some(10));
    }

    #[test]
    fn ratchet_is_noop_on_equal_version() {
        let storage = in_memory();
        seed_metadata(&storage, Some(7));

        ratchet_last_imported_registry_version(&storage, SYNC_ID, 7).unwrap();

        assert_eq!(read_baseline(&storage), Some(7));
    }

    #[test]
    fn ratchet_is_noop_on_missing_row() {
        let storage = in_memory();
        // No metadata row seeded for SYNC_ID.

        ratchet_last_imported_registry_version(&storage, SYNC_ID, 42).unwrap();

        // No row was fabricated; the gate stays at the fail-safe NULL baseline.
        assert!(storage.get_sync_metadata(SYNC_ID).unwrap().is_none());
    }

    #[test]
    fn ratchet_sequence_is_monotonic_max() {
        let storage = in_memory();
        seed_metadata(&storage, None);

        for v in [4, 2, 4, 7, 1, 7, 11, 11, 6] {
            ratchet_last_imported_registry_version(&storage, SYNC_ID, v).unwrap();
        }

        // Final value is the max ever offered, regardless of arrival order.
        assert_eq!(read_baseline(&storage), Some(11));
    }

    // ── build_signed_registry_from_pinned: revoked-absorption + signer check ──

    #[test]
    fn build_emits_explicit_revoked_entry_never_omits() {
        let storage = in_memory();
        let signer = device_record("a1b2c3d4e5f6", "active");
        let revoked = device_record("dead00000000", "revoked");
        pin(&storage, &signer);
        pin(&storage, &revoked);

        let snapshot = build_signed_registry_from_pinned(
            &storage,
            SYNC_ID,
            "a1b2c3d4e5f6",
            1,
            1,
            &hierarchy_with_epoch(1),
            None,
        )
        .unwrap();

        // The revoked device is present with an explicit revoked status — not
        // dropped the way the old active-only publisher would have dropped it.
        let revoked_entry = snapshot
            .entries
            .iter()
            .find(|e| e.device_id == "dead00000000")
            .expect("revoked device must be present in the registry, not omitted");
        assert_eq!(revoked_entry.status, "revoked");

        // The signer is present and active.
        let signer_entry = snapshot
            .entries
            .iter()
            .find(|e| e.device_id == "a1b2c3d4e5f6")
            .expect("signer must be present");
        assert_eq!(signer_entry.status, "active");

        assert_eq!(snapshot.registry_version, 1);
        assert_eq!(snapshot.current_epoch, 1);
        assert!(snapshot.epoch_key_hashes.contains_key(&1));
    }

    #[test]
    fn build_preserves_active_status_for_active_devices() {
        let storage = in_memory();
        pin(&storage, &device_record("a1b2c3d4e5f6", "active"));
        pin(&storage, &device_record("beef00000000", "active"));

        let snapshot = build_signed_registry_from_pinned(
            &storage,
            SYNC_ID,
            "a1b2c3d4e5f6",
            2,
            1,
            &hierarchy_with_epoch(1),
            None,
        )
        .unwrap();

        assert_eq!(snapshot.entries.len(), 2);
        assert!(snapshot.entries.iter().all(|e| e.status == "active"));
    }

    #[test]
    fn build_refuses_when_signer_absent() {
        let storage = in_memory();
        // Only a peer is pinned; the signer has no record.
        pin(&storage, &device_record("beef00000000", "active"));

        let err = build_signed_registry_from_pinned(
            &storage,
            SYNC_ID,
            "a1b2c3d4e5f6",
            1,
            1,
            &hierarchy_with_epoch(1),
            None,
        )
        .unwrap_err();

        assert!(matches!(err, CoreError::Engine(_)));
    }

    #[test]
    fn build_refuses_when_signer_revoked() {
        let storage = in_memory();
        // The signer's own pinned record is revoked — must not publish.
        pin(&storage, &device_record("a1b2c3d4e5f6", "revoked"));
        pin(&storage, &device_record("beef00000000", "active"));

        let err = build_signed_registry_from_pinned(
            &storage,
            SYNC_ID,
            "a1b2c3d4e5f6",
            1,
            1,
            &hierarchy_with_epoch(1),
            None,
        )
        .unwrap_err();

        assert!(matches!(err, CoreError::Engine(_)));
    }

    #[test]
    fn build_refuses_when_binding_epoch_key_absent() {
        let storage = in_memory();
        pin(&storage, &device_record("a1b2c3d4e5f6", "active"));

        // Hierarchy holds epoch 1, but we ask to bind epoch 2.
        let err = build_signed_registry_from_pinned(
            &storage,
            SYNC_ID,
            "a1b2c3d4e5f6",
            1,
            2,
            &hierarchy_with_epoch(1),
            None,
        )
        .unwrap_err();

        assert!(matches!(err, CoreError::Engine(_)));
    }

    #[test]
    fn build_normalizes_stale_pin_to_active() {
        // The relay can mint `stale`, and merge_relay_device can fold it into a
        // pin. The builder must normalize it to `active` (relay precedent), not
        // emit a registry the relay's pairing validator would reject.
        let storage = in_memory();
        pin(&storage, &device_record("a1b2c3d4e5f6", "active"));
        pin(&storage, &device_record("beef00000000", "stale"));

        let snapshot = build_signed_registry_from_pinned(
            &storage,
            SYNC_ID,
            "a1b2c3d4e5f6",
            1,
            1,
            &hierarchy_with_epoch(1),
            None,
        )
        .unwrap();

        let stale_entry = snapshot
            .entries
            .iter()
            .find(|e| e.device_id == "beef00000000")
            .expect("stale device must still be present");
        assert_eq!(stale_entry.status, "active", "stale must normalize to active");
        assert!(snapshot.entries.iter().all(|e| e.status == "active" || e.status == "revoked"));
    }

    #[test]
    fn build_refuses_unknown_pinned_status() {
        // A status outside the registry alphabet must fail closed rather than
        // produce a self-inconsistent artifact.
        let storage = in_memory();
        pin(&storage, &device_record("a1b2c3d4e5f6", "active"));
        pin(&storage, &device_record("beef00000000", "quarantined"));

        let err = build_signed_registry_from_pinned(
            &storage,
            SYNC_ID,
            "a1b2c3d4e5f6",
            1,
            1,
            &hierarchy_with_epoch(1),
            None,
        )
        .unwrap_err();

        assert!(matches!(err, CoreError::Engine(_)));
    }

    #[test]
    fn build_refuses_sub_floor_version() {
        // The builder always attaches epoch binding, so a sub-floor version
        // (which the wire encoding treats as binding-exempt) would be a
        // self-inconsistent artifact. Reject it at the shared chokepoint.
        let storage = in_memory();
        pin(&storage, &device_record("a1b2c3d4e5f6", "active"));

        let err = build_signed_registry_from_pinned(
            &storage,
            SYNC_ID,
            "a1b2c3d4e5f6",
            SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING - 1,
            1,
            &hierarchy_with_epoch(1),
            None,
        )
        .unwrap_err();

        assert!(matches!(err, CoreError::Engine(_)));
    }

    #[test]
    fn ratchet_ignores_sub_floor_version() {
        let storage = in_memory();
        seed_metadata(&storage, None);

        // A sub-floor (legacy `0`) version must never become the baseline.
        ratchet_last_imported_registry_version(
            &storage,
            SYNC_ID,
            SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING - 1,
        )
        .unwrap();
        assert_eq!(read_baseline(&storage), None);

        // The first at-or-above-floor version does land.
        ratchet_last_imported_registry_version(
            &storage,
            SYNC_ID,
            SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
        )
        .unwrap();
        assert_eq!(read_baseline(&storage), Some(SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING));
    }

    // ── sign / verify / import round-trip ──
    //
    // Pins the exact glue the revoke publisher and confirm_self_revocation depend on:
    // an artifact built here must sign_hybrid → verify → import cleanly, and a
    // built revoked entry must flip a pinned active record to revoked. Catches
    // canonical-JSON / epoch-binding incompatibilities before any wiring exists.

    #[test]
    fn build_sign_verify_import_round_trip_flips_active_to_revoked() {
        use crate::device_registry::DeviceRegistryManager;

        // Producer storage: signer active, peer pinned *revoked* so the built
        // artifact carries an explicit revoked entry (revoked-absorbing).
        let producer = in_memory();
        let (signer, signer_secret) = device_record_with_secret("a1b2c3d4e5f6", "active");
        let peer_revoked = device_record("dead00000000", "revoked");
        pin(&producer, &signer);
        pin(&producer, &peer_revoked);

        let snapshot = build_signed_registry_from_pinned(
            &producer,
            SYNC_ID,
            "a1b2c3d4e5f6",
            2,
            1,
            &hierarchy_with_epoch(1),
            None,
        )
        .unwrap();

        // Sign with the signer's own Ed25519 + ML-DSA keys (re-derived from its
        // retained secret), exactly as the revoke publisher will.
        let signing_key = signer_secret.ed25519_keypair("a1b2c3d4e5f6").unwrap();
        let pq_signing_key = signer_secret.ml_dsa_65_keypair("a1b2c3d4e5f6").unwrap();
        let artifact = snapshot.sign_hybrid(&signing_key, &pq_signing_key);

        // Consumer storage: same signer pinned (so verification has a trusted
        // signer key), and the peer pinned *active*. Importing the artifact must
        // flip the peer to revoked — the confirm_self_revocation read path.
        let consumer = in_memory();
        pin(&consumer, &signer);
        pin(&consumer, &device_record_with_same_keys(&peer_revoked, "active"));

        // Verify-only succeeds against the consumer's trusted signer pin.
        DeviceRegistryManager::verify_signed_registry_snapshot(&consumer, SYNC_ID, &artifact)
            .expect("artifact must verify against the pinned signer");

        let imported = DeviceRegistryManager::verify_and_import_signed_registry(
            &consumer,
            SYNC_ID,
            &artifact,
            Some(1),
        )
        .expect("artifact must import");
        assert_eq!(imported, 2);

        let peer = consumer.get_device_record(SYNC_ID, "dead00000000").unwrap().unwrap();
        assert_eq!(peer.status, "revoked", "import must flip the active pin to revoked");
    }

    /// Clone a record's keys/ids but override its status — so the producer and
    /// consumer agree on permanent keys (no key-change rejection on import).
    fn device_record_with_same_keys(src: &DeviceRecord, status: &str) -> DeviceRecord {
        DeviceRecord { status: status.to_string(), ..src.clone() }
    }
}
