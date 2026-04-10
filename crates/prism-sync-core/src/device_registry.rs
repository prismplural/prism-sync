//! Device registry management — key pinning and change detection.
//!
//! When a device is first seen during pairing or pull, its Ed25519 public key
//! is "pinned" in local storage. Subsequent operations verify that the claimed
//! key matches the pinned key, raising an error on mismatch (TOFU model).

use crate::error::{CoreError, Result};
use crate::storage::{DeviceRecord, SyncStorage};
use prism_sync_crypto::pq::continuity_proof::MlDsaContinuityProof;

/// Stateless helper for device registry operations.
///
/// All state lives in the [`SyncStorage`] implementation; this struct provides
/// a convenient API surface.
pub struct DeviceRegistryManager;

impl DeviceRegistryManager {
    fn keys_match(existing: &DeviceRecord, candidate: &DeviceRecord) -> bool {
        existing.ed25519_public_key == candidate.ed25519_public_key
            && existing.x25519_public_key == candidate.x25519_public_key
            && existing.ml_dsa_65_public_key == candidate.ml_dsa_65_public_key
            && existing.ml_kem_768_public_key == candidate.ml_kem_768_public_key
    }

    fn write_device_record(storage: &dyn SyncStorage, device: &DeviceRecord) -> Result<()> {
        let mut tx = storage.begin_tx()?;
        tx.upsert_device_record(device)?;
        tx.commit()
    }

    /// Pin a device's keys on first sight (Trust On First Use).
    ///
    /// If the device already exists with the same keys, status metadata may be
    /// updated. Key changes fail closed.
    pub fn pin_device(
        storage: &dyn SyncStorage,
        sync_id: &str,
        device: &DeviceRecord,
    ) -> Result<()> {
        let _ = sync_id; // sync_id is part of the DeviceRecord
        match storage.get_device_record(sync_id, &device.device_id)? {
            None => Self::write_device_record(storage, device),
            Some(existing) if Self::keys_match(&existing, device) => {
                Self::write_device_record(storage, device)
            }
            Some(existing)
                if device.ml_dsa_key_generation > existing.ml_dsa_key_generation
                    && device.ed25519_public_key == existing.ed25519_public_key
                    && device.x25519_public_key == existing.x25519_public_key
                    && device.ml_kem_768_public_key == existing.ml_kem_768_public_key =>
            {
                // Accept ML-DSA rotation during keyring import (e.g., signed registry
                // snapshot from a trusted device that saw a peer rotation).
                Self::write_device_record(storage, device)
            }
            Some(_) => Err(CoreError::DeviceKeyChanged {
                device_id: device.device_id.clone(),
            }),
        }
    }

    /// Verify that a device's claimed Ed25519 public key matches the pinned key.
    ///
    /// Returns `Ok(())` if the key matches, or an error if:
    /// - The device is not in the registry
    /// - The key has changed since it was pinned
    /// - The device has been revoked
    pub fn verify_device_key(
        storage: &dyn SyncStorage,
        sync_id: &str,
        device_id: &str,
        claimed_ed25519_pk: &[u8],
    ) -> Result<()> {
        let record = storage.get_device_record(sync_id, device_id)?;
        match record {
            None => Err(CoreError::Storage(format!(
                "device {device_id} not in registry"
            ))),
            Some(r) if r.status == "revoked" => Err(CoreError::Storage(format!(
                "device {device_id} has been revoked"
            ))),
            Some(r) if r.ed25519_public_key != claimed_ed25519_pk => {
                Err(CoreError::DeviceKeyChanged {
                    device_id: device_id.to_string(),
                })
            }
            Some(_) => Ok(()),
        }
    }

    /// Import a batch of device records (e.g. from a signed keyring during pairing).
    ///
    /// Each device in the keyring is pinned via upsert. This is used when a
    /// joining device receives the existing device registry from the inviting
    /// device.
    pub fn import_keyring(
        storage: &dyn SyncStorage,
        sync_id: &str,
        keyring: &[DeviceRecord],
    ) -> Result<()> {
        for device in keyring {
            Self::pin_device(storage, sync_id, device)?;
        }
        Ok(())
    }

    /// Merge a relay-provided device record without allowing silent key
    /// replacement for a known device.
    ///
    /// Current behavior still allows inserting unknown devices from the relay
    /// so existing pair flows continue to work until signed registry updates are
    /// fully wired. Known devices may only receive status/timestamp updates if
    /// their keys are unchanged.
    pub fn merge_relay_device(
        storage: &dyn SyncStorage,
        sync_id: &str,
        device: &DeviceRecord,
    ) -> Result<()> {
        let _ = sync_id; // sync_id is part of the DeviceRecord
        let existing = storage.get_device_record(sync_id, &device.device_id)?;
        let merged = match existing {
            None => device.clone(),
            Some(existing) if !Self::keys_match(&existing, device) => {
                // Check if this is an ML-DSA rotation (only ML-DSA key differs, generation increased)
                if device.ml_dsa_key_generation > existing.ml_dsa_key_generation
                    && device.ed25519_public_key == existing.ed25519_public_key
                    && device.x25519_public_key == existing.x25519_public_key
                    && device.ml_kem_768_public_key == existing.ml_kem_768_public_key
                {
                    // Reject unverified ML-DSA rotation from relay device list.
                    //
                    // ML-DSA rotations must arrive through either:
                    // 1. Verified signed registry import (verify_and_import_signed_registry)
                    // 2. Explicit accept_ml_dsa_rotation with continuity proof
                    //
                    // The relay verifies the continuity proof at rotation time, but a
                    // compromised relay could inject a fake ML-DSA key via list_devices.
                    // Closing this gap forces all rotation trust through client-verifiable
                    // artifacts.
                    tracing::warn!(
                        device_id = %device.device_id,
                        local_gen = existing.ml_dsa_key_generation,
                        relay_gen = device.ml_dsa_key_generation,
                        "Rejecting unverified ML-DSA rotation from relay device list"
                    );
                    // Don't fail the entire merge — just skip this device's key update.
                    // Other metadata (status, timestamps) from the existing record is kept.
                    return Ok(());
                } else {
                    return Err(CoreError::DeviceKeyChanged {
                        device_id: device.device_id.clone(),
                    });
                }
            }
            Some(existing) if existing.status == "revoked" && device.status != "revoked" => {
                return Ok(());
            }
            Some(existing) => DeviceRecord {
                sync_id: device.sync_id.clone(),
                device_id: device.device_id.clone(),
                ed25519_public_key: existing.ed25519_public_key,
                x25519_public_key: existing.x25519_public_key,
                ml_dsa_65_public_key: existing.ml_dsa_65_public_key,
                ml_kem_768_public_key: existing.ml_kem_768_public_key,
                x_wing_public_key: existing.x_wing_public_key,
                status: device.status.clone(),
                registered_at: existing.registered_at,
                revoked_at: if device.status == "revoked" {
                    existing
                        .revoked_at
                        .or(device.revoked_at)
                        .or_else(|| Some(chrono::Utc::now()))
                } else {
                    None
                },
                // Preserve the local generation counter; do not accept the relay's
                // unverified value.  A malicious relay could inflate this field to
                // poison the generation-hint check in resolve_sender_keys_with_generation_hint.
                // Legitimate ML-DSA rotations arrive through verify_and_import_signed_registry.
                ml_dsa_key_generation: existing.ml_dsa_key_generation,
            },
        };

        Self::write_device_record(storage, &merged)
    }

    /// Merge a relay-provided device list using [`merge_relay_device`] rules.
    pub fn merge_relay_devices(
        storage: &dyn SyncStorage,
        sync_id: &str,
        devices: &[DeviceRecord],
    ) -> Result<()> {
        for device in devices {
            Self::merge_relay_device(storage, sync_id, device)?;
        }
        Ok(())
    }

    /// Mark a device as revoked by setting its status to "revoked".
    ///
    /// The record is preserved (not deleted) so that:
    /// 1. `verify_device_key` correctly reports "revoked" instead of "not found"
    /// 2. Other devices can see the revocation history
    ///
    /// An epoch rotation should be triggered after revocation to exclude
    /// the device from future encrypted traffic.
    pub fn revoke_device(storage: &dyn SyncStorage, sync_id: &str, device_id: &str) -> Result<()> {
        let record = storage
            .get_device_record(sync_id, device_id)?
            .ok_or_else(|| CoreError::Storage(format!("device {device_id} not in registry")))?;

        let revoked = DeviceRecord {
            status: "revoked".into(),
            revoked_at: Some(chrono::Utc::now()),
            ..record
        };

        let mut tx = storage.begin_tx()?;
        tx.upsert_device_record(&revoked)?;
        tx.commit()
    }

    /// Accept an ML-DSA key rotation for a known device.
    ///
    /// Verifies the continuity proof, then updates the local device record
    /// with the new ML-DSA key and generation.
    pub fn accept_ml_dsa_rotation(
        storage: &dyn SyncStorage,
        sync_id: &str,
        device_id: &str,
        new_ml_dsa_pk: &[u8],
        new_generation: u32,
        proof: &MlDsaContinuityProof,
    ) -> Result<()> {
        let existing = storage
            .get_device_record(sync_id, device_id)?
            .ok_or_else(|| CoreError::Storage(format!("device {device_id} not in registry")))?;

        if existing.status == "revoked" {
            return Err(CoreError::Storage(format!(
                "device {device_id} has been revoked"
            )));
        }

        if new_generation <= existing.ml_dsa_key_generation {
            return Err(CoreError::DeviceKeyChanged {
                device_id: device_id.to_string(),
            });
        }

        // Verify the continuity proof against the stored keys
        let ed25519_pk: [u8; 32] = existing
            .ed25519_public_key
            .clone()
            .try_into()
            .map_err(|_| CoreError::Storage("invalid ed25519 pk length in registry".into()))?;

        proof
            .verify(&ed25519_pk, &existing.ml_dsa_65_public_key)
            .map_err(|e| CoreError::Storage(format!("continuity proof verification failed: {e}")))?;

        // Update the device record with the new ML-DSA key
        let updated = DeviceRecord {
            ml_dsa_65_public_key: new_ml_dsa_pk.to_vec(),
            ml_dsa_key_generation: new_generation,
            ..existing
        };

        let mut tx = storage.begin_tx()?;
        tx.upsert_device_record(&updated)?;
        tx.commit()
    }

    /// List all device records for a sync group.
    pub fn list_devices(storage: &dyn SyncStorage, sync_id: &str) -> Result<Vec<DeviceRecord>> {
        storage.list_device_records(sync_id)
    }

    /// Verify and import a signed registry artifact.
    ///
    /// Parses the V3 hybrid-signed registry snapshot, verifies the signature
    /// against a locally known device's keys, and imports the device records.
    ///
    /// Returns the signed `registry_version` on success, or an error if
    /// verification or the monotonicity check fails.
    pub fn verify_and_import_signed_registry(
        storage: &dyn SyncStorage,
        sync_id: &str,
        artifact_blob: &[u8],
        last_imported_version: Option<i64>,
    ) -> Result<i64> {
        use prism_sync_crypto::pq::HybridSignature;

        // 1. Check version byte
        let Some((&version, remaining)) = artifact_blob.split_first() else {
            return Err(CoreError::Engine("signed registry artifact is empty".into()));
        };
        if version != 0x03 {
            return Err(CoreError::Engine(format!(
                "unsupported registry artifact version: 0x{version:02x}, expected 0x03"
            )));
        }

        // 2. Parse the hybrid signature to find where JSON starts
        if remaining.len() < 8 {
            return Err(CoreError::Engine("signed registry artifact too short".into()));
        }
        let ed_len = u32::from_le_bytes(remaining[0..4].try_into().unwrap()) as usize;
        if remaining.len() < 4 + ed_len + 4 {
            return Err(CoreError::Engine(
                "signed registry artifact truncated (ed25519)".into(),
            ));
        }
        let ml_len_offset = 4 + ed_len;
        let ml_len = u32::from_le_bytes(
            remaining[ml_len_offset..ml_len_offset + 4].try_into().unwrap(),
        ) as usize;
        let signature_len = ml_len_offset + 4 + ml_len;
        if remaining.len() <= signature_len {
            return Err(CoreError::Engine(
                "signed registry artifact missing JSON payload".into(),
            ));
        }

        let signature = HybridSignature::from_bytes(&remaining[..signature_len]).map_err(
            |e| {
                CoreError::Engine(format!(
                    "invalid hybrid signature in registry artifact: {e}"
                ))
            },
        )?;
        let json_bytes = &remaining[signature_len..];

        // 3. Build signing data (same domain as relay's verification)
        let mut signing_data =
            Vec::with_capacity(b"PRISM_SYNC_REGISTRY_V3\x00".len() + json_bytes.len());
        signing_data.extend_from_slice(b"PRISM_SYNC_REGISTRY_V3\x00");
        signing_data.extend_from_slice(json_bytes);

        // 4. Try to verify against any locally known device's keys
        let local_devices = storage.list_device_records(sync_id)?;
        let mut signer_device_id: Option<String> = None;
        for device in &local_devices {
            if device.status == "revoked" {
                continue; // skip revoked devices — they retain their keys but must not sign
            }
            if device.ed25519_public_key.len() != 32 || device.ml_dsa_65_public_key.is_empty() {
                continue;
            }
            let ed_pk: [u8; 32] = device.ed25519_public_key.clone().try_into().unwrap();
            if signature
                .verify_v3(
                    &signing_data,
                    b"registry_snapshot",
                    &ed_pk,
                    &device.ml_dsa_65_public_key,
                )
                .is_ok()
            {
                signer_device_id = Some(device.device_id.clone());
                break;
            }
        }

        if signer_device_id.is_none() {
            return Err(CoreError::Engine(
                "registry artifact signature could not be verified against any known device"
                    .into(),
            ));
        }

        // 5. Parse and import device entries
        // The JSON entries use byte arrays (not hex) for public keys
        #[derive(serde::Deserialize)]
        struct RegistryEntry {
            sync_id: String,
            device_id: String,
            ed25519_public_key: Vec<u8>,
            x25519_public_key: Vec<u8>,
            #[serde(default)]
            ml_dsa_65_public_key: Vec<u8>,
            #[serde(default)]
            ml_kem_768_public_key: Vec<u8>,
            #[serde(default)]
            x_wing_public_key: Vec<u8>,
            status: String,
            #[serde(default)]
            ml_dsa_key_generation: u32,
        }

        // V3 format wraps entries in {"registry_version": N, "entries": [...]}
        #[derive(serde::Deserialize)]
        struct RegistryWrapper {
            registry_version: i64,
            entries: Vec<RegistryEntry>,
        }

        let wrapper: RegistryWrapper = serde_json::from_slice(json_bytes)
            .map_err(|e| CoreError::Engine(format!("invalid registry artifact JSON: {e}")))?;

        // 4a. Monotonicity check — reject stale or replayed artifacts
        if wrapper.registry_version <= last_imported_version.unwrap_or(-1) {
            return Err(CoreError::Engine(format!(
                "stale registry artifact: version {} <= last imported {}",
                wrapper.registry_version,
                last_imported_version.unwrap_or(-1)
            )));
        }

        let signed_version = wrapper.registry_version;
        let entries = wrapper.entries;

        // 5a. Require signer to appear and be non-revoked in their own snapshot.
        //     This catches self-contradictory snapshots and closes the revocation
        //     window between when we skip the key above and what the payload says.
        let signer_id = signer_device_id.unwrap(); // safe: checked above (is_none returned)
        match entries.iter().find(|e| e.device_id == signer_id) {
            None => {
                return Err(CoreError::Engine(
                    "registry signer not present in own snapshot".into(),
                ));
            }
            Some(entry) if entry.status == "revoked" => {
                return Err(CoreError::Engine(
                    "registry signed by device that marks itself as revoked".into(),
                ));
            }
            _ => {} // signer is present and not revoked — proceed
        }

        let device_records: Vec<DeviceRecord> = entries
            .into_iter()
            .filter(|e| e.sync_id == sync_id)
            .map(|e| {
                let now = chrono::Utc::now();
                DeviceRecord {
                    sync_id: e.sync_id,
                    device_id: e.device_id,
                    ed25519_public_key: e.ed25519_public_key,
                    x25519_public_key: e.x25519_public_key,
                    ml_dsa_65_public_key: e.ml_dsa_65_public_key,
                    ml_kem_768_public_key: e.ml_kem_768_public_key,
                    x_wing_public_key: e.x_wing_public_key,
                    status: e.status,
                    registered_at: now,
                    revoked_at: None,
                    ml_dsa_key_generation: e.ml_dsa_key_generation,
                }
            })
            .collect();

        Self::import_keyring(storage, sync_id, &device_records)?;

        Ok(signed_version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::rusqlite_storage::RusqliteSyncStorage;
    use chrono::Utc;

    fn make_storage() -> RusqliteSyncStorage {
        RusqliteSyncStorage::in_memory().expect("in-memory storage")
    }

    fn make_device(sync_id: &str, device_id: &str, ed_pk: &[u8]) -> DeviceRecord {
        DeviceRecord {
            sync_id: sync_id.into(),
            device_id: device_id.into(),
            ed25519_public_key: ed_pk.to_vec(),
            x25519_public_key: vec![0u8; 32],
            ml_dsa_65_public_key: vec![0u8; 1952],
            ml_kem_768_public_key: vec![0u8; 1184],
            x_wing_public_key: vec![],
            status: "active".into(),
            registered_at: Utc::now(),
            revoked_at: None,
            ml_dsa_key_generation: 0,
        }
    }

    #[test]
    fn pin_and_verify() {
        let storage = make_storage();
        let device = make_device("sync-1", "dev-a", &[1u8; 32]);
        DeviceRegistryManager::pin_device(&storage, "sync-1", &device).unwrap();
        DeviceRegistryManager::verify_device_key(&storage, "sync-1", "dev-a", &[1u8; 32]).unwrap();
    }

    #[test]
    fn verify_unknown_device_fails() {
        let storage = make_storage();
        let result =
            DeviceRegistryManager::verify_device_key(&storage, "sync-1", "unknown", &[1u8; 32]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("not in registry"), "got: {msg}");
    }

    #[test]
    fn key_change_detected() {
        let storage = make_storage();
        let device = make_device("sync-1", "dev-a", &[1u8; 32]);
        DeviceRegistryManager::pin_device(&storage, "sync-1", &device).unwrap();

        // Try to verify with a different key
        let result =
            DeviceRegistryManager::verify_device_key(&storage, "sync-1", "dev-a", &[2u8; 32]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("key changed"), "got: {msg}");
    }

    #[test]
    fn revoked_device_fails_verification() {
        let storage = make_storage();
        let device = make_device("sync-1", "dev-a", &[1u8; 32]);
        DeviceRegistryManager::pin_device(&storage, "sync-1", &device).unwrap();
        DeviceRegistryManager::revoke_device(&storage, "sync-1", "dev-a").unwrap();

        let result =
            DeviceRegistryManager::verify_device_key(&storage, "sync-1", "dev-a", &[1u8; 32]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("revoked"),
            "expected 'revoked' error, got: {msg}"
        );

        // Device record still exists (not deleted)
        let record = storage.get_device_record("sync-1", "dev-a").unwrap();
        assert!(record.is_some());
        assert_eq!(record.unwrap().status, "revoked");
    }

    #[test]
    fn import_keyring_pins_multiple_devices() {
        let storage = make_storage();
        let devices = vec![
            make_device("sync-1", "dev-a", &[1u8; 32]),
            make_device("sync-1", "dev-b", &[2u8; 32]),
            make_device("sync-1", "dev-c", &[3u8; 32]),
        ];
        DeviceRegistryManager::import_keyring(&storage, "sync-1", &devices).unwrap();

        // All three should verify
        DeviceRegistryManager::verify_device_key(&storage, "sync-1", "dev-a", &[1u8; 32]).unwrap();
        DeviceRegistryManager::verify_device_key(&storage, "sync-1", "dev-b", &[2u8; 32]).unwrap();
        DeviceRegistryManager::verify_device_key(&storage, "sync-1", "dev-c", &[3u8; 32]).unwrap();
    }

    #[test]
    fn list_devices_returns_all() {
        let storage = make_storage();
        let devices = vec![
            make_device("sync-1", "dev-a", &[1u8; 32]),
            make_device("sync-1", "dev-b", &[2u8; 32]),
        ];
        DeviceRegistryManager::import_keyring(&storage, "sync-1", &devices).unwrap();

        let listed = DeviceRegistryManager::list_devices(&storage, "sync-1").unwrap();
        assert_eq!(listed.len(), 2);
    }

    #[test]
    fn upsert_updates_existing_device() {
        let storage = make_storage();
        let device1 = make_device("sync-1", "dev-a", &[1u8; 32]);
        DeviceRegistryManager::pin_device(&storage, "sync-1", &device1).unwrap();

        // Re-pinning with a different key should fail closed.
        let device2 = make_device("sync-1", "dev-a", &[99u8; 32]);
        let result = DeviceRegistryManager::pin_device(&storage, "sync-1", &device2);
        assert!(matches!(
            result,
            Err(CoreError::DeviceKeyChanged { ref device_id }) if device_id == "dev-a"
        ));

        DeviceRegistryManager::verify_device_key(&storage, "sync-1", "dev-a", &[1u8; 32]).unwrap();
    }

    #[test]
    fn merge_relay_device_updates_status_without_repinning() {
        let storage = make_storage();
        let original = make_device("sync-1", "dev-a", &[1u8; 32]);
        DeviceRegistryManager::pin_device(&storage, "sync-1", &original).unwrap();

        let mut revoked = original.clone();
        revoked.status = "revoked".into();
        revoked.revoked_at = Some(Utc::now());

        DeviceRegistryManager::merge_relay_device(&storage, "sync-1", &revoked).unwrap();

        let stored = storage
            .get_device_record("sync-1", "dev-a")
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, "revoked");
        assert_eq!(stored.ed25519_public_key, original.ed25519_public_key);
        assert_eq!(stored.x25519_public_key, original.x25519_public_key);
    }

    #[test]
    fn merge_relay_device_rejects_key_change() {
        let storage = make_storage();
        let original = make_device("sync-1", "dev-a", &[1u8; 32]);
        DeviceRegistryManager::pin_device(&storage, "sync-1", &original).unwrap();

        let changed = make_device("sync-1", "dev-a", &[9u8; 32]);
        let result = DeviceRegistryManager::merge_relay_device(&storage, "sync-1", &changed);
        assert!(matches!(
            result,
            Err(CoreError::DeviceKeyChanged { ref device_id }) if device_id == "dev-a"
        ));
    }

    #[test]
    fn merge_relay_device_does_not_unrevoke_local_tombstone() {
        let storage = make_storage();
        let device = make_device("sync-1", "dev-a", &[1u8; 32]);
        DeviceRegistryManager::pin_device(&storage, "sync-1", &device).unwrap();
        DeviceRegistryManager::revoke_device(&storage, "sync-1", "dev-a").unwrap();

        let active_again = make_device("sync-1", "dev-a", &[1u8; 32]);
        DeviceRegistryManager::merge_relay_device(&storage, "sync-1", &active_again).unwrap();

        let stored = storage
            .get_device_record("sync-1", "dev-a")
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, "revoked");
    }

    #[test]
    fn accept_ml_dsa_rotation_with_valid_proof() {
        let storage = make_storage();
        let secret = prism_sync_crypto::DeviceSecret::from_bytes(vec![42u8; 32]).unwrap();
        let device_id = "dev-rotate";

        // Create initial device with gen 0 keys
        let ed25519 = secret.ed25519_keypair(device_id).unwrap();
        let ml_dsa_0 = secret.ml_dsa_65_keypair_v(device_id, 0).unwrap();

        let device = DeviceRecord {
            sync_id: "sync-1".into(),
            device_id: device_id.into(),
            ed25519_public_key: ed25519.public_key_bytes().to_vec(),
            x25519_public_key: vec![0u8; 32],
            ml_dsa_65_public_key: ml_dsa_0.public_key_bytes(),
            ml_kem_768_public_key: vec![0u8; 1184],
            x_wing_public_key: vec![],
            status: "active".into(),
            registered_at: Utc::now(),
            revoked_at: None,
            ml_dsa_key_generation: 0,
        };
        DeviceRegistryManager::pin_device(&storage, "sync-1", &device).unwrap();

        // Create rotation proof
        let proof = prism_sync_crypto::pq::continuity_proof::MlDsaContinuityProof::create(
            &secret, device_id, 0, 1,
        )
        .unwrap();
        let ml_dsa_1 = secret.ml_dsa_65_keypair_v(device_id, 1).unwrap();

        // Accept the rotation
        DeviceRegistryManager::accept_ml_dsa_rotation(
            &storage,
            "sync-1",
            device_id,
            &ml_dsa_1.public_key_bytes(),
            1,
            &proof,
        )
        .unwrap();

        // Verify the new key is stored
        let stored = storage
            .get_device_record("sync-1", device_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored.ml_dsa_key_generation, 1);
        assert_eq!(stored.ml_dsa_65_public_key, ml_dsa_1.public_key_bytes());
    }

    #[test]
    fn accept_ml_dsa_rotation_rejects_invalid_proof() {
        let storage = make_storage();
        let secret = prism_sync_crypto::DeviceSecret::from_bytes(vec![42u8; 32]).unwrap();
        let device_id = "dev-rotate-bad";

        let ed25519 = secret.ed25519_keypair(device_id).unwrap();
        let ml_dsa_0 = secret.ml_dsa_65_keypair_v(device_id, 0).unwrap();

        let device = DeviceRecord {
            sync_id: "sync-1".into(),
            device_id: device_id.into(),
            ed25519_public_key: ed25519.public_key_bytes().to_vec(),
            x25519_public_key: vec![0u8; 32],
            ml_dsa_65_public_key: ml_dsa_0.public_key_bytes(),
            ml_kem_768_public_key: vec![0u8; 1184],
            x_wing_public_key: vec![],
            status: "active".into(),
            registered_at: Utc::now(),
            revoked_at: None,
            ml_dsa_key_generation: 0,
        };
        DeviceRegistryManager::pin_device(&storage, "sync-1", &device).unwrap();

        // Create a valid proof but tamper with old_signs_new
        let mut proof = prism_sync_crypto::pq::continuity_proof::MlDsaContinuityProof::create(
            &secret, device_id, 0, 1,
        )
        .unwrap();
        proof.old_signs_new[10] ^= 0xFF;
        let ml_dsa_1 = secret.ml_dsa_65_keypair_v(device_id, 1).unwrap();

        let result = DeviceRegistryManager::accept_ml_dsa_rotation(
            &storage,
            "sync-1",
            device_id,
            &ml_dsa_1.public_key_bytes(),
            1,
            &proof,
        );
        assert!(result.is_err(), "tampered proof should be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("continuity proof verification failed"),
            "got: {msg}"
        );
    }

    #[test]
    fn accept_ml_dsa_rotation_rejects_generation_rollback() {
        let storage = make_storage();
        let secret = prism_sync_crypto::DeviceSecret::from_bytes(vec![42u8; 32]).unwrap();
        let device_id = "dev-rotate-rollback";

        let ed25519 = secret.ed25519_keypair(device_id).unwrap();
        let ml_dsa_0 = secret.ml_dsa_65_keypair_v(device_id, 0).unwrap();
        let ml_dsa_1 = secret.ml_dsa_65_keypair_v(device_id, 1).unwrap();

        // Pin device at generation 1
        let device = DeviceRecord {
            sync_id: "sync-1".into(),
            device_id: device_id.into(),
            ed25519_public_key: ed25519.public_key_bytes().to_vec(),
            x25519_public_key: vec![0u8; 32],
            ml_dsa_65_public_key: ml_dsa_1.public_key_bytes(),
            ml_kem_768_public_key: vec![0u8; 1184],
            x_wing_public_key: vec![],
            status: "active".into(),
            registered_at: Utc::now(),
            revoked_at: None,
            ml_dsa_key_generation: 1,
        };
        DeviceRegistryManager::pin_device(&storage, "sync-1", &device).unwrap();

        // Try to rotate back to generation 0 (should fail)
        let proof = prism_sync_crypto::pq::continuity_proof::MlDsaContinuityProof::create(
            &secret, device_id, 1, 2,
        )
        .unwrap();

        // Even with a valid proof for 1->2, try to pass generation 0
        let result = DeviceRegistryManager::accept_ml_dsa_rotation(
            &storage,
            "sync-1",
            device_id,
            &ml_dsa_0.public_key_bytes(),
            0,
            &proof,
        );
        assert!(
            matches!(result, Err(CoreError::DeviceKeyChanged { .. })),
            "generation rollback should be rejected"
        );

        // Also try the same generation
        let result = DeviceRegistryManager::accept_ml_dsa_rotation(
            &storage,
            "sync-1",
            device_id,
            &ml_dsa_1.public_key_bytes(),
            1,
            &proof,
        );
        assert!(
            matches!(result, Err(CoreError::DeviceKeyChanged { .. })),
            "same generation should be rejected"
        );
    }

    #[test]
    fn merge_relay_device_rejects_unverified_ml_dsa_rotation() {
        let storage = make_storage();
        let secret = prism_sync_crypto::DeviceSecret::from_bytes(vec![42u8; 32]).unwrap();
        let device_id = "dev-merge-rotate";

        let ed25519 = secret.ed25519_keypair(device_id).unwrap();
        let ml_dsa_0 = secret.ml_dsa_65_keypair_v(device_id, 0).unwrap();
        let ml_dsa_1 = secret.ml_dsa_65_keypair_v(device_id, 1).unwrap();

        let device = DeviceRecord {
            sync_id: "sync-1".into(),
            device_id: device_id.into(),
            ed25519_public_key: ed25519.public_key_bytes().to_vec(),
            x25519_public_key: vec![0u8; 32],
            ml_dsa_65_public_key: ml_dsa_0.public_key_bytes(),
            ml_kem_768_public_key: vec![0u8; 1184],
            x_wing_public_key: vec![],
            status: "active".into(),
            registered_at: Utc::now(),
            revoked_at: None,
            ml_dsa_key_generation: 0,
        };
        DeviceRegistryManager::pin_device(&storage, "sync-1", &device).unwrap();

        // Relay sends updated device with new ML-DSA key and higher generation —
        // merge_relay_device should return Ok but NOT update the key.
        let rotated = DeviceRecord {
            ml_dsa_65_public_key: ml_dsa_1.public_key_bytes(),
            ml_dsa_key_generation: 1,
            ..device.clone()
        };
        DeviceRegistryManager::merge_relay_device(&storage, "sync-1", &rotated).unwrap();

        // The stored record should still have the OLD key and generation
        let stored = storage
            .get_device_record("sync-1", device_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored.ml_dsa_key_generation, 0, "generation should not be updated");
        assert_eq!(stored.ml_dsa_65_public_key, ml_dsa_0.public_key_bytes(), "ML-DSA key should not be updated");
    }

    #[test]
    fn merge_relay_device_still_rejects_ed25519_change() {
        let storage = make_storage();
        let secret = prism_sync_crypto::DeviceSecret::from_bytes(vec![42u8; 32]).unwrap();
        let device_id = "dev-merge-ed-change";

        let ed25519 = secret.ed25519_keypair(device_id).unwrap();
        let ml_dsa_0 = secret.ml_dsa_65_keypair_v(device_id, 0).unwrap();
        let ml_dsa_1 = secret.ml_dsa_65_keypair_v(device_id, 1).unwrap();

        let device = DeviceRecord {
            sync_id: "sync-1".into(),
            device_id: device_id.into(),
            ed25519_public_key: ed25519.public_key_bytes().to_vec(),
            x25519_public_key: vec![0u8; 32],
            ml_dsa_65_public_key: ml_dsa_0.public_key_bytes(),
            ml_kem_768_public_key: vec![0u8; 1184],
            x_wing_public_key: vec![],
            status: "active".into(),
            registered_at: Utc::now(),
            revoked_at: None,
            ml_dsa_key_generation: 0,
        };
        DeviceRegistryManager::pin_device(&storage, "sync-1", &device).unwrap();

        // Change both Ed25519 key AND ML-DSA key — should still be rejected
        let changed = DeviceRecord {
            ed25519_public_key: vec![99u8; 32],
            ml_dsa_65_public_key: ml_dsa_1.public_key_bytes(),
            ml_dsa_key_generation: 1,
            ..device.clone()
        };
        let result = DeviceRegistryManager::merge_relay_device(&storage, "sync-1", &changed);
        assert!(
            matches!(result, Err(CoreError::DeviceKeyChanged { .. })),
            "Ed25519 key change should still be rejected even with higher ML-DSA generation"
        );
    }

    #[test]
    fn accept_ml_dsa_rotation_rejects_revoked_device() {
        let storage = make_storage();
        let secret = prism_sync_crypto::DeviceSecret::from_bytes(vec![42u8; 32]).unwrap();
        let device_id = "dev-revoked";

        let ed25519 = secret.ed25519_keypair(device_id).unwrap();
        let ml_dsa_0 = secret.ml_dsa_65_keypair_v(device_id, 0).unwrap();
        let device = DeviceRecord {
            sync_id: "sync-1".into(),
            device_id: device_id.into(),
            ed25519_public_key: ed25519.public_key_bytes().to_vec(),
            x25519_public_key: vec![0u8; 32],
            ml_dsa_65_public_key: ml_dsa_0.public_key_bytes(),
            ml_kem_768_public_key: vec![0u8; 1184],
            x_wing_public_key: vec![],
            status: "active".into(),
            registered_at: Utc::now(),
            revoked_at: None,
            ml_dsa_key_generation: 0,
        };
        DeviceRegistryManager::pin_device(&storage, "sync-1", &device).unwrap();
        DeviceRegistryManager::revoke_device(&storage, "sync-1", device_id).unwrap();

        let proof = prism_sync_crypto::pq::continuity_proof::MlDsaContinuityProof::create(
            &secret, device_id, 0, 1,
        )
        .unwrap();
        let ml_dsa_1 = secret.ml_dsa_65_keypair_v(device_id, 1).unwrap();

        let result = DeviceRegistryManager::accept_ml_dsa_rotation(
            &storage, "sync-1", device_id, &ml_dsa_1.public_key_bytes(), 1, &proof,
        );
        assert!(result.is_err(), "rotation on revoked device should fail");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("revoked"), "error should mention revoked, got: {msg}");
    }

    #[test]
    fn pin_device_accepts_ml_dsa_rotation_via_keyring() {
        let storage = make_storage();
        let secret = prism_sync_crypto::DeviceSecret::from_bytes(vec![42u8; 32]).unwrap();
        let device_id = "dev-pin-rotate";

        let ed25519 = secret.ed25519_keypair(device_id).unwrap();
        let ml_dsa_0 = secret.ml_dsa_65_keypair_v(device_id, 0).unwrap();
        let ml_dsa_1 = secret.ml_dsa_65_keypair_v(device_id, 1).unwrap();

        // Pin at generation 0
        let device_gen0 = DeviceRecord {
            sync_id: "sync-1".into(),
            device_id: device_id.into(),
            ed25519_public_key: ed25519.public_key_bytes().to_vec(),
            x25519_public_key: vec![0u8; 32],
            ml_dsa_65_public_key: ml_dsa_0.public_key_bytes(),
            ml_kem_768_public_key: vec![0u8; 1184],
            x_wing_public_key: vec![],
            status: "active".into(),
            registered_at: Utc::now(),
            revoked_at: None,
            ml_dsa_key_generation: 0,
        };
        DeviceRegistryManager::pin_device(&storage, "sync-1", &device_gen0).unwrap();

        // Re-pin with generation 1 (simulates keyring import from a snapshot
        // that saw the rotation)
        let device_gen1 = DeviceRecord {
            ml_dsa_65_public_key: ml_dsa_1.public_key_bytes(),
            ml_dsa_key_generation: 1,
            ..device_gen0.clone()
        };
        DeviceRegistryManager::pin_device(&storage, "sync-1", &device_gen1).unwrap();

        let stored = storage.get_device_record("sync-1", device_id).unwrap().unwrap();
        assert_eq!(stored.ml_dsa_key_generation, 1);
        assert_eq!(stored.ml_dsa_65_public_key, ml_dsa_1.public_key_bytes());
    }

    #[test]
    fn future_registry_version_byte_rejected() {
        let storage = make_storage();

        // Build an artifact blob starting with version byte 0x04 (unknown future version)
        let mut blob = Vec::new();
        blob.push(0x04u8); // future version byte — not 0x03
        blob.extend_from_slice(b"some payload that would never be parsed");

        let result =
            DeviceRegistryManager::verify_and_import_signed_registry(&storage, "sync-1", &blob, None);
        assert!(
            result.is_err(),
            "future registry version byte should be rejected"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("unsupported registry artifact version"),
            "error should mention unsupported version, got: {msg}"
        );
    }

    #[test]
    fn malformed_registry_json_rejected() {
        let storage = make_storage();

        // Build a blob with valid version byte 0x03, followed by a plausible
        // HybridSignature encoding (length-prefixed zeros), followed by invalid JSON.
        //
        // Format per verify_and_import_signed_registry:
        //   [0x03] || le_u32(ed_len) || ed_bytes || le_u32(ml_len) || ml_bytes || json
        //
        // This will fail at signature verification (not JSON parsing), which is
        // expected — the test verifies the function handles malformed input
        // without panicking.
        let mut blob = Vec::new();
        blob.push(0x03u8); // version byte

        // Fake Ed25519 signature part (64 zero bytes with LE length prefix)
        let ed_len: u32 = 64;
        blob.extend_from_slice(&ed_len.to_le_bytes());
        blob.extend_from_slice(&[0u8; 64]);

        // Fake ML-DSA signature part (100 zero bytes with LE length prefix)
        let ml_len: u32 = 100;
        blob.extend_from_slice(&ml_len.to_le_bytes());
        blob.extend_from_slice(&[0u8; 100]);

        // Invalid JSON payload
        blob.extend_from_slice(b"not valid json {{{{");

        let result =
            DeviceRegistryManager::verify_and_import_signed_registry(&storage, "sync-1", &blob, None);
        assert!(
            result.is_err(),
            "blob with invalid content should be rejected without panic"
        );
    }
}
