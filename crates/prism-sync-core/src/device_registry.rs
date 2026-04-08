//! Device registry management — key pinning and change detection.
//!
//! When a device is first seen during pairing or pull, its Ed25519 public key
//! is "pinned" in local storage. Subsequent operations verify that the claimed
//! key matches the pinned key, raising an error on mismatch (TOFU model).

use crate::error::{CoreError, Result};
use crate::storage::{DeviceRecord, SyncStorage};

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
                return Err(CoreError::DeviceKeyChanged {
                    device_id: device.device_id.clone(),
                });
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

    /// List all device records for a sync group.
    pub fn list_devices(storage: &dyn SyncStorage, sync_id: &str) -> Result<Vec<DeviceRecord>> {
        storage.list_device_records(sync_id)
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
            status: "active".into(),
            registered_at: Utc::now(),
            revoked_at: None,
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
}
