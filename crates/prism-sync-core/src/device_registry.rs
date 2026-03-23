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
    /// Pin a device's keys on first sight (Trust On First Use).
    ///
    /// If the device already exists, its record is updated (upsert).
    pub fn pin_device(
        storage: &dyn SyncStorage,
        sync_id: &str,
        device: &DeviceRecord,
    ) -> Result<()> {
        let _ = sync_id; // sync_id is part of the DeviceRecord
        let mut tx = storage.begin_tx()?;
        tx.upsert_device_record(device)?;
        tx.commit()
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
            Some(r) if r.ed25519_public_key != claimed_ed25519_pk => Err(CoreError::Storage(
                format!("device {device_id} key changed — verification required"),
            )),
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
        _sync_id: &str,
        keyring: &[DeviceRecord],
    ) -> Result<()> {
        let mut tx = storage.begin_tx()?;
        for device in keyring {
            tx.upsert_device_record(device)?;
        }
        tx.commit()
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

        // Update with new key (re-pin after SAS verification, for example)
        let device2 = make_device("sync-1", "dev-a", &[99u8; 32]);
        DeviceRegistryManager::pin_device(&storage, "sync-1", &device2).unwrap();

        // New key should now verify
        DeviceRegistryManager::verify_device_key(&storage, "sync-1", "dev-a", &[99u8; 32]).unwrap();
        // Old key should fail
        let result =
            DeviceRegistryManager::verify_device_key(&storage, "sync-1", "dev-a", &[1u8; 32]);
        assert!(result.is_err());
    }
}
