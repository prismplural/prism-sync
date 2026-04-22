use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use prism_sync_crypto::{aead, KeyHierarchy};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};
use crate::secure_store::SecureStore;
use crate::storage::StorageError;

const DEVICE_WRAP_KEY_STORAGE_KEY: &str = "device_wrap_key";
const RUNTIME_KEYS_PREFIX: &str = "runtime_keys_";

/// Persists epoch keys from [`KeyHierarchy`] to [`SecureStore`] encrypted under
/// a device-local wrap key.  Enables restart-safe recovery of epoch keys without
/// requiring the user to re-enter their password.
pub struct SyncRuntimeKeys;

impl SyncRuntimeKeys {
    /// Persist current epoch keys from `KeyHierarchy` to `SecureStore`.
    ///
    /// Epoch keys are serialised as `{"epoch_0": "<base64>", ...}`, encrypted
    /// with XChaCha20-Poly1305 under a device wrap key, then stored under
    /// `"runtime_keys_{sync_id}"`.
    pub async fn persist(
        key_hierarchy: &KeyHierarchy,
        sync_id: &str,
        secure_store: &dyn SecureStore,
    ) -> Result<()> {
        let epoch_keys = key_hierarchy.export_epoch_keys()?;
        if epoch_keys.is_empty() {
            return Ok(());
        }

        let wrap_key = Self::get_or_create_wrap_key(secure_store)?;

        // Serialise epoch keys: {"epoch_0": "<base64>", ...}
        let payload: HashMap<String, String> = epoch_keys
            .iter()
            .map(|(epoch, key)| (format!("epoch_{epoch}"), STANDARD.encode(&**key)))
            .collect();
        let json =
            serde_json::to_vec(&payload).map_err(|e| CoreError::Serialization(e.to_string()))?;

        // Encrypt under wrap key
        let encrypted = aead::xchacha_encrypt(&wrap_key, &json)
            .map_err(|e| CoreError::Storage(StorageError::Logic(format!("encrypt failed: {e}"))))?;

        let storage_key = format!("{RUNTIME_KEYS_PREFIX}{sync_id}");
        secure_store.set(&storage_key, &encrypted)?;
        Ok(())
    }

    /// Restore epoch keys from `SecureStore` into `KeyHierarchy`.
    ///
    /// Returns `true` if keys were restored, `false` if nothing was stored yet.
    pub async fn restore(
        key_hierarchy: &mut KeyHierarchy,
        sync_id: &str,
        secure_store: &dyn SecureStore,
    ) -> Result<bool> {
        let storage_key = format!("{RUNTIME_KEYS_PREFIX}{sync_id}");

        let encrypted = match secure_store.get(&storage_key)? {
            Some(data) => data,
            None => return Ok(false),
        };

        let wrap_key = match secure_store.get(DEVICE_WRAP_KEY_STORAGE_KEY)? {
            Some(key) => key,
            None => return Ok(false),
        };

        let json = Zeroizing::new(aead::xchacha_decrypt(&wrap_key, &encrypted).map_err(|e| {
            CoreError::Storage(StorageError::Logic(format!("decrypt failed: {e}")))
        })?);

        let payload: HashMap<String, String> =
            serde_json::from_slice(&json).map_err(|e| CoreError::Serialization(e.to_string()))?;

        let mut keys: HashMap<u32, Zeroizing<Vec<u8>>> = HashMap::new();
        for (key_str, value_b64) in payload {
            if let Some(epoch_str) = key_str.strip_prefix("epoch_") {
                let epoch: u32 = epoch_str.parse().map_err(|e| {
                    CoreError::Storage(StorageError::Logic(format!("invalid epoch: {e}")))
                })?;
                let key_bytes = STANDARD.decode(&value_b64).map_err(|e| {
                    CoreError::Storage(StorageError::Logic(format!("base64 decode: {e}")))
                })?;
                keys.insert(epoch, Zeroizing::new(key_bytes));
            }
        }

        key_hierarchy.import_epoch_keys(keys);
        Ok(true)
    }

    /// Get the device wrap key from SecureStore, generating a fresh one if absent.
    fn get_or_create_wrap_key(secure_store: &dyn SecureStore) -> Result<Zeroizing<Vec<u8>>> {
        if let Some(key) = secure_store.get(DEVICE_WRAP_KEY_STORAGE_KEY)? {
            return Ok(Zeroizing::new(key));
        }
        let mut key = Zeroizing::new(vec![0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut key);
        secure_store.set(DEVICE_WRAP_KEY_STORAGE_KEY, &key)?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use crate::error::Result as CoreResult;

    /// Minimal in-memory SecureStore for testing.
    #[derive(Default)]
    struct MemStore(Mutex<HashMap<String, Vec<u8>>>);

    impl SecureStore for MemStore {
        fn get(&self, key: &str) -> CoreResult<Option<Vec<u8>>> {
            Ok(self.0.lock().unwrap().get(key).cloned())
        }
        fn set(&self, key: &str, value: &[u8]) -> CoreResult<()> {
            self.0.lock().unwrap().insert(key.to_string(), value.to_vec());
            Ok(())
        }
        fn delete(&self, key: &str) -> CoreResult<()> {
            self.0.lock().unwrap().remove(key);
            Ok(())
        }
        fn clear(&self) -> CoreResult<()> {
            self.0.lock().unwrap().clear();
            Ok(())
        }
    }

    fn unlocked_hierarchy() -> KeyHierarchy {
        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();
        kh
    }

    #[tokio::test]
    async fn persist_and_restore_roundtrip() {
        let store = MemStore::default();
        let mut kh = unlocked_hierarchy();
        // Add an extra epoch key to verify it survives the round-trip.
        kh.store_epoch_key(3, Zeroizing::new(vec![77u8; 32]));

        let epoch0_before = kh.epoch_key(0).unwrap().to_vec();
        let epoch3_before = kh.epoch_key(3).unwrap().to_vec();

        SyncRuntimeKeys::persist(&kh, "sync-abc", &store).await.unwrap();

        // Create a fresh KeyHierarchy and restore into it.
        let mut kh2 = KeyHierarchy::new();
        // import_epoch_keys doesn't require the hierarchy to be unlocked, but we
        // still need a place to load into. Unlock via the same credentials first so
        // that epoch 0 is available.
        kh2.initialize("password", &[1u8; 16]).unwrap();

        let restored = SyncRuntimeKeys::restore(&mut kh2, "sync-abc", &store).await.unwrap();
        assert!(restored, "should report keys were restored");

        assert_eq!(kh2.epoch_key(0).unwrap(), epoch0_before.as_slice());
        assert_eq!(kh2.epoch_key(3).unwrap(), epoch3_before.as_slice());
    }

    #[tokio::test]
    async fn restore_returns_false_when_empty() {
        let store = MemStore::default();
        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();

        let restored = SyncRuntimeKeys::restore(&mut kh, "missing-sync-id", &store).await.unwrap();
        assert!(!restored, "should return false when nothing stored");
    }

    #[tokio::test]
    async fn different_sync_ids_do_not_interfere() {
        let store = MemStore::default();

        let mut kh_a = unlocked_hierarchy();
        kh_a.store_epoch_key(1, Zeroizing::new(vec![0xAA; 32]));

        let mut kh_b = unlocked_hierarchy();
        kh_b.store_epoch_key(1, Zeroizing::new(vec![0xBB; 32]));

        SyncRuntimeKeys::persist(&kh_a, "sync-aaa", &store).await.unwrap();
        SyncRuntimeKeys::persist(&kh_b, "sync-bbb", &store).await.unwrap();

        let mut out_a = unlocked_hierarchy();
        SyncRuntimeKeys::restore(&mut out_a, "sync-aaa", &store).await.unwrap();
        assert_eq!(out_a.epoch_key(1).unwrap(), &[0xAA; 32]);

        let mut out_b = unlocked_hierarchy();
        SyncRuntimeKeys::restore(&mut out_b, "sync-bbb", &store).await.unwrap();
        assert_eq!(out_b.epoch_key(1).unwrap(), &[0xBB; 32]);
    }

    #[tokio::test]
    async fn wrap_key_reused_across_calls() {
        let store = MemStore::default();
        let kh = unlocked_hierarchy();

        SyncRuntimeKeys::persist(&kh, "s1", &store).await.unwrap();
        let wrap_key_first = store.get(DEVICE_WRAP_KEY_STORAGE_KEY).unwrap().unwrap();
        SyncRuntimeKeys::persist(&kh, "s2", &store).await.unwrap();
        let wrap_key_second = store.get(DEVICE_WRAP_KEY_STORAGE_KEY).unwrap().unwrap();

        assert_eq!(wrap_key_first, wrap_key_second, "wrap key must be stable");
    }
}
