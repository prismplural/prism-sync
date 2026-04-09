//! Epoch rotation and rekey.
//!
//! When a device is revoked, the sync group rotates to a new epoch with a
//! fresh epoch key. The revoking device posts per-device wrapped epoch keys
//! to the relay so that remaining devices can recover the new key. Revoked
//! devices never receive a wrapped key for the new epoch.

use std::collections::HashMap;

use crate::error::{CoreError, Result};
use crate::relay::SyncRelay;
use prism_sync_crypto::{DeviceExchangeKey, KeyHierarchy};
use zeroize::Zeroizing;

/// Stateless helper for epoch rotation operations.
pub struct EpochManager;

impl EpochManager {
    /// Handle an epoch rotation event: fetch the new epoch key from the relay,
    /// unwrap it via X25519 DH + HKDF, and store it in the key hierarchy.
    ///
    /// This is called when the local device receives an `EpochRotated` or
    /// `DeviceRevoked` notification. The relay holds a per-device wrapped
    /// epoch key that was posted by the device that initiated the revocation.
    pub async fn handle_rotation(
        relay: &dyn SyncRelay,
        key_hierarchy: &mut KeyHierarchy,
        new_epoch: u32,
        device_id: &str,
        device_exchange_key: &DeviceExchangeKey,
        sender_x25519_pk: &[u8; 32],
    ) -> Result<()> {
        let wrapped = relay
            .get_rekey_artifact(new_epoch as i32, device_id)
            .await
            .map_err(|e| CoreError::Storage(format!("failed to fetch rekey artifact: {e}")))?
            .ok_or_else(|| {
                CoreError::Storage(format!("no rekey artifact for epoch {new_epoch}"))
            })?;

        // 1. Compute DH shared secret
        let shared_secret = device_exchange_key.diffie_hellman(sender_x25519_pk);

        // 2. Derive unwrap key via HKDF
        let unwrap_key =
            prism_sync_crypto::kdf::derive_subkey(&shared_secret, &[], b"prism_epoch_unwrap")
                .map_err(CoreError::Crypto)?;

        // 3. Decrypt epoch key
        let epoch_key = prism_sync_crypto::aead::xchacha_decrypt(&unwrap_key, &wrapped)
            .map_err(CoreError::Crypto)?;

        // 4. Store the epoch key
        key_hierarchy.store_epoch_key(new_epoch, Zeroizing::new(epoch_key));
        Ok(())
    }

    /// Generate a fresh epoch key and wrap it for all active devices, optionally
    /// excluding one target device (for atomic revocation).
    pub async fn prepare_wrapped_keys(
        relay: &dyn SyncRelay,
        device_exchange_key: &DeviceExchangeKey,
        excluded_device_id: Option<&str>,
    ) -> Result<(Zeroizing<Vec<u8>>, HashMap<String, Vec<u8>>)> {
        // 1. Generate a random 32-byte epoch key
        let mut epoch_key_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut epoch_key_bytes);

        // 2. List active devices from relay
        let devices = relay
            .list_devices()
            .await
            .map_err(|e| CoreError::Storage(format!("failed to list devices: {e}")))?;

        // 3. For each active surviving device, wrap the epoch key
        let mut wrapped_keys: HashMap<String, Vec<u8>> = HashMap::new();
        for device in &devices {
            if device.status != "active" {
                continue;
            }
            if excluded_device_id.is_some_and(|excluded| excluded == device.device_id) {
                continue;
            }
            if device.x25519_public_key.len() != 32 {
                continue;
            }
            let peer_pk: [u8; 32] = device.x25519_public_key.as_slice().try_into().unwrap();

            // Compute DH shared secret with this device
            let shared_secret = device_exchange_key.diffie_hellman(&peer_pk);

            // Derive wrap key via HKDF
            let wrap_key =
                prism_sync_crypto::kdf::derive_subkey(&shared_secret, &[], b"prism_epoch_unwrap")
                    .map_err(CoreError::Crypto)?;

            // Encrypt epoch key for this device
            let wrapped = prism_sync_crypto::aead::xchacha_encrypt(&wrap_key, &epoch_key_bytes)
                .map_err(CoreError::Crypto)?;

            wrapped_keys.insert(device.device_id.clone(), wrapped);
        }

        Ok((Zeroizing::new(epoch_key_bytes.to_vec()), wrapped_keys))
    }

    /// Standalone non-revoking epoch rotation: upload wrapped artifacts for all
    /// active devices and store the new epoch key locally.
    pub async fn post_rekey(
        relay: &dyn SyncRelay,
        key_hierarchy: &mut KeyHierarchy,
        new_epoch: u32,
        device_exchange_key: &DeviceExchangeKey,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let (epoch_key, wrapped_keys) =
            Self::prepare_wrapped_keys(relay, device_exchange_key, None).await?;

        key_hierarchy.store_epoch_key(new_epoch, Zeroizing::new(epoch_key.to_vec()));
        relay
            .post_rekey_artifacts(new_epoch as i32, wrapped_keys)
            .await
            .map_err(|e| CoreError::Storage(format!("failed to post rekey artifacts: {e}")))?;

        Ok(epoch_key)
    }

    /// Generate a new sync_id: 32 random bytes, hex-encoded (64 chars).
    pub fn generate_sync_id() -> String {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        hex::encode(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_sync_id_is_64_hex_chars() {
        let id = EpochManager::generate_sync_id();
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_sync_id_is_unique() {
        let id1 = EpochManager::generate_sync_id();
        let id2 = EpochManager::generate_sync_id();
        assert_ne!(id1, id2);
    }

    // Integration tests for handle_rotation and post_rekey using mock relay.

    use crate::relay::traits::*;
    use async_trait::async_trait;
    use futures_util::Stream;
    use prism_sync_crypto::DeviceSecret;
    use std::collections::HashMap;
    use std::pin::Pin;
    use std::sync::Mutex;

    struct MockRelay {
        artifact: Option<Vec<u8>>,
        devices: Vec<DeviceInfo>,
        #[allow(clippy::type_complexity)]
        posted_artifacts: Mutex<Option<(i32, HashMap<String, Vec<u8>>)>>,
    }

    impl MockRelay {
        fn new_with_artifact(artifact: Option<Vec<u8>>) -> Self {
            Self {
                artifact,
                devices: Vec::new(),
                posted_artifacts: Mutex::new(None),
            }
        }

        fn new_with_devices(devices: Vec<DeviceInfo>) -> Self {
            Self {
                artifact: None,
                devices,
                posted_artifacts: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl SyncRelay for MockRelay {
        async fn get_registration_nonce(
            &self,
        ) -> std::result::Result<crate::relay::traits::RegistrationNonceResponse, RelayError>
        {
            Ok(crate::relay::traits::RegistrationNonceResponse {
                nonce: uuid::Uuid::new_v4().to_string(),
                pow_challenge: None,
                min_signature_version: None,
            })
        }
        async fn register_device(
            &self,
            _req: RegisterRequest,
        ) -> std::result::Result<RegisterResponse, RelayError> {
            Ok(RegisterResponse {
                device_session_token: "mock-token".to_string(),
                min_signature_version: None,
            })
        }
        async fn pull_changes(&self, _since: i64) -> std::result::Result<PullResponse, RelayError> {
            unimplemented!()
        }
        async fn push_changes(
            &self,
            _batch: OutgoingBatch,
        ) -> std::result::Result<i64, RelayError> {
            unimplemented!()
        }
        async fn get_snapshot(&self) -> std::result::Result<Option<SnapshotResponse>, RelayError> {
            unimplemented!()
        }
        async fn put_snapshot(
            &self,
            _epoch: i32,
            _seq: i64,
            _data: Vec<u8>,
            _ttl_secs: Option<u64>,
            _for_device_id: Option<String>,
            _sender_device_id: String,
        ) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn list_devices(&self) -> std::result::Result<Vec<DeviceInfo>, RelayError> {
            Ok(self.devices.clone())
        }
        async fn revoke_device(
            &self,
            _device_id: &str,
            _remote_wipe: bool,
            _new_epoch: i32,
            _wrapped_keys: HashMap<String, Vec<u8>>,
        ) -> std::result::Result<i32, RelayError> {
            unimplemented!()
        }
        async fn post_rekey_artifacts(
            &self,
            epoch: i32,
            keys: HashMap<String, Vec<u8>>,
        ) -> std::result::Result<i32, RelayError> {
            *self.posted_artifacts.lock().unwrap() = Some((epoch, keys));
            Ok(epoch)
        }
        async fn get_rekey_artifact(
            &self,
            _epoch: i32,
            _device_id: &str,
        ) -> std::result::Result<Option<Vec<u8>>, RelayError> {
            Ok(self.artifact.clone())
        }
        async fn deregister(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn delete_sync_group(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn ack(&self, _seq: i64) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn connect_websocket(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn disconnect_websocket(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        fn notifications(&self) -> Pin<Box<dyn Stream<Item = SyncNotification> + Send>> {
            unimplemented!()
        }
        async fn dispose(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn handle_rotation_unwraps_and_stores_epoch_key() {
        // Simulate: sender wraps a known epoch key for receiver via DH
        let sender_secret = DeviceSecret::generate();
        let receiver_secret = DeviceSecret::generate();
        let sender_xk = sender_secret.x25519_keypair("sender").unwrap();
        let receiver_xk = receiver_secret.x25519_keypair("receiver").unwrap();

        // Sender wraps the epoch key for receiver
        let epoch_key = vec![0xABu8; 32];
        let shared = sender_xk.diffie_hellman(&receiver_xk.public_key_bytes());
        let wrap_key =
            prism_sync_crypto::kdf::derive_subkey(&shared, &[], b"prism_epoch_unwrap").unwrap();
        let wrapped = prism_sync_crypto::aead::xchacha_encrypt(&wrap_key, &epoch_key).unwrap();

        let relay = MockRelay::new_with_artifact(Some(wrapped));
        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();

        EpochManager::handle_rotation(
            &relay,
            &mut kh,
            5,
            "receiver",
            &receiver_xk,
            &sender_xk.public_key_bytes(),
        )
        .await
        .unwrap();

        assert!(kh.has_epoch_key(5));
        assert_eq!(kh.epoch_key(5).unwrap(), &epoch_key);
    }

    #[tokio::test]
    async fn handle_rotation_missing_artifact_errors() {
        let relay = MockRelay::new_with_artifact(None);
        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();

        let secret = DeviceSecret::generate();
        let xk = secret.x25519_keypair("dev-a").unwrap();
        let fake_pk = [0u8; 32];

        let result =
            EpochManager::handle_rotation(&relay, &mut kh, 5, "dev-a", &xk, &fake_pk).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("no rekey artifact"), "got: {msg}");
    }

    fn make_devices(
        sender_xk: &DeviceExchangeKey,
        receiver_xk: &DeviceExchangeKey,
    ) -> Vec<DeviceInfo> {
        vec![
            DeviceInfo {
                device_id: "sender".to_string(),
                epoch: 1,
                status: "active".to_string(),
                ed25519_public_key: vec![],
                x25519_public_key: sender_xk.public_key_bytes().to_vec(),
                ml_dsa_65_public_key: vec![],
                ml_kem_768_public_key: vec![],
                permission: None,
            },
            DeviceInfo {
                device_id: "receiver".to_string(),
                epoch: 1,
                status: "active".to_string(),
                ed25519_public_key: vec![],
                x25519_public_key: receiver_xk.public_key_bytes().to_vec(),
                ml_dsa_65_public_key: vec![],
                ml_kem_768_public_key: vec![],
                permission: None,
            },
            DeviceInfo {
                device_id: "revoked-dev".to_string(),
                epoch: 1,
                status: "revoked".to_string(),
                ed25519_public_key: vec![],
                x25519_public_key: vec![0u8; 32],
                ml_dsa_65_public_key: vec![],
                ml_kem_768_public_key: vec![],
                permission: None,
            },
        ]
    }

    #[tokio::test]
    async fn post_rekey_wraps_for_active_devices_only() {
        let sender_secret = DeviceSecret::generate();
        let sender_xk = sender_secret.x25519_keypair("sender").unwrap();

        let receiver_secret = DeviceSecret::generate();
        let receiver_xk = receiver_secret.x25519_keypair("receiver").unwrap();

        let devices = make_devices(&sender_xk, &receiver_xk);
        let relay = MockRelay::new_with_devices(devices);

        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();

        EpochManager::post_rekey(&relay, &mut kh, 2, &sender_xk)
            .await
            .unwrap();

        let posted = relay.posted_artifacts.lock().unwrap();
        let (epoch, keys) = posted.as_ref().unwrap();
        assert_eq!(*epoch, 2);
        // Should have wrapped keys for sender and receiver, not revoked-dev
        assert_eq!(keys.len(), 2);
        assert!(keys.contains_key("sender"));
        assert!(keys.contains_key("receiver"));
        assert!(!keys.contains_key("revoked-dev"));

        // Verify receiver can unwrap
        let wrapped_for_receiver = &keys["receiver"];
        let shared = receiver_xk.diffie_hellman(&sender_xk.public_key_bytes());
        let unwrap_key =
            prism_sync_crypto::kdf::derive_subkey(&shared, &[], b"prism_epoch_unwrap").unwrap();
        let decrypted =
            prism_sync_crypto::aead::xchacha_decrypt(&unwrap_key, wrapped_for_receiver).unwrap();
        assert_eq!(decrypted.len(), 32);
    }

    #[tokio::test]
    async fn post_rekey_stores_epoch_key_in_hierarchy() {
        let sender_secret = DeviceSecret::generate();
        let sender_xk = sender_secret.x25519_keypair("sender").unwrap();

        let receiver_secret = DeviceSecret::generate();
        let receiver_xk = receiver_secret.x25519_keypair("receiver").unwrap();

        let devices = make_devices(&sender_xk, &receiver_xk);
        let relay = MockRelay::new_with_devices(devices);

        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();

        // Epoch 2 key should not exist yet
        assert!(!kh.has_epoch_key(2));

        let returned_key = EpochManager::post_rekey(&relay, &mut kh, 2, &sender_xk)
            .await
            .unwrap();

        // Epoch 2 key should now be stored in the hierarchy
        assert!(kh.has_epoch_key(2));
        let stored_key = kh.epoch_key(2).unwrap();
        assert_eq!(stored_key, &*returned_key);
        assert_eq!(stored_key.len(), 32);
    }
}
