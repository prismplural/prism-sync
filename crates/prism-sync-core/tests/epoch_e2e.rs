//! Epoch rotation end-to-end test (C12).
//!
//! Verifies the full cycle: Device A generates a new epoch key, posts it via
//! atomic revoke, Device B recovers it via `handle_rotation`, and both
//! can encrypt/decrypt with the same epoch key.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Mutex;

use async_trait::async_trait;
use futures_util::Stream;
use prism_sync_core::epoch::EpochManager;
use prism_sync_core::relay::traits::*;
use prism_sync_crypto::{aead, DeviceSecret, KeyHierarchy};

// ── MockRelay that stores and retrieves rekey artifacts ──

struct RekeyMockRelay {
    devices: Vec<DeviceInfo>,
    /// epoch -> device_id -> wrapped key
    artifacts: Mutex<HashMap<(i32, String), Vec<u8>>>,
}

impl RekeyMockRelay {
    fn new(devices: Vec<DeviceInfo>) -> Self {
        Self {
            devices,
            artifacts: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl SyncRelay for RekeyMockRelay {
    async fn get_registration_nonce(
        &self,
    ) -> Result<prism_sync_core::relay::traits::RegistrationNonceResponse, RelayError> {
        Ok(prism_sync_core::relay::traits::RegistrationNonceResponse {
            nonce: uuid::Uuid::new_v4().to_string(),
            pow_challenge: None,
            min_signature_version: None,
        })
    }
    async fn register_device(&self, _req: RegisterRequest) -> Result<RegisterResponse, RelayError> {
        Ok(RegisterResponse {
            device_session_token: "mock".to_string(),
            min_signature_version: None,
        })
    }
    async fn pull_changes(&self, _: i64) -> Result<PullResponse, RelayError> {
        unimplemented!()
    }
    async fn push_changes(&self, _: OutgoingBatch) -> Result<i64, RelayError> {
        unimplemented!()
    }
    async fn get_snapshot(&self) -> Result<Option<SnapshotResponse>, RelayError> {
        unimplemented!()
    }
    async fn put_snapshot(
        &self,
        _: i32,
        _: i64,
        _: Vec<u8>,
        _: Option<u64>,
        _: Option<String>,
        _: String,
    ) -> Result<(), RelayError> {
        unimplemented!()
    }
    async fn list_devices(&self) -> Result<Vec<DeviceInfo>, RelayError> {
        Ok(self.devices.clone())
    }
    async fn revoke_device(
        &self,
        _: &str,
        _remote_wipe: bool,
        epoch: i32,
        wrapped_keys: HashMap<String, Vec<u8>>,
    ) -> Result<i32, RelayError> {
        let mut artifacts = self.artifacts.lock().unwrap();
        for (device_id, wrapped) in wrapped_keys {
            artifacts.insert((epoch, device_id), wrapped);
        }
        Ok(epoch)
    }
    async fn post_rekey_artifacts(
        &self,
        epoch: i32,
        keys: HashMap<String, Vec<u8>>,
    ) -> Result<i32, RelayError> {
        let mut artifacts = self.artifacts.lock().unwrap();
        for (device_id, wrapped) in keys {
            artifacts.insert((epoch, device_id), wrapped);
        }
        Ok(epoch)
    }
    async fn get_rekey_artifact(
        &self,
        epoch: i32,
        device_id: &str,
    ) -> Result<Option<Vec<u8>>, RelayError> {
        let artifacts = self.artifacts.lock().unwrap();
        Ok(artifacts.get(&(epoch, device_id.to_string())).cloned())
    }
    async fn deregister(&self) -> Result<(), RelayError> {
        Ok(())
    }
    async fn delete_sync_group(&self) -> Result<(), RelayError> {
        unimplemented!()
    }
    async fn ack(&self, _: i64) -> Result<(), RelayError> {
        unimplemented!()
    }
    async fn connect_websocket(&self) -> Result<(), RelayError> {
        unimplemented!()
    }
    async fn disconnect_websocket(&self) -> Result<(), RelayError> {
        unimplemented!()
    }
    fn notifications(&self) -> Pin<Box<dyn Stream<Item = SyncNotification> + Send>> {
        unimplemented!()
    }
    async fn rotate_ml_dsa(
        &self,
        _: &str,
        _: &[u8],
        _: u32,
        _: &prism_sync_crypto::pq::continuity_proof::MlDsaContinuityProof,
        _: Option<&[u8]>,
    ) -> Result<RotateMlDsaResponse, RelayError> {
        unimplemented!()
    }
    async fn upload_media(&self, _: &str, _: &str, _: Vec<u8>) -> Result<(), RelayError> {
        unimplemented!()
    }
    async fn download_media(&self, _: &str) -> Result<Vec<u8>, RelayError> {
        unimplemented!()
    }
    async fn dispose(&self) -> Result<(), RelayError> {
        Ok(())
    }
    async fn get_signed_registry(&self) -> Result<Option<SignedRegistryResponse>, RelayError> {
        Ok(None)
    }
}

// ══════════════════════════════════════════════════════════════════════════
// E2E test
// ══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn epoch_rotation_full_cycle() {
    // ── Setup: two devices (A and B) plus a revoked device C ──

    let secret_a = DeviceSecret::generate();
    let secret_b = DeviceSecret::generate();
    let secret_c = DeviceSecret::generate();

    let xk_a = secret_a.x25519_keypair("device-a").unwrap();
    let xk_b = secret_b.x25519_keypair("device-b").unwrap();
    let xk_c = secret_c.x25519_keypair("device-c").unwrap();

    let devices = vec![
        DeviceInfo {
            device_id: "device-a".to_string(),
            epoch: 0,
            status: "active".to_string(),
            ed25519_public_key: vec![],
            x25519_public_key: xk_a.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: vec![],
            ml_kem_768_public_key: vec![],
            x_wing_public_key: vec![],
            ml_dsa_key_generation: 0,
            permission: None,
        },
        DeviceInfo {
            device_id: "device-b".to_string(),
            epoch: 0,
            status: "active".to_string(),
            ed25519_public_key: vec![],
            x25519_public_key: xk_b.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: vec![],
            ml_kem_768_public_key: vec![],
            x_wing_public_key: vec![],
            ml_dsa_key_generation: 0,
            permission: None,
        },
        DeviceInfo {
            device_id: "device-c".to_string(),
            epoch: 0,
            status: "revoked".to_string(),
            ed25519_public_key: vec![],
            x25519_public_key: xk_c.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: vec![],
            ml_kem_768_public_key: vec![],
            x_wing_public_key: vec![],
            ml_dsa_key_generation: 0,
            permission: None,
        },
    ];

    let relay = RekeyMockRelay::new(devices);

    // Both A and B have key hierarchies at epoch 0
    let mut kh_a = KeyHierarchy::new();
    kh_a.initialize("password", &[1u8; 16]).unwrap();

    let mut kh_b = KeyHierarchy::new();
    kh_b.initialize("password", &[2u8; 16]).unwrap();

    // ── Step 1: Device A generates a new epoch key and performs atomic revoke ──
    let (epoch_key_a, wrapped_keys) =
        EpochManager::prepare_wrapped_keys(&relay, &xk_a, Some("device-c"))
            .await
            .expect("prepare_wrapped_keys should succeed");
    relay
        .revoke_device("device-c", false, 1, wrapped_keys)
        .await
        .expect("atomic revoke should succeed");
    kh_a.store_epoch_key(1, zeroize::Zeroizing::new(epoch_key_a.to_vec()));

    // Verify A has the new epoch key stored locally
    assert!(kh_a.has_epoch_key(1), "Device A should have epoch 1 key");
    let stored_a = kh_a.epoch_key(1).unwrap();
    assert_eq!(stored_a, &*epoch_key_a);

    // Verify the relay has artifacts for A and B but not C
    {
        let artifacts = relay.artifacts.lock().unwrap();
        assert!(
            artifacts.contains_key(&(1, "device-a".to_string())),
            "relay should have wrapped key for device-a"
        );
        assert!(
            artifacts.contains_key(&(1, "device-b".to_string())),
            "relay should have wrapped key for device-b"
        );
        assert!(
            !artifacts.contains_key(&(1, "device-c".to_string())),
            "relay should NOT have wrapped key for revoked device-c"
        );
    }

    // ── Step 2: Device B recovers the epoch key via handle_rotation ──
    EpochManager::handle_rotation(
        &relay,
        &mut kh_b,
        1,
        "device-b",
        &xk_b,
        &xk_a.public_key_bytes(),
    )
    .await
    .expect("handle_rotation should succeed");

    assert!(kh_b.has_epoch_key(1), "Device B should have epoch 1 key");
    let stored_b = kh_b.epoch_key(1).unwrap();

    // ── Step 3: Verify both have the SAME epoch key ──
    assert_eq!(
        stored_a, stored_b,
        "Device A and B should have the same epoch 1 key"
    );

    // ── Step 4: Verify encrypt/decrypt interop ──
    let plaintext = b"hello from device A at epoch 1";
    let ciphertext = aead::xchacha_encrypt(stored_a, plaintext)
        .expect("encryption with epoch key should succeed");

    let decrypted = aead::xchacha_decrypt(stored_b, &ciphertext)
        .expect("decryption with epoch key should succeed");

    assert_eq!(
        decrypted, plaintext,
        "Device B should decrypt what Device A encrypted"
    );

    // Also verify reverse direction
    let plaintext_b = b"reply from device B";
    let ciphertext_b =
        aead::xchacha_encrypt(stored_b, plaintext_b).expect("encryption by B should succeed");

    let decrypted_b =
        aead::xchacha_decrypt(stored_a, &ciphertext_b).expect("decryption by A should succeed");

    assert_eq!(
        decrypted_b, plaintext_b,
        "Device A should decrypt what Device B encrypted"
    );
}

/// Verify that a revoked device cannot recover the new epoch key (no artifact).
#[tokio::test]
async fn revoked_device_cannot_recover_epoch_key() {
    let secret_a = DeviceSecret::generate();
    let secret_c = DeviceSecret::generate();

    let xk_a = secret_a.x25519_keypair("device-a").unwrap();
    let xk_c = secret_c.x25519_keypair("device-c").unwrap();

    let devices = vec![
        DeviceInfo {
            device_id: "device-a".to_string(),
            epoch: 0,
            status: "active".to_string(),
            ed25519_public_key: vec![],
            x25519_public_key: xk_a.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: vec![],
            ml_kem_768_public_key: vec![],
            x_wing_public_key: vec![],
            ml_dsa_key_generation: 0,
            permission: None,
        },
        DeviceInfo {
            device_id: "device-c".to_string(),
            epoch: 0,
            status: "active".to_string(), // still listed as active in device list
            ed25519_public_key: vec![],
            x25519_public_key: xk_c.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: vec![],
            ml_kem_768_public_key: vec![],
            x_wing_public_key: vec![],
            ml_dsa_key_generation: 0,
            permission: None,
        },
    ];

    let relay = RekeyMockRelay::new(devices);

    let mut kh_a = KeyHierarchy::new();
    kh_a.initialize("password", &[1u8; 16]).unwrap();

    let (_epoch_key, wrapped_keys) =
        EpochManager::prepare_wrapped_keys(&relay, &xk_a, Some("device-c"))
            .await
            .expect("prepare_wrapped_keys should succeed");
    relay
        .revoke_device("device-c", false, 1, wrapped_keys)
        .await
        .expect("atomic revoke should succeed");

    // Device C tries to recover -- no artifact for it
    let mut kh_c = KeyHierarchy::new();
    kh_c.initialize("password", &[3u8; 16]).unwrap();

    let result = EpochManager::handle_rotation(
        &relay,
        &mut kh_c,
        1,
        "device-c",
        &xk_c,
        &xk_a.public_key_bytes(),
    )
    .await;

    assert!(
        result.is_err(),
        "revoked device should fail to recover epoch key"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("no rekey artifact"),
        "error should mention missing artifact, got: {msg}"
    );
}
