//! Epoch rotation end-to-end test (C12).
//!
//! Verifies the full cycle: Device A generates a new epoch key, posts it via
//! atomic revoke using X-Wing KEM, Device B recovers it via `handle_rotation`,
//! and both can encrypt/decrypt with the same epoch key.

use std::collections::{BTreeMap, HashMap};
use std::pin::Pin;
use std::sync::Mutex;

use async_trait::async_trait;
use futures_util::Stream;
use prism_sync_core::epoch::EpochManager;
use prism_sync_core::pairing::{compute_epoch_key_hash, SignedRegistrySnapshot};
use prism_sync_core::relay::traits::*;
use prism_sync_core::storage::DeviceRecord;
use prism_sync_crypto::{aead, DeviceSecret, DeviceXWingKey, KeyHierarchy};
use zeroize::Zeroizing;

/// Mirror a relay `DeviceInfo` list into pinned `DeviceRecord`s so the wrap
/// intersection in `prepare_wrapped_keys` is satisfied when the pinned registry
/// agrees with the relay.
fn pinned_from_devices(devices: &[DeviceInfo]) -> Vec<DeviceRecord> {
    devices
        .iter()
        .map(|d| DeviceRecord {
            sync_id: "test-sync".to_string(),
            device_id: d.device_id.clone(),
            ed25519_public_key: d.ed25519_public_key.clone(),
            x25519_public_key: d.x25519_public_key.clone(),
            ml_dsa_65_public_key: d.ml_dsa_65_public_key.clone(),
            ml_kem_768_public_key: d.ml_kem_768_public_key.clone(),
            x_wing_public_key: d.x_wing_public_key.clone(),
            status: d.status.clone(),
            registered_at: chrono::Utc::now(),
            revoked_at: None,
            ml_dsa_key_generation: d.ml_dsa_key_generation,
        })
        .collect()
}

/// Build a signed-registry snapshot committing a single epoch's key hash.
/// `EpochManager::handle_rotation` only checks the hash, not the signature, so
/// tests construct this directly with no signing key required.
fn single_epoch_snapshot(epoch: u32, key: &[u8; 32]) -> SignedRegistrySnapshot {
    SignedRegistrySnapshot::new_with_epoch_binding(
        vec![],
        0,
        epoch,
        BTreeMap::from([(epoch, compute_epoch_key_hash(key))]),
    )
}

/// Wrap a CHOSEN epoch key into a valid v2 rekey artifact for `receiver_xwing`,
/// replicating the encapsulate → derive_subkey → xchacha_encrypt_aead steps of
/// `EpochManager::prepare_wrapped_keys_for_devices`. Lets a test fabricate an
/// honest-looking artifact that wraps an attacker-chosen key.
fn build_v2_artifact(
    receiver_xwing: &DeviceXWingKey,
    epoch_key: &[u8],
    epoch: u32,
    device_id: &str,
) -> Vec<u8> {
    use prism_sync_crypto::pq::hybrid_kem::XWingKem;

    let ek_bytes = receiver_xwing.encapsulation_key_bytes();
    let ek = XWingKem::encapsulation_key_from_bytes(&ek_bytes).unwrap();
    let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
    let (ciphertext, shared_secret_raw) = XWingKem::encapsulate(&ek, &mut rng);
    let shared_secret = Zeroizing::new(shared_secret_raw);

    let mut salt = Vec::with_capacity(4 + device_id.len());
    salt.extend_from_slice(&epoch.to_le_bytes());
    salt.extend_from_slice(device_id.as_bytes());
    let wrap_key =
        prism_sync_crypto::kdf::derive_subkey(&shared_secret, &salt, b"prism_epoch_rekey_v2")
            .unwrap();
    // AAD must match epoch::build_rekey_artifact_aad (pub(crate), replicated here).
    let aad = format!("prism_epoch_rekey_v2|{epoch}|{device_id}").into_bytes();
    let encrypted_epoch_key =
        prism_sync_crypto::aead::xchacha_encrypt_aead(&wrap_key, epoch_key, &aad).unwrap();

    let mut artifact = Vec::with_capacity(1 + ciphertext.len() + encrypted_epoch_key.len());
    artifact.push(0x02);
    artifact.extend_from_slice(&ciphertext);
    artifact.extend_from_slice(&encrypted_epoch_key);
    artifact
}

// ── MockRelay that stores and retrieves rekey artifacts ──

struct RekeyMockRelay {
    devices: Vec<DeviceInfo>,
    /// epoch -> device_id -> wrapped key
    artifacts: Mutex<HashMap<(i32, String), Vec<u8>>>,
}

impl RekeyMockRelay {
    fn new(devices: Vec<DeviceInfo>) -> Self {
        Self { devices, artifacts: Mutex::new(HashMap::new()) }
    }

    /// Directly seed a rekey artifact for an (epoch, device) — used to serve a
    /// poisoned or honest artifact to `handle_rotation`.
    fn insert_artifact(&self, epoch: i32, device_id: &str, artifact: Vec<u8>) {
        self.artifacts.lock().unwrap().insert((epoch, device_id.to_string()), artifact);
    }
}

#[async_trait]
impl SyncTransport for RekeyMockRelay {
    async fn pull_changes(&self, _: i64) -> Result<PullResponse, RelayError> {
        unimplemented!()
    }
    async fn push_changes(&self, _: OutgoingBatch) -> Result<i64, RelayError> {
        unimplemented!()
    }
    async fn ack(&self, _: i64) -> Result<(), RelayError> {
        unimplemented!()
    }
}

#[async_trait]
impl DeviceRegistry for RekeyMockRelay {
    async fn get_registration_nonce(&self) -> Result<RegistrationNonceResponse, RelayError> {
        Ok(RegistrationNonceResponse {
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
    async fn deregister(&self) -> Result<(), RelayError> {
        Ok(())
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
    async fn get_signed_registry(&self) -> Result<Option<SignedRegistryResponse>, RelayError> {
        Ok(None)
    }
    async fn put_signed_registry(&self, _: &[u8]) -> Result<i64, RelayError> {
        Ok(0)
    }
}

#[async_trait]
impl EpochManagement for RekeyMockRelay {
    async fn post_rekey_artifacts(
        &self,
        epoch: i32,
        keys: HashMap<String, Vec<u8>>,
        _signed_registry_snapshot: Option<&[u8]>,
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
}

#[async_trait]
impl SnapshotExchange for RekeyMockRelay {
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
        _: Option<prism_sync_core::relay::SnapshotUploadProgress>,
    ) -> Result<(), RelayError> {
        unimplemented!()
    }
    async fn delete_snapshot(&self) -> Result<(), RelayError> {
        unimplemented!()
    }
}

#[async_trait]
impl MediaRelay for RekeyMockRelay {
    async fn upload_media(
        &self,
        _: &str,
        _: &str,
        _: Vec<u8>,
        _: Option<u64>,
    ) -> Result<MediaUploadOutcome, RelayError> {
        unimplemented!()
    }
    async fn download_media(&self, _: &str) -> Result<Vec<u8>, RelayError> {
        unimplemented!()
    }
    async fn batch_exists(&self, _: &[String]) -> Result<Vec<String>, RelayError> {
        unimplemented!()
    }
}

#[async_trait]
impl SyncRelay for RekeyMockRelay {
    async fn delete_sync_group(&self) -> Result<(), RelayError> {
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
    async fn dispose(&self) -> Result<(), RelayError> {
        Ok(())
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

    // Derive X-Wing keypairs for each device
    let xwing_a = secret_a.xwing_keypair("device-a").unwrap();
    let xwing_b = secret_b.xwing_keypair("device-b").unwrap();
    let xwing_c = secret_c.xwing_keypair("device-c").unwrap();

    let devices = vec![
        DeviceInfo {
            device_id: "device-a".to_string(),
            epoch: 0,
            status: "active".to_string(),
            ed25519_public_key: vec![],
            x25519_public_key: vec![],
            ml_dsa_65_public_key: vec![],
            ml_kem_768_public_key: vec![],
            x_wing_public_key: xwing_a.encapsulation_key_bytes(),
            ml_dsa_key_generation: 0,
            permission: None,
        },
        DeviceInfo {
            device_id: "device-b".to_string(),
            epoch: 0,
            status: "active".to_string(),
            ed25519_public_key: vec![],
            x25519_public_key: vec![],
            ml_dsa_65_public_key: vec![],
            ml_kem_768_public_key: vec![],
            x_wing_public_key: xwing_b.encapsulation_key_bytes(),
            ml_dsa_key_generation: 0,
            permission: None,
        },
        DeviceInfo {
            device_id: "device-c".to_string(),
            epoch: 0,
            status: "revoked".to_string(),
            ed25519_public_key: vec![],
            x25519_public_key: vec![],
            ml_dsa_65_public_key: vec![],
            ml_kem_768_public_key: vec![],
            x_wing_public_key: xwing_c.encapsulation_key_bytes(),
            ml_dsa_key_generation: 0,
            permission: None,
        },
    ];

    let pinned = pinned_from_devices(&devices);
    let relay = RekeyMockRelay::new(devices);

    // Both A and B have key hierarchies at epoch 0
    let mut kh_a = KeyHierarchy::new();
    kh_a.initialize("password", &[1u8; 16]).unwrap();

    let mut kh_b = KeyHierarchy::new();
    kh_b.initialize("password", &[2u8; 16]).unwrap();

    // ── Step 1: Device A generates a new epoch key and performs atomic revoke ──
    // Device C is revoked (excluded) — X-Wing wraps for A and B only.
    let (epoch_key_a, wrapped_keys) =
        EpochManager::prepare_wrapped_keys(&relay, 1, Some("device-c"), &pinned)
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
    // With X-Wing KEM, B only needs its own DK — no sender identity needed.
    // The signed registry commits the hash of the real epoch-1 key.
    let epoch_key_a_arr: [u8; 32] = epoch_key_a.as_slice().try_into().unwrap();
    let signed_registry = single_epoch_snapshot(1, &epoch_key_a_arr);
    EpochManager::handle_rotation(&relay, &mut kh_b, 1, "device-b", &xwing_b, &signed_registry)
        .await
        .expect("handle_rotation should succeed");

    assert!(kh_b.has_epoch_key(1), "Device B should have epoch 1 key");
    let stored_b = kh_b.epoch_key(1).unwrap();

    // ── Step 3: Verify both have the SAME epoch key ──
    assert_eq!(stored_a, stored_b, "Device A and B should have the same epoch 1 key");

    // ── Step 4: Verify encrypt/decrypt interop ──
    let plaintext = b"hello from device A at epoch 1";
    let ciphertext = aead::xchacha_encrypt(stored_a, plaintext)
        .expect("encryption with epoch key should succeed");

    let decrypted = aead::xchacha_decrypt(stored_b, &ciphertext)
        .expect("decryption with epoch key should succeed");

    assert_eq!(decrypted, plaintext, "Device B should decrypt what Device A encrypted");

    // Also verify reverse direction
    let plaintext_b = b"reply from device B";
    let ciphertext_b =
        aead::xchacha_encrypt(stored_b, plaintext_b).expect("encryption by B should succeed");

    let decrypted_b =
        aead::xchacha_decrypt(stored_a, &ciphertext_b).expect("decryption by A should succeed");

    assert_eq!(decrypted_b, plaintext_b, "Device A should decrypt what Device B encrypted");
}

/// Verify that a revoked device cannot recover the new epoch key (no artifact).
#[tokio::test]
async fn revoked_device_cannot_recover_epoch_key() {
    let secret_a = DeviceSecret::generate();
    let secret_c = DeviceSecret::generate();

    let xwing_a = secret_a.xwing_keypair("device-a").unwrap();
    let xwing_c = secret_c.xwing_keypair("device-c").unwrap();

    let devices = vec![
        DeviceInfo {
            device_id: "device-a".to_string(),
            epoch: 0,
            status: "active".to_string(),
            ed25519_public_key: vec![],
            x25519_public_key: vec![],
            ml_dsa_65_public_key: vec![],
            ml_kem_768_public_key: vec![],
            x_wing_public_key: xwing_a.encapsulation_key_bytes(),
            ml_dsa_key_generation: 0,
            permission: None,
        },
        DeviceInfo {
            device_id: "device-c".to_string(),
            epoch: 0,
            // listed as active in device list but will be excluded from wrapped keys
            status: "active".to_string(),
            ed25519_public_key: vec![],
            x25519_public_key: vec![],
            ml_dsa_65_public_key: vec![],
            ml_kem_768_public_key: vec![],
            x_wing_public_key: xwing_c.encapsulation_key_bytes(),
            ml_dsa_key_generation: 0,
            permission: None,
        },
    ];

    let pinned = pinned_from_devices(&devices);
    let relay = RekeyMockRelay::new(devices);

    let mut kh_a = KeyHierarchy::new();
    kh_a.initialize("password", &[1u8; 16]).unwrap();

    // Device A excludes device-c from wrapped keys
    let (_epoch_key, wrapped_keys) =
        EpochManager::prepare_wrapped_keys(&relay, 1, Some("device-c"), &pinned)
            .await
            .expect("prepare_wrapped_keys should succeed");
    relay
        .revoke_device("device-c", false, 1, wrapped_keys)
        .await
        .expect("atomic revoke should succeed");

    // Device C tries to recover -- no artifact was posted for it
    let mut kh_c = KeyHierarchy::new();
    kh_c.initialize("password", &[3u8; 16]).unwrap();

    // Any snapshot suffices — the missing-artifact error fires before the hash check.
    let signed_registry = single_epoch_snapshot(1, &[0u8; 32]);
    let result =
        EpochManager::handle_rotation(&relay, &mut kh_c, 1, "device-c", &xwing_c, &signed_registry)
            .await;

    assert!(result.is_err(), "revoked device should fail to recover epoch key");
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("no rekey artifact"), "error should mention missing artifact, got: {msg}");
}

/// A malicious relay must not be able to inject an attacker-chosen epoch key via
/// the live rotation path. `handle_rotation` only installs a key that is
/// byte-for-byte bound to the signature-verified registry hash.
#[tokio::test]
async fn relay_injected_epoch_key_is_refused() {
    let victim_secret = DeviceSecret::generate();
    let victim_xwing = victim_secret.xwing_keypair("victim").unwrap();

    // The REAL epoch-1 key and the signed registry committing its hash.
    let real_key = [0x11u8; 32];
    let signed_registry = single_epoch_snapshot(1, &real_key);

    // ── ATTACK: relay serves an artifact wrapping an attacker-chosen key ──
    // The artifact is cryptographically valid (it decapsulates with the
    // victim's own DK and decrypts cleanly), but the key inside is NOT the one
    // the signed registry committed.
    let attacker_key = [0x41u8; 32];
    let poisoned_artifact = build_v2_artifact(&victim_xwing, &attacker_key, 1, "victim");

    let relay = RekeyMockRelay::new(vec![DeviceInfo {
        device_id: "victim".to_string(),
        epoch: 0,
        status: "active".to_string(),
        ed25519_public_key: vec![],
        x25519_public_key: vec![],
        ml_dsa_65_public_key: vec![],
        ml_kem_768_public_key: vec![],
        x_wing_public_key: victim_xwing.encapsulation_key_bytes(),
        ml_dsa_key_generation: 0,
        permission: None,
    }]);
    relay.insert_artifact(1, "victim", poisoned_artifact);

    let mut kh = KeyHierarchy::new();
    kh.initialize("password", &[1u8; 16]).unwrap();

    let result =
        EpochManager::handle_rotation(&relay, &mut kh, 1, "victim", &victim_xwing, &signed_registry)
            .await;

    assert!(result.is_err(), "relay-injected attacker key must be refused");
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("hash mismatch"), "error should be a hash mismatch, got: {msg}");
    assert!(
        !kh.has_epoch_key(1),
        "attacker key must NOT be installed into the key hierarchy"
    );

    // ── POSITIVE CONTROL: serving the REAL key installs cleanly ──
    let honest_artifact = build_v2_artifact(&victim_xwing, &real_key, 1, "victim");
    relay.insert_artifact(1, "victim", honest_artifact);

    EpochManager::handle_rotation(&relay, &mut kh, 1, "victim", &victim_xwing, &signed_registry)
        .await
        .expect("honest key bound to the signed registry hash should install");

    assert!(kh.has_epoch_key(1), "honest key must be installed");
    assert_eq!(kh.epoch_key(1).unwrap(), &real_key);
}
