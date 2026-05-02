use std::collections::BTreeMap;

use prism_sync_core::{
    pairing::{
        compute_epoch_key_hash, RegistrySnapshotEntry, SignedRegistrySnapshot,
        SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
    },
    storage::{DeviceRecord, RusqliteSyncStorage, SyncStorage},
    CoreError, DeviceRegistryManager,
};
use prism_sync_crypto::DeviceSecret;

const SYNC_ID: &str = "registry-authority-sync";

struct DeviceMaterial {
    secret: DeviceSecret,
    record: DeviceRecord,
}

fn make_device(device_id: &str) -> DeviceMaterial {
    let secret = DeviceSecret::generate();
    let ed25519 = secret.ed25519_keypair(device_id).unwrap();
    let x25519 = secret.x25519_keypair(device_id).unwrap();
    let ml_dsa = secret.ml_dsa_65_keypair(device_id).unwrap();
    let ml_kem = secret.ml_kem_768_keypair(device_id).unwrap();
    let xwing = secret.xwing_keypair(device_id).unwrap();

    DeviceMaterial {
        secret,
        record: DeviceRecord {
            sync_id: SYNC_ID.to_string(),
            device_id: device_id.to_string(),
            ed25519_public_key: ed25519.public_key_bytes().to_vec(),
            x25519_public_key: x25519.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: ml_dsa.public_key_bytes(),
            ml_kem_768_public_key: ml_kem.public_key_bytes(),
            x_wing_public_key: xwing.encapsulation_key_bytes(),
            status: "active".to_string(),
            registered_at: chrono::Utc::now(),
            revoked_at: None,
            ml_dsa_key_generation: 0,
        },
    }
}

fn registry_entry(device: &DeviceRecord) -> RegistrySnapshotEntry {
    RegistrySnapshotEntry {
        sync_id: device.sync_id.clone(),
        device_id: device.device_id.clone(),
        ed25519_public_key: device.ed25519_public_key.clone(),
        x25519_public_key: device.x25519_public_key.clone(),
        ml_dsa_65_public_key: device.ml_dsa_65_public_key.clone(),
        ml_kem_768_public_key: device.ml_kem_768_public_key.clone(),
        x_wing_public_key: device.x_wing_public_key.clone(),
        status: device.status.clone(),
        ml_dsa_key_generation: device.ml_dsa_key_generation,
    }
}

fn epoch_hashes() -> BTreeMap<u32, [u8; 32]> {
    BTreeMap::from([(0, compute_epoch_key_hash(&[0x42; 32]))])
}

fn signed_registry_blob(entries: Vec<RegistrySnapshotEntry>, signer: &DeviceMaterial) -> Vec<u8> {
    let signing_key = signer.secret.ed25519_keypair(&signer.record.device_id).unwrap();
    let pq_signing_key = signer.secret.ml_dsa_65_keypair(&signer.record.device_id).unwrap();
    let snapshot = SignedRegistrySnapshot::new_with_epoch_binding(
        entries,
        SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
        0,
        epoch_hashes(),
    );
    snapshot.sign_hybrid(&signing_key, &pq_signing_key)
}

fn pin(storage: &RusqliteSyncStorage, device: &DeviceMaterial) {
    DeviceRegistryManager::pin_device(storage, SYNC_ID, &device.record).unwrap();
}

fn assert_keys_unchanged(stored: &DeviceRecord, expected: &DeviceRecord) {
    assert_eq!(stored.ed25519_public_key, expected.ed25519_public_key);
    assert_eq!(stored.x25519_public_key, expected.x25519_public_key);
    assert_eq!(stored.ml_dsa_65_public_key, expected.ml_dsa_65_public_key);
    assert_eq!(stored.ml_kem_768_public_key, expected.ml_kem_768_public_key);
    assert_eq!(stored.x_wing_public_key, expected.x_wing_public_key);
    assert_eq!(stored.ml_dsa_key_generation, expected.ml_dsa_key_generation);
}

#[test]
fn relay_device_merge_rejects_unknown_device_without_verified_registry() {
    let storage = RusqliteSyncStorage::in_memory().unwrap();
    let approver = make_device("device-approver");
    let injected = make_device("device-injected");
    pin(&storage, &approver);

    let result = DeviceRegistryManager::merge_relay_device(&storage, SYNC_ID, &injected.record);

    assert!(result.is_err(), "unknown relay device must not be TOFU-pinned");
    let error = result.unwrap_err().to_string();
    assert!(
        error.contains("unknown device") && error.contains("verified registry"),
        "unexpected error: {error}"
    );
    assert!(storage.get_device_record(SYNC_ID, &injected.record.device_id).unwrap().is_none());
}

#[test]
fn signed_registry_import_authorizes_unknown_device_from_trusted_signer() {
    let storage = RusqliteSyncStorage::in_memory().unwrap();
    let approver = make_device("device-approver");
    let joiner = make_device("device-joiner");
    pin(&storage, &approver);

    let blob = signed_registry_blob(
        vec![registry_entry(&approver.record), registry_entry(&joiner.record)],
        &approver,
    );

    let imported_version =
        DeviceRegistryManager::verify_and_import_signed_registry(&storage, SYNC_ID, &blob, None)
            .unwrap();
    assert_eq!(imported_version, SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING);

    let stored = storage
        .get_device_record(SYNC_ID, &joiner.record.device_id)
        .unwrap()
        .expect("trusted signed registry should import joiner");
    assert_keys_unchanged(&stored, &joiner.record);
}

#[test]
fn signed_registry_from_untrusted_signer_is_rejected() {
    let storage = RusqliteSyncStorage::in_memory().unwrap();
    let approver = make_device("device-approver");
    let attacker = make_device("device-attacker");
    let injected = make_device("device-injected");
    pin(&storage, &approver);

    let blob = signed_registry_blob(
        vec![
            registry_entry(&approver.record),
            registry_entry(&attacker.record),
            registry_entry(&injected.record),
        ],
        &attacker,
    );

    let result =
        DeviceRegistryManager::verify_and_import_signed_registry(&storage, SYNC_ID, &blob, None);

    assert!(result.is_err(), "registry signed by non-local device should be rejected");
    let error = result.unwrap_err().to_string();
    assert!(
        error.contains("could not be verified against any known device"),
        "unexpected error: {error}"
    );
    assert!(storage.get_device_record(SYNC_ID, &injected.record.device_id).unwrap().is_none());
}

#[test]
fn relay_key_substitution_cannot_replace_any_hybrid_identity_component() {
    let storage = RusqliteSyncStorage::in_memory().unwrap();
    let original = make_device("device-target");
    let replacement = make_device("device-target");
    pin(&storage, &original);

    let mut ed25519_swap = original.record.clone();
    ed25519_swap.ed25519_public_key = replacement.record.ed25519_public_key.clone();

    let mut x25519_swap = original.record.clone();
    x25519_swap.x25519_public_key = replacement.record.x25519_public_key.clone();

    let mut ml_kem_swap = original.record.clone();
    ml_kem_swap.ml_kem_768_public_key = replacement.record.ml_kem_768_public_key.clone();

    let mut xwing_swap = original.record.clone();
    xwing_swap.x_wing_public_key = replacement.record.x_wing_public_key.clone();

    let mut ml_dsa_same_generation_swap = original.record.clone();
    ml_dsa_same_generation_swap.ml_dsa_65_public_key =
        replacement.record.ml_dsa_65_public_key.clone();

    for (label, candidate) in [
        ("ed25519", ed25519_swap),
        ("x25519", x25519_swap),
        ("ml-kem-768", ml_kem_swap),
        ("x-wing", xwing_swap),
        ("ml-dsa-same-generation", ml_dsa_same_generation_swap),
    ] {
        let result = DeviceRegistryManager::merge_relay_device(&storage, SYNC_ID, &candidate);
        assert!(
            matches!(result, Err(CoreError::DeviceKeyChanged { ref device_id }) if device_id == "device-target"),
            "{label} substitution should be rejected, got {result:?}"
        );

        let stored = storage
            .get_device_record(SYNC_ID, &original.record.device_id)
            .unwrap()
            .expect("original device should remain pinned");
        assert_keys_unchanged(&stored, &original.record);
    }

    let mut ml_dsa_rotation_injection = original.record.clone();
    ml_dsa_rotation_injection.ml_dsa_65_public_key =
        replacement.record.ml_dsa_65_public_key.clone();
    ml_dsa_rotation_injection.ml_dsa_key_generation = original.record.ml_dsa_key_generation + 1;

    DeviceRegistryManager::merge_relay_device(&storage, SYNC_ID, &ml_dsa_rotation_injection)
        .expect("unverified ML-DSA rotation is skipped without accepting substituted key");
    let stored = storage
        .get_device_record(SYNC_ID, &original.record.device_id)
        .unwrap()
        .expect("original device should remain pinned");
    assert_keys_unchanged(&stored, &original.record);
}
