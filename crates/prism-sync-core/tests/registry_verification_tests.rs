//! Integration tests for the signed registry fetch/import/verification pipeline.
//!
//! These tests exercise:
//! - End-to-end verified import through the SyncEngine
//! - Unverified ML-DSA rotation rejection in `merge_relay_device`
//! - Generation preservation through verified import
//! - Tampered artifact rejection
//! - Fallback to `list_devices` when no artifact is available

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use prism_sync_core::device_registry::DeviceRegistryManager;
use prism_sync_core::engine::{SyncConfig, SyncEngine};
use prism_sync_core::pairing::{
    compute_epoch_key_hash, RegistrySnapshotEntry, SignedRegistrySnapshot,
};
use prism_sync_core::relay::traits::SignedRegistryResponse;
use prism_sync_core::relay::{DeviceInfo, MockRelay, SignedBatchEnvelope};
use prism_sync_core::schema::SyncValue;
use prism_sync_core::storage::{DeviceRecord, RusqliteSyncStorage, SyncStorage};
use prism_sync_core::syncable_entity::SyncableEntity;
use prism_sync_core::{batch_signature, sync_aad, CrdtChange, Hlc};
use prism_sync_crypto::DeviceSecret;

use common::*;

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Create a signed + encrypted batch envelope from CrdtChange ops.
fn make_encrypted_batch(
    ops: &[CrdtChange],
    key_hierarchy: &prism_sync_crypto::KeyHierarchy,
    signing_key: &ed25519_dalek::SigningKey,
    ml_dsa_signing_key: &prism_sync_crypto::DevicePqSigningKey,
    batch_id: &str,
    sender_device_id: &str,
) -> SignedBatchEnvelope {
    let plaintext = CrdtChange::encode_batch(ops).unwrap();
    let payload_hash = batch_signature::compute_payload_hash(&plaintext);
    let epoch_key = key_hierarchy.epoch_key(0).unwrap();
    let aad = sync_aad::build_sync_aad(SYNC_ID, sender_device_id, 0, batch_id, "ops");
    let (ciphertext, nonce) =
        prism_sync_crypto::aead::xchacha_encrypt_for_sync(epoch_key, &plaintext, &aad).unwrap();

    batch_signature::sign_batch(
        signing_key,
        ml_dsa_signing_key,
        SYNC_ID,
        0,
        batch_id,
        "ops",
        sender_device_id,
        0,
        &payload_hash,
        nonce,
        ciphertext,
    )
    .unwrap()
}

/// Like [`make_encrypted_batch`] but signs the envelope at an explicit ML-DSA
/// generation (the rotation tests need batches signed under gen 0 and gen 1
/// of the same device).
#[allow(clippy::too_many_arguments)]
fn make_encrypted_batch_at_generation(
    ops: &[CrdtChange],
    key_hierarchy: &prism_sync_crypto::KeyHierarchy,
    signing_key: &ed25519_dalek::SigningKey,
    ml_dsa_signing_key: &prism_sync_crypto::DevicePqSigningKey,
    batch_id: &str,
    sender_device_id: &str,
    generation: u32,
) -> SignedBatchEnvelope {
    let plaintext = CrdtChange::encode_batch(ops).unwrap();
    let payload_hash = batch_signature::compute_payload_hash(&plaintext);
    let epoch_key = key_hierarchy.epoch_key(0).unwrap();
    let aad = sync_aad::build_sync_aad(SYNC_ID, sender_device_id, 0, batch_id, "ops");
    let (ciphertext, nonce) =
        prism_sync_crypto::aead::xchacha_encrypt_for_sync(epoch_key, &plaintext, &aad).unwrap();

    batch_signature::sign_batch(
        signing_key,
        ml_dsa_signing_key,
        SYNC_ID,
        0,
        batch_id,
        "ops",
        sender_device_id,
        generation,
        &payload_hash,
        nonce,
        ciphertext,
    )
    .unwrap()
}

/// Build a signed registry snapshot artifact blob using hybrid signing.
///
/// Returns the signed artifact blob suitable for `set_signed_registry`.
fn build_signed_registry_blob(
    entries: Vec<RegistrySnapshotEntry>,
    signer_device_secret: &DeviceSecret,
    signer_device_id: &str,
) -> Vec<u8> {
    build_signed_registry_blob_with_version(entries, signer_device_secret, signer_device_id, 1)
}

fn build_signed_registry_blob_with_version(
    entries: Vec<RegistrySnapshotEntry>,
    signer_device_secret: &DeviceSecret,
    signer_device_id: &str,
    registry_version: i64,
) -> Vec<u8> {
    let signing_key = signer_device_secret.ed25519_keypair(signer_device_id).unwrap();
    let pq_signing_key = signer_device_secret.ml_dsa_65_keypair(signer_device_id).unwrap();
    let snapshot = SignedRegistrySnapshot::new_with_epoch_binding(
        entries,
        registry_version,
        0,
        test_epoch_key_hashes(),
    );
    snapshot.sign_hybrid(&signing_key, &pq_signing_key)
}

fn test_epoch_key_hashes() -> BTreeMap<u32, [u8; 32]> {
    let mut hashes = BTreeMap::new();
    hashes.insert(0, compute_epoch_key_hash(&[0x42; 32]));
    hashes
}

/// Register a device in storage only (not the relay). Useful for setting up
/// the verifier device's record before import.
fn register_device_in_storage(
    storage: &RusqliteSyncStorage,
    device_id: &str,
    ed25519_pk: &[u8],
    x25519_pk: &[u8],
    ml_dsa_pk: &[u8],
    ml_kem_pk: &[u8],
    ml_dsa_key_generation: u32,
) {
    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_device_record(&DeviceRecord {
        sync_id: SYNC_ID.to_string(),
        device_id: device_id.to_string(),
        ed25519_public_key: ed25519_pk.to_vec(),
        x25519_public_key: x25519_pk.to_vec(),
        ml_dsa_65_public_key: ml_dsa_pk.to_vec(),
        ml_kem_768_public_key: ml_kem_pk.to_vec(),
        x_wing_public_key: vec![],
        status: "active".to_string(),
        registered_at: chrono::Utc::now(),
        revoked_at: None,
        ml_dsa_key_generation,
    })
    .unwrap();
    tx.commit().unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 1: Verified import happy path
//
// Build a signed registry artifact using real crypto, set it on MockRelay,
// create a SyncEngine, and verify that resolve_sender_public_key
// successfully resolves an unknown sender via the verified registry path.
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn registry_verification_verified_import_happy_path() {
    let key_hierarchy = init_key_hierarchy();

    // --- Device A: the known/approver device ---
    let device_a_id = "device-aaa";
    let device_secret_a = DeviceSecret::generate();
    let ed25519_a = device_secret_a.ed25519_keypair(device_a_id).unwrap();
    let x25519_a = device_secret_a.x25519_keypair(device_a_id).unwrap();
    let ml_dsa_a = device_secret_a.ml_dsa_65_keypair(device_a_id).unwrap();
    let ml_kem_a = device_secret_a.ml_kem_768_keypair(device_a_id).unwrap();

    // --- Device B: the unknown sender ---
    let device_b_id = "device-bbb";
    let device_secret_b = DeviceSecret::generate();
    let ed25519_b = device_secret_b.ed25519_keypair(device_b_id).unwrap();
    let x25519_b = device_secret_b.x25519_keypair(device_b_id).unwrap();
    let ml_dsa_b = device_secret_b.ml_dsa_65_keypair(device_b_id).unwrap();
    let ml_kem_b = device_secret_b.ml_kem_768_keypair(device_b_id).unwrap();

    // Build registry snapshot entries for both devices
    let entries = vec![
        RegistrySnapshotEntry {
            sync_id: SYNC_ID.to_string(),
            device_id: device_a_id.to_string(),
            ed25519_public_key: ed25519_a.public_key_bytes().to_vec(),
            x25519_public_key: x25519_a.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: ml_dsa_a.public_key_bytes(),
            ml_kem_768_public_key: ml_kem_a.public_key_bytes(),
            x_wing_public_key: vec![],
            status: "active".to_string(),
            ml_dsa_key_generation: 0,
            remote_wipe: false,
        },
        RegistrySnapshotEntry {
            sync_id: SYNC_ID.to_string(),
            device_id: device_b_id.to_string(),
            ed25519_public_key: ed25519_b.public_key_bytes().to_vec(),
            x25519_public_key: x25519_b.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: ml_dsa_b.public_key_bytes(),
            ml_kem_768_public_key: ml_kem_b.public_key_bytes(),
            x_wing_public_key: vec![],
            status: "active".to_string(),
            ml_dsa_key_generation: 0,
            remote_wipe: false,
        },
    ];

    // Sign the snapshot with device A's keys
    let signed_blob = build_signed_registry_blob(entries, &device_secret_a, device_a_id);

    // --- Set up MockRelay ---
    let relay = Arc::new(MockRelay::new());
    relay.set_signed_registry(SignedRegistryResponse {
        registry_version: 1,
        artifact_blob: signed_blob,
        artifact_kind: "signed_registry_snapshot".to_string(),
    });

    // Add device B to relay's device list (as fallback), but we expect
    // the engine to resolve via the signed registry path first.
    relay.add_device(DeviceInfo {
        device_id: device_b_id.to_string(),
        epoch: 0,
        status: "active".to_string(),
        ed25519_public_key: ed25519_b.public_key_bytes().to_vec(),
        x25519_public_key: x25519_b.public_key_bytes().to_vec(),
        ml_dsa_65_public_key: ml_dsa_b.public_key_bytes(),
        ml_kem_768_public_key: ml_kem_b.public_key_bytes(),
        x_wing_public_key: vec![],
        permission: None,
        ml_dsa_key_generation: 0,
        needs_rekey: false,
    });

    // --- Set up storage for the local device (A) ---
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    setup_sync_metadata(&storage, device_a_id);

    // Register device A in storage (so it can verify the signed registry)
    register_device_in_storage(
        &storage,
        device_a_id,
        &ed25519_a.public_key_bytes(),
        &x25519_a.public_key_bytes(),
        &ml_dsa_a.public_key_bytes(),
        &ml_kem_a.public_key_bytes(),
        0,
    );

    // Device A is also in the relay device list
    relay.add_device(DeviceInfo {
        device_id: device_a_id.to_string(),
        epoch: 0,
        status: "active".to_string(),
        ed25519_public_key: ed25519_a.public_key_bytes().to_vec(),
        x25519_public_key: x25519_a.public_key_bytes().to_vec(),
        ml_dsa_65_public_key: ml_dsa_a.public_key_bytes(),
        ml_kem_768_public_key: ml_kem_a.public_key_bytes(),
        x_wing_public_key: vec![],
        permission: None,
        ml_dsa_key_generation: 0,
        needs_rekey: false,
    });

    // DO NOT register device B in local storage — it should be discovered
    // via the signed registry fetch during sync.

    // --- Inject a batch from device B ---
    let signing_key_b = ed25519_b.into_signing_key();
    let hlc = Hlc::now(device_b_id, None);
    let ops = vec![CrdtChange {
        op_id: format!("tasks:task-1:title:{}:{}", hlc, device_b_id),
        batch_id: Some("batch-b1".to_string()),
        entity_id: "task-1".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Hello from B\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: device_b_id.to_string(),
        epoch: 0,
        server_seq: None,
    }];

    let ml_dsa_key_b_for_signing = device_secret_b.ml_dsa_65_keypair(device_b_id).unwrap();
    let envelope = make_encrypted_batch(
        &ops,
        &key_hierarchy,
        &signing_key_b,
        &ml_dsa_key_b_for_signing,
        "batch-b1",
        device_b_id,
    );
    relay.inject_batch(envelope);

    // --- Create SyncEngine and sync ---
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    let signing_key_a = device_secret_a.ed25519_keypair(device_a_id).unwrap();

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_a.into_signing_key(), None, device_a_id, 0)
        .await
        .unwrap();

    assert!(
        result.error.is_none(),
        "sync should succeed via verified registry: {:?}",
        result.error
    );
    assert!(result.pulled > 0, "expected at least 1 batch pulled");
    assert!(result.merged > 0, "expected ops merged from device B");

    // Verify data arrived
    let title = entity.get_field("task-1", "title");
    assert_eq!(title, Some(SyncValue::String("Hello from B".to_string())));

    // Verify device B was imported into local storage
    let device_b_record = storage
        .get_device_record(SYNC_ID, device_b_id)
        .unwrap()
        .expect("device B should be in local storage after verified import");
    assert_eq!(device_b_record.status, "active");
}

#[tokio::test]
async fn registry_verification_same_version_artifact_repairs_missing_device_record() {
    let key_hierarchy = init_key_hierarchy();

    let device_a_id = "device-aaa";
    let device_secret_a = DeviceSecret::generate();
    let ed25519_a = device_secret_a.ed25519_keypair(device_a_id).unwrap();
    let x25519_a = device_secret_a.x25519_keypair(device_a_id).unwrap();
    let ml_dsa_a = device_secret_a.ml_dsa_65_keypair(device_a_id).unwrap();
    let ml_kem_a = device_secret_a.ml_kem_768_keypair(device_a_id).unwrap();

    let device_b_id = "device-bbb";
    let device_secret_b = DeviceSecret::generate();
    let ed25519_b = device_secret_b.ed25519_keypair(device_b_id).unwrap();
    let x25519_b = device_secret_b.x25519_keypair(device_b_id).unwrap();
    let ml_dsa_b = device_secret_b.ml_dsa_65_keypair(device_b_id).unwrap();
    let ml_kem_b = device_secret_b.ml_kem_768_keypair(device_b_id).unwrap();

    let entries = vec![
        RegistrySnapshotEntry {
            sync_id: SYNC_ID.to_string(),
            device_id: device_a_id.to_string(),
            ed25519_public_key: ed25519_a.public_key_bytes().to_vec(),
            x25519_public_key: x25519_a.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: ml_dsa_a.public_key_bytes(),
            ml_kem_768_public_key: ml_kem_a.public_key_bytes(),
            x_wing_public_key: vec![],
            status: "active".to_string(),
            ml_dsa_key_generation: 0,
            remote_wipe: false,
        },
        RegistrySnapshotEntry {
            sync_id: SYNC_ID.to_string(),
            device_id: device_b_id.to_string(),
            ed25519_public_key: ed25519_b.public_key_bytes().to_vec(),
            x25519_public_key: x25519_b.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: ml_dsa_b.public_key_bytes(),
            ml_kem_768_public_key: ml_kem_b.public_key_bytes(),
            x_wing_public_key: vec![],
            status: "active".to_string(),
            ml_dsa_key_generation: 0,
            remote_wipe: false,
        },
    ];

    let registry_version = 5;
    let signed_blob = build_signed_registry_blob_with_version(
        entries,
        &device_secret_a,
        device_a_id,
        registry_version,
    );

    let relay = Arc::new(MockRelay::new());
    relay.set_signed_registry(SignedRegistryResponse {
        registry_version,
        artifact_blob: signed_blob,
        artifact_kind: "signed_registry_snapshot".to_string(),
    });

    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    setup_sync_metadata(&storage, device_a_id);
    register_device_in_storage(
        &storage,
        device_a_id,
        &ed25519_a.public_key_bytes(),
        &x25519_a.public_key_bytes(),
        &ml_dsa_a.public_key_bytes(),
        &ml_kem_a.public_key_bytes(),
        0,
    );

    {
        let mut tx = storage.begin_tx().unwrap();
        tx.update_last_imported_registry_version(SYNC_ID, registry_version).unwrap();
        tx.commit().unwrap();
    }

    let signing_key_b = ed25519_b.into_signing_key();
    let hlc = Hlc::now(device_b_id, None);
    let ops = vec![CrdtChange {
        op_id: format!("tasks:task-1:title:{}:{}", hlc, device_b_id),
        batch_id: Some("batch-b1".to_string()),
        entity_id: "task-1".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Hello from B\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: device_b_id.to_string(),
        epoch: 0,
        server_seq: None,
    }];

    let envelope = make_encrypted_batch(
        &ops,
        &key_hierarchy,
        &signing_key_b,
        &ml_dsa_b,
        "batch-b1",
        device_b_id,
    );
    relay.inject_batch(envelope);

    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();
    let signing_key_a = device_secret_a.ed25519_keypair(device_a_id).unwrap();
    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_a.into_signing_key(), None, device_a_id, 0)
        .await
        .unwrap();

    assert!(
        result.error.is_none(),
        "sync should succeed via same-version repair: {:?}",
        result.error
    );
    assert!(result.pulled > 0, "expected the remote batch to be pulled");
    assert!(result.merged > 0, "same-version registry repair should allow B's ops to merge");
    assert_eq!(
        entity.get_field("task-1", "title"),
        Some(SyncValue::String("Hello from B".to_string()))
    );
    assert!(
        storage.get_device_record(SYNC_ID, device_b_id).unwrap().is_some(),
        "same-version registry artifact repaired the missing device record",
    );
}

#[test]
fn registry_verification_same_version_artifact_rejects_existing_key_change() {
    let device_a_id = "device-a-same-version-change";
    let device_secret_a = DeviceSecret::generate();
    let ed25519_a = device_secret_a.ed25519_keypair(device_a_id).unwrap();
    let x25519_a = device_secret_a.x25519_keypair(device_a_id).unwrap();
    let ml_dsa_a = device_secret_a.ml_dsa_65_keypair(device_a_id).unwrap();
    let ml_kem_a = device_secret_a.ml_kem_768_keypair(device_a_id).unwrap();

    let storage = RusqliteSyncStorage::in_memory().unwrap();
    setup_sync_metadata(&storage, device_a_id);
    register_device_in_storage(
        &storage,
        device_a_id,
        &ed25519_a.public_key_bytes(),
        &x25519_a.public_key_bytes(),
        &ml_dsa_a.public_key_bytes(),
        &ml_kem_a.public_key_bytes(),
        0,
    );

    let registry_version = 5;
    let entries = vec![RegistrySnapshotEntry {
        sync_id: SYNC_ID.to_string(),
        device_id: device_a_id.to_string(),
        ed25519_public_key: ed25519_a.public_key_bytes().to_vec(),
        x25519_public_key: vec![0x99; 32],
        ml_dsa_65_public_key: ml_dsa_a.public_key_bytes(),
        ml_kem_768_public_key: ml_kem_a.public_key_bytes(),
        x_wing_public_key: vec![],
        status: "active".to_string(),
        ml_dsa_key_generation: 0,
        remote_wipe: false,
    }];
    let signed_blob = build_signed_registry_blob_with_version(
        entries,
        &device_secret_a,
        device_a_id,
        registry_version,
    );

    let result = DeviceRegistryManager::verify_and_import_signed_registry(
        &storage,
        SYNC_ID,
        &signed_blob,
        Some(registry_version),
    );

    assert!(result.is_err(), "same-version registry artifacts must not mutate existing key pins");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("changes existing device records"), "unexpected error: {err}");

    let record = storage.get_device_record(SYNC_ID, device_a_id).unwrap().unwrap();
    assert_eq!(record.x25519_public_key, x25519_a.public_key_bytes().to_vec());
}

#[test]
fn registry_verification_same_version_artifact_rejects_existing_status_or_generation_change() {
    let device_a_id = "device-a-same-version-status";
    let device_secret_a = DeviceSecret::generate();
    let ed25519_a = device_secret_a.ed25519_keypair(device_a_id).unwrap();
    let x25519_a = device_secret_a.x25519_keypair(device_a_id).unwrap();
    let ml_dsa_a = device_secret_a.ml_dsa_65_keypair(device_a_id).unwrap();
    let ml_kem_a = device_secret_a.ml_kem_768_keypair(device_a_id).unwrap();

    let device_b_id = "device-b-same-version-status";
    let device_secret_b = DeviceSecret::generate();
    let ed25519_b = device_secret_b.ed25519_keypair(device_b_id).unwrap();
    let x25519_b = device_secret_b.x25519_keypair(device_b_id).unwrap();
    let ml_dsa_b = device_secret_b.ml_dsa_65_keypair(device_b_id).unwrap();
    let ml_kem_b = device_secret_b.ml_kem_768_keypair(device_b_id).unwrap();

    let storage = RusqliteSyncStorage::in_memory().unwrap();
    setup_sync_metadata(&storage, device_a_id);
    register_device_in_storage(
        &storage,
        device_a_id,
        &ed25519_a.public_key_bytes(),
        &x25519_a.public_key_bytes(),
        &ml_dsa_a.public_key_bytes(),
        &ml_kem_a.public_key_bytes(),
        0,
    );
    register_device_in_storage(
        &storage,
        device_b_id,
        &ed25519_b.public_key_bytes(),
        &x25519_b.public_key_bytes(),
        &ml_dsa_b.public_key_bytes(),
        &ml_kem_b.public_key_bytes(),
        0,
    );

    let registry_version = 5;
    let unchanged_signer = RegistrySnapshotEntry {
        sync_id: SYNC_ID.to_string(),
        device_id: device_a_id.to_string(),
        ed25519_public_key: ed25519_a.public_key_bytes().to_vec(),
        x25519_public_key: x25519_a.public_key_bytes().to_vec(),
        ml_dsa_65_public_key: ml_dsa_a.public_key_bytes(),
        ml_kem_768_public_key: ml_kem_a.public_key_bytes(),
        x_wing_public_key: vec![],
        status: "active".to_string(),
        ml_dsa_key_generation: 0,
        remote_wipe: false,
    };
    let changed_peer = RegistrySnapshotEntry {
        sync_id: SYNC_ID.to_string(),
        device_id: device_b_id.to_string(),
        ed25519_public_key: ed25519_b.public_key_bytes().to_vec(),
        x25519_public_key: x25519_b.public_key_bytes().to_vec(),
        ml_dsa_65_public_key: ml_dsa_b.public_key_bytes(),
        ml_kem_768_public_key: ml_kem_b.public_key_bytes(),
        x_wing_public_key: vec![],
        status: "revoked".to_string(),
        ml_dsa_key_generation: 1,
        remote_wipe: false,
    };
    let signed_blob = build_signed_registry_blob_with_version(
        vec![unchanged_signer, changed_peer],
        &device_secret_a,
        device_a_id,
        registry_version,
    );

    let result = DeviceRegistryManager::verify_and_import_signed_registry(
        &storage,
        SYNC_ID,
        &signed_blob,
        Some(registry_version),
    );

    assert!(
        result.is_err(),
        "same-version registry artifacts must only add missing rows, not mutate known status or generation"
    );
    let err = result.unwrap_err().to_string();
    assert!(err.contains("changes existing device records"), "unexpected error: {err}");

    let record = storage.get_device_record(SYNC_ID, device_b_id).unwrap().unwrap();
    assert_eq!(record.status, "active");
    assert_eq!(record.ml_dsa_key_generation, 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 2: Unverified ML-DSA rotation blocked in merge_relay_device
//
// Test that merge_relay_device rejects ML-DSA rotations from the relay
// device list (they must come through verified import or explicit accept).
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn registry_verification_unverified_merge_blocked() {
    let storage = RusqliteSyncStorage::in_memory().unwrap();

    // Pin a device with generation 0
    let original_ml_dsa_pk = vec![0xAA; 1952];
    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_device_record(&DeviceRecord {
        sync_id: SYNC_ID.to_string(),
        device_id: "dev-target".to_string(),
        ed25519_public_key: vec![1u8; 32],
        x25519_public_key: vec![2u8; 32],
        ml_dsa_65_public_key: original_ml_dsa_pk.clone(),
        ml_kem_768_public_key: vec![4u8; 1184],
        x_wing_public_key: vec![],
        status: "active".to_string(),
        registered_at: chrono::Utc::now(),
        revoked_at: None,
        ml_dsa_key_generation: 0,
    })
    .unwrap();
    tx.commit().unwrap();

    // Try to merge a record with a different ML-DSA key at generation 1
    let rotated_record = DeviceRecord {
        sync_id: SYNC_ID.to_string(),
        device_id: "dev-target".to_string(),
        ed25519_public_key: vec![1u8; 32],      // same
        x25519_public_key: vec![2u8; 32],       // same
        ml_dsa_65_public_key: vec![0xBB; 1952], // DIFFERENT
        ml_kem_768_public_key: vec![4u8; 1184], // same
        x_wing_public_key: vec![],
        status: "active".to_string(),
        registered_at: chrono::Utc::now(),
        revoked_at: None,
        ml_dsa_key_generation: 1, // higher generation
    };

    // merge_relay_device should succeed (not error)
    let result = DeviceRegistryManager::merge_relay_device(&storage, SYNC_ID, &rotated_record);
    assert!(result.is_ok(), "merge_relay_device should not error, got: {:?}", result.err());

    // But the stored record should still have the old ML-DSA key at generation 0
    let stored = storage
        .get_device_record(SYNC_ID, "dev-target")
        .unwrap()
        .expect("device record should exist");
    assert_eq!(
        stored.ml_dsa_key_generation, 0,
        "generation should remain at 0 (rotation rejected)"
    );
    assert_eq!(
        stored.ml_dsa_65_public_key, original_ml_dsa_pk,
        "ML-DSA public key should remain unchanged"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 3: Verified import preserves ml_dsa_key_generation
//
// Build a signed snapshot where device_b has ml_dsa_key_generation: 3,
// import it, and verify the generation is preserved.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn registry_verification_verified_import_preserves_generation() {
    let storage = RusqliteSyncStorage::in_memory().unwrap();

    // Device A is the signer/approver — registered locally so verification
    // can find its keys
    let device_a_id = "device-aaa";
    let device_secret_a = DeviceSecret::generate();
    let ed25519_a = device_secret_a.ed25519_keypair(device_a_id).unwrap();
    let x25519_a = device_secret_a.x25519_keypair(device_a_id).unwrap();
    let ml_dsa_a = device_secret_a.ml_dsa_65_keypair(device_a_id).unwrap();
    let ml_kem_a = device_secret_a.ml_kem_768_keypair(device_a_id).unwrap();

    register_device_in_storage(
        &storage,
        device_a_id,
        &ed25519_a.public_key_bytes(),
        &x25519_a.public_key_bytes(),
        &ml_dsa_a.public_key_bytes(),
        &ml_kem_a.public_key_bytes(),
        0,
    );

    // Device B has a high ML-DSA key generation
    let device_b_id = "device-bbb";
    let device_secret_b = DeviceSecret::generate();
    let ed25519_b = device_secret_b.ed25519_keypair(device_b_id).unwrap();
    let x25519_b = device_secret_b.x25519_keypair(device_b_id).unwrap();
    // Use generation 3 for the ML-DSA key
    let ml_dsa_b_gen3 = device_secret_b.ml_dsa_65_keypair_v(device_b_id, 3).unwrap();
    let ml_kem_b = device_secret_b.ml_kem_768_keypair(device_b_id).unwrap();

    let entries = vec![
        RegistrySnapshotEntry {
            sync_id: SYNC_ID.to_string(),
            device_id: device_a_id.to_string(),
            ed25519_public_key: ed25519_a.public_key_bytes().to_vec(),
            x25519_public_key: x25519_a.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: ml_dsa_a.public_key_bytes(),
            ml_kem_768_public_key: ml_kem_a.public_key_bytes(),
            x_wing_public_key: vec![],
            status: "active".to_string(),
            ml_dsa_key_generation: 0,
            remote_wipe: false,
        },
        RegistrySnapshotEntry {
            sync_id: SYNC_ID.to_string(),
            device_id: device_b_id.to_string(),
            ed25519_public_key: ed25519_b.public_key_bytes().to_vec(),
            x25519_public_key: x25519_b.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: ml_dsa_b_gen3.public_key_bytes(),
            ml_kem_768_public_key: ml_kem_b.public_key_bytes(),
            x_wing_public_key: vec![],
            status: "active".to_string(),
            ml_dsa_key_generation: 3,
            remote_wipe: false,
        },
    ];

    let signed_blob = build_signed_registry_blob(entries, &device_secret_a, device_a_id);

    // Import the signed registry
    let result = DeviceRegistryManager::verify_and_import_signed_registry(
        &storage,
        SYNC_ID,
        &signed_blob,
        None,
    );
    assert!(result.is_ok(), "verified import should succeed: {:?}", result.err());

    // Verify device B's generation was preserved
    let device_b_record = storage
        .get_device_record(SYNC_ID, device_b_id)
        .unwrap()
        .expect("device B should be in storage after import");
    assert_eq!(
        device_b_record.ml_dsa_key_generation, 3,
        "ml_dsa_key_generation should be preserved as 3"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 4: Tampered artifact rejected
//
// Build a valid signed snapshot, corrupt a byte, and verify that
// verify_and_import_signed_registry returns an error.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn registry_verification_tampered_artifact_rejected() {
    let storage = RusqliteSyncStorage::in_memory().unwrap();

    let device_a_id = "device-aaa";
    let device_secret_a = DeviceSecret::generate();
    let ed25519_a = device_secret_a.ed25519_keypair(device_a_id).unwrap();
    let x25519_a = device_secret_a.x25519_keypair(device_a_id).unwrap();
    let ml_dsa_a = device_secret_a.ml_dsa_65_keypair(device_a_id).unwrap();
    let ml_kem_a = device_secret_a.ml_kem_768_keypair(device_a_id).unwrap();

    // Register device A in storage so verification can find its keys
    register_device_in_storage(
        &storage,
        device_a_id,
        &ed25519_a.public_key_bytes(),
        &x25519_a.public_key_bytes(),
        &ml_dsa_a.public_key_bytes(),
        &ml_kem_a.public_key_bytes(),
        0,
    );

    let entries = vec![RegistrySnapshotEntry {
        sync_id: SYNC_ID.to_string(),
        device_id: device_a_id.to_string(),
        ed25519_public_key: ed25519_a.public_key_bytes().to_vec(),
        x25519_public_key: x25519_a.public_key_bytes().to_vec(),
        ml_dsa_65_public_key: ml_dsa_a.public_key_bytes(),
        ml_kem_768_public_key: ml_kem_a.public_key_bytes(),
        x_wing_public_key: vec![],
        status: "active".to_string(),
        ml_dsa_key_generation: 0,
        remote_wipe: false,
    }];

    let mut signed_blob = build_signed_registry_blob(entries, &device_secret_a, device_a_id);

    // Corrupt a byte near the end (in the JSON payload area)
    let last_idx = signed_blob.len() - 2;
    signed_blob[last_idx] ^= 0xFF;

    let result = DeviceRegistryManager::verify_and_import_signed_registry(
        &storage,
        SYNC_ID,
        &signed_blob,
        None,
    );
    assert!(result.is_err(), "tampered artifact should be rejected, but got Ok");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 5: Stall (don't skip) when no signed registry is available
//
// When MockRelay returns None for get_signed_registry and a batch arrives from
// an unknown sender, the engine must remain fail-closed on APPLY (no data from
// the unknown sender is merged, and it never falls back to the unverified
// list_devices endpoint) — but the disposition is now a transient STALL, not a
// skip-and-advance. `Ok(None)` is ambiguous (the registry may simply not be
// uploaded yet, or this peer is racing a behind publisher), so advancing past
// the batch and acking it would let the relay prune it and lose the data
// permanently. Instead the cursor is held behind the batch, a pull_stall row is
// recorded, a PullStalled event fires, and the sync still completes without
// error. The batch resolves on a later cycle once the registry imports the
// sender (covered by the e2e/budget tests in engine_integration.rs).
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn unknown_sender_with_no_artifact_stalls_without_advancing() {
    let key_hierarchy = init_key_hierarchy();

    let device_a_id = "device-local";
    let signing_key_a = make_signing_key();

    let device_b_id = "device-remote";
    let signing_key_b = make_signing_key();
    let ml_dsa_key_b = make_ml_dsa_keypair();

    let relay = Arc::new(MockRelay::new());
    // No signed registry set (default is None)

    // Add device B to the relay's device list — with fail-closed behavior,
    // this must NOT be consulted for key resolution.
    relay.add_device(DeviceInfo {
        device_id: device_b_id.to_string(),
        epoch: 0,
        status: "active".to_string(),
        ed25519_public_key: signing_key_b.verifying_key().to_bytes().to_vec(),
        x25519_public_key: vec![0u8; 32],
        ml_dsa_65_public_key: ml_dsa_key_b.public_key_bytes(),
        ml_kem_768_public_key: Vec::new(),
        x_wing_public_key: Vec::new(),
        permission: None,
        ml_dsa_key_generation: 0,
        needs_rekey: false,
    });

    // Also add device A to relay
    relay.add_device(DeviceInfo {
        device_id: device_a_id.to_string(),
        epoch: 0,
        status: "active".to_string(),
        ed25519_public_key: signing_key_a.verifying_key().to_bytes().to_vec(),
        x25519_public_key: vec![0u8; 32],
        ml_dsa_65_public_key: Vec::new(),
        ml_kem_768_public_key: Vec::new(),
        x_wing_public_key: Vec::new(),
        permission: None,
        ml_dsa_key_generation: 0,
        needs_rekey: false,
    });

    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    setup_sync_metadata(&storage, device_a_id);

    // Register device A locally (so its own ops can be signed)
    register_device(&relay, &storage, device_a_id, &signing_key_a.verifying_key());

    // DO NOT register device B locally and provide no signed registry.
    // The engine must fail closed and skip device B's batch entirely.

    // Inject a batch from device B
    let hlc = Hlc::now(device_b_id, None);
    let ops = vec![CrdtChange {
        op_id: format!("tasks:task-1:title:{}:{}", hlc, device_b_id),
        batch_id: Some("batch-b1".to_string()),
        entity_id: "task-1".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Fallback data\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: device_b_id.to_string(),
        epoch: 0,
        server_seq: None,
    }];

    let envelope = make_encrypted_batch(
        &ops,
        &key_hierarchy,
        &signing_key_b,
        &ml_dsa_key_b,
        "batch-b1",
        device_b_id,
    );
    let batch_seq = relay.inject_batch(envelope);

    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    let (event_tx, mut event_rx) =
        tokio::sync::broadcast::channel::<prism_sync_core::events::SyncEvent>(32);
    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    )
    .with_event_sink(event_tx.clone());

    let result =
        engine.sync(SYNC_ID, &key_hierarchy, &signing_key_a, None, device_a_id, 0).await.unwrap();

    // Sync must succeed overall (a stall is non-fatal: cursor frozen, push still
    // runs, retry next cycle).
    assert!(
        result.error.is_none(),
        "sync should complete even when unknown sender batch stalls: {:?}",
        result.error
    );

    // Fail-closed on APPLY: nothing from the unknown sender is merged.
    assert_eq!(result.merged, 0, "expected 0 ops merged from unknown sender (fail closed)");
    let title = entity.get_field("task-1", "title");
    assert_eq!(title, None, "data from unknown sender must not be applied (fail closed)");

    // The batch is NOT consumed: the cursor is held behind it so the relay can
    // never prune it, and nothing is acked past it. (Old behaviour was
    // skip-and-advance to batch_seq + an ack of batch_seq — the data-losing bug
    // the stall discipline fixes.)
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        0,
        "cursor must stay behind the stalled batch (not advance to {batch_seq})"
    );
    // The cursor never left 0, so the engine spawns NO ack at all
    // (`acked_cursor > 0` gates the ack). Assert the ack list is empty — a
    // deterministic positive check that does not depend on the fire-and-forget
    // ack task being polled, and that fails if a regression acks the stalled or
    // page-max seq.
    tokio::task::yield_now().await;
    assert!(
        relay.ack_calls().is_empty(),
        "a stall at the head of the page must not ack anything, acks were: {:?}",
        relay.ack_calls()
    );

    // A pull_stall row records the transient verdict under the budget.
    let stalls = storage.list_pull_stalls(SYNC_ID).unwrap();
    assert_eq!(stalls.len(), 1, "expected exactly one stall row");
    assert_eq!(stalls[0].server_seq, batch_seq);
    assert_eq!(stalls[0].reason, "sender_unresolved");
    assert_eq!(stalls[0].attempts, 1, "first stall = attempt 1");

    // PullStalled event surfaced for the app.
    let mut saw_stalled = false;
    while let Ok(event) = event_rx.try_recv() {
        if let prism_sync_core::events::SyncEvent::PullStalled { server_seq, reason, attempt } =
            event
        {
            if server_seq == batch_seq && reason == "sender_unresolved" && attempt == 1 {
                saw_stalled = true;
            }
        }
    }
    assert!(saw_stalled, "expected PullStalled(sender_unresolved, attempt 1) event");
}

// ═══════════════════════════════════════════════════════════════════════════
// Transient sender-key resolution failures STALL (don't skip-and-advance)
//
// These exercise the unknown-sender path where the older code conflated a
// permanent revocation with a transient registry-fetch failure and durably
// advanced the cursor past the batch, then acked it — letting the relay prune
// the batch and lose the data forever. The fix: a transient verdict stalls (no
// cursor advance, no ack past, push still runs) and retries under a budget; only
// a genuine revocation skips-and-advances.
// ═══════════════════════════════════════════════════════════════════════════

/// Shared A+B fixture: device A (local verifier/approver) plus an unknown sender
/// B whose single ops batch is injected on the relay. The signed registry
/// containing both is built and returned but NOT set on the relay — the caller
/// decides when (or whether) to make it resolvable. Returns the pieces the test
/// needs to drive the engine and assert.
struct F13Fixture {
    key_hierarchy: prism_sync_crypto::KeyHierarchy,
    relay: Arc<MockRelay>,
    storage: Arc<RusqliteSyncStorage>,
    entity: Arc<MockTaskEntity>,
    engine: SyncEngine,
    signing_key_a: ed25519_dalek::SigningKey,
    ml_dsa_a: prism_sync_crypto::DevicePqSigningKey,
    device_a_id: &'static str,
    device_b_id: &'static str,
    signed_blob: Vec<u8>,
    batch_seq: i64,
    event_rx: tokio::sync::broadcast::Receiver<prism_sync_core::events::SyncEvent>,
}

fn setup_f13_fixture() -> F13Fixture {
    setup_f13_fixture_with_config(SyncConfig::default())
}

fn setup_f13_fixture_with_config(config: SyncConfig) -> F13Fixture {
    let key_hierarchy = init_key_hierarchy();

    let device_a_id = "device-aaa";
    let device_secret_a = DeviceSecret::generate();
    let ed25519_a = device_secret_a.ed25519_keypair(device_a_id).unwrap();
    let x25519_a = device_secret_a.x25519_keypair(device_a_id).unwrap();
    let ml_dsa_a = device_secret_a.ml_dsa_65_keypair(device_a_id).unwrap();
    let ml_kem_a = device_secret_a.ml_kem_768_keypair(device_a_id).unwrap();

    let device_b_id = "device-bbb";
    let device_secret_b = DeviceSecret::generate();
    let ed25519_b = device_secret_b.ed25519_keypair(device_b_id).unwrap();
    let x25519_b = device_secret_b.x25519_keypair(device_b_id).unwrap();
    let ml_dsa_b = device_secret_b.ml_dsa_65_keypair(device_b_id).unwrap();
    let ml_kem_b = device_secret_b.ml_kem_768_keypair(device_b_id).unwrap();

    let entries = vec![
        RegistrySnapshotEntry {
            sync_id: SYNC_ID.to_string(),
            device_id: device_a_id.to_string(),
            ed25519_public_key: ed25519_a.public_key_bytes().to_vec(),
            x25519_public_key: x25519_a.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: ml_dsa_a.public_key_bytes(),
            ml_kem_768_public_key: ml_kem_a.public_key_bytes(),
            x_wing_public_key: vec![],
            status: "active".to_string(),
            ml_dsa_key_generation: 0,
            remote_wipe: false,
        },
        RegistrySnapshotEntry {
            sync_id: SYNC_ID.to_string(),
            device_id: device_b_id.to_string(),
            ed25519_public_key: ed25519_b.public_key_bytes().to_vec(),
            x25519_public_key: x25519_b.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: ml_dsa_b.public_key_bytes(),
            ml_kem_768_public_key: ml_kem_b.public_key_bytes(),
            x_wing_public_key: vec![],
            status: "active".to_string(),
            ml_dsa_key_generation: 0,
            remote_wipe: false,
        },
    ];
    let signed_blob = build_signed_registry_blob(entries, &device_secret_a, device_a_id);

    let relay = Arc::new(MockRelay::new());

    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    setup_sync_metadata(&storage, device_a_id);
    register_device_in_storage(
        &storage,
        device_a_id,
        &ed25519_a.public_key_bytes(),
        &x25519_a.public_key_bytes(),
        &ml_dsa_a.public_key_bytes(),
        &ml_kem_a.public_key_bytes(),
        0,
    );
    // DO NOT register device B locally — it is the unknown sender.

    // Inject B's batch.
    let signing_key_b = ed25519_b.into_signing_key();
    let ml_dsa_key_b = device_secret_b.ml_dsa_65_keypair(device_b_id).unwrap();
    let hlc = Hlc::now(device_b_id, None);
    let ops = vec![CrdtChange {
        op_id: format!("tasks:task-1:title:{}:{}", hlc, device_b_id),
        batch_id: Some("batch-b1".to_string()),
        entity_id: "task-1".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Hello from B\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: device_b_id.to_string(),
        epoch: 0,
        server_seq: None,
    }];
    let envelope = make_encrypted_batch(
        &ops,
        &key_hierarchy,
        &signing_key_b,
        &ml_dsa_key_b,
        "batch-b1",
        device_b_id,
    );
    let batch_seq = relay.inject_batch(envelope);

    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    let (event_tx, event_rx) =
        tokio::sync::broadcast::channel::<prism_sync_core::events::SyncEvent>(64);
    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        config,
    )
    .with_event_sink(event_tx);

    let signing_key_a = device_secret_a.ed25519_keypair(device_a_id).unwrap().into_signing_key();

    F13Fixture {
        key_hierarchy,
        relay,
        storage,
        entity,
        engine,
        signing_key_a,
        ml_dsa_a,
        device_a_id,
        device_b_id,
        signed_blob,
        batch_seq,
        event_rx,
    }
}

fn drain_pull_stalled(
    rx: &mut tokio::sync::broadcast::Receiver<prism_sync_core::events::SyncEvent>,
) -> Vec<(i64, String, i64)> {
    let mut out = Vec::new();
    while let Ok(event) = rx.try_recv() {
        if let prism_sync_core::events::SyncEvent::PullStalled { server_seq, reason, attempt } =
            event
        {
            out.push((server_seq, reason, attempt));
        }
    }
    out
}

/// Collected `PullSenderStalled` events: (sender_device_id, reason,
/// live_stall_count, quarantined_batch_count).
fn drain_pull_sender_stalled(
    rx: &mut tokio::sync::broadcast::Receiver<prism_sync_core::events::SyncEvent>,
) -> Vec<(String, String, i64, i64)> {
    let mut out = Vec::new();
    while let Ok(event) = rx.try_recv() {
        if let prism_sync_core::events::SyncEvent::PullSenderStalled {
            sender_device_id,
            reason,
            live_stall_count,
            quarantined_batch_count,
            ..
        } = event
        {
            out.push((sender_device_id, reason, live_stall_count, quarantined_batch_count));
        }
    }
    out
}

/// Collected `PullSenderRecovered` events: (sender_device_id, reason,
/// replayed_batch_count).
fn drain_pull_sender_recovered(
    rx: &mut tokio::sync::broadcast::Receiver<prism_sync_core::events::SyncEvent>,
) -> Vec<(String, String, i64)> {
    let mut out = Vec::new();
    while let Ok(event) = rx.try_recv() {
        if let prism_sync_core::events::SyncEvent::PullSenderRecovered {
            sender_device_id,
            reason,
            replayed_batch_count,
        } = event
        {
            out.push((sender_device_id, reason, replayed_batch_count));
        }
    }
    out
}

/// A retryable registry-fetch failure on the cycle that first sees an unknown
/// sender's batch must STALL — cursor frozen, no ack past, push still runs — and
/// the batch must apply on the next cycle once the fetch succeeds. The data is
/// never lost.
#[tokio::test]
async fn f13_transient_registry_outage_stalls_then_applies() {
    let mut f = setup_f13_fixture();

    // The registry IS resolvable, but the first get_signed_registry call 503s.
    f.relay.set_signed_registry(SignedRegistryResponse {
        registry_version: 1,
        artifact_blob: f.signed_blob.clone(),
        artifact_kind: "signed_registry_snapshot".to_string(),
    });
    f.relay.fail_next_get_signed_registry(1);

    // Cycle 1: the fetch fails -> stall.
    let r1 = f
        .engine
        .sync(SYNC_ID, &f.key_hierarchy, &f.signing_key_a, None, f.device_a_id, 0)
        .await
        .unwrap();
    assert!(r1.error.is_none(), "stall is non-fatal: {:?}", r1.error);
    assert_eq!(r1.merged, 0, "nothing applied while stalled");

    assert_eq!(
        f.storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        0,
        "cursor must stay behind the stalled batch"
    );
    // Cursor never left 0 -> no ack spawned at all. Deterministic empty-ack
    // assertion (independent of the fire-and-forget ack task's scheduling).
    tokio::task::yield_now().await;
    assert!(
        f.relay.ack_calls().is_empty(),
        "a head-of-page stall must not ack anything: {:?}",
        f.relay.ack_calls()
    );
    let stalls = f.storage.list_pull_stalls(SYNC_ID).unwrap();
    assert_eq!(stalls.len(), 1);
    assert_eq!(stalls[0].server_seq, f.batch_seq);
    assert_eq!(stalls[0].reason, "sender_unresolved");
    assert_eq!(stalls[0].attempts, 1);
    let events = drain_pull_stalled(&mut f.event_rx);
    assert!(
        events.iter().any(|(s, r, a)| *s == f.batch_seq && r == "sender_unresolved" && *a == 1),
        "expected PullStalled attempt 1, got {events:?}"
    );
    assert_eq!(f.entity.get_field("task-1", "title"), None, "no data applied yet");

    // Cycle 2: the fetch succeeds -> batch resolves and applies.
    let r2 = f
        .engine
        .sync(SYNC_ID, &f.key_hierarchy, &f.signing_key_a, None, f.device_a_id, 0)
        .await
        .unwrap();
    assert!(r2.error.is_none(), "{:?}", r2.error);
    assert!(r2.merged >= 1, "batch must apply once the registry resolves");
    assert_eq!(
        f.entity.get_field("task-1", "title"),
        Some(SyncValue::String("Hello from B".to_string())),
        "B's data must converge after the outage clears"
    );
    assert_eq!(
        f.storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        f.batch_seq,
        "cursor advances to the batch once applied"
    );
    assert!(
        f.storage.list_pull_stalls(SYNC_ID).unwrap().is_empty(),
        "stall row cleared once the batch resolves"
    );
    // Now that the batch applied, the cursor advanced to batch_seq and the engine
    // acks it. Deterministic positive check the relay can now prune.
    tokio::task::yield_now().await;
    assert!(
        f.relay.ack_calls().contains(&f.batch_seq),
        "after the batch applies, the cursor (batch_seq) must be acked: {:?}",
        f.relay.ack_calls()
    );
}

/// A stall must cost the retry budget at most ONE attempt per sync CYCLE, even
/// when a full page (`>= pull_page_limit` batches) remains at/after the stalled
/// seq — the high-backlog catch-up / post-pairing case the maintainer's "8 sync
/// cycles" budget was meant to cover.
///
/// Regression guard for the paging-loop review blocker: `pull_one_page` returned a full
/// `page_len` even when it broke early on a stall, so `pull_phase`'s paging loop
/// (which stops only on a short page or the page/time budget) re-invoked it up to
/// `max_pull_pages_per_cycle` times in ONE cycle. Each re-invocation re-hit the
/// same frozen-cursor batch and bumped `pull_stall.attempts`, exhausting the
/// 8-cycle budget within seconds (and re-fetching the registry up to 8x). The fix
/// signals the stall so the paging loop stops for the cycle.
///
/// Setup: `pull_page_limit = 1` so the single stalled batch is a FULL page (the
/// old code's re-page trigger), and `max_pull_pages_per_cycle = 5` so the bug,
/// if present, would bump `attempts` to 5 in this one cycle. With the fix the
/// loop stops after the first page: exactly one pull, `attempts == 1`.
#[tokio::test]
async fn f13_stall_bumps_attempts_at_most_once_per_cycle_under_backlog() {
    let f = setup_f13_fixture_with_config(SyncConfig {
        pull_page_limit: 1,
        max_pull_pages_per_cycle: 5,
        // Leave the stall budget at its default (8) so a within-cycle over-bump
        // would manifest as attempts climbing, not as an early conversion.
        ..SyncConfig::default()
    });

    // One sync cycle. B is unknown and no registry is set -> transient stall.
    let r = f
        .engine
        .sync(SYNC_ID, &f.key_hierarchy, &f.signing_key_a, None, f.device_a_id, 0)
        .await
        .unwrap();
    assert!(r.error.is_none(), "stall is non-fatal: {:?}", r.error);

    // The cursor never advanced and the batch was not quarantined (within budget).
    assert_eq!(
        f.storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        0,
        "cursor frozen behind the stalled batch"
    );
    assert!(
        f.storage.list_quarantined_pull_batches(SYNC_ID).unwrap().is_empty(),
        "one cycle within budget must NOT convert to quarantine"
    );

    // The crux: exactly ONE attempt despite a full page and a 5-page cycle budget.
    let stalls = f.storage.list_pull_stalls(SYNC_ID).unwrap();
    assert_eq!(stalls.len(), 1, "one stall row");
    assert_eq!(
        stalls[0].attempts, 1,
        "a stall must cost exactly one attempt per cycle; >1 means the paging loop \
         re-hit the frozen batch within the cycle (the paging-loop blocker)"
    );

    // And the page loop stopped: one pull_changes call, not max_pull_pages_per_cycle.
    assert_eq!(
        f.relay.pull_call_count(),
        1,
        "the paging loop must stop for the cycle on a stall (no re-paging the same batch)"
    );
    // The registry was fetched at most once too (the stall short-circuits the loop).
    assert!(
        f.relay.signed_registry_call_count() <= 1,
        "registry fetched at most once per cycle, was {}",
        f.relay.signed_registry_call_count()
    );
}

/// A persistent registry outage holds the cursor for the budget, then converts
/// the batch to a durable (replayable) quarantine and advances — never a silent
/// skip. A later cycle that imports the sender replays the quarantined batch and
/// applies its ops, restoring the data losslessly.
///
/// Budget semantics pinned here (maintainer reading of "8 sync cycles"): the
/// stall converts on the cycle whose attempt count REACHES `pull_stall_max_attempts`
/// (`attempts >= max`, with `attempts` incremented before the check). So with the
/// default 8, attempts 1..=7 stall (the cursor is held across 7 completed retry
/// cycles) and the 8th observation converts. Each sync cycle bumps `attempts` by
/// exactly one (the page loop stops paging on a stall, so a backlog can't burn
/// the budget within a single cycle). With `max_attempts = 2` below: cycle 1 =
/// attempt 1 (stall), cycle 2 = attempt 2 (convert).
#[tokio::test]
async fn f13_budget_exhaustion_quarantines_then_replay_applies() {
    // Tighten the budget so the test converts on the 2nd cycle rather than the
    // 8th. Disable replay backoff so Phase 0b replay is eligible every cycle.
    let f = setup_f13_fixture_with_config(SyncConfig {
        pull_stall_max_attempts: 2,
        quarantine_replay_backoff_base_ms: 0,
        ..SyncConfig::default()
    });

    // No signed registry set yet: get_signed_registry returns Ok(None) every
    // cycle, an ambiguous transient verdict -> stall.

    // Cycle 1: stall (attempt 1).
    let r1 = f
        .engine
        .sync(SYNC_ID, &f.key_hierarchy, &f.signing_key_a, None, f.device_a_id, 0)
        .await
        .unwrap();
    assert!(r1.error.is_none(), "{:?}", r1.error);
    assert_eq!(
        f.storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        0,
        "cursor frozen on attempt 1"
    );
    assert_eq!(f.storage.list_pull_stalls(SYNC_ID).unwrap()[0].attempts, 1);
    assert!(f.storage.list_quarantined_pull_batches(SYNC_ID).unwrap().is_empty());

    // Cycle 2: attempt 2 hits the budget (max_attempts = 2) -> convert to
    // quarantine-and-advance.
    let r2 = f
        .engine
        .sync(SYNC_ID, &f.key_hierarchy, &f.signing_key_a, None, f.device_a_id, 0)
        .await
        .unwrap();
    assert!(r2.error.is_none(), "{:?}", r2.error);
    assert_eq!(
        f.storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        f.batch_seq,
        "cursor advances once the batch is durably quarantined"
    );
    let quarantined = f.storage.list_quarantined_pull_batches(SYNC_ID).unwrap();
    assert_eq!(quarantined.len(), 1, "batch durably quarantined, not dropped");
    assert_eq!(quarantined[0].reason, "sender_unresolved");
    assert_eq!(quarantined[0].server_seq, f.batch_seq);
    assert!(
        f.storage.list_pull_stalls(SYNC_ID).unwrap().is_empty(),
        "stall row cleared on conversion to quarantine"
    );
    assert_eq!(f.entity.get_field("task-1", "title"), None, "still not applied (fail closed)");

    // Now make the sender resolvable, then sync: Phase 0b replay applies the
    // quarantined batch and deletes the row.
    f.relay.set_signed_registry(SignedRegistryResponse {
        registry_version: 1,
        artifact_blob: f.signed_blob.clone(),
        artifact_kind: "signed_registry_snapshot".to_string(),
    });
    let r3 = f
        .engine
        .sync(SYNC_ID, &f.key_hierarchy, &f.signing_key_a, None, f.device_a_id, 0)
        .await
        .unwrap();
    assert!(r3.error.is_none(), "{:?}", r3.error);
    assert_eq!(
        f.entity.get_field("task-1", "title"),
        Some(SyncValue::String("Hello from B".to_string())),
        "Phase 0b replay restores B's data once the registry imports"
    );
    assert!(
        f.storage.list_quarantined_pull_batches(SYNC_ID).unwrap().is_empty(),
        "quarantine row deleted after a successful replay"
    );
}

/// A genuinely-revoked sender keeps today's skip-and-advance policy. Pinned
/// explicitly so it can't silently regress into a stall (which would freeze the
/// cursor on a revoked device's in-flight batch forever).
#[tokio::test]
async fn f13_revoked_sender_skip_and_advance_unchanged() {
    let mut f = setup_f13_fixture();

    // Give A a local record for B with a non-active status (revoked).
    {
        let mut tx = f.storage.begin_tx().unwrap();
        tx.upsert_device_record(&DeviceRecord {
            sync_id: SYNC_ID.to_string(),
            device_id: f.device_b_id.to_string(),
            ed25519_public_key: vec![0u8; 32],
            x25519_public_key: vec![0u8; 32],
            ml_dsa_65_public_key: vec![],
            ml_kem_768_public_key: vec![],
            x_wing_public_key: vec![],
            status: "revoked".to_string(),
            registered_at: chrono::Utc::now(),
            revoked_at: Some(chrono::Utc::now()),
            ml_dsa_key_generation: 0,
        })
        .unwrap();
        tx.commit().unwrap();
    }

    let r1 = f
        .engine
        .sync(SYNC_ID, &f.key_hierarchy, &f.signing_key_a, None, f.device_a_id, 0)
        .await
        .unwrap();
    assert!(r1.error.is_none(), "{:?}", r1.error);
    assert_eq!(r1.merged, 0, "nothing from a revoked sender is applied");
    assert_eq!(
        f.storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        f.batch_seq,
        "a revoked sender's batch is skipped-and-advanced (not stalled)"
    );
    assert!(
        f.storage.list_pull_stalls(SYNC_ID).unwrap().is_empty(),
        "a revoked sender must NOT create a stall row"
    );
    assert!(
        f.storage.list_quarantined_pull_batches(SYNC_ID).unwrap().is_empty(),
        "a revoked sender's batch is not quarantined either (skip policy)"
    );
    let events = drain_pull_stalled(&mut f.event_rx);
    assert!(events.is_empty(), "no PullStalled for a revoked sender, got {events:?}");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 6: SenderKeyInfo includes ML-DSA keys
//
// Verify that resolve_sender_keys_with_generation_hint returns the correct
// ML-DSA public key and generation from the local device registry.
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn sender_key_info_includes_ml_dsa_keys() {
    let device_id = "device-aaa";
    let device_secret = DeviceSecret::generate();
    let ed25519_kp = device_secret.ed25519_keypair(device_id).unwrap();
    let x25519_kp = device_secret.x25519_keypair(device_id).unwrap();
    let ml_dsa_kp = device_secret.ml_dsa_65_keypair(device_id).unwrap();
    let ml_kem_kp = device_secret.ml_kem_768_keypair(device_id).unwrap();

    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    setup_sync_metadata(&storage, device_id);

    // Insert device record with ML-DSA key at generation 0
    register_device_in_storage(
        &storage,
        device_id,
        &ed25519_kp.public_key_bytes(),
        &x25519_kp.public_key_bytes(),
        &ml_dsa_kp.public_key_bytes(),
        &ml_kem_kp.public_key_bytes(),
        0,
    );

    let relay = Arc::new(MockRelay::new());
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );

    let info = engine
        .resolve_sender_keys_with_generation_hint(SYNC_ID, device_id, None)
        .await
        .expect("resolve_sender_keys_with_generation_hint should succeed");

    assert_eq!(info.ed25519_pk, ed25519_kp.public_key_bytes(), "Ed25519 public key should match");
    assert_eq!(
        info.ml_dsa_65_pk,
        ml_dsa_kp.public_key_bytes(),
        "ML-DSA-65 public key should match"
    );
    assert_eq!(info.ml_dsa_key_generation, 0, "ML-DSA key generation should be 0");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 7: Generation mismatch triggers registry fetch
//
// When the expected ML-DSA generation is higher than what is stored locally,
// resolve_sender_keys_with_generation_hint should fetch the signed registry
// and import the updated key.
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn generation_mismatch_triggers_registry_fetch() {
    // --- Verifier device ---
    let verifier_id = "device-verifier";
    let verifier_secret = DeviceSecret::generate();
    let verifier_ed25519 = verifier_secret.ed25519_keypair(verifier_id).unwrap();
    let verifier_x25519 = verifier_secret.x25519_keypair(verifier_id).unwrap();
    let verifier_ml_dsa = verifier_secret.ml_dsa_65_keypair(verifier_id).unwrap();
    let verifier_ml_kem = verifier_secret.ml_kem_768_keypair(verifier_id).unwrap();

    // --- Sender device ---
    let sender_id = "device-sender";
    let sender_secret = DeviceSecret::generate();
    let sender_ed25519 = sender_secret.ed25519_keypair(sender_id).unwrap();
    let sender_x25519 = sender_secret.x25519_keypair(sender_id).unwrap();
    let sender_ml_dsa_gen0 = sender_secret.ml_dsa_65_keypair(sender_id).unwrap();
    let sender_ml_dsa_gen1 = sender_secret.ml_dsa_65_keypair_v(sender_id, 1).unwrap();
    let sender_ml_kem = sender_secret.ml_kem_768_keypair(sender_id).unwrap();

    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    setup_sync_metadata(&storage, verifier_id);

    // Register verifier in local storage
    register_device_in_storage(
        &storage,
        verifier_id,
        &verifier_ed25519.public_key_bytes(),
        &verifier_x25519.public_key_bytes(),
        &verifier_ml_dsa.public_key_bytes(),
        &verifier_ml_kem.public_key_bytes(),
        0,
    );

    // Insert sender into verifier's local storage at generation 0
    register_device_in_storage(
        &storage,
        sender_id,
        &sender_ed25519.public_key_bytes(),
        &sender_x25519.public_key_bytes(),
        &sender_ml_dsa_gen0.public_key_bytes(),
        &sender_ml_kem.public_key_bytes(),
        0,
    );

    // Build a signed registry snapshot with sender at generation 1
    let entries = vec![
        RegistrySnapshotEntry {
            sync_id: SYNC_ID.to_string(),
            device_id: verifier_id.to_string(),
            ed25519_public_key: verifier_ed25519.public_key_bytes().to_vec(),
            x25519_public_key: verifier_x25519.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: verifier_ml_dsa.public_key_bytes(),
            ml_kem_768_public_key: verifier_ml_kem.public_key_bytes(),
            x_wing_public_key: vec![],
            status: "active".to_string(),
            ml_dsa_key_generation: 0,
            remote_wipe: false,
        },
        RegistrySnapshotEntry {
            sync_id: SYNC_ID.to_string(),
            device_id: sender_id.to_string(),
            ed25519_public_key: sender_ed25519.public_key_bytes().to_vec(),
            x25519_public_key: sender_x25519.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: sender_ml_dsa_gen1.public_key_bytes(),
            ml_kem_768_public_key: sender_ml_kem.public_key_bytes(),
            x_wing_public_key: vec![],
            status: "active".to_string(),
            ml_dsa_key_generation: 1,
            remote_wipe: false,
        },
    ];

    // Sign with verifier's keys (any known device can sign the registry)
    let signed_blob = build_signed_registry_blob(entries, &verifier_secret, verifier_id);

    let relay = Arc::new(MockRelay::new());
    relay.set_signed_registry(SignedRegistryResponse {
        registry_version: 1,
        artifact_blob: signed_blob,
        artifact_kind: "signed_registry_snapshot".to_string(),
    });

    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );

    // Request resolution with expected generation 1 (local has 0)
    let info = engine
        .resolve_sender_keys_with_generation_hint(SYNC_ID, sender_id, Some(1))
        .await
        .expect("resolve should succeed after registry fetch");

    assert_eq!(info.ml_dsa_key_generation, 1, "ML-DSA generation should be updated to 1");
    assert_eq!(
        info.ml_dsa_65_pk,
        sender_ml_dsa_gen1.public_key_bytes(),
        "ML-DSA public key should be the generation-1 key"
    );
    // Verify it's NOT the generation-0 key
    assert_ne!(
        info.ml_dsa_65_pk,
        sender_ml_dsa_gen0.public_key_bytes(),
        "ML-DSA public key should differ from generation-0 key"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 8: Generation mismatch — relay returns no registry (fallback to stale)
//
// When the relay fails to return a signed registry during a generation
// mismatch, the resolver should fall back to the stale local key rather
// than erroring — the caller's verification decides whether to accept.
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn generation_mismatch_registry_fetch_fails_returns_stale_info() {
    let device_id = "device-stale";
    let device_secret = DeviceSecret::generate();
    let ed25519_kp = device_secret.ed25519_keypair(device_id).unwrap();
    let x25519_kp = device_secret.x25519_keypair(device_id).unwrap();
    let ml_dsa_kp = device_secret.ml_dsa_65_keypair(device_id).unwrap();
    let ml_kem_kp = device_secret.ml_kem_768_keypair(device_id).unwrap();

    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    setup_sync_metadata(&storage, "other-device");

    register_device_in_storage(
        &storage,
        device_id,
        &ed25519_kp.public_key_bytes(),
        &x25519_kp.public_key_bytes(),
        &ml_dsa_kp.public_key_bytes(),
        &ml_kem_kp.public_key_bytes(),
        0,
    );

    // Mock relay returns None for signed registry (no artifact available)
    let relay = Arc::new(MockRelay::new());
    // Don't set any signed registry — relay returns Ok(None)

    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );

    // Request gen 1 but relay has no registry — should fall back to local gen 0
    let info = engine
        .resolve_sender_keys_with_generation_hint(SYNC_ID, device_id, Some(1))
        .await
        .expect("should succeed with stale info when registry unavailable");

    assert_eq!(
        info.ml_dsa_key_generation, 0,
        "should fall back to local generation 0 when registry fetch fails"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 9: Generation mismatch — registry fetched but still at old generation
//
// When the signed registry is fetched but still has the sender at the old
// generation, the resolver should return the (unchanged) local key info.
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn generation_mismatch_registry_still_stale_returns_local() {
    let verifier_id = "device-verifier2";
    let verifier_secret = DeviceSecret::generate();
    let verifier_ed25519 = verifier_secret.ed25519_keypair(verifier_id).unwrap();
    let verifier_x25519 = verifier_secret.x25519_keypair(verifier_id).unwrap();
    let verifier_ml_dsa = verifier_secret.ml_dsa_65_keypair(verifier_id).unwrap();
    let verifier_ml_kem = verifier_secret.ml_kem_768_keypair(verifier_id).unwrap();

    let sender_id = "device-sender2";
    let sender_secret = DeviceSecret::generate();
    let sender_ed25519 = sender_secret.ed25519_keypair(sender_id).unwrap();
    let sender_x25519 = sender_secret.x25519_keypair(sender_id).unwrap();
    let sender_ml_dsa_gen0 = sender_secret.ml_dsa_65_keypair(sender_id).unwrap();
    let sender_ml_kem = sender_secret.ml_kem_768_keypair(sender_id).unwrap();

    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    setup_sync_metadata(&storage, verifier_id);

    register_device_in_storage(
        &storage,
        verifier_id,
        &verifier_ed25519.public_key_bytes(),
        &verifier_x25519.public_key_bytes(),
        &verifier_ml_dsa.public_key_bytes(),
        &verifier_ml_kem.public_key_bytes(),
        0,
    );
    register_device_in_storage(
        &storage,
        sender_id,
        &sender_ed25519.public_key_bytes(),
        &sender_x25519.public_key_bytes(),
        &sender_ml_dsa_gen0.public_key_bytes(),
        &sender_ml_kem.public_key_bytes(),
        0,
    );

    // Build signed registry with sender STILL at generation 0
    let entries = vec![
        RegistrySnapshotEntry {
            sync_id: SYNC_ID.to_string(),
            device_id: verifier_id.to_string(),
            ed25519_public_key: verifier_ed25519.public_key_bytes().to_vec(),
            x25519_public_key: verifier_x25519.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: verifier_ml_dsa.public_key_bytes(),
            ml_kem_768_public_key: verifier_ml_kem.public_key_bytes(),
            x_wing_public_key: vec![],
            status: "active".to_string(),
            ml_dsa_key_generation: 0,
            remote_wipe: false,
        },
        RegistrySnapshotEntry {
            sync_id: SYNC_ID.to_string(),
            device_id: sender_id.to_string(),
            ed25519_public_key: sender_ed25519.public_key_bytes().to_vec(),
            x25519_public_key: sender_x25519.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: sender_ml_dsa_gen0.public_key_bytes(),
            ml_kem_768_public_key: sender_ml_kem.public_key_bytes(),
            x_wing_public_key: vec![],
            status: "active".to_string(),
            ml_dsa_key_generation: 0,
            remote_wipe: false,
        },
    ];

    let signed_blob = build_signed_registry_blob(entries, &verifier_secret, verifier_id);

    let relay = Arc::new(MockRelay::new());
    relay.set_signed_registry(SignedRegistryResponse {
        registry_version: 1,
        artifact_blob: signed_blob,
        artifact_kind: "signed_registry_snapshot".to_string(),
    });

    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );

    // Request gen 1 but registry only has gen 0
    let info = engine
        .resolve_sender_keys_with_generation_hint(SYNC_ID, sender_id, Some(1))
        .await
        .expect("should succeed with stale info when registry doesn't have expected gen");

    assert_eq!(
        info.ml_dsa_key_generation, 0,
        "should return generation 0 when registry doesn't have expected generation"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// G4+G5 — Negative tests for registry trust hardening (G1, G2, G3)
// ═══════════════════════════════════════════════════════════════════════════

// ── G1: Revoked devices cannot sign registry ─────────────────────────────

/// A device that is revoked in local storage must not be able to verify
/// a registry snapshot it signed. `verify_and_import_signed_registry` skips
/// revoked devices in the verification loop, so the signature cannot be matched.
#[test]
fn revoked_signer_rejected() {
    let storage = RusqliteSyncStorage::in_memory().unwrap();

    let device_a_id = "device-aaa-revoked";
    let device_secret_a = DeviceSecret::generate();
    let ed25519_a = device_secret_a.ed25519_keypair(device_a_id).unwrap();
    let x25519_a = device_secret_a.x25519_keypair(device_a_id).unwrap();
    let ml_dsa_a = device_secret_a.ml_dsa_65_keypair(device_a_id).unwrap();
    let ml_kem_a = device_secret_a.ml_kem_768_keypair(device_a_id).unwrap();

    // Register device A as active initially
    register_device_in_storage(
        &storage,
        device_a_id,
        &ed25519_a.public_key_bytes(),
        &x25519_a.public_key_bytes(),
        &ml_dsa_a.public_key_bytes(),
        &ml_kem_a.public_key_bytes(),
        0,
    );

    // Build a signed blob using device A's keys (while still active)
    let entries = vec![RegistrySnapshotEntry {
        sync_id: SYNC_ID.to_string(),
        device_id: device_a_id.to_string(),
        ed25519_public_key: ed25519_a.public_key_bytes().to_vec(),
        x25519_public_key: x25519_a.public_key_bytes().to_vec(),
        ml_dsa_65_public_key: ml_dsa_a.public_key_bytes(),
        ml_kem_768_public_key: ml_kem_a.public_key_bytes(),
        x_wing_public_key: vec![],
        status: "active".to_string(),
        ml_dsa_key_generation: 0,
        remote_wipe: false,
    }];
    let signed_blob = build_signed_registry_blob(entries, &device_secret_a, device_a_id);

    // Now revoke device A in local storage
    DeviceRegistryManager::revoke_device(&storage, SYNC_ID, device_a_id)
        .expect("revoke should succeed");

    // Attempt to import the signed blob — must fail because device A is revoked
    let result = DeviceRegistryManager::verify_and_import_signed_registry(
        &storage,
        SYNC_ID,
        &signed_blob,
        None,
    );

    assert!(result.is_err(), "revoked signer should be rejected, but got Ok");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("could not be verified")
            || err_msg.contains("signature could not be verified"),
        "error should mention verification failure, got: {err_msg}"
    );
}

/// A device that marks itself as revoked in the snapshot must be rejected,
/// even if its local record is active and its signature is cryptographically valid.
///
/// This tests the self-consistency check (G1): the signer must appear as
/// non-revoked in their own snapshot.
#[test]
fn signer_self_revoked_in_snapshot_rejected() {
    let storage = RusqliteSyncStorage::in_memory().unwrap();

    let device_a_id = "device-aaa-self-revoked";
    let device_secret_a = DeviceSecret::generate();
    let ed25519_a = device_secret_a.ed25519_keypair(device_a_id).unwrap();
    let x25519_a = device_secret_a.x25519_keypair(device_a_id).unwrap();
    let ml_dsa_a = device_secret_a.ml_dsa_65_keypair(device_a_id).unwrap();
    let ml_kem_a = device_secret_a.ml_kem_768_keypair(device_a_id).unwrap();

    // Register device A as active in local storage (so the signature can be verified)
    register_device_in_storage(
        &storage,
        device_a_id,
        &ed25519_a.public_key_bytes(),
        &x25519_a.public_key_bytes(),
        &ml_dsa_a.public_key_bytes(),
        &ml_kem_a.public_key_bytes(),
        0,
    );

    // Build entries where device A appears with status "revoked" in the snapshot
    let entries = vec![RegistrySnapshotEntry {
        sync_id: SYNC_ID.to_string(),
        device_id: device_a_id.to_string(),
        ed25519_public_key: ed25519_a.public_key_bytes().to_vec(),
        x25519_public_key: x25519_a.public_key_bytes().to_vec(),
        ml_dsa_65_public_key: ml_dsa_a.public_key_bytes(),
        ml_kem_768_public_key: ml_kem_a.public_key_bytes(),
        x_wing_public_key: vec![],
        // Self-contradictory: signing but claiming to be revoked
        status: "revoked".to_string(),
        ml_dsa_key_generation: 0,
        remote_wipe: false,
    }];
    let signed_blob = build_signed_registry_blob(entries, &device_secret_a, device_a_id);

    let result = DeviceRegistryManager::verify_and_import_signed_registry(
        &storage,
        SYNC_ID,
        &signed_blob,
        None,
    );

    assert!(result.is_err(), "self-revoked signer in snapshot should be rejected, but got Ok");
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("revoked"), "error should mention revoked status, got: {err_msg}");
}

/// The signer must be present in their own snapshot. If device A signs the blob
/// but the snapshot only includes device B (omitting A), the import must fail.
///
/// This tests the signer-presence check (G1): omitting the signer from their
/// own snapshot would allow a compromised or removed device to issue fake
/// updates without appearing in the registry.
#[test]
fn signer_missing_from_own_snapshot_rejected() {
    let storage = RusqliteSyncStorage::in_memory().unwrap();

    let device_a_id = "device-aaa-missing";
    let device_secret_a = DeviceSecret::generate();
    let ed25519_a = device_secret_a.ed25519_keypair(device_a_id).unwrap();
    let x25519_a = device_secret_a.x25519_keypair(device_a_id).unwrap();
    let ml_dsa_a = device_secret_a.ml_dsa_65_keypair(device_a_id).unwrap();
    let ml_kem_a = device_secret_a.ml_kem_768_keypair(device_a_id).unwrap();

    let device_b_id = "device-bbb-only";
    let device_secret_b = DeviceSecret::generate();
    let ed25519_b = device_secret_b.ed25519_keypair(device_b_id).unwrap();
    let x25519_b = device_secret_b.x25519_keypair(device_b_id).unwrap();
    let ml_dsa_b = device_secret_b.ml_dsa_65_keypair(device_b_id).unwrap();
    let ml_kem_b = device_secret_b.ml_kem_768_keypair(device_b_id).unwrap();

    // Register device A as active so its keys are known for signature verification
    register_device_in_storage(
        &storage,
        device_a_id,
        &ed25519_a.public_key_bytes(),
        &x25519_a.public_key_bytes(),
        &ml_dsa_a.public_key_bytes(),
        &ml_kem_a.public_key_bytes(),
        0,
    );

    // Build entries that only include device B — device A (the signer) is absent
    let entries = vec![RegistrySnapshotEntry {
        sync_id: SYNC_ID.to_string(),
        device_id: device_b_id.to_string(),
        ed25519_public_key: ed25519_b.public_key_bytes().to_vec(),
        x25519_public_key: x25519_b.public_key_bytes().to_vec(),
        ml_dsa_65_public_key: ml_dsa_b.public_key_bytes(),
        ml_kem_768_public_key: ml_kem_b.public_key_bytes(),
        x_wing_public_key: vec![],
        status: "active".to_string(),
        ml_dsa_key_generation: 0,
        remote_wipe: false,
    }];
    // Sign with device A's keys (A is absent from the snapshot itself)
    let signed_blob = build_signed_registry_blob(entries, &device_secret_a, device_a_id);

    let result = DeviceRegistryManager::verify_and_import_signed_registry(
        &storage,
        SYNC_ID,
        &signed_blob,
        None,
    );

    assert!(result.is_err(), "snapshot missing the signer should be rejected, but got Ok");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("signer not present"),
        "error should mention signer not present in snapshot, got: {err_msg}"
    );
}

/// When no signed registry is available on the relay and a batch arrives from
/// an unknown sender, the engine must remain fail-closed on APPLY (no merge, and
/// it never falls back to the unverified `list_devices` endpoint). With the stall discipline the
/// batch's disposition is a transient stall rather than a skip-and-advance, but
/// the security property — never trust `list_devices`, never apply the unknown
/// sender's ops — is unchanged.
///
/// NOTE: This property is verified by
/// `unknown_sender_with_no_artifact_stalls_without_advancing` (Test 5 above).
/// That test sets up a MockRelay with no signed registry, adds the unknown
/// device to `list_devices`, injects a batch from that device, and asserts that
/// `merged == 0` (the batch is not applied) — directly covering the G2 security
/// property: fail-closed behavior when the signed registry is unavailable.
///
/// The test below is kept as a named alias so the property is easy to find by
/// the G2 label, but the actual assertion is in Test 5.
#[test]
fn malicious_device_list_injection_rejected() {
    // See `unknown_sender_with_no_artifact_stalls_without_advancing` above,
    // which is the authoritative test for G2 fail-closed behavior.
    //
    // Key properties verified there:
    // - MockRelay has no signed registry (`set_signed_registry` not called)
    // - Unknown device is present in `list_devices` only
    // - Engine does not apply the unknown sender's batch (merged == 0)
    // - Data from unknown sender does not appear in entity store
}

// ── G3: registry_version bound into signed payload ────────────────────────

/// Monotonicity check: a relay that replays an older signed registry version
/// should be rejected. Import at version 5, then attempt version 3 — must fail.
#[test]
fn stale_registry_version_rejected() {
    let device_a_id = "device-a-stale";
    let device_secret_a = DeviceSecret::generate();
    let ed25519_kp_a = device_secret_a.ed25519_keypair(device_a_id).unwrap();
    let x25519_kp_a = device_secret_a.x25519_keypair(device_a_id).unwrap();
    let ml_dsa_kp_a = device_secret_a.ml_dsa_65_keypair(device_a_id).unwrap();
    let ml_kem_kp_a = device_secret_a.ml_kem_768_keypair(device_a_id).unwrap();

    let storage = RusqliteSyncStorage::in_memory().unwrap();
    setup_sync_metadata(&storage, "other");
    register_device_in_storage(
        &storage,
        device_a_id,
        &ed25519_kp_a.public_key_bytes(),
        &x25519_kp_a.public_key_bytes(),
        &ml_dsa_kp_a.public_key_bytes(),
        &ml_kem_kp_a.public_key_bytes(),
        0,
    );

    let entries = vec![RegistrySnapshotEntry {
        sync_id: SYNC_ID.into(),
        device_id: device_a_id.into(),
        ed25519_public_key: ed25519_kp_a.public_key_bytes().to_vec(),
        x25519_public_key: x25519_kp_a.public_key_bytes().to_vec(),
        ml_dsa_65_public_key: ml_dsa_kp_a.public_key_bytes(),
        ml_kem_768_public_key: ml_kem_kp_a.public_key_bytes(),
        x_wing_public_key: Vec::new(),
        status: "active".into(),
        ml_dsa_key_generation: 0,
        remote_wipe: false,
    }];

    // Build a signed blob at version 5
    let signing_key = device_secret_a.ed25519_keypair(device_a_id).unwrap();
    let pq_signing_key = device_secret_a.ml_dsa_65_keypair(device_a_id).unwrap();
    let snapshot_v5 = SignedRegistrySnapshot::new_with_epoch_binding(
        entries.clone(),
        5,
        0,
        test_epoch_key_hashes(),
    );
    let blob_v5 = snapshot_v5.sign_hybrid(&signing_key, &pq_signing_key);

    // Import version 5 — should succeed
    let result =
        DeviceRegistryManager::verify_and_import_signed_registry(&storage, SYNC_ID, &blob_v5, None);
    assert!(result.is_ok(), "version 5 import should succeed: {:?}", result.err());
    assert_eq!(result.unwrap(), 5, "should return signed version 5");

    // Build a signed blob at version 3 (stale replay)
    let snapshot_v3 = SignedRegistrySnapshot::new_with_epoch_binding(
        entries.clone(),
        3,
        0,
        test_epoch_key_hashes(),
    );
    let blob_v3 = snapshot_v3.sign_hybrid(&signing_key, &pq_signing_key);

    // Import version 3 with last_imported=5 — must fail
    let result = DeviceRegistryManager::verify_and_import_signed_registry(
        &storage,
        SYNC_ID,
        &blob_v3,
        Some(5),
    );
    assert!(result.is_err(), "stale version 3 should be rejected when 5 was already imported");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("stale"), "error should mention staleness: {err}");

    // Build a signed blob at version 7 (newer) — should succeed
    let snapshot_v7 =
        SignedRegistrySnapshot::new_with_epoch_binding(entries, 7, 0, test_epoch_key_hashes());
    let blob_v7 = snapshot_v7.sign_hybrid(&signing_key, &pq_signing_key);

    let result = DeviceRegistryManager::verify_and_import_signed_registry(
        &storage,
        SYNC_ID,
        &blob_v7,
        Some(5),
    );
    assert!(result.is_ok(), "newer version 7 should succeed: {:?}", result.err());
    assert_eq!(result.unwrap(), 7, "should return signed version 7");
}

#[test]
fn signed_registry_import_requires_epoch_binding_at_version_floor() {
    let device_a_id = "device-a-binding-required";
    let device_secret_a = DeviceSecret::generate();
    let ed25519_kp_a = device_secret_a.ed25519_keypair(device_a_id).unwrap();
    let x25519_kp_a = device_secret_a.x25519_keypair(device_a_id).unwrap();
    let ml_dsa_kp_a = device_secret_a.ml_dsa_65_keypair(device_a_id).unwrap();
    let ml_kem_kp_a = device_secret_a.ml_kem_768_keypair(device_a_id).unwrap();

    let storage = RusqliteSyncStorage::in_memory().unwrap();
    setup_sync_metadata(&storage, "other");
    register_device_in_storage(
        &storage,
        device_a_id,
        &ed25519_kp_a.public_key_bytes(),
        &x25519_kp_a.public_key_bytes(),
        &ml_dsa_kp_a.public_key_bytes(),
        &ml_kem_kp_a.public_key_bytes(),
        0,
    );

    let entries = vec![RegistrySnapshotEntry {
        sync_id: SYNC_ID.into(),
        device_id: device_a_id.into(),
        ed25519_public_key: ed25519_kp_a.public_key_bytes().to_vec(),
        x25519_public_key: x25519_kp_a.public_key_bytes().to_vec(),
        ml_dsa_65_public_key: ml_dsa_kp_a.public_key_bytes(),
        ml_kem_768_public_key: ml_kem_kp_a.public_key_bytes(),
        x_wing_public_key: Vec::new(),
        status: "active".into(),
        ml_dsa_key_generation: 0,
        remote_wipe: false,
    }];

    let signing_key = device_secret_a.ed25519_keypair(device_a_id).unwrap();
    let pq_signing_key = device_secret_a.ml_dsa_65_keypair(device_a_id).unwrap();
    let blob = SignedRegistrySnapshot::new(entries, 1).sign_hybrid(&signing_key, &pq_signing_key);

    let result =
        DeviceRegistryManager::verify_and_import_signed_registry(&storage, SYNC_ID, &blob, None);
    assert!(result.is_err(), "version-floor import without epoch binding should fail");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("requires non-empty epoch_key_hashes"), "unexpected error: {err}");
}

// ── G2: bootstrap fail-closed for unknown snapshot senders ───────────────

/// When a snapshot on the relay was signed by a device that is not known
/// locally (and no signed registry resolves it), bootstrap must fail rather
/// than silently importing untrusted data.
///
/// This tests the fail-closed property (G2) applied to the pairing bootstrap
/// path: unknown snapshot sender → resolve_sender_public_key fails →
/// bootstrap_from_snapshot returns Err.
#[tokio::test]
async fn bootstrap_from_snapshot_fail_closed() {
    use prism_sync_core::relay::traits::SnapshotExchange as _;

    let key_hierarchy = init_key_hierarchy();

    // Device A: the local device (will attempt bootstrap)
    let device_a_id = "device-aaa-bootstrap";
    let signing_key_a = make_signing_key();
    let ml_dsa_a = make_ml_dsa_keypair();

    // Device X: an unknown device that uploaded the snapshot but is not in
    // local storage and no signed registry is available to resolve it.
    let device_x_id = "device-xxx-unknown";
    let signing_key_x = make_signing_key();

    let relay = Arc::new(MockRelay::new());
    // No signed registry set — relay.get_signed_registry() returns Ok(None).

    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    setup_sync_metadata(&storage, device_a_id);

    // Register device A locally (not device X — it remains unknown)
    register_device(&relay, &storage, device_a_id, &signing_key_a.verifying_key());

    // Build a minimal snapshot envelope signed by device X.
    // We use an empty plaintext — the bootstrap will fail before decryption.
    let hlc = Hlc::now(device_x_id, None);
    let ops = vec![CrdtChange {
        op_id: format!("tasks:task-1:title:{}:{}", hlc, device_x_id),
        batch_id: Some("batch-x1".to_string()),
        entity_id: "task-1".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Secret data from unknown device\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: device_x_id.to_string(),
        epoch: 0,
        server_seq: None,
    }];

    let snapshot_envelope = make_encrypted_batch(
        &ops,
        &key_hierarchy,
        &signing_key_x,
        &ml_dsa_a, // uses device A's ML-DSA key just to build a valid envelope shape
        "batch-x1",
        device_x_id,
    );

    // Upload the snapshot to MockRelay (signed by the unknown device X)
    relay
        .put_snapshot(
            0,
            1,
            serde_json::to_vec(&snapshot_envelope).unwrap(),
            None,
            None,
            device_x_id.to_string(),
            None,
        )
        .await
        .unwrap();

    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );

    // Bootstrap must fail because device X is unknown and no signed registry
    // is available to resolve it (fail-closed behavior).
    let result = engine.bootstrap_from_snapshot(SYNC_ID, &key_hierarchy).await;

    assert!(result.is_err(), "bootstrap from snapshot by unknown sender should fail (fail closed)");

    // Verify the entity store remains empty — no data imported
    let title = entity.get_field("task-1", "title");
    assert_eq!(title, None, "data from unknown snapshot sender should not be imported");
}

// ═══════════════════════════════════════════════════════════════════════════
// G7: Integration — hybrid batch roundtrip with verified registry
//
// NOTE: The full round-trip integration test for G7 is already covered by
// `registry_verification_verified_import_happy_path` (Test 1 above), which:
//   1. Creates two devices (A and B) with ML-DSA keys
//   2. Builds and signs a registry snapshot containing both devices
//   3. Sets it on MockRelay
//   4. Device A creates a SyncEngine and calls sync()
//   5. The engine fetches the signed registry, verifies it, imports B's keys,
//      verifies B's batch signature, and merges B's ops
//   6. Asserts: merged > 0, B's data is present in the entity store, and
//      B's device record is in local storage
//
// The test below explicitly documents the G7 property and verifies that
// `resolve_sender_keys_with_generation_hint` resolves a newly imported device
// after a signed registry import — covering the key resolution integration path.
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn hybrid_batch_roundtrip_with_verified_registry() {
    // Full round-trip is covered by `registry_verification_verified_import_happy_path`.
    //
    // This test additionally verifies that after a verified registry import,
    // the local key resolver can find the newly imported device's keys —
    // confirming the integration between verify_and_import_signed_registry
    // and resolve_sender_keys_with_generation_hint.

    let device_a_id = "device-aaa-g7";
    let device_secret_a = DeviceSecret::generate();
    let ed25519_a = device_secret_a.ed25519_keypair(device_a_id).unwrap();
    let x25519_a = device_secret_a.x25519_keypair(device_a_id).unwrap();
    let ml_dsa_a = device_secret_a.ml_dsa_65_keypair(device_a_id).unwrap();
    let ml_kem_a = device_secret_a.ml_kem_768_keypair(device_a_id).unwrap();

    let device_b_id = "device-bbb-g7";
    let device_secret_b = DeviceSecret::generate();
    let ed25519_b = device_secret_b.ed25519_keypair(device_b_id).unwrap();
    let x25519_b = device_secret_b.x25519_keypair(device_b_id).unwrap();
    let ml_dsa_b = device_secret_b.ml_dsa_65_keypair(device_b_id).unwrap();
    let ml_kem_b = device_secret_b.ml_kem_768_keypair(device_b_id).unwrap();

    let entries = vec![
        RegistrySnapshotEntry {
            sync_id: SYNC_ID.to_string(),
            device_id: device_a_id.to_string(),
            ed25519_public_key: ed25519_a.public_key_bytes().to_vec(),
            x25519_public_key: x25519_a.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: ml_dsa_a.public_key_bytes(),
            ml_kem_768_public_key: ml_kem_a.public_key_bytes(),
            x_wing_public_key: vec![],
            status: "active".to_string(),
            ml_dsa_key_generation: 0,
            remote_wipe: false,
        },
        RegistrySnapshotEntry {
            sync_id: SYNC_ID.to_string(),
            device_id: device_b_id.to_string(),
            ed25519_public_key: ed25519_b.public_key_bytes().to_vec(),
            x25519_public_key: x25519_b.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: ml_dsa_b.public_key_bytes(),
            ml_kem_768_public_key: ml_kem_b.public_key_bytes(),
            x_wing_public_key: vec![],
            status: "active".to_string(),
            ml_dsa_key_generation: 0,
            remote_wipe: false,
        },
    ];

    let signed_blob = build_signed_registry_blob(entries, &device_secret_a, device_a_id);

    let relay = Arc::new(MockRelay::new());
    relay.set_signed_registry(SignedRegistryResponse {
        registry_version: 1,
        artifact_blob: signed_blob,
        artifact_kind: "signed_registry_snapshot".to_string(),
    });

    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    setup_sync_metadata(&storage, device_a_id);

    // Register only device A locally — B is unknown until registry is imported
    register_device_in_storage(
        &storage,
        device_a_id,
        &ed25519_a.public_key_bytes(),
        &x25519_a.public_key_bytes(),
        &ml_dsa_a.public_key_bytes(),
        &ml_kem_a.public_key_bytes(),
        0,
    );

    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );

    // After the signed registry is imported, device B's keys should be resolvable.
    // The engine fetches the signed registry lazily; we trigger it by calling
    // resolve_sender_keys_with_generation_hint for device B.
    let info = engine
        .resolve_sender_keys_with_generation_hint(SYNC_ID, device_b_id, Some(0))
        .await
        .expect("device B should be resolved after verified registry import");

    assert_eq!(
        info.ed25519_pk,
        ed25519_b.public_key_bytes(),
        "Ed25519 public key for device B should match after registry import"
    );
    assert_eq!(
        info.ml_dsa_65_pk,
        ml_dsa_b.public_key_bytes(),
        "ML-DSA public key for device B should match after registry import"
    );
    assert_eq!(info.ml_dsa_key_generation, 0, "ML-DSA generation for device B should be 0");

    // Verify device B is now in local storage (imported from the signed registry)
    let device_b_record = storage
        .get_device_record(SYNC_ID, device_b_id)
        .unwrap()
        .expect("device B should be in local storage after verified import");
    assert_eq!(device_b_record.status, "active");
}

// ═══════════════════════════════════════════════════════════════════════════
// ML-DSA key-rotation race — stale-generation stall + archived key history
// ═══════════════════════════════════════════════════════════════════════════

/// A pre-rotation gen-0 batch that is still unpulled when the receiver imports
/// the gen-1 registry must verify against the ARCHIVED gen-0 key from
/// device_key_history and apply — not be lost because the receiver now only
/// holds the gen-1 key. This is the core key-history mechanism: a verified
/// import that supersedes a device's generation archives the outgoing key.
#[tokio::test]
async fn f16_pre_rotation_batch_verifies_against_archived_key() {
    let key_hierarchy = init_key_hierarchy();

    let verifier_id = "device-verifier";
    let verifier_secret = DeviceSecret::generate();

    let sender_id = "device-sender";
    let sender_secret = DeviceSecret::generate();
    let sender_ed25519 = sender_secret.ed25519_keypair(sender_id).unwrap();
    let sender_x25519 = sender_secret.x25519_keypair(sender_id).unwrap();
    let sender_ml_dsa_gen0 = sender_secret.ml_dsa_65_keypair(sender_id).unwrap();
    let sender_ml_dsa_gen1 = sender_secret.ml_dsa_65_keypair_v(sender_id, 1).unwrap();
    let sender_ml_kem = sender_secret.ml_kem_768_keypair(sender_id).unwrap();

    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    setup_sync_metadata(&storage, verifier_id);

    // Verifier knows the sender at gen 0 (pre-rotation).
    register_device_in_storage(
        &storage,
        verifier_id,
        &verifier_secret.ed25519_keypair(verifier_id).unwrap().public_key_bytes(),
        &verifier_secret.x25519_keypair(verifier_id).unwrap().public_key_bytes(),
        &verifier_secret.ml_dsa_65_keypair(verifier_id).unwrap().public_key_bytes(),
        &verifier_secret.ml_kem_768_keypair(verifier_id).unwrap().public_key_bytes(),
        0,
    );
    register_device_in_storage(
        &storage,
        sender_id,
        &sender_ed25519.public_key_bytes(),
        &sender_x25519.public_key_bytes(),
        &sender_ml_dsa_gen0.public_key_bytes(),
        &sender_ml_kem.public_key_bytes(),
        0,
    );

    // The sender pushed a gen-0 batch BEFORE rotating. It is still unpulled.
    let sender_ed25519_pk = sender_ed25519.public_key_bytes().to_vec();
    let signing_key_sender = sender_ed25519.into_signing_key();
    let hlc = Hlc::now(sender_id, None);
    let ops = vec![CrdtChange {
        op_id: format!("tasks:task-pre:title:{}:{}", hlc, sender_id),
        batch_id: Some("batch-pre-rotation".to_string()),
        entity_id: "task-pre".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Signed at gen 0\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: sender_id.to_string(),
        epoch: 0,
        server_seq: None,
    }];
    let envelope = make_encrypted_batch_at_generation(
        &ops,
        &key_hierarchy,
        &signing_key_sender,
        &sender_ml_dsa_gen0,
        "batch-pre-rotation",
        sender_id,
        0,
    );

    let relay = Arc::new(MockRelay::new());
    let seq = relay.inject_batch(envelope);

    // The verifier imports a signed registry advancing the sender to gen 1 —
    // this is what archives the gen-0 key into device_key_history.
    let entries = vec![
        RegistrySnapshotEntry {
            sync_id: SYNC_ID.to_string(),
            device_id: verifier_id.to_string(),
            ed25519_public_key: verifier_secret
                .ed25519_keypair(verifier_id)
                .unwrap()
                .public_key_bytes()
                .to_vec(),
            x25519_public_key: verifier_secret
                .x25519_keypair(verifier_id)
                .unwrap()
                .public_key_bytes()
                .to_vec(),
            ml_dsa_65_public_key: verifier_secret
                .ml_dsa_65_keypair(verifier_id)
                .unwrap()
                .public_key_bytes(),
            ml_kem_768_public_key: verifier_secret
                .ml_kem_768_keypair(verifier_id)
                .unwrap()
                .public_key_bytes(),
            x_wing_public_key: vec![],
            status: "active".to_string(),
            ml_dsa_key_generation: 0,
            remote_wipe: false,
        },
        RegistrySnapshotEntry {
            sync_id: SYNC_ID.to_string(),
            device_id: sender_id.to_string(),
            ed25519_public_key: sender_ed25519_pk.clone(),
            x25519_public_key: sender_x25519.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: sender_ml_dsa_gen1.public_key_bytes(),
            ml_kem_768_public_key: sender_ml_kem.public_key_bytes(),
            x_wing_public_key: vec![],
            status: "active".to_string(),
            ml_dsa_key_generation: 1,
            remote_wipe: false,
        },
    ];
    let signed_blob = build_signed_registry_blob(entries, &verifier_secret, verifier_id);

    let verifier_signing = verifier_secret.ed25519_keypair(verifier_id).unwrap().into_signing_key();
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();
    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );

    // Resolve with the gen-1 hint via the registry import — this advances the
    // sender's record to gen 1 AND archives the gen-0 key.
    relay.set_signed_registry(SignedRegistryResponse {
        registry_version: 1,
        artifact_blob: signed_blob,
        artifact_kind: "signed_registry_snapshot".to_string(),
    });
    engine
        .resolve_sender_keys_with_generation_hint(SYNC_ID, sender_id, Some(1))
        .await
        .expect("registry import to gen 1 should succeed");

    assert_eq!(
        storage.get_device_record(SYNC_ID, sender_id).unwrap().unwrap().ml_dsa_key_generation,
        1,
        "sender record advanced to gen 1"
    );
    let archived = storage
        .get_archived_device_key(SYNC_ID, sender_id, 0)
        .unwrap()
        .expect("gen-0 key must be archived when the record advanced to gen 1");
    assert_eq!(
        archived,
        sender_ml_dsa_gen0.public_key_bytes(),
        "archived gen-0 key must equal the original gen-0 key"
    );

    // Now pull: the gen-0 batch verifies against the archived gen-0 key (current
    // record is gen 1) and applies, instead of being lost.
    let r = engine
        .sync(SYNC_ID, &key_hierarchy, &verifier_signing, None, verifier_id, 0)
        .await
        .unwrap();
    assert!(r.error.is_none(), "{:?}", r.error);
    assert_eq!(
        entity.get_field("task-pre", "title"),
        Some(SyncValue::String("Signed at gen 0".to_string())),
        "the pre-rotation gen-0 batch must apply via the archived gen-0 key"
    );
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        seq,
        "cursor advances once the batch applies"
    );
}

/// A malicious enrolled device claiming a bogus future generation (gen 999) that
/// no registry will ever satisfy must NOT wedge the group: it stalls for exactly
/// the retry budget, then converts to a replayable `stale_key_generation`
/// quarantine and the cursor advances. Nothing from the batch is ever applied
/// (fail-closed).
#[tokio::test]
async fn f16_malicious_future_generation_stalls_then_quarantines() {
    let key_hierarchy = init_key_hierarchy();

    let verifier_id = "device-verifier";
    let verifier_secret = DeviceSecret::generate();
    let verifier_signing =
        verifier_secret.ed25519_keypair(verifier_id).unwrap().into_signing_key();

    let attacker_id = "device-attacker";
    let attacker_secret = DeviceSecret::generate();
    let attacker_ed25519 = attacker_secret.ed25519_keypair(attacker_id).unwrap();
    let attacker_ml_dsa = attacker_secret.ml_dsa_65_keypair(attacker_id).unwrap();

    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    setup_sync_metadata(&storage, verifier_id);
    register_device_in_storage(
        &storage,
        verifier_id,
        &verifier_secret.ed25519_keypair(verifier_id).unwrap().public_key_bytes(),
        &verifier_secret.x25519_keypair(verifier_id).unwrap().public_key_bytes(),
        &verifier_secret.ml_dsa_65_keypair(verifier_id).unwrap().public_key_bytes(),
        &verifier_secret.ml_kem_768_keypair(verifier_id).unwrap().public_key_bytes(),
        0,
    );
    register_device_in_storage(
        &storage,
        attacker_id,
        &attacker_ed25519.public_key_bytes(),
        &attacker_secret.x25519_keypair(attacker_id).unwrap().public_key_bytes(),
        &attacker_ml_dsa.public_key_bytes(),
        &attacker_secret.ml_kem_768_keypair(attacker_id).unwrap().public_key_bytes(),
        0,
    );

    // Envelope claims gen 999 (signed at gen 999, but no registry ever has it).
    let attacker_ml_dsa_gen999 = attacker_secret.ml_dsa_65_keypair_v(attacker_id, 999).unwrap();
    let signing_key_attacker = attacker_ed25519.into_signing_key();
    let hlc = Hlc::now(attacker_id, None);
    let ops = vec![CrdtChange {
        op_id: format!("tasks:task-mal:title:{}:{}", hlc, attacker_id),
        batch_id: Some("batch-malicious".to_string()),
        entity_id: "task-mal".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Should never apply\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: attacker_id.to_string(),
        epoch: 0,
        server_seq: None,
    }];
    let envelope = make_encrypted_batch_at_generation(
        &ops,
        &key_hierarchy,
        &signing_key_attacker,
        &attacker_ml_dsa_gen999,
        "batch-malicious",
        attacker_id,
        999,
    );

    let relay = Arc::new(MockRelay::new());
    let seq = relay.inject_batch(envelope);

    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();
    // Tight budget so the conversion happens on the 2nd cycle. Disable replay
    // backoff so the quarantine row is replay-eligible every cycle (and stays
    // quarantined because the gen-999 key never resolves).
    let engine = SyncEngine::new(
        storage.clone(),
        relay,
        vec![entity_ref],
        test_schema(),
        SyncConfig {
            pull_stall_max_attempts: 2,
            quarantine_replay_backoff_base_ms: 0,
            ..SyncConfig::default()
        },
    );

    // Cycle 1: stall (attempt 1), cursor frozen.
    let r1 = engine
        .sync(SYNC_ID, &key_hierarchy, &verifier_signing, None, verifier_id, 0)
        .await
        .unwrap();
    assert!(r1.error.is_none(), "{:?}", r1.error);
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        0,
        "cursor frozen while a bogus future generation stalls"
    );
    let stalls = storage.list_pull_stalls(SYNC_ID).unwrap();
    assert_eq!(stalls.len(), 1);
    assert_eq!(stalls[0].reason, "stale_key_generation");
    assert!(storage.list_quarantined_pull_batches(SYNC_ID).unwrap().is_empty());

    // Cycle 2: attempt 2 hits the budget -> quarantine-and-advance.
    let r2 = engine
        .sync(SYNC_ID, &key_hierarchy, &verifier_signing, None, verifier_id, 0)
        .await
        .unwrap();
    assert!(r2.error.is_none(), "{:?}", r2.error);
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        seq,
        "cursor advances once the bogus-generation batch is durably quarantined"
    );
    let quarantined = storage.list_quarantined_pull_batches(SYNC_ID).unwrap();
    assert_eq!(quarantined.len(), 1, "batch durably quarantined, not dropped");
    assert_eq!(quarantined[0].reason, "stale_key_generation");
    assert!(
        storage.list_pull_stalls(SYNC_ID).unwrap().is_empty(),
        "stall row cleared on conversion"
    );
    assert_eq!(
        entity.get_field("task-mal", "title"),
        None,
        "a bogus-generation batch is never applied (fail closed)"
    );

    // Cycle 3: replay re-attempts, the gen-999 key still never resolves -> stays
    // quarantined, retry backs off, group is not wedged.
    let r3 = engine
        .sync(SYNC_ID, &key_hierarchy, &verifier_signing, None, verifier_id, 0)
        .await
        .unwrap();
    assert!(r3.error.is_none(), "{:?}", r3.error);
    assert_eq!(
        storage.list_quarantined_pull_batches(SYNC_ID).unwrap().len(),
        1,
        "still quarantined while the bogus generation is unresolvable"
    );
    assert_eq!(entity.get_field("task-mal", "title"), None);
}

/// A genuine not-yet-propagated rotation whose stall exhausts the budget
/// converts to a replayable `stale_key_generation` quarantine; once the gen-1
/// registry imports, Phase 0b replay verifies against it and applies the batch
/// — the data is restored losslessly even after the cursor advanced.
#[tokio::test]
async fn f16_stale_generation_budget_exhaustion_quarantines_then_replay_applies() {
    let key_hierarchy = init_key_hierarchy();

    let verifier_id = "device-verifier";
    let verifier_secret = DeviceSecret::generate();
    let verifier_signing =
        verifier_secret.ed25519_keypair(verifier_id).unwrap().into_signing_key();

    let sender_id = "device-sender";
    let sender_secret = DeviceSecret::generate();
    let sender_ed25519 = sender_secret.ed25519_keypair(sender_id).unwrap();
    let sender_x25519 = sender_secret.x25519_keypair(sender_id).unwrap();
    let sender_ml_dsa_gen0 = sender_secret.ml_dsa_65_keypair(sender_id).unwrap();
    let sender_ml_dsa_gen1 = sender_secret.ml_dsa_65_keypair_v(sender_id, 1).unwrap();
    let sender_ml_kem = sender_secret.ml_kem_768_keypair(sender_id).unwrap();

    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    setup_sync_metadata(&storage, verifier_id);
    register_device_in_storage(
        &storage,
        verifier_id,
        &verifier_secret.ed25519_keypair(verifier_id).unwrap().public_key_bytes(),
        &verifier_secret.x25519_keypair(verifier_id).unwrap().public_key_bytes(),
        &verifier_secret.ml_dsa_65_keypair(verifier_id).unwrap().public_key_bytes(),
        &verifier_secret.ml_kem_768_keypair(verifier_id).unwrap().public_key_bytes(),
        0,
    );
    // Verifier knows the sender at gen 0.
    register_device_in_storage(
        &storage,
        sender_id,
        &sender_ed25519.public_key_bytes(),
        &sender_x25519.public_key_bytes(),
        &sender_ml_dsa_gen0.public_key_bytes(),
        &sender_ml_kem.public_key_bytes(),
        0,
    );

    // The sender rotated and pushed a gen-1 batch.
    let sender_ed25519_pk = sender_ed25519.public_key_bytes().to_vec();
    let signing_key_sender = sender_ed25519.into_signing_key();
    let hlc = Hlc::now(sender_id, None);
    let ops = vec![CrdtChange {
        op_id: format!("tasks:task-rot:title:{}:{}", hlc, sender_id),
        batch_id: Some("batch-rotated".to_string()),
        entity_id: "task-rot".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Edit after rotation\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: sender_id.to_string(),
        epoch: 0,
        server_seq: None,
    }];
    let envelope = make_encrypted_batch_at_generation(
        &ops,
        &key_hierarchy,
        &signing_key_sender,
        &sender_ml_dsa_gen1,
        "batch-rotated",
        sender_id,
        1,
    );

    let relay = Arc::new(MockRelay::new());
    let seq = relay.inject_batch(envelope);

    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();
    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig {
            pull_stall_max_attempts: 2,
            quarantine_replay_backoff_base_ms: 0,
            ..SyncConfig::default()
        },
    );

    // No registry set: gen 1 > local gen 0 and no refresh succeeds -> stall.
    let r1 = engine
        .sync(SYNC_ID, &key_hierarchy, &verifier_signing, None, verifier_id, 0)
        .await
        .unwrap();
    assert!(r1.error.is_none(), "{:?}", r1.error);
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        0,
        "cursor frozen on attempt 1"
    );

    // Cycle 2: budget hit -> quarantine + advance.
    let r2 = engine
        .sync(SYNC_ID, &key_hierarchy, &verifier_signing, None, verifier_id, 0)
        .await
        .unwrap();
    assert!(r2.error.is_none(), "{:?}", r2.error);
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        seq,
        "cursor advances once durably quarantined"
    );
    let quarantined = storage.list_quarantined_pull_batches(SYNC_ID).unwrap();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].reason, "stale_key_generation");
    assert_eq!(entity.get_field("task-rot", "title"), None, "fail closed until keys propagate");

    // Make the gen-1 registry available, then sync: Phase 0b replay imports the
    // gen-1 key, verifies the quarantined batch against it, and applies.
    let entries = vec![
        RegistrySnapshotEntry {
            sync_id: SYNC_ID.to_string(),
            device_id: verifier_id.to_string(),
            ed25519_public_key: verifier_secret
                .ed25519_keypair(verifier_id)
                .unwrap()
                .public_key_bytes()
                .to_vec(),
            x25519_public_key: verifier_secret
                .x25519_keypair(verifier_id)
                .unwrap()
                .public_key_bytes()
                .to_vec(),
            ml_dsa_65_public_key: verifier_secret
                .ml_dsa_65_keypair(verifier_id)
                .unwrap()
                .public_key_bytes(),
            ml_kem_768_public_key: verifier_secret
                .ml_kem_768_keypair(verifier_id)
                .unwrap()
                .public_key_bytes(),
            x_wing_public_key: vec![],
            status: "active".to_string(),
            ml_dsa_key_generation: 0,
            remote_wipe: false,
        },
        RegistrySnapshotEntry {
            sync_id: SYNC_ID.to_string(),
            device_id: sender_id.to_string(),
            ed25519_public_key: sender_ed25519_pk.clone(),
            x25519_public_key: sender_x25519.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: sender_ml_dsa_gen1.public_key_bytes(),
            ml_kem_768_public_key: sender_ml_kem.public_key_bytes(),
            x_wing_public_key: vec![],
            status: "active".to_string(),
            ml_dsa_key_generation: 1,
            remote_wipe: false,
        },
    ];
    let signed_blob = build_signed_registry_blob(entries, &verifier_secret, verifier_id);
    relay.set_signed_registry(SignedRegistryResponse {
        registry_version: 1,
        artifact_blob: signed_blob,
        artifact_kind: "signed_registry_snapshot".to_string(),
    });

    let r3 = engine
        .sync(SYNC_ID, &key_hierarchy, &verifier_signing, None, verifier_id, 0)
        .await
        .unwrap();
    assert!(r3.error.is_none(), "{:?}", r3.error);
    assert_eq!(
        entity.get_field("task-rot", "title"),
        Some(SyncValue::String("Edit after rotation".to_string())),
        "Phase 0b replay restores the rotated sender's data once gen-1 imports"
    );
    assert!(
        storage.list_quarantined_pull_batches(SYNC_ID).unwrap().is_empty(),
        "quarantine row deleted after a successful replay"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// One-way-sync liveness: sender-level pull-health tracking
//
// The per-seq `pull_stall` / `quarantined_pull_batches` rows answer "is THIS
// server_seq stuck?". `pull_sender_health` answers the asymmetric one-way
// question: "is a given PEER's inbound stream persistently failing to apply
// while our push to the group still succeeds?". These tests reproduce that
// symptom and prove the diagnostics identify the broken sender and reason, and
// that recovery clears the state.
// ═══════════════════════════════════════════════════════════════════════════

/// Find the single sender-health row for `(sender, reason)`, failing the test
/// with the full table dumped if it is absent.
fn sender_health_row(
    storage: &RusqliteSyncStorage,
    sender: &str,
    reason: &str,
) -> prism_sync_core::storage::PullSenderHealth {
    let rows = storage.list_pull_sender_health(SYNC_ID).unwrap();
    rows.iter()
        .find(|h| h.sender_device_id == sender && h.reason == reason)
        .cloned()
        .unwrap_or_else(|| panic!("no pull_sender_health for ({sender}, {reason}); rows: {rows:?}"))
}

/// A persistently-unresolvable sender produces a rolling per-cycle stall stream:
/// each sync cycle re-stalls the same batch and bumps the sender-level
/// `live_stall_count`, so the broken peer is attributable instead of looking
/// like ordinary transient retries. Cursor stays frozen and nothing applies
/// (fail-closed), and no quarantine forms while the batch is within budget.
#[tokio::test]
async fn rolling_sender_stalls_are_sender_tracked() {
    // Default budget (8 attempts) so three cycles all stay within budget and
    // keep stalling live rather than converting to quarantine.
    let mut f = setup_f13_fixture();

    // No signed registry set: get_signed_registry returns Ok(None) every cycle,
    // an ambiguous transient verdict -> stall.
    for _ in 0..3 {
        let r = f
            .engine
            .sync(SYNC_ID, &f.key_hierarchy, &f.signing_key_a, None, f.device_a_id, 0)
            .await
            .unwrap();
        assert!(r.error.is_none(), "stall is non-fatal: {:?}", r.error);
    }

    // The sender-level rollup accumulated one live stall per cycle.
    let health = sender_health_row(&f.storage, f.device_b_id, "sender_unresolved");
    assert_eq!(health.live_stall_count, 3, "one live stall accrued per cycle");
    assert_eq!(health.quarantined_batch_count, 0, "still within budget — no quarantine yet");
    assert!(health.last_error.is_some(), "last resolution error captured for diagnostics");

    // Fail-closed: cursor frozen, B's data never applied, batch not yet quarantined.
    assert_eq!(
        f.storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        0,
        "cursor frozen across the rolling stalls"
    );
    assert_eq!(f.entity.get_field("task-1", "title"), None, "nothing applied (fail closed)");
    assert!(f.storage.list_quarantined_pull_batches(SYNC_ID).unwrap().is_empty());

    // The app sees a sender-level liveness signal, not just per-seq stalls.
    let events = drain_pull_sender_stalled(&mut f.event_rx);
    assert!(
        events.iter().any(|(s, r, live, _)| s == f.device_b_id
            && r == "sender_unresolved"
            && *live >= 1),
        "expected a PullSenderStalled for device B; got {events:?}"
    );
}

/// While a peer's inbound batch stalls and never applies, this device's own push
/// to the group still succeeds — the asymmetric one-way symptom. A single cycle
/// proves both halves: A's pending op is pushed while B's batch stalls, never
/// applies, and a sender-level liveness event is emitted.
#[tokio::test]
async fn device_a_pushes_while_device_b_inbound_stalls() {
    let mut f = setup_f13_fixture();

    // Give device A a local pending op so the push phase has something to send.
    let hlc_a = Hlc::now(f.device_a_id, None);
    let op_a = CrdtChange {
        op_id: format!("tasks:task-a:title:{}:{}", hlc_a, f.device_a_id),
        batch_id: Some("batch-a1".to_string()),
        entity_id: "task-a".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Hello from A\"".to_string(),
        client_hlc: hlc_a.to_string(),
        is_delete: false,
        device_id: f.device_a_id.to_string(),
        epoch: 0,
        server_seq: None,
    };
    insert_pending_ops(&f.storage, std::slice::from_ref(&op_a), "batch-a1");

    // One cycle: B is the unknown sender (no registry) -> pull stalls; push runs.
    let r = f
        .engine
        .sync(SYNC_ID, &f.key_hierarchy, &f.signing_key_a, Some(&f.ml_dsa_a), f.device_a_id, 0)
        .await
        .unwrap();
    assert!(r.error.is_none(), "asymmetric cycle is non-fatal: {:?}", r.error);

    // Outbound (push) succeeded.
    assert!(
        !f.relay.push_call_batch_ids().is_empty(),
        "device A's push must run even while device B's inbound batch stalls"
    );
    assert!(r.pushed >= 1, "A's pending op was pushed: {r:?}");

    // Inbound (pull) stalled — fail-closed, nothing from B applied.
    assert_eq!(f.entity.get_field("task-1", "title"), None, "B's batch did not apply");
    assert_eq!(
        f.storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        0,
        "cursor held behind B's stalled batch"
    );
    let health = sender_health_row(&f.storage, f.device_b_id, "sender_unresolved");
    assert_eq!(health.live_stall_count, 1);

    // The degraded-inbound signal is surfaced.
    let events = drain_pull_sender_stalled(&mut f.event_rx);
    assert!(
        events.iter().any(|(s, _, _, _)| s == f.device_b_id),
        "expected a PullSenderStalled for device B; got {events:?}"
    );
}

/// Budget exhaustion converts the stall to a durable quarantine and the
/// sender-level `quarantined_batch_count` records it. Once the registry imports
/// and Phase 0b replay applies the batch, the sender's health is cleared and a
/// `PullSenderRecovered` is emitted — the inverse signal.
#[tokio::test]
async fn sender_health_tracks_quarantine_then_recovery() {
    let mut f = setup_f13_fixture_with_config(SyncConfig {
        pull_stall_max_attempts: 2,
        quarantine_replay_backoff_base_ms: 0,
        ..SyncConfig::default()
    });

    // Cycle 1: stall (attempt 1) -> live_stall_count = 1.
    f.engine
        .sync(SYNC_ID, &f.key_hierarchy, &f.signing_key_a, None, f.device_a_id, 0)
        .await
        .unwrap();
    // Cycle 2: attempt 2 hits the budget -> quarantine-and-advance.
    f.engine
        .sync(SYNC_ID, &f.key_hierarchy, &f.signing_key_a, None, f.device_a_id, 0)
        .await
        .unwrap();

    let health = sender_health_row(&f.storage, f.device_b_id, "sender_unresolved");
    assert_eq!(health.live_stall_count, 1, "one within-budget live stall before conversion");
    assert_eq!(health.quarantined_batch_count, 1, "the conversion is tallied per sender");

    // The per-sender quarantine drill-down sees B's unapplied backlog.
    let by_sender = f
        .storage
        .list_quarantined_pull_batches_by_sender(SYNC_ID, f.device_b_id)
        .unwrap();
    assert_eq!(by_sender.len(), 1);
    assert_eq!(by_sender[0].reason, "sender_unresolved");

    // The quarantine-conversion cycle surfaced a sender-level event carrying the
    // quarantine count.
    let stalled = drain_pull_sender_stalled(&mut f.event_rx);
    assert!(
        stalled.iter().any(|(s, _, _, q)| s == f.device_b_id && *q == 1),
        "expected PullSenderStalled with quarantined_batch_count=1; got {stalled:?}"
    );

    // Make the sender resolvable, then sync: Phase 0b replay applies the batch.
    f.relay.set_signed_registry(SignedRegistryResponse {
        registry_version: 1,
        artifact_blob: f.signed_blob.clone(),
        artifact_kind: "signed_registry_snapshot".to_string(),
    });
    f.engine
        .sync(SYNC_ID, &f.key_hierarchy, &f.signing_key_a, None, f.device_a_id, 0)
        .await
        .unwrap();

    assert_eq!(
        f.entity.get_field("task-1", "title"),
        Some(SyncValue::String("Hello from B".to_string())),
        "Phase 0b replay applied B's batch once the registry imported"
    );
    assert!(
        f.storage.list_pull_sender_health(SYNC_ID).unwrap().is_empty(),
        "sender health cleared on recovery"
    );
    let recovered = drain_pull_sender_recovered(&mut f.event_rx);
    assert!(
        recovered
            .iter()
            .any(|(s, r, n)| s == f.device_b_id && r == "sender_unresolved" && *n == 1),
        "expected PullSenderRecovered for device B; got {recovered:?}"
    );
}

/// A stale-generation stall is tracked under the `stale_key_generation` reason
/// (distinct from `sender_unresolved`), so diagnostics distinguish a peer whose
/// registry generation has not propagated from one whose keys are entirely
/// unresolvable. Recovery via gen-1 import clears it and emits the matching
/// `PullSenderRecovered`.
#[tokio::test]
async fn stale_generation_sender_health_tracks_and_recovers() {
    let key_hierarchy = init_key_hierarchy();

    let verifier_id = "device-verifier";
    let verifier_secret = DeviceSecret::generate();
    let verifier_signing =
        verifier_secret.ed25519_keypair(verifier_id).unwrap().into_signing_key();

    let sender_id = "device-sender";
    let sender_secret = DeviceSecret::generate();
    let sender_ed25519 = sender_secret.ed25519_keypair(sender_id).unwrap();
    let sender_x25519 = sender_secret.x25519_keypair(sender_id).unwrap();
    let sender_ml_dsa_gen0 = sender_secret.ml_dsa_65_keypair(sender_id).unwrap();
    let sender_ml_dsa_gen1 = sender_secret.ml_dsa_65_keypair_v(sender_id, 1).unwrap();
    let sender_ml_kem = sender_secret.ml_kem_768_keypair(sender_id).unwrap();

    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    setup_sync_metadata(&storage, verifier_id);
    register_device_in_storage(
        &storage,
        verifier_id,
        &verifier_secret.ed25519_keypair(verifier_id).unwrap().public_key_bytes(),
        &verifier_secret.x25519_keypair(verifier_id).unwrap().public_key_bytes(),
        &verifier_secret.ml_dsa_65_keypair(verifier_id).unwrap().public_key_bytes(),
        &verifier_secret.ml_kem_768_keypair(verifier_id).unwrap().public_key_bytes(),
        0,
    );
    // Verifier knows the sender only at gen 0.
    register_device_in_storage(
        &storage,
        sender_id,
        &sender_ed25519.public_key_bytes(),
        &sender_x25519.public_key_bytes(),
        &sender_ml_dsa_gen0.public_key_bytes(),
        &sender_ml_kem.public_key_bytes(),
        0,
    );

    // The sender rotated and pushed a gen-1 batch.
    let sender_ed25519_pk = sender_ed25519.public_key_bytes().to_vec();
    let signing_key_sender = sender_ed25519.into_signing_key();
    let hlc = Hlc::now(sender_id, None);
    let ops = vec![CrdtChange {
        op_id: format!("tasks:task-rot:title:{}:{}", hlc, sender_id),
        batch_id: Some("batch-rotated".to_string()),
        entity_id: "task-rot".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Edit after rotation\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: sender_id.to_string(),
        epoch: 0,
        server_seq: None,
    }];
    let envelope = make_encrypted_batch_at_generation(
        &ops,
        &key_hierarchy,
        &signing_key_sender,
        &sender_ml_dsa_gen1,
        "batch-rotated",
        sender_id,
        1,
    );

    let relay = Arc::new(MockRelay::new());
    relay.inject_batch(envelope);

    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();
    let (event_tx, mut event_rx) =
        tokio::sync::broadcast::channel::<prism_sync_core::events::SyncEvent>(64);
    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig {
            pull_stall_max_attempts: 2,
            quarantine_replay_backoff_base_ms: 0,
            ..SyncConfig::default()
        },
    )
    .with_event_sink(event_tx);

    // Cycle 1: gen 1 > local gen 0, no registry to refresh -> stall.
    engine
        .sync(SYNC_ID, &key_hierarchy, &verifier_signing, None, verifier_id, 0)
        .await
        .unwrap();
    // Cycle 2: budget hit -> quarantine (reason stale_key_generation).
    engine
        .sync(SYNC_ID, &key_hierarchy, &verifier_signing, None, verifier_id, 0)
        .await
        .unwrap();

    let health = sender_health_row(&storage, sender_id, "stale_key_generation");
    assert_eq!(health.live_stall_count, 1);
    assert_eq!(health.quarantined_batch_count, 1);
    // The sender-unresolved reason must NOT be what we recorded here.
    assert!(
        storage
            .list_pull_sender_health(SYNC_ID)
            .unwrap()
            .iter()
            .all(|h| h.reason == "stale_key_generation"),
        "a generation stall is attributed to stale_key_generation, not sender_unresolved"
    );

    // Publish the gen-1 registry, then sync: Phase 0b replay imports gen 1,
    // verifies, applies, and recovery clears the sender health.
    let entries = vec![
        RegistrySnapshotEntry {
            sync_id: SYNC_ID.to_string(),
            device_id: verifier_id.to_string(),
            ed25519_public_key: verifier_secret
                .ed25519_keypair(verifier_id)
                .unwrap()
                .public_key_bytes()
                .to_vec(),
            x25519_public_key: verifier_secret
                .x25519_keypair(verifier_id)
                .unwrap()
                .public_key_bytes()
                .to_vec(),
            ml_dsa_65_public_key: verifier_secret
                .ml_dsa_65_keypair(verifier_id)
                .unwrap()
                .public_key_bytes(),
            ml_kem_768_public_key: verifier_secret
                .ml_kem_768_keypair(verifier_id)
                .unwrap()
                .public_key_bytes(),
            x_wing_public_key: vec![],
            status: "active".to_string(),
            ml_dsa_key_generation: 0,
            remote_wipe: false,
        },
        RegistrySnapshotEntry {
            sync_id: SYNC_ID.to_string(),
            device_id: sender_id.to_string(),
            ed25519_public_key: sender_ed25519_pk.clone(),
            x25519_public_key: sender_x25519.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: sender_ml_dsa_gen1.public_key_bytes(),
            ml_kem_768_public_key: sender_ml_kem.public_key_bytes(),
            x_wing_public_key: vec![],
            status: "active".to_string(),
            ml_dsa_key_generation: 1,
            remote_wipe: false,
        },
    ];
    let signed_blob = build_signed_registry_blob(entries, &verifier_secret, verifier_id);
    relay.set_signed_registry(SignedRegistryResponse {
        registry_version: 1,
        artifact_blob: signed_blob,
        artifact_kind: "signed_registry_snapshot".to_string(),
    });

    engine
        .sync(SYNC_ID, &key_hierarchy, &verifier_signing, None, verifier_id, 0)
        .await
        .unwrap();

    assert_eq!(
        entity.get_field("task-rot", "title"),
        Some(SyncValue::String("Edit after rotation".to_string())),
        "Phase 0b replay applied the rotated batch once gen-1 imported"
    );
    assert!(
        storage.list_pull_sender_health(SYNC_ID).unwrap().is_empty(),
        "sender health cleared on stale-generation recovery"
    );
    let recovered = drain_pull_sender_recovered(&mut event_rx);
    assert!(
        recovered
            .iter()
            .any(|(s, r, n)| s == sender_id && r == "stale_key_generation" && *n == 1),
        "expected PullSenderRecovered(stale_key_generation) for the sender; got {recovered:?}"
    );
}
