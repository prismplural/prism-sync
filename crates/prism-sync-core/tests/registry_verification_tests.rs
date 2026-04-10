//! Integration tests for the signed registry fetch/import/verification pipeline.
//!
//! These tests exercise:
//! - End-to-end verified import through the SyncEngine
//! - Unverified ML-DSA rotation rejection in `merge_relay_device`
//! - Generation preservation through verified import
//! - Tampered artifact rejection
//! - Fallback to `list_devices` when no artifact is available

mod common;

use std::sync::Arc;

use prism_sync_core::device_registry::DeviceRegistryManager;
use prism_sync_core::engine::{SyncConfig, SyncEngine};
use prism_sync_core::pairing::{RegistrySnapshotEntry, SignedRegistrySnapshot};
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

/// Build a signed registry snapshot artifact blob using hybrid signing.
///
/// Returns the signed artifact blob suitable for `set_signed_registry`.
fn build_signed_registry_blob(
    entries: Vec<RegistrySnapshotEntry>,
    signer_device_secret: &DeviceSecret,
    signer_device_id: &str,
) -> Vec<u8> {
    let signing_key = signer_device_secret
        .ed25519_keypair(signer_device_id)
        .unwrap();
    let pq_signing_key = signer_device_secret
        .ml_dsa_65_keypair(signer_device_id)
        .unwrap();
    let snapshot = SignedRegistrySnapshot::new(entries);
    snapshot.sign_hybrid(&signing_key, &pq_signing_key)
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
        .sync(
            SYNC_ID,
            &key_hierarchy,
            &signing_key_a.into_signing_key(),
            None,
            device_a_id,
            0,
        )
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
        ed25519_public_key: vec![1u8; 32],    // same
        x25519_public_key: vec![2u8; 32],     // same
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
    assert!(
        result.is_ok(),
        "merge_relay_device should not error, got: {:?}",
        result.err()
    );

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
    let ml_dsa_b_gen3 = device_secret_b
        .ml_dsa_65_keypair_v(device_b_id, 3)
        .unwrap();
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
        },
    ];

    let signed_blob = build_signed_registry_blob(entries, &device_secret_a, device_a_id);

    // Import the signed registry
    let result = DeviceRegistryManager::verify_and_import_signed_registry(
        &storage, SYNC_ID, &signed_blob,
    );
    assert!(
        result.is_ok(),
        "verified import should succeed: {:?}",
        result.err()
    );

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
    }];

    let mut signed_blob = build_signed_registry_blob(entries, &device_secret_a, device_a_id);

    // Corrupt a byte near the end (in the JSON payload area)
    let last_idx = signed_blob.len() - 2;
    signed_blob[last_idx] ^= 0xFF;

    let result = DeviceRegistryManager::verify_and_import_signed_registry(
        &storage, SYNC_ID, &signed_blob,
    );
    assert!(
        result.is_err(),
        "tampered artifact should be rejected, but got Ok"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 5: Fail closed when no signed registry is available
//
// When MockRelay returns None for get_signed_registry and a batch arrives
// from an unknown sender, the engine must skip that batch (fail closed)
// rather than falling back to the unverified list_devices endpoint.
// The sync should complete without error, but no data from the unknown
// sender should be merged.
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn registry_verification_fallback_when_no_artifact() {
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
    });

    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    setup_sync_metadata(&storage, device_a_id);

    // Register device A locally (so its own ops can be signed)
    register_device(
        &relay,
        &storage,
        device_a_id,
        &signing_key_a.verifying_key(),
    );

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
    relay.inject_batch(envelope);

    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_a, None, device_a_id, 0)
        .await
        .unwrap();

    // Sync must succeed overall (fail closed = skip batch, not abort sync)
    assert!(
        result.error.is_none(),
        "sync should complete even when unknown sender batch is skipped: {:?}",
        result.error
    );
    assert!(result.pulled > 0, "expected at least 1 batch pulled");

    // The unknown sender's batch must be SKIPPED — no ops merged
    assert_eq!(
        result.merged, 0,
        "expected 0 ops merged from unknown sender (fail closed)"
    );

    // Verify that the injected data did NOT arrive
    let title = entity.get_field("task-1", "title");
    assert_eq!(
        title, None,
        "data from unknown sender should not be present (fail closed)"
    );
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

    assert_eq!(
        info.ed25519_pk,
        ed25519_kp.public_key_bytes(),
        "Ed25519 public key should match"
    );
    assert_eq!(
        info.ml_dsa_65_pk,
        ml_dsa_kp.public_key_bytes(),
        "ML-DSA-65 public key should match"
    );
    assert_eq!(
        info.ml_dsa_key_generation, 0,
        "ML-DSA key generation should be 0"
    );
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

    assert_eq!(
        info.ml_dsa_key_generation, 1,
        "ML-DSA generation should be updated to 1"
    );
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
