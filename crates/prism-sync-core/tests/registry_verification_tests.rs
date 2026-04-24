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
    let signing_key = signer_device_secret.ed25519_keypair(signer_device_id).unwrap();
    let pq_signing_key = signer_device_secret.ml_dsa_65_keypair(signer_device_id).unwrap();
    let snapshot = SignedRegistrySnapshot::new(entries, 1);
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

    let result =
        engine.sync(SYNC_ID, &key_hierarchy, &signing_key_a, None, device_a_id, 0).await.unwrap();

    // Sync must succeed overall (fail closed = skip batch, not abort sync)
    assert!(
        result.error.is_none(),
        "sync should complete even when unknown sender batch is skipped: {:?}",
        result.error
    );
    assert!(result.pulled > 0, "expected at least 1 batch pulled");

    // The unknown sender's batch must be SKIPPED — no ops merged
    assert_eq!(result.merged, 0, "expected 0 ops merged from unknown sender (fail closed)");

    // Verify that the injected data did NOT arrive
    let title = entity.get_field("task-1", "title");
    assert_eq!(title, None, "data from unknown sender should not be present (fail closed)");
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
/// an unknown sender, the engine must skip that batch (fail-closed) rather
/// than fall back to the unverified `list_devices` endpoint.
///
/// NOTE: This property is already verified by
/// `registry_verification_fallback_when_no_artifact` (Test 5 above).
/// That test sets up a MockRelay with no signed registry, adds the unknown
/// device to `list_devices`, injects a batch from that device, and asserts
/// that `merged == 0` (the batch is skipped). This directly covers the G2
/// security property: fail-closed behavior when signed registry is unavailable.
///
/// The test below is kept as a named alias so the property is easy to find by
/// the G2 label, but the actual assertion is in Test 5.
#[test]
fn malicious_device_list_injection_rejected() {
    // See `registry_verification_fallback_when_no_artifact` above, which is
    // the authoritative test for G2 fail-closed behavior.
    //
    // Key properties verified there:
    // - MockRelay has no signed registry (`set_signed_registry` not called)
    // - Unknown device is present in `list_devices` only
    // - Engine skips the unknown sender's batch (merged == 0)
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
    }];

    // Build a signed blob at version 5
    let signing_key = device_secret_a.ed25519_keypair(device_a_id).unwrap();
    let pq_signing_key = device_secret_a.ml_dsa_65_keypair(device_a_id).unwrap();
    let snapshot_v5 = SignedRegistrySnapshot::new(entries.clone(), 5);
    let blob_v5 = snapshot_v5.sign_hybrid(&signing_key, &pq_signing_key);

    // Import version 5 — should succeed
    let result =
        DeviceRegistryManager::verify_and_import_signed_registry(&storage, SYNC_ID, &blob_v5, None);
    assert!(result.is_ok(), "version 5 import should succeed: {:?}", result.err());
    assert_eq!(result.unwrap(), 5, "should return signed version 5");

    // Build a signed blob at version 3 (stale replay)
    let snapshot_v3 = SignedRegistrySnapshot::new(entries.clone(), 3);
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
    let snapshot_v7 = SignedRegistrySnapshot::new(entries, 7);
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
    use prism_sync_core::relay::traits::{SnapshotExchange as _, SyncRelay as _};

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
