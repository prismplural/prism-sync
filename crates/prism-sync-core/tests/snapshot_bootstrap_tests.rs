//! Integration tests for snapshot bootstrap (new device bootstrapping from snapshot).
//!
//! These tests verify that a new device can bootstrap its state from a snapshot
//! uploaded by another device, including fallback behavior when no snapshot exists.
//!
//! **Key insight:** `field_versions` are only populated during the *merge*
//! phase (when pulling remote ops). A device that only pushes its own ops
//! will not have field_versions in its storage. Therefore, for snapshot tests
//! that need populated snapshots, we use a two-device pattern:
//!   1. Device A pushes ops to the relay.
//!   2. Device B pulls and merges them (populating field_versions on B).
//!   3. Device B exports/uploads the snapshot.
//!   4. Device C bootstraps from the snapshot.

mod common;

use std::sync::Arc;

use ed25519_dalek::SigningKey;

use prism_sync_core::batch_signature;
use prism_sync_core::engine::{SyncConfig, SyncEngine};
use prism_sync_core::relay::traits::{SignedBatchEnvelope, SnapshotExchange, SyncRelay};
use prism_sync_core::relay::MockRelay;
use prism_sync_core::storage::RusqliteSyncStorage;
use prism_sync_core::syncable_entity::SyncableEntity;
use prism_sync_core::{CrdtChange, Hlc};

use common::*;

// ═══════════════════════════════════════════════════════════════════════════
// Test-file-specific helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Create a key hierarchy that shares the same epoch 0 key as the given one.
fn shared_key_hierarchy(
    source: &prism_sync_crypto::KeyHierarchy,
) -> prism_sync_crypto::KeyHierarchy {
    let mut kh = prism_sync_crypto::KeyHierarchy::new();
    kh.initialize("other-password", &[2u8; 16]).unwrap();
    let epoch0 = source.epoch_key(0).unwrap();
    kh.store_epoch_key(0, zeroize::Zeroizing::new(epoch0.to_vec()));
    kh
}

/// Create ops for a single task with title and done fields.
fn make_task_ops(
    device_id: &str,
    task_id: &str,
    title: &str,
    done: bool,
    batch_id: &str,
) -> Vec<CrdtChange> {
    let hlc = Hlc::now(device_id, None);
    vec![
        CrdtChange {
            op_id: format!("tasks:{task_id}:title:{hlc}:{device_id}"),
            batch_id: Some(batch_id.to_string()),
            entity_id: task_id.to_string(),
            entity_table: "tasks".to_string(),
            field_name: "title".to_string(),
            encoded_value: format!("\"{title}\""),
            client_hlc: hlc.to_string(),
            is_delete: false,
            device_id: device_id.to_string(),
            epoch: 0,
            server_seq: None,
        },
        CrdtChange {
            op_id: format!("tasks:{task_id}:done:{hlc}:{device_id}"),
            batch_id: Some(batch_id.to_string()),
            entity_id: task_id.to_string(),
            entity_table: "tasks".to_string(),
            field_name: "done".to_string(),
            encoded_value: done.to_string(),
            client_hlc: hlc.to_string(),
            is_delete: false,
            device_id: device_id.to_string(),
            epoch: 0,
            server_seq: None,
        },
    ]
}

/// Set up a device pair where:
///  - Device A pushes the given task ops to the relay.
///  - Device B pulls and merges them (populating field_versions).
///  - Device B uploads a snapshot.
///
/// Returns (relay, key_hierarchy, device_b_signing_key, device_b_storage).
/// The relay now has a snapshot and the pushed batches.
async fn push_and_create_snapshot(
    task_ops: Vec<(&str, &str, bool, &str)>, // (task_id, title, done, batch_id)
) -> (
    Arc<MockRelay>,
    prism_sync_crypto::KeyHierarchy,
    SigningKey,
    SigningKey,
    prism_sync_crypto::DevicePqSigningKey,
    prism_sync_crypto::DevicePqSigningKey,
    Arc<RusqliteSyncStorage>,
) {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_a = make_signing_key();
    let ml_dsa_key_a = make_ml_dsa_keypair();
    let signing_key_b = make_signing_key();
    let ml_dsa_key_b = make_ml_dsa_keypair();
    let device_a_id = "device-aaa";
    let device_b_id = "device-bbb";

    let relay = Arc::new(MockRelay::new());

    // --- Device A setup ---
    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_a: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_a, device_a_id);
    register_device_with_pq(
        &relay,
        &storage_a,
        device_a_id,
        &signing_key_a.verifying_key(),
        &ml_dsa_key_a.public_key_bytes(),
    );

    // Insert all task ops for device A
    for (task_id, title, done, batch_id) in &task_ops {
        let ops = make_task_ops(device_a_id, task_id, title, *done, batch_id);
        insert_pending_ops(&storage_a, &ops, batch_id);
    }

    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay.clone(),
        vec![entity_a],
        test_schema(),
        SyncConfig::default(),
    );

    // Push all from device A
    let result = engine_a
        .sync(SYNC_ID, &key_hierarchy, &signing_key_a, Some(&ml_dsa_key_a), device_a_id, 0)
        .await
        .unwrap();
    assert!(result.error.is_none(), "Device A push failed: {:?}", result.error);

    // --- Device B setup: pull and merge to populate field_versions ---
    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_b, device_b_id);
    register_device_with_pq(
        &relay,
        &storage_b,
        device_a_id,
        &signing_key_a.verifying_key(),
        &ml_dsa_key_a.public_key_bytes(),
    );
    register_device_with_pq(
        &relay,
        &storage_b,
        device_b_id,
        &signing_key_b.verifying_key(),
        &ml_dsa_key_b.public_key_bytes(),
    );

    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay.clone(),
        vec![entity_b],
        test_schema(),
        SyncConfig::default(),
    );

    // Pull and merge (populates field_versions on device B)
    let result_b = engine_b
        .sync(SYNC_ID, &key_hierarchy, &signing_key_b, Some(&ml_dsa_key_b), device_b_id, 0)
        .await
        .unwrap();
    assert!(result_b.error.is_none(), "Device B pull failed: {:?}", result_b.error);
    assert!(result_b.merged > 0, "Device B should have merged ops");

    // Device B uploads the snapshot
    engine_b
        .upload_pairing_snapshot(
            SYNC_ID,
            &key_hierarchy,
            0,
            device_b_id,
            &signing_key_b,
            &ml_dsa_key_b,
            0,
            Some(300),
            None,
            None,
        )
        .await
        .unwrap();

    (relay, key_hierarchy, signing_key_a, signing_key_b, ml_dsa_key_a, ml_dsa_key_b, storage_b)
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 4: Snapshot bootstrap then incremental
// ═══════════════════════════════════════════════════════════════════════════

/// Device A pushes task-1, Device B merges and uploads snapshot at seq N.
/// Device A then pushes task-2 (N+1). Device C bootstraps from snapshot
/// (state at N), syncs incrementally (gets N+1), verify complete state.
#[tokio::test]
async fn test_snapshot_bootstrap_then_incremental() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_a = make_signing_key();
    let ml_dsa_key_a = make_ml_dsa_keypair();
    let device_a_id = "device-aaa";

    let relay = Arc::new(MockRelay::new());

    // --- Device A: create task-1 and push ---
    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_a: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_a, device_a_id);
    register_device_with_pq(
        &relay,
        &storage_a,
        device_a_id,
        &signing_key_a.verifying_key(),
        &ml_dsa_key_a.public_key_bytes(),
    );

    let ops_1 = make_task_ops(device_a_id, "task-1", "Buy groceries", false, "batch-1");
    insert_pending_ops(&storage_a, &ops_1, "batch-1");

    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay.clone(),
        vec![entity_a.clone()],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine_a
        .sync(SYNC_ID, &key_hierarchy, &signing_key_a, Some(&ml_dsa_key_a), device_a_id, 0)
        .await
        .unwrap();
    assert!(result.error.is_none(), "push failed: {:?}", result.error);
    assert_eq!(result.pushed, 1);

    // --- Device B: pull/merge to populate field_versions, then upload snapshot ---
    let signing_key_b = make_signing_key();
    let ml_dsa_key_b = make_ml_dsa_keypair();
    let device_b_id = "device-bbb";
    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_b, device_b_id);
    register_device_with_pq(
        &relay,
        &storage_b,
        device_a_id,
        &signing_key_a.verifying_key(),
        &ml_dsa_key_a.public_key_bytes(),
    );
    register_device_with_pq(
        &relay,
        &storage_b,
        device_b_id,
        &signing_key_b.verifying_key(),
        &ml_dsa_key_b.public_key_bytes(),
    );

    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay.clone(),
        vec![entity_b],
        test_schema(),
        SyncConfig::default(),
    );

    let result_b = engine_b
        .sync(SYNC_ID, &key_hierarchy, &signing_key_b, Some(&ml_dsa_key_b), device_b_id, 0)
        .await
        .unwrap();
    assert!(result_b.error.is_none());
    assert_eq!(result_b.merged, 2, "should merge title + done ops");

    // Device B uploads snapshot (has field_versions from merge)
    engine_b
        .upload_pairing_snapshot(
            SYNC_ID,
            &key_hierarchy,
            0,
            device_b_id,
            &signing_key_b,
            &ml_dsa_key_b,
            0,
            Some(300),
            None,
            None,
        )
        .await
        .unwrap();

    // --- Device A: push task-2 AFTER snapshot was taken ---
    // Need a small delay so HLC (millisecond-resolution wall clock) is different.
    // Uses std::thread::sleep for a reliable wall-clock delay (not tokio, which
    // depends on async scheduling and can be paused in test mode).
    std::thread::sleep(std::time::Duration::from_millis(2));
    let ops_2 = make_task_ops(device_a_id, "task-2", "Walk the dog", true, "batch-2");
    insert_pending_ops(&storage_a, &ops_2, "batch-2");

    let result_a2 = engine_a
        .sync(SYNC_ID, &key_hierarchy, &signing_key_a, Some(&ml_dsa_key_a), device_a_id, 0)
        .await
        .unwrap();
    assert!(result_a2.error.is_none());
    assert_eq!(result_a2.pushed, 1);

    // --- Device C: bootstrap from snapshot, then incremental ---
    let key_hierarchy_c = shared_key_hierarchy(&key_hierarchy);
    let signing_key_c = make_signing_key();
    let device_c_id = "device-ccc";

    let storage_c = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_c: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    let ml_dsa_key_c = make_ml_dsa_keypair();

    setup_sync_metadata(&storage_c, device_c_id);
    register_device_with_pq(
        &relay,
        &storage_c,
        device_a_id,
        &signing_key_a.verifying_key(),
        &ml_dsa_key_a.public_key_bytes(),
    );
    register_device_with_pq(
        &relay,
        &storage_c,
        device_b_id,
        &signing_key_b.verifying_key(),
        &ml_dsa_key_b.public_key_bytes(),
    );
    register_device_with_pq(
        &relay,
        &storage_c,
        device_c_id,
        &signing_key_c.verifying_key(),
        &ml_dsa_key_c.public_key_bytes(),
    );

    let engine_c = SyncEngine::new(
        storage_c.clone(),
        relay.clone(),
        vec![entity_c],
        test_schema(),
        SyncConfig::default(),
    );

    // Bootstrap from snapshot — restores task-1 field_versions
    let (count, entity_changes) =
        engine_c.bootstrap_from_snapshot(SYNC_ID, &key_hierarchy_c).await.unwrap();

    assert!(count > 0, "snapshot should contain at least 1 entity");
    assert!(!entity_changes.is_empty(), "entity_changes should be non-empty");

    // Verify task-1 is in the bootstrap entity_changes
    let task_1_change = entity_changes.iter().find(|c| c.entity_id == "task-1");
    assert!(task_1_change.is_some(), "task-1 should be in snapshot entity_changes");
    let task_1 = task_1_change.unwrap();
    assert_eq!(task_1.table, "tasks");
    assert_eq!(task_1.fields.get("title"), Some(&"\"Buy groceries\"".to_string()));

    // Incremental sync to get task-2 (pushed after snapshot)
    let result_c = engine_c
        .sync(SYNC_ID, &key_hierarchy_c, &signing_key_c, None, device_c_id, 0)
        .await
        .unwrap();
    assert!(result_c.error.is_none(), "incremental sync failed: {:?}", result_c.error);
    assert!(result_c.pulled > 0, "should pull post-snapshot batches");
    assert!(result_c.merged > 0, "should merge post-snapshot ops");

    // Verify task-2 arrived via incremental sync
    let task_2_change = result_c.entity_changes.iter().find(|c| c.entity_id == "task-2");
    assert!(task_2_change.is_some(), "task-2 should be in incremental changes");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 5: Bootstrap without snapshot falls back
// ═══════════════════════════════════════════════════════════════════════════

/// Device B calls bootstrap with no snapshot on relay, returns Ok(0),
/// then syncs incrementally to get all data.
#[tokio::test]
async fn test_bootstrap_without_snapshot_falls_back() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_a = make_signing_key();
    let ml_dsa_key_a = make_ml_dsa_keypair();
    let device_a_id = "device-aaa";

    let relay = Arc::new(MockRelay::new());
    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_a: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_a, device_a_id);
    register_device_with_pq(
        &relay,
        &storage_a,
        device_a_id,
        &signing_key_a.verifying_key(),
        &ml_dsa_key_a.public_key_bytes(),
    );

    // Device A pushes data (no snapshot uploaded)
    let ops = make_task_ops(device_a_id, "task-1", "Test task", false, "batch-1");
    insert_pending_ops(&storage_a, &ops, "batch-1");

    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay.clone(),
        vec![entity_a],
        test_schema(),
        SyncConfig::default(),
    );

    engine_a
        .sync(SYNC_ID, &key_hierarchy, &signing_key_a, Some(&ml_dsa_key_a), device_a_id, 0)
        .await
        .unwrap();

    // --- Device B: try bootstrap (no snapshot available) ---
    let key_hierarchy_b = shared_key_hierarchy(&key_hierarchy);
    let signing_key_b = make_signing_key();
    let ml_dsa_key_b = make_ml_dsa_keypair();
    let device_b_id = "device-bbb";

    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_b, device_b_id);
    register_device_with_pq(
        &relay,
        &storage_b,
        device_a_id,
        &signing_key_a.verifying_key(),
        &ml_dsa_key_a.public_key_bytes(),
    );
    register_device_with_pq(
        &relay,
        &storage_b,
        device_b_id,
        &signing_key_b.verifying_key(),
        &ml_dsa_key_b.public_key_bytes(),
    );

    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay.clone(),
        vec![entity_b],
        test_schema(),
        SyncConfig::default(),
    );

    // Bootstrap returns (0, []) when no snapshot exists
    let (count, entity_changes) =
        engine_b.bootstrap_from_snapshot(SYNC_ID, &key_hierarchy_b).await.unwrap();

    assert_eq!(count, 0, "bootstrap with no snapshot should return 0 entities");
    assert!(entity_changes.is_empty(), "entity_changes should be empty");

    // Incremental sync picks up all data
    let result = engine_b
        .sync(SYNC_ID, &key_hierarchy_b, &signing_key_b, Some(&ml_dsa_key_b), device_b_id, 0)
        .await
        .unwrap();
    assert!(result.error.is_none(), "incremental sync failed: {:?}", result.error);
    assert_eq!(result.pulled, 1, "should pull 1 batch incrementally");
    assert_eq!(result.merged, 2, "should merge 2 ops (title + done)");

    let task = result.entity_changes.iter().find(|c| c.entity_id == "task-1");
    assert!(task.is_some(), "task-1 should be in entity_changes");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 6: Bootstrap wrong epoch key
// ═══════════════════════════════════════════════════════════════════════════

/// Upload snapshot with epoch 0 key, try bootstrap with different key —
/// decrypt should fail.
#[tokio::test]
async fn test_bootstrap_wrong_epoch_key() {
    // Use the helper to create a snapshot with real data
    let (relay, _key_hierarchy, _sk_a, _sk_b, _ml_a, _ml_b, _storage_b) =
        push_and_create_snapshot(vec![("task-1", "Secret task", false, "batch-1")]).await;

    // --- Device C: try bootstrap with a COMPLETELY DIFFERENT key hierarchy ---
    let mut wrong_kh = prism_sync_crypto::KeyHierarchy::new();
    wrong_kh.initialize("completely-wrong-password", &[99u8; 16]).unwrap();
    // Do NOT copy epoch 0 key — the default epoch key will be different

    let storage_c = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_c: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_c, "device-ccc");

    // Register device B in device C's storage so the signature lookup
    // succeeds (fail-closed) and the test reaches the decryption check.
    register_device_with_pq(
        &relay,
        &storage_c,
        "device-bbb",
        &_sk_b.verifying_key(),
        &_ml_b.public_key_bytes(),
    );

    let engine_c = SyncEngine::new(
        storage_c.clone(),
        relay.clone(),
        vec![entity_c],
        test_schema(),
        SyncConfig::default(),
    );

    // Bootstrap should fail because the epoch key doesn't match
    let result = engine_c.bootstrap_from_snapshot(SYNC_ID, &wrong_kh).await;

    assert!(result.is_err(), "bootstrap with wrong epoch key should fail");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("decrypt")
            || err_msg.contains("Decrypt")
            || err_msg.contains("crypto")
            || err_msg.contains("snapshot"),
        "error should mention decryption failure, got: {err_msg}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 11: Pairing works without snapshot
// ═══════════════════════════════════════════════════════════════════════════

/// Full pairing flow where snapshot is not available — verify the new device
/// can still sync via incremental pull.
#[tokio::test]
async fn test_pairing_works_without_snapshot() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_a = make_signing_key();
    let ml_dsa_key_a = make_ml_dsa_keypair();
    let signing_key_b = make_signing_key();
    let ml_dsa_key_b = make_ml_dsa_keypair();
    let device_a_id = "device-aaa";
    let device_b_id = "device-bbb";

    let relay = Arc::new(MockRelay::new());

    // --- Device A: push data (no snapshot) ---
    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_a: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_a, device_a_id);
    register_device_with_pq(
        &relay,
        &storage_a,
        device_a_id,
        &signing_key_a.verifying_key(),
        &ml_dsa_key_a.public_key_bytes(),
    );

    let ops_1 = make_task_ops(device_a_id, "task-1", "First task", false, "batch-1");
    let ops_2 = make_task_ops(device_a_id, "task-2", "Second task", true, "batch-2");
    insert_pending_ops(&storage_a, &ops_1, "batch-1");
    insert_pending_ops(&storage_a, &ops_2, "batch-2");

    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay.clone(),
        vec![entity_a],
        test_schema(),
        SyncConfig::default(),
    );

    let result_a = engine_a
        .sync(SYNC_ID, &key_hierarchy, &signing_key_a, Some(&ml_dsa_key_a), device_a_id, 0)
        .await
        .unwrap();
    assert!(result_a.error.is_none());
    assert_eq!(result_a.pushed, 2);

    // Device A does NOT upload a snapshot (simulating snapshot upload failure)

    // --- Device B: join without snapshot ---
    let key_hierarchy_b = shared_key_hierarchy(&key_hierarchy);
    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_b, device_b_id);
    register_device_with_pq(
        &relay,
        &storage_b,
        device_a_id,
        &signing_key_a.verifying_key(),
        &ml_dsa_key_a.public_key_bytes(),
    );
    register_device_with_pq(
        &relay,
        &storage_b,
        device_b_id,
        &signing_key_b.verifying_key(),
        &ml_dsa_key_b.public_key_bytes(),
    );

    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay.clone(),
        vec![entity_b],
        test_schema(),
        SyncConfig::default(),
    );

    // Bootstrap returns nothing
    let (count, _) = engine_b.bootstrap_from_snapshot(SYNC_ID, &key_hierarchy_b).await.unwrap();
    assert_eq!(count, 0);

    // Incremental sync picks up all data
    let result_b = engine_b
        .sync(SYNC_ID, &key_hierarchy_b, &signing_key_b, Some(&ml_dsa_key_b), device_b_id, 0)
        .await
        .unwrap();
    assert!(result_b.error.is_none(), "sync failed: {:?}", result_b.error);
    assert_eq!(result_b.pulled, 2, "should pull both batches");
    assert_eq!(result_b.merged, 4, "should merge 4 ops (2 tasks x 2 fields)");

    let has_task_1 = result_b.entity_changes.iter().any(|c| c.entity_id == "task-1");
    let has_task_2 = result_b.entity_changes.iter().any(|c| c.entity_id == "task-2");
    assert!(has_task_1, "task-1 should be in entity_changes");
    assert!(has_task_2, "task-2 should be in entity_changes");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 12: Bootstrap emits remote changes
// ═══════════════════════════════════════════════════════════════════════════

/// Bootstrap from snapshot, verify entity_changes are returned with correct
/// entities and field values.
#[tokio::test]
async fn test_bootstrap_emits_remote_changes() {
    // Create a snapshot containing 3 tasks
    let (relay, key_hierarchy, _sk_a, _sk_b, _ml_a, _ml_b, _storage_b) =
        push_and_create_snapshot(vec![
            ("task-1", "Alpha", false, "batch-1"),
            ("task-2", "Beta", true, "batch-2"),
            ("task-3", "Gamma", false, "batch-3"),
        ])
        .await;

    // --- Device C: bootstrap ---
    let key_hierarchy_c = shared_key_hierarchy(&key_hierarchy);
    let storage_c = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_c: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_c, "device-ccc");

    // Register device B in device C's storage so the signature verification
    // can proceed (fail-closed: no unverified fallback available).
    register_device_with_pq(
        &relay,
        &storage_c,
        "device-bbb",
        &_sk_b.verifying_key(),
        &_ml_b.public_key_bytes(),
    );

    let engine_c = SyncEngine::new(
        storage_c.clone(),
        relay.clone(),
        vec![entity_c],
        test_schema(),
        SyncConfig::default(),
    );

    let (count, entity_changes) =
        engine_c.bootstrap_from_snapshot(SYNC_ID, &key_hierarchy_c).await.unwrap();

    assert_eq!(count, 3, "snapshot should contain 3 entities");
    assert_eq!(entity_changes.len(), 3, "should emit 3 EntityChange entries");

    // Verify each entity has the correct fields
    for change in &entity_changes {
        assert_eq!(change.table, "tasks");
        assert!(!change.is_delete);
        assert!(change.fields.contains_key("title"), "should have title field");
        assert!(change.fields.contains_key("done"), "should have done field");
    }

    // Verify specific values
    let alpha = entity_changes.iter().find(|c| c.entity_id == "task-1").unwrap();
    assert_eq!(alpha.fields.get("title"), Some(&"\"Alpha\"".to_string()));

    let beta = entity_changes.iter().find(|c| c.entity_id == "task-2").unwrap();
    assert_eq!(beta.fields.get("title"), Some(&"\"Beta\"".to_string()));

    let gamma = entity_changes.iter().find(|c| c.entity_id == "task-3").unwrap();
    assert_eq!(gamma.fields.get("title"), Some(&"\"Gamma\"".to_string()));
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Tampered signature rejection
// ═══════════════════════════════════════════════════════════════════════════

/// Upload a valid signed snapshot, corrupt the signature bytes in the relay's
/// stored data, then attempt bootstrap — should fail with a signature error.
#[tokio::test]
async fn test_bootstrap_rejects_tampered_signature() {
    let (relay, key_hierarchy, _sk_a, _sk_b, _ml_a, _ml_b, _storage_b) =
        push_and_create_snapshot(vec![("task-1", "Signed task", false, "batch-1")]).await;

    // Retrieve the snapshot from the relay and corrupt the signature
    let snapshot = relay.get_snapshot().await.unwrap().unwrap();
    let mut envelope: SignedBatchEnvelope =
        serde_json::from_slice(&snapshot.data).expect("deserialize envelope");

    // Flip every byte in the signature to ensure it's invalid
    for byte in envelope.signature.iter_mut() {
        *byte ^= 0xFF;
    }

    let tampered_data = serde_json::to_vec(&envelope).expect("re-serialize envelope");

    // Replace the snapshot in the relay with the tampered version
    relay
        .put_snapshot(
            snapshot.epoch,
            snapshot.server_seq_at,
            tampered_data,
            None,
            None,
            snapshot.sender_device_id.clone(),
            None,
        )
        .await
        .unwrap();

    // Device C attempts to bootstrap from the tampered snapshot
    let key_hierarchy_c = shared_key_hierarchy(&key_hierarchy);
    let storage_c = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_c: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_c, "device-ccc");

    // Register Device B's key so signature lookup succeeds (but verification fails)
    register_device_with_pq(
        &relay,
        &storage_c,
        &snapshot.sender_device_id,
        &_sk_b.verifying_key(),
        &_ml_b.public_key_bytes(),
    );

    let engine_c = SyncEngine::new(
        storage_c.clone(),
        relay.clone(),
        vec![entity_c],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine_c.bootstrap_from_snapshot(SYNC_ID, &key_hierarchy_c).await;

    assert!(result.is_err(), "bootstrap with tampered signature should fail");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("signature")
            || err_msg.contains("Signature")
            || err_msg.contains("verify")
            || err_msg.contains("Verify"),
        "error should mention signature verification failure, got: {err_msg}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Payload hash mismatch rejection
// ═══════════════════════════════════════════════════════════════════════════

/// Upload a valid signed snapshot, then re-sign the same ciphertext with an
/// incorrect payload hash. Bootstrap should fail after decryption when the
/// plaintext no longer matches the signed hash.
#[tokio::test]
async fn test_bootstrap_rejects_snapshot_payload_hash_mismatch() {
    let (relay, key_hierarchy, _sk_a, sk_b, _ml_a, _ml_b, _storage_b) =
        push_and_create_snapshot(vec![("task-1", "Signed task", false, "batch-1")]).await;

    let snapshot = relay.get_snapshot().await.unwrap().unwrap();
    let envelope: SignedBatchEnvelope =
        serde_json::from_slice(&snapshot.data).expect("deserialize envelope");

    let wrong_payload_hash = batch_signature::compute_payload_hash(b"not the snapshot bytes");
    let ml_dsa_key_b_new = make_ml_dsa_keypair();
    let tampered_envelope = batch_signature::sign_batch(
        &sk_b,
        &ml_dsa_key_b_new,
        &envelope.sync_id,
        envelope.epoch,
        &envelope.batch_id,
        &envelope.batch_kind,
        &envelope.sender_device_id,
        0,
        &wrong_payload_hash,
        envelope.nonce,
        envelope.ciphertext.clone(),
    )
    .expect("re-sign envelope with mismatched payload hash");

    relay
        .put_snapshot(
            snapshot.epoch,
            snapshot.server_seq_at,
            serde_json::to_vec(&tampered_envelope).expect("serialize tampered envelope"),
            None,
            None,
            snapshot.sender_device_id.clone(),
            None,
        )
        .await
        .unwrap();

    let key_hierarchy_c = shared_key_hierarchy(&key_hierarchy);
    let storage_c = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_c: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_c, "device-ccc");
    register_device_with_pq(
        &relay,
        &storage_c,
        &snapshot.sender_device_id,
        &sk_b.verifying_key(),
        &ml_dsa_key_b_new.public_key_bytes(),
    );

    let engine_c = SyncEngine::new(
        storage_c,
        relay.clone(),
        vec![entity_c],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine_c.bootstrap_from_snapshot(SYNC_ID, &key_hierarchy_c).await;

    assert!(result.is_err(), "bootstrap with mismatched snapshot payload hash should fail");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Payload hash mismatch"),
        "error should mention payload hash mismatch, got: {err_msg}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: AAD mismatch rejection
// ═══════════════════════════════════════════════════════════════════════════

/// Upload a valid signed snapshot, then change `server_seq_at` in the relay's
/// stored snapshot metadata (without touching the ciphertext). The AAD was
/// bound to the original `server_seq_at`, so decryption should fail.
#[tokio::test]
async fn test_bootstrap_rejects_aad_mismatch() {
    let (relay, key_hierarchy, _sk_a, _sk_b, _ml_a, _ml_b, _storage_b) =
        push_and_create_snapshot(vec![("task-1", "AAD task", false, "batch-1")]).await;

    // Retrieve the snapshot and re-store it with a different server_seq_at
    let snapshot = relay.get_snapshot().await.unwrap().unwrap();
    let original_seq = snapshot.server_seq_at;
    let tampered_seq = original_seq + 999; // Different from the AAD-bound value

    relay
        .put_snapshot(
            snapshot.epoch,
            tampered_seq,
            snapshot.data.clone(),
            None,
            None,
            snapshot.sender_device_id.clone(),
            None,
        )
        .await
        .unwrap();

    // Device C attempts to bootstrap — signature is valid but AAD won't match
    let key_hierarchy_c = shared_key_hierarchy(&key_hierarchy);
    let storage_c = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_c: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_c, "device-ccc");

    // Register Device B's key so signature verification passes
    register_device_with_pq(
        &relay,
        &storage_c,
        &snapshot.sender_device_id,
        &_sk_b.verifying_key(),
        &_ml_b.public_key_bytes(),
    );

    let engine_c = SyncEngine::new(
        storage_c.clone(),
        relay.clone(),
        vec![entity_c],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine_c.bootstrap_from_snapshot(SYNC_ID, &key_hierarchy_c).await;

    assert!(result.is_err(), "bootstrap with mismatched server_seq_at (AAD mismatch) should fail");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("decrypt")
            || err_msg.contains("Decrypt")
            || err_msg.contains("crypto")
            || err_msg.contains("aead"),
        "error should mention decryption failure, got: {err_msg}"
    );
}
