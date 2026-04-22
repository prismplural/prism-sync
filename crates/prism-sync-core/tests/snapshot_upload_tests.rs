//! Integration tests for snapshot creation/upload and the push+snapshot workflow.
//!
//! These tests verify that snapshots can be created, uploaded, and that
//! data roundtrips correctly through snapshot export/import.
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

use prism_sync_core::engine::{SyncConfig, SyncEngine};
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
/// Returns (relay, key_hierarchy, device_a_signing_key, device_b_signing_key, device_b_ml_dsa_key, device_b_storage).
/// The relay now has a snapshot and the pushed batches.
async fn push_and_create_snapshot(
    task_ops: Vec<(&str, &str, bool, &str)>, // (task_id, title, done, batch_id)
) -> (
    Arc<MockRelay>,
    prism_sync_crypto::KeyHierarchy,
    SigningKey,
    SigningKey,
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
        )
        .await
        .unwrap();

    (relay, key_hierarchy, signing_key_a, signing_key_b, ml_dsa_key_b, storage_b)
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 13: Push limit without snapshot
// ═══════════════════════════════════════════════════════════════════════════

/// No snapshot, push many batches, verify push still works and no blocking.
#[tokio::test]
async fn test_push_limit_without_snapshot() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key = make_signing_key();
    let ml_dsa_key = make_ml_dsa_keypair();
    let device_id = "device-aaa";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, device_id);
    register_device_with_pq(
        &relay,
        &storage,
        device_id,
        &signing_key.verifying_key(),
        &ml_dsa_key.public_key_bytes(),
    );

    // Push 10 batches
    for i in 0..10 {
        let ops = make_task_ops(
            device_id,
            &format!("task-{i}"),
            &format!("Task number {i}"),
            false,
            &format!("batch-{i}"),
        );
        insert_pending_ops(&storage, &ops, &format!("batch-{i}"));
    }

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key, Some(&ml_dsa_key), device_id, 0)
        .await
        .unwrap();
    assert!(result.error.is_none(), "push failed: {:?}", result.error);
    assert_eq!(result.pushed, 10);
    assert_eq!(relay.batch_count(), 10);

    // Push more after initial batches — verify no blocking
    let more_ops = make_task_ops(device_id, "task-extra", "Extra task", true, "batch-extra");
    insert_pending_ops(&storage, &more_ops, "batch-extra");

    let result2 = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key, Some(&ml_dsa_key), device_id, 0)
        .await
        .unwrap();
    assert!(result2.error.is_none());
    assert_eq!(result2.pushed, 1);
    assert_eq!(relay.batch_count(), 11);
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 14: Snapshot roundtrip preserves data
// ═══════════════════════════════════════════════════════════════════════════

/// Create data, export snapshot via engine, import on fresh storage,
/// verify all field_versions match.
#[tokio::test]
async fn test_snapshot_roundtrip_preserves_data() {
    // Use the helper to create a populated snapshot
    let (relay, key_hierarchy, _sk_a, _sk_b, _ml_b, storage_b) = push_and_create_snapshot(vec![
        ("task-1", "First", false, "batch-1"),
        ("task-2", "Second", true, "batch-2"),
    ])
    .await;

    // --- Device C: bootstrap from the snapshot ---
    let key_hierarchy_c = shared_key_hierarchy(&key_hierarchy);
    let storage_c = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_c: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_c, "device-ccc");

    // Register device B in device C's storage so the signature verification
    // can proceed (fail-closed: no unverified list_devices fallback).
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

    assert_eq!(count, 2, "should restore 2 entities");

    // Verify field_versions in storage_c match those in storage_b (the snapshot source)
    use prism_sync_core::storage::SyncStorage;
    // Check task-1 title
    let fv_b_1_title = storage_b
        .get_field_version(SYNC_ID, "tasks", "task-1", "title")
        .unwrap()
        .expect("source field_version for task-1 title should exist");
    let fv_c_1_title = storage_c
        .get_field_version(SYNC_ID, "tasks", "task-1", "title")
        .unwrap()
        .expect("imported field_version for task-1 title should exist");

    assert_eq!(fv_b_1_title.winning_op_id, fv_c_1_title.winning_op_id);
    assert_eq!(fv_b_1_title.winning_hlc, fv_c_1_title.winning_hlc);
    assert_eq!(fv_b_1_title.winning_encoded_value, fv_c_1_title.winning_encoded_value);
    assert_eq!(fv_b_1_title.winning_device_id, fv_c_1_title.winning_device_id);

    // Check task-2 done
    let fv_b_2_done = storage_b
        .get_field_version(SYNC_ID, "tasks", "task-2", "done")
        .unwrap()
        .expect("source field_version for task-2 done should exist");
    let fv_c_2_done = storage_c
        .get_field_version(SYNC_ID, "tasks", "task-2", "done")
        .unwrap()
        .expect("imported field_version for task-2 done should exist");

    assert_eq!(fv_b_2_done.winning_op_id, fv_c_2_done.winning_op_id);
    assert_eq!(fv_b_2_done.winning_encoded_value, fv_c_2_done.winning_encoded_value);

    // Bootstrap must preserve the joining device's local identity, not the
    // source device identity embedded in the snapshot.
    let imported_meta =
        storage_c.get_sync_metadata(SYNC_ID).unwrap().expect("imported sync metadata should exist");
    assert_eq!(imported_meta.local_device_id, "device-ccc");

    // Verify entity_changes have correct data
    let task_1 = entity_changes.iter().find(|c| c.entity_id == "task-1").unwrap();
    assert_eq!(task_1.fields.get("title"), Some(&"\"First\"".to_string()));

    let task_2 = entity_changes.iter().find(|c| c.entity_id == "task-2").unwrap();
    assert_eq!(task_2.fields.get("done"), Some(&"true".to_string()));
}
