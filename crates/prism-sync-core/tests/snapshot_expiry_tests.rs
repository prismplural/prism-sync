//! Integration tests for snapshot expiry, targeting, and device-specific access.
//!
//! These tests verify that snapshots are correctly targeted (or not targeted)
//! at specific devices, and that the targeting parameter flows through the engine.
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
use prism_sync_core::relay::{DeviceInfo, MockRelay};
use prism_sync_core::schema::SyncValue;
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
/// Returns (relay, key_hierarchy, device_a_signing_key, device_b_signing_key, device_b_storage).
/// The relay now has a snapshot and the pushed batches.
async fn push_and_create_snapshot(
    task_ops: Vec<(&str, &str, bool, &str)>, // (task_id, title, done, batch_id)
) -> (
    Arc<MockRelay>,
    prism_sync_crypto::KeyHierarchy,
    SigningKey,
    SigningKey,
    Arc<RusqliteSyncStorage>,
) {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_a = make_signing_key();
    let signing_key_b = make_signing_key();
    let device_a_id = "device-aaa";
    let device_b_id = "device-bbb";

    let relay = Arc::new(MockRelay::new());

    // --- Device A setup ---
    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_a: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_a, device_a_id);
    register_device(
        &relay,
        &storage_a,
        device_a_id,
        &signing_key_a.verifying_key(),
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
        .sync(SYNC_ID, &key_hierarchy, &signing_key_a, device_a_id)
        .await
        .unwrap();
    assert!(
        result.error.is_none(),
        "Device A push failed: {:?}",
        result.error
    );

    // --- Device B setup: pull and merge to populate field_versions ---
    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_b, device_b_id);
    register_device(
        &relay,
        &storage_b,
        device_a_id,
        &signing_key_a.verifying_key(),
    );
    register_device(
        &relay,
        &storage_b,
        device_b_id,
        &signing_key_b.verifying_key(),
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
        .sync(SYNC_ID, &key_hierarchy, &signing_key_b, device_b_id)
        .await
        .unwrap();
    assert!(
        result_b.error.is_none(),
        "Device B pull failed: {:?}",
        result_b.error
    );
    assert!(result_b.merged > 0, "Device B should have merged ops");

    // Device B uploads the snapshot
    engine_b
        .upload_pairing_snapshot(SYNC_ID, &key_hierarchy, 0, device_b_id, Some(300), None)
        .await
        .unwrap();

    (
        relay,
        key_hierarchy,
        signing_key_a,
        signing_key_b,
        storage_b,
    )
}

// ═══════════════════════════════════════════════════════════════════════════
// Regression: snapshot must not be device-targeted
// ═══════════════════════════════════════════════════════════════════════════

/// Regression test for: engine was passing uploader's device_id as for_device_id,
/// causing the relay to target the snapshot at the uploader. The joining device
/// (different device_id) would then receive 403 Forbidden when bootstrapping.
///
/// This test asserts two things:
///   1. The engine uploads the snapshot with for_device_id = None (no targeting).
///   2. A device with a completely different ID can still bootstrap from it.
///
/// If someone regresses this by passing Some(device_id) to put_snapshot again,
/// assertion 1 will fail immediately. Assertion 2 also guards against server-side
/// regressions where targeting enforcement would break bootstrap for new devices.
#[tokio::test]
async fn test_snapshot_not_targeted_at_uploader() {
    let (relay, key_hierarchy, _sk_a, _sk_b, _storage_b) =
        push_and_create_snapshot(vec![("task-1", "Buy groceries", false, "batch-1")]).await;

    // 1. The snapshot must have been uploaded with no device targeting.
    //    If this fails, the engine is passing the uploader's device_id as
    //    for_device_id — which would block any joining device from downloading.
    assert_eq!(
        relay.snapshot_target_device_id(),
        None,
        "snapshot must not be targeted at a specific device: the joining \
         device's ID is unknown at upload time, so for_device_id must be None"
    );

    // 2. A device that was not involved in uploading can still bootstrap.
    //    "device-zzz" is a completely fresh device with no prior relationship
    //    to the snapshot uploader.
    let key_hierarchy_z = shared_key_hierarchy(&key_hierarchy);
    let signing_key_z = make_signing_key();
    let device_z_id = "device-zzz";

    let storage_z = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_z: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_z, device_z_id);

    let engine_z = SyncEngine::new(
        storage_z.clone(),
        relay.clone(),
        vec![entity_z],
        test_schema(),
        SyncConfig::default(),
    );

    let (count, entity_changes) = engine_z
        .bootstrap_from_snapshot(SYNC_ID, &key_hierarchy_z)
        .await
        .expect("bootstrap must succeed for a device that was not the snapshot uploader");

    assert!(
        count > 0,
        "joining device should receive entities from snapshot"
    );
    assert!(
        entity_changes.iter().any(|c| c.entity_id == "task-1"),
        "joining device should see task-1 from snapshot"
    );

    // Also verify via get_snapshot_for_device that the relay would serve
    // the snapshot to any device when no targeting is set.
    let snap_for_z = relay.get_snapshot_for_device(device_z_id);
    assert!(
        snap_for_z.is_some(),
        "relay should serve untargeted snapshot to any device"
    );
    let _ = signing_key_z; // suppress unused warning
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Snapshot upload with device targeting
// ═══════════════════════════════════════════════════════════════════════════

/// Verify that `upload_pairing_snapshot` succeeds when called with a
/// `for_device_id` (targeted snapshot). The relay-side enforcement of
/// targeting is outside our scope — this test only checks that the
/// parameter flows through the engine without error.
#[tokio::test]
async fn test_snapshot_upload_with_device_targeting() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_a = make_signing_key();
    let signing_key_b = make_signing_key();
    let device_a_id = "device-aaa";
    let device_b_id = "device-bbb";

    let relay = Arc::new(MockRelay::new());

    // --- Device A: push data ---
    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_a: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_a, device_a_id);
    register_device(
        &relay,
        &storage_a,
        device_a_id,
        &signing_key_a.verifying_key(),
    );

    let ops = make_task_ops(device_a_id, "task-1", "Targeted task", false, "batch-1");
    insert_pending_ops(&storage_a, &ops, "batch-1");

    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay.clone(),
        vec![entity_a],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine_a
        .sync(SYNC_ID, &key_hierarchy, &signing_key_a, device_a_id)
        .await
        .unwrap();
    assert!(result.error.is_none(), "push failed: {:?}", result.error);

    // --- Device B: pull/merge to populate field_versions ---
    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_b, device_b_id);
    register_device(
        &relay,
        &storage_b,
        device_a_id,
        &signing_key_a.verifying_key(),
    );
    register_device(
        &relay,
        &storage_b,
        device_b_id,
        &signing_key_b.verifying_key(),
    );

    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay.clone(),
        vec![entity_b],
        test_schema(),
        SyncConfig::default(),
    );

    let result_b = engine_b
        .sync(SYNC_ID, &key_hierarchy, &signing_key_b, device_b_id)
        .await
        .unwrap();
    assert!(result_b.error.is_none());
    assert!(result_b.merged > 0, "Device B should have merged ops");

    // Upload snapshot with a specific target device
    engine_b
        .upload_pairing_snapshot(
            SYNC_ID,
            &key_hierarchy,
            0,
            device_b_id,
            Some(300),
            Some("target-device-123".to_string()),
        )
        .await
        .unwrap();

    // Verify the relay recorded the target device ID
    assert_eq!(
        relay.snapshot_target_device_id(),
        Some("target-device-123".to_string()),
        "snapshot should be targeted at the specified device"
    );
}
