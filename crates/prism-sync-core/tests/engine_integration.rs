//! Integration tests for the SyncEngine pull -> merge -> push cycle.
//!
//! These tests exercise the full sync pipeline using:
//! - `RusqliteSyncStorage::in_memory()` for local sync state
//! - `MockRelay` for the relay transport
//! - A `MockTaskEntity` implementing `SyncableEntity` backed by a `HashMap`
//! - Real `KeyHierarchy` and `Ed25519` signing keys for crypto

mod common;

use std::sync::Arc;

use ed25519_dalek::SigningKey;

use prism_sync_core::engine::{SyncConfig, SyncEngine};
use prism_sync_core::relay::{MockRelay, SignedBatchEnvelope};
use prism_sync_core::schema::SyncValue;
use prism_sync_core::storage::RusqliteSyncStorage;
use prism_sync_core::syncable_entity::SyncableEntity;
use prism_sync_core::{batch_signature, sync_aad, CrdtChange, Hlc};

use common::*;

// ═══════════════════════════════════════════════════════════════════════════
// Test-file-specific helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Create a signed + encrypted batch envelope from CrdtChange ops.
fn make_encrypted_batch(
    ops: &[CrdtChange],
    key_hierarchy: &prism_sync_crypto::KeyHierarchy,
    signing_key: &SigningKey,
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
        SYNC_ID,
        0,
        batch_id,
        "ops",
        sender_device_id,
        &payload_hash,
        nonce,
        ciphertext,
    )
    .unwrap()
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 1: Push and pull roundtrip
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_push_and_pull_roundtrip() {
    // --- Device A: create ops and push ---
    let key_hierarchy_a = init_key_hierarchy();
    let signing_key_a = make_signing_key();
    let device_a_id = "device-aaa";

    let relay = Arc::new(MockRelay::new());
    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_a: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_a, device_a_id);
    register_device(
        &relay,
        &storage_a,
        device_a_id,
        &signing_key_a.verifying_key(),
    );

    // Create ops for device A
    let hlc_a = Hlc::now(device_a_id, None);
    let ops_a = vec![
        CrdtChange {
            op_id: format!("tasks:task-1:title:{}:{}", hlc_a, device_a_id),
            batch_id: Some("batch-a1".to_string()),
            entity_id: "task-1".to_string(),
            entity_table: "tasks".to_string(),
            field_name: "title".to_string(),
            encoded_value: "\"Buy groceries\"".to_string(),
            client_hlc: hlc_a.to_string(),
            is_delete: false,
            device_id: device_a_id.to_string(),
            epoch: 0,
            server_seq: None,
        },
        CrdtChange {
            op_id: format!("tasks:task-1:done:{}:{}", hlc_a, device_a_id),
            batch_id: Some("batch-a1".to_string()),
            entity_id: "task-1".to_string(),
            entity_table: "tasks".to_string(),
            field_name: "done".to_string(),
            encoded_value: "false".to_string(),
            client_hlc: hlc_a.to_string(),
            is_delete: false,
            device_id: device_a_id.to_string(),
            epoch: 0,
            server_seq: None,
        },
    ];

    insert_pending_ops(&storage_a, &ops_a, "batch-a1");

    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay.clone(),
        vec![entity_a],
        test_schema(),
        SyncConfig::default(),
    );

    // Push from device A
    let result_a = engine_a
        .sync(SYNC_ID, &key_hierarchy_a, &signing_key_a, device_a_id)
        .await
        .unwrap();
    assert!(
        result_a.error.is_none(),
        "push failed: {:?}",
        result_a.error
    );
    assert_eq!(result_a.pushed, 1, "expected 1 batch pushed");
    assert_eq!(relay.batch_count(), 1, "relay should have 1 batch");

    // --- Device B: pull and verify ---
    let key_hierarchy_b = {
        // Device B needs the same epoch key as A (same sync group).
        // In production this comes from rekey exchange; here we just reuse.
        let mut kh = prism_sync_crypto::KeyHierarchy::new();
        kh.initialize("test-password-b", &[2u8; 16]).unwrap();
        // Copy epoch 0 key from A
        let epoch0 = key_hierarchy_a.epoch_key(0).unwrap();
        kh.store_epoch_key(0, zeroize::Zeroizing::new(epoch0.to_vec()));
        kh
    };
    let signing_key_b = make_signing_key();
    let device_b_id = "device-bbb";

    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b = Arc::new(MockTaskEntity::new());
    let entity_b_ref: Arc<dyn SyncableEntity> = entity_b.clone();

    setup_sync_metadata(&storage_b, device_b_id);
    // Device B must know device A's public key for signature verification
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
        vec![entity_b_ref],
        test_schema(),
        SyncConfig::default(),
    );

    let result_b = engine_b
        .sync(SYNC_ID, &key_hierarchy_b, &signing_key_b, device_b_id)
        .await
        .unwrap();
    assert!(
        result_b.error.is_none(),
        "pull failed: {:?}",
        result_b.error
    );
    assert_eq!(result_b.pulled, 1, "expected 1 batch pulled");
    assert_eq!(result_b.merged, 2, "expected 2 ops merged (title + done)");

    // Verify entity data arrived
    let title = entity_b.get_field("task-1", "title");
    assert_eq!(title, Some(SyncValue::String("Buy groceries".to_string())));

    let done = entity_b.get_field("task-1", "done");
    assert_eq!(done, Some(SyncValue::Bool(false)));
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 2: Conflict resolution — higher HLC wins
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_conflict_resolution() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_local = make_signing_key();
    let signing_key_remote = make_signing_key();
    let local_device = "device-local";
    let remote_device = "device-remote";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    setup_sync_metadata(&storage, local_device);
    register_device(
        &relay,
        &storage,
        local_device,
        &signing_key_local.verifying_key(),
    );
    register_device(
        &relay,
        &storage,
        remote_device,
        &signing_key_remote.verifying_key(),
    );

    // Local device wrote title="Local Title" at a recent HLC
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let hlc_local = Hlc::new(now_ms - 5000, 0, local_device);

    // Seed a field_version for the local write so merge sees it as the incumbent
    {
        use prism_sync_core::storage::{FieldVersion, SyncStorage};
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_field_version(&FieldVersion {
            sync_id: SYNC_ID.to_string(),
            entity_table: "tasks".to_string(),
            entity_id: "task-conflict".to_string(),
            field_name: "title".to_string(),
            winning_op_id: "local-op-1".to_string(),
            winning_device_id: local_device.to_string(),
            winning_hlc: hlc_local.to_string(),
            winning_encoded_value: None,
            updated_at: chrono::Utc::now(),
        })
        .unwrap();
        tx.commit().unwrap();
    }

    // Remote device wrote title="Remote Title" at a later HLC (HIGHER — should win)
    let hlc_remote = Hlc::new(now_ms - 2000, 0, remote_device);
    let remote_ops = vec![CrdtChange {
        op_id: format!("tasks:task-conflict:title:{}:{}", hlc_remote, remote_device),
        batch_id: Some("batch-remote".to_string()),
        entity_id: "task-conflict".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Remote Title\"".to_string(),
        client_hlc: hlc_remote.to_string(),
        is_delete: false,
        device_id: remote_device.to_string(),
        epoch: 0,
        server_seq: None,
    }];

    let envelope = make_encrypted_batch(
        &remote_ops,
        &key_hierarchy,
        &signing_key_remote,
        "batch-remote",
        remote_device,
    );
    relay.inject_batch(envelope);

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, local_device)
        .await
        .unwrap();
    assert!(result.error.is_none(), "sync error: {:?}", result.error);
    assert_eq!(result.merged, 1, "remote op should win and be applied");

    // Remote's higher HLC should have won
    let title = entity.get_field("task-conflict", "title");
    assert_eq!(
        title,
        Some(SyncValue::String("Remote Title".to_string())),
        "Higher HLC (remote) should win the conflict"
    );

    // Verify field_version was updated to reflect remote winner
    {
        use prism_sync_core::storage::SyncStorage;
        let fv = storage
            .get_field_version(SYNC_ID, "tasks", "task-conflict", "title")
            .unwrap()
            .expect("field_version should exist");
        assert_eq!(fv.winning_device_id, remote_device);
        assert_eq!(fv.winning_hlc, hlc_remote.to_string());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 3: Signature verification — wrong signature is rejected
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_signature_verification() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_local = make_signing_key();
    let signing_key_remote = make_signing_key();
    let signing_key_attacker = make_signing_key(); // different key!
    let local_device = "device-local";
    let remote_device = "device-remote";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, local_device);
    register_device(
        &relay,
        &storage,
        local_device,
        &signing_key_local.verifying_key(),
    );
    // Register remote device with its REAL public key
    register_device(
        &relay,
        &storage,
        remote_device,
        &signing_key_remote.verifying_key(),
    );

    // Create a batch signed with the ATTACKER's key (not the remote device's)
    let hlc = Hlc::now(remote_device, None);
    let ops = vec![CrdtChange {
        op_id: "attacker-op-1".to_string(),
        batch_id: Some("batch-evil".to_string()),
        entity_id: "task-evil".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Evil Title\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: remote_device.to_string(), // claims to be remote
        epoch: 0,
        server_seq: None,
    }];

    // Sign with attacker's key (not the registered remote key)
    let envelope = make_encrypted_batch(
        &ops,
        &key_hierarchy,
        &signing_key_attacker,
        "batch-evil",
        remote_device,
    );
    relay.inject_batch(envelope);

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, local_device)
        .await
        .unwrap();

    // Bad-signature batches are skipped (not merged), not fatal errors.
    // The batch is counted as pulled (server_seq advanced) but not merged.
    assert!(
        result.error.is_none(),
        "Signature failure should skip the batch, not abort sync: {:?}",
        result.error
    );
    assert_eq!(
        result.pulled, 1,
        "Bad batch should still be counted as pulled"
    );
    assert_eq!(result.merged, 0, "Bad batch should NOT be merged");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 4: Payload hash verification — tampered ciphertext content rejected
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_payload_hash_verification() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_local = make_signing_key();
    let signing_key_remote = make_signing_key();
    let local_device = "device-local";
    let remote_device = "device-remote";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, local_device);
    register_device(
        &relay,
        &storage,
        local_device,
        &signing_key_local.verifying_key(),
    );
    register_device(
        &relay,
        &storage,
        remote_device,
        &signing_key_remote.verifying_key(),
    );

    // Build a valid batch first
    let hlc = Hlc::now(remote_device, None);
    let ops_original = vec![CrdtChange {
        op_id: "legit-op-1".to_string(),
        batch_id: Some("batch-tampered".to_string()),
        entity_id: "task-legit".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Original Title\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: remote_device.to_string(),
        epoch: 0,
        server_seq: None,
    }];

    // Compute payload_hash from the ORIGINAL ops
    let plaintext_original = CrdtChange::encode_batch(&ops_original).unwrap();
    let payload_hash_original = batch_signature::compute_payload_hash(&plaintext_original);

    // Now encrypt DIFFERENT content (tampered ops) but sign with the original hash
    let ops_tampered = vec![CrdtChange {
        op_id: "legit-op-1".to_string(),
        batch_id: Some("batch-tampered".to_string()),
        entity_id: "task-legit".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"TAMPERED Title\"".to_string(), // different!
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: remote_device.to_string(),
        epoch: 0,
        server_seq: None,
    }];

    let plaintext_tampered = CrdtChange::encode_batch(&ops_tampered).unwrap();

    let epoch_key = key_hierarchy.epoch_key(0).unwrap();
    let aad = sync_aad::build_sync_aad(SYNC_ID, remote_device, 0, "batch-tampered", "ops");
    let (ciphertext, nonce) =
        prism_sync_crypto::aead::xchacha_encrypt_for_sync(epoch_key, &plaintext_tampered, &aad)
            .unwrap();

    // Sign with the ORIGINAL payload_hash (mismatches the encrypted content)
    let envelope = batch_signature::sign_batch(
        &signing_key_remote,
        SYNC_ID,
        0,
        "batch-tampered",
        "ops",
        remote_device,
        &payload_hash_original, // hash of original, but ciphertext is tampered
        nonce,
        ciphertext,
    )
    .unwrap();

    relay.inject_batch(envelope);

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, local_device)
        .await
        .unwrap();

    // The pull phase should have failed due to payload hash mismatch
    assert!(
        result.error.is_some(),
        "Expected an error from payload hash mismatch, got success"
    );
    let err_msg = result.error.unwrap();
    assert!(
        err_msg.contains("hash") || err_msg.contains("Hash") || err_msg.contains("payload"),
        "Error should mention payload hash mismatch: {err_msg}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 5: Ack is sent after pull with correct max_server_seq
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_sync_sends_ack_after_pull() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_local = make_signing_key();
    let signing_key_remote = make_signing_key();
    let local_device = "device-local";
    let remote_device = "device-remote";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, local_device);
    register_device(
        &relay,
        &storage,
        local_device,
        &signing_key_local.verifying_key(),
    );
    register_device(
        &relay,
        &storage,
        remote_device,
        &signing_key_remote.verifying_key(),
    );

    // Inject a batch from the remote device
    let hlc = Hlc::now(remote_device, None);
    let ops = vec![CrdtChange {
        op_id: format!("tasks:t1:title:{}:{}", hlc, remote_device),
        batch_id: Some("batch-1".to_string()),
        entity_id: "t1".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Hello\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: remote_device.to_string(),
        epoch: 0,
        server_seq: None,
    }];
    let envelope = make_encrypted_batch(
        &ops,
        &key_hierarchy,
        &signing_key_remote,
        "batch-1",
        remote_device,
    );
    let injected_seq = relay.inject_batch(envelope);

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, local_device)
        .await
        .unwrap();
    assert!(result.error.is_none(), "sync failed: {:?}", result.error);

    // Yield to let the fire-and-forget ack task complete
    tokio::task::yield_now().await;

    // Verify ack was called with the injected batch's server_seq
    let acks = relay.ack_calls();
    assert_eq!(acks.len(), 1, "expected exactly 1 ack call");
    assert_eq!(
        acks[0], injected_seq,
        "ack should report the max_server_seq from pull"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 6: Ack failure does not abort sync
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_ack_failure_does_not_abort_sync() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_local = make_signing_key();
    let signing_key_remote = make_signing_key();
    let local_device = "device-local";
    let remote_device = "device-remote";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, local_device);
    register_device(
        &relay,
        &storage,
        local_device,
        &signing_key_local.verifying_key(),
    );
    register_device(
        &relay,
        &storage,
        remote_device,
        &signing_key_remote.verifying_key(),
    );

    let hlc = Hlc::now(remote_device, None);
    let ops = vec![CrdtChange {
        op_id: format!("tasks:t1:title:{}:{}", hlc, remote_device),
        batch_id: Some("batch-1".to_string()),
        entity_id: "t1".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Hello\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: remote_device.to_string(),
        epoch: 0,
        server_seq: None,
    }];
    let envelope = make_encrypted_batch(
        &ops,
        &key_hierarchy,
        &signing_key_remote,
        "batch-1",
        remote_device,
    );
    relay.inject_batch(envelope);

    // Make ack fail
    relay.set_ack_error("simulated network failure");

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, local_device)
        .await
        .unwrap();

    // Sync should succeed despite ack failure
    assert!(
        result.error.is_none(),
        "ack failure should not cause sync error: {:?}",
        result.error
    );
    assert_eq!(result.pulled, 1, "batch should still be pulled");
    assert_eq!(result.merged, 1, "ops should still be merged");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 7: Pruning runs when min_acked_seq is available
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_sync_prunes_with_min_acked_seq() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_local = make_signing_key();
    let signing_key_remote = make_signing_key();
    let local_device = "device-local";
    let remote_device = "device-remote";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, local_device);
    register_device(
        &relay,
        &storage,
        local_device,
        &signing_key_local.verifying_key(),
    );
    register_device(
        &relay,
        &storage,
        remote_device,
        &signing_key_remote.verifying_key(),
    );

    // Inject and pull a batch first so applied_ops get populated
    let hlc = Hlc::now(remote_device, None);
    let ops = vec![CrdtChange {
        op_id: format!("tasks:t1:title:{}:{}", hlc, remote_device),
        batch_id: Some("batch-1".to_string()),
        entity_id: "t1".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Hello\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: remote_device.to_string(),
        epoch: 0,
        server_seq: None,
    }];
    let envelope = make_encrypted_batch(
        &ops,
        &key_hierarchy,
        &signing_key_remote,
        "batch-1",
        remote_device,
    );
    relay.inject_batch(envelope);

    // Set min_acked_seq high enough to prune the batch we just pulled
    relay.set_min_acked_seq(100);

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, local_device)
        .await
        .unwrap();
    assert!(result.error.is_none(), "sync failed: {:?}", result.error);

    // Should have pruned the applied_ops for the batch we pulled
    assert!(
        result.pruned > 0,
        "expected pruning to have cleaned up ops, got pruned={}",
        result.pruned
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 8: Pruning runs on empty pull when min_acked_seq is set
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_prune_runs_on_empty_pull() {
    use prism_sync_core::storage::{AppliedOp, SyncStorage};

    let key_hierarchy = init_key_hierarchy();
    let signing_key = make_signing_key();
    let device_id = "device-local";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, device_id);
    register_device(&relay, &storage, device_id, &signing_key.verifying_key());

    // Manually insert an applied_op with a low server_seq
    {
        let mut tx = storage.begin_tx().unwrap();
        tx.insert_applied_op(&AppliedOp {
            op_id: "old-op-1".to_string(),
            sync_id: SYNC_ID.to_string(),
            epoch: 0,
            device_id: "device-remote".to_string(),
            client_hlc: "0:0:device-remote".to_string(),
            server_seq: 5,
            applied_at: chrono::Utc::now(),
        })
        .unwrap();
        tx.commit().unwrap();
    }

    // No batches to pull, but min_acked_seq is above our applied_op
    relay.set_min_acked_seq(10);

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key, device_id)
        .await
        .unwrap();
    assert!(result.error.is_none(), "sync failed: {:?}", result.error);

    // Verify the old applied_op was pruned
    assert!(
        result.pruned > 0,
        "expected pruning on empty pull with min_acked_seq=10"
    );

    // Verify the op is actually gone from storage
    assert!(
        !storage.is_op_applied("old-op-1").unwrap(),
        "old-op-1 should have been pruned from applied_ops"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 9: No pruning when min_acked_seq is None
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_no_pruning_without_min_acked_seq() {
    use prism_sync_core::storage::{AppliedOp, SyncStorage};

    let key_hierarchy = init_key_hierarchy();
    let signing_key = make_signing_key();
    let device_id = "device-local";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, device_id);
    register_device(&relay, &storage, device_id, &signing_key.verifying_key());

    // Insert an applied_op
    {
        let mut tx = storage.begin_tx().unwrap();
        tx.insert_applied_op(&AppliedOp {
            op_id: "keep-me".to_string(),
            sync_id: SYNC_ID.to_string(),
            epoch: 0,
            device_id: "device-remote".to_string(),
            client_hlc: "0:0:device-remote".to_string(),
            server_seq: 5,
            applied_at: chrono::Utc::now(),
        })
        .unwrap();
        tx.commit().unwrap();
    }

    // min_acked_seq is None (default) — no pruning should happen

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key, device_id)
        .await
        .unwrap();
    assert!(result.error.is_none(), "sync failed: {:?}", result.error);
    assert_eq!(result.pruned, 0, "should not prune without min_acked_seq");

    // Op should still exist
    assert!(
        storage.is_op_applied("keep-me").unwrap(),
        "op should not have been pruned"
    );
}
