//! Regression tests for pruning tombstoned entities.

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::SigningKey;

use prism_sync_core::engine::{SyncConfig, SyncEngine};
use prism_sync_core::pruning::TombstonePruner;
use prism_sync_core::relay::{MockRelay, SignedBatchEnvelope};
use prism_sync_core::schema::SyncValue;
use prism_sync_core::storage::{AppliedOp, FieldVersion, RusqliteSyncStorage, SyncStorage};
use prism_sync_core::syncable_entity::SyncableEntity;
use prism_sync_core::{batch_signature, sync_aad, CrdtChange, Hlc};

use common::*;

fn make_encrypted_batch(
    ops: &[CrdtChange],
    key_hierarchy: &prism_sync_crypto::KeyHierarchy,
    signing_key: &SigningKey,
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

#[tokio::test]
async fn prune_preserves_tombstone_and_blocks_stale_pre_tombstone_update() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_local = make_signing_key();
    let signing_key_remote = make_signing_key();
    let ml_dsa_key_remote = make_ml_dsa_keypair();
    let local_device = "device-local";
    let remote_device = "device-remote";
    let entity_id = "t-dead";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    setup_sync_metadata(&storage, local_device);
    register_device(&relay, &storage, local_device, &signing_key_local.verifying_key());
    register_device_with_pq(
        &relay,
        &storage,
        remote_device,
        &signing_key_remote.verifying_key(),
        &ml_dsa_key_remote.public_key_bytes(),
    );

    let title_hlc = Hlc::new(1_000, 0, remote_device);
    let delete_hlc = Hlc::new(2_000, 0, remote_device);
    let title_op_id = format!("tasks:{entity_id}:title:{title_hlc}:{remote_device}");
    let delete_op_id = format!("tasks:{entity_id}:is_deleted:{delete_hlc}:{remote_device}");

    let mut local_fields = HashMap::new();
    local_fields.insert("title".to_string(), SyncValue::String("Before delete".to_string()));
    entity.write_fields(entity_id, &local_fields, &title_hlc.to_string(), true).await.unwrap();
    entity.soft_delete(entity_id, &delete_hlc.to_string()).await.unwrap();

    {
        let mut tx = storage.begin_tx().unwrap();
        tx.insert_applied_op(&AppliedOp {
            op_id: title_op_id.clone(),
            sync_id: SYNC_ID.to_string(),
            epoch: 0,
            device_id: remote_device.to_string(),
            client_hlc: title_hlc.to_string(),
            server_seq: 1,
            applied_at: chrono::Utc::now(),
        })
        .unwrap();
        tx.insert_applied_op(&AppliedOp {
            op_id: delete_op_id.clone(),
            sync_id: SYNC_ID.to_string(),
            epoch: 0,
            device_id: remote_device.to_string(),
            client_hlc: delete_hlc.to_string(),
            server_seq: 2,
            applied_at: chrono::Utc::now(),
        })
        .unwrap();
        tx.upsert_field_version(&FieldVersion {
            sync_id: SYNC_ID.to_string(),
            entity_table: "tasks".to_string(),
            entity_id: entity_id.to_string(),
            field_name: "title".to_string(),
            winning_op_id: title_op_id.clone(),
            winning_device_id: remote_device.to_string(),
            winning_hlc: title_hlc.to_string(),
            winning_encoded_value: Some("\"Before delete\"".to_string()),
            updated_at: chrono::Utc::now(),
        })
        .unwrap();
        tx.upsert_field_version(&FieldVersion {
            sync_id: SYNC_ID.to_string(),
            entity_table: "tasks".to_string(),
            entity_id: entity_id.to_string(),
            field_name: "is_deleted".to_string(),
            winning_op_id: delete_op_id.clone(),
            winning_device_id: remote_device.to_string(),
            winning_hlc: delete_hlc.to_string(),
            winning_encoded_value: Some("true".to_string()),
            updated_at: chrono::Utc::now(),
        })
        .unwrap();
        tx.commit().unwrap();
    }

    let registered_entities = vec![entity_ref.clone()];
    let prune_result =
        TombstonePruner::prune(storage.clone(), &registered_entities, SYNC_ID, 3, 100)
            .await
            .unwrap();

    assert_eq!(prune_result.entities_hard_deleted, 1);
    assert_eq!(prune_result.field_versions_pruned, 1);
    assert_eq!(prune_result.applied_ops_pruned, 2);
    assert!(entity.get_field(entity_id, "title").is_none());
    assert!(!storage.is_op_applied(&title_op_id).unwrap());
    assert!(!storage.is_op_applied(&delete_op_id).unwrap());
    assert!(storage.get_field_version(SYNC_ID, "tasks", entity_id, "title").unwrap().is_none());

    let tombstone = storage
        .get_field_version(SYNC_ID, "tasks", entity_id, "is_deleted")
        .unwrap()
        .expect("prune must preserve is_deleted tombstone field version");
    assert_eq!(tombstone.winning_op_id, delete_op_id);
    assert_eq!(tombstone.winning_encoded_value.as_deref(), Some("true"));

    let stale_hlc = Hlc::new(1_500, 0, remote_device);
    let stale_op_id = format!("tasks:{entity_id}:title:{stale_hlc}:{remote_device}");
    let stale_update = CrdtChange {
        op_id: stale_op_id,
        batch_id: Some("stale-batch".to_string()),
        entity_id: entity_id.to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Resurrected\"".to_string(),
        client_hlc: stale_hlc.to_string(),
        is_delete: false,
        device_id: remote_device.to_string(),
        epoch: 0,
        server_seq: None,
    };
    let envelope = make_encrypted_batch(
        &[stale_update],
        &key_hierarchy,
        &signing_key_remote,
        &ml_dsa_key_remote,
        "stale-batch",
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
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, None, local_device, 0)
        .await
        .unwrap();

    assert!(result.error.is_none(), "sync error: {:?}", result.error);
    assert_eq!(result.pulled, 1);
    assert_eq!(result.merged, 0, "stale pre-tombstone op must not win after prune");
    assert!(entity.get_field(entity_id, "title").is_none());

    let tombstone_after = storage
        .get_field_version(SYNC_ID, "tasks", entity_id, "is_deleted")
        .unwrap()
        .expect("stale replay must not remove the tombstone field version");
    assert_eq!(tombstone_after.winning_encoded_value.as_deref(), Some("true"));
}
