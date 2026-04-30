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

use prism_sync_core::engine::{SyncConfig, SyncEngine, SyncResult};
use prism_sync_core::relay::{MockRelay, SignedBatchEnvelope, SnapshotExchange, SyncTransport};
use prism_sync_core::schema::SyncValue;
use prism_sync_core::storage::{
    AppliedOpEntry, DeviceRegistryEntry, FieldVersionEntry, RusqliteSyncStorage, SnapshotData,
    SyncMetadataEntry, SyncStorage, SNAPSHOT_VERSION,
};
use prism_sync_core::syncable_entity::SyncableEntity;
use prism_sync_core::{batch_signature, sync_aad, CoreError, CrdtChange, Hlc};

use common::*;

// ═══════════════════════════════════════════════════════════════════════════
// Test-file-specific helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Create a signed + encrypted batch envelope from CrdtChange ops.
fn make_encrypted_batch(
    ops: &[CrdtChange],
    key_hierarchy: &prism_sync_crypto::KeyHierarchy,
    signing_key: &SigningKey,
    ml_dsa_signing_key: &prism_sync_crypto::DevicePqSigningKey,
    batch_id: &str,
    sender_device_id: &str,
) -> SignedBatchEnvelope {
    make_encrypted_batch_with_generation(
        ops,
        key_hierarchy,
        signing_key,
        ml_dsa_signing_key,
        batch_id,
        sender_device_id,
        0,
    )
}

fn make_encrypted_batch_with_generation(
    ops: &[CrdtChange],
    key_hierarchy: &prism_sync_crypto::KeyHierarchy,
    signing_key: &SigningKey,
    ml_dsa_signing_key: &prism_sync_crypto::DevicePqSigningKey,
    batch_id: &str,
    sender_device_id: &str,
    sender_ml_dsa_key_generation: u32,
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
        sender_ml_dsa_key_generation,
        &payload_hash,
        nonce,
        ciphertext,
    )
    .unwrap()
}

fn make_snapshot_envelope_bytes(
    snapshot: &SnapshotData,
    key_hierarchy: &prism_sync_crypto::KeyHierarchy,
    signing_key: &SigningKey,
    ml_dsa_signing_key: &prism_sync_crypto::DevicePqSigningKey,
    batch_id: &str,
    sender_device_id: &str,
    server_seq_at: i64,
) -> Vec<u8> {
    let json = serde_json::to_vec(snapshot).unwrap();
    let compressed = zstd::encode_all(json.as_slice(), 3).unwrap();
    let payload_hash = batch_signature::compute_payload_hash(&compressed);
    let epoch_key = key_hierarchy.epoch_key(0).unwrap();
    let aad = sync_aad::build_snapshot_aad(
        SYNC_ID,
        sender_device_id,
        0,
        server_seq_at,
        batch_id,
        "snapshot",
    );
    let (ciphertext, nonce) =
        prism_sync_crypto::aead::xchacha_encrypt_for_sync(epoch_key, &compressed, &aad).unwrap();

    let envelope = batch_signature::sign_batch(
        signing_key,
        ml_dsa_signing_key,
        SYNC_ID,
        0,
        batch_id,
        "snapshot",
        sender_device_id,
        0,
        &payload_hash,
        nonce,
        ciphertext,
    )
    .unwrap();

    serde_json::to_vec(&envelope).unwrap()
}

fn task_title_op(op_id: &str, device_id: &str, hlc_node_id: &str) -> CrdtChange {
    let hlc = Hlc::new(1_710_500_000_000, 0, hlc_node_id);
    CrdtChange {
        op_id: op_id.to_string(),
        batch_id: Some("batch-attribution".to_string()),
        entity_id: "task-attribution".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Forged title\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: device_id.to_string(),
        epoch: 0,
        server_seq: None,
    }
}

async fn pull_injected_sender_batch(
    ops: Vec<CrdtChange>,
) -> (SyncResult, Arc<RusqliteSyncStorage>, Arc<MockTaskEntity>) {
    pull_injected_sender_batch_with_config(ops, SyncConfig::default()).await
}

async fn pull_injected_sender_batch_with_config(
    ops: Vec<CrdtChange>,
    config: SyncConfig,
) -> (SyncResult, Arc<RusqliteSyncStorage>, Arc<MockTaskEntity>) {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    let envelope = make_encrypted_batch(
        &ops,
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "batch-attribution",
        sender_id,
    );
    relay.inject_batch(envelope);

    let engine = SyncEngine::new(storage.clone(), relay, vec![entity_ref], test_schema(), config);
    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap();

    (result, storage, entity)
}

fn current_time_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

fn snapshot_device_entry(
    device_id: &str,
    verifying_key: &ed25519_dalek::VerifyingKey,
    ml_dsa_pk: &[u8],
) -> DeviceRegistryEntry {
    DeviceRegistryEntry {
        device_id: device_id.to_string(),
        ed25519_public_key: hex::encode(verifying_key.to_bytes()),
        x25519_public_key: hex::encode([0u8; 32]),
        ml_dsa_65_public_key: hex::encode(ml_dsa_pk),
        ml_kem_768_public_key: String::new(),
        x_wing_public_key: String::new(),
        status: "active".to_string(),
        registered_at: "2024-03-15T00:00:00Z".to_string(),
        revoked_at: None,
        ml_dsa_key_generation: 0,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Attribution binding regressions
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn rejects_entire_batch_when_op_device_id_differs_from_envelope_sender() {
    let sender_id = "device-sender";
    let good = task_title_op("op-good", sender_id, sender_id);
    let bad = CrdtChange {
        op_id: "op-bad-device".to_string(),
        field_name: "done".to_string(),
        encoded_value: "true".to_string(),
        ..task_title_op("op-bad-device", "device-forged", "device-forged")
    };

    let (result, storage, entity) = pull_injected_sender_batch(vec![good, bad]).await;

    let err = result.error.as_deref().unwrap_or("");
    assert!(err.contains("CRDT op attribution mismatch"), "{err}");
    assert_eq!(result.merged, 0);
    assert_eq!(entity.get_field("task-attribution", "title"), None);
    assert_eq!(entity.get_field("task-attribution", "done"), None);
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        0,
        "bad-attribution batch must not advance the pull cursor"
    );
}

#[tokio::test]
async fn rejects_batch_when_op_hlc_node_differs_from_envelope_sender() {
    let sender_id = "device-sender";
    let op = task_title_op("op-bad-hlc", sender_id, "device-forged");

    let (result, storage, entity) = pull_injected_sender_batch(vec![op]).await;

    let err = result.error.as_deref().unwrap_or("");
    assert!(err.contains("CRDT op HLC attribution mismatch"), "{err}");
    assert_eq!(result.merged, 0);
    assert_eq!(entity.get_field("task-attribution", "title"), None);
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        0,
        "bad-attribution batch must not advance the pull cursor"
    );
}

#[tokio::test]
async fn snapshot_import_accepts_rows_from_trusted_non_uploader_device() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_source = make_signing_key();
    let ml_dsa_key_source = make_ml_dsa_keypair();
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let source_id = "device-source";
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";
    let server_seq_at = 7;

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        source_id,
        &signing_key_source.verifying_key(),
        &ml_dsa_key_source.public_key_bytes(),
    );
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    let source_hlc = Hlc::new(1_710_500_000_000, 0, source_id).to_string();
    let snapshot = SnapshotData {
        version: SNAPSHOT_VERSION,
        field_versions: vec![FieldVersionEntry {
            entity_table: "tasks".to_string(),
            entity_id: "task-snapshot".to_string(),
            field_name: "title".to_string(),
            winning_hlc: source_hlc.clone(),
            winning_device_id: source_id.to_string(),
            winning_op_id: "op-source-snapshot".to_string(),
            winning_encoded_value: Some("\"Source snapshot row\"".to_string()),
            updated_at: "2024-03-15T00:00:00Z".to_string(),
        }],
        device_registry: vec![
            snapshot_device_entry(
                source_id,
                &signing_key_source.verifying_key(),
                &ml_dsa_key_source.public_key_bytes(),
            ),
            snapshot_device_entry(
                sender_id,
                &signing_key_sender.verifying_key(),
                &ml_dsa_key_sender.public_key_bytes(),
            ),
        ],
        applied_ops: vec![AppliedOpEntry {
            op_id: "op-source-snapshot".to_string(),
            sync_id: SYNC_ID.to_string(),
            epoch: 0,
            device_id: source_id.to_string(),
            client_hlc: source_hlc,
            server_seq: server_seq_at,
            applied_at: "2024-03-15T00:00:00Z".to_string(),
        }],
        sync_metadata: SyncMetadataEntry {
            sync_id: SYNC_ID.to_string(),
            local_device_id: sender_id.to_string(),
            current_epoch: 0,
            last_pulled_server_seq: server_seq_at,
        },
    };
    let envelope_bytes = make_snapshot_envelope_bytes(
        &snapshot,
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "snapshot-trusted-source",
        sender_id,
        server_seq_at,
    );
    relay
        .put_snapshot(0, server_seq_at, envelope_bytes, None, None, sender_id.to_string(), None)
        .await
        .unwrap();

    let engine =
        SyncEngine::new(storage.clone(), relay, vec![entity], test_schema(), SyncConfig::default());
    let (count, entity_changes) =
        engine.bootstrap_from_snapshot(SYNC_ID, &key_hierarchy).await.unwrap();

    assert_eq!(count, 1);
    assert_eq!(
        storage
            .get_field_version(SYNC_ID, "tasks", "task-snapshot", "title")
            .unwrap()
            .unwrap()
            .winning_device_id,
        source_id
    );
    assert!(storage.is_op_applied("op-source-snapshot").unwrap());
    assert_eq!(entity_changes.len(), 1);
    assert_eq!(entity_changes[0].fields.get("title"), Some(&"\"Source snapshot row\"".to_string()));
}

#[tokio::test]
async fn snapshot_import_rejects_rows_from_untrusted_foreign_device() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";
    let foreign_id = "device-forged";
    let server_seq_at = 7;

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    let foreign_hlc = Hlc::new(1_710_500_000_000, 0, foreign_id).to_string();
    let snapshot = SnapshotData {
        version: SNAPSHOT_VERSION,
        field_versions: vec![FieldVersionEntry {
            entity_table: "tasks".to_string(),
            entity_id: "task-snapshot".to_string(),
            field_name: "title".to_string(),
            winning_hlc: foreign_hlc.clone(),
            winning_device_id: foreign_id.to_string(),
            winning_op_id: "op-foreign-snapshot".to_string(),
            winning_encoded_value: Some("\"Foreign snapshot row\"".to_string()),
            updated_at: "2024-03-15T00:00:00Z".to_string(),
        }],
        device_registry: Vec::new(),
        applied_ops: Vec::new(),
        sync_metadata: SyncMetadataEntry {
            sync_id: SYNC_ID.to_string(),
            local_device_id: sender_id.to_string(),
            current_epoch: 0,
            last_pulled_server_seq: server_seq_at,
        },
    };
    let envelope_bytes = make_snapshot_envelope_bytes(
        &snapshot,
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "snapshot-attribution",
        sender_id,
        server_seq_at,
    );
    relay
        .put_snapshot(0, server_seq_at, envelope_bytes, None, None, sender_id.to_string(), None)
        .await
        .unwrap();

    let engine =
        SyncEngine::new(storage.clone(), relay, vec![entity], test_schema(), SyncConfig::default());
    let result = engine.bootstrap_from_snapshot(SYNC_ID, &key_hierarchy).await;

    let err = result.unwrap_err().to_string();
    assert!(err.contains("snapshot field_versions references untrusted device"), "{err}");
    assert!(
        storage.get_field_version(SYNC_ID, "tasks", "task-snapshot", "title").unwrap().is_none(),
        "foreign-attribution snapshot row must not be imported"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// HLC hardening regressions
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn drops_malformed_hlc_op_without_blocking_good_ops_in_same_batch() {
    let sender_id = "device-sender";
    let good_hlc = Hlc::new(current_time_ms() - 1_000, 0, sender_id);

    let good = CrdtChange {
        op_id: "op-good-hlc".to_string(),
        batch_id: Some("batch-attribution".to_string()),
        entity_id: "task-malformed-hlc".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Accepted title\"".to_string(),
        client_hlc: good_hlc.to_string(),
        is_delete: false,
        device_id: sender_id.to_string(),
        epoch: 0,
        server_seq: None,
    };
    let malformed = CrdtChange {
        op_id: "op-malformed-hlc".to_string(),
        batch_id: Some("batch-attribution".to_string()),
        entity_id: "task-malformed-hlc".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "done".to_string(),
        encoded_value: "true".to_string(),
        client_hlc: "-1:0:device-sender".to_string(),
        is_delete: false,
        device_id: sender_id.to_string(),
        epoch: 0,
        server_seq: None,
    };

    let (result, storage, entity) = pull_injected_sender_batch(vec![good, malformed]).await;

    assert!(result.error.is_none(), "malformed HLC op should be dropped: {:?}", result.error);
    assert_eq!(result.pulled, 1);
    assert_eq!(result.merged, 1);
    assert_eq!(
        entity.get_field("task-malformed-hlc", "title"),
        Some(SyncValue::String("Accepted title".to_string()))
    );
    assert_eq!(entity.get_field("task-malformed-hlc", "done"), None);
    assert!(storage.is_op_applied("op-good-hlc").unwrap());
    assert!(!storage.is_op_applied("op-malformed-hlc").unwrap());
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        1,
        "batch cursor should advance after dropping only the malformed op"
    );
}

#[tokio::test]
async fn drops_future_drifted_op_without_blocking_good_ops_in_same_batch() {
    let sender_id = "device-sender";
    let now_ms = current_time_ms();
    let good_hlc = Hlc::new(now_ms - 1_000, 0, sender_id);
    let future_hlc = Hlc::new(now_ms + 120_000, 0, sender_id);

    let good = CrdtChange {
        op_id: "op-good-hlc".to_string(),
        batch_id: Some("batch-attribution".to_string()),
        entity_id: "task-hlc-drift".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Accepted title\"".to_string(),
        client_hlc: good_hlc.to_string(),
        is_delete: false,
        device_id: sender_id.to_string(),
        epoch: 0,
        server_seq: None,
    };
    let future_drifted = CrdtChange {
        op_id: "op-future-hlc".to_string(),
        batch_id: Some("batch-attribution".to_string()),
        entity_id: "task-hlc-drift".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "done".to_string(),
        encoded_value: "true".to_string(),
        client_hlc: future_hlc.to_string(),
        is_delete: false,
        device_id: sender_id.to_string(),
        epoch: 0,
        server_seq: None,
    };

    let (result, storage, entity) = pull_injected_sender_batch_with_config(
        vec![good, future_drifted],
        SyncConfig { max_clock_drift_ms: 1_000 },
    )
    .await;

    assert!(result.error.is_none(), "future-drifted op should be dropped: {:?}", result.error);
    assert_eq!(result.pulled, 1);
    assert_eq!(result.merged, 1);
    assert_eq!(
        entity.get_field("task-hlc-drift", "title"),
        Some(SyncValue::String("Accepted title".to_string()))
    );
    assert_eq!(entity.get_field("task-hlc-drift", "done"), None);
    assert!(storage.is_op_applied("op-good-hlc").unwrap());
    assert!(!storage.is_op_applied("op-future-hlc").unwrap());
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        1,
        "batch cursor should advance after applying the non-drifted ops"
    );
}

#[tokio::test]
async fn skips_batch_when_envelope_generation_differs_from_registry_generation() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_local = make_signing_key();
    let signing_key_remote = make_signing_key();
    let ml_dsa_key_remote = make_ml_dsa_keypair();
    let local_device = "device-local";
    let remote_device = "device-remote";

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

    let hlc = Hlc::new(current_time_ms() - 1_000, 0, remote_device);
    let ops = vec![CrdtChange {
        op_id: "op-generation-mismatch".to_string(),
        batch_id: Some("batch-generation-mismatch".to_string()),
        entity_id: "task-generation-mismatch".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Should not merge\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: remote_device.to_string(),
        epoch: 0,
        server_seq: None,
    }];

    let envelope = make_encrypted_batch_with_generation(
        &ops,
        &key_hierarchy,
        &signing_key_remote,
        &ml_dsa_key_remote,
        "batch-generation-mismatch",
        remote_device,
        1,
    );
    relay.inject_batch(envelope);

    let engine = SyncEngine::new(
        storage.clone(),
        relay,
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );
    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, None, local_device, 0)
        .await
        .unwrap();

    assert!(result.error.is_none(), "generation mismatch should skip batch: {:?}", result.error);
    assert_eq!(result.pulled, 1);
    assert_eq!(result.merged, 0);
    assert_eq!(entity.get_field("task-generation-mismatch", "title"), None);
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        1,
        "bad-generation batch should be skipped and acknowledged like other bad signatures"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 1: Push and pull roundtrip
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_push_and_pull_roundtrip() {
    // --- Device A: create ops and push ---
    let key_hierarchy_a = init_key_hierarchy();
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
        .sync(SYNC_ID, &key_hierarchy_a, &signing_key_a, Some(&ml_dsa_key_a), device_a_id, 0)
        .await
        .unwrap();
    assert!(result_a.error.is_none(), "push failed: {:?}", result_a.error);
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
    register_device_with_pq(
        &relay,
        &storage_b,
        device_a_id,
        &signing_key_a.verifying_key(),
        &ml_dsa_key_a.public_key_bytes(),
    );
    register_device(&relay, &storage_b, device_b_id, &signing_key_b.verifying_key());

    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay.clone(),
        vec![entity_b_ref],
        test_schema(),
        SyncConfig::default(),
    );

    let result_b = engine_b
        .sync(SYNC_ID, &key_hierarchy_b, &signing_key_b, None, device_b_id, 0)
        .await
        .unwrap();
    assert!(result_b.error.is_none(), "pull failed: {:?}", result_b.error);
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
    let ml_dsa_key_remote = make_ml_dsa_keypair();
    let local_device = "device-local";
    let remote_device = "device-remote";

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

    // Local device wrote title="Local Title" at a recent HLC
    let now_ms =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()
            as i64;
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
        &ml_dsa_key_remote,
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
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, None, local_device, 0)
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
    let ml_dsa_key_remote = make_ml_dsa_keypair();
    let signing_key_attacker = make_signing_key(); // different key!
    let ml_dsa_key_attacker = make_ml_dsa_keypair(); // different key!
    let local_device = "device-local";
    let remote_device = "device-remote";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, local_device);
    register_device(&relay, &storage, local_device, &signing_key_local.verifying_key());
    // Register remote device with its REAL public key
    register_device_with_pq(
        &relay,
        &storage,
        remote_device,
        &signing_key_remote.verifying_key(),
        &ml_dsa_key_remote.public_key_bytes(),
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
        &ml_dsa_key_attacker,
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
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, None, local_device, 0)
        .await
        .unwrap();

    // Bad-signature batches are skipped (not merged), not fatal errors.
    // The batch is counted as pulled (server_seq advanced) but not merged.
    assert!(
        result.error.is_none(),
        "Signature failure should skip the batch, not abort sync: {:?}",
        result.error
    );
    assert_eq!(result.pulled, 1, "Bad batch should still be counted as pulled");
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
    let ml_dsa_key_remote = make_ml_dsa_keypair();
    let local_device = "device-local";
    let remote_device = "device-remote";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, local_device);
    register_device(&relay, &storage, local_device, &signing_key_local.verifying_key());
    register_device_with_pq(
        &relay,
        &storage,
        remote_device,
        &signing_key_remote.verifying_key(),
        &ml_dsa_key_remote.public_key_bytes(),
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
        &ml_dsa_key_remote,
        SYNC_ID,
        0,
        "batch-tampered",
        "ops",
        remote_device,
        0,
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
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, None, local_device, 0)
        .await
        .unwrap();

    // The pull phase should have failed due to payload hash mismatch
    assert!(result.error.is_some(), "Expected an error from payload hash mismatch, got success");
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
    let ml_dsa_key_remote = make_ml_dsa_keypair();
    let local_device = "device-local";
    let remote_device = "device-remote";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, local_device);
    register_device(&relay, &storage, local_device, &signing_key_local.verifying_key());
    register_device_with_pq(
        &relay,
        &storage,
        remote_device,
        &signing_key_remote.verifying_key(),
        &ml_dsa_key_remote.public_key_bytes(),
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
        &ml_dsa_key_remote,
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
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, None, local_device, 0)
        .await
        .unwrap();
    assert!(result.error.is_none(), "sync failed: {:?}", result.error);

    // Yield to let the fire-and-forget ack task complete
    tokio::task::yield_now().await;

    // Verify ack was called with the injected batch's server_seq
    let acks = relay.ack_calls();
    assert_eq!(acks.len(), 1, "expected exactly 1 ack call");
    assert_eq!(acks[0], injected_seq, "ack should report the max_server_seq from pull");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 6: Ack failure does not abort sync
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_ack_failure_does_not_abort_sync() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_local = make_signing_key();
    let signing_key_remote = make_signing_key();
    let ml_dsa_key_remote = make_ml_dsa_keypair();
    let local_device = "device-local";
    let remote_device = "device-remote";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, local_device);
    register_device(&relay, &storage, local_device, &signing_key_local.verifying_key());
    register_device_with_pq(
        &relay,
        &storage,
        remote_device,
        &signing_key_remote.verifying_key(),
        &ml_dsa_key_remote.public_key_bytes(),
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
        &ml_dsa_key_remote,
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
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, None, local_device, 0)
        .await
        .unwrap();

    // Sync should succeed despite ack failure
    assert!(result.error.is_none(), "ack failure should not cause sync error: {:?}", result.error);
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
    let ml_dsa_key_remote = make_ml_dsa_keypair();
    let local_device = "device-local";
    let remote_device = "device-remote";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, local_device);
    register_device(&relay, &storage, local_device, &signing_key_local.verifying_key());
    register_device_with_pq(
        &relay,
        &storage,
        remote_device,
        &signing_key_remote.verifying_key(),
        &ml_dsa_key_remote.public_key_bytes(),
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
        &ml_dsa_key_remote,
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
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, None, local_device, 0)
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

    let result =
        engine.sync(SYNC_ID, &key_hierarchy, &signing_key, None, device_id, 0).await.unwrap();
    assert!(result.error.is_none(), "sync failed: {:?}", result.error);

    // Verify the old applied_op was pruned
    assert!(result.pruned > 0, "expected pruning on empty pull with min_acked_seq=10");

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

    let result =
        engine.sync(SYNC_ID, &key_hierarchy, &signing_key, None, device_id, 0).await.unwrap();
    assert!(result.error.is_none(), "sync failed: {:?}", result.error);
    assert_eq!(result.pruned, 0, "should not prune without min_acked_seq");

    // Op should still exist
    assert!(storage.is_op_applied("keep-me").unwrap(), "op should not have been pruned");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 10: Push without ML-DSA key errors
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn push_without_ml_dsa_key_errors() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key = make_signing_key();
    let ml_dsa_key = make_ml_dsa_keypair();
    let device_id = "device-local";

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

    // Insert pending ops so there is something to push
    let hlc = Hlc::now(device_id, None);
    let ops = vec![CrdtChange {
        op_id: format!("tasks:t1:title:{}:{}", hlc, device_id),
        batch_id: Some("batch-nopq".to_string()),
        entity_id: "t1".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Hello\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: device_id.to_string(),
        epoch: 0,
        server_seq: None,
    }];
    insert_pending_ops(&storage, &ops, "batch-nopq");

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    // Call sync with None for ml_dsa_signing_key — push should fail
    let result =
        engine.sync(SYNC_ID, &key_hierarchy, &signing_key, None, device_id, 0).await.unwrap();

    assert!(result.error.is_some(), "Expected an error when pushing without ML-DSA signing key");
    let err_msg = result.error.unwrap();
    assert!(
        err_msg.contains("ML-DSA signing key required"),
        "Error should mention ML-DSA signing key required, got: {err_msg}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Push at current-epoch semantics (Bucket 3 of sync-robustness plan)
// ═══════════════════════════════════════════════════════════════════════════

/// Helper: seed epoch 1 key into a KeyHierarchy derived from epoch 0.
fn seed_epoch_1_key(kh: &mut prism_sync_crypto::KeyHierarchy) {
    // 32 deterministic bytes — the actual key value doesn't matter for
    // these tests; only that the hierarchy has something at epoch 1.
    kh.store_epoch_key(1, zeroize::Zeroizing::new(vec![0xCDu8; 32]));
}

/// Helper: overwrite `current_epoch` in `sync_metadata`.
fn set_metadata_current_epoch(storage: &RusqliteSyncStorage, device_id: &str, epoch: i32) {
    use prism_sync_core::storage::SyncStorage;
    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_sync_metadata(&prism_sync_core::SyncMetadata {
        sync_id: SYNC_ID.to_string(),
        local_device_id: device_id.to_string(),
        current_epoch: epoch,
        last_pulled_server_seq: 0,
        last_pushed_at: None,
        last_successful_sync_at: None,
        registered_at: Some(chrono::Utc::now()),
        needs_rekey: false,
        last_imported_registry_version: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    })
    .unwrap();
    tx.commit().unwrap();
}

fn make_op(device_id: &str, batch_id: &str, epoch: i32, suffix: &str) -> CrdtChange {
    let hlc = Hlc::now(device_id, None);
    CrdtChange {
        op_id: format!("tasks:task-{suffix}:title:{hlc}:{device_id}"),
        batch_id: Some(batch_id.to_string()),
        entity_id: format!("task-{suffix}"),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"hello\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: device_id.to_string(),
        epoch,
        server_seq: None,
    }
}

/// If the group rotates from epoch 0 -> 1 while ops are still pending at
/// epoch 0, the push must re-tag the envelope to the current epoch (1)
/// so the relay's `envelope.epoch == group.current_epoch` check succeeds.
#[tokio::test]
async fn push_uses_current_epoch_not_stored_op_epoch() {
    let mut key_hierarchy = init_key_hierarchy();
    seed_epoch_1_key(&mut key_hierarchy);

    let signing_key = make_signing_key();
    let ml_dsa_key = make_ml_dsa_keypair();
    let device_id = "device-push-curr";

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

    // Pending op was created at epoch 0.
    let ops = vec![make_op(device_id, "batch-push-curr", 0, "1")];
    insert_pending_ops(&storage, &ops, "batch-push-curr");

    // Group has since rotated to epoch 1.
    set_metadata_current_epoch(&storage, device_id, 1);

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
    assert!(result.error.is_none(), "push should succeed at re-tagged epoch: {:?}", result.error);
    assert_eq!(result.pushed, 1, "expected 1 batch pushed");
    assert_eq!(relay.batch_count(), 1, "relay should have 1 envelope");

    // The relay stores StoredBatch with envelope.epoch — we can't poke
    // into the private state, but pull_changes returns the envelopes.
    let pulled = relay.pull_changes(0).await.unwrap();
    assert_eq!(pulled.batches.len(), 1);
    assert_eq!(
        pulled.batches[0].envelope.epoch, 1,
        "envelope must be re-tagged to current_epoch (1)"
    );
}

/// Degenerate case: metadata claims current_epoch = N but the KeyHierarchy
/// has no key at N. Push must fail with a clear error, NOT silently fall
/// back to an older epoch key. It must bubble as `MissingEpochKey` so the
/// higher-level sync service can recover the key and retry the push.
#[tokio::test]
async fn push_still_fails_when_current_epoch_key_missing() {
    let key_hierarchy = init_key_hierarchy(); // only epoch 0 available

    let signing_key = make_signing_key();
    let ml_dsa_key = make_ml_dsa_keypair();
    let device_id = "device-push-missing-key";

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

    let ops = vec![make_op(device_id, "batch-missing-key", 0, "1")];
    insert_pending_ops(&storage, &ops, "batch-missing-key");
    set_metadata_current_epoch(&storage, device_id, 2); // no key for epoch 2

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    let err = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key, Some(&ml_dsa_key), device_id, 0)
        .await
        .expect_err("push must fail when current_epoch key is missing");
    assert!(matches!(err, CoreError::MissingEpochKey { epoch: 2 }), "unexpected error: {err}");
}

/// If the stored op epoch is somehow *higher* than sync_metadata
/// current_epoch (shouldn't happen in practice), the defensive `.max`
/// keeps the push at the higher value so it doesn't regress to a stale
/// epoch. Exercises the `current_epoch.max(ops[0].epoch)` branch.
#[tokio::test]
async fn push_honors_max_of_current_and_op_epoch() {
    let mut key_hierarchy = init_key_hierarchy();
    seed_epoch_1_key(&mut key_hierarchy);

    let signing_key = make_signing_key();
    let ml_dsa_key = make_ml_dsa_keypair();
    let device_id = "device-push-max";

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

    // Op claims epoch 1 (unexpected but possible after a recovered rekey);
    // sync_metadata still shows 0. Push must use epoch 1.
    let ops = vec![make_op(device_id, "batch-max", 1, "1")];
    insert_pending_ops(&storage, &ops, "batch-max");
    set_metadata_current_epoch(&storage, device_id, 0);

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
    assert!(result.error.is_none(), "push must succeed: {:?}", result.error);

    let pulled = relay.pull_changes(0).await.unwrap();
    assert_eq!(pulled.batches.len(), 1);
    assert_eq!(pulled.batches[0].envelope.epoch, 1, "envelope must be at max(current=0, op=1) = 1");
}
