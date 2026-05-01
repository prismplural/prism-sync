//! Launch-blocker harness for pair-time snapshot atomicity.
//!
//! These tests intentionally drive the public `PrismSync` snapshot bootstrap
//! API against real encrypted snapshots on `MockRelay`. A pairing attempt must
//! not look complete unless the whole snapshot imported and the consumer has a
//! chance to apply the emitted `RemoteChanges`; failed attempts must leave the
//! relay snapshot available for retry/cancel instead of ACKing it away.

mod common;

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use tokio::sync::broadcast::error::TryRecvError;

use prism_sync_core::batch_signature;
use prism_sync_core::engine::{SyncConfig, SyncEngine};
use prism_sync_core::events::SyncEvent;
use prism_sync_core::relay::traits::{SnapshotExchange, SnapshotResponse};
use prism_sync_core::relay::MockRelay;
use prism_sync_core::secure_store::SecureStore;
use prism_sync_core::storage::{RusqliteSyncStorage, SnapshotData, SyncStorage};
use prism_sync_core::syncable_entity::SyncableEntity;
use prism_sync_core::{CrdtChange, Hlc, PrismSync};

use common::*;

const PASSWORD: &str = "pairing-password";
const SECRET_KEY: &[u8; 16] = b"pairing-secret!!";
const DEVICE_A: &str = "device-aaa";
const DEVICE_B: &str = "device-bbb";
const DEVICE_C: &str = "device-ccc";

struct SnapshotFixture {
    relay: Arc<MockRelay>,
    key_hierarchy: prism_sync_crypto::KeyHierarchy,
    wrapped_dek: Vec<u8>,
    dek_salt: Vec<u8>,
    signing_key_a: SigningKey,
    signing_key_b: SigningKey,
    ml_dsa_key_a: prism_sync_crypto::DevicePqSigningKey,
    ml_dsa_key_b: prism_sync_crypto::DevicePqSigningKey,
    source_storage: Arc<RusqliteSyncStorage>,
    valid_snapshot: SnapshotResponse,
}

struct JoinerFixture {
    storage: Arc<RusqliteSyncStorage>,
    secure_store: Arc<MemorySecureStore>,
}

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

async fn create_snapshot_fixture(task_count: usize) -> SnapshotFixture {
    let mut key_hierarchy = prism_sync_crypto::KeyHierarchy::new();
    let (wrapped_dek, dek_salt) = key_hierarchy.initialize(PASSWORD, SECRET_KEY).unwrap();

    let signing_key_a = make_signing_key();
    let signing_key_b = make_signing_key();
    let ml_dsa_key_a = make_ml_dsa_keypair();
    let ml_dsa_key_b = make_ml_dsa_keypair();
    let relay = Arc::new(MockRelay::new());

    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    setup_sync_metadata(&storage_a, DEVICE_A);
    register_device_with_pq(
        &relay,
        &storage_a,
        DEVICE_A,
        &signing_key_a.verifying_key(),
        &ml_dsa_key_a.public_key_bytes(),
    );

    for i in 0..task_count {
        let task_id = format!("task-{i}");
        let title = format!("Task {i}");
        let batch_id = format!("batch-{i}");
        let ops = make_task_ops(DEVICE_A, &task_id, &title, i % 2 == 0, &batch_id);
        insert_pending_ops(&storage_a, &ops, &batch_id);
    }

    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay.clone(),
        vec![Arc::new(MockTaskEntity::new()) as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );
    let pushed = engine_a
        .sync(SYNC_ID, &key_hierarchy, &signing_key_a, Some(&ml_dsa_key_a), DEVICE_A, 0)
        .await
        .unwrap();
    assert!(pushed.error.is_none(), "source push failed: {:?}", pushed.error);

    let source_storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    setup_sync_metadata(&source_storage, DEVICE_B);
    register_device_with_pq(
        &relay,
        &source_storage,
        DEVICE_A,
        &signing_key_a.verifying_key(),
        &ml_dsa_key_a.public_key_bytes(),
    );
    register_device_with_pq(
        &relay,
        &source_storage,
        DEVICE_B,
        &signing_key_b.verifying_key(),
        &ml_dsa_key_b.public_key_bytes(),
    );

    let engine_b = SyncEngine::new(
        source_storage.clone(),
        relay.clone(),
        vec![Arc::new(MockTaskEntity::new()) as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );
    let pulled = engine_b
        .sync(SYNC_ID, &key_hierarchy, &signing_key_b, Some(&ml_dsa_key_b), DEVICE_B, 0)
        .await
        .unwrap();
    assert!(pulled.error.is_none(), "snapshot source pull failed: {:?}", pulled.error);
    assert_eq!(pulled.merged, (task_count * 2) as u64, "source must merge every task field");

    engine_b
        .upload_pairing_snapshot(
            SYNC_ID,
            &key_hierarchy,
            0,
            DEVICE_B,
            &signing_key_b,
            &ml_dsa_key_b,
            0,
            Some(300),
            None,
            None,
        )
        .await
        .unwrap();

    let valid_snapshot =
        relay.get_snapshot().await.unwrap().expect("snapshot source must upload snapshot");

    SnapshotFixture {
        relay,
        key_hierarchy,
        wrapped_dek,
        dek_salt,
        signing_key_a,
        signing_key_b,
        ml_dsa_key_a,
        ml_dsa_key_b,
        source_storage,
        valid_snapshot,
    }
}

fn create_joiner_fixture(source: &SnapshotFixture) -> JoinerFixture {
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    setup_sync_metadata(&storage, DEVICE_C);
    register_device_with_pq(
        &source.relay,
        &storage,
        DEVICE_A,
        &source.signing_key_a.verifying_key(),
        &source.ml_dsa_key_a.public_key_bytes(),
    );
    register_device_with_pq(
        &source.relay,
        &storage,
        DEVICE_B,
        &source.signing_key_b.verifying_key(),
        &source.ml_dsa_key_b.public_key_bytes(),
    );

    let signing_key_c = make_signing_key();
    let ml_dsa_key_c = make_ml_dsa_keypair();
    register_device_with_pq(
        &source.relay,
        &storage,
        DEVICE_C,
        &signing_key_c.verifying_key(),
        &ml_dsa_key_c.public_key_bytes(),
    );

    let secure_store = Arc::new(MemorySecureStore::new());
    secure_store.set("wrapped_dek", &source.wrapped_dek).unwrap();
    secure_store.set("dek_salt", &source.dek_salt).unwrap();
    secure_store
        .set("device_secret", prism_sync_crypto::DeviceSecret::generate().as_bytes())
        .unwrap();

    JoinerFixture { storage, secure_store }
}

fn build_joiner_sync(source: &SnapshotFixture, joiner: &JoinerFixture) -> PrismSync {
    let storage: Arc<dyn SyncStorage> = joiner.storage.clone();
    let secure_store: Arc<dyn SecureStore> = joiner.secure_store.clone();
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());
    let mut sync = PrismSync::builder()
        .schema(test_schema())
        .storage(storage)
        .secure_store(secure_store)
        .entity(entity)
        .build()
        .unwrap();
    sync.unlock(PASSWORD, SECRET_KEY).unwrap();
    sync.configure_engine(source.relay.clone(), SYNC_ID.to_string(), DEVICE_C.to_string(), 0, 0);
    sync
}

fn assert_joiner_has_no_snapshot_state(storage: &RusqliteSyncStorage) {
    let meta = storage.get_sync_metadata(SYNC_ID).unwrap().expect("joiner metadata exists");
    assert_eq!(meta.local_device_id, DEVICE_C);
    assert_eq!(meta.last_pulled_server_seq, 0, "failed bootstrap must not advance cursor");
    assert!(
        storage.get_field_version(SYNC_ID, "tasks", "task-0", "title").unwrap().is_none(),
        "failed bootstrap must not leave partially imported field_versions"
    );
}

fn assert_no_remote_changes_event(rx: &mut tokio::sync::broadcast::Receiver<SyncEvent>) {
    match rx.try_recv() {
        Err(TryRecvError::Empty) => {}
        other => panic!("failed bootstrap must not emit RemoteChanges, got {other:?}"),
    }
}

fn assert_remote_changes_event(
    rx: &mut tokio::sync::broadcast::Receiver<SyncEvent>,
    expected_entities: usize,
) {
    match rx.try_recv() {
        Ok(SyncEvent::RemoteChanges(changes)) => {
            assert_eq!(changes.entity_changes.len(), expected_entities);
        }
        other => panic!("successful bootstrap must emit RemoteChanges, got {other:?}"),
    }
}

async fn store_snapshot(relay: &MockRelay, snapshot: &SnapshotResponse) {
    relay
        .put_snapshot(
            snapshot.epoch,
            snapshot.server_seq_at,
            snapshot.data.clone(),
            Some(300),
            None,
            snapshot.sender_device_id.clone(),
            None,
        )
        .await
        .unwrap();
}

async fn store_aad_tampered_snapshot(relay: &MockRelay, snapshot: &SnapshotResponse) {
    relay
        .put_snapshot(
            snapshot.epoch,
            snapshot.server_seq_at + 1,
            snapshot.data.clone(),
            Some(300),
            None,
            snapshot.sender_device_id.clone(),
            None,
        )
        .await
        .unwrap();
}

fn signed_snapshot_with_mutated_plaintext(
    source: &SnapshotFixture,
    batch_id: &str,
    mutate: impl FnOnce(&mut SnapshotData),
) -> SnapshotResponse {
    let compressed = source.source_storage.export_snapshot(SYNC_ID).unwrap();
    let json = zstd::decode_all(compressed.as_slice()).unwrap();
    let mut snapshot_data: SnapshotData = serde_json::from_slice(&json).unwrap();
    mutate(&mut snapshot_data);

    let json = serde_json::to_vec(&snapshot_data).unwrap();
    let compressed = zstd::encode_all(json.as_slice(), 3).unwrap();
    let aad = prism_sync_core::sync_aad::build_snapshot_aad(
        SYNC_ID,
        DEVICE_B,
        source.valid_snapshot.epoch,
        source.valid_snapshot.server_seq_at,
        batch_id,
        "snapshot",
    );
    let epoch_key = source.key_hierarchy.epoch_key(source.valid_snapshot.epoch as u32).unwrap();
    let (ciphertext, nonce) =
        prism_sync_crypto::aead::xchacha_encrypt_for_sync(epoch_key, &compressed, &aad).unwrap();
    let payload_hash = batch_signature::compute_payload_hash(&compressed);
    let envelope = batch_signature::sign_batch(
        &source.signing_key_b,
        &source.ml_dsa_key_b,
        SYNC_ID,
        source.valid_snapshot.epoch,
        batch_id,
        "snapshot",
        DEVICE_B,
        0,
        &payload_hash,
        nonce,
        ciphertext,
    )
    .unwrap();

    SnapshotResponse {
        epoch: source.valid_snapshot.epoch,
        server_seq_at: source.valid_snapshot.server_seq_at,
        data: serde_json::to_vec(&envelope).unwrap(),
        sender_device_id: DEVICE_B.to_string(),
    }
}

async fn assert_snapshot_still_available(relay: &MockRelay) {
    assert!(
        relay.get_snapshot().await.unwrap().is_some(),
        "failed bootstrap must not ACK/delete the relay snapshot"
    );
}

async fn assert_ack_deletes_snapshot(sync: &PrismSync, relay: &MockRelay) {
    sync.acknowledge_snapshot_applied().await.unwrap();
    assert!(
        relay.get_snapshot().await.unwrap().is_none(),
        "ACK after successful import should delete the relay snapshot"
    );
}

#[tokio::test]
async fn tampered_snapshot_retry_preserves_credentials_and_only_acks_after_success() {
    let source = create_snapshot_fixture(2).await;
    let joiner = create_joiner_fixture(&source);

    store_aad_tampered_snapshot(&source.relay, &source.valid_snapshot).await;

    let mut first_attempt = build_joiner_sync(&source, &joiner);
    let mut rx = first_attempt.events();
    let result = first_attempt.bootstrap_from_snapshot().await;
    assert!(result.is_err(), "tampered snapshot metadata must fail before import");
    assert_joiner_has_no_snapshot_state(&joiner.storage);
    assert_no_remote_changes_event(&mut rx);
    assert_snapshot_still_available(&source.relay).await;

    store_snapshot(&source.relay, &source.valid_snapshot).await;

    // Rebuild the public handle from the same storage + secure-store material
    // to model the app retry path after a failed pair-time snapshot attempt.
    let mut retry_attempt = build_joiner_sync(&source, &joiner);
    let mut retry_rx = retry_attempt.events();
    let (restored, changes) = retry_attempt.bootstrap_from_snapshot().await.unwrap();
    assert_eq!(restored, 2);
    assert_eq!(changes.len(), 2);
    assert_eq!(
        joiner
            .storage
            .get_field_version(SYNC_ID, "tasks", "task-0", "title")
            .unwrap()
            .unwrap()
            .winning_encoded_value,
        Some("\"Task 0\"".to_string())
    );
    assert_remote_changes_event(&mut retry_rx, 2);
    assert_ack_deletes_snapshot(&retry_attempt, &source.relay).await;
}

#[tokio::test]
async fn mid_import_failure_rolls_back_and_keeps_snapshot_retryable() {
    let source = create_snapshot_fixture(3).await;
    let joiner = create_joiner_fixture(&source);
    let invalid_snapshot =
        signed_snapshot_with_mutated_plaintext(&source, "snapshot-invalid-registry", |snapshot| {
            snapshot.device_registry[0].ed25519_public_key = "not-hex".to_string();
        });
    store_snapshot(&source.relay, &invalid_snapshot).await;

    let mut failed_attempt = build_joiner_sync(&source, &joiner);
    let mut rx = failed_attempt.events();
    let result = failed_attempt.bootstrap_from_snapshot().await;
    let error = result.expect_err("invalid registry hex must fail during import").to_string();
    assert!(error.contains("bad hex in ed25519_public_key"), "unexpected import error: {error}");
    assert_joiner_has_no_snapshot_state(&joiner.storage);
    assert_no_remote_changes_event(&mut rx);
    assert_snapshot_still_available(&source.relay).await;

    store_snapshot(&source.relay, &source.valid_snapshot).await;

    let mut retry_attempt = build_joiner_sync(&source, &joiner);
    let mut retry_rx = retry_attempt.events();
    let (restored, changes) = retry_attempt.bootstrap_from_snapshot().await.unwrap();
    assert_eq!(restored, 3);
    assert_eq!(changes.len(), 3);
    assert_remote_changes_event(&mut retry_rx, 3);
    assert_ack_deletes_snapshot(&retry_attempt, &source.relay).await;
}
