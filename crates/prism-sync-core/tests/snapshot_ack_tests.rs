//! Pair-time snapshot ACK handshake + upload progress events.

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::{MemorySecureStore, MockTaskEntity, SYNC_ID};

use prism_sync_core::engine::SyncEngine;
use prism_sync_core::relay::traits::{SnapshotExchange, SnapshotUploadProgress};
use prism_sync_core::relay::MockRelay;
use prism_sync_core::schema::{SyncSchema, SyncType};
use prism_sync_core::storage::{DeviceRecord, RusqliteSyncStorage, SyncMetadata, SyncStorage};
use prism_sync_core::syncable_entity::SyncableEntity;
use prism_sync_core::{engine::SyncConfig, CoreError, PrismSync, SyncEvent};

fn ack_schema() -> SyncSchema {
    SyncSchema::builder()
        .entity("tasks", |e| e.field("title", SyncType::String).field("done", SyncType::Bool))
        .build()
}

/// Build a `PrismSync` configured with a mock relay and a pre-seeded
/// device record so `upload_pairing_snapshot` has everything it needs
/// (sync_metadata, our own device record, ML-DSA/ED25519 keys, epoch key).
fn setup_sync_for_upload() -> (PrismSync, Arc<MockRelay>) {
    let schema = ack_schema();
    let storage: Arc<RusqliteSyncStorage> = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    {
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_sync_metadata(&SyncMetadata {
            sync_id: SYNC_ID.to_string(),
            local_device_id: "device-a".to_string(),
            current_epoch: 0,
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
        tx.upsert_device_record(&DeviceRecord {
            sync_id: SYNC_ID.to_string(),
            device_id: "device-a".to_string(),
            ed25519_public_key: vec![1u8; 32],
            x25519_public_key: vec![2u8; 32],
            ml_dsa_65_public_key: vec![],
            ml_kem_768_public_key: vec![],
            x_wing_public_key: vec![],
            status: "active".to_string(),
            registered_at: chrono::Utc::now(),
            revoked_at: None,
            ml_dsa_key_generation: 0,
        })
        .unwrap();
        tx.commit().unwrap();
    }

    let mut sync = PrismSync::builder()
        .schema(schema)
        .storage(storage)
        .secure_store(Arc::new(MemorySecureStore::new()))
        .entity(entity)
        .build()
        .unwrap();

    sync.initialize("pw", &[7u8; 16]).unwrap();

    // Seed epoch 0 key so upload_pairing_snapshot has something to
    // encrypt with. `KeyHierarchy::store_epoch_key` is pub so we can
    // dig in through the accessor.
    sync.key_hierarchy_mut().store_epoch_key(0, zeroize::Zeroizing::new(vec![0xAB; 32]));

    let relay = Arc::new(MockRelay::new());
    sync.configure_engine(relay.clone(), SYNC_ID.to_string(), "device-a".to_string(), 0, 0);

    (sync, relay)
}

#[tokio::test]
async fn acknowledge_snapshot_applied_calls_delete() {
    let (sync, relay) = setup_sync_for_upload();

    sync.upload_pairing_snapshot(None, None).await.unwrap();
    assert!(relay.get_snapshot().await.unwrap().is_some(), "snapshot should exist pre-ACK");

    sync.acknowledge_snapshot_applied().await.unwrap();
    assert!(relay.get_snapshot().await.unwrap().is_none(), "snapshot should be gone after ACK");
}

#[tokio::test]
async fn acknowledge_snapshot_applied_is_idempotent_on_missing() {
    let (sync, relay) = setup_sync_for_upload();

    // No snapshot uploaded — ACK should still succeed (idempotent).
    assert!(relay.get_snapshot().await.unwrap().is_none());
    sync.acknowledge_snapshot_applied().await.expect("ACK on missing must be idempotent");
}

#[tokio::test]
async fn upload_pairing_snapshot_invokes_progress_callback() {
    // Go through the engine directly so we can inject a progress
    // callback alongside MockRelay (which invokes it once with
    // `(total, total)` on successful store).
    let storage: Arc<RusqliteSyncStorage> = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    {
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_sync_metadata(&SyncMetadata {
            sync_id: SYNC_ID.to_string(),
            local_device_id: "device-a".to_string(),
            current_epoch: 0,
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
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());
    let relay = Arc::new(MockRelay::new());
    let schema = ack_schema();
    let engine =
        SyncEngine::new(storage, relay.clone(), vec![entity], schema, SyncConfig::default());

    let ds = prism_sync_crypto::DeviceSecret::generate();
    let signing_key = ds.ed25519_keypair("device-a").unwrap().into_signing_key();
    let ml_dsa_key = ds.ml_dsa_65_keypair_v("device-a", 0).unwrap();
    let mut kh = prism_sync_crypto::KeyHierarchy::new();
    kh.initialize("pw", &[7u8; 16]).unwrap();
    kh.store_epoch_key(0, zeroize::Zeroizing::new(vec![0xAB; 32]));

    let counter = Arc::new(AtomicU64::new(0));
    let last_sent = Arc::new(AtomicU64::new(0));
    let last_total = Arc::new(AtomicU64::new(0));

    let counter_cb = counter.clone();
    let last_sent_cb = last_sent.clone();
    let last_total_cb = last_total.clone();
    let cb: SnapshotUploadProgress = Arc::new(move |sent, total| {
        counter_cb.fetch_add(1, Ordering::SeqCst);
        last_sent_cb.store(sent, Ordering::SeqCst);
        last_total_cb.store(total, Ordering::SeqCst);
    });

    engine
        .upload_pairing_snapshot(
            SYNC_ID,
            &kh,
            0,
            "device-a",
            &signing_key,
            &ml_dsa_key,
            0,
            None,
            None,
            Some(cb),
        )
        .await
        .unwrap();

    let invocations = counter.load(Ordering::SeqCst);
    let final_sent = last_sent.load(Ordering::SeqCst);
    let final_total = last_total.load(Ordering::SeqCst);
    assert!(invocations >= 1, "progress callback must fire at least once");
    assert_eq!(final_sent, final_total, "final progress must report 100%");
    assert!(final_total > 0, "final total must be nonzero");
}

#[tokio::test]
async fn upload_pairing_snapshot_rejects_oversized() {
    // Assemble an engine whose `export_snapshot` emits a blob > 100 MB.
    // We pack large encoded values into field_versions before calling
    // upload_pairing_snapshot so that the engine's size gate fires.
    let storage: Arc<RusqliteSyncStorage> = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    {
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_sync_metadata(&SyncMetadata {
            sync_id: SYNC_ID.to_string(),
            local_device_id: "device-a".to_string(),
            current_epoch: 0,
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

        // Pack ~130 MiB of cryptographically random bytes — zstd can't
        // compress high-entropy content below the 100 MiB compressed
        // threshold.
        use base64::Engine as _;
        use prism_sync_core::storage::FieldVersion;
        use rand::RngCore;
        for i in 0..260u32 {
            let mut blob = vec![0u8; 512 * 1024];
            rand::thread_rng().fill_bytes(&mut blob);
            let encoded =
                format!("\"{}\"", base64::engine::general_purpose::STANDARD.encode(&blob));
            tx.upsert_field_version(&FieldVersion {
                sync_id: SYNC_ID.to_string(),
                entity_table: "tasks".to_string(),
                entity_id: format!("t-{i}"),
                field_name: "title".to_string(),
                winning_op_id: format!("op-{i}"),
                winning_device_id: "device-a".to_string(),
                winning_hlc: format!("1:{i}:devicea000000"),
                winning_encoded_value: Some(encoded),
                updated_at: chrono::Utc::now(),
            })
            .unwrap();
        }
        tx.commit().unwrap();
    }

    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());
    let relay = Arc::new(MockRelay::new());
    let schema = ack_schema();
    let engine =
        SyncEngine::new(storage, relay.clone(), vec![entity], schema, SyncConfig::default());

    let ds = prism_sync_crypto::DeviceSecret::generate();
    let signing_key = ds.ed25519_keypair("device-a").unwrap().into_signing_key();
    let ml_dsa_key = ds.ml_dsa_65_keypair_v("device-a", 0).unwrap();
    let mut kh = prism_sync_crypto::KeyHierarchy::new();
    kh.initialize("pw", &[7u8; 16]).unwrap();
    kh.store_epoch_key(0, zeroize::Zeroizing::new(vec![0xAB; 32]));

    let err = engine
        .upload_pairing_snapshot(
            SYNC_ID,
            &kh,
            0,
            "device-a",
            &signing_key,
            &ml_dsa_key,
            0,
            None,
            None,
            None,
        )
        .await
        .unwrap_err();

    match err {
        CoreError::SnapshotTooLarge { bytes } => assert!(bytes > 100 * 1024 * 1024),
        other => panic!("expected SnapshotTooLarge, got {other:?}"),
    }

    // Nothing should have reached the relay.
    assert!(relay.get_snapshot().await.unwrap().is_none());
}

#[tokio::test]
async fn upload_pairing_snapshot_emits_failed_event_on_error() {
    // Build a full PrismSync but DON'T seed an epoch key for epoch 0,
    // so the engine's "missing epoch key" path fires inside
    // upload_pairing_snapshot. The service must emit
    // `SnapshotUploadFailed` before returning `Err(..)`.
    let schema = ack_schema();
    let storage: Arc<RusqliteSyncStorage> = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());
    {
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_sync_metadata(&SyncMetadata {
            sync_id: SYNC_ID.to_string(),
            local_device_id: "device-a".to_string(),
            current_epoch: 0,
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
        tx.upsert_device_record(&DeviceRecord {
            sync_id: SYNC_ID.to_string(),
            device_id: "device-a".to_string(),
            ed25519_public_key: vec![1u8; 32],
            x25519_public_key: vec![2u8; 32],
            ml_dsa_65_public_key: vec![],
            ml_kem_768_public_key: vec![],
            x_wing_public_key: vec![],
            status: "active".to_string(),
            registered_at: chrono::Utc::now(),
            revoked_at: None,
            ml_dsa_key_generation: 0,
        })
        .unwrap();
        tx.commit().unwrap();
    }

    let mut sync = PrismSync::builder()
        .schema(schema)
        .storage(storage)
        .secure_store(Arc::new(MemorySecureStore::new()))
        .entity(entity)
        .build()
        .unwrap();

    sync.initialize("pw", &[7u8; 16]).unwrap();
    let relay = Arc::new(MockRelay::new());
    // Configure the engine at epoch 99 so `upload_pairing_snapshot` looks
    // up an epoch key that isn't in the hierarchy (initialize only seeds
    // epoch 0). The engine surfaces that as `CoreError::Engine("no epoch
    // key: ...")`, which the service wraps with a
    // `SnapshotUploadFailed` event before returning `Err(..)`.
    sync.configure_engine(relay, SYNC_ID.to_string(), "device-a".to_string(), 99, 0);

    let mut rx = sync.events();
    let result = sync.upload_pairing_snapshot(None, None).await;
    assert!(result.is_err(), "upload must fail with missing epoch key");

    // Drain the channel briefly and look for SnapshotUploadFailed.
    let mut saw_failed = false;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Ok(SyncEvent::SnapshotUploadFailed { sync_id, reason: _ })) => {
                assert_eq!(sync_id, SYNC_ID);
                saw_failed = true;
                break;
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) | Err(_) => break,
        }
    }
    assert!(saw_failed, "expected SnapshotUploadFailed event");
}
