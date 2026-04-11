//! End-to-end integration tests for Prism's hybrid post-quantum encryption.
//!
//! These tests exercise multi-device sync through a real in-process relay server
//! with hybrid Ed25519 + ML-DSA-65 signature verification.
//!
//! Key properties verified:
//! - Two devices can sync through a real relay with hybrid-signed V3 batches
//! - Tampered ML-DSA signatures are rejected by the pulling device
//! - Signed registry allows unknown device resolution
//! - Revoked devices are excluded from new epochs
//! - V2 Ed25519-only batches are rejected (clean V3 cutover)

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use common::*;
use reqwest::Client;

use prism_sync_core::engine::{SyncConfig, SyncEngine};
use prism_sync_core::relay::ServerRelay;
use prism_sync_core::schema::{SyncFieldDef, SyncSchema, SyncType, SyncValue};
use prism_sync_core::storage::{DeviceRecord, RusqliteSyncStorage, SyncStorage};
use prism_sync_core::syncable_entity::SyncableEntity;
use prism_sync_core::{batch_signature, sync_aad, CrdtChange, Hlc, SyncMetadata};
use prism_sync_crypto::{kdf, KeyHierarchy};

// ═══════════════════════════════════════════════════════════════════════════
// MockTaskEntity — in-memory SyncableEntity for testing
// ═══════════════════════════════════════════════════════════════════════════

/// A test entity that stores rows in a `HashMap<entity_id, HashMap<field, SyncValue>>`.
struct MockTaskEntity {
    rows: Mutex<HashMap<String, HashMap<String, SyncValue>>>,
    deleted: Mutex<HashMap<String, bool>>,
}

impl MockTaskEntity {
    fn new() -> Self {
        Self {
            rows: Mutex::new(HashMap::new()),
            deleted: Mutex::new(HashMap::new()),
        }
    }

    fn get_field(&self, entity_id: &str, field: &str) -> Option<SyncValue> {
        self.rows
            .lock()
            .unwrap()
            .get(entity_id)
            .and_then(|row| row.get(field).cloned())
    }

    fn row_count(&self) -> usize {
        self.rows.lock().unwrap().len()
    }
}

#[async_trait::async_trait]
impl SyncableEntity for MockTaskEntity {
    fn table_name(&self) -> &str {
        "tasks"
    }

    fn field_definitions(&self) -> &[SyncFieldDef] {
        static FIELDS: std::sync::LazyLock<Vec<SyncFieldDef>> = std::sync::LazyLock::new(|| {
            vec![
                SyncFieldDef {
                    name: "title".to_string(),
                    sync_type: SyncType::String,
                },
                SyncFieldDef {
                    name: "done".to_string(),
                    sync_type: SyncType::Bool,
                },
            ]
        });
        &FIELDS
    }

    async fn read_row(
        &self,
        entity_id: &str,
    ) -> prism_sync_core::Result<Option<HashMap<String, SyncValue>>> {
        Ok(self.rows.lock().unwrap().get(entity_id).cloned())
    }

    async fn write_fields(
        &self,
        entity_id: &str,
        fields: &HashMap<String, SyncValue>,
        _hlc: &str,
        _is_new: bool,
    ) -> prism_sync_core::Result<()> {
        let mut rows = self.rows.lock().unwrap();
        let row = rows.entry(entity_id.to_string()).or_default();
        for (k, v) in fields {
            row.insert(k.clone(), v.clone());
        }
        Ok(())
    }

    async fn soft_delete(&self, entity_id: &str, _hlc: &str) -> prism_sync_core::Result<()> {
        self.deleted
            .lock()
            .unwrap()
            .insert(entity_id.to_string(), true);
        Ok(())
    }

    async fn is_deleted(&self, entity_id: &str) -> prism_sync_core::Result<bool> {
        Ok(self
            .deleted
            .lock()
            .unwrap()
            .get(entity_id)
            .copied()
            .unwrap_or(false))
    }

    async fn hard_delete(&self, entity_id: &str) -> prism_sync_core::Result<()> {
        self.rows.lock().unwrap().remove(entity_id);
        self.deleted.lock().unwrap().remove(entity_id);
        Ok(())
    }

    async fn begin_batch(&self) -> prism_sync_core::Result<()> {
        Ok(())
    }
    async fn commit_batch(&self) -> prism_sync_core::Result<()> {
        Ok(())
    }
    async fn rollback_batch(&self) -> prism_sync_core::Result<()> {
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

fn test_schema() -> SyncSchema {
    SyncSchema::builder()
        .entity("tasks", |e| {
            e.field("title", SyncType::String)
                .field("done", SyncType::Bool)
        })
        .build()
}

/// Initialize a KeyHierarchy with deterministic inputs so multiple devices
/// can derive the same epoch 0 key.
fn shared_key_hierarchy() -> KeyHierarchy {
    let mut kh = KeyHierarchy::new();
    kh.initialize("test-password", &[0u8; 16]).unwrap();
    kh
}

/// Extract port from a `http://127.0.0.1:{port}` URL and reconstruct as
/// `http://localhost:{port}` which ServerRelay accepts.
fn to_localhost_url(url: &str) -> String {
    let port = url.rsplit(':').next().unwrap();
    format!("http://localhost:{port}")
}

/// Register a joiner device with registry approval from an existing device.
/// The first device in a sync group can use `register_device` directly.
/// All subsequent devices need an existing device to provide registry approval.
#[allow(clippy::too_many_arguments)]
async fn register_joiner_device(
    client: &Client,
    url: &str,
    sync_id: &str,
    joiner_device_id: &str,
    joiner_keys: &TestDeviceKeys,
    approver_device_id: &str,
    approver_keys: &TestDeviceKeys,
    all_entries: Vec<prism_sync_core::pairing::models::RegistrySnapshotEntry>,
) -> String {
    let ml_dsa_kp = joiner_keys
        .device_secret
        .ml_dsa_65_keypair(joiner_device_id)
        .unwrap();

    // 1. Fetch nonce
    let nonce_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
        .send()
        .await
        .unwrap();
    assert_eq!(nonce_resp.status(), 200, "nonce request failed");
    let nonce_json: serde_json::Value = nonce_resp.json().await.unwrap();
    let nonce = nonce_json["nonce"].as_str().unwrap().to_string();

    // 2. Sign hybrid challenge
    let challenge_sig = sign_hybrid_challenge(
        &joiner_keys.ed25519_signing_key,
        &ml_dsa_kp,
        sync_id,
        joiner_device_id,
        &nonce,
    );

    // 3. Build registry approval
    let registry_approval = build_registry_approval(
        sync_id,
        approver_device_id,
        approver_keys,
        all_entries,
    );

    // 4. Register with registry approval
    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": joiner_device_id,
            "signing_public_key": hex::encode(joiner_keys.ed25519_signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(joiner_keys.x25519_pk),
            "ml_dsa_65_public_key": hex::encode(&joiner_keys.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&joiner_keys.ml_kem_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
            "registry_approval": registry_approval,
        }))
        .send()
        .await
        .unwrap();
    let status = register_resp.status();
    let token_json: serde_json::Value = register_resp.json().await.unwrap_or_else(|e| {
        panic!("joiner registration failed (status {status}): {e}");
    });
    assert!(
        status.is_success(),
        "joiner registration failed: {status} - {token_json}"
    );
    token_json["device_session_token"]
        .as_str()
        .expect("missing device_session_token in register response")
        .to_string()
}

/// Setup sync metadata in local storage.
fn setup_sync_metadata(storage: &RusqliteSyncStorage, sync_id: &str, device_id: &str) {
    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_sync_metadata(&SyncMetadata {
        sync_id: sync_id.to_string(),
        local_device_id: device_id.to_string(),
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

/// Register a peer device's keys in local storage so signature verification works.
fn register_peer_device(
    storage: &RusqliteSyncStorage,
    sync_id: &str,
    device_id: &str,
    keys: &TestDeviceKeys,
) {
    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_device_record(&DeviceRecord {
        sync_id: sync_id.to_string(),
        device_id: device_id.to_string(),
        ed25519_public_key: keys.ed25519_signing_key.verifying_key().to_bytes().to_vec(),
        x25519_public_key: keys.x25519_pk.to_vec(),
        ml_dsa_65_public_key: keys.ml_dsa_pk.clone(),
        ml_kem_768_public_key: keys.ml_kem_pk.clone(),
        x_wing_public_key: Vec::new(),
        status: "active".to_string(),
        registered_at: chrono::Utc::now(),
        revoked_at: None,
        ml_dsa_key_generation: 0,
    })
    .unwrap();
    tx.commit().unwrap();
}

/// Create pending ops for a task and insert them into storage.
fn create_task_ops(
    storage: &RusqliteSyncStorage,
    sync_id: &str,
    device_id: &str,
    task_id: &str,
    title: &str,
    batch_id: &str,
) {
    let hlc = Hlc::now(device_id, None);
    let ops = vec![
        CrdtChange {
            op_id: format!("tasks:{task_id}:title:{hlc}:{device_id}"),
            batch_id: Some(batch_id.to_string()),
            entity_id: task_id.to_string(),
            entity_table: "tasks".to_string(),
            field_name: "title".to_string(),
            encoded_value: format!("\"{}\"", title),
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
            encoded_value: "false".to_string(),
            client_hlc: hlc.to_string(),
            is_delete: false,
            device_id: device_id.to_string(),
            epoch: 0,
            server_seq: None,
        },
    ];

    use prism_sync_core::storage::PendingOp;
    let mut tx = storage.begin_tx().unwrap();
    for op in &ops {
        tx.insert_pending_op(&PendingOp {
            op_id: op.op_id.clone(),
            sync_id: sync_id.to_string(),
            epoch: op.epoch,
            device_id: op.device_id.clone(),
            local_batch_id: batch_id.to_string(),
            entity_table: op.entity_table.clone(),
            entity_id: op.entity_id.clone(),
            field_name: op.field_name.clone(),
            encoded_value: op.encoded_value.clone(),
            is_delete: op.is_delete,
            client_hlc: op.client_hlc.clone(),
            created_at: chrono::Utc::now(),
            pushed_at: None,
        })
        .unwrap();
    }
    tx.commit().unwrap();
}

/// Create a ServerRelay for a device. Requires the relay URL (as http://localhost:{port}).
fn make_server_relay(
    base_url: &str,
    sync_id: &str,
    device_id: &str,
    token: &str,
    keys: &TestDeviceKeys,
) -> ServerRelay {
    let ml_dsa_kp = keys.device_secret.ml_dsa_65_keypair(device_id).unwrap();
    ServerRelay::new(
        base_url.to_string(),
        sync_id.to_string(),
        device_id.to_string(),
        token.to_string(),
        keys.ed25519_signing_key.clone(),
        ml_dsa_kp,
        None,
    )
    .expect("ServerRelay::new should succeed with localhost URL")
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 1: Two devices sync through real relay with hybrid signatures
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn e2e_hybrid_batch_push_pull_cross_device() {
    let (url, _server, _db) = start_test_relay().await;
    let localhost_url = to_localhost_url(&url);
    let client = Client::new();
    let sync_id = generate_sync_id();

    // ── Register Device A ──
    let device_a_id = generate_device_id();
    let keys_a = TestDeviceKeys::generate(&device_a_id);
    let token_a = register_device(&client, &url, &sync_id, &device_a_id, &keys_a).await;

    // ── Register Device B (needs registry approval from A) ──
    let device_b_id = generate_device_id();
    let keys_b = TestDeviceKeys::generate(&device_b_id);
    let token_b = register_joiner_device(
        &client,
        &url,
        &sync_id,
        &device_b_id,
        &keys_b,
        &device_a_id,
        &keys_a,
        vec![
            registry_snapshot_entry_hybrid(&sync_id, &device_a_id, &keys_a, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &device_b_id, &keys_b, "active"),
        ],
    )
    .await;

    // ── Shared key hierarchy (both devices have the same epoch 0 key) ──
    let kh = shared_key_hierarchy();

    // ── Device A: create storage, engine, task ──
    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_a = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_a, &sync_id, &device_a_id);
    register_peer_device(&storage_a, &sync_id, &device_a_id, &keys_a);
    register_peer_device(&storage_a, &sync_id, &device_b_id, &keys_b);

    create_task_ops(
        &storage_a,
        &sync_id,
        &device_a_id,
        "task-1",
        "Buy groceries",
        "batch-a1",
    );

    let relay_a = Arc::new(make_server_relay(
        &localhost_url,
        &sync_id,
        &device_a_id,
        &token_a,
        &keys_a,
    ));
    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay_a.clone(),
        vec![entity_a.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );

    let ml_dsa_a = keys_a.device_secret.ml_dsa_65_keypair(&device_a_id).unwrap();

    // ── Device A syncs: pushes hybrid-signed V3 batch ──
    let result_a = engine_a
        .sync(
            &sync_id,
            &kh,
            &keys_a.ed25519_signing_key,
            Some(&ml_dsa_a),
            &device_a_id,
            0,
        )
        .await
        .unwrap();
    assert!(
        result_a.error.is_none(),
        "Device A push failed: {:?}",
        result_a.error
    );
    assert_eq!(result_a.pushed, 1, "expected 1 batch pushed from A");

    // ── Device B: create storage, engine ──
    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_b, &sync_id, &device_b_id);
    register_peer_device(&storage_b, &sync_id, &device_a_id, &keys_a);
    register_peer_device(&storage_b, &sync_id, &device_b_id, &keys_b);

    let relay_b = Arc::new(make_server_relay(
        &localhost_url,
        &sync_id,
        &device_b_id,
        &token_b,
        &keys_b,
    ));
    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay_b.clone(),
        vec![entity_b.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );

    let ml_dsa_b = keys_b.device_secret.ml_dsa_65_keypair(&device_b_id).unwrap();

    // ── Device B syncs: pulls and verifies BOTH Ed25519 + ML-DSA sigs ──
    let result_b = engine_b
        .sync(
            &sync_id,
            &kh,
            &keys_b.ed25519_signing_key,
            Some(&ml_dsa_b),
            &device_b_id,
            0,
        )
        .await
        .unwrap();
    assert!(
        result_b.error.is_none(),
        "Device B pull failed: {:?}",
        result_b.error
    );
    assert_eq!(result_b.pulled, 1, "expected 1 batch pulled by B");
    assert_eq!(result_b.merged, 2, "expected 2 ops merged (title + done)");

    // Verify entity data arrived
    assert_eq!(
        entity_b.get_field("task-1", "title"),
        Some(SyncValue::String("Buy groceries".to_string()))
    );
    assert_eq!(
        entity_b.get_field("task-1", "done"),
        Some(SyncValue::Bool(false))
    );

    // ── Device B: create a task and sync ──
    create_task_ops(
        &storage_b,
        &sync_id,
        &device_b_id,
        "task-2",
        "Walk the dog",
        "batch-b1",
    );

    let result_b2 = engine_b
        .sync(
            &sync_id,
            &kh,
            &keys_b.ed25519_signing_key,
            Some(&ml_dsa_b),
            &device_b_id,
            0,
        )
        .await
        .unwrap();
    assert!(
        result_b2.error.is_none(),
        "Device B push failed: {:?}",
        result_b2.error
    );
    assert_eq!(result_b2.pushed, 1, "expected 1 batch pushed from B");

    // ── Device A syncs: pulls B's batch ──
    let result_a2 = engine_a
        .sync(
            &sync_id,
            &kh,
            &keys_a.ed25519_signing_key,
            Some(&ml_dsa_a),
            &device_a_id,
            0,
        )
        .await
        .unwrap();
    assert!(
        result_a2.error.is_none(),
        "Device A pull failed: {:?}",
        result_a2.error
    );
    assert!(result_a2.pulled >= 1, "expected at least 1 batch pulled by A");
    assert_eq!(result_a2.merged, 2, "expected 2 ops merged from B's batch");

    // Verify cross-device data arrival
    // entity_a has task-2 from B (merged via pull), but task-1 was local pending ops
    // (MockTaskEntity only receives remote writes from merge, not local ops)
    assert_eq!(
        entity_a.get_field("task-2", "title"),
        Some(SyncValue::String("Walk the dog".to_string()))
    );
    // entity_b has task-1 from A (merged via pull)
    assert_eq!(entity_b.row_count(), 1, "B should have 1 remote task from A");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 2: Tampered ML-DSA signature is rejected
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn e2e_hybrid_signature_rejection() {
    let (url, _server, db) = start_test_relay().await;
    let localhost_url = to_localhost_url(&url);
    let client = Client::new();
    let sync_id = generate_sync_id();

    // ── Register Device A and B ──
    let device_a_id = generate_device_id();
    let keys_a = TestDeviceKeys::generate(&device_a_id);
    let token_a = register_device(&client, &url, &sync_id, &device_a_id, &keys_a).await;

    let device_b_id = generate_device_id();
    let keys_b = TestDeviceKeys::generate(&device_b_id);
    let token_b = register_joiner_device(
        &client, &url, &sync_id, &device_b_id, &keys_b,
        &device_a_id, &keys_a,
        vec![
            registry_snapshot_entry_hybrid(&sync_id, &device_a_id, &keys_a, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &device_b_id, &keys_b, "active"),
        ],
    ).await;

    let kh = shared_key_hierarchy();

    // ── Device A: push a valid batch ──
    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_a = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_a, &sync_id, &device_a_id);
    register_peer_device(&storage_a, &sync_id, &device_a_id, &keys_a);

    create_task_ops(
        &storage_a,
        &sync_id,
        &device_a_id,
        "task-tamper",
        "Tamper test",
        "batch-tamper",
    );

    let relay_a = Arc::new(make_server_relay(
        &localhost_url,
        &sync_id,
        &device_a_id,
        &token_a,
        &keys_a,
    ));
    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay_a.clone(),
        vec![entity_a.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );

    let ml_dsa_a = keys_a.device_secret.ml_dsa_65_keypair(&device_a_id).unwrap();
    let result_a = engine_a
        .sync(
            &sync_id,
            &kh,
            &keys_a.ed25519_signing_key,
            Some(&ml_dsa_a),
            &device_a_id,
            0,
        )
        .await
        .unwrap();
    assert!(result_a.error.is_none(), "push failed: {:?}", result_a.error);
    assert_eq!(result_a.pushed, 1);

    // ── Tamper with the stored batch in the relay DB ──
    // The relay stores batches as JSON blobs. We modify the signature field
    // to corrupt the ML-DSA component while keeping the envelope parseable.
    let sid = sync_id.clone();
    db.with_conn(|conn| {
        // Read the stored batch data
        let data: Vec<u8> = conn.query_row(
            "SELECT data FROM batches WHERE sync_id = ?1 LIMIT 1",
            rusqlite::params![sid],
            |row| row.get(0),
        )?;

        // Parse as JSON, tamper with the signature
        let mut envelope: serde_json::Value = serde_json::from_slice(&data).unwrap();
        if let Some(sig) = envelope.get("signature").and_then(|s| s.as_str()) {
            // Decode the base64 signature, flip a byte in the ML-DSA portion, re-encode
            use base64::Engine;
            let mut sig_bytes =
                base64::engine::general_purpose::STANDARD.decode(sig).unwrap();
            // The ML-DSA signature starts after the Ed25519 component.
            // Flip a byte deep inside the ML-DSA portion to corrupt it.
            if sig_bytes.len() > 200 {
                sig_bytes[200] ^= 0xFF;
            }
            let tampered_sig =
                base64::engine::general_purpose::STANDARD.encode(&sig_bytes);
            envelope["signature"] = serde_json::Value::String(tampered_sig);
        }

        let tampered_data = serde_json::to_vec(&envelope).unwrap();
        conn.execute(
            "UPDATE batches SET data = ?1 WHERE sync_id = ?2",
            rusqlite::params![tampered_data, sid],
        )?;
        Ok(())
    })
    .expect("tamper with batch");

    // ── Device B: pull → batch must be SKIPPED (bad sig) ──
    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_b, &sync_id, &device_b_id);
    register_peer_device(&storage_b, &sync_id, &device_a_id, &keys_a);
    register_peer_device(&storage_b, &sync_id, &device_b_id, &keys_b);

    let relay_b = Arc::new(make_server_relay(
        &localhost_url,
        &sync_id,
        &device_b_id,
        &token_b,
        &keys_b,
    ));
    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay_b.clone(),
        vec![entity_b.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );

    let ml_dsa_b = keys_b.device_secret.ml_dsa_65_keypair(&device_b_id).unwrap();
    let result_b = engine_b
        .sync(
            &sync_id,
            &kh,
            &keys_b.ed25519_signing_key,
            Some(&ml_dsa_b),
            &device_b_id,
            0,
        )
        .await
        .unwrap();

    // The sync should succeed (not crash) but no data should be merged
    assert!(
        result_b.error.is_none(),
        "sync should not error, just skip bad batch: {:?}",
        result_b.error
    );
    assert_eq!(
        result_b.pulled, 1,
        "batch was pulled (received from relay)"
    );
    assert_eq!(
        result_b.merged, 0,
        "tampered batch must NOT be merged"
    );
    assert_eq!(
        entity_b.row_count(),
        0,
        "no data should arrive from tampered batch"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 3: Signed registry fetch and import resolves unknown sender
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn e2e_signed_registry_fetch_and_import() {
    let (url, _server, _db) = start_test_relay().await;
    let localhost_url = to_localhost_url(&url);
    let client = Client::new();
    let sync_id = generate_sync_id();

    // ── Register Device A (admin), B, and C ──
    let device_a_id = generate_device_id();
    let keys_a = TestDeviceKeys::generate(&device_a_id);
    let token_a = register_device(&client, &url, &sync_id, &device_a_id, &keys_a).await;

    let device_b_id = generate_device_id();
    let keys_b = TestDeviceKeys::generate(&device_b_id);
    let token_b = register_joiner_device(
        &client, &url, &sync_id, &device_b_id, &keys_b,
        &device_a_id, &keys_a,
        vec![
            registry_snapshot_entry_hybrid(&sync_id, &device_a_id, &keys_a, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &device_b_id, &keys_b, "active"),
        ],
    ).await;

    let device_c_id = generate_device_id();
    let keys_c = TestDeviceKeys::generate(&device_c_id);
    let token_c = register_joiner_device(
        &client, &url, &sync_id, &device_c_id, &keys_c,
        &device_a_id, &keys_a,
        vec![
            registry_snapshot_entry_hybrid(&sync_id, &device_a_id, &keys_a, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &device_b_id, &keys_b, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &device_c_id, &keys_c, "active"),
        ],
    ).await;

    let kh = shared_key_hierarchy();

    // ── A publishes signed registry including all three devices ──
    let ml_dsa_a = keys_a.device_secret.ml_dsa_65_keypair(&device_a_id).unwrap();
    let entries = vec![
        registry_snapshot_entry_hybrid(&sync_id, &device_a_id, &keys_a, "active"),
        registry_snapshot_entry_hybrid(&sync_id, &device_b_id, &keys_b, "active"),
        registry_snapshot_entry_hybrid(&sync_id, &device_c_id, &keys_c, "active"),
    ];
    let signed_registry = build_signed_registry_snapshot_hybrid(
        entries,
        &keys_a.ed25519_signing_key,
        &ml_dsa_a,
    );

    // Upload to relay via PUT /v1/sync/{sync_id}/registry
    let path = format!("/v1/sync/{sync_id}/registry");
    let body = serde_json::to_vec(&serde_json::json!({
        "signed_registry_snapshot": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &signed_registry),
    }))
    .unwrap();
    let resp = apply_signed_headers(
        client
            .put(format!("{url}/v1/sync/{sync_id}/registry"))
            .header("Authorization", format!("Bearer {token_a}"))
            .header("X-Device-Id", &device_a_id)
            .header("Content-Type", "application/json"),
        &keys_a,
        "PUT",
        &path,
        &sync_id,
        &device_a_id,
        &body,
    )
    .body(body)
    .send()
    .await
    .unwrap();
    assert!(
        resp.status().is_success(),
        "registry upload failed: {}",
        resp.status()
    );

    // ── C pushes a batch ──
    let storage_c = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_c = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_c, &sync_id, &device_c_id);
    register_peer_device(&storage_c, &sync_id, &device_c_id, &keys_c);

    create_task_ops(
        &storage_c,
        &sync_id,
        &device_c_id,
        "task-from-c",
        "C's task",
        "batch-c1",
    );

    let relay_c = Arc::new(make_server_relay(
        &localhost_url,
        &sync_id,
        &device_c_id,
        &token_c,
        &keys_c,
    ));
    let ml_dsa_c = keys_c.device_secret.ml_dsa_65_keypair(&device_c_id).unwrap();
    let engine_c = SyncEngine::new(
        storage_c.clone(),
        relay_c.clone(),
        vec![entity_c.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );
    let result_c = engine_c
        .sync(
            &sync_id,
            &kh,
            &keys_c.ed25519_signing_key,
            Some(&ml_dsa_c),
            &device_c_id,
            0,
        )
        .await
        .unwrap();
    assert!(result_c.error.is_none(), "C push failed: {:?}", result_c.error);
    assert_eq!(result_c.pushed, 1);

    // ── B pulls → unknown sender C → fetches registry → verifies A's sig → imports C's keys → verifies C's batch ──
    // B only knows A's keys initially (not C's)
    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_b, &sync_id, &device_b_id);
    register_peer_device(&storage_b, &sync_id, &device_a_id, &keys_a);
    register_peer_device(&storage_b, &sync_id, &device_b_id, &keys_b);
    // NOTE: B does NOT know C's keys — this is the whole point

    let relay_b = Arc::new(make_server_relay(
        &localhost_url,
        &sync_id,
        &device_b_id,
        &token_b,
        &keys_b,
    ));
    let ml_dsa_b = keys_b.device_secret.ml_dsa_65_keypair(&device_b_id).unwrap();
    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay_b.clone(),
        vec![entity_b.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );
    let result_b = engine_b
        .sync(
            &sync_id,
            &kh,
            &keys_b.ed25519_signing_key,
            Some(&ml_dsa_b),
            &device_b_id,
            0,
        )
        .await
        .unwrap();
    assert!(
        result_b.error.is_none(),
        "B pull failed: {:?}",
        result_b.error
    );
    assert_eq!(result_b.merged, 2, "B should have merged C's 2 ops via registry lookup");
    assert_eq!(
        entity_b.get_field("task-from-c", "title"),
        Some(SyncValue::String("C's task".to_string()))
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 4: ML-DSA rotation with peer verification
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn e2e_ml_dsa_rotation_with_peer_verification() {
    let (url, _server, _db) = start_test_relay().await;
    let localhost_url = to_localhost_url(&url);
    let client = Client::new();
    let sync_id = generate_sync_id();

    // ── Register A and B ──
    let device_a_id = generate_device_id();
    let keys_a = TestDeviceKeys::generate(&device_a_id);
    let token_a = register_device(&client, &url, &sync_id, &device_a_id, &keys_a).await;

    let device_b_id = generate_device_id();
    let keys_b = TestDeviceKeys::generate(&device_b_id);
    let token_b = register_joiner_device(
        &client, &url, &sync_id, &device_b_id, &keys_b,
        &device_a_id, &keys_a,
        vec![
            registry_snapshot_entry_hybrid(&sync_id, &device_a_id, &keys_a, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &device_b_id, &keys_b, "active"),
        ],
    ).await;

    let kh = shared_key_hierarchy();

    // ── A pushes batch (gen 0), B pulls and verifies ──
    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_a = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_a, &sync_id, &device_a_id);
    register_peer_device(&storage_a, &sync_id, &device_a_id, &keys_a);
    register_peer_device(&storage_a, &sync_id, &device_b_id, &keys_b);

    create_task_ops(
        &storage_a,
        &sync_id,
        &device_a_id,
        "task-rot-1",
        "Before rotation",
        "batch-rot-1",
    );

    let relay_a = Arc::new(make_server_relay(
        &localhost_url,
        &sync_id,
        &device_a_id,
        &token_a,
        &keys_a,
    ));
    let ml_dsa_a_gen0 = keys_a.device_secret.ml_dsa_65_keypair(&device_a_id).unwrap();
    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay_a.clone(),
        vec![entity_a.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );
    let result = engine_a
        .sync(
            &sync_id,
            &kh,
            &keys_a.ed25519_signing_key,
            Some(&ml_dsa_a_gen0),
            &device_a_id,
            0,
        )
        .await
        .unwrap();
    assert!(result.error.is_none());
    assert_eq!(result.pushed, 1);

    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_b, &sync_id, &device_b_id);
    register_peer_device(&storage_b, &sync_id, &device_a_id, &keys_a);
    register_peer_device(&storage_b, &sync_id, &device_b_id, &keys_b);

    let relay_b = Arc::new(make_server_relay(
        &localhost_url,
        &sync_id,
        &device_b_id,
        &token_b,
        &keys_b,
    ));
    let ml_dsa_b = keys_b.device_secret.ml_dsa_65_keypair(&device_b_id).unwrap();
    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay_b.clone(),
        vec![entity_b.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );
    let result = engine_b
        .sync(
            &sync_id,
            &kh,
            &keys_b.ed25519_signing_key,
            Some(&ml_dsa_b),
            &device_b_id,
            0,
        )
        .await
        .unwrap();
    assert!(result.error.is_none());
    assert_eq!(result.merged, 2, "B should verify gen-0 batch");

    // ── A rotates ML-DSA to gen 1 ──
    // Use the SAME DeviceSecret with generation 1 (not a new secret)
    let ml_dsa_a_gen1 = keys_a
        .device_secret
        .ml_dsa_65_keypair_v(&device_a_id, 1)
        .unwrap();

    // Build continuity proof
    let proof = prism_sync_crypto::pq::continuity_proof::MlDsaContinuityProof::create(
        &keys_a.device_secret,
        &device_a_id,
        0, // old generation
        1, // new generation
    )
    .expect("create continuity proof");

    // Build signed registry with the new key
    let entries_gen1 = vec![
        {
            let mut entry =
                registry_snapshot_entry_hybrid(&sync_id, &device_a_id, &keys_a, "active");
            entry.ml_dsa_65_public_key = ml_dsa_a_gen1.public_key_bytes();
            entry.ml_dsa_key_generation = 1;
            entry
        },
        registry_snapshot_entry_hybrid(&sync_id, &device_b_id, &keys_b, "active"),
    ];
    let signed_registry_gen1 = build_signed_registry_snapshot_hybrid_versioned(
        entries_gen1,
        &keys_a.ed25519_signing_key,
        &ml_dsa_a_gen0, // Sign with old key (still trusted)
        2,              // registry_version = 2
    );

    // POST rotation to relay
    let path = format!(
        "/v1/sync/{sync_id}/devices/{device_a_id}/rotate-ml-dsa"
    );
    let body = serde_json::json!({
        "new_ml_dsa_pk": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ml_dsa_a_gen1.public_key_bytes()),
        "ml_dsa_key_generation": 1,
        "timestamp": proof.timestamp,
        "old_signs_new": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &proof.old_signs_new),
        "new_signs_old": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &proof.new_signs_old),
        "signed_registry_snapshot": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &signed_registry_gen1),
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let resp = apply_signed_headers(
        client
            .post(format!("{url}{path}"))
            .header("Authorization", format!("Bearer {token_a}"))
            .header("X-Device-Id", &device_a_id)
            .header("Content-Type", "application/json"),
        &keys_a,
        "POST",
        &path,
        &sync_id,
        &device_a_id,
        &body_bytes,
    )
    .body(body_bytes)
    .send()
    .await
    .unwrap();
    assert!(
        resp.status().is_success(),
        "rotate-ml-dsa failed: {} - {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );

    // ── A pushes batch signed with gen 1 ──
    // Need to update A's local device record
    {
        let mut tx = storage_a.begin_tx().unwrap();
        tx.upsert_device_record(&DeviceRecord {
            sync_id: sync_id.clone(),
            device_id: device_a_id.clone(),
            ed25519_public_key: keys_a.ed25519_signing_key.verifying_key().to_bytes().to_vec(),
            x25519_public_key: keys_a.x25519_pk.to_vec(),
            ml_dsa_65_public_key: ml_dsa_a_gen1.public_key_bytes(),
            ml_kem_768_public_key: keys_a.ml_kem_pk.clone(),
            x_wing_public_key: Vec::new(),
            status: "active".to_string(),
            registered_at: chrono::Utc::now(),
            revoked_at: None,
            ml_dsa_key_generation: 1,
        })
        .unwrap();
        tx.commit().unwrap();
    }

    create_task_ops(
        &storage_a,
        &sync_id,
        &device_a_id,
        "task-rot-2",
        "After rotation",
        "batch-rot-2",
    );

    // Need a new ServerRelay with the gen1 key for A
    let relay_a_gen1 = Arc::new({
        let ml_dsa_a_gen1_for_relay = keys_a
            .device_secret
            .ml_dsa_65_keypair_v(&device_a_id, 1)
            .unwrap();
        ServerRelay::new(
            localhost_url.clone(),
            sync_id.clone(),
            device_a_id.clone(),
            token_a.clone(),
            keys_a.ed25519_signing_key.clone(),
            ml_dsa_a_gen1_for_relay,
            None,
        )
        .unwrap()
    });
    let engine_a_gen1 = SyncEngine::new(
        storage_a.clone(),
        relay_a_gen1,
        vec![entity_a.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );
    let result = engine_a_gen1
        .sync(
            &sync_id,
            &kh,
            &keys_a.ed25519_signing_key,
            Some(&ml_dsa_a_gen1),
            &device_a_id,
            1, // ml_dsa_key_generation = 1
        )
        .await
        .unwrap();
    assert!(result.error.is_none(), "A gen1 push failed: {:?}", result.error);
    assert_eq!(result.pushed, 1);

    // ── B pulls → generation mismatch → fetches signed registry → imports new key → verifies ──
    let result = engine_b
        .sync(
            &sync_id,
            &kh,
            &keys_b.ed25519_signing_key,
            Some(&ml_dsa_b),
            &device_b_id,
            0,
        )
        .await
        .unwrap();
    assert!(result.error.is_none(), "B pull gen1 failed: {:?}", result.error);
    assert_eq!(result.merged, 2, "B should merge gen-1 batch after registry update");
    assert_eq!(
        entity_b.get_field("task-rot-2", "title"),
        Some(SyncValue::String("After rotation".to_string()))
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 5: Revoked device excluded from new epoch
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn e2e_revoked_device_excluded_from_new_epoch() {
    let (url, _server, _db) = start_test_relay().await;
    let _localhost_url = to_localhost_url(&url);
    let client = Client::new();
    let sync_id = generate_sync_id();

    // ── Register A, B, C sharing epoch 0 ──
    let device_a_id = generate_device_id();
    let keys_a = TestDeviceKeys::generate(&device_a_id);
    let token_a = register_device(&client, &url, &sync_id, &device_a_id, &keys_a).await;

    let device_b_id = generate_device_id();
    let keys_b = TestDeviceKeys::generate(&device_b_id);
    let token_b = register_joiner_device(
        &client, &url, &sync_id, &device_b_id, &keys_b,
        &device_a_id, &keys_a,
        vec![
            registry_snapshot_entry_hybrid(&sync_id, &device_a_id, &keys_a, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &device_b_id, &keys_b, "active"),
        ],
    ).await;

    let device_c_id = generate_device_id();
    let keys_c = TestDeviceKeys::generate(&device_c_id);
    let _token_c = register_joiner_device(
        &client, &url, &sync_id, &device_c_id, &keys_c,
        &device_a_id, &keys_a,
        vec![
            registry_snapshot_entry_hybrid(&sync_id, &device_a_id, &keys_a, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &device_b_id, &keys_b, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &device_c_id, &keys_c, "active"),
        ],
    ).await;

    // ── A revokes C, rekeys to epoch 1 ──
    // Generate wrapped keys for A and B only (not C)
    let wrapped_key_for_a = b"wrapped-epoch-1-key-for-A".to_vec();
    let wrapped_key_for_b = b"wrapped-epoch-1-key-for-B".to_vec();
    let mut wrapped_keys = HashMap::new();
    wrapped_keys.insert(device_a_id.clone(), wrapped_key_for_a.clone());
    wrapped_keys.insert(device_b_id.clone(), wrapped_key_for_b.clone());

    let encoded_keys: HashMap<String, String> = wrapped_keys
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, v),
            )
        })
        .collect();

    let _ml_dsa_a = keys_a.device_secret.ml_dsa_65_keypair(&device_a_id).unwrap();

    let path = format!("/v1/sync/{sync_id}/devices/{device_c_id}/revoke");
    let body = serde_json::json!({
        "new_epoch": 1,
        "remote_wipe": false,
        "wrapped_keys": encoded_keys,
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let resp = apply_signed_headers(
        client
            .post(format!("{url}{path}"))
            .header("Authorization", format!("Bearer {token_a}"))
            .header("X-Device-Id", &device_a_id)
            .header("Content-Type", "application/json"),
        &keys_a,
        "POST",
        &path,
        &sync_id,
        &device_a_id,
        &body_bytes,
    )
    .body(body_bytes)
    .send()
    .await
    .unwrap();
    assert!(
        resp.status().is_success(),
        "revoke failed: {}",
        resp.status()
    );

    // ── B fetches rekey artifact successfully ──
    let b_artifact_resp = client
        .get(format!(
            "{url}/v1/sync/{sync_id}/rekey/{device_b_id}?epoch=1"
        ))
        .header("Authorization", format!("Bearer {token_b}"))
        .header("X-Device-Id", &device_b_id)
        .send()
        .await
        .unwrap();
    assert_eq!(b_artifact_resp.status(), 200);
    let b_json: serde_json::Value = b_artifact_resp.json().await.unwrap();
    assert!(b_json.get("wrapped_key").is_some(), "B should get wrapped key");

    // ── C tries to fetch rekey artifact → should fail (revoked) ──
    // C's session is invalidated on revoke, so any request should fail with 401
    let c_artifact_resp = client
        .get(format!(
            "{url}/v1/sync/{sync_id}/rekey/{device_c_id}?epoch=1"
        ))
        .header("Authorization", format!("Bearer {_token_c}"))
        .header("X-Device-Id", &device_c_id)
        .send()
        .await
        .unwrap();
    // Revoked device's session is invalidated — expect 401 or 404
    assert!(
        c_artifact_resp.status() == 401 || c_artifact_resp.status() == 404,
        "Revoked device should not access rekey artifact, got: {}",
        c_artifact_resp.status()
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 6: V2 Ed25519-only batch rejected (clean V3 cutover)
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn e2e_v2_ed25519_only_batch_rejected() {
    let (url, _server, _db) = start_test_relay().await;
    let localhost_url = to_localhost_url(&url);
    let client = Client::new();
    let sync_id = generate_sync_id();

    // ── Register A and B ──
    let device_a_id = generate_device_id();
    let keys_a = TestDeviceKeys::generate(&device_a_id);
    let token_a = register_device(&client, &url, &sync_id, &device_a_id, &keys_a).await;

    let device_b_id = generate_device_id();
    let keys_b = TestDeviceKeys::generate(&device_b_id);
    let token_b = register_joiner_device(
        &client, &url, &sync_id, &device_b_id, &keys_b,
        &device_a_id, &keys_a,
        vec![
            registry_snapshot_entry_hybrid(&sync_id, &device_a_id, &keys_a, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &device_b_id, &keys_b, "active"),
        ],
    ).await;

    let kh = shared_key_hierarchy();

    // ── Construct a V2 Ed25519-only batch envelope and push it directly ──
    // Build a real encrypted payload
    let hlc = Hlc::now(&device_a_id, None);
    let ops = vec![
        CrdtChange {
            op_id: format!("tasks:v2task:title:{hlc}:{device_a_id}"),
            batch_id: Some("batch-v2".to_string()),
            entity_id: "v2task".to_string(),
            entity_table: "tasks".to_string(),
            field_name: "title".to_string(),
            encoded_value: "\"V2 task\"".to_string(),
            client_hlc: hlc.to_string(),
            is_delete: false,
            device_id: device_a_id.to_string(),
            epoch: 0,
            server_seq: None,
        },
    ];
    let plaintext = CrdtChange::encode_batch(&ops).unwrap();
    let payload_hash = batch_signature::compute_payload_hash(&plaintext);
    let epoch_key = kh.epoch_key(0).unwrap();
    let aad = sync_aad::build_sync_aad(&sync_id, &device_a_id, 0, "batch-v2", "ops");
    let (ciphertext, nonce) =
        prism_sync_crypto::aead::xchacha_encrypt_for_sync(epoch_key, &plaintext, &aad).unwrap();

    // Build V2-style canonical signed data (Ed25519 only, no ML-DSA)
    let mut canonical_v2 = Vec::new();
    canonical_v2.extend_from_slice(b"PRISM_SYNC_BATCH_V2\x00");
    canonical_v2.extend_from_slice(&2u16.to_be_bytes()); // protocol_version = 2
    write_len_prefixed_utf8(&mut canonical_v2, &sync_id);
    canonical_v2.extend_from_slice(&0i32.to_be_bytes()); // epoch
    write_len_prefixed_utf8(&mut canonical_v2, "batch-v2");
    write_len_prefixed_utf8(&mut canonical_v2, "ops");
    write_len_prefixed_utf8(&mut canonical_v2, &device_a_id);
    canonical_v2.extend_from_slice(&payload_hash);

    use ed25519_dalek::Signer;
    let ed25519_sig = keys_a.ed25519_signing_key.sign(&canonical_v2);

    // Build V2 envelope (Ed25519-only signature)
    let envelope_json = serde_json::json!({
        "protocol_version": 2,
        "sync_id": sync_id,
        "epoch": 0,
        "batch_id": "batch-v2",
        "batch_kind": "ops",
        "sender_device_id": device_a_id,
        "sender_ml_dsa_key_generation": 0,
        "payload_hash": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, payload_hash),
        "signature": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ed25519_sig.to_bytes()),
        "nonce": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce),
        "ciphertext": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ciphertext),
    });

    // Push directly via HTTP (bypass SyncEngine which would use V3)
    let body_bytes = serde_json::to_vec(&envelope_json).unwrap();
    let path = format!("/v1/sync/{sync_id}/changes");
    let resp = apply_signed_headers(
        client
            .put(format!("{url}/v1/sync/{sync_id}/changes"))
            .header("Authorization", format!("Bearer {token_a}"))
            .header("X-Device-Id", &device_a_id)
            .header("X-Batch-Id", "batch-v2")
            .header("Content-Type", "application/json"),
        &keys_a,
        "PUT",
        &path,
        &sync_id,
        &device_a_id,
        &body_bytes,
    )
    .body(body_bytes)
    .send()
    .await
    .unwrap();
    assert!(
        resp.status().is_success(),
        "V2 push should succeed at relay level (relay stores opaquely): {}",
        resp.status()
    );

    // ── B pulls → verifier rejects V2 signature → batch skipped ──
    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_b, &sync_id, &device_b_id);
    register_peer_device(&storage_b, &sync_id, &device_a_id, &keys_a);
    register_peer_device(&storage_b, &sync_id, &device_b_id, &keys_b);

    let relay_b = Arc::new(make_server_relay(
        &localhost_url,
        &sync_id,
        &device_b_id,
        &token_b,
        &keys_b,
    ));
    let ml_dsa_b = keys_b.device_secret.ml_dsa_65_keypair(&device_b_id).unwrap();
    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay_b.clone(),
        vec![entity_b.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );
    let result_b = engine_b
        .sync(
            &sync_id,
            &kh,
            &keys_b.ed25519_signing_key,
            Some(&ml_dsa_b),
            &device_b_id,
            0,
        )
        .await
        .unwrap();

    assert!(result_b.error.is_none(), "sync should not crash: {:?}", result_b.error);
    assert_eq!(result_b.pulled, 1, "V2 batch was received from relay");
    assert_eq!(
        result_b.merged, 0,
        "V2 Ed25519-only batch must be rejected by V3 verifier"
    );
    assert_eq!(entity_b.row_count(), 0, "no data from rejected V2 batch");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 7: X-Wing rekey through relay (epoch rotation lifecycle)
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn e2e_xwing_rekey_through_relay() {
    let (url, _server, _db) = start_test_relay().await;
    let localhost_url = to_localhost_url(&url);
    let client = Client::new();
    let sync_id = generate_sync_id();

    // ── Register 3 devices sharing epoch 0 ──
    let device_a_id = generate_device_id();
    let keys_a = TestDeviceKeys::generate(&device_a_id);
    let token_a = register_device(&client, &url, &sync_id, &device_a_id, &keys_a).await;

    let device_b_id = generate_device_id();
    let keys_b = TestDeviceKeys::generate(&device_b_id);
    let token_b = register_joiner_device(
        &client, &url, &sync_id, &device_b_id, &keys_b,
        &device_a_id, &keys_a,
        vec![
            registry_snapshot_entry_hybrid(&sync_id, &device_a_id, &keys_a, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &device_b_id, &keys_b, "active"),
        ],
    ).await;

    let device_c_id = generate_device_id();
    let keys_c = TestDeviceKeys::generate(&device_c_id);
    let _token_c = register_joiner_device(
        &client, &url, &sync_id, &device_c_id, &keys_c,
        &device_a_id, &keys_a,
        vec![
            registry_snapshot_entry_hybrid(&sync_id, &device_a_id, &keys_a, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &device_b_id, &keys_b, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &device_c_id, &keys_c, "active"),
        ],
    ).await;

    // ── A revokes C and posts wrapped epoch-1 keys for A and B ──
    // For this test, we use simple byte blobs as wrapped keys
    // (the relay stores them opaquely — the client-side unwrapping is what matters)
    let wrapped_for_a = b"wrapped-for-A-epoch-1".to_vec();
    let wrapped_for_b = b"wrapped-for-B-epoch-1".to_vec();

    let mut wrapped_keys = HashMap::new();
    wrapped_keys.insert(device_a_id.clone(), wrapped_for_a.clone());
    wrapped_keys.insert(device_b_id.clone(), wrapped_for_b.clone());

    let encoded_keys: HashMap<String, String> = wrapped_keys
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, v),
            )
        })
        .collect();

    let path = format!("/v1/sync/{sync_id}/devices/{device_c_id}/revoke");
    let body = serde_json::json!({
        "new_epoch": 1,
        "remote_wipe": false,
        "wrapped_keys": encoded_keys,
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let resp = apply_signed_headers(
        client
            .post(format!("{url}{path}"))
            .header("Authorization", format!("Bearer {token_a}"))
            .header("X-Device-Id", &device_a_id)
            .header("Content-Type", "application/json"),
        &keys_a,
        "POST",
        &path,
        &sync_id,
        &device_a_id,
        &body_bytes,
    )
    .body(body_bytes)
    .send()
    .await
    .unwrap();
    assert!(
        resp.status().is_success(),
        "revoke + rekey failed: {} - {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );

    // ── B fetches rekey artifact and recovers epoch 1 key ──
    let b_resp = client
        .get(format!(
            "{url}/v1/sync/{sync_id}/rekey/{device_b_id}?epoch=1"
        ))
        .header("Authorization", format!("Bearer {token_b}"))
        .header("X-Device-Id", &device_b_id)
        .send()
        .await
        .unwrap();
    assert_eq!(b_resp.status(), 200);
    let b_json: serde_json::Value = b_resp.json().await.unwrap();
    let recovered_wrapped = b_json["wrapped_key"]
        .as_str()
        .expect("wrapped_key should exist");
    let recovered_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        recovered_wrapped,
    )
    .unwrap();
    assert_eq!(
        recovered_bytes, wrapped_for_b,
        "B should recover the exact wrapped key material"
    );

    // ── C tries to get artifact → should fail ──
    let c_resp = client
        .get(format!(
            "{url}/v1/sync/{sync_id}/rekey/{device_c_id}?epoch=1"
        ))
        .header("Authorization", format!("Bearer {_token_c}"))
        .header("X-Device-Id", &device_c_id)
        .send()
        .await
        .unwrap();
    // C's session is invalidated on revoke
    assert!(
        c_resp.status() == 401 || c_resp.status() == 404,
        "Revoked device C should not access epoch 1 artifact, got: {}",
        c_resp.status()
    );

    // ── A pushes data encrypted with epoch 1 key ──
    // For this test, we verify at the HTTP level since actual epoch 1 key
    // management requires X-Wing unwrap which is complex. We verify the
    // rekey artifact delivery mechanism works end-to-end.

    // Push a batch at epoch 1 from A
    let ml_dsa_a = keys_a.device_secret.ml_dsa_65_keypair(&device_a_id).unwrap();
    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_a = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_a, &sync_id, &device_a_id);
    register_peer_device(&storage_a, &sync_id, &device_a_id, &keys_a);
    register_peer_device(&storage_a, &sync_id, &device_b_id, &keys_b);

    // Store epoch 1 key in A's hierarchy (simulate successful rekey).
    // Both A and B must share the SAME key hierarchy (same DEK → same epoch keys).
    let mut kh_shared = shared_key_hierarchy();
    // Derive a unique epoch 1 key using HKDF from the shared DEK
    let epoch1_key = kdf::derive_subkey(
        kh_shared.dek().unwrap(),
        b"epoch_1",
        b"prism_epoch_sync",
    )
    .unwrap();
    kh_shared.store_epoch_key(1, epoch1_key);

    // Update current epoch in storage
    {
        let mut tx = storage_a.begin_tx().unwrap();
        tx.update_current_epoch(&sync_id, 1).unwrap();
        tx.commit().unwrap();
    }

    // Create ops at epoch 1
    let hlc = Hlc::now(&device_a_id, None);
    let ops_epoch1 = vec![
        CrdtChange {
            op_id: format!("tasks:epoch1-task:title:{hlc}:{device_a_id}"),
            batch_id: Some("batch-epoch1".to_string()),
            entity_id: "epoch1-task".to_string(),
            entity_table: "tasks".to_string(),
            field_name: "title".to_string(),
            encoded_value: "\"Epoch 1 data\"".to_string(),
            client_hlc: hlc.to_string(),
            is_delete: false,
            device_id: device_a_id.to_string(),
            epoch: 1,
            server_seq: None,
        },
    ];
    {
        use prism_sync_core::storage::PendingOp;
        let mut tx = storage_a.begin_tx().unwrap();
        for op in &ops_epoch1 {
            tx.insert_pending_op(&PendingOp {
                op_id: op.op_id.clone(),
                sync_id: sync_id.to_string(),
                epoch: 1,
                device_id: op.device_id.clone(),
                local_batch_id: "batch-epoch1".to_string(),
                entity_table: op.entity_table.clone(),
                entity_id: op.entity_id.clone(),
                field_name: op.field_name.clone(),
                encoded_value: op.encoded_value.clone(),
                is_delete: op.is_delete,
                client_hlc: op.client_hlc.clone(),
                created_at: chrono::Utc::now(),
                pushed_at: None,
            })
            .unwrap();
        }
        tx.commit().unwrap();
    }

    let relay_a = Arc::new(make_server_relay(
        &localhost_url,
        &sync_id,
        &device_a_id,
        &token_a,
        &keys_a,
    ));
    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay_a.clone(),
        vec![entity_a.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );
    let result = engine_a
        .sync(
            &sync_id,
            &kh_shared,
            &keys_a.ed25519_signing_key,
            Some(&ml_dsa_a),
            &device_a_id,
            0,
        )
        .await
        .unwrap();
    assert!(
        result.error.is_none(),
        "A epoch-1 push failed: {:?}",
        result.error
    );
    assert_eq!(result.pushed, 1, "A should push epoch-1 batch");

    // ── B pulls with epoch 1 key and decrypts ──
    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_b, &sync_id, &device_b_id);
    register_peer_device(&storage_b, &sync_id, &device_a_id, &keys_a);
    register_peer_device(&storage_b, &sync_id, &device_b_id, &keys_b);

    // B uses the same shared key hierarchy (simulating successful X-Wing unwrap)

    let relay_b = Arc::new(make_server_relay(
        &localhost_url,
        &sync_id,
        &device_b_id,
        &token_b,
        &keys_b,
    ));
    let ml_dsa_b = keys_b.device_secret.ml_dsa_65_keypair(&device_b_id).unwrap();
    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay_b.clone(),
        vec![entity_b.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );
    let result = engine_b
        .sync(
            &sync_id,
            &kh_shared,
            &keys_b.ed25519_signing_key,
            Some(&ml_dsa_b),
            &device_b_id,
            0,
        )
        .await
        .unwrap();
    assert!(
        result.error.is_none(),
        "B epoch-1 pull failed: {:?}",
        result.error
    );
    assert_eq!(result.merged, 1, "B should decrypt and merge epoch-1 data");
    assert_eq!(
        entity_b.get_field("epoch1-task", "title"),
        Some(SyncValue::String("Epoch 1 data".to_string()))
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Helper: write_len_prefixed_utf8 (matches batch_signature format)
// ═══════════════════════════════════════════════════════════════════════════

fn write_len_prefixed_utf8(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}
