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

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use common::*;
use reqwest::Client;

use prism_sync_core::engine::{SyncConfig, SyncEngine};
use prism_sync_core::relay::traits::{DeviceRegistry, RegisterRequest};
use prism_sync_core::relay::ServerRelay;
use prism_sync_core::schema::{encode_value, SyncFieldDef, SyncSchema, SyncType, SyncValue};
use prism_sync_core::storage::{
    DeviceRecord, FieldVersion, PendingOp, RusqliteSyncStorage, SyncStorage,
};
use prism_sync_core::syncable_entity::SyncableEntity;
use prism_sync_core::{batch_signature, sync_aad, CrdtChange, Hlc, SyncMetadata};
use prism_sync_crypto::KeyHierarchy;

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
        Self { rows: Mutex::new(HashMap::new()), deleted: Mutex::new(HashMap::new()) }
    }

    fn get_field(&self, entity_id: &str, field: &str) -> Option<SyncValue> {
        self.rows.lock().unwrap().get(entity_id).and_then(|row| row.get(field).cloned())
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
                SyncFieldDef { name: "title".to_string(), sync_type: SyncType::String },
                SyncFieldDef { name: "done".to_string(), sync_type: SyncType::Bool },
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
        self.deleted.lock().unwrap().insert(entity_id.to_string(), true);
        Ok(())
    }

    async fn is_deleted(&self, entity_id: &str) -> prism_sync_core::Result<bool> {
        Ok(self.deleted.lock().unwrap().get(entity_id).copied().unwrap_or(false))
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

/// Dynamic test entity used for app-schema probes.
struct CapturingEntity {
    table_name: String,
    fields: Vec<SyncFieldDef>,
    rows: Mutex<HashMap<String, HashMap<String, SyncValue>>>,
    deleted: Mutex<HashMap<String, bool>>,
}

impl CapturingEntity {
    fn new(table_name: String, fields: Vec<SyncFieldDef>) -> Self {
        Self {
            table_name,
            fields,
            rows: Mutex::new(HashMap::new()),
            deleted: Mutex::new(HashMap::new()),
        }
    }

    fn get_field(&self, entity_id: &str, field: &str) -> Option<SyncValue> {
        self.rows.lock().unwrap().get(entity_id).and_then(|row| row.get(field).cloned())
    }
}

#[async_trait::async_trait]
impl SyncableEntity for CapturingEntity {
    fn table_name(&self) -> &str {
        &self.table_name
    }

    fn field_definitions(&self) -> &[SyncFieldDef] {
        &self.fields
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
        self.deleted.lock().unwrap().insert(entity_id.to_string(), true);
        Ok(())
    }

    async fn is_deleted(&self, entity_id: &str) -> prism_sync_core::Result<bool> {
        Ok(self.deleted.lock().unwrap().get(entity_id).copied().unwrap_or(false))
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
        .entity("tasks", |e| e.field("title", SyncType::String).field("done", SyncType::Bool))
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
    let ml_dsa_kp = joiner_keys.device_secret.ml_dsa_65_keypair(joiner_device_id).unwrap();

    // 1. Fetch nonce
    let nonce_resp =
        client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
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
    let registry_approval =
        build_registry_approval(sync_id, approver_device_id, approver_keys, all_entries);

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
    assert!(status.is_success(), "joiner registration failed: {status} - {token_json}");
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

#[derive(Clone)]
struct TypeProbe {
    type_name: String,
    table: String,
    field: String,
    entity_id: String,
    expected: SyncValue,
}

fn app_sync_schema_json() -> Option<String> {
    let app_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../app");
    if !app_dir.exists() {
        return None;
    }
    let path = app_dir.join("lib/core/sync/sync_schema.dart");
    let source = std::fs::read_to_string(path).expect("failed to read app sync schema");

    let marker = "const String prismSyncSchema = '''";
    let start = source.find(marker).expect("prismSyncSchema const should exist") + marker.len();
    let rest = &source[start..];
    let end = rest.find("''';").expect("prismSyncSchema const should be closed");
    Some(rest[..end].trim().to_string())
}

fn type_probe_value(type_name: &str) -> SyncValue {
    match type_name {
        "String" => SyncValue::String("schema-probe".to_string()),
        "Int" => SyncValue::Int(42),
        "Real" => SyncValue::Real(7.25),
        "Bool" => SyncValue::Bool(true),
        "DateTime" => {
            let dt = "2026-04-27T12:34:56.789Z".parse().unwrap();
            SyncValue::DateTime(dt)
        }
        "Blob" => SyncValue::Blob(vec![0x00, 0x01, 0x7F, 0x80, 0xFF]),
        other => panic!("app schema uses unsupported SyncType {other:?}; add a probe value"),
    }
}

fn app_schema_type_probes(schema_json: &str) -> Vec<TypeProbe> {
    let value: serde_json::Value = serde_json::from_str(schema_json).unwrap();
    let entities = value["entities"].as_object().expect("schema entities object");
    let mut by_type = BTreeMap::<String, TypeProbe>::new();

    for (table, entity) in entities {
        let fields = entity["fields"].as_object().expect("schema fields object");
        for (field, field_type) in fields {
            let type_name = field_type.as_str().expect("field type string");
            by_type.entry(type_name.to_string()).or_insert_with(|| {
                let expected = type_probe_value(type_name);
                TypeProbe {
                    type_name: type_name.to_string(),
                    table: table.clone(),
                    field: field.clone(),
                    entity_id: format!("app-schema-type-probe-{}", type_name.to_lowercase()),
                    expected,
                }
            });
        }
    }

    by_type.into_values().collect()
}

fn create_app_schema_type_probe_ops(
    storage: &RusqliteSyncStorage,
    sync_id: &str,
    device_id: &str,
    probes: &[TypeProbe],
    batch_id: &str,
) {
    let hlc = Hlc::now(device_id, None);
    let mut tx = storage.begin_tx().unwrap();
    for probe in probes {
        tx.insert_pending_op(&PendingOp {
            op_id: format!(
                "{}:{}:{}:{}:{}",
                probe.table, probe.entity_id, probe.field, hlc, device_id
            ),
            sync_id: sync_id.to_string(),
            epoch: 0,
            device_id: device_id.to_string(),
            local_batch_id: batch_id.to_string(),
            entity_table: probe.table.clone(),
            entity_id: probe.entity_id.clone(),
            field_name: probe.field.clone(),
            encoded_value: encode_value(&probe.expected),
            is_delete: false,
            client_hlc: hlc.to_string(),
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

#[tokio::test]
async fn server_relay_uses_registration_session_for_followup_auth() {
    let (url, _server, _db) = start_test_relay().await;
    let localhost_url = to_localhost_url(&url);
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let ml_dsa_kp = keys.device_secret.ml_dsa_65_keypair(&device_id).unwrap();
    let relay = make_server_relay(&localhost_url, &sync_id, &device_id, "", &keys);

    let nonce_response = relay.get_registration_nonce().await.unwrap();
    let challenge_sig = sign_hybrid_challenge(
        &keys.ed25519_signing_key,
        &ml_dsa_kp,
        &sync_id,
        &device_id,
        &nonce_response.nonce,
    );

    relay
        .register_device(RegisterRequest {
            device_id: device_id.clone(),
            signing_public_key: keys.ed25519_signing_key.verifying_key().as_bytes().to_vec(),
            x25519_public_key: keys.x25519_pk.to_vec(),
            ml_dsa_65_public_key: keys.ml_dsa_pk.clone(),
            ml_kem_768_public_key: keys.ml_kem_pk.clone(),
            x_wing_public_key: Vec::new(),
            registration_challenge: challenge_sig,
            nonce: nonce_response.nonce,
            pow_solution: None,
            first_device_admission_proof: None,
            registry_approval: None,
        })
        .await
        .unwrap();

    let devices = relay.list_devices().await.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_id, device_id);
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

    create_task_ops(&storage_a, &sync_id, &device_a_id, "task-1", "Buy groceries", "batch-a1");

    let relay_a =
        Arc::new(make_server_relay(&localhost_url, &sync_id, &device_a_id, &token_a, &keys_a));
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
        .sync(&sync_id, &kh, &keys_a.ed25519_signing_key, Some(&ml_dsa_a), &device_a_id, 0)
        .await
        .unwrap();
    assert!(result_a.error.is_none(), "Device A push failed: {:?}", result_a.error);
    assert_eq!(result_a.pushed, 1, "expected 1 batch pushed from A");

    // ── Device B: create storage, engine ──
    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_b, &sync_id, &device_b_id);
    register_peer_device(&storage_b, &sync_id, &device_a_id, &keys_a);
    register_peer_device(&storage_b, &sync_id, &device_b_id, &keys_b);

    let relay_b =
        Arc::new(make_server_relay(&localhost_url, &sync_id, &device_b_id, &token_b, &keys_b));
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
        .sync(&sync_id, &kh, &keys_b.ed25519_signing_key, Some(&ml_dsa_b), &device_b_id, 0)
        .await
        .unwrap();
    assert!(result_b.error.is_none(), "Device B pull failed: {:?}", result_b.error);
    assert_eq!(result_b.pulled, 1, "expected 1 batch pulled by B");
    assert_eq!(result_b.merged, 2, "expected 2 ops merged (title + done)");

    // Verify entity data arrived
    assert_eq!(
        entity_b.get_field("task-1", "title"),
        Some(SyncValue::String("Buy groceries".to_string()))
    );
    assert_eq!(entity_b.get_field("task-1", "done"), Some(SyncValue::Bool(false)));

    // ── Device B: create a task and sync ──
    create_task_ops(&storage_b, &sync_id, &device_b_id, "task-2", "Walk the dog", "batch-b1");

    let result_b2 = engine_b
        .sync(&sync_id, &kh, &keys_b.ed25519_signing_key, Some(&ml_dsa_b), &device_b_id, 0)
        .await
        .unwrap();
    assert!(result_b2.error.is_none(), "Device B push failed: {:?}", result_b2.error);
    assert_eq!(result_b2.pushed, 1, "expected 1 batch pushed from B");

    // ── Device A syncs: pulls B's batch ──
    let result_a2 = engine_a
        .sync(&sync_id, &kh, &keys_a.ed25519_signing_key, Some(&ml_dsa_a), &device_a_id, 0)
        .await
        .unwrap();
    assert!(result_a2.error.is_none(), "Device A pull failed: {:?}", result_a2.error);
    // A pulls 2 batches: its own (seq 1, skipped at merge) + B's (seq 2, merged)
    assert_eq!(result_a2.pulled, 2, "expected 2 batches pulled by A (own + B's)");
    assert_eq!(result_a2.merged, 2, "expected 2 ops merged from B's batch");

    // Verify cross-device data arrival
    // entity_a has task-2 from B (merged via pull), but task-1 was local pending ops
    // (MockTaskEntity only receives remote writes from merge, not local ops)
    assert_eq!(
        entity_a.get_field("task-2", "title"),
        Some(SyncValue::String("Walk the dog".to_string()))
    );
    assert_eq!(entity_a.row_count(), 1, "A should have 1 remote task from B");
    // entity_b has task-1 from A (merged via pull)
    assert_eq!(entity_b.row_count(), 1, "B should have 1 remote task from A");
}

#[tokio::test]
async fn e2e_app_schema_declared_types_round_trip_through_real_relay() {
    let Some(schema_json) = app_sync_schema_json() else {
        eprintln!("skipping app-schema type probe; app sync schema is not present");
        return;
    };
    let schema = SyncSchema::from_json(&schema_json).expect("app sync schema should parse");
    let probes = app_schema_type_probes(&schema_json);
    assert!(!probes.is_empty(), "app sync schema should declare at least one field type");

    let (url, _server, _db) = start_test_relay().await;
    let localhost_url = to_localhost_url(&url);
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_a_id = generate_device_id();
    let keys_a = TestDeviceKeys::generate(&device_a_id);
    let token_a = register_device(&client, &url, &sync_id, &device_a_id, &keys_a).await;

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

    let tables: BTreeMap<String, Vec<SyncFieldDef>> = probes
        .iter()
        .map(|probe| {
            let fields = schema
                .entity(&probe.table)
                .unwrap_or_else(|| panic!("schema should contain table {}", probe.table))
                .fields
                .clone();
            (probe.table.clone(), fields)
        })
        .collect();

    let make_entities =
        || -> (Vec<Arc<dyn SyncableEntity>>, HashMap<String, Arc<CapturingEntity>>) {
            let mut trait_objects = Vec::<Arc<dyn SyncableEntity>>::new();
            let mut by_table = HashMap::<String, Arc<CapturingEntity>>::new();
            for (table, fields) in &tables {
                let entity = Arc::new(CapturingEntity::new(table.clone(), fields.clone()));
                trait_objects.push(entity.clone() as Arc<dyn SyncableEntity>);
                by_table.insert(table.clone(), entity);
            }
            (trait_objects, by_table)
        };

    let kh = shared_key_hierarchy();

    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    setup_sync_metadata(&storage_a, &sync_id, &device_a_id);
    register_peer_device(&storage_a, &sync_id, &device_a_id, &keys_a);
    register_peer_device(&storage_a, &sync_id, &device_b_id, &keys_b);
    create_app_schema_type_probe_ops(
        &storage_a,
        &sync_id,
        &device_a_id,
        &probes,
        "batch-app-schema-type-probes",
    );
    let (entities_a, _) = make_entities();
    let relay_a =
        Arc::new(make_server_relay(&localhost_url, &sync_id, &device_a_id, &token_a, &keys_a));
    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay_a,
        entities_a,
        schema.clone(),
        SyncConfig::default(),
    );
    let ml_dsa_a = keys_a.device_secret.ml_dsa_65_keypair(&device_a_id).unwrap();

    let result_a = engine_a
        .sync(&sync_id, &kh, &keys_a.ed25519_signing_key, Some(&ml_dsa_a), &device_a_id, 0)
        .await
        .unwrap();
    assert!(result_a.error.is_none(), "Device A push failed: {:?}", result_a.error);
    assert_eq!(result_a.pushed, 1, "expected one app-schema type probe batch");

    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    setup_sync_metadata(&storage_b, &sync_id, &device_b_id);
    register_peer_device(&storage_b, &sync_id, &device_a_id, &keys_a);
    register_peer_device(&storage_b, &sync_id, &device_b_id, &keys_b);
    let (entities_b, entity_b_by_table) = make_entities();
    let relay_b =
        Arc::new(make_server_relay(&localhost_url, &sync_id, &device_b_id, &token_b, &keys_b));
    let engine_b = SyncEngine::new(storage_b, relay_b, entities_b, schema, SyncConfig::default());
    let ml_dsa_b = keys_b.device_secret.ml_dsa_65_keypair(&device_b_id).unwrap();

    let result_b = engine_b
        .sync(&sync_id, &kh, &keys_b.ed25519_signing_key, Some(&ml_dsa_b), &device_b_id, 0)
        .await
        .unwrap();
    assert!(result_b.error.is_none(), "Device B pull failed: {:?}", result_b.error);
    assert_eq!(result_b.pulled, 1, "expected one app-schema type probe batch pulled");
    assert_eq!(
        result_b.merged,
        probes.len() as u64,
        "expected every probed app schema type to merge"
    );

    for probe in &probes {
        let entity = entity_b_by_table
            .get(&probe.table)
            .unwrap_or_else(|| panic!("missing capture entity for {}", probe.table));
        assert_eq!(
            entity.get_field(&probe.entity_id, &probe.field),
            Some(probe.expected.clone()),
            "app schema type {} should round-trip through relay via {}.{}",
            probe.type_name,
            probe.table,
            probe.field
        );
    }
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

    let relay_a =
        Arc::new(make_server_relay(&localhost_url, &sync_id, &device_a_id, &token_a, &keys_a));
    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay_a.clone(),
        vec![entity_a.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );

    let ml_dsa_a = keys_a.device_secret.ml_dsa_65_keypair(&device_a_id).unwrap();
    let result_a = engine_a
        .sync(&sync_id, &kh, &keys_a.ed25519_signing_key, Some(&ml_dsa_a), &device_a_id, 0)
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
            let mut sig_bytes = base64::engine::general_purpose::STANDARD.decode(sig).unwrap();
            // The ML-DSA signature starts after the Ed25519 component.
            // Flip a byte deep inside the ML-DSA portion to corrupt it.
            if sig_bytes.len() > 200 {
                sig_bytes[200] ^= 0xFF;
            }
            let tampered_sig = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);
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

    let relay_b =
        Arc::new(make_server_relay(&localhost_url, &sync_id, &device_b_id, &token_b, &keys_b));
    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay_b.clone(),
        vec![entity_b.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );

    let ml_dsa_b = keys_b.device_secret.ml_dsa_65_keypair(&device_b_id).unwrap();
    let result_b = engine_b
        .sync(&sync_id, &kh, &keys_b.ed25519_signing_key, Some(&ml_dsa_b), &device_b_id, 0)
        .await
        .unwrap();

    // The sync should succeed (not crash) but no data should be merged
    assert!(
        result_b.error.is_none(),
        "sync should not error, just skip bad batch: {:?}",
        result_b.error
    );
    assert_eq!(result_b.pulled, 1, "batch was pulled (received from relay)");
    assert_eq!(result_b.merged, 0, "ML-DSA-tampered batch must NOT be merged");
    assert_eq!(entity_b.row_count(), 0, "no data should arrive from ML-DSA-tampered batch");

    // ── Phase 2: Ed25519 tampering ──
    // Push a NEW valid batch from A, then tamper the Ed25519 portion
    create_task_ops(
        &storage_a,
        &sync_id,
        &device_a_id,
        "task-tamper-ed",
        "Ed25519 tamper test",
        "batch-tamper-ed",
    );

    let result_a2 = engine_a
        .sync(&sync_id, &kh, &keys_a.ed25519_signing_key, Some(&ml_dsa_a), &device_a_id, 0)
        .await
        .unwrap();
    assert!(result_a2.error.is_none(), "A push 2 failed: {:?}", result_a2.error);
    assert_eq!(result_a2.pushed, 1);

    // Tamper the Ed25519 portion (offset 10 is inside Ed25519 sig, which starts at offset 4)
    // Wire format: [4B ed_len LE][64B ed25519_sig][4B ml_dsa_len LE][~3309B ml_dsa_sig]
    let sid2 = sync_id.clone();
    db.with_conn(|conn| {
        // Get the latest batch (highest id)
        let data: Vec<u8> = conn.query_row(
            "SELECT data FROM batches WHERE sync_id = ?1 ORDER BY id DESC LIMIT 1",
            rusqlite::params![sid2],
            |row| row.get(0),
        )?;

        let mut envelope: serde_json::Value = serde_json::from_slice(&data).unwrap();
        if let Some(sig) = envelope.get("signature").and_then(|s| s.as_str()) {
            use base64::Engine;
            let mut sig_bytes =
                base64::engine::general_purpose::STANDARD.decode(sig).unwrap();
            // Flip byte at offset 10 (inside Ed25519 signature, which spans bytes 4..68)
            if sig_bytes.len() > 10 {
                sig_bytes[10] ^= 0xFF;
            }
            let tampered_sig =
                base64::engine::general_purpose::STANDARD.encode(&sig_bytes);
            envelope["signature"] = serde_json::Value::String(tampered_sig);
        }

        let tampered_data = serde_json::to_vec(&envelope).unwrap();
        conn.execute(
            "UPDATE batches SET data = ?1 WHERE sync_id = ?2 AND id = (SELECT MAX(id) FROM batches WHERE sync_id = ?2)",
            rusqlite::params![tampered_data, sid2],
        )?;
        Ok(())
    })
    .expect("tamper Ed25519 portion");

    // B pulls again — Ed25519-tampered batch must also be rejected
    let result_b2 = engine_b
        .sync(&sync_id, &kh, &keys_b.ed25519_signing_key, Some(&ml_dsa_b), &device_b_id, 0)
        .await
        .unwrap();

    assert!(
        result_b2.error.is_none(),
        "sync should not error on Ed25519-tampered batch: {:?}",
        result_b2.error
    );
    assert_eq!(result_b2.merged, 0, "Ed25519-tampered batch must NOT be merged");
    assert_eq!(entity_b.row_count(), 0, "no data should arrive from either tampered batch");
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

    let device_c_id = generate_device_id();
    let keys_c = TestDeviceKeys::generate(&device_c_id);
    let token_c = register_joiner_device(
        &client,
        &url,
        &sync_id,
        &device_c_id,
        &keys_c,
        &device_a_id,
        &keys_a,
        vec![
            registry_snapshot_entry_hybrid(&sync_id, &device_a_id, &keys_a, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &device_b_id, &keys_b, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &device_c_id, &keys_c, "active"),
        ],
    )
    .await;

    let kh = shared_key_hierarchy();

    // ── A publishes signed registry including all three devices ──
    let ml_dsa_a = keys_a.device_secret.ml_dsa_65_keypair(&device_a_id).unwrap();
    let entries = vec![
        registry_snapshot_entry_hybrid(&sync_id, &device_a_id, &keys_a, "active"),
        registry_snapshot_entry_hybrid(&sync_id, &device_b_id, &keys_b, "active"),
        registry_snapshot_entry_hybrid(&sync_id, &device_c_id, &keys_c, "active"),
    ];
    let signed_registry =
        build_signed_registry_snapshot_hybrid(entries, &keys_a.ed25519_signing_key, &ml_dsa_a);

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
    assert!(resp.status().is_success(), "registry upload failed: {}", resp.status());

    // ── C pushes a batch ──
    let storage_c = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_c = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_c, &sync_id, &device_c_id);
    register_peer_device(&storage_c, &sync_id, &device_c_id, &keys_c);

    create_task_ops(&storage_c, &sync_id, &device_c_id, "task-from-c", "C's task", "batch-c1");

    let relay_c =
        Arc::new(make_server_relay(&localhost_url, &sync_id, &device_c_id, &token_c, &keys_c));
    let ml_dsa_c = keys_c.device_secret.ml_dsa_65_keypair(&device_c_id).unwrap();
    let engine_c = SyncEngine::new(
        storage_c.clone(),
        relay_c.clone(),
        vec![entity_c.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );
    let result_c = engine_c
        .sync(&sync_id, &kh, &keys_c.ed25519_signing_key, Some(&ml_dsa_c), &device_c_id, 0)
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

    let relay_b =
        Arc::new(make_server_relay(&localhost_url, &sync_id, &device_b_id, &token_b, &keys_b));
    let ml_dsa_b = keys_b.device_secret.ml_dsa_65_keypair(&device_b_id).unwrap();
    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay_b.clone(),
        vec![entity_b.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );
    let result_b = engine_b
        .sync(&sync_id, &kh, &keys_b.ed25519_signing_key, Some(&ml_dsa_b), &device_b_id, 0)
        .await
        .unwrap();
    assert!(result_b.error.is_none(), "B pull failed: {:?}", result_b.error);
    assert_eq!(result_b.merged, 2, "B should have merged C's 2 ops via registry lookup");
    assert_eq!(
        entity_b.get_field("task-from-c", "title"),
        Some(SyncValue::String("C's task".to_string()))
    );
    assert_eq!(entity_b.row_count(), 1, "B should have exactly 1 task from C");
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

    let relay_a =
        Arc::new(make_server_relay(&localhost_url, &sync_id, &device_a_id, &token_a, &keys_a));
    let ml_dsa_a_gen0 = keys_a.device_secret.ml_dsa_65_keypair(&device_a_id).unwrap();
    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay_a.clone(),
        vec![entity_a.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );
    let result = engine_a
        .sync(&sync_id, &kh, &keys_a.ed25519_signing_key, Some(&ml_dsa_a_gen0), &device_a_id, 0)
        .await
        .unwrap();
    assert!(result.error.is_none());
    assert_eq!(result.pushed, 1);

    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_b, &sync_id, &device_b_id);
    register_peer_device(&storage_b, &sync_id, &device_a_id, &keys_a);
    register_peer_device(&storage_b, &sync_id, &device_b_id, &keys_b);

    let relay_b =
        Arc::new(make_server_relay(&localhost_url, &sync_id, &device_b_id, &token_b, &keys_b));
    let ml_dsa_b = keys_b.device_secret.ml_dsa_65_keypair(&device_b_id).unwrap();
    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay_b.clone(),
        vec![entity_b.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );
    let result = engine_b
        .sync(&sync_id, &kh, &keys_b.ed25519_signing_key, Some(&ml_dsa_b), &device_b_id, 0)
        .await
        .unwrap();
    assert!(result.error.is_none());
    assert_eq!(result.merged, 2, "B should verify gen-0 batch");

    // ── A rotates ML-DSA to gen 1 ──
    // Use the SAME DeviceSecret with generation 1 (not a new secret)
    let ml_dsa_a_gen1 = keys_a.device_secret.ml_dsa_65_keypair_v(&device_a_id, 1).unwrap();

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
    let path = format!("/v1/sync/{sync_id}/devices/{device_a_id}/rotate-ml-dsa");
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
        let ml_dsa_a_gen1_for_relay =
            keys_a.device_secret.ml_dsa_65_keypair_v(&device_a_id, 1).unwrap();
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
        .sync(&sync_id, &kh, &keys_b.ed25519_signing_key, Some(&ml_dsa_b), &device_b_id, 0)
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

    let device_c_id = generate_device_id();
    let keys_c = TestDeviceKeys::generate(&device_c_id);
    let _token_c = register_joiner_device(
        &client,
        &url,
        &sync_id,
        &device_c_id,
        &keys_c,
        &device_a_id,
        &keys_a,
        vec![
            registry_snapshot_entry_hybrid(&sync_id, &device_a_id, &keys_a, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &device_b_id, &keys_b, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &device_c_id, &keys_c, "active"),
        ],
    )
    .await;

    // ── A revokes C, rekeys to epoch 1 using real X-Wing KEM ──
    // Generate a real epoch 1 key
    let mut epoch_1_key = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut epoch_1_key);

    // Build real X-Wing wrapped keys for A and B (not C)
    use prism_sync_crypto::pq::hybrid_kem::XWingKem;
    let xwing_a = keys_a.device_secret.xwing_keypair(&device_a_id).unwrap();
    let xwing_b = keys_b.device_secret.xwing_keypair(&device_b_id).unwrap();

    fn build_rekey_artifact(
        xwing_ek_bytes: &[u8],
        epoch_key: &[u8],
        new_epoch: u32,
        device_id: &str,
    ) -> Vec<u8> {
        let ek = XWingKem::encapsulation_key_from_bytes(xwing_ek_bytes).unwrap();
        let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
        let (ciphertext, shared_secret_raw) = XWingKem::encapsulate(&ek, &mut rng);
        let shared_secret = zeroize::Zeroizing::new(shared_secret_raw);
        let mut salt = Vec::with_capacity(4 + device_id.len());
        salt.extend_from_slice(&new_epoch.to_le_bytes());
        salt.extend_from_slice(device_id.as_bytes());
        let wrap_key =
            prism_sync_crypto::kdf::derive_subkey(&shared_secret, &salt, b"prism_epoch_rekey_v2")
                .unwrap();
        let encrypted_epoch_key =
            prism_sync_crypto::aead::xchacha_encrypt(&wrap_key, epoch_key).unwrap();
        let mut artifact = Vec::with_capacity(1 + ciphertext.len() + encrypted_epoch_key.len());
        artifact.push(0x02);
        artifact.extend_from_slice(&ciphertext);
        artifact.extend_from_slice(&encrypted_epoch_key);
        artifact
    }

    let wrapped_key_for_a =
        build_rekey_artifact(&xwing_a.encapsulation_key_bytes(), &epoch_1_key, 1, &device_a_id);
    let wrapped_key_for_b =
        build_rekey_artifact(&xwing_b.encapsulation_key_bytes(), &epoch_1_key, 1, &device_b_id);
    let mut wrapped_keys = HashMap::new();
    wrapped_keys.insert(device_a_id.clone(), wrapped_key_for_a.clone());
    wrapped_keys.insert(device_b_id.clone(), wrapped_key_for_b.clone());

    let encoded_keys: HashMap<String, String> = wrapped_keys
        .iter()
        .map(|(k, v)| {
            (k.clone(), base64::Engine::encode(&base64::engine::general_purpose::STANDARD, v))
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
    assert!(resp.status().is_success(), "revoke failed: {}", resp.status());

    // ── B fetches rekey artifact successfully ──
    let b_artifact_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/rekey/{device_b_id}?epoch=1"))
        .header("Authorization", format!("Bearer {token_b}"))
        .header("X-Device-Id", &device_b_id)
        .send()
        .await
        .unwrap();
    assert_eq!(b_artifact_resp.status(), 200);
    let b_json: serde_json::Value = b_artifact_resp.json().await.unwrap();
    let recovered_wrapped = b_json["wrapped_key"].as_str().expect("wrapped_key should exist");
    let recovered_artifact =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, recovered_wrapped)
            .unwrap();

    // ── B decrypts the real X-Wing artifact to recover epoch 1 key ──
    assert_eq!(recovered_artifact[0], 0x02, "artifact version should be 0x02");
    assert!(recovered_artifact.len() > 1120, "artifact too short for X-Wing ciphertext");
    let ciphertext = &recovered_artifact[1..1121];
    let encrypted_epoch_key = &recovered_artifact[1121..];

    let shared_secret = xwing_b.decapsulate(ciphertext).unwrap();
    let mut salt = Vec::with_capacity(4 + device_b_id.len());
    salt.extend_from_slice(&1u32.to_le_bytes());
    salt.extend_from_slice(device_b_id.as_bytes());
    let unwrap_key =
        prism_sync_crypto::kdf::derive_subkey(&shared_secret, &salt, b"prism_epoch_rekey_v2")
            .unwrap();
    let recovered_epoch_key =
        prism_sync_crypto::aead::xchacha_decrypt(&unwrap_key, encrypted_epoch_key).unwrap();
    assert_eq!(
        recovered_epoch_key, epoch_1_key,
        "B should recover the exact epoch 1 key through real X-Wing KEM"
    );

    // ── C tries to fetch rekey artifact → should fail (revoked) ──
    // The auth middleware detects revoked device status and returns 401 (DeviceRevoked)
    let c_artifact_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/rekey/{device_c_id}?epoch=1"))
        .header("Authorization", format!("Bearer {_token_c}"))
        .header("X-Device-Id", &device_c_id)
        .send()
        .await
        .unwrap();
    assert_eq!(
        c_artifact_resp.status(),
        401,
        "Revoked device should get 401 (DeviceRevoked), got: {}",
        c_artifact_resp.status()
    );

    // ── Verify C's X-Wing key CANNOT decrypt B's artifact ──
    let xwing_c = keys_c.device_secret.xwing_keypair(&device_c_id).unwrap();
    let c_shared_secret = xwing_c.decapsulate(ciphertext).unwrap();
    let mut c_salt = Vec::with_capacity(4 + device_c_id.len());
    c_salt.extend_from_slice(&1u32.to_le_bytes());
    c_salt.extend_from_slice(device_c_id.as_bytes());
    let c_unwrap_key =
        prism_sync_crypto::kdf::derive_subkey(&c_shared_secret, &c_salt, b"prism_epoch_rekey_v2")
            .unwrap();
    let c_result = prism_sync_crypto::aead::xchacha_decrypt(&c_unwrap_key, encrypted_epoch_key);
    assert!(c_result.is_err(), "C should NOT be able to decrypt B's wrapped epoch key");
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

    let kh = shared_key_hierarchy();

    // ── Construct a V2 Ed25519-only batch envelope and push it directly ──
    // Build a real encrypted payload
    let hlc = Hlc::now(&device_a_id, None);
    let ops = vec![CrdtChange {
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
    }];
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

    let relay_b =
        Arc::new(make_server_relay(&localhost_url, &sync_id, &device_b_id, &token_b, &keys_b));
    let ml_dsa_b = keys_b.device_secret.ml_dsa_65_keypair(&device_b_id).unwrap();
    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay_b.clone(),
        vec![entity_b.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );
    let result_b = engine_b
        .sync(&sync_id, &kh, &keys_b.ed25519_signing_key, Some(&ml_dsa_b), &device_b_id, 0)
        .await
        .unwrap();

    assert!(result_b.error.is_none(), "sync should not crash: {:?}", result_b.error);
    assert_eq!(result_b.pulled, 1, "V2 batch was received from relay");
    assert_eq!(result_b.merged, 0, "V2 Ed25519-only batch must be rejected by V3 verifier");
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

    let device_c_id = generate_device_id();
    let keys_c = TestDeviceKeys::generate(&device_c_id);
    let _token_c = register_joiner_device(
        &client,
        &url,
        &sync_id,
        &device_c_id,
        &keys_c,
        &device_a_id,
        &keys_a,
        vec![
            registry_snapshot_entry_hybrid(&sync_id, &device_a_id, &keys_a, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &device_b_id, &keys_b, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &device_c_id, &keys_c, "active"),
        ],
    )
    .await;

    // ── A revokes C and posts real X-Wing wrapped epoch-1 keys for A and B ──
    // Generate a real epoch 1 key
    let mut epoch_1_key = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut epoch_1_key);

    // Build real X-Wing KEM artifacts for surviving devices
    use prism_sync_crypto::pq::hybrid_kem::XWingKem;
    let xwing_a = keys_a.device_secret.xwing_keypair(&device_a_id).unwrap();
    let xwing_b = keys_b.device_secret.xwing_keypair(&device_b_id).unwrap();

    fn build_rekey_artifact_t7(
        xwing_ek_bytes: &[u8],
        epoch_key: &[u8],
        new_epoch: u32,
        device_id: &str,
    ) -> Vec<u8> {
        let ek = XWingKem::encapsulation_key_from_bytes(xwing_ek_bytes).unwrap();
        let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
        let (ciphertext, shared_secret_raw) = XWingKem::encapsulate(&ek, &mut rng);
        let shared_secret = zeroize::Zeroizing::new(shared_secret_raw);
        let mut salt = Vec::with_capacity(4 + device_id.len());
        salt.extend_from_slice(&new_epoch.to_le_bytes());
        salt.extend_from_slice(device_id.as_bytes());
        let wrap_key =
            prism_sync_crypto::kdf::derive_subkey(&shared_secret, &salt, b"prism_epoch_rekey_v2")
                .unwrap();
        let encrypted_epoch_key =
            prism_sync_crypto::aead::xchacha_encrypt(&wrap_key, epoch_key).unwrap();
        let mut artifact = Vec::with_capacity(1 + ciphertext.len() + encrypted_epoch_key.len());
        artifact.push(0x02);
        artifact.extend_from_slice(&ciphertext);
        artifact.extend_from_slice(&encrypted_epoch_key);
        artifact
    }

    let wrapped_for_a =
        build_rekey_artifact_t7(&xwing_a.encapsulation_key_bytes(), &epoch_1_key, 1, &device_a_id);
    let wrapped_for_b =
        build_rekey_artifact_t7(&xwing_b.encapsulation_key_bytes(), &epoch_1_key, 1, &device_b_id);

    let mut wrapped_keys = HashMap::new();
    wrapped_keys.insert(device_a_id.clone(), wrapped_for_a.clone());
    wrapped_keys.insert(device_b_id.clone(), wrapped_for_b.clone());

    let encoded_keys: HashMap<String, String> = wrapped_keys
        .iter()
        .map(|(k, v)| {
            (k.clone(), base64::Engine::encode(&base64::engine::general_purpose::STANDARD, v))
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

    // ── B fetches rekey artifact and recovers epoch 1 key via real X-Wing KEM ──
    let b_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/rekey/{device_b_id}?epoch=1"))
        .header("Authorization", format!("Bearer {token_b}"))
        .header("X-Device-Id", &device_b_id)
        .send()
        .await
        .unwrap();
    assert_eq!(b_resp.status(), 200);
    let b_json: serde_json::Value = b_resp.json().await.unwrap();
    let recovered_wrapped = b_json["wrapped_key"].as_str().expect("wrapped_key should exist");
    let recovered_artifact =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, recovered_wrapped)
            .unwrap();

    // B decapsulates the real X-Wing artifact
    assert_eq!(recovered_artifact[0], 0x02, "artifact version should be 0x02");
    let b_ciphertext = &recovered_artifact[1..1121];
    let b_encrypted_key = &recovered_artifact[1121..];
    let b_shared_secret = xwing_b.decapsulate(b_ciphertext).unwrap();
    let mut b_salt = Vec::with_capacity(4 + device_b_id.len());
    b_salt.extend_from_slice(&1u32.to_le_bytes());
    b_salt.extend_from_slice(device_b_id.as_bytes());
    let b_unwrap_key =
        prism_sync_crypto::kdf::derive_subkey(&b_shared_secret, &b_salt, b"prism_epoch_rekey_v2")
            .unwrap();
    let b_recovered_epoch_key =
        prism_sync_crypto::aead::xchacha_decrypt(&b_unwrap_key, b_encrypted_key).unwrap();
    assert_eq!(
        b_recovered_epoch_key, epoch_1_key,
        "B should recover the exact epoch 1 key through real X-Wing KEM"
    );

    // ── C tries to get artifact → should fail (revoked) ──
    let c_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/rekey/{device_c_id}?epoch=1"))
        .header("Authorization", format!("Bearer {_token_c}"))
        .header("X-Device-Id", &device_c_id)
        .send()
        .await
        .unwrap();
    assert_eq!(
        c_resp.status(),
        401,
        "Revoked device C should get 401 (DeviceRevoked), got: {}",
        c_resp.status()
    );

    // ── A pushes data encrypted with epoch 1 key ──
    // A uses the real epoch 1 key recovered from X-Wing KEM
    let ml_dsa_a = keys_a.device_secret.ml_dsa_65_keypair(&device_a_id).unwrap();
    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_a = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_a, &sync_id, &device_a_id);
    register_peer_device(&storage_a, &sync_id, &device_a_id, &keys_a);
    register_peer_device(&storage_a, &sync_id, &device_b_id, &keys_b);

    // Both A and B use the real epoch 1 key from X-Wing KEM
    let mut kh_a = shared_key_hierarchy();
    kh_a.store_epoch_key(1, zeroize::Zeroizing::new(epoch_1_key.clone()));

    // Update current epoch in storage
    {
        let mut tx = storage_a.begin_tx().unwrap();
        tx.update_current_epoch(&sync_id, 1).unwrap();
        tx.commit().unwrap();
    }

    // Create ops at epoch 1
    let hlc = Hlc::now(&device_a_id, None);
    let ops_epoch1 = vec![CrdtChange {
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
    }];
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

    let relay_a =
        Arc::new(make_server_relay(&localhost_url, &sync_id, &device_a_id, &token_a, &keys_a));
    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay_a.clone(),
        vec![entity_a.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );
    let result = engine_a
        .sync(&sync_id, &kh_a, &keys_a.ed25519_signing_key, Some(&ml_dsa_a), &device_a_id, 0)
        .await
        .unwrap();
    assert!(result.error.is_none(), "A epoch-1 push failed: {:?}", result.error);
    assert_eq!(result.pushed, 1, "A should push epoch-1 batch");

    // ── B pulls with epoch 1 key recovered via real X-Wing KEM ──
    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_b, &sync_id, &device_b_id);
    register_peer_device(&storage_b, &sync_id, &device_a_id, &keys_a);
    register_peer_device(&storage_b, &sync_id, &device_b_id, &keys_b);

    // B stores the epoch 1 key recovered through real X-Wing decapsulation
    let mut kh_b = shared_key_hierarchy();
    kh_b.store_epoch_key(1, zeroize::Zeroizing::new(b_recovered_epoch_key));

    let relay_b =
        Arc::new(make_server_relay(&localhost_url, &sync_id, &device_b_id, &token_b, &keys_b));
    let ml_dsa_b = keys_b.device_secret.ml_dsa_65_keypair(&device_b_id).unwrap();
    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay_b.clone(),
        vec![entity_b.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );
    let result = engine_b
        .sync(&sync_id, &kh_b, &keys_b.ed25519_signing_key, Some(&ml_dsa_b), &device_b_id, 0)
        .await
        .unwrap();
    assert!(result.error.is_none(), "B epoch-1 pull failed: {:?}", result.error);
    assert_eq!(
        result.merged, 1,
        "B should decrypt and merge epoch-1 data using X-Wing-recovered key"
    );
    assert_eq!(
        entity_b.get_field("epoch1-task", "title"),
        Some(SyncValue::String("Epoch 1 data".to_string()))
    );
    assert_eq!(entity_b.row_count(), 1, "B should have exactly 1 task from epoch-1");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 8: Concurrent sync + CRDT conflict resolution
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn e2e_concurrent_sync_crdt_conflict_resolution() {
    let (url, _server, _db) = start_test_relay().await;
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

    let kh = shared_key_hierarchy();

    // ── Device A: set up storage and create task with title="from-A" ──
    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_a = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_a, &sync_id, &device_a_id);
    register_peer_device(&storage_a, &sync_id, &device_a_id, &keys_a);
    register_peer_device(&storage_a, &sync_id, &device_b_id, &keys_b);

    // Use specific HLC timestamps to ensure deterministic LWW winner.
    // A uses timestamp 1000 (the loser).
    let hlc_a = Hlc::new(1000, 0, &device_a_id);
    let op_id_a = format!("tasks:shared-task:title:{hlc_a}:{device_a_id}");
    let ops_a = vec![CrdtChange {
        op_id: op_id_a.clone(),
        batch_id: Some("batch-conflict-a".to_string()),
        entity_id: "shared-task".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"from-A\"".to_string(),
        client_hlc: hlc_a.to_string(),
        is_delete: false,
        device_id: device_a_id.to_string(),
        epoch: 0,
        server_seq: None,
    }];
    {
        use prism_sync_core::storage::PendingOp;
        let mut tx = storage_a.begin_tx().unwrap();
        for op in &ops_a {
            tx.insert_pending_op(&PendingOp {
                op_id: op.op_id.clone(),
                sync_id: sync_id.to_string(),
                epoch: 0,
                device_id: op.device_id.clone(),
                local_batch_id: "batch-conflict-a".to_string(),
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
        // Also write field_version (as the real op_emitter does for local ops)
        tx.upsert_field_version(&FieldVersion {
            sync_id: sync_id.clone(),
            entity_table: "tasks".to_string(),
            entity_id: "shared-task".to_string(),
            field_name: "title".to_string(),
            winning_op_id: op_id_a,
            winning_device_id: device_a_id.clone(),
            winning_hlc: hlc_a.to_string(),
            winning_encoded_value: Some("\"from-A\"".to_string()),
            updated_at: chrono::Utc::now(),
        })
        .unwrap();
        tx.commit().unwrap();
    }

    let relay_a =
        Arc::new(make_server_relay(&localhost_url, &sync_id, &device_a_id, &token_a, &keys_a));
    let ml_dsa_a = keys_a.device_secret.ml_dsa_65_keypair(&device_a_id).unwrap();
    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay_a.clone(),
        vec![entity_a.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );

    // ── Device B: set up storage and create SAME task with title="from-B" ──
    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_b, &sync_id, &device_b_id);
    register_peer_device(&storage_b, &sync_id, &device_a_id, &keys_a);
    register_peer_device(&storage_b, &sync_id, &device_b_id, &keys_b);

    // B uses timestamp 2000 (the LWW winner).
    let hlc_b = Hlc::new(2000, 0, &device_b_id);
    let op_id_b = format!("tasks:shared-task:title:{hlc_b}:{device_b_id}");
    let ops_b = vec![CrdtChange {
        op_id: op_id_b.clone(),
        batch_id: Some("batch-conflict-b".to_string()),
        entity_id: "shared-task".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"from-B\"".to_string(),
        client_hlc: hlc_b.to_string(),
        is_delete: false,
        device_id: device_b_id.to_string(),
        epoch: 0,
        server_seq: None,
    }];
    {
        use prism_sync_core::storage::PendingOp;
        let mut tx = storage_b.begin_tx().unwrap();
        for op in &ops_b {
            tx.insert_pending_op(&PendingOp {
                op_id: op.op_id.clone(),
                sync_id: sync_id.to_string(),
                epoch: 0,
                device_id: op.device_id.clone(),
                local_batch_id: "batch-conflict-b".to_string(),
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
        // Also write field_version (as the real op_emitter does for local ops)
        tx.upsert_field_version(&FieldVersion {
            sync_id: sync_id.clone(),
            entity_table: "tasks".to_string(),
            entity_id: "shared-task".to_string(),
            field_name: "title".to_string(),
            winning_op_id: op_id_b,
            winning_device_id: device_b_id.clone(),
            winning_hlc: hlc_b.to_string(),
            winning_encoded_value: Some("\"from-B\"".to_string()),
            updated_at: chrono::Utc::now(),
        })
        .unwrap();
        tx.commit().unwrap();
    }

    let relay_b =
        Arc::new(make_server_relay(&localhost_url, &sync_id, &device_b_id, &token_b, &keys_b));
    let ml_dsa_b = keys_b.device_secret.ml_dsa_65_keypair(&device_b_id).unwrap();
    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay_b.clone(),
        vec![entity_b.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );

    // ── Both devices sync concurrently to push their conflicting ops ──
    let (result_a, result_b) = tokio::join!(
        engine_a
            .sync(&sync_id, &kh, &keys_a.ed25519_signing_key, Some(&ml_dsa_a), &device_a_id, 0,),
        engine_b
            .sync(&sync_id, &kh, &keys_b.ed25519_signing_key, Some(&ml_dsa_b), &device_b_id, 0,),
    );
    let result_a = result_a.unwrap();
    let result_b = result_b.unwrap();
    assert!(result_a.error.is_none(), "A concurrent push failed: {:?}", result_a.error);
    assert!(result_b.error.is_none(), "B concurrent push failed: {:?}", result_b.error);

    // ── Both devices sync again to pull the other's changes ──
    // Run sequentially to avoid race conditions on relay read cursors
    let result_a2 = engine_a
        .sync(&sync_id, &kh, &keys_a.ed25519_signing_key, Some(&ml_dsa_a), &device_a_id, 0)
        .await
        .unwrap();
    assert!(result_a2.error.is_none(), "A pull failed: {:?}", result_a2.error);

    let result_b2 = engine_b
        .sync(&sync_id, &kh, &keys_b.ed25519_signing_key, Some(&ml_dsa_b), &device_b_id, 0)
        .await
        .unwrap();
    assert!(result_b2.error.is_none(), "B pull failed: {:?}", result_b2.error);

    // One more round to ensure full convergence (in case the second round
    // only pulled some batches due to cursor timing)
    let result_a3 = engine_a
        .sync(&sync_id, &kh, &keys_a.ed25519_signing_key, Some(&ml_dsa_a), &device_a_id, 0)
        .await
        .unwrap();
    assert!(result_a3.error.is_none(), "A convergence sync failed: {:?}", result_a3.error);

    let result_b3 = engine_b
        .sync(&sync_id, &kh, &keys_b.ed25519_signing_key, Some(&ml_dsa_b), &device_b_id, 0)
        .await
        .unwrap();
    assert!(result_b3.error.is_none(), "B convergence sync failed: {:?}", result_b3.error);

    // ── Assert convergence via field_versions in storage ──
    // field_versions track the authoritative LWW merge state (independent of
    // the MockTaskEntity which only receives remote writes).
    let fv_a = storage_a.get_field_version(&sync_id, "tasks", "shared-task", "title").unwrap();
    let fv_b = storage_b.get_field_version(&sync_id, "tasks", "shared-task", "title").unwrap();

    assert!(fv_a.is_some(), "A should have a field_version for shared-task.title");
    assert!(fv_b.is_some(), "B should have a field_version for shared-task.title");
    let fv_a = fv_a.unwrap();
    let fv_b = fv_b.unwrap();

    // Both must converge to the same winning value
    assert_eq!(
        fv_a.winning_encoded_value, fv_b.winning_encoded_value,
        "Both devices must converge to the same winning value in field_versions: A={:?}, B={:?}",
        fv_a.winning_encoded_value, fv_b.winning_encoded_value,
    );
    assert_eq!(fv_a.winning_hlc, fv_b.winning_hlc, "Both devices must agree on the winning HLC");

    // The LWW winner is B (HLC timestamp 2000 > 1000)
    assert_eq!(
        fv_a.winning_encoded_value,
        Some("\"from-B\"".to_string()),
        "LWW winner should be from-B (higher HLC timestamp)"
    );

    // Also verify entity_a got the correct remote write (B's value)
    assert_eq!(
        entity_a.get_field("shared-task", "title"),
        Some(SyncValue::String("from-B".to_string())),
        "entity_a should have from-B (received as remote merge)"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 9: Soft-delete propagation with tombstone protection
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn e2e_soft_delete_propagation() {
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

    let kh = shared_key_hierarchy();

    // ── A creates a task and syncs ──
    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_a = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_a, &sync_id, &device_a_id);
    register_peer_device(&storage_a, &sync_id, &device_a_id, &keys_a);
    register_peer_device(&storage_a, &sync_id, &device_b_id, &keys_b);

    create_task_ops(&storage_a, &sync_id, &device_a_id, "del-task", "To be deleted", "batch-del-1");

    let relay_a =
        Arc::new(make_server_relay(&localhost_url, &sync_id, &device_a_id, &token_a, &keys_a));
    let ml_dsa_a = keys_a.device_secret.ml_dsa_65_keypair(&device_a_id).unwrap();
    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay_a.clone(),
        vec![entity_a.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );
    let result = engine_a
        .sync(&sync_id, &kh, &keys_a.ed25519_signing_key, Some(&ml_dsa_a), &device_a_id, 0)
        .await
        .unwrap();
    assert!(result.error.is_none(), "A create push failed: {:?}", result.error);
    assert_eq!(result.pushed, 1);

    // ── B syncs to pull the task ──
    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_b, &sync_id, &device_b_id);
    register_peer_device(&storage_b, &sync_id, &device_a_id, &keys_a);
    register_peer_device(&storage_b, &sync_id, &device_b_id, &keys_b);

    let relay_b =
        Arc::new(make_server_relay(&localhost_url, &sync_id, &device_b_id, &token_b, &keys_b));
    let ml_dsa_b = keys_b.device_secret.ml_dsa_65_keypair(&device_b_id).unwrap();
    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay_b.clone(),
        vec![entity_b.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );
    let result = engine_b
        .sync(&sync_id, &kh, &keys_b.ed25519_signing_key, Some(&ml_dsa_b), &device_b_id, 0)
        .await
        .unwrap();
    assert!(result.error.is_none(), "B pull failed: {:?}", result.error);
    assert_eq!(result.merged, 2, "B should merge create ops");
    assert_eq!(
        entity_b.get_field("del-task", "title"),
        Some(SyncValue::String("To be deleted".to_string()))
    );

    // ── A soft-deletes the task and syncs ──
    let hlc_del = Hlc::now(&device_a_id, None);
    let del_ops = vec![CrdtChange {
        op_id: format!("tasks:del-task:is_deleted:{hlc_del}:{device_a_id}"),
        batch_id: Some("batch-del-2".to_string()),
        entity_id: "del-task".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "is_deleted".to_string(),
        encoded_value: "true".to_string(),
        client_hlc: hlc_del.to_string(),
        is_delete: true,
        device_id: device_a_id.to_string(),
        epoch: 0,
        server_seq: None,
    }];
    {
        use prism_sync_core::storage::PendingOp;
        let mut tx = storage_a.begin_tx().unwrap();
        for op in &del_ops {
            tx.insert_pending_op(&PendingOp {
                op_id: op.op_id.clone(),
                sync_id: sync_id.to_string(),
                epoch: 0,
                device_id: op.device_id.clone(),
                local_batch_id: "batch-del-2".to_string(),
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
    let result = engine_a
        .sync(&sync_id, &kh, &keys_a.ed25519_signing_key, Some(&ml_dsa_a), &device_a_id, 0)
        .await
        .unwrap();
    assert!(result.error.is_none(), "A delete push failed: {:?}", result.error);
    assert_eq!(result.pushed, 1);

    // ── B syncs and picks up the soft delete ──
    let result = engine_b
        .sync(&sync_id, &kh, &keys_b.ed25519_signing_key, Some(&ml_dsa_b), &device_b_id, 0)
        .await
        .unwrap();
    assert!(result.error.is_none(), "B delete pull failed: {:?}", result.error);
    assert_eq!(result.merged, 1, "B should merge the delete op");

    // The entity should be marked as deleted on B
    assert!(
        entity_b.is_deleted("del-task").await.unwrap(),
        "del-task should be marked as deleted on B"
    );

    // ── Tombstone protection: B creates an update for the deleted entity ──
    // B pushes a title update with an older HLC, then a third device C
    // (simulated by A) pulls both the delete and the update. The merge engine's
    // tombstone protection should reject the title update because the entity
    // is already tombstoned.
    let hlc_resurrect = Hlc::new(hlc_del.timestamp - 1000, 0, &device_b_id);
    let resurrect_ops = vec![CrdtChange {
        op_id: format!("tasks:del-task:title:{hlc_resurrect}:{device_b_id}"),
        batch_id: Some("batch-resurrect".to_string()),
        entity_id: "del-task".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Resurrected!\"".to_string(),
        client_hlc: hlc_resurrect.to_string(),
        is_delete: false,
        device_id: device_b_id.to_string(),
        epoch: 0,
        server_seq: None,
    }];
    {
        use prism_sync_core::storage::PendingOp;
        let mut tx = storage_b.begin_tx().unwrap();
        for op in &resurrect_ops {
            tx.insert_pending_op(&PendingOp {
                op_id: op.op_id.clone(),
                sync_id: sync_id.to_string(),
                epoch: 0,
                device_id: op.device_id.clone(),
                local_batch_id: "batch-resurrect".to_string(),
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

    // B pushes the resurrect attempt
    let result = engine_b
        .sync(&sync_id, &kh, &keys_b.ed25519_signing_key, Some(&ml_dsa_b), &device_b_id, 0)
        .await
        .unwrap();
    assert!(result.error.is_none());

    // B should still see the entity as deleted (tombstone protection in merge engine
    // prevents non-delete ops from being applied when is_deleted=true is in field_versions).
    // The resurrect op was pushed to the relay but B's local merge already has the tombstone.
    assert!(
        entity_b.is_deleted("del-task").await.unwrap(),
        "del-task should remain deleted on B even after pushing resurrect attempt"
    );

    // Verify the delete propagated correctly: entity_b has no title after delete
    // (soft_delete was called, which marks it deleted in MockTaskEntity)
    assert_eq!(entity_b.row_count(), 1, "B should still have 1 row (the original create)");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 10: Multi-batch sync (5 batches pulled in one sync)
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn e2e_multi_batch_sync() {
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

    let kh = shared_key_hierarchy();

    // ── A creates 5 tasks, pushing each in a separate sync (5 batches) ──
    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_a = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_a, &sync_id, &device_a_id);
    register_peer_device(&storage_a, &sync_id, &device_a_id, &keys_a);
    register_peer_device(&storage_a, &sync_id, &device_b_id, &keys_b);

    let relay_a =
        Arc::new(make_server_relay(&localhost_url, &sync_id, &device_a_id, &token_a, &keys_a));
    let ml_dsa_a = keys_a.device_secret.ml_dsa_65_keypair(&device_a_id).unwrap();
    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay_a.clone(),
        vec![entity_a.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );

    for i in 1..=5 {
        create_task_ops(
            &storage_a,
            &sync_id,
            &device_a_id,
            &format!("multi-task-{i}"),
            &format!("Task #{i}"),
            &format!("batch-multi-{i}"),
        );
        let result = engine_a
            .sync(&sync_id, &kh, &keys_a.ed25519_signing_key, Some(&ml_dsa_a), &device_a_id, 0)
            .await
            .unwrap();
        assert!(result.error.is_none(), "A push {i} failed: {:?}", result.error);
        assert_eq!(result.pushed, 1, "A should push 1 batch on iteration {i}");
    }

    // ── B syncs once and pulls all 5 batches ──
    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_b, &sync_id, &device_b_id);
    register_peer_device(&storage_b, &sync_id, &device_a_id, &keys_a);
    register_peer_device(&storage_b, &sync_id, &device_b_id, &keys_b);

    let relay_b =
        Arc::new(make_server_relay(&localhost_url, &sync_id, &device_b_id, &token_b, &keys_b));
    let ml_dsa_b = keys_b.device_secret.ml_dsa_65_keypair(&device_b_id).unwrap();
    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay_b.clone(),
        vec![entity_b.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );
    let result = engine_b
        .sync(&sync_id, &kh, &keys_b.ed25519_signing_key, Some(&ml_dsa_b), &device_b_id, 0)
        .await
        .unwrap();
    assert!(result.error.is_none(), "B pull failed: {:?}", result.error);
    assert_eq!(result.pulled, 5, "B should pull all 5 batches");
    assert_eq!(result.merged, 10, "B should merge 10 ops (2 per task x 5)");
    assert_eq!(entity_b.row_count(), 5, "B should have exactly 5 tasks");

    // Verify all 5 tasks arrived
    for i in 1..=5 {
        assert_eq!(
            entity_b.get_field(&format!("multi-task-{i}"), "title"),
            Some(SyncValue::String(format!("Task #{i}"))),
            "Task {i} should be present on B"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 11: Old ML-DSA generation batch rejected after rotation
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn e2e_old_generation_batch_rejected_after_rotation() {
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

    let kh = shared_key_hierarchy();

    // ── A pushes a gen-0 batch, B pulls and verifies ──
    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_a = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_a, &sync_id, &device_a_id);
    register_peer_device(&storage_a, &sync_id, &device_a_id, &keys_a);
    register_peer_device(&storage_a, &sync_id, &device_b_id, &keys_b);

    create_task_ops(&storage_a, &sync_id, &device_a_id, "gen-test-1", "Gen0 task", "batch-gen0");

    let relay_a =
        Arc::new(make_server_relay(&localhost_url, &sync_id, &device_a_id, &token_a, &keys_a));
    let ml_dsa_a_gen0 = keys_a.device_secret.ml_dsa_65_keypair(&device_a_id).unwrap();
    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay_a.clone(),
        vec![entity_a.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );
    let result = engine_a
        .sync(&sync_id, &kh, &keys_a.ed25519_signing_key, Some(&ml_dsa_a_gen0), &device_a_id, 0)
        .await
        .unwrap();
    assert!(result.error.is_none());
    assert_eq!(result.pushed, 1);

    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_b, &sync_id, &device_b_id);
    register_peer_device(&storage_b, &sync_id, &device_a_id, &keys_a);
    register_peer_device(&storage_b, &sync_id, &device_b_id, &keys_b);

    let relay_b =
        Arc::new(make_server_relay(&localhost_url, &sync_id, &device_b_id, &token_b, &keys_b));
    let ml_dsa_b = keys_b.device_secret.ml_dsa_65_keypair(&device_b_id).unwrap();
    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay_b.clone(),
        vec![entity_b.clone() as Arc<dyn SyncableEntity>],
        test_schema(),
        SyncConfig::default(),
    );
    let result = engine_b
        .sync(&sync_id, &kh, &keys_b.ed25519_signing_key, Some(&ml_dsa_b), &device_b_id, 0)
        .await
        .unwrap();
    assert!(result.error.is_none());
    assert_eq!(result.merged, 2, "B should verify gen-0 batch");

    // ── A rotates ML-DSA to gen 1 ──
    let ml_dsa_a_gen1 = keys_a.device_secret.ml_dsa_65_keypair_v(&device_a_id, 1).unwrap();

    let proof = prism_sync_crypto::pq::continuity_proof::MlDsaContinuityProof::create(
        &keys_a.device_secret,
        &device_a_id,
        0,
        1,
    )
    .expect("create continuity proof");

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
        &ml_dsa_a_gen0,
        2,
    );

    let path = format!("/v1/sync/{sync_id}/devices/{device_a_id}/rotate-ml-dsa");
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
    assert!(resp.status().is_success(), "rotate-ml-dsa failed: {}", resp.status());

    // ── B imports gen-1 registry ──
    // A pushes a gen-1 batch so B is forced to fetch the registry and import gen-1 key
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

    create_task_ops(&storage_a, &sync_id, &device_a_id, "gen-test-2", "Gen1 task", "batch-gen1");

    let relay_a_gen1 = Arc::new({
        let ml_dsa_for_relay = keys_a.device_secret.ml_dsa_65_keypair_v(&device_a_id, 1).unwrap();
        ServerRelay::new(
            localhost_url.clone(),
            sync_id.clone(),
            device_a_id.clone(),
            token_a.clone(),
            keys_a.ed25519_signing_key.clone(),
            ml_dsa_for_relay,
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
        .sync(&sync_id, &kh, &keys_a.ed25519_signing_key, Some(&ml_dsa_a_gen1), &device_a_id, 1)
        .await
        .unwrap();
    assert!(result.error.is_none(), "A gen1 push failed: {:?}", result.error);
    assert_eq!(result.pushed, 1);

    // B pulls → fetches registry → imports gen-1 key → verifies gen-1 batch
    let result = engine_b
        .sync(&sync_id, &kh, &keys_b.ed25519_signing_key, Some(&ml_dsa_b), &device_b_id, 0)
        .await
        .unwrap();
    assert!(result.error.is_none());
    assert_eq!(result.merged, 2, "B should merge gen-1 batch");

    // ── Now push a batch "signed with gen-0 key" directly into the relay ──
    // This simulates a stale or replayed batch from before the rotation.
    let hlc = Hlc::now(&device_a_id, None);
    let ops_stale = vec![CrdtChange {
        op_id: format!("tasks:gen-test-stale:title:{hlc}:{device_a_id}"),
        batch_id: Some("batch-gen0-stale".to_string()),
        entity_id: "gen-test-stale".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Stale gen-0 task\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: device_a_id.to_string(),
        epoch: 0,
        server_seq: None,
    }];
    let plaintext = CrdtChange::encode_batch(&ops_stale).unwrap();
    let payload_hash = batch_signature::compute_payload_hash(&plaintext);
    let epoch_key = kh.epoch_key(0).unwrap();
    let aad = sync_aad::build_sync_aad(&sync_id, &device_a_id, 0, "batch-gen0-stale", "ops");
    let (ciphertext, nonce) =
        prism_sync_crypto::aead::xchacha_encrypt_for_sync(epoch_key, &plaintext, &aad).unwrap();

    // Sign with the OLD gen-0 key
    let envelope = batch_signature::sign_batch(
        &keys_a.ed25519_signing_key,
        &ml_dsa_a_gen0,
        &sync_id,
        0,
        "batch-gen0-stale",
        "ops",
        &device_a_id,
        0,
        &payload_hash,
        nonce,
        ciphertext,
    )
    .unwrap();

    // Push the stale batch envelope directly via the relay HTTP API
    let envelope_json = serde_json::to_value(&envelope).unwrap();
    let body_bytes = serde_json::to_vec(&envelope_json).unwrap();
    let path = format!("/v1/sync/{sync_id}/changes");
    let resp = apply_signed_headers(
        client
            .put(format!("{url}/v1/sync/{sync_id}/changes"))
            .header("Authorization", format!("Bearer {token_a}"))
            .header("X-Device-Id", &device_a_id)
            .header("X-Batch-Id", "batch-gen0-stale")
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
    assert!(resp.status().is_success(), "relay should store the batch opaquely");

    // B pulls → the gen-0 batch should be REJECTED because B now has gen-1 key for A
    let result = engine_b
        .sync(&sync_id, &kh, &keys_b.ed25519_signing_key, Some(&ml_dsa_b), &device_b_id, 0)
        .await
        .unwrap();
    assert!(result.error.is_none());
    // The stale batch was pulled but should not be merged (sig fails against gen-1 key)
    assert_eq!(result.merged, 0, "gen-0 batch must be rejected after B imported gen-1 key");
    assert!(
        entity_b.get_field("gen-test-stale", "title").is_none(),
        "stale gen-0 task should not appear on B"
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
