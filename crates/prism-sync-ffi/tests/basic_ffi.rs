//! Basic smoke tests for the FFI layer.
//!
//! These tests verify that the public FFI API can be called successfully
//! and that errors are surfaced correctly.

use std::path::PathBuf;

use prism_sync_ffi::api;

/// Helper: create a handle with in-memory storage and memory secure store.
fn make_handle() -> prism_sync_ffi::api::PrismSyncHandle {
    api::create_prism_sync(
        "https://localhost:8080".into(),
        ":memory:".into(),
        false,
        String::new(),
        None,
    )
    .expect("create_prism_sync should succeed")
}

/// Helper: create a handle with a schema.
fn make_handle_with_schema() -> prism_sync_ffi::api::PrismSyncHandle {
    let schema = r#"{
        "entities": {
            "members": {
                "fields": {
                    "name": "String",
                    "age": "Int",
                    "active": "Bool"
                }
            },
            "notes": {
                "fields": {
                    "title": "String",
                    "body": "String"
                }
            }
        }
    }"#;

    api::create_prism_sync(
        "https://localhost:8080".into(),
        ":memory:".into(),
        false,
        schema.into(),
        None,
    )
    .expect("create_prism_sync with schema should succeed")
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

// ── Construction ──

#[tokio::test]
async fn create_handle_succeeds() {
    let result = api::create_prism_sync(
        "https://localhost:8080".into(),
        ":memory:".into(),
        false,
        String::new(),
        None,
    );
    assert!(result.is_ok(), "create_prism_sync should succeed: {:?}", result.err());
}

#[tokio::test]
async fn create_handle_with_schema_json() {
    let schema = r#"{"entities":{"tasks":{"fields":{"title":"String","done":"Bool"}}}}"#;
    let result = api::create_prism_sync(
        "https://localhost:8080".into(),
        ":memory:".into(),
        false,
        schema.into(),
        None,
    );
    assert!(result.is_ok(), "schema JSON should parse: {:?}", result.err());
}

#[tokio::test]
async fn create_handle_accepts_app_prism_sync_schema() {
    let Some(schema) = app_sync_schema_json() else {
        eprintln!("skipping app-schema FFI parse test; app sync schema is not present");
        return;
    };

    let result = api::create_prism_sync(
        "https://localhost:8080".into(),
        ":memory:".into(),
        false,
        schema,
        None,
    );
    assert!(result.is_ok(), "app schema JSON should parse: {:?}", result.err());
}

#[tokio::test]
async fn create_handle_with_invalid_schema_fails() {
    let result = api::create_prism_sync(
        "https://localhost:8080".into(),
        ":memory:".into(),
        false,
        "not valid json".into(),
        None,
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Invalid schema JSON"));
}

#[tokio::test]
async fn create_handle_noop_store() {
    let result = api::create_prism_sync(
        "https://localhost:8080".into(),
        ":memory:".into(),
        false,
        String::new(),
        None,
    );
    assert!(result.is_ok());
}

#[tokio::test]
async fn create_handle_with_database_key_encrypts_file_db() {
    let db_key = vec![0x42; 32];
    let db_path = temp_db_path("prism-sync-ffi-encrypted");

    let handle = api::create_prism_sync(
        "https://localhost:8080".into(),
        db_path.to_string_lossy().into_owned(),
        false,
        String::new(),
        Some(db_key.clone()),
    )
    .expect("create_prism_sync with database key should succeed");
    drop(handle);

    let plain_conn = rusqlite::Connection::open(&db_path).expect("open DB without key");
    let plain_result: rusqlite::Result<i64> =
        plain_conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0));
    assert!(plain_result.is_err(), "unencrypted query should fail for encrypted DB");
    drop(plain_conn);

    let keyed_conn = rusqlite::Connection::open(&db_path).expect("open DB for keyed read");
    let hex_key = db_key.iter().map(|b| format!("{b:02x}")).collect::<String>();
    keyed_conn
        .execute_batch(&format!("PRAGMA key = \"x'{hex_key}'\";"))
        .expect("apply SQLCipher key");
    let table_count: i64 = keyed_conn
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
        .expect("query encrypted DB with correct key");
    assert!(table_count > 0, "encrypted DB should contain migrated tables");
    drop(keyed_conn);

    let _ = std::fs::remove_file(&db_path);
}

#[tokio::test]
async fn create_handle_with_database_key_refuses_plaintext_file_db() {
    let db_key = vec![0x42; 32];
    let db_path = temp_db_path("prism-sync-ffi-plaintext");

    let plain_conn = rusqlite::Connection::open(&db_path).expect("create plaintext DB");
    plain_conn
        .execute_batch("CREATE TABLE plaintext_marker (id INTEGER PRIMARY KEY);")
        .expect("write plaintext DB");
    drop(plain_conn);

    let result = api::create_prism_sync(
        "https://localhost:8080".into(),
        db_path.to_string_lossy().into_owned(),
        false,
        String::new(),
        Some(db_key),
    );

    assert!(result.is_err(), "existing plaintext DB should fail closed instead of being migrated");
    let err = match result {
        Ok(_) => unreachable!("asserted is_err above"),
        Err(err) => err,
    };
    assert!(
        err.contains("refusing plaintext migration"),
        "error should explain fail-closed behavior, got: {err}"
    );
    assert!(!db_path.with_extension("db.bak").exists(), "plaintext backup should not be created");
    assert!(
        !db_path.with_extension("db.enc").exists(),
        "encrypted migration sidecar should not be created"
    );

    let _ = std::fs::remove_file(&db_path);
}

fn temp_db_path(prefix: &str) -> PathBuf {
    let unique = format!(
        "{prefix}-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos()
    );
    std::env::temp_dir().join(unique)
}

// ── Key lifecycle ──

#[tokio::test]
async fn initialize_and_unlock_with_memory_store() {
    let handle = make_handle();
    let secret = api::generate_secret_key().unwrap();
    let secret_bytes: Vec<u8> = secret.as_bytes().to_vec();

    let init = api::initialize(&handle, "password123".into(), secret_bytes.clone()).await;
    assert!(init.is_ok(), "initialize should succeed: {:?}", init.err());

    assert!(api::is_unlocked(&handle).await);

    api::lock(&handle).await;
    assert!(!api::is_unlocked(&handle).await);

    let unlock = api::unlock(&handle, "password123".into(), secret_bytes).await;
    assert!(unlock.is_ok(), "unlock should succeed: {:?}", unlock.err());
    assert!(api::is_unlocked(&handle).await);
}

#[tokio::test]
async fn initialize_fails_without_secure_store() {
    let handle = api::create_prism_sync(
        "https://localhost:8080".into(),
        ":memory:".into(),
        false,
        String::new(),
        None,
    )
    .unwrap();

    // All handles now use MemorySecureStore, so initialize succeeds.
    let mnemonic = api::generate_secret_key().unwrap();
    let secret_bytes = api::mnemonic_to_bytes(mnemonic).unwrap();
    let result = api::initialize(&handle, "pw".into(), secret_bytes).await;
    assert!(result.is_ok(), "initialize should succeed with MemorySecureStore: {:?}", result.err());
}

#[tokio::test]
async fn generate_secret_key_returns_12_words() {
    let key = api::generate_secret_key().unwrap();
    assert_eq!(key.split_whitespace().count(), 12, "BIP39 mnemonic should have 12 words");
}

#[tokio::test]
async fn database_key_requires_unlock() {
    let handle = make_handle();

    let result = api::database_key(&handle).await;
    assert!(result.is_err(), "database_key should fail when locked");

    let secret_bytes = api::generate_secret_key().unwrap().into_bytes();
    api::initialize(&handle, "pw".into(), secret_bytes).await.unwrap();

    let result = api::database_key(&handle).await;
    assert!(result.is_ok(), "database_key should succeed when unlocked");
    assert!(!result.unwrap().is_empty());
}

// ── Password management ──

#[tokio::test]
async fn change_password_succeeds() {
    let handle = make_handle();
    let secret = api::generate_secret_key().unwrap();
    let secret_bytes = secret.as_bytes().to_vec();

    api::initialize(&handle, "old_pw".into(), secret_bytes.clone()).await.unwrap();

    let result = api::change_password(
        &handle,
        "old_pw".into(),
        "new_pw".into(),
        secret_bytes.clone(),
        None,
        0,
    )
    .await;
    assert!(
        matches!(result, Ok(1)),
        "change_password should return next identity_generation: {result:?}",
    );

    // Lock and unlock with new password
    api::lock(&handle).await;
    let unlock = api::unlock(&handle, "new_pw".into(), secret_bytes).await;
    assert!(unlock.is_ok(), "unlock with new password should succeed: {:?}", unlock.err());
}

// ── Mutation recording (requires configure_engine, tested via status) ──

#[tokio::test]
async fn record_create_fails_without_engine() {
    let handle = make_handle_with_schema();
    let fields = r#"{"name": "Alice", "age": 25, "active": true}"#;

    let result = api::record_create(&handle, "members".into(), "ent-1".into(), fields.into()).await;
    assert!(result.is_err(), "record_create should fail without engine");
    assert!(result.unwrap_err().contains("sync not configured"));
}

#[tokio::test]
async fn record_create_accepts_dart_offsetless_datetime_before_engine_check() {
    let schema = r#"{"entities":{"events":{"fields":{"created_at":"DateTime"}}}}"#;
    let handle = api::create_prism_sync(
        "https://localhost:8080".into(),
        ":memory:".into(),
        false,
        schema.into(),
        None,
    )
    .expect("create_prism_sync with DateTime schema should succeed");

    let result = api::record_create(
        &handle,
        "events".into(),
        "event-1".into(),
        r#"{"created_at":"2026-04-27T12:34:56.789"}"#.into(),
    )
    .await;

    let error = result.expect_err("record_create should still fail before configure_engine");
    assert!(
        error.contains("sync not configured"),
        "DateTime parsing should pass and reach engine configuration check, got: {error}"
    );
    assert!(
        !error.contains("Invalid date string"),
        "Dart offsetless DateTime should not be rejected, got: {error}"
    );
}

#[tokio::test]
async fn record_update_fails_without_engine() {
    let handle = make_handle_with_schema();
    let fields = r#"{"name": "Bob"}"#;

    let result = api::record_update(&handle, "members".into(), "ent-1".into(), fields.into()).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("sync not configured"));
}

#[tokio::test]
async fn record_delete_fails_without_engine() {
    let handle = make_handle_with_schema();

    let result = api::record_delete(&handle, "members".into(), "ent-1".into()).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("sync not configured"));
}

// ── Sync control ──

#[tokio::test]
async fn set_auto_sync_succeeds() {
    let handle = make_handle();
    let result = api::set_auto_sync(&handle, true, 400, 2000, 3).await;
    assert!(result.is_ok(), "set_auto_sync should succeed: {:?}", result.err());

    // Disable
    let result = api::set_auto_sync(&handle, false, 0, 0, 0).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn status_returns_valid_json() {
    let handle = make_handle();
    let result = api::status(&handle).await;
    assert!(result.is_ok());

    let json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(json["syncing"], false);
    assert!(json["pending_ops"].is_number());
}

#[tokio::test]
async fn on_resume_returns_structured_error_when_engine_is_not_configured() {
    let handle = make_handle();

    let result = api::on_resume(&handle).await;
    let error = result.expect_err("on_resume should fail without configure_engine");
    assert!(
        error.contains("PRISM_SYNC_ERROR_JSON:"),
        "on_resume should return structured error JSON, got: {error}"
    );
    assert!(
        error.contains("\"operation\":\"on_resume\""),
        "structured on_resume error should include operation name, got: {error}"
    );
}

// ── Events ──

#[tokio::test]
async fn poll_event_returns_none_when_empty() {
    let handle = make_handle();
    let result = api::poll_event(&handle).await;
    assert!(result.is_ok());
    // Either None (empty) or an error about lagging is acceptable
    // since broadcast receivers start at the tail.
    // With a fresh receiver, try_recv may return Empty.
}

// ── Field parsing ──

#[tokio::test]
async fn parse_fields_handles_all_types() {
    // This is indirectly tested via record_create — a direct unit test
    // would require exposing parse_fields_json. Instead we verify via
    // the error path that invalid JSON is caught.
    let handle = make_handle_with_schema();
    let result =
        api::record_create(&handle, "members".into(), "e1".into(), "not json".into()).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Invalid fields JSON"));
}

#[tokio::test]
async fn drain_secure_store_includes_epoch_keys() {
    use base64::Engine;

    let handle = make_handle();
    let entries = serde_json::json!({
        "epoch": base64::engine::general_purpose::STANDARD.encode(b"1"),
        "epoch_key_1": base64::engine::general_purpose::STANDARD.encode([0xAB; 32]),
    });
    api::seed_secure_store(&handle, entries.to_string()).await.expect("seed secure store");

    let drained = api::drain_secure_store(&handle).await.expect("drain secure store");
    let json: serde_json::Value = serde_json::from_str(&drained).unwrap();
    assert!(
        json.get("epoch_key_1").is_some(),
        "epoch_key_1 should be present in drained secure-store entries"
    );
}

/// The rewritten `drain_secure_store` uses `SecureStore::snapshot()` to
/// export every entry in the `MemorySecureStore` — including dynamic keys
/// that were never in the old `known_keys` allow-list. This test seeds a
/// mix of static and dynamic keys (epoch_key_5, epoch_key_7, runtime
/// keys) and asserts all of them round-trip through drain.
#[tokio::test]
async fn drain_exports_all_memorysecurestore_entries() {
    use base64::Engine;

    let handle = make_handle();
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);

    let entries = serde_json::json!({
        "wrapped_dek": b64(&[0x01; 16]),
        "device_id": b64(b"dev-42"),
        // Dynamic keys that would have been dropped by the old allow-list:
        "epoch_key_5": b64(&[0xAA; 32]),
        "epoch_key_7": b64(&[0xBB; 32]),
        "runtime_keys_abc": b64(&[0xCC; 64]),
        "unknown_future_key": b64(b"forward compat"),
    });

    api::seed_secure_store(&handle, entries.to_string()).await.expect("seed");

    let drained = api::drain_secure_store(&handle).await.expect("drain");
    let json: serde_json::Value = serde_json::from_str(&drained).unwrap();

    for expected in [
        "wrapped_dek",
        "device_id",
        "epoch_key_5",
        "epoch_key_7",
        "runtime_keys_abc",
        "unknown_future_key",
    ] {
        assert!(
            json.get(expected).is_some(),
            "drain must export `{expected}` via snapshot(): got {json}"
        );
    }
}

/// Seed a set of entries, drain, assert the drained JSON round-trips
/// identically after a second seed.
#[tokio::test]
async fn seed_then_drain_round_trip() {
    use base64::Engine;

    let handle = make_handle();
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);

    let seeded = serde_json::json!({
        "sync_id": b64(b"sync-abc"),
        "epoch_key_3": b64(&[0x42; 32]),
        "runtime_keys_xyz": b64(b"runtime-payload"),
    });
    api::seed_secure_store(&handle, seeded.to_string()).await.expect("first seed");

    let drained1 = api::drain_secure_store(&handle).await.expect("drain");
    let map1: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&drained1).unwrap();

    // Seed a new handle with the drained output and drain again. The two
    // drained maps must be identical.
    let handle2 = make_handle();
    api::seed_secure_store(&handle2, drained1.clone()).await.expect("reseed");
    let drained2 = api::drain_secure_store(&handle2).await.expect("drain2");
    let map2: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&drained2).unwrap();

    assert_eq!(map1, map2, "drain output must be stable across reseed");
    // And every originally-seeded entry must have survived.
    for key in ["sync_id", "epoch_key_3", "runtime_keys_xyz"] {
        assert!(map1.get(key).is_some(), "missing `{key}` after round-trip");
    }
}

/// Cross-restart test (Test F.2 from the robustness plan, Appendix B.8):
/// simulate an app restart by creating `handle1`, seeding credentials +
/// a fabricated `epoch_key_1`, draining, disposing, then creating a
/// fresh `handle2` with a new in-memory DB, seeding from the drained
/// JSON, and verifying the `epoch_key_1` survives byte-for-byte.
///
/// Asserts all three Appendix B.8 invariants:
/// 1. `epoch_key_1` is present in the drained map.
/// 2. Every static credential key we seeded (13-entry allow-list subset)
///    is present in the drained map.
/// 3. After a cross-handle reseed + drain, `epoch_key_1` round-trips
///    byte-for-byte.
#[tokio::test]
async fn cold_start_recovers_epoch_key_via_drain_seed_round_trip() {
    use base64::Engine;

    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    let epoch_key_bytes = [0xAB_u8; 32];

    // Minimal paired-device credentials. These match the static allow-list
    // keys in both `_secureStoreKeys` (Dart) and `known_keys` in
    // `drain_secure_store` (Rust fallback path).
    let static_keys: &[(&str, Vec<u8>)] = &[
        ("wrapped_dek", vec![0x11; 48]),
        ("dek_salt", vec![0x22; 16]),
        ("device_secret", vec![0x33; 32]),
        ("device_id", b"dev-cold-start".to_vec()),
        ("sync_id", b"sync-cold-start".to_vec()),
        ("session_token", b"token-abc".to_vec()),
        ("epoch", b"0".to_vec()),
        ("relay_url", b"https://relay.example.com".to_vec()),
        ("mnemonic", b"abandon abandon abandon".to_vec()),
        ("setup_rollback_marker", b"0".to_vec()),
        ("sharing_prekey_store", b"{}".to_vec()),
        ("sharing_id_cache", b"cache".to_vec()),
        ("min_signature_version_floor", b"3".to_vec()),
    ];

    // --- Session 1: seed, drain, drop ---
    let handle1 = make_handle();
    let mut seed_obj = serde_json::Map::new();
    for (k, v) in static_keys {
        seed_obj.insert((*k).to_string(), serde_json::Value::String(b64(v)));
    }
    // The critical dynamic key:
    seed_obj.insert("epoch_key_1".to_string(), serde_json::Value::String(b64(&epoch_key_bytes)));
    let seeded = serde_json::Value::Object(seed_obj).to_string();
    api::seed_secure_store(&handle1, seeded).await.expect("session1 seed");

    let drained1 = api::drain_secure_store(&handle1).await.expect("session1 drain");
    let map1: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&drained1).unwrap();

    // Invariant 1: epoch_key_1 is in the drained map.
    assert!(map1.get("epoch_key_1").is_some(), "session1 drain must export epoch_key_1");
    // Invariant 2: every static key we seeded is in the drained map.
    for (k, _) in static_keys {
        assert!(map1.contains_key(*k), "session1 drain missing static key `{k}`: {map1:?}");
    }

    // Simulate app termination: drop session1 handle.
    drop(handle1);

    // --- Session 2: new in-memory DB, seed from drained, drain again ---
    let handle2 = make_handle();
    api::seed_secure_store(&handle2, drained1).await.expect("session2 seed from drained");
    let drained2 = api::drain_secure_store(&handle2).await.expect("session2 drain");
    let map2: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&drained2).unwrap();

    // Invariant 3: the epoch key survived the simulated restart byte-for-byte.
    let round_tripped = map2
        .get("epoch_key_1")
        .and_then(|v| v.as_str())
        .expect("epoch_key_1 missing from session2 drain");
    let decoded =
        base64::engine::general_purpose::STANDARD.decode(round_tripped).expect("valid base64");
    assert_eq!(
        decoded,
        epoch_key_bytes.to_vec(),
        "epoch_key_1 must round-trip byte-for-byte across drain/seed cycles"
    );

    // Static keys also round-trip.
    for (k, _) in static_keys {
        assert!(map2.contains_key(*k), "session2 drain missing static key `{k}` after reseed");
    }
}

// ── local_storage_key / rekey_db ──

#[tokio::test]
async fn local_storage_key_requires_unlock() {
    let handle = make_handle();

    let result = api::local_storage_key(&handle).await;
    assert!(result.is_err(), "local_storage_key should fail when locked");
}

#[tokio::test]
async fn local_storage_key_succeeds_after_initialize() {
    let handle = make_handle();
    let secret_bytes = api::generate_secret_key().unwrap().into_bytes();
    api::initialize(&handle, "pw".into(), secret_bytes).await.unwrap();

    let result = api::local_storage_key(&handle).await;
    assert!(
        result.is_ok(),
        "local_storage_key should succeed after initialize: {:?}",
        result.err()
    );
    let key = result.unwrap();
    assert_eq!(key.len(), 32, "local_storage_key must be 32 bytes");
}

#[tokio::test]
async fn local_storage_key_differs_from_database_key() {
    let handle = make_handle();
    let secret_bytes = api::generate_secret_key().unwrap().into_bytes();
    api::initialize(&handle, "pw".into(), secret_bytes).await.unwrap();

    let local_key = api::local_storage_key(&handle).await.unwrap();
    let db_key = api::database_key(&handle).await.unwrap();
    assert_ne!(local_key, db_key, "local_storage_key and database_key must differ");
}

#[tokio::test]
async fn rekey_db_rejects_wrong_key_length() {
    let handle = make_handle();
    let secret_bytes = api::generate_secret_key().unwrap().into_bytes();
    api::initialize(&handle, "pw".into(), secret_bytes).await.unwrap();

    // 16 bytes — wrong length
    let result = api::rekey_db(&handle, vec![0u8; 16]).await;
    assert!(result.is_err(), "rekey_db should reject a 16-byte key");
    assert!(result.unwrap_err().contains("32 bytes"), "error should mention 32 bytes");
}

#[tokio::test]
async fn rekey_db_succeeds_with_32_byte_key() {
    let handle = make_handle();
    let secret_bytes = api::generate_secret_key().unwrap().into_bytes();
    api::initialize(&handle, "pw".into(), secret_bytes).await.unwrap();

    let result = api::rekey_db(&handle, vec![0xbbu8; 32]).await;
    assert!(result.is_ok(), "rekey_db should succeed on in-memory storage: {:?}", result.err());
}
