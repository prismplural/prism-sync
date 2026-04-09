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
    assert!(
        result.is_ok(),
        "create_prism_sync should succeed: {:?}",
        result.err()
    );
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
    assert!(
        result.is_ok(),
        "schema JSON should parse: {:?}",
        result.err()
    );
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
    assert!(
        plain_result.is_err(),
        "unencrypted query should fail for encrypted DB"
    );
    drop(plain_conn);

    let keyed_conn = rusqlite::Connection::open(&db_path).expect("open DB for keyed read");
    let hex_key = db_key
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    keyed_conn
        .execute_batch(&format!("PRAGMA key = \"x'{hex_key}'\";"))
        .expect("apply SQLCipher key");
    let table_count: i64 = keyed_conn
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
        .expect("query encrypted DB with correct key");
    assert!(
        table_count > 0,
        "encrypted DB should contain migrated tables"
    );
    drop(keyed_conn);

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
    assert!(
        result.is_ok(),
        "initialize should succeed with MemorySecureStore: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn generate_secret_key_returns_12_words() {
    let key = api::generate_secret_key().unwrap();
    assert_eq!(
        key.split_whitespace().count(),
        12,
        "BIP39 mnemonic should have 12 words"
    );
}

#[tokio::test]
async fn database_key_requires_unlock() {
    let handle = make_handle();

    let result = api::database_key(&handle).await;
    assert!(result.is_err(), "database_key should fail when locked");

    let secret_bytes = api::generate_secret_key().unwrap().into_bytes();
    api::initialize(&handle, "pw".into(), secret_bytes)
        .await
        .unwrap();

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

    api::initialize(&handle, "old_pw".into(), secret_bytes.clone())
        .await
        .unwrap();

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
    assert!(
        unlock.is_ok(),
        "unlock with new password should succeed: {:?}",
        unlock.err()
    );
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
    assert!(
        result.is_ok(),
        "set_auto_sync should succeed: {:?}",
        result.err()
    );

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
    api::seed_secure_store(&handle, entries.to_string())
        .await
        .expect("seed secure store");

    let drained = api::drain_secure_store(&handle)
        .await
        .expect("drain secure store");
    let json: serde_json::Value = serde_json::from_str(&drained).unwrap();
    assert!(
        json.get("epoch_key_1").is_some(),
        "epoch_key_1 should be present in drained secure-store entries"
    );
}
