//! Consumer API and pairing integration tests.
//!
//! These tests exercise the `PrismSync` builder validation and the
//! `PairingService` create/join flow using in-memory storage and a minimal
//! in-memory `SecureStore`.

mod common;

use std::sync::Arc;

use prism_sync_core::pairing::service::PairingService;
use prism_sync_core::relay::MockRelay;
use prism_sync_core::schema::{SyncSchema, SyncType};
use prism_sync_core::secure_store::SecureStore;
use prism_sync_core::storage::RusqliteSyncStorage;
use prism_sync_core::PrismSync;

use common::MemorySecureStore;

// ══════════════════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════════════════

fn minimal_schema() -> SyncSchema {
    SyncSchema::builder()
        .entity("items", |e| e.field("name", SyncType::String))
        .build()
}

fn in_memory_storage() -> Arc<RusqliteSyncStorage> {
    Arc::new(RusqliteSyncStorage::in_memory().expect("in-memory SQLite should succeed"))
}

fn memory_secure_store() -> Arc<MemorySecureStore> {
    Arc::new(MemorySecureStore::new())
}

// ══════════════════════════════════════════════════════════════════════════
// Builder validation tests
// ══════════════════════════════════════════════════════════════════════════

/// `PrismSync::builder().build()` without a schema must return an error.
#[test]
fn test_builder_requires_schema() {
    let storage = in_memory_storage();
    let store = memory_secure_store();

    let result = PrismSync::builder()
        .storage(storage)
        .secure_store(store)
        .build();

    assert!(result.is_err(), "build() without schema should return Err");
    let msg = result.err().unwrap().to_string();
    assert!(
        msg.contains("schema"),
        "error message should mention 'schema', got: {msg}"
    );
}

/// `PrismSync::builder().schema(...).build()` without storage must return an error.
#[test]
fn test_builder_requires_storage() {
    let store = memory_secure_store();

    let result = PrismSync::builder()
        .schema(minimal_schema())
        .secure_store(store)
        .build();

    assert!(result.is_err(), "build() without storage should return Err");
    let msg = result.err().unwrap().to_string();
    assert!(
        msg.contains("storage"),
        "error message should mention 'storage', got: {msg}"
    );
}

/// Builder with an `http://` relay URL (without `allow_insecure_transport`) must
/// return an error.
#[test]
fn test_builder_rejects_http_url() {
    let storage = in_memory_storage();
    let store = memory_secure_store();

    let result = PrismSync::builder()
        .schema(minimal_schema())
        .storage(storage)
        .secure_store(store)
        .relay_url("http://localhost:8080")
        .build();

    assert!(
        result.is_err(),
        "build() with http:// URL should return Err"
    );
    let msg = result.err().unwrap().to_string();
    assert!(
        msg.contains("HTTPS") || msg.contains("insecure") || msg.contains("https"),
        "error should mention HTTPS requirement, got: {msg}"
    );
}

/// Builder with an `https://` relay URL must succeed.
#[test]
fn test_builder_allows_https() {
    let storage = in_memory_storage();
    let store = memory_secure_store();

    let result = PrismSync::builder()
        .schema(minimal_schema())
        .storage(storage)
        .secure_store(store)
        .relay_url("https://relay.example.com")
        .build();

    assert!(result.is_ok(), "build() with https:// URL should succeed");
}

/// Builder with an `http://` URL and `allow_insecure_transport()` must succeed.
#[test]
fn test_builder_allows_insecure() {
    let storage = in_memory_storage();
    let store = memory_secure_store();

    let result = PrismSync::builder()
        .schema(minimal_schema())
        .storage(storage)
        .secure_store(store)
        .relay_url("http://localhost:8080")
        .allow_insecure_transport()
        .build();

    assert!(
        result.is_ok(),
        "build() with http:// + allow_insecure_transport() should succeed"
    );
}

// ══════════════════════════════════════════════════════════════════════════
// Key lifecycle tests
// ══════════════════════════════════════════════════════════════════════════

/// Initialize, lock, unlock, and verify `is_unlocked` transitions correctly.
#[test]
fn test_initialize_and_unlock() {
    let storage = in_memory_storage();
    let store = memory_secure_store();

    let mut sync = PrismSync::builder()
        .schema(minimal_schema())
        .storage(storage)
        .secure_store(store)
        .build()
        .expect("build should succeed");

    // Before initialization the hierarchy is locked.
    assert!(!sync.is_unlocked(), "should start locked");

    // Generate a secret key and initialize.
    let secret_key_mnemonic =
        PrismSync::generate_secret_key().expect("generate_secret_key should succeed");
    let secret_key_bytes = prism_sync_crypto::mnemonic::to_bytes(&secret_key_mnemonic)
        .expect("mnemonic to bytes should succeed");

    sync.initialize("test-password-1", &secret_key_bytes)
        .expect("initialize should succeed");

    assert!(sync.is_unlocked(), "should be unlocked after initialize");

    // Lock clears key material.
    sync.lock();
    assert!(!sync.is_unlocked(), "should be locked after lock()");

    // Unlock with same credentials should restore access.
    sync.unlock("test-password-1", &secret_key_bytes)
        .expect("unlock should succeed");
    assert!(sync.is_unlocked(), "should be unlocked after unlock");

    // The database key should be derivable when unlocked.
    let db_key = sync.database_key().expect("database_key should succeed");
    assert!(!db_key.is_empty(), "database key should not be empty");
}

// ══════════════════════════════════════════════════════════════════════════
// Pairing integration tests
// ══════════════════════════════════════════════════════════════════════════

/// `PairingService::create_sync_group` followed by `join_sync_group` with the
/// same password must produce an unlocked `KeyHierarchy` with the same DEK.
#[tokio::test]
async fn test_pairing_create_and_join() {
    // Device A creates the sync group.
    let relay_a = Arc::new(MockRelay::new());
    let store_a = memory_secure_store();
    let service_a = PairingService::new(relay_a, store_a.clone());

    let (credentials, invite) = service_a
        .create_sync_group(
            "shared-password",
            "wss://relay.example.com",
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("create_sync_group should succeed");

    // Basic credential sanity checks.
    assert!(!credentials.sync_id.is_empty(), "sync_id must not be empty");
    assert_eq!(
        credentials.sync_id.len(),
        64,
        "sync_id should be 32 bytes hex (64 chars)"
    );
    assert!(
        !credentials.mnemonic.is_empty(),
        "mnemonic must not be empty"
    );
    assert!(
        !credentials.wrapped_dek.is_empty(),
        "wrapped_dek must not be empty"
    );
    assert!(!credentials.salt.is_empty(), "salt must not be empty");

    // Invite must reference the same sync_id.
    assert_eq!(
        invite.response().sync_id,
        credentials.sync_id,
        "invite sync_id must match credentials sync_id"
    );
    assert_eq!(
        invite.response().relay_url,
        "wss://relay.example.com",
        "invite relay_url must match"
    );
    assert_eq!(
        invite.response().admission_context(),
        "first_device",
        "initial invite should be a first-device snapshot"
    );

    // Device A credentials must be persisted to the secure store.
    let stored_sync_id = store_a
        .get("sync_id")
        .expect("get sync_id should not fail")
        .expect("sync_id should be stored");
    assert_eq!(
        String::from_utf8(stored_sync_id).unwrap(),
        credentials.sync_id,
        "stored sync_id must match"
    );

    // Device B joins using the invite's PairingResponse and the same password.
    let relay_b = Arc::new(MockRelay::new());
    let store_b = memory_secure_store();
    let service_b = PairingService::new(relay_b, store_b.clone());

    let (key_hierarchy_b, snapshot) = service_b
        .join_sync_group(invite.response(), "shared-password")
        .await
        .expect("join_sync_group with correct password should succeed");

    // The joined key hierarchy must be unlocked and usable.
    assert!(
        key_hierarchy_b.is_unlocked(),
        "joined key hierarchy should be unlocked"
    );
    let db_key_b = key_hierarchy_b
        .database_key()
        .expect("database_key should succeed on joined device");
    assert!(
        !db_key_b.is_empty(),
        "database key on Device B must not be empty"
    );

    let imported_snapshot = snapshot.to_device_records();
    let registry = RusqliteSyncStorage::in_memory().expect("in-memory registry storage");
    prism_sync_core::device_registry::DeviceRegistryManager::import_keyring(
        &registry,
        &credentials.sync_id,
        &imported_snapshot,
    )
    .expect("joined snapshot should import cleanly");
    prism_sync_core::device_registry::DeviceRegistryManager::verify_device_key(
        &registry,
        &credentials.sync_id,
        &imported_snapshot[0].device_id,
        &imported_snapshot[0].ed25519_public_key,
    )
    .expect("imported registry entry should verify");

    // Device B credentials must be persisted too.
    let stored_b_sync_id = store_b
        .get("sync_id")
        .expect("get sync_id from store_b should not fail")
        .expect("sync_id should be stored on Device B");
    assert_eq!(
        String::from_utf8(stored_b_sync_id).unwrap(),
        credentials.sync_id,
        "Device B stored sync_id must match Device A's sync_id"
    );

    // Wrong password must be rejected.
    let relay_c = Arc::new(MockRelay::new());
    let store_c = memory_secure_store();
    let service_c = PairingService::new(relay_c, store_c);

    let bad_join = service_c
        .join_sync_group(invite.response(), "wrong-password")
        .await;
    assert!(
        bad_join.is_err(),
        "join_sync_group with wrong password should return Err"
    );
}
