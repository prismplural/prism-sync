//! Pairing failure-case tests (C11).
//!
//! Tests that the pairing flow handles errors correctly:
//! - Tampered invitation rejected
//! - Wrong password rejected
//! - Rollback marker cleanup

mod common;

use std::sync::Arc;

use prism_sync_core::pairing::models::PairingResponse;
use prism_sync_core::pairing::service::{cleanup_failed_setup, PairingService};
use prism_sync_core::relay::MockRelay;
use prism_sync_core::secure_store::SecureStore;
use prism_sync_crypto::DeviceSecret;

use common::MemorySecureStore;

// ── Helpers ──

async fn create_invite(password: &str) -> (PairingResponse, Arc<MemorySecureStore>) {
    let relay = Arc::new(MockRelay::new());
    let store = Arc::new(MemorySecureStore::new());
    let service = PairingService::new(relay, store.clone());

    let (_creds, invite) = service
        .create_sync_group(password, "wss://relay.example.com", None, None)
        .await
        .expect("create_sync_group should succeed");

    (invite.response().clone(), store)
}

// ══════════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════════

/// Modifying a field in PairingResponse after signing must cause join to
/// reject the invitation with a signature error.
#[tokio::test]
async fn join_with_tampered_invitation_fails() {
    let (mut response, _) = create_invite("test-password").await;

    // Tamper: change the sync_id after the invitation was signed
    response.sync_id = "tampered-sync-id-value".into();

    let join_relay = Arc::new(MockRelay::new());
    let join_store = Arc::new(MemorySecureStore::new());
    let join_service = PairingService::new(join_relay, join_store);

    let result = join_service
        .join_sync_group(&response, "test-password")
        .await;

    let msg = match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("join with tampered invitation should fail"),
    };
    assert!(
        msg.contains("signature invalid"),
        "expected signature error, got: {msg}"
    );
}

/// Modifying the wrapped_dek (payload field) after signing must also be
/// detected by signature verification.
#[tokio::test]
async fn join_with_tampered_wrapped_dek_fails() {
    let (mut response, _) = create_invite("test-password").await;

    // Tamper: flip a byte in the wrapped DEK
    if let Some(byte) = response.wrapped_dek.first_mut() {
        *byte ^= 0xFF;
    }

    let join_relay = Arc::new(MockRelay::new());
    let join_store = Arc::new(MemorySecureStore::new());
    let join_service = PairingService::new(join_relay, join_store);

    let result = join_service
        .join_sync_group(&response, "test-password")
        .await;

    let msg = match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("join with tampered wrapped_dek should fail"),
    };
    assert!(
        msg.contains("signature invalid"),
        "expected signature error, got: {msg}"
    );
}

/// Replacing the inviter's public key with a different device's key must
/// cause signature verification to fail.
#[tokio::test]
async fn join_with_wrong_inviter_key_fails() {
    let (mut response, _) = create_invite("test-password").await;

    // Replace the inviter's public key with a different key
    let fake_secret = DeviceSecret::generate();
    let fake_key = fake_secret.ed25519_keypair("fake").unwrap();
    response.inviter_ed25519_pk = fake_key.public_key_bytes().to_vec();

    let join_relay = Arc::new(MockRelay::new());
    let join_store = Arc::new(MemorySecureStore::new());
    let join_service = PairingService::new(join_relay, join_store);

    let result = join_service
        .join_sync_group(&response, "test-password")
        .await;

    let msg = match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("join with wrong inviter key should fail"),
    };
    assert!(
        msg.contains("signature invalid"),
        "expected signature error, got: {msg}"
    );
}

/// Joining with a different password than was used to create the group must
/// fail (Argon2id will derive a different MEK, unwrapping the DEK fails).
#[tokio::test]
async fn join_with_wrong_password_fails() {
    let (response, _) = create_invite("correct-password").await;

    let join_relay = Arc::new(MockRelay::new());
    let join_store = Arc::new(MemorySecureStore::new());
    let join_service = PairingService::new(join_relay, join_store);

    let result = join_service
        .join_sync_group(&response, "wrong-password")
        .await;

    assert!(
        result.is_err(),
        "join with wrong password should return Err"
    );
}

/// When `setup_rollback_marker` is present in the secure store (simulating a
/// crash mid-setup), `cleanup_failed_setup` must remove all partial state.
#[tokio::test]
async fn cleanup_failed_setup_removes_partial_state() {
    let store = Arc::new(MemorySecureStore::new());
    let relay = Arc::new(MockRelay::new());

    // Simulate a partially-completed setup that crashed
    store.set("setup_rollback_marker", b"in_progress").unwrap();
    store.set("sync_id", b"some-sync-id").unwrap();
    store.set("mnemonic", b"word1 word2 ...").unwrap();
    store.set("device_id", b"dev-123").unwrap();
    store.set("device_secret", &[0u8; 32]).unwrap();

    // Verify marker is present
    assert!(store.get("setup_rollback_marker").unwrap().is_some());

    // Run cleanup
    let cleaned = cleanup_failed_setup(store.as_ref(), relay.as_ref())
        .await
        .expect("cleanup should succeed");

    assert!(cleaned, "cleanup should report it performed cleanup");

    // All setup keys should be gone
    assert!(store.get("setup_rollback_marker").unwrap().is_none());
    assert!(store.get("sync_id").unwrap().is_none());
    assert!(store.get("mnemonic").unwrap().is_none());
    assert!(store.get("device_id").unwrap().is_none());
    assert!(store.get("device_secret").unwrap().is_none());
}

/// When no rollback marker is present, `cleanup_failed_setup` is a no-op.
#[tokio::test]
async fn cleanup_no_marker_is_noop() {
    let store = Arc::new(MemorySecureStore::new());
    let relay = Arc::new(MockRelay::new());

    // Store some unrelated data
    store.set("unrelated_key", b"keep me").unwrap();

    let cleaned = cleanup_failed_setup(store.as_ref(), relay.as_ref())
        .await
        .expect("cleanup should succeed");

    assert!(!cleaned, "cleanup should report no cleanup needed");
    // Unrelated data should still be there
    assert!(store.get("unrelated_key").unwrap().is_some());
}

/// After a successful join, the rollback marker must not be present.
#[tokio::test]
async fn successful_join_has_no_rollback_marker() {
    let (response, _) = create_invite("my-password").await;

    let join_relay = Arc::new(MockRelay::new());
    let join_store = Arc::new(MemorySecureStore::new());
    let join_service = PairingService::new(join_relay, join_store.clone());

    let kh = join_service
        .join_sync_group(&response, "my-password")
        .await
        .expect("join should succeed");

    assert!(kh.is_unlocked());

    // Rollback marker must be gone
    assert!(
        join_store.get("setup_rollback_marker").unwrap().is_none(),
        "rollback marker should be removed after successful join"
    );

    // But credentials should be persisted
    assert!(join_store.get("sync_id").unwrap().is_some());
    assert!(join_store.get("device_id").unwrap().is_some());
    assert!(join_store.get("device_secret").unwrap().is_some());
    assert!(join_store.get("relay_url").unwrap().is_some());
}
