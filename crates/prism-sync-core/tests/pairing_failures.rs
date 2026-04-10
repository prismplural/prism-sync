//! Pairing failure-case tests (C11).
//!
//! Tests that the pairing flow handles errors correctly:
//! - Tampered invitation rejected
//! - Wrong password rejected
//! - Rollback marker cleanup
//!
//! Also covers pairing happy-path roundtrips (Agent A security plan):
//! - Approve flow produces verifiable PairingResponse
//! - Join from approval roundtrip

mod common;

use std::sync::Arc;

use ed25519_dalek::Signer as _;
use prism_sync_core::pairing::models::{
    build_invitation_signing_data_v2, PairingRequest, PairingResponse, RegistrySnapshotEntry,
    SignedRegistrySnapshot,
};
use prism_sync_core::pairing::service::{cleanup_failed_setup, PairingService};
use prism_sync_core::relay::MockRelay;
use prism_sync_core::secure_store::SecureStore;
use prism_sync_crypto::DeviceSecret;
use prism_sync_crypto::pq::HybridSignature;

use common::MemorySecureStore;

// ── Helpers ──

async fn create_invite(password: &str) -> (PairingResponse, Arc<MemorySecureStore>) {
    let relay = Arc::new(MockRelay::new());
    let store = Arc::new(MemorySecureStore::new());
    let service = PairingService::new(relay, store.clone());

    let (_creds, response) = service
        .create_sync_group(
            password,
            "wss://relay.example.com",
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("create_sync_group should succeed");

    (response, store)
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

/// After a successful join, the verified registry snapshot can be imported
/// into the device registry for TOFU key pinning.
#[tokio::test]
async fn join_imports_verified_registry_snapshot() {
    use prism_sync_core::device_registry::DeviceRegistryManager;
    use prism_sync_core::storage::RusqliteSyncStorage;

    let (response, _) = create_invite("my-password").await;

    let join_relay = Arc::new(MockRelay::new());
    let join_store = Arc::new(MemorySecureStore::new());
    let join_service = PairingService::new(join_relay, join_store);

    let (_kh, snapshot) = join_service
        .join_sync_group(&response, "my-password")
        .await
        .expect("join should succeed");

    // Snapshot should contain exactly the inviter device
    assert_eq!(snapshot.entries.len(), 1);
    assert_eq!(snapshot.entries[0].status, "active");
    assert_eq!(snapshot.entries[0].ed25519_public_key.len(), 32);
    assert_eq!(snapshot.entries[0].x25519_public_key.len(), 32);

    // Import into a real storage backend
    let storage = RusqliteSyncStorage::in_memory().expect("in-memory storage");
    let records = snapshot.to_device_records();
    DeviceRegistryManager::import_keyring(&storage, &response.sync_id, &records)
        .expect("import should succeed");

    // Verify the imported device can be found
    DeviceRegistryManager::verify_device_key(
        &storage,
        &response.sync_id,
        &records[0].device_id,
        &records[0].ed25519_public_key,
    )
    .expect("imported device should verify");
}

/// A tampered signed_keyring (registry snapshot) should be rejected during join.
#[tokio::test]
async fn join_rejects_tampered_registry_snapshot() {
    let (mut response, _) = create_invite("test-password").await;

    // Tamper: flip a byte in the registry snapshot JSON (after the 64-byte sig)
    if response.signed_keyring.len() > 65 {
        response.signed_keyring[65] ^= 0xFF;
    }

    let join_relay = Arc::new(MockRelay::new());
    let join_store = Arc::new(MemorySecureStore::new());
    let join_service = PairingService::new(join_relay, join_store);

    let result = join_service
        .join_sync_group(&response, "test-password")
        .await;

    let msg = match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("join with tampered registry snapshot should fail"),
    };
    assert!(
        msg.contains("registry snapshot rejected"),
        "expected registry snapshot error, got: {msg}"
    );
}

/// After a successful join, the rollback marker must not be present.
#[tokio::test]
async fn successful_join_has_no_rollback_marker() {
    let (response, _) = create_invite("my-password").await;

    let join_relay = Arc::new(MockRelay::new());
    let join_store = Arc::new(MemorySecureStore::new());
    let join_service = PairingService::new(join_relay, join_store.clone());

    let (kh, _snapshot) = join_service
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

// ══════════════════════════════════════════════════════════════════════════
// Pairing happy-path roundtrip tests (Agent A security plan)
// ══════════════════════════════════════════════════════════════════════════

/// Manually construct an approve flow (as approve_pairing_request does in
/// the FFI layer) and verify the resulting PairingResponse can be joined.
#[tokio::test]
async fn approve_flow_produces_verifiable_pairing_response() {
    // Device A: create sync group
    let relay_a = Arc::new(MockRelay::new());
    let store_a = Arc::new(MemorySecureStore::new());
    let service_a = PairingService::new(relay_a, store_a.clone());

    let password = "test-password";
    let (_creds, _invite) = service_a
        .create_sync_group(
            password,
            "wss://relay.example.com",
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("create_sync_group should succeed");

    // Read credentials back from store (as the FFI approve function does)
    let sync_id = String::from_utf8(store_a.get("sync_id").unwrap().unwrap()).unwrap();
    let relay_url = String::from_utf8(store_a.get("relay_url").unwrap().unwrap()).unwrap();
    let mnemonic = String::from_utf8(store_a.get("mnemonic").unwrap().unwrap()).unwrap();
    let wrapped_dek = store_a.get("wrapped_dek").unwrap().unwrap();
    let salt = store_a.get("dek_salt").unwrap().unwrap();
    let device_id_a = String::from_utf8(store_a.get("device_id").unwrap().unwrap()).unwrap();
    let device_secret_bytes = store_a.get("device_secret").unwrap().unwrap();

    let device_secret_a =
        DeviceSecret::from_bytes(device_secret_bytes).expect("valid device secret");
    let signing_key_a = device_secret_a
        .ed25519_keypair(&device_id_a)
        .expect("ed25519 keypair");
    let exchange_key_a = device_secret_a
        .x25519_keypair(&device_id_a)
        .expect("x25519 keypair");

    // Device B: generate a PairingRequest
    let device_secret_b = DeviceSecret::generate();
    let device_id_b = "joiner-device-b";
    let signing_key_b = device_secret_b
        .ed25519_keypair(device_id_b)
        .expect("ed25519 keypair");
    let exchange_key_b = device_secret_b
        .x25519_keypair(device_id_b)
        .expect("x25519 keypair");
    let ed_signing_key_a = device_secret_a
        .ed25519_keypair(&device_id_a)
        .expect("ed25519 signing key")
        .into_signing_key();
    let pq_signing_key_a = device_secret_a
        .ml_dsa_65_keypair(&device_id_a)
        .expect("ml-dsa keypair");
    let pq_kem_key_a = device_secret_a
        .ml_kem_768_keypair(&device_id_a)
        .expect("ml-kem keypair");

    let _request = PairingRequest {
        device_id: device_id_b.to_string(),
        ed25519_public_key: signing_key_b.public_key_bytes().to_vec(),
        x25519_public_key: exchange_key_b.public_key_bytes().to_vec(),
    };

    // Device A: approve the request (mirrors FFI approve_pairing_request logic)
    let signing_data = build_invitation_signing_data_v2(
        &sync_id,
        &relay_url,
        &wrapped_dek,
        &salt,
        &device_id_a,
        &signing_key_a.public_key_bytes(),
        &pq_signing_key_a.public_key_bytes(),
        Some(device_id_b),
        0,
        &[],
    );
    let m_prime =
        prism_sync_crypto::pq::build_hybrid_message_representative(b"invitation", &signing_data)
            .expect("hardcoded invitation context should be <= 255 bytes");
    let hybrid_invitation = HybridSignature {
        ed25519_sig: ed_signing_key_a.sign(&m_prime).to_bytes().to_vec(),
        ml_dsa_65_sig: pq_signing_key_a.sign(&m_prime),
    };
    let mut signature = vec![0x03];
    signature.extend_from_slice(&hybrid_invitation.to_bytes());

    let registry_snapshot = SignedRegistrySnapshot::new(vec![RegistrySnapshotEntry {
        sync_id: sync_id.clone(),
        device_id: device_id_a.clone(),
        ed25519_public_key: signing_key_a.public_key_bytes().to_vec(),
        x25519_public_key: exchange_key_a.public_key_bytes().to_vec(),
        ml_dsa_65_public_key: pq_signing_key_a.public_key_bytes(),
        ml_kem_768_public_key: pq_kem_key_a.public_key_bytes(),
        x_wing_public_key: Vec::new(),
        ml_dsa_key_generation: 0,
        status: "active".into(),
    }]);
    let signed_keyring = registry_snapshot.sign_hybrid(&signing_key_a, &pq_signing_key_a);

    let response = PairingResponse {
        relay_url: relay_url.clone(),
        sync_id: sync_id.clone(),
        mnemonic,
        wrapped_dek,
        salt,
        signed_invitation: prism_sync_crypto::hex::encode(&signature),
        signed_keyring,
        inviter_device_id: device_id_a.clone(),
        inviter_ed25519_pk: signing_key_a.public_key_bytes().to_vec(),
        inviter_ml_dsa_65_pk: pq_signing_key_a.public_key_bytes(),
        joiner_device_id: Some(device_id_b.to_string()),
        current_epoch: 0,
        epoch_key: vec![],
        registry_approval_signature: None,
        registration_token: None,
    };
    assert_eq!(
        response.admission_context(),
        "first_device",
        "single-device snapshot should be treated as first-device admission"
    );

    // Verify: invitation signature is valid
    let verify_signing_data = build_invitation_signing_data_v2(
        &response.sync_id,
        &response.relay_url,
        &response.wrapped_dek,
        &response.salt,
        &response.inviter_device_id,
        &signing_key_a.public_key_bytes(),
        &pq_signing_key_a.public_key_bytes(),
        response.joiner_device_id.as_deref(),
        response.current_epoch,
        &response.epoch_key,
    );
    let sig_bytes = prism_sync_crypto::hex::decode(&response.signed_invitation).expect("valid hex");
    assert_eq!(sig_bytes[0], 0x03);
    let hybrid_sig = HybridSignature::from_bytes(&sig_bytes[1..]).expect("valid hybrid signature");
    hybrid_sig
        .verify_v3(
            &verify_signing_data,
            b"invitation",
            &signing_key_a.public_key_bytes(),
            &pq_signing_key_a.public_key_bytes(),
        )
        .expect("invitation signature should verify");

    // Verify: registry snapshot is valid
    let snapshot = SignedRegistrySnapshot::verify_and_decode_hybrid(
        &response.signed_keyring,
        &signing_key_a.public_key_bytes(),
        &pq_signing_key_a.public_key_bytes(),
    )
    .expect("registry snapshot should verify");
    assert_eq!(snapshot.entries.len(), 1);
    assert_eq!(snapshot.entries[0].device_id, device_id_a);

    // Verify: Device B can join using this response
    let join_relay = Arc::new(MockRelay::new());
    let join_store = Arc::new(MemorySecureStore::new());
    let join_service = PairingService::new(join_relay, join_store);

    let (kh, joined_snapshot) = join_service
        .join_sync_group(&response, password)
        .await
        .expect("join should succeed with approved response");

    assert!(kh.is_unlocked(), "key hierarchy should be unlocked");
    assert_eq!(joined_snapshot.entries.len(), 1);
    assert_eq!(joined_snapshot.entries[0].device_id, device_id_a);
}

/// Full roundtrip: Device A creates group, Device B generates request,
/// Device A approves targeting B's device_id, Device B joins, and the
/// registry snapshot contains both Device A and Device B entries.
#[tokio::test]
async fn join_from_approval_roundtrip() {
    let password = "roundtrip-password";

    // ── Device A: create sync group ──
    let relay_a = Arc::new(MockRelay::new());
    let store_a = Arc::new(MemorySecureStore::new());
    let service_a = PairingService::new(relay_a, store_a.clone());

    let (_creds, _invite) = service_a
        .create_sync_group(password, "wss://relay.test", None, None, None, None, None)
        .await
        .expect("create_sync_group");

    let sync_id = String::from_utf8(store_a.get("sync_id").unwrap().unwrap()).unwrap();
    let relay_url = String::from_utf8(store_a.get("relay_url").unwrap().unwrap()).unwrap();
    let mnemonic = String::from_utf8(store_a.get("mnemonic").unwrap().unwrap()).unwrap();
    let wrapped_dek = store_a.get("wrapped_dek").unwrap().unwrap();
    let salt = store_a.get("dek_salt").unwrap().unwrap();
    let device_id_a = String::from_utf8(store_a.get("device_id").unwrap().unwrap()).unwrap();
    let device_secret_a = DeviceSecret::from_bytes(store_a.get("device_secret").unwrap().unwrap())
        .expect("valid device secret");
    let signing_key_a = device_secret_a
        .ed25519_keypair(&device_id_a)
        .expect("keypair");
    let exchange_key_a = device_secret_a
        .x25519_keypair(&device_id_a)
        .expect("keypair");
    let ed_signing_key_a = device_secret_a
        .ed25519_keypair(&device_id_a)
        .expect("keypair")
        .into_signing_key();
    let pq_signing_key_a = device_secret_a
        .ml_dsa_65_keypair(&device_id_a)
        .expect("keypair");
    let pq_kem_key_a = device_secret_a
        .ml_kem_768_keypair(&device_id_a)
        .expect("keypair");

    // ── Device B: generate PairingRequest ──
    let device_secret_b = DeviceSecret::generate();
    let device_id_b = "device-b-roundtrip";
    let signing_key_b = device_secret_b
        .ed25519_keypair(device_id_b)
        .expect("keypair");
    let exchange_key_b = device_secret_b
        .x25519_keypair(device_id_b)
        .expect("keypair");
    let pq_signing_key_b = device_secret_b
        .ml_dsa_65_keypair(device_id_b)
        .expect("keypair");
    let pq_kem_key_b = device_secret_b
        .ml_kem_768_keypair(device_id_b)
        .expect("keypair");

    let request = PairingRequest {
        device_id: device_id_b.to_string(),
        ed25519_public_key: signing_key_b.public_key_bytes().to_vec(),
        x25519_public_key: exchange_key_b.public_key_bytes().to_vec(),
    };

    // Verify request fields carry the expected classical identity lengths.
    assert_eq!(request.ed25519_public_key.len(), 32);
    assert_eq!(request.x25519_public_key.len(), 32);

    // ── Device A: approve the request ──
    let signing_data = build_invitation_signing_data_v2(
        &sync_id,
        &relay_url,
        &wrapped_dek,
        &salt,
        &device_id_a,
        &signing_key_a.public_key_bytes(),
        &pq_signing_key_a.public_key_bytes(),
        Some(device_id_b),
        0,
        &[],
    );
    let m_prime =
        prism_sync_crypto::pq::build_hybrid_message_representative(b"invitation", &signing_data)
            .expect("hardcoded invitation context should be <= 255 bytes");
    let hybrid_invitation = HybridSignature {
        ed25519_sig: ed_signing_key_a.sign(&m_prime).to_bytes().to_vec(),
        ml_dsa_65_sig: pq_signing_key_a.sign(&m_prime),
    };
    let mut signature = vec![0x03];
    signature.extend_from_slice(&hybrid_invitation.to_bytes());

    let registry_snapshot = SignedRegistrySnapshot::new(vec![
        RegistrySnapshotEntry {
            sync_id: sync_id.clone(),
            device_id: device_id_a.clone(),
            ed25519_public_key: signing_key_a.public_key_bytes().to_vec(),
            x25519_public_key: exchange_key_a.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: pq_signing_key_a.public_key_bytes(),
            ml_kem_768_public_key: pq_kem_key_a.public_key_bytes(),
            x_wing_public_key: vec![],
            ml_dsa_key_generation: 0,
            status: "active".into(),
        },
        RegistrySnapshotEntry {
            sync_id: sync_id.clone(),
            device_id: device_id_b.to_string(),
            ed25519_public_key: signing_key_b.public_key_bytes().to_vec(),
            x25519_public_key: exchange_key_b.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: pq_signing_key_b.public_key_bytes(),
            ml_kem_768_public_key: pq_kem_key_b.public_key_bytes(),
            x_wing_public_key: vec![],
            ml_dsa_key_generation: 0,
            status: "active".into(),
        },
    ]);
    let signed_keyring = registry_snapshot.sign_hybrid(&signing_key_a, &pq_signing_key_a);

    let response = PairingResponse {
        relay_url: relay_url.clone(),
        sync_id: sync_id.clone(),
        mnemonic,
        wrapped_dek,
        salt,
        signed_invitation: prism_sync_crypto::hex::encode(&signature),
        signed_keyring,
        inviter_device_id: device_id_a.clone(),
        inviter_ed25519_pk: signing_key_a.public_key_bytes().to_vec(),
        inviter_ml_dsa_65_pk: pq_signing_key_a.public_key_bytes(),
        joiner_device_id: Some(device_id_b.to_string()),
        current_epoch: 0,
        epoch_key: vec![],
        registry_approval_signature: None,
        registration_token: None,
    };
    assert_eq!(
        response.admission_context(),
        "existing_group",
        "full membership snapshot should be treated as existing-group admission"
    );

    // ── Device B: join using the approved response ──
    let join_relay = Arc::new(MockRelay::new());
    let join_store = Arc::new(MemorySecureStore::new());
    let join_service = PairingService::new(join_relay, join_store.clone());

    let (kh, snapshot) = join_service
        .join_sync_group(&response, password)
        .await
        .expect("join should succeed");

    assert!(kh.is_unlocked());

    // Registry snapshot must contain both the approver and joiner.
    assert_eq!(snapshot.entries.len(), 2);
    assert!(snapshot.entries.iter().any(|e| e.device_id == device_id_a));
    assert!(snapshot.entries.iter().any(|e| e.device_id == device_id_b));
    let approver_entry = snapshot
        .entries
        .iter()
        .find(|e| e.device_id == device_id_a)
        .expect("approver entry should be present");
    assert_eq!(approver_entry.status, "active");
    assert_eq!(approver_entry.ed25519_public_key.len(), 32);
    assert_eq!(approver_entry.x25519_public_key.len(), 32);

    // Verify the snapshot can be imported into storage
    let storage =
        prism_sync_core::storage::RusqliteSyncStorage::in_memory().expect("in-memory storage");
    let records = snapshot.to_device_records();
    prism_sync_core::device_registry::DeviceRegistryManager::import_keyring(
        &storage, &sync_id, &records,
    )
    .expect("import should succeed");

    // Verify imported keys match the approved registry snapshot.
    prism_sync_core::device_registry::DeviceRegistryManager::verify_device_key(
        &storage,
        &sync_id,
        &device_id_a,
        &signing_key_a.public_key_bytes(),
    )
    .expect("imported approver should verify");
    prism_sync_core::device_registry::DeviceRegistryManager::verify_device_key(
        &storage,
        &sync_id,
        device_id_b,
        &signing_key_b.public_key_bytes(),
    )
    .expect("imported joiner should verify");

    // Verify Device B's credentials were persisted
    assert!(join_store.get("sync_id").unwrap().is_some());
    assert!(join_store.get("device_id").unwrap().is_some());
    assert!(join_store.get("device_secret").unwrap().is_some());
    assert!(
        join_store.get("setup_rollback_marker").unwrap().is_none(),
        "rollback marker should be cleared after successful join"
    );
}

/// Creating a sync group with a registration_token propagates it into the
/// PairingResponse so paired devices can use token-gated relays.
#[tokio::test]
async fn create_sync_group_with_registration_token() {
    let relay = Arc::new(MockRelay::new());
    let store = Arc::new(MemorySecureStore::new());
    let service = PairingService::new(relay, store.clone());

    let (_creds, response) = service
        .create_sync_group(
            "test-password",
            "wss://relay.example.com",
            None,
            None,
            None,
            None,
            Some("test-token".into()),
        )
        .await
        .expect("create_sync_group with registration_token should succeed");

    // The registration_token must be carried through to the PairingResponse
    assert_eq!(
        response.registration_token,
        Some("test-token".to_string()),
        "PairingResponse should carry the registration_token"
    );

    // Verify the invite JSON also contains the token
    let json_str = serde_json::to_string(&response).expect("serialize PairingResponse");
    let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("parse JSON");
    assert_eq!(
        parsed["registration_token"].as_str(),
        Some("test-token"),
        "serialized PairingResponse JSON should include registration_token"
    );
}
