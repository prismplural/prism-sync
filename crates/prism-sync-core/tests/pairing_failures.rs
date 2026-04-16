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
use prism_sync_core::relay::{MockRelay, SyncRelay};
use prism_sync_core::secure_store::SecureStore;
use prism_sync_crypto::DeviceSecret;
use prism_sync_crypto::pq::HybridSignature;

use common::MemorySecureStore;

// ══════════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════════

// Note: Tests for tampered invitations, wrong password, and wrong inviter key
// that previously used the removed `join_sync_group` method are now covered by
// unit tests in `pairing/service.rs` (tampered_invitation_rejected,
// wrong_inviter_key_rejected) and by the bootstrap ceremony round-trip tests.

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

// Tests for join_imports_verified_registry_snapshot, join_rejects_tampered_registry_snapshot,
// and successful_join_has_no_rollback_marker were removed along with the `join_sync_group`
// method. The ceremony-based flow (`complete_bootstrap_join`) is tested in the service module's
// bootstrap_pairing_round_trip_and_rekey test.

// ══════════════════════════════════════════════════════════════════════════
// Pairing happy-path roundtrip tests (Agent A security plan)
// ══════════════════════════════════════════════════════════════════════════

/// Manually construct an approve flow (as approve_pairing_request does in
/// the FFI layer) and verify the resulting PairingResponse has valid signatures.
#[tokio::test]
async fn approve_flow_produces_verifiable_pairing_response() {
    // Device A: create sync group
    let store_a = Arc::new(MemorySecureStore::new());
    let service_a = PairingService::new(store_a.clone());

    let password = "test-password";
    let (creds, _invite) = service_a
        .create_sync_group(
            password,
            "wss://relay.example.com",
            None,
            None,
            None,
            None,
            None,
            |_sync_id, _device_id, _token| {
                Ok(Arc::new(MockRelay::new()) as Arc<dyn SyncRelay>)
            },
        )
        .await
        .expect("create_sync_group should succeed");

    // Read credentials back from store (as the FFI approve function does).
    // The recovery phrase is not persisted — take it from the returned
    // credentials bundle, where it's surfaced once for the caller to display.
    let sync_id = String::from_utf8(store_a.get("sync_id").unwrap().unwrap()).unwrap();
    let relay_url = String::from_utf8(store_a.get("relay_url").unwrap().unwrap()).unwrap();
    let mnemonic = creds.mnemonic.clone();
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
    }], 0);
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

    // Note: The legacy join_sync_group method was removed. The approve flow's
    // invitation and registry snapshot signatures are verified above. The
    // ceremony-based join flow is tested by bootstrap_pairing_round_trip_and_rekey.
}

/// Full roundtrip: Device A creates group, Device B generates request,
/// Device A approves targeting B's device_id, Device B joins, and the
/// registry snapshot contains both Device A and Device B entries.
#[tokio::test]
async fn join_from_approval_roundtrip() {
    let password = "roundtrip-password";

    // ── Device A: create sync group ──
    let store_a = Arc::new(MemorySecureStore::new());
    let service_a = PairingService::new(store_a.clone());

    let (creds, _invite) = service_a
        .create_sync_group(
            password,
            "wss://relay.test",
            None,
            None,
            None,
            None,
            None,
            |_sync_id, _device_id, _token| {
                Ok(Arc::new(MockRelay::new()) as Arc<dyn SyncRelay>)
            },
        )
        .await
        .expect("create_sync_group");

    let sync_id = String::from_utf8(store_a.get("sync_id").unwrap().unwrap()).unwrap();
    let relay_url = String::from_utf8(store_a.get("relay_url").unwrap().unwrap()).unwrap();
    // Recovery phrase is not persisted; read it from the credentials returned
    // by create_sync_group.
    let mnemonic = creds.mnemonic.clone();
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
    ], 1);
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

    // Verify the signed registry snapshot directly (join_sync_group was removed)
    let verified_snapshot = SignedRegistrySnapshot::verify_and_decode_hybrid(
        &response.signed_keyring,
        &signing_key_a.public_key_bytes(),
        &pq_signing_key_a.public_key_bytes(),
    )
    .expect("registry snapshot should verify");

    // Registry snapshot must contain both the approver and joiner.
    assert_eq!(verified_snapshot.entries.len(), 2);
    assert!(verified_snapshot.entries.iter().any(|e| e.device_id == device_id_a));
    assert!(verified_snapshot.entries.iter().any(|e| e.device_id == device_id_b));
}

/// Creating a sync group with a registration_token propagates it into the
/// PairingResponse so paired devices can use token-gated relays.
#[tokio::test]
async fn create_sync_group_with_registration_token() {
    let store = Arc::new(MemorySecureStore::new());
    let service = PairingService::new(store.clone());

    let (_creds, response) = service
        .create_sync_group(
            "test-password",
            "wss://relay.example.com",
            None,
            None,
            None,
            None,
            Some("test-token".into()),
            |_sync_id, _device_id, _token| {
                Ok(Arc::new(MockRelay::new()) as Arc<dyn SyncRelay>)
            },
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
