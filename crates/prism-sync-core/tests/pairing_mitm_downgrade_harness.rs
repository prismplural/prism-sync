//! Launch-blocker adversarial coverage for relay-based public-sync pairing.
//!
//! These tests intentionally drive the same core path that the FFI ceremony
//! functions call: `PairingService::start_bootstrap_pairing` for the joiner,
//! `PairingService::start_bootstrap_initiator` for the inviter, and the real
//! `JoinerCeremony` SAS/confirmation processing over the in-memory pairing
//! relay used by the core tests.

mod common;

use std::sync::Arc;

use prism_sync_core::bootstrap::RendezvousToken;
use prism_sync_core::pairing::service::PairingService;
use prism_sync_core::relay::{MockPairingRelay, PairingRelay, PairingSlot};
use prism_sync_core::secure_store::SecureStore;
use prism_sync_crypto::DeviceSecret;

use common::MemorySecureStore;

const RELAY_URL: &str = "https://relay.example.com";

fn service_with_existing_device() -> PairingService {
    let store = Arc::new(MemorySecureStore::new());
    let device_secret = DeviceSecret::generate();
    let device_id = prism_sync_core::generate_node_id();

    store.set("device_secret", device_secret.as_bytes()).unwrap();
    store.set("device_id", device_id.as_bytes()).unwrap();

    PairingService::new(store)
}

fn empty_joiner_service() -> PairingService {
    PairingService::new(Arc::new(MemorySecureStore::new()))
}

#[tokio::test]
async fn swapped_rendezvous_commitment_cannot_bind_to_different_joiner_record() {
    let relay = MockPairingRelay::new();

    let (_first_joiner, first_token) = empty_joiner_service()
        .start_bootstrap_pairing(&relay, RELAY_URL)
        .await
        .expect("first joiner should publish bootstrap");
    let (_second_joiner, second_token) = empty_joiner_service()
        .start_bootstrap_pairing(&relay, RELAY_URL)
        .await
        .expect("second joiner should publish bootstrap");

    let swapped_token = RendezvousToken {
        version: first_token.version,
        rendezvous_id: second_token.rendezvous_id,
        commitment: first_token.commitment,
        relay_url_hint: first_token.relay_url_hint.clone(),
    };

    let result =
        service_with_existing_device().start_bootstrap_initiator(swapped_token, &relay).await;

    let err = match result {
        Ok(_) => panic!("swapped commitment token must not start an initiator ceremony"),
        Err(err) => err,
    };
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("commitment mismatch"),
        "expected commitment mismatch, got: {err_msg}"
    );
    assert!(
        relay
            .get_slot(&second_token.rendezvous_id_hex(), PairingSlot::Init)
            .await
            .expect("slot read should succeed")
            .is_none(),
        "initiator must abort before posting PairingInit for the substituted record"
    );
}

#[tokio::test]
async fn pairing_init_from_another_slot_cannot_drive_joiner_sas() {
    let relay = MockPairingRelay::new();

    let (mut intended_joiner, intended_token) = empty_joiner_service()
        .start_bootstrap_pairing(&relay, RELAY_URL)
        .await
        .expect("intended joiner should publish bootstrap");
    let (mut victim_joiner, _victim_token) = empty_joiner_service()
        .start_bootstrap_pairing(&relay, RELAY_URL)
        .await
        .expect("victim joiner should publish bootstrap");

    let (initiator, initiator_sas) = service_with_existing_device()
        .start_bootstrap_initiator(intended_token, &relay)
        .await
        .expect("valid initiator ceremony should start");

    let replayed_init = relay
        .get_slot(&intended_joiner.rendezvous_id_hex(), PairingSlot::Init)
        .await
        .expect("slot read should succeed")
        .expect("initiator should have posted PairingInit");

    let err = victim_joiner
        .process_pairing_init(&replayed_init)
        .expect_err("cross-session PairingInit must be rejected");
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("confirmation MAC verification failed"),
        "expected confirmation failure for substituted slot payload, got: {err_msg}"
    );
    assert!(
        victim_joiner.confirmation_mac().is_err(),
        "rejected substitution must not arm the victim joiner's confirmation state"
    );

    let intended_sas = intended_joiner
        .process_pairing_init(&replayed_init)
        .expect("same-slot PairingInit should still be valid for its intended joiner");
    assert_eq!(intended_sas.words, initiator_sas.words);
    assert_eq!(intended_sas.decimal, initiator_sas.decimal);

    let intended_mac = intended_joiner.confirmation_mac().expect("valid joiner confirmation");
    initiator
        .verify_joiner_confirmation(&intended_mac)
        .expect("intended joiner confirmation should verify");
}

#[tokio::test]
async fn pairing_init_slot_replay_is_rejected_by_pairing_relay() {
    let relay = MockPairingRelay::new();
    let (joiner, token) = empty_joiner_service()
        .start_bootstrap_pairing(&relay, RELAY_URL)
        .await
        .expect("joiner should publish bootstrap");

    let (_initiator, _sas) = service_with_existing_device()
        .start_bootstrap_initiator(token, &relay)
        .await
        .expect("initiator should post PairingInit");

    let rendezvous_id = joiner.rendezvous_id_hex();
    let init = relay
        .get_slot(&rendezvous_id, PairingSlot::Init)
        .await
        .expect("slot read should succeed")
        .expect("initiator should have posted PairingInit");

    let err = relay
        .put_slot(&rendezvous_id, PairingSlot::Init, &init)
        .await
        .expect_err("replay write to PairingInit slot must be rejected");
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("slot already written"),
        "expected relay single-write rejection, got: {err_msg}"
    );
}
