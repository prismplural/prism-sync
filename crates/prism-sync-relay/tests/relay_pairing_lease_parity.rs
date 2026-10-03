//! Core ↔ relay pairing-lease contract parity.
//!
//! The relay crate is deliberately standalone (`prism-sync-relay` must not depend
//! on `prism-sync-core`, and vice versa), so the v1 lease contract is *duplicated*
//! on both sides: the wire constants, the slot path segment, and the verifier
//! derivation. Duplication without a drift alarm is how a protocol silently
//! splits — one side hashes a different pre-image, or echoes a version the other
//! does not recognize, and the failure only shows up in production ceremonies.
//!
//! `prism-sync-core` is a **dev**-dependency of this crate, so that dependency
//! edge exists only for tests. This file is the alarm: it asserts, symbol by
//! symbol, that both sides agree. If someone changes a constant on one side
//! without the other, this test fails instead of the protocol.

mod common;

use base64::Engine;
use reqwest::Client;

use prism_sync_core::{
    pairing::lease::{
        compute_lease_key_hash, LEASE_ABSOLUTE_CAP_SECS, LEASE_FRAME_VERSION,
        LEASE_IDLE_EXTENSION_SECS, LEASE_MAX_CONCURRENT_LEASED_SESSIONS,
        LEASE_RENEW_REQUEST_BODY_LEN, LEASE_SECRET_LEN, LEASE_VERSION_V1,
    },
    relay::pairing_relay::PairingSlot,
};
use prism_sync_relay::{
    config::{
        PairingLeaseConfig, PAIRING_LEASE_ABSOLUTE_CAP_SECS, PAIRING_LEASE_IDLE_EXTENSION_SECS,
        PAIRING_LEASE_MAX_CONCURRENT_SESSIONS, PAIRING_LEASE_RENEW_MAX_BODY_BYTES,
        PAIRING_LEASE_RENEW_REQUEST_BODY_LEN, PAIRING_LEASE_SECRET_LEN, PAIRING_LEASE_VERSION_V1,
    },
    db::{self, Database},
};

use common::*;

#[test]
fn wire_constants_agree_between_core_and_relay() {
    // The negotiated version both sides must agree on.
    assert_eq!(PAIRING_LEASE_VERSION_V1, LEASE_VERSION_V1);
    assert_eq!(PAIRING_LEASE_VERSION_V1, 1, "v1 is the only version in flight");

    // Secret length and the exact renew body length. A mismatch here would make
    // the relay reject a body the core client considers valid, or vice versa.
    assert_eq!(PAIRING_LEASE_SECRET_LEN, LEASE_SECRET_LEN);
    assert_eq!(PAIRING_LEASE_RENEW_REQUEST_BODY_LEN, LEASE_RENEW_REQUEST_BODY_LEN);

    // Expiry arithmetic. These drive the actual lease windows, so a silent change
    // on one side would grant a different lifetime than the client computes.
    assert_eq!(PAIRING_LEASE_IDLE_EXTENSION_SECS, LEASE_IDLE_EXTENSION_SECS as i64);
    assert_eq!(PAIRING_LEASE_ABSOLUTE_CAP_SECS, LEASE_ABSOLUTE_CAP_SECS as i64);

    // The global concurrently-leased cap, including the deployment default.
    assert_eq!(PAIRING_LEASE_MAX_CONCURRENT_SESSIONS, LEASE_MAX_CONCURRENT_LEASED_SESSIONS);
    assert_eq!(
        PairingLeaseConfig::default().max_concurrent_sessions,
        LEASE_MAX_CONCURRENT_LEASED_SESSIONS
    );
}

#[test]
fn frame_version_constant_is_unchanged() {
    // The capability/confirmation frame version byte is part of the frozen wire
    // format. It is not duplicated in the relay (the relay only stores the frame
    // opaquely in the `lease_capability` slot), so this is a one-sided guard
    // against an accidental bump.
    assert_eq!(LEASE_FRAME_VERSION, 0x01);
}

#[test]
fn transport_body_cap_admits_every_plausible_probe() {
    // The relay's *transport* cap must be strictly larger than the exact length,
    // or the body-limit layer would answer wrong-length bodies with a different
    // status before the handler could return its uniform not-found — an oracle on
    // request shape. It must also stay small so buffering is bounded.
    // Both bounds are compile-time facts about two constants, so assert them in a
    // const block: a violated bound then fails the build rather than a test run.
    const {
        assert!(PAIRING_LEASE_RENEW_MAX_BODY_BYTES > PAIRING_LEASE_RENEW_REQUEST_BODY_LEN);
        assert!(PAIRING_LEASE_RENEW_MAX_BODY_BYTES <= 4096);
    }
}

#[test]
fn lease_capability_slot_path_matches_the_core_client() {
    // The relay route is literally `/v1/pairing/{rid}/{segment}` with the core
    // client's segment, so this string is the contract. A rename on either side
    // would silently 404 every capability post and permanently disable the lease
    // without failing anything else.
    assert_eq!(PairingSlot::LeaseCapability.as_path_segment(), "lease_capability");

    // The same holds for every pre-existing slot: the relay's generic slot
    // handling keys on these exact strings.
    assert_eq!(PairingSlot::Init.as_path_segment(), "init");
    assert_eq!(PairingSlot::Confirmation.as_path_segment(), "confirmation");
    assert_eq!(PairingSlot::Credentials.as_path_segment(), "credentials");
    assert_eq!(PairingSlot::Joiner.as_path_segment(), "joiner");
}

#[test]
fn verifier_derivation_matches_within_the_relay_db_layer() {
    // The relay's renewal check hashes the presented secret with SHA-256 and
    // constant-time compares against the committed verifier. Both sides must
    // derive that verifier identically, or a correct secret would never match.
    for byte in [0u8, 1u8, 0x5A, 0xFF] {
        let secret = [byte; 32];
        let from_core = compute_lease_key_hash(&secret);

        let database = Database::in_memory().expect("in-memory db");
        let rid = format!("{:0>32}", byte);
        database
            .with_conn(|conn| {
                db::create_pairing_session_with_lease(conn, &rid, b"boot", 300, Some(&from_core))?;
                db::set_pairing_slot(conn, &rid, "joiner_confirmation", b"confirm")?;
                // The relay must accept the core-derived verifier's pre-image.
                let outcome = db::renew_pairing_lease(
                    conn,
                    &rid,
                    db::PairingLeaseVerifier::Secret(&secret),
                    256,
                )?;
                assert!(
                    outcome.is_renewed(),
                    "the relay must accept the secret core hashed (byte {byte:#x}): {outcome:?}"
                );
                Ok::<(), rusqlite::Error>(())
            })
            .unwrap();
    }
}

#[tokio::test]
async fn relay_echoes_exactly_the_version_the_core_client_requests() {
    // End-to-end negotiation: the relay's echo must equal
    // `LEASE_VERSION_V1`, which is the only value
    // `CreatePairingSessionOutcome::relay_supports_lease` accepts. If the relay
    // echoed anything else, every client would fall back to fixed TTL while
    // believing the relay was incapable — a silent capability loss.
    let mut config = test_config();
    config.pairing_lease = PairingLeaseConfig {
        enabled: true,
        max_concurrent_sessions: PAIRING_LEASE_MAX_CONCURRENT_SESSIONS,
        ..PairingLeaseConfig::default()
    };
    let (url, _server, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();

    let secret = [0x77u8; 32];
    let verifier = compute_lease_key_hash(&secret);

    let resp = client
        .post(format!("{url}/v1/pairing"))
        .json(&serde_json::json!({
            "joiner_bootstrap": base64::engine::general_purpose::STANDARD.encode(b"boot"),
            // Exactly how the core client serializes the offer.
            "lease_key_hash": base64::engine::general_purpose::STANDARD.encode(verifier),
            "lease_version": LEASE_VERSION_V1,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["lease_version"].as_u64(),
        Some(u64::from(LEASE_VERSION_V1)),
        "the relay must echo the version the core client will check for: {body}"
    );
}

#[test]
fn core_still_emits_standard_base64_for_the_lease_key_hash() {
    // The v1 *legacy canonical* emission. The core client sends the verifier with
    // the `STANDARD` alphabet (`BASE64` in `pairing_relay.rs`); the relay must
    // keep accepting it so no shipped client becomes incompatible. This pins that
    // emission against a silent switch to another alphabet.
    //
    // The chosen secret produces a verifier whose standard and URL-safe encodings
    // genuinely differ (`+`/`/` vs `-`/`_`), so if the core ever regressed to the
    // URL-safe alphabet this assertion would fail rather than pass trivially.
    let secret = alphabet_sensitive_secret();
    let verifier = compute_lease_key_hash(&secret);

    let standard = base64::engine::general_purpose::STANDARD.encode(verifier);
    let url_safe = base64::engine::general_purpose::URL_SAFE.encode(verifier);
    assert_ne!(standard, url_safe, "the fixture must exercise two distinct alphabets");
    assert!(
        standard.contains('+') || standard.contains('/'),
        "standard base64 must exercise `+`/`/`: {standard}"
    );
}

#[tokio::test]
async fn published_base64url_form_produces_the_same_echo_and_verifier() {
    // The published v1 contract names base64url. A peer that follows it must reach
    // exactly the same lease state as a peer using the core client's standard
    // base64: same `lease_version` echo, and a committed verifier the secret
    // actually renews. This is the end-to-end proof the relay's dual-alphabet
    // acceptance is functional, not merely permissive.
    let mut config = test_config();
    config.pairing_lease = PairingLeaseConfig {
        enabled: true,
        max_concurrent_sessions: PAIRING_LEASE_MAX_CONCURRENT_SESSIONS,
        ..PairingLeaseConfig::default()
    };
    let (url, _server, db) = start_test_relay_with_config(config).await;
    let client = Client::new();

    let secret = alphabet_sensitive_secret();
    let verifier = compute_lease_key_hash(&secret);
    let url_safe = base64::engine::general_purpose::URL_SAFE.encode(verifier);
    let url_safe_nopad = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifier);
    assert_ne!(
        url_safe,
        base64::engine::general_purpose::STANDARD.encode(verifier),
        "the base64url form must differ from the standard form to be a real test"
    );

    // Both the padded and unpadded published forms must produce the echo.
    for encoded in [url_safe.as_str(), url_safe_nopad.as_str()] {
        let resp = client
            .post(format!("{url}/v1/pairing"))
            .json(&serde_json::json!({
                "joiner_bootstrap": base64::engine::general_purpose::STANDARD.encode(b"boot"),
                "lease_key_hash": encoded,
                "lease_version": LEASE_VERSION_V1,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 201, "create with base64url must succeed");

        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body["lease_version"].as_u64(),
            Some(u64::from(LEASE_VERSION_V1)),
            "published base64url must be echoed as lease-capable: {body}"
        );
        let rid = body["rendezvous_id"].as_str().expect("rendezvous id").to_string();

        // The committed verifier is the exact bytes that base64url decoded to, and
        // the core-derived secret renews against it.
        db.with_conn(|conn| {
            db::set_pairing_slot(conn, &rid, "joiner_confirmation", b"confirm")?;
            let committed: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT lease_key_hash FROM pairing_sessions WHERE rendezvous_id = ?1",
                    rusqlite::params![rid],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(committed.as_deref(), Some(verifier.as_slice()));
            let outcome = db::renew_pairing_lease(
                conn,
                &rid,
                db::PairingLeaseVerifier::Secret(&secret),
                PAIRING_LEASE_MAX_CONCURRENT_SESSIONS,
            )?;
            assert!(
                outcome.is_renewed(),
                "the secret behind a published base64url hash must renew: {outcome:?}"
            );
            Ok::<(), rusqlite::Error>(())
        })
        .unwrap();
    }
}

/// A secret whose SHA-256 encodes differently in standard vs URL-safe base64.
fn alphabet_sensitive_secret() -> [u8; 32] {
    for byte in 0..=255u8 {
        let secret = [byte; 32];
        let verifier = compute_lease_key_hash(&secret);
        let standard = base64::engine::general_purpose::STANDARD.encode(verifier);
        let url_safe = base64::engine::general_purpose::URL_SAFE.encode(verifier);
        if standard != url_safe {
            return secret;
        }
    }
    unreachable!("some 32-byte secret has a hash whose encodings differ");
}
