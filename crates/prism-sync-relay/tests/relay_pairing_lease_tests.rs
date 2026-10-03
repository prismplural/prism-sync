//! Pairing lease (v1) HTTP integration tests.
//!
//! Covers the relay-owned parts of the three-party lease surface:
//!
//! - create-time optional verifier commitment and the authoritative
//!   `lease_version` echo (with safe downgrade for malformed/unsupported input);
//! - the optional nonterminal `lease_capability` slot;
//! - `POST /v1/pairing/{rid}/lease/renew` — exact body handling, uniform
//!   byte-identical rejection, trusted-proxy limiter keying, and the
//!   per-rendezvous failure bucket that must never gate a legitimate renewal.
//!
//! Timer semantics (the first renewal starts the 4h absolute clock; later ones
//! are `max(expires_at, min(now+30m, absolute))`) are asserted directly against
//! the DB layer, because driving 30-minute clocks through HTTP is impractical.

mod common;

use base64::Engine;
use reqwest::Client;
use rusqlite::OptionalExtension;
use serde_json::Value;

use prism_sync_relay::{
    config::{Config, PairingLeaseConfig},
    db::{self, Database, PairingLeaseVerifier},
};

use common::*;

// ---------------------------------------------------------------------------
// Local helpers (no production code is added just for tests)
// ---------------------------------------------------------------------------

/// `SHA-256(bytes)`, matching the create-time verifier the joiner commits.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Read a row's committed lease verifier directly, bypassing the API.
///
/// Used to prove the relay actually *stored* what it echoed: the response alone
/// could claim support that was never persisted.
fn committed_verifier(database: &Database, rid: &str) -> Option<Vec<u8>> {
    database
        .with_read_conn(|conn| {
            conn.query_row(
                "SELECT lease_key_hash FROM pairing_sessions WHERE rendezvous_id = ?1",
                rusqlite::params![rid],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()
        })
        .expect("verifier query should succeed")
        .flatten()
}

/// Force a rendezvous row to look expired while keeping it stored.
fn expire_session(database: &Database, rid: &str) {
    database
        .with_conn(|conn| {
            conn.execute(
                "UPDATE pairing_sessions SET expires_at = ?1 WHERE rendezvous_id = ?2",
                rusqlite::params![db::now_secs() - 10, rid],
            )
            .map(|_| ())
        })
        .expect("expiry update should succeed");
}

/// Config with the lease enabled and predictable limiter sizes.
fn lease_config(max_leased: u32, renew_limit: u32, failure_limit: u32) -> Config {
    let mut config = test_config();
    config.pairing_lease = PairingLeaseConfig {
        enabled: true,
        max_concurrent_sessions: max_leased,
        renew_rate_limit: renew_limit,
        renew_rate_window_secs: 60,
        failure_limit,
        failure_window_secs: 60,
    };
    config
}

/// Create a rendezvous, optionally offering lease metadata.
async fn create_session_raw(
    client: &Client,
    url: &str,
    bootstrap: &[u8],
    lease_key_hash: Option<&[u8; 32]>,
    lease_version: Option<u64>,
) -> (String, u16, Value) {
    let encoded = base64::engine::general_purpose::STANDARD.encode(bootstrap);
    let mut body = serde_json::json!({ "joiner_bootstrap": encoded });
    if let Some(hash) = lease_key_hash {
        body["lease_key_hash"] =
            Value::String(base64::engine::general_purpose::STANDARD.encode(hash));
    }
    if let Some(version) = lease_version {
        body["lease_version"] = Value::Number(version.into());
    }

    let resp = client.post(format!("{url}/v1/pairing")).json(&body).send().await.unwrap();
    let status = resp.status().as_u16();
    let parsed: Value = resp.json().await.unwrap_or_else(|_| Value::Object(Default::default()));
    let rid = parsed["rendezvous_id"].as_str().unwrap_or_default().to_string();
    (rid, status, parsed)
}

/// Create a lease-capable rendezvous and return `(rendezvous_id, secret)`.
async fn create_leased_session(client: &Client, url: &str) -> (String, [u8; 32]) {
    use rand::RngCore;
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    let verifier = sha256(&secret);
    let (rid, status, body) =
        create_session_raw(client, url, b"bootstrap", Some(&verifier), Some(1)).await;
    assert_eq!(status, 201, "create should succeed: {body}");
    assert_eq!(body["lease_version"].as_u64(), Some(1), "relay must echo lease v1");
    (rid, secret)
}

/// Create a rendezvous offering an already-encoded `lease_key_hash` string.
///
/// Lets a test choose the exact alphabet (standard vs URL-safe, padded vs
/// unpadded) the relay must accept, instead of always using the standard form
/// [`create_session_raw`] emits.
async fn create_session_with_encoded_hash(
    client: &Client,
    url: &str,
    encoded_hash: &str,
    lease_version: Option<u64>,
) -> (String, u16, Value) {
    let mut body = serde_json::json!({
        "joiner_bootstrap": base64::engine::general_purpose::STANDARD.encode(b"bootstrap"),
        "lease_key_hash": encoded_hash,
    });
    if let Some(version) = lease_version {
        body["lease_version"] = Value::Number(version.into());
    }

    let resp = client.post(format!("{url}/v1/pairing")).json(&body).send().await.unwrap();
    let status = resp.status().as_u16();
    let parsed: Value = resp.json().await.unwrap_or_else(|_| Value::Object(Default::default()));
    let rid = parsed["rendezvous_id"].as_str().unwrap_or_default().to_string();
    (rid, status, parsed)
}

/// A secret whose verifier encodes differently in standard vs URL-safe base64.
///
/// Returns `(secret, verifier, standard_encoding, url_safe_encoding)`. The two
/// encodings differ only when the hash bytes contain a sextet mapping to `+`/`/`
/// (`-`/`_`), which is what makes a dual-alphabet relay necessary; a test built on
/// a hash that encoded identically would pass even against a single-alphabet
/// relay.
fn alphabet_sensitive_secret() -> ([u8; 32], [u8; 32], String, String) {
    for byte in 0..=255u8 {
        let secret = [byte; 32];
        let verifier = sha256(&secret);
        let standard = base64::engine::general_purpose::STANDARD.encode(verifier);
        let url_safe = base64::engine::general_purpose::URL_SAFE.encode(verifier);
        if standard != url_safe {
            return (secret, verifier, standard, url_safe);
        }
    }
    unreachable!("a 32-byte hash whose encodings differ exists for some byte value");
}

/// Post the joiner confirmation slot, which gates renewal (post-confirmation only).
async fn post_confirmation(client: &Client, url: &str, rid: &str) {
    let resp = client
        .put(format!("{url}/v1/pairing/{rid}/confirmation"))
        .header("Content-Type", "application/octet-stream")
        .body(b"confirmation".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 204, "confirmation slot should write");
}

async fn renew(client: &Client, url: &str, rid: &str, secret: &[u8]) -> (u16, Vec<u8>) {
    renew_with_headers(client, url, rid, secret, &[]).await
}

/// Renew with an arbitrary forwarded-header set, for proxy-keying tests.
async fn renew_with_headers(
    client: &Client,
    url: &str,
    rid: &str,
    secret: &[u8],
    headers: &[(&str, &str)],
) -> (u16, Vec<u8>) {
    let mut request = client
        .post(format!("{url}/v1/pairing/{rid}/lease/renew"))
        .header("Content-Type", "application/octet-stream");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let resp = request.body(secret.to_vec()).send().await.unwrap();
    let status = resp.status().as_u16();
    let body = resp.bytes().await.unwrap().to_vec();
    (status, body)
}

// ---------------------------------------------------------------------------
// 1. Create: echo, no echo, and unknown-JSON compatibility
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_without_lease_metadata_stays_compatible_and_echoes_nothing() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();

    // A legacy joiner sends only the original field. It must still get a 201 and
    // the response must carry no `lease_version` key at all (absent, not `null`).
    let (rid, status, body) = create_session_raw(&client, &url, b"legacy", None, None).await;
    assert_eq!(status, 201);
    assert_eq!(rid.len(), 32);
    assert!(body.get("lease_version").is_none(), "no echo for a legacy create: {body}");
}

#[tokio::test]
async fn create_with_unknown_json_fields_is_still_accepted() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();

    // Unknown-field tolerance is part of the compatibility contract: a future
    // client may send extra keys and this relay must ignore them.
    let resp = client
        .post(format!("{url}/v1/pairing"))
        .json(&serde_json::json!({
            "joiner_bootstrap": base64::engine::general_purpose::STANDARD.encode(b"x"),
            "some_future_field": { "nested": [1, 2, 3] },
            "another": "value",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201);
    let body: Value = resp.json().await.unwrap();
    assert!(body["rendezvous_id"].is_string());
    assert!(body.get("lease_version").is_none());
}

#[tokio::test]
async fn create_with_valid_lease_metadata_echoes_v1_and_commits_the_verifier() {
    let (url, _server, db) = start_test_relay_with_config(lease_config(256, 120, 20)).await;
    let client = Client::new();

    let (rid, secret) = create_leased_session(&client, &url).await;

    // The echo is only trustworthy if the verifier really landed in the row.
    assert_eq!(
        committed_verifier(&db, &rid).as_deref(),
        Some(sha256(&secret).as_slice()),
        "the echoed lease must correspond to a committed verifier"
    );
}

#[tokio::test]
async fn create_with_lease_metadata_when_disabled_downgrades_without_echo() {
    // The capability gate: a dark relay must behave exactly like an old relay.
    let (url, _server, db) = start_test_relay_with_config(test_config()).await;
    let client = Client::new();

    let mut secret = [0u8; 32];
    secret[0] = 7;
    let verifier = sha256(&secret);
    let (rid, status, body) =
        create_session_raw(&client, &url, b"bootstrap", Some(&verifier), Some(1)).await;

    assert_eq!(status, 201, "create must still succeed");
    assert!(body.get("lease_version").is_none(), "a dark relay echoes nothing: {body}");
    assert_eq!(
        committed_verifier(&db, &rid),
        None,
        "no verifier may be committed when the lease is disabled"
    );
}

#[tokio::test]
async fn create_downgrades_for_malformed_or_unsupported_lease_metadata() {
    let (url, _server, db) = start_test_relay_with_config(lease_config(256, 120, 20)).await;
    let client = Client::new();

    // Every one of these must still create the rendezvous, with no echo and no
    // committed verifier. Refusing the create would break an optional feature.
    let cases: Vec<(&str, Value)> = vec![
        ("non-string hash", serde_json::json!(12345)),
        ("null hash", Value::Null),
        ("object hash", serde_json::json!({ "a": 1 })),
        ("not base64", Value::String("not!base64!!".into())),
        (
            "valid b64, 16 bytes",
            Value::String(base64::engine::general_purpose::STANDARD.encode([1u8; 16])),
        ),
        (
            "valid b64, 33 bytes",
            Value::String(base64::engine::general_purpose::STANDARD.encode([1u8; 33])),
        ),
        ("empty string", Value::String(String::new())),
    ];

    for (name, hash) in cases {
        let body = serde_json::json!({
            "joiner_bootstrap": base64::engine::general_purpose::STANDARD.encode(b"x"),
            "lease_key_hash": hash,
            "lease_version": 1,
        });
        let resp = client.post(format!("{url}/v1/pairing")).json(&body).send().await.unwrap();
        assert_eq!(resp.status().as_u16(), 201, "{name} must not fail create");
        let parsed: Value = resp.json().await.unwrap();
        assert!(parsed.get("lease_version").is_none(), "{name} must not echo a version: {parsed}");
        let rid = parsed["rendezvous_id"].as_str().unwrap();
        assert_eq!(committed_verifier(&db, rid), None, "{name} must not commit a verifier");
    }

    // An unsupported requested version downgrades the same way, and must not
    // commit the verifier either.
    let verifier = sha256(&[9u8; 32]);
    let (rid, status, parsed) =
        create_session_raw(&client, &url, b"x", Some(&verifier), Some(2)).await;
    assert_eq!(status, 201);
    assert!(parsed.get("lease_version").is_none(), "v2 request against a v1 relay: {parsed}");
    assert_eq!(committed_verifier(&db, &rid), None);
}

#[tokio::test]
async fn create_accepts_standard_and_url_safe_lease_key_hash_and_echoes_v1() {
    // The published v1 contract names base64url while the core client emits
    // standard base64. The relay must accept both, or a peer using either form
    // would be silently downgraded to fixed-TTL pairing — indistinguishable from
    // a relay with no lease support at all. Encodings are chosen so the two
    // alphabets really differ (`+`/`/` vs `-`/`_`); on a hash that encoded
    // identically this test would pass vacuously.
    let (url, _server, db) = start_test_relay_with_config(lease_config(256, 120, 20)).await;
    let client = Client::new();

    let (secret, verifier, standard, url_safe) = alphabet_sensitive_secret();
    assert_ne!(standard, url_safe, "the fixture must exercise two distinct alphabets");
    assert!(
        standard.contains('+') || standard.contains('/'),
        "standard encoding must exercise `+`/`/`: {standard}"
    );
    assert!(
        url_safe.contains('-') || url_safe.contains('_'),
        "url-safe encoding must exercise `-`/`_`: {url_safe}"
    );

    let standard_nopad = standard.trim_end_matches('=');
    let url_safe_nopad = url_safe.trim_end_matches('=');

    for (name, encoded) in [
        ("standard padded", standard.as_str()),
        ("standard unpadded", standard_nopad),
        ("url-safe padded", url_safe.as_str()),
        ("url-safe unpadded", url_safe_nopad),
    ] {
        let (rid, status, body) =
            create_session_with_encoded_hash(&client, &url, encoded, Some(1)).await;
        assert_eq!(status, 201, "{name} create must succeed: {body}");
        assert_eq!(
            body["lease_version"].as_u64(),
            Some(1),
            "{name} must be echoed as lease-capable: {body}"
        );
        // The echo is only trustworthy if the exact 32 bytes landed in the row.
        assert_eq!(
            committed_verifier(&db, &rid).as_deref(),
            Some(verifier.as_slice()),
            "{name} must commit the same verifier the peer offered"
        );

        // And the peer can actually renew with the secret that hash came from —
        // the end-to-end proof that the accepted encoding is usable, not merely
        // accepted.
        post_confirmation(&client, &url, &rid).await;
        let (renew_status, _) = renew(&client, &url, &rid, &secret).await;
        assert_eq!(renew_status, 204, "{name} verifier must renew");
    }
}

#[tokio::test]
async fn create_downgrades_for_url_safe_hashes_of_the_wrong_length() {
    // Dual-alphabet acceptance must not loosen the exact-length rule: a URL-safe
    // value that is not 32 bytes still downgrades with no echo and no commit.
    let (url, _server, db) = start_test_relay_with_config(lease_config(256, 120, 20)).await;
    let client = Client::new();

    for len in [16usize, 31, 33, 64] {
        let encoded = base64::engine::general_purpose::URL_SAFE.encode(vec![0xABu8; len]);
        let (rid, status, body) =
            create_session_with_encoded_hash(&client, &url, &encoded, Some(1)).await;
        assert_eq!(status, 201, "{len}-byte url-safe value must not fail create: {body}");
        assert!(
            body.get("lease_version").is_none(),
            "{len}-byte url-safe value must downgrade: {body}"
        );
        assert_eq!(committed_verifier(&db, &rid), None, "{len}-byte value must not commit");
    }

    // A 32-byte string in a mixed alphabet (standard `+`/`/` and url-safe `-`/`_`
    // in the same value) matches neither engine, so it too downgrades.
    let mixed = "AAAA+///AAA-___AAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let (rid, status, body) = create_session_with_encoded_hash(&client, &url, mixed, Some(1)).await;
    assert_eq!(status, 201);
    assert!(body.get("lease_version").is_none(), "mixed alphabet must downgrade: {body}");
    assert_eq!(committed_verifier(&db, &rid), None);
}

// ---------------------------------------------------------------------------
// 2. lease_capability slot: nonterminal and repeatable
// ---------------------------------------------------------------------------

#[tokio::test]
async fn lease_capability_slot_is_set_once_and_repeatably_readable() {
    let (url, _server, _db) = start_test_relay_with_config(lease_config(256, 120, 20)).await;
    let client = Client::new();

    let (rid, _secret) = create_leased_session(&client, &url).await;
    let frame = b"capability-frame-bytes";

    // 204 before the slot is written — a joiner reading early sees "not set",
    // never an error.
    let resp = client.get(format!("{url}/v1/pairing/{rid}/lease_capability")).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 204);

    // The initiator posts the capability *before* the legacy `pairing_init`.
    let resp = client
        .put(format!("{url}/v1/pairing/{rid}/lease_capability"))
        .header("Content-Type", "application/octet-stream")
        .body(frame.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 204);

    // Repeatable: a retrying joiner must see identical bytes every time. This is
    // what separates a nonterminal slot from the take-once terminal payloads,
    // which would 404 on a second read.
    for attempt in 0..3 {
        let resp =
            client.get(format!("{url}/v1/pairing/{rid}/lease_capability")).send().await.unwrap();
        assert_eq!(resp.status().as_u16(), 200, "read {attempt} must succeed");
        assert_eq!(resp.bytes().await.unwrap().as_ref(), frame, "read {attempt} must be stable");
    }

    // Set-once: a second write conflicts rather than replacing the frame.
    let resp = client
        .put(format!("{url}/v1/pairing/{rid}/lease_capability"))
        .header("Content-Type", "application/octet-stream")
        .body(b"different".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 409);

    // Posting the capability does not disturb the ceremony slots: the legacy init
    // slot is still independently writable afterwards.
    let resp = client
        .put(format!("{url}/v1/pairing/{rid}/init"))
        .header("Content-Type", "application/octet-stream")
        .body(b"legacy-init".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 204, "capability must not block the init slot");

    let resp = client.get(format!("{url}/v1/pairing/{rid}/init")).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"legacy-init");
}

#[tokio::test]
async fn lease_capability_slot_on_unknown_session_is_404() {
    let (url, _server, _db) = start_test_relay_with_config(lease_config(256, 120, 20)).await;
    let client = Client::new();

    // The initiator posts the capability first; when the rendezvous does not exist
    // the write 404s and the client treats that as "no lease", never a ceremony
    // failure. The route-level contract is just the generic slot handling.
    let unknown = "0".repeat(32);
    let resp = client
        .put(format!("{url}/v1/pairing/{unknown}/lease_capability"))
        .header("Content-Type", "application/octet-stream")
        .body(b"frame".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);

    // A read of the optional slot on an unknown session is likewise 404, which the
    // joiner already treats as "no lease".
    let resp =
        client.get(format!("{url}/v1/pairing/{unknown}/lease_capability")).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 404);
}

// ---------------------------------------------------------------------------
// 3. Renew: success, exact body, and content type
// ---------------------------------------------------------------------------

#[tokio::test]
async fn renew_succeeds_after_confirmation_with_an_empty_body() {
    let (url, _server, _db) = start_test_relay_with_config(lease_config(256, 120, 20)).await;
    let client = Client::new();

    let (rid, secret) = create_leased_session(&client, &url).await;

    // Pre-confirmation renewal is rejected: the lease is post-confirmation only,
    // which preserves the short pre-confirmation MITM/SAS window.
    let (status, body) = renew(&client, &url, &rid, &secret).await;
    assert_eq!(status, 404);
    assert_eq!(body, b"Not Found");

    post_confirmation(&client, &url, &rid).await;

    let (status, body) = renew(&client, &url, &rid, &secret).await;
    assert_eq!(status, 204, "renewal after confirmation should succeed");
    assert!(body.is_empty(), "success carries no body and no timestamp");
}

#[tokio::test]
async fn renew_is_idempotent_and_repeatable() {
    let (url, _server, _db) = start_test_relay_with_config(lease_config(256, 120, 20)).await;
    let client = Client::new();

    let (rid, secret) = create_leased_session(&client, &url).await;
    post_confirmation(&client, &url, &rid).await;

    // A lost 204 must be harmless: renewing again succeeds rather than
    // conflicting, and never shortens the lease.
    for _ in 0..3 {
        let (status, _) = renew(&client, &url, &rid, &secret).await;
        assert_eq!(status, 204);
    }
}

#[tokio::test]
async fn renew_rejects_wrong_and_short_bodies_uniformly() {
    let (url, _server, _db) = start_test_relay_with_config(lease_config(256, 120, 20)).await;
    let client = Client::new();

    let (rid, secret) = create_leased_session(&client, &url).await;
    post_confirmation(&client, &url, &rid).await;

    // A body of the wrong length must never be accepted, padded, or truncated:
    // the route requires an exact 32-byte body.
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("31 bytes", vec![0u8; 31]),
        ("33 bytes", vec![0u8; 33]),
        ("64 bytes", vec![0u8; 64]),
        ("wrong 32-byte secret", vec![0u8; 32]),
    ];

    for (name, body) in cases {
        let (status, response) = renew(&client, &url, &rid, &body).await;
        assert_eq!(status, 404, "{name} must be rejected");
        assert_eq!(response, b"Not Found", "{name} must use the uniform body");
    }

    // The legitimate secret still works after all those failures: wrong-body
    // probes never disable the real renewal.
    let (status, _) = renew(&client, &url, &rid, &secret).await;
    assert_eq!(status, 204, "legitimate renewal must survive wrong-body probes");
}

#[tokio::test]
async fn renew_treats_the_body_as_opaque_octets_not_json() {
    let (url, _server, _db) = start_test_relay_with_config(lease_config(256, 120, 20)).await;
    let client = Client::new();

    let (rid, secret) = create_leased_session(&client, &url).await;
    post_confirmation(&client, &url, &rid).await;

    // A JSON-shaped body of exactly 32 bytes is simply 32 opaque bytes, so it must
    // not renew unless those bytes *are* the secret. This proves there is no JSON
    // parsing on the path.
    let json_ish: Vec<u8> = format!(r#"{{"lease_secret":"{}"}}"#, "a".repeat(13)).into_bytes();
    assert_eq!(json_ish.len(), 32, "the probe body must be exactly 32 bytes");
    let (status, _) = renew(&client, &url, &rid, &json_ish).await;
    assert_eq!(status, 404, "a 32-byte non-secret body must not renew");

    // Content-Type is not authority either: the same secret sent as JSON still
    // renews, because only the bytes are compared.
    let resp = client
        .post(format!("{url}/v1/pairing/{rid}/lease/renew"))
        .header("Content-Type", "application/json")
        .body(secret.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 204);
    assert!(resp.bytes().await.unwrap().is_empty(), "no JSON envelope on success");
}

#[tokio::test]
async fn renew_oversized_body_returns_the_same_byte_identical_404() {
    let (url, _server, _db) = start_test_relay_with_config(lease_config(256, 120, 20)).await;
    let client = Client::new();

    let (rid, secret) = create_leased_session(&client, &url).await;
    post_confirmation(&client, &url, &rid).await;

    // Establish the exact rejection a *semantic* wrong length produces, so the
    // oversize cases can be compared against it byte-for-byte.
    let (wrong_len_status, wrong_len_body) = renew(&client, &url, &rid, &[0u8; 31]).await;
    assert_eq!(wrong_len_status, 404);
    assert_eq!(wrong_len_body, b"Not Found");

    // An oversize body must be indistinguishable from that semantic wrong length:
    // same status, same body. A body-limit *layer* would answer 413 here, which is
    // a distinct response and therefore a shape oracle. The handler bounds its own
    // read so every size collapses to the same uniform not-found.
    for size in [1025usize, 256 * 1024] {
        let resp = client
            .post(format!("{url}/v1/pairing/{rid}/lease/renew"))
            .header("Content-Type", "application/octet-stream")
            .body(vec![0u8; size])
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let body = resp.bytes().await.unwrap().to_vec();
        assert_eq!(status, 404, "a {size}-byte body must return the uniform 404, got {status}");
        assert_eq!(
            body, wrong_len_body,
            "a {size}-byte body must be byte-identical to the semantic wrong-length 404"
        );
    }

    // The live lease is unaffected by the oversize probes.
    let (status, _) = renew(&client, &url, &rid, &secret).await;
    assert_eq!(status, 204, "legitimate renewal must survive an oversized probe");
}

#[tokio::test]
async fn oversize_body_is_still_failure_accounted_against_the_presented_id() {
    // An over-cap body is a failed verifier attempt like any other, so it must
    // still feed the per-rendezvous failure bucket. With a limit of 1, one
    // oversize probe is enough to take the ID over budget — and the legitimate
    // renewal must nevertheless still be admitted, because the bucket only counts.
    let (url, _server, _db) = start_test_relay_with_config(lease_config(256, 120, 1)).await;
    let client = Client::new();

    let (rid, secret) = create_leased_session(&client, &url).await;
    post_confirmation(&client, &url, &rid).await;

    let resp = client
        .post(format!("{url}/v1/pairing/{rid}/lease/renew"))
        .header("Content-Type", "application/octet-stream")
        .body(vec![0u8; 4096])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"Not Found");

    let (status, _) = renew(&client, &url, &rid, &secret).await;
    assert_eq!(status, 204, "an oversize probe must never starve the real renewal");
}

// ---------------------------------------------------------------------------
// 4. Uniform byte-identical 404 across every rejection reason
// ---------------------------------------------------------------------------

#[tokio::test]
async fn all_rejection_reasons_return_byte_identical_404() {
    let (url, _server, db) = start_test_relay_with_config(lease_config(2, 120, 20)).await;
    let client = Client::new();

    let mut observed: Vec<(&str, u16, Vec<u8>)> = Vec::new();

    // (a) Unknown rendezvous.
    let (status, body) = renew(&client, &url, &"a".repeat(32), &[0u8; 32]).await;
    observed.push(("unknown", status, body));

    // (b) Wrong secret against a real, confirmed, lease-capable row.
    let (rid_wrong, _secret_wrong) = create_leased_session(&client, &url).await;
    post_confirmation(&client, &url, &rid_wrong).await;
    let (status, body) = renew(&client, &url, &rid_wrong, &[0xAAu8; 32]).await;
    observed.push(("wrong secret", status, body));

    // (c) Pre-confirmation use of the correct secret.
    let (rid_pre, secret_pre) = create_leased_session(&client, &url).await;
    let (status, body) = renew(&client, &url, &rid_pre, &secret_pre).await;
    observed.push(("pre-confirmation", status, body));

    // (d) Legacy / lease-declined row: valid rendezvous, no committed verifier.
    let (rid_legacy, status_legacy, _) =
        create_session_raw(&client, &url, b"legacy", None, None).await;
    assert_eq!(status_legacy, 201);
    post_confirmation(&client, &url, &rid_legacy).await;
    let (status, body) = renew(&client, &url, &rid_legacy, &[0u8; 32]).await;
    observed.push(("lease-declined row", status, body));

    // (e) Consumed terminal slot: consuming the joiner bundle makes the row
    //     terminal for lease purposes.
    let (rid_consumed, secret_consumed) = create_leased_session(&client, &url).await;
    post_confirmation(&client, &url, &rid_consumed).await;
    let resp = client
        .put(format!("{url}/v1/pairing/{rid_consumed}/joiner"))
        .header("Content-Type", "application/octet-stream")
        .body(b"terminal-bundle".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 204);
    let resp = client.get(format!("{url}/v1/pairing/{rid_consumed}/joiner")).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200, "consume the terminal slot");
    let (status, body) = renew(&client, &url, &rid_consumed, &secret_consumed).await;
    observed.push(("consumed terminal slot", status, body));

    // (f) Expired row: retained but no longer live, the case a lapsed lease hits.
    let (rid_expired, secret_expired) = create_leased_session(&client, &url).await;
    post_confirmation(&client, &url, &rid_expired).await;
    expire_session(&db, &rid_expired);
    let (status, body) = renew(&client, &url, &rid_expired, &secret_expired).await;
    observed.push(("expired", status, body));

    // (g) Global leased-session saturation: the cap is 2, so a third row cannot
    //     start a lease.
    let (rid_a, secret_a) = create_leased_session(&client, &url).await;
    post_confirmation(&client, &url, &rid_a).await;
    assert_eq!(renew(&client, &url, &rid_a, &secret_a).await.0, 204, "first lease");
    let (rid_b, secret_b) = create_leased_session(&client, &url).await;
    post_confirmation(&client, &url, &rid_b).await;
    assert_eq!(renew(&client, &url, &rid_b, &secret_b).await.0, 204, "second lease");

    let (rid_sat, secret_sat) = create_leased_session(&client, &url).await;
    post_confirmation(&client, &url, &rid_sat).await;
    let (status, body) = renew(&client, &url, &rid_sat, &secret_sat).await;
    observed.push(("saturated", status, body));

    // (h) Wrong body length against an otherwise-valid row.
    let (status, body) = renew(&client, &url, &rid_wrong, &[0u8; 31]).await;
    observed.push(("wrong body length", status, body));

    // Every rejection must be 404 with one identical body. Any divergence is a
    // state oracle: an attacker could distinguish "row exists but is unconfirmed"
    // from "no such row".
    for (name, status, body) in &observed {
        assert_eq!(*status, 404, "{name} must be 404");
        assert_eq!(body, b"Not Found", "{name} must use the uniform body");
    }

    // Saturation must not disturb already-leased rows: a lease that is already
    // counted always renews, even at the cap.
    assert_eq!(
        renew(&client, &url, &rid_a, &secret_a).await.0,
        204,
        "an already-leased row must keep renewing at the cap"
    );
    assert_eq!(renew(&client, &url, &rid_b, &secret_b).await.0, 204);

    // The DB's leased count is exactly the two continued leases: saturation never
    // created a third.
    let leased = db.with_read_conn(db::count_nonexpired_leased_pairing_sessions).unwrap();
    assert_eq!(leased, 2, "only the two live leases are counted");
}

#[tokio::test]
async fn renew_on_unsupported_relay_is_uniform_404() {
    // With the lease disabled, renew must be indistinguishable from an unknown
    // rendezvous — the same response a legacy relay produces by not having the
    // route at all.
    let (url, _server, _db) = start_test_relay_with_config(test_config()).await;
    let client = Client::new();

    let (rid, status, _) = create_session_raw(&client, &url, b"legacy", None, None).await;
    assert_eq!(status, 201);

    let (status, body) = renew(&client, &url, &rid, &[0u8; 32]).await;
    assert_eq!(status, 404);
    assert_eq!(body, b"Not Found");
}

// ---------------------------------------------------------------------------
// 5. Limiter keying: trusted-proxy-derived IP
// ---------------------------------------------------------------------------

#[tokio::test]
async fn renew_limiter_buckets_by_trusted_proxy_client_ip() {
    // The test peer is trusted and the per-client-IP budget is 2. Two clients
    // arriving through the same peer must nonetheless have independent buckets;
    // if the limiter keyed on the raw peer, the second client would be rejected.
    let mut config = lease_config(256, 2, 20);
    config.trusted_proxy_cidrs = vec!["127.0.0.0/8".into()];
    let (url, _server, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();

    let client_a = "203.0.113.10";
    let client_b = "203.0.113.11";

    let (rid_a, secret_a) = create_leased_session(&client, &url).await;
    post_confirmation(&client, &url, &rid_a).await;
    let (rid_b, secret_b) = create_leased_session(&client, &url).await;
    post_confirmation(&client, &url, &rid_b).await;

    // Client A uses its full budget.
    for attempt in 0..2 {
        let (status, _) =
            renew_with_headers(&client, &url, &rid_a, &secret_a, &[("cf-connecting-ip", client_a)])
                .await;
        assert_eq!(status, 204, "client A attempt {attempt} should be admitted");
    }

    // Client A is now over budget — proof the limiter is actually enforcing.
    let (status, body) =
        renew_with_headers(&client, &url, &rid_a, &secret_a, &[("cf-connecting-ip", client_a)])
            .await;
    assert_eq!(status, 404, "client A should be throttled after its budget");
    assert_eq!(body, b"Not Found", "limiter rejection must be the uniform response");

    // Client B is unaffected: it has its own bucket despite sharing the peer.
    let (status, _) =
        renew_with_headers(&client, &url, &rid_b, &secret_b, &[("cf-connecting-ip", client_b)])
            .await;
    assert_eq!(status, 204, "a different client IP must have an independent bucket");
}

#[tokio::test]
async fn untrusted_peer_forwarded_headers_do_not_create_a_new_bucket() {
    // The peer is *not* in TRUSTED_PROXY_CIDRS, so a spoofed CF-Connecting-IP must
    // be ignored and the peer address used. Two requests claiming different
    // forwarded IPs therefore share one bucket.
    let config = lease_config(256, 1, 20);
    assert!(config.trusted_proxy_cidrs.is_empty(), "the peer must be untrusted here");
    let (url, _server, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();

    let (rid_a, secret_a) = create_leased_session(&client, &url).await;
    post_confirmation(&client, &url, &rid_a).await;
    let (first, _) = renew_with_headers(
        &client,
        &url,
        &rid_a,
        &secret_a,
        &[("cf-connecting-ip", "198.51.100.1")],
    )
    .await;
    assert_eq!(first, 204);

    let (rid_b, secret_b) = create_leased_session(&client, &url).await;
    post_confirmation(&client, &url, &rid_b).await;
    let (second, body) = renew_with_headers(
        &client,
        &url,
        &rid_b,
        &secret_b,
        &[("cf-connecting-ip", "198.51.100.99")],
    )
    .await;
    assert_eq!(second, 404, "a spoofed header must not buy a separate bucket");
    assert_eq!(body, b"Not Found", "the limiter rejection is the uniform response");
}

#[tokio::test]
async fn invalid_or_untrusted_forwarded_headers_fall_back_safely() {
    // Malformed and untrusted forwarded values must not panic, must not be
    // trusted, and must not leak a distinguishable response. Each request has to
    // land on either the uniform 204 or the uniform 404.
    let config = lease_config(256, 40, 40);
    assert!(config.trusted_proxy_cidrs.is_empty(), "the peer must be untrusted here");
    let (url, _server, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();

    let header_sets: Vec<Vec<(&str, &str)>> = vec![
        vec![("cf-connecting-ip", "not-an-ip")],
        vec![("cf-connecting-ip", "")],
        vec![("cf-connecting-ip", "unknown")],
        vec![("x-forwarded-for", "unknown")],
        vec![("x-forwarded-for", "999.999.999.999")],
        vec![("forwarded", "for=;;;")],
        vec![("forwarded", "for=\"[::1\"")],
        vec![("cf-connecting-ip", "203.0.113.7"), ("x-forwarded-for", "198.51.100.4")],
    ];

    for headers in &header_sets {
        let (rid, secret) = create_leased_session(&client, &url).await;
        post_confirmation(&client, &url, &rid).await;
        let (status, body) = renew_with_headers(&client, &url, &rid, &secret, headers).await;
        assert!(
            status == 204 || status == 404,
            "unexpected status {status} for headers {headers:?}"
        );
        if status == 404 {
            assert_eq!(body, b"Not Found", "rejections stay uniform for {headers:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// 6. Failure bucket must not starve a legitimate renewal
// ---------------------------------------------------------------------------

#[tokio::test]
async fn failure_bucket_counts_failures_only_and_never_starves_success() {
    // The failure limit is deliberately tiny. An attacker who knows the rendezvous
    // ID floods it with wrong secrets; the legitimate initiator must still renew.
    let (url, _server, db) = start_test_relay_with_config(lease_config(256, 120, 2)).await;
    let client = Client::new();

    let (rid, secret) = create_leased_session(&client, &url).await;
    post_confirmation(&client, &url, &rid).await;

    // Establish that the lease is live before the flood.
    assert_eq!(renew(&client, &url, &rid, &secret).await.0, 204);

    // Flood far past the failure budget with garbage for this exact ID.
    for _ in 0..10 {
        let (status, body) = renew(&client, &url, &rid, &[0x5Au8; 32]).await;
        assert_eq!(status, 404);
        assert_eq!(body, b"Not Found", "failure responses stay uniform");
    }

    // The real renewal still succeeds. This is what makes the bucket safe: it
    // observes failures instead of gating requests, so merely knowing an ID grants
    // no veto over that ID's legitimate traffic.
    let (status, _) = renew(&client, &url, &rid, &secret).await;
    assert_eq!(status, 204, "legitimate renewal must not be starved by garbage knowing the rid");

    // Garbage against an ID with no row is counted too, and affects nothing else.
    let (unknown_status, unknown_body) = renew(&client, &url, &"b".repeat(32), &[0u8; 32]).await;
    assert_eq!(unknown_status, 404);
    assert_eq!(unknown_body, b"Not Found");
    assert_eq!(renew(&client, &url, &rid, &secret).await.0, 204);

    // The leased count is unaffected by all the garbage.
    let leased = db.with_read_conn(db::count_nonexpired_leased_pairing_sessions).unwrap();
    assert_eq!(leased, 1);
}

#[tokio::test]
async fn exhausted_failure_bucket_still_answers_uniformly() {
    // Once a bucket genuinely is exhausted, further failures for that ID must
    // still produce the same uniform 404 — the bucket itself must not leak — and
    // the legitimate secret must still be admitted.
    let (url, _server, _db) = start_test_relay_with_config(lease_config(256, 120, 1)).await;
    let client = Client::new();

    let (rid, secret) = create_leased_session(&client, &url).await;
    post_confirmation(&client, &url, &rid).await;

    for _ in 0..5 {
        let (status, body) = renew(&client, &url, &rid, &[0x11u8; 32]).await;
        assert_eq!(status, 404);
        assert_eq!(body, b"Not Found");
    }

    let (status, body) = renew(&client, &url, &rid, &secret).await;
    assert_eq!(status, 204);
    assert!(body.is_empty());
}

#[tokio::test]
async fn huge_and_malformed_rendezvous_ids_answer_uniformly() {
    let (url, _server, _db) = start_test_relay_with_config(lease_config(256, 120, 20)).await;
    let client = Client::new();

    // A legitimate, live lease exists. Probing other IDs — huge or malformed —
    // must neither change its behavior nor produce a distinguishable response.
    // The failure bucket keys these on a fixed-size domain-separated digest, so a
    // multi-kilobyte "ID" cannot become a multi-kilobyte stored map key; that
    // bounded-key property is asserted directly in the route's unit tests.
    let (rid, secret) = create_leased_session(&client, &url).await;
    post_confirmation(&client, &url, &rid).await;
    assert_eq!(renew(&client, &url, &rid, &secret).await.0, 204);

    let huge = "a".repeat(2000);
    for probe in ["!", "not-hex", huge.as_str()] {
        let (status, body) = renew(&client, &url, probe, &[0u8; 32]).await;
        assert_eq!(status, 404, "probe of length {} must be uniform", probe.len());
        assert_eq!(body, b"Not Found", "probe of length {} must use the uniform body", probe.len());
    }

    // No probe starved or disabled the real lease.
    assert_eq!(renew(&client, &url, &rid, &secret).await.0, 204);
}

// ---------------------------------------------------------------------------
// 7. Timer semantics and constant parity, via the DB layer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn first_renewal_starts_the_absolute_clock_and_later_ones_only_raise_idle() {
    let database = Database::in_memory().expect("in-memory db");
    let rid = "c".repeat(32);
    let secret = [0x33u8; 32];
    let verifier = sha256(&secret);

    database
        .with_conn(|conn| {
            db::create_pairing_session_with_lease(conn, &rid, b"boot", 300, Some(&verifier))?;
            db::set_pairing_slot(conn, &rid, "joiner_confirmation", b"confirm")?;

            // Before any renewal the row behaves like a legacy fixed-TTL session:
            // no absolute deadline, so it is not counted as leased.
            assert_eq!(db::count_nonexpired_leased_pairing_sessions(conn)?, 0);

            // The first renewal starts the 4h nonrenewable absolute clock.
            let first =
                db::renew_pairing_lease(conn, &rid, PairingLeaseVerifier::Secret(&secret), 256)?;
            let (expires_a, absolute_a) = match first {
                db::PairingLeaseRenewOutcome::Renewed { expires_at, absolute_expires_at } => {
                    (expires_at, absolute_expires_at)
                }
                other => panic!("first renewal should succeed, got {other:?}"),
            };
            let now = db::now_secs();
            assert!(
                (absolute_a - (now + 14400)).abs() <= 2,
                "absolute deadline must be now + 4h, delta {}",
                absolute_a - (now + 14400)
            );
            assert!(
                (expires_a - (now + 1800)).abs() <= 2,
                "first idle extension must be now + 30m, delta {}",
                expires_a - (now + 1800)
            );

            // The row is now a counted lease.
            assert_eq!(db::count_nonexpired_leased_pairing_sessions(conn)?, 1);

            // A later renewal keeps the absolute deadline verbatim and only raises
            // idle expiry to max(existing, min(now + 30m, absolute)).
            let second =
                db::renew_pairing_lease(conn, &rid, PairingLeaseVerifier::Secret(&secret), 256)?;
            match second {
                db::PairingLeaseRenewOutcome::Renewed { expires_at, absolute_expires_at } => {
                    assert_eq!(
                        absolute_expires_at, absolute_a,
                        "the absolute deadline never moves"
                    );
                    assert!(expires_at >= expires_a, "idle expiry is only ever raised");
                }
                other => panic!("second renewal should succeed, got {other:?}"),
            }

            // The cap only gates the *first* renewal: an already-leased row renews
            // even at a cap of 0.
            let third =
                db::renew_pairing_lease(conn, &rid, PairingLeaseVerifier::Secret(&secret), 0)?;
            assert!(third.is_renewed(), "an already-leased row must renew regardless of the cap");

            // Expiry is not reversible: an expired row cannot be resurrected.
            conn.execute(
                "UPDATE pairing_sessions SET expires_at = ?1 WHERE rendezvous_id = ?2",
                rusqlite::params![db::now_secs() - 5, rid],
            )?;
            let after_expiry =
                db::renew_pairing_lease(conn, &rid, PairingLeaseVerifier::Secret(&secret), 256)?;
            assert!(
                after_expiry.is_not_found(),
                "an expired row must not be resurrected, got {after_expiry:?}"
            );

            Ok::<(), rusqlite::Error>(())
        })
        .unwrap();
}

#[test]
fn lease_constants_match_the_db_layer_and_the_v1_protocol() {
    // Guard the numbers this feature depends on. If any drifts from the spec's v1
    // values, renewals would silently grant the wrong windows.
    assert_eq!(prism_sync_relay::config::PAIRING_LEASE_IDLE_EXTENSION_SECS, 1800);
    assert_eq!(prism_sync_relay::config::PAIRING_LEASE_ABSOLUTE_CAP_SECS, 14400);
    assert_eq!(prism_sync_relay::config::PAIRING_LEASE_MAX_CONCURRENT_SESSIONS, 256);
    assert_eq!(prism_sync_relay::config::PAIRING_LEASE_SECRET_LEN, 32);
    assert_eq!(prism_sync_relay::config::PAIRING_LEASE_RENEW_REQUEST_BODY_LEN, 32);
    assert_eq!(prism_sync_relay::config::PAIRING_LEASE_VERSION_V1, 1);

    // The config copy and the persistence copy must agree; they are separate
    // constants precisely so a mismatch is visible here.
    assert_eq!(
        prism_sync_relay::config::PAIRING_LEASE_IDLE_EXTENSION_SECS,
        db::PAIRING_LEASE_IDLE_EXTENSION_SECS
    );
    assert_eq!(
        prism_sync_relay::config::PAIRING_LEASE_ABSOLUTE_CAP_SECS,
        db::PAIRING_LEASE_ABSOLUTE_CAP_SECS
    );
    assert_eq!(
        prism_sync_relay::config::PAIRING_LEASE_MAX_CONCURRENT_SESSIONS,
        db::PAIRING_LEASE_MAX_CONCURRENT_SESSIONS
    );
    assert_eq!(prism_sync_relay::config::PAIRING_LEASE_SECRET_LEN, db::PAIRING_LEASE_VERIFIER_LEN);
}

#[test]
fn lease_config_accessors_refuse_degenerate_values() {
    let mut config = test_config();

    // Zeroing the cap or a window must not silently disable a control.
    config.pairing_lease = PairingLeaseConfig {
        enabled: true,
        max_concurrent_sessions: 0,
        renew_rate_limit: 0,
        renew_rate_window_secs: 0,
        failure_limit: 0,
        failure_window_secs: 0,
    };
    assert_eq!(config.pairing_lease_max_concurrent_sessions(), 1);
    assert_eq!(config.pairing_lease_renew_rate_window_secs(), 1);
    assert_eq!(config.pairing_lease_failure_window_secs(), 1);
    assert!(config.pairing_lease_supported());
}

#[test]
fn hosted_enablement_requires_a_trusted_proxy_allowlist() {
    // Hosted + proxy-fronted + no allowlist would collapse every user into one
    // limiter bucket, so it must be a startup error rather than a silent hazard.
    let mut config = test_config();
    config.pairing_lease.enabled = true;
    assert!(config.validate_pairing_lease_proxy_trust(true).is_err());
    assert!(config.pairing_lease_trusted_proxy_warning().is_some());

    // Self-host with direct peers is correct without an allowlist.
    assert!(config.validate_pairing_lease_proxy_trust(false).is_ok());

    // With the allowlist set, hosted enablement is allowed and the warning clears.
    config.trusted_proxy_cidrs = vec!["10.0.0.0/8".into()];
    assert!(config.validate_pairing_lease_proxy_trust(true).is_ok());
    assert!(config.pairing_lease_trusted_proxy_warning().is_none());

    // A dark relay is never blocked by proxy trust, and never warns.
    config.pairing_lease.enabled = false;
    config.trusted_proxy_cidrs = vec![];
    assert!(config.validate_pairing_lease_proxy_trust(true).is_ok());
    assert!(config.pairing_lease_trusted_proxy_warning().is_none());

    // Defaults are dark.
    assert!(!PairingLeaseConfig::default().enabled);
}

// ---------------------------------------------------------------------------
// 8. Old-client / old-relay compatibility
// ---------------------------------------------------------------------------

#[tokio::test]
async fn legacy_ceremony_is_unaffected_by_the_lease_surface_existing() {
    // A fully legacy client against a lease-capable relay: no lease fields on
    // create, no capability slot, no renewal. The ceremony must work exactly as
    // before, and the legacy confirmation payload must stay byte-identical.
    let (url, _server, _db) = start_test_relay_with_config(lease_config(256, 120, 20)).await;
    let client = Client::new();

    let (rid, status, body) =
        create_session_raw(&client, &url, b"legacy-bootstrap", None, None).await;
    assert_eq!(status, 201);
    assert!(body.get("lease_version").is_none());

    let resp = client.get(format!("{url}/v1/pairing/{rid}/bootstrap")).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // The legacy exact-32-byte confirmation MAC round-trips unchanged.
    let legacy_mac = [0x42u8; 32];
    let resp = client
        .put(format!("{url}/v1/pairing/{rid}/confirmation"))
        .header("Content-Type", "application/octet-stream")
        .body(legacy_mac.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 204);

    let resp = client.get(format!("{url}/v1/pairing/{rid}/confirmation")).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.bytes().await.unwrap().as_ref(),
        legacy_mac.as_slice(),
        "legacy confirmation bytes must round-trip unchanged"
    );

    // The remaining ceremony slots still work: the lease surface never interfered.
    for slot in ["init", "credentials"] {
        let resp = client
            .put(format!("{url}/v1/pairing/{rid}/{slot}"))
            .header("Content-Type", "application/octet-stream")
            .body(format!("{slot}-payload").into_bytes())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 204, "{slot} slot must still write");
    }
}

#[tokio::test]
async fn renew_endpoint_on_a_dark_relay_matches_old_relay_semantics() {
    // A new client against a lease-disabled relay must see the same uniform 404
    // it would get from an old relay without the route, so it downgrades quietly
    // instead of surfacing an error.
    let (url, _server, _db) = start_test_relay_with_config(test_config()).await;
    let client = Client::new();

    let (status, body) = renew(&client, &url, &"d".repeat(32), &[0u8; 32]).await;
    assert_eq!(status, 404);
    assert_eq!(body, b"Not Found");
}
