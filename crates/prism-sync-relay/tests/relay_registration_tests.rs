//! End-to-end tests for device registration, listing, status, authentication,
//! revocation, and rekey flows against the actual prism-sync-relay
//! server running in-process with an in-memory SQLite database.
//!
//! These tests use raw `reqwest` calls to exercise the relay HTTP API because
//! `ServerRelay::new()` only accepts `http://localhost` or `https://` URLs and
//! uses base64 encoding for keys while the relay expects hex — so direct HTTP
//! calls give us more control and validate the actual wire protocol.

mod common;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use prism_sync_crypto::pq::hybrid_signature_contexts;
use rand::RngCore;
use reqwest::Client;
use serde_json::Value;
use sha2::{Digest, Sha256};

use prism_sync_relay::{
    config::Config,
    db::{self, Database},
    routes,
    state::AppState,
};

use common::*;

async fn fetch_nonce(client: &Client, url: &str, sync_id: &str) -> String {
    let nonce_resp =
        client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
    assert_eq!(nonce_resp.status(), 200);
    let nonce_json: Value = nonce_resp.json().await.unwrap();
    nonce_json["nonce"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn relay_routes_are_mounted_under_v1_not_v2() {
    let (url, _handle, _db) = start_test_relay().await;
    let sync_id = generate_sync_id();
    let client = Client::new();

    let v1 = client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
    assert_eq!(v1.status(), 200);

    let v2 = client.get(format!("{url}/v2/sync/{sync_id}/register-nonce")).send().await.unwrap();
    assert_eq!(v2.status(), 404);
}

#[tokio::test]
async fn test_first_device_nonce_omits_pow_challenge_when_difficulty_zero() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let resp = client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    let nonce_json: Value = resp.json().await.unwrap();
    assert!(nonce_json.get("nonce").and_then(Value::as_str).is_some());
    assert!(
        nonce_json.get("pow_challenge").is_none(),
        "zero difficulty should disable PoW instead of advertising a trivially satisfied challenge"
    );
}

fn is_first_device_pow_valid(
    sync_id: &str,
    device_id: &str,
    nonce: &str,
    counter: u64,
    difficulty_bits: u8,
) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(b"PRISM_SYNC_FIRST_DEVICE_POW_V1\x00");
    hasher.update(sync_id.as_bytes());
    hasher.update([0]);
    hasher.update(device_id.as_bytes());
    hasher.update([0]);
    hasher.update(nonce.as_bytes());
    hasher.update([0]);
    hasher.update(counter.to_be_bytes());
    let hash: [u8; 32] = hasher.finalize().into();

    let full_zero_bytes = (difficulty_bits / 8) as usize;
    let remaining_bits = difficulty_bits % 8;
    if hash[..full_zero_bytes].iter().any(|byte| *byte != 0) {
        return false;
    }
    if remaining_bits == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - remaining_bits);
    hash.get(full_zero_bytes).is_some_and(|byte| byte & mask == 0)
}

fn registration_key_bundle_hash(
    signing_pk: &[u8],
    x25519_pk: &[u8],
    ml_dsa_pk: &[u8],
    ml_kem_pk: &[u8],
    xwing_pk: &[u8],
) -> [u8; 32] {
    fn write_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
    }

    let mut hasher = Sha256::new();
    hasher.update(b"PRISM_SYNC_REGISTRATION_KEY_BUNDLE_V1\x00");
    write_len_prefixed(&mut hasher, signing_pk);
    write_len_prefixed(&mut hasher, x25519_pk);
    write_len_prefixed(&mut hasher, ml_dsa_pk);
    write_len_prefixed(&mut hasher, ml_kem_pk);
    write_len_prefixed(&mut hasher, xwing_pk);
    hasher.finalize().into()
}

fn apple_attestation_challenge(
    sync_id: &str,
    device_id: &str,
    nonce: &str,
    registration_key_bundle_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"PRISM_SYNC_APPLE_APP_ATTEST_V2\x00");
    hasher.update(sync_id.as_bytes());
    hasher.update([0]);
    hasher.update(device_id.as_bytes());
    hasher.update([0]);
    hasher.update(nonce.as_bytes());
    hasher.update([0]);
    hasher.update(registration_key_bundle_hash);
    hasher.finalize().into()
}

fn build_apple_auth_data(app_id: &str, credential_id: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&Sha256::digest(app_id.as_bytes()));
    data.push(0x41);
    data.extend_from_slice(&0u32.to_be_bytes());
    data.extend_from_slice(&[0u8; 16]);
    data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    data.extend_from_slice(credential_id);
    data.extend_from_slice(&[0u8; 65]);
    data
}

fn build_apple_certificate_nonce(auth_data: &[u8], client_data_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(auth_data);
    hasher.update(client_data_hash);
    hasher.finalize().into()
}

fn build_apple_attestation_extension(nonce: [u8; 32]) -> Vec<u8> {
    use simple_asn1::{to_der, ASN1Block};
    to_der(&ASN1Block::Sequence(0, vec![ASN1Block::OctetString(0, nonce.to_vec())])).unwrap()
}

fn build_apple_app_attest_proof(
    sync_id: &str,
    device_id: &str,
    nonce: &str,
    registration_key_bundle_hash: &[u8; 32],
    app_id: &str,
    key_id: &[u8],
    root_cert: &rcgen::Certificate,
    root_key: &rcgen::KeyPair,
) -> Value {
    use rcgen::{CertificateParams, CustomExtension, KeyPair};

    let client_data_hash =
        apple_attestation_challenge(sync_id, device_id, nonce, registration_key_bundle_hash);
    let auth_data = build_apple_auth_data(app_id, key_id);
    let attestation_nonce = build_apple_certificate_nonce(&auth_data, &client_data_hash);

    let mut leaf_params = CertificateParams::new(vec!["leaf".into()]).unwrap();
    leaf_params.custom_extensions.push(CustomExtension::from_oid_content(
        &[1, 2, 840, 113635, 100, 8, 2],
        build_apple_attestation_extension(attestation_nonce),
    ));
    let leaf_key = KeyPair::generate().unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_key, root_cert, root_key).unwrap();

    let attestation_value = ciborium::Value::Map(vec![
        (ciborium::Value::Text("fmt".into()), ciborium::Value::Text("apple-appattest".into())),
        (ciborium::Value::Text("authData".into()), ciborium::Value::Bytes(auth_data)),
        (
            ciborium::Value::Text("attStmt".into()),
            ciborium::Value::Map(vec![(
                ciborium::Value::Text("x5c".into()),
                ciborium::Value::Array(vec![
                    ciborium::Value::Bytes(leaf_cert.der().to_vec()),
                    ciborium::Value::Bytes(root_cert.der().to_vec()),
                ]),
            )]),
        ),
    ]);
    let mut attestation_object = Vec::new();
    ciborium::ser::into_writer(&attestation_value, &mut attestation_object).unwrap();

    serde_json::json!({
        "kind": "apple_app_attest",
        "key_id": base64::engine::general_purpose::STANDARD.encode(key_id),
        "attestation_object": base64::engine::general_purpose::STANDARD.encode(attestation_object),
    })
}

fn make_apple_test_root() -> (rcgen::Certificate, rcgen::KeyPair) {
    use rcgen::{CertificateParams, IsCa, KeyPair};

    let mut params = CertificateParams::new(vec!["Apple App Attest CA".into()]).unwrap();
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    (cert, key_pair)
}

#[cfg(feature = "test-helpers")]
async fn fetch_nonce_json_with_ip(client: &Client, url: &str, sync_id: &str, ip: &str) -> Value {
    let nonce_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
        .header("X-Test-Client-Ip", ip)
        .send()
        .await
        .unwrap();
    assert_eq!(nonce_resp.status(), 200);
    nonce_resp.json().await.unwrap()
}

#[cfg(feature = "test-helpers")]
async fn register_first_device_with_ip(
    client: &Client,
    url: &str,
    sync_id: &str,
    device_id: &str,
    test_keys: &TestDeviceKeys,
    nonce_json: &Value,
    ip: &str,
) -> reqwest::Response {
    let signing_key = &test_keys.ed25519_signing_key;
    let ml_dsa_key = test_keys.device_secret.ml_dsa_65_keypair(device_id).unwrap();
    let nonce = nonce_json["nonce"].as_str().unwrap();
    let challenge_sig = sign_hybrid_challenge(signing_key, &ml_dsa_key, sync_id, device_id, nonce);

    let req = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .header("X-Test-Client-Ip", ip)
        .json(&serde_json::json!({
            "device_id": device_id,
            "signing_public_key": hex::encode(signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(test_keys.x25519_pk),
            "ml_dsa_65_public_key": hex::encode(&test_keys.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&test_keys.ml_kem_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
            "pow_solution": pow_solution_from_nonce_json(sync_id, device_id, nonce_json),
        }));

    req.send().await.unwrap()
}

// ───────────────────────────── Test 1: Registration E2E ─────────────────

#[tokio::test]
async fn test_registration_flow() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let test_keys = TestDeviceKeys::generate(&device_id);
    let signing_key = &test_keys.ed25519_signing_key;

    // 1. Fetch nonce
    let nonce_resp =
        client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
    assert_eq!(nonce_resp.status(), 200);
    let nonce_json: Value = nonce_resp.json().await.unwrap();
    let nonce = nonce_json["nonce"].as_str().expect("nonce field missing");
    assert!(!nonce.is_empty());

    // 2. Sign challenge
    let challenge_sig_ml_dsa_kp = test_keys.device_secret.ml_dsa_65_keypair(&device_id).unwrap();

    let challenge_sig =
        sign_hybrid_challenge(signing_key, &challenge_sig_ml_dsa_kp, &sync_id, &device_id, nonce);

    // 4. Register
    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_id,
            "signing_public_key": hex::encode(signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(test_keys.x25519_pk),
            "ml_dsa_65_public_key": hex::encode(&test_keys.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&test_keys.ml_kem_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
        }))
        .send()
        .await
        .unwrap();
    assert!(register_resp.status().is_success(), "register failed: {}", register_resp.status());
    let token_json: Value = register_resp.json().await.unwrap();
    let token = token_json["device_session_token"].as_str().unwrap();
    assert!(token.len() >= 32, "session token too short");

    // 5. Verify we can use the token for an authenticated request (health-check via devices list)
    let devices_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/devices"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(devices_resp.status(), 200);
    let devices: Vec<Value> = devices_resp.json().await.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["device_id"].as_str().unwrap(), device_id);
    assert_eq!(devices[0]["status"].as_str().unwrap(), "active");
}

#[tokio::test]
async fn test_registration_rejects_bad_challenge() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();

    // Fetch nonce
    let nonce_resp =
        client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
    let nonce_json: Value = nonce_resp.json().await.unwrap();
    let nonce = nonce_json["nonce"].as_str().unwrap();

    // Use a random key but sign with wrong data (wrong nonce)
    let test_keys = TestDeviceKeys::generate(&device_id);
    let signing_key = &test_keys.ed25519_signing_key;
    let bad_sig_ml_dsa_kp = test_keys.device_secret.ml_dsa_65_keypair(&device_id).unwrap();

    let bad_sig =
        sign_hybrid_challenge(signing_key, &bad_sig_ml_dsa_kp, &sync_id, &device_id, "wrong-nonce");

    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_id,
            "signing_public_key": hex::encode(signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(test_keys.x25519_pk),
            "ml_dsa_65_public_key": hex::encode(&test_keys.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&test_keys.ml_kem_pk),
            "registration_challenge": hex::encode(&bad_sig),
            "nonce": nonce,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(register_resp.status(), 401, "bad challenge should be rejected");
}

#[tokio::test]
async fn test_registration_rejects_expired_nonce() {
    // Start relay with very short nonce expiry
    let config = Config {
        port: 0,
        db_path: ":memory:".into(),
        nonce_expiry_secs: 0, // Expire immediately
        session_expiry_secs: 3600,
        first_device_pow_difficulty_bits: 0,
        invite_ttl_secs: 86400,
        sync_inactive_ttl_secs: 7_776_000,
        stale_device_secs: 2_592_000,
        cleanup_interval_secs: 3600,
        max_unpruned_batches: 10_000,
        metrics_token: None,
        nonce_rate_limit: 100,
        nonce_rate_window_secs: 60,
        revoke_rate_limit: 100,
        revoke_rate_window_secs: 60,
        ws_upgrade_rate_limit: 20,
        ws_upgrade_rate_window_secs: 60,
        trusted_proxy_cidrs: vec![],
        signed_request_max_skew_secs: 60,
        signed_request_nonce_window_secs: 120,
        snapshot_default_ttl_secs: 86400,
        revoked_tombstone_retention_secs: 2_592_000,
        reader_pool_size: 2,
        node_exporter_url: None,
        first_device_apple_attestation_enabled: false,
        first_device_apple_attestation_trust_roots_pem: vec![],
        first_device_apple_attestation_allowed_app_ids: vec![],
        first_device_android_attestation_enabled: true,
        first_device_android_attestation_trust_roots_pem: vec![],
        grapheneos_verified_boot_key_allowlist: vec![],
        registration_token: None,
        registration_enabled: true,
        pairing_session_ttl_secs: 300,
        pairing_session_rate_limit: 100,
        pairing_session_max_payload_bytes: 32768,
        sharing_init_ttl_secs: 604800,
        sharing_init_max_payload_bytes: 65536,
        sharing_identity_max_bytes: 8192,
        sharing_prekey_max_bytes: 4096,
        sharing_fetch_rate_limit: 100,
        sharing_init_rate_limit: 100,
        sharing_init_max_pending: 50,
        prekey_upload_max_age_secs: 604800,
        prekey_serve_max_age_secs: 2_592_000,
        prekey_max_future_skew_secs: 300,
        min_signature_version: 3,
        media_storage_path: std::env::temp_dir()
            .join(format!("prism_test_media_{}", uuid::Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string(),
        media_max_file_bytes: 10_485_760,
        media_quota_bytes_per_group: 1_073_741_824,
        media_retention_days: 90,
        media_upload_rate_limit: 100,
        media_upload_rate_window_secs: 60,
        media_orphan_cleanup_secs: 86400,
        gif_provider_mode: prism_sync_relay::GifProviderMode::Disabled,
        gif_public_base_url: None,
        gif_prism_base_url: None,
        gif_api_base_url: "https://api.klipy.com".into(),
        gif_api_key: None,
        gif_http_timeout_secs: 15,
        gif_request_rate_limit: 20,
        gif_request_rate_window_secs: 60,
        gif_query_max_len: 200,
    };

    let db = Database::in_memory().expect("in-memory db");
    let state = AppState::new(db, config);
    let app = routes::router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let _handle = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await
            .unwrap();
    });

    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let test_keys = TestDeviceKeys::generate(&device_id);
    let signing_key = &test_keys.ed25519_signing_key;

    // Fetch nonce
    let nonce_resp =
        client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
    let nonce_json: Value = nonce_resp.json().await.unwrap();
    let nonce = nonce_json["nonce"].as_str().unwrap();

    // No sleep needed: nonce_expiry_secs=0 means expires_at == created_at.
    // The consume check is `expires_at > now` (strict inequality), so a nonce
    // with zero TTL is expired the instant it is created — even within the same
    // second.

    let challenge_sig_ml_dsa_kp = test_keys.device_secret.ml_dsa_65_keypair(&device_id).unwrap();

    let challenge_sig =
        sign_hybrid_challenge(signing_key, &challenge_sig_ml_dsa_kp, &sync_id, &device_id, nonce);

    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_id,
            "signing_public_key": hex::encode(signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(test_keys.x25519_pk),
            "ml_dsa_65_public_key": hex::encode(&test_keys.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&test_keys.ml_kem_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
        }))
        .send()
        .await
        .unwrap();
    // Should fail with 400 (bad request — expired nonce)
    assert_eq!(register_resp.status(), 400, "expired nonce should be rejected");
}

// ───────────────────────────── Test: Nonce rate limiting ────────────────

#[tokio::test]
async fn test_nonce_rate_limiting() {
    // Start relay with a low nonce rate limit
    let config = Config {
        port: 0,
        db_path: ":memory:".into(),
        nonce_expiry_secs: 60,
        session_expiry_secs: 3600,
        first_device_pow_difficulty_bits: 0,
        invite_ttl_secs: 86400,
        sync_inactive_ttl_secs: 7_776_000,
        stale_device_secs: 2_592_000,
        cleanup_interval_secs: 3600,
        max_unpruned_batches: 10_000,
        metrics_token: None,
        nonce_rate_limit: 3, // Only 3 nonces per window
        nonce_rate_window_secs: 60,
        revoke_rate_limit: 100,
        revoke_rate_window_secs: 60,
        ws_upgrade_rate_limit: 20,
        ws_upgrade_rate_window_secs: 60,
        trusted_proxy_cidrs: vec![],
        signed_request_max_skew_secs: 60,
        signed_request_nonce_window_secs: 120,
        snapshot_default_ttl_secs: 86400,
        revoked_tombstone_retention_secs: 2_592_000,
        reader_pool_size: 2,
        node_exporter_url: None,
        first_device_apple_attestation_enabled: false,
        first_device_apple_attestation_trust_roots_pem: vec![],
        first_device_apple_attestation_allowed_app_ids: vec![],
        first_device_android_attestation_enabled: true,
        first_device_android_attestation_trust_roots_pem: vec![],
        grapheneos_verified_boot_key_allowlist: vec![],
        registration_token: None,
        registration_enabled: true,
        pairing_session_ttl_secs: 300,
        pairing_session_rate_limit: 100,
        pairing_session_max_payload_bytes: 32768,
        sharing_init_ttl_secs: 604800,
        sharing_init_max_payload_bytes: 65536,
        sharing_identity_max_bytes: 8192,
        sharing_prekey_max_bytes: 4096,
        sharing_fetch_rate_limit: 100,
        sharing_init_rate_limit: 100,
        sharing_init_max_pending: 50,
        prekey_upload_max_age_secs: 604800,
        prekey_serve_max_age_secs: 2_592_000,
        prekey_max_future_skew_secs: 300,
        min_signature_version: 3,
        media_storage_path: std::env::temp_dir()
            .join(format!("prism_test_media_{}", uuid::Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string(),
        media_max_file_bytes: 10_485_760,
        media_quota_bytes_per_group: 1_073_741_824,
        media_retention_days: 90,
        media_upload_rate_limit: 100,
        media_upload_rate_window_secs: 60,
        media_orphan_cleanup_secs: 86400,
        gif_provider_mode: prism_sync_relay::GifProviderMode::Disabled,
        gif_public_base_url: None,
        gif_prism_base_url: None,
        gif_api_base_url: "https://api.klipy.com".into(),
        gif_api_key: None,
        gif_http_timeout_secs: 15,
        gif_request_rate_limit: 20,
        gif_request_rate_window_secs: 60,
        gif_query_max_len: 200,
    };

    let (url, _server, db) = start_test_relay_with_config(config).await;

    let client = Client::new();
    let sync_id = generate_sync_id();
    db.with_conn(|conn| db::create_sync_group(conn, &sync_id, 0)).unwrap();

    // Existing groups still use the per-sync nonce limiter.
    for i in 0..3 {
        let resp =
            client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
        assert_eq!(resp.status(), 200, "request {i} should succeed");
    }

    let resp = client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
    assert_eq!(resp.status(), 429, "4th request should be rate-limited");
}

#[tokio::test]
#[cfg(feature = "test-helpers")]
async fn test_first_device_nonce_rate_limiting_is_ip_scoped() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let ip = "203.0.113.10";

    for i in 0..3 {
        let sync_id = generate_sync_id();
        let resp = client
            .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
            .header("X-Test-Client-Ip", ip)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "request {i} should succeed");
    }

    let sync_id = generate_sync_id();
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
        .header("X-Test-Client-Ip", ip)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429, "4th first-device nonce should be limited");
}

#[tokio::test]
#[cfg(feature = "test-helpers")]
async fn test_first_device_registration_rate_limiting() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let ip = "198.51.100.9";

    for i in 0..3 {
        let sync_id = generate_sync_id();
        let nonce_json = fetch_nonce_json_with_ip(&client, &url, &sync_id, ip).await;
        let device_id = generate_device_id();
        let test_keys = TestDeviceKeys::generate(&device_id);
        let resp = register_first_device_with_ip(
            &client,
            &url,
            &sync_id,
            &device_id,
            &test_keys,
            &nonce_json,
            ip,
        )
        .await;
        assert_eq!(resp.status(), 201, "registration {i} should succeed");
    }

    let sync_id = generate_sync_id();
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
        .header("X-Test-Client-Ip", ip)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429, "4th first-device admission should be limited");
}

#[tokio::test]
async fn test_brand_new_group_storage_cap_applies_before_global_cap() {
    let config = Config {
        port: 0,
        db_path: ":memory:".into(),
        nonce_expiry_secs: 60,
        session_expiry_secs: 3600,
        first_device_pow_difficulty_bits: 0,
        invite_ttl_secs: 86400,
        sync_inactive_ttl_secs: 7_776_000,
        stale_device_secs: 2_592_000,
        cleanup_interval_secs: 3600,
        max_unpruned_batches: 50,
        metrics_token: None,
        nonce_rate_limit: 100,
        nonce_rate_window_secs: 60,
        revoke_rate_limit: 100,
        revoke_rate_window_secs: 60,
        ws_upgrade_rate_limit: 20,
        ws_upgrade_rate_window_secs: 60,
        trusted_proxy_cidrs: vec![],
        signed_request_max_skew_secs: 60,
        signed_request_nonce_window_secs: 120,
        snapshot_default_ttl_secs: 86400,
        revoked_tombstone_retention_secs: 2_592_000,
        reader_pool_size: 2,
        node_exporter_url: None,
        first_device_apple_attestation_enabled: false,
        first_device_apple_attestation_trust_roots_pem: vec![],
        first_device_apple_attestation_allowed_app_ids: vec![],
        first_device_android_attestation_enabled: true,
        first_device_android_attestation_trust_roots_pem: vec![],
        grapheneos_verified_boot_key_allowlist: vec![],
        registration_token: None,
        registration_enabled: true,
        pairing_session_ttl_secs: 300,
        pairing_session_rate_limit: 100,
        pairing_session_max_payload_bytes: 32768,
        sharing_init_ttl_secs: 604800,
        sharing_init_max_payload_bytes: 65536,
        sharing_identity_max_bytes: 8192,
        sharing_prekey_max_bytes: 4096,
        sharing_fetch_rate_limit: 100,
        sharing_init_rate_limit: 100,
        sharing_init_max_pending: 50,
        prekey_upload_max_age_secs: 604800,
        prekey_serve_max_age_secs: 2_592_000,
        prekey_max_future_skew_secs: 300,
        min_signature_version: 3,
        media_storage_path: std::env::temp_dir()
            .join(format!("prism_test_media_{}", uuid::Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string(),
        media_max_file_bytes: 10_485_760,
        media_quota_bytes_per_group: 1_073_741_824,
        media_retention_days: 90,
        media_upload_rate_limit: 100,
        media_upload_rate_window_secs: 60,
        media_orphan_cleanup_secs: 86400,
        gif_provider_mode: prism_sync_relay::GifProviderMode::Disabled,
        gif_public_base_url: None,
        gif_prism_base_url: None,
        gif_api_base_url: "https://api.klipy.com".into(),
        gif_api_key: None,
        gif_http_timeout_secs: 15,
        gif_request_rate_limit: 20,
        gif_request_rate_window_secs: 60,
        gif_query_max_len: 200,
    };

    let (url, _server, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let path = format!("/v1/sync/{sync_id}/changes");
    for i in 0..10 {
        let envelope = make_test_envelope(&sync_id, &device_id, &format!("batch-{i:03}"), 0);
        let body_bytes = serde_json::to_vec(&envelope).unwrap();
        let resp = apply_signed_headers(
            client
                .put(format!("{url}/v1/sync/{sync_id}/changes"))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Device-Id", &device_id)
                .header("Content-Type", "application/json"),
            &keys,
            "PUT",
            &path,
            &sync_id,
            &device_id,
            &body_bytes,
        )
        .body(body_bytes)
        .send()
        .await
        .unwrap();
        assert!(resp.status().is_success(), "batch {i} should succeed");
    }

    let envelope = make_test_envelope(&sync_id, &device_id, "batch-010", 0);
    let body_bytes = serde_json::to_vec(&envelope).unwrap();
    let resp = apply_signed_headers(
        client
            .put(format!("{url}/v1/sync/{sync_id}/changes"))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Device-Id", &device_id)
            .header("Content-Type", "application/json"),
        &keys,
        "PUT",
        &path,
        &sync_id,
        &device_id,
        &body_bytes,
    )
    .body(body_bytes)
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 507, "brand-new group should hit the smaller storage cap");
}

#[tokio::test]
async fn test_first_device_registration_requires_valid_pow_when_enabled() {
    let config = Config {
        port: 0,
        db_path: ":memory:".into(),
        nonce_expiry_secs: 60,
        session_expiry_secs: 3600,
        first_device_pow_difficulty_bits: 8,
        invite_ttl_secs: 86400,
        sync_inactive_ttl_secs: 7_776_000,
        stale_device_secs: 2_592_000,
        cleanup_interval_secs: 3600,
        max_unpruned_batches: 10_000,
        metrics_token: None,
        nonce_rate_limit: 100,
        nonce_rate_window_secs: 60,
        revoke_rate_limit: 100,
        revoke_rate_window_secs: 60,
        ws_upgrade_rate_limit: 20,
        ws_upgrade_rate_window_secs: 60,
        trusted_proxy_cidrs: vec![],
        signed_request_max_skew_secs: 60,
        signed_request_nonce_window_secs: 120,
        snapshot_default_ttl_secs: 86400,
        revoked_tombstone_retention_secs: 2_592_000,
        reader_pool_size: 2,
        node_exporter_url: None,
        first_device_apple_attestation_enabled: false,
        first_device_apple_attestation_trust_roots_pem: vec![],
        first_device_apple_attestation_allowed_app_ids: vec![],
        first_device_android_attestation_enabled: true,
        first_device_android_attestation_trust_roots_pem: vec![],
        grapheneos_verified_boot_key_allowlist: vec![],
        registration_token: None,
        registration_enabled: true,
        pairing_session_ttl_secs: 300,
        pairing_session_rate_limit: 100,
        pairing_session_max_payload_bytes: 32768,
        sharing_init_ttl_secs: 604800,
        sharing_init_max_payload_bytes: 65536,
        sharing_identity_max_bytes: 8192,
        sharing_prekey_max_bytes: 4096,
        sharing_fetch_rate_limit: 100,
        sharing_init_rate_limit: 100,
        sharing_init_max_pending: 50,
        prekey_upload_max_age_secs: 604800,
        prekey_serve_max_age_secs: 2_592_000,
        prekey_max_future_skew_secs: 300,
        min_signature_version: 3,
        media_storage_path: std::env::temp_dir()
            .join(format!("prism_test_media_{}", uuid::Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string(),
        media_max_file_bytes: 10_485_760,
        media_quota_bytes_per_group: 1_073_741_824,
        media_retention_days: 90,
        media_upload_rate_limit: 100,
        media_upload_rate_window_secs: 60,
        media_orphan_cleanup_secs: 86400,
        gif_provider_mode: prism_sync_relay::GifProviderMode::Disabled,
        gif_public_base_url: None,
        gif_prism_base_url: None,
        gif_api_base_url: "https://api.klipy.com".into(),
        gif_api_key: None,
        gif_http_timeout_secs: 15,
        gif_request_rate_limit: 20,
        gif_request_rate_window_secs: 60,
        gif_query_max_len: 200,
    };

    let (url, _server, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let test_keys = TestDeviceKeys::generate(&device_id);
    let signing_key = &test_keys.ed25519_signing_key;

    let nonce_resp =
        client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
    assert_eq!(nonce_resp.status(), 200);
    let nonce_json: Value = nonce_resp.json().await.unwrap();
    assert_eq!(nonce_json["pow_challenge"]["difficulty_bits"].as_u64(), Some(8));
    let nonce = nonce_json["nonce"].as_str().unwrap();

    let challenge_sig_ml_dsa_kp = test_keys.device_secret.ml_dsa_65_keypair(&device_id).unwrap();

    let challenge_sig =
        sign_hybrid_challenge(signing_key, &challenge_sig_ml_dsa_kp, &sync_id, &device_id, nonce);

    let missing_pow_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_id,
            "signing_public_key": hex::encode(signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(test_keys.x25519_pk),
            "ml_dsa_65_public_key": hex::encode(&test_keys.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&test_keys.ml_kem_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(missing_pow_resp.status(), 403);
    let missing_body: Value = missing_pow_resp.json().await.unwrap();
    assert_eq!(missing_body["error"].as_str(), Some("first_device_admission_required"));

    let nonce_resp =
        client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
    assert_eq!(nonce_resp.status(), 200);
    let nonce_json: Value = nonce_resp.json().await.unwrap();
    let nonce = nonce_json["nonce"].as_str().unwrap();
    let challenge_sig_ml_dsa_kp = test_keys.device_secret.ml_dsa_65_keypair(&device_id).unwrap();

    let challenge_sig =
        sign_hybrid_challenge(signing_key, &challenge_sig_ml_dsa_kp, &sync_id, &device_id, nonce);
    let invalid_pow_solution = pow_solution_from_nonce_json(&sync_id, &device_id, &nonce_json)
        .map(|solution| {
            serde_json::json!({
                "counter": solution["counter"].as_u64().unwrap() + 1,
            })
        })
        .unwrap();

    let invalid_pow_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_id,
            "signing_public_key": hex::encode(signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(test_keys.x25519_pk),
            "ml_dsa_65_public_key": hex::encode(&test_keys.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&test_keys.ml_kem_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
            "pow_solution": invalid_pow_solution,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(invalid_pow_resp.status(), 403);
    let invalid_body: Value = invalid_pow_resp.json().await.unwrap();
    assert_eq!(invalid_body["error"].as_str(), Some("first_device_admission_invalid"));

    let nonce_resp =
        client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
    assert_eq!(nonce_resp.status(), 200);
    let nonce_json: Value = nonce_resp.json().await.unwrap();
    let nonce = nonce_json["nonce"].as_str().unwrap();
    let challenge_sig_ml_dsa_kp = test_keys.device_secret.ml_dsa_65_keypair(&device_id).unwrap();

    let challenge_sig =
        sign_hybrid_challenge(signing_key, &challenge_sig_ml_dsa_kp, &sync_id, &device_id, nonce);
    let pow_solution = pow_solution_from_nonce_json(&sync_id, &device_id, &nonce_json).unwrap();

    let valid_pow_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_id,
            "signing_public_key": hex::encode(signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(test_keys.x25519_pk),
            "ml_dsa_65_public_key": hex::encode(&test_keys.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&test_keys.ml_kem_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
            "pow_solution": pow_solution,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(valid_pow_resp.status(), 201);
}

#[tokio::test]
async fn test_first_device_registration_accepts_apple_app_attest() {
    let (root_cert, root_key) = make_apple_test_root();
    let app_id = "TEAMID.com.prism.prism_plurality";
    let config = Config {
        port: 0,
        db_path: ":memory:".into(),
        nonce_expiry_secs: 60,
        session_expiry_secs: 3600,
        first_device_pow_difficulty_bits: 8,
        invite_ttl_secs: 86400,
        sync_inactive_ttl_secs: 7_776_000,
        stale_device_secs: 2_592_000,
        cleanup_interval_secs: 3600,
        max_unpruned_batches: 10_000,
        metrics_token: None,
        nonce_rate_limit: 100,
        nonce_rate_window_secs: 60,
        revoke_rate_limit: 100,
        revoke_rate_window_secs: 60,
        ws_upgrade_rate_limit: 20,
        ws_upgrade_rate_window_secs: 60,
        trusted_proxy_cidrs: vec![],
        signed_request_max_skew_secs: 60,
        signed_request_nonce_window_secs: 120,
        snapshot_default_ttl_secs: 86400,
        revoked_tombstone_retention_secs: 2_592_000,
        reader_pool_size: 2,
        node_exporter_url: None,
        first_device_apple_attestation_enabled: true,
        first_device_apple_attestation_trust_roots_pem: vec![root_cert.pem()],
        first_device_apple_attestation_allowed_app_ids: vec![app_id.into()],
        first_device_android_attestation_enabled: true,
        first_device_android_attestation_trust_roots_pem: vec![],
        grapheneos_verified_boot_key_allowlist: vec![],
        registration_token: None,
        registration_enabled: true,
        pairing_session_ttl_secs: 300,
        pairing_session_rate_limit: 100,
        pairing_session_max_payload_bytes: 32768,
        sharing_init_ttl_secs: 604800,
        sharing_init_max_payload_bytes: 65536,
        sharing_identity_max_bytes: 8192,
        sharing_prekey_max_bytes: 4096,
        sharing_fetch_rate_limit: 100,
        sharing_init_rate_limit: 100,
        sharing_init_max_pending: 50,
        prekey_upload_max_age_secs: 604800,
        prekey_serve_max_age_secs: 2_592_000,
        prekey_max_future_skew_secs: 300,
        min_signature_version: 3,
        media_storage_path: std::env::temp_dir()
            .join(format!("prism_test_media_{}", uuid::Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string(),
        media_max_file_bytes: 10_485_760,
        media_quota_bytes_per_group: 1_073_741_824,
        media_retention_days: 90,
        media_upload_rate_limit: 100,
        media_upload_rate_window_secs: 60,
        media_orphan_cleanup_secs: 86400,
        gif_provider_mode: prism_sync_relay::GifProviderMode::Disabled,
        gif_public_base_url: None,
        gif_prism_base_url: None,
        gif_api_base_url: "https://api.klipy.com".into(),
        gif_api_key: None,
        gif_http_timeout_secs: 15,
        gif_request_rate_limit: 20,
        gif_request_rate_window_secs: 60,
        gif_query_max_len: 200,
    };

    let (url, _server, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let test_keys = TestDeviceKeys::generate(&device_id);
    let signing_key = &test_keys.ed25519_signing_key;
    let key_bundle_hash = registration_key_bundle_hash(
        signing_key.verifying_key().as_bytes(),
        &test_keys.x25519_pk,
        &test_keys.ml_dsa_pk,
        &test_keys.ml_kem_pk,
        &[],
    );

    let nonce_resp =
        client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
    assert_eq!(nonce_resp.status(), 200);
    let nonce_json: Value = nonce_resp.json().await.unwrap();
    let nonce = nonce_json["nonce"].as_str().unwrap();

    let challenge_sig_ml_dsa_kp = test_keys.device_secret.ml_dsa_65_keypair(&device_id).unwrap();

    let challenge_sig =
        sign_hybrid_challenge(signing_key, &challenge_sig_ml_dsa_kp, &sync_id, &device_id, nonce);
    let proof = build_apple_app_attest_proof(
        &sync_id,
        &device_id,
        nonce,
        &key_bundle_hash,
        app_id,
        &[0x42; 16],
        &root_cert,
        &root_key,
    );

    let substituted_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_id,
            "signing_public_key": hex::encode(signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode([0x99u8; 32]),
            "ml_dsa_65_public_key": hex::encode(&test_keys.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&test_keys.ml_kem_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
            "first_device_admission_proof": proof,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(substituted_resp.status(), 403);
    let substituted_body: Value = substituted_resp.json().await.unwrap();
    assert_eq!(substituted_body["error"].as_str(), Some("first_device_admission_required"));

    let nonce_resp =
        client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
    assert_eq!(nonce_resp.status(), 200);
    let nonce_json: Value = nonce_resp.json().await.unwrap();
    let nonce = nonce_json["nonce"].as_str().unwrap();
    let challenge_sig =
        sign_hybrid_challenge(signing_key, &challenge_sig_ml_dsa_kp, &sync_id, &device_id, nonce);
    let proof = build_apple_app_attest_proof(
        &sync_id,
        &device_id,
        nonce,
        &key_bundle_hash,
        app_id,
        &[0x42; 16],
        &root_cert,
        &root_key,
    );

    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_id,
            "signing_public_key": hex::encode(signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(test_keys.x25519_pk),
            "ml_dsa_65_public_key": hex::encode(&test_keys.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&test_keys.ml_kem_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
            "first_device_admission_proof": proof,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(register_resp.status(), 201);
}

#[tokio::test]
async fn test_existing_group_registration_does_not_require_pow_when_enabled() {
    let config = Config {
        port: 0,
        db_path: ":memory:".into(),
        nonce_expiry_secs: 60,
        session_expiry_secs: 3600,
        first_device_pow_difficulty_bits: 8,
        invite_ttl_secs: 86400,
        sync_inactive_ttl_secs: 7_776_000,
        stale_device_secs: 2_592_000,
        cleanup_interval_secs: 3600,
        max_unpruned_batches: 10_000,
        metrics_token: None,
        nonce_rate_limit: 100,
        nonce_rate_window_secs: 60,
        revoke_rate_limit: 100,
        revoke_rate_window_secs: 60,
        ws_upgrade_rate_limit: 20,
        ws_upgrade_rate_window_secs: 60,
        trusted_proxy_cidrs: vec![],
        signed_request_max_skew_secs: 60,
        signed_request_nonce_window_secs: 120,
        snapshot_default_ttl_secs: 86400,
        revoked_tombstone_retention_secs: 2_592_000,
        reader_pool_size: 2,
        node_exporter_url: None,
        first_device_apple_attestation_enabled: false,
        first_device_apple_attestation_trust_roots_pem: vec![],
        first_device_apple_attestation_allowed_app_ids: vec![],
        first_device_android_attestation_enabled: true,
        first_device_android_attestation_trust_roots_pem: vec![],
        grapheneos_verified_boot_key_allowlist: vec![],
        registration_token: None,
        registration_enabled: true,
        pairing_session_ttl_secs: 300,
        pairing_session_rate_limit: 100,
        pairing_session_max_payload_bytes: 32768,
        sharing_init_ttl_secs: 604800,
        sharing_init_max_payload_bytes: 65536,
        sharing_identity_max_bytes: 8192,
        sharing_prekey_max_bytes: 4096,
        sharing_fetch_rate_limit: 100,
        sharing_init_rate_limit: 100,
        sharing_init_max_pending: 50,
        prekey_upload_max_age_secs: 604800,
        prekey_serve_max_age_secs: 2_592_000,
        prekey_max_future_skew_secs: 300,
        min_signature_version: 3,
        media_storage_path: std::env::temp_dir()
            .join(format!("prism_test_media_{}", uuid::Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string(),
        media_max_file_bytes: 10_485_760,
        media_quota_bytes_per_group: 1_073_741_824,
        media_retention_days: 90,
        media_upload_rate_limit: 100,
        media_upload_rate_window_secs: 60,
        media_orphan_cleanup_secs: 86400,
        gif_provider_mode: prism_sync_relay::GifProviderMode::Disabled,
        gif_public_base_url: None,
        gif_prism_base_url: None,
        gif_api_base_url: "https://api.klipy.com".into(),
        gif_api_key: None,
        gif_http_timeout_secs: 15,
        gif_request_rate_limit: 20,
        gif_request_rate_window_secs: 60,
        gif_query_max_len: 200,
    };

    let (url, _server, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // Register first device (creates the sync group) — use _with_x25519 so we have the key
    let approver_device_id = generate_device_id();
    let approver_keys = TestDeviceKeys::generate(&approver_device_id);
    let _approver_token =
        register_device(&client, &url, &sync_id, &approver_device_id, &approver_keys).await;
    let joiner_device_id = generate_device_id();
    let joiner_keys = TestDeviceKeys::generate(&joiner_device_id);
    let nonce_resp =
        client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
    assert_eq!(nonce_resp.status(), 200);
    let nonce_json: Value = nonce_resp.json().await.unwrap();
    assert!(
        nonce_json.get("pow_challenge").is_some(),
        "nonce shape should not reveal whether the sync group exists"
    );
    let nonce = nonce_json["nonce"].as_str().unwrap();

    let joiner_ml_dsa_kp = joiner_keys.device_secret.ml_dsa_65_keypair(&joiner_device_id).unwrap();
    let challenge_sig = sign_hybrid_challenge(
        &joiner_keys.ed25519_signing_key,
        &joiner_ml_dsa_kp,
        &sync_id,
        &joiner_device_id,
        nonce,
    );
    // Use registry_approval — existing groups don't need PoW
    let registry_approval = build_registry_approval(
        &sync_id,
        &approver_device_id,
        &approver_keys,
        vec![
            registry_snapshot_entry_hybrid(&sync_id, &approver_device_id, &approver_keys, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &joiner_device_id, &joiner_keys, "active"),
        ],
    );

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
    assert_eq!(register_resp.status(), 201);
}

#[tokio::test]
async fn test_existing_group_registration_accepts_registry_approval() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let approver_device_id = generate_device_id();
    let approver_keys = TestDeviceKeys::generate(&approver_device_id);
    let _approver_token =
        register_device(&client, &url, &sync_id, &approver_device_id, &approver_keys).await;
    let joiner_device_id = generate_device_id();
    let joiner_keys = TestDeviceKeys::generate(&joiner_device_id);
    let nonce = fetch_nonce(&client, &url, &sync_id).await;
    let challenge_sig_ml_dsa_kp =
        joiner_keys.device_secret.ml_dsa_65_keypair(&joiner_device_id).unwrap();

    let challenge_sig = sign_hybrid_challenge(
        &joiner_keys.ed25519_signing_key,
        &challenge_sig_ml_dsa_kp,
        &sync_id,
        &joiner_device_id,
        &nonce,
    );

    let registry_approval = build_registry_approval(
        &sync_id,
        &approver_device_id,
        &approver_keys,
        vec![
            registry_snapshot_entry_hybrid(&sync_id, &approver_device_id, &approver_keys, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &joiner_device_id, &joiner_keys, "active"),
        ],
    );

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
    assert_eq!(register_resp.status(), 201);

    db.with_conn(|conn| {
        let devices = db::list_devices(conn, &sync_id)?;
        assert_eq!(devices.len(), 2);
        Ok(())
    })
    .unwrap();
}

#[tokio::test]
async fn test_existing_group_registration_rejects_stale_registry_approval_after_membership_change()
{
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let approver_device_id = generate_device_id();
    let approver_keys = TestDeviceKeys::generate(&approver_device_id);
    let _approver_token =
        register_device(&client, &url, &sync_id, &approver_device_id, &approver_keys).await;
    let joiner_device_id = generate_device_id();
    let joiner_keys = TestDeviceKeys::generate(&joiner_device_id);
    let nonce = fetch_nonce(&client, &url, &sync_id).await;
    let challenge_sig_ml_dsa_kp =
        joiner_keys.device_secret.ml_dsa_65_keypair(&joiner_device_id).unwrap();

    let challenge_sig = sign_hybrid_challenge(
        &joiner_keys.ed25519_signing_key,
        &challenge_sig_ml_dsa_kp,
        &sync_id,
        &joiner_device_id,
        &nonce,
    );

    let stale_registry_approval = build_registry_approval(
        &sync_id,
        &approver_device_id,
        &approver_keys,
        vec![
            registry_snapshot_entry_hybrid(&sync_id, &approver_device_id, &approver_keys, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &joiner_device_id, &joiner_keys, "active"),
        ],
    );

    let other_device_id = generate_device_id();
    let other_key = SigningKey::generate(&mut rand::thread_rng());
    let mut other_x25519_pk = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut other_x25519_pk);
    db.with_conn(|conn| {
        db::register_device(
            conn,
            &sync_id,
            &other_device_id,
            other_key.verifying_key().as_bytes(),
            &other_x25519_pk,
            0,
        )?;
        Ok(())
    })
    .unwrap();

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
            "registry_approval": stale_registry_approval,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(register_resp.status(), 409);
    assert_eq!(register_resp.text().await.unwrap(), "Stale registry approval");
}

// Regression: a sync group that has ever revoked a device must still accept
// new admissions. The initiator builds its approval snapshot from active
// devices only, so the server must compare against active-only as well.
// Before the fix, revoked rows in the DB with no match in the snapshot
// caused a deterministic 409 "Stale registry approval".
#[tokio::test]
async fn test_existing_group_registration_ignores_revoked_devices_in_current_registry() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let approver_device_id = generate_device_id();
    let approver_keys = TestDeviceKeys::generate(&approver_device_id);
    let _approver_token =
        register_device(&client, &url, &sync_id, &approver_device_id, &approver_keys).await;

    // Seed a revoked device directly into the DB to simulate a group whose
    // membership has changed over time. The initiator never includes revoked
    // rows in its signed snapshot.
    let revoked_device_id = generate_device_id();
    let revoked_keys = TestDeviceKeys::generate(&revoked_device_id);
    db.with_conn(|conn| {
        db::register_device_with_pq(
            conn,
            &sync_id,
            &revoked_device_id,
            revoked_keys.ed25519_signing_key.verifying_key().as_bytes(),
            &revoked_keys.x25519_pk,
            &revoked_keys.ml_dsa_pk,
            &revoked_keys.ml_kem_pk,
            &[],
            0,
        )?;
        let revoked = db::revoke_device(conn, &sync_id, &revoked_device_id, false)?;
        assert!(revoked, "revoke_device should mark the row as revoked");
        Ok(())
    })
    .unwrap();

    let joiner_device_id = generate_device_id();
    let joiner_keys = TestDeviceKeys::generate(&joiner_device_id);
    let nonce = fetch_nonce(&client, &url, &sync_id).await;
    let joiner_ml_dsa_kp = joiner_keys.device_secret.ml_dsa_65_keypair(&joiner_device_id).unwrap();
    let challenge_sig = sign_hybrid_challenge(
        &joiner_keys.ed25519_signing_key,
        &joiner_ml_dsa_kp,
        &sync_id,
        &joiner_device_id,
        &nonce,
    );

    // Approval snapshot matches what the real initiator builds: active
    // members only (approver + new joiner). The revoked row in the DB is
    // intentionally absent from the snapshot.
    let registry_approval = build_registry_approval(
        &sync_id,
        &approver_device_id,
        &approver_keys,
        vec![
            registry_snapshot_entry_hybrid(&sync_id, &approver_device_id, &approver_keys, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &joiner_device_id, &joiner_keys, "active"),
        ],
    );

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
    assert_eq!(
        register_resp.status(),
        201,
        "registration should succeed even when the DB has revoked devices not in the snapshot"
    );

    db.with_conn(|conn| {
        let devices = db::list_devices(conn, &sync_id)?;
        assert_eq!(devices.len(), 3, "approver + revoked + joiner");
        let active: Vec<_> = devices.iter().filter(|d| d.status == "active").collect();
        assert_eq!(active.len(), 2, "approver + joiner are active");
        Ok(())
    })
    .unwrap();
}

#[tokio::test]
async fn test_first_device_pow_is_bound_to_device_and_nonce() {
    let config = Config {
        port: 0,
        db_path: ":memory:".into(),
        nonce_expiry_secs: 60,
        session_expiry_secs: 3600,
        first_device_pow_difficulty_bits: 8,
        invite_ttl_secs: 86400,
        sync_inactive_ttl_secs: 7_776_000,
        stale_device_secs: 2_592_000,
        cleanup_interval_secs: 3600,
        max_unpruned_batches: 10_000,
        metrics_token: None,
        nonce_rate_limit: 100,
        nonce_rate_window_secs: 60,
        revoke_rate_limit: 100,
        revoke_rate_window_secs: 60,
        ws_upgrade_rate_limit: 20,
        ws_upgrade_rate_window_secs: 60,
        trusted_proxy_cidrs: vec![],
        signed_request_max_skew_secs: 60,
        signed_request_nonce_window_secs: 120,
        snapshot_default_ttl_secs: 86400,
        revoked_tombstone_retention_secs: 2_592_000,
        reader_pool_size: 2,
        node_exporter_url: None,
        first_device_apple_attestation_enabled: false,
        first_device_apple_attestation_trust_roots_pem: vec![],
        first_device_apple_attestation_allowed_app_ids: vec![],
        first_device_android_attestation_enabled: true,
        first_device_android_attestation_trust_roots_pem: vec![],
        grapheneos_verified_boot_key_allowlist: vec![],
        registration_token: None,
        registration_enabled: true,
        pairing_session_ttl_secs: 300,
        pairing_session_rate_limit: 100,
        pairing_session_max_payload_bytes: 32768,
        sharing_init_ttl_secs: 604800,
        sharing_init_max_payload_bytes: 65536,
        sharing_identity_max_bytes: 8192,
        sharing_prekey_max_bytes: 4096,
        sharing_fetch_rate_limit: 100,
        sharing_init_rate_limit: 100,
        sharing_init_max_pending: 50,
        prekey_upload_max_age_secs: 604800,
        prekey_serve_max_age_secs: 2_592_000,
        prekey_max_future_skew_secs: 300,
        min_signature_version: 3,
        media_storage_path: std::env::temp_dir()
            .join(format!("prism_test_media_{}", uuid::Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string(),
        media_max_file_bytes: 10_485_760,
        media_quota_bytes_per_group: 1_073_741_824,
        media_retention_days: 90,
        media_upload_rate_limit: 100,
        media_upload_rate_window_secs: 60,
        media_orphan_cleanup_secs: 86400,
        gif_provider_mode: prism_sync_relay::GifProviderMode::Disabled,
        gif_public_base_url: None,
        gif_prism_base_url: None,
        gif_api_base_url: "https://api.klipy.com".into(),
        gif_api_key: None,
        gif_http_timeout_secs: 15,
        gif_request_rate_limit: 20,
        gif_request_rate_window_secs: 60,
        gif_query_max_len: 200,
    };

    let (url, _server, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let other_device_id = generate_device_id();
    let test_keys = TestDeviceKeys::generate(&device_id);
    let signing_key = &test_keys.ed25519_signing_key;

    let nonce_resp =
        client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
    assert_eq!(nonce_resp.status(), 200);
    let nonce_json: Value = nonce_resp.json().await.unwrap();
    let nonce = nonce_json["nonce"].as_str().unwrap();
    let pow_solution = pow_solution_from_nonce_json(&sync_id, &device_id, &nonce_json).unwrap();
    let other_device_sig_ml_dsa_kp = test_keys.device_secret.ml_dsa_65_keypair(&device_id).unwrap();

    let other_device_sig = sign_hybrid_challenge(
        signing_key,
        &other_device_sig_ml_dsa_kp,
        &sync_id,
        &other_device_id,
        nonce,
    );

    let wrong_device_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": other_device_id,
            "signing_public_key": hex::encode(signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(test_keys.x25519_pk),
            "ml_dsa_65_public_key": hex::encode(&test_keys.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&test_keys.ml_kem_pk),
            "registration_challenge": hex::encode(&other_device_sig),
            "nonce": nonce,
            "pow_solution": pow_solution,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_device_resp.status(), 403);
    let wrong_device_body: Value = wrong_device_resp.json().await.unwrap();
    assert_eq!(wrong_device_body["error"].as_str(), Some("first_device_admission_invalid"));

    let nonce_resp =
        client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
    assert_eq!(nonce_resp.status(), 200);
    let first_nonce_json: Value = nonce_resp.json().await.unwrap();
    let first_nonce = first_nonce_json["nonce"].as_str().unwrap().to_string();
    let mut replay_pow_solution =
        pow_solution_from_nonce_json(&sync_id, &device_id, &first_nonce_json)
            .expect("PoW solution should be present");
    let mut replay_counter = replay_pow_solution["counter"].as_u64().unwrap();
    let nonce_resp =
        client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
    assert_eq!(nonce_resp.status(), 200);
    let second_nonce_json: Value = nonce_resp.json().await.unwrap();
    let second_nonce = second_nonce_json["nonce"].as_str().unwrap();
    assert_ne!(first_nonce, second_nonce);
    while is_first_device_pow_valid(&sync_id, &device_id, second_nonce, replay_counter, 8) {
        replay_counter += 1;
    }
    replay_pow_solution["counter"] = serde_json::json!(replay_counter);
    let challenge_sig_ml_dsa_kp = test_keys.device_secret.ml_dsa_65_keypair(&device_id).unwrap();

    let challenge_sig = sign_hybrid_challenge(
        signing_key,
        &challenge_sig_ml_dsa_kp,
        &sync_id,
        &device_id,
        second_nonce,
    );

    let replay_nonce_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_id,
            "signing_public_key": hex::encode(signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(test_keys.x25519_pk),
            "ml_dsa_65_public_key": hex::encode(&test_keys.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&test_keys.ml_kem_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": second_nonce,
            "pow_solution": replay_pow_solution,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(replay_nonce_resp.status(), 403);
    let replay_nonce_body: Value = replay_nonce_resp.json().await.unwrap();
    assert_eq!(replay_nonce_body["error"].as_str(), Some("first_device_admission_invalid"));
}

// ───────────────────────────── Test 3: Device List ──────────────────────

#[tokio::test]
async fn test_list_devices_returns_public_keys() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // Register device
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    // List devices
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/devices"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let devices: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(devices.len(), 1);

    let dev = &devices[0];
    assert_eq!(dev["device_id"].as_str().unwrap(), device_id);
    assert_eq!(dev["status"].as_str().unwrap(), "active");
    assert_eq!(dev["epoch"].as_i64().unwrap(), 0);
    // Verify public keys are present (base64-encoded by the relay)
    let b64 = base64::engine::general_purpose::STANDARD;
    let signing_pk_b64 = dev["signing_public_key"].as_str().unwrap();
    let signing_pk_bytes = b64.decode(signing_pk_b64).unwrap();
    assert_eq!(
        signing_pk_bytes,
        keys.ed25519_signing_key.verifying_key().as_bytes().as_slice(),
        "signing public key should match"
    );

    let x25519_pk_b64 = dev["x25519_public_key"].as_str().unwrap();
    let x25519_pk_bytes = b64.decode(x25519_pk_b64).unwrap();
    assert_eq!(x25519_pk_bytes.len(), 32, "x25519 key should be 32 bytes");
}

// ───────────────────────────── Test 6: Auth rejection ───────────────────

#[tokio::test]
async fn test_unauthenticated_requests_rejected() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // No auth header
    let resp = client.get(format!("{url}/v1/sync/{sync_id}/devices")).send().await.unwrap();
    assert_eq!(resp.status(), 401);

    // Invalid token
    let resp2 = client
        .get(format!("{url}/v1/sync/{sync_id}/devices"))
        .header("Authorization", "Bearer invalid-short")
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), 401);

    // Token with correct length but not registered
    let fake_token = "a".repeat(64);
    let resp3 = client
        .get(format!("{url}/v1/sync/{sync_id}/devices"))
        .header("Authorization", format!("Bearer {fake_token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp3.status(), 401);
}

// ──────────────────────── Test 8: Delete sync group ─────────────────────

#[tokio::test]
async fn test_delete_sync_group() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    // Push some data first
    let envelope = make_test_envelope(&sync_id, &device_id, "batch-delete-test", 0);
    let body_bytes = serde_json::to_vec(&envelope).unwrap();
    let path = format!("/v1/sync/{sync_id}/changes");
    let push_resp = apply_signed_headers(
        client
            .put(format!("{url}/v1/sync/{sync_id}/changes"))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Device-Id", &device_id)
            .header("Content-Type", "application/json"),
        &keys,
        "PUT",
        &path,
        &sync_id,
        &device_id,
        &body_bytes,
    )
    .body(body_bytes)
    .send()
    .await
    .unwrap();
    assert!(push_resp.status().is_success());

    // Delete the sync group (only sole admin can do this)
    let del_resp = apply_signed_headers(
        client.delete(format!("{url}/v1/sync/{sync_id}")),
        &keys,
        "DELETE",
        &format!("/v1/sync/{sync_id}"),
        &sync_id,
        &device_id,
        &[],
    )
    .header("Authorization", format!("Bearer {token}"))
    .header("X-Device-Id", &device_id)
    .send()
    .await
    .unwrap();
    assert_eq!(del_resp.status(), 204);

    // Further requests should fail (session invalidated / group gone)
    let pull_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/changes?since=0"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    // Should fail — either 401 (session deleted) or 404 (group gone)
    assert!(
        pull_resp.status() == 401 || pull_resp.status() == 404,
        "expected 401 or 404 after group deletion, got {}",
        pull_resp.status()
    );
}

// ──────────────────────── Test 9: Rekey artifacts ───────────────────────

#[tokio::test]
async fn test_rekey_artifacts_store_and_retrieve() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // Register a single device (admin)
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let b64 = base64::engine::general_purpose::STANDARD;

    // Post rekey artifacts: epoch 0 -> 1, no revoked device, just wrap for self
    let wrapped_key_data = b"fake-wrapped-epoch-key-for-device";
    let rekey_body = serde_json::json!({
        "epoch": 1,
        "wrapped_keys": {
            device_id.clone(): b64.encode(wrapped_key_data),
        },
    });
    let rekey_body_bytes = serde_json::to_vec(&rekey_body).unwrap();
    let rekey_resp = apply_signed_headers(
        client.post(format!("{url}/v1/sync/{sync_id}/rekey")),
        &keys,
        "POST",
        &format!("/v1/sync/{sync_id}/rekey"),
        &sync_id,
        &device_id,
        &rekey_body_bytes,
    )
    .header("Authorization", format!("Bearer {token}"))
    .header("X-Device-Id", &device_id)
    .header("Content-Type", "application/json")
    .body(rekey_body_bytes)
    .send()
    .await
    .unwrap();
    assert!(
        rekey_resp.status().is_success(),
        "rekey failed: {} - {:?}",
        rekey_resp.status(),
        rekey_resp.text().await.ok()
    );

    // Re-register to get a new token (epoch has changed, old session should still work
    // but let's use the one we have)
    // Actually the token should still be valid since we just bumped epoch.

    // Retrieve the artifact
    let artifact_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/rekey/{device_id}"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(artifact_resp.status(), 200);
    let artifact_json: Value = artifact_resp.json().await.unwrap();
    let retrieved = b64.decode(artifact_json["wrapped_key"].as_str().unwrap()).unwrap();
    assert_eq!(retrieved, wrapped_key_data);

    // Non-existent device returns 404
    let missing_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/rekey/nonexistent-device"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(missing_resp.status(), 404);
}

// ──────────────────────── Test 10: Health check ─────────────────────────

#[tokio::test]
async fn test_health_endpoint() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();

    let resp = client.get(format!("{url}/health")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["status"].as_str().unwrap(), "ok");
}

// ───────────────────── Test: Rate limiting with window expiry e2e ────────

#[tokio::test]
async fn test_nonce_rate_limiting_window_expiry() {
    // Start relay with a very low rate limit and short window
    let config = Config {
        port: 0,
        db_path: ":memory:".into(),
        nonce_expiry_secs: 60,
        session_expiry_secs: 3600,
        first_device_pow_difficulty_bits: 0,
        invite_ttl_secs: 86400,
        sync_inactive_ttl_secs: 7_776_000,
        stale_device_secs: 2_592_000,
        cleanup_interval_secs: 3600,
        max_unpruned_batches: 10_000,
        metrics_token: None,
        nonce_rate_limit: 2,       // Only 2 nonces per window
        nonce_rate_window_secs: 1, // 1-second window
        revoke_rate_limit: 100,
        revoke_rate_window_secs: 60,
        ws_upgrade_rate_limit: 20,
        ws_upgrade_rate_window_secs: 60,
        trusted_proxy_cidrs: vec![],
        signed_request_max_skew_secs: 60,
        signed_request_nonce_window_secs: 120,
        snapshot_default_ttl_secs: 86400,
        revoked_tombstone_retention_secs: 2_592_000,
        reader_pool_size: 2,
        node_exporter_url: None,
        first_device_apple_attestation_enabled: false,
        first_device_apple_attestation_trust_roots_pem: vec![],
        first_device_apple_attestation_allowed_app_ids: vec![],
        first_device_android_attestation_enabled: true,
        first_device_android_attestation_trust_roots_pem: vec![],
        grapheneos_verified_boot_key_allowlist: vec![],
        registration_token: None,
        registration_enabled: true,
        pairing_session_ttl_secs: 300,
        pairing_session_rate_limit: 100,
        pairing_session_max_payload_bytes: 32768,
        sharing_init_ttl_secs: 604800,
        sharing_init_max_payload_bytes: 65536,
        sharing_identity_max_bytes: 8192,
        sharing_prekey_max_bytes: 4096,
        sharing_fetch_rate_limit: 100,
        sharing_init_rate_limit: 100,
        sharing_init_max_pending: 50,
        prekey_upload_max_age_secs: 604800,
        prekey_serve_max_age_secs: 2_592_000,
        prekey_max_future_skew_secs: 300,
        min_signature_version: 3,
        media_storage_path: std::env::temp_dir()
            .join(format!("prism_test_media_{}", uuid::Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string(),
        media_max_file_bytes: 10_485_760,
        media_quota_bytes_per_group: 1_073_741_824,
        media_retention_days: 90,
        media_upload_rate_limit: 100,
        media_upload_rate_window_secs: 60,
        media_orphan_cleanup_secs: 86400,
        gif_provider_mode: prism_sync_relay::GifProviderMode::Disabled,
        gif_public_base_url: None,
        gif_prism_base_url: None,
        gif_api_base_url: "https://api.klipy.com".into(),
        gif_api_key: None,
        gif_http_timeout_secs: 15,
        gif_request_rate_limit: 20,
        gif_request_rate_window_secs: 60,
        gif_query_max_len: 200,
    };

    let (url, _server, db) = start_test_relay_with_config(config).await;

    let client = Client::new();
    let sync_id = generate_sync_id();
    db.with_conn(|conn| db::create_sync_group(conn, &sync_id, 0)).unwrap();

    // First 2 requests after the initial registration should succeed
    for i in 0..2 {
        let resp =
            client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
        assert_eq!(resp.status(), 200, "request {i} should succeed");
    }

    // 3rd request should be rate-limited
    let resp = client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
    assert_eq!(resp.status(), 429, "3rd request should be rate-limited");

    // Poll until the 1-second rate-limit window expires.
    // Uses a retry loop instead of a fixed sleep to tolerate CI timing jitter.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let resp =
            client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
        if resp.status() == 200 {
            break; // Window expired, request succeeded
        }
        assert!(
            std::time::Instant::now() < deadline,
            "rate-limit window did not expire within 5 seconds"
        );
    }
}

// ──────────────── Test: Existing-group registration without registry_approval ──────

#[tokio::test]
async fn test_existing_group_registration_without_registry_approval_returns_401() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // Register first device successfully (creates the sync group)
    let device_a_id = generate_device_id();
    let keys_a = TestDeviceKeys::generate(&device_a_id);
    let token_a = register_device(&client, &url, &sync_id, &device_a_id, &keys_a).await;

    // Attempt to register a second device WITHOUT registry_approval
    let device_b_id = generate_device_id();
    let test_keys_b = TestDeviceKeys::generate(&device_b_id);
    let signing_key_b = &test_keys_b.ed25519_signing_key;

    // Fetch nonce for device B
    let nonce_resp =
        client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
    assert_eq!(nonce_resp.status(), 200);
    let nonce_json: Value = nonce_resp.json().await.unwrap();
    let nonce = nonce_json["nonce"].as_str().unwrap().to_string();

    // Sign challenge for device B
    let challenge_sig_ml_dsa_kp =
        test_keys_b.device_secret.ml_dsa_65_keypair(&device_b_id).unwrap();

    let challenge_sig = sign_hybrid_challenge(
        signing_key_b,
        &challenge_sig_ml_dsa_kp,
        &sync_id,
        &device_b_id,
        &nonce,
    );

    // Register device B without registry_approval — should fail
    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_b_id,
            "signing_public_key": hex::encode(signing_key_b.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(test_keys_b.x25519_pk),
            "ml_dsa_65_public_key": hex::encode(&test_keys_b.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&test_keys_b.ml_kem_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        register_resp.status(),
        401,
        "second device without registry_approval should be rejected"
    );

    // Verify the first device's sync group is still intact
    let devices_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/devices"))
        .header("Authorization", format!("Bearer {token_a}"))
        .header("X-Device-Id", &device_a_id)
        .send()
        .await
        .unwrap();
    assert_eq!(devices_resp.status(), 200);
    let devices: Vec<Value> = devices_resp.json().await.unwrap();
    assert_eq!(devices.len(), 1, "only the first device should exist");
    assert_eq!(devices[0]["device_id"].as_str().unwrap(), device_a_id);
    assert_eq!(devices[0]["status"].as_str().unwrap(), "active");

    // Verify push still works for device A (sync group not corrupted)
    let envelope = make_test_envelope(&sync_id, &device_a_id, "batch-after-rollback", 0);
    let body_bytes = serde_json::to_vec(&envelope).unwrap();
    let path = format!("/v1/sync/{sync_id}/changes");
    let push_resp = apply_signed_headers(
        client
            .put(format!("{url}/v1/sync/{sync_id}/changes"))
            .header("Authorization", format!("Bearer {token_a}"))
            .header("X-Device-Id", &device_a_id)
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
        push_resp.status().is_success(),
        "push should still work after failed registration: {}",
        push_resp.status()
    );
}

#[tokio::test]
async fn test_reregister_existing_device_with_same_keys_succeeds() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let test_keys = TestDeviceKeys::generate(&device_id);
    let signing_key = &test_keys.ed25519_signing_key;

    let nonce = fetch_nonce(&client, &url, &sync_id).await;
    let ml_dsa_kp = test_keys.device_secret.ml_dsa_65_keypair(&device_id).unwrap();
    let challenge_sig =
        sign_hybrid_challenge(signing_key, &ml_dsa_kp, &sync_id, &device_id, &nonce);

    let first_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_id.clone(),
            "signing_public_key": hex::encode(signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(test_keys.x25519_pk),
            "ml_dsa_65_public_key": hex::encode(&test_keys.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&test_keys.ml_kem_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(first_resp.status(), 201);

    // Re-register the same device using registry_approval
    let registry_approval = build_registry_approval(
        &sync_id,
        &device_id,
        &test_keys,
        vec![registry_snapshot_entry_hybrid(&sync_id, &device_id, &test_keys, "active")],
    );
    let nonce = fetch_nonce(&client, &url, &sync_id).await;
    let challenge_sig =
        sign_hybrid_challenge(signing_key, &ml_dsa_kp, &sync_id, &device_id, &nonce);

    let reregister_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_id.clone(),
            "signing_public_key": hex::encode(signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(test_keys.x25519_pk),
            "ml_dsa_65_public_key": hex::encode(&test_keys.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&test_keys.ml_kem_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
            "registry_approval": registry_approval,
        }))
        .send()
        .await
        .unwrap();
    let status = reregister_resp.status();
    let body_text = reregister_resp.text().await.unwrap();
    let body: Value = serde_json::from_str(&body_text).unwrap_or_default();
    assert!(status.is_success(), "re-register should succeed: {status} - {body_text}");
    assert!(body["device_session_token"].as_str().is_some());
}

#[tokio::test]
async fn test_reregister_existing_device_with_changed_signing_key_is_rejected() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let original_keys = TestDeviceKeys::generate(&device_id);
    let replacement_keys = TestDeviceKeys::generate(&device_id);

    let nonce = fetch_nonce(&client, &url, &sync_id).await;
    let original_ml_dsa_kp = original_keys.device_secret.ml_dsa_65_keypair(&device_id).unwrap();
    let challenge_sig = sign_hybrid_challenge(
        &original_keys.ed25519_signing_key,
        &original_ml_dsa_kp,
        &sync_id,
        &device_id,
        &nonce,
    );

    let first_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_id.clone(),
            "signing_public_key": hex::encode(original_keys.ed25519_signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(original_keys.x25519_pk),
            "ml_dsa_65_public_key": hex::encode(&original_keys.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&original_keys.ml_kem_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(first_resp.status(), 201);

    // Build registry_approval signed by original_keys (the approver)
    let registry_approval = build_registry_approval(
        &sync_id,
        &device_id,
        &original_keys,
        vec![registry_snapshot_entry_hybrid(&sync_id, &device_id, &original_keys, "active")],
    );
    let nonce = fetch_nonce(&client, &url, &sync_id).await;
    let replacement_ml_dsa_kp =
        replacement_keys.device_secret.ml_dsa_65_keypair(&device_id).unwrap();
    let challenge_sig = sign_hybrid_challenge(
        &replacement_keys.ed25519_signing_key,
        &replacement_ml_dsa_kp,
        &sync_id,
        &device_id,
        &nonce,
    );

    let reregister_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_id.clone(),
            "signing_public_key": hex::encode(replacement_keys.ed25519_signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(replacement_keys.x25519_pk),
            "ml_dsa_65_public_key": hex::encode(&replacement_keys.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&replacement_keys.ml_kem_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
            "registry_approval": registry_approval,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(reregister_resp.status(), 401);
    let body: Value = reregister_resp.json().await.unwrap();
    assert_eq!(body["error"], "device_identity_mismatch");
}

#[tokio::test]
async fn test_reregister_existing_device_with_changed_x25519_key_is_rejected() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let test_keys = TestDeviceKeys::generate(&device_id);
    let signing_key = &test_keys.ed25519_signing_key;
    let original_x25519_pk = [11u8; 32];
    let replacement_x25519_pk = [12u8; 32];

    let nonce = fetch_nonce(&client, &url, &sync_id).await;
    let challenge_sig_ml_dsa_kp = test_keys.device_secret.ml_dsa_65_keypair(&device_id).unwrap();

    let challenge_sig =
        sign_hybrid_challenge(signing_key, &challenge_sig_ml_dsa_kp, &sync_id, &device_id, &nonce);

    let first_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_id.clone(),
            "signing_public_key": hex::encode(signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(original_x25519_pk),
            "ml_dsa_65_public_key": hex::encode(&test_keys.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&test_keys.ml_kem_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(first_resp.status(), 201);

    // Build registry_approval with the original x25519 key
    let registry_approval = build_registry_approval(
        &sync_id,
        &device_id,
        &test_keys,
        vec![prism_sync_core::pairing::models::RegistrySnapshotEntry {
            sync_id: sync_id.clone(),
            device_id: device_id.clone(),
            ed25519_public_key: signing_key.verifying_key().as_bytes().to_vec(),
            x25519_public_key: original_x25519_pk.to_vec(),
            ml_dsa_65_public_key: test_keys.ml_dsa_pk.clone(),
            ml_kem_768_public_key: test_keys.ml_kem_pk.clone(),
            x_wing_public_key: Vec::new(),
            ml_dsa_key_generation: 0,
            status: "active".into(),
        }],
    );
    let nonce = fetch_nonce(&client, &url, &sync_id).await;
    let challenge_sig_ml_dsa_kp = test_keys.device_secret.ml_dsa_65_keypair(&device_id).unwrap();

    let challenge_sig =
        sign_hybrid_challenge(signing_key, &challenge_sig_ml_dsa_kp, &sync_id, &device_id, &nonce);

    let reregister_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_id.clone(),
            "signing_public_key": hex::encode(signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(replacement_x25519_pk),
            "ml_dsa_65_public_key": hex::encode(&test_keys.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&test_keys.ml_kem_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
            "registry_approval": registry_approval,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(reregister_resp.status(), 401);
    let body: Value = reregister_resp.json().await.unwrap();
    assert_eq!(body["error"], "device_identity_mismatch");
}

#[tokio::test]
async fn test_revoked_device_token_is_invalidated_but_still_identifies_revocation() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let admin_id = generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let _admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;

    let target_id = generate_device_id();
    let (target_token, _target_id_keys) = prepare_device(&db, &sync_id, &target_id).await;

    // Revoke via DB (this test is about session invalidation, not the revoke endpoint)
    db.with_conn(|conn| {
        db::revoke_device(conn, &sync_id, &target_id, true)?;
        db::revoke_session(conn, &sync_id, &target_id, 86400)?;
        Ok::<_, rusqlite::Error>(())
    })
    .unwrap();

    db.with_read_conn(|conn| {
        assert!(db::validate_session(conn, &target_token)?.is_none());
        assert_eq!(
            db::validate_revoked_session(conn, &target_token)?,
            Some((sync_id.clone(), target_id.clone()))
        );
        Ok::<_, rusqlite::Error>(())
    })
    .unwrap();

    let devices_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/devices"))
        .header("Authorization", format!("Bearer {target_token}"))
        .header("X-Device-Id", &target_id)
        .send()
        .await
        .unwrap();
    assert_eq!(devices_resp.status(), 401);
    let body: Value = devices_resp.json().await.unwrap();
    assert_eq!(body["error"], "device_revoked");
    assert_eq!(body["remote_wipe"], true);
}

// ────────────── Test: Revoke does not bump epoch ──────────────

#[tokio::test]
async fn test_old_revoke_other_path_is_gated() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // Register admin device via HTTP
    let admin_id = generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;

    // Register target device directly via DB
    let target_id = generate_device_id();
    let (_target_token, _target_id_keys) = prepare_device(&db, &sync_id, &target_id).await;

    // Revoke the target device
    let revoke_resp = client
        .delete(format!("{url}/v1/sync/{sync_id}/devices/{target_id}"))
        .header("Authorization", format!("Bearer {admin_token}"))
        .header("X-Device-Id", &admin_id)
        .send()
        .await
        .unwrap();
    assert_eq!(revoke_resp.status(), 409, "legacy revoke path should be gated");
}

// ────────────── Test: Revoke then rekey atomic flow ──────────────

#[tokio::test]
async fn test_revoke_then_rekey_atomic_flow() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // Register admin device via HTTP
    let admin_id = generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;

    // Register target device directly via DB
    let target_id = generate_device_id();
    let (_target_token, _target_id_keys) = prepare_device(&db, &sync_id, &target_id).await;

    let b64 = base64::engine::general_purpose::STANDARD;
    let wrapped_key_data = b"fake-wrapped-epoch-key-for-admin";
    let revoke_body = serde_json::json!({
        "new_epoch": 1,
        "remote_wipe": false,
        "wrapped_keys": {
            admin_id.clone(): b64.encode(wrapped_key_data),
        },
    });
    let revoke_body_bytes = serde_json::to_vec(&revoke_body).unwrap();
    let revoke_resp = apply_signed_headers(
        client.post(format!("{url}/v1/sync/{sync_id}/devices/{target_id}/revoke")),
        &admin_keys,
        "POST",
        &format!("/v1/sync/{sync_id}/devices/{target_id}/revoke"),
        &sync_id,
        &admin_id,
        &revoke_body_bytes,
    )
    .header("Authorization", format!("Bearer {admin_token}"))
    .header("X-Device-Id", &admin_id)
    .header("Content-Type", "application/json")
    .body(revoke_body_bytes)
    .send()
    .await
    .unwrap();
    assert_eq!(
        revoke_resp.status(),
        200,
        "atomic revoke should succeed: {:?}",
        revoke_resp.text().await.ok()
    );

    // Verify the rekey artifact exists for the admin device
    let artifact_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/rekey/{admin_id}"))
        .header("Authorization", format!("Bearer {admin_token}"))
        .header("X-Device-Id", &admin_id)
        .send()
        .await
        .unwrap();
    assert_eq!(artifact_resp.status(), 200);
    let artifact_json: Value = artifact_resp.json().await.unwrap();
    let retrieved = b64.decode(artifact_json["wrapped_key"].as_str().unwrap()).unwrap();
    assert_eq!(retrieved, wrapped_key_data);
}

// ────────────── Test: Rekey idempotent revocation ──────────────

#[tokio::test]
async fn test_standalone_rekey_rejects_revoked_device_id() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // Register admin device via HTTP
    let admin_id = generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;

    let b64 = base64::engine::general_purpose::STANDARD;
    let rekey_body = serde_json::json!({
        "epoch": 1,
        "revoked_device_id": "target-device",
        "wrapped_keys": {
            admin_id.clone(): b64.encode(b"fake-wrapped-key-idempotent"),
        },
    });
    let rekey_body_bytes = serde_json::to_vec(&rekey_body).unwrap();
    let rekey_resp = apply_signed_headers(
        client.post(format!("{url}/v1/sync/{sync_id}/rekey")),
        &admin_keys,
        "POST",
        &format!("/v1/sync/{sync_id}/rekey"),
        &sync_id,
        &admin_id,
        &rekey_body_bytes,
    )
    .header("Authorization", format!("Bearer {admin_token}"))
    .header("X-Device-Id", &admin_id)
    .header("Content-Type", "application/json")
    .body(rekey_body_bytes)
    .send()
    .await
    .unwrap();
    assert_eq!(
        rekey_resp.status(),
        409,
        "standalone rekey with revoked_device_id should be rejected: {:?}",
        rekey_resp.text().await.ok()
    );
}

// ────── Test: Registration after epoch rotation via registry_approval ──────

#[tokio::test]
async fn test_registration_after_epoch_rotation_via_registry_approval() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // 1. Register admin device via HTTP
    let admin_id = generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;
    // 2. Register a second device (target to be revoked) directly via DB
    let target_id = generate_device_id();
    let (_target_token, target_keys) = prepare_device(&db, &sync_id, &target_id).await;

    let b64 = base64::engine::general_purpose::STANDARD;
    let revoke_body = serde_json::json!({
        "new_epoch": 1,
        "remote_wipe": false,
        "wrapped_keys": {
            admin_id.clone(): b64.encode(b"fake-wrapped-key-epoch1"),
        },
    });
    let revoke_body_bytes = serde_json::to_vec(&revoke_body).unwrap();
    let revoke_resp = apply_signed_headers(
        client.post(format!("{url}/v1/sync/{sync_id}/devices/{target_id}/revoke")),
        &admin_keys,
        "POST",
        &format!("/v1/sync/{sync_id}/devices/{target_id}/revoke"),
        &sync_id,
        &admin_id,
        &revoke_body_bytes,
    )
    .header("Authorization", format!("Bearer {admin_token}"))
    .header("X-Device-Id", &admin_id)
    .header("Content-Type", "application/json")
    .body(revoke_body_bytes)
    .send()
    .await
    .unwrap();
    assert_eq!(
        revoke_resp.status(),
        200,
        "atomic revoke to epoch 1 should succeed: {:?}",
        revoke_resp.text().await.ok()
    );

    // 3. Verify the sync group is now at epoch 1
    let epoch = db.with_conn(|conn| db::get_sync_group_epoch(conn, &sync_id)).expect("get epoch");
    assert_eq!(epoch, Some(1), "sync group should be at epoch 1 after rekey");

    // 4. Register a third device using registry_approval from admin
    let joiner_id = generate_device_id();
    let joiner_keys = TestDeviceKeys::generate(&joiner_id);
    let nonce = fetch_nonce(&client, &url, &sync_id).await;
    let joiner_ml_dsa_kp = joiner_keys.device_secret.ml_dsa_65_keypair(&joiner_id).unwrap();
    let challenge_sig = sign_hybrid_challenge(
        &joiner_keys.ed25519_signing_key,
        &joiner_ml_dsa_kp,
        &sync_id,
        &joiner_id,
        &nonce,
    );

    // The initiator builds its snapshot from active devices only (see
    // complete_bootstrap_initiator in prism-sync-core). The revoked target is
    // intentionally absent; the server compares against active-only current
    // membership.
    let _ = &target_keys;
    let registry_approval = build_registry_approval(
        &sync_id,
        &admin_id,
        &admin_keys,
        vec![
            registry_snapshot_entry_hybrid(&sync_id, &admin_id, &admin_keys, "active"),
            registry_snapshot_entry_hybrid(&sync_id, &joiner_id, &joiner_keys, "active"),
        ],
    );

    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": joiner_id,
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
    let body: Value = register_resp.json().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "registration after epoch rotation should succeed: {status} - {body}"
    );
    assert!(
        body["device_session_token"].as_str().is_some(),
        "response should contain a session token"
    );
}

#[tokio::test]
async fn test_stale_registry_approval_after_revoke_is_rejected() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let admin_id = generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;
    let admin_x25519_pk = admin_keys.x25519_pk;

    let target_id = generate_device_id();
    let (_target_token, target_keys) = prepare_device(&db, &sync_id, &target_id).await;

    // Build a stale registry_approval BEFORE the revocation that still lists the target
    let joiner_id = generate_device_id();
    let joiner_keys = TestDeviceKeys::generate(&joiner_id);
    let joiner_x25519_pk = joiner_keys.x25519_pk;

    let stale_registry_approval = build_registry_approval(
        &sync_id,
        &admin_id,
        &admin_keys,
        vec![
            registry_snapshot_entry(
                &sync_id,
                &admin_id,
                admin_keys.ed25519_signing_key.verifying_key().as_bytes(),
                &admin_x25519_pk,
                "active",
            ),
            registry_snapshot_entry(
                &sync_id,
                &target_id,
                target_keys.ed25519_signing_key.verifying_key().as_bytes(),
                &target_keys.x25519_pk,
                "active", // still listed as active — stale!
            ),
            registry_snapshot_entry(
                &sync_id,
                &joiner_id,
                joiner_keys.ed25519_signing_key.verifying_key().as_bytes(),
                &joiner_x25519_pk,
                "active",
            ),
        ],
    );

    // Now revoke the target, advancing to epoch 1
    let b64 = base64::engine::general_purpose::STANDARD;
    let revoke_body = serde_json::json!({
        "new_epoch": 1,
        "remote_wipe": false,
        "wrapped_keys": {
            admin_id.clone(): b64.encode(b"fake-wrapped-key-epoch1"),
        },
    });
    let revoke_body_bytes = serde_json::to_vec(&revoke_body).unwrap();
    let revoke_resp = apply_signed_headers(
        client.post(format!("{url}/v1/sync/{sync_id}/devices/{target_id}/revoke")),
        &admin_keys,
        "POST",
        &format!("/v1/sync/{sync_id}/devices/{target_id}/revoke"),
        &sync_id,
        &admin_id,
        &revoke_body_bytes,
    )
    .header("Authorization", format!("Bearer {admin_token}"))
    .header("X-Device-Id", &admin_id)
    .header("Content-Type", "application/json")
    .body(revoke_body_bytes)
    .send()
    .await
    .unwrap();
    assert_eq!(revoke_resp.status(), 200);

    // Try to register joiner with the stale registry_approval
    let nonce = fetch_nonce(&client, &url, &sync_id).await;
    let challenge_sig_ml_dsa_kp = joiner_keys.device_secret.ml_dsa_65_keypair(&joiner_id).unwrap();

    let challenge_sig = sign_hybrid_challenge(
        &joiner_keys.ed25519_signing_key,
        &challenge_sig_ml_dsa_kp,
        &sync_id,
        &joiner_id,
        &nonce,
    );

    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": joiner_id,
            "signing_public_key": hex::encode(joiner_keys.ed25519_signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(joiner_keys.x25519_pk),
            "ml_dsa_65_public_key": hex::encode(&joiner_keys.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&joiner_keys.ml_kem_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
            "registry_approval": stale_registry_approval,
        }))
        .send()
        .await
        .unwrap();

    let status = register_resp.status().as_u16();
    assert!(
        status == 401 || status == 409,
        "stale registry_approval after revoke should be rejected, got {status}"
    );
}

// ─────────── Test: Atomic revoke rejects missing survivor ───────────

#[tokio::test]
async fn test_atomic_revoke_rejects_missing_survivor() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // Register admin
    let admin_id = generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;

    // Register dev2 and dev3
    let dev2_id = generate_device_id();
    let (_dev2_token, _dev2_id_keys) = prepare_device(&db, &sync_id, &dev2_id).await;
    let dev3_id = generate_device_id();
    let (_dev3_token, _dev3_id_keys) = prepare_device(&db, &sync_id, &dev3_id).await;

    let b64 = base64::engine::general_purpose::STANDARD;
    // Revoke dev3 but only include wrapped_keys for admin — missing dev2
    let revoke_body = serde_json::json!({
        "new_epoch": 1,
        "remote_wipe": false,
        "wrapped_keys": {
            admin_id.clone(): b64.encode(b"fake-wrapped-key-epoch1"),
        },
    });
    let revoke_body_bytes = serde_json::to_vec(&revoke_body).unwrap();
    let resp = apply_signed_headers(
        client.post(format!("{url}/v1/sync/{sync_id}/devices/{dev3_id}/revoke")),
        &admin_keys,
        "POST",
        &format!("/v1/sync/{sync_id}/devices/{dev3_id}/revoke"),
        &sync_id,
        &admin_id,
        &revoke_body_bytes,
    )
    .header("Authorization", format!("Bearer {admin_token}"))
    .header("X-Device-Id", &admin_id)
    .header("Content-Type", "application/json")
    .body(revoke_body_bytes)
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 400, "should reject when wrapped_keys is missing a surviving device");
}

// ─────────── Test: Atomic revoke rejects extra device ID ───────────

#[tokio::test]
async fn test_atomic_revoke_rejects_extra_device_id() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let admin_id = generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;

    let target_id = generate_device_id();
    let (_target_token, _target_id_keys) = prepare_device(&db, &sync_id, &target_id).await;

    let b64 = base64::engine::general_purpose::STANDARD;
    // Include admin (correct) + "fake-device" (extra)
    let revoke_body = serde_json::json!({
        "new_epoch": 1,
        "remote_wipe": false,
        "wrapped_keys": {
            admin_id.clone(): b64.encode(b"fake-wrapped-key"),
            "fake-device-id": b64.encode(b"fake-wrapped-key"),
        },
    });
    let revoke_body_bytes = serde_json::to_vec(&revoke_body).unwrap();
    let resp = apply_signed_headers(
        client.post(format!("{url}/v1/sync/{sync_id}/devices/{target_id}/revoke")),
        &admin_keys,
        "POST",
        &format!("/v1/sync/{sync_id}/devices/{target_id}/revoke"),
        &sync_id,
        &admin_id,
        &revoke_body_bytes,
    )
    .header("Authorization", format!("Bearer {admin_token}"))
    .header("X-Device-Id", &admin_id)
    .header("Content-Type", "application/json")
    .body(revoke_body_bytes)
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 400, "should reject when wrapped_keys contains an extra device ID");
}

// ─────────── Test: Atomic revoke rejects already revoked target ───────────

#[tokio::test]
async fn test_atomic_revoke_rejects_already_revoked_target() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let admin_id = generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;

    let target_id = generate_device_id();
    let (_target_token, _target_id_keys) = prepare_device(&db, &sync_id, &target_id).await;

    let b64 = base64::engine::general_purpose::STANDARD;

    // First revoke — should succeed
    let revoke_body = serde_json::json!({
        "new_epoch": 1,
        "remote_wipe": false,
        "wrapped_keys": {
            admin_id.clone(): b64.encode(b"fake-wrapped-key-epoch1"),
        },
    });
    let revoke_body_bytes = serde_json::to_vec(&revoke_body).unwrap();
    let resp1 = apply_signed_headers(
        client.post(format!("{url}/v1/sync/{sync_id}/devices/{target_id}/revoke")),
        &admin_keys,
        "POST",
        &format!("/v1/sync/{sync_id}/devices/{target_id}/revoke"),
        &sync_id,
        &admin_id,
        &revoke_body_bytes,
    )
    .header("Authorization", format!("Bearer {admin_token}"))
    .header("X-Device-Id", &admin_id)
    .header("Content-Type", "application/json")
    .body(revoke_body_bytes)
    .send()
    .await
    .unwrap();
    assert_eq!(resp1.status(), 200, "first revoke should succeed");

    // Second revoke of same target — should fail 409
    let revoke_body2 = serde_json::json!({
        "new_epoch": 2,
        "remote_wipe": false,
        "wrapped_keys": {
            admin_id.clone(): b64.encode(b"fake-wrapped-key-epoch2"),
        },
    });
    let revoke_body_bytes2 = serde_json::to_vec(&revoke_body2).unwrap();
    let resp2 = apply_signed_headers(
        client.post(format!("{url}/v1/sync/{sync_id}/devices/{target_id}/revoke")),
        &admin_keys,
        "POST",
        &format!("/v1/sync/{sync_id}/devices/{target_id}/revoke"),
        &sync_id,
        &admin_id,
        &revoke_body_bytes2,
    )
    .header("Authorization", format!("Bearer {admin_token}"))
    .header("X-Device-Id", &admin_id)
    .header("Content-Type", "application/json")
    .body(revoke_body_bytes2)
    .send()
    .await
    .unwrap();
    assert_eq!(resp2.status(), 409, "revoking an already-revoked target should return 409");
}

// ─────────── Test: Atomic revoke rejects wrong epoch ───────────

#[tokio::test]
async fn test_atomic_revoke_rejects_wrong_epoch() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let admin_id = generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;

    let target_id = generate_device_id();
    let (_target_token, _target_id_keys) = prepare_device(&db, &sync_id, &target_id).await;

    let b64 = base64::engine::general_purpose::STANDARD;
    // new_epoch: 5 instead of expected 1 (current epoch is 0)
    let revoke_body = serde_json::json!({
        "new_epoch": 5,
        "remote_wipe": false,
        "wrapped_keys": {
            admin_id.clone(): b64.encode(b"fake-wrapped-key"),
        },
    });
    let revoke_body_bytes = serde_json::to_vec(&revoke_body).unwrap();
    let resp = apply_signed_headers(
        client.post(format!("{url}/v1/sync/{sync_id}/devices/{target_id}/revoke")),
        &admin_keys,
        "POST",
        &format!("/v1/sync/{sync_id}/devices/{target_id}/revoke"),
        &sync_id,
        &admin_id,
        &revoke_body_bytes,
    )
    .header("Authorization", format!("Bearer {admin_token}"))
    .header("X-Device-Id", &admin_id)
    .header("Content-Type", "application/json")
    .body(revoke_body_bytes)
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 400, "wrong epoch should be rejected");
}

// ─────────── Test: Atomic revoke rejects oversized wrapped key ───────────

#[tokio::test]
async fn test_atomic_revoke_rejects_oversized_wrapped_key() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let admin_id = generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;

    let target_id = generate_device_id();
    let (_target_token, _target_id_keys) = prepare_device(&db, &sync_id, &target_id).await;

    let b64 = base64::engine::general_purpose::STANDARD;
    // 1537 bytes exceeds MAX_WRAPPED_KEY_SIZE (1536)
    let oversized_key = vec![0xAB_u8; 1537];
    let revoke_body = serde_json::json!({
        "new_epoch": 1,
        "remote_wipe": false,
        "wrapped_keys": {
            admin_id.clone(): b64.encode(&oversized_key),
        },
    });
    let revoke_body_bytes = serde_json::to_vec(&revoke_body).unwrap();
    let resp = apply_signed_headers(
        client.post(format!("{url}/v1/sync/{sync_id}/devices/{target_id}/revoke")),
        &admin_keys,
        "POST",
        &format!("/v1/sync/{sync_id}/devices/{target_id}/revoke"),
        &sync_id,
        &admin_id,
        &revoke_body_bytes,
    )
    .header("Authorization", format!("Bearer {admin_token}"))
    .header("X-Device-Id", &admin_id)
    .header("Content-Type", "application/json")
    .body(revoke_body_bytes)
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 400, "oversized wrapped key should be rejected");
}

// ─────────── Test: Revoke rate limiting ───────────

#[tokio::test]
async fn test_revoke_rate_limiting() {
    let config = Config {
        port: 0,
        db_path: ":memory:".into(),
        nonce_expiry_secs: 60,
        session_expiry_secs: 3600,
        invite_ttl_secs: 86400,
        sync_inactive_ttl_secs: 7_776_000,
        stale_device_secs: 2_592_000,
        cleanup_interval_secs: 3600,
        max_unpruned_batches: 10_000,
        metrics_token: None,
        nonce_rate_limit: 100,
        nonce_rate_window_secs: 60,
        revoke_rate_limit: 1,
        revoke_rate_window_secs: 3600,
        ws_upgrade_rate_limit: 20,
        ws_upgrade_rate_window_secs: 60,
        trusted_proxy_cidrs: vec![],
        signed_request_max_skew_secs: 60,
        signed_request_nonce_window_secs: 120,
        snapshot_default_ttl_secs: 86400,
        revoked_tombstone_retention_secs: 2_592_000,
        reader_pool_size: 2,
        node_exporter_url: None,
        first_device_pow_difficulty_bits: 0,
        first_device_apple_attestation_enabled: false,
        first_device_apple_attestation_trust_roots_pem: vec![],
        first_device_apple_attestation_allowed_app_ids: vec![],
        first_device_android_attestation_enabled: true,
        first_device_android_attestation_trust_roots_pem: vec![],
        grapheneos_verified_boot_key_allowlist: vec![],
        registration_token: None,
        registration_enabled: true,
        pairing_session_ttl_secs: 300,
        pairing_session_rate_limit: 100,
        pairing_session_max_payload_bytes: 32768,
        sharing_init_ttl_secs: 604800,
        sharing_init_max_payload_bytes: 65536,
        sharing_identity_max_bytes: 8192,
        sharing_prekey_max_bytes: 4096,
        sharing_fetch_rate_limit: 100,
        sharing_init_rate_limit: 100,
        sharing_init_max_pending: 50,
        prekey_upload_max_age_secs: 604800,
        prekey_serve_max_age_secs: 2_592_000,
        prekey_max_future_skew_secs: 300,
        min_signature_version: 3,
        media_storage_path: std::env::temp_dir()
            .join(format!("prism_test_media_{}", uuid::Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string(),
        media_max_file_bytes: 10_485_760,
        media_quota_bytes_per_group: 1_073_741_824,
        media_retention_days: 90,
        media_upload_rate_limit: 100,
        media_upload_rate_window_secs: 60,
        media_orphan_cleanup_secs: 86400,
        gif_provider_mode: prism_sync_relay::GifProviderMode::Disabled,
        gif_public_base_url: None,
        gif_prism_base_url: None,
        gif_api_base_url: "https://api.klipy.com".into(),
        gif_api_key: None,
        gif_http_timeout_secs: 15,
        gif_request_rate_limit: 20,
        gif_request_rate_window_secs: 60,
        gif_query_max_len: 200,
    };

    let db = Database::in_memory().expect("in-memory db");
    let state = AppState::new(db, config);
    let db = state.db.clone();
    let app = routes::router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let _handle = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await
            .unwrap();
    });

    let client = Client::new();
    let sync_id = generate_sync_id();

    let admin_id = generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;

    let dev2_id = generate_device_id();
    let (_dev2_token, _dev2_id_keys) = prepare_device(&db, &sync_id, &dev2_id).await;
    let dev3_id = generate_device_id();
    let (_dev3_token, _dev3_id_keys) = prepare_device(&db, &sync_id, &dev3_id).await;

    let b64 = base64::engine::general_purpose::STANDARD;

    // First revoke (dev2) — should succeed
    let revoke_body = serde_json::json!({
        "new_epoch": 1,
        "remote_wipe": false,
        "wrapped_keys": {
            admin_id.clone(): b64.encode(b"key-epoch1"),
            dev3_id.clone(): b64.encode(b"key-epoch1-dev3"),
        },
    });
    let revoke_body_bytes = serde_json::to_vec(&revoke_body).unwrap();
    let resp1 = apply_signed_headers(
        client.post(format!("{url}/v1/sync/{sync_id}/devices/{dev2_id}/revoke")),
        &admin_keys,
        "POST",
        &format!("/v1/sync/{sync_id}/devices/{dev2_id}/revoke"),
        &sync_id,
        &admin_id,
        &revoke_body_bytes,
    )
    .header("Authorization", format!("Bearer {admin_token}"))
    .header("X-Device-Id", &admin_id)
    .header("Content-Type", "application/json")
    .body(revoke_body_bytes)
    .send()
    .await
    .unwrap();
    assert_eq!(resp1.status(), 200, "first revoke should succeed");

    // Second revoke (dev3) — should be rate limited
    // After revoking dev2, only admin and dev3 survive, so wrapped_keys = admin only
    let revoke_body2 = serde_json::json!({
        "new_epoch": 2,
        "remote_wipe": false,
        "wrapped_keys": {
            admin_id.clone(): b64.encode(b"key-epoch2"),
        },
    });
    let revoke_body_bytes2 = serde_json::to_vec(&revoke_body2).unwrap();
    let resp2 = apply_signed_headers(
        client.post(format!("{url}/v1/sync/{sync_id}/devices/{dev3_id}/revoke")),
        &admin_keys,
        "POST",
        &format!("/v1/sync/{sync_id}/devices/{dev3_id}/revoke"),
        &sync_id,
        &admin_id,
        &revoke_body_bytes2,
    )
    .header("Authorization", format!("Bearer {admin_token}"))
    .header("X-Device-Id", &admin_id)
    .header("Content-Type", "application/json")
    .body(revoke_body_bytes2)
    .send()
    .await
    .unwrap();
    assert_eq!(resp2.status(), 429, "second revoke should be rate-limited");
}

// ─────────── Test: Atomic revoke audit log ───────────

#[tokio::test]
async fn test_atomic_revoke_audit_log() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let admin_id = generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;

    let target_id = generate_device_id();
    let (_target_token, _target_id_keys) = prepare_device(&db, &sync_id, &target_id).await;

    let b64 = base64::engine::general_purpose::STANDARD;
    let revoke_body = serde_json::json!({
        "new_epoch": 1,
        "remote_wipe": false,
        "wrapped_keys": {
            admin_id.clone(): b64.encode(b"fake-wrapped-key"),
        },
    });
    let revoke_body_bytes = serde_json::to_vec(&revoke_body).unwrap();
    let resp = apply_signed_headers(
        client.post(format!("{url}/v1/sync/{sync_id}/devices/{target_id}/revoke")),
        &admin_keys,
        "POST",
        &format!("/v1/sync/{sync_id}/devices/{target_id}/revoke"),
        &sync_id,
        &admin_id,
        &revoke_body_bytes,
    )
    .header("Authorization", format!("Bearer {admin_token}"))
    .header("X-Device-Id", &admin_id)
    .header("Content-Type", "application/json")
    .body(revoke_body_bytes)
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);

    // Query revocation_events from DB
    let (revoker, target, epoch, remote_wipe) = db
        .with_read_conn(|conn| {
            conn.query_row(
                "SELECT revoker_device_id, target_device_id, new_epoch, remote_wipe
                 FROM revocation_events WHERE sync_id = ?1",
                rusqlite::params![sync_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
        })
        .expect("query revocation_events");

    assert_eq!(revoker, admin_id);
    assert_eq!(target, target_id);
    assert_eq!(epoch, 1);
    assert_eq!(remote_wipe, 0, "remote_wipe should be false (0)");
}

// ─────────── Test: Registry approval for wrong device rejected ───────────

#[tokio::test]
async fn test_registry_approval_device_mismatch_rejected() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // Register admin
    let admin_id = generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let _admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;
    let admin_x25519_pk = admin_keys.x25519_pk;

    // Registry approval includes device-X, but device-Y tries to register
    let device_x_id = generate_device_id();
    let device_x_keys = TestDeviceKeys::generate(&device_x_id);
    let device_y_id = generate_device_id();
    let device_y_keys = TestDeviceKeys::generate(&device_y_id);
    let mut device_x_x25519 = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut device_x_x25519);
    let mut device_y_x25519 = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut device_y_x25519);

    // Build registry_approval that approves device-X (not device-Y)
    let registry_approval = build_registry_approval(
        &sync_id,
        &admin_id,
        &admin_keys,
        vec![
            registry_snapshot_entry(
                &sync_id,
                &admin_id,
                admin_keys.ed25519_signing_key.verifying_key().as_bytes(),
                &admin_x25519_pk,
                "active",
            ),
            registry_snapshot_entry(
                &sync_id,
                &device_x_id,
                device_x_keys.ed25519_signing_key.verifying_key().as_bytes(),
                &device_x_x25519,
                "active",
            ),
        ],
    );

    // Fetch nonce for device-Y
    let nonce = fetch_nonce(&client, &url, &sync_id).await;
    let challenge_sig_ml_dsa_kp =
        device_y_keys.device_secret.ml_dsa_65_keypair(&device_y_id).unwrap();

    let challenge_sig = sign_hybrid_challenge(
        &device_y_keys.ed25519_signing_key,
        &challenge_sig_ml_dsa_kp,
        &sync_id,
        &device_y_id,
        &nonce,
    );

    // Try to register as device-Y with registry_approval that only includes device-X
    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_y_id,
            "signing_public_key": hex::encode(device_y_keys.ed25519_signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(device_y_x25519),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
            "registry_approval": registry_approval,
        }))
        .send()
        .await
        .unwrap();
    let status = register_resp.status().as_u16();
    assert!(
        status == 400 || status == 401,
        "device not in registry_approval should be rejected, got {status}"
    );
}

#[tokio::test]
async fn test_registry_approval_pq_device_mismatch_rejected() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let admin_id = generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let _admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;

    let joiner_id = generate_device_id();
    let joiner_keys = TestDeviceKeys::generate(&joiner_id);

    let mut joiner_snapshot_entry =
        registry_snapshot_entry_hybrid(&sync_id, &joiner_id, &joiner_keys, "active");
    joiner_snapshot_entry.ml_kem_768_public_key[0] ^= 0xFF;

    let registry_approval = build_registry_approval(
        &sync_id,
        &admin_id,
        &admin_keys,
        vec![
            registry_snapshot_entry_hybrid(&sync_id, &admin_id, &admin_keys, "active"),
            joiner_snapshot_entry,
        ],
    );

    let nonce = fetch_nonce(&client, &url, &sync_id).await;
    let challenge_sig_ml_dsa_kp = joiner_keys.device_secret.ml_dsa_65_keypair(&joiner_id).unwrap();
    let challenge_sig = sign_hybrid_challenge(
        &joiner_keys.ed25519_signing_key,
        &challenge_sig_ml_dsa_kp,
        &sync_id,
        &joiner_id,
        &nonce,
    );

    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": joiner_id,
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

    assert_eq!(
        register_resp.status(),
        401,
        "PQ key mismatch in registry approval should be rejected"
    );
}

#[tokio::test]
async fn test_signed_request_below_min_signature_version_returns_403() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let admin_id = generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;

    let target_id = generate_device_id();
    let (_target_token, _target_id_keys) = prepare_device(&db, &sync_id, &target_id).await;

    let revoke_body = serde_json::json!({
        "new_epoch": 1,
        "remote_wipe": false,
        "wrapped_keys": {
            admin_id.clone(): base64::engine::general_purpose::STANDARD.encode(b"legacy-v2-key"),
        },
    });
    let revoke_body_bytes = serde_json::to_vec(&revoke_body).unwrap();
    let path = format!("/v1/sync/{sync_id}/devices/{target_id}/revoke");

    let timestamp = db::now_secs().to_string();
    let nonce = uuid::Uuid::new_v4().to_string();
    let admin_ml_dsa_kp = admin_keys.device_secret.ml_dsa_65_keypair(&admin_id).unwrap();
    let signing_data = prism_sync_relay::auth::build_request_signing_data_v2(
        "POST",
        &path,
        &sync_id,
        &admin_id,
        &revoke_body_bytes,
        &timestamp,
        &nonce,
    );
    let legacy_sig = prism_sync_crypto::pq::HybridSignature {
        ed25519_sig: admin_keys.ed25519_signing_key.sign(&signing_data).to_bytes().to_vec(),
        ml_dsa_65_sig: admin_ml_dsa_kp.sign(&signing_data),
    };
    let mut legacy_wire = vec![0x02u8];
    legacy_wire.extend_from_slice(&legacy_sig.to_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&legacy_wire);

    let resp = client
        .post(format!("{url}{path}"))
        .header("Authorization", format!("Bearer {admin_token}"))
        .header("X-Device-Id", &admin_id)
        .header("Content-Type", "application/json")
        .header("X-Prism-Timestamp", &timestamp)
        .header("X-Prism-Nonce", &nonce)
        .header("X-Prism-Signature", &sig_b64)
        .body(revoke_body_bytes)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403, "below-minimum signature versions should return 403");
}

// ─────────── Test: Unsigned request rejected on atomic revoke ───────────

#[tokio::test]
async fn test_unsigned_request_rejected_on_atomic_revoke() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let admin_id = generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;

    let target_id = generate_device_id();
    let (_target_token, _target_id_keys) = prepare_device(&db, &sync_id, &target_id).await;

    let b64 = base64::engine::general_purpose::STANDARD;
    let revoke_body = serde_json::json!({
        "new_epoch": 1,
        "remote_wipe": false,
        "wrapped_keys": {
            admin_id.clone(): b64.encode(b"fake-wrapped-key"),
        },
    });

    // Send with bearer token but NO X-Prism-* headers
    let resp = client
        .post(format!("{url}/v1/sync/{sync_id}/devices/{target_id}/revoke"))
        .header("Authorization", format!("Bearer {admin_token}"))
        .header("X-Device-Id", &admin_id)
        .header("Content-Type", "application/json")
        .json(&revoke_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "atomic revoke without signature headers should be rejected");
}

// ─────────── Test: Replayed nonce rejected ───────────

#[tokio::test]
async fn test_replayed_nonce_rejected() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let b64 = base64::engine::general_purpose::STANDARD;

    // Build a standalone rekey request with a fixed nonce
    let rekey_body = serde_json::json!({
        "epoch": 1,
        "wrapped_keys": {
            device_id.clone(): b64.encode(b"wrapped-key-epoch1"),
        },
    });
    let rekey_body_bytes = serde_json::to_vec(&rekey_body).unwrap();
    let path = format!("/v1/sync/{sync_id}/rekey");
    let timestamp = db::now_secs().to_string();
    let fixed_nonce = uuid::Uuid::new_v4().to_string();

    let ml_dsa_kp = keys.device_secret.ml_dsa_65_keypair(&device_id).unwrap();

    let signing_data = prism_sync_relay::auth::build_request_signing_data_v2(
        "POST",
        &path,
        &sync_id,
        &device_id,
        &rekey_body_bytes,
        &timestamp,
        &fixed_nonce,
    );
    let m_prime = prism_sync_crypto::pq::build_hybrid_message_representative(
        hybrid_signature_contexts::HTTP_REQUEST,
        &signing_data,
    )
    .expect("hardcoded http request context should be <= 255 bytes");
    let hybrid_sig = prism_sync_crypto::pq::HybridSignature {
        ed25519_sig: keys.ed25519_signing_key.sign(&m_prime).to_bytes().to_vec(),
        ml_dsa_65_sig: ml_dsa_kp.sign(&m_prime),
    };
    let mut wire = vec![0x03u8];
    wire.extend_from_slice(&hybrid_sig.to_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&wire);

    // First request — should succeed
    let resp1 = client
        .post(format!("{url}{path}"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .header("Content-Type", "application/json")
        .header("X-Prism-Timestamp", &timestamp)
        .header("X-Prism-Nonce", &fixed_nonce)
        .header("X-Prism-Signature", &sig_b64)
        .body(rekey_body_bytes.clone())
        .send()
        .await
        .unwrap();
    assert!(resp1.status().is_success(), "first rekey should succeed: {}", resp1.status());

    // Second request — rekey to epoch 2 but replay the same nonce
    let rekey_body2 = serde_json::json!({
        "epoch": 2,
        "wrapped_keys": {
            device_id.clone(): b64.encode(b"wrapped-key-epoch2"),
        },
    });
    let rekey_body_bytes2 = serde_json::to_vec(&rekey_body2).unwrap();
    let signing_data2 = prism_sync_relay::auth::build_request_signing_data_v2(
        "POST",
        &path,
        &sync_id,
        &device_id,
        &rekey_body_bytes2,
        &timestamp,
        &fixed_nonce, // same nonce
    );
    let m_prime2 = prism_sync_crypto::pq::build_hybrid_message_representative(
        hybrid_signature_contexts::HTTP_REQUEST,
        &signing_data2,
    )
    .expect("hardcoded http request context should be <= 255 bytes");
    let hybrid_sig2 = prism_sync_crypto::pq::HybridSignature {
        ed25519_sig: keys.ed25519_signing_key.sign(&m_prime2).to_bytes().to_vec(),
        ml_dsa_65_sig: ml_dsa_kp.sign(&m_prime2),
    };
    let mut wire2 = vec![0x03u8];
    wire2.extend_from_slice(&hybrid_sig2.to_bytes());
    let sig_b64_2 = base64::engine::general_purpose::STANDARD.encode(&wire2);

    let resp2 = client
        .post(format!("{url}{path}"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .header("Content-Type", "application/json")
        .header("X-Prism-Timestamp", &timestamp)
        .header("X-Prism-Nonce", &fixed_nonce) // replayed nonce
        .header("X-Prism-Signature", &sig_b64_2)
        .body(rekey_body_bytes2)
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), 401, "replayed nonce should be rejected");
}

// ─────────── Test: Expired timestamp rejected ───────────

#[tokio::test]
async fn test_expired_timestamp_rejected() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let admin_id = generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;

    let target_id = generate_device_id();
    let (_target_token, _target_id_keys) = prepare_device(&db, &sync_id, &target_id).await;

    let b64 = base64::engine::general_purpose::STANDARD;
    let revoke_body = serde_json::json!({
        "new_epoch": 1,
        "remote_wipe": false,
        "wrapped_keys": {
            admin_id.clone(): b64.encode(b"fake-wrapped-key"),
        },
    });
    let revoke_body_bytes = serde_json::to_vec(&revoke_body).unwrap();
    let path = format!("/v1/sync/{sync_id}/devices/{target_id}/revoke");

    // Set timestamp 120 seconds in the past (exceeds 60s max skew)
    let old_timestamp = (db::now_secs() - 120).to_string();
    let nonce = uuid::Uuid::new_v4().to_string();
    let admin_ml_dsa_kp = admin_keys.device_secret.ml_dsa_65_keypair(&admin_id).unwrap();
    let signing_data = prism_sync_relay::auth::build_request_signing_data_v2(
        "POST",
        &path,
        &sync_id,
        &admin_id,
        &revoke_body_bytes,
        &old_timestamp,
        &nonce,
    );
    let m_prime = prism_sync_crypto::pq::build_hybrid_message_representative(
        hybrid_signature_contexts::HTTP_REQUEST,
        &signing_data,
    )
    .expect("hardcoded http request context should be <= 255 bytes");
    let hybrid_sig = prism_sync_crypto::pq::HybridSignature {
        ed25519_sig: admin_keys.ed25519_signing_key.sign(&m_prime).to_bytes().to_vec(),
        ml_dsa_65_sig: admin_ml_dsa_kp.sign(&m_prime),
    };
    let mut wire = vec![0x03u8];
    wire.extend_from_slice(&hybrid_sig.to_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&wire);

    let resp = client
        .post(format!("{url}{path}"))
        .header("Authorization", format!("Bearer {admin_token}"))
        .header("X-Device-Id", &admin_id)
        .header("Content-Type", "application/json")
        .header("X-Prism-Timestamp", &old_timestamp)
        .header("X-Prism-Nonce", &nonce)
        .header("X-Prism-Signature", &sig_b64)
        .body(revoke_body_bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "expired timestamp should be rejected");
}

// ─────────── Test: Atomic revoke remote wipe true ───────────

#[tokio::test]
async fn test_atomic_revoke_remote_wipe_true() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let admin_id = generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;

    let target_id = generate_device_id();
    let (_target_token, _target_id_keys) = prepare_device(&db, &sync_id, &target_id).await;

    let b64 = base64::engine::general_purpose::STANDARD;
    let revoke_body = serde_json::json!({
        "new_epoch": 1,
        "remote_wipe": true,
        "wrapped_keys": {
            admin_id.clone(): b64.encode(b"fake-wrapped-key"),
        },
    });
    let revoke_body_bytes = serde_json::to_vec(&revoke_body).unwrap();
    let resp = apply_signed_headers(
        client.post(format!("{url}/v1/sync/{sync_id}/devices/{target_id}/revoke")),
        &admin_keys,
        "POST",
        &format!("/v1/sync/{sync_id}/devices/{target_id}/revoke"),
        &sync_id,
        &admin_id,
        &revoke_body_bytes,
    )
    .header("Authorization", format!("Bearer {admin_token}"))
    .header("X-Device-Id", &admin_id)
    .header("Content-Type", "application/json")
    .body(revoke_body_bytes)
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);

    // Verify remote_wipe = 1 in audit log
    let remote_wipe_val = db
        .with_read_conn(|conn| {
            conn.query_row(
                "SELECT remote_wipe FROM revocation_events WHERE sync_id = ?1",
                rusqlite::params![sync_id],
                |row| row.get::<_, i64>(0),
            )
        })
        .expect("query revocation_events");
    assert_eq!(remote_wipe_val, 1, "remote_wipe should be 1 (true)");
}

// ─────────── Test: Concurrent atomic revokes — one wins ───────────

#[tokio::test]
async fn test_concurrent_atomic_revokes_one_wins() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let admin_id = generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;

    let dev2_id = generate_device_id();
    let (_dev2_token, _dev2_id_keys) = prepare_device(&db, &sync_id, &dev2_id).await;
    let dev3_id = generate_device_id();
    let (_dev3_token, _dev3_id_keys) = prepare_device(&db, &sync_id, &dev3_id).await;

    let b64 = base64::engine::general_purpose::STANDARD;

    // Build request to revoke dev2 (epoch → 1), wrapped_keys = admin + dev3
    let revoke_body_a = serde_json::json!({
        "new_epoch": 1,
        "remote_wipe": false,
        "wrapped_keys": {
            admin_id.clone(): b64.encode(b"key-a-admin"),
            dev3_id.clone(): b64.encode(b"key-a-dev3"),
        },
    });
    let revoke_body_bytes_a = serde_json::to_vec(&revoke_body_a).unwrap();
    let req_a = apply_signed_headers(
        client.post(format!("{url}/v1/sync/{sync_id}/devices/{dev2_id}/revoke")),
        &admin_keys,
        "POST",
        &format!("/v1/sync/{sync_id}/devices/{dev2_id}/revoke"),
        &sync_id,
        &admin_id,
        &revoke_body_bytes_a,
    )
    .header("Authorization", format!("Bearer {admin_token}"))
    .header("X-Device-Id", &admin_id)
    .header("Content-Type", "application/json")
    .body(revoke_body_bytes_a)
    .send();

    // Build request to revoke dev3 (epoch → 1), wrapped_keys = admin + dev2
    let revoke_body_b = serde_json::json!({
        "new_epoch": 1,
        "remote_wipe": false,
        "wrapped_keys": {
            admin_id.clone(): b64.encode(b"key-b-admin"),
            dev2_id.clone(): b64.encode(b"key-b-dev2"),
        },
    });
    let revoke_body_bytes_b = serde_json::to_vec(&revoke_body_b).unwrap();
    let req_b = apply_signed_headers(
        client.post(format!("{url}/v1/sync/{sync_id}/devices/{dev3_id}/revoke")),
        &admin_keys,
        "POST",
        &format!("/v1/sync/{sync_id}/devices/{dev3_id}/revoke"),
        &sync_id,
        &admin_id,
        &revoke_body_bytes_b,
    )
    .header("Authorization", format!("Bearer {admin_token}"))
    .header("X-Device-Id", &admin_id)
    .header("Content-Type", "application/json")
    .body(revoke_body_bytes_b)
    .send();

    // Send concurrently
    let (resp_a, resp_b) = tokio::join!(req_a, req_b);
    let status_a = resp_a.unwrap().status().as_u16();
    let status_b = resp_b.unwrap().status().as_u16();

    // Exactly one should succeed (200) and the other should fail (400 epoch mismatch or 409)
    let successes = [status_a, status_b].iter().filter(|&&s| s == 200).count();
    let failures = [status_a, status_b].iter().filter(|&&s| s == 400 || s == 409).count();
    assert_eq!(
        successes, 1,
        "exactly one revoke should succeed, got statuses: {status_a}, {status_b}"
    );
    assert_eq!(failures, 1, "exactly one revoke should fail, got statuses: {status_a}, {status_b}");
}

// ─────────── Test: Standalone rekey rejected when needs_rekey ───────────

#[tokio::test]
async fn test_standalone_rekey_rejected_when_needs_rekey() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let admin_id = generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;

    let dev2_id = generate_device_id();
    let (_dev2_token, _dev2_id_keys) = prepare_device(&db, &sync_id, &dev2_id).await;

    // Manually set needs_rekey = true
    db.with_conn(|conn| db::set_needs_rekey(conn, &sync_id, true)).expect("set needs_rekey");

    let b64 = base64::engine::general_purpose::STANDARD;
    let rekey_body = serde_json::json!({
        "epoch": 1,
        "wrapped_keys": {
            admin_id.clone(): b64.encode(b"wrapped-key"),
            dev2_id.clone(): b64.encode(b"wrapped-key-dev2"),
        },
    });
    let rekey_body_bytes = serde_json::to_vec(&rekey_body).unwrap();
    let resp = apply_signed_headers(
        client.post(format!("{url}/v1/sync/{sync_id}/rekey")),
        &admin_keys,
        "POST",
        &format!("/v1/sync/{sync_id}/rekey"),
        &sync_id,
        &admin_id,
        &rekey_body_bytes,
    )
    .header("Authorization", format!("Bearer {admin_token}"))
    .header("X-Device-Id", &admin_id)
    .header("Content-Type", "application/json")
    .body(rekey_body_bytes)
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 409, "standalone rekey should be rejected when needs_rekey is true");
}

// ─── Test: Standalone rekey allowed after atomic revoke clears needs_rekey ───

#[tokio::test]
async fn test_standalone_rekey_allowed_after_atomic_revoke_clears_needs_rekey() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let admin_id = generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;

    let dev2_id = generate_device_id();
    let (_dev2_token, _dev2_id_keys) = prepare_device(&db, &sync_id, &dev2_id).await;
    let dev3_id = generate_device_id();
    let (_dev3_token, _dev3_id_keys) = prepare_device(&db, &sync_id, &dev3_id).await;

    let b64 = base64::engine::general_purpose::STANDARD;

    // Atomic revoke dev2 (epoch → 1), wrapped_keys for admin + dev3
    let revoke_body = serde_json::json!({
        "new_epoch": 1,
        "remote_wipe": false,
        "wrapped_keys": {
            admin_id.clone(): b64.encode(b"key-epoch1-admin"),
            dev3_id.clone(): b64.encode(b"key-epoch1-dev3"),
        },
    });
    let revoke_body_bytes = serde_json::to_vec(&revoke_body).unwrap();
    let revoke_resp = apply_signed_headers(
        client.post(format!("{url}/v1/sync/{sync_id}/devices/{dev2_id}/revoke")),
        &admin_keys,
        "POST",
        &format!("/v1/sync/{sync_id}/devices/{dev2_id}/revoke"),
        &sync_id,
        &admin_id,
        &revoke_body_bytes,
    )
    .header("Authorization", format!("Bearer {admin_token}"))
    .header("X-Device-Id", &admin_id)
    .header("Content-Type", "application/json")
    .body(revoke_body_bytes)
    .send()
    .await
    .unwrap();
    assert_eq!(revoke_resp.status(), 200, "atomic revoke should succeed");

    // Standalone rekey to epoch 2 should now succeed (needs_rekey cleared by atomic revoke)
    let rekey_body = serde_json::json!({
        "epoch": 2,
        "wrapped_keys": {
            admin_id.clone(): b64.encode(b"key-epoch2-admin"),
            dev3_id.clone(): b64.encode(b"key-epoch2-dev3"),
        },
    });
    let rekey_body_bytes = serde_json::to_vec(&rekey_body).unwrap();
    let rekey_resp = apply_signed_headers(
        client.post(format!("{url}/v1/sync/{sync_id}/rekey")),
        &admin_keys,
        "POST",
        &format!("/v1/sync/{sync_id}/rekey"),
        &sync_id,
        &admin_id,
        &rekey_body_bytes,
    )
    .header("Authorization", format!("Bearer {admin_token}"))
    .header("X-Device-Id", &admin_id)
    .header("Content-Type", "application/json")
    .body(rekey_body_bytes)
    .send()
    .await
    .unwrap();
    assert!(
        rekey_resp.status().is_success(),
        "standalone rekey after atomic revoke should succeed: {}",
        rekey_resp.status()
    );
}

// ─────────── Test: Snapshot body limit allows large upload ───────────

#[tokio::test]
async fn test_snapshot_body_limit_allows_large_upload() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    // 3MB payload
    let big_payload = vec![0xAA_u8; 3 * 1024 * 1024];

    // PUT 3MB snapshot — should succeed (snapshot route has 25MB limit)
    let snap_path = format!("/v1/sync/{sync_id}/snapshot");
    let snapshot_resp = apply_signed_headers(
        client
            .put(format!("{url}/v1/sync/{sync_id}/snapshot"))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Device-Id", &device_id)
            .header("X-Server-Seq-At", "1"),
        &keys,
        "PUT",
        &snap_path,
        &sync_id,
        &device_id,
        &big_payload,
    )
    .body(big_payload.clone())
    .send()
    .await
    .unwrap();
    assert!(
        snapshot_resp.status().is_success(),
        "3MB snapshot should be accepted, got {}",
        snapshot_resp.status()
    );

    // POST 3MB to changes — should fail 413 (default body limit is 2MB)
    let changes_path = format!("/v1/sync/{sync_id}/changes");
    let changes_resp = apply_signed_headers(
        client
            .put(format!("{url}/v1/sync/{sync_id}/changes"))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Device-Id", &device_id),
        &keys,
        "PUT",
        &changes_path,
        &sync_id,
        &device_id,
        &big_payload,
    )
    .body(big_payload)
    .send()
    .await
    .unwrap();
    assert_eq!(changes_resp.status(), 413, "3MB changes body should exceed default limit");
}

// ─── Test: Bearer token without signature rejected on destructive endpoints ───

#[tokio::test]
async fn test_bearer_token_without_signature_rejected_on_destructive_endpoints() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let admin_id = generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;

    let target_id = generate_device_id();
    let (_target_token, _target_id_keys) = prepare_device(&db, &sync_id, &target_id).await;

    let b64 = base64::engine::general_purpose::STANDARD;

    // 1. POST atomic revoke without signature headers
    let revoke_body = serde_json::json!({
        "new_epoch": 1,
        "remote_wipe": false,
        "wrapped_keys": {
            admin_id.clone(): b64.encode(b"fake-key"),
        },
    });
    let revoke_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/devices/{target_id}/revoke"))
        .header("Authorization", format!("Bearer {admin_token}"))
        .header("X-Device-Id", &admin_id)
        .header("Content-Type", "application/json")
        .json(&revoke_body)
        .send()
        .await
        .unwrap();
    assert_eq!(revoke_resp.status(), 400, "atomic revoke without signature should return 400");

    // 2. POST rekey without signature headers
    let rekey_body = serde_json::json!({
        "epoch": 1,
        "wrapped_keys": {
            admin_id.clone(): b64.encode(b"fake-key"),
            target_id.clone(): b64.encode(b"fake-key-target"),
        },
    });
    let rekey_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/rekey"))
        .header("Authorization", format!("Bearer {admin_token}"))
        .header("X-Device-Id", &admin_id)
        .header("Content-Type", "application/json")
        .json(&rekey_body)
        .send()
        .await
        .unwrap();
    assert_eq!(rekey_resp.status(), 400, "rekey without signature should return 400");

    // 3. DELETE sync group without signature headers
    let delete_resp = client
        .delete(format!("{url}/v1/sync/{sync_id}"))
        .header("Authorization", format!("Bearer {admin_token}"))
        .header("X-Device-Id", &admin_id)
        .send()
        .await
        .unwrap();
    assert_eq!(delete_resp.status(), 400, "delete sync group without signature should return 400");
}

// ───────────────── Registration access control tests ──────────────────

fn default_test_config() -> Config {
    Config {
        port: 0,
        db_path: ":memory:".into(),
        nonce_expiry_secs: 60,
        session_expiry_secs: 3600,
        first_device_pow_difficulty_bits: 0,
        invite_ttl_secs: 86400,
        sync_inactive_ttl_secs: 7_776_000,
        stale_device_secs: 2_592_000,
        cleanup_interval_secs: 3600,
        max_unpruned_batches: 10_000,
        metrics_token: None,
        nonce_rate_limit: 100,
        nonce_rate_window_secs: 60,
        revoke_rate_limit: 100,
        revoke_rate_window_secs: 60,
        ws_upgrade_rate_limit: 20,
        ws_upgrade_rate_window_secs: 60,
        trusted_proxy_cidrs: vec![],
        signed_request_max_skew_secs: 60,
        signed_request_nonce_window_secs: 120,
        snapshot_default_ttl_secs: 86400,
        revoked_tombstone_retention_secs: 2_592_000,
        reader_pool_size: 2,
        node_exporter_url: None,
        first_device_apple_attestation_enabled: false,
        first_device_apple_attestation_trust_roots_pem: vec![],
        first_device_apple_attestation_allowed_app_ids: vec![],
        first_device_android_attestation_enabled: true,
        first_device_android_attestation_trust_roots_pem: vec![],
        grapheneos_verified_boot_key_allowlist: vec![],
        registration_token: None,
        registration_enabled: true,
        pairing_session_ttl_secs: 300,
        pairing_session_rate_limit: 100,
        pairing_session_max_payload_bytes: 32768,
        sharing_init_ttl_secs: 604800,
        sharing_init_max_payload_bytes: 65536,
        sharing_identity_max_bytes: 8192,
        sharing_prekey_max_bytes: 4096,
        sharing_fetch_rate_limit: 100,
        sharing_init_rate_limit: 100,
        sharing_init_max_pending: 50,
        prekey_upload_max_age_secs: 604800,
        prekey_serve_max_age_secs: 2_592_000,
        prekey_max_future_skew_secs: 300,
        min_signature_version: 3,
        media_storage_path: std::env::temp_dir()
            .join(format!("prism_test_media_{}", uuid::Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string(),
        media_max_file_bytes: 10_485_760,
        media_quota_bytes_per_group: 1_073_741_824,
        media_retention_days: 90,
        media_upload_rate_limit: 100,
        media_upload_rate_window_secs: 60,
        media_orphan_cleanup_secs: 86400,
        gif_provider_mode: prism_sync_relay::GifProviderMode::Disabled,
        gif_public_base_url: None,
        gif_prism_base_url: None,
        gif_api_base_url: "https://api.klipy.com".into(),
        gif_api_key: None,
        gif_http_timeout_secs: 15,
        gif_request_rate_limit: 20,
        gif_request_rate_window_secs: 60,
        gif_query_max_len: 200,
    }
}

#[tokio::test]
async fn test_open_mode_no_token_configured() {
    let config = default_test_config();
    let (url, _server, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let test_keys = TestDeviceKeys::generate(&device_id);
    let signing_key = &test_keys.ed25519_signing_key;

    // Fetch nonce — no token header needed
    let nonce = fetch_nonce(&client, &url, &sync_id).await;
    assert!(!nonce.is_empty());

    // Full registration succeeds without any token
    let challenge_sig_ml_dsa_kp = test_keys.device_secret.ml_dsa_65_keypair(&device_id).unwrap();

    let challenge_sig =
        sign_hybrid_challenge(signing_key, &challenge_sig_ml_dsa_kp, &sync_id, &device_id, &nonce);

    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_id,
            "signing_public_key": hex::encode(signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(test_keys.x25519_pk),
            "ml_dsa_65_public_key": hex::encode(&test_keys.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&test_keys.ml_kem_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
        }))
        .send()
        .await
        .unwrap();
    assert!(
        register_resp.status().is_success(),
        "open mode registration should succeed: {}",
        register_resp.status()
    );
}

#[tokio::test]
async fn test_token_gated_correct_token() {
    let mut config = default_test_config();
    config.registration_token = Some("secret-token-123".to_string());
    let (url, _server, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let test_keys = TestDeviceKeys::generate(&device_id);
    let signing_key = &test_keys.ed25519_signing_key;

    // Fetch nonce with correct token
    let nonce_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
        .header("X-Registration-Token", "secret-token-123")
        .send()
        .await
        .unwrap();
    assert_eq!(nonce_resp.status(), 200);
    let nonce_json: Value = nonce_resp.json().await.unwrap();
    let nonce = nonce_json["nonce"].as_str().unwrap();

    // Register with correct token
    let challenge_sig_ml_dsa_kp = test_keys.device_secret.ml_dsa_65_keypair(&device_id).unwrap();

    let challenge_sig =
        sign_hybrid_challenge(signing_key, &challenge_sig_ml_dsa_kp, &sync_id, &device_id, nonce);

    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .header("X-Registration-Token", "secret-token-123")
        .json(&serde_json::json!({
            "device_id": device_id,
            "signing_public_key": hex::encode(signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(test_keys.x25519_pk),
            "ml_dsa_65_public_key": hex::encode(&test_keys.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&test_keys.ml_kem_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
        }))
        .send()
        .await
        .unwrap();
    assert!(
        register_resp.status().is_success(),
        "token-gated registration with correct token should succeed: {}",
        register_resp.status()
    );
}

#[tokio::test]
async fn test_token_gated_wrong_token() {
    let mut config = default_test_config();
    config.registration_token = Some("secret-token-123".to_string());
    let (url, _server, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // Nonce endpoint with wrong token should return 403
    let nonce_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
        .header("X-Registration-Token", "wrong-token")
        .send()
        .await
        .unwrap();
    assert_eq!(nonce_resp.status(), 403, "wrong token should return 403");

    // Register endpoint with wrong token should also return 403
    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .header("X-Registration-Token", "wrong-token")
        .json(&serde_json::json!({
            "device_id": "fake",
            "signing_public_key": hex::encode([0u8; 32]),
            "x25519_public_key": hex::encode([0u8; 32]),
            "registration_challenge": hex::encode([0u8; 64]),
            "nonce": "fake",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(register_resp.status(), 403, "wrong token on register should return 403");
}

#[tokio::test]
async fn test_token_gated_missing_token() {
    let mut config = default_test_config();
    config.registration_token = Some("secret-token-123".to_string());
    let (url, _server, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // Nonce endpoint with no token header should return 403
    let nonce_resp =
        client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
    assert_eq!(nonce_resp.status(), 403, "missing token should return 403");

    // Register endpoint with no token header should also return 403
    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": "fake",
            "signing_public_key": hex::encode([0u8; 32]),
            "x25519_public_key": hex::encode([0u8; 32]),
            "registration_challenge": hex::encode([0u8; 64]),
            "nonce": "fake",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(register_resp.status(), 403, "missing token on register should return 403");
}

#[tokio::test]
async fn test_registration_disabled() {
    let mut config = default_test_config();
    config.registration_enabled = false;
    let (url, _server, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // Nonce endpoint should return 403 when registration is disabled
    let nonce_resp =
        client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
    assert_eq!(
        nonce_resp.status(),
        403,
        "disabled registration should return 403 on nonce endpoint"
    );

    // Register endpoint should also return 403
    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": "fake",
            "signing_public_key": hex::encode([0u8; 32]),
            "x25519_public_key": hex::encode([0u8; 32]),
            "registration_challenge": hex::encode([0u8; 64]),
            "nonce": "fake",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        register_resp.status(),
        403,
        "disabled registration should return 403 on register endpoint"
    );
}

#[tokio::test]
async fn test_nonce_endpoint_checks_token() {
    let mut config = default_test_config();
    config.registration_token = Some("my-secret".to_string());
    let (url, _server, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // Without token — 403
    let resp = client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
    assert_eq!(resp.status(), 403, "nonce without token should be 403");

    // With wrong token — 403
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
        .header("X-Registration-Token", "not-my-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "nonce with wrong token should be 403");

    // With correct token — 200
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
        .header("X-Registration-Token", "my-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "nonce with correct token should be 200");
}
