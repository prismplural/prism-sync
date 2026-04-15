//! End-to-end tests for sharing identity, prekey, and init-payload routes.

mod common;

use base64::Engine;
use rand::RngCore;
use reqwest::Client;
use serde_json::Value;

use rusqlite::params;

use prism_sync_relay::{
    config::Config,
    db::{self, Database},
};

use common::*;

/// Generate a 32-char hex sharing_id.
fn generate_sharing_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

const ML_DSA_65_PK_LEN: usize = 1952;

fn b64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn encode_test_identity_bundle(
    sharing_id: &str,
    identity_generation: u32,
    signature_payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        1 + 2 + sharing_id.len() + 4 + 32 + 2 + ML_DSA_65_PK_LEN + 4 + signature_payload.len(),
    );
    out.push(0x01);
    out.extend_from_slice(&(sharing_id.len() as u16).to_be_bytes());
    out.extend_from_slice(sharing_id.as_bytes());
    out.extend_from_slice(&identity_generation.to_be_bytes());
    out.extend_from_slice(&[0xAA; 32]);
    out.extend_from_slice(&(ML_DSA_65_PK_LEN as u16).to_be_bytes());
    out.extend_from_slice(&vec![0xBB; ML_DSA_65_PK_LEN]);
    out.extend_from_slice(&(signature_payload.len() as u32).to_be_bytes());
    out.extend_from_slice(signature_payload);
    out
}

/// Helper: publish identity bundle for a device and return the sharing_id.
#[allow(clippy::too_many_arguments)]
async fn publish_identity(
    client: &Client,
    url: &str,
    token: &str,
    keys: &TestDeviceKeys,
    sync_id: &str,
    device_id: &str,
    sharing_id: &str,
    bundle: &[u8],
) -> reqwest::Response {
    publish_identity_with_generation(
        client, url, token, keys, sync_id, device_id, sharing_id, 0, bundle,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn publish_identity_with_generation(
    client: &Client,
    url: &str,
    token: &str,
    keys: &TestDeviceKeys,
    sync_id: &str,
    device_id: &str,
    sharing_id: &str,
    identity_generation: u32,
    bundle: &[u8],
) -> reqwest::Response {
    let identity_bundle = encode_test_identity_bundle(sharing_id, identity_generation, bundle);
    let body = serde_json::json!({
        "sharing_id": sharing_id,
        "identity_bundle": b64_encode(&identity_bundle),
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let builder = client
        .put(format!("{url}/v1/sharing/identity"))
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(body_bytes.clone());

    let builder = apply_signed_headers(
        builder,
        keys,
        "PUT",
        "/v1/sharing/identity",
        sync_id,
        device_id,
        &body_bytes,
    );
    builder.send().await.unwrap()
}

#[allow(clippy::too_many_arguments)]
async fn publish_prekey(
    client: &Client,
    url: &str,
    token: &str,
    keys: &TestDeviceKeys,
    sync_id: &str,
    device_id: &str,
    sharing_id: &str,
    prekey_id: &str,
    bundle: &[u8],
) -> reqwest::Response {
    let body = serde_json::json!({
        "sharing_id": sharing_id,
        "device_id": device_id,
        "prekey_id": prekey_id,
        "prekey_bundle": b64_encode(bundle),
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let builder = client
        .put(format!("{url}/v1/sharing/prekey"))
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(body_bytes.clone());

    let builder = apply_signed_headers(
        builder,
        keys,
        "PUT",
        "/v1/sharing/prekey",
        sync_id,
        device_id,
        &body_bytes,
    );
    builder.send().await.unwrap()
}

#[tokio::test]
async fn test_publish_identity_and_fetch_bundle() {
    let (url, _handle, _db) = start_test_relay().await;
    let client = Client::new();

    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;
    let sharing_id = generate_sharing_id();
    let identity_payload = b"test-identity-bundle";
    let identity_bundle = encode_test_identity_bundle(&sharing_id, 0, identity_payload);
    let prekey_bundle = b"test-prekey-bundle";

    // 1. Publish identity
    let resp = publish_identity(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id,
        identity_payload,
    )
    .await;
    assert_eq!(resp.status(), 204, "publish identity should return 204");

    // 2. Publish prekey
    let resp = publish_prekey(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id,
        "pk1",
        prekey_bundle,
    )
    .await;
    assert_eq!(resp.status(), 204, "publish prekey should return 204");

    // 3. Fetch bundle (public route)
    let resp = client
        .get(format!("{url}/v1/sharing/{sharing_id}/bundle"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["device_id"].as_str().unwrap(), device_id);
    assert_eq!(body["prekey_id"].as_str().unwrap(), "pk1");
    let fetched_identity = base64::engine::general_purpose::STANDARD
        .decode(body["identity_bundle"].as_str().unwrap())
        .unwrap();
    assert_eq!(fetched_identity, identity_bundle);
    let fetched_prekey = base64::engine::general_purpose::STANDARD
        .decode(body["signed_prekey"].as_str().unwrap())
        .unwrap();
    assert_eq!(fetched_prekey, prekey_bundle);
}

#[tokio::test]
async fn test_sharing_id_conflict_different_sync_group() {
    let (url, _handle, _db) = start_test_relay().await;
    let client = Client::new();

    let sync_id_1 = generate_sync_id();
    let device_id_1 = generate_device_id();
    let keys_1 = TestDeviceKeys::generate(&device_id_1);
    let token_1 = register_device(&client, &url, &sync_id_1, &device_id_1, &keys_1).await;

    let sync_id_2 = generate_sync_id();
    let device_id_2 = generate_device_id();
    let keys_2 = TestDeviceKeys::generate(&device_id_2);
    let token_2 = register_device(&client, &url, &sync_id_2, &device_id_2, &keys_2).await;

    let sharing_id = generate_sharing_id();

    // First group claims sharing_id
    let resp = publish_identity(
        &client,
        &url,
        &token_1,
        &keys_1,
        &sync_id_1,
        &device_id_1,
        &sharing_id,
        b"bundle1",
    )
    .await;
    assert_eq!(resp.status(), 204);

    // Second group tries same sharing_id -> 409
    let resp = publish_identity(
        &client,
        &url,
        &token_2,
        &keys_2,
        &sync_id_2,
        &device_id_2,
        &sharing_id,
        b"bundle2",
    )
    .await;
    assert_eq!(
        resp.status(),
        409,
        "different sync group with same sharing_id should 409"
    );
}

#[tokio::test]
async fn test_same_sync_group_cannot_switch_sharing_id() {
    let (url, _handle, _db) = start_test_relay().await;
    let client = Client::new();

    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let sharing_id_1 = generate_sharing_id();
    let sharing_id_2 = generate_sharing_id();

    // Claim sharing_id_1
    let resp = publish_identity(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id_1,
        b"bundle",
    )
    .await;
    assert_eq!(resp.status(), 204);

    // Try to switch to sharing_id_2 -> 409
    let resp = publish_identity(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id_2,
        b"bundle",
    )
    .await;
    assert_eq!(resp.status(), 409, "switching sharing_id should 409");
}

#[tokio::test]
async fn test_identity_publish_rejects_generation_rollback() {
    let (url, _handle, _db) = start_test_relay().await;
    let client = Client::new();

    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;
    let sharing_id = generate_sharing_id();

    let accepted_bundle = encode_test_identity_bundle(&sharing_id, 2, b"sig-v2");
    let resp = publish_identity_with_generation(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id,
        1,
        b"sig-v1",
    )
    .await;
    assert_eq!(resp.status(), 204);

    let resp = publish_identity_with_generation(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id,
        2,
        b"sig-v2",
    )
    .await;
    assert_eq!(resp.status(), 204);

    let resp = publish_identity_with_generation(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id,
        1,
        b"sig-v1-rollback",
    )
    .await;
    assert_eq!(resp.status(), 409, "rollback publish should 409");

    let resp = publish_prekey(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id,
        "pk1",
        b"prekey",
    )
    .await;
    assert_eq!(resp.status(), 204);

    let resp = client
        .get(format!("{url}/v1/sharing/{sharing_id}/bundle"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let fetched_identity = base64::engine::general_purpose::STANDARD
        .decode(body["identity_bundle"].as_str().unwrap())
        .unwrap();
    assert_eq!(fetched_identity, accepted_bundle);
}

#[tokio::test]
async fn test_identity_delete_preserves_generation_floor_and_bundle_hash() {
    let (url, _handle, _db) = start_test_relay().await;
    let client = Client::new();

    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;
    let sharing_id = generate_sharing_id();

    let resp = publish_identity_with_generation(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id,
        3,
        b"sig-v3",
    )
    .await;
    assert_eq!(resp.status(), 204);

    let builder = client
        .delete(format!("{url}/v1/sharing/identity"))
        .header("Authorization", format!("Bearer {token}"));
    let builder = apply_signed_headers(
        builder,
        &keys,
        "DELETE",
        "/v1/sharing/identity",
        &sync_id,
        &device_id,
        &[],
    );
    let resp = builder.send().await.unwrap();
    assert_eq!(resp.status(), 204);

    let resp = publish_identity_with_generation(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id,
        2,
        b"sig-v2",
    )
    .await;
    assert_eq!(resp.status(), 409, "deleted identity must still reject rollback");

    let resp = publish_identity_with_generation(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id,
        3,
        b"sig-v3-mutated",
    )
    .await;
    assert_eq!(
        resp.status(),
        409,
        "equal-generation republish must be byte-identical to prior identity"
    );

    let resp = publish_identity_with_generation(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id,
        3,
        b"sig-v3",
    )
    .await;
    assert_eq!(resp.status(), 204, "same bundle at same generation should replay cleanly");
}

#[tokio::test]
async fn test_fetch_bundle_returns_most_recent_active_prekey() {
    let (url, _handle, db) = start_test_relay().await;
    let client = Client::new();

    let sync_id = generate_sync_id();
    let device_id_1 = generate_device_id();
    let keys_1 = TestDeviceKeys::generate(&device_id_1);
    let token_1 = register_device(&client, &url, &sync_id, &device_id_1, &keys_1).await;

    // Register a second device in the same sync group (via direct DB)
    let device_id_2 = generate_device_id();
    let (_token_2, _keys_2) = prepare_device(&db, &sync_id, &device_id_2).await;

    let sharing_id = generate_sharing_id();

    // Publish identity from device 1
    let resp = publish_identity(
        &client,
        &url,
        &token_1,
        &keys_1,
        &sync_id,
        &device_id_1,
        &sharing_id,
        b"identity",
    )
    .await;
    assert_eq!(resp.status(), 204);

    // Insert prekeys directly with controlled timestamps to ensure ordering
    let sid2 = sharing_id.clone();
    let did1 = device_id_1.clone();
    let did2 = device_id_2.clone();
    db.with_conn(move |conn| {
        let now = db::now_secs();
        // Device 1 prekey: older timestamp
        db::upsert_sharing_prekey(conn, &sid2, &did1, "pk-old", b"prekey-old", now - 100)?;
        // Device 2 prekey: newer timestamp
        db::upsert_sharing_prekey(conn, &sid2, &did2, "pk-new", b"prekey-new", now)?;
        Ok(())
    })
    .unwrap();

    // Fetch bundle should return the most recent prekey (device 2)
    let resp = client
        .get(format!("{url}/v1/sharing/{sharing_id}/bundle"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["device_id"].as_str().unwrap(), device_id_2);
    assert_eq!(body["prekey_id"].as_str().unwrap(), "pk-new");
}

#[tokio::test]
async fn test_fetch_nonexistent_sharing_id_returns_404() {
    let (url, _handle, _db) = start_test_relay().await;
    let client = Client::new();
    let sharing_id = generate_sharing_id();

    let resp = client
        .get(format!("{url}/v1/sharing/{sharing_id}/bundle"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_sharing_init_upload_fetch_consume() {
    let (url, _handle, _db) = start_test_relay().await;
    let client = Client::new();

    // Set up sender
    let sender_sync_id = generate_sync_id();
    let sender_device_id = generate_device_id();
    let sender_keys = TestDeviceKeys::generate(&sender_device_id);
    let sender_token = register_device(
        &client,
        &url,
        &sender_sync_id,
        &sender_device_id,
        &sender_keys,
    )
    .await;
    let sender_sharing_id = generate_sharing_id();

    // Bind sender's sharing_id
    let resp = publish_identity(
        &client,
        &url,
        &sender_token,
        &sender_keys,
        &sender_sync_id,
        &sender_device_id,
        &sender_sharing_id,
        b"sender-identity",
    )
    .await;
    assert_eq!(resp.status(), 204);

    // Set up recipient
    let recipient_sync_id = generate_sync_id();
    let recipient_device_id = generate_device_id();
    let recipient_keys = TestDeviceKeys::generate(&recipient_device_id);
    let recipient_token = register_device(
        &client,
        &url,
        &recipient_sync_id,
        &recipient_device_id,
        &recipient_keys,
    )
    .await;
    let recipient_sharing_id = generate_sharing_id();

    // Bind recipient's sharing_id
    let resp = publish_identity(
        &client,
        &url,
        &recipient_token,
        &recipient_keys,
        &recipient_sync_id,
        &recipient_device_id,
        &recipient_sharing_id,
        b"recipient-identity",
    )
    .await;
    assert_eq!(resp.status(), 204);

    // Upload sharing-init
    let init_id = generate_sharing_id(); // 32 hex chars
    let payload = b"encrypted-sharing-init-payload";
    let body = serde_json::json!({
        "init_id": init_id,
        "recipient_id": recipient_sharing_id,
        "sender_id": sender_sharing_id,
        "payload": b64_encode(payload),
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let builder = client
        .post(format!("{url}/v1/sharing/init"))
        .header("Authorization", format!("Bearer {sender_token}"))
        .header("Content-Type", "application/json")
        .body(body_bytes.clone());
    let builder = apply_signed_headers(
        builder,
        &sender_keys,
        "POST",
        "/v1/sharing/init",
        &sender_sync_id,
        &sender_device_id,
        &body_bytes,
    );
    let resp = builder.send().await.unwrap();
    assert_eq!(resp.status(), 201, "sharing-init should return 201");

    // Fetch pending (atomically consumes)
    let builder = client
        .get(format!("{url}/v1/sharing/init/pending"))
        .header("Authorization", format!("Bearer {recipient_token}"));
    let builder = apply_signed_headers(
        builder,
        &recipient_keys,
        "GET",
        "/v1/sharing/init/pending",
        &recipient_sync_id,
        &recipient_device_id,
        &[],
    );
    let resp = builder.send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let arr = body["payloads"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["init_id"].as_str().unwrap(), init_id);
    assert_eq!(arr[0]["sender_id"].as_str().unwrap(), sender_sharing_id);
    let fetched_payload = base64::engine::general_purpose::STANDARD
        .decode(arr[0]["payload"].as_str().unwrap())
        .unwrap();
    assert_eq!(fetched_payload, payload);

    // Re-fetch should return empty (consumed)
    let builder = client
        .get(format!("{url}/v1/sharing/init/pending"))
        .header("Authorization", format!("Bearer {recipient_token}"));
    let builder = apply_signed_headers(
        builder,
        &recipient_keys,
        "GET",
        "/v1/sharing/init/pending",
        &recipient_sync_id,
        &recipient_device_id,
        &[],
    );
    let resp = builder.send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["payloads"].as_array().unwrap().len(),
        0,
        "consumed inits should not be returned"
    );
}

#[tokio::test]
async fn test_duplicate_init_id_returns_409() {
    let (url, _handle, _db) = start_test_relay().await;
    let client = Client::new();

    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;
    let sharing_id = generate_sharing_id();

    // Bind sharing_id
    let resp = publish_identity(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id,
        b"identity",
    )
    .await;
    assert_eq!(resp.status(), 204);

    let init_id = generate_sharing_id();
    let recipient_id = generate_sharing_id();

    let send_init = |init_id: &str| {
        let body = serde_json::json!({
            "init_id": init_id,
            "recipient_id": recipient_id,
            "sender_id": sharing_id,
            "payload": b64_encode(b"data"),
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let builder = client
            .post(format!("{url}/v1/sharing/init"))
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(body_bytes.clone());
        apply_signed_headers(
            builder,
            &keys,
            "POST",
            "/v1/sharing/init",
            &sync_id,
            &device_id,
            &body_bytes,
        )
        .send()
    };

    let resp = send_init(&init_id).await.unwrap();
    assert_eq!(resp.status(), 201);

    let resp = send_init(&init_id).await.unwrap();
    assert_eq!(resp.status(), 409, "duplicate init_id should return 409");
}

#[tokio::test]
async fn test_max_pending_limit_enforced() {
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
        nonce_rate_limit: 100,
        nonce_rate_window_secs: 60,
        revoke_rate_limit: 100,
        revoke_rate_window_secs: 60,
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
        pairing_session_rate_limit: 5,
        pairing_session_max_payload_bytes: 65536,
        sharing_init_ttl_secs: 604800,
        sharing_init_max_payload_bytes: 65536,
        sharing_identity_max_bytes: 8192,
        sharing_prekey_max_bytes: 4096,
        sharing_fetch_rate_limit: 100,
        sharing_init_rate_limit: 1000,
        sharing_init_max_pending: 3, // very low limit for testing
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

    let (url, _handle, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();

    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;
    let sharing_id = generate_sharing_id();

    let resp = publish_identity(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id,
        b"identity",
    )
    .await;
    assert_eq!(resp.status(), 204);

    let recipient_id = generate_sharing_id();

    for i in 0..3 {
        let init_id = generate_sharing_id();
        let body = serde_json::json!({
            "init_id": init_id,
            "recipient_id": recipient_id,
            "sender_id": sharing_id,
            "payload": b64_encode(b"data"),
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let builder = client
            .post(format!("{url}/v1/sharing/init"))
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(body_bytes.clone());
        let builder = apply_signed_headers(
            builder,
            &keys,
            "POST",
            "/v1/sharing/init",
            &sync_id,
            &device_id,
            &body_bytes,
        );
        let resp = builder.send().await.unwrap();
        assert_eq!(resp.status(), 201, "init {i} should succeed");
    }

    // 4th should fail with 429
    let init_id = generate_sharing_id();
    let body = serde_json::json!({
        "init_id": init_id,
        "recipient_id": recipient_id,
        "sender_id": sharing_id,
        "payload": b64_encode(b"data"),
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let builder = client
        .post(format!("{url}/v1/sharing/init"))
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(body_bytes.clone());
    let builder = apply_signed_headers(
        builder,
        &keys,
        "POST",
        "/v1/sharing/init",
        &sync_id,
        &device_id,
        &body_bytes,
    );
    let resp = builder.send().await.unwrap();
    assert_eq!(
        resp.status(),
        429,
        "exceeding max_pending should return 429"
    );
}

#[tokio::test]
async fn test_delete_identity_removes_identity_and_prekeys() {
    let (url, _handle, _db) = start_test_relay().await;
    let client = Client::new();

    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;
    let sharing_id = generate_sharing_id();

    // Publish identity + prekey
    let resp = publish_identity(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id,
        b"identity",
    )
    .await;
    assert_eq!(resp.status(), 204);

    let resp = publish_prekey(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id,
        "pk1",
        b"prekey",
    )
    .await;
    assert_eq!(resp.status(), 204);

    // Verify bundle is available
    let resp = client
        .get(format!("{url}/v1/sharing/{sharing_id}/bundle"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Delete identity
    let builder = client
        .delete(format!("{url}/v1/sharing/identity"))
        .header("Authorization", format!("Bearer {token}"));
    let builder = apply_signed_headers(
        builder,
        &keys,
        "DELETE",
        "/v1/sharing/identity",
        &sync_id,
        &device_id,
        &[],
    );
    let resp = builder.send().await.unwrap();
    assert_eq!(resp.status(), 204);

    // Bundle should now be 404
    let resp = client
        .get(format!("{url}/v1/sharing/{sharing_id}/bundle"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_delete_identity_preserves_generation_floor_for_identical_republish() {
    let (url, _handle, _db) = start_test_relay().await;
    let client = Client::new();

    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;
    let sharing_id = generate_sharing_id();

    let resp = publish_identity_with_generation(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id,
        3,
        b"sig-v3",
    )
    .await;
    assert_eq!(resp.status(), 204);

    let builder = client
        .delete(format!("{url}/v1/sharing/identity"))
        .header("Authorization", format!("Bearer {token}"));
    let builder = apply_signed_headers(
        builder,
        &keys,
        "DELETE",
        "/v1/sharing/identity",
        &sync_id,
        &device_id,
        &[],
    );
    let resp = builder.send().await.unwrap();
    assert_eq!(resp.status(), 204);

    let resp = publish_identity_with_generation(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id,
        2,
        b"sig-v2-rollback",
    )
    .await;
    assert_eq!(resp.status(), 409, "delete should not reset generation floor");

    let resp = publish_identity_with_generation(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id,
        3,
        b"sig-v3",
    )
    .await;
    assert_eq!(
        resp.status(),
        204,
        "same bundle at the same generation should be republishable after delete"
    );
}

#[tokio::test]
async fn test_cleanup_removes_expired_and_consumed_sharing_inits() {
    let db = Database::in_memory().expect("in-memory db");
    db.with_conn(|conn| {
        let now = db::now_secs();

        // Create an expired payload
        conn.execute(
            "INSERT INTO sharing_init_payloads
             (init_id, recipient_id, sender_id, payload, created_at, consumed_at, expires_at)
             VALUES ('expired1', 'r1', 's1', X'AA', ?1, NULL, ?2)",
            rusqlite::params![now - 100, now - 1],
        )?;

        // Create a consumed payload older than 24h
        conn.execute(
            "INSERT INTO sharing_init_payloads
             (init_id, recipient_id, sender_id, payload, created_at, consumed_at, expires_at)
             VALUES ('consumed1', 'r1', 's1', X'BB', ?1, ?2, ?3)",
            rusqlite::params![now - 200000, now - 86401, now + 100000],
        )?;

        // Create a still-valid unconsumed payload
        conn.execute(
            "INSERT INTO sharing_init_payloads
             (init_id, recipient_id, sender_id, payload, created_at, consumed_at, expires_at)
             VALUES ('valid1', 'r1', 's1', X'CC', ?1, NULL, ?2)",
            rusqlite::params![now, now + 86400],
        )?;

        // Create a recently consumed payload (should NOT be cleaned)
        conn.execute(
            "INSERT INTO sharing_init_payloads
             (init_id, recipient_id, sender_id, payload, created_at, consumed_at, expires_at)
             VALUES ('recent_consumed', 'r1', 's1', X'DD', ?1, ?2, ?3)",
            rusqlite::params![now - 100, now - 100, now + 86400],
        )?;

        let cleaned = db::cleanup_expired_sharing_init_payloads(conn)?;
        assert_eq!(cleaned, 2, "should clean expired + old consumed");

        // Verify remaining
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM sharing_init_payloads", [], |row| {
                row.get(0)
            })?;
        assert_eq!(count, 2, "valid + recently consumed should remain");

        Ok(())
    })
    .unwrap();
}

#[tokio::test]
async fn test_fetch_and_consume_pending_sharing_inits_is_stable_and_ordered() {
    let db = Database::in_memory().expect("in-memory db");
    db.with_conn(|conn| {
        let now = db::now_secs();

        conn.execute(
            "INSERT INTO sharing_init_payloads
             (init_id, recipient_id, sender_id, payload, created_at, consumed_at, expires_at)
             VALUES ('late', 'recipient', 's1', X'AA', ?1, NULL, ?2)",
            params![now + 20, now + 3600],
        )?;
        conn.execute(
            "INSERT INTO sharing_init_payloads
             (init_id, recipient_id, sender_id, payload, created_at, consumed_at, expires_at)
             VALUES ('early', 'recipient', 's2', X'BB', ?1, NULL, ?2)",
            params![now + 10, now + 3600],
        )?;
        conn.execute(
            "INSERT INTO sharing_init_payloads
             (init_id, recipient_id, sender_id, payload, created_at, consumed_at, expires_at)
             VALUES ('middle', 'recipient', 's3', X'CC', ?1, NULL, ?2)",
            params![now + 15, now + 3600],
        )?;
        conn.execute(
            "INSERT INTO sharing_init_payloads
             (init_id, recipient_id, sender_id, payload, created_at, consumed_at, expires_at)
             VALUES ('other', 'other-recipient', 's4', X'DD', ?1, NULL, ?2)",
            params![now + 5, now + 3600],
        )?;

        let fetched = db::fetch_and_consume_pending_sharing_inits(conn, "recipient")?;
        let ids: Vec<_> = fetched.into_iter().map(|pending| pending.init_id).collect();
        assert_eq!(ids, vec!["early", "middle", "late"]);

        let remaining_other: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sharing_init_payloads
             WHERE recipient_id = 'other-recipient' AND consumed_at IS NULL",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(remaining_other, 1, "other recipients must remain untouched");

        Ok(())
    })
    .unwrap();
}

#[tokio::test]
async fn test_bundle_fetch_rate_limiting_ignores_spoofed_forwarded_headers() {
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
        nonce_rate_limit: 100,
        nonce_rate_window_secs: 60,
        revoke_rate_limit: 100,
        revoke_rate_window_secs: 60,
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
        sharing_fetch_rate_limit: 2,
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

    let (url, _handle, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();

    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;
    let sharing_id = generate_sharing_id();

    // Publish identity + prekey so bundle is fetchable
    let resp = publish_identity(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id,
        b"identity",
    )
    .await;
    assert_eq!(resp.status(), 204);

    let resp = publish_prekey(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id,
        "pk1",
        b"prekey",
    )
    .await;
    assert_eq!(resp.status(), 204);

    // First 2 fetches should succeed
    for (i, spoofed_ip) in ["203.0.113.42", "198.51.100.99"].into_iter().enumerate() {
        let resp = client
            .get(format!("{url}/v1/sharing/{sharing_id}/bundle"))
            .header("X-Forwarded-For", spoofed_ip)
            .header("Forwarded", format!("for={spoofed_ip}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "fetch {i} should succeed");
    }

    // 3rd fetch should be rate-limited
    let resp = client
        .get(format!("{url}/v1/sharing/{sharing_id}/bundle"))
        .header("X-Forwarded-For", "192.0.2.77")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429, "3rd fetch should be rate-limited");
}

#[tokio::test]
async fn test_sharing_init_upload_rate_limiting() {
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
        nonce_rate_limit: 100,
        nonce_rate_window_secs: 60,
        revoke_rate_limit: 100,
        revoke_rate_window_secs: 60,
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
        sharing_init_rate_limit: 2,
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

    let (url, _handle, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();

    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;
    let sharing_id = generate_sharing_id();

    let resp = publish_identity(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id,
        b"identity",
    )
    .await;
    assert_eq!(resp.status(), 204);

    let recipient_id = generate_sharing_id();

    // First 2 uploads should succeed
    for i in 0..2 {
        let init_id = generate_sharing_id();
        let body = serde_json::json!({
            "init_id": init_id,
            "recipient_id": recipient_id,
            "sender_id": sharing_id,
            "payload": b64_encode(b"data"),
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let builder = client
            .post(format!("{url}/v1/sharing/init"))
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(body_bytes.clone());
        let builder = apply_signed_headers(
            builder,
            &keys,
            "POST",
            "/v1/sharing/init",
            &sync_id,
            &device_id,
            &body_bytes,
        );
        let resp = builder.send().await.unwrap();
        assert_eq!(resp.status(), 201, "init upload {i} should succeed");
    }

    // 3rd upload should be rate-limited
    let init_id = generate_sharing_id();
    let body = serde_json::json!({
        "init_id": init_id,
        "recipient_id": recipient_id,
        "sender_id": sharing_id,
        "payload": b64_encode(b"data"),
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let builder = client
        .post(format!("{url}/v1/sharing/init"))
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(body_bytes.clone());
    let builder = apply_signed_headers(
        builder,
        &keys,
        "POST",
        "/v1/sharing/init",
        &sync_id,
        &device_id,
        &body_bytes,
    );
    let resp = builder.send().await.unwrap();
    assert_eq!(resp.status(), 429, "3rd init upload should be rate-limited");
}

#[tokio::test]
async fn test_revoked_device_prekey_not_returned() {
    let (url, _handle, db) = start_test_relay().await;
    let client = Client::new();

    let sync_id = generate_sync_id();

    // Register device_a via HTTP
    let device_id_a = generate_device_id();
    let keys_a = TestDeviceKeys::generate(&device_id_a);
    let token_a = register_device(&client, &url, &sync_id, &device_id_a, &keys_a).await;

    // Register device_b via direct DB (same sync group)
    let device_id_b = generate_device_id();
    let (_token_b, _keys_b) = prepare_device(&db, &sync_id, &device_id_b).await;

    let sharing_id = generate_sharing_id();

    // Publish identity from device_a
    let resp = publish_identity(
        &client,
        &url,
        &token_a,
        &keys_a,
        &sync_id,
        &device_id_a,
        &sharing_id,
        b"identity",
    )
    .await;
    assert_eq!(resp.status(), 204);

    // Insert prekeys for both devices directly (with controlled timestamps)
    let sid = sharing_id.clone();
    let did_a = device_id_a.clone();
    let did_b = device_id_b.clone();
    db.with_conn(move |conn| {
        let now = db::now_secs();
        db::upsert_sharing_prekey(conn, &sid, &did_a, "pk-a", b"prekey-a", now - 50)?;
        db::upsert_sharing_prekey(conn, &sid, &did_b, "pk-b", b"prekey-b", now)?;
        Ok(())
    })
    .unwrap();

    // Revoke device_a
    let did_a2 = device_id_a.clone();
    let sid2 = sync_id.clone();
    db.with_conn(move |conn| db::revoke_device(conn, &sid2, &did_a2, false))
        .unwrap();

    // Fetch bundle: should return device_b's prekey (device_a is revoked)
    let resp = client
        .get(format!("{url}/v1/sharing/{sharing_id}/bundle"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["device_id"].as_str().unwrap(), device_id_b);
    assert_eq!(body["prekey_id"].as_str().unwrap(), "pk-b");

    // Now revoke device_b too
    let did_b2 = device_id_b.clone();
    let sid3 = sync_id.clone();
    db.with_conn(move |conn| db::revoke_device(conn, &sid3, &did_b2, false))
        .unwrap();

    // Fetch bundle: should return 404 (all devices revoked)
    let resp = client
        .get(format!("{url}/v1/sharing/{sharing_id}/bundle"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "bundle with all devices revoked should 404"
    );
}

#[tokio::test]
async fn test_bundle_404_no_presence_probing() {
    let (url, _handle, _db) = start_test_relay().await;
    let client = Client::new();

    // Scenario A: sharing_id doesn't exist at all
    let nonexistent_id = generate_sharing_id();
    let resp_a = client
        .get(format!("{url}/v1/sharing/{nonexistent_id}/bundle"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp_a.status(), 404, "nonexistent sharing_id should 404");

    // Scenario B: publish identity but NO prekeys
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;
    let sharing_id = generate_sharing_id();

    let resp = publish_identity(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id,
        b"identity",
    )
    .await;
    assert_eq!(resp.status(), 204);

    // Fetch bundle with identity but no prekeys
    let resp_b = client
        .get(format!("{url}/v1/sharing/{sharing_id}/bundle"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp_b.status(), 404, "identity without prekeys should 404");

    // Both scenarios must return the same status code (404) — no presence probing
    assert_eq!(
        resp_a.status(),
        resp_b.status(),
        "both scenarios must return identical status to prevent presence probing"
    );
}

// ---------------------------------------------------------------------------
// Prekey freshness enforcement tests
// ---------------------------------------------------------------------------

/// Helper: set up a device with identity + prekey and return handles for
/// further manipulation. Returns (sharing_id, sync_id, device_id).
async fn setup_device_with_prekey(
    client: &Client,
    url: &str,
    _db: &std::sync::Arc<Database>,
) -> (String, String, String) {
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(client, url, &sync_id, &device_id, &keys).await;
    let sharing_id = generate_sharing_id();

    // Publish identity
    let resp = publish_identity(
        client,
        url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id,
        b"test-identity",
    )
    .await;
    assert_eq!(resp.status(), 204);

    // Publish prekey (relay stamps created_at = now)
    let resp = publish_prekey(
        client,
        url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        &sharing_id,
        "pk-fresh",
        b"test-prekey",
    )
    .await;
    assert_eq!(resp.status(), 204);

    (sharing_id, sync_id, device_id)
}

#[tokio::test]
async fn test_stale_prekey_not_served() {
    let (url, _handle, db) = start_test_relay().await;
    let client = Client::new();
    let (sharing_id, _sync_id, device_id) = setup_device_with_prekey(&client, &url, &db).await;

    // Backdate the prekey to 31 days ago (default serve limit is 30 days)
    let stale_time = db::now_secs() - (31 * 86400);
    let sid = sharing_id.clone();
    let did = device_id.clone();
    db.with_conn(move |conn| {
        conn.execute(
            "UPDATE sharing_signed_prekeys SET created_at = ?1
             WHERE sharing_id = ?2 AND device_id = ?3",
            params![stale_time, sid, did],
        )
    })
    .unwrap();

    // Fetch bundle should return a generic 404 so callers cannot distinguish
    // stale prekeys from other "recipient unavailable" states.
    let resp = client
        .get(format!("{url}/v1/sharing/{sharing_id}/bundle"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "Not Found");
}

#[tokio::test]
async fn test_fresh_prekey_served_normally() {
    let (url, _handle, db) = start_test_relay().await;
    let client = Client::new();
    let (sharing_id, _sync_id, device_id) = setup_device_with_prekey(&client, &url, &db).await;

    // Backdate to 6 days ago (within 7-day upload limit and 30-day serve limit)
    let recent_time = db::now_secs() - (6 * 86400);
    let sid = sharing_id.clone();
    let did = device_id.clone();
    db.with_conn(move |conn| {
        conn.execute(
            "UPDATE sharing_signed_prekeys SET created_at = ?1
             WHERE sharing_id = ?2 AND device_id = ?3",
            params![recent_time, sid, did],
        )
    })
    .unwrap();

    // Fetch bundle should succeed
    let resp = client
        .get(format!("{url}/v1/sharing/{sharing_id}/bundle"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["device_id"].as_str().unwrap(), device_id);
    assert_eq!(body["prekey_id"].as_str().unwrap(), "pk-fresh");
}

#[tokio::test]
async fn test_prekey_at_serve_boundary_still_served() {
    let (url, _handle, db) = start_test_relay().await;
    let client = Client::new();
    let (sharing_id, _sync_id, device_id) = setup_device_with_prekey(&client, &url, &db).await;

    // Set to exactly 29 days ago (just within 30-day limit)
    let boundary_time = db::now_secs() - (29 * 86400);
    let sid = sharing_id.clone();
    let did = device_id.clone();
    db.with_conn(move |conn| {
        conn.execute(
            "UPDATE sharing_signed_prekeys SET created_at = ?1
             WHERE sharing_id = ?2 AND device_id = ?3",
            params![boundary_time, sid, did],
        )
    })
    .unwrap();

    let resp = client
        .get(format!("{url}/v1/sharing/{sharing_id}/bundle"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "prekey within serve limit should be served"
    );
}

#[tokio::test]
async fn test_cleanup_removes_stale_prekeys() {
    let db = Database::in_memory().expect("in-memory db");
    let sharing_id = generate_sharing_id();
    let device_id = generate_device_id();
    let sync_id = generate_sync_id();

    db.with_conn(|conn| {
        // Set up the device and sharing mapping
        db::create_sync_group(conn, &sync_id, 0)?;
        db::register_device(conn, &sync_id, &device_id, &[1; 32], &[2; 32], 0)?;
        db::upsert_sharing_id_mapping(conn, &sync_id, &sharing_id)?;

        let now = db::now_secs();

        // Insert a fresh prekey
        db::upsert_sharing_prekey(conn, &sharing_id, &device_id, "pk-fresh", b"fresh", now)?;

        // Insert a stale prekey (for a different device) older than serve limit
        let stale_time = now - 2_592_001; // 30 days + 1 second
        let stale_device = generate_device_id();
        db::register_device(conn, &sync_id, &stale_device, &[3; 32], &[4; 32], 0)?;
        db::upsert_sharing_prekey(
            conn,
            &sharing_id,
            &stale_device,
            "pk-stale",
            b"stale",
            stale_time,
        )?;

        // Cleanup should remove the stale prekey
        let removed = db::cleanup_stale_sharing_prekeys(conn, 2_592_000)?;
        assert_eq!(removed, 1, "one stale prekey should be removed");

        // Fresh prekey should remain
        let best = db::get_best_sharing_prekey(conn, &sharing_id)?;
        assert!(best.is_some(), "fresh prekey should still exist");
        let (_, pk_id, _, _) = best.unwrap();
        assert_eq!(pk_id, "pk-fresh");

        Ok(())
    })
    .unwrap();
}
