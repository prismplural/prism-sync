//! End-to-end tests for sharing identity, prekey, and init-payload routes.

mod common;

use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use reqwest::Client;
use serde_json::Value;

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

fn b64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Helper: publish identity bundle for a device and return the sharing_id.
#[allow(clippy::too_many_arguments)]
async fn publish_identity(
    client: &Client,
    url: &str,
    token: &str,
    signing_key: &SigningKey,
    sync_id: &str,
    device_id: &str,
    sharing_id: &str,
    bundle: &[u8],
) -> reqwest::Response {
    let body = serde_json::json!({
        "sharing_id": sharing_id,
        "identity_bundle": b64_encode(bundle),
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let builder = client
        .put(format!("{url}/v1/sharing/identity"))
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(body_bytes.clone());

    let builder = apply_signed_headers(
        builder,
        signing_key,
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
    signing_key: &SigningKey,
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
        signing_key,
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
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let token = register_device(&client, &url, &sync_id, &device_id, &signing_key).await;
    let sharing_id = generate_sharing_id();
    let identity_bundle = b"test-identity-bundle";
    let prekey_bundle = b"test-prekey-bundle";

    // 1. Publish identity
    let resp = publish_identity(
        &client,
        &url,
        &token,
        &signing_key,
        &sync_id,
        &device_id,
        &sharing_id,
        identity_bundle,
    )
    .await;
    assert_eq!(resp.status(), 204, "publish identity should return 204");

    // 2. Publish prekey
    let resp = publish_prekey(
        &client,
        &url,
        &token,
        &signing_key,
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
    let key_1 = SigningKey::generate(&mut rand::thread_rng());
    let token_1 = register_device(&client, &url, &sync_id_1, &device_id_1, &key_1).await;

    let sync_id_2 = generate_sync_id();
    let device_id_2 = generate_device_id();
    let key_2 = SigningKey::generate(&mut rand::thread_rng());
    let token_2 = register_device(&client, &url, &sync_id_2, &device_id_2, &key_2).await;

    let sharing_id = generate_sharing_id();

    // First group claims sharing_id
    let resp = publish_identity(
        &client,
        &url,
        &token_1,
        &key_1,
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
        &key_2,
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
    let key = SigningKey::generate(&mut rand::thread_rng());
    let token = register_device(&client, &url, &sync_id, &device_id, &key).await;

    let sharing_id_1 = generate_sharing_id();
    let sharing_id_2 = generate_sharing_id();

    // Claim sharing_id_1
    let resp = publish_identity(
        &client,
        &url,
        &token,
        &key,
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
        &key,
        &sync_id,
        &device_id,
        &sharing_id_2,
        b"bundle",
    )
    .await;
    assert_eq!(resp.status(), 409, "switching sharing_id should 409");
}

#[tokio::test]
async fn test_fetch_bundle_returns_most_recent_active_prekey() {
    let (url, _handle, db) = start_test_relay().await;
    let client = Client::new();

    let sync_id = generate_sync_id();
    let device_id_1 = generate_device_id();
    let key_1 = SigningKey::generate(&mut rand::thread_rng());
    let token_1 = register_device(&client, &url, &sync_id, &device_id_1, &key_1).await;

    // Register a second device in the same sync group (via direct DB)
    let device_id_2 = generate_device_id();
    let _token_2 = prepare_device(&db, &sync_id, &device_id_2).await;

    let sharing_id = generate_sharing_id();

    // Publish identity from device 1
    let resp = publish_identity(
        &client,
        &url,
        &token_1,
        &key_1,
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
    let sender_key = SigningKey::generate(&mut rand::thread_rng());
    let sender_token = register_device(
        &client,
        &url,
        &sender_sync_id,
        &sender_device_id,
        &sender_key,
    )
    .await;
    let sender_sharing_id = generate_sharing_id();

    // Bind sender's sharing_id
    let resp = publish_identity(
        &client,
        &url,
        &sender_token,
        &sender_key,
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
    let recipient_key = SigningKey::generate(&mut rand::thread_rng());
    let recipient_token = register_device(
        &client,
        &url,
        &recipient_sync_id,
        &recipient_device_id,
        &recipient_key,
    )
    .await;
    let recipient_sharing_id = generate_sharing_id();

    // Bind recipient's sharing_id
    let resp = publish_identity(
        &client,
        &url,
        &recipient_token,
        &recipient_key,
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
        &sender_key,
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
        &recipient_key,
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
        &recipient_key,
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
    let key = SigningKey::generate(&mut rand::thread_rng());
    let token = register_device(&client, &url, &sync_id, &device_id, &key).await;
    let sharing_id = generate_sharing_id();

    // Bind sharing_id
    let resp = publish_identity(
        &client,
        &url,
        &token,
        &key,
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
            &key,
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
    };

    let (url, _handle, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();

    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let key = SigningKey::generate(&mut rand::thread_rng());
    let token = register_device(&client, &url, &sync_id, &device_id, &key).await;
    let sharing_id = generate_sharing_id();

    let resp = publish_identity(
        &client,
        &url,
        &token,
        &key,
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
            &key,
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
        &key,
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
    let key = SigningKey::generate(&mut rand::thread_rng());
    let token = register_device(&client, &url, &sync_id, &device_id, &key).await;
    let sharing_id = generate_sharing_id();

    // Publish identity + prekey
    let resp = publish_identity(
        &client,
        &url,
        &token,
        &key,
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
        &key,
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
        &key,
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
    };

    let (url, _handle, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();

    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let key = SigningKey::generate(&mut rand::thread_rng());
    let token = register_device(&client, &url, &sync_id, &device_id, &key).await;
    let sharing_id = generate_sharing_id();

    // Publish identity + prekey so bundle is fetchable
    let resp = publish_identity(
        &client,
        &url,
        &token,
        &key,
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
        &key,
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
    };

    let (url, _handle, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();

    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let key = SigningKey::generate(&mut rand::thread_rng());
    let token = register_device(&client, &url, &sync_id, &device_id, &key).await;
    let sharing_id = generate_sharing_id();

    let resp = publish_identity(
        &client,
        &url,
        &token,
        &key,
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
            &key,
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
        &key,
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
    let key_a = SigningKey::generate(&mut rand::thread_rng());
    let token_a = register_device(&client, &url, &sync_id, &device_id_a, &key_a).await;

    // Register device_b via direct DB (same sync group)
    let device_id_b = generate_device_id();
    let _token_b = prepare_device(&db, &sync_id, &device_id_b).await;

    let sharing_id = generate_sharing_id();

    // Publish identity from device_a
    let resp = publish_identity(
        &client,
        &url,
        &token_a,
        &key_a,
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
    let key = SigningKey::generate(&mut rand::thread_rng());
    let token = register_device(&client, &url, &sync_id, &device_id, &key).await;
    let sharing_id = generate_sharing_id();

    let resp = publish_identity(
        &client,
        &url,
        &token,
        &key,
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
