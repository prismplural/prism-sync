//! End-to-end tests for the pairing session API.

mod common;

use base64::Engine;
use reqwest::Client;
use serde_json::Value;

use prism_sync_relay::{
    config::Config,
    db::{self, Database},
};

use common::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn create_pairing_session(client: &Client, url: &str, bootstrap: &[u8]) -> (String, u16) {
    let encoded = base64::engine::general_purpose::STANDARD.encode(bootstrap);
    let resp = client
        .post(format!("{url}/v1/pairing"))
        .json(&serde_json::json!({ "joiner_bootstrap": encoded }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    if status == 201 {
        let body: Value = resp.json().await.unwrap();
        let rid = body["rendezvous_id"].as_str().unwrap().to_string();
        (rid, status)
    } else {
        (String::new(), status)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_pairing_create_and_get_bootstrap() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();

    let bootstrap = b"test-bootstrap-data";
    let (rid, status) = create_pairing_session(&client, &url, bootstrap).await;
    assert_eq!(status, 201);
    assert_eq!(rid.len(), 32, "rendezvous_id should be 32 hex chars (16 bytes)");

    // GET bootstrap
    let resp = client.get(format!("{url}/v1/pairing/{rid}/bootstrap")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    let decoded = base64::engine::general_purpose::STANDARD.decode(&body).unwrap();
    assert_eq!(decoded, bootstrap);
}

#[tokio::test]
async fn test_pairing_put_get_slots() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();

    let (rid, _) = create_pairing_session(&client, &url, b"bootstrap").await;

    // Test all four slots
    let slots = [
        ("init", b"init-data" as &[u8]),
        ("confirmation", b"confirm-data"),
        ("credentials", b"cred-data"),
        ("joiner", b"joiner-data"),
    ];

    for (slot_name, slot_data) in &slots {
        // GET before PUT -> 204 (not yet set)
        let resp = client.get(format!("{url}/v1/pairing/{rid}/{slot_name}")).send().await.unwrap();
        assert_eq!(resp.status(), 204, "GET {slot_name} before PUT should be 204");

        // PUT the slot
        let resp = client
            .put(format!("{url}/v1/pairing/{rid}/{slot_name}"))
            .body(slot_data.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 204, "PUT {slot_name} should succeed with 204");

        // GET after PUT -> 200 with data
        let resp = client.get(format!("{url}/v1/pairing/{rid}/{slot_name}")).send().await.unwrap();
        assert_eq!(resp.status(), 200, "GET {slot_name} after PUT should be 200");
        let body = resp.bytes().await.unwrap();
        assert_eq!(body.as_ref(), *slot_data);
    }
}

#[tokio::test]
async fn test_pairing_terminal_slots_are_single_consume() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();

    let (rid, _) = create_pairing_session(&client, &url, b"bootstrap").await;

    for (slot_name, slot_data) in
        [("credentials", b"cred-data" as &[u8]), ("joiner", b"joiner-data" as &[u8])]
    {
        let put_resp = client
            .put(format!("{url}/v1/pairing/{rid}/{slot_name}"))
            .body(slot_data.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(put_resp.status(), 204);

        let first_get =
            client.get(format!("{url}/v1/pairing/{rid}/{slot_name}")).send().await.unwrap();
        assert_eq!(first_get.status(), 200);
        assert_eq!(first_get.bytes().await.unwrap().as_ref(), slot_data);

        let second_get =
            client.get(format!("{url}/v1/pairing/{rid}/{slot_name}")).send().await.unwrap();
        assert_eq!(second_get.status(), 404);

        let replace_resp = client
            .put(format!("{url}/v1/pairing/{rid}/{slot_name}"))
            .body(b"replacement".to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(replace_resp.status(), 409);
    }
}

#[tokio::test]
async fn test_pairing_polling_slots_remain_readable() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();

    let (rid, _) = create_pairing_session(&client, &url, b"bootstrap").await;

    for (slot_name, slot_data) in
        [("init", b"init-data" as &[u8]), ("confirmation", b"confirm-data" as &[u8])]
    {
        let put_resp = client
            .put(format!("{url}/v1/pairing/{rid}/{slot_name}"))
            .body(slot_data.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(put_resp.status(), 204);

        for _ in 0..2 {
            let get_resp =
                client.get(format!("{url}/v1/pairing/{rid}/{slot_name}")).send().await.unwrap();
            assert_eq!(get_resp.status(), 200);
            assert_eq!(get_resp.bytes().await.unwrap().as_ref(), slot_data);
        }
    }
}

#[tokio::test]
async fn test_pairing_put_slot_twice_returns_409() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();

    let (rid, _) = create_pairing_session(&client, &url, b"bootstrap").await;

    // First PUT -> 204
    let resp = client
        .put(format!("{url}/v1/pairing/{rid}/init"))
        .body(b"first".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Second PUT -> 409
    let resp = client
        .put(format!("{url}/v1/pairing/{rid}/init"))
        .body(b"second".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
}

#[tokio::test]
async fn test_pairing_nonexistent_session_returns_404() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();

    let fake_rid = "00000000000000000000000000000000";

    // GET bootstrap -> 404
    let resp = client.get(format!("{url}/v1/pairing/{fake_rid}/bootstrap")).send().await.unwrap();
    assert_eq!(resp.status(), 404);

    // PUT slot -> 404
    let resp = client
        .put(format!("{url}/v1/pairing/{fake_rid}/init"))
        .body(b"data".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // GET slot -> 404
    let resp = client.get(format!("{url}/v1/pairing/{fake_rid}/init")).send().await.unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_pairing_delete_session() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();

    let (rid, _) = create_pairing_session(&client, &url, b"bootstrap").await;

    // DELETE -> 204
    let resp = client.delete(format!("{url}/v1/pairing/{rid}")).send().await.unwrap();
    assert_eq!(resp.status(), 204);

    // GET bootstrap after delete -> 404
    let resp = client.get(format!("{url}/v1/pairing/{rid}/bootstrap")).send().await.unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_pairing_expired_session_returns_404() {
    // Use a Config with 0 TTL so sessions expire immediately
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
        pairing_session_ttl_secs: 0, // Expire immediately
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

    let (rid, status) = create_pairing_session(&client, &url, b"bootstrap").await;
    assert_eq!(status, 201);

    // Session should be expired already (TTL=0)
    let resp = client.get(format!("{url}/v1/pairing/{rid}/bootstrap")).send().await.unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_pairing_cleanup_removes_expired() {
    let db = Database::in_memory().expect("in-memory db");
    db.with_conn(|conn| {
        // Insert an already-expired session
        let now = db::now_secs();
        conn.execute(
            "INSERT INTO pairing_sessions (rendezvous_id, joiner_bootstrap, created_at, expires_at)
             VALUES ('expired-id', X'AABB', ?1, ?2)",
            rusqlite::params![now - 100, now - 50],
        )?;

        // Insert a still-valid session
        conn.execute(
            "INSERT INTO pairing_sessions (rendezvous_id, joiner_bootstrap, created_at, expires_at)
             VALUES ('valid-id', X'CCDD', ?1, ?2)",
            rusqlite::params![now, now + 3600],
        )?;

        let cleaned = db::cleanup_expired_pairing_sessions(conn)?;
        assert_eq!(cleaned, 1, "should clean up 1 expired session");

        // Valid session should still exist
        let bootstrap = db::get_pairing_bootstrap(conn, "valid-id")?;
        assert!(bootstrap.is_some());

        // Expired session should be gone
        let bootstrap = db::get_pairing_bootstrap(conn, "expired-id")?;
        assert!(bootstrap.is_none());

        Ok(())
    })
    .unwrap();
}

#[tokio::test]
async fn test_pairing_invalid_base64_returns_400() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();

    let resp = client
        .post(format!("{url}/v1/pairing"))
        .json(&serde_json::json!({ "joiner_bootstrap": "not-valid-base64!!!" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_pairing_rate_limiting_ignores_spoofed_forwarded_headers() {
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
        pairing_session_rate_limit: 1,
        pairing_session_max_payload_bytes: 65536,
        sharing_init_ttl_secs: 604800,
        sharing_init_max_payload_bytes: 65536,
        sharing_identity_max_bytes: 8192,
        sharing_prekey_max_bytes: 4096,
        sharing_fetch_rate_limit: 100,
        sharing_init_rate_limit: 100,
        sharing_init_max_pending: 100,
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
    let bootstrap = base64::engine::general_purpose::STANDARD.encode(b"bootstrap");

    let resp = client
        .post(format!("{url}/v1/pairing"))
        .header("x-forwarded-for", "203.0.113.10")
        .json(&serde_json::json!({ "joiner_bootstrap": bootstrap }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    let resp = client
        .post(format!("{url}/v1/pairing"))
        .header("x-forwarded-for", "198.51.100.77")
        .json(&serde_json::json!({ "joiner_bootstrap": bootstrap }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429, "spoofed forwarded headers must not bypass pairing rate limits");
}

#[tokio::test]
async fn test_pairing_payload_too_large_returns_413() {
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
        pairing_session_max_payload_bytes: 64, // Very small limit
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

    // Bootstrap data larger than 64 bytes
    let big_data = vec![0u8; 128];
    let encoded = base64::engine::general_purpose::STANDARD.encode(&big_data);
    let resp = client
        .post(format!("{url}/v1/pairing"))
        .json(&serde_json::json!({ "joiner_bootstrap": encoded }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
}

#[tokio::test]
async fn test_pairing_put_slot_payload_too_large() {
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
        pairing_session_max_payload_bytes: 64, // Very small limit
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

    // Create session with small bootstrap (within limit)
    let (rid, status) = create_pairing_session(&client, &url, b"small").await;
    assert_eq!(status, 201);

    // PUT slot with data exceeding limit
    let big_data = vec![0u8; 128];
    let resp =
        client.put(format!("{url}/v1/pairing/{rid}/init")).body(big_data).send().await.unwrap();
    assert_eq!(resp.status(), 413);
}

#[tokio::test]
async fn test_pairing_full_ceremony_flow() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();

    // 1. Joiner creates session
    let (rid, status) = create_pairing_session(&client, &url, b"joiner-bootstrap-blob").await;
    assert_eq!(status, 201);

    // 2. Existing device gets bootstrap
    let resp = client.get(format!("{url}/v1/pairing/{rid}/bootstrap")).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    // 3. Existing device puts init
    let resp = client
        .put(format!("{url}/v1/pairing/{rid}/init"))
        .body(b"pairing-init-blob".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // 4. Joiner gets init
    let resp = client.get(format!("{url}/v1/pairing/{rid}/init")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"pairing-init-blob");

    // 5. Joiner puts confirmation
    let resp = client
        .put(format!("{url}/v1/pairing/{rid}/confirmation"))
        .body(b"joiner-confirmation-blob".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // 6. Existing device gets confirmation
    let resp = client.get(format!("{url}/v1/pairing/{rid}/confirmation")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"joiner-confirmation-blob");

    // 7. Existing device puts credentials
    let resp = client
        .put(format!("{url}/v1/pairing/{rid}/credentials"))
        .body(b"credential-bundle-blob".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // 8. Joiner gets credentials
    let resp = client.get(format!("{url}/v1/pairing/{rid}/credentials")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"credential-bundle-blob");

    // 9. Joiner puts joiner bundle
    let resp = client
        .put(format!("{url}/v1/pairing/{rid}/joiner"))
        .body(b"joiner-bundle-blob".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // 10. Existing device gets joiner bundle
    let resp = client.get(format!("{url}/v1/pairing/{rid}/joiner")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"joiner-bundle-blob");

    // 11. Delete session
    let resp = client.delete(format!("{url}/v1/pairing/{rid}")).send().await.unwrap();
    assert_eq!(resp.status(), 204);

    // 12. Verify session is gone
    let resp = client.get(format!("{url}/v1/pairing/{rid}/bootstrap")).send().await.unwrap();
    assert_eq!(resp.status(), 404);
}
