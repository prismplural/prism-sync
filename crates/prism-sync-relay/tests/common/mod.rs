//! Shared test harness for prism-sync-relay end-to-end tests.
//!
//! Not every test file uses every item, so we allow dead_code globally.
#![allow(dead_code)]

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use reqwest::Client;
use serde_json::Value;

use prism_sync_relay::{
    config::Config,
    db::{self, Database},
    routes,
    state::AppState,
};

/// Start the relay server in-process on a random port with an in-memory DB.
/// Returns `(base_url, server_handle, db)`.
pub async fn start_test_relay() -> (
    String,
    tokio::task::JoinHandle<()>,
    std::sync::Arc<Database>,
) {
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
        snapshot_default_ttl_secs: 86400,
    };

    let db = Database::in_memory().expect("in-memory db");
    let state = AppState::new(db, config);
    let db = state.db.clone();
    let app = routes::router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (url, handle, db)
}

/// Generate a valid 64-char hex sync ID (32 random bytes).
pub fn generate_sync_id() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Generate a short device ID.
pub fn generate_device_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Build the canonical challenge bytes that the relay expects, then sign them.
///
/// Format: `"PRISM_SYNC_CHALLENGE_V1" || 0x00 || len_prefixed(sync_id) || len_prefixed(device_id) || len_prefixed(nonce)`
pub fn sign_challenge(
    signing_key: &SigningKey,
    sync_id: &str,
    device_id: &str,
    nonce: &str,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"PRISM_SYNC_CHALLENGE_V1\x00");
    write_len_prefixed(&mut data, sync_id.as_bytes());
    write_len_prefixed(&mut data, device_id.as_bytes());
    write_len_prefixed(&mut data, nonce.as_bytes());

    let sig = signing_key.sign(&data);
    sig.to_bytes().to_vec()
}

pub fn write_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Full registration helper: fetches nonce, signs challenge, registers device.
/// Returns the session token.
pub async fn register_device(
    client: &Client,
    url: &str,
    sync_id: &str,
    device_id: &str,
    signing_key: &SigningKey,
) -> String {
    // 1. Fetch nonce
    let nonce_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
        .send()
        .await
        .unwrap();
    assert_eq!(nonce_resp.status(), 200, "nonce request failed");
    let nonce_json: Value = nonce_resp.json().await.unwrap();
    let nonce = nonce_json["nonce"].as_str().unwrap().to_string();

    // 2. Sign challenge
    let challenge_sig = sign_challenge(signing_key, sync_id, device_id, &nonce);

    // 3. Generate X25519 key (just random 32 bytes for testing)
    let mut x25519_pk = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut x25519_pk);

    // 4. Register — relay expects hex-encoded keys
    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_id,
            "signing_public_key": hex::encode(signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(x25519_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
        }))
        .send()
        .await
        .unwrap();
    let status = register_resp.status();
    let token_json: Value = register_resp.json().await.unwrap_or_else(|e| {
        panic!("registration failed (status {status}): {e}");
    });
    assert!(
        status.is_success(),
        "registration failed: {status} - {token_json}"
    );
    token_json["device_session_token"]
        .as_str()
        .expect("missing device_session_token in register response")
        .to_string()
}

/// Build a minimal valid `SignedBatchEnvelope` JSON for testing.
/// The relay stores it opaquely — it only extracts `batch_id` and `epoch`.
pub fn make_test_envelope(sync_id: &str, device_id: &str, batch_id: &str, epoch: i64) -> Value {
    let payload_hash = vec![0u8; 32];
    let signature = vec![0u8; 64];
    let nonce = vec![0u8; 24];
    serde_json::json!({
        "protocol_version": 1,
        "sync_id": sync_id,
        "epoch": epoch,
        "batch_id": batch_id,
        "batch_kind": "incremental",
        "sender_device_id": device_id,
        "payload_hash": payload_hash,
        "signature": signature,
        "nonce": nonce,
        "ciphertext": base64::engine::general_purpose::STANDARD.encode(b"test-encrypted-data"),
    })
}

pub async fn prepare_device(db: &std::sync::Arc<Database>, sync_id: &str, device_id: &str) -> String {
    let device_id = device_id.to_string();
    let sync_id = sync_id.to_string();
    db.with_conn(|conn| {
        db::register_device(
            conn, &sync_id, &device_id, &[7u8; 32], &[8u8; 32], 0, "admin",
        )?;
        let token = db::create_session(conn, &sync_id, &device_id, 3600)?;
        Ok(token)
    })
    .expect("prepare device")
}
