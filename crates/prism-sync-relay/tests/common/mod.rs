//! Shared test harness for prism-sync-relay end-to-end tests.
//!
//! Not every test file uses every item, so we allow dead_code globally.
#![allow(dead_code)]

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use reqwest::{Client, RequestBuilder};
use serde_json::Value;
use sha2::{Digest, Sha256};

use prism_sync_core::{
    pairing::models::{RegistrySnapshotEntry, SignedRegistrySnapshot},
    relay::traits::RegistryApproval,
};
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
        sharing_init_rate_limit: 100,
        sharing_init_max_pending: 50,
    };

    start_test_relay_with_config(config).await
}

pub async fn start_test_relay_with_config(
    config: Config,
) -> (
    String,
    tokio::task::JoinHandle<()>,
    std::sync::Arc<Database>,
) {
    let db = Database::in_memory().expect("in-memory db");
    let state = AppState::new(db, config);
    let db = state.db.clone();
    let app = routes::router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());

    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
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

pub fn apply_signed_headers(
    builder: RequestBuilder,
    signing_key: &SigningKey,
    method: &str,
    path: &str,
    sync_id: &str,
    device_id: &str,
    body: &[u8],
) -> RequestBuilder {
    let timestamp = db::now_secs().to_string();
    let nonce = uuid::Uuid::new_v4().to_string();
    let signing_data = prism_sync_relay::auth::build_request_signing_data(
        method, path, sync_id, device_id, body, &timestamp, &nonce,
    );
    let signature = signing_key.sign(&signing_data);

    builder
        .header("X-Prism-Timestamp", timestamp)
        .header("X-Prism-Nonce", nonce)
        .header(
            "X-Prism-Signature",
            base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        )
}

fn solve_first_device_pow(sync_id: &str, device_id: &str, nonce: &str, difficulty_bits: u8) -> u64 {
    for counter in 0..=u64::MAX {
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
            continue;
        }
        if remaining_bits == 0 {
            return counter;
        }
        let mask = 0xFFu8 << (8 - remaining_bits);
        if hash
            .get(full_zero_bytes)
            .is_some_and(|byte| byte & mask == 0)
        {
            return counter;
        }
    }

    panic!("failed to solve test PoW challenge");
}

pub fn pow_solution_from_nonce_json(
    sync_id: &str,
    device_id: &str,
    nonce_json: &Value,
) -> Option<Value> {
    let challenge = nonce_json.get("pow_challenge")?;
    let difficulty_bits = challenge.get("difficulty_bits")?.as_u64()? as u8;
    let nonce = nonce_json.get("nonce")?.as_str()?;
    let counter = solve_first_device_pow(sync_id, device_id, nonce, difficulty_bits);
    Some(serde_json::json!({ "counter": counter }))
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
    register_device_with_x25519(client, url, sync_id, device_id, signing_key)
        .await
        .0
}

/// Full registration helper that also returns the generated X25519 key.
pub async fn register_device_with_x25519(
    client: &Client,
    url: &str,
    sync_id: &str,
    device_id: &str,
    signing_key: &SigningKey,
) -> (String, [u8; 32]) {
    // 1. Fetch nonce
    let nonce_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
        .send()
        .await
        .unwrap();
    assert_eq!(nonce_resp.status(), 200, "nonce request failed");
    let nonce_json: Value = nonce_resp.json().await.unwrap();
    let nonce = nonce_json["nonce"].as_str().unwrap().to_string();
    let pow_solution = pow_solution_from_nonce_json(sync_id, device_id, &nonce_json);

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
            "pow_solution": pow_solution,
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
    (
        token_json["device_session_token"]
            .as_str()
            .expect("missing device_session_token in register response")
            .to_string(),
        x25519_pk,
    )
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

pub async fn prepare_device(
    db: &std::sync::Arc<Database>,
    sync_id: &str,
    device_id: &str,
) -> String {
    let device_id = device_id.to_string();
    let sync_id = sync_id.to_string();
    db.with_conn(|conn| {
        db::register_device(conn, &sync_id, &device_id, &[7u8; 32], &[8u8; 32], 0)?;
        let token = db::create_session(conn, &sync_id, &device_id, 3600)?;
        Ok(token)
    })
    .expect("prepare device")
}

/// Build a registry snapshot entry for test payloads.
pub fn registry_snapshot_entry(
    sync_id: &str,
    device_id: &str,
    ed25519_public_key: &[u8],
    x25519_public_key: &[u8],
    status: &str,
) -> RegistrySnapshotEntry {
    RegistrySnapshotEntry {
        sync_id: sync_id.to_string(),
        device_id: device_id.to_string(),
        ed25519_public_key: ed25519_public_key.to_vec(),
        x25519_public_key: x25519_public_key.to_vec(),
        status: status.to_string(),
    }
}

/// Build a signed registry snapshot using the current core wire format.
pub fn build_signed_registry_snapshot(
    entries: Vec<RegistrySnapshotEntry>,
    signing_key: &SigningKey,
) -> Vec<u8> {
    let snapshot = SignedRegistrySnapshot::new(entries);
    let canonical_json = snapshot.canonical_json();

    let mut signing_data =
        Vec::with_capacity(b"PRISM_SYNC_REGISTRY_V1\x00".len() + canonical_json.len());
    signing_data.extend_from_slice(b"PRISM_SYNC_REGISTRY_V1\x00");
    signing_data.extend_from_slice(&canonical_json);

    let signature = signing_key.sign(&signing_data);
    let mut wire = Vec::with_capacity(64 + canonical_json.len());
    wire.extend_from_slice(&signature.to_bytes());
    wire.extend_from_slice(&canonical_json);
    wire
}

/// Deterministic hash for a signed registry snapshot wire payload.
pub fn registry_snapshot_hash(signed_registry_snapshot: &[u8]) -> String {
    hex::encode(Sha256::digest(signed_registry_snapshot))
}

/// Build the compact registry-approval payload used by `/register`.
pub fn build_registry_approval(
    sync_id: &str,
    approver_device_id: &str,
    approver_key: &SigningKey,
    entries: Vec<RegistrySnapshotEntry>,
) -> RegistryApproval {
    let signed_registry_snapshot = build_signed_registry_snapshot(entries, approver_key);

    let mut approval_data = Vec::new();
    approval_data.extend_from_slice(b"PRISM_SYNC_REGISTRY_APPROVAL_V1\x00");
    write_len_prefixed(&mut approval_data, sync_id.as_bytes());
    write_len_prefixed(&mut approval_data, approver_device_id.as_bytes());
    write_len_prefixed(&mut approval_data, &signed_registry_snapshot);

    let signature = approver_key.sign(&approval_data);

    RegistryApproval {
        approver_device_id: approver_device_id.to_string(),
        approver_ed25519_pk: hex::encode(approver_key.verifying_key().as_bytes()),
        approval_signature: hex::encode(signature.to_bytes()),
        signed_registry_snapshot,
    }
}
