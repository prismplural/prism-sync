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
use prism_sync_crypto::DeviceSecret;
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

/// Build the canonical V1 challenge bytes that the relay expects, then sign them.
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

/// Build a V3 hybrid challenge signature.
///
/// Wire format: `[0x03][HybridSignature::to_bytes()]`
pub fn sign_hybrid_challenge(
    ed25519_key: &SigningKey,
    ml_dsa_key: &prism_sync_crypto::DevicePqSigningKey,
    sync_id: &str,
    device_id: &str,
    nonce: &str,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"PRISM_SYNC_CHALLENGE_V2\x00");
    write_len_prefixed(&mut data, sync_id.as_bytes());
    write_len_prefixed(&mut data, device_id.as_bytes());
    write_len_prefixed(&mut data, nonce.as_bytes());

    let m_prime = prism_sync_crypto::pq::build_hybrid_message_representative(
        b"device_challenge",
        &data,
    )
    .expect("hardcoded device challenge context should be <= 255 bytes");
    let hybrid_sig = prism_sync_crypto::pq::HybridSignature {
        ed25519_sig: ed25519_key.sign(&m_prime).to_bytes().to_vec(),
        ml_dsa_65_sig: ml_dsa_key.sign(&m_prime),
    };
    let mut wire = vec![0x03];
    wire.extend_from_slice(&hybrid_sig.to_bytes());
    wire
}

pub fn write_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Apply V3 hybrid signed request headers using `TestDeviceKeys`.
pub fn apply_signed_headers(
    builder: RequestBuilder,
    keys: &TestDeviceKeys,
    method: &str,
    path: &str,
    sync_id: &str,
    device_id: &str,
    body: &[u8],
) -> RequestBuilder {
    let ml_dsa_kp = keys
        .device_secret
        .ml_dsa_65_keypair(device_id)
        .unwrap();
    apply_signed_headers_hybrid(
        builder,
        &keys.ed25519_signing_key,
        &ml_dsa_kp,
        method,
        path,
        sync_id,
        device_id,
        body,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn apply_signed_headers_hybrid(
    builder: RequestBuilder,
    ed25519_key: &SigningKey,
    ml_dsa_key: &prism_sync_crypto::DevicePqSigningKey,
    method: &str,
    path: &str,
    sync_id: &str,
    device_id: &str,
    body: &[u8],
) -> RequestBuilder {
    let timestamp = db::now_secs().to_string();
    let nonce = uuid::Uuid::new_v4().to_string();
    let signing_data = prism_sync_relay::auth::build_request_signing_data_v2(
        method, path, sync_id, device_id, body, &timestamp, &nonce,
    );
    let m_prime = prism_sync_crypto::pq::build_hybrid_message_representative(
        b"http_request",
        &signing_data,
    )
    .expect("hardcoded http request context should be <= 255 bytes");
    let hybrid_sig = prism_sync_crypto::pq::HybridSignature {
        ed25519_sig: ed25519_key.sign(&m_prime).to_bytes().to_vec(),
        ml_dsa_65_sig: ml_dsa_key.sign(&m_prime),
    };
    let mut wire = vec![0x03u8];
    wire.extend_from_slice(&hybrid_sig.to_bytes());

    builder
        .header("X-Prism-Timestamp", timestamp)
        .header("X-Prism-Nonce", nonce)
        .header(
            "X-Prism-Signature",
            base64::engine::general_purpose::STANDARD.encode(&wire),
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

/// Full V3 hybrid registration helper using `TestDeviceKeys`.
/// Returns the session token.
pub async fn register_device(
    client: &Client,
    url: &str,
    sync_id: &str,
    device_id: &str,
    keys: &TestDeviceKeys,
) -> String {
    register_device_hybrid(client, url, sync_id, device_id, keys).await
}

/// Registration keys derived from a `DeviceSecret`, for V2 hybrid tests.
pub struct TestDeviceKeys {
    pub device_secret: DeviceSecret,
    pub ed25519_signing_key: SigningKey,
    pub ml_dsa_pk: Vec<u8>,
    pub ml_kem_pk: Vec<u8>,
    pub x25519_pk: [u8; 32],
}

impl TestDeviceKeys {
    pub fn generate(device_id: &str) -> Self {
        let device_secret = DeviceSecret::generate();
        let ed_kp = device_secret.ed25519_keypair(device_id).unwrap();
        let ml_dsa_kp = device_secret.ml_dsa_65_keypair(device_id).unwrap();
        let ml_kem_kp = device_secret.ml_kem_768_keypair(device_id).unwrap();
        let x25519_kp = device_secret.x25519_keypair(device_id).unwrap();
        TestDeviceKeys {
            device_secret,
            ed25519_signing_key: ed_kp.into_signing_key(),
            ml_dsa_pk: ml_dsa_kp.public_key_bytes(),
            ml_kem_pk: ml_kem_kp.public_key_bytes(),
            x25519_pk: x25519_kp.public_key_bytes(),
        }
    }
}

/// Full V2 hybrid registration helper.
/// Returns the session token.
pub async fn register_device_hybrid(
    client: &Client,
    url: &str,
    sync_id: &str,
    device_id: &str,
    keys: &TestDeviceKeys,
) -> String {
    let ml_dsa_kp = keys
        .device_secret
        .ml_dsa_65_keypair(device_id)
        .unwrap();

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

    // 2. Sign V2 hybrid challenge
    let challenge_sig = sign_hybrid_challenge(
        &keys.ed25519_signing_key,
        &ml_dsa_kp,
        sync_id,
        device_id,
        &nonce,
    );

    // 3. Register with PQ keys
    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_id,
            "signing_public_key": hex::encode(keys.ed25519_signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(keys.x25519_pk),
            "ml_dsa_65_public_key": hex::encode(&keys.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&keys.ml_kem_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
            "pow_solution": pow_solution,
        }))
        .send()
        .await
        .unwrap();
    let status = register_resp.status();
    let token_json: Value = register_resp.json().await.unwrap_or_else(|e| {
        panic!("hybrid registration failed (status {status}): {e}");
    });
    assert!(
        status.is_success(),
        "hybrid registration failed: {status} - {token_json}"
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

/// Insert a device directly into the DB with real PQ keys, returning
/// both the session token and the `TestDeviceKeys` needed for signed requests.
pub async fn prepare_device(
    db: &std::sync::Arc<Database>,
    sync_id: &str,
    device_id: &str,
) -> (String, TestDeviceKeys) {
    let keys = TestDeviceKeys::generate(device_id);
    let device_id = device_id.to_string();
    let sync_id = sync_id.to_string();
    let signing_pk = keys.ed25519_signing_key.verifying_key().to_bytes().to_vec();
    let x25519_pk = keys.x25519_pk.to_vec();
    let ml_dsa_pk = keys.ml_dsa_pk.clone();
    let ml_kem_pk = keys.ml_kem_pk.clone();
    let token = db
        .with_conn(|conn| {
            db::register_device_with_pq(
                conn,
                &sync_id,
                &device_id,
                &signing_pk,
                &x25519_pk,
                &ml_dsa_pk,
                &ml_kem_pk,
                &[],
                0,
            )?;
            let token = db::create_session(conn, &sync_id, &device_id, 3600)?;
            Ok(token)
        })
        .expect("prepare device");
    (token, keys)
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
        ml_dsa_65_public_key: Vec::new(),
        ml_kem_768_public_key: Vec::new(),
        x_wing_public_key: Vec::new(),
        ml_dsa_key_generation: 0,
        status: status.to_string(),
    }
}

/// Build a registry snapshot entry with PQ keys for hybrid test payloads.
pub fn registry_snapshot_entry_hybrid(
    sync_id: &str,
    device_id: &str,
    keys: &TestDeviceKeys,
    status: &str,
) -> RegistrySnapshotEntry {
    RegistrySnapshotEntry {
        sync_id: sync_id.to_string(),
        device_id: device_id.to_string(),
        ed25519_public_key: keys.ed25519_signing_key.verifying_key().to_bytes().to_vec(),
        x25519_public_key: keys.x25519_pk.to_vec(),
        ml_dsa_65_public_key: keys.ml_dsa_pk.clone(),
        ml_kem_768_public_key: keys.ml_kem_pk.clone(),
        x_wing_public_key: Vec::new(),
        ml_dsa_key_generation: 0,
        status: status.to_string(),
    }
}

/// Build a V1 signed registry snapshot using the current core wire format.
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

/// Build a V3 hybrid signed registry snapshot.
pub fn build_signed_registry_snapshot_hybrid(
    entries: Vec<RegistrySnapshotEntry>,
    ed25519_key: &SigningKey,
    ml_dsa_key: &prism_sync_crypto::DevicePqSigningKey,
) -> Vec<u8> {
    let snapshot = SignedRegistrySnapshot::new(entries);
    let canonical_json = snapshot.canonical_json();

    let mut signing_data =
        Vec::with_capacity(b"PRISM_SYNC_REGISTRY_V2\x00".len() + canonical_json.len());
    signing_data.extend_from_slice(b"PRISM_SYNC_REGISTRY_V2\x00");
    signing_data.extend_from_slice(&canonical_json);

    let m_prime = prism_sync_crypto::pq::build_hybrid_message_representative(
        b"registry_snapshot",
        &signing_data,
    )
    .expect("hardcoded registry snapshot context should be <= 255 bytes");
    let hybrid_sig = prism_sync_crypto::pq::HybridSignature {
        ed25519_sig: ed25519_key.sign(&m_prime).to_bytes().to_vec(),
        ml_dsa_65_sig: ml_dsa_key.sign(&m_prime),
    };
    let sig_bytes = hybrid_sig.to_bytes();
    let mut wire = Vec::with_capacity(1 + sig_bytes.len() + canonical_json.len());
    wire.push(0x03);
    wire.extend_from_slice(&sig_bytes);
    wire.extend_from_slice(&canonical_json);
    wire
}

/// Deterministic hash for a signed registry snapshot wire payload.
pub fn registry_snapshot_hash(signed_registry_snapshot: &[u8]) -> String {
    hex::encode(Sha256::digest(signed_registry_snapshot))
}

/// Build a V3 hybrid registry-approval payload used by `/register`.
///
/// This delegates to `build_registry_approval_hybrid` using `TestDeviceKeys`.
pub fn build_registry_approval(
    sync_id: &str,
    approver_device_id: &str,
    approver_keys: &TestDeviceKeys,
    entries: Vec<RegistrySnapshotEntry>,
) -> RegistryApproval {
    let ml_dsa_kp = approver_keys
        .device_secret
        .ml_dsa_65_keypair(approver_device_id)
        .unwrap();
    build_registry_approval_hybrid(
        sync_id,
        approver_device_id,
        &approver_keys.ed25519_signing_key,
        &ml_dsa_kp,
        entries,
    )
}

/// Build a V3 hybrid registry-approval payload used by `/register`.
pub fn build_registry_approval_hybrid(
    sync_id: &str,
    approver_device_id: &str,
    approver_ed25519_key: &SigningKey,
    approver_ml_dsa_key: &prism_sync_crypto::DevicePqSigningKey,
    entries: Vec<RegistrySnapshotEntry>,
) -> RegistryApproval {
    let signed_registry_snapshot =
        build_signed_registry_snapshot_hybrid(entries, approver_ed25519_key, approver_ml_dsa_key);

    let mut approval_data = Vec::new();
    approval_data.extend_from_slice(b"PRISM_SYNC_REGISTRY_APPROVAL_V2\x00");
    write_len_prefixed(&mut approval_data, sync_id.as_bytes());
    write_len_prefixed(&mut approval_data, approver_device_id.as_bytes());
    write_len_prefixed(&mut approval_data, &signed_registry_snapshot);

    let m_prime = prism_sync_crypto::pq::build_hybrid_message_representative(
        b"registry_approval",
        &approval_data,
    )
    .expect("hardcoded registry approval context should be <= 255 bytes");
    let hybrid_sig = prism_sync_crypto::pq::HybridSignature {
        ed25519_sig: approver_ed25519_key
            .sign(&m_prime)
            .to_bytes()
            .to_vec(),
        ml_dsa_65_sig: approver_ml_dsa_key.sign(&m_prime),
    };
    let mut sig_wire = vec![0x03u8];
    sig_wire.extend_from_slice(&hybrid_sig.to_bytes());

    RegistryApproval {
        approver_device_id: approver_device_id.to_string(),
        approver_ed25519_pk: hex::encode(approver_ed25519_key.verifying_key().as_bytes()),
        approver_ml_dsa_65_pk: hex::encode(approver_ml_dsa_key.public_key_bytes()),
        approval_signature: hex::encode(&sig_wire),
        signed_registry_snapshot,
    }
}
