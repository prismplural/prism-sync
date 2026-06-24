use anyhow::{anyhow, Result};
use base64::Engine;
use ed25519_dalek::SigningKey;
use ml_dsa::signature::Keypair;
use ml_dsa::{KeyGen, MlDsa65};
use prism_sync_crypto::pq::{hybrid_signature_contexts, HybridSignature};
use rand::RngCore;
use reqwest::Client;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Wire signature version byte the relay enforces (V3 hybrid).
const SIGNATURE_VERSION: u8 = 0x03;

/// An ML-DSA-65 signing key for a simulated device.
pub(crate) type MlDsaSigningKey = ml_dsa::SigningKey<MlDsa65>;

/// Generate a valid 64-char hex sync ID (32 random bytes).
pub(crate) fn generate_sync_id() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Generate a short device ID.
pub(crate) fn generate_device_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Generate a fresh ML-DSA-65 keypair for a simulated device.
pub(crate) fn generate_ml_dsa_key() -> MlDsaSigningKey {
    use getrandom::rand_core::UnwrapErr;
    use getrandom::SysRng;
    let mut rng = UnwrapErr(SysRng);
    MlDsa65::key_gen(&mut rng)
}

/// Hex-encode the ML-DSA-65 public key (1952 bytes) for the wire.
pub(crate) fn ml_dsa_public_hex(ml_dsa_sk: &MlDsaSigningKey) -> String {
    let vk = ml_dsa_sk.verifying_key();
    let encoded = vk.encode();
    hex::encode(AsRef::<[u8]>::as_ref(&encoded))
}

pub(crate) fn write_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Build the V2 challenge bytes the relay's `verify_hybrid_challenge` expects,
/// then sign them with a V3 hybrid signature: `[0x03][HybridSignature bytes]`.
pub(crate) fn sign_challenge(
    ed_sk: &SigningKey,
    ml_dsa_sk: &MlDsaSigningKey,
    sync_id: &str,
    device_id: &str,
    nonce: &str,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"PRISM_SYNC_CHALLENGE_V2\x00");
    write_len_prefixed(&mut data, sync_id.as_bytes());
    write_len_prefixed(&mut data, device_id.as_bytes());
    write_len_prefixed(&mut data, nonce.as_bytes());

    let sig = HybridSignature::sign_v3(
        &data,
        hybrid_signature_contexts::DEVICE_CHALLENGE,
        ed_sk,
        ml_dsa_sk,
    )
    .expect("sign challenge");
    let mut versioned = vec![SIGNATURE_VERSION];
    versioned.extend_from_slice(&sig.to_bytes());
    versioned
}

/// Produce the three `X-Prism-*` signed-request headers (timestamp, nonce,
/// signature) for a write request. The signature covers the same canonical
/// message the relay reconstructs in `build_request_signing_data_v2`.
pub(crate) fn sign_request(
    ed_sk: &SigningKey,
    ml_dsa_sk: &MlDsaSigningKey,
    method: &str,
    path: &str,
    sync_id: &str,
    device_id: &str,
    body: &[u8],
) -> (String, String, String) {
    let timestamp = now_secs().to_string();
    let mut nonce_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = hex::encode(nonce_bytes);

    let body_hash = Sha256::digest(body);
    let mut data = Vec::new();
    data.extend_from_slice(b"PRISM_SYNC_HTTP_V2\x00");
    write_len_prefixed(&mut data, method.as_bytes());
    write_len_prefixed(&mut data, path.as_bytes());
    write_len_prefixed(&mut data, sync_id.as_bytes());
    write_len_prefixed(&mut data, device_id.as_bytes());
    data.extend_from_slice(&body_hash);
    write_len_prefixed(&mut data, timestamp.as_bytes());
    write_len_prefixed(&mut data, nonce.as_bytes());

    let sig = HybridSignature::sign_v3(
        &data,
        hybrid_signature_contexts::HTTP_REQUEST,
        ed_sk,
        ml_dsa_sk,
    )
    .expect("sign request");
    let mut versioned = vec![SIGNATURE_VERSION];
    versioned.extend_from_slice(&sig.to_bytes());
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&versioned);

    (timestamp, nonce, signature_b64)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Full registration helper: fetches nonce, signs the hybrid challenge,
/// registers the device with its ed25519 + ML-DSA-65 public keys.
pub(crate) async fn register_device(
    client: &Client,
    url: &str,
    sync_id: &str,
    device_id: &str,
    ed_sk: &SigningKey,
    ml_dsa_sk: &MlDsaSigningKey,
) -> Result<String> {
    // 1. Fetch nonce
    let nonce_resp = client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await?;
    if !nonce_resp.status().is_success() {
        return Err(anyhow!("nonce request failed: {}", nonce_resp.status()));
    }
    let nonce_json: Value = nonce_resp.json().await?;
    let nonce = nonce_json["nonce"]
        .as_str()
        .ok_or_else(|| anyhow!("missing nonce in response"))?
        .to_string();

    // 2. Sign the V3 hybrid challenge
    let challenge_sig = sign_challenge(ed_sk, ml_dsa_sk, sync_id, device_id, &nonce);

    // 3. Generate X25519 key (just random 32 bytes for testing)
    let mut x25519_pk = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut x25519_pk);

    // 4. Register (ML-DSA-65 public key is required)
    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_id,
            "signing_public_key": hex::encode(ed_sk.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(x25519_pk),
            "ml_dsa_65_public_key": ml_dsa_public_hex(ml_dsa_sk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
        }))
        .send()
        .await?;

    let status = register_resp.status();
    let token_json: Value = register_resp
        .json()
        .await
        .map_err(|e| anyhow!("registration failed (status {status}): {e}"))?;

    if !status.is_success() {
        return Err(anyhow!("registration failed: {status} - {token_json}"));
    }

    token_json["device_session_token"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("missing device_session_token in register response"))
}

/// Build a minimal valid `SignedBatchEnvelope` JSON for testing.
pub(crate) fn make_test_envelope(
    sync_id: &str,
    device_id: &str,
    batch_id: &str,
    epoch: i64,
) -> Value {
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
