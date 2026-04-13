use anyhow::{anyhow, Result};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use reqwest::Client;
use serde_json::Value;

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
pub async fn register_device(
    client: &Client,
    url: &str,
    sync_id: &str,
    device_id: &str,
    signing_key: &SigningKey,
) -> Result<String> {
    // 1. Fetch nonce
    let nonce_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
        .send()
        .await?;
    if !nonce_resp.status().is_success() {
        return Err(anyhow!("nonce request failed: {}", nonce_resp.status()));
    }
    let nonce_json: Value = nonce_resp.json().await?;
    let nonce = nonce_json["nonce"]
        .as_str()
        .ok_or_else(|| anyhow!("missing nonce in response"))?
        .to_string();

    // 2. Sign challenge
    let challenge_sig = sign_challenge(signing_key, sync_id, device_id, &nonce);

    // 3. Generate X25519 key (just random 32 bytes for testing)
    let mut x25519_pk = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut x25519_pk);

    // 4. Register
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
