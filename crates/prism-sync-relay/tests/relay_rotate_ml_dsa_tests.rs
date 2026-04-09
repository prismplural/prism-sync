//! Integration tests for POST /v1/sync/{sync_id}/devices/{device_id}/rotate-ml-dsa

mod common;

use base64::Engine;
use prism_sync_crypto::{pq::continuity_proof::MlDsaContinuityProof, DeviceSecret};
use reqwest::Client;
use serde_json::Value;

use common::{
    apply_signed_headers, apply_signed_headers_hybrid, generate_device_id, generate_sync_id,
    prepare_device, start_test_relay, TestDeviceKeys,
};
use prism_sync_relay::db;

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Build a rotation request body for the given device.
fn build_rotation_request(
    device_id: &str,
    keys: &TestDeviceKeys,
    _new_device_secret: &DeviceSecret,
    old_generation: u32,
    new_generation: u32,
) -> (Vec<u8>, Vec<u8>) {
    let proof = MlDsaContinuityProof::create(
        &keys.device_secret,
        device_id,
        old_generation,
        new_generation,
    )
    .expect("continuity proof creation should succeed");

    let new_sk = keys
        .device_secret
        .ml_dsa_65_keypair_v(device_id, new_generation)
        .unwrap();
    let new_pk = new_sk.public_key_bytes();
    let body = serde_json::json!({
        "new_ml_dsa_pk": b64().encode(&new_pk),
        "ml_dsa_key_generation": new_generation,
        "timestamp": proof.timestamp,
        "old_signs_new": b64().encode(&proof.old_signs_new),
        "new_signs_old": b64().encode(&proof.new_signs_old),
    });

    (serde_json::to_vec(&body).unwrap(), new_pk)
}

#[tokio::test]
async fn test_valid_rotation_succeeds() {
    let (url, _handle, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();

    db.with_conn(|conn| db::create_sync_group(conn, &sync_id, 0))
        .unwrap();
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    let new_secret = DeviceSecret::generate();
    let (body, new_pk) = build_rotation_request(&device_id, &keys, &new_secret, 0, 1);

    let path = format!("/v1/sync/{sync_id}/devices/{device_id}/rotate-ml-dsa");
    let resp = apply_signed_headers(
        client
            .post(format!("{url}{path}"))
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(body.clone()),
        &keys,
        "POST",
        &path,
        &sync_id,
        &device_id,
        &body,
    )
    .send()
    .await
    .unwrap();

    assert_eq!(resp.status(), 200, "rotation should succeed");
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["ml_dsa_key_generation"], 1);

    // Verify the DB was updated
    let device = db
        .with_read_conn(|conn| db::get_device(conn, &sync_id, &device_id))
        .unwrap()
        .unwrap();
    assert_eq!(device.ml_dsa_key_generation, 1);
    assert_eq!(device.ml_dsa_65_public_key, new_pk);
}

#[tokio::test]
async fn test_invalid_proof_returns_400() {
    let (url, _handle, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();

    db.with_conn(|conn| db::create_sync_group(conn, &sync_id, 0))
        .unwrap();
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    let new_secret = DeviceSecret::generate();
    let (mut body_bytes, _new_pk) =
        build_rotation_request(&device_id, &keys, &new_secret, 0, 1);

    // Tamper with the body: flip a byte in old_signs_new
    let mut body_json: Value = serde_json::from_slice(&body_bytes).unwrap();
    let old_sig_b64 = body_json["old_signs_new"].as_str().unwrap().to_string();
    let mut old_sig = b64().decode(&old_sig_b64).unwrap();
    old_sig[0] ^= 0xFF;
    body_json["old_signs_new"] = Value::String(b64().encode(&old_sig));
    body_bytes = serde_json::to_vec(&body_json).unwrap();

    let path = format!("/v1/sync/{sync_id}/devices/{device_id}/rotate-ml-dsa");
    let resp = apply_signed_headers(
        client
            .post(format!("{url}{path}"))
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(body_bytes.clone()),
        &keys,
        "POST",
        &path,
        &sync_id,
        &device_id,
        &body_bytes,
    )
    .send()
    .await
    .unwrap();

    assert_eq!(resp.status(), 400, "tampered proof should be rejected");
}

#[tokio::test]
async fn test_rollback_generation_returns_409() {
    let (url, _handle, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();

    db.with_conn(|conn| db::create_sync_group(conn, &sync_id, 0))
        .unwrap();
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    // First, do a valid rotation to generation 1
    let new_secret_1 = DeviceSecret::generate();
    let (body, _new_pk) = build_rotation_request(&device_id, &keys, &new_secret_1, 0, 1);
    let path = format!("/v1/sync/{sync_id}/devices/{device_id}/rotate-ml-dsa");
    let resp = apply_signed_headers(
        client
            .post(format!("{url}{path}"))
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(body.clone()),
        &keys,
        "POST",
        &path,
        &sync_id,
        &device_id,
        &body,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 200, "first rotation should succeed");

    // Now try to roll back to generation 0 — should fail with 409.
    // After the first rotation, the DB has the gen-1 ML-DSA key.
    // We need to sign the HTTP request with the gen-1 key so auth passes.
    let gen1_sk = keys.device_secret.ml_dsa_65_keypair_v(&device_id, 1).unwrap();

    // Craft a request body with generation 0 (rollback) — the relay should reject this
    // even before proof verification since generation <= current.
    let gen0_sk = keys.device_secret.ml_dsa_65_keypair_v(&device_id, 0).unwrap();
    let body = serde_json::to_vec(&serde_json::json!({
        "new_ml_dsa_pk": b64().encode(gen0_sk.public_key_bytes()),
        "ml_dsa_key_generation": 0,
        "timestamp": 0,
        "old_signs_new": b64().encode([0u8; 64]),
        "new_signs_old": b64().encode([0u8; 64]),
    }))
    .unwrap();

    // Sign the HTTP request with the gen-1 ML-DSA key (current key in DB)
    let resp = apply_signed_headers_hybrid(
        client
            .post(format!("{url}{path}"))
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(body.clone()),
        &keys.ed25519_signing_key,
        &gen1_sk,
        "POST",
        &path,
        &sync_id,
        &device_id,
        &body,
    )
    .send()
    .await
    .unwrap();

    assert_eq!(resp.status(), 409, "rollback should be rejected");
}

#[tokio::test]
async fn test_wrong_device_id_returns_403() {
    let (url, _handle, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_a = generate_device_id();
    let device_b = generate_device_id();

    db.with_conn(|conn| db::create_sync_group(conn, &sync_id, 0))
        .unwrap();
    let (token_a, keys_a) = prepare_device(&db, &sync_id, &device_a).await;
    let (_token_b, _keys_b) = prepare_device(&db, &sync_id, &device_b).await;

    // Device A tries to rotate Device B's key
    let new_secret = DeviceSecret::generate();
    let (body, _) = build_rotation_request(&device_b, &keys_a, &new_secret, 0, 1);
    let path = format!("/v1/sync/{sync_id}/devices/{device_b}/rotate-ml-dsa");
    let resp = apply_signed_headers(
        client
            .post(format!("{url}{path}"))
            .header("Authorization", format!("Bearer {token_a}"))
            .header("Content-Type", "application/json")
            .body(body.clone()),
        &keys_a,
        "POST",
        &path,
        &sync_id,
        &device_a,
        &body,
    )
    .send()
    .await
    .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "rotating another device's key should be forbidden"
    );
}

#[tokio::test]
async fn test_double_rotation_succeeds() {
    let (url, _handle, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();

    db.with_conn(|conn| db::create_sync_group(conn, &sync_id, 0))
        .unwrap();
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    // Rotation 0 -> 1
    let new_secret_1 = DeviceSecret::generate();
    let (body, _) = build_rotation_request(&device_id, &keys, &new_secret_1, 0, 1);
    let path = format!("/v1/sync/{sync_id}/devices/{device_id}/rotate-ml-dsa");
    let resp = apply_signed_headers(
        client
            .post(format!("{url}{path}"))
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(body.clone()),
        &keys,
        "POST",
        &path,
        &sync_id,
        &device_id,
        &body,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);

    // Rotation 1 -> 2
    // After the first rotation, the DB has the gen-1 ML-DSA key.
    // We need to sign the HTTP request with the gen-1 key.
    let gen1_sk = keys.device_secret.ml_dsa_65_keypair_v(&device_id, 1).unwrap();
    // Build proof for gen 1→2 using the same device secret
    let proof = MlDsaContinuityProof::create(&keys.device_secret, &device_id, 1, 2)
        .expect("proof gen 1→2 should succeed");
    let gen2_sk = keys.device_secret.ml_dsa_65_keypair_v(&device_id, 2).unwrap();
    let body = serde_json::to_vec(&serde_json::json!({
        "new_ml_dsa_pk": b64().encode(gen2_sk.public_key_bytes()),
        "ml_dsa_key_generation": 2,
        "timestamp": proof.timestamp,
        "old_signs_new": b64().encode(&proof.old_signs_new),
        "new_signs_old": b64().encode(&proof.new_signs_old),
    }))
    .unwrap();

    // Sign with gen-1 ML-DSA key (what's currently in the DB)
    let resp = apply_signed_headers_hybrid(
        client
            .post(format!("{url}{path}"))
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(body.clone()),
        &keys.ed25519_signing_key,
        &gen1_sk,
        "POST",
        &path,
        &sync_id,
        &device_id,
        &body,
    )
    .send()
    .await
    .unwrap();

    assert_eq!(resp.status(), 200, "second rotation should succeed");
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["ml_dsa_key_generation"], 2);

    // Verify DB
    let device = db
        .with_read_conn(|conn| db::get_device(conn, &sync_id, &device_id))
        .unwrap()
        .unwrap();
    assert_eq!(device.ml_dsa_key_generation, 2);
    assert_eq!(device.ml_dsa_65_public_key, gen2_sk.public_key_bytes());
}
