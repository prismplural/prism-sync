//! Integration tests for the ephemeral device-message mailbox (media re-supply
//! C3): `POST /v1/sync/{sync_id}/device-messages`, `GET …/pending`, `POST …/ack`.

mod common;

use common::*;
use base64::Engine;
use reqwest::Client;
use serde_json::Value;

use prism_sync_relay::{config::Config, db};

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// A valid 32-hex message_id built from a short seed.
fn mid(seed: &str) -> String {
    let mut s = format!("{seed:0<32}");
    s.truncate(32);
    s.chars().map(|c| if c.is_ascii_hexdigit() { c } else { '0' }).collect()
}

#[allow(clippy::too_many_arguments)]
async fn send(
    client: &Client,
    url: &str,
    token: &str,
    keys: &TestDeviceKeys,
    sync_id: &str,
    device_id: &str,
    message_id: &str,
    recipient: Option<&str>,
    payload: &[u8],
) -> reqwest::Response {
    let path = format!("/v1/sync/{sync_id}/device-messages");
    let body = serde_json::to_vec(&serde_json::json!({
        "message_id": message_id,
        "epoch_id": 0,
        "recipient_device_id": recipient,
        "payload": b64(payload),
    }))
    .unwrap();
    let builder = client.post(format!("{url}{path}")).bearer_auth(token).body(body.clone());
    apply_signed_headers(builder, keys, "POST", &path, sync_id, device_id, &body)
        .send()
        .await
        .unwrap()
}

async fn pending(
    client: &Client,
    url: &str,
    token: &str,
    keys: &TestDeviceKeys,
    sync_id: &str,
    device_id: &str,
) -> Vec<Value> {
    let path = format!("/v1/sync/{sync_id}/device-messages/pending");
    let builder = client.get(format!("{url}{path}")).bearer_auth(token);
    let resp = apply_signed_headers(builder, keys, "GET", &path, sync_id, device_id, &[])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "pending should be 200");
    let body: Value = resp.json().await.unwrap();
    body["messages"].as_array().cloned().unwrap_or_default()
}

async fn ack(
    client: &Client,
    url: &str,
    token: &str,
    keys: &TestDeviceKeys,
    sync_id: &str,
    device_id: &str,
    ids: &[&str],
) -> reqwest::Response {
    let path = format!("/v1/sync/{sync_id}/device-messages/ack");
    let body = serde_json::to_vec(&serde_json::json!({ "message_ids": ids })).unwrap();
    let builder = client.post(format!("{url}{path}")).bearer_auth(token).body(body.clone());
    apply_signed_headers(builder, keys, "POST", &path, sync_id, device_id, &body)
        .send()
        .await
        .unwrap()
}

fn message_ids(msgs: &[Value]) -> Vec<String> {
    msgs.iter().map(|m| m["message_id"].as_str().unwrap().to_string()).collect()
}

/// (token, keys, device_id) for one registered device.
type TestDevice = (String, TestDeviceKeys, String);

/// Set up a group with three devices d1/d2/d3; returns (url, handle, db,
/// sync_id, [device…]).
type ThreeDeviceGroup =
    (String, tokio::task::JoinHandle<()>, std::sync::Arc<db::Database>, String, Vec<TestDevice>);

async fn three_device_group() -> ThreeDeviceGroup {
    let (url, handle, db) = start_test_relay().await;
    let sync_id = generate_sync_id();
    db.with_conn(|conn| db::create_sync_group(conn, &sync_id, 0).map(|_| ())).unwrap();
    let mut devices = Vec::new();
    for _ in 0..3 {
        let device_id = generate_device_id();
        let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;
        devices.push((token, keys, device_id));
    }
    (url, handle, db, sync_id, devices)
}

#[tokio::test]
async fn broadcast_roundtrip_excludes_sender_and_preserves_payload() {
    let (url, _h, _db, sync_id, dev) = three_device_group().await;
    let client = Client::new();
    let (t1, k1, id1) = &dev[0];
    let (t2, k2, id2) = &dev[1];
    let payload = b"opaque-sealed-bytes-\x00\x01\x02";

    let resp = send(&client, &url, t1, k1, &sync_id, id1, &mid("a1"), None, payload).await;
    assert_eq!(resp.status(), 201);

    // Sender does not receive its own broadcast.
    assert!(pending(&client, &url, t1, k1, &sync_id, id1).await.is_empty());

    // A peer receives it, with the payload intact.
    let got = pending(&client, &url, t2, k2, &sync_id, id2).await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0]["message_id"], mid("a1"));
    assert_eq!(got[0]["sender_device_id"], id1.as_str());
    assert!(got[0]["recipient_device_id"].is_null());
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(got[0]["payload"].as_str().unwrap())
        .unwrap();
    assert_eq!(decoded, payload);
}

#[tokio::test]
async fn targeted_message_only_to_recipient() {
    let (url, _h, _db, sync_id, dev) = three_device_group().await;
    let client = Client::new();
    let (t1, k1, id1) = &dev[0];
    let (t2, k2, id2) = &dev[1];
    let (t3, k3, id3) = &dev[2];

    let resp = send(&client, &url, t1, k1, &sync_id, id1, &mid("b1"), Some(id2.as_str()), b"x").await;
    assert_eq!(resp.status(), 201);

    assert_eq!(message_ids(&pending(&client, &url, t2, k2, &sync_id, id2).await), vec![mid("b1")]);
    assert!(pending(&client, &url, t3, k3, &sync_id, id3).await.is_empty());
}

#[tokio::test]
async fn per_device_ack_does_not_suppress_for_others() {
    // Spec: A acks an (e.g. undecryptable) message, B must still process it.
    let (url, _h, _db, sync_id, dev) = three_device_group().await;
    let client = Client::new();
    let (t1, k1, id1) = &dev[0];
    let (t2, k2, id2) = &dev[1];
    let (t3, k3, id3) = &dev[2];

    send(&client, &url, t1, k1, &sync_id, id1, &mid("c1"), None, b"x").await;
    let r = ack(&client, &url, t2, k2, &sync_id, id2, &[&mid("c1")]).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.json::<Value>().await.unwrap()["acked"], 1);

    assert!(pending(&client, &url, t2, k2, &sync_id, id2).await.is_empty(), "d2 acked");
    assert_eq!(
        message_ids(&pending(&client, &url, t3, k3, &sync_id, id3).await),
        vec![mid("c1")],
        "d3 still sees the message"
    );
}

#[tokio::test]
async fn duplicate_message_id_coalesces() {
    let (url, _h, _db, sync_id, dev) = three_device_group().await;
    let client = Client::new();
    let (t1, k1, id1) = &dev[0];
    let (t2, k2, id2) = &dev[1];

    assert_eq!(send(&client, &url, t1, k1, &sync_id, id1, &mid("d1"), None, b"x").await.status(), 201);
    // Re-send same id → coalesced, still a success, only one delivered.
    assert_eq!(send(&client, &url, t1, k1, &sync_id, id1, &mid("d1"), None, b"x").await.status(), 201);
    assert_eq!(pending(&client, &url, t2, k2, &sync_id, id2).await.len(), 1);
}

#[tokio::test]
async fn pending_cap_rejects_when_exceeded() {
    let mut config = base_dm_config();
    config.device_message_max_pending = 2;
    config.device_message_send_rate_limit = 100; // isolate the cap
    let (url, _h, db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    db.with_conn(|conn| db::create_sync_group(conn, &sync_id, 0).map(|_| ())).unwrap();
    let id1 = generate_device_id();
    let (t1, k1) = prepare_device(&db, &sync_id, &id1).await;

    assert_eq!(send(&client, &url, &t1, &k1, &sync_id, &id1, &mid("a"), None, b"x").await.status(), 201);
    assert_eq!(send(&client, &url, &t1, &k1, &sync_id, &id1, &mid("b"), None, b"x").await.status(), 201);
    assert_eq!(
        send(&client, &url, &t1, &k1, &sync_id, &id1, &mid("c"), None, b"x").await.status(),
        429,
        "third outstanding message exceeds the pending cap"
    );
}

#[tokio::test]
async fn send_rate_limited_per_device() {
    let mut config = base_dm_config();
    config.device_message_send_rate_limit = 2;
    config.device_message_max_pending = 256; // isolate the rate limit
    let (url, _h, db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    db.with_conn(|conn| db::create_sync_group(conn, &sync_id, 0).map(|_| ())).unwrap();
    let id1 = generate_device_id();
    let (t1, k1) = prepare_device(&db, &sync_id, &id1).await;

    assert_eq!(send(&client, &url, &t1, &k1, &sync_id, &id1, &mid("a"), None, b"x").await.status(), 201);
    assert_eq!(send(&client, &url, &t1, &k1, &sync_id, &id1, &mid("b"), None, b"x").await.status(), 201);
    assert_eq!(
        send(&client, &url, &t1, &k1, &sync_id, &id1, &mid("c"), None, b"x").await.status(),
        429,
        "third send within the window is rate limited"
    );
}

#[tokio::test]
async fn oversized_payload_rejected() {
    let (url, _h, _db, sync_id, dev) = three_device_group().await;
    let client = Client::new();
    let (t1, k1, id1) = &dev[0];
    // 5000 > 4096 max payload, but base64 (~6.6 KiB) < the 16 KiB route cap, so
    // the field-level size check (413) fires, not the body-limit extractor.
    let big = vec![7u8; 5000];
    let resp = send(&client, &url, t1, k1, &sync_id, id1, &mid("e1"), None, &big).await;
    assert_eq!(resp.status(), 413);
}

#[tokio::test]
async fn invalid_message_id_rejected() {
    let (url, _h, _db, sync_id, dev) = three_device_group().await;
    let client = Client::new();
    let (t1, k1, id1) = &dev[0];
    let resp = send(&client, &url, t1, k1, &sync_id, id1, "not-32-hex", None, b"x").await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn send_requires_auth() {
    let (url, _h, _db, sync_id, dev) = three_device_group().await;
    let client = Client::new();
    let (_t1, _k1, id1) = &dev[0];
    let path = format!("/v1/sync/{sync_id}/device-messages");
    // No bearer token / no signature.
    let resp = client
        .post(format!("{url}{path}"))
        .json(&serde_json::json!({
            "message_id": mid("f1"),
            "epoch_id": 0,
            "recipient_device_id": id1,
            "payload": b64(b"x"),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn cross_group_isolation() {
    let (url, _h, db) = start_test_relay().await;
    let client = Client::new();
    // Group A with a sender.
    let sa = generate_sync_id();
    db.with_conn(|conn| db::create_sync_group(conn, &sa, 0).map(|_| ())).unwrap();
    let a1 = generate_device_id();
    let (ta1, ka1) = prepare_device(&db, &sa, &a1).await;
    // Group B with a recipient.
    let sb = generate_sync_id();
    db.with_conn(|conn| db::create_sync_group(conn, &sb, 0).map(|_| ())).unwrap();
    let b1 = generate_device_id();
    let (tb1, kb1) = prepare_device(&db, &sb, &b1).await;

    send(&client, &url, &ta1, &ka1, &sa, &a1, &mid("a1"), None, b"x").await;
    // The other group sees nothing.
    assert!(pending(&client, &url, &tb1, &kb1, &sb, &b1).await.is_empty());
}

#[tokio::test]
async fn ack_only_counts_existing_messages() {
    let (url, _h, _db, sync_id, dev) = three_device_group().await;
    let client = Client::new();
    let (t1, k1, id1) = &dev[0];
    let (t2, k2, id2) = &dev[1];

    send(&client, &url, t1, k1, &sync_id, id1, &mid("g1"), None, b"x").await;
    let r = ack(&client, &url, t2, k2, &sync_id, id2, &[&mid("g1"), &mid("ffff")]).await;
    assert_eq!(r.json::<Value>().await.unwrap()["acked"], 1, "only the real message is acked");
}

/// A full test Config for mailbox tests with the default-ish knobs; callers
/// override the specific limit under test.
fn base_dm_config() -> Config {
    let mut config = test_config();
    config.device_message_ttl_secs = 604_800;
    config.device_message_max_payload_bytes = 4096;
    config.device_message_send_rate_limit = 100;
    config.device_message_send_rate_window_secs = 60;
    config.device_message_max_pending = 256;
    config.device_message_fetch_limit = 256;
    config
}
