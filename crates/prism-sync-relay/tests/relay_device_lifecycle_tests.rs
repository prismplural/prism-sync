//! Tests for the relay device-lifecycle state machine (active/stale/revoked)
//! and its cleanup transitions, run against the actual prism-sync-relay DB.
//!
//! This file currently hosts the smoke test for the shared device-lifecycle
//! fixture (`age_device` / `run_mark_stale_devices` / `run_auto_revoke_devices`
//! in `common`); the device-trust-lockout behavioral tests build on the same
//! helpers.

mod common;

use common::{
    age_device, apply_signed_headers, device_status, expire_device_session, group_needs_rekey,
    prepare_device, run_auto_revoke_devices, run_mark_stale_devices, start_test_relay,
    start_test_relay_with_config, start_test_relay_with_state, test_config, TestDeviceKeys,
    AUTO_REVOKE_SECS, STALE_DEVICE_SECS,
};
use ed25519_dalek::Signer;
use futures::StreamExt;
use prism_sync_crypto::pq::hybrid_signature_contexts;
use prism_sync_relay::db;
use reqwest::Client;
use serde_json::Value;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest,
    http::{header::AUTHORIZATION, HeaderValue},
    Message,
};

const fn day_secs(days: i64) -> i64 {
    days * 86_400
}

/// POST a signed `/session/refresh` for `device_id` using its `TestDeviceKeys`,
/// with a fresh UUID nonce and the current timestamp.
async fn refresh_session(
    client: &Client,
    url: &str,
    sync_id: &str,
    device_id: &str,
    keys: &TestDeviceKeys,
) -> reqwest::Response {
    let body = serde_json::json!({ "device_id": device_id });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let path = format!("/v1/sync/{sync_id}/session/refresh");
    apply_signed_headers(
        client
            .post(format!("{url}{path}"))
            .header("X-Device-Id", device_id)
            .header("Content-Type", "application/json"),
        keys,
        "POST",
        &path,
        sync_id,
        device_id,
        &body_bytes,
    )
    .body(body_bytes)
    .send()
    .await
    .unwrap()
}

/// POST a signed `/session/refresh` with caller-controlled timestamp + nonce so
/// the replay and timestamp-skew rejections can be exercised deterministically.
#[allow(clippy::too_many_arguments)]
async fn refresh_session_with(
    client: &Client,
    url: &str,
    sync_id: &str,
    device_id: &str,
    keys: &TestDeviceKeys,
    sign_with: &TestDeviceKeys,
    timestamp: &str,
    nonce: &str,
) -> reqwest::Response {
    let body = serde_json::json!({ "device_id": device_id });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let path = format!("/v1/sync/{sync_id}/session/refresh");
    let ml_dsa_key = sign_with.device_secret.ml_dsa_65_keypair(device_id).unwrap();
    let signing_data = prism_sync_relay::auth::build_request_signing_data_v2(
        "POST", &path, sync_id, device_id, &body_bytes, timestamp, nonce,
    );
    let m_prime = prism_sync_crypto::pq::build_hybrid_message_representative(
        hybrid_signature_contexts::HTTP_REQUEST,
        &signing_data,
    )
    .unwrap();
    let hybrid_sig = prism_sync_crypto::pq::HybridSignature {
        ed25519_sig: sign_with.ed25519_signing_key.sign(&m_prime).to_bytes().to_vec(),
        ml_dsa_65_sig: ml_dsa_key.sign(&m_prime),
    };
    let mut wire = vec![0x03u8];
    wire.extend_from_slice(&hybrid_sig.to_bytes());
    let _ = keys; // identity is taken from the stored row; `keys` documents intent
    client
        .post(format!("{url}{path}"))
        .header("X-Device-Id", device_id)
        .header("Content-Type", "application/json")
        .header("X-Prism-Timestamp", timestamp)
        .header("X-Prism-Nonce", nonce)
        .header("X-Prism-Signature", base64::engine::general_purpose::STANDARD.encode(&wire))
        .body(body_bytes)
        .send()
        .await
        .unwrap()
}

/// Push a batch with signed headers, returning the raw response.
async fn push_signed(
    client: &Client,
    url: &str,
    sync_id: &str,
    device_id: &str,
    token: &str,
    keys: &TestDeviceKeys,
    batch_id: &str,
) -> reqwest::Response {
    let envelope = common::make_test_envelope(sync_id, device_id, batch_id, 0);
    let body_bytes = serde_json::to_vec(&envelope).unwrap();
    let path = format!("/v1/sync/{sync_id}/changes");
    apply_signed_headers(
        client
            .put(format!("{url}{path}"))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Device-Id", device_id)
            .header("X-Batch-Id", batch_id)
            .header("Content-Type", "application/json"),
        keys,
        "PUT",
        &path,
        sync_id,
        device_id,
        &body_bytes,
    )
    .body(body_bytes)
    .send()
    .await
    .unwrap()
}

use base64::Engine as _;

/// The fixture can age a device past the stale floor and past the auto-revoke
/// floor, and the cleanup steps drive the documented state transitions:
/// 31d offline + `mark_stale_devices` -> `stale`; 91d offline +
/// `auto_revoke_devices` -> `revoked` with the group flagged `needs_rekey`.
#[tokio::test]
async fn fixture_ages_device_through_stale_and_revoked() {
    let (_url, _server, db) = start_test_relay().await;
    let sync_id = "f".repeat(64);
    let device_id = "device-lifecycle-smoke";

    // The DB-direct device helper does not create the sync_groups row, but
    // auto_revoke flags needs_rekey on it — create it so the flag is readable.
    let sid = sync_id.clone();
    db.with_conn(move |conn| db::create_sync_group(conn, &sid, 0)).expect("create sync group");
    let (_token, _keys) = prepare_device(&db, &sync_id, device_id).await;

    // Freshly registered device starts active, group not yet flagged.
    assert_eq!(device_status(&db, &sync_id, device_id).as_deref(), Some("active"));
    assert_eq!(group_needs_rekey(&db, &sync_id), Some(false));

    // 31 days offline, then mark-stale -> stale.
    age_device(&db, &sync_id, device_id, 31);
    let staled = run_mark_stale_devices(&db, STALE_DEVICE_SECS);
    assert_eq!(staled, 1, "exactly one device should flip to stale");
    assert_eq!(device_status(&db, &sync_id, device_id).as_deref(), Some("stale"));
    // Group is not flagged for rekey by mark-stale alone.
    assert_eq!(group_needs_rekey(&db, &sync_id), Some(false));

    // 91 days offline, then auto-revoke -> revoked + needs_rekey.
    age_device(&db, &sync_id, device_id, 91);
    let revoked = run_auto_revoke_devices(&db, AUTO_REVOKE_SECS);
    assert_eq!(
        revoked,
        vec![(sync_id.clone(), device_id.to_string())],
        "the revoked (sync_id, device_id) pair should be reported"
    );
    assert_eq!(device_status(&db, &sync_id, device_id).as_deref(), Some("revoked"));
    assert_eq!(group_needs_rekey(&db, &sync_id), Some(true));
}

// ───────────────────────── device-revoke behavioral tests ───────────────────

/// A stale device whose session is still valid (SESSION_EXPIRY > STALE_DEVICE)
/// reaches authenticated endpoints and is reactivated by the fire-and-forget
/// touch. The auth middleware no longer treats 'stale' as 'revoked'.
#[tokio::test]
async fn stale_device_with_valid_token_succeeds_and_reactivates() {
    // SESSION_EXPIRY_SECS > STALE_DEVICE_SECS so the session outlives staleness.
    let mut config = test_config();
    config.stale_device_secs = day_secs(30) as u64;
    config.session_expiry_secs = day_secs(60) as u64;
    let (url, _server, db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = "a".repeat(64);
    let device_id = "stale-but-valid";

    let sid = sync_id.clone();
    db.with_conn(move |conn| db::create_sync_group(conn, &sid, 0)).expect("create sync group");
    let (token, keys) = prepare_device(&db, &sync_id, device_id).await;
    // Keep the freshly-minted session valid (60d) but age last_seen_at + flip
    // the device to stale via the cleanup pass.
    age_device(&db, &sync_id, device_id, 31);
    let staled = run_mark_stale_devices(&db, day_secs(30));
    assert_eq!(staled, 1);
    assert_eq!(device_status(&db, &sync_id, device_id).as_deref(), Some("stale"));

    // An authenticated GET succeeds (was a false 401 device_revoked before the fix).
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/devices"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "stale device with valid token should be served");

    // The Phase-2 fire-and-forget touch reactivates it. Poll briefly.
    let mut reactivated = false;
    for _ in 0..50 {
        if device_status(&db, &sync_id, device_id).as_deref() == Some("active") {
            reactivated = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(reactivated, "stale device should auto-reactivate on a touched request");
    let _ = keys;
}

/// A device aged past stale AND with an expired session recovers via the signed
/// `/session/refresh` door: 200 + a fresh token + status flips to active, and a
/// previously-stranded push then succeeds with the new token.
#[tokio::test]
async fn expired_session_recovers_via_refresh_then_push_succeeds() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = "b".repeat(64);
    let device_id = "expired-session-dev";

    let sid = sync_id.clone();
    db.with_conn(move |conn| db::create_sync_group(conn, &sid, 0)).expect("create sync group");
    let (_old_token, keys) = prepare_device(&db, &sync_id, device_id).await;

    // 31 days offline -> stale, and force the session to be expired too (the
    // default config aligns SESSION_EXPIRY with STALE_DEVICE).
    age_device(&db, &sync_id, device_id, 31);
    run_mark_stale_devices(&db, STALE_DEVICE_SECS);
    expire_device_session(&db, &sync_id, device_id);
    assert_eq!(device_status(&db, &sync_id, device_id).as_deref(), Some("stale"));

    // Refresh recovers a fresh session token.
    let resp = refresh_session(&client, &url, &sync_id, device_id, &keys).await;
    assert_eq!(resp.status(), 200, "stale device should recover via session refresh");
    let json: Value = resp.json().await.unwrap();
    let new_token = json["device_session_token"].as_str().expect("fresh session token").to_string();
    assert!(!new_token.is_empty());
    assert_eq!(device_status(&db, &sync_id, device_id).as_deref(), Some("active"));

    // The stranded push now succeeds with the new token.
    let push = push_signed(&client, &url, &sync_id, device_id, &new_token, &keys, "stranded-1").await;
    assert!(push.status().is_success(), "post-refresh push should succeed: {}", push.status());
    let push_json: Value = push.json().await.unwrap();
    assert!(push_json["server_seq"].as_i64().unwrap() > 0);
}

/// Refresh for a genuinely revoked device returns a structured 401 carrying a
/// verifiable `signed_registry` blob (and `remote_wipe`), with no status change.
#[tokio::test]
async fn refresh_for_revoked_returns_signed_registry() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = "c".repeat(64);
    let device_id = "revoked-dev";

    let sid = sync_id.clone();
    db.with_conn(move |conn| db::create_sync_group(conn, &sid, 0)).expect("create sync group");
    let (_token, keys) = prepare_device(&db, &sync_id, device_id).await;

    // Store a registry artifact (and the state row that points at it) so the
    // refresh body can serve the latest stored artifact.
    let sid = sync_id.clone();
    db.with_conn(move |conn| {
        db::upsert_registry_state(conn, &sid, 1, "hash-1")?;
        db::store_registry_artifact(conn, &sid, 1, "hash-1", "signed_registry_snapshot", b"registry-blob")
    })
    .expect("store registry artifact");

    // Auto-revoke the device (91d offline).
    age_device(&db, &sync_id, device_id, 91);
    run_auto_revoke_devices(&db, AUTO_REVOKE_SECS);
    assert_eq!(device_status(&db, &sync_id, device_id).as_deref(), Some("revoked"));

    let resp = refresh_session(&client, &url, &sync_id, device_id, &keys).await;
    assert_eq!(resp.status(), 401, "revoked device refresh must be 401");
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["error"].as_str(), Some("device_revoked"));
    assert!(json.get("remote_wipe").is_some());
    let signed = json["signed_registry"].as_str().expect("signed_registry present");
    let decoded = base64::engine::general_purpose::STANDARD.decode(signed).expect("valid base64");
    assert_eq!(decoded, b"registry-blob", "signed_registry must serve the stored artifact");

    // Status unchanged.
    assert_eq!(device_status(&db, &sync_id, device_id).as_deref(), Some("revoked"));
}

/// Wrong-key, replayed-nonce, and skewed-timestamp refresh requests all return
/// 401 with no status change.
#[tokio::test]
async fn refresh_rejects_wrong_key_replay_and_skew() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = "d".repeat(64);
    let device_id = "stale-refresh-guarded";

    let sid = sync_id.clone();
    db.with_conn(move |conn| db::create_sync_group(conn, &sid, 0)).expect("create sync group");
    let (_token, keys) = prepare_device(&db, &sync_id, device_id).await;
    age_device(&db, &sync_id, device_id, 31);
    run_mark_stale_devices(&db, STALE_DEVICE_SECS);
    expire_device_session(&db, &sync_id, device_id);

    let now = db::now_secs().to_string();

    // (1) Wrong signing keys -> 401, still stale.
    let wrong_keys = TestDeviceKeys::generate(device_id);
    let resp = refresh_session_with(
        &client, &url, &sync_id, device_id, &keys, &wrong_keys, &now, "nonce-wrong-key",
    )
    .await;
    assert_eq!(resp.status(), 401, "wrong-key refresh must be rejected");
    assert_eq!(device_status(&db, &sync_id, device_id).as_deref(), Some("stale"));

    // (2) Skewed timestamp (well beyond the 60s window) -> 401, still stale.
    let skewed = (db::now_secs() - 3600).to_string();
    let resp = refresh_session_with(
        &client, &url, &sync_id, device_id, &keys, &keys, &skewed, "nonce-skew",
    )
    .await;
    assert_eq!(resp.status(), 401, "skewed-timestamp refresh must be rejected");
    assert_eq!(device_status(&db, &sync_id, device_id).as_deref(), Some("stale"));

    // (3) Replayed nonce: first use must succeed (recovers the device), the
    // replay of the same nonce must be rejected. Re-stale between so the second
    // attempt is observably a no-op on a now-active device — instead we assert
    // the replay is 401 directly.
    let ts = db::now_secs().to_string();
    let first = refresh_session_with(
        &client, &url, &sync_id, device_id, &keys, &keys, &ts, "nonce-replay",
    )
    .await;
    assert_eq!(first.status(), 200, "first use of a fresh nonce should succeed");
    let replay = refresh_session_with(
        &client, &url, &sync_id, device_id, &keys, &keys, &ts, "nonce-replay",
    )
    .await;
    assert_eq!(replay.status(), 401, "replayed nonce must be rejected");
}

/// Re-register of a stale device with matching keys reactivates it; mismatched
/// keys yield DeviceIdentityMismatch; a revoked device is told it was revoked.
#[tokio::test]
async fn stale_reregister_reactivates_mismatch_and_revoked_rejected() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = common::generate_sync_id();

    // First device admits the group (creates it) so subsequent registrations go
    // through the existing-group / registry-approval path.
    let admin_id = common::generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let _admin_token = common::register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;

    // Insert the joiner directly so we control its keys, then age it to stale.
    let dev_id = common::generate_device_id();
    let (_t, dev_keys) = prepare_device(&db, &sync_id, &dev_id).await;
    age_device(&db, &sync_id, &dev_id, 31);
    run_mark_stale_devices(&db, STALE_DEVICE_SECS);
    assert_eq!(device_status(&db, &sync_id, &dev_id).as_deref(), Some("stale"));

    // (a) Re-register with matching keys + a fresh admin approval -> 200 and
    // reactivates (was 403 'Device has been revoked' before the fix).
    let resp =
        reregister(&client, &url, &sync_id, &admin_id, &admin_keys, &dev_id, &dev_keys, &dev_keys)
            .await;
    assert_eq!(resp.status(), 201, "stale re-register with matching keys should reactivate");
    assert_eq!(device_status(&db, &sync_id, &dev_id).as_deref(), Some("active"));

    // (b) Re-stale, then re-register presenting MISMATCHED keys while the
    // approval snapshot names the real stored keys -> DeviceIdentityMismatch
    // (the key-match proof gate stays intact for a stale device).
    age_device(&db, &sync_id, &dev_id, 31);
    run_mark_stale_devices(&db, STALE_DEVICE_SECS);
    let wrong_keys = TestDeviceKeys::generate(&dev_id);
    let resp = reregister(
        &client, &url, &sync_id, &admin_id, &admin_keys, &dev_id, &wrong_keys, &dev_keys,
    )
    .await;
    assert_eq!(resp.status(), 401, "mismatched keys must yield DeviceIdentityMismatch");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"].as_str(), Some("device_identity_mismatch"));

    // (c) Revoke the device, then re-register with matching keys -> 403.
    let sid = sync_id.clone();
    let did = dev_id.clone();
    db.with_conn(move |conn| {
        conn.execute(
            "UPDATE devices SET status = 'revoked', revoked_at = ?1 WHERE sync_id = ?2 AND device_id = ?3",
            rusqlite::params![db::now_secs(), sid, did],
        )?;
        Ok::<_, rusqlite::Error>(())
    })
    .unwrap();
    let resp =
        reregister(&client, &url, &sync_id, &admin_id, &admin_keys, &dev_id, &dev_keys, &dev_keys)
            .await;
    assert_eq!(resp.status(), 403, "revoked device re-register must be forbidden");
    assert_eq!(device_status(&db, &sync_id, &dev_id).as_deref(), Some("revoked"));
}

/// Regression: a genuinely revoked device holding a still-valid revoked session
/// keeps getting the structured `device_revoked` 401 from auth_middleware on
/// every non-exempt route (the registry-exemption path is unchanged).
#[tokio::test]
async fn revoked_device_still_gets_structured_401_from_auth_middleware() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = "e".repeat(64);
    let device_id = "revoked-with-session";

    let sid = sync_id.clone();
    db.with_conn(move |conn| db::create_sync_group(conn, &sid, 0)).expect("create sync group");
    let (token, _keys) = prepare_device(&db, &sync_id, device_id).await;

    // Move the device's live session into the revoked-session table and mark the
    // device revoked, mirroring an atomic revoke (which keeps the session valid
    // so the device can fetch the signed registry / learn of its revocation).
    let sid = sync_id.clone();
    let did = device_id.to_string();
    db.with_conn(move |conn| {
        db::revoke_session(conn, &sid, &did, day_secs(30))?;
        conn.execute(
            "UPDATE devices SET status = 'revoked', revoked_at = ?1 WHERE sync_id = ?2 AND device_id = ?3",
            rusqlite::params![db::now_secs(), sid, did],
        )?;
        Ok::<_, rusqlite::Error>(())
    })
    .unwrap();

    // A non-exempt authenticated GET (pull) returns the structured device_revoked 401.
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/changes?since=0"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["error"].as_str(), Some("device_revoked"));
}

/// Regression: a revoked device may STILL `GET /v1/sync/{id}/registry` (the
/// registry exemption added in commit 1b4dd59), while every other route —
/// including the new `/session/refresh` and an ordinary pull — keeps the 401.
/// The device-revoke middleware rework must not leak or remove this exemption.
#[tokio::test]
async fn revoked_device_registry_get_exemption_is_preserved() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = "1".repeat(64);
    let device_id = "revoked-c7";

    let sid = sync_id.clone();
    db.with_conn(move |conn| {
        db::create_sync_group(conn, &sid, 0)?;
        db::upsert_registry_state(conn, &sid, 1, "hash-1")?;
        db::store_registry_artifact(conn, &sid, 1, "hash-1", "signed_registry_snapshot", b"reg")?;
        Ok::<_, rusqlite::Error>(())
    })
    .expect("seed group + registry");
    let (token, _keys) = prepare_device(&db, &sync_id, device_id).await;

    // Atomic-revoke shape: keep a valid revoked session, mark the device revoked.
    let sid = sync_id.clone();
    let did = device_id.to_string();
    db.with_conn(move |conn| {
        db::revoke_session(conn, &sid, &did, day_secs(30))?;
        conn.execute(
            "UPDATE devices SET status = 'revoked', revoked_at = ?1 WHERE sync_id = ?2 AND device_id = ?3",
            rusqlite::params![db::now_secs(), sid, did],
        )?;
        Ok::<_, rusqlite::Error>(())
    })
    .unwrap();

    // GET /registry is exempt -> 200.
    let registry = client
        .get(format!("{url}/v1/sync/{sync_id}/registry"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(registry.status(), 200, "revoked device must still read its own registry (C7)");

    // A pull is NOT exempt -> 401 device_revoked.
    let pull = client
        .get(format!("{url}/v1/sync/{sync_id}/changes?since=0"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(pull.status(), 401, "pull stays locked out for a revoked device");
}

/// A `stale` target must stay revocable. With this change a stale
/// device can self-reactivate via `/session/refresh`, so if the owner could not
/// revoke it the composition would be strictly weaker than before for a
/// lost/stolen device idle >30d. Atomic-revoking a stale target succeeds (200),
/// flips it to `revoked`, wraps keys for exactly the active survivor set (the
/// stale target excluded — no artifact is stored for it), and its subsequent
/// `/session/refresh` returns the structured `device_revoked` 401.
#[tokio::test]
async fn atomic_revoke_of_stale_target_succeeds_and_then_refresh_is_401() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = common::generate_sync_id();

    // Admin (the revoker) registers over HTTP so it has a valid session/token.
    let admin_id = common::generate_device_id();
    let admin_keys = TestDeviceKeys::generate(&admin_id);
    let admin_token = common::register_device(&client, &url, &sync_id, &admin_id, &admin_keys).await;

    // Target joins via DB so we control its keys, then ages to stale (30–90d).
    let target_id = common::generate_device_id();
    let (_target_token, target_keys) = prepare_device(&db, &sync_id, &target_id).await;
    age_device(&db, &sync_id, &target_id, 31);
    run_mark_stale_devices(&db, STALE_DEVICE_SECS);
    assert_eq!(device_status(&db, &sync_id, &target_id).as_deref(), Some("stale"));

    // Atomic-revoke the stale target. The wrapped-key set is exactly the active
    // survivor set {admin} — the stale target is already excluded, so this is
    // the same set the client builds from `status == "active"`.
    let b64 = base64::engine::general_purpose::STANDARD;
    let wrapped_for_admin = b"wrapped-epoch-1-for-admin";
    let revoke_body = serde_json::json!({
        "new_epoch": 1,
        "remote_wipe": false,
        "wrapped_keys": { admin_id.clone(): b64.encode(wrapped_for_admin) },
    });
    let revoke_body_bytes = serde_json::to_vec(&revoke_body).unwrap();
    let revoke_path = format!("/v1/sync/{sync_id}/devices/{target_id}/revoke");
    let revoke_resp = apply_signed_headers(
        client.post(format!("{url}{revoke_path}")),
        &admin_keys,
        "POST",
        &revoke_path,
        &sync_id,
        &admin_id,
        &revoke_body_bytes,
    )
    .header("Authorization", format!("Bearer {admin_token}"))
    .header("X-Device-Id", &admin_id)
    .header("Content-Type", "application/json")
    .body(revoke_body_bytes)
    .send()
    .await
    .unwrap();
    assert_eq!(
        revoke_resp.status(),
        200,
        "revoking a stale target must succeed: {:?}",
        revoke_resp.text().await.ok()
    );
    assert_eq!(device_status(&db, &sync_id, &target_id).as_deref(), Some("revoked"));

    // The wrapped keys cover the active survivor set only: admin has an epoch-1
    // artifact, the (now-revoked, formerly-stale) target has none.
    let sid = sync_id.clone();
    let aid = admin_id.clone();
    let tid = target_id.clone();
    let (admin_artifact, target_artifact) = db
        .with_conn(move |conn| {
            Ok((
                db::get_rekey_artifact(conn, &sid, 1, &aid)?,
                db::get_rekey_artifact(conn, &sid, 1, &tid)?,
            ))
        })
        .unwrap();
    assert_eq!(admin_artifact.as_deref(), Some(&wrapped_for_admin[..]));
    assert!(target_artifact.is_none(), "no epoch-1 artifact for the revoked target");

    // The target can no longer self-reactivate: `/session/refresh` is now the
    // structured `device_revoked` 401, not a fresh session.
    let refresh = refresh_session(&client, &url, &sync_id, &target_id, &target_keys).await;
    assert_eq!(refresh.status(), 401, "revoked stale target must not refresh back to active");
    let json: Value = refresh.json().await.unwrap();
    assert_eq!(json["error"].as_str(), Some("device_revoked"));
    assert_eq!(device_status(&db, &sync_id, &target_id).as_deref(), Some("revoked"));
}

/// A validly-signed `/session/refresh` for one sync group is rejected when
/// replayed against another group's path: the signing data binds sync_id, so the
/// signature fails verification under the second group's device row. The same
/// device_id AND keys are registered in both groups, so sync_id binding is the
/// *only* thing that can reject the cross-group request.
#[tokio::test]
async fn refresh_signed_for_one_sync_is_rejected_against_another() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();

    let sync_a = "a".repeat(64);
    let sync_b = "b".repeat(64);
    let device_id = "shared-device-id";

    let sa = sync_a.clone();
    let sb = sync_b.clone();
    db.with_conn(move |conn| {
        db::create_sync_group(conn, &sa, 0)?;
        db::create_sync_group(conn, &sb, 0)?;
        Ok::<_, rusqlite::Error>(())
    })
    .unwrap();

    // Register the device in group A normally, then mirror the SAME keys into
    // group B's devices row so only sync_id differs between the two rows.
    let (_ta, keys_a) = prepare_device(&db, &sync_a, device_id).await;
    let sb2 = sync_b.clone();
    let did = device_id.to_string();
    let signing_pk = keys_a.ed25519_signing_key.verifying_key().to_bytes().to_vec();
    let x25519_pk = keys_a.x25519_pk.to_vec();
    let ml_dsa_pk = keys_a.ml_dsa_pk.clone();
    let ml_kem_pk = keys_a.ml_kem_pk.clone();
    db.with_conn(move |conn| {
        db::register_device_with_pq(
            conn, &sb2, &did, &signing_pk, &x25519_pk, &ml_dsa_pk, &ml_kem_pk, &[], 0,
        )?;
        Ok::<_, rusqlite::Error>(())
    })
    .unwrap();

    // Sign for group A, but POST to group B's refresh path. The signed-request
    // data is bound to sync_a, so verification against B's stored row fails.
    let body = serde_json::json!({ "device_id": device_id });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let path_b = format!("/v1/sync/{sync_b}/session/refresh");
    let resp = apply_signed_headers(
        client
            .post(format!("{url}{path_b}"))
            .header("X-Device-Id", device_id)
            .header("Content-Type", "application/json"),
        &keys_a,
        "POST",
        // Sign over group A's path/sync_id while sending to group B.
        &format!("/v1/sync/{sync_a}/session/refresh"),
        &sync_a,
        device_id,
        &body_bytes,
    )
    .body(body_bytes)
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 401, "a refresh signed for sync A must not authorize sync B");
    // Neither group's device was reactivated by the rejected request.
    assert_eq!(device_status(&db, &sync_b, device_id).as_deref(), Some("active"));
}

// ─────────────────────── auto-revoke rekey behavioral tests ─────────────────

/// Read WS text frames until one with `type == wanted` arrives (or timeout).
/// Returns the matching frame's JSON. Skips `auth_ok`/`pong` and unrelated types.
async fn await_ws_frame(
    ws: &mut (impl StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
              + Unpin),
    wanted: &str,
) -> Value {
    let deadline = std::time::Duration::from_secs(5);
    loop {
        let next = tokio::time::timeout(deadline, ws.next())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for WS frame type={wanted}"));
        match next {
            Some(Ok(Message::Text(text))) => {
                let json: Value = match serde_json::from_str(&text) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if json["type"].as_str() == Some(wanted) {
                    return json;
                }
            }
            Some(Ok(_)) => continue,
            other => panic!("WS closed/errored before {wanted}: {other:?}"),
        }
    }
}

/// The cleanup auto-revoke parks the victim's session into
/// `revoked_device_sessions` (so its still-valid token returns the structured
/// `device_revoked` 401), and broadcasts both a `device_revoked` and a
/// `rekey_needed` WS frame to the surviving devices.
#[tokio::test]
async fn auto_revoke_parks_session_and_cleanup_emits_both_ws_frames() {
    // SESSION_EXPIRY_SECS > the offline gap so the victim's session is still
    // valid when it gets parked as revoked (the structured-401 case lives only
    // under non-default config; default-aligned returners use /session/refresh).
    let mut config = test_config();
    config.stale_device_secs = day_secs(30) as u64;
    config.session_expiry_secs = day_secs(120) as u64;
    let (url, _server, db, state) = start_test_relay_with_state(config).await;
    let client = Client::new();
    let sync_id = common::generate_sync_id();

    // Survivor registers over HTTP (creates the group, opens a WS below).
    let survivor_id = common::generate_device_id();
    let survivor_keys = TestDeviceKeys::generate(&survivor_id);
    let survivor_token =
        common::register_device(&client, &url, &sync_id, &survivor_id, &survivor_keys).await;

    // Victim joins with a long-lived session, then ages 91d offline.
    let victim_id = common::generate_device_id();
    let (victim_token, victim_keys) = prepare_device(&db, &sync_id, &victim_id).await;
    // Give the victim's session the long expiry too (prepare_device mints 3600s).
    let sid = sync_id.clone();
    let did = victim_id.clone();
    db.with_conn(move |conn| {
        conn.execute(
            "UPDATE device_sessions SET expires_at = ?1 WHERE sync_id = ?2 AND device_id = ?3",
            rusqlite::params![db::now_secs() + day_secs(120), sid, did],
        )?;
        Ok::<_, rusqlite::Error>(())
    })
    .unwrap();
    age_device(&db, &sync_id, &victim_id, 91);

    // Survivor opens a WS so it can receive the cleanup broadcasts.
    let mut req = format!("{url}/v1/sync/{sync_id}/ws")
        .replacen("http://", "ws://", 1)
        .into_client_request()
        .unwrap();
    req.headers_mut().insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {survivor_token}")).unwrap(),
    );
    let (mut ws, _) = connect_async(req).await.expect("survivor WS upgrade");
    // Drain the initial auth_ok so it doesn't shadow our matching below.
    let _ = await_ws_frame(&mut ws, "auth_ok").await;

    // Trigger one cleanup pass against the shared state.
    prism_sync_relay::cleanup::run_cleanup(&state).await;

    // The victim is revoked and the group is flagged for rekey.
    assert_eq!(device_status(&db, &sync_id, &victim_id).as_deref(), Some("revoked"));
    assert_eq!(group_needs_rekey(&db, &sync_id), Some(true));

    // Both WS frames reach the survivor.
    let revoked_frame = await_ws_frame(&mut ws, "device_revoked").await;
    assert_eq!(revoked_frame["device_id"].as_str(), Some(victim_id.as_str()));
    assert_eq!(revoked_frame["remote_wipe"].as_bool(), Some(false));
    let _rekey_frame = await_ws_frame(&mut ws, "rekey_needed").await;

    // The victim's still-valid token now returns the structured device_revoked
    // 401 (its session was moved into revoked_device_sessions).
    let pull = client
        .get(format!("{url}/v1/sync/{sync_id}/changes?since=0"))
        .header("Authorization", format!("Bearer {victim_token}"))
        .header("X-Device-Id", &victim_id)
        .send()
        .await
        .unwrap();
    assert_eq!(pull.status(), 401, "auto-revoked victim's old token must be 401");
    let json: Value = pull.json().await.unwrap();
    assert_eq!(json["error"].as_str(), Some("device_revoked"));

    let _ = ws.close(None).await;
    let _ = victim_keys;
    let _ = survivor_keys;
}

/// Cross-config companion: under the DEFAULT aligned config (the victim's
/// session has already expired by the time it is auto-revoked), a returner still
/// gets a verifiable structured `device_revoked` answer on BOTH doors:
///   - its now-expired token: `auto_revoke_devices` parks the token into
///     `revoked_device_sessions` with a fixed 30d retention that is independent
///     of `SESSION_EXPIRY_SECS`, so `validate_revoked_session` matches it and the
///     auth middleware returns the structured `device_revoked` 401 (not a generic
///     one) for that window;
///   - a signed `/session/refresh` (the door the db.rs comment names): 401
///     with the same structured `device_revoked`.
/// This pins the cross-config story so a future change to either door can't
/// silently regress a default-config returner to a bare "Unauthorized".
#[tokio::test]
async fn auto_revoke_default_config_returner_gets_structured_device_revoked() {
    // Default-aligned config: STALE (30d) < SESSION_EXPIRY, victim ages past the
    // 90d auto-revoke floor and its 3600s session has long since expired.
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = common::generate_sync_id();

    let sid = sync_id.clone();
    db.with_conn(move |conn| db::create_sync_group(conn, &sid, 0)).expect("create sync group");
    let victim_id = common::generate_device_id();
    let (victim_token, victim_keys) = prepare_device(&db, &sync_id, &victim_id).await;
    age_device(&db, &sync_id, &victim_id, 91);
    // The session TTL elapsed while the device was offline — the default case the
    // db.rs comment describes (vs. the non-default still-valid-token case above).
    expire_device_session(&db, &sync_id, &victim_id);

    // Auto-revoke: revokes the victim and parks its (expired) token as revoked.
    let revoked = run_auto_revoke_devices(&db, AUTO_REVOKE_SECS);
    assert!(
        revoked.iter().any(|(s, d)| s == &sync_id && d == &victim_id),
        "victim must be auto-revoked"
    );
    assert_eq!(device_status(&db, &sync_id, &victim_id).as_deref(), Some("revoked"));

    // Door 1 — the expired bearer token: the parked session means the auth
    // middleware answers with the STRUCTURED `device_revoked` 401, not a bare
    // "Unauthorized", even though the original session had already expired.
    let pull = client
        .get(format!("{url}/v1/sync/{sync_id}/changes?since=0"))
        .header("Authorization", format!("Bearer {victim_token}"))
        .header("X-Device-Id", &victim_id)
        .send()
        .await
        .unwrap();
    assert_eq!(pull.status(), 401, "expired token of an auto-revoked device must be 401");
    let pull_json: Value = pull.json().await.unwrap();
    assert_eq!(
        pull_json["error"].as_str(),
        Some("device_revoked"),
        "the parked session yields the structured answer under default config too"
    );

    // Door 2 — the signed `/session/refresh` recovery path: also the structured
    // `device_revoked` 401, so a returner whose parked window has lapsed still
    // gets a verifiable terminal answer instead of looping in reconnecting.
    let refresh = refresh_session(&client, &url, &sync_id, &victim_id, &victim_keys).await;
    assert_eq!(refresh.status(), 401, "refreshing an auto-revoked device must not mint a token");
    let refresh_json: Value = refresh.json().await.unwrap();
    assert_eq!(refresh_json["error"].as_str(), Some("device_revoked"));
    assert_eq!(device_status(&db, &sync_id, &victim_id).as_deref(), Some("revoked"));
}

// ── helper for the re-register test ──

/// POST `/register` for `dev_id` into an existing group, attaching an admin
/// registry approval. `presented_keys` are the public keys put in the register
/// body (and used to sign the challenge); `snapshot_keys` are the keys named for
/// `dev_id` in the approval snapshot — they differ only to drive the mismatch
/// case. Returns the raw response so callers assert the status.
#[allow(clippy::too_many_arguments)]
async fn reregister(
    client: &Client,
    url: &str,
    sync_id: &str,
    admin_id: &str,
    admin_keys: &TestDeviceKeys,
    dev_id: &str,
    presented_keys: &TestDeviceKeys,
    snapshot_keys: &TestDeviceKeys,
) -> reqwest::Response {
    let nonce_resp =
        client.get(format!("{url}/v1/sync/{sync_id}/register-nonce")).send().await.unwrap();
    let nonce_json: Value = nonce_resp.json().await.unwrap();
    let nonce = nonce_json["nonce"].as_str().unwrap().to_string();

    let ml_dsa_kp = presented_keys.device_secret.ml_dsa_65_keypair(dev_id).unwrap();
    let challenge_sig = common::sign_hybrid_challenge(
        &presented_keys.ed25519_signing_key,
        &ml_dsa_kp,
        sync_id,
        dev_id,
        &nonce,
    );

    let approval = common::build_registry_approval(
        sync_id,
        admin_id,
        admin_keys,
        vec![
            common::registry_snapshot_entry_hybrid(sync_id, admin_id, admin_keys, "active"),
            common::registry_snapshot_entry_hybrid(sync_id, dev_id, snapshot_keys, "active"),
        ],
    );

    client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": dev_id,
            "signing_public_key": hex::encode(presented_keys.ed25519_signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(presented_keys.x25519_pk),
            "ml_dsa_65_public_key": hex::encode(&presented_keys.ml_dsa_pk),
            "ml_kem_768_public_key": hex::encode(&presented_keys.ml_kem_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
            "registry_approval": approval,
        }))
        .send()
        .await
        .unwrap()
}
