mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use common::*;
use reqwest::Client;
use serde_json::{json, Value};

use prism_sync_relay::{config::Config, db, GifProviderMode};

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecordedRequest {
    endpoint: &'static str,
    api_key: String,
    query: HashMap<String, String>,
}

#[derive(Clone, Default)]
struct UpstreamState {
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

fn base_test_config() -> Config {
    Config {
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
        gif_provider_mode: GifProviderMode::Disabled,
        gif_public_base_url: None,
        gif_prism_base_url: None,
        gif_api_base_url: "https://api.klipy.com".into(),
        gif_api_key: None,
        gif_http_timeout_secs: 15,
        gif_request_rate_limit: 20,
        gif_request_rate_window_secs: 60,
        gif_query_max_len: 200,
    }
}

async fn start_mock_upstream() -> (String, tokio::task::JoinHandle<()>, UpstreamState) {
    async fn trending(
        Path(api_key): Path<String>,
        Query(query): Query<HashMap<String, String>>,
        State(state): State<UpstreamState>,
    ) -> Json<Value> {
        state.requests.lock().unwrap().push(RecordedRequest {
            endpoint: "trending",
            api_key,
            query,
        });
        Json(json!({
            "data": {
                "data": [{
                    "id": "trend-1",
                    "title": "Trending GIF",
                    "type": "gif",
                    "file": {
                        "xs": {
                            "mp4": {
                                "url": "https://media.klipy.com/trend.mp4",
                                "width": 100,
                                "height": 80
                            },
                            "gif": {
                                "url": "https://media.klipy.com/trend.gif",
                                "width": 100,
                                "height": 80
                            }
                        }
                    }
                }]
            }
        }))
    }

    async fn search(
        Path(api_key): Path<String>,
        Query(query): Query<HashMap<String, String>>,
        State(state): State<UpstreamState>,
    ) -> Json<Value> {
        state.requests.lock().unwrap().push(RecordedRequest {
            endpoint: "search",
            api_key,
            query,
        });
        Json(json!({
            "data": {
                "data": [{
                    "id": "search-1",
                    "title": "Search GIF",
                    "type": "gif",
                    "file": {
                        "xs": {
                            "mp4": {
                                "url": "https://media.klipy.com/search.mp4",
                                "width": 120,
                                "height": 90
                            },
                            "gif": {
                                "url": "https://media.klipy.com/search.gif",
                                "width": 120,
                                "height": 90
                            }
                        }
                    }
                }]
            }
        }))
    }

    let state = UpstreamState::default();
    let app = Router::new()
        .route("/api/v1/{api_key}/gifs/trending", get(trending))
        .route("/api/v1/{api_key}/gifs/search", get(search))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, handle, state)
}

async fn prepare_capabilities_client(
    config: Config,
) -> (String, tokio::task::JoinHandle<()>, String, String, String) {
    let (url, handle, db) = start_test_relay_with_config(config).await;
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    db.with_conn(|conn| {
        db::create_sync_group(conn, &sync_id, 0)?;
        Ok(())
    })
    .unwrap();
    let (token, _keys) = prepare_device(&db, &sync_id, &device_id).await;
    (url, handle, sync_id, device_id, token)
}

#[tokio::test]
async fn capabilities_require_authentication() {
    let config = base_test_config();
    let (url, _handle, _sync_id, _device_id, _token) = prepare_capabilities_client(config).await;

    let client = Client::new();
    let response = client
        .get(format!("{url}/v1/sync/{}/capabilities", generate_sync_id()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn capabilities_report_disabled_mode() {
    let config = base_test_config();
    let (url, _handle, sync_id, _device_id, token) = prepare_capabilities_client(config).await;

    let client = Client::new();
    let response = client
        .get(format!("{url}/v1/sync/{sync_id}/capabilities"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let json: Value = response.json().await.unwrap();
    assert_eq!(json["gifs"]["enabled"], false);
    assert_eq!(json["gifs"]["media_proxy_enabled"], false);
    assert!(json["gifs"].get("api_base_url").is_none());
}

#[tokio::test]
async fn capabilities_report_prism_hosted_mode() {
    let mut config = base_test_config();
    config.gif_provider_mode = GifProviderMode::PrismHosted;
    config.gif_prism_base_url = Some("https://gif.prism.app/v1/gifs".into());
    let (url, _handle, sync_id, _device_id, token) = prepare_capabilities_client(config).await;

    let client = Client::new();
    let response = client
        .get(format!("{url}/v1/sync/{sync_id}/capabilities"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let json: Value = response.json().await.unwrap();
    assert_eq!(json["gifs"]["enabled"], true);
    assert_eq!(json["gifs"]["api_base_url"], "https://gif.prism.app/v1/gifs");
}

#[tokio::test]
async fn self_hosted_proxy_forwards_trending_and_search() {
    let (upstream_url, _upstream_handle, upstream_state) = start_mock_upstream().await;

    let mut config = base_test_config();
    config.gif_provider_mode = GifProviderMode::SelfHosted;
    config.gif_public_base_url = Some("/v1/gifs".into());
    config.gif_api_base_url = upstream_url;
    config.gif_api_key = Some("relay-secret".into());
    config.gif_request_rate_limit = 10;

    let (url, _relay_handle, sync_id, _device_id, token) = prepare_capabilities_client(config).await;
    let client = Client::new();

    let capabilities = client
        .get(format!("{url}/v1/sync/{sync_id}/capabilities"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(capabilities.status(), 200);
    let capabilities_json: Value = capabilities.json().await.unwrap();
    assert_eq!(capabilities_json["gifs"]["api_base_url"], "/v1/gifs");

    let trending = client
        .get(format!("{url}/v1/gifs/trending?per_page=3"))
        .send()
        .await
        .unwrap();
    assert_eq!(trending.status(), 200);
    let trending_json: Value = trending.json().await.unwrap();
    assert_eq!(trending_json["data"]["data"][0]["id"], "trend-1");

    let search = client
        .get(format!("{url}/v1/gifs/search?q=cats&per_page=4"))
        .send()
        .await
        .unwrap();
    assert_eq!(search.status(), 200);
    let search_json: Value = search.json().await.unwrap();
    assert_eq!(search_json["data"]["data"][0]["id"], "search-1");

    let requests = upstream_state.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].endpoint, "trending");
    assert_eq!(requests[0].api_key, "relay-secret");
    assert_eq!(requests[0].query.get("per_page").map(String::as_str), Some("3"));
    assert_eq!(requests[0].query.get("page").map(String::as_str), Some("1"));
    assert_eq!(
        requests[0].query.get("content_filter").map(String::as_str),
        Some("medium")
    );
    assert_eq!(requests[1].endpoint, "search");
    assert_eq!(requests[1].api_key, "relay-secret");
    assert_eq!(requests[1].query.get("q").map(String::as_str), Some("cats"));
    assert_eq!(requests[1].query.get("per_page").map(String::as_str), Some("4"));
}

#[tokio::test]
async fn self_hosted_proxy_rate_limits_requests() {
    let (upstream_url, _upstream_handle, _upstream_state) = start_mock_upstream().await;

    let mut config = base_test_config();
    config.gif_provider_mode = GifProviderMode::SelfHosted;
    config.gif_public_base_url = Some("/v1/gifs".into());
    config.gif_api_base_url = upstream_url;
    config.gif_api_key = Some("relay-secret".into());
    config.gif_request_rate_limit = 1;
    config.gif_request_rate_window_secs = 60;

    let (url, _relay_handle, _sync_id, _device_id, _token) = prepare_capabilities_client(config).await;
    let client = Client::new();

    let first = client
        .get(format!("{url}/v1/gifs/trending"))
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);

    let second = client
        .get(format!("{url}/v1/gifs/trending"))
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), 429);
}
