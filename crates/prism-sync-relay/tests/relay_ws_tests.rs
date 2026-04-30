//! End-to-end tests for WebSocket upgrade authentication and rate limiting.

mod common;

use reqwest::Client;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest,
    http::{header::AUTHORIZATION, HeaderValue, Request, StatusCode},
    Error as WsError,
};

use common::*;

fn ws_endpoint(base_url: &str, sync_id: &str) -> String {
    format!("{base_url}/v1/sync/{sync_id}/ws").replacen("http://", "ws://", 1)
}

fn authenticated_ws_request(base_url: &str, sync_id: &str, token: &str) -> Request<()> {
    let mut request = ws_endpoint(base_url, sync_id).into_client_request().unwrap();
    request
        .headers_mut()
        .insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {token}")).unwrap());
    request
}

fn assert_ws_http_status<T>(result: Result<T, WsError>, expected: StatusCode) {
    match result {
        Err(WsError::Http(response)) => assert_eq!(response.status(), expected),
        Err(err) => panic!("expected HTTP {expected}, got websocket error: {err}"),
        Ok(_) => panic!("expected HTTP {expected}, but WebSocket connection opened"),
    }
}

async fn register_test_device(base_url: &str) -> (String, String) {
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, base_url, &sync_id, &device_id, &keys).await;
    (sync_id, token)
}

#[tokio::test]
async fn unauthenticated_ws_upgrade_returns_401_before_connection_opens() {
    let (url, _server, _db) = start_test_relay().await;
    let sync_id = generate_sync_id();
    let request = ws_endpoint(&url, &sync_id).into_client_request().unwrap();

    let result = connect_async(request).await;

    assert_ws_http_status(result, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn spoofed_forwarded_ip_is_ignored_outside_trusted_cidr_for_ws_upgrade_limit() {
    let mut config = test_config();
    config.ws_upgrade_rate_limit = 1;
    config.ws_upgrade_rate_window_secs = 60;
    config.trusted_proxy_cidrs = vec![];
    let (url, _server, _db) = start_test_relay_with_config(config).await;
    let (sync_id, token) = register_test_device(&url).await;

    let mut first = authenticated_ws_request(&url, &sync_id, &token);
    first.headers_mut().insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));
    let (mut ws, _) = connect_async(first).await.expect("first WS upgrade should succeed");

    let mut second = authenticated_ws_request(&url, &sync_id, &token);
    second.headers_mut().insert("x-forwarded-for", HeaderValue::from_static("203.0.113.11"));
    let result = connect_async(second).await;

    assert_ws_http_status(result, StatusCode::TOO_MANY_REQUESTS);
    let _ = ws.close(None).await;
}

#[tokio::test]
async fn trusted_proxy_cidr_uses_forwarded_ip_for_ws_upgrade_limit() {
    let mut config = test_config();
    config.ws_upgrade_rate_limit = 1;
    config.ws_upgrade_rate_window_secs = 60;
    config.trusted_proxy_cidrs = vec!["127.0.0.0/8".into()];
    let (url, _server, _db) = start_test_relay_with_config(config).await;
    let (sync_id, token) = register_test_device(&url).await;

    let mut first = authenticated_ws_request(&url, &sync_id, &token);
    first.headers_mut().insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));
    let (mut ws_a, _) = connect_async(first).await.expect("first WS upgrade should succeed");

    let mut second = authenticated_ws_request(&url, &sync_id, &token);
    second.headers_mut().insert("x-forwarded-for", HeaderValue::from_static("203.0.113.11"));
    let (mut ws_b, _) = connect_async(second).await.expect("second forwarded IP should succeed");

    let mut third = authenticated_ws_request(&url, &sync_id, &token);
    third.headers_mut().insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));
    let result = connect_async(third).await;

    assert_ws_http_status(result, StatusCode::TOO_MANY_REQUESTS);
    let _ = ws_a.close(None).await;
    let _ = ws_b.close(None).await;
}

#[tokio::test]
async fn trusted_proxy_cidr_uses_cf_connecting_ip_and_forwarded_headers_for_ws_upgrade_limit() {
    let mut config = test_config();
    config.ws_upgrade_rate_limit = 1;
    config.ws_upgrade_rate_window_secs = 60;
    config.trusted_proxy_cidrs = vec!["127.0.0.0/8".into()];
    let (url, _server, _db) = start_test_relay_with_config(config).await;
    let (sync_id, token) = register_test_device(&url).await;

    let mut first = authenticated_ws_request(&url, &sync_id, &token);
    first.headers_mut().insert("cf-connecting-ip", HeaderValue::from_static("203.0.113.20"));
    let (mut ws_a, _) =
        connect_async(first).await.expect("CF-Connecting-IP upgrade should succeed");

    let mut second = authenticated_ws_request(&url, &sync_id, &token);
    second.headers_mut().insert("forwarded", HeaderValue::from_static("for=203.0.113.21"));
    let (mut ws_b, _) =
        connect_async(second).await.expect("Forwarded header upgrade should succeed");

    let mut third = authenticated_ws_request(&url, &sync_id, &token);
    third.headers_mut().insert("cf-connecting-ip", HeaderValue::from_static("203.0.113.20"));
    let result = connect_async(third).await;

    assert_ws_http_status(result, StatusCode::TOO_MANY_REQUESTS);
    let _ = ws_a.close(None).await;
    let _ = ws_b.close(None).await;
}
