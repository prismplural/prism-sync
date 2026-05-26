//! Smoke tests for the Prometheus `/metrics` endpoint.

mod common;

use common::*;
use reqwest::Client;

#[tokio::test]
async fn metrics_endpoint_exposes_new_counters() {
    let (url, _server, _db) = start_test_relay().await;
    let body = Client::new()
        .get(format!("{url}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    for line in [
        "# TYPE prism_ws_notifications_dropped_total counter",
        "prism_ws_notifications_dropped_total 0",
        "# TYPE prism_snapshots_rejected_stale_total counter",
        "prism_snapshots_rejected_stale_total 0",
    ] {
        assert!(body.contains(line), "missing {line:?} in:\n{body}");
    }
}
