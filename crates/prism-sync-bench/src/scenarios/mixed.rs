use anyhow::Result;
use futures::StreamExt;
use reqwest::Client;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

use crate::client::SimulatedClient;
use crate::relay;
use crate::stats::Stats;

pub(crate) async fn run(
    http: &Client,
    base_url: &str,
    ws_clients: usize,
    active_clients: usize,
    sync_interval: Duration,
    duration: Duration,
    report_interval: Duration,
) -> Result<()> {
    let stats = Arc::new(Stats::new());
    let ws_connected = Arc::new(AtomicUsize::new(0));
    let total_clients = ws_clients + active_clients;

    // Each client gets its own sync group (joining existing groups requires
    // signed invitations). This tests server capacity accurately.
    println!("Registering {total_clients} devices ({ws_clients} WS + {active_clients} active)...");
    let mut all_clients = Vec::with_capacity(total_clients);

    for _ in 0..ws_clients {
        all_clients.push((SimulatedClient::new(relay::generate_sync_id()), false));
    }
    for _ in 0..active_clients {
        all_clients.push((SimulatedClient::new(relay::generate_sync_id()), true));
    }

    // Register all
    let sem = Arc::new(Semaphore::new(50));
    let mut reg_handles = Vec::new();
    for (mut client, is_active) in all_clients {
        let http = http.clone();
        let base_url = base_url.to_string();
        let sem = sem.clone();
        let stats = stats.clone();
        reg_handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            if let Err(e) = client.register(&http, &base_url, &stats).await {
                tracing::warn!("registration failed: {e}");
            }
            (client, is_active)
        }));
    }

    let mut registered = Vec::new();
    for handle in reg_handles {
        registered.push(handle.await?);
    }
    let reg_count = registered.iter().filter(|(c, _)| c.token.is_some()).count();
    println!(
        "Registered {reg_count}/{total_clients} devices. Starting mixed workload for {}s...",
        duration.as_secs()
    );

    // Reset stats after registration
    let stats = Arc::new(Stats::new());
    let deadline = Instant::now() + duration;

    let mut handles = Vec::new();

    for (client, is_active) in registered {
        if client.token.is_none() {
            continue;
        }

        if is_active {
            // Active sync client
            let http = http.clone();
            let base_url = base_url.to_string();
            let stats = stats.clone();
            let mut client = client;
            handles.push(tokio::spawn(async move {
                let jitter =
                    Duration::from_millis(rand::random::<u64>() % sync_interval.as_millis() as u64);
                tokio::time::sleep(jitter).await;
                while Instant::now() < deadline {
                    let _ = client.push(&http, &base_url, &stats).await;
                    if let Ok(seq) = client.pull(&http, &base_url, &stats).await {
                        if seq > 0 {
                            let _ = client.ack(&http, &base_url, seq, &stats).await;
                        }
                    }
                    tokio::time::sleep(sync_interval).await;
                }
            }));
        } else {
            // WS idle client
            let base_url = base_url.to_string();
            let stats = stats.clone();
            let ws_connected = ws_connected.clone();
            handles.push(tokio::spawn(async move {
                match client.ws_connect(&base_url, &stats).await {
                    Ok(ws) => {
                        ws_connected.fetch_add(1, Ordering::Relaxed);
                        let (_write, mut read) = ws.split();
                        loop {
                            match tokio::time::timeout(Duration::from_secs(60), read.next()).await {
                                Ok(Some(Ok(_))) => {}
                                Ok(Some(Err(_))) | Ok(None) => break,
                                Err(_) => {}
                            }
                        }
                        ws_connected.fetch_sub(1, Ordering::Relaxed);
                    }
                    Err(e) => tracing::warn!("ws connect failed: {e}"),
                }
            }));
        }
    }

    // Progress reporting
    let stats_report = stats.clone();
    let ws_report = ws_connected.clone();
    let report_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(report_interval);
        while Instant::now() < deadline {
            interval.tick().await;
            stats_report.print_progress();
            let ws = ws_report.load(Ordering::Relaxed);
            println!("       ws_connected: {ws}/{ws_clients}");
        }
    });

    // Wait for deadline
    tokio::time::sleep(duration).await;

    // Cleanup
    report_handle.abort();
    for handle in handles {
        handle.abort();
    }

    stats.print_summary(
        "Mixed Workload",
        &format!(
            "WS clients: {ws_clients}, Active clients: {active_clients}\nPeak WS connected: {}",
            ws_connected.load(Ordering::Relaxed)
        ),
    );

    Ok(())
}
