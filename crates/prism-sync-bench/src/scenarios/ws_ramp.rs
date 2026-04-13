use anyhow::Result;
use futures::StreamExt;
use reqwest::Client;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

use crate::client::SimulatedClient;
use crate::relay;
use crate::stats::Stats;

pub(crate) async fn run(
    http: &Client,
    base_url: &str,
    num_clients: usize,
    ramp_duration: Duration,
    hold_duration: Duration,
    report_interval: Duration,
) -> Result<()> {
    let stats = Arc::new(Stats::new());
    let connected = Arc::new(AtomicUsize::new(0));

    println!("Registering {num_clients} devices...");

    // Create and register clients
    let mut clients = Vec::with_capacity(num_clients);
    for _ in 0..num_clients {
        clients.push(SimulatedClient::new(relay::generate_sync_id()));
    }

    // Register with bounded concurrency
    let sem = Arc::new(Semaphore::new(50));
    let mut reg_handles = Vec::new();
    for mut client in clients {
        let http = http.clone();
        let base_url = base_url.to_string();
        let sem = sem.clone();
        let stats = stats.clone();
        reg_handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            if let Err(e) = client.register(&http, &base_url, &stats).await {
                tracing::warn!("registration failed: {e}");
            }
            client
        }));
    }

    let mut registered_clients = Vec::new();
    for handle in reg_handles {
        registered_clients.push(handle.await?);
    }
    let registered = registered_clients
        .iter()
        .filter(|c| c.token.is_some())
        .count();
    println!("Registered {registered}/{num_clients} devices");

    // Ramp WS connections
    println!(
        "Ramping {registered} WebSocket connections over {}s...",
        ramp_duration.as_secs()
    );
    let ramp_interval = if registered > 0 {
        ramp_duration / registered as u32
    } else {
        Duration::from_secs(1)
    };

    let mut ws_handles = Vec::new();
    for client in registered_clients {
        if client.token.is_none() {
            continue;
        }

        let base_url = base_url.to_string();
        let stats = stats.clone();
        let connected = connected.clone();

        let handle = tokio::spawn(async move {
            match client.ws_connect(&base_url, &stats).await {
                Ok(ws) => {
                    connected.fetch_add(1, Ordering::Relaxed);
                    // Hold connection: read loop (auto-pong handled by tungstenite)
                    let (_write, mut read) = ws.split();
                    loop {
                        match tokio::time::timeout(Duration::from_secs(60), read.next()).await {
                            Ok(Some(Ok(_))) => {}                 // message received, continue
                            Ok(Some(Err(_))) | Ok(None) => break, // connection closed
                            Err(_) => {}                          // timeout, continue waiting
                        }
                    }
                    connected.fetch_sub(1, Ordering::Relaxed);
                }
                Err(e) => {
                    tracing::warn!("ws connect failed: {e}");
                }
            }
        });
        ws_handles.push(handle);

        tokio::time::sleep(ramp_interval).await;
    }

    // Hold phase with progress reporting
    println!("Holding connections for {}s...", hold_duration.as_secs());
    let hold_deadline = tokio::time::Instant::now() + hold_duration;
    let mut interval = tokio::time::interval(report_interval);
    while tokio::time::Instant::now() < hold_deadline {
        interval.tick().await;
        stats.print_ws_progress(connected.load(Ordering::Relaxed), registered);
    }

    // Summary
    stats.print_summary(
        "WS Ramp",
        &format!(
            "Clients: {registered}\nPeak connected: {}",
            connected.load(Ordering::Relaxed)
        ),
    );

    // Drop all WS connections (abort the tasks)
    for handle in ws_handles {
        handle.abort();
    }

    Ok(())
}
