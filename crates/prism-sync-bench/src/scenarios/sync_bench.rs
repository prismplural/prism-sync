use anyhow::Result;
use reqwest::Client;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

use crate::client::SimulatedClient;
use crate::relay;
use crate::stats::Stats;

pub(crate) async fn run(
    http: &Client,
    base_url: &str,
    num_clients: usize,
    sync_interval: Duration,
    duration: Duration,
    report_interval: Duration,
) -> Result<()> {
    let stats = Arc::new(Stats::new());

    // Each client gets its own sync group (joining an existing group requires
    // a signed invitation which is complex to generate). This tests server
    // throughput accurately — each device pushes and pulls from its own group.
    println!("Registering {num_clients} devices (1 per sync group)...");
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
    let registered = registered_clients.iter().filter(|c| c.token.is_some()).count();
    let num_groups = registered; // 1 group per client
    println!(
        "Registered {registered}/{num_clients} devices. Starting benchmark for {}s...",
        duration.as_secs()
    );

    // Reset stats after registration
    let stats = Arc::new(Stats::new());
    let deadline = Instant::now() + duration;

    // Start sync loops
    let mut sync_handles = Vec::new();
    for mut client in registered_clients {
        if client.token.is_none() {
            continue;
        }

        let http = http.clone();
        let base_url = base_url.to_string();
        let stats = stats.clone();

        let handle = tokio::spawn(async move {
            // Add jitter to avoid thundering herd
            let jitter =
                Duration::from_millis(rand::random::<u64>() % sync_interval.as_millis() as u64);
            tokio::time::sleep(jitter).await;

            while Instant::now() < deadline {
                // Push
                match client.push(&http, &base_url, &stats).await {
                    Ok(_) => {}
                    Err(e) => tracing::debug!("push error: {e}"),
                }

                // Pull
                match client.pull(&http, &base_url, &stats).await {
                    Ok(seq) => {
                        if seq > 0 {
                            let _ = client.ack(&http, &base_url, seq, &stats).await;
                        }
                    }
                    Err(e) => tracing::debug!("pull error: {e}"),
                }

                tokio::time::sleep(sync_interval).await;
            }
        });
        sync_handles.push(handle);
    }

    // Progress reporting
    let stats_report = stats.clone();
    let report_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(report_interval);
        while Instant::now() < deadline {
            interval.tick().await;
            stats_report.print_progress();
        }
    });

    // Wait for all sync tasks
    for handle in sync_handles {
        let _ = handle.await;
    }
    report_handle.abort();

    stats.print_summary(
        "Sync Bench",
        &format!("Clients: {registered} across {num_groups} sync groups"),
    );

    Ok(())
}
