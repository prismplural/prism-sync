use anyhow::Result;
use clap::{Parser, Subcommand};
use std::time::Duration;

mod client;
mod relay;
mod scenarios;
mod stats;

#[derive(Parser)]
#[command(
    name = "prism-sync-bench",
    about = "Load test tool for the Prism relay server"
)]
struct Cli {
    /// Relay URL. If omitted, starts an in-process relay.
    #[arg(long, global = true)]
    url: Option<String>,

    /// How often to print progress.
    #[arg(long, global = true, default_value = "5s", value_parser = humantime::parse_duration)]
    report_interval: Duration,

    /// Reader pool size for in-process relay.
    #[arg(long, global = true, default_value = "4")]
    reader_pool_size: usize,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Ramp WebSocket connections to find the connection ceiling.
    WsRamp {
        #[arg(long, default_value = "1000")]
        clients: usize,
        #[arg(long, default_value = "10s", value_parser = humantime::parse_duration)]
        ramp_duration: Duration,
        #[arg(long, default_value = "30s", value_parser = humantime::parse_duration)]
        hold_duration: Duration,
    },
    /// Benchmark sync cycle throughput.
    SyncBench {
        #[arg(long, default_value = "100")]
        clients: usize,
        #[arg(long, default_value = "1s", value_parser = humantime::parse_duration)]
        sync_interval: Duration,
        #[arg(long, default_value = "30s", value_parser = humantime::parse_duration)]
        duration: Duration,
    },
    /// Mixed workload: idle WS + active sync.
    Mixed {
        #[arg(long, default_value = "1000")]
        ws_clients: usize,
        #[arg(long, default_value = "100")]
        active_clients: usize,
        #[arg(long, default_value = "1s", value_parser = humantime::parse_duration)]
        sync_interval: Duration,
        #[arg(long, default_value = "60s", value_parser = humantime::parse_duration)]
        duration: Duration,
    },
}

async fn start_in_process_relay(reader_pool_size: usize) -> Result<String> {
    use prism_sync_relay::{config::Config, db::Database, routes, state::AppState};

    let config = Config {
        port: 0,
        db_path: ":memory:".into(),
        nonce_expiry_secs: 60,
        session_expiry_secs: 86400,
        first_device_pow_difficulty_bits: 0,
        invite_ttl_secs: 86400,
        sync_inactive_ttl_secs: 7_776_000,
        stale_device_secs: 2_592_000,
        cleanup_interval_secs: 3600,
        max_unpruned_batches: 1_000_000,
        metrics_token: None,
        nonce_rate_limit: 1_000_000,
        nonce_rate_window_secs: 60,
        revoke_rate_limit: 100,
        revoke_rate_window_secs: 3600,
        signed_request_max_skew_secs: 60,
        signed_request_nonce_window_secs: 120,
        snapshot_default_ttl_secs: 86400,
        revoked_tombstone_retention_secs: 2_592_000,
        reader_pool_size,
        node_exporter_url: None,
        first_device_apple_attestation_enabled: false,
        first_device_apple_attestation_trust_roots_pem: vec![],
        first_device_apple_attestation_allowed_app_ids: vec![],
        first_device_android_attestation_enabled: false,
        first_device_android_attestation_trust_roots_pem: vec![],
        grapheneos_verified_boot_key_allowlist: vec![],
        registration_enabled: true,
        registration_token: None,
    };

    let db = Database::open(
        std::env::temp_dir()
            .join(format!("prism_bench_{}.db", uuid::Uuid::new_v4()))
            .to_str()
            .unwrap(),
        reader_pool_size,
    )?;
    let state = AppState::new(db, config);
    let app = routes::router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let url = format!("http://127.0.0.1:{}", addr.port());

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    Ok(url)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("warn".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    let base_url = match cli.url {
        Some(url) => {
            println!("Targeting remote relay: {url}");
            url
        }
        None => {
            println!("Starting in-process relay...");
            let url = start_in_process_relay(cli.reader_pool_size).await?;
            println!("In-process relay started at {url}");
            url
        }
    };

    let http = reqwest::Client::new();

    match cli.command {
        Command::WsRamp {
            clients,
            ramp_duration,
            hold_duration,
        } => {
            scenarios::ws_ramp::run(
                &http,
                &base_url,
                clients,
                ramp_duration,
                hold_duration,
                cli.report_interval,
            )
            .await?;
        }
        Command::SyncBench {
            clients,
            sync_interval,
            duration,
        } => {
            scenarios::sync_bench::run(
                &http,
                &base_url,
                clients,
                sync_interval,
                duration,
                cli.report_interval,
            )
            .await?;
        }
        Command::Mixed {
            ws_clients,
            active_clients,
            sync_interval,
            duration,
        } => {
            scenarios::mixed::run(
                &http,
                &base_url,
                ws_clients,
                active_clients,
                sync_interval,
                duration,
                cli.report_interval,
            )
            .await?;
        }
    }

    Ok(())
}
