//! Throwaway localhost relay for the end-to-end FFI test harness.
//!
//! Binds 127.0.0.1 with OPEN registration, prints `RELAY_URL=http://127.0.0.1:<port>`
//! to stdout (so a spawning test can read the URL), then serves until killed.
//! NOT for production.
//!
//! Env overrides (for the kill+restart chaos test — so the relay can come back
//! on the SAME url with the SAME state):
//!   TEST_RELAY_PORT=<n>   bind a fixed port instead of an ephemeral one
//!   TEST_RELAY_DB=<path>  open a persistent file DB instead of in-memory
//!
//! Build: `cargo build --release -p prism-sync-relay --example test_relay`

use std::io::Write;

#[tokio::main]
async fn main() {
    let config = prism_sync_relay::config::localhost_test_config();
    let db = match std::env::var("TEST_RELAY_DB") {
        Ok(path) if !path.is_empty() => {
            prism_sync_relay::db::Database::open(&path, 2).expect("open file db")
        }
        _ => prism_sync_relay::db::Database::in_memory().expect("in-memory db"),
    };
    let state = prism_sync_relay::state::AppState::new(db, config);
    let app = prism_sync_relay::routes::router(state);

    let port: u16 = std::env::var("TEST_RELAY_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.expect("bind port");
    let addr = listener.local_addr().expect("local addr");

    // The spawning test reads this line to discover the port.
    println!("RELAY_URL=http://127.0.0.1:{}", addr.port());
    std::io::stdout().flush().expect("flush stdout");

    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await
        .expect("serve");
}
