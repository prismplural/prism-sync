//! Throwaway localhost relay for the end-to-end FFI test harness.
//!
//! Binds an ephemeral 127.0.0.1 port with an in-memory DB and OPEN registration,
//! prints `RELAY_URL=http://127.0.0.1:<port>` to stdout (so a spawning test can
//! read the URL), then serves until the process is killed. NOT for production.
//!
//! Build: `cargo build --release -p prism-sync-relay --example test_relay`

use std::io::Write;

#[tokio::main]
async fn main() {
    let config = prism_sync_relay::config::localhost_test_config();
    let db = prism_sync_relay::db::Database::in_memory().expect("in-memory db");
    let state = prism_sync_relay::state::AppState::new(db, config);
    let app = prism_sync_relay::routes::router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");

    // The spawning test reads this line to discover the port.
    println!("RELAY_URL=http://127.0.0.1:{}", addr.port());
    std::io::stdout().flush().expect("flush stdout");

    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await
        .expect("serve");
}
