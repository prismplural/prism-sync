use std::sync::OnceLock;

use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Get or create the shared background tokio runtime.
///
/// Uses `multi_thread` with `worker_threads=1` to minimize mobile overhead
/// while still supporting persistent WebSocket connections, async timers,
/// and background auto-sync.
///
/// The runtime is initialized once on first call and lives for the process
/// lifetime (`'static`). Subsequent calls return the same runtime.
pub fn background_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        // Install the rustls crypto provider exactly once.
        //
        // Since rustls 0.23, a process-level CryptoProvider must be registered
        // before any TLS connection is made (including WebSocket wss://). Without
        // this, tokio-tungstenite panics with "no process-level CryptoProvider
        // available". The call is safe to make multiple times — subsequent calls
        // return Err and are silently ignored.
        let _ = rustls::crypto::ring::default_provider().install_default();
        eprintln!("[prism_sync_bg] rustls ring provider installed (or already set)");

        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("prism-sync-bg")
            .enable_all()
            .build()
            .expect("failed to create tokio runtime")
    })
}
