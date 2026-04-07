pub mod mock;
pub mod pairing_relay;
pub mod server_relay;
pub mod traits;
pub mod websocket;

pub use mock::MockRelay;
pub use pairing_relay::{MockPairingRelay, PairingRelay, PairingSlot, ServerPairingRelay};
pub use server_relay::ServerRelay;
pub use traits::*;

/// Redact sync_id from a WebSocket URL for safe logging.
///
/// Turns `wss://host/v1/sync/abcdef0123456789.../ws` into
/// `wss://host/v1/sync/abcdef01.../ws` (first 8 chars only).
pub(crate) fn redact_url(url: &str) -> String {
    // Pattern: .../v1/sync/{sync_id}/ws
    if let Some(idx) = url.find("/v1/sync/") {
        let after = &url[idx + "/v1/sync/".len()..];
        if let Some(slash) = after.find('/') {
            let sync_id = &after[..slash];
            let truncated = &sync_id[..sync_id.len().min(8)];
            return format!(
                "{}...{}",
                &url[..idx + "/v1/sync/".len() + truncated.len()],
                &after[slash..]
            );
        }
    }
    url.to_string()
}
