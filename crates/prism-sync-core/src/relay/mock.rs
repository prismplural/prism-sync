use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::Stream;
use tokio::sync::broadcast;

use super::traits::{
    DeviceInfo, OutgoingBatch, PullResponse, ReceivedBatch, RegisterRequest, RegisterResponse,
    RelayError, SignedBatchEnvelope, SnapshotResponse, SyncNotification, SyncRelay,
};

/// In-memory mock implementation of [`SyncRelay`] for testing.
///
/// Stores batches in memory with incrementing server sequence numbers.
/// Does not perform any encryption or network operations.
///
/// Use [`inject_batch`] to simulate another device pushing data, and
/// [`send_notification`] to simulate relay WebSocket pushes.
pub struct MockRelay {
    state: Mutex<MockRelayState>,
    notification_tx: broadcast::Sender<SyncNotification>,
}

struct MockRelayState {
    batches: Vec<StoredBatch>,
    next_server_seq: i64,
    devices: Vec<DeviceInfo>,
    snapshot: Option<SnapshotResponse>,
    snapshot_target_device_id: Option<String>,
    registered: bool,
    /// Configurable `min_acked_seq` returned in pull responses.
    min_acked_seq: Option<i64>,
    /// Records each ack call for test assertions.
    ack_calls: Vec<i64>,
    /// If set, `ack()` will return this error.
    ack_error: Option<String>,
}

/// Full stored batch — keeps the original `SignedBatchEnvelope` so that
/// pull returns verifiable envelopes (matching real relay behaviour).
struct StoredBatch {
    server_seq: i64,
    received_at: DateTime<Utc>,
    envelope: SignedBatchEnvelope,
}

impl MockRelay {
    /// Create a new empty mock relay.
    pub fn new() -> Self {
        let (notification_tx, _) = broadcast::channel(64);
        Self {
            state: Mutex::new(MockRelayState {
                batches: Vec::new(),
                next_server_seq: 1,
                devices: Vec::new(),
                snapshot: None,
                snapshot_target_device_id: None,
                registered: false,
                min_acked_seq: None,
                ack_calls: Vec::new(),
                ack_error: None,
            }),
            notification_tx,
        }
    }

    /// Inject a batch into the relay (simulates another device pushing).
    ///
    /// Returns the server sequence number assigned to the batch.
    pub fn inject_batch(&self, envelope: SignedBatchEnvelope) -> i64 {
        let mut state = self.state.lock().unwrap();
        let seq = state.next_server_seq;
        state.next_server_seq += 1;
        state.batches.push(StoredBatch {
            server_seq: seq,
            received_at: Utc::now(),
            envelope,
        });
        seq
    }

    /// Send a notification to all active subscribers (simulates relay WebSocket push).
    pub fn send_notification(&self, notification: SyncNotification) {
        let _ = self.notification_tx.send(notification);
    }

    /// Add a device to the registry.
    pub fn add_device(&self, device: DeviceInfo) {
        self.state.lock().unwrap().devices.push(device);
    }

    /// Get the number of stored batches.
    pub fn batch_count(&self) -> usize {
        self.state.lock().unwrap().batches.len()
    }

    /// Returns `true` if `register_device` has been called.
    pub fn is_registered(&self) -> bool {
        self.state.lock().unwrap().registered
    }

    /// Returns the `target_device_id` stored with the current snapshot, if any.
    ///
    /// Use in tests to assert that the engine uploads snapshots without targeting
    /// (i.e. `for_device_id = None`), which is required so that a joining device
    /// — whose device_id is not yet known at upload time — can download it.
    pub fn snapshot_target_device_id(&self) -> Option<String> {
        self.state.lock().unwrap().snapshot_target_device_id.clone()
    }

    /// Set the `min_acked_seq` value returned in pull responses.
    pub fn set_min_acked_seq(&self, seq: i64) {
        self.state.lock().unwrap().min_acked_seq = Some(seq);
    }

    /// Get all `server_seq` values passed to `ack()`.
    pub fn ack_calls(&self) -> Vec<i64> {
        self.state.lock().unwrap().ack_calls.clone()
    }

    /// Make the next `ack()` call return an error.
    pub fn set_ack_error(&self, msg: &str) {
        self.state.lock().unwrap().ack_error = Some(msg.to_string());
    }

    /// Returns the snapshot only if the caller's `device_id` is allowed to see it.
    ///
    /// Mirrors the server relay's `target_device_id` enforcement: if the snapshot
    /// has a `target_device_id` set, only that device may download it. Use this in
    /// tests that want to verify access-control behaviour without hitting the real
    /// server.
    pub fn get_snapshot_for_device(&self, device_id: &str) -> Option<SnapshotResponse> {
        let state = self.state.lock().unwrap();
        match (&state.snapshot, &state.snapshot_target_device_id) {
            (Some(snap), Some(target)) if target != device_id => {
                // Targeted at a different device — deny access.
                None
            }
            (snap, _) => snap.clone(),
        }
    }
}

impl Default for MockRelay {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SyncRelay for MockRelay {
    async fn get_registration_nonce(&self) -> Result<String, RelayError> {
        Ok(uuid::Uuid::new_v4().to_string())
    }

    async fn register_device(&self, _req: RegisterRequest) -> Result<RegisterResponse, RelayError> {
        self.state.lock().unwrap().registered = true;
        Ok(RegisterResponse {
            device_session_token: "mock-session-token".to_string(),
        })
    }

    async fn pull_changes(&self, since: i64) -> Result<PullResponse, RelayError> {
        let state = self.state.lock().unwrap();
        let batches: Vec<ReceivedBatch> = state
            .batches
            .iter()
            .filter(|b| b.server_seq > since)
            .map(|b| ReceivedBatch {
                server_seq: b.server_seq,
                received_at: b.received_at,
                envelope: b.envelope.clone(),
            })
            .collect();
        let max_server_seq = batches.iter().map(|b| b.server_seq).max().unwrap_or(since);
        Ok(PullResponse {
            batches,
            max_server_seq,
            min_acked_seq: state.min_acked_seq,
        })
    }

    async fn push_changes(&self, batch: OutgoingBatch) -> Result<i64, RelayError> {
        let mut state = self.state.lock().unwrap();
        let seq = state.next_server_seq;
        state.next_server_seq += 1;
        state.batches.push(StoredBatch {
            server_seq: seq,
            received_at: Utc::now(),
            envelope: batch.envelope,
        });
        Ok(seq)
    }

    async fn get_snapshot(&self) -> Result<Option<SnapshotResponse>, RelayError> {
        Ok(self.state.lock().unwrap().snapshot.clone())
    }

    async fn put_snapshot(
        &self,
        epoch: i32,
        server_seq_at: i64,
        data: Vec<u8>,
        _ttl_secs: Option<u64>,
        for_device_id: Option<String>,
    ) -> Result<(), RelayError> {
        let mut state = self.state.lock().unwrap();
        state.snapshot = Some(SnapshotResponse {
            epoch,
            server_seq_at,
            data,
        });
        state.snapshot_target_device_id = for_device_id;
        Ok(())
    }

    async fn list_devices(&self) -> Result<Vec<DeviceInfo>, RelayError> {
        Ok(self.state.lock().unwrap().devices.clone())
    }

    async fn revoke_device(&self, device_id: &str, _remote_wipe: bool) -> Result<(), RelayError> {
        let mut state = self.state.lock().unwrap();
        state.devices.retain(|d| d.device_id != device_id);
        Ok(())
    }

    async fn post_rekey_artifacts(
        &self,
        epoch: i32,
        _revoked_device_id: &str,
        _wrapped_keys: HashMap<String, Vec<u8>>,
    ) -> Result<i32, RelayError> {
        // Return next epoch (current epoch + 1) as a stub.
        Ok(epoch + 1)
    }

    async fn get_rekey_artifact(
        &self,
        _epoch: i32,
        _device_id: &str,
    ) -> Result<Option<Vec<u8>>, RelayError> {
        Ok(None)
    }

    async fn deregister(&self) -> Result<(), RelayError> {
        Ok(())
    }

    async fn delete_sync_group(&self) -> Result<(), RelayError> {
        Ok(())
    }

    async fn ack(&self, server_seq: i64) -> Result<(), RelayError> {
        let mut state = self.state.lock().unwrap();
        state.ack_calls.push(server_seq);
        if let Some(err_msg) = state.ack_error.take() {
            return Err(RelayError::Network { message: err_msg });
        }
        Ok(())
    }

    async fn connect_websocket(&self) -> Result<(), RelayError> {
        Ok(())
    }

    async fn disconnect_websocket(&self) -> Result<(), RelayError> {
        Ok(())
    }

    fn notifications(&self) -> Pin<Box<dyn Stream<Item = SyncNotification> + Send>> {
        use futures_util::StreamExt;
        let rx = self.notification_tx.subscribe();
        Box::pin(
            tokio_stream::wrappers::BroadcastStream::new(rx)
                .filter_map(|r: Result<SyncNotification, _>| async move { r.ok() }),
        )
    }

    async fn dispose(&self) -> Result<(), RelayError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_envelope(batch_id: &str) -> SignedBatchEnvelope {
        SignedBatchEnvelope {
            protocol_version: 2,
            sync_id: "sync-abc".to_string(),
            epoch: 1,
            batch_id: batch_id.to_string(),
            batch_kind: "ops".to_string(),
            sender_device_id: "device-1".to_string(),
            payload_hash: [0u8; 32],
            signature: vec![0u8; 64],
            nonce: [0u8; 24],
            ciphertext: vec![1, 2, 3],
        }
    }

    #[tokio::test]
    async fn register_sets_flag() {
        let relay = MockRelay::new();
        assert!(!relay.is_registered());
        let resp = relay
            .register_device(RegisterRequest {
                device_id: "d1".to_string(),
                signing_public_key: vec![],
                x25519_public_key: vec![],
                registration_challenge: vec![],
                nonce: "nonce".to_string(),
                signed_invitation: None,
            })
            .await
            .unwrap();
        assert!(relay.is_registered());
        assert_eq!(resp.device_session_token, "mock-session-token");
    }

    #[tokio::test]
    async fn push_and_pull() {
        let relay = MockRelay::new();
        let env = make_envelope("batch-1");
        let seq = relay
            .push_changes(OutgoingBatch {
                batch_id: "batch-1".to_string(),
                envelope: env,
            })
            .await
            .unwrap();
        assert_eq!(seq, 1);
        assert_eq!(relay.batch_count(), 1);

        let pull = relay.pull_changes(0).await.unwrap();
        assert_eq!(pull.batches.len(), 1);
        assert_eq!(pull.batches[0].server_seq, 1);
        assert_eq!(pull.max_server_seq, 1);
    }

    #[tokio::test]
    async fn pull_since_filters_correctly() {
        let relay = MockRelay::new();
        relay.inject_batch(make_envelope("b1"));
        relay.inject_batch(make_envelope("b2"));
        relay.inject_batch(make_envelope("b3"));

        let pull = relay.pull_changes(1).await.unwrap();
        // server_seq 1 is NOT included (> 1 means seq 2 and 3)
        assert_eq!(pull.batches.len(), 2);
        assert_eq!(pull.batches[0].server_seq, 2);
        assert_eq!(pull.batches[1].server_seq, 3);
    }

    #[tokio::test]
    async fn inject_batch_increments_seq() {
        let relay = MockRelay::new();
        let s1 = relay.inject_batch(make_envelope("b1"));
        let s2 = relay.inject_batch(make_envelope("b2"));
        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
    }

    #[tokio::test]
    async fn snapshot_round_trip() {
        let relay = MockRelay::new();
        assert!(relay.get_snapshot().await.unwrap().is_none());
        relay
            .put_snapshot(1, 10, vec![9, 8, 7], None, None)
            .await
            .unwrap();
        let snap = relay.get_snapshot().await.unwrap().unwrap();
        assert_eq!(snap.epoch, 1);
        assert_eq!(snap.server_seq_at, 10);
        assert_eq!(snap.data, vec![9, 8, 7]);
    }

    #[tokio::test]
    async fn snapshot_target_device_id_stored_and_inspectable() {
        let relay = MockRelay::new();

        // No snapshot yet — no target.
        assert_eq!(relay.snapshot_target_device_id(), None);

        // Upload with a specific target.
        relay
            .put_snapshot(1, 5, vec![1, 2, 3], None, Some("device-a".to_string()))
            .await
            .unwrap();
        assert_eq!(
            relay.snapshot_target_device_id(),
            Some("device-a".to_string())
        );

        // Replace with an untargeted snapshot.
        relay
            .put_snapshot(1, 6, vec![4, 5, 6], None, None)
            .await
            .unwrap();
        assert_eq!(relay.snapshot_target_device_id(), None);
    }

    #[tokio::test]
    async fn get_snapshot_for_device_enforces_targeting() {
        let relay = MockRelay::new();

        // Upload snapshot targeted at "device-a".
        relay
            .put_snapshot(1, 5, vec![1, 2, 3], None, Some("device-a".to_string()))
            .await
            .unwrap();

        // Targeted device can download.
        assert!(relay.get_snapshot_for_device("device-a").is_some());

        // Different device is blocked.
        assert!(
            relay.get_snapshot_for_device("device-b").is_none(),
            "snapshot targeted at device-a must not be served to device-b"
        );

        // Untargeted snapshot is served to any device.
        relay
            .put_snapshot(1, 6, vec![4, 5, 6], None, None)
            .await
            .unwrap();
        assert!(relay.get_snapshot_for_device("device-b").is_some());
        assert!(relay.get_snapshot_for_device("device-c").is_some());
    }

    #[tokio::test]
    async fn list_and_revoke_devices() {
        let relay = MockRelay::new();
        relay.add_device(DeviceInfo {
            device_id: "d1".to_string(),
            epoch: 1,
            status: "active".to_string(),
            ed25519_public_key: vec![],
            x25519_public_key: vec![],
            permission: None,
        });
        relay.add_device(DeviceInfo {
            device_id: "d2".to_string(),
            epoch: 1,
            status: "active".to_string(),
            ed25519_public_key: vec![],
            x25519_public_key: vec![],
            permission: None,
        });

        let devices = relay.list_devices().await.unwrap();
        assert_eq!(devices.len(), 2);

        relay.revoke_device("d1", false).await.unwrap();
        let devices = relay.list_devices().await.unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, "d2");
    }
}
