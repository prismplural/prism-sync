use std::collections::HashMap;

use tokio::sync::broadcast;

use crate::engine::state::SyncResult;
use crate::relay::traits::DeviceInfo;

/// An event emitted by the sync engine to consumers.
#[derive(Debug, Clone)]
pub enum SyncEvent {
    /// A sync cycle has started.
    SyncStarted,
    /// A sync cycle completed (successfully or with an error).
    SyncCompleted(SyncResult),
    /// Snapshot download progress during first-sync bootstrap.
    SnapshotProgress { received: u64, total: u64 },
    /// An error occurred during sync.
    Error(SyncError),
    /// Remote changes were merged into local state.
    RemoteChanges(ChangeSet),
    /// A new device joined the sync group.
    DeviceJoined(DeviceInfo),
    /// A device was revoked from the sync group.
    DeviceRevoked {
        device_id: String,
        remote_wipe: bool,
    },
    /// The epoch was rotated (new epoch number).
    EpochRotated(u32),
    /// WebSocket real-time connection state changed.
    WebSocketStateChanged { connected: bool },
    /// A backoff delay was scheduled after a sync failure.
    BackoffScheduled { attempt: u32, delay_secs: u64 },
}

/// A single entity change with full field data, for consumer DB application.
#[derive(Debug, Clone)]
pub struct EntityChange {
    /// The entity table name (e.g. "members", "fronting_sessions").
    pub table: String,
    /// The entity's unique identifier.
    pub entity_id: String,
    /// Whether this change is a soft-delete (tombstone).
    pub is_delete: bool,
    /// The winning field values (field_name -> encoded_value).
    ///
    /// Values use the same encoding as `encode_value` / `decode_value`:
    /// - String -> JSON string (e.g. `"\"hello\""`)
    /// - Int -> JSON number (e.g. `"42"`)
    /// - Bool -> `"true"` / `"false"`
    /// - DateTime -> JSON-encoded ISO-8601 (e.g. `"\"2026-03-15T12:00:00.000Z\""`)
    /// - Blob -> JSON-encoded base64 (e.g. `"\"3q2+7w==\""`)
    /// - null -> `"null"`
    ///
    /// Empty for deletes.
    pub fields: HashMap<String, String>,
}

/// A summary of remote changes applied during a sync cycle.
#[derive(Debug, Clone)]
pub struct ChangeSet {
    /// Entities created: (table, entity_id)
    pub created: Vec<(String, String)>,
    /// Entities updated: (table, entity_id, field_names)
    pub updated: Vec<(String, String, Vec<String>)>,
    /// Entities deleted: (table, entity_id)
    pub deleted: Vec<(String, String)>,
    /// Full entity changes with field values for consumer DB application.
    ///
    /// This is the authoritative list -- use this to apply changes to the
    /// consumer database (e.g. Drift). Each entry contains the winning
    /// field values after CRDT merge.
    pub entity_changes: Vec<EntityChange>,
}

impl ChangeSet {
    /// Returns true if there are no changes.
    pub fn is_empty(&self) -> bool {
        self.created.is_empty() && self.updated.is_empty() && self.deleted.is_empty()
    }
}

/// An error that occurred during sync, surfaced as a `SyncEvent::Error`.
#[derive(Debug, Clone)]
pub struct SyncError {
    pub kind: SyncErrorKind,
    pub message: String,
    pub retryable: bool,
    pub code: Option<String>,
    pub remote_wipe: Option<bool>,
}

/// Classification of sync error kinds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncErrorKind {
    Network,
    Auth,
    DeviceIdentityMismatch,
    Server,
    EpochRotation,
    Protocol,
    ClockSkew,
    KeyChanged,
    Timeout,
}

/// Create a new broadcast channel for `SyncEvent`s.
///
/// The channel capacity is 256 — enough to buffer a burst of events
/// while the consumer processes them. Receivers that fall too far behind
/// will receive `RecvError::Lagged`.
pub fn event_channel() -> (broadcast::Sender<SyncEvent>, broadcast::Receiver<SyncEvent>) {
    broadcast::channel(256)
}
