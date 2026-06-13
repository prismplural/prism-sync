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
    DeviceRevoked { device_id: String, remote_wipe: bool },
    /// The relay minted a fresh device-session token (via the signed
    /// `/session/refresh` recovery path after the old session expired). The app
    /// should re-persist `token` to its keychain so the next launch starts with
    /// a valid credential; until it does, refresh-on-401 at launch recovers.
    /// Additive event — the Dart decoder ignores unknown event types.
    SessionTokenRotated { token: String },
    /// The epoch was rotated (new epoch number).
    EpochRotated(u32),
    /// The relay auto-revoked an abandoned device and the group now owes a
    /// forced rekey. Emitted when one active device drives the standalone
    /// rekey in reaction to a `rekey_needed` WS frame (or a `needs_rekey=true`
    /// seen via `list_devices`). Additive event — the Dart decoder ignores
    /// unknown event types.
    RekeyNeeded,
    /// WebSocket real-time connection state changed.
    WebSocketStateChanged { connected: bool },
    /// A backoff delay was scheduled after a sync failure.
    BackoffScheduled { attempt: u32, delay_secs: u64 },
    /// Pair-time snapshot upload progress. Emitted by `SyncService` while
    /// `put_snapshot` streams the body to the relay.
    SnapshotUploadProgress { sync_id: String, bytes_sent: u64, bytes_total: u64 },
    /// Pair-time snapshot upload failed. Emitted by `SyncService` before the
    /// underlying `Err(..)` is returned to the caller.
    SnapshotUploadFailed { sync_id: String, reason: String },
    /// A local push batch was quarantined because its envelope exceeded the
    /// relay's 1 MB body cap (either rejected with HTTP 413 or caught by the
    /// client-side guard before push). The batch remains in `pending_ops`
    /// but is excluded from future push cycles until recovery
    /// (Phase 1C) repartitions it. `body_bytes` is informational only.
    QuarantinedBatch {
        batch_id: String,
        entity_table: String,
        entity_id: String,
        body_bytes: usize,
        /// `"payload_too_large"` when the relay returned 413, or
        /// `"payload_too_large_client_guard"` when the client-side guard
        /// fired before push.
        error_code: String,
        error_message: String,
    },
    /// A decrypted ephemeral message drained from the relay's device-message
    /// mailbox during a sync cycle (ephemeral media mailbox). Advisory / lossy-OK:
    /// the app reactor dispatches on `kind` (e.g. `"media_request"` /
    /// `"media_uploaded"`); the requester re-issues if a message is missed.
    EphemeralMessage {
        /// The authenticated device that sent the message.
        sender_device_id: String,
        /// App-level message kind.
        kind: String,
        /// The media id the message concerns.
        media_id: String,
        /// The epoch the message was sealed under.
        epoch_id: u32,
    },
    /// A received remote pull batch failed a deterministic check (payload-hash
    /// mismatch, undecodable plaintext, op attribution mismatch, or an invalid
    /// signature under a generation-matched key) and was durably quarantined.
    /// The cursor advanced past it so the group is not wedged; the full envelope
    /// is kept locally for Phase 0b replay once the blocking condition clears.
    /// `reason` is the persisted `quarantined_pull_batches.reason` string.
    PullBatchQuarantined {
        server_seq: i64,
        batch_id: String,
        sender_device_id: String,
        reason: String,
    },
    /// A received remote pull batch could not be processed *yet* because the
    /// sender's keys or ML-DSA generation were transiently unresolvable (a
    /// network/5xx registry fetch, a stale registry that has not yet imported
    /// the sender, or a not-yet-propagated key rotation). The pull cursor is
    /// held *behind* the batch (no advance, no ack past it, push still runs) and
    /// the batch is retried next cycle, bounded by the stall budget — after
    /// which it converts to a `PullBatchQuarantined`. `attempt` is the running
    /// `pull_stall.attempts` count; `reason` is the persisted stall reason.
    PullStalled {
        server_seq: i64,
        reason: String,
        attempt: i64,
    },
    /// A forward clock excursion poisoned this device's own HLCs (watermark and
    /// self-authored `field_versions` winners drifted past the drift bound) and
    /// the relay-anchored repair rewrote those winners at sane HLCs and
    /// re-queued them for push. The failure it cures was previously silent —
    /// every excursion-era op was dropped by peers' future-drift filters with no
    /// detection. `field_count` is how many self-authored fields were re-emitted;
    /// `max_drift_ms` is the largest future drift observed before repair.
    /// Additive event — the Dart decoder ignores unknown event types.
    ClockExcursionRepaired { field_count: u64, max_drift_ms: i64 },
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
    /// - Real -> JSON number (e.g. `"3.14"`)
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

/// Classify a `CoreError` into a `SyncErrorKind` for structured reporting.
///
/// Called by `SyncEngine` when converting pull/push errors into a populated
/// `SyncResult { error, error_kind }`, and by `SyncService::sync_now` when
/// deciding whether to retry. Keeping the mapping here avoids duplication
/// between the engine and the service.
///
/// **Retryability invariant:** only `Network`, `Server`, and `Timeout`
/// kinds are treated as retryable by `sync_error_kind_retryable` in
/// `sync_service.rs`. Local errors (`CoreError::Engine`,
/// `CoreError::Storage`, `CoreError::Schema`, unknown table/field,
/// serialization, etc.) must NOT map to `Network`: they are permanent
/// local failures (missing epoch key, ML-DSA key not configured,
/// corrupted pending op, schema mismatch) and retrying them burns 6
/// seconds of user-visible latency for nothing. Map them to `Protocol`
/// so the retry loop surfaces them immediately and the Dart
/// event-driven drain does not treat them as transient.
pub(crate) fn classify_core_error(e: &crate::error::CoreError) -> SyncErrorKind {
    use crate::error::{CoreError, RelayErrorCategory};
    match e {
        CoreError::Relay { kind, .. } => match kind {
            RelayErrorCategory::Network => SyncErrorKind::Network,
            RelayErrorCategory::Auth => SyncErrorKind::Auth,
            RelayErrorCategory::DeviceIdentityMismatch => SyncErrorKind::DeviceIdentityMismatch,
            RelayErrorCategory::Server => SyncErrorKind::Server,
            RelayErrorCategory::Protocol => SyncErrorKind::Protocol,
            RelayErrorCategory::Other => SyncErrorKind::Network,
        },
        CoreError::DeviceKeyChanged { .. } => SyncErrorKind::KeyChanged,
        CoreError::ClockDrift { .. } => SyncErrorKind::ClockSkew,
        // Local/permanent failures — surface immediately, do not retry,
        // do not drain. Storage busy-lock flakes are rare enough that
        // the outer auto-sync driver will pick them up on the next
        // cycle without us burning the inner retry budget.
        CoreError::MissingEpochKey { .. }
        | CoreError::EpochMismatch { .. }
        | CoreError::EpochKeyMismatch { .. }
        | CoreError::DecryptFailed { .. }
        // A generation mismatch is normally intercepted by the pull path's stall
        // route before it reaches classification; if it ever propagates as
        // a flat error it is a local-resolution failure, not a relay/transport
        // one — surface it as Protocol (non-retryable in the inner loop).
        | CoreError::StaleKeyGeneration { .. }
        | CoreError::Engine(_)
        | CoreError::Storage(_) => SyncErrorKind::Protocol,
        CoreError::Schema(_)
        | CoreError::Serialization(_)
        | CoreError::Json(_)
        | CoreError::HlcParse(_)
        | CoreError::UnknownTable(_)
        | CoreError::UnknownField { .. }
        | CoreError::Crypto(_)
        | CoreError::BootstrapNotAllowed(_)
        | CoreError::SnapshotTooLarge { .. } => SyncErrorKind::Protocol,
    }
}

/// Create a new broadcast channel for `SyncEvent`s.
///
/// The channel capacity is 256 — enough to buffer a burst of events
/// while the consumer processes them. Receivers that fall too far behind
/// will receive `RecvError::Lagged`.
pub fn event_channel() -> (broadcast::Sender<SyncEvent>, broadcast::Receiver<SyncEvent>) {
    broadcast::channel(256)
}
