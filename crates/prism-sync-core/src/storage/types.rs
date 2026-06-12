use chrono::{DateTime, Utc};

use crate::crdt_change::CrdtChange;
use crate::relay::traits::SignedBatchEnvelope;

/// Metadata for a sync group stored locally.
#[derive(Debug, Clone)]
pub struct SyncMetadata {
    pub sync_id: String,
    pub local_device_id: String,
    pub current_epoch: i32,
    pub last_pulled_server_seq: i64,
    pub last_pushed_at: Option<DateTime<Utc>>,
    pub last_successful_sync_at: Option<DateTime<Utc>>,
    pub registered_at: Option<DateTime<Utc>>,
    pub needs_rekey: bool,
    pub last_imported_registry_version: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A pending local mutation awaiting push to the relay.
#[derive(Debug, Clone)]
pub struct PendingOp {
    pub op_id: String,
    pub sync_id: String,
    pub epoch: i32,
    pub device_id: String,
    pub local_batch_id: String,
    pub entity_table: String,
    pub entity_id: String,
    pub field_name: String,
    pub encoded_value: String,
    pub is_delete: bool,
    pub client_hlc: String,
    pub created_at: DateTime<Utc>,
    pub pushed_at: Option<DateTime<Utc>>,
}

/// A received remote op that has been applied (idempotency tracking).
#[derive(Debug, Clone)]
pub struct AppliedOp {
    pub op_id: String,
    pub sync_id: String,
    pub epoch: i32,
    pub device_id: String,
    pub client_hlc: String,
    pub server_seq: i64,
    pub applied_at: DateTime<Utc>,
}

/// Per-field version tracking for LWW merge decisions.
#[derive(Debug, Clone)]
pub struct FieldVersion {
    pub sync_id: String,
    pub entity_table: String,
    pub entity_id: String,
    pub field_name: String,
    pub winning_op_id: String,
    pub winning_device_id: String,
    pub winning_hlc: String,
    /// The encoded value of the winning op.
    /// Used by the merge engine to check tombstone values
    /// (e.g. `is_deleted = "true"` vs `"false"` for un-deletes).
    pub winning_encoded_value: Option<String>,
    pub updated_at: DateTime<Utc>,
}

/// Whether an `is_deleted` field's winning value represents a tombstone.
///
/// The single source of truth for the per-ENTITY absorbing rule, shared by the
/// live merge (`engine::merge`), the snapshot import gate, and the
/// snapshot consumer-delivery/EntityChange derivation. A delete subsumes
/// every other field, so a NULL/absent value is treated as a tombstone
/// (defensive default); only an explicit `"false"` is live.
pub fn is_tombstone_value(encoded_value: Option<&str>) -> bool {
    encoded_value != Some("false")
}

/// A received remote op that could not be applied because the local schema
/// does not yet know its table or field.
#[derive(Debug, Clone)]
pub struct QuarantinedOp {
    pub sync_id: String,
    pub op_id: String,
    pub op: CrdtChange,
    pub reason: String,
    pub server_seq: i64,
    pub quarantined_at: DateTime<Utc>,
}

/// A received remote batch whose full envelope was durably quarantined because
/// a deterministic pull-side check failed (payload-hash / decode / attribution /
/// invalid signature / missing-epoch-key / stale generation / unresolved sender).
///
/// The cursor advances past the batch's `server_seq` so the relay can prune it,
/// but this device keeps the full `SignedBatchEnvelope` so Phase 0b replay can
/// re-run the complete verify->decrypt->decode->filter->apply pipeline once the
/// blocking condition clears. Device-local, never replicated, never snapshotted.
#[derive(Debug, Clone)]
pub struct QuarantinedPullBatch {
    pub sync_id: String,
    pub batch_id: String,
    pub server_seq: i64,
    /// Envelope epoch, captured for the missing-epoch-key replay arm so it can
    /// check whether the key is now in the hierarchy. `None` when not recorded.
    pub epoch: Option<i32>,
    pub sender_device_id: String,
    /// The full `SignedBatchEnvelope`, re-verified on every replay attempt.
    pub envelope: SignedBatchEnvelope,
    pub reason: String,
    pub retry_count: i64,
    pub quarantined_at: DateTime<Utc>,
    pub last_retry_at: Option<DateTime<Utc>>,
}

/// A stalled inbound `server_seq`: the sender's keys or registry generation
/// could not be resolved *yet*, so the cursor is frozen and the batch retried
/// next cycle. `attempts` bounds how long a flaky registry endpoint — or a
/// device claiming a bogus future ML-DSA generation — can hold the cursor before
/// the batch converts to quarantine-and-advance. Device-local.
#[derive(Debug, Clone)]
pub struct PullStall {
    pub sync_id: String,
    pub server_seq: i64,
    pub reason: String,
    pub attempts: i64,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

/// Diagnostic info about a local push batch that was quarantined because its
/// serialized envelope exceeded the relay's 1 MB body cap.
///
/// Stored locally only — never replicated, never included in snapshots, never
/// re-sent. The original ops remain in `pending_ops`; Phase 1C recovery
/// repartitions them into smaller batches and clears the quarantine row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedBatchInfo {
    pub batch_id: String,
    pub entity_table: String,
    pub entity_id: String,
    pub body_bytes: i64,
    pub error_code: String,
    pub error_message: String,
    pub quarantined_at: String,
}

/// An archived (superseded) ML-DSA verification key for a device. When a signed
/// registry import rotates a device to a higher generation, the prior
/// `(generation, ml_dsa_65_public_key)` is preserved here so an in-flight
/// pre-rotation batch — pulled or replayed after the receiver already imported
/// the new registry — still verifies against the exact key it was signed with.
/// Without this, the receiver stored only the latest key and could never
/// verify a straggling older-generation batch, silently and permanently dropping
/// it. Device-local, never replicated, never snapshotted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKeyHistoryEntry {
    pub sync_id: String,
    pub device_id: String,
    pub ml_dsa_key_generation: u32,
    pub ml_dsa_65_public_key: Vec<u8>,
    pub archived_at: DateTime<Utc>,
}

/// One durable at-least-once delivery-journal row: a single winning op (field
/// write or entity delete) that the Rust engine has committed to its own state
/// and now owes to the Dart consumer database.
///
/// Written in the SAME storage transaction as the Phase C bookkeeping
/// (`applied_ops` / `field_versions` / cursor) and the snapshot import, so a
/// pulled winner survives process death between the Rust apply-commit and the
/// Dart consumer-DB write. Dart drains rows in `id` order and acks (deletes up
/// to an `id`) only after its own transaction commits — closing the
/// fire-and-forget `RemoteChanges`-event delivery gap.
///
/// `id` is a local `AUTOINCREMENT` (not a server seq), so a relay-log lineage
/// reset leaves the journal untouched. `server_seq` is carried for diagnostics
/// and ordering hints only. Device-local, never replicated, never snapshotted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerDelivery {
    pub id: i64,
    pub sync_id: String,
    pub entity_table: String,
    pub entity_id: String,
    /// `None` for a delete delivery (the whole entity is tombstoned); otherwise
    /// the field whose `encoded_value` won.
    pub field_name: Option<String>,
    pub encoded_value: Option<String>,
    pub is_delete: bool,
    pub server_seq: i64,
    pub created_at: DateTime<Utc>,
}

/// Local device registry record for signature verification on pull.
#[derive(Debug, Clone)]
pub struct DeviceRecord {
    pub sync_id: String,
    pub device_id: String,
    pub ed25519_public_key: Vec<u8>,
    pub x25519_public_key: Vec<u8>,
    pub ml_dsa_65_public_key: Vec<u8>,
    pub ml_kem_768_public_key: Vec<u8>,
    pub x_wing_public_key: Vec<u8>,
    pub status: String, // "active" or "revoked"
    pub registered_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub ml_dsa_key_generation: u32,
}
