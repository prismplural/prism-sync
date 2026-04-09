use chrono::{DateTime, Utc};

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

/// Local device registry record for signature verification on pull.
#[derive(Debug, Clone)]
pub struct DeviceRecord {
    pub sync_id: String,
    pub device_id: String,
    pub ed25519_public_key: Vec<u8>,
    pub x25519_public_key: Vec<u8>,
    pub ml_dsa_65_public_key: Vec<u8>,
    pub ml_kem_768_public_key: Vec<u8>,
    pub status: String, // "active" or "revoked"
    pub registered_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub ml_dsa_key_generation: u32,
}
