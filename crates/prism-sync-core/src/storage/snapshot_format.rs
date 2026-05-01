use serde::{Deserialize, Serialize};

/// Current snapshot format version.
pub const SNAPSHOT_VERSION: u32 = 1;

/// Top-level snapshot container. Serialized to JSON, then zstd-compressed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotData {
    pub version: u32,
    pub field_versions: Vec<FieldVersionEntry>,
    pub device_registry: Vec<DeviceRegistryEntry>,
    pub applied_ops: Vec<AppliedOpEntry>,
    pub sync_metadata: SyncMetadataEntry,
}

/// Snapshot representation of a field_versions row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldVersionEntry {
    pub entity_table: String,
    pub entity_id: String,
    pub field_name: String,
    pub winning_hlc: String,
    pub winning_device_id: String,
    pub winning_op_id: String,
    pub winning_encoded_value: Option<String>,
    pub updated_at: String,
}

/// Snapshot representation of a device_registry row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistryEntry {
    pub device_id: String,
    pub ed25519_public_key: String,    // hex-encoded
    pub x25519_public_key: String,     // hex-encoded
    pub ml_dsa_65_public_key: String,  // hex-encoded
    pub ml_kem_768_public_key: String, // hex-encoded
    #[serde(default)]
    pub x_wing_public_key: String, // hex-encoded
    pub status: String,
    pub registered_at: String,
    pub revoked_at: Option<String>,
    #[serde(default)]
    pub ml_dsa_key_generation: u32,
}

/// Snapshot representation of an applied_ops row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedOpEntry {
    pub op_id: String,
    pub sync_id: String,
    pub epoch: i32,
    pub device_id: String,
    pub client_hlc: String,
    pub server_seq: i64,
    pub applied_at: String,
}

/// Snapshot representation of sync_metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncMetadataEntry {
    pub sync_id: String,
    pub local_device_id: String,
    pub current_epoch: i32,
    pub last_pulled_server_seq: i64,
}
