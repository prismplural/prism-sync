use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::hlc::Hlc;

/// Sentinel field name used for bulk reset operations.
pub const BULK_RESET_FIELD: &str = "_bulk_reset";

/// Field-level sync operation used by the V2 sync engine.
///
/// Each CrdtChange represents a single field mutation on a single entity.
/// Operations are grouped into batches via `batch_id` and ordered by HLC.
///
/// JSON serialization uses snake_case field names matching the Dart implementation
/// exactly for wire compatibility.
///
/// Ported from Dart `lib/core/sync/crdt_change.dart`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrdtChange {
    pub op_id: String,

    /// Batch identifier. Only included in JSON if present (matches Dart's
    /// conditional inclusion).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_id: Option<String>,

    pub entity_id: String,
    pub entity_table: String,
    pub field_name: String,
    pub encoded_value: String,
    pub client_hlc: String,
    pub is_delete: bool,
    pub device_id: String,
    pub epoch: i32,

    /// Server-assigned sequence number. Only included in JSON if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_seq: Option<i64>,
}

impl CrdtChange {
    /// Create a new CrdtChange with all required fields.
    ///
    /// If `op_id` is None, a default is generated from the composite key:
    /// `"{entity_table}:{entity_id}:{field_name}:{client_hlc}:{device_id}"`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        op_id: Option<String>,
        batch_id: Option<String>,
        entity_id: String,
        entity_table: String,
        field_name: String,
        encoded_value: Option<String>,
        client_hlc: Option<String>,
        is_delete: bool,
        device_id: Option<String>,
        epoch: Option<i32>,
        server_seq: Option<i64>,
    ) -> Self {
        let client_hlc = client_hlc.unwrap_or_default();
        let device_id = device_id.unwrap_or_default();
        let epoch = epoch.unwrap_or(0);
        let encoded_value = encoded_value.unwrap_or_else(|| "null".to_string());

        let op_id = op_id.unwrap_or_else(|| {
            Self::default_op_id(
                &entity_table,
                &entity_id,
                &field_name,
                &client_hlc,
                &device_id,
            )
        });

        Self {
            op_id,
            batch_id,
            entity_id,
            entity_table,
            field_name,
            encoded_value,
            client_hlc,
            is_delete,
            device_id,
            epoch,
            server_seq,
        }
    }

    /// Returns true if this is a bulk reset operation.
    pub fn is_bulk_reset(&self) -> bool {
        self.field_name == BULK_RESET_FIELD
    }

    /// Field-level Last-Write-Wins comparison.
    ///
    /// Three-level tiebreaker (matching Dart implementation):
    /// 1. Compare HLC (timestamp, counter, node_id)
    /// 2. Compare device_id lexicographically
    /// 3. Compare op_id lexicographically
    ///
    /// Returns true if `self` wins over `other`.
    pub fn wins_over(&self, other: &CrdtChange) -> Result<bool> {
        let self_hlc = Hlc::from_string(&self.client_hlc)?;
        let other_hlc = Hlc::from_string(&other.client_hlc)?;

        let hlc_cmp = self_hlc.cmp(&other_hlc);
        if hlc_cmp != std::cmp::Ordering::Equal {
            return Ok(hlc_cmp == std::cmp::Ordering::Greater);
        }

        let device_cmp = self.device_id.cmp(&other.device_id);
        if device_cmp != std::cmp::Ordering::Equal {
            return Ok(device_cmp == std::cmp::Ordering::Greater);
        }

        Ok(self.op_id > other.op_id)
    }

    /// Encode a list of CrdtChange ops to a JSON array as UTF-8 bytes.
    ///
    /// This is the wire format for sync batches.
    pub fn encode_batch(ops: &[CrdtChange]) -> Result<Vec<u8>> {
        serde_json::to_vec(ops).map_err(|e| CoreError::Serialization(e.to_string()))
    }

    /// Decode a JSON array of CrdtChange ops from UTF-8 bytes.
    pub fn decode_batch(bytes: &[u8]) -> Result<Vec<CrdtChange>> {
        serde_json::from_slice(bytes).map_err(|e| CoreError::Serialization(e.to_string()))
    }

    /// Generate the default op_id from the composite key.
    fn default_op_id(
        entity_table: &str,
        entity_id: &str,
        field_name: &str,
        client_hlc: &str,
        device_id: &str,
    ) -> String {
        format!("{entity_table}:{entity_id}:{field_name}:{client_hlc}:{device_id}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_change(op_id: &str, hlc: &str, device_id: &str) -> CrdtChange {
        CrdtChange {
            op_id: op_id.to_string(),
            batch_id: None,
            entity_id: "entity1".to_string(),
            entity_table: "members".to_string(),
            field_name: "name".to_string(),
            encoded_value: "\"Alice\"".to_string(),
            client_hlc: hlc.to_string(),
            is_delete: false,
            device_id: device_id.to_string(),
            epoch: 0,
            server_seq: None,
        }
    }

    #[test]
    fn wins_over_higher_timestamp_wins() {
        let a = make_change("op1", "2000:0:node", "device1");
        let b = make_change("op2", "1000:0:node", "device1");
        assert!(a.wins_over(&b).unwrap());
        assert!(!b.wins_over(&a).unwrap());
    }

    #[test]
    fn wins_over_higher_counter_wins() {
        let a = make_change("op1", "1000:5:node", "device1");
        let b = make_change("op2", "1000:3:node", "device1");
        assert!(a.wins_over(&b).unwrap());
        assert!(!b.wins_over(&a).unwrap());
    }

    #[test]
    fn wins_over_higher_device_id_wins() {
        let a = make_change("op1", "1000:0:node", "device_b");
        let b = make_change("op2", "1000:0:node", "device_a");
        assert!(a.wins_over(&b).unwrap());
        assert!(!b.wins_over(&a).unwrap());
    }

    #[test]
    fn wins_over_higher_op_id_wins_as_final_tiebreaker() {
        let a = make_change("op_z", "1000:0:node", "device_a");
        let b = make_change("op_a", "1000:0:node", "device_a");
        assert!(a.wins_over(&b).unwrap());
        assert!(!b.wins_over(&a).unwrap());
    }

    #[test]
    fn wins_over_equal_returns_false() {
        let a = make_change("op1", "1000:0:node", "device1");
        let b = make_change("op1", "1000:0:node", "device1");
        assert!(!a.wins_over(&b).unwrap());
    }

    #[test]
    fn is_bulk_reset() {
        let mut change = make_change("op1", "1000:0:node", "device1");
        assert!(!change.is_bulk_reset());
        change.field_name = BULK_RESET_FIELD.to_string();
        assert!(change.is_bulk_reset());
    }

    #[test]
    fn default_op_id_generation() {
        let change = CrdtChange::new(
            None,
            None,
            "ent1".to_string(),
            "members".to_string(),
            "name".to_string(),
            Some("\"Alice\"".to_string()),
            Some("1000:0:node".to_string()),
            false,
            Some("dev1".to_string()),
            Some(0),
            None,
        );
        assert_eq!(change.op_id, "members:ent1:name:1000:0:node:dev1");
    }

    #[test]
    fn json_serialization_matches_dart_format() {
        let change = CrdtChange {
            op_id: "test-op".to_string(),
            batch_id: None,
            entity_id: "entity-1".to_string(),
            entity_table: "members".to_string(),
            field_name: "name".to_string(),
            encoded_value: "\"Alice\"".to_string(),
            client_hlc: "1710500000000:0:a1b2c3d4e5f6".to_string(),
            is_delete: false,
            device_id: "a1b2c3d4e5f6".to_string(),
            epoch: 0,
            server_seq: None,
        };

        let json: serde_json::Value = serde_json::to_value(&change).unwrap();

        // Verify exact field names match Dart's snake_case format
        assert_eq!(json["op_id"], "test-op");
        assert_eq!(json["entity_id"], "entity-1");
        assert_eq!(json["entity_table"], "members");
        assert_eq!(json["field_name"], "name");
        assert_eq!(json["encoded_value"], "\"Alice\"");
        assert_eq!(json["client_hlc"], "1710500000000:0:a1b2c3d4e5f6");
        assert_eq!(json["is_delete"], false);
        assert_eq!(json["device_id"], "a1b2c3d4e5f6");
        assert_eq!(json["epoch"], 0);

        // batch_id and server_seq should NOT be present when None
        assert!(json.get("batch_id").is_none());
        assert!(json.get("server_seq").is_none());
    }

    #[test]
    fn json_serialization_with_optional_fields() {
        let change = CrdtChange {
            op_id: "test-op".to_string(),
            batch_id: Some("batch-1".to_string()),
            entity_id: "entity-1".to_string(),
            entity_table: "members".to_string(),
            field_name: "name".to_string(),
            encoded_value: "\"Alice\"".to_string(),
            client_hlc: "1000:0:node".to_string(),
            is_delete: false,
            device_id: "node".to_string(),
            epoch: 0,
            server_seq: Some(42),
        };

        let json: serde_json::Value = serde_json::to_value(&change).unwrap();
        assert_eq!(json["batch_id"], "batch-1");
        assert_eq!(json["server_seq"], 42);
    }

    #[test]
    fn json_deserialization_matches_dart_format() {
        let json_str = r#"{
            "op_id": "test-op",
            "entity_id": "entity-1",
            "entity_table": "members",
            "field_name": "name",
            "encoded_value": "\"Bob\"",
            "client_hlc": "1000:0:node",
            "is_delete": false,
            "device_id": "node",
            "epoch": 0
        }"#;

        let change: CrdtChange = serde_json::from_str(json_str).unwrap();
        assert_eq!(change.op_id, "test-op");
        assert_eq!(change.entity_id, "entity-1");
        assert_eq!(change.encoded_value, "\"Bob\"");
        assert!(change.batch_id.is_none());
        assert!(change.server_seq.is_none());
    }

    #[test]
    fn encode_decode_batch_roundtrip() {
        let ops = vec![
            make_change("op1", "1000:0:node", "dev1"),
            make_change("op2", "1001:0:node", "dev1"),
        ];

        let bytes = CrdtChange::encode_batch(&ops).unwrap();
        let decoded = CrdtChange::decode_batch(&bytes).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].op_id, "op1");
        assert_eq!(decoded[1].op_id, "op2");
    }

    #[test]
    fn encode_batch_empty() {
        let ops: Vec<CrdtChange> = vec![];
        let bytes = CrdtChange::encode_batch(&ops).unwrap();
        let decoded = CrdtChange::decode_batch(&bytes).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn decode_batch_invalid_json() {
        assert!(CrdtChange::decode_batch(b"not json").is_err());
    }
}
