use serde::{de::IgnoredAny, Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::hlc::Hlc;

/// Sentinel field name used for bulk reset operations.
pub const BULK_RESET_FIELD: &str = "_bulk_reset";

/// XChaCha20-Poly1305 authentication tag bytes appended to sync ciphertexts.
pub const OP_BATCH_AEAD_TAG_BYTES: usize = 16;

/// Ciphertext+tag size buckets for newly encoded encrypted op batches.
///
/// `CrdtChange::encode_batch` pads plaintext so the ciphertext returned by
/// `xchacha_encrypt_for_sync` lands exactly on one of these sizes for batches
/// at or below the largest bucket. Larger batches are left unpadded to avoid
/// inflating already-large relay uploads.
pub const PADDED_OP_BATCH_CIPHERTEXT_BUCKETS: &[usize] = &[
    512,
    1024,
    2 * 1024,
    4 * 1024,
    8 * 1024,
    16 * 1024,
    32 * 1024,
    64 * 1024,
    128 * 1024,
    256 * 1024,
    512 * 1024,
];

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

#[derive(Serialize)]
struct EncodedCrdtBatch<'a> {
    ops: &'a [CrdtChange],
    padding: &'a str,
}

#[derive(Deserialize)]
struct DecodedCrdtBatch {
    ops: Vec<CrdtChange>,
    #[serde(default = "ignored_padding")]
    #[allow(dead_code)]
    padding: IgnoredAny,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum CrdtBatchWire {
    Padded(DecodedCrdtBatch),
    Legacy(Vec<CrdtChange>),
}

fn ignored_padding() -> IgnoredAny {
    IgnoredAny
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
            Self::default_op_id(&entity_table, &entity_id, &field_name, &client_hlc, &device_id)
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

    pub fn is_bulk_reset(&self) -> bool {
        self.field_name == BULK_RESET_FIELD
    }

    /// Validate that this op's embedded attribution matches the verified
    /// sender identity from its signed relay envelope.
    pub fn validate_attribution(&self, sender_device_id: &str) -> Result<()> {
        if self.device_id != sender_device_id {
            return Err(CoreError::Engine(format!(
                "CRDT op attribution mismatch for {}: op.device_id={} envelope.sender_device_id={}",
                self.op_id, self.device_id, sender_device_id
            )));
        }

        let hlc = Hlc::from_string(&self.client_hlc)?;
        if hlc.node_id != sender_device_id {
            return Err(CoreError::Engine(format!(
                "CRDT op HLC attribution mismatch for {}: client_hlc.node_id={} envelope.sender_device_id={}",
                self.op_id, hlc.node_id, sender_device_id
            )));
        }

        Ok(())
    }

    /// Field-level Last-Write-Wins comparison.
    ///
    /// Three-level tiebreaker (matching Dart implementation):
    /// 1. Compare HLC (timestamp, counter, node_id)
    /// 2. Compare device_id lexicographically
    /// 3. Compare op_id lexicographically
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

    /// Encode a list of CrdtChange ops to padded JSON UTF-8 bytes.
    ///
    /// New batches use an object wrapper with an ignored `padding` field so
    /// encrypted op batch ciphertext sizes fall into coarse buckets. Receivers
    /// remain backward-compatible with the historical bare JSON array.
    pub fn encode_batch(ops: &[CrdtChange]) -> Result<Vec<u8>> {
        let empty_padding = Self::encode_batch_envelope(ops, "")?;
        let Some(ciphertext_bucket) =
            Self::ciphertext_bucket_for_plaintext_len(empty_padding.len())
        else {
            return Ok(empty_padding);
        };

        let target_plaintext_len = ciphertext_bucket - OP_BATCH_AEAD_TAG_BYTES;
        let padding_len = target_plaintext_len.saturating_sub(empty_padding.len());
        if padding_len == 0 {
            return Ok(empty_padding);
        }

        let padding = "A".repeat(padding_len);
        let padded = Self::encode_batch_envelope(ops, &padding)?;
        if padded.len() != target_plaintext_len {
            return Err(CoreError::Serialization(format!(
                "padded op batch length {} did not match target {}",
                padded.len(),
                target_plaintext_len
            )));
        }

        Ok(padded)
    }

    /// Decode CrdtChange ops from UTF-8 bytes.
    ///
    /// Accepts both the padded object wrapper and the historical bare JSON
    /// array. The `padding` field is intentionally ignored.
    pub fn decode_batch(bytes: &[u8]) -> Result<Vec<CrdtChange>> {
        let batch: CrdtBatchWire =
            serde_json::from_slice(bytes).map_err(|e| CoreError::Serialization(e.to_string()))?;
        Ok(match batch {
            CrdtBatchWire::Padded(batch) => batch.ops,
            CrdtBatchWire::Legacy(ops) => ops,
        })
    }

    fn encode_batch_envelope(ops: &[CrdtChange], padding: &str) -> Result<Vec<u8>> {
        serde_json::to_vec(&EncodedCrdtBatch { ops, padding })
            .map_err(|e| CoreError::Serialization(e.to_string()))
    }

    fn ciphertext_bucket_for_plaintext_len(plaintext_len: usize) -> Option<usize> {
        let ciphertext_len = plaintext_len.checked_add(OP_BATCH_AEAD_TAG_BYTES)?;
        PADDED_OP_BATCH_CIPHERTEXT_BUCKETS.iter().copied().find(|bucket| *bucket >= ciphertext_len)
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

/// Length of the base64-encoded form of `raw_len` raw bytes, using standard
/// padding (each 3 input bytes -> 4 output chars, rounded up).
const fn base64_encoded_len(raw_len: usize) -> usize {
    // Standard base64 with `=` padding: ceil(raw_len / 3) * 4.
    raw_len.div_ceil(3) * 4
}

/// Length in characters of the JSON-decimal form of a `u64` (no sign).
fn json_u64_len(n: u64) -> usize {
    if n == 0 {
        return 1;
    }
    let mut len = 0usize;
    let mut x = n;
    while x > 0 {
        len += 1;
        x /= 10;
    }
    len
}

/// Length in characters of the JSON-decimal form of an `i64` (with optional
/// leading minus sign).
fn json_i64_len(n: i64) -> usize {
    if n < 0 {
        // i64::MIN cannot be negated, so go through unsigned absolute form.
        1 + json_u64_len(n.unsigned_abs())
    } else {
        json_u64_len(n as u64)
    }
}

/// Conservative budget for fields in a `SignedBatchEnvelope` we cannot derive
/// from `&[CrdtChange]`. The partitioner uses this to keep the estimate tight
/// without taking extra parameters: real sync ids are 64 hex chars.
const ESTIMATED_SYNC_ID_LEN: usize = 64;
/// `batch_kind` is always `"ops"` for the push path the partitioner targets.
const ESTIMATED_BATCH_KIND: &str = "ops";

/// Conservative upper bound on the serialized JSON body size of a
/// `SignedBatchEnvelope` carrying `ops`, given the signature's raw byte count.
///
/// Accounts for:
///   * `ops` plaintext (`CrdtChange::encode_batch`),
///   * the 16-byte XChaCha20-Poly1305 AEAD tag,
///   * AEAD ciphertext padding (`PADDED_OP_BATCH_CIPHERTEXT_BUCKETS`) — when
///     the plaintext fits in a bucket the ciphertext lands at the bucket size;
///     beyond 512 KiB the ciphertext is unpadded,
///   * base64 expansion (`ceil(N/3) * 4`) for `ciphertext`, `signature`,
///     `nonce` (always 24 bytes), and `payload_hash` (always 32 bytes),
///   * the fixed envelope-key overhead and the variable field strings
///     `batch_id`, `device_id`, and `epoch` taken from the first op. The
///     `sync_id` field is budgeted at `ESTIMATED_SYNC_ID_LEN` (typical
///     production size).
///
/// The estimate is tight to a small constant: the partitioner sizes batches
/// against this number, leaving the relay-cap headroom to absorb the slack.
pub fn estimate_envelope_body_size(ops: &[CrdtChange], signature_bytes: usize) -> usize {
    // 1. Plaintext length is the same the engine would produce when it calls
    //    `encode_batch` on this op list. A serialization error here returns
    //    `usize::MAX` so the partitioner forces an own-bucket placement.
    let plaintext_len = match CrdtChange::encode_batch(ops) {
        Ok(p) => p.len(),
        Err(_) => return usize::MAX,
    };

    // 2. Ciphertext = plaintext + AEAD tag. `encode_batch` already padded
    //    plaintext so that ciphertext lands on a bucket boundary (if one
    //    applies); beyond 512 KiB the plaintext is left as-is.
    let ciphertext_len = plaintext_len + OP_BATCH_AEAD_TAG_BYTES;

    // 3. Base64 expansion for the four byte-array envelope fields.
    let ciphertext_b64_len = base64_encoded_len(ciphertext_len);
    let signature_b64_len = base64_encoded_len(signature_bytes);
    let nonce_b64_len = base64_encoded_len(24);
    let payload_hash_b64_len = base64_encoded_len(32);

    // 4. Per-op contextual fields. All ops in one batch share `device_id`,
    //    `batch_id`, and `epoch`, so the first op is representative.
    let (device_id_len, batch_id_len, epoch_len) = match ops.first() {
        Some(op) => {
            let batch_id_len = op.batch_id.as_deref().map(str::len).unwrap_or(0);
            (op.device_id.len(), batch_id_len, json_i64_len(op.epoch as i64))
        }
        None => (0, 0, json_u64_len(0)),
    };

    // 5. Envelope key + delimiter overhead. Each `"key":` token contributes
    //    its UTF-8 length plus the surrounding JSON quote/colon characters,
    //    and one separator comma per field (the trailing field has no comma,
    //    but accounting one for all simplifies the math; we shave the extra
    //    later via the trailing brace adjustment).
    //
    // JSON skeleton (newlines/spaces are illustrative — `to_vec` emits a
    // single-line, no-whitespace form):
    //
    // {"protocol_version":<n>,"sync_id":"<sync_id>",
    //  "epoch":<n>,"batch_id":"<batch_id>",
    //  "batch_kind":"ops","sender_device_id":"<device_id>",
    //  "sender_ml_dsa_key_generation":<n>,"payload_hash":"<b64>",
    //  "signature":"<b64>","nonce":"<b64>","ciphertext":"<b64>"}
    //
    // We size the key-and-quote overhead conservatively:
    //   * `"<key>":` for each of the 11 fields
    //   * `"<value>"` quotes for the 8 string fields
    //   * `,` between fields (one fewer than field count)
    //   * `{}` braces
    //
    // Numeric value characters are added separately. `sender_ml_dsa_key_generation`
    // and `protocol_version` are budgeted at 10 chars each (max digits of u32),
    // which is conservative.

    let fixed_overhead = 2 /* braces */
        // field-name overhead: `"<name>":` (i.e. name.len() + 3) for each field.
        + ("protocol_version".len() + 3)
        + ("sync_id".len() + 3)
        + ("epoch".len() + 3)
        + ("batch_id".len() + 3)
        + ("batch_kind".len() + 3)
        + ("sender_device_id".len() + 3)
        + ("sender_ml_dsa_key_generation".len() + 3)
        + ("payload_hash".len() + 3)
        + ("signature".len() + 3)
        + ("nonce".len() + 3)
        + ("ciphertext".len() + 3)
        // separators between the 11 fields
        + 10
        // string value quotes for the 8 string-typed fields
        // (sync_id, batch_id, batch_kind, sender_device_id,
        //  payload_hash, signature, nonce, ciphertext)
        + 16
        // conservative max digit count for u16 protocol_version
        + 5
        // conservative max digit count for u32 sender_ml_dsa_key_generation
        + 10;

    fixed_overhead
        + ESTIMATED_SYNC_ID_LEN
        + epoch_len
        + batch_id_len
        + ESTIMATED_BATCH_KIND.len()
        + device_id_len
        + payload_hash_b64_len
        + signature_b64_len
        + nonce_b64_len
        + ciphertext_b64_len
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
    fn validate_attribution_accepts_matching_sender() {
        let change = make_change("op1", "1000:0:device1", "device1");
        change.validate_attribution("device1").unwrap();
    }

    #[test]
    fn validate_attribution_rejects_mismatched_device_id() {
        let change = make_change("op1", "1000:0:device1", "device2");
        let err = change.validate_attribution("device1").unwrap_err().to_string();
        assert!(err.contains("op.device_id=device2"), "{err}");
        assert!(err.contains("envelope.sender_device_id=device1"), "{err}");
    }

    #[test]
    fn validate_attribution_rejects_mismatched_hlc_node_id() {
        let change = make_change("op1", "1000:0:device2", "device1");
        let err = change.validate_attribution("device1").unwrap_err().to_string();
        assert!(err.contains("client_hlc.node_id=device2"), "{err}");
        assert!(err.contains("envelope.sender_device_id=device1"), "{err}");
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
    fn decode_batch_accepts_legacy_array() {
        let ops = vec![
            make_change("op1", "1000:0:node", "dev1"),
            make_change("op2", "1001:0:node", "dev1"),
        ];

        let legacy_bytes = serde_json::to_vec(&ops).unwrap();
        let decoded = CrdtChange::decode_batch(&legacy_bytes).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].op_id, "op1");
        assert_eq!(decoded[1].op_id, "op2");
    }

    #[test]
    fn decode_batch_ignores_padding_field() {
        let ops = vec![make_change("op1", "1000:0:node", "dev1")];
        let padded = serde_json::json!({
            "ops": ops,
            "padding": "ignored encrypted filler"
        });
        let padded_bytes = serde_json::to_vec(&padded).unwrap();

        let decoded = CrdtChange::decode_batch(&padded_bytes).unwrap();

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].op_id, "op1");
    }

    #[test]
    fn encode_batch_pads_encrypted_ciphertext_to_documented_bucket() {
        let key = [7u8; 32];

        for value_len in [0usize, 600, 1800] {
            let mut change = make_change("op1", "1000:0:node", "dev1");
            change.encoded_value = format!("\"{}\"", "x".repeat(value_len));

            let plaintext = CrdtChange::encode_batch(&[change]).unwrap();
            let (ciphertext, _nonce) =
                prism_sync_crypto::aead::xchacha_encrypt_for_sync(&key, &plaintext, b"aad")
                    .unwrap();

            assert!(
                PADDED_OP_BATCH_CIPHERTEXT_BUCKETS.contains(&ciphertext.len()),
                "ciphertext length {} was not in {:?}",
                ciphertext.len(),
                PADDED_OP_BATCH_CIPHERTEXT_BUCKETS
            );
        }
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

    /// Realistic sender state used by the envelope-size tests below.
    struct EstimateFixture {
        sync_id: String,
        epoch: i32,
        device_id: String,
        ml_dsa_key_generation: u32,
        ed25519_signing_key: ed25519_dalek::SigningKey,
        ml_dsa_signing_key: prism_sync_crypto::DevicePqSigningKey,
        encryption_key: [u8; 32],
    }

    impl EstimateFixture {
        fn new() -> Self {
            use rand::rngs::OsRng;
            let ed25519_signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
            let device_secret = prism_sync_crypto::DeviceSecret::generate();
            let device_id = "ee1ee1ee1ee1ee1ee1ee1ee1ee1ee1ee".to_string();
            let ml_dsa_signing_key =
                device_secret.ml_dsa_65_keypair(&device_id).expect("ml-dsa-65 keypair");
            Self {
                sync_id:
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
                epoch: 7,
                device_id,
                ml_dsa_key_generation: 0,
                ed25519_signing_key,
                ml_dsa_signing_key,
                encryption_key: [42u8; 32],
            }
        }

        /// Encode + encrypt + sign the same way the push path does, so we can
        /// compare the estimate to a real envelope serialization.
        fn real_envelope_body_size(&self, ops: &[CrdtChange], batch_id: &str) -> usize {
            let plaintext = CrdtChange::encode_batch(ops).expect("encode_batch");
            let payload_hash = crate::batch_signature::compute_payload_hash(&plaintext);
            let aad =
                crate::sync_aad::build_sync_aad(&self.sync_id, &self.device_id, self.epoch, batch_id, "ops");
            let (ciphertext, nonce) =
                prism_sync_crypto::aead::xchacha_encrypt_for_sync(&self.encryption_key, &plaintext, &aad)
                    .expect("encrypt");
            let envelope = crate::batch_signature::sign_batch(
                &self.ed25519_signing_key,
                &self.ml_dsa_signing_key,
                &self.sync_id,
                self.epoch,
                batch_id,
                "ops",
                &self.device_id,
                self.ml_dsa_key_generation,
                &payload_hash,
                nonce,
                ciphertext,
            )
            .expect("sign_batch");
            serde_json::to_vec(&envelope).expect("envelope to_vec").len()
        }

        fn signature_bytes(&self, ops: &[CrdtChange]) -> usize {
            // Sign once just to discover the produced signature width
            // (length-prefixed wire format: 4 + 64 + 4 + 3309 = 3381).
            let plaintext = CrdtChange::encode_batch(ops).expect("encode_batch");
            let payload_hash = crate::batch_signature::compute_payload_hash(&plaintext);
            let envelope = crate::batch_signature::sign_batch(
                &self.ed25519_signing_key,
                &self.ml_dsa_signing_key,
                &self.sync_id,
                self.epoch,
                "estimate-probe",
                "ops",
                &self.device_id,
                self.ml_dsa_key_generation,
                &payload_hash,
                [0u8; 24],
                vec![],
            )
            .expect("sign_batch");
            envelope.signature.len()
        }

        fn make_op(&self, field_name: &str, encoded_value: String, batch_id: &str) -> CrdtChange {
            CrdtChange {
                op_id: format!("op-{field_name}-1234abcd-5678efab-90ab-cdef01234567"),
                batch_id: Some(batch_id.to_string()),
                entity_id: "entity-abcdefabcdefabcdefabcdefabcdef12".to_string(),
                entity_table: "members".to_string(),
                field_name: field_name.to_string(),
                encoded_value,
                client_hlc: format!("1715000000000:5:{}", self.device_id),
                is_delete: false,
                device_id: self.device_id.clone(),
                epoch: self.epoch,
                server_seq: None,
            }
        }
    }

    fn quoted_string_of_len(byte_len: usize) -> String {
        // Avatar/banner blobs go through SyncValue::String (base64) → encoded
        // as a JSON-quoted string. Produce one of approximately `byte_len`.
        format!("\"{}\"", "A".repeat(byte_len))
    }

    fn assert_estimate_within_slack(estimate: usize, actual: usize, label: &str) {
        // The estimator MUST be an upper bound and within a small slack so the
        // partitioner can be sized against it.
        assert!(
            estimate >= actual,
            "{label}: estimate {estimate} < actual {actual} (must be an upper bound)",
        );
        let slack = estimate - actual;
        assert!(
            slack <= 200,
            "{label}: estimate {estimate} exceeded actual {actual} by {slack} bytes (cap 200)",
        );
    }

    #[test]
    fn estimate_envelope_body_size_tight_for_small_batch() {
        let fixture = EstimateFixture::new();
        let batch_id = "0aaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let ops = vec![
            fixture.make_op("name", "\"Alice\"".to_string(), batch_id),
            fixture.make_op("pronouns", "\"she/her\"".to_string(), batch_id),
        ];

        let actual = fixture.real_envelope_body_size(&ops, batch_id);
        let estimate = estimate_envelope_body_size(&ops, fixture.signature_bytes(&ops));
        assert_estimate_within_slack(estimate, actual, "small batch");
    }

    #[test]
    fn estimate_envelope_body_size_tight_for_avatar_only_batch() {
        let fixture = EstimateFixture::new();
        let batch_id = "0aaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        // Avatar after base64 expansion ≈ 256 KB raw → 342 KB JSON string body.
        let avatar_value = quoted_string_of_len(342 * 1024);
        let ops = vec![fixture.make_op("avatar", avatar_value, batch_id)];

        let actual = fixture.real_envelope_body_size(&ops, batch_id);
        let estimate = estimate_envelope_body_size(&ops, fixture.signature_bytes(&ops));
        assert_estimate_within_slack(estimate, actual, "avatar-only batch");
    }

    #[test]
    fn estimate_envelope_body_size_tight_for_banner_only_batch() {
        let fixture = EstimateFixture::new();
        let batch_id = "0aaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        // Banner ≈ 512 KB raw → 683 KB JSON string body. Exceeds the largest
        // ciphertext-padding bucket; the ciphertext is left unpadded.
        let banner_value = quoted_string_of_len(683 * 1024);
        let ops = vec![fixture.make_op("banner", banner_value, batch_id)];

        let actual = fixture.real_envelope_body_size(&ops, batch_id);
        let estimate = estimate_envelope_body_size(&ops, fixture.signature_bytes(&ops));
        assert_estimate_within_slack(estimate, actual, "banner-only batch");
    }

    #[test]
    fn estimate_envelope_body_size_tight_for_avatar_plus_banner_batch() {
        let fixture = EstimateFixture::new();
        let batch_id = "0aaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let avatar_value = quoted_string_of_len(342 * 1024);
        let banner_value = quoted_string_of_len(683 * 1024);
        let ops = vec![
            fixture.make_op("avatar", avatar_value, batch_id),
            fixture.make_op("banner", banner_value, batch_id),
        ];

        let actual = fixture.real_envelope_body_size(&ops, batch_id);
        let estimate = estimate_envelope_body_size(&ops, fixture.signature_bytes(&ops));
        assert_estimate_within_slack(estimate, actual, "avatar + banner batch");
    }
}
