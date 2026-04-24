use std::collections::HashMap;

use chrono::Utc;
use uuid::Uuid;

use crate::error::Result;
use crate::hlc::Hlc;
use crate::schema::{encode_value, SyncValue};
use crate::storage::{FieldVersion, PendingOp, SyncStorage};

/// Constant field name used for delete tombstone ops.
pub const DELETED_FIELD: &str = "is_deleted";

/// Records field-level ops into pending_ops at mutation time.
///
/// The caller is responsible for:
/// - Creating a `local_batch_id` (UUID v4) shared by all ops in one transaction
/// - Invoking `emit_create`, `emit_update`, or `emit_delete`
///
/// The OpEmitter ticks the HLC once per call and stamps every op in that
/// invocation with the same HLC value, ensuring causal consistency within
/// a batch.
///
/// Ported from Dart `lib/core/sync/op_emitter.dart`.
pub struct OpEmitter {
    device_id: String,
    sync_id: String,
    epoch: i32,
    last_hlc: Hlc,
}

impl OpEmitter {
    pub fn new(device_id: String, sync_id: String, epoch: i32, last_hlc: Option<Hlc>) -> Self {
        let last_hlc = last_hlc.unwrap_or_else(|| Hlc::zero(&device_id));
        Self { device_id, sync_id, epoch, last_hlc }
    }

    /// The most recent HLC assigned by this emitter.
    pub fn last_hlc(&self) -> &Hlc {
        &self.last_hlc
    }

    /// Update the epoch used for new ops.
    pub fn set_epoch(&mut self, new_epoch: i32) {
        self.epoch = new_epoch;
    }

    /// Advance the emitter's HLC watermark. The next `tick()` will produce
    /// an HLC strictly greater than either `new_hlc` or the current
    /// wall-clock time, whichever is larger.
    ///
    /// Used after bootstrap/snapshot imports so locally minted HLCs never
    /// fall behind state that was seeded from an external source.
    pub fn set_last_hlc(&mut self, new_hlc: Hlc) {
        if new_hlc > self.last_hlc {
            self.last_hlc = new_hlc;
        }
    }

    /// Tick the HLC once and return the new value.
    fn tick(&mut self) -> Hlc {
        self.last_hlc = Hlc::now(&self.device_id, Some(&self.last_hlc));
        self.last_hlc.clone()
    }

    /// Emit ops for a newly created entity.
    ///
    /// Every entry in `fields` becomes one pending op row. All ops share the
    /// same HLC and `local_batch_id`.
    pub fn emit_create(
        &mut self,
        storage: &dyn SyncStorage,
        entity_table: &str,
        entity_id: &str,
        fields: &HashMap<String, SyncValue>,
        local_batch_id: &str,
    ) -> Result<()> {
        let hlc = self.tick();
        let hlc_string = hlc.to_string();
        let now = Utc::now();

        let mut tx = storage.begin_tx()?;

        for (field_name, value) in fields {
            let op_id = Uuid::new_v4().to_string();
            let encoded = encode_value(value);

            tx.insert_pending_op(&PendingOp {
                op_id: op_id.clone(),
                sync_id: self.sync_id.clone(),
                epoch: self.epoch,
                device_id: self.device_id.clone(),
                local_batch_id: local_batch_id.to_string(),
                entity_table: entity_table.to_string(),
                entity_id: entity_id.to_string(),
                field_name: field_name.clone(),
                encoded_value: encoded.clone(),
                is_delete: false,
                client_hlc: hlc_string.clone(),
                created_at: now,
                pushed_at: None,
            })?;

            tx.upsert_field_version(&FieldVersion {
                sync_id: self.sync_id.clone(),
                entity_table: entity_table.to_string(),
                entity_id: entity_id.to_string(),
                field_name: field_name.clone(),
                winning_op_id: op_id,
                winning_device_id: self.device_id.clone(),
                winning_hlc: hlc_string.clone(),
                winning_encoded_value: Some(encoded),
                updated_at: now,
            })?;
        }

        tx.commit()?;

        tracing::debug!(
            table = entity_table,
            entity_id = entity_id,
            field_count = fields.len(),
            batch_id = local_batch_id,
            "Queued create ops"
        );

        Ok(())
    }

    /// Emit ops for changed fields on an existing entity.
    ///
    /// Only the fields that actually changed should be passed in
    /// `changed_fields`. Each becomes one pending op row.
    pub fn emit_update(
        &mut self,
        storage: &dyn SyncStorage,
        entity_table: &str,
        entity_id: &str,
        changed_fields: &HashMap<String, SyncValue>,
        local_batch_id: &str,
    ) -> Result<()> {
        if changed_fields.is_empty() {
            return Ok(());
        }

        let hlc = self.tick();
        let hlc_string = hlc.to_string();
        let now = Utc::now();

        let mut tx = storage.begin_tx()?;

        for (field_name, value) in changed_fields {
            let op_id = Uuid::new_v4().to_string();
            let encoded = encode_value(value);

            tx.insert_pending_op(&PendingOp {
                op_id: op_id.clone(),
                sync_id: self.sync_id.clone(),
                epoch: self.epoch,
                device_id: self.device_id.clone(),
                local_batch_id: local_batch_id.to_string(),
                entity_table: entity_table.to_string(),
                entity_id: entity_id.to_string(),
                field_name: field_name.clone(),
                encoded_value: encoded.clone(),
                is_delete: false,
                client_hlc: hlc_string.clone(),
                created_at: now,
                pushed_at: None,
            })?;

            tx.upsert_field_version(&FieldVersion {
                sync_id: self.sync_id.clone(),
                entity_table: entity_table.to_string(),
                entity_id: entity_id.to_string(),
                field_name: field_name.clone(),
                winning_op_id: op_id,
                winning_device_id: self.device_id.clone(),
                winning_hlc: hlc_string.clone(),
                winning_encoded_value: Some(encoded),
                updated_at: now,
            })?;
        }

        tx.commit()?;

        tracing::debug!(
            table = entity_table,
            entity_id = entity_id,
            field_count = changed_fields.len(),
            batch_id = local_batch_id,
            "Queued update ops"
        );

        Ok(())
    }

    /// Populate `field_versions` for an entity without emitting a `pending_op`.
    ///
    /// Used exclusively by the first-device bootstrap path to reconstruct
    /// CRDT state from pre-existing local data. Callers MUST guarantee the
    /// resulting state should not be pushed to the relay — there is no
    /// legitimate code path that mixes seeded rows with normal mutations,
    /// because bootstrap runs before first sync on the first device.
    ///
    /// Semantics: identical to `emit_create` except that we skip
    /// `insert_pending_op`. We still tick the HLC once and stamp every
    /// field in this invocation with that HLC, and we still upsert one
    /// `field_versions` row per field. Writes happen inside a single
    /// `BEGIN IMMEDIATE` transaction.
    #[allow(dead_code)] // Wired into `client::bootstrap_existing_state` by a follow-up patch.
    pub(crate) fn seed_fields(
        &mut self,
        storage: &dyn SyncStorage,
        entity_table: &str,
        entity_id: &str,
        fields: &HashMap<String, SyncValue>,
    ) -> Result<()> {
        if fields.is_empty() {
            return Ok(());
        }

        let hlc = self.tick();
        let hlc_string = hlc.to_string();
        let now = Utc::now();

        let mut tx = storage.begin_tx()?;

        for (field_name, value) in fields {
            let op_id = Uuid::new_v4().to_string();
            let encoded = encode_value(value);

            tx.upsert_field_version(&FieldVersion {
                sync_id: self.sync_id.clone(),
                entity_table: entity_table.to_string(),
                entity_id: entity_id.to_string(),
                field_name: field_name.clone(),
                winning_op_id: op_id,
                winning_device_id: self.device_id.clone(),
                winning_hlc: hlc_string.clone(),
                winning_encoded_value: Some(encoded),
                updated_at: now,
            })?;
        }

        tx.commit()?;

        tracing::debug!(
            table = entity_table,
            entity_id = entity_id,
            field_count = fields.len(),
            "Seeded field_versions for bootstrap"
        );

        Ok(())
    }

    /// Emit a tombstone op for a soft-deleted entity.
    ///
    /// Creates a single op with `field_name = "is_deleted"` and
    /// `encoded_value = "true"`.
    pub fn emit_delete(
        &mut self,
        storage: &dyn SyncStorage,
        entity_table: &str,
        entity_id: &str,
        local_batch_id: &str,
    ) -> Result<()> {
        let hlc = self.tick();
        let hlc_string = hlc.to_string();
        let now = Utc::now();
        let op_id = Uuid::new_v4().to_string();

        let mut tx = storage.begin_tx()?;

        tx.insert_pending_op(&PendingOp {
            op_id: op_id.clone(),
            sync_id: self.sync_id.clone(),
            epoch: self.epoch,
            device_id: self.device_id.clone(),
            local_batch_id: local_batch_id.to_string(),
            entity_table: entity_table.to_string(),
            entity_id: entity_id.to_string(),
            field_name: DELETED_FIELD.to_string(),
            encoded_value: "true".to_string(),
            is_delete: true,
            client_hlc: hlc_string.clone(),
            created_at: now,
            pushed_at: None,
        })?;

        tx.upsert_field_version(&FieldVersion {
            sync_id: self.sync_id.clone(),
            entity_table: entity_table.to_string(),
            entity_id: entity_id.to_string(),
            field_name: DELETED_FIELD.to_string(),
            winning_op_id: op_id,
            winning_device_id: self.device_id.clone(),
            winning_hlc: hlc_string,
            winning_encoded_value: Some("true".to_string()),
            updated_at: now,
        })?;

        tx.commit()?;

        tracing::debug!(
            table = entity_table,
            entity_id = entity_id,
            batch_id = local_batch_id,
            "Queued delete op"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::RusqliteSyncStorage;

    fn make_storage() -> RusqliteSyncStorage {
        RusqliteSyncStorage::in_memory().expect("in_memory storage should succeed")
    }

    fn make_emitter() -> OpEmitter {
        OpEmitter::new("a1b2c3d4e5f6".to_string(), "sync-1".to_string(), 1, None)
    }

    fn make_fields() -> HashMap<String, SyncValue> {
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        fields.insert("age".to_string(), SyncValue::Int(25));
        fields.insert("active".to_string(), SyncValue::Bool(true));
        fields
    }

    #[test]
    fn emit_create_stores_correct_number_of_pending_ops() {
        let storage = make_storage();
        let mut emitter = make_emitter();
        let fields = make_fields();

        emitter.emit_create(&storage, "members", "ent-1", &fields, "batch-1").unwrap();

        let ops = storage.load_batch_ops("batch-1").unwrap();
        assert_eq!(ops.len(), 3);

        // All ops should share the same entity info
        for op in &ops {
            assert_eq!(op.sync_id, "sync-1");
            assert_eq!(op.entity_table, "members");
            assert_eq!(op.entity_id, "ent-1");
            assert_eq!(op.local_batch_id, "batch-1");
            assert_eq!(op.device_id, "a1b2c3d4e5f6");
            assert_eq!(op.epoch, 1);
            assert!(!op.is_delete);
            assert!(op.pushed_at.is_none());
        }

        // All field names should be present
        let field_names: Vec<&str> = ops.iter().map(|op| op.field_name.as_str()).collect();
        assert!(field_names.contains(&"name"));
        assert!(field_names.contains(&"age"));
        assert!(field_names.contains(&"active"));
    }

    #[test]
    fn emit_update_stores_only_changed_fields() {
        let storage = make_storage();
        let mut emitter = make_emitter();

        let mut changed = HashMap::new();
        changed.insert("name".to_string(), SyncValue::String("Bob".to_string()));

        emitter.emit_update(&storage, "members", "ent-1", &changed, "batch-2").unwrap();

        let ops = storage.load_batch_ops("batch-2").unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].field_name, "name");
        assert_eq!(ops[0].encoded_value, "\"Bob\"");
    }

    #[test]
    fn emit_update_skips_empty_fields() {
        let storage = make_storage();
        let mut emitter = make_emitter();
        let hlc_before = emitter.last_hlc().clone();

        let empty: HashMap<String, SyncValue> = HashMap::new();
        emitter.emit_update(&storage, "members", "ent-1", &empty, "batch-empty").unwrap();

        // No ops stored
        let ops = storage.load_batch_ops("batch-empty").unwrap();
        assert!(ops.is_empty());

        // HLC should NOT have advanced (no tick for empty update)
        assert_eq!(*emitter.last_hlc(), hlc_before);
    }

    #[test]
    fn emit_delete_stores_is_deleted_op() {
        let storage = make_storage();
        let mut emitter = make_emitter();

        emitter.emit_delete(&storage, "members", "ent-1", "batch-3").unwrap();

        let ops = storage.load_batch_ops("batch-3").unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].field_name, DELETED_FIELD);
        assert_eq!(ops[0].encoded_value, "true");
        assert!(ops[0].is_delete);
    }

    #[test]
    fn hlc_advances_between_emissions() {
        let storage = make_storage();
        let mut emitter = make_emitter();

        let mut fields1 = HashMap::new();
        fields1.insert("name".to_string(), SyncValue::String("Alice".to_string()));

        emitter.emit_create(&storage, "members", "ent-1", &fields1, "batch-a").unwrap();
        let hlc_after_create = emitter.last_hlc().clone();

        let mut fields2 = HashMap::new();
        fields2.insert("name".to_string(), SyncValue::String("Bob".to_string()));

        emitter.emit_update(&storage, "members", "ent-1", &fields2, "batch-b").unwrap();
        let hlc_after_update = emitter.last_hlc().clone();

        // HLC must advance: either timestamp increases or counter increments
        assert!(hlc_after_update > hlc_after_create);

        emitter.emit_delete(&storage, "members", "ent-1", "batch-c").unwrap();
        let hlc_after_delete = emitter.last_hlc().clone();

        assert!(hlc_after_delete > hlc_after_update);
    }

    #[test]
    fn field_versions_are_updated() {
        let storage = make_storage();
        let mut emitter = make_emitter();

        let mut fields = HashMap::new();
        fields.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        fields.insert("age".to_string(), SyncValue::Int(25));

        emitter.emit_create(&storage, "members", "ent-1", &fields, "batch-fv").unwrap();

        // Both fields should have field versions
        let fv_name = storage.get_field_version("sync-1", "members", "ent-1", "name").unwrap();
        assert!(fv_name.is_some());
        let fv_name = fv_name.unwrap();
        assert_eq!(fv_name.winning_device_id, "a1b2c3d4e5f6");

        let fv_age = storage.get_field_version("sync-1", "members", "ent-1", "age").unwrap();
        assert!(fv_age.is_some());
        let fv_age = fv_age.unwrap();
        assert_eq!(fv_age.winning_device_id, "a1b2c3d4e5f6");

        // Both should share the same HLC (same tick)
        assert_eq!(fv_name.winning_hlc, fv_age.winning_hlc);

        // Now update name — should get a newer HLC
        let mut changed = HashMap::new();
        changed.insert("name".to_string(), SyncValue::String("Bob".to_string()));

        emitter.emit_update(&storage, "members", "ent-1", &changed, "batch-fv2").unwrap();

        let fv_name_updated =
            storage.get_field_version("sync-1", "members", "ent-1", "name").unwrap().unwrap();

        // The winning HLC for name should be newer than the original
        assert_ne!(fv_name_updated.winning_hlc, fv_name.winning_hlc);
        assert_ne!(fv_name_updated.winning_op_id, fv_name.winning_op_id);
    }

    #[test]
    fn field_version_for_delete() {
        let storage = make_storage();
        let mut emitter = make_emitter();

        emitter.emit_delete(&storage, "members", "ent-1", "batch-del").unwrap();

        let fv = storage.get_field_version("sync-1", "members", "ent-1", DELETED_FIELD).unwrap();
        assert!(fv.is_some());
        let fv = fv.unwrap();
        assert_eq!(fv.field_name, DELETED_FIELD);
        assert_eq!(fv.winning_device_id, "a1b2c3d4e5f6");
    }

    #[test]
    fn batch_id_groups_ops_correctly() {
        let storage = make_storage();
        let mut emitter = make_emitter();

        // Batch A: create with 2 fields
        let mut fields_a = HashMap::new();
        fields_a.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        fields_a.insert("age".to_string(), SyncValue::Int(25));

        emitter.emit_create(&storage, "members", "ent-1", &fields_a, "batch-A").unwrap();

        // Batch B: update 1 field
        let mut fields_b = HashMap::new();
        fields_b.insert("name".to_string(), SyncValue::String("Bob".to_string()));

        emitter.emit_update(&storage, "members", "ent-1", &fields_b, "batch-B").unwrap();

        // Batch C: delete
        emitter.emit_delete(&storage, "members", "ent-1", "batch-C").unwrap();

        // Verify each batch has correct number of ops
        let ops_a = storage.load_batch_ops("batch-A").unwrap();
        assert_eq!(ops_a.len(), 2);
        for op in &ops_a {
            assert_eq!(op.local_batch_id, "batch-A");
        }

        let ops_b = storage.load_batch_ops("batch-B").unwrap();
        assert_eq!(ops_b.len(), 1);
        assert_eq!(ops_b[0].local_batch_id, "batch-B");

        let ops_c = storage.load_batch_ops("batch-C").unwrap();
        assert_eq!(ops_c.len(), 1);
        assert_eq!(ops_c[0].local_batch_id, "batch-C");

        // All batches should show up as unpushed
        let batch_ids = storage.get_unpushed_batch_ids("sync-1").unwrap();
        assert_eq!(batch_ids.len(), 3);
    }

    #[test]
    fn all_ops_in_create_share_same_hlc() {
        let storage = make_storage();
        let mut emitter = make_emitter();
        let fields = make_fields();

        emitter.emit_create(&storage, "members", "ent-1", &fields, "batch-hlc").unwrap();

        let ops = storage.load_batch_ops("batch-hlc").unwrap();
        assert_eq!(ops.len(), 3);

        // All ops in the same emission should share the same HLC
        let hlc = &ops[0].client_hlc;
        for op in &ops {
            assert_eq!(&op.client_hlc, hlc);
        }
    }

    #[test]
    fn seed_fields_upserts_field_versions_but_not_pending_ops() {
        let storage = make_storage();
        let mut emitter = make_emitter();
        let fields = make_fields();

        emitter.seed_fields(&storage, "members", "ent-seed", &fields).unwrap();

        // field_versions rows exist for each field
        for field_name in ["name", "age", "active"] {
            let fv = storage
                .get_field_version("sync-1", "members", "ent-seed", field_name)
                .unwrap()
                .expect("field_version should exist after seed_fields");
            assert_eq!(fv.winning_device_id, "a1b2c3d4e5f6");
            assert!(fv.winning_encoded_value.is_some());
        }

        // No pending_ops produced — no unpushed batches for this sync group
        let batch_ids = storage.get_unpushed_batch_ids("sync-1").unwrap();
        assert!(
            batch_ids.is_empty(),
            "seed_fields must NOT produce pending_ops (got batches: {batch_ids:?})"
        );

        // HLC advances on next emit_create: must be greater than the seeded HLC
        let seeded_hlc = emitter.last_hlc().clone();
        let mut more = HashMap::new();
        more.insert("name".to_string(), SyncValue::String("Carol".to_string()));
        emitter.emit_create(&storage, "members", "ent-next", &more, "batch-after-seed").unwrap();
        assert!(emitter.last_hlc() > &seeded_hlc);
    }

    #[test]
    fn seed_fields_skips_empty_fields() {
        let storage = make_storage();
        let mut emitter = make_emitter();
        let hlc_before = emitter.last_hlc().clone();

        let empty: HashMap<String, SyncValue> = HashMap::new();
        emitter.seed_fields(&storage, "members", "ent-empty", &empty).unwrap();

        // HLC should NOT have advanced when nothing was seeded
        assert_eq!(*emitter.last_hlc(), hlc_before);
    }

    #[test]
    fn encoded_values_match_schema_encoding() {
        let storage = make_storage();
        let mut emitter = make_emitter();

        let mut fields = HashMap::new();
        fields.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        fields.insert("count".to_string(), SyncValue::Int(42));
        fields.insert("active".to_string(), SyncValue::Bool(false));
        fields.insert("note".to_string(), SyncValue::Null);

        emitter.emit_create(&storage, "members", "ent-1", &fields, "batch-enc").unwrap();

        let ops = storage.load_batch_ops("batch-enc").unwrap();

        for op in &ops {
            match op.field_name.as_str() {
                "name" => assert_eq!(op.encoded_value, "\"Alice\""),
                "count" => assert_eq!(op.encoded_value, "42"),
                "active" => assert_eq!(op.encoded_value, "false"),
                "note" => assert_eq!(op.encoded_value, "null"),
                other => panic!("Unexpected field: {other}"),
            }
        }
    }
}
