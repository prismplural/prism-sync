use std::collections::HashMap;

use crate::error::Result;
use crate::schema::{SyncFieldDef, SyncValue};

/// How the library reads/writes consumer data tables during merge.
///
/// Each registered entity type gets one implementation. All methods are
/// async to support FFI consumers (Dart isolate model requires async
/// message passing). Sync Rust consumers use `async { Ok(result) }`.
///
/// **Concurrent creation:** If two devices create the same entity_id
/// simultaneously, `write_fields` may be called with `is_new=true` for
/// the first arrival and `is_new=false` for subsequent fields. The consumer
/// MUST implement upsert semantics (INSERT OR UPDATE).
///
/// **Plan 3 integration:** Plan 3's merge engine calls `write_fields()`,
/// `soft_delete()`, `begin_batch()`, `commit_batch()`, and `rollback_batch()`
/// during the pull/apply phase. The engine coordinates `SyncStorageTx` commits
/// with `SyncableEntity` batch commits.
#[async_trait::async_trait]
pub trait SyncableEntity: Send + Sync {
    fn table_name(&self) -> &str;
    fn field_definitions(&self) -> &[SyncFieldDef];

    async fn read_row(&self, entity_id: &str) -> Result<Option<HashMap<String, SyncValue>>>;
    async fn write_fields(
        &self,
        entity_id: &str,
        fields: &HashMap<String, SyncValue>,
        hlc: &str,
        is_new: bool,
    ) -> Result<()>;
    async fn soft_delete(&self, entity_id: &str, hlc: &str) -> Result<()>;
    async fn is_deleted(&self, entity_id: &str) -> Result<bool>;
    async fn hard_delete(&self, entity_id: &str) -> Result<()>;

    /// Called before applying a batch of remote changes. Consumer should begin a transaction.
    async fn begin_batch(&self) -> Result<()> {
        Ok(())
    }
    /// Called after all ops in a batch succeed. Consumer should commit.
    async fn commit_batch(&self) -> Result<()> {
        Ok(())
    }
    /// Called if any op in a batch fails. Consumer should rollback.
    async fn rollback_batch(&self) -> Result<()> {
        Ok(())
    }
}
