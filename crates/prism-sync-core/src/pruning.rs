use std::sync::Arc;

use crate::error::{CoreError, Result};
use crate::storage::{StorageError, SyncStorage};
use crate::syncable_entity::SyncableEntity;

/// Result of a single pruning pass.
#[derive(Debug, Default)]
pub struct PruneResult {
    /// Number of `applied_ops` rows pruned.
    pub applied_ops_pruned: usize,
    /// Number of `field_versions` rows pruned.
    pub field_versions_pruned: usize,
    /// Number of soft-deleted entities hard-deleted from consumer storage.
    pub entities_hard_deleted: usize,
}

/// Prunes tombstones and acknowledged ops that are no longer needed.
pub struct TombstonePruner;

impl TombstonePruner {
    /// Prune tombstones that all active devices have acknowledged.
    ///
    /// Bounded to `max_rows` per pass to avoid long-running transactions.
    ///
    /// # Arguments
    ///
    /// * `storage` - Sync storage for reading/writing op tables.
    /// * `entities` - All registered syncable entities (for `hard_delete`).
    /// * `sync_id` - The sync group to prune.
    /// * `min_acked_seq` - Minimum server_seq acknowledged by all active devices.
    ///   Only ops with `server_seq < min_acked_seq` are eligible for pruning.
    /// * `max_rows` - Maximum rows to prune per call (default: 1000).
    pub async fn prune(
        storage: Arc<dyn SyncStorage>,
        entities: &[Arc<dyn SyncableEntity>],
        sync_id: &str,
        min_acked_seq: i64,
        max_rows: usize,
    ) -> Result<PruneResult> {
        let mut result = PruneResult::default();

        // Phase 1: Find tombstoned entities whose delete op has been acknowledged
        // by all devices (server_seq < min_acked_seq) and hard-delete them.
        let storage_clone = storage.clone();
        let sid = sync_id.to_string();
        let tombstones = tokio::task::spawn_blocking(move || {
            storage_clone.list_prunable_tombstones(&sid, min_acked_seq, max_rows)
        })
        .await
        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;

        // Phase 1a: Hard-delete consumer entities (async, must be outside spawn_blocking)
        let mut deleted_tombstones: Vec<(String, String)> = Vec::new();
        for (table, entity_id) in &tombstones {
            let entity_impl = entities.iter().find(|e| e.table_name() == table);
            if let Some(entity) = entity_impl {
                match entity.hard_delete(entity_id).await {
                    Ok(()) => {
                        result.entities_hard_deleted += 1;
                        deleted_tombstones.push((table.clone(), entity_id.clone()));
                    }
                    Err(e) => {
                        tracing::warn!("hard_delete failed for {}/{}: {e}", table, entity_id);
                    }
                }
            } else {
                // Entity type not registered but field_versions should still be cleaned
                deleted_tombstones.push((table.clone(), entity_id.clone()));
            }
        }

        // Phase 1b: Batch-delete field_versions in a single transaction
        if !deleted_tombstones.is_empty() {
            let storage_clone = storage.clone();
            let sid = sync_id.to_string();
            let count = deleted_tombstones.len();
            tokio::task::spawn_blocking(move || {
                let mut tx = storage_clone.begin_tx()?;
                for (tbl, eid) in &deleted_tombstones {
                    tx.delete_field_versions_for_entity(&sid, tbl, eid)?;
                }
                tx.commit()
            })
            .await
            .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
            result.field_versions_pruned = count;
        }

        // Phase 2: Prune old applied_ops (server_seq < min_acked_seq, up to max_rows).
        let remaining_budget = max_rows.saturating_sub(result.entities_hard_deleted);
        if remaining_budget > 0 {
            let storage_clone = storage.clone();
            let sid = sync_id.to_string();
            let pruned = tokio::task::spawn_blocking(move || {
                let mut tx = storage_clone.begin_tx()?;
                let pruned =
                    tx.delete_applied_ops_below_seq(&sid, min_acked_seq, remaining_budget)?;
                tx.commit()?;
                Ok::<_, crate::error::CoreError>(pruned)
            })
            .await
            .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
            result.applied_ops_pruned = pruned;
        }

        Ok(result)
    }
}
