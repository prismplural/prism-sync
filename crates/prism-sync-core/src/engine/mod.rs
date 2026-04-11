pub mod merge;
pub mod state;

pub use merge::{MergeEngine, WinningOp};
pub use state::{SyncConfig, SyncResult, SyncState};

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::watch;

use crate::batch_signature;
use crate::crdt_change::CrdtChange;
use crate::device_registry::DeviceRegistryManager;
use crate::error::{CoreError, Result};
use crate::events::EntityChange;
use crate::hlc::Hlc;
use crate::pruning::TombstonePruner;
use crate::relay::{OutgoingBatch, SyncRelay};
use crate::schema::{SyncSchema, SyncType};
use crate::storage::{AppliedOp, DeviceRecord, FieldVersion, SyncStorage};
use crate::sync_aad;
use crate::syncable_entity::SyncableEntity;

/// Key material resolved for a batch sender device.
pub struct SenderKeyInfo {
    /// Ed25519 public key (32 bytes).
    pub ed25519_pk: [u8; 32],
    /// ML-DSA-65 public key (may be empty for legacy devices).
    pub ml_dsa_65_pk: Vec<u8>,
    /// ML-DSA key generation (0 = initial, increases on rotation).
    pub ml_dsa_key_generation: u32,
}

/// Result of the pull phase, bundling counts with relay-reported metadata.
struct PullPhaseResult {
    pulled: u64,
    merged: u64,
    entity_changes: Vec<EntityChange>,
    max_server_seq: i64,
    min_acked_seq: Option<i64>,
}

/// The sync engine orchestrates the full pull -> merge -> push cycle.
///
/// It owns references to:
/// - `SyncStorage` -- local sync state (pending_ops, field_versions, etc.)
/// - `SyncRelay` -- transport to the relay server
/// - `SyncableEntity` implementations -- consumer data tables for merge writes
/// - `SyncSchema` -- registered entity tables and field types
///
/// All SyncStorage calls are wrapped in `tokio::task::spawn_blocking`
/// to avoid stalling the tokio reactor.
///
/// Uses trait objects (`dyn`) instead of generics so that Plan 4's public API
/// can store `Option<SyncEngine>` without propagating generic type parameters.
pub struct SyncEngine {
    storage: Arc<dyn SyncStorage>,
    relay: Arc<dyn SyncRelay>,
    entities: Vec<Arc<dyn SyncableEntity>>,
    schema: SyncSchema,
    config: SyncConfig,
    state_tx: watch::Sender<SyncState>,
    state_rx: watch::Receiver<SyncState>,
    merge_engine: MergeEngine,
}

impl SyncEngine {
    /// Create a new SyncEngine.
    pub fn new(
        storage: Arc<dyn SyncStorage>,
        relay: Arc<dyn SyncRelay>,
        entities: Vec<Arc<dyn SyncableEntity>>,
        schema: SyncSchema,
        config: SyncConfig,
    ) -> Self {
        let (state_tx, state_rx) = watch::channel(SyncState::Idle);
        let merge_engine = MergeEngine::new(schema.clone());
        Self {
            storage,
            relay,
            entities,
            schema,
            config,
            state_tx,
            state_rx,
            merge_engine,
        }
    }

    /// Get the current sync state.
    pub fn state(&self) -> SyncState {
        self.state_rx.borrow().clone()
    }

    /// Subscribe to state changes.
    pub fn watch_state(&self) -> watch::Receiver<SyncState> {
        self.state_rx.clone()
    }

    /// Borrow the relay trait object used for sync operations.
    ///
    /// Exposed so higher layers (PrismSync) can perform out-of-band relay
    /// work such as epoch-key catch-up recovery before a sync cycle runs.
    pub fn relay(&self) -> &Arc<dyn SyncRelay> {
        &self.relay
    }

    /// Execute a full sync cycle: pull -> merge -> push.
    ///
    /// `key_hierarchy` provides epoch keys by epoch number (not just "current epoch").
    /// This is critical because pulled batches may span multiple epochs during
    /// epoch rotation -- each batch is decrypted with its own epoch's key.
    pub async fn sync(
        &self,
        sync_id: &str,
        key_hierarchy: &prism_sync_crypto::KeyHierarchy,
        signing_key: &ed25519_dalek::SigningKey,
        ml_dsa_signing_key: Option<&prism_sync_crypto::DevicePqSigningKey>,
        device_id: &str,
        ml_dsa_key_generation: u32,
    ) -> Result<SyncResult> {
        let start = Instant::now();
        let mut result = SyncResult::default();

        // Phase 1: Pull
        self.set_state(SyncState::Pulling);
        let pull_result = self.pull_phase(sync_id, key_hierarchy, device_id).await;
        let min_acked_seq;
        match pull_result {
            Ok(pr) => {
                result.pulled = pr.pulled;
                result.merged = pr.merged;
                result.entity_changes = pr.entity_changes;
                min_acked_seq = pr.min_acked_seq;

                // Acknowledge processed ops so relay can prune its batches (fire-and-forget)
                if pr.max_server_seq > 0 {
                    let relay = self.relay.clone();
                    let seq = pr.max_server_seq;
                    tokio::spawn(async move {
                        if let Err(e) = relay.ack(seq).await {
                            tracing::warn!("ack failed (non-fatal): {e}");
                        }
                    });
                }
            }
            Err(e) => {
                result.error = Some(e.to_string());
                result.duration = start.elapsed();
                self.set_state(SyncState::Error {
                    message: e.to_string(),
                });
                return Ok(result);
            }
        }

        // Phase 1b: Prune acknowledged ops and tombstones
        if let Some(min_acked) = min_acked_seq {
            if min_acked > 0 {
                match TombstonePruner::prune(
                    self.storage.clone(),
                    &self.entities,
                    sync_id,
                    min_acked,
                    1000,
                )
                .await
                {
                    Ok(pr) => {
                        result.pruned = (pr.applied_ops_pruned
                            + pr.entities_hard_deleted
                            + pr.field_versions_pruned)
                            as u64;
                        if result.pruned > 0 {
                            tracing::info!(
                                applied_ops = pr.applied_ops_pruned,
                                tombstones = pr.entities_hard_deleted,
                                field_versions = pr.field_versions_pruned,
                                "pruned local ops"
                            );
                        }
                    }
                    Err(e) => tracing::warn!("prune failed (non-fatal): {e}"),
                }
            }
        }

        // Phase 2: Push
        self.set_state(SyncState::Pushing);
        let push_result = self
            .push_phase(sync_id, key_hierarchy, signing_key, ml_dsa_signing_key, device_id, ml_dsa_key_generation)
            .await;
        match push_result {
            Ok(pushed) => {
                result.pushed = pushed;
            }
            Err(e) => {
                result.error = Some(e.to_string());
                result.duration = start.elapsed();
                self.set_state(SyncState::Error {
                    message: e.to_string(),
                });
                return Ok(result);
            }
        }

        result.duration = start.elapsed();
        self.set_state(SyncState::Idle);

        // Update last successful sync timestamp
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        tokio::task::spawn_blocking(move || {
            let mut tx = storage.begin_tx()?;
            tx.update_last_successful_sync(&sid)?;
            tx.commit()
        })
        .await
        .map_err(|e| CoreError::Storage(e.to_string()))??;

        Ok(result)
    }

    fn set_state(&self, state: SyncState) {
        let _ = self.state_tx.send(state);
    }

    /// Pull phase: fetch batches, verify signature, decrypt, verify payload hash, merge.
    async fn pull_phase(
        &self,
        sync_id: &str,
        key_hierarchy: &prism_sync_crypto::KeyHierarchy,
        device_id: &str,
    ) -> Result<PullPhaseResult> {
        // Get last pulled seq from storage (spawn_blocking)
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let meta = tokio::task::spawn_blocking(move || storage.get_sync_metadata(&sid))
            .await
            .map_err(|e| CoreError::Storage(e.to_string()))??;

        let since_seq = meta.map(|m| m.last_pulled_server_seq).unwrap_or(0);

        // Pull from relay
        let pull_response = self
            .relay
            .pull_changes(since_seq)
            .await
            .map_err(CoreError::from_relay)?;

        let min_acked_seq = pull_response.min_acked_seq;
        let max_server_seq = pull_response.max_server_seq;

        if pull_response.batches.is_empty() {
            return Ok(PullPhaseResult {
                pulled: 0,
                merged: 0,
                entity_changes: Vec::new(),
                max_server_seq,
                min_acked_seq,
            });
        }

        let mut total_pulled = 0u64;
        let mut total_merged = 0u64;
        let mut all_entity_changes: Vec<EntityChange> = Vec::new();

        // Process each batch
        for batch in &pull_response.batches {
            let envelope = &batch.envelope;

            // Skip our own batches (still advance server_seq)
            if envelope.sender_device_id == device_id {
                let storage = self.storage.clone();
                let sid = sync_id.to_string();
                let seq = batch.server_seq;
                tokio::task::spawn_blocking(move || {
                    let mut tx = storage.begin_tx()?;
                    tx.update_last_pulled_seq(&sid, seq)?;
                    tx.commit()
                })
                .await
                .map_err(|e| CoreError::Storage(e.to_string()))??;
                total_pulled += 1;
                continue;
            }

            // STEP 1: Verify batch signature BEFORE decrypting.
            // Look up sender's hybrid (Ed25519 + ML-DSA-65) public key from device registry.
            // If the sender device was deregistered (hard-deleted from relay),
            // its public key is gone — skip the batch and advance server_seq.
            let sender_key_info = match self
                .resolve_sender_public_key(sync_id, &envelope.sender_device_id)
                .await
            {
                Ok(ki) => ki,
                Err(e) => {
                    tracing::warn!(
                        "Skipping batch from unresolvable sender {}: {e}",
                        envelope.sender_device_id
                    );
                    let storage = self.storage.clone();
                    let sid = sync_id.to_string();
                    let seq = batch.server_seq;
                    tokio::task::spawn_blocking(move || {
                        let mut tx = storage.begin_tx()?;
                        tx.update_last_pulled_seq(&sid, seq)?;
                        tx.commit()
                    })
                    .await
                    .map_err(|e| CoreError::Storage(e.to_string()))??;
                    total_pulled += 1;
                    continue;
                }
            };

            // If the sender's envelope declares a newer ML-DSA generation than
            // we have locally, try to refresh from the relay before verifying.
            let sender_key_info = if envelope.sender_ml_dsa_key_generation > sender_key_info.ml_dsa_key_generation {
                match self.resolve_sender_keys_with_generation_hint(
                    sync_id,
                    &envelope.sender_device_id,
                    Some(envelope.sender_ml_dsa_key_generation),
                ).await {
                    Ok(updated) => updated,
                    Err(_) => sender_key_info, // Fall back to what we have
                }
            } else {
                sender_key_info
            };

            if let Err(e) = batch_signature::verify_batch_signature(envelope, &sender_key_info.ed25519_pk, &sender_key_info.ml_dsa_65_pk) {
                tracing::warn!(
                    "Skipping batch {} with invalid signature from {}: {e}",
                    envelope.batch_id,
                    envelope.sender_device_id,
                );
                let storage = self.storage.clone();
                let sid = sync_id.to_string();
                let seq = batch.server_seq;
                tokio::task::spawn_blocking(move || {
                    let mut tx = storage.begin_tx()?;
                    tx.update_last_pulled_seq(&sid, seq)?;
                    tx.commit()
                })
                .await
                .map_err(|e| CoreError::Storage(e.to_string()))??;
                total_pulled += 1;
                continue;
            }

            // STEP 2: Decrypt batch using the epoch key from THIS batch's epoch
            // (not "current epoch" -- pulled batches may span multiple epochs)
            let epoch_key = key_hierarchy
                .epoch_key(envelope.epoch as u32)
                .map_err(|_| {
                    CoreError::Engine(format!(
                        "Missing epoch key for epoch {} -- may need epoch rotation recovery",
                        envelope.epoch
                    ))
                })?;
            let aad = sync_aad::build_sync_aad(
                sync_id,
                &envelope.sender_device_id,
                envelope.epoch,
                &envelope.batch_id,
                &envelope.batch_kind,
            );
            let plaintext = prism_sync_crypto::aead::xchacha_decrypt_from_sync(
                epoch_key,
                &envelope.ciphertext,
                &envelope.nonce,
                &aad,
            )
            .map_err(|e| CoreError::Engine(format!("Decrypt failed: {e}")))?;

            // STEP 3: Verify payload hash matches decrypted plaintext
            batch_signature::verify_payload_hash(envelope, &plaintext)?;

            // Decode ops
            let ops = CrdtChange::decode_batch(&plaintext)?;

            // Clock drift check
            for op in &ops {
                let hlc = Hlc::from_string(&op.client_hlc)?;
                if hlc.is_drift_exceeded(self.config.max_clock_drift_ms) {
                    let now_hlc = Hlc::now(device_id, None);
                    return Err(CoreError::ClockDrift {
                        drift_ms: hlc.timestamp - now_hlc.timestamp,
                        max_ms: self.config.max_clock_drift_ms,
                        device_id: op.device_id.clone(),
                    });
                }
            }

            // Merge phase
            self.set_state(SyncState::Merging);
            let (merged, batch_changes) = self
                .apply_remote_batch(sync_id, &ops, batch.server_seq)
                .await?;
            total_merged += merged;
            all_entity_changes.extend(batch_changes);
            total_pulled += 1;
        }

        Ok(PullPhaseResult {
            pulled: total_pulled,
            merged: total_merged,
            entity_changes: all_entity_changes,
            max_server_seq,
            min_acked_seq,
        })
    }

    /// Resolve a sender's key material from the local device registry,
    /// refreshing from the relay if the sender is unknown.
    async fn resolve_sender_public_key(
        &self,
        sync_id: &str,
        sender_device_id: &str,
    ) -> Result<SenderKeyInfo> {
        self.resolve_sender_keys_with_generation_hint(sync_id, sender_device_id, None)
            .await
    }

    /// Resolve sender keys, optionally checking for ML-DSA generation freshness.
    ///
    /// If `expected_generation` is `Some(n)` and the locally stored generation
    /// for this sender is less than `n`, triggers a signed registry fetch +
    /// import before returning, so that hybrid verification can proceed with
    /// the sender's current ML-DSA key.
    pub async fn resolve_sender_keys_with_generation_hint(
        &self,
        sync_id: &str,
        sender_device_id: &str,
        expected_generation: Option<u32>,
    ) -> Result<SenderKeyInfo> {
        // Stage 1: local lookup
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let sender_id = sender_device_id.to_string();
        let record =
            tokio::task::spawn_blocking(move || storage.get_device_record(&sid, &sender_id))
                .await
                .map_err(|e| CoreError::Storage(e.to_string()))??;

        if let Some(ref r) = record {
            if r.status == "active" {
                let info = pk_from_record(r)?;

                // Generation-freshness check: if the caller expects a newer
                // ML-DSA generation than we have locally, try a signed registry
                // fetch to update the key before returning.
                if let Some(expected) = expected_generation {
                    if expected > info.ml_dsa_key_generation {
                        tracing::info!(
                            sender = %sender_device_id,
                            local_gen = info.ml_dsa_key_generation,
                            expected_gen = expected,
                            "ML-DSA generation stale; fetching signed registry"
                        );
                        // Re-run Stage 2 (signed registry fetch) to try to get updated keys.
                        // If it succeeds and the generation is now sufficient, return the updated info.
                        if let Ok(updated) =
                            self.fetch_and_import_registry(sync_id, sender_device_id).await
                        {
                            if updated.ml_dsa_key_generation >= expected {
                                return Ok(updated);
                            }
                        }
                        // Re-read the device record after the refresh attempt — the import may
                        // have changed the device status (e.g., revoked it) even if the generation
                        // did not reach the expected level.  Returning stale `info` here would
                        // hand back an active key for a device that was just revoked.
                        let storage = self.storage.clone();
                        let sid = sync_id.to_string();
                        let sender_id = sender_device_id.to_string();
                        let refreshed_record = tokio::task::spawn_blocking(move || {
                            storage.get_device_record(&sid, &sender_id)
                        })
                        .await
                        .map_err(|e| CoreError::Storage(e.to_string()))??;

                        return match refreshed_record {
                            Some(ref r) if r.status == "active" => pk_from_record(r),
                            Some(ref r) => {
                                tracing::warn!(
                                    "Device {} was revoked during registry refresh",
                                    sender_device_id
                                );
                                Err(CoreError::Storage(format!(
                                    "Device {} was revoked during registry refresh (status: {})",
                                    sender_device_id, r.status
                                )))
                            }
                            None => {
                                // Device was removed during refresh; fall through to the
                                // unknown-sender stages below by returning an error here so
                                // the caller can skip or reject the batch.
                                Err(CoreError::Storage(format!(
                                    "Device {} disappeared during registry refresh",
                                    sender_device_id
                                )))
                            }
                        };
                    }
                }

                return Ok(info);
            }
            tracing::warn!("Skipping batch from revoked device {}", sender_device_id);
            return Err(CoreError::Storage(format!(
                "Device {} is revoked",
                sender_device_id
            )));
        }

        // Unknown sender -- attempt signed registry; fail closed if unavailable
        tracing::info!(
            "Unknown sender device {}, attempting signed registry fetch",
            sender_device_id
        );

        // Stage 2: Try to fetch and verify a signed registry artifact
        match self.fetch_and_import_registry(sync_id, sender_device_id).await {
            Ok(info) => return Ok(info),
            Err(e) => {
                tracing::warn!(
                    "Signed registry fetch/import failed for sender {}: {e}",
                    sender_device_id
                );
            }
        }

        // Stage 3: Fail closed — no unverified fallback.
        // If signed registry is unavailable, the batch from this unknown
        // sender will be skipped. Legitimate devices become known through
        // pairing (import_keyring) or signed registry artifacts.
        tracing::warn!(
            "No verified registry path for unknown sender {}; skipping batch (fail closed)",
            sender_device_id
        );
        Err(CoreError::Storage(format!(
            "Unknown device {} and no verified registry available (fail closed)",
            sender_device_id
        )))
    }

    /// Fetch signed registry, verify, import, and re-lookup a specific device.
    ///
    /// Returns the resolved `SenderKeyInfo` for `device_id` after importing the
    /// signed registry artifact. Errors if the registry fetch fails, verification
    /// fails, or the device is still not found (or not active) after import.
    async fn fetch_and_import_registry(
        &self,
        sync_id: &str,
        device_id: &str,
    ) -> Result<SenderKeyInfo> {
        match self.relay.get_signed_registry().await {
            Ok(Some(response)) => {
                // Read the last imported version for monotonicity check
                let storage = self.storage.clone();
                let sid = sync_id.to_string();
                let last_version = tokio::task::spawn_blocking(move || {
                    storage.get_sync_metadata(&sid)
                })
                .await
                .map_err(|e| CoreError::Storage(e.to_string()))?
                .ok()
                .flatten()
                .and_then(|m| m.last_imported_registry_version);

                let storage = self.storage.clone();
                let sid = sync_id.to_string();
                let blob = response.artifact_blob.clone();

                let import_result = tokio::task::spawn_blocking(move || {
                    DeviceRegistryManager::verify_and_import_signed_registry(
                        &*storage, &sid, &blob, last_version,
                    )
                })
                .await
                .map_err(|e| CoreError::Storage(e.to_string()))?;

                match import_result {
                    Ok(signed_version) => {
                        tracing::info!(
                            "Imported verified registry v{signed_version} for device {}",
                            device_id
                        );
                        // Store the signed (verified) version — not the relay response version
                        let storage = self.storage.clone();
                        let sid = sync_id.to_string();
                        let _ = tokio::task::spawn_blocking(move || {
                            let mut tx = storage.begin_tx()?;
                            tx.update_last_imported_registry_version(&sid, signed_version)?;
                            tx.commit()
                        })
                        .await
                        .map_err(|e| CoreError::Storage(e.to_string()))?;

                        // Retry local lookup after verified import
                        let storage = self.storage.clone();
                        let sid = sync_id.to_string();
                        let dev_id = device_id.to_string();
                        let record = tokio::task::spawn_blocking(move || {
                            storage.get_device_record(&sid, &dev_id)
                        })
                        .await
                        .map_err(|e| CoreError::Storage(e.to_string()))??;

                        if let Some(ref r) = record {
                            if r.status == "active" {
                                return pk_from_record(r);
                            }
                        }
                        // Device still not found after verified import
                        Err(CoreError::Storage(format!(
                            "Device {} not found in signed registry",
                            device_id
                        )))
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Signed registry verification failed for device {}: {e}",
                            device_id
                        );
                        Err(CoreError::Storage(format!(
                            "Signed registry verification failed: {e}"
                        )))
                    }
                }
            }
            Ok(None) => {
                tracing::debug!(
                    "No signed registry artifact available for device {}",
                    device_id
                );
                Err(CoreError::Storage(
                    "No signed registry artifact available".to_string(),
                ))
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to fetch signed registry for device {}: {e}",
                    device_id
                );
                Err(CoreError::from_relay(e))
            }
        }
    }

    /// Apply a single remote batch: determine winners, write consumer data, then persist sync state.
    ///
    /// Returns `(merged_count, entity_changes)` where `entity_changes` contains the
    /// winning field values grouped by entity for consumer DB application.
    ///
    /// **CRITICAL ORDERING:** Consumer entity writes happen BEFORE sync bookkeeping commits.
    /// This ensures that if entity writes fail, sync state is not advanced -- the batch
    /// will be re-pulled and re-applied on next sync (idempotent via applied_ops check).
    /// If sync bookkeeping fails after entity writes succeed, replay is safe because
    /// the merge is idempotent and write_fields uses upsert semantics.
    async fn apply_remote_batch(
        &self,
        sync_id: &str,
        ops: &[CrdtChange],
        server_seq: i64,
    ) -> Result<(u64, Vec<EntityChange>)> {
        // Phase A: Determine winners (READ-ONLY -- no sync state persisted yet)
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let ops_vec = ops.to_vec();
        let schema = self.schema.clone();
        let merge_engine = self.merge_engine.clone();

        let (all_ops_checked, winning_ops) = tokio::task::spawn_blocking(move || {
            // Track which ops were already applied (for Phase C bookkeeping)
            let mut checked: Vec<(CrdtChange, bool)> = Vec::new();

            // Use non-transactional reads for winner determination
            let get_fv = |sync_id: &str, table: &str, entity_id: &str, field: &str| {
                storage.get_field_version(sync_id, table, entity_id, field)
            };
            let is_applied = |op_id: &str| storage.is_op_applied(op_id);

            // Determine winners via MergeEngine
            let winners = merge_engine.determine_winners(&ops_vec, &get_fv, &is_applied, &sid)?;

            // Build the checked ops list for bookkeeping
            for op in &ops_vec {
                if !schema.has_table(&op.entity_table) {
                    continue;
                }
                if op.field_name != "is_deleted"
                    && !op.is_bulk_reset()
                    && schema
                        .entity(&op.entity_table)
                        .and_then(|e| e.field_by_name(&op.field_name))
                        .is_none()
                {
                    continue;
                }
                let already_applied = is_applied(&op.op_id)?;
                checked.push((op.clone(), already_applied));
            }

            // Collect winning ops as a Vec
            let winning_ops: Vec<CrdtChange> = winners
                .into_values()
                .filter(|w| !w.is_bulk_reset)
                .map(|w| w.op)
                .collect();

            Ok::<_, CoreError>((checked, winning_ops))
        })
        .await
        .map_err(|e| CoreError::Storage(e.to_string()))??;

        let merged_count = winning_ops.len() as u64;

        // Build EntityChange list from winning ops, grouped by (table, entity_id).
        let entity_changes = {
            let mut change_map: HashMap<(String, String), EntityChange> = HashMap::new();
            for op in &winning_ops {
                let key = (op.entity_table.clone(), op.entity_id.clone());
                let entry = change_map.entry(key).or_insert_with(|| EntityChange {
                    table: op.entity_table.clone(),
                    entity_id: op.entity_id.clone(),
                    is_delete: false,
                    fields: HashMap::new(),
                });
                if op.is_delete {
                    entry.is_delete = true;
                    entry.fields.clear();
                } else {
                    entry
                        .fields
                        .insert(op.field_name.clone(), op.encoded_value.clone());
                }
            }
            change_map.into_values().collect::<Vec<_>>()
        };

        // Phase B: Write winning changes to consumer entity tables
        if !winning_ops.is_empty() {
            let mut tables_touched: HashSet<String> = HashSet::new();
            for op in &winning_ops {
                tables_touched.insert(op.entity_table.clone());
            }

            // Begin batch on all touched entities
            for entity in &self.entities {
                if tables_touched.contains(entity.table_name()) {
                    entity.begin_batch().await?;
                }
            }

            // Write fields / soft-delete for each winning op
            let write_result: Result<()> = async {
                for op in &winning_ops {
                    if let Some(entity) = self
                        .entities
                        .iter()
                        .find(|e| e.table_name() == op.entity_table)
                    {
                        if op.is_delete {
                            entity.soft_delete(&op.entity_id, &op.client_hlc).await?;
                        } else {
                            let sync_type = self
                                .schema
                                .entity(&op.entity_table)
                                .and_then(|e| e.field_by_name(&op.field_name))
                                .map(|f| f.sync_type)
                                .unwrap_or(SyncType::String);
                            let decoded =
                                match crate::schema::decode_value(&op.encoded_value, sync_type) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        tracing::warn!(
                                            table = %op.entity_table,
                                            entity_id = %op.entity_id,
                                            field = %op.field_name,
                                            encoded_value = %op.encoded_value,
                                            "Skipping field op with type mismatch: {e}. \
                                             Dart-side quarantine will record the bad value."
                                        );
                                        continue;
                                    }
                                };
                            let mut fields = HashMap::new();
                            fields.insert(op.field_name.clone(), decoded);
                            entity
                                .write_fields(
                                    &op.entity_id,
                                    &fields,
                                    &op.client_hlc,
                                    false, // is_new determined by consumer's upsert
                                )
                                .await?;
                        }
                    }
                }
                Ok(())
            }
            .await;

            match write_result {
                Ok(()) => {
                    for entity in &self.entities {
                        if tables_touched.contains(entity.table_name()) {
                            entity.commit_batch().await?;
                        }
                    }
                }
                Err(e) => {
                    for entity in &self.entities {
                        if tables_touched.contains(entity.table_name()) {
                            let _ = entity.rollback_batch().await;
                        }
                    }
                    // Entity writes failed -- do NOT persist sync state.
                    return Err(e);
                }
            }
        }

        // Phase C: ONLY AFTER entity writes succeed, persist sync bookkeeping.
        {
            let storage = self.storage.clone();
            let sid = sync_id.to_string();
            let ops_checked = all_ops_checked;
            let winners = winning_ops;
            tokio::task::spawn_blocking(move || {
                let mut tx = storage.begin_tx()?;

                // Record all valid ops as applied (for idempotency on replay)
                for (op, was_already_applied) in &ops_checked {
                    if !was_already_applied {
                        tx.insert_applied_op(&AppliedOp {
                            op_id: op.op_id.clone(),
                            sync_id: sid.clone(),
                            epoch: op.epoch,
                            device_id: op.device_id.clone(),
                            client_hlc: op.client_hlc.clone(),
                            server_seq,
                            applied_at: chrono::Utc::now(),
                        })?;
                    }
                }

                // Update field_versions for winning ops only
                for op in &winners {
                    tx.upsert_field_version(&FieldVersion {
                        sync_id: sid.clone(),
                        entity_table: op.entity_table.clone(),
                        entity_id: op.entity_id.clone(),
                        field_name: op.field_name.clone(),
                        winning_op_id: op.op_id.clone(),
                        winning_device_id: op.device_id.clone(),
                        winning_hlc: op.client_hlc.clone(),
                        winning_encoded_value: Some(op.encoded_value.clone()),
                        updated_at: chrono::Utc::now(),
                    })?;
                }

                // Advance server_seq
                tx.update_last_pulled_seq(&sid, server_seq)?;
                tx.commit()
            })
            .await
            .map_err(|e| CoreError::Storage(e.to_string()))??;
        }

        Ok((merged_count, entity_changes))
    }

    /// Push phase: encrypt and push dirty local batches.
    ///
    /// **Idempotency note:** If `mark_batch_pushed` fails after the relay
    /// accepts the push, the batch will be re-pushed on the next sync cycle.
    /// The relay MUST support idempotent push by deduplicating on `batch_id`
    /// (sent via X-Batch-Id header). If the relay does not deduplicate,
    /// the merge engine handles duplicate batches gracefully via the
    /// `applied_ops` idempotency table.
    async fn push_phase(
        &self,
        sync_id: &str,
        key_hierarchy: &prism_sync_crypto::KeyHierarchy,
        signing_key: &ed25519_dalek::SigningKey,
        ml_dsa_signing_key: Option<&prism_sync_crypto::DevicePqSigningKey>,
        device_id: &str,
        ml_dsa_key_generation: u32,
    ) -> Result<u64> {
        // Get dirty batch IDs
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let batch_ids = tokio::task::spawn_blocking(move || storage.get_unpushed_batch_ids(&sid))
            .await
            .map_err(|e| CoreError::Storage(e.to_string()))??;

        if batch_ids.is_empty() {
            return Ok(0);
        }

        let mut pushed_count = 0u64;

        for batch_id in &batch_ids {
            // Load batch ops
            let storage = self.storage.clone();
            let bid = batch_id.clone();
            let ops = tokio::task::spawn_blocking(move || storage.load_batch_ops(&bid))
                .await
                .map_err(|e| CoreError::Storage(e.to_string()))??;

            if ops.is_empty() {
                continue;
            }

            let epoch = ops[0].epoch;

            // Convert PendingOps to CrdtChanges for encoding
            let changes: Vec<CrdtChange> = ops
                .iter()
                .map(|op| CrdtChange {
                    op_id: op.op_id.clone(),
                    batch_id: Some(op.local_batch_id.clone()),
                    entity_id: op.entity_id.clone(),
                    entity_table: op.entity_table.clone(),
                    field_name: op.field_name.clone(),
                    encoded_value: op.encoded_value.clone(),
                    client_hlc: op.client_hlc.clone(),
                    is_delete: op.is_delete,
                    device_id: op.device_id.clone(),
                    epoch: op.epoch,
                    server_seq: None,
                })
                .collect();

            // Encode to JSON bytes
            let plaintext = CrdtChange::encode_batch(&changes)?;

            // Compute payload hash
            let payload_hash = batch_signature::compute_payload_hash(&plaintext);

            // Get epoch key for encryption
            let epoch_key = key_hierarchy.epoch_key(epoch as u32).map_err(|_| {
                CoreError::Engine(format!("Missing epoch key for push epoch {epoch}"))
            })?;

            // Build AAD and encrypt
            let aad = sync_aad::build_sync_aad(sync_id, device_id, epoch, batch_id, "ops");
            let (ciphertext, nonce) =
                prism_sync_crypto::aead::xchacha_encrypt_for_sync(epoch_key, &plaintext, &aad)
                    .map_err(|e| CoreError::Engine(format!("Encrypt failed: {e}")))?;

            // Sign the batch
            let ml_dsa_sk = ml_dsa_signing_key
                .ok_or_else(|| CoreError::Engine("ML-DSA signing key required for hybrid batch signing".into()))?;
            let envelope = batch_signature::sign_batch(
                signing_key,
                ml_dsa_sk,
                sync_id,
                epoch,
                batch_id,
                "ops",
                device_id,
                ml_dsa_key_generation,
                &payload_hash,
                nonce,
                ciphertext,
            )?;

            // Push to relay
            let outgoing = OutgoingBatch {
                batch_id: batch_id.clone(),
                envelope,
            };
            self.relay
                .push_changes(outgoing)
                .await
                .map_err(CoreError::from_relay)?;

            // Mark batch as pushed
            let storage = self.storage.clone();
            let bid = batch_id.clone();
            let sid = sync_id.to_string();
            tokio::task::spawn_blocking(move || {
                let mut tx = storage.begin_tx()?;
                tx.mark_batch_pushed(&bid)?;
                tx.delete_pushed_ops(&sid)?;
                tx.commit()?;
                Ok::<_, CoreError>(())
            })
            .await
            .map_err(|e| CoreError::Storage(e.to_string()))??;

            pushed_count += 1;
        }

        Ok(pushed_count)
    }

    // ── Snapshot operations ──

    /// Create and upload an encrypted snapshot for device pairing.
    ///
    /// The existing device calls this after generating an invite. The snapshot
    /// is encrypted with the current epoch key and uploaded with a TTL.
    #[allow(clippy::too_many_arguments)]
    pub async fn upload_pairing_snapshot(
        &self,
        sync_id: &str,
        key_hierarchy: &prism_sync_crypto::KeyHierarchy,
        epoch: i32,
        device_id: &str,
        signing_key: &ed25519_dalek::SigningKey,
        ml_dsa_signing_key: &prism_sync_crypto::DevicePqSigningKey,
        ml_dsa_key_generation: u32,
        ttl_secs: Option<u64>,
        for_device_id: Option<String>,
    ) -> Result<()> {
        // 1. Export snapshot from storage (already zstd-compressed)
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let snapshot_data = tokio::task::spawn_blocking(move || storage.export_snapshot(&sid))
            .await
            .map_err(|e| CoreError::Storage(e.to_string()))??;

        // 2. Get last pulled seq as the snapshot point
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let server_seq = tokio::task::spawn_blocking(move || {
            let meta = storage.get_sync_metadata(&sid)?;
            Ok::<_, CoreError>(meta.map(|m| m.last_pulled_server_seq).unwrap_or(0))
        })
        .await
        .map_err(|e| CoreError::Storage(e.to_string()))??;

        // 3. Encrypt with epoch key + snapshot AAD (binds metadata to ciphertext)
        let epoch_key = key_hierarchy
            .epoch_key(epoch as u32)
            .map_err(|e| CoreError::Engine(format!("no epoch key: {e}")))?;
        let aad = crate::sync_aad::build_snapshot_aad(sync_id, device_id, epoch, server_seq);
        let (ciphertext, nonce) =
            prism_sync_crypto::aead::xchacha_encrypt_for_sync(epoch_key, &snapshot_data, &aad)
                .map_err(|e| CoreError::Engine(format!("snapshot encrypt failed: {e}")))?;

        // 4. Compute payload hash and sign the snapshot as a batch envelope
        let payload_hash = crate::batch_signature::compute_payload_hash(&snapshot_data);
        let batch_id = format!("snapshot-{}", chrono::Utc::now().timestamp_millis());
        let envelope = crate::batch_signature::sign_batch(
            signing_key,
            ml_dsa_signing_key,
            sync_id,
            epoch,
            &batch_id,
            "snapshot",
            device_id,
            ml_dsa_key_generation,
            &payload_hash,
            nonce,
            ciphertext,
        )?;

        // 5. Serialize the envelope to JSON bytes and upload
        let envelope_bytes =
            serde_json::to_vec(&envelope).map_err(|e| CoreError::Serialization(e.to_string()))?;
        self.relay
            .put_snapshot(
                epoch,
                server_seq,
                envelope_bytes,
                ttl_secs,
                for_device_id,
                device_id.to_string(),
            )
            .await
            .map_err(CoreError::from_relay)?;

        Ok(())
    }

    /// Download and apply a snapshot for initial device bootstrap.
    ///
    /// Returns the number of entities restored and the entity changes for the
    /// caller to emit as `RemoteChanges` so Dart can populate its local
    /// database via the drift sync adapter.
    ///
    /// Returns `(0, [])` if no snapshot is available on the relay.
    pub async fn bootstrap_from_snapshot(
        &self,
        sync_id: &str,
        key_hierarchy: &prism_sync_crypto::KeyHierarchy,
    ) -> Result<(u64, Vec<EntityChange>)> {
        // 1. Download snapshot from relay
        let snapshot = self
            .relay
            .get_snapshot()
            .await
            .map_err(CoreError::from_relay)?;

        let snapshot = match snapshot {
            Some(s) => s,
            None => return Ok((0, Vec::new())),
        };

        // 2. Deserialize the signed envelope and verify signature
        let envelope: crate::relay::traits::SignedBatchEnvelope =
            serde_json::from_slice(&snapshot.data).map_err(|e| {
                CoreError::Serialization(format!("snapshot envelope deserialization failed: {e}"))
            })?;

        // Look up the sender's key material and verify the batch signature
        let sender_key_info = self
            .resolve_sender_public_key(sync_id, &envelope.sender_device_id)
            .await?;

        // If the sender's envelope declares a newer ML-DSA generation than
        // we have locally, try to refresh from the relay before verifying.
        let sender_key_info = if envelope.sender_ml_dsa_key_generation > sender_key_info.ml_dsa_key_generation {
            match self.resolve_sender_keys_with_generation_hint(
                sync_id,
                &envelope.sender_device_id,
                Some(envelope.sender_ml_dsa_key_generation),
            ).await {
                Ok(updated) => updated,
                Err(_) => sender_key_info, // Fall back to what we have
            }
        } else {
            sender_key_info
        };

        crate::batch_signature::verify_batch_signature(&envelope, &sender_key_info.ed25519_pk, &sender_key_info.ml_dsa_65_pk)?;

        // Verify relay-reported metadata matches the signed envelope
        if snapshot.epoch != envelope.epoch {
            return Err(CoreError::Engine(format!(
                "snapshot epoch mismatch: relay reported {} but sender signed {}",
                snapshot.epoch, envelope.epoch,
            )));
        }

        // 3. Decrypt with epoch key + snapshot AAD
        let epoch_key = key_hierarchy
            .epoch_key(snapshot.epoch as u32)
            .map_err(|e| CoreError::Engine(format!("no epoch key for snapshot: {e}")))?;
        let aad = crate::sync_aad::build_snapshot_aad(
            sync_id,
            &envelope.sender_device_id,
            snapshot.epoch,
            snapshot.server_seq_at,
        );
        let compressed = prism_sync_crypto::aead::xchacha_decrypt_from_sync(
            epoch_key,
            &envelope.ciphertext,
            &envelope.nonce,
            &aad,
        )
        .map_err(|e| CoreError::Engine(format!("snapshot decrypt failed: {e}")))?;
        crate::batch_signature::verify_payload_hash(&envelope, &compressed)?;

        // 3. Import into storage (within transaction)
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let seq = snapshot.server_seq_at;
        let data = compressed.clone();
        let count = tokio::task::spawn_blocking(move || {
            let mut tx = storage.begin_tx()?;
            let count = tx.import_snapshot(&sid, &data)?;
            tx.update_last_pulled_seq(&sid, seq)?;
            tx.commit()?;
            Ok::<_, CoreError>(count)
        })
        .await
        .map_err(|e| CoreError::Storage(e.to_string()))??;

        // 4. Build EntityChange list from the snapshot data so the caller
        //    can emit RemoteChanges to Dart for consumer DB population.
        let entity_changes = Self::build_entity_changes_from_snapshot(&compressed)?;

        Ok((count, entity_changes))
    }

    /// Parse a decompressed snapshot blob and build `EntityChange` entries
    /// grouped by `(table, entity_id)`, collecting all winning field values.
    ///
    /// This is used after bootstrap to tell the consumer which entities and
    /// fields need to be written into the consumer database.
    fn build_entity_changes_from_snapshot(compressed: &[u8]) -> Result<Vec<EntityChange>> {
        // Decompress zstd
        let json = zstd::decode_all(std::io::Cursor::new(compressed))
            .map_err(|e| CoreError::Storage(format!("zstd decompress failed: {e}")))?;

        // Parse snapshot data
        let snapshot: crate::storage::SnapshotData = serde_json::from_slice(&json)?;

        // Group field_versions by (table, entity_id) into EntityChange structs
        let mut change_map: HashMap<(String, String), EntityChange> = HashMap::new();
        for fv in &snapshot.field_versions {
            let key = (fv.entity_table.clone(), fv.entity_id.clone());
            let entry = change_map.entry(key).or_insert_with(|| EntityChange {
                table: fv.entity_table.clone(),
                entity_id: fv.entity_id.clone(),
                is_delete: false,
                fields: HashMap::new(),
            });

            // Check for soft-delete tombstone
            if fv.field_name == "is_deleted" {
                if let Some(ref val) = fv.winning_encoded_value {
                    if val == "true" {
                        entry.is_delete = true;
                        entry.fields.clear();
                        continue;
                    }
                }
            }

            // Skip adding fields if this entity is already marked as deleted
            if entry.is_delete {
                continue;
            }

            if let Some(ref val) = fv.winning_encoded_value {
                entry.fields.insert(fv.field_name.clone(), val.clone());
            }
        }

        Ok(change_map.into_values().collect())
    }
}

/// Extract sender key material from a DeviceRecord.
fn pk_from_record(record: &DeviceRecord) -> Result<SenderKeyInfo> {
    let ed25519_pk: [u8; 32] = record
        .ed25519_public_key
        .clone()
        .try_into()
        .map_err(|_| CoreError::Storage("invalid ed25519 key length".into()))?;
    Ok(SenderKeyInfo {
        ed25519_pk,
        ml_dsa_65_pk: record.ml_dsa_65_public_key.clone(),
        ml_dsa_key_generation: record.ml_dsa_key_generation,
    })
}
