# prism-sync-core

The sync engine and everything it needs: CRDT primitives, storage, relay client, pairing, epoch rotation, and the consumer-facing `PrismSync` API.

## Module Map

| Module | Purpose |
|--------|---------|
| `client` | `PrismSync` builder pattern, consumer-facing API |
| `engine` | `SyncEngine` orchestrates pull -> merge -> push cycle |
| `engine::merge` | `MergeEngine` field-level LWW with 3-level tiebreaker |
| `engine::state` | `SyncConfig`, `SyncResult`, `SyncState` |
| `hlc` | Hybrid Logical Clock: merge, comparison, drift detection |
| `crdt_change` | `CrdtChange` struct -- one field-level mutation op |
| `schema` | `SyncSchema` builder, `SyncType`, `SyncValue`, field definitions |
| `storage` | `SyncStorage` + `SyncStorageTx` traits, `RusqliteSyncStorage` |
| `op_emitter` | `OpEmitter` generates pending ops from consumer mutations |
| `relay` | `SyncRelay` trait, `ServerRelay` (HTTP+WS), `MockRelay` |
| `pairing` | `PairingService`: create/join sync groups, SAS verification |
| `epoch` | `EpochManager`: X-Wing hybrid key rotation (X25519 + ML-KEM-768) after device revocation |
| `device_registry` | `DeviceRegistryManager`: track devices and public keys |
| `sync_service` | `SyncService`: auto-sync debounce, lifecycle hooks |
| `events` | `SyncEvent` enum, broadcast channel, `ChangeSet` |
| `runtime` | `background_runtime()` for spawning the tokio runtime |
| `runtime_keys` | Persist/restore key material across app restarts |
| `batch_signature` | Hybrid Ed25519 + ML-DSA-65 sign/verify over deterministic binary canonical format (protocol V3) |
| `sync_aad` | Build AAD strings for AEAD encryption |
| `syncable_entity` | `SyncableEntity` trait for consumer data table writes |
| `secure_store` | `SecureStore` trait for platform Keychain/Keystore |
| `pruning` | `TombstonePruner` for cleaning up old applied ops and tombstones |
| `debug_log` | `SyncDebugLog` for structured debug logging |
| `node_id` | Generate 12-character hex node identifiers |
| `error` | `CoreError`, `RelayErrorCategory`, `Result` |

## Consumer API

`PrismSync` is the single entry point for consumers. It wraps key lifecycle, sync orchestration, and event streaming behind a cohesive builder API.

```rust
use prism_sync_core::{PrismSync, SyncSchema, SyncType, SyncValue};
use prism_sync_core::storage::RusqliteSyncStorage;
use std::collections::HashMap;
use std::sync::Arc;

// 1. Define schema
let schema = SyncSchema::builder()
    .entity("tasks", |e| {
        e.field("title", SyncType::String)
         .field("done", SyncType::Bool)
         .field("priority", SyncType::Int)
    })
    .build();

// 2. Build PrismSync
let storage = Arc::new(RusqliteSyncStorage::in_memory()?);
let sync = PrismSync::builder()
    .schema(schema)
    .storage(storage)
    .secure_store(my_secure_store)
    .relay_url("https://relay.example.com")
    .build()?;

// 3. Key lifecycle
sync.initialize("password", &secret_key_bytes)?;  // First time
// or: sync.unlock("password", &secret_key_bytes)?;  // Subsequent

// 4. Configure sync engine
sync.configure_engine(relay, sync_id, node_id, epoch);

// 5. Record mutations
let mut fields = HashMap::new();
fields.insert("title".into(), SyncValue::String("Buy milk".into()));
fields.insert("done".into(), SyncValue::Bool(false));
sync.record_create("tasks", "task-1", &fields)?;

// 6. Sync
let result = sync.sync_now().await?;
println!("Pulled {}, merged {}, pushed {}", result.pulled, result.merged, result.pushed);

// 7. Listen for events
let mut rx = sync.events();
while let Ok(event) = rx.recv().await {
    match event {
        SyncEvent::RemoteChanges(cs) => { /* update UI */ }
        SyncEvent::Error(err) => { /* handle error */ }
        _ => {}
    }
}
```

### KeyMode

`PrismSync` supports three key management modes:

| Mode | Description |
|------|-------------|
| `KeyMode::Managed` | Default. Keys managed by PrismSync (password + BIP39 secret key). |
| `KeyMode::ExternalMaster` | Master key material provided by the parent app. |
| `KeyMode::ExternalKeys` | Individual encryption keys provided directly. |

## Storage Design

### Traits

- **`SyncStorage`** (top-level, object-safe): Read-only queries + `begin_tx()`. All methods are synchronous -- the engine wraps calls in `tokio::task::spawn_blocking`.
- **`SyncStorageTx`** (transaction handle): Mutating operations within a transaction. Obtained via `begin_tx()`, committed with `commit()`, auto-rolls-back on drop.

This two-trait design solves the Rust object-safety constraint: `SyncStorage` has no generic methods, so `Arc<dyn SyncStorage>` works. Transactional writes go through `SyncStorageTx`.

### Transaction pattern

```rust
let mut tx = storage.begin_tx()?;          // BEGIN IMMEDIATE
tx.upsert_field_version(sync_id, &fv)?;   // writes
tx.insert_applied_op(&applied)?;           // more writes
tx.commit()?;                              // COMMIT
// If commit() is not called, Drop impl runs ROLLBACK
```

### RusqliteSyncStorage

The built-in SQLite implementation uses:
- WAL mode for concurrent reads
- `BEGIN IMMEDIATE` to prevent writer starvation
- Bundled SQLite (no system dependency)
- Schema migrations via `rusqlite_migration`
- In-memory mode for testing: `RusqliteSyncStorage::in_memory()`

### Key tables

| Table | Purpose |
|-------|---------|
| `sync_metadata` | Per-sync-group state (last pulled seq, last push seq, timestamps) |
| `pending_ops` | Locally emitted ops waiting to be pushed |
| `applied_ops` | Remote ops that have been merged (idempotency tracking) |
| `field_versions` | Current winning value per (table, entity_id, field) |
| `device_records` | Known devices with public keys |

## Sync Engine

`SyncEngine` orchestrates the full sync cycle using trait objects:

```rust
pub struct SyncEngine {
    storage: Arc<dyn SyncStorage>,
    relay: Arc<dyn SyncRelay>,
    entities: Vec<Arc<dyn SyncableEntity>>,
    schema: SyncSchema,
    ...
}
```

### Pull phase
1. Read `last_pulled_server_seq` from storage
2. `relay.pull_changes(since_seq)` -- paginated batch fetch
3. For each batch:
   - Skip own batches (advance seq only)
   - Verify hybrid signature (Ed25519 + ML-DSA-65, before decryption)
   - Decrypt with epoch key from the batch's epoch
   - Verify SHA-256 payload hash
   - Decode `CrdtChange` ops
   - Clock drift check
   - `MergeEngine::determine_winners()` -- field-level LWW
   - In a transaction: write winning values to entity tables, update `field_versions`, insert `applied_ops`, advance `last_pulled_server_seq`

### Push phase
1. Load unpushed `batch_ids` from `pending_ops`
2. For each batch:
   - Load ops, encode to JSON
   - Encrypt with current epoch key + AAD
   - Sign with hybrid Ed25519 + ML-DSA-65 keys
   - `relay.push_changes(envelope)`
   - On success: delete pending ops, advance seq

### State machine
```
Idle -> Pulling -> Pushing -> Idle
                          \-> Error { message }
```
Observable via `SyncEngine::watch_state()` (tokio `watch` channel).

## Merge Algorithm

`MergeEngine` implements per-field Last-Write-Wins:

1. **Schema validation:** Skip unknown tables/fields (log warning).
2. **Idempotency:** Skip already-applied ops (checked via `applied_ops`).
3. **Tombstone protection:** If entity has `is_deleted = "true"`, reject non-delete ops.
4. **3-level tiebreaker:** HLC > device_id > op_id (all lexicographic).
5. **In-batch winner tracking:** Handles multiple ops on the same field within one batch.

The merge engine is pure -- it only determines winners. The caller (`SyncEngine`) writes results to storage within a transaction.

## Auto-Sync Debounce

`SyncService` provides automatic sync with configurable debounce:

```rust
let config = AutoSyncConfig {
    enabled: true,
    debounce: Duration::from_millis(500),
    retry_delay: Duration::from_millis(2000),
    max_retries: 3,
    enable_pruning: false,
};
sync.set_auto_sync(config);
```

After a mutation, the service waits for `debounce` duration of quiet time before triggering a push. Failed syncs are retried with `retry_delay` up to `max_retries` times.

## Pairing

`PairingService` handles multi-device setup:

### Create sync group (first device)
1. Generate sync_id, node_id, device secret
2. Initialize key hierarchy (password + generated BIP39 secret key)
3. Register with relay via hybrid challenge-response
4. Persist the first-device pairing response and local credentials

### Join sync group (additional devices)
1. Start a relay-backed rendezvous ceremony
2. Exchange bootstrap material through the pairing mailbox
3. Verify pairing via SAS (Short Authentication String)
4. Receive signed registry material plus DEK/epoch keys

## Epoch Rotation

When a device is revoked, `EpochManager` handles key rotation:

1. Owner generates new epoch key
2. Wraps epoch key for each remaining device using X-Wing hybrid key exchange (X25519 + ML-KEM-768)
3. Posts wrapped artifacts to relay via `POST /v2/sync/{sync_id}/rekey`
4. Each device fetches and unwraps its artifact
5. Future batches use the new epoch key
6. Old epoch keys are retained for decrypting historical batches

## Events

```rust
pub enum SyncEvent {
    SyncStarted,
    SyncCompleted(SyncResult),
    SnapshotProgress { received: u64, total: u64 },
    Error(SyncError),
    RemoteChanges(ChangeSet),
    DeviceJoined(DeviceInfo),
    DeviceRevoked(String),
    EpochRotated(i32),
}
```

Subscribe via `sync.events()` which returns a `broadcast::Receiver<SyncEvent>`.
