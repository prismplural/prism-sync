# Architecture

## Crate Dependency Graph

```
prism-sync-crypto          prism-sync-relay
(standalone primitives)    (standalone server)
        |
        v
prism-sync-core
(engine, storage, relay client, pairing, consumer API)
        |
        v
prism-sync-ffi
(flutter_rust_bridge bindings for Dart/Flutter)
        |
        v
dart/packages/prism_sync           (generated Dart API)
dart/packages/prism_sync_drift     (Drift database adapter)
dart/packages/prism_sync_flutter   (Flutter secure storage + Riverpod)
```

- **prism-sync-crypto** has zero sync awareness. It provides AEAD, KDF, key hierarchy, device identity, and BIP39 mnemonics as pure cryptographic building blocks.
- **prism-sync-core** depends on crypto and contains everything needed for sync: HLC, CRDT merge, schema, storage, engine, relay client, pairing, and the consumer `PrismSync` API.
- **prism-sync-ffi** depends on core and crypto, exposing a flat function API for flutter_rust_bridge codegen.
- **prism-sync-relay** is fully standalone -- it stores encrypted blobs and has no dependency on the other crates.

## Data Flow

```
App mutation
    |
    v
PrismSync.record_create/update/delete()
    |
    v
OpEmitter  ──>  pending_ops table (SyncStorage)
    |                    |
    |                    v
    |            SyncEngine.push_phase()
    |                    |
    |              encrypt (XChaCha20-Poly1305 with epoch key)
    |              sign (hybrid Ed25519 + ML-DSA-65, protocol V3)
    |                    |
    |                    v
    |              Relay server (stores encrypted blob)
    |                    |
    |              WebSocket notification to other devices
    |                    |
    v                    v
Other device:    SyncEngine.pull_phase()
                         |
                   verify hybrid signature (Ed25519 + ML-DSA-65)
                   decrypt (XChaCha20-Poly1305)
                   verify payload hash (SHA-256)
                   decode CrdtChange ops
                         |
                         v
                   MergeEngine.determine_winners()
                   (field-level LWW, tombstone protection)
                         |
                         v
                   SyncableEntity writes (consumer data tables)
                   field_versions + applied_ops bookkeeping
```

## Key Hierarchy

```
PIN (6-digit in Prism app; arbitrary string at library level) + SecretKey (BIP39 12-word mnemonic, 128-bit entropy)
    |
    v
Argon2id (64 MiB, 3 iterations, parallelism=1)
    |
    v
MEK (Master Encryption Key, 32 bytes)
    |
    |── XSalsa20-Poly1305 wraps/unwraps ──> DEK (Data Encryption Key, 32 bytes, random)
                                                |
                                                |── HKDF("epoch_sync\0", salt=epoch.to_be_bytes())
                                                |       └── Epoch 0 sync key (for XChaCha20-Poly1305 payload encryption)
                                                |
                                                |── HKDF(IKM=DEK, salt=DeviceSecret, info="prism_local_storage_v2")
                                                |       └── Local storage key (SQLite DB encryption; device-specific)
                                                |
                                                |── HKDF("prism_group_invite")
                                                        └── Group invitation secret (reserved)

DeviceSecret (32 bytes, per-device CSPRNG -- NOT derived from DEK)
    |
    |── HKDF("prism_device_ed25519", salt=device_id)
    |       └── Ed25519 signing keypair (batch signatures, registration, SAS)
    |
    |── HKDF("prism_device_x25519", salt=device_id)
    |       └── X25519 key exchange keypair (pairing, epoch key wrapping)
    |
    |── HKDF("prism_device_ml_dsa_65", salt=device_id)
    |       └── ML-DSA-65 PQ signing keypair (generation-versioned: _v{N} suffix for N>0)
    |
    |── HKDF("prism_device_ml_kem_768", salt=device_id)
    |       └── ML-KEM-768 PQ key exchange
    |
    |── HKDF("prism_device_xwing_rekey", salt=device_id)
            └── X-Wing hybrid KEM for epoch rekey (X25519 + ML-KEM-768)
```

Key design decisions:
- **Password change = re-wrap only.** The DEK never changes, so no data re-encryption is needed. Only the MEK-wrapped DEK envelope is regenerated.
- **Device identity is independent of shared secrets.** Per-device CSPRNG prevents key compromise on one device from exposing another device's signing/exchange keys.
- **Epoch keys enable forward secrecy after revocation.** When a device is revoked, a new epoch key is generated via X-Wing hybrid key exchange (X25519 + ML-KEM-768) and distributed to remaining devices.

## CRDT Merge Algorithm

The merge engine implements field-level Last-Write-Wins (LWW) with deterministic conflict resolution.

### Per-field merge for each incoming op:

1. **Schema validation:** Skip ops for unknown tables or unknown fields (with warning log). `is_deleted` and `_bulk_reset` are always allowed.

2. **Idempotency:** Skip ops whose `op_id` already exists in `applied_ops`.

3. **Tombstone protection:** If the entity has a winning `is_deleted = "true"` in `field_versions`, reject all non-delete ops to prevent resurrection.

4. **Three-level tiebreaker** (when comparing against current field winner):
   - **HLC comparison:** Higher HLC wins (timestamp:counter:nodeId)
   - **device_id:** Lexicographic comparison as tiebreaker
   - **op_id:** Final tiebreaker for determinism

5. **In-batch tracking:** Multiple ops on the same field within a single batch are resolved using batch-local winner tracking, so later ops in the batch correctly compare against earlier batch-local winners rather than only the persisted field_versions.

6. **Output:** Map of `op_id -> WinningOp`. The caller (SyncEngine) writes winning values to consumer entity tables and updates `field_versions` + `applied_ops` within a single transaction.

## Security Model

### What is encrypted (zero-knowledge)
- All field-level data content (XChaCha20-Poly1305 with epoch key)
- Each batch has its own random 24-byte nonce
- AAD binds ciphertext to: sync_id, sender_device_id, epoch, batch_id, batch_kind

### What the relay server sees (metadata)
- Sync group membership (which device IDs belong to a group)
- Device public keys (Ed25519, X25519, ML-DSA-65, ML-KEM-768, X-Wing)
- Epoch numbers and batch sequence numbers
- Batch sizes and timing patterns
- Session tokens (per-device, issued via challenge-response)

### Integrity guarantees
- **Hybrid batch signatures:** Every pushed batch is signed with hybrid Ed25519 + ML-DSA-65 (protocol V3). Both signatures must verify. Verified BEFORE decryption on pull.
- **SHA-256 payload hash:** The plaintext content is hashed and included in the signed envelope. Verified AFTER decryption to detect payload tampering.
- **Hybrid challenge-response registration:** Devices prove possession of Ed25519 and ML-DSA-65 private keys during relay registration.

## Sync Cycle

A full sync cycle (`SyncEngine::sync`) executes two phases:

### Phase 1: Pull
```
1. Read last_pulled_server_seq from SyncMetadata
2. relay.pull_changes(since_seq) -> batches
3. For each batch:
   a. Skip own batches (still advance server_seq)
   b. Look up sender's Ed25519 and ML-DSA-65 public keys from device registry
   c. Verify hybrid signature (Ed25519 + ML-DSA-65, before decryption)
   d. Decrypt with epoch key from THIS batch's epoch (not "current epoch")
   e. Verify payload hash (SHA-256 of plaintext == envelope.payload_hash)
   f. Decode CrdtChange ops from JSON
   g. Check clock drift
   h. MergeEngine.determine_winners() -> winning ops
   i. Within a transaction:
      - Write winning values to consumer entity tables (SyncableEntity)
      - Update field_versions for each winner
      - Insert applied_ops for all processed ops
      - Update last_pulled_server_seq
   j. Commit transaction
```

### Phase 2: Push
```
1. Load unpushed batch_ids from pending_ops
2. For each batch:
   a. Load ops for this batch
   b. Encode ops to JSON
   c. Encrypt with current epoch key (XChaCha20-Poly1305 + AAD)
   d. Compute SHA-256 payload hash of plaintext
   e. Build SignedBatchEnvelope with hybrid signatures (Ed25519 + ML-DSA-65)
   f. relay.push_changes(envelope)
   g. On success: delete pending_ops for this batch in a transaction
   h. Update last_pushed_server_seq
```

### Phase 1b: Ack + Prune
```
1. Fire-and-forget: relay.ack(max_server_seq) via tokio::spawn
   - Tells the relay this device has processed up to this seq
   - Relay records receipt in device_receipts table
   - Relay computes min_acked_seq across all active devices
   - Relay prunes batches below the safe prune threshold
2. If min_acked_seq > 0 (returned in pull response):
   a. TombstonePruner::prune() — async, bounded to 1000 rows/pass
   b. Phase 1: Hard-delete tombstoned entities from consumer storage
   c. Phase 1b: Batch-delete field_versions in a single transaction
   d. Phase 2: Delete applied_ops with server_seq < min_acked_seq
   e. Report pruned count in SyncResult
```

### Post-sync
- Update `last_successful_sync_at` timestamp in SyncMetadata

## FFI Boundary Design

The FFI layer (`prism-sync-ffi`) bridges Rust to Dart/Flutter via `flutter_rust_bridge` v2.

### Design constraints
- **No trait objects across FFI.** Dart cannot hold `dyn SyncRelay` or `dyn SecureStore`. The FFI layer wraps these internally.
- **Primitive types only.** All FFI function parameters and return types are primitives (String, Vec<u8>, bool, u64) or opaque handles.
- **JSON for complex data.** Schema definitions, field values, sync results, and events are serialized as JSON strings across the boundary.

### Opaque handle pattern
```rust
pub struct PrismSyncHandle {
    inner: Arc<tokio::sync::Mutex<PrismSync>>,
    relay_url: String,
    allow_insecure: bool,
}
```
- `PrismSyncHandle` is an opaque type that Dart holds as `RustOpaqueInterface`.
- `tokio::sync::Mutex` (not `std::sync::Mutex`) allows async methods to hold the lock across `.await` points.
- `relay_url` and `allow_insecure` are stored on the handle so `ServerRelay` instances can be constructed on the Rust side when needed (e.g., for pairing, device management).
- Compile-time assertions verify `Send + Sync`.

### Relay construction
Instead of passing relay trait objects from Dart, the FFI layer constructs `ServerRelay` instances internally from primitive parameters:
```rust
fn build_relay(relay_url, sync_id, device_id, session_token, allow_insecure) -> Arc<ServerRelay>
```
This keeps the FFI surface clean while allowing full relay functionality.

### MemorySecureStore
A `MemorySecureStore` (HashMap-backed `SecureStore`) is provided for testing. In production, the real `SecureStore` is provided by `prism_sync_flutter` which bridges to platform Keychain/Keystore.
