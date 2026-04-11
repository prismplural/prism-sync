# prism-sync

End-to-end encrypted CRDT sync library built in Rust. Add private, multi-device sync to any app with minimal integration effort.

## What it does

prism-sync provides field-level CRDT synchronization with zero-knowledge encryption. The relay server stores only encrypted blobs — it cannot read your data. Device identity, key management, pairing, epoch rotation, and conflict resolution are all handled by the library.

**Privacy model:** Field-level data is encrypted with XChaCha20-Poly1305. The relay server sees sync group membership, device identifiers, epoch numbers, batch sizes, and timing patterns, but never plaintext content.

## Architecture

```
prism-sync/
├── crates/
│   ├── prism-sync-crypto/     # Standalone crypto primitives (no sync awareness)
│   ├── prism-sync-core/       # CRDT engine, storage, relay client, pairing, consumer API
│   └── prism-sync-ffi/        # FFI layer for Flutter/Dart via flutter_rust_bridge
└── dart/
    └── packages/
        ├── prism_sync/            # Dart bindings
        ├── prism_sync_drift/      # Drift database adapter
        └── prism_sync_flutter/    # Flutter secure storage + Riverpod providers
```

### prism-sync-crypto

Standalone cryptographic primitives with no sync awareness:

- **AEAD:** XChaCha20-Poly1305 (sync data) + XSalsa20-Poly1305 (DEK wrapping)
- **KDF:** Argon2id (password → MEK) + HKDF-SHA256 (subkey derivation)
- **Key hierarchy:** Password + BIP39 secret key → MEK → wraps DEK → derives epoch keys, database key, group invite secret
- **Device identity:** Per-device Ed25519 (signing) + X25519 (key exchange) + ML-DSA-65 (PQ signing) + ML-KEM-768 (PQ key exchange) + X-Wing (hybrid rekey) from local CSPRNG — not derived from shared secrets
- **BIP39:** 12-word mnemonic generation, validation, byte conversion
- All sensitive buffers use `Zeroizing<Vec<u8>>` for automatic cleanup on drop

### prism-sync-core

The sync engine and everything it needs:

- **HLC:** Hybrid Logical Clock with merge, comparison, and drift detection
- **CRDT:** Field-level Last-Write-Wins with 3-level tiebreaker (HLC → device_id → op_id), tombstone protection, bulk reset
- **Storage:** Object-safe `SyncStorage` + `SyncStorageTx` traits with `BEGIN IMMEDIATE` / `COMMIT` / `ROLLBACK` transaction pattern. Ships with `RusqliteSyncStorage` (SQLite with WAL).
- **Sync engine:** Pull → verify signature → decrypt → verify payload hash → merge → ack → prune → push. Ack reports processed seq to relay (fire-and-forget). Prune cleans up acknowledged `applied_ops`, `field_versions`, and tombstoned entities.
- **Batch signatures:** Hybrid Ed25519 + ML-DSA-65 over deterministic binary canonical format (protocol V3). Verified before decryption.
- **Relay client:** HTTP (reqwest) + WebSocket (tokio-tungstenite) with `/v2/` protocol, per-device session tokens, message-based WebSocket auth, auto-reconnect with exponential backoff.
- **Pairing:** Hybrid-signed invitations (Ed25519 + ML-DSA-65), hybrid challenge-response relay registration, SAS verification protocol, signed keyring exchange.
- **Epoch rotation:** X-Wing hybrid key exchange (X25519 + ML-KEM-768) for epoch key wrapping/unwrapping after device revocation.
- **Consumer API:** `PrismSync::builder()` with fluent configuration, `record_create/update/delete` for mutations, `events()` stream, auto-sync debounce.

## Quick start

```rust
use prism_sync_core::{PrismSync, SyncSchema, SyncType};
use prism_sync_core::storage::RusqliteSyncStorage;
use std::sync::Arc;

// 1. Define your schema
let schema = SyncSchema::builder()
    .entity("tasks", |e| {
        e.field("title", SyncType::String)
         .field("done", SyncType::Bool)
    })
    .build();

// 2. Build the sync client
let storage = Arc::new(RusqliteSyncStorage::in_memory()?);
let client = PrismSync::builder()
    .schema(schema)
    .storage(storage)
    .secure_store(my_secure_store)
    .relay_url("https://relay.example.com")
    .build()?;

// 3. Initialize with password + secret key
client.initialize("my_password", &secret_key_bytes)?;

// 4. Record mutations
client.record_create("tasks", &task_id, &fields)?;

// 5. Sync
let result = client.sync().await?;
```

## Building

```bash
# Install Rust (if needed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build all crates
cargo build --workspace

# Run all tests
cargo test --workspace

# Lint
cargo clippy --workspace --all-targets -- -D warnings
```

## Testing

920+ tests across 4 crates covering:

- Crypto primitives (AEAD roundtrip, KDF determinism, key hierarchy lifecycle, device identity)
- CRDT correctness (HLC merge, LWW comparison, tombstone protection, schema validation)
- Storage (transaction commit/rollback, CRUD operations, migration, pruning)
- Sync engine (push/pull roundtrip, conflict resolution, signature verification, payload hash tampering)
- Pairing (create/join, signed invitations, tampered invite rejection, wrong password)
- Epoch rotation (full cycle: revoke → rekey → unwrap → encrypt/decrypt)
- Consumer API (builder validation, HTTPS enforcement, mutation recording)

```bash
# Run everything
cargo test --workspace

# Run specific crate
cargo test -p prism-sync-crypto
cargo test -p prism-sync-core

# Run cross-language vectors (requires Dart reference values)
cargo test -p prism-sync-crypto --test cross_language_vectors -- --ignored
```

## Security

- **Encryption:** XChaCha20-Poly1305 with 24-byte random nonces (AEAD)
- **Key derivation:** Argon2id (64 MiB, 3 iterations) + HKDF-SHA256
- **Signatures:** Hybrid Ed25519 + ML-DSA-65 batch signatures with deterministic binary canonical format (protocol V3)
- **Post-quantum:** Hybrid device identity (Ed25519 + ML-DSA-65 + X25519 + ML-KEM-768), X-Wing hybrid rekey, signed registry trust model
- **Device identity:** Per-device CSPRNG keys, never derived from shared DEK
- **Transport:** HTTPS/WSS required (enforced at both builder and relay constructor)
- **Memory:** All key material in `Zeroizing<Vec<u8>>` — auto-zeroed on drop
- **Transactions:** `BEGIN IMMEDIATE` / `COMMIT` / `ROLLBACK` with auto-rollback on drop

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design and threat model.

## License

MIT
