# prism-sync

End-to-end encrypted CRDT sync library in Rust. Add private, multi-device sync to any app
with field-level conflict resolution and zero-knowledge encryption — the relay server stores
only encrypted blobs and never sees plaintext.

Used by [Prism](https://github.com/prismplural/prism-app) and designed to be embeddable in
other apps via a schema-driven API.

## Highlights

- **Field-level CRDTs** — Last-Write-Wins with Hybrid Logical Clocks, not row-level overwrites
- **Zero-knowledge relay** — the server sees encrypted blobs, device IDs, and timing; never content
- **Post-quantum ready** — hybrid Ed25519 + ML-DSA-65 signatures, X-Wing (X25519 + ML-KEM-768) epoch rekey
- **Schema-driven** — define your entities and fields; the engine handles merge, versioning, and tombstones
- **Flutter integration** — Dart bindings, Drift adapter, and Riverpod providers included

## How It Works

```
Password + BIP39 mnemonic → Argon2id → MEK → wraps DEK
  DEK → HKDF → epoch sync keys (XChaCha20-Poly1305)
  DEK → HKDF → database encryption key
  DeviceSecret (per-device CSPRNG) → HKDF → Ed25519 + X25519 + ML-DSA-65 + ML-KEM-768 + X-Wing

Sync cycle: pull → verify signature → decrypt → merge → ack → prune → push
```

Each device has its own cryptographic identity derived from a local secret. Devices pair via
a relay-mediated ceremony with SAS verification. When a device is revoked, epoch rotation
uses X-Wing hybrid KEM to distribute fresh keys to surviving devices.

Password changes re-wrap the DEK — no data re-encryption needed.

## Architecture

```
crates/
├── prism-sync-crypto/     # Standalone crypto primitives
├── prism-sync-core/       # CRDT engine, storage, relay client, pairing
├── prism-sync-ffi/        # FFI layer for Flutter/Dart
└── prism-sync-relay/      # Self-hosted relay server (Axum + SQLite)

dart/packages/
├── prism_sync/            # Generated Dart bindings
├── prism_sync_drift/      # Drift database adapter
└── prism_sync_flutter/    # Flutter secure storage + Riverpod providers
```

`prism-sync-crypto` is standalone with no sync awareness. `prism-sync-core` builds on it
for the CRDT engine and sync protocol. `prism-sync-relay` is independently deployable with
no dependency on the other crates.

## Quick Start

```rust
use prism_sync_core::{PrismSync, SyncSchema, SyncType};
use prism_sync_core::storage::RusqliteSyncStorage;
use std::sync::Arc;

// Define your schema
let schema = SyncSchema::builder()
    .entity("tasks", |e| {
        e.field("title", SyncType::String)
         .field("done", SyncType::Bool)
    })
    .build();

// Build the sync client
let storage = Arc::new(RusqliteSyncStorage::in_memory()?);
let client = PrismSync::builder()
    .schema(schema)
    .storage(storage)
    .secure_store(my_secure_store)
    .relay_url("https://relay.example.com")
    .build()?;

// Initialize with credentials
client.initialize("my_password", &secret_key_bytes)?;

// Record mutations — these become CRDT ops
client.record_create("tasks", &task_id, &fields)?;

// Sync with the relay
let result = client.sync().await?;
```

## Building

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Testing

920+ tests across all crates:

- Crypto: AEAD roundtrip, KDF determinism, key hierarchy, device identity, cross-language vectors
- CRDT: HLC merge, LWW tiebreakers, tombstone protection, schema validation
- Storage: transactions, CRUD, migration, pruning
- Sync engine: push/pull roundtrip, conflict resolution, signature verification, payload tampering
- Pairing: create/join ceremony, tampered invitation rejection, wrong-password handling
- Epoch rotation: revoke → rekey → unwrap → encrypt/decrypt full cycle
- Relay: authentication, quota enforcement, WebSocket notifications

```bash
cargo test --workspace                    # Everything
cargo test -p prism-sync-crypto           # Crypto only
cargo test -p prism-sync-core             # Engine + CRDT
cargo test -p prism-sync-relay            # Relay server
```

## Security

| Layer | Primitive |
|-------|-----------|
| Encryption | XChaCha20-Poly1305 (24-byte random nonces) |
| Key derivation | Argon2id (64 MiB, 3 iterations) + HKDF-SHA256 |
| Signatures | Hybrid Ed25519 + ML-DSA-65 batch signatures |
| Post-quantum KEM | X-Wing (X25519 + ML-KEM-768) for epoch rekey |
| Device identity | Per-device CSPRNG keys (5 keypairs), never derived from shared secrets |
| Transport | HTTPS/WSS required (enforced at builder and relay constructor) |
| Memory | All key material in `Zeroizing<Vec<u8>>` — auto-zeroed on drop |

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design and threat model,
and [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## Self-hosting a relay

See [`self-host/SELF-HOSTING.md`](self-host/SELF-HOSTING.md) for Docker Compose
and Kubernetes deployment guides. The relay stores only encrypted blobs, so
running your own gives you full control over your data without requiring any
cryptographic trust in the operator.

## Contributing

Contributions are welcome. Please open an issue first to discuss what you'd like to change.

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE).
