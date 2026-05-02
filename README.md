# prism-sync

End-to-end encrypted CRDT sync, in Rust. Add private, multi-device sync to
any app — field-level conflict resolution, hybrid post-quantum crypto, and a
relay server that only ever sees ciphertext.

Used by [Prism](https://github.com/prismplural/prism-app), and designed to be
embeddable in other apps via a schema-driven API.

## Highlights

- **Field-level CRDTs** — Last-Write-Wins with Hybrid Logical Clocks, not row-level overwrites
- **Ciphertext-only relay** — the server sees encrypted blobs, device IDs, and timing; never content
- **Post-quantum from day one** — hybrid Ed25519 + ML-DSA-65 batch signatures, X-Wing (X25519 + ML-KEM-768) for epoch rekey
- **Schema-driven** — declare your entities and fields; the engine handles merge, versioning, and tombstones
- **Defense in depth** — padded ciphertext to mask op-batch size, schema-unknown ops quarantined instead of merged, AAD-bound key wrapping, redacted FFI errors, supply-chain CI gate
- **Flutter integration** — Dart bindings, a Drift adapter, and Riverpod providers in `dart/packages/`

## How it works

```
Password + 12-word mnemonic → Argon2id → MEK → wraps DEK
  DEK → HKDF → epoch sync keys (XChaCha20-Poly1305)
  DEK → HKDF → database encryption key
  DeviceSecret (per-device CSPRNG, never derived from DEK)
    → HKDF → Ed25519 + X25519 + ML-DSA-65 + ML-KEM-768 + X-Wing keypairs

Sync cycle: pull → verify hybrid signature → decrypt → merge → ack → prune → push
```

Each device gets its own cryptographic identity from a local secret — not
from the shared DEK — so revoking one device can't compromise the others.
Pairing is a relay-mediated ceremony with SAS verification. When a device is
revoked, an epoch rotation uses X-Wing hybrid KEM to deliver fresh keys to
the surviving devices.

Password changes re-wrap the DEK. No data re-encryption needed.

> Prism, the consumer, treats the "password" slot as a 6-digit PIN. The
> library itself accepts any byte string, so apps with different unlock UX
> can use it directly.

## Architecture

```
crates/
├── prism-sync-crypto/     # Standalone crypto primitives (no sync awareness)
├── prism-sync-core/       # CRDT engine, storage, relay client, pairing
├── prism-sync-ffi/        # FFI layer for Flutter/Dart
└── prism-sync-relay/      # Self-hosted relay server (Axum + SQLite)

dart/packages/
├── prism_sync/            # Generated Dart bindings
├── prism_sync_drift/      # Drift database adapter
└── prism_sync_flutter/    # Flutter secure storage + Riverpod providers
```

`prism-sync-crypto` is standalone with no sync awareness. `prism-sync-core`
builds on it for the CRDT engine and sync protocol. `prism-sync-relay` is
independently deployable with no dependency on the other crates.

## Quick start

```rust
use prism_sync_core::{PrismSync, SyncSchema, SyncType};
use prism_sync_core::storage::RusqliteSyncStorage;
use std::sync::Arc;

// Declare your schema
let schema = SyncSchema::builder()
    .entity("tasks", |e| {
        e.field("title", SyncType::String)
         .field("done", SyncType::Bool)
         .field("priority", SyncType::Real)
    })
    .build();

// Build the sync client
let storage = Arc::new(RusqliteSyncStorage::in_memory()?);
let mut client = PrismSync::builder()
    .schema(schema)
    .storage(storage)
    .secure_store(my_secure_store)
    .relay_url("https://relay.example.com")
    .build()?;

// Initialize with credentials (password is a byte string from your unlock UX)
client.initialize("123456", &secret_key_bytes)?;

// Record mutations — these become CRDT ops in pending_ops
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

Or via the [`justfile`](./justfile): `just test`, `just lint`.

## Testing

920+ tests across the four crates:

- **Crypto** — AEAD roundtrip, KDF determinism, key hierarchy, device identity, cross-language vectors
- **CRDT** — HLC merge, LWW tiebreakers, tombstone protection, schema validation
- **Storage** — transactions, CRUD, migrations, pruning
- **Sync engine** — push/pull roundtrip, conflict resolution, signature verification, payload tampering, schema-unknown quarantine
- **Pairing** — create/join ceremony, tampered invitation rejection, wrong-PIN handling, MITM harnesses
- **Epoch rotation** — revoke → rekey → unwrap → encrypt/decrypt full cycle
- **Relay** — authentication, quota enforcement, WebSocket notifications, malformed-attestation rejection

```bash
cargo test --workspace                    # everything
cargo test -p prism-sync-crypto           # crypto only
cargo test -p prism-sync-core             # engine + CRDT
cargo test -p prism-sync-relay            # relay server
```

Cross-language crypto vectors against Dart/libsodium run with
`cargo test -p prism-sync-crypto --test cross_language_vectors -- --ignored`.

## Security

| Layer | Primitive |
|-------|-----------|
| Encryption | XChaCha20-Poly1305 (24-byte random nonces) |
| Op-batch padding | Fixed-bucket size padding to mask plaintext length |
| Key derivation | Argon2id (64 MiB, 3 iterations) + HKDF-SHA256 |
| Signatures | Hybrid Ed25519 + ML-DSA-65 batch signatures, registered context strings |
| Post-quantum KEM | X-Wing (X25519 + ML-KEM-768) for epoch rekey |
| Device identity | Per-device CSPRNG keys (5 keypairs), never derived from shared secrets |
| Key wrapping | AAD-bound, versioned (`sync_id ǀ device_id ǀ v`) |
| Transport | HTTPS/WSS required (enforced at builder and relay constructor) |
| Memory | All key material in `Zeroizing<Vec<u8>>` — auto-zeroed on drop |
| Supply chain | `cargo audit -D warnings` and `cargo deny --locked check` gate every change |

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design and threat model,
and [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## Self-hosting a relay

See [`self-host/SELF-HOSTING.md`](self-host/SELF-HOSTING.md) for Docker
Compose and Kubernetes deployment guides. The relay stores only encrypted
blobs, so running your own gives you full control over your data without
requiring any cryptographic trust in the operator.

## Contributing

Contributions are welcome. Please open an issue first to discuss what you'd
like to change. PRs that change crypto, FFI, or the relay protocol need
cross-language vectors and a clippy-clean build. All contributions require
a signed Contributor License Agreement — see [CLA.md](CLA.md).

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE).
