# prism-sync

## Overview
Plug-and-play encrypted CRDT sync library in Rust with cross-platform FFI bindings. Provides field-level Last-Write-Wins CRDT synchronization with end-to-end encryption -- the relay server stores only encrypted blobs and never sees plaintext content.

## Tech Stack
- **Language:** Rust 2021 edition
- **Framework:** Axum (relay server), tokio (async runtime)
- **Database:** SQLite via rusqlite (bundled)
- **Crypto:** RustCrypto (chacha20poly1305, argon2, hkdf, ed25519-dalek, x25519-dalek), pqcrypto (ml-dsa-65, ml-kem-768)
- **FFI:** flutter_rust_bridge v2.12.0 for Dart/Flutter bindings
- **Dart:** Flutter packages for mobile integration

## Project Structure
```
prism-sync/
├── crates/
│   ├── prism-sync-crypto/     # Standalone crypto primitives (no sync awareness)
│   ├── prism-sync-core/       # CRDT engine, storage, relay client, consumer API
│   ├── prism-sync-ffi/        # FFI layer for Flutter/Dart
│   └── prism-sync-relay/      # V2 relay server (Axum + SQLite)
├── dart/packages/
│   ├── prism_sync/            # Generated Dart bindings
│   ├── prism_sync_drift/      # Drift database adapter
│   └── prism_sync_flutter/    # Flutter secure storage + Riverpod providers
├── Dockerfile                 # Multi-stage build for relay
├── docker-compose.yml         # Production deployment config
└── justfile                   # Task runner shortcuts
```

## Build Commands
```bash
cargo build --workspace                    # Build all crates
cargo test --workspace                     # Run all tests (~920)
cargo clippy --workspace --all-targets -- -D warnings  # Lint
cargo fmt --all                            # Format
just test                                  # Shorthand via justfile
just lint
```

## Crate Dependency Graph
```
prism-sync-crypto  (standalone, no sync awareness)
       |
       v
prism-sync-core    (depends on crypto)
       |
       v
prism-sync-ffi     (depends on core + crypto)

prism-sync-relay   (standalone, no dependency on other crates)
```

## Key Conventions
- All sensitive key material uses `Zeroizing<Vec<u8>>` (auto-zeroed on drop)
- Storage traits are object-safe (no generic methods on `SyncStorage`)
- `SyncStorageTx` for transactional writes, `SyncStorage` for reads + `begin_tx()`
- `BEGIN IMMEDIATE` / `COMMIT` / `ROLLBACK` for SQLite transactions
- All relay paths use `/v1/sync/{sync_id}/...`
- Batch signatures use hybrid Ed25519 + ML-DSA-65 over deterministic binary canonical format (protocol V3)
- Pull phase skips unverifiable batches (unknown/deleted sender, bad signature) instead of aborting
- SyncEngine uses `Arc<dyn SyncStorage>` and `Arc<dyn SyncRelay>` (trait objects, not generics)
- FFI functions use only primitive types (no trait objects across FFI boundary)
- All SyncStorage calls in the engine are wrapped in `tokio::task::spawn_blocking`
- Consumer API: `PrismSync::builder()` pattern with fluent configuration
- Merge algorithm: field-level LWW with 3-level tiebreaker (HLC -> device_id -> op_id)
- Device identity uses per-device CSPRNG, never derived from shared DEK

## Testing
- 920+ tests across 4 crates
- Cross-language crypto vectors verified against Dart/libsodium
- E2E relay tests start server in-process with in-memory SQLite
- Mock relay for engine tests without HTTP
- `cargo test -p prism-sync-crypto --test cross_language_vectors -- --ignored` for cross-language vectors

```bash
cargo test --workspace                          # Run everything
cargo test -p prism-sync-crypto                 # Crypto only
cargo test -p prism-sync-core                   # Core only
cargo test -p prism-sync-relay                  # Relay only
just test-crate prism-sync-core                 # Via justfile
```

## Dependency Watchlist
- **Supply-chain gate owner:** sync release owner. Keep `.github/workflows/sync-supply-chain.yml` blocking on `cargo audit -D warnings` and `cargo deny --locked check`.
- **SQLite lane owner:** sync storage owner. Track `rusqlite`, `rusqlite_migration`, and `libsqlite3-sys`; bundled SQLite must stay on a version with current security fixes, and SQLCipher builds must keep `bundled-sqlcipher-vendored-openssl` working.
- **OpenSSL lane owner:** sync release owner. Track `openssl-src` advisories/releases because the SQLCipher feature vendors OpenSSL.
- **RustCrypto PQ owner:** sync crypto owner. Track `RustCrypto/signatures` (`ml-dsa`), `RustCrypto/KEMs` (`ml-kem`), and `x-wing`; pre-1.0 PQ crates need explicit review before updates and cross-language/vector tests after updates.
- **Relay TLS/WebSocket owner:** relay owner. Track `rustls`, `ring`, `webpki-roots`, `tungstenite`, and `tokio-tungstenite`; keep relay/client WS tests and `cargo deny` duplicate-version warnings visible during upgrades.

## Side-Channel Residual Risk
- Apple M1/M2 GoFetch/DMP exposure remains a documented residual risk for userspace lattice math; there is no local code-only mitigation for those devices in the current threat model.
- Apple M3 and later DIT support is a tracked follow-up. Do not enable a DIT toggle without a measured platform check, failure behavior, and release note.
- Keep Ed25519 strict verification and hybrid-signature context/domain tests in the regression set; these are defense-in-depth against primitive or implementation regressions.

## Deployment
- Relay deploys via Docker (self-hosted)
- SQLite on LUKS-encrypted volume
- Cloudflare Tunnel for ingress (no exposed ports)

## FFI Codegen
After changing `crates/prism-sync-ffi/src/api.rs`:
```bash
flutter_rust_bridge_codegen generate
```
This regenerates `dart/packages/prism_sync/lib/generated/` -- never edit those files manually.
