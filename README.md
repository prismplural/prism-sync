# prism-sync

Hi. This is the sync engine behind [Prism](https://github.com/prismplural/prism-app)
— a plural system management app built by a plural system that uses it every day.
We pulled the sync layer out of the app repo so it can be audited and embedded
on its own.

It's a Rust CRDT library with end-to-end encryption, a `flutter_rust_bridge`
FFI surface, Dart packages for Flutter integration, and a self-hostable relay
server. The relay only ever sees encrypted blobs.

If you're here to deploy a relay rather than work on the code, the
[self-hosting guide](self-host/SELF-HOSTING.md) is what you want.
[ARCHITECTURE.md](ARCHITECTURE.md) covers the protocol and threat model.

## What's in here

Rust 2021 (MSRV 1.75), tokio, Axum for the relay, `rusqlite` (bundled SQLite),
RustCrypto for symmetric crypto and signatures, `ml-dsa` / `ml-kem` / `x-wing`
for the post-quantum layer, and `flutter_rust_bridge` 2.12.0 for the FFI.

```
crates/
├── prism-sync-crypto/   # Standalone crypto primitives — no sync awareness
├── prism-sync-core/     # CRDT engine, HLC, storage, pairing, relay client
├── prism-sync-ffi/      # flutter_rust_bridge surface — Dart/Flutter bindings
├── prism-sync-relay/    # Self-hostable relay (Axum + SQLite + WebSockets)
└── prism-sync-bench/    # Criterion benchmarks

dart/packages/
├── prism_sync/          # Generated Dart bindings (never edit by hand)
├── prism_sync_drift/    # Drift database adapter
└── prism_sync_flutter/  # Flutter secure storage + Riverpod providers

self-host/               # Dockerfile, compose, Kubernetes manifests, runbook
docs/                    # Protocol specs
```

Dependency-wise: `prism-sync-crypto` is pure cryptography with no sync state
and is safe to use on its own. `prism-sync-core` builds on it and owns
everything sync-related — HLC, CRDT merge, schema, storage traits, engine,
relay client, pairing, and the consumer `PrismSync` builder. `prism-sync-ffi`
sits on top with a flat, primitive-typed function API that
`flutter_rust_bridge` codegen consumes. `prism-sync-relay` is fully
standalone — it stores opaque encrypted blobs and depends on none of the
other crates.

## Build and test

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

A `justfile` wraps these (`just build`, `just test`, `just test-crate <name>`,
`just lint`, `just fmt`).

Per-crate testing:

```bash
cargo test -p prism-sync-crypto
cargo test -p prism-sync-core
cargo test -p prism-sync-relay
cargo test -p prism-sync-crypto --test cross_language_vectors -- --ignored
```

The cross-language vector tests verify crypto outputs byte-for-byte against
the Dart/libsodium side. Run them whenever you touch the crypto crate or the
FFI boundary.

## FFI codegen

After changing the public FFI API in `crates/prism-sync-ffi/src/api.rs`:

```bash
flutter_rust_bridge_codegen generate
```

That regenerates `dart/packages/prism_sync/lib/generated/`. **Never edit those
files by hand** — they'll be clobbered on the next codegen run.

## Dart packages

The `dart/packages/` workspace is managed via Melos.

```bash
cd dart
dart pub global activate melos
melos bootstrap
melos run test
```

Consumers can either depend on these packages via git or point at a local
checkout via `pubspec_overrides.yaml`. The prism-app README has the override
pattern.

## Using it from Rust

A minimal embed looks like this:

```rust
use prism_sync_core::{PrismSync, SyncSchema, SyncType};
use prism_sync_core::storage::RusqliteSyncStorage;
use std::sync::Arc;

let schema = SyncSchema::builder()
    .entity("tasks", |e| {
        e.field("title", SyncType::String)
         .field("done", SyncType::Bool)
    })
    .build();

let storage = Arc::new(RusqliteSyncStorage::in_memory()?);
let client = PrismSync::builder()
    .schema(schema)
    .storage(storage)
    .secure_store(my_secure_store)
    .relay_url("https://relay.example.com")
    .build()?;

client.initialize("my_password", &secret_key_bytes)?;
client.record_create("tasks", &task_id, &fields)?;
let _result = client.sync().await?;
```

## Contributing

We're glad you're here. Bug reports, protocol questions, performance work, and
patches are all welcome.

Please open an issue before starting on anything larger than a bug fix or a
doc PR. Crypto, CRDT, and pairing changes especially benefit from up-front
discussion — they're easy to get subtly wrong, and once a protocol version
ships we have to keep parsing it forever. We'd rather talk through the design
before you spend time on code.

A few things worth knowing before sending a patch:

- All key material lives in `Zeroizing<Vec<u8>>` and auto-zeroes on drop.
  Don't introduce raw `Vec<u8>` for keys.
- `SyncStorage` and `SyncRelay` are object-safe traits. Keep them that way —
  no generic methods.
- `SyncStorage` calls inside the engine are wrapped in
  `tokio::task::spawn_blocking`.
- FFI functions use primitive types only. No trait objects across the FFI
  boundary.
- Merge order is field-level LWW with a 3-level tiebreaker: HLC → device_id →
  op_id. Don't reorder without a protocol version bump.
- Relay paths are `/v1/sync/{sync_id}/...`. Don't break path versioning.
- If you change the FFI surface, regenerate Dart bindings and commit both
  sides in the same change.

By submitting a pull request you agree to the
[Contributor License Agreement](CLA.md). The CLA exists so the project can
cleanly dual-license under MIT and Apache 2.0.

For security issues, please don't open a public issue. See
[SECURITY.md](SECURITY.md) — it lists scope, disclosure process, and the
categories of bugs we care about most (key-material leakage, signature or
authentication bypass, CRDT soundness, relay flaws).

## Related repositories

- [prism-app](https://github.com/prismplural/prism-app) — the Flutter app
  that consumes this engine.

## On AI

We use AI coding tools (local and hosted) heavily while building Prism. The
security architecture, design decisions, and protocol are ours; the
encryption is fully auditable regardless of what tools wrote the surrounding
code.

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE), at
your option.
