# prism-sync

prism-sync keeps [Prism Plural](https://github.com/prismplural/prism-app) devices in sync without giving the server their content. Each device records changes locally, encrypts them, and exchanges them through a relay. Devices merge the changes when they reconnect.

This repository contains the Rust engine, its Dart/Flutter integration, and the relay server. We develop them for Prism, a plural system management app, and keep them separate so the protocol can be inspected and the engine can be used outside the app.

- **Run a relay:** follow the [self-hosting guide](self-host/SELF-HOSTING.md).
- **Understand the protocol:** read [ARCHITECTURE.md](ARCHITECTURE.md) and the [pairing contract](docs/sync-pairing-protocol-contract.md).
- **Work on the code:** start with [CONTRIBUTING.md](CONTRIBUTING.md).
- **Use Prism:** visit the [app's download page](https://prismplural.com/download/).

## How it works

The engine records field-level changes with a hybrid logical clock. When devices edit different fields, both changes can survive. When they edit the same field, a deterministic last-write-wins order chooses the result: clock, then device ID, then operation ID. It doesn't combine two competing edits to the same text field. Deletes have tombstone handling to prevent stale edits from bringing records back.

Content is encrypted on the client. The protocol uses XChaCha20-Poly1305 for content encryption, hybrid Ed25519/ML-DSA-65 batch signatures, and X-Wing for key exchange. [Architecture](ARCHITECTURE.md) explains the key lifecycle and what gets verified before a change is applied.

The relay stores encrypted payloads, but also sees device membership, public keys, epochs, and transfer sizes and timing. Encryption doesn't hide that metadata or guarantee delivery. A relay can withhold valid batches; the current protocol does not detect all resulting forks or selective withholding. Read [the documented security limits](SECURITY.md#known-limitations) when evaluating whether it fits your application.

## What's here

| Component | Role |
| --- | --- |
| [prism-sync-core](crates/prism-sync-core/) | Schema, change tracking, merge, storage, device pairing, key lifecycle, and relay client |
| [prism-sync-crypto](crates/prism-sync-crypto/) | Cryptographic primitives without app or sync state |
| [prism-sync-ffi](crates/prism-sync-ffi/) | Rust API exposed through flutter_rust_bridge |
| [prism-sync-relay](crates/prism-sync-relay/) | Axum/SQLite relay with WebSocket notifications; runs without the app or core engine |
| [Dart packages](dart/packages/) | Generated bindings, Drift adapter, and Flutter storage/provider integration |
| [prism-sync-bench](crates/prism-sync-bench/) | Local relay benchmarks |

## Use it in another app

Prism is currently the only app we know of using `prism-sync`. If you'd like to use it in another app, [open an issue](https://github.com/prismplural/prism-sync/issues). We're happy to work with you one-on-one and improve the library for other uses.

Rust consumers start with `PrismSync` in [`prism-sync-core`](crates/prism-sync-core/src/client.rs). You supply the entity schema, storage integration, secure key storage, and relay configuration. The engine's `sync_now()` operation pulls, merges, and pushes changes; your app is responsible for applying them to its own data model and updating its interface. See [the core guide](crates/prism-sync-core/README.md) for the module map and storage interfaces.

Flutter consumers use the three packages under `dart/packages/`: `prism_sync`, `prism_sync_drift`, and `prism_sync_flutter`. Keep them on the same Git revision. Prism's [dependency declarations](https://github.com/prismplural/prism-app/blob/main/pubspec.yaml) and [local development guide](https://github.com/prismplural/prism-app/blob/main/CONTRIBUTING.md#work-across-app-and-sync) show both pinned Git dependencies and path overrides.

## Build the Rust workspace

You need Rust **1.88 or newer**, Cargo, Git, and a native C/C++ build toolchain. The workspace uses Rust 2021.

```bash
git clone https://github.com/prismplural/prism-sync.git
cd prism-sync
cargo build --workspace --locked
cargo test --workspace --locked
```

Dart/Flutter setup, test lanes, code generation, and compatibility checks are in [CONTRIBUTING.md](CONTRIBUTING.md).

## Contributing and security

Bug reports, reproducible sync failures, protocol questions, and documentation fixes are welcome in the [issue tracker](https://github.com/prismplural/prism-sync/issues). Discuss protocol, cryptography, or pairing changes before implementing them; we need to consider devices already running older versions.

Report vulnerabilities privately through [SECURITY.md](SECURITY.md). Don't attach real keys, tokens, recovery phrases, or user records to public reports.

We use local and hosted AI tools extensively in development. AI-assisted contributions are welcome under our [AI policy](AI_POLICY.md), which covers scope, repository conventions, verification, and communication.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your option. Contributions are subject to the existing [CLA](CLA.md); see [Contributing](CONTRIBUTING.md#send-a-pull-request) for the sign-off requirement.
