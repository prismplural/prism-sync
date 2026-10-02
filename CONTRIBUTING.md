# Contributing to prism-sync

A small reproduction of a sync failure is useful, even if you don't know where the bug lives yet. Include the versions involved, the order of device actions, and what each device ended up with. Use synthetic records and remove secrets from logs. Security problems go through [SECURITY.md](SECURITY.md).

Check existing issues and PRs before starting. Small bug fixes and documentation changes can go straight to a PR. Discuss changes to merge rules, wire formats, cryptography, pairing, or storage first: a working change still needs to coexist with devices running older code.

AI-assisted work follows [AI_POLICY.md](AI_POLICY.md).

## Set up the repository

Fork the repository and clone your fork. You need Rust 1.88 or newer, Cargo, Git, and a native C/C++ build toolchain.

```bash
git clone https://github.com/YOUR-USERNAME/prism-sync.git
cd prism-sync
cargo build --workspace --locked
cargo test --workspace --locked
```

You can work on the Rust crates without setting up Flutter. For Dart package or FFI work, install Flutter (CI uses **3.44.1**) and Melos **6.3.3**:

```bash
dart pub global activate melos 6.3.3
cd dart
melos bootstrap
melos run test
cd ..
```

Make sure your Dart global executable directory is on `PATH`. The [`justfile`](justfile) provides shortcuts; install `just` to use them. CI's `scripts/test_lane.sh` wrapper also needs Node.js to write result inventories.

## Find the right layer

The [README](README.md#whats-here) maps the crates and packages. [ARCHITECTURE.md](ARCHITECTURE.md) explains the protocol and threat model; [the pairing contract](docs/sync-pairing-protocol-contract.md) covers the pairing state transitions and compatibility requirements.

Keep these boundaries intact:

- `prism-sync-crypto` has no app concepts or sync state.
- `SyncStorage` and `SyncRelay` remain object-safe traits. Don't add generic methods that prevent using them as trait objects.
- Blocking storage work in the engine runs through `tokio::task::spawn_blocking`.
- FFI APIs use bridge-friendly types. Don't expose trait objects to Dart.
- Synced fields use the ordering `HLC → device_id → op_id`. Changing merge order, tombstones, or serialization needs a compatibility plan.
- Relay routes are versioned under `/v1/sync/{sync_id}/...`.
- Sensitive key material uses zeroizing wrappers. Don't log plaintext records, keys, wrapped keys, session tokens, or pairing/invite secrets.

Use the nearest crate's tests to reproduce a bug before changing the behavior. For merge work, cover out-of-order delivery and deletes. For pairing or key rotation, cover failure and retry paths as well as successful setup.

## Run the checks that cover your change

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
```

While iterating, target a crate with `cargo test -p prism-sync-core` (or the crate you're changing). For crypto, serialization, or FFI changes, also run:

```bash
cargo test --locked -p prism-sync-crypto --test cross_language_vectors
```

Changes to the post-quantum dependencies or their version pins also need `just verify-pq-vectors`.

After bootstrapping Dart packages, the CI-style lanes are:

```bash
scripts/test_lane.sh fast
scripts/test_lane.sh native
just check-production
```

The fast lane runs Rust workspace tests and discovered Dart package tests. The native lane builds release FFI and local test-relay artifacts, then runs Dart package tests. Both wrappers record logs and results in `test-results/` (or `PRISM_TEST_RESULTS_DIR`). The native lane here is not a substitute for the app's two-device integration tests.

The [workflow](.github/workflows/test.yml) also checks Rust 1.88 compatibility and generated bindings. To reproduce the minimum-version check:

```bash
cargo +1.88.0 check --workspace --locked --all-targets
```

Install that toolchain with rustup if needed. For deliberate performance measurements, `just benchmark --help` lists the local relay workload options. Benchmarks are not PR timing thresholds; report inputs and the environment alongside results.

## Change the FFI API

Rust **1.88** is the workspace minimum, but the FFI crate pins **1.95.0** in [`rust-toolchain.toml`](crates/prism-sync-ffi/rust-toolchain.toml). Install that toolchain with rustfmt before generating bindings, along with the generator versions used by CI:

```bash
rustup toolchain install 1.95.0 --profile minimal --component rustfmt
cargo install cargo-expand --version 1.0.122 --locked
cargo install flutter_rust_bridge_codegen --version 2.12.0 --locked
rustup component add rustfmt
```

After changing `crates/prism-sync-ffi/src/api.rs`, run from the repository root:

```bash
flutter_rust_bridge_codegen generate
just codegen-check
```

Commit generated Dart bindings and Rust bridge output with the source change. Don't edit generated bindings by hand. The drift check regenerates into a temporary directory and compares against the committed output with formatting normalized; it does not test runtime integration.

For an app-facing change, test the candidate through prism-app's [local override and native test workflow](https://github.com/prismplural/prism-app/blob/main/CONTRIBUTING.md#work-across-app-and-sync). Prefer a backward-compatible sync PR first, then an app PR consuming the new revision. Link related PRs and describe what happens with an older peer.

## Send a pull request

Use the AI assistance checkbox in the PR template and list the model and harness if applicable. See [AI_POLICY.md](AI_POLICY.md).

Write the PR description yourself. Explain the failure or use case, what changed, and why. Include a reproduction or regression test where relevant, the checks you actually ran, and any checks you couldn't run. For protocol changes, describe compatibility and migration behavior. Keep unrelated cleanup separate.

Contributions require agreement to the existing [Contributor License Agreement](CLA.md). It specifies a Git `Signed-off-by: Name <email>` trailer as your electronic signature. Read it before signing; `git commit -s` adds the trailer. Identify third-party code and preserve its license and attribution.
