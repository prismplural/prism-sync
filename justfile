test:
    cargo test --workspace

# Deterministic Rust and Dart package tests. Bootstrap Dart packages first.
test-fast:
    cargo test --workspace --locked
    cd dart && melos run test

# Builds the FFI and local relay artifacts that consumers' native lanes require.
test-native:
    cargo build --locked --release -p prism_sync_ffi
    cargo build --locked --release -p prism-sync-relay --example test_relay
    cd dart && melos run test

check-production:
    cargo build --workspace --locked --release

codegen-check:
    scripts/check_codegen.sh

# Deliberate local relay workload; it is not an ordinary PR timing gate.
benchmark *args:
    cargo run --release -p prism-sync-bench -- {{args}}

test-crate crate:
    cargo test -p {{crate}}

lint:
    cargo clippy --workspace --all-targets -- -D warnings

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

build:
    cargo build --workspace

test-crypto:
    cargo test -p prism-sync-crypto

# Run the PQ / cross-language vector gate. Invoke after any change to the
# post-quantum crates (ml-kem / ml-dsa / x-wing) or their `=` pins in
# Cargo.toml. Covers the X-Wing draft vector (xwing_matches_draft_vector_1)
# and the cross-language vectors so a crate bump that changes the combiner
# or encap-key handling fails loudly.
verify-pq-vectors:
    cargo test --locked -p prism-sync-crypto pq
    cargo test --locked -p prism-sync-crypto --test cross_language_vectors
