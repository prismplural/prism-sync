test:
    cargo test --workspace

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
