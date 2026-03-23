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
