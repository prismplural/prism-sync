#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
expected_version=2.12.0
actual_version=$(flutter_rust_bridge_codegen --version | awk '{print $NF}')
[[ $actual_version == "$expected_version" ]] || {
  echo "flutter_rust_bridge_codegen $expected_version is required; found $actual_version" >&2
  exit 2
}
tmp=$(mktemp -d /tmp/prism-sync-codegen.XXXXXX)
tmp=$(cd "$tmp" && pwd -P)
trap 'rm -rf "$tmp"' EXIT
cp "$root/Cargo.toml" "$root/Cargo.lock" "$tmp/"
cp -R "$root/crates" "$tmp/crates"
cp "$root/crates/prism-sync-ffi/src/frb_generated.rs" "$tmp/committed-frb_generated.rs"
mkdir -p "$tmp/dart/packages/prism_sync"
cp "$root/dart/packages/prism_sync/pubspec.yaml" "$tmp/dart/packages/prism_sync/pubspec.yaml"
flutter_rust_bridge_codegen generate --rust-input crate::api --rust-root "$tmp/crates/prism-sync-ffi" \
  --dart-output "$tmp/dart/packages/prism_sync/lib/generated" --rust-output "$tmp/crates/prism-sync-ffi/src/frb_generated.rs" \
  --c-output "$tmp/frb.h" --no-build-runner --no-dart-fix
diff -ru "$root/dart/packages/prism_sync/lib/generated" "$tmp/dart/packages/prism_sync/lib/generated"
# Use one formatter to exclude version-dependent line wrapping from the diff.
rustfmt --edition 2021 "$tmp/committed-frb_generated.rs" "$tmp/crates/prism-sync-ffi/src/frb_generated.rs"
diff -u "$tmp/committed-frb_generated.rs" "$tmp/crates/prism-sync-ffi/src/frb_generated.rs"
