#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 1 || ( $1 != fast && $1 != native ) ]]; then
  echo 'Usage: scripts/test_lane.sh <fast|native>' >&2
  exit 2
fi

lane=$1
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
results_dir=${PRISM_TEST_RESULTS_DIR:-test-results}
mkdir -p "$results_dir"
command -v node >/dev/null || { echo 'Node.js is required to write the Rust test inventory.' >&2; exit 2; }
started_epoch=$(date +%s)
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# shellcheck disable=SC2329 # invoked by the EXIT trap below
finish() {
  status=$?
  finished_epoch=$(date +%s)
  printf 'lane=%s\nrevision=%s\nstarted_at=%s\nfinished_at=%s\nduration_seconds=%s\nexit_status=%s\n' \
    "$lane" "$(git rev-parse HEAD)" "$started_at" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$((finished_epoch - started_epoch))" "$status" \
    > "$results_dir/$lane-status.txt"
}
trap finish EXIT

set +e
{
  rustc --version
  cargo --version
  flutter --version
  dart --version
  just "test-$lane"
} 2>&1 | tee "$results_dir/$lane.log"
lane_status=${PIPESTATUS[0]}
set -e

node - "$results_dir/$lane.log" "$results_dir/$lane-rust-summary.json" <<'NODE'
const fs = require('fs');
const [input, output] = process.argv.slice(2);
const totals = { passed: 0, failed: 0, ignored: 0, measured: 0, filteredOut: 0 };
const suites = [];
const tests = [];
const lines = fs.readFileSync(input, 'utf8').split(/\r?\n/);
let binary = null;
const pattern = /test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out/g;
for (const match of lines.join('\n').matchAll(pattern)) {
  const [, outcome, passed, failed, ignored, measured, filteredOut] = match;
  const row = { outcome, passed: +passed, failed: +failed, ignored: +ignored, measured: +measured, filteredOut: +filteredOut };
  suites.push(row);
  for (const key of Object.keys(totals)) totals[key] += row[key];
}
for (const line of lines) {
  const binaryMatch = line.match(/^\s*Running (?:unittests .+|tests\/[^ ]+) \(([^)]+)\)$/) || line.match(/^\s*Doc-tests (.+)$/);
  if (binaryMatch) binary = binaryMatch[1];
  const match = line.match(/^test (.+) \.\.\. (ok|FAILED|ignored(?:, (.*))?)$/);
  if (match) {
    const [, name, result, ignoredReason] = match;
    const normalizedReason = ignoredReason?.trim();
    tests.push({ binary, name, outcome: result.startsWith('ignored') ? 'ignored' : result, ...(normalizedReason ? { ignoredReason: normalizedReason } : {}) });
  }
}
fs.writeFileSync(output, JSON.stringify({ suites, totals, tests, rustTests: tests.length ? 'observed' : 'not-run' }, null, 2) + '\n');
NODE

exit "$lane_status"
