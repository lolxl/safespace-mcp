#!/usr/bin/env bash
# v1.8.1 — parallel typecheck + test runner. Used by `bun run validate`.
# v1.22 Phase 1 — also runs scripts/check-manifest-versions.sh as a
# pre-step (NEW-4 drift class closure; CHECK-ONLY per design Q2 LOCKED).
# Check runs BEFORE typecheck/tests so drift fails fast pre-CI. The check
# reports drift + exits non-zero — operator manually fixes (does NOT
# auto-rewrite; design Q2 explicitly rejected auto-rewrite as caller-
# surprise footgun). The in-process CI sentinel
# (src/manifest-versions.test.ts) catches drift if a developer skips this
# shell wrapper (defense-in-depth).
#
# Why parallel: typecheck (~3s tsc) and test suite (~6s bun test) are
# independent. Running them sequentially adds 3s of wall-time per
# pre-commit / pre-push cycle. Parallel cuts that to max(3s, 6s) = 6s.
#
# Exit codes: 0 if all pass; 1 if any fail. Both logs are printed
# AFTER both finish so interleaved output doesn't make logs unreadable.

set -uo pipefail

# v1.22 Phase 1 — manifest version CHECK (NEW-4 drift class closure).
# Located at repo root (not under .claude-plugin/scripts/) because it
# operates on .claude-plugin/{package,marketplace,plugin}.json from
# above. CHECK-ONLY per design Q2: reports drift + exits non-zero; does
# NOT rewrite files (caller-surprise-free; operator decides fix path).
SCRIPT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
if [[ -x "${SCRIPT_ROOT}/scripts/check-manifest-versions.sh" ]]; then
  if ! bash "${SCRIPT_ROOT}/scripts/check-manifest-versions.sh"; then
    echo "validate.sh: manifest version drift — aborting before typecheck/tests" >&2
    exit 1
  fi
fi

TC_LOG=$(mktemp -t validate-tc.XXXXXX)
TEST_LOG=$(mktemp -t validate-test.XXXXXX)
trap 'rm -f "$TC_LOG" "$TEST_LOG"' EXIT

bun run typecheck > "$TC_LOG" 2>&1 &
PID_TC=$!

bun test > "$TEST_LOG" 2>&1 &
PID_TEST=$!

EXIT=0
if ! wait "$PID_TC"; then
  EXIT=1
fi
if ! wait "$PID_TEST"; then
  EXIT=1
fi

echo "=== typecheck ==="
cat "$TC_LOG"
echo
echo "=== test ==="
cat "$TEST_LOG"

exit "$EXIT"
