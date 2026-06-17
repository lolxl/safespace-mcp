#!/usr/bin/env bash
# Enforce 100% line coverage on src/sanitize/.
#
# Why line% (not branch%): Bun 1.3.x emits line + function % via
# --coverage-reporter=text and LCOV without BRDA records. Branch coverage
# is the original TEST_PLAN.md goal but is unreachable with current Bun
# tooling — line coverage is the strictest available substitute.
#
# Also scoped to src/sanitize/ only: running --coverage across the full
# suite triggers test-runner instrumentation flakiness (some auth tests
# error out under coverage). The sanitize subtree is self-contained and
# stable under coverage.

set -euo pipefail

TARGETS=("src/sanitize/index.ts" "src/sanitize/patterns.ts")
MIN_PCT=100

COVERAGE_TMP=$(mktemp)
trap 'rm -f "$COVERAGE_TMP"' EXIT

# Capture bun test exit code explicitly. Command substitution (OUTPUT=$(...))
# would swallow a non-zero exit even under `set -e`, masking test failures
# that would still leave a parseable coverage table.
if ! bun test src/sanitize/ --coverage > "$COVERAGE_TMP" 2>&1; then
  echo "FAIL: bun test src/sanitize/ exited non-zero" >&2
  cat "$COVERAGE_TMP" >&2
  exit 1
fi

OUTPUT=$(cat "$COVERAGE_TMP")

# Locate the '% Lines' column index dynamically from the header row so the
# gate doesn't silently parse the wrong metric if Bun reorders columns.
LINES_COL=$(echo "$OUTPUT" | awk -F'|' '
  /% Lines/ {
    for (i = 1; i <= NF; i++) {
      if ($i ~ /% Lines/) { print i; exit }
    }
  }
')
if [ -z "$LINES_COL" ]; then
  echo "FAIL: could not locate '% Lines' header in coverage output" >&2
  echo "$OUTPUT" >&2
  exit 1
fi

failed=0
for target in "${TARGETS[@]}"; do
  # Match the file column (first '|' field) against the target after
  # trimming surrounding whitespace. Bun pads the file column to the
  # longest filename width, so a fixed-string grep would have to know
  # the pad count. Field-aware matching is immune to that.
  line=$(echo "$OUTPUT" | awk -F'|' -v t="$target" '
    {
      f = $1
      gsub(/^[ \t]+|[ \t]+$/, "", f)
      if (f == t) { print; exit }
    }
  ')
  if [ -z "$line" ]; then
    echo "FAIL: no coverage row found for $target" >&2
    failed=1
    continue
  fi
  pct=$(echo "$line" | awk -F'|' -v c="$LINES_COL" '{ gsub(/ /, "", $c); print $c }')
  if ! echo "$pct" | grep -qE '^[0-9]+(\.[0-9]+)?$'; then
    echo "FAIL: could not parse numeric line% from row: $line" >&2
    failed=1
    continue
  fi
  cmp=$(awk -v a="$pct" -v b="$MIN_PCT" 'BEGIN { print (a+0 >= b+0) }')
  if [ "$cmp" != "1" ]; then
    echo "FAIL: $target line coverage ${pct}% < ${MIN_PCT}%" >&2
    failed=1
  else
    echo "OK: $target line coverage ${pct}%"
  fi
done

if [ "$failed" -ne 0 ]; then
  echo >&2
  echo "Coverage gate failed. Full output:" >&2
  echo "$OUTPUT" >&2
  exit 1
fi
