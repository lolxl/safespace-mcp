#!/usr/bin/env bash
# v1.22 Phase 1 — manifest version sync CHECK (NEW-4 drift class closure).
#
# CHECK-ONLY (design Q2 sub-decision LOCKED): reports drift across the 3
# manifests and exits non-zero on mismatch. Does NOT rewrite any file —
# operator decides whether to bump source-of-truth (.claude-plugin/package.json)
# or fix the drifted manifest manually.
#
# Source of truth: .claude-plugin/package.json (SERVER_VERSION imports
# from here per issue #115/#117). Compared against:
#   - .claude-plugin/marketplace.json — Claude Code plugin marketplace
#     discovery (plugins[0].version)
#   - .claude-plugin/plugin.json      — Claude Code plugin local install
#
# Pre-v1.22 drift history:
#   v1.19.0 release — only package.json bumped; marketplace.json stuck at
#                     1.18.0, plugin.json stuck at 1.10.0 (9-release drift)
#   v1.19.2         — manual resync; NEW-4 carry-forward opened
#   v1.20.0 / v1.21.0 — manual checklist edits per release-PR; fragile
#   v1.22.0 (this)  — this check + CI sentinel test close the class
#
# Why CHECK-ONLY (NOT auto-rewrite)? Auto-rewrite was REJECTED at design
# Q2 sub-decision because (a) it modifies committed files silently during
# pre-commit, surprising the developer; (b) it picks package.json as the
# universal source of truth, but release flows sometimes intentionally
# leave manifests at older versions during staged work; (c) defense-in-depth
# is preserved by the CI sentinel (src/manifest-versions.test.ts) which
# still fails the build on drift.
#
# Exit codes:
#   0 — all 3 manifests match
#   1 — drift detected (one or more manifests diverge from package.json)
#   2 — fatal (missing file, unreadable JSON, etc.)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PKG="${ROOT}/.claude-plugin/package.json"
MKT="${ROOT}/.claude-plugin/marketplace.json"
PLG="${ROOT}/.claude-plugin/plugin.json"

[[ -f "$PKG" ]] || { echo "FATAL: package.json missing at $PKG" >&2; exit 2; }
[[ -f "$MKT" ]] || { echo "FATAL: marketplace.json missing at $MKT" >&2; exit 2; }
[[ -f "$PLG" ]] || { echo "FATAL: plugin.json missing at $PLG" >&2; exit 2; }

VERSION="$(jq -r '.version' "$PKG")"
[[ -n "$VERSION" && "$VERSION" != "null" ]] || {
  echo "FATAL: could not read version from $PKG" >&2
  exit 2
}

MKT_VERSION="$(jq -r '.plugins[0].version' "$MKT")"
PLG_VERSION="$(jq -r '.version' "$PLG")"

DRIFT=0

if [[ "$MKT_VERSION" != "$VERSION" ]]; then
  echo "DRIFT: marketplace.json plugins[0].version = '$MKT_VERSION' (expected '$VERSION' from package.json)" >&2
  DRIFT=1
fi

if [[ "$PLG_VERSION" != "$VERSION" ]]; then
  echo "DRIFT: plugin.json version = '$PLG_VERSION' (expected '$VERSION' from package.json)" >&2
  DRIFT=1
fi

if [[ "$DRIFT" -eq 1 ]]; then
  echo "FAIL: 3-manifest version drift detected. Source of truth is .claude-plugin/package.json." >&2
  echo "Fix: edit the drifted file(s) above to match version '$VERSION', or bump package.json if release intent changed." >&2
  exit 1
fi

echo "OK: 3 manifests in sync at $VERSION"
