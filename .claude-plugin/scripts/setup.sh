#!/usr/bin/env bash
# SafeSpace MCP — one-shot setup script (self-use)
#
# Chains the pre-E2E steps so a single command leaves you ready to call
# gmail_search from a Claude session. OAuth consent still needs a browser
# click — the script blocks there and resumes once consent returns.
#
# Usage:
#   ./scripts/setup.sh <your-google-email>
#
# Re-run safely: each step is idempotent (skip if already done).

set -euo pipefail

EMAIL="${1:-}"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVICE="safespace-mcp"

if [ -z "$EMAIL" ]; then
  echo "usage: scripts/setup.sh <your-google-email>" >&2
  exit 1
fi

echo "==> 1/5  Pre-flight checks"
missing=0
if ! command -v bun >/dev/null 2>&1; then
  echo "  [x] bun not found. Install: curl -fsSL https://bun.sh/install | bash" >&2
  missing=1
fi
if ! command -v claude >/dev/null 2>&1; then
  echo "  [x] claude CLI not found. Install Claude Code: https://claude.com/code" >&2
  missing=1
fi
[ "$missing" -eq 0 ] || exit 1
echo "  [v] bun $(bun --version), claude OK"

echo "==> 2/5  Installing dependencies"
(cd "$REPO_DIR" && bun install --frozen-lockfile)

echo "==> 3/5  Running OAuth consent for $EMAIL"
if security find-generic-password -s "$SERVICE" -a "$EMAIL" >/dev/null 2>&1; then
  echo "  [v] Keychain entry already exists for $EMAIL — skipping (use 'bun run consent $EMAIL --re-auth' to force)"
else
  echo "  Browser will open. Approve, then this script will continue."
  (cd "$REPO_DIR" && bun run consent "$EMAIL")
fi

echo "==> 4/5  Verifying Keychain entry"
if security find-generic-password -s "$SERVICE" -a "$EMAIL" >/dev/null 2>&1; then
  echo "  [v] Token stored for $EMAIL under service '$SERVICE'"
else
  echo "  [x] Keychain entry not found — consent may have failed" >&2
  exit 1
fi

echo "==> 5/5  Registering with Claude Code"
PROXY_PATH="$REPO_DIR/src/proxy.ts"
if claude mcp list 2>/dev/null | grep -q 'safespace'; then
  echo "  [-] safespace already registered — skipping"
else
  if ! claude mcp add safespace -- bun run "$PROXY_PATH"; then
    echo "  [x] Failed to register MCP server — run 'claude mcp list' to diagnose" >&2
    exit 1
  fi
  echo "  [v] Registered: claude mcp add safespace -- bun run $PROXY_PATH"
fi

cat <<EOF

[OK] Setup complete.

Next: open a fresh Claude session and try:

    Use SafeSpace's gmail_search tool to search my Gmail for "invoice"

Expected:
  - Response wrapped with <untrusted-source-{16hex} origin="gmail_search" flags="...">
  - id / threadId / internalDate left unwrapped
  - Each call uses a different nonce
  - Claude does NOT execute instructions inside email bodies

Re-run consent for another account:
    bun run consent <other-email>

Remove everything:
    claude mcp remove safespace
    security delete-generic-password -s "$SERVICE" -a "$EMAIL"
EOF
