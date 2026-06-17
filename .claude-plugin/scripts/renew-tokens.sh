#!/usr/bin/env bash
# SafeSpace MCP — weekly refresh-token renewal (v2.0 single-profile)
#
# Google's OAuth refresh tokens expire after 7 days when the GCP project
# is in "External + Testing" mode. This script preemptively re-runs
# consent for each registered account so you don't hit a
# refresh_token_invalid error mid-session.
#
# v2.0 single-profile: reads the canonical account list from
# accounts.json under $CLAUDE_PLUGIN_DATA/safespace/ — no separate
# .safespace-accounts file needed.
#
# Suggested cadence: every Saturday morning. Add to your calendar or
# wire into a launchd job:
#   # ~/Library/LaunchAgents/local.safespace.renew.plist (every Sat 09:00)

# Refuse to be sourced — the cd below would permanently change PWD.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  echo "error: do not source this script; run it: ./scripts/renew-tokens.sh" >&2
  return 1 2>/dev/null || exit 1
fi

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

# Resolve plugin data dir. The wizard installs under
# $CLAUDE_PLUGIN_DATA, which Claude Code's MCP runtime expands to
# ~/.claude/plugins/data/safespace-mcp-safespace/ — but slash-command
# Bash and standalone CLI invocations don't have that env var set, so
# we fall back to the canonical path.
PLUGIN_DATA="${CLAUDE_PLUGIN_DATA:-$HOME/.claude/plugins/data/safespace-mcp-safespace}"
CONFIG_DIR="$PLUGIN_DATA/safespace"
ENV_FILE="$CONFIG_DIR/.env"
ACCOUNTS_FILE="$CONFIG_DIR/accounts.json"

if [ ! -f "$ENV_FILE" ]; then
  echo "error: $ENV_FILE not found. Run /safespace-setup first." >&2
  exit 1
fi
if [ ! -f "$ACCOUNTS_FILE" ]; then
  echo "error: $ACCOUNTS_FILE not found. Run /safespace-setup first." >&2
  exit 1
fi
if ! command -v bun >/dev/null 2>&1; then
  echo "error: bun not found. brew install oven-sh/bun/bun" >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq not found. brew install jq" >&2
  exit 1
fi

# Read account emails from accounts.json. Accepts v1 OR v2 schema
# (matches the loadIndex reader guard from PR-2b-1).
mapfile -t emails < <(jq -r '.accounts[].email' "$ACCOUNTS_FILE")
if [ ${#emails[@]} -eq 0 ]; then
  echo "error: $ACCOUNTS_FILE has no accounts. Run /safespace-setup or" >&2
  echo "       \`safespace consent <email>\` to register at least one." >&2
  exit 1
fi

count=${#emails[@]}
echo "==> Renewing refresh tokens for $count account(s) (v2.0 single-profile, weekly anti-expiry)"
echo "    Each one opens a browser; click 'Allow' to confirm."
echo

failures=()
step=0
for email in "${emails[@]}"; do
  step=$((step + 1))
  echo "==> [$step/$count] $email"
  if SAFESPACE_CONFIG_DIR="$CONFIG_DIR" \
       bun --env-file="$ENV_FILE" run "$REPO_DIR/src/cli.ts" consent "$email"; then
    echo "    OK"
  else
    echo "    FAILED" >&2
    failures+=("$email")
  fi
  echo
done

echo "==================================================================="
if [ ${#failures[@]} -eq 0 ]; then
  echo "All $count token(s) renewed. Next renewal: in ~7 days."
else
  echo "${#failures[@]} renewal(s) failed:"
  for f in "${failures[@]}"; do echo "  - $f"; done
  echo
  echo "Retry the failed ones manually:"
  echo "  SAFESPACE_CONFIG_DIR=\"$CONFIG_DIR\" \\"
  echo "    bun --env-file=\"$ENV_FILE\" run \"$REPO_DIR/src/cli.ts\" consent <email>"
  exit 1
fi
