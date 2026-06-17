---
description: Interactive wizard for SafeSpace MCP first-time setup. Pre-flight checks, GCP OAuth creds, account consent, and verification — all targeting the v2.0 single-profile layout.
allowed-tools: Bash, Read, Write
---

# SafeSpace MCP Setup Wizard

You are guiding the user through first-time setup of SafeSpace MCP v2.0. The user has just installed the plugin (`claude plugin install lolxl/safespace-mcp`) and wants the `safespace` MCP server operational with their Google accounts.

Follow the 6 steps below **strictly in order**. Pause and ask the user before proceeding between major steps. Read the user's responses carefully and re-prompt on invalid input. Never skip pre-flight checks.

## Conventions

- **Plugin data root** (where per-user state lives): `${HOME}/.claude/plugins/data/safespace-mcp-safespace/`. The `-safespace` suffix is Claude Code's `<plugin-name>-<marketplace-name>` data-dir convention — `${CLAUDE_PLUGIN_DATA}` resolves to this path inside MCP subprocesses. `.mcp.json` already points the `safespace` MCP server here, so all the wizard does is populate `$PLUGIN_DATA/safespace/`.
- **Plugin code root**: the directory containing `src/proxy.ts` and `src/cli.ts`. Resolved via `${CLAUDE_PLUGIN_ROOT}` if available (it's set for MCP / hook subprocesses but **not** for slash-command Bash tool calls), otherwise via globbing `~/.claude/plugins/cache/safespace/safespace-mcp/*/` and picking the newest dir. Hard-fails with a clear "re-install plugin" message if neither resolution works.
- **v2.0 single profile**: one config dir (`safespace/`), one MCP server (`safespace`), one `.env` file, one `accounts.json` (schema v2). The v1.x `safespace-read/` + `safespace-send/` split is gone — tool exposure is now controlled by `SAFESPACE_TIER=read|write|share` (set in `.env`).
- **Verify each shell command's exit status before continuing.** If anything fails, stop and report to the user.

---

## Step 0: Pre-flight

Run the following Bash command and report results in a 4-line summary:

```bash
echo "bun:    $(command -v bun || echo MISSING)"
echo "claude: $(command -v claude || echo MISSING)"
echo "jq:     $(command -v jq || echo MISSING)"
```

If any is `MISSING`:
- `bun`: tell the user to run `brew install oven-sh/bun/bun`
- `claude`: tell the user to (re)install Claude Code itself
- `jq`: tell the user to run `brew install jq` (needed weekly by `renew-tokens.sh`; checked up-front so the dependency surfaces before OAuth investment)

**Halt the wizard if any tool is missing.** Do not proceed.

Resolve plugin paths and show them to the user:

```bash
PLUGIN_DATA="${HOME}/.claude/plugins/data/safespace-mcp-safespace"
echo "Plugin data dir: $PLUGIN_DATA"
echo "(v2.0 config will live at $PLUGIN_DATA/safespace/)"
```

**Detect legacy v1.x two-profile layout** (users upgrading from <= 0.3.x). If `safespace-read/` or `safespace-send/` exist under `$PLUGIN_DATA`, the user must run the migration tool FIRST to merge them into the v2.0 layout. The wizard refuses to overwrite legacy state:

```bash
LEGACY_READ="$PLUGIN_DATA/safespace-read"
LEGACY_SEND="$PLUGIN_DATA/safespace-send"
if [ -d "$LEGACY_READ" ] || [ -d "$LEGACY_SEND" ]; then
  echo "error: legacy v1.x profile dirs detected:" >&2
  [ -d "$LEGACY_READ" ] && echo "  $LEGACY_READ" >&2
  [ -d "$LEGACY_SEND" ] && echo "  $LEGACY_SEND" >&2
  echo >&2
  echo "v2.0 uses a single-profile layout. Run the migration tool first:" >&2
  echo "  safespace migrate-v2 --dry-run    # preview the plan" >&2
  echo "  safespace migrate-v2              # actually migrate" >&2
  echo >&2
  echo "After migration, the old dirs are renamed to safespace-{read,send}.migrated/" >&2
  echo "(safe to delete manually once you've verified the new safespace/ dir works)." >&2
  echo >&2
  echo "Then re-run /safespace-setup if you need to (re)configure." >&2
  exit 1
fi
```

If the wizard halts here, tell the user clearly: their v1.x data still exists — the migration tool will merge it cleanly without touching the Keychain entries (which are already shared across profiles by email). They should run the migration before continuing the wizard.

Then install plugin runtime dependencies:

```bash
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-}"
if [ -z "$PLUGIN_ROOT" ] || [ ! -f "$PLUGIN_ROOT/package.json" ]; then
  PLUGIN_ROOT=$(ls -dt "${HOME}/.claude/plugins/cache/safespace/safespace-mcp"/*/ 2>/dev/null | head -1 | sed 's|/$||')
fi
if [ -z "$PLUGIN_ROOT" ] || [ ! -f "$PLUGIN_ROOT/package.json" ]; then
  echo "error: cannot locate installed plugin — run \`/plugin install safespace-mcp@safespace\` first, or set \$CLAUDE_PLUGIN_ROOT manually" >&2
  exit 1
fi
echo "Plugin code root: $PLUGIN_ROOT"
if [ ! -d "$PLUGIN_ROOT/node_modules" ]; then
  echo "Installing plugin runtime deps (one-time, ~3-5s on cold cache)…"
  ( cd "$PLUGIN_ROOT" && bun install --frozen-lockfile )
else
  echo "Plugin deps already installed at $PLUGIN_ROOT/node_modules (skip)"
fi
```

If `bun install` fails, halt the wizard. Most likely cause: network or lockfile drift after a plugin upgrade. Suggest the user delete `$PLUGIN_ROOT/node_modules` and re-run the wizard.

---

## Step 1: GCP OAuth credential checklist (manual)

Print this checklist verbatim and ask the user to confirm completion:

```
You need a Google Cloud Console OAuth client. If you don't already have one:

1. Go to https://console.cloud.google.com/projectcreate and create a project
   (any name, e.g. "safespace-personal").
2. Enable the Gmail and Drive APIs:
     https://console.cloud.google.com/apis/library/gmail.googleapis.com
     https://console.cloud.google.com/apis/library/drive.googleapis.com
3. OAuth consent screen → User Type "External" → fill required fields →
   Add the Gmail addresses you plan to use under "Test users" (up to 100).
   Save & continue.
4. Credentials → Create Credentials → OAuth client ID → Application type
   "Desktop app" → name "SafeSpace MCP" → Create. Copy the Client ID and
   Client Secret to a secure scratchpad — you'll paste them in the next step.
```

Then ask the user: **"Have you completed steps 1-4 above and do you have your Client ID and Client Secret ready?"** Wait for an affirmative reply (`yes`, `done`, `ok`) before proceeding. If they say no, halt and tell them to come back when ready.

---

## Step 2: Collect creds + write `.env`

**Idempotency check** — if the `.env` already exists, ask the user before overwriting. Also detect the v1.0 → v1.1 upgrade trap: a `.env` that carries the removed `SAFESPACE_ENABLE_{SEND,MODIFY,DRIVE_SHARE}=1` flags but **no** `SAFESPACE_TIER=` line. v1.1 hard-fails on startup in that state — the wizard offers a guided fix.

```bash
PLUGIN_DATA="${HOME}/.claude/plugins/data/safespace-mcp-safespace"
ENV_FILE="$PLUGIN_DATA/safespace/.env"
if [ ! -f "$ENV_FILE" ]; then
  echo "EXISTING_ENV_FILE=0"
else
  echo "EXISTING_ENV_FILE=1"
  # Detect legacy-only state via grep — NEVER echo .env line content.
  # `HAS_TIER` counts uncommented SAFESPACE_TIER= lines; `LEGACY_FLAGS`
  # lists which legacy enable-flags are set to 1 (NAMES ONLY, no values —
  # sed strips everything after the key name). Do not modify this pipeline
  # to include values: every downstream user-facing message assumes
  # LEGACY_FLAGS_FOUND contains key tokens only, never secret-adjacent data.
  # `grep -c` exits 1 when matches=0 — `|| HAS_TIER=0` overrides the (already
  # captured) stdout in that case while keeping a real count on match. Do NOT
  # use `|| echo 0` here: that would append a second "0" to stdout, giving
  # HAS_TIER="0\n0" and breaking the equality check below.
  HAS_TIER=$(grep -cE '^[[:space:]]*SAFESPACE_TIER[[:space:]]*=' "$ENV_FILE" 2>/dev/null) || HAS_TIER=0
  LEGACY_FLAGS=$(grep -E '^[[:space:]]*SAFESPACE_ENABLE_(SEND|MODIFY|DRIVE_SHARE)[[:space:]]*=[[:space:]]*1([[:space:]]|$)' "$ENV_FILE" 2>/dev/null \
    | sed -E 's/^[[:space:]]*(SAFESPACE_ENABLE_(SEND|MODIFY|DRIVE_SHARE)).*/\1/' \
    | sort -u | tr '\n' ' ')
  if [ "$HAS_TIER" = "0" ] && [ -n "$LEGACY_FLAGS" ]; then
    echo "LEGACY_ENV_ONLY=1"
    echo "LEGACY_FLAGS_FOUND=$LEGACY_FLAGS"
  else
    echo "LEGACY_ENV_ONLY=0"
  fi
fi
```

**If `EXISTING_ENV_FILE=1` and `LEGACY_ENV_ONLY=0`** — standard idempotency prompt:

> "I found an existing `.env` at `$PLUGIN_DATA/safespace/.env`. **(K)**eep it and skip to Step 3, or **(O)**verwrite with fresh creds?"

If `K`, skip the rest of this step.

**If `EXISTING_ENV_FILE=1` and `LEGACY_ENV_ONLY=1`** — show the upgrade trap warning and offer a 3-way choice:

> "Your `.env` contains v1.x legacy flags (`$LEGACY_FLAGS_FOUND`) but no `SAFESPACE_TIER=`. v1.1 removed the auto-derive bridge — the proxy will hard-fail at startup in this state. Three options:
>
> **(F)ix legacy env** — derive `SAFESPACE_TIER` from the legacy flags, append it to `.env`, comment out the legacy lines (recommended; keeps `GOOGLE_CLIENT_*` untouched).
> **(K)eep as-is** — skip to Step 3 (proxy will still hard-fail; only useful if you'll edit `.env` manually).
> **(O)verwrite** — wipe and re-collect everything from scratch."

On `F`, derive the tier and ask for a **secondary confirmation**:

```bash
# Tier precedence matches the removed v1.x bridge exactly:
#   DRIVE_SHARE=1 → share  (highest blast radius any of the legacy flags grants)
#   SEND=1 or MODIFY=1 → write
#   (no match should be unreachable here — grep already filtered)
case " $LEGACY_FLAGS_FOUND " in
  *" SAFESPACE_ENABLE_DRIVE_SHARE "*)
    DERIVED_TIER="share"
    TIER_BLAST_RADIUS="adds anyone-with-link Drive sharing (drive_share_file with share_type=anyone) on top of write-tier tools. Highest blast radius."
    ;;
  *" SAFESPACE_ENABLE_SEND "*|*" SAFESPACE_ENABLE_MODIFY "*)
    DERIVED_TIER="write"
    TIER_BLAST_RADIUS="adds gmail_send, gmail_modify_message, drive_share_file (user-targeted only) on top of read-tier tools."
    ;;
  *)
    DERIVED_TIER="read"
    TIER_BLAST_RADIUS="search & read only; gmail_search, gmail_get_message, drive_search, drive_get_file_content, gmail_list_labels, drive_unshare_file."
    ;;
esac
echo "DERIVED_TIER=$DERIVED_TIER"
echo "TIER_BLAST_RADIUS=$TIER_BLAST_RADIUS"
```

Print to the user (spell out exactly which tools the derived tier unlocks — this is the primary privilege-escalation gate, so the user must understand the blast radius before confirming):

> "Derived tier from legacy flags (`$LEGACY_FLAGS_FOUND`): **`$DERIVED_TIER`**.
>
> What tier=`$DERIVED_TIER` exposes: `$TIER_BLAST_RADIUS`
>
> This matches what the removed v1.0 bridge would have done. Apply? [y/N]"

Default is `N` (no — fall back to K/O). On `y`, perform the atomic rewrite:

```bash
# Atomic rewrite: write to a sibling tmp in the same dir at mode 600,
# then rename(2) (mv) onto the target. install(8) on macOS is NOT atomic
# (creat+write+chmod has a partial-content window) — mv-within-same-fs is.
TMP=$(mktemp "$ENV_FILE.migrate.XXXXXX") || { echo "error: mktemp failed" >&2; exit 1; }
chmod 600 "$TMP"  # defensive; macOS mktemp already creates 0600.

# Clean up the tmp file if anything below exits unexpectedly (kill, awk crash,
# verification failure that already rm'd $TMP — the rm -f is idempotent).
trap 'rm -f "$TMP"' EXIT

# awk transformation:
#   - SAFESPACE_ENABLE_{SEND,MODIFY,DRIVE_SHARE}=... lines → prefixed with
#     "# v1.1: removed — auto-migrated to SAFESPACE_TIER" + commented out.
#   - All other lines pass through unchanged (GOOGLE_CLIENT_ID/SECRET intact).
#   - Append "SAFESPACE_TIER=<derived>" once at the end.
# We do NOT echo .env content; awk reads from $ENV_FILE and writes to $TMP.
awk -v tier="$DERIVED_TIER" '
  /^[[:space:]]*SAFESPACE_ENABLE_(SEND|MODIFY|DRIVE_SHARE)[[:space:]]*=/ {
    print "# v1.1: removed — auto-migrated to SAFESPACE_TIER below"
    print "# " $0
    next
  }
  { print }
  END {
    print "SAFESPACE_TIER=" tier
  }
' "$ENV_FILE" > "$TMP" || { rm -f "$TMP"; echo "error: rewrite failed" >&2; exit 1; }

# Verify rewrite produced both the new tier line AND preserved GOOGLE_CLIENT_*
# (grep -q only — never echo matched content).
if ! grep -qE "^SAFESPACE_TIER=$DERIVED_TIER\$" "$TMP" \
   || ! grep -qE '^[[:space:]]*GOOGLE_CLIENT_ID[[:space:]]*=' "$TMP" \
   || ! grep -qE '^[[:space:]]*GOOGLE_CLIENT_SECRET[[:space:]]*=' "$TMP"; then
  rm -f "$TMP"
  echo "error: rewrite verification failed — .env left untouched" >&2
  exit 1
fi

mv -f "$TMP" "$ENV_FILE"
# Verify final mode (paranoia; mv preserved the tmp's 0600).
stat -f '%N: %Lp' "$ENV_FILE"
```

Confirm to the user: "Migrated `.env` to use `SAFESPACE_TIER=$DERIVED_TIER` (legacy `$LEGACY_FLAGS_FOUND` lines commented out, mode 0600 preserved). Skipping to Step 3."

Then skip the rest of Step 2 — credentials are already present.

On `N` (declined the derived tier) or any non-`y` reply, fall back to the K/O prompt above.

**Warn the user before prompting for the secret:**

> "I'll prompt you for your Client ID and Client Secret. Heads-up: the secret you paste will appear in this Claude Code session's transcript at `~/.claude/projects/`. If you sync that directory or share session logs, consider rotating the GCP OAuth client secret afterwards. On a single-user machine without log sharing this is acceptable."

Then ask separately, validating each:

- **Client ID** — should end in `.apps.googleusercontent.com`. Regex: `^[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com$`. Re-prompt on mismatch.
- **Client Secret** — should start with `GOCSPX-`. Regex: `^GOCSPX-[A-Za-z0-9_-]+$`. Re-prompt on mismatch.

Now ask about the **tier** — this controls which MCP tools are exposed:

```
SafeSpace v2.0 uses a tier system instead of separate read/send profiles.
Pick a starting tier (you can change it later by editing the .env file):

  read    Search & read only. gmail_search, gmail_get_message,
          drive_search, drive_get_file_content, gmail_list_labels,
          drive_unshare_file. (Safest. Recommended for first setup.)

  write   Adds gmail_send, gmail_modify_message, drive_share_file
          (user-targeted shares only). For drafting + replying.

  share   Adds anyone-with-link Drive sharing. Highest blast radius —
          only enable when you actually need to publish a Drive link.
```

Default to `read` if the user is unsure. Validate against `^(read|write|share)$`.

Once Client ID, Client Secret, and tier are all valid, write the single `.env` file using `install -m 0600` (atomic creation with target mode in one syscall — no world-readable window):

```bash
PLUGIN_DATA="${HOME}/.claude/plugins/data/safespace-mcp-safespace"
mkdir -p "$PLUGIN_DATA/safespace"
chmod 700 "$PLUGIN_DATA/safespace"

# Heredoc avoids GOOGLE_CLIENT_SECRET being written via `echo` to a
# shell-history-visible location. The 0o600 mode is applied at create time.
install -m 0600 /dev/stdin "$PLUGIN_DATA/safespace/.env" <<EOF
GOOGLE_CLIENT_ID=<CLIENT_ID>
GOOGLE_CLIENT_SECRET=<CLIENT_SECRET>
SAFESPACE_TIER=<TIER>
EOF
```

Substitute the actual values where `<CLIENT_ID>`, `<CLIENT_SECRET>`, and `<TIER>` appear. Verify the file mode by running `stat -f '%N: %Lp' "$PLUGIN_DATA/safespace/.env"` and confirm it reports `600`.

Confirm to the user: "Wrote `.env` at `$PLUGIN_DATA/safespace/.env` (mode 0600, tier=`<TIER>`)."

---

## Step 2.5: Drive share whitelist (v2.1, only if tier=write or share)

**Skip this step entirely if the chosen `<TIER>` is `read`** — `drive_share_file` is not exposed at the read tier, so the whitelist policy is moot.

For `write` or `share` tiers, check whether `drive-whitelist.json` already exists:

```bash
WHITELIST_FILE="$PLUGIN_DATA/safespace/drive-whitelist.json"
if [ -f "$WHITELIST_FILE" ]; then
  echo "EXISTING_WHITELIST=1"
else
  echo "EXISTING_WHITELIST=0"
fi
```

If `EXISTING_WHITELIST=1`: confirm "Whitelist already configured at `$WHITELIST_FILE`. Skipping setup." and move to Step 3.

If `EXISTING_WHITELIST=0`: present the 3-way choice (DESIGN.md v2.1 Addendum spec):

> "SafeSpace v2.1 supports an opt-in Drive whitelist that gates `drive_share_file` to specific folders / files. Without this gate, share-tier sessions can share ANY Drive file the account has access to.
>
> **(S)et up whitelist now** — paste folder IDs (get them from the Drive URL: `https://drive.google.com/drive/folders/<this-is-the-id>`). Only files in these folders + their subtrees become shareable.
> **(K)eep open** — skip; tier=share/write remains fully open as in v2.0. You can re-run /safespace-setup later to add a whitelist.
> **(D)efault-deny** — create empty whitelist. ALL share calls will fail until you add entries via re-running this wizard or editing `$WHITELIST_FILE` manually."

On `S`: loop asking for folder/file IDs until the user enters empty input. Validate each against `^[A-Za-z0-9_-]{20,}$` (the same regex `isValidDriveId` uses). Build the JSON safely with `jq` (so user-supplied IDs can't break the file via shell metachar injection — even though they were validated, defense-in-depth):

```bash
NOW=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
TMP=$(mktemp "$WHITELIST_FILE.write.XXXXXX")
chmod 600 "$TMP"
# $ENTRIES_JSON is a JSON array built during the prompt loop using
# `jq -n --arg id <id> --arg label <label> --arg now "$NOW"
#       '{type: "folder", id: $id, label: $label, added_at: $now}'`
# and accumulated. jq's --arg interface treats IDs as literal strings, no
# shell expansion.
jq -n \
  --arg now "$NOW" \
  --argjson entries "$ENTRIES_JSON" \
  '{schema_version: 1, updated_at: $now, entries: $entries}' > "$TMP"
mv -f "$TMP" "$WHITELIST_FILE"
```

On `K`: do nothing (no file created). Show: "Skipped whitelist setup — tier=share/write remains fully open. Re-run /safespace-setup to configure later."

On `D`: write the empty-entries file:

```bash
NOW=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
TMP=$(mktemp "$WHITELIST_FILE.write.XXXXXX")
chmod 600 "$TMP"
jq -n --arg now "$NOW" \
  '{schema_version: 1, updated_at: $now, entries: []}' > "$TMP"
mv -f "$TMP" "$WHITELIST_FILE"
```

Show: "Wrote `drive-whitelist.json` at default-deny. All `drive_share_file` calls will return `share_denied_by_policy` until you add entries. Re-run /safespace-setup or edit the file directly."

In all branches: confirm the file mode is 0600 if it was created:

```bash
[ -f "$WHITELIST_FILE" ] && stat -f '%N: %Lp' "$WHITELIST_FILE"
```

---

## Step 2.6: Recipient allowlist (v2.2, only if tier=write or share)

**Skip this step entirely if the chosen `<TIER>` is `read`** — neither `gmail_send` nor `drive_share_file (share_type=user)` is exposed at the read tier, so the recipient allowlist is moot.

For `write` or `share` tiers, check whether `SAFESPACE_RECIPIENT_ALLOW` is already configured in `.env`:

```bash
ENV_FILE="$PLUGIN_DATA/safespace/.env"
if grep -qE '^[[:space:]]*SAFESPACE_RECIPIENT_ALLOW=' "$ENV_FILE" 2>/dev/null; then
  echo "EXISTING_RECIPIENT_ALLOW=1"
else
  echo "EXISTING_RECIPIENT_ALLOW=0"
fi
```

If `EXISTING_RECIPIENT_ALLOW=1`: confirm "Recipient allowlist already configured in `.env`. Skipping setup." and move to Step 3.

If `EXISTING_RECIPIENT_ALLOW=0`: present the 3-way choice (DESIGN.md v2.2 Addendum spec):

> "SafeSpace v2.2 supports a recipient allowlist that gates `drive_share_file (share_type=user)` `target_email` and `gmail_send` `to` field (all-or-nothing across comma-separated addresses). Without it, prompt-injection or long-running agent sessions could send/share to any recipient. v2.2 does NOT gate Cc/Bcc — those fields are not yet supported by `gmail_send` itself; if they're added later, the gate will need to be extended.
>
> **(S)et up allowlist** — type comma-separated domains (`@client.com`) or exact emails (`alice@client.com`). Wizard appends `SAFESPACE_RECIPIENT_ALLOW=<your-list>` to `$ENV_FILE`. Implicit self-send: emails registered in accounts.json are auto-allowed (no need to list yourself).
> **(K)eep open** — no var added; v2.0/v2.1 behavior preserved (recipient gate OFF). You can add later via re-running this wizard or editing `.env` directly.
> **(D)efault-deny** — wizard appends `SAFESPACE_RECIPIENT_ALLOW=` (empty value). Only self-send + per-session `SAFESPACE_RECIPIENT_ALLOW_EXTRA` allowed."

On `S`: collect comma-separated tokens (each must be `@domain.tld` or `localpart@domain.tld` — reject bare `domain.tld`). Validate each token; if any fails, re-prompt for that token. Atomic-append to `.env`:

```bash
# Atomic append: read current .env, append new line, write to tmp at 0o600,
# rename onto target. Preserves existing mode + atomic-replace semantics
# matching #63's legacy-env-fix pattern.
#
# Sec-rev MEDIUM #1 hardening: use `printf '%s\n'` (format string is a
# literal; user content is the data argument and is never interpreted as
# shell) instead of `echo "$NEWLINE_CONTENT"` — defense in depth even
# though the upstream token validator already rejects shell metachars.
TMP=$(mktemp "$ENV_FILE.write.XXXXXX") || { printf 'error: mktemp failed\n' >&2; exit 1; }
chmod 600 "$TMP"
trap 'rm -f "$TMP"' EXIT
cp "$ENV_FILE" "$TMP"
# Ensure trailing newline before appending
[ -n "$(tail -c1 "$TMP")" ] && printf '\n' >> "$TMP"
# `$VALIDATED_VALUE` is the comma-separated allowlist string assembled from
# already-validated tokens. printf with a literal format string is safe
# regardless of token contents.
printf 'SAFESPACE_RECIPIENT_ALLOW=%s\n' "$VALIDATED_VALUE" >> "$TMP"
# Verify GOOGLE_CLIENT_* preserved and new line present.
if ! grep -qE '^[[:space:]]*GOOGLE_CLIENT_ID[[:space:]]*=' "$TMP" \
   || ! grep -qE '^[[:space:]]*GOOGLE_CLIENT_SECRET[[:space:]]*=' "$TMP" \
   || ! grep -qE '^SAFESPACE_RECIPIENT_ALLOW=' "$TMP"; then
  printf 'error: append verification failed — .env left untouched\n' >&2
  exit 1
fi
mv -f "$TMP" "$ENV_FILE"
stat -f '%N: %Lp' "$ENV_FILE"
```

On `K`: do nothing (no `.env` modification). Show: "Skipped recipient allowlist — recipient gate OFF; tier=share/write fully open. Re-run /safespace-setup to configure later, or use shell env `SAFESPACE_RECIPIENT_ALLOW_EXTRA=alice@x.com claude` for one-off session grants."

On `D`: append the empty-value line via the same atomic-append pattern above, substituting `printf 'SAFESPACE_RECIPIENT_ALLOW=\n' >> "$TMP"` (no `%s`, no value). Show: "Wrote default-deny baseline. All `drive_share_file` / `gmail_send` to external recipients will be refused with `recipient_denied_by_policy` until you add entries (re-run wizard or edit `.env`). Self-send to your registered accounts continues to work."

In all branches, mention the per-session escape hatch in the summary:

> "Tip: for ad-hoc session-only grants without editing .env, launch Claude Code with `SAFESPACE_RECIPIENT_ALLOW_EXTRA=alice@x.com,@new-domain.com claude`. The EXTRA value unions with the .env baseline; it does NOT persist across sessions."

---

## Step 3: Collect accounts

Ask the user **how many Gmail accounts** they want to register. The single-profile model in v2.0 means any number is fine (1-10 is typical). For each, ask for the email address and validate against `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`. Re-prompt on mismatch.

**Security note to share with the user**: in v2.0, all registered accounts get the full scope set (gmail.readonly + gmail.labels + gmail.modify + gmail.send + drive). The v1.x "read-only procurement account" structural defense is gone — replaced by:

- The `SAFESPACE_TIER` env var (process-wide; controls which tools the MCP exposes)
- Claude Code's per-call approve UI (you can deny any specific tool call)
- The use-pattern: if a high-risk account shouldn't be reachable, **don't register it**

If a user wants a "procurement account that physically can't send mail", they should run a separate Claude Code session with `SAFESPACE_TIER=read` set in that session's `.env`, OR not register that account at all.

Show a summary and ask the user to confirm before proceeding:

```
About to open <N> browser tabs (one per account):
  1. <email1>
  2. <email2>
  ...

Each tab will request these 5 scopes:
  - gmail.readonly
  - gmail.labels
  - gmail.modify
  - gmail.send
  - drive (full)

Proceed? [yes/no]
```

If user says no, halt. The `.env` from Step 2 remains on disk for re-running the wizard.

---

## Step 4: Run consent loop

Re-resolve PLUGIN_ROOT (the Step 0 assignment may not survive a Bash session boundary):

```bash
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-}"
if [ -z "$PLUGIN_ROOT" ] || [ ! -f "$PLUGIN_ROOT/src/cli.ts" ]; then
  PLUGIN_ROOT=$(ls -dt "${HOME}/.claude/plugins/cache/safespace/safespace-mcp"/*/ 2>/dev/null | head -1 | sed 's|/$||')
fi
if [ -z "$PLUGIN_ROOT" ] || [ ! -f "$PLUGIN_ROOT/src/cli.ts" ]; then
  echo "error: cannot resolve PLUGIN_ROOT — re-install plugin or set \$CLAUDE_PLUGIN_ROOT manually" >&2
  exit 1
fi
echo "Plugin code root: $PLUGIN_ROOT"
```

For each email collected in Step 3, run consent. The loop is inlined here (no helper script needed in v2.0 — single dir, single env file, single scope set):

```bash
PLUGIN_DATA="${HOME}/.claude/plugins/data/safespace-mcp-safespace"
CONFIG_DIR="$PLUGIN_DATA/safespace"
ENV_FILE="$CONFIG_DIR/.env"

# Expand the for-loop arguments to one quoted string per account the user
# provided in Step 3 — N items total, NOT hardcoded to 3. The placeholders
# below are illustrative; replace them with the actual emails from Step 3.
failures=0
for email in "<email1>" "<email2>" "<email3>"; do
  echo
  echo "==> consent: $email"
  echo "    Browser will open. Check all 5 permission boxes, then return here."
  if SAFESPACE_CONFIG_DIR="$CONFIG_DIR" \
       bun --env-file="$ENV_FILE" run "$PLUGIN_ROOT/src/cli.ts" consent "$email"; then
    echo "    OK"
  else
    echo "    FAILED — re-run manually:" >&2
    echo "      SAFESPACE_CONFIG_DIR=\"$CONFIG_DIR\" bun --env-file=\"$ENV_FILE\" run \"$PLUGIN_ROOT/src/cli.ts\" consent \"$email\"" >&2
    failures=$((failures + 1))
  fi
done

if [ "$failures" -gt 0 ]; then
  echo
  echo "$failures consent(s) failed. Address them before continuing." >&2
  exit 1
fi
```

Before invoking, warn the user:

> "About to open `<N>` browser tabs in sequence. For EACH tab:
> - **Check ALL 5 permission boxes** (gmail.readonly + gmail.labels + gmail.modify + gmail.send + drive).
> - Click **Allow**.
> - Return to this terminal. The script will continue automatically.
>
> If a single tab fails, the script reports which one. Re-run that consent manually with the printed command."

Replace `<email1> <email2> <email3>` in the for-loop with the actual emails. If a consent fails, surface that to the user with the printed retry command.

---

## Step 5: Verify

Run `account-list` against the new single profile to confirm what landed:

```bash
SAFESPACE_CONFIG_DIR="$PLUGIN_DATA/safespace" \
  bun --env-file="$PLUGIN_DATA/safespace/.env" \
  run "$PLUGIN_ROOT/src/cli.ts" account-list
```

Expected output:
- **N rows** (one per email the user registered in Step 3)
- **SCOPES column = 5** for each (gmail.readonly + gmail.labels + gmail.modify + gmail.send + drive)

If any account is missing or has a scope count != 5, tell the user which one and offer the retry command from Step 4.

Optionally set the active account (the default account the proxy will use when a tool call doesn't specify one):

```bash
# Default to the first email the user gave, or ask which to set active.
SAFESPACE_CONFIG_DIR="$PLUGIN_DATA/safespace" \
  bun --env-file="$PLUGIN_DATA/safespace/.env" \
  run "$PLUGIN_ROOT/src/cli.ts" account-switch "<chosen-email>"
```

---

## Step 6: Success

Print:

```
SafeSpace MCP v2.0 is ready.

The plugin manifest already registered the `safespace` MCP server — no
`claude mcp add` needed. Restart your Claude Code session to load it.

Current tier: <TIER> (from .env)
  read    safe-by-default; only search & read tools exposed
  write   gmail_send, gmail_modify_message, drive_share_file (user)
  share   anyone-with-link Drive sharing

To change tier later: edit $PLUGIN_DATA/safespace/.env and restart Claude
Code. The proxy reads SAFESPACE_TIER at startup; per-call escalation is
not supported by design — flip the env var and restart.

Try (after restarting Claude Code):
  "Use safespace to search my Gmail for invoice"
  "Use safespace to draft a reply from <email>"   (only if tier=write or share)

Weekly reminder: Google's External + Testing mode expires refresh tokens
after 7 days. Run this to renew (opens N browser tabs):
  bash $PLUGIN_ROOT/scripts/renew-tokens.sh
```

Add an entry to the user's calendar / reminder system if they want. Done.

---

## On failure

If anything in Steps 0-5 fails, halt and:
1. Show the user the exact error output.
2. Suggest the most likely fix (missing tool → install; invalid creds → re-check GCP Console; consent fail → re-run that one command; legacy dirs detected → run `safespace migrate-v2`).
3. Mention that the wizard is **idempotent**: they can re-run `/safespace-setup` at any time. Steps that already succeeded (env file in place, accounts already consented) can be skipped via the keep/overwrite prompts.
