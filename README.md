# SafeSpace MCP

**The AI safety gateway for an agent's external surface** — a provider-agnostic safety **envelope** between an AI agent and **any source it touches**: input sanitize + untrusted-content tagging, scope·tier·burst·recipient egress gates, autonomy hardening, `run_id` session forensics, and tokens behind a pluggable `SecretBackend` — with a full audit trail on every call.

The problem it solves: the moment you connect an LLM agent to your real email, files, the open web, or a messaging channel, a prompt-injection payload hidden in that data can try to make the agent exfiltrate secrets, send mail, or delete things. SafeSpace sits between the agent and the outside world as a hardened envelope that enforces **least privilege**, **untrusted-content tagging**, **egress control**, and **full auditability** — regardless of which source is behind it. **The envelope is the product; sources are connectors behind it.**

```
AI agent ──stdio MCP (Model A, local)──────▶  SafeSpace envelope  ──▶  Google Workspace      (OAuth · flagship · 84)
         ──HTTP MCP over a tailnet─────────▶       │                   GitHub · Notion       (OAuth · 14 + 5)
           (Model B · multi-operator)              │                   web-fetch · fs-read   (keyless · SSRF/path-gated)
   sanitize · tier · scope · operator              │                   LINE · Telegram · Discord  (service-token push)
   egress gates · burst · autonomy                 │
   hardening · audit ──────────────────────────────┘
```

**Status:** v1.80.0 — **108 tools** across **8 connectors**: **Google Workspace** (Gmail · Drive · Docs · Calendar · Contacts · YouTube + Analytics · Tasks · Sheets · Slides · Forms — the flagship reference connector, 84 tools), **GitHub** (14), **Notion** (5, multi-workspace), **web-fetch** + **fs-read** (keyless), and **LINE · Telegram · Discord** push (service-token). Three connector classes — **OAuth-account · service-token · keyless** — and two deployment models: **Model A** (local, stdio) and **Model B** (a shared multi-operator server on a private tailnet). Apache-2.0 licensed.

| Connector | Class | Tools | Auth |
|-----------|-------|------:|------|
| Google Workspace | OAuth-account | 84 | OAuth — multi-account |
| GitHub | OAuth-account | 14 | GitHub OAuth App — single account |
| Notion | OAuth-account | 5 | Notion public integration — multi-workspace |
| X (Twitter) | OAuth-account | 3 | X OAuth 2.0 PKCE — multi-account (`x_get_me` + `x_search_recent` + `x_post_create`) |
| web-fetch | keyless | 1 | none — SSRF-gated |
| fs-read | keyless | 1 | none — default-deny path allowlist |
| LINE Official Account | service-token | 1 | channel token in `SecretBackend` |
| Telegram Bot | service-token | 1 | bot token in `SecretBackend` |
| Discord Bot | service-token | 1 | bot token in `SecretBackend` |

> Per-version history lives in [`docs/CHANGELOG.md`](docs/CHANGELOG.md). The north-star framing is in [`docs/safety-gateway-thesis.md`](docs/safety-gateway-thesis.md). This README describes the current release.

---

## Why SafeSpace

Four layers protect you regardless of what the agent (or a malicious document) tries to do:

1. **Tier-based tool exposure.** A single env var `SAFESPACE_TIER=read|write|share` decides which tools the proxy even advertises. `read` (the default) exposes search/read tools only; `write` adds sending, labelling, file creation, RSVP, GitHub issue writes; `share` additionally allows anyone-with-link Drive sharing and the messaging push connectors (LINE / Telegram / Discord). The proxy filters at the MCP `tools/list` boundary, so disallowed tools are **invisible** to the agent — there is no per-call escalation by design. Under Model B the tier is **per operator**.

2. **Tokens never sit in plain text.** Credentials live behind a pluggable `SecretBackend` seam — the **macOS Keychain** by default, or an **encrypted file** (AES‑256‑GCM with an scrypt-derived key from `SAFESPACE_SECRET_PASSPHRASE`) for Linux / headless / portable setups. The same seam holds OAuth tokens (Google · GitHub · Notion) and service tokens (LINE · Telegram · Discord) alike. `accounts.json` is mode `0o600` and holds only metadata — **never tokens**. No telemetry, no cloud.

3. **Untrusted-content tagging.** Every inbound tool response is wrapped in `<untrusted-source>…</untrusted-source>` with zero-width-character stripping and Unicode confusable normalization before it reaches the model, so injected instructions inside your data are clearly framed as data. The sanitize pipeline targets 100% branch coverage as a CI gate.

4. **Egress control + autonomy hardening.** Outbound actions pass centralized egress gates — a recipient allowlist (mail / Drive share / LINE / Telegram / Discord push), a **default-deny** `owner/repo` allowlist for GitHub writes, an outbound secret-shape scan, and tainted-source provenance flagging. For unattended deployments, `SAFESPACE_AUTONOMOUS=true` flips the OFF=allow allowlists to deny-by-default, hard-denies permanent deletes, applies universal write/delete **burst** caps, and refuses to start with a key sitting at rest. Every call — and every policy decision — is recorded to a per-session (`run_id`) JSONL audit trail.

On top of these, source-specific policies add defense-in-depth: a Drive folder/file sharing whitelist, an inbound spreadsheet-formula reject list (blocks `IMPORTRANGE`-class SSRF + phishing), an outbound sanitize pipeline for public surfaces (YouTube comments, GitHub issues), an SSRF URL gate for `web_fetch`, a canonical-path root allowlist for `fs_read`, and per-target allowlists for YouTube comments / Tasks deletes / messaging recipients. See [`SECURITY.md`](SECURITY.md) for the full threat model.

---

## How it works

Every call flows through the envelope — one of three choke points by connector class (`src/tools/with-context.ts` for OAuth, `with-nonoauth-context.ts` for keyless / service-token, `with-all-accounts.ts` for cross-account fan-out), each running the same pipeline:

1. **Resolve the credential** — OAuth account (refresh + 401 force-retry), a service token from the `SecretBackend`, or none (keyless). Connectors are modelled as a `Source` with a `Credential` discriminated union.
2. **Authorize** — the tool's `min_tier` is gated, and for OAuth the `requiredScopes` are checked against the granted set, *before* any network call.
3. **Egress gates** (outbound tools) — recipient allowlist (or the default-deny GitHub repo allowlist) + outbound secret-shape scan on the resolved recipients / body.
4. **Invoke** — the connector's client (the typed `googleapis` SDK for Google; hardened REST clients for GitHub / Notion; a gated `node:https` request for `web_fetch`; the messaging APIs for LINE / Telegram / Discord).
5. **Map errors** — upstream statuses become stable JSON-RPC codes.
6. **Sanitize** — the inbound result is wrapped in `<untrusted-source>` and run through the strip/normalize pipeline (per-source opaque-field skip list).
7. **Audit** — one JSONL line records timestamp, source, tool, account/operator, args SHA‑256, `run_id`, status, and latency. Sharing/egress additionally writes a forensic line with an HMAC‑SHA256-hashed target.

---

## Tools

Tools are gated by **tier** (`read` ⊂ `write` ⊂ `share`) and, for Google connectors, **OAuth scope**. At tier `read`, write/share tools are not advertised at all. The full per-tool list (with every tier, gate, and note) lives in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and the registry (`src/tools/registry/`); the summary:

| Surface | Tools | Tier | What |
|---------|------:|------|------|
| **Gmail** | 17 | read–write | search (+ cross-account), read message/thread/attachment, drafts, labels, filters; `gmail_send` + `gmail_create_draft` (recipient-allowlisted, header-injection guards) |
| **Drive** | 11 | read–share | search (+ cross-account), read content, list permissions; create/copy/rename/move folders & text files; `drive_share_file` (whitelist + recipient-allowlist); `drive_unshare_file` (recovery, every tier) |
| **Docs** | 4 | read–write | read structured; create / append-text / allowlisted `batchUpdate` (7 request types) |
| **Calendar** | 8 | read–write | list/get events, free/busy, calendar list; create/update/delete/RSVP — `sendUpdates="none"` hard-coded (no invite spam) |
| **Contacts** | 5 | read–write | search / name→email (no enumeration oracle) / get; create / update (allowlist-constructed) |
| **YouTube** | 16 | read–write | subscriptions (cross-account), uploads, video, search, comments, playlists, own-channel **Analytics**; comment post/reply/delete (**public + permanent**, empty-default hard-deny allowlist + burst), playlist write + delete |
| **Tasks** | 9 | read–write | lists/get/search (cross-account); create/update/move/clear; `tasks_delete` (**permanent — no trash**, optional target allowlist) |
| **Sheets** | 6 | read–write | read values/metadata; create/append/update/batch — formula **reject-list** (`IMPORTRANGE`-class SSRF/phishing), `RAW`-locked append |
| **Slides** | 3 | read–write | read; create / allowlisted `batchUpdate` (external-URL image/chart/video EXCLUDED — SSRF) |
| **Forms** | 5 | read–write | get form / list+get responses; create / allowlisted modify (nested image-fetch + Drive-artifact rejected) |
| **GitHub** | 14 | read–write | repos, issues, PRs + per-file diffs, commits, file content (READ — the decoded file/diff/issue text is sanitize-wrapped); create issue / comment / update issue (**default-deny `owner/repo` allowlist** + outbound-sanitize REJECT + secret scan; request body allowlist-constructed) |
| **Notion** | 5 | read | search, page, page content (blocks), database query + schema — **multi-workspace** (per-call `account_id` = workspace id or name); attacker-controlled column names + content all sanitize-wrapped |
| **web-fetch** | 1 | read | `web_fetch(url)` through the SSRF gate — scheme/port allowlist, private/metadata-IP block, DNS-rebind IP-pin, per-hop redirect re-gate, size+timeout caps (**keyless — no account**) |
| **fs-read** | 1 | read | `fs_read(path)` through a **default-deny root allowlist** — canonical (symlink-safe) containment, no path-existence oracle, regular files ≤5 MB UTF-8 only (**keyless**) |
| **LINE** | 1 | share | `line_push_message(to, text)` to an allowlisted LINE id — plain TEXT only, secret-shape scanned (**service-token — no OAuth**) |
| **Telegram** | 1 | share | `telegram_send_message(chat_id, text)` to an allowlisted chat — plain TEXT only, no `parse_mode` (**service-token**) |
| **Discord** | 1 | share | `discord_send_message(channel_id, content)` to an allowlisted channel — plain TEXT only, `@everyone`/role mentions hard-disabled (**service-token**) |

> ⚠️ **Public + permanent:** `youtube_video_comment_post` / `youtube_comment_reply` post under your channel identity to anyone who can see the video — gated by write tier, the `youtube.force-ssl` scope, an **empty-by-default hard-deny** target allowlist, and a per-session burst limit. GitHub issue/PR writes (and PR merges) act under your GitHub identity on **public or private repos** — same empty-by-default hard-deny posture (`SAFESPACE_GITHUB_WRITE_TARGETS`; merges have their own stricter `SAFESPACE_GITHUB_MERGE_TARGETS`). `tasks_delete` is **irrecoverable** (the Tasks API has no trash). `drive_share_file` can grant access outside your org — gated by the Drive whitelist + recipient allowlist.

### Scopes (Google connector)

All Google tools' OAuth scopes are requested as a single union at `safespace consent <email>`; tier exposure is enforced at `tools/list`, not at scope time. Broader-granted satisfies narrower-required, never the reverse. The granted set:

`gmail.readonly` · `gmail.labels` · `gmail.modify` · `gmail.send` · `gmail.settings.basic` · `drive` · `documents` · `calendar.events` · `calendar.freebusy` · `calendar.calendarlist.readonly` · `contacts` · `youtube.readonly` · `youtube.force-ssl` · `yt-analytics.readonly` · `tasks` · `spreadsheets` · `presentations` · `forms.body` · `forms.responses.readonly`

Enabling `SAFESPACE_YOUTUBE_ANALYTICS_MONETARY=true` adds the narrow `yt-analytics-monetary.readonly` scope at consent (revenue metrics, opt-in).

The **GitHub** connector uses GitHub's flat OAuth scopes — `read:user` + `repo` (public **and** private repos; which repos a write/merge can touch is bounded by the default-deny target allowlists, not the scope) — requested wholesale at `safespace consent --provider github` and **never mixed into the Google scope union**. The **Notion** connector has no granular scopes: access is exactly the pages/databases the workspace owner shares with the integration. `web-fetch` / `fs-read` (keyless) and LINE / Telegram / Discord (service-token) use no OAuth at all.

---

## Prerequisites

- **A runtime** — **Bun** 1.3+ for the Claude Code plugin path (`brew install oven-sh/bun/bun`); or **Node ≥ 20** for the `npx` / other-MCP-client path (the published package ships a prebuilt bundle, so consumers need no Bun — see [`docs/CLIENTS.md`](docs/CLIENTS.md)).
- **Google Cloud OAuth client** (Desktop app type) — `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET` in `.env`. See [`.env.example`](.env.example).
  - ⚠️ **Publish the OAuth consent screen to "In production"** (Google Cloud Console → *APIs & Services → OAuth consent screen* → **Publish app**). An app left in the default **"Testing"** status issues **refresh tokens that expire after 7 days** — you would have to re-run `safespace consent` every week. Because SafeSpace is **self-hosted with _your own_ OAuth client**, the "Google hasn't verified this app" prompt is expected and correct — you are the app's author *and* its only user, so you are the right party to trust it; click *Advanced → Go to \<app\>*. **No Google verification is required** (that process targets public multi-tenant SaaS, which SafeSpace is not). **Google Workspace users** can instead set the **user type to "Internal"** — no 7-day expiry and no warning at all, but it requires a Workspace org and confines the app to that org's accounts. After changing either setting, re-run `safespace consent <email> --re-auth` to mint a fresh long-lived token.
- **GCP APIs enabled** in the same project as the OAuth client: Gmail, Drive, Docs, Calendar, People (Contacts), YouTube Data API v3 + YouTube Analytics API, Tasks, Sheets, Slides, and Forms.
- **(optional) GitHub OAuth App** — `GITHUB_CLIENT_ID` + `GITHUB_CLIENT_SECRET` in `.env`, then `safespace consent --provider github` (only for the GitHub tools).
- **(optional) Notion public integration** — `NOTION_CLIENT_ID` + `NOTION_CLIENT_SECRET` in `.env`, then `safespace consent --provider notion` (only for the Notion tools; multi-workspace = consent once per workspace).
- **(optional) LINE / Telegram / Discord** — a channel/bot token, set via `safespace line|telegram|discord set-token` (stdin; never echoed).
- **(optional) `fs_read`** — set `SAFESPACE_FS_READ_ROOTS` to the directories the agent may read (unset = reads nothing).

No Python required — SafeSpace calls the `googleapis` SDK directly. `web_fetch` and `fs_read` need no account or API.

---

## Deployment models

**Model A — local (default).** One human operator, one local process, MCP over stdio. Nothing listens on any port. This is the plugin install below.

**Model B — shared multi-operator server.** One deployment serves several trusted people (e.g. co-managing a YouTube channel). Set `SAFESPACE_TRANSPORT=http`, bind a **Tailscale** interface (never `0.0.0.0`), and list operators in `operators.json`. Connection identity is the **verified tailnet login**, read from the local `tailscaled` WhoIs API — a peer-IP fact of the WireGuard tunnel, not a forgeable client header; unlisted or unidentified peers get a generic 403. Each operator gets a per-operator **tier** and **`allowedAccounts`** confinement (operator A can never resolve, fan out to, or self-send to operator B's accounts), every audit row carries the operator, and the registry **hot-reloads** — removing an operator revokes their live session on their next call, no restart. Docker runbook: [`docs/DEPLOY.md`](docs/DEPLOY.md); design rationale: [`docs/model-b-deployment.md`](docs/model-b-deployment.md).

---

## Install as a Claude Code plugin (recommended)

The repo ships `.claude-plugin/plugin.json`, `.claude-plugin/.mcp.json` (declares the single `safespace` MCP server), and `.claude-plugin/marketplace.json`. Two-step install:

```bash
# 1. Register this repo as a Claude Code marketplace.
claude plugin marketplace add lolxl/safespace-mcp

# 2. Install the plugin.
claude plugin install safespace-mcp@safespace

# Restart Claude Code, then run /safespace-setup in any session.
```

Per-user state lives at `${CLAUDE_PLUGIN_DATA}/safespace/`, which resolves to `~/.claude/plugins/data/safespace-mcp-safespace/safespace/` on macOS.

### Recommended path: the `/safespace-setup` wizard

After installing, **run `/safespace-setup` in any Claude Code session**. It is idempotent (re-running skips completed steps) and walks you through:

1. Pre-flight checks (and refuses if legacy v1.x profile dirs exist — run `safespace migrate-v2` first).
2. GCP OAuth client checklist (links + verification).
3. Client ID / Secret entry + **tier choice (read / write / share)**, written to `.env` at mode `0600`.
4. Account collection with email validation (1 to ~10 accounts).
5. Consent loop — opens a tab per account requesting the full scope set.
6. Verification via `account-list`; optionally set the active account.

### Manual setup (alternative to the wizard)

```bash
PLUGIN_DATA="${HOME}/.claude/plugins/data/safespace-mcp-safespace"
mkdir -p "$PLUGIN_DATA/safespace" && chmod 700 "$PLUGIN_DATA/safespace"

install -m 0600 /dev/stdin "$PLUGIN_DATA/safespace/.env" <<EOF
GOOGLE_CLIENT_ID=<your-client-id>.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-<your-secret>
SAFESPACE_TIER=read
EOF

SAFESPACE_CONFIG_DIR="$PLUGIN_DATA/safespace" \
  bun --env-file="$PLUGIN_DATA/safespace/.env" \
  run "${CLAUDE_PLUGIN_ROOT}/src/cli.ts" consent you@example.com
```

The plugin manifest already registers the MCP server — no `claude mcp add` needed. Restart Claude Code after consent finishes.

---

## Install via npx (Antigravity, Codex, or any MCP client)

SafeSpace is a standard MCP **stdio** server — the same safety envelope runs no matter which agent launches it. Clients without the Claude Code plugin system (Google Antigravity / Gemini, OpenAI Codex, Cursor, Claude Desktop, …) launch it on **plain Node** (no Bun) via the npm package:

```json
{
  "command": "npx",
  "args": ["-y", "safespace-mcp"],
  "env": {
    "SAFESPACE_CONFIG_DIR": "/Users/you/.safespace",
    "SAFESPACE_TIER": "read",
    "GOOGLE_CLIENT_ID": "<your-id>.apps.googleusercontent.com",
    "GOOGLE_CLIENT_SECRET": "GOCSPX-<your-secret>"
  }
}
```

`npx -y safespace-mcp` runs the **server**; one-time consent + the posture check run through the same package:

```bash
npx -y -p safespace-mcp safespace consent you@example.com
npx -y -p safespace-mcp safespace doctor
```

The npm tarball ships a prebuilt Node bundle, so consumers need only **Node ≥ 20** (Bun is a build-time tool, not a runtime dependency). Per-client config (Codex `config.toml`, Antigravity/Gemini + Cursor/Desktop `mcpServers` JSON), the required env block, and Windows notes are in **[Running from any client → `docs/CLIENTS.md`](docs/CLIENTS.md)**.

---

## CLI

```
safespace consent <email> [--re-auth] [--provider google|github|notion]
                                                        # OAuth consent flow (Google takes an email;
                                                        # GitHub / Notion discover the identity)
safespace account-list [--provider …]                   # list accounts/workspaces; * marks active
safespace account-switch <id> [--provider …]            # persist active account / workspace
safespace account-revoke <id> [--provider …]            # revoke + wipe local state
safespace migrate-v2 [--dry-run]                        # one-shot v1.x → v2.0 data migration
safespace status [--json]                               # tier, account count, last call
safespace doctor [--deep] [--json]                      # diagnostic checks (deps, file modes, schema)
safespace whitelist {list|add <id> --type <folder|file>|remove <id>}   # mutate drive-whitelist.json
safespace recipient {list|add <email|@domain>|remove <email|@domain>}  # mutate the recipient allowlist
safespace line {set-token|status|clear-token}           # LINE channel token (stdin; never echoed)
safespace telegram {set-token|status|clear-token}       # Telegram bot token (stdin; never echoed)
safespace discord {set-token|status|clear-token}        # Discord bot token (stdin; never echoed)
safespace audit {recent|stats|deletes|policy-decisions|suspicious|sessions}  # read-only log analysis
safespace exec <tool> [--account <email>] --params <json> [--raw]      # run an MCP tool from the CLI
```

### Invoking `safespace`

The examples show `safespace <subcommand>` as if it were on `$PATH`. In practice, invoke via the plugin paths:

```bash
# Plugin install (most users):
PLUGIN_DATA="${HOME}/.claude/plugins/data/safespace-mcp-safespace"
PLUGIN_ROOT=$(ls -dt "${HOME}/.claude/plugins/cache/safespace/safespace-mcp"/*/ | head -1 | sed 's|/$||')
SAFESPACE_CONFIG_DIR="$PLUGIN_DATA/safespace" \
  bun --env-file="$PLUGIN_DATA/safespace/.env" \
  run "$PLUGIN_ROOT/src/cli.ts" status

# Local clone (developers / contributors):
cd .claude-plugin
bun --env-file="$PLUGIN_DATA/safespace/.env" run src/cli.ts status
```

> Bun runs the TypeScript directly — there is no build step.

### `safespace audit` — read-only log analysis

Six sub-subcommands inspect `${CLAUDE_PLUGIN_DATA}/safespace/audit.jsonl` without writing a `jq` pipeline. The JSONL reader is O(1) memory regardless of log size, and every sub-subcommand is read-only.

```bash
safespace audit recent [--limit N=50] [--include-events] [--json]
safespace audit stats  [--since YYYY-MM-DD] [--json]
safespace audit deletes [--window 24h] [--threshold N=5] [--json]
safespace audit policy-decisions [--since YYYY-MM-DD] [--json]
safespace audit suspicious [--window 24h] [--threshold N=3] [--json] [...opt-in flags]
safespace audit sessions [--json]
```

- **`recent`** — last N rows (default 50, max 1000); event rows hidden unless `--include-events`. Hashes truncated to 12 hex chars.
- **`stats`** — counts grouped by tool / account / status.
- **`deletes`** — density alert for destructive write tools. Exits 1 if any window exceeds the threshold (handy in cron). Tier-denied attempts are excluded.
- **`policy-decisions`** — distribution of `policy_decision` values per audit channel, driven by the channel registry.
- **`suspicious`** — density alert for **prompt-injection canaries** (formula rejects, outbound sanitize rejects) at a lower default threshold. Output is aggregate counts only — never raw hashes, args, URLs, or titles.
- **`sessions`** — groups rows by `run_id` (one MCP process lifetime) with a per-session anomaly verdict.

### `safespace exec` — call tools from any non-Claude client

Runs a tool through the **same** auth / sanitize / audit / tier middleware Claude uses, emitting one JSON line on stdout. Useful for cron jobs and scripts.

```bash
safespace exec gmail_search \
  --params '{"query": "category:promotions newer_than:1d", "max_results": 20}' | jq '.messages[0]'
```

- Pass the account via `--account <email>`, not inside `--params`.
- `--raw` skips the `<untrusted-source>` wrap for non-LLM consumers. **Only safe when the caller is not an LLM** — it emits a loud stderr warning and records `"sanitize":"bypassed"` in the audit log.

---

## Configuration

The full catalog of environment variables (grouped by parsing idiom, with security notes) lives in [`.env.example`](.env.example) and is the single source of truth in `src/config.ts`. The essentials:

| Env var | Purpose |
|---------|---------|
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | OAuth Desktop-app credentials (required for Google connectors). |
| `SAFESPACE_TIER` | `read` (default) / `write` / `share`. Process-wide; controls which tools `tools/list` advertises. |
| `SAFESPACE_CONFIG_DIR` | Override the config dir. Plugin install uses `${CLAUDE_PLUGIN_DATA}/safespace`; local CLI defaults to `~/.config/safespace`. |
| `SAFESPACE_SECRET_BACKEND` / `SAFESPACE_SECRET_PASSPHRASE` | `keychain` or `file`; the passphrase derives the AES‑256‑GCM token-file key (scrypt; no key at rest). |
| `SAFESPACE_AUTONOMOUS` | `"true"` (strict lowercase) → unattended mode: deny-by-default allowlists, permanent-delete deny, refuse key-at-rest. |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | GitHub OAuth App credentials (optional — GitHub connector only). |
| `NOTION_CLIENT_ID` / `NOTION_CLIENT_SECRET` | Notion public-integration credentials (optional — Notion connector only). |
| `SAFESPACE_RECIPIENT_ALLOW` / `_EXTRA` | Recipient allowlist for `gmail_send` / `gmail_create_draft` / `drive_share_file (user)`. `_EXTRA` is a shell-only overlay. |
| `SAFESPACE_LINE_RECIPIENT_ALLOW` / `_EXTRA`, `SAFESPACE_TELEGRAM_RECIPIENT_ALLOW` / `_EXTRA`, `SAFESPACE_DISCORD_RECIPIENT_ALLOW` / `_EXTRA` | Recipient allowlists for the messaging push connectors. |
| `SAFESPACE_GITHUB_WRITE_TARGETS` / `_EXTRA` | **Default-deny** `owner/repo` allowlist for GitHub writes — unset = every GitHub write denied. |
| `SAFESPACE_FS_READ_ROOTS` / `_EXTRA` | **Default-deny** root allowlist for `fs_read` — unset = reads nothing. |
| `SAFESPACE_WEBFETCH_ALLOW` / `_EXTRA` | Optional host allowlist for `web_fetch` (autonomous + empty = deny-all). |
| `SAFESPACE_TRANSPORT` / `SAFESPACE_HTTP_PORT` / `SAFESPACE_HTTP_BIND` | `http` switches on the Model B Streamable-HTTP transport (default `stdio`). Bind a tailnet interface — never `0.0.0.0`. |
| `SAFESPACE_OPERATORS_FILE` / `SAFESPACE_TAILSCALE_SOCKET` | Model B operator registry (`login → operatorId / tier / allowedAccounts`, hot-reloaded) + the `tailscaled` LocalAPI socket for WhoIs identity. |
| `SAFESPACE_OPERATOR_ID` | Model A operator handle stamped on every audit row (not a secret). Model B resolves the operator per connection instead. |
| `SAFESPACE_*_BURST_LIMIT` | Write / delete / YouTube burst caps (sane defaults; see `.env.example`). |

### Per-session tier override

Bun's `--env-file` does not override a variable already set in the parent shell. Since each Claude Code session spawns its own `safespace` subprocess, you can set the tier per session without editing `.env`:

```bash
SAFESPACE_TIER=share claude    # this session = full Drive sharing
SAFESPACE_TIER=read  claude    # another terminal = read-only
claude                         # falls back to .env (or "read")
```

`safespace doctor` reports the effective tier so you can confirm the override took.

---

## Audit log

Every call appends one JSON line to `${CLAUDE_PLUGIN_DATA}/safespace/audit.jsonl`:

```json
{"ts":"2026-06-09T10:23:45.123Z","run_id":"…","source":"google-workspace","tool":"gmail_search","account":"alice@example.com","argsHash":"sha256:…","status":"ok","duration_ms":412}
```

Egress (mail / share / messaging push) additionally writes a forensic line with an HMAC‑SHA256-hashed target (salt at `${configDir}/audit-salt`, mode `0o600`). The file is `0o600`, the config dir `0o700`. The proxy never logs tokens, raw args, or response bodies.

---

## Upgrading

Both upgrade paths are idempotent and reversible (old state is renamed, not deleted).

**From v0.3.x or earlier (two-profile → single-profile):** the pre-v2.0 layout had separate `safespace-read/` + `safespace-send/` dirs. Run `safespace migrate-v2 --dry-run` to preview, then `safespace migrate-v2` (old dirs renamed to `*.migrated/`).

**When a release adds an OAuth scope**, existing accounts must re-consent once: `safespace consent <email> --re-auth` (the `--re-auth` flag is required so Google re-displays the consent screen). Run sequentially per account. Tier still gates exposure, so consenting to a write scope does not expose write tools at tier `read`.

---

## Error codes (selected)

SafeSpace returns stable JSON-RPC `code` values for proxy-layer rejections — log readers may pattern-match on them. There are **27** SafeSpace-specific codes; the full set is in `src/errors.ts` (`ERROR_CODES`). A representative slice:

| Code | Symbol | Notes |
|------|--------|-------|
| -32023 | `comment_target_denied_by_policy` | YouTube comment target not in `SAFESPACE_YOUTUBE_COMMENT_TARGETS`. |
| -32027 | `outbound_sanitize_rejected` | Outbound comment text rejected by the 6-step pipeline. |
| -32029 | `formula_rejected` | A `USER_ENTERED` cell uses a rejected function (`IMPORTRANGE`-class SSRF / phishing). |
| -32030 | `tasks_delete_denied_by_policy` | `tasks_delete` target not in `SAFESPACE_TASKS_DELETE_TARGETS`. |
| -32031 | `secret_store_corrupt` | The encrypted token file can't be decrypted (wrong passphrase / tamper / corruption). |
| -32032 | `write_burst_limit_exceeded` | The universal write/delete burst cap tripped. |
| -32033 | `destructive_denied_in_autonomous_mode` | A permanent-delete was refused under `SAFESPACE_AUTONOMOUS`. |
| -32034 | `tainted_recipient_denied` | An outbound recipient came from untrusted content (autonomous mode). |
| -32035 | `outbound_secret_rejected` | An outbound body matched a secret SHAPE (autonomous mode). |
| -32036 | `url_blocked_by_policy` | `web_fetch` blocked by the SSRF gate (`data.reason` names the cause). |
| -32037 | `web_fetch_failed` | `web_fetch` operational failure (DNS, connect, timeout, content-type). |
| -32038 | `line_api_failed` | LINE push failed (no token / auth / rate-limit / invalid recipient). Telegram / Discord / GitHub / Notion API failures use `-32039` / `-32040` / `-32041` / `-32045` with the same closed-set-reason shape. |
| -32042 | `github_write_denied_by_policy` | GitHub write target not in `SAFESPACE_GITHUB_WRITE_TARGETS` (default-deny; the target is never echoed). |
| -32043 | `path_blocked_by_policy` | `fs_read` path outside the root allowlist (no path-existence oracle). |

---

## Documentation

- [`docs/safety-gateway-thesis.md`](docs/safety-gateway-thesis.md) — the north-star framing (envelope = product, sources = connectors)
- [`SECURITY.md`](SECURITY.md) — security policy + threat model
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — architecture overview + full tool list
- [`docs/DESIGN.md`](docs/DESIGN.md) — full design + addenda chain
- [`docs/CLIENTS.md`](docs/CLIENTS.md) — running SafeSpace from any MCP client (Antigravity / Gemini, Codex, Cursor, Claude Desktop) via `npx`
- [`docs/DEPLOY.md`](docs/DEPLOY.md) — Model B operator runbook (Docker / Tailscale / operators.json)
- [`docs/model-b-deployment.md`](docs/model-b-deployment.md) — Model B design + rationale
- [`docs/CHANGELOG.md`](docs/CHANGELOG.md) — per-version history and per-cycle design-doc index
- [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md) — test inventory
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to contribute · [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)

## License

Apache-2.0 — see [LICENSE](LICENSE).
