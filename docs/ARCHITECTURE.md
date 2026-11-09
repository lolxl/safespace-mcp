# Architecture

How SafeSpace MCP is built and how its security controls compose. This is the
engineering companion to [`SECURITY.md`](../SECURITY.md) — the authoritative
threat model and trust boundary — and [`docs/DESIGN.md`](DESIGN.md), the locked
design decisions. **Read `SECURITY.md` first** for the threat model; this document
focuses on the structure that implements it.

> **Status:** 135 MCP tools across 11 connectors (Google Workspace 89 ·
> GitHub 18 · Notion 10 · X 3 · web-fetch 1 · fs-read 1 · LINE 1 · Telegram 2 ·
> Discord 1 · Slack 5 · Mattermost 4). Deployment: one human operator
> per local process, MCP over stdio.

---

## Part 1 — Software architecture

### Topology

SafeSpace is a **security proxy**, not a library. It sits between the agent and
every external source and mediates every call:

```
┌──────────┐  stdio                    ┌──────────────────────────┐   per-connector client    ┌──────────────────────┐
│ AI agent │ ◄──────────────────────►  │   SafeSpace proxy         │ ◄──────────────────────► │ Google Workspace · X   │
│ (Claude  │                           │   (TypeScript on Bun)     │   googleapis SDK ·       │ GitHub · Notion       │
│  Code …) │                           │                           │   hardened REST ·        │ web-fetch · fs-read   │
└──────────┘                           └──────────────────────────┘   gated node:https        │ LINE·Telegram·Discord │
                                                                                              │ Slack · Mattermost    │
                                                                                              └──────────────────────┘
                              every tool call passes the same envelope:
                              ├─ tier:     visible tools filtered at tools/list + per-call re-check
                              ├─ auth:     SecretBackend (Keychain / encrypted file) issues the credential
                              ├─ egress:   recipient / target allowlists + outbound secret scan (outbound tools)
                              ├─ sanitize: responses wrapped in <untrusted-source> before reaching the agent
                              └─ audit:    a structured JSONL row per call (run_id · source)
```

- **Transport:** stdio MCP only; nothing listens on any port.
- **Stack:** TypeScript on the Bun runtime. Connectors are `Source` descriptors
  behind a `Credential` discriminated union (`oauth` / `service-token` / `none`)
  — the envelope is connector-agnostic.
- **Stateless by design:** SafeSpace stores no user content. The only things that
  touch disk are credentials (behind `SecretBackend`) and the `audit.jsonl` log.

### Module layout (`.claude-plugin/src/`)

| Module | Responsibility |
|---|---|
| `auth/` | `SecretBackend` interface + `KeychainBackend` / `FileBackend`, the token-store facade, Google token refresh (mutex-coalesced, 60s buffer, force-refresh on upstream 401), `service-token-store.ts` (LINE / Telegram / Discord / Slack / Mattermost), `github/` + `notion/` + `x/` (per-provider consent + store + hardened REST/API clients — `x/consent.ts` + `x/pkce.ts` implement the PKCE S256 loopback consent, `x/oauth.ts` the multi-account token store with proactive refresh, `x/client.ts` the hardened `api.x.com` REST client), `oauth-callback.ts` (shared loopback consent server) |
| `tools/source.ts` | The **`Source` descriptor** per OAuth/keyless connector — `authModel`, credential resolution / authorization strategies, per-source sanitize skip-fields, error mapper; `tools/service-token-pack.ts` mirrors it for the 5 class-B service-token connectors (LINE / Telegram / Discord / Slack / Mattermost) |
| `tools/registry/` | Per-tool declarations — `min_tier`, `requiredScopes`, `source`, `direction`, input schema (split per connector behind barrels) |
| `tools/handlers/` | Per-tool implementations — build the connector client, call it, shape the response (split per connector) |
| `tools/with-context.ts` | The **OAuth choke point** (Google / GitHub / Notion / X): resolve account, tier + scope pre-check, resolve credential, run handler, map errors, sanitize, write audit; also fires the pipeline egress descriptor (below) for the OAuth-routed pipeline tools |
| `tools/with-nonoauth-context.ts` | The **keyless / service-token choke point** (web-fetch, fs-read, LINE, Telegram, Discord, Slack, Mattermost) — same envelope, no account resolution |
| `tools/with-all-accounts.ts` | Cross-account `*_all` fan-out (per-account sanitize nonce + audit rows) |
| `tools/egress.ts` | The composite egress gate wrappers (per-connector `enforce*EgressGates`) — recipient/target allowlists, F3a outbound secret-shape scan, tainted-source flag |
| `tools/egress-pipeline.ts` | **Pipeline-fired egress descriptors** (B6.1) — each descriptor's `extract`→`gate` fires at the choke point *before* the handler runs (the choke point owns enforcement; a drifted handler can no longer skip the gate). As of v1.126.0 all 21 `outbound-write` tools are pipeline-fired this way; the sole survivor of the older handler-called posture is `drive_share_file` (bespoke whitelist gate, `HANDLER_GATED_EXTERNAL` — see `tools/egress-coverage.sets.ts` for the live bucket membership). `gmail_send`'s pipeline gate resolves contact names through the google-workspace Source strategy (`source.resolveRecipients`), protected by a gate-stage 401 force-refresh retry (since A3+D) |
| `identity/` | `OperatorContext` / resolvers (env-derived) |
| `sanitize/` | Inbound untrusted-content pipeline + `outbound.ts` REJECT pipeline for public surfaces (100% branch-coverage gate) |
| `sheets/` | `formula-reject.ts` (formula REJECT) + `homoglyph-normalize.ts` (UTS #39 normalization) + `a1.ts` (A1 coordinate parser) |
| `policy/` | Allowlist parsers, burst limiters, autonomy hardening (`autonomous-mode.ts`, `write-burst.ts`, `outbound-secret.ts`, `tainted-source.ts`), the `url-gate.ts` SSRF gate, the `fs-gate.ts` path gate, the `x-post-allowlist.ts` default-deny X post-account gate, `egress-destinations.ts` (the auditable egress-host registry) |
| `audit.ts` | The 8-channel audit registry (`audit/meta-channels.ts`), HMAC hashing, `run_id`, JSONL writer |
| `google-api/client.ts` | The 11 Google SDK client factories (one per API) |
| `tier.ts` | `SAFESPACE_TIER` parsing; scope hierarchy lives in `auth/scopes.ts` |

### Per-call request flow (the choke points)

Every tool call runs the same pipeline, at one of three choke points by
connector class (`with-context.ts` OAuth · `with-nonoauth-context.ts`
keyless / service-token · `with-all-accounts.ts` cross-account fan-out):

1. **Resolve the tier** — a per-call `OperatorContext` (env-derived) supplies `tier`.
2. **Resolve account + credential** — via the connector's `Source` strategies: `args.account_id` → persisted active → per-source last-used (OAuth); a service token from the `SecretBackend`; or none (keyless). Google tokens refresh mutex-coalesced with a 60s buffer + force-refresh on upstream 401.
3. **Pre-flight gate** — `min_tier`, `requiredScopes` (Google), autonomy-hardening gates (permanent-delete deny, write/delete burst caps) — all *before* any network call.
4. **Egress gates** (outbound tools) — recipient / target allowlists + outbound secret-shape scan on the resolved recipients / body. As of v1.126.0 every `outbound-write` tool but `drive_share_file` fires this as a **pipeline-fired egress descriptor** (`tools/egress-pipeline.ts`): the registry def carries `extract`→`gate`, and the choke point runs it *before* the handler — the handler can no longer skip it. `drive_share_file` alone keeps its bespoke handler-called whitelist gate.
5. **Handler** — builds the connector client and calls it (typed `googleapis` SDK; hardened GitHub/Notion REST; the SSRF-gated `web_fetch` request; the path-gated `fs_read`).
6. **Error mapping** — each handler maps upstream statuses to stable `MCPError` codes in its own catch (Google → `toGoogleError`; `web_fetch` → `mapWebFetchError`; `fs_read` → `mapFsReadError`; the REST connectors throw their own `*_api_failed` code directly); an `MCPError` passes through unchanged.
7. **Sanitize** — the result is wrapped in `<untrusted-source-${nonce}>` (per-source opaque-field skip list) before it returns to the agent.
8. **Audit** — one structured JSONL row (timestamp, `run_id`, source, tool, account, args sha256, status, latency; `operator` is always null); sensitive mutations also write a forensic row with hashed targets.

### Tool surface & multi-account

- **135 MCP tools across 11 connectors:** Gmail 17 / Drive 13 / Docs 4 / Calendar 8 / Contacts 5 / YouTube 17 / Tasks 9 / Sheets 6 / Slides 3 / Forms 7 (= Google Workspace 89) · GitHub 18 · Notion 10 · X 3 · web-fetch 1 · fs-read 1 · LINE 1 · Telegram 2 · Discord 1 · Slack 5 · Mattermost 4.
- **Multi-account:** `accounts.json` (schema v2, mode `0600`, metadata only — never tokens) plus a per-account token store; Notion mirrors the same model per workspace. `gmail_search_all` / `drive_search_all` / `tasks_search_all` / `youtube_subscriptions_all` use the `withAllAccounts` middleware to fan a query across accounts in parallel — each account gets a fresh sanitize nonce and its own audit row, plus one aggregate row.

---

## Part 2 — Security architecture

### Trust boundary

SafeSpace's core job is to **contain a compromised or prompt-injected agent**:
even if the model is steered by hostile content it reads (an email, a doc, a
comment, a PR diff, a Notion page), the proxy bounds what it can do.

- One operator per local process over stdio; tokens are per-operator and never
  shared; nothing listens on any port.

The full trust boundary and assumptions live in
[`SECURITY.md`](../SECURITY.md).

### Defense-in-depth layers

Most write/share operations pass several of these. Detail in `SECURITY.md`.

| # | Layer | Mechanism |
|---|---|---|
| 1 | **Privilege tier** (`SAFESPACE_TIER`) | `read`→`write`→`share`. Filters `tools/list` at startup so the agent cannot even see higher-tier tools; a per-call `ctx.tier` re-check backs it up. No per-call escalation. |
| 2 | **Recipient allowlist** | Gates every `gmail_send` / `gmail_create_draft` / `drive_share_file` recipient and all five service-token push targets — LINE / Telegram / Discord / Slack / Mattermost (env two-layer, default unset = allow; deny-by-default under `SAFESPACE_AUTONOMOUS`; one shared factory in `policy/service-token-allowlist.ts`, per-connector id regex). Rejected recipients are HMAC-SHA256 hashed in the audit log, never logged in plaintext. |
| 3 | **Drive share whitelist** | `drive-whitelist.json` folder-subtree + file-ID allowlist at the share boundary (depth-capped parent walk, LRU cache). Malformed config **fails closed**; `unshare` bypasses unconditionally (recovery beats policy). |
| 4 | **Target allowlists** | `SAFESPACE_TASKS_DELETE_TARGETS` tightens `tasks_delete` *above* the tier (opt-in, default allow — a private surface). The public-surface lists are all **empty-by-default hard-deny**: `SAFESPACE_YOUTUBE_COMMENT_TARGETS` · `SAFESPACE_YOUTUBE_VIDEO_TARGETS` (v1.106, `video:<id>` only) · `SAFESPACE_GITHUB_WRITE_TARGETS` · `SAFESPACE_GITHUB_MERGE_TARGETS` (v1.82 — a merge is irreversible, so its own list) · `SAFESPACE_GITHUB_APPROVE_TARGETS` (v1.90 — an APPROVE can unblock a merge under branch protection, so its own list; the review gate is event-conditional) · `SAFESPACE_X_POST_ACCOUNTS` (v1.115, numeric user ids). Notion is the deliberate exception — no target list, because an integration can only reach pages a human shared with it (`SECURITY.md` §14). Denials echo no target. |
| 5 | **Autonomy hardening (F1–F6)** | Universal write/delete **burst caps** (F1); `SAFESPACE_AUTONOMOUS` flips OFF=allow allowlists to deny (F2); tainted-recipient + outbound **secret-shape REJECT** (F3/F3a); permanent-delete hard deny (F4); `run_id` session forensics (F5); refuse-to-start on key-at-rest (F6). |
| 6 | **Inbound sanitize** | Content from any connector → zero-width strip → confusables normalize → pattern flag → truncate → wrap in `<untrusted-source-${nonce}>` (per-source opaque-field skip list). The per-call 16-hex (64-bit) nonce prevents pre-staged closing-tag injection. |
| 7 | **Inbound formula REJECT** (Sheets) | An 11-function REJECT set (`IMPORTRANGE`-class SSRF + phishing) applied *after* NFKC + zero-width strip + UTS #39 homoglyph normalization + bidi strip; a nested-, string-literal-aware scanner closes wrapper smuggling. Rejection → `-32029`. |
| 8 | **Outbound sanitize REJECT** (public surfaces) | Text bound for a public surface — YouTube comments + video metadata, GitHub issues / comments / PRs / reviews / labels, X posts — passes a locked-order 6-step REJECT pipeline → `-32027`. Every outbound request body is allowlist-constructed (injected fields dropped), across GitHub, Notion, X, YouTube and the service-token connectors. |
| 9 | **Network/path gates** (keyless connectors) | `web_fetch`: scheme/port allowlist, private/metadata-IP block, DNS-rebind IP-pin, per-hop redirect re-gate, size + timeout caps. `fs_read`: default-deny root allowlist with canonical (symlink-safe) containment and no path-existence oracle. |
| 10 | **Input-shape gates** | Gmail label-name gates (CR/LF/NUL/NEL/U+2028/U+2029 reject, system-label block, 225-byte cap); batch caps + TRASH/SPAM block; GitHub `owner/repo`/path/ref anti-traversal validation; Notion 32-hex id validation. |

### Secret handling

All credentials — Google / GitHub / Notion OAuth tokens and the LINE / Telegram /
Discord service tokens — live behind a `SecretBackend` interface, selected by
`$SAFESPACE_SECRET_BACKEND` (`keychain` default on macOS, `file` elsewhere):

- **`KeychainBackend`** — macOS Keychain via the OS Security framework.
- **`FileBackend`** — encrypted-at-rest token file (**AES-256-GCM**, **scrypt** key
  derivation). *Passphrase mode* derives the key from your passphrase (no key
  material at rest); *key-file mode* (default) is file-permission-bound to your OS
  user (`0600`) and warns on startup. A corrupt store → `-32031`, recovered by
  re-running consent.

Tokens are **never** logged, never placed in error `data`, never hashed into
`args_hash`. `ToolContext.getAccessToken()` is a **getter, not a field** — an
accidental `JSON.stringify` of a context cannot serialize the bearer token.

### OAuth least privilege

Each Google API requests the **narrowest scope sufficient** for its tools:
`gmail.modify` + `gmail.send` + `gmail.labels` + `gmail.settings.basic` (not
full mail), `documents` / `calendar.events` + `calendar.freebusy` /
`spreadsheets` / `presentations` / `forms.body` / `tasks` / `contacts`, and
`youtube.force-ssl` (**not** full `youtube`, which would grant upload + channel
management — locked-rejected). The one deliberate exception is the full `drive`
scope (no narrower Google scope grants permission changes on arbitrary files
referenced by ID). **Scope governs which APIs; tier governs which tools.**

GitHub requests `read:user` + `repo` (public **and** private repos, v1.83; a
write/merge is bounded by the default-deny target allowlist, not the scope); its
flat scopes never enter the Google scope union. Notion has no
granular scopes — access is the pages the workspace owner shares with the
integration.

**X (Twitter)** is the 4th OAuth provider (class A) and the first non-Google
source with expiring access tokens: a fixed MVP scope set `tweet.read users.read
tweet.write offline.access` (`auth/x/consent.ts`), granted via a **PKCE S256**
loopback consent flow (`auth/x/pkce.ts` — RFC 7636; `auth/x/consent.ts`). Access
tokens (2h) are refreshed **proactively** inside `resolveCredential`
(`auth/x/oauth.ts`) rather than via the choke point's Google-only 401-retry
(`refreshable: false`, `tools/source.ts`). Posting (`x_post_create`) is
bounded by the default-deny `SAFESPACE_X_POST_ACCOUNTS` numeric-account
allowlist (`policy/x-post-allowlist.ts`), not the scope — same pattern as
GitHub's write-target allowlist.

### Audit

Every call writes a structured JSONL row stamped with the per-process **`run_id`**
and the always-present **`source`**. **8 forensic channels** (comment-post,
calendar-mutation, docs-modify, comment-delete, tasks-mutation, sheets-mutation,
playlist-mutation, video-mutation) carry per-operation metadata. Sensitive targets (recipient
emails, doc/task/comment IDs) are **HMAC-SHA256 hashed** with a per-install salt
(`0600`). The `account` identifies which account acted (`operator` is always null since `SAFESPACE_OPERATOR_ID` was retired). **No
plaintext bodies, comment text, or content payloads** ever reach the log — only
hashes, counts, and policy decisions.
`safespace audit {recent,stats,deletes,policy-decisions,suspicious,sessions}`
surfaces it (`sessions` groups rows by `run_id` with a per-session anomaly
verdict).

### Error-code taxonomy

55 `MCPError` codes. The security-relevant ones: `-32027` outbound sanitize
rejected, `-32029` formula rejected, `-32030` tasks-delete denied by policy,
`-32031` secret store corrupt, `-32032` write-burst limit, `-32033` destructive
denied in autonomous mode, `-32034`/`-32035` tainted-recipient / outbound-secret
rejected, `-32036` URL blocked by policy (SSRF gate), `-32042` GitHub write
denied by policy, `-32043` path blocked by policy (fs gate), `-32020` batch too
large, `-32047` egress destination blocked (the connector egress-host registry
backstop), `-32053` Mattermost API failed, `-32054` X API failed, `-32056` X
post denied by policy (the default-deny post-account allowlist).

---

## Where things live

- **Threat model & trust boundary** → [`SECURITY.md`](../SECURITY.md)
- **Locked design decisions** → [`docs/DESIGN.md`](DESIGN.md)
- **Per-version history** → [`docs/CHANGELOG.md`](CHANGELOG.md)
- **PR-level history** → `git log --oneline`
