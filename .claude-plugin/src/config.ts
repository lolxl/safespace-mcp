// v1.67 D8 — the single catalog of SafeSpace environment variables.
//
// WHY THIS FILE EXISTS
// -------------------
// SafeSpace reads ~30 `SAFESPACE_*` env vars. Before v1.67 each one's NAME was
// a string literal declared ad-hoc in the module that read it, and the parsing
// IDIOM (strict-truthy, two-layer, numeric, …) was copy-pasted with its
// security reasoning re-derived per file. Two real drift risks followed:
//
//   1. No single place lists every env var → no `.env.example`, hard to audit
//      "what does SafeSpace read", a rename can orphan a doc. Each connector
//      adds more (LINE alone added 3).
//   2. The strict-truthy `=== "true"` idiom was copy-pasted across 5 security
//      flags. A 6th author writing `Boolean(env)` / `=== "True"` would SILENTLY
//      widen the truthy surface of a security flag — the worst kind of drift.
//
// This module is the fix: ONE catalog of names (so `.env.example` + audits are
// derivable + a rename is one line) + ONE `readStrictTruthy` helper (so the
// truthy rule can't drift). See `docs/v1.67-config-centralization.md`.
//
// HARD CONSTRAINT — NEVER SNAPSHOT
// --------------------------------
// This module exports NO evaluated config VALUES, only (a) name constants and
// (b) reader FUNCTIONS that read `process.env` LIVE on every call. A snapshot
// (`export const AUTONOMOUS = process.env... === "true"`) would break two
// load-bearing behaviors the whole codebase relies on:
//   - the `*_EXTRA` shell-only overlay (a shell that exports the var mid-session
//     must take effect on the next call — no MCP restart), and
//   - the test suite, which mutates `process.env` between assertions.
// So: name constants + functions only. Keep it a PURE LEAF — no imports from
// `policy/` / `tools/` / `auth/` (anything may import config; config imports
// nothing) so it can never form an import cycle.
//
// THE SIX ENV-VAR IDIOM FAMILIES (and why each differs — read this ONCE here
// instead of re-deriving it per file; `contact-lookup.ts` notes these
// differences are "INTENTIONAL and load-bearing"):
//
//   1. STRICT-TRUTHY  (`=== "true"`, lowercase only) — security on/off flags.
//      A typo ("True"/"1"/"yes"/"") evaluates false, which each call site has
//      chosen to be its SAFE direction (autonomous → today's permissive
//      behavior; monetary → OFF; keyfile-at-rest hatch → refuse-to-start).
//      Parsed ONLY by `readStrictTruthy` below. § §2.2.
//   2. LEGACY `=== "1"` — `tier.ts`'s `SAFESPACE_ENABLE_{SEND,MODIFY,
//      DRIVE_SHARE}` ONLY. A pre-tier escape hatch kept for back-compat;
//      deliberately NOT migrated to family 1 (changing the accepted token would
//      change behavior). The lone outlier — do not add to it.
//   3. SET-MEMBERSHIP — `SAFESPACE_TIER` ∈ {read,write,share}; an invalid value
//      falls back to "read" with a stderr warning (fails LOUD). `tier.ts` owns
//      the parse.
//   4. SET-VS-UNSET — `SAFESPACE_RECIPIENT_ALLOW` activates on ANY defined value
//      INCLUDING `""` (not a truthy check — presence flips allow-all → deny-
//      unlisted). `recipient-allowlist.ts` owns the parse.
//   5. TWO-LAYER LIST — a persistent base + a shell-only `_EXTRA` overlay, union
//      of valid tokens. FOUR allowlists use it (recipient / tasks-delete /
//      youtube-comment / line) but with DIFFERENT caching, warn-on-`_EXTRA`-
//      only, default posture (off→allow vs off→deny) and state shapes — so the
//      PARSING stays per-file by design (v1.67 §0 dropped a shared helper that
//      would have flattened those differences). This catalog owns only the
//      name PAIRS.
//   6. NUMERIC TUNING — burst limits + webfetch size/timeout. Parsed per-call by
//      `burst.ts`'s `makeBurstLimitReader` seam and `url-gate.ts` (clamp +
//      default-on-garbage). This catalog owns only the names.
//
// A denied/secret value NEVER appears in errors, doctor, or this file — the
// no-PII-echo invariant the allowlist modules enforce extends to `.env.example`.

// ── Family 1: strict-truthy security flags (`=== "true"`) ──────────────────
/** F2 autonomous/strict deployment mode (v1.53). Flips OFF=allow allowlists to
 *  deny-by-default + gates F4 permanent-delete. */
export const ENV_AUTONOMOUS = "SAFESPACE_AUTONOMOUS";
/** Opt-in name→email contact resolution for gmail_send/calendar (v1.15). */
export const ENV_RECIPIENT_ALLOW_CONTACTS = "SAFESPACE_RECIPIENT_ALLOW_CONTACTS";
/** Enables the FP-prone entropy rule in the F3a outbound secret-shape scan (v1.57). */
export const ENV_OUTBOUND_SECRET_EXTRA = "SAFESPACE_OUTBOUND_SECRET_EXTRA";
/** Unlocks revenue metrics on youtube_analytics_query + requests the monetary scope (v1.61). */
export const ENV_YOUTUBE_ANALYTICS_MONETARY = "SAFESPACE_YOUTUBE_ANALYTICS_MONETARY";
/** Escape hatch: allow FileBackend key-at-rest under autonomous mode (v1.55 F6). */
export const ENV_ALLOW_KEYFILE_AT_REST = "SAFESPACE_ALLOW_KEYFILE_AT_REST";
/** Company-deployment hardening assertion (v1.86). When "true" the bootstrap
 *  REFUSES to start unless the SafeSpace-side hardening knobs hold (autonomous
 *  mode on / non-keyfile token store / non-all-interfaces bind). A typo → false →
 *  today's non-enforced posture (safe direction). See `policy/enforced-mode.ts`. */
export const ENV_ENFORCED = "SAFESPACE_ENFORCED";
/** TLS-termination attestation for the plaintext HTTP listener (v1.94 A2). When
 *  "true" it RELAXES the enforced-mode all-interfaces bind gate: the operator
 *  attests an external TLS-terminating proxy fronts the listener (and restricts who
 *  can reach it). SafeSpace's listener is `node:http`/plaintext and CANNOT verify
 *  this — it is the same deployment-external responsibility as the egress lockdown
 *  (docs/SOLE-EGRESS.md). A typo → false → the bind gate stays a hard fail (safe
 *  direction). ONLY relaxes the bind gate; never weakens auth. See
 *  `policy/enforced-mode.ts`. */
export const ENV_TLS_TERMINATED = "SAFESPACE_TLS_TERMINATED";

// ── Family 2: legacy `=== "1"` tier escape hatches (tier.ts ONLY) ──────────
/** Pre-tier escape hatch — promote to write-tier send. Token is `"1"`, NOT
 *  `"true"` (family 2; do not route through readStrictTruthy). */
export const ENV_ENABLE_SEND = "SAFESPACE_ENABLE_SEND";
/** Pre-tier escape hatch — promote to write-tier modify. Token `"1"`. */
export const ENV_ENABLE_MODIFY = "SAFESPACE_ENABLE_MODIFY";
/** Pre-tier escape hatch — promote to share-tier drive-share. Token `"1"`. */
export const ENV_ENABLE_DRIVE_SHARE = "SAFESPACE_ENABLE_DRIVE_SHARE";

// ── Family 3: set-membership ───────────────────────────────────────────────
/** Process privilege tier ∈ {read,write,share}; invalid → "read" + stderr. */
export const ENV_TIER = "SAFESPACE_TIER";

// ── Family 4: set-vs-unset + Family 5: two-layer list allowlists ───────────
/** Recipient allowlist base (v2.2; set-vs-unset activation). */
export const ENV_RECIPIENT_ALLOW = "SAFESPACE_RECIPIENT_ALLOW";
/** Recipient allowlist shell-only overlay. */
export const ENV_RECIPIENT_ALLOW_EXTRA = "SAFESPACE_RECIPIENT_ALLOW_EXTRA";
/** Tasks-delete target allowlist base (v1.39; off→allow). */
export const ENV_TASKS_DELETE_TARGETS = "SAFESPACE_TASKS_DELETE_TARGETS";
/** Tasks-delete target allowlist shell-only overlay. */
export const ENV_TASKS_DELETE_TARGETS_EXTRA = "SAFESPACE_TASKS_DELETE_TARGETS_EXTRA";
/** YouTube comment target allowlist base (off→DENY — public surface). */
export const ENV_YOUTUBE_COMMENT_TARGETS = "SAFESPACE_YOUTUBE_COMMENT_TARGETS";
/** YouTube comment target allowlist shell-only overlay. */
export const ENV_YOUTUBE_COMMENT_TARGETS_EXTRA = "SAFESPACE_YOUTUBE_COMMENT_TARGETS_EXTRA";
/** v1.106 — YouTube video-metadata write target allowlist base (off→DENY —
 *  a video's title/description is the most public, identity-defining text on
 *  the channel, so its write surface is deny-default like comments / github). */
export const ENV_YOUTUBE_VIDEO_TARGETS = "SAFESPACE_YOUTUBE_VIDEO_TARGETS";
/** YouTube video-metadata write target allowlist shell-only overlay. */
export const ENV_YOUTUBE_VIDEO_TARGETS_EXTRA = "SAFESPACE_YOUTUBE_VIDEO_TARGETS_EXTRA";
/** LINE recipient (userId/groupId/roomId) allowlist base (v1.66; off→allow). */
export const ENV_LINE_RECIPIENT_ALLOW = "SAFESPACE_LINE_RECIPIENT_ALLOW";
/** LINE recipient allowlist shell-only overlay. */
export const ENV_LINE_RECIPIENT_ALLOW_EXTRA = "SAFESPACE_LINE_RECIPIENT_ALLOW_EXTRA";
/** Telegram recipient (chat_id / @username) allowlist base (v1.68; off→allow). */
export const ENV_TELEGRAM_RECIPIENT_ALLOW = "SAFESPACE_TELEGRAM_RECIPIENT_ALLOW";
/** Telegram recipient allowlist shell-only overlay. */
export const ENV_TELEGRAM_RECIPIENT_ALLOW_EXTRA = "SAFESPACE_TELEGRAM_RECIPIENT_ALLOW_EXTRA";
/** Discord recipient (channel_id snowflake) allowlist base (v1.69; off→allow). */
export const ENV_DISCORD_RECIPIENT_ALLOW = "SAFESPACE_DISCORD_RECIPIENT_ALLOW";
/** Discord recipient allowlist shell-only overlay. */
export const ENV_DISCORD_RECIPIENT_ALLOW_EXTRA = "SAFESPACE_DISCORD_RECIPIENT_ALLOW_EXTRA";
/** Slack recipient (channel/group/DM/user id) allowlist base (v1.95; off→allow). */
export const ENV_SLACK_RECIPIENT_ALLOW = "SAFESPACE_SLACK_RECIPIENT_ALLOW";
/** Slack recipient allowlist shell-only overlay. */
export const ENV_SLACK_RECIPIENT_ALLOW_EXTRA = "SAFESPACE_SLACK_RECIPIENT_ALLOW_EXTRA";
/** Mattermost recipient (channel_id) allowlist base (v1.107; off→allow). */
export const ENV_MATTERMOST_RECIPIENT_ALLOW = "SAFESPACE_MATTERMOST_RECIPIENT_ALLOW";
/** Mattermost recipient allowlist shell-only overlay. */
export const ENV_MATTERMOST_RECIPIENT_ALLOW_EXTRA = "SAFESPACE_MATTERMOST_RECIPIENT_ALLOW_EXTRA";
/** GitHub WRITE target (owner/repo) allowlist base (v1.71; off→DENY — PUBLIC surface,
 *  mirrors the youtube-comment-targets default-deny, NOT the recipient off→allow). */
export const ENV_GITHUB_WRITE_TARGETS = "SAFESPACE_GITHUB_WRITE_TARGETS";
/** GitHub WRITE target allowlist shell-only overlay. */
export const ENV_GITHUB_WRITE_TARGETS_EXTRA = "SAFESPACE_GITHUB_WRITE_TARGETS_EXTRA";
/** GitHub MERGE target (owner/repo) allowlist base (v1.82; off→DENY). SEPARATE from
 *  WRITE_TARGETS: merging to a default branch is IRREVERSIBLE, a higher bar than
 *  opening a PR / commenting, so the operator opts a repo into "agent may MERGE" on its
 *  own list. */
export const ENV_GITHUB_MERGE_TARGETS = "SAFESPACE_GITHUB_MERGE_TARGETS";
/** GitHub MERGE target allowlist shell-only overlay. */
export const ENV_GITHUB_MERGE_TARGETS_EXTRA = "SAFESPACE_GITHUB_MERGE_TARGETS_EXTRA";
/** GitHub APPROVE target (owner/repo) allowlist base (v1.90; off→DENY). SEPARATE from
 *  WRITE_TARGETS: an APPROVE review vouches for a PR and — under branch protection — can
 *  UNBLOCK a merge, a higher bar than a COMMENT / REQUEST_CHANGES review (which only
 *  comment or block). So the operator opts a repo into "agent may APPROVE" on its own
 *  list; COMMENT / REQUEST_CHANGES stay on the WRITE allowlist. */
export const ENV_GITHUB_APPROVE_TARGETS = "SAFESPACE_GITHUB_APPROVE_TARGETS";
/** GitHub APPROVE target allowlist shell-only overlay. */
export const ENV_GITHUB_APPROVE_TARGETS_EXTRA = "SAFESPACE_GITHUB_APPROVE_TARGETS_EXTRA";
/** X (Twitter) POST account (numeric user id) allowlist base (v1.115; off→DENY —
 *  PUBLIC surface, mirrors github-write / youtube-video default-deny). Entries are
 *  numeric user ids only (`^[0-9]{1,32}$`) — usernames rotate. */
export const ENV_X_POST_ACCOUNTS = "SAFESPACE_X_POST_ACCOUNTS";
/** X POST account allowlist shell-only overlay. */
export const ENV_X_POST_ACCOUNTS_EXTRA = "SAFESPACE_X_POST_ACCOUNTS_EXTRA";

// ── Family 6: numeric tuning (burst + webfetch) ────────────────────────────
/** Universal write-burst sliding-window cap (v1.52 F1; default 60/60s). */
export const ENV_WRITE_BURST_LIMIT = "SAFESPACE_WRITE_BURST_LIMIT";
/** Permanent-delete burst cap (v1.52 F1; default 20/60s). */
export const ENV_DELETE_BURST_LIMIT = "SAFESPACE_DELETE_BURST_LIMIT";
/** YouTube comment-post burst cap. */
export const ENV_YOUTUBE_COMMENT_BURST_LIMIT = "SAFESPACE_YOUTUBE_COMMENT_BURST_LIMIT";
/** YouTube search burst cap. */
export const ENV_YOUTUBE_SEARCH_BURST_LIMIT = "SAFESPACE_YOUTUBE_SEARCH_BURST_LIMIT";
/** web_fetch host allowlist base (v1.65; autonomous+empty = deny-all). */
export const ENV_WEBFETCH_ALLOW = "SAFESPACE_WEBFETCH_ALLOW";
/** web_fetch host allowlist shell-only overlay. */
export const ENV_WEBFETCH_ALLOW_EXTRA = "SAFESPACE_WEBFETCH_ALLOW_EXTRA";
/** web_fetch response body cap (bytes; default 5 MB). */
export const ENV_WEBFETCH_MAX_BYTES = "SAFESPACE_WEBFETCH_MAX_BYTES";
/** web_fetch connect+body timeout (ms; default 10000). */
export const ENV_WEBFETCH_TIMEOUT_MS = "SAFESPACE_WEBFETCH_TIMEOUT_MS";
/** fs_read root allowlist base (v1.75; comma-separated ABSOLUTE dirs; DEFAULT-DENY —
 *  unset = read nothing). A path must resolve (lexically + via realpath) within a root. */
export const ENV_FS_READ_ROOTS = "SAFESPACE_FS_READ_ROOTS";
/** fs_read root allowlist shell-only overlay. */
export const ENV_FS_READ_ROOTS_EXTRA = "SAFESPACE_FS_READ_ROOTS_EXTRA";

// ── Raw string + default / secret / service-token ──────────────────────────
/** Config + token-store directory root (default ~/.config/safespace). */
export const ENV_CONFIG_DIR = "SAFESPACE_CONFIG_DIR";
/** SecretBackend selector (keychain | file; auto-detected when unset). */
export const ENV_SECRET_BACKEND = "SAFESPACE_SECRET_BACKEND";
/** Audit-actor operator id stamped on every audit row (v1.36). */
export const ENV_OPERATOR_ID = "SAFESPACE_OPERATOR_ID";
/** Passphrase for the encrypted FileBackend no-key-at-rest mode (v1.37). */
export const ENV_SECRET_PASSPHRASE = "SAFESPACE_SECRET_PASSPHRASE";
/** LINE channel access token (v1.66). Resolved env→SecretBackend; set via
 *  `safespace line set-token`, NEVER committed or echoed. */
export const ENV_LINE_CHANNEL_TOKEN = "SAFESPACE_LINE_CHANNEL_TOKEN";
/** Telegram bot token (v1.68). Resolved env→SecretBackend; set via
 *  `safespace telegram set-token`, NEVER committed or echoed. */
export const ENV_TELEGRAM_BOT_TOKEN = "SAFESPACE_TELEGRAM_BOT_TOKEN";
/** Discord bot token (v1.69). Resolved env→SecretBackend; set via
 *  `safespace discord set-token`, NEVER committed or echoed. */
export const ENV_DISCORD_BOT_TOKEN = "SAFESPACE_DISCORD_BOT_TOKEN";
/** Slack bot token (v1.95). Resolved env→SecretBackend; set via
 *  `safespace slack set-token`, NEVER committed or echoed. */
export const ENV_SLACK_BOT_TOKEN = "SAFESPACE_SLACK_BOT_TOKEN";
/** Mattermost bot/personal access token (v1.107). Resolved env→SecretBackend; set via
 *  `safespace mattermost set-token`, NEVER committed or echoed. */
export const ENV_MATTERMOST_BOT_TOKEN = "SAFESPACE_MATTERMOST_BOT_TOKEN";
/** Mattermost SELF-HOSTED server base URL (v1.107). Unlike the SaaS service-token
 *  connectors (fixed hosts), Mattermost is self-hosted so its host is per-deployment.
 *  This is CONFIG, not a secret — an https:// URL the OWNER sets once; the connector
 *  pins egress to its host. NOT agent-controlled. */
export const ENV_MATTERMOST_SERVER_URL = "SAFESPACE_MATTERMOST_SERVER_URL";
/** Slack Events webhook SIGNING SECRET (v1.102 W0). The HMAC key the inbound webhook
 *  listener verifies each `POST /webhook/slack` against. Resolved env→SecretBackend;
 *  set via `safespace webhook set-secret slack`, NEVER committed or echoed. Distinct
 *  from the bot token (a different secret, a different reserved key). */
export const ENV_SLACK_WEBHOOK_SECRET = "SAFESPACE_SLACK_WEBHOOK_SECRET";
/** LINE Messaging-API webhook CHANNEL SECRET (v1.103 W1). The HMAC key the inbound
 *  webhook listener verifies each `POST /webhook/line` against. Resolved
 *  env→SecretBackend; set via `safespace webhook set-secret line`, NEVER committed or
 *  echoed. DISTINCT from the LINE channel ACCESS TOKEN (`SAFESPACE_LINE_CHANNEL_TOKEN`)
 *  the outbound line_push_message uses — a different LINE credential, a different key. */
export const ENV_LINE_WEBHOOK_SECRET = "SAFESPACE_LINE_WEBHOOK_SECRET";
// (v1.77 ENV_NOTION_TOKEN retired in v1.78 — Notion became an OAuth source using
//  NOTION_CLIENT_ID / NOTION_CLIENT_SECRET, read raw via process.env like GitHub's.)

// ── X (Twitter) OAuth client (v1.113 — class-A OAuth provider; ZERO tools yet) ──
// Unlike GitHub/Notion (which use bare GITHUB_/NOTION_ prefixes, pre-catalog), X
// is SAFESPACE_-prefixed so it rides the config catalog + drift sentinel. CLIENT_ID
// is required for consent/refresh; CLIENT_SECRET is OPTIONAL (unset → public client
// with client_id in the form body; set → confidential client with HTTP Basic).
/** X OAuth 2.0 client id (required for `safespace consent --provider x` + proactive refresh). */
export const ENV_X_CLIENT_ID = "SAFESPACE_X_CLIENT_ID";
/** X OAuth 2.0 client secret (optional — set for a confidential client; omit for a public/PKCE-only client). */
export const ENV_X_CLIENT_SECRET = "SAFESPACE_X_CLIENT_SECRET";

// ── Model B transport (v1.73 — PR-1) ───────────────────────────────────────
// The opt-in Streamable HTTP transport. Default (unset) = stdio = Model A
// byte-identical. SECURITY: the HTTP listener binds loopback by default and has
// NO operator auth yet (PR-2) — do NOT bind beyond loopback / a trusted tailnet.
/** Transport selector ∈ {stdio (default), http}; any other value → stdio. */
export const ENV_TRANSPORT = "SAFESPACE_TRANSPORT";
/** HTTP listener port when `SAFESPACE_TRANSPORT=http` (numeric; required in http mode). */
export const ENV_HTTP_PORT = "SAFESPACE_HTTP_PORT";
/** HTTP listener bind address (default `127.0.0.1` — loopback only; NEVER defaults
 *  to `0.0.0.0`. For Model B the operator binds the tailscale interface (`100.x.y.z`)
 *  explicitly; a non-loopback bind is the operator's documented choice). */
export const ENV_HTTP_BIND = "SAFESPACE_HTTP_BIND";
/** v1.74 PR-2b — path to the operators.json registry (REQUIRED when
 *  `SAFESPACE_TRANSPORT=http`: maps a verified tailnet login → operator policy).
 *  Default-deny: a login absent from the registry is refused. */
export const ENV_OPERATORS_FILE = "SAFESPACE_OPERATORS_FILE";
/** v1.74 PR-2b — override for the `tailscaled` LocalAPI unix socket path (used to
 *  verify a connection's tailnet identity via WhoIs). Defaults to the standard
 *  Linux path; settable for non-default installs. */
export const ENV_TAILSCALE_SOCKET = "SAFESPACE_TAILSCALE_SOCKET";
/** v1.93 A1 — the HTTP operator-auth source ∈ {tailscale (default), token}; any
 *  other value (unset, a typo) → tailscale (the safe, byte-identical default). In
 *  `token` mode each request authenticates by an `Authorization: Bearer <token>`
 *  resolved (via its HMAC hash) to a registered login, instead of by Tailscale
 *  WhoIs. LOOPBACK-ONLY for now (the enforced-mode bind gate is unchanged). */
export const ENV_AUTH = "SAFESPACE_AUTH";
/** v1.93 A1 — path to the agent-tokens.json store (REQUIRED when
 *  `SAFESPACE_AUTH=token`): maps each bearer token's HMAC hash → a login the
 *  operators registry knows. Default-deny: a token absent from the store (or
 *  expired) is refused. Managed via `safespace agent-token {mint,revoke,list}`. */
export const ENV_AGENT_TOKENS_FILE = "SAFESPACE_AGENT_TOKENS_FILE";

// ── Inbound webhook listener (v1.102 — W0) ─────────────────────────────────
// The opt-in PUBLIC listener that receives provider-pushed messages. SEPARATE
// from the MCP transport (its own port + bind), Model-B only. Unset port = no
// listener = Model A byte-identical. See docs/v1.102-webhook-listener.md.
/** Inbound webhook listener port. Presence ENABLES the listener (the only knob);
 *  unset = no webhook listener. A separate `node:http` server from the MCP transport. */
export const ENV_WEBHOOK_PORT = "SAFESPACE_WEBHOOK_PORT";
/** Inbound webhook listener bind address (default `127.0.0.1`; NEVER defaults to
 *  `0.0.0.0`). The webhook must be publicly reachable by the provider, so the operator
 *  fronts it with a TLS-terminating reverse proxy and (under enforced mode) attests it
 *  via `SAFESPACE_TLS_TERMINATED` — same rule as the MCP `http_bind` gate. */
export const ENV_WEBHOOK_BIND = "SAFESPACE_WEBHOOK_BIND";

/** True iff `process.env[name]` is the literal lowercase string `"true"`.
 *
 *  The STRICT-TRUTHY family-1 reader. Every other value — `"True"`, `"TRUE"`,
 *  `"1"`, `"yes"`, `"on"`, `"false"`, `""`, undefined, any whitespace-padded
 *  variant — returns `false`. Callers depend on this so a typo fails toward
 *  the SAFE direction (each call site documents which direction that is for it).
 *
 *  Read LIVE every call — never snapshot (see the file header): tests mutate
 *  `process.env` and a shell may export the var mid-session. */
export function readStrictTruthy(name: string): boolean {
  return process.env[name] === "true";
}
