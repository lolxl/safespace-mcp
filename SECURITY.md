# Security Policy

SafeSpace MCP is a **security-first** MCP proxy for Google Workspace. This
document states what it defends, the trust boundary it assumes, how to report a
vulnerability, and the limitations you should know before deploying it.

Every claim below maps to shipped, tested code under `.claude-plugin/src/`. If
you find a gap between this document and the code, that gap is itself a bug —
please report it.

---

## Supported versions

SafeSpace is pre-1.0 in spirit (rapid point-release cadence). **Only the latest
released minor line receives security fixes.** Check `.claude-plugin/package.json`
for the current version; upgrade before reporting an issue against an older build.

| Version | Supported |
|---------|-----------|
| Latest `1.x` | ✅ |
| Older | ❌ (upgrade first) |

---

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Open a [GitHub private security advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository (**Security ▸ Advisories ▸ Report a vulnerability**). This
keeps the report private until a fix ships, and is the only supported reporting
channel.

Please include: the affected version, a minimal reproduction, the impact, and
(if known) which trust-boundary assumption below it violates. We aim to
acknowledge within a few days; there is no bounty program.

---

## Threat model & trust boundary

### What SafeSpace defends against

SafeSpace sits between an LLM agent (Claude) and Google APIs. Its core job is to
**contain a compromised or prompt-injected agent**: even if the model is steered
by hostile content it reads (an email, a doc, a comment), the proxy bounds what
it can do — which tools exist, who it can message, what it can delete, and how
much damage a single session can cause.

### Deployment model = **Model A** (the trust boundary you must respect)

SafeSpace's supported deployment is **Model A: one human operator per local
process**, speaking MCP over **stdio**.

- **Tokens are per-operator and never shared between operators** — each operator
  runs their own process with their own token store (`SecretBackend`).
- **Policy and audit are shared by operator _convention_** (e.g. a shared
  `drive-whitelist.json` or audit directory), not enforced across operators by
  the proxy.
- `operatorId` (`$SAFESPACE_OPERATOR_ID`) labels the human actor on every audit
  row, distinct from the Google account email.

**Everything in this document holds under Model A.** Two assumptions are
**correct under Model A but would become weaknesses under a (currently
unsupported) multi-tenant "Model B"** — one shared server process loading
multiple operators' accounts behind an auth gateway. They are documented here as
explicit, bounded assumptions, each with its Model-B follow-up:

1. **Self-send implicit allow (`selfEmails`) — partitioned per operator since
   v1.80.** The recipient allowlist implicitly permits sending to the
   operator's *own* Google accounts (`policy/recipient-allowlist.ts`). Under
   Model A every loaded account **is** the operator's, so the global set is
   correct (and unchanged — `allowedAccounts` is `null`). Under Model B the
   exemption is **confined to the calling operator's `allowedAccounts`**
   (v1.80 PR-3): operator A can no longer reach operator B's self address via
   the implicit route, at BOTH consumers (gmail egress + `drive_share_file`).
   Explicit allowlist entries are never narrowed by the partition (membership
   ⟂ provenance).
2. **Per-process = per-operator policy/tier.** The privilege tier and all four
   allowlists resolve from per-process configuration. Under Model A
   (process-per-operator) that **is** per-operator. Per-*session* enforcement —
   one process serving multiple operators at different tiers — is Model B.

**Model B is not built and not supported.** Do not run one SafeSpace process for
multiple distinct operators expecting cross-operator isolation.

### What SafeSpace does **not** defend against

- A compromised host / OS user (it can read the token store subject to file
  permissions — see *Secret handling*).
- The Google account owner themselves (SafeSpace constrains the *agent*, not the
  human who holds the credentials).
- Vulnerabilities in Google's APIs or the underlying SDKs/runtime.
- Model B multi-tenant isolation (above).

---

## Defense layers

These are the shipped, tested controls. They compose; most write/share
operations pass several.

### 1. Privilege tier (`SAFESPACE_TIER`)
`read` (default) → `write` → `share`. At startup the proxy **filters
`tools/list`** so the agent cannot even see tools above the configured tier
(`proxy.ts`); a per-call defense-in-depth re-check (`ctx.tier`, resolved once at
the orchestration choke point) denies any speculative call from a stale tool
list. There is no per-call escalation.

### 2. Recipient allowlist (`gmail_send`, `drive_share_file` user shares)
Two-layer env config: `SAFESPACE_RECIPIENT_ALLOW` (persistent) +
`SAFESPACE_RECIPIENT_ALLOW_EXTRA` (shell-only). Gates every `to`/`cc`/`bcc`
recipient and user-share target (all-or-nothing). Default **unset = allow**
(opt-in). Optional contact-name resolution
(`SAFESPACE_RECIPIENT_ALLOW_CONTACTS`) still passes resolved emails through this
gate — lookup augments input, never bypasses the output gate. Rejected
recipients are **HMAC-SHA256 hashed** in the audit log, never logged in plaintext.

### 3. Drive share whitelist (`drive_share_file`)
`drive-whitelist.json` — a folder-subtree + file-ID allowlist enforced at the
share boundary (parent walk, depth-capped, per-process LRU cache). Malformed
config **fails closed**. `drive_unshare_file` bypasses the whitelist
unconditionally (recovery must beat policy).

**Bounded assumption (v1.42 `drive_move_file`).** The whitelist constrains
share-ability **by location** — "a file is shareable iff its parent chain
reaches a whitelisted folder." `drive_move_file` (tier=`write`) can relocate
any file **into** a whitelisted folder, after which `drive_share_file` would
permit it. This is accepted, not closed: a `write`-tier caller can already
read+re-create content inside the whitelisted subtree by hand, so move adds no
capability the tier didn't already grant. Residual exposure stays bounded by
the **recipient allowlist** *when configured* (user-shares; it is opt-in —
default is allow-all, see §2) and the **`share`-tier requirement** (anyone-links,
unconditional). To keep the location guarantee strict, do not place sensitive
files one move away from a whitelisted folder under a `share`-tier process.
(Separately, every successful move **clears the ancestor LRU cache** so a file
moved *out* of a whitelisted folder cannot be shared via a stale cache hit.)

**Same assumption extends to v1.46 file-write (`drive_create_file` /
`drive_copy_file`).** Both accept an optional `parent_id`, so a `write`-tier
caller can create or copy a file **directly inside** a whitelisted folder,
making it shareable via `drive_share_file` — exactly the relocation-escalation
above, by a different verb. It adds no capability the tier didn't already grant
(create-then-`drive_move_file` already reaches the same state). Neither tool
needs the ancestor-cache clear: `drive_copy_file` mints a brand-new file ID (no
stale cache entry can exist) and `drive_create_file` likewise produces a fresh
ID; only `drive_move_file`, which mutates an *existing* file's parents, must
clear the cache. `drive_rename_file` changes name/description only (never
parents), so it does not interact with the whitelist at all.

### 4. Tasks-delete target allowlist (`tasks_delete`)
Two-layer env config (`SAFESPACE_TASKS_DELETE_TARGETS` / `..._EXTRA`),
`tasklist:<id>` entries, gating a permanently destructive op **above** the tier
check. Default **unset = allow** (opt-in tightening). Denial →
`tasks_delete_denied_by_policy` (`-32030`); the gate fires **before** the SDK
delete and echoes no task/tasklist id.

This allowlist gates the **permanently destructive** `tasks_delete` **only**.
The v1.47 `tasks_clear` (bulk-hide all completed tasks in a list via
`tasks.tasks.clear`) is **recoverable** — it marks completed tasks hidden, it
does not destroy them — so it is gated by the write tier alone (no allowlist),
matching its bounded, reversible blast radius. The v1.47 `tasks_move`
(`tasks.tasks.move`, within-list reparent/reorder) is likewise non-destructive
and write-tier-gated; cross-list move (`destinationTasklist`) is not exposed.

### 5. Blast-radius burst limiters
Per-session counters cap prompt-injection-driven loops:
`SAFESPACE_YOUTUBE_SEARCH_BURST_LIMIT` (default 20) and
`SAFESPACE_YOUTUBE_COMMENT_BURST_LIMIT` (default 10), each clamped 1–100, reset
on restart. `gmail_modify_messages_batch` caps message IDs per batch
(`batch_too_large`, `-32020`) and blocks `TRASH`/`SPAM` on add.

The YouTube **playlist** writes (`youtube_playlist_create` / `playlist_update` /
`playlist_item_insert`, v1.48; `youtube_playlist_item_remove` /
`youtube_playlist_delete`, v1.49) are deliberately **neither** burst-limited
**nor** behind a target allowlist (contrast the public-comment surface): a
playlist is a **channel-owned** object, not a public-broadcast surface, so
write-tier + `youtube.force-ssl` scope is the floor. Each write costs 50 quota
units — surfaced in every tool description so a runaway loop is operator-visible.
(`playlist_create` defaults `privacyStatus:"private"`; setting `public` makes the
title visible, but it remains channel metadata, never content posted onto another
user's video.)

The two **destructive** playlist ops (v1.49) follow the `youtube_comment_delete`
**recovery-bias** posture — write-tier is the floor (deletion destroys content +
audit evidence), `youtube.force-ssl` is enforced, but there is **no** target
allowlist to block an operator from cleaning up their **own** channel.
`youtube_playlist_item_remove` (`playlistItems.delete`) is **recoverable**
(re-add via `playlist_item_insert`) so it is **not** counted in the `safespace
audit deletes` density alert. `youtube_playlist_delete` (`playlists.delete`) is
**permanently irreversible** — YouTube has **no** playlist trash (asymmetric with
Drive's 30-day trash) — so it **is** counted (discriminated by
`operation === "playlist_delete"`, mirroring `tasks_delete`). Both record a
forensic `playlistMutationMeta` row carrying only the SHA-256
`target_playlist_hash` + `operation` + `policy_decision` (never the plaintext
playlist/item id). Neither pre-fetches (TOCTOU-free); Google rejects deleting
playlists/items you don't own with a 403.

### 5a. Autonomous / strict mode (`SAFESPACE_AUTONOMOUS`) — v1.53
The single deployment-mode switch for unattended agents. When
`SAFESPACE_AUTONOMOUS=true` (**strict-truthy**: the literal lowercase `"true"`
only — any other value, including `"True"` / `"1"` / `"yes"` / `""`, leaves it
**off**), the three **`OFF=allow`** allowlists above flip to **deny-by-default**:

- **Recipient allowlist** (layer 2): an unconfigured allowlist denies every
  external recipient (`-32019`); **self-sends stay allowed** (the operator's own
  accounts — no external blast radius). Also gates `drive_share_file` user-shares.
- **Drive share whitelist** (layer 3): an **absent** `drive-whitelist.json` denies
  all shares (`-32018`, decision reason `default_deny_autonomous`).
- **Tasks-delete allowlist** (layer 4): an unconfigured allowlist denies **all**
  `tasks_delete` (`-32030`).

No new error code — the flag only changes **when** the existing
`-32018`/`-32019`/`-32030` fire, with the same no-echo recovery copy. The match
logic of each gate is unchanged; only the default-when-unconfigured flips. The
`youtube-comment-targets` allowlist (layer 8) already defaults to **deny**, so it
is unaffected.

**Failure direction:** a typo evaluates to `false` → the deployment stays in the
permissive interactive default (byte-identical to a deployment without the flag).
A misconfigured flag never silently bricks every write/share/delete; autonomous
mode is an explicit opt-in you set **deliberately** before handing the box to an
unattended agent: *"now nothing leaves unless you listed it."*

### 5b. Autonomous permanent-delete hard-deny (`-32033`) — v1.54 (F4)
Under the same `SAFESPACE_AUTONOMOUS=true` flag, **permanent-delete tools are
hard-denied** at the `with-context.ts` choke point. Permanent deletes rely on a
*soft* control — the tool description tells the model "confirm with the user
first" — which is meaningless when no human is present, so autonomous mode
replaces it with a structural deny:

- The denied set reuses F1's `PERMANENT_DELETE_TOOLS` const Set **verbatim**:
  `tasks_delete`, `youtube_comment_delete`, `youtube_playlist_delete`,
  `calendar_delete_event`, `gmail_delete_draft` (drafts bypass Trash → permanent).
  One set, audited once — F1's burst classifier and F4's deny cannot drift.
- **Recoverable mutations are unaffected**: gmail trash/archive, `tasks_clear`
  (hides completed), `youtube_playlist_item_remove` (re-addable),
  `gmail_delete_filter` (recreatable), `drive_unshare_file` (a recovery action)
  all fall in the write bucket, not this set.
- Denial throws **`-32033 destructive_denied_in_autonomous_mode`** *before* the
  SDK call and *before* the F1 burst counter (a denied delete does not consume
  delete-bucket budget). Recovery copy echoes **no** tool / target (the tool name
  is already on the audit row). Flag unset → no-op, byte-identical to v1.53.

To run a legitimate permanent delete, do it from an interactive (non-autonomous)
session, or via the corresponding Google web UI.

### 5c. Autonomous token-at-rest hardening (`SAFESPACE_ALLOW_KEYFILE_AT_REST`) — v1.55 (F6)
Completes the autonomous-deploy story (deny-external → deny-permanent-delete →
**harden the token at rest**). The autonomous target is a Linux/headless host, so
it uses **FileBackend**, which defaults to **key-file mode** — the AES key sits in
`secret.key` *beside* the ciphertext `secret.enc`. For an *unattended* box that is
backed up / imaged routinely, a single directory/backup snapshot yields both
halves = full **offline** token compromise, no agent interaction needed.

When `SAFESPACE_AUTONOMOUS=true` and FileBackend resolves to key-file mode, the
proxy **refuses to start** (loud stderr + non-zero exit, *before* serving any
tool) unless the operator either:
- sets `SAFESPACE_SECRET_PASSPHRASE` (no key at rest — **recommended**), or
- sets `SAFESPACE_ALLOW_KEYFILE_AT_REST=true` (strict-truthy literal `"true"`) to
  deliberately accept key-beside-ciphertext for this deployment.

KeychainBackend is exempt (the key is OS-guarded, not beside the ciphertext). A
typo'd `SAFESPACE_AUTONOMOUS` fails permissive (no refusal — inherits the F2
fail-toward-permissive contract); the strictness only engages on a
deliberately-set flag.

**Honest boundary — this raises the bar against *offline* capture only.** A
same-host agent that can run arbitrary shell/HTTP with the passphrase in its
environment can still read the *live* token and call Google directly, bypassing
every SafeSpace gate (the **axis-3** path). SafeSpace is a proxy, not a sandbox —
it cannot see around itself. An autonomous deployment **MUST** therefore isolate
the agent's arbitrary-exec capability from SafeSpace's token environment
(separate OS user / container); F6 does **not** and cannot substitute for that
isolation.

**Account-security surface is a deliberate non-goal.** SafeSpace exposes **no**
tool to add a recovery contact, grant an OAuth application, or change 2FA / login
devices, and holds no OAuth scope for any of them. This capability-absence is the
strongest structural defense against consent / recovery-contact phishing — e.g.
the Google app-name *"confused-deputy"* lure where the attacker makes Google's own
servers send a legitimate-looking notification (see
`docs/social-engineering-threat-analysis.md`): an agent driving SafeSpace simply
*cannot* perform the account-takeover step the lure steers toward. (Note
`contacts_create` is People-API *address-book*, a different surface from an
account *recovery contact*.) This omission is intentional and recorded here so a
future cycle does not add such a tool without a re-design.

### 5d. Autonomous outbound enforcement (`-32034` / `-32035`) — v1.57 (F3b-gate + F3a)
Under the same `SAFESPACE_AUTONOMOUS=true` flag, the v1.56 F3 *observability*
signals become *enforcement* — outbound only, and only unattended:

- **F3b-gate** — a `gmail_send` / `gmail_create_draft` whose recipient first
  appeared inside untrusted **body** content this session (the v1.56 tainted-source
  set) is **denied** (`-32034 tainted_recipient_denied`), not just flagged. This is
  **orthogonal to the recipient allowlist**: even an *allowlisted* recipient is
  denied if its value is tainted-source (provenance is independent of membership —
  it catches an address the agent lifted from a malicious doc that happens to be
  allowlisted). The v1.56 `tainted_source` audit flag still fires on the denied row.
- **F3a** — a send/draft **body** containing a mechanically-recognizable secret
  *shape* (a private-key block or a provider API-key: `AKIA…`, `AIza…`, `ghp_…`,
  Slack/Stripe/OpenAI) is **rejected** (`-32035 outbound_secret_rejected`, the
  `reason` names the shape class, never the bytes) before the SDK call. Interactive
  mode records an `outbound_secret_shape` audit flag instead (no block). F3a is the
  *narrow mechanical* fragment of outbound DLP — a closed list of unambiguous
  shapes, **not** a "looks confidential" content judgement; the FP-prone
  high-entropy / verification-code rules are **default OFF** behind the opt-in
  `SAFESPACE_OUTBOUND_SECRET_EXTRA`.

Both are **autonomous-only**: a typo'd flag → no enforcement (inherits the F2
fail-toward-permissive contract); interactive behaviour is byte-identical to v1.56.

### 6. Untrusted-content sanitize pipeline (inbound reads)
Content returned from Google to the agent is run through
(`src/sanitize/`): zero-width strip → Unicode confusables normalize → suspicious-
pattern flag → length truncate → wrap in `<untrusted-source-${nonce}>`. The
per-call **16-hex (64-bit) nonce** prevents pre-staged closing-tag injection.
Opaque fields (IDs, timestamps) are skipped.

### 7. Inbound formula REJECT (Sheets writes)
An 11-function REJECT set (the `IMPORTRANGE`-class SSRF + phishing functions) is
rejected **after** NFKC normalization + zero-width strip + UTS #39
Cyrillic/Greek/Armenian homoglyph normalization + bidi/Default_Ignorable strip
(`src/sheets/`). A nested-formula-aware, string-literal-aware scanner closes
wrapper-smuggling. Rejection → `formula_rejected` (`-32029`).

**Slides batchUpdate — the same SSRF class (v1.60).** `slides_modify`
(`presentations.batchUpdate`) uses a **positive request-type allowlist** (the
load-bearing gate): only `insertText` / `deleteText` / `replaceAllText` /
`createSlide` / `updateTextStyle` / `updateParagraphStyle` are permitted, built
literally (caller `requestBody` is never spread). The image/sheet/video insert
requests — `createImage` / `createSheetsChart` / `createVideo` — are **excluded**
because they take an external URL that **Google's servers fetch** with the user's
identity: the same SSRF class as the Sheets `IMAGE` / `IMPORTRANGE` reject above.
A Google-added request type auto-rejects (not in the allowlist); a
negative-sentinel test pins each known-forbidden type's rejection.

### 8. Outbound sanitize REJECT (public-surface writes)
Text destined for a **public** surface (YouTube comments) passes a locked-order
6-step REJECT pipeline (`src/sanitize/outbound.ts`). Rejection →
`outbound_sanitize_rejected` (`-32027`). Comment *targets* are additionally
gated by `SAFESPACE_YOUTUBE_COMMENT_TARGETS` — note this allowlist **defaults to
deny** (the opposite of the private allowlists), because it writes to a public
surface.

### 9. Gmail label-name gates
Label create/modify rejects CR/LF/NUL/NEL/U+2028/U+2029, blocks system labels,
and caps length at 225 bytes.

### 9a. Gmail filter create gates (v1.51)
`gmail_create_filter` builds the Gmail `Filter` body field-by-field from fixed
allowlists (`buildValidatedFilterCriteria` / `buildValidatedFilterAction`) — any
field outside the allowed set is rejected. Two persistent-abuse vectors are
blocked: (1) the **`forward` action is rejected outright** (a forwarding filter is
a persistent exfiltration channel — every future matching message silently copied
to a third party); it is not a schema property, never copied through the
allowlist-constructed action body, and explicitly rejected with a clear message if
smuggled past the schema. (2) **`addLabelIds` cannot contain TRASH or SPAM** (a
silent auto-delete / auto-spam rule), reusing the `gmail_modify_message`
`system_label_forbidden` block; `removeLabelIds` is unrestricted (INBOX=archive,
UNREAD=mark-read are the legitimate auto-organize use case). Criteria free-text is
header-injection-rejected + 1024-byte-capped; ≥1 criteria and ≥1 action field are
required (an empty criteria would match all mail). A filter is the caller's own
private mailbox config (no recipient blast radius), so tier=write is the only floor
— there is no extra allowlist gate. `gmail_create_filter` / `gmail_delete_filter`
are write-tier; `gmail_list_filters` surfaces any UI-authored `forward` action on
read (SafeSpace never creates one).

### 10. Outbound fetch / SSRF gate (`web_fetch`) — v1.65 (Phase C)

`web_fetch` is the first **keyless** connector: it has no upstream account, so the
new attack surface is the outbound HTTP request itself — classic **Server-Side
Request Forgery**. An agent (possibly steered by prompt-injected instructions in
content it already read) could ask `web_fetch` to hit the host's loopback, a LAN
box, or the cloud-metadata endpoint (`169.254.169.254` → IAM credentials).

The gate (`src/policy/url-gate.ts`) fails **closed** at every step, and crucially
**SafeSpace owns DNS resolution + the connect IP + redirect following** (it uses
`node:dns` + `node:https.request`, NOT an off-the-shelf client that would do those
steps invisibly):

1. **scheme + port allowlist** — `http` / `https` only (rejects `file:`/`ftp:`/
   `gopher:`/`data:`/…), and only the default web ports **80 / 443** (blocks SSRF to
   internal services — Redis 6379, SSH 22, k8s 6443, … — on a non-standard port of a
   genuinely-public IP).
2. **resolve + block private/reserved IPs** — every resolved A/AAAA record is
   checked against loopback, RFC1918, CGNAT, link-local (incl. `169.254.169.254`),
   IPv6 ULA/link-local/multicast/doc/NAT64, and IPv4-mapped IPv6. If **any**
   resolved address is private, the fetch is refused.
3. **IP pinning** — the connection targets a **validated** IP (with the original
   hostname kept for `Host` + TLS SNI), closing the **DNS-rebinding** window between
   check and connect.
4. **per-redirect re-gate** — redirects are followed manually (≤5), re-running the
   whole gate on each hop, so a public URL that 302s to `169.254.169.254` is caught.
5. **size cap + timeout** — streamed body capped at 5 MB (`-32007`); 10 s timeout.
6. **content-type allowlist** — text/JSON/XML only; binary (image/PDF/octet-stream)
   is rejected, never read into context.
7. **host allowlist (optional / autonomous-required)** — `SAFESPACE_WEBFETCH_ALLOW`
   (+`_EXTRA`) tightens to specific hosts; under `SAFESPACE_AUTONOMOUS=true` an unset
   allowlist **denies all** `web_fetch` (deny-by-default, the §5a idiom).

Rejections raise `-32036 url_blocked_by_policy` (policy) or `-32037 web_fetch_failed`
(operational) with a **closed-set `reason`** — never a resolved IP, response byte, or
env value. The fetched body is wrapped by the inbound sanitize pipeline (§6) with an
**empty** SKIP_FIELDS set, so every field of a remote page is treated as untrusted.

### 11. LINE Official Account egress (`line_push_message`) — v1.66 (Phase C)

`line_push_message` is the first **service-token** connector (class B): it
authenticates with one long-lived LINE channel access token (no OAuth, no per-user
refresh). The token is stored behind the same `SecretBackend` as OAuth tokens
(§ Secret handling) under a reserved non-email key, or supplied via the shell-only
`SAFESPACE_LINE_CHANNEL_TOKEN` (env takes precedence). It is read only via the
credential getter when building the `Authorization` header — never logged, echoed
(`safespace line set-token` reads it from stdin, never argv), or serialized.

Because it sends to a recipient, the outbound envelope applies:

1. **Outbound secret-shape gate (F3a, §5d)** — reused verbatim: a body matching a
   private-key / API-key shape is rejected under autonomous mode (`-32035`) /
   flagged interactively, so a secret can't be pushed to a LINE recipient.
2. **LINE recipient allowlist** — `SAFESPACE_LINE_RECIPIENT_ALLOW`(+`_EXTRA`), a
   two-layer allowlist of `U`/`C`/`R` ids (the §2 recipient-allowlist idiom for LINE
   ids). **Default unset = allow** (a private, tier-gated `share` surface — the §4
   tasks-delete posture); **under `SAFESPACE_AUTONOMOUS` an unset/empty allowlist
   denies all** (the §5a deny-by-default idiom). A denied id is HMAC-hashed into the
   audit denied-event, never echoed; the denial reuses `-32019`.
3. **No SSRF-by-proxy** — only `type:"text"` messages are constructible.
   image/sticker/flex/template messages (which carry an `originalContentUrl` LINE's
   servers fetch — the §7 Sheets `IMAGE` / Slides `createImage` class) are
   structurally impossible to send. The LINE API host is hardcoded; the
   user-controlled `to`/`text` go in the request body, never a URL.

Operational LINE API failures raise `-32038 line_api_failed` with a closed-set
`reason` (`no_token`/`auth_failed`/`rate_limited`/`invalid_recipient`/`api_error`) —
no token or recipient id echoed. A 401 (token rejected) has no OAuth re-consent
recovery: the operator re-runs `safespace line set-token`. **Inbound LINE (webhook)
is out of scope** — it is a push model (a public HTTPS endpoint + signature
verification), a separate architecture, deferred.

### 12. X (Twitter) post egress (`x_post_create`) — v1.113 / v1.115

X is SafeSpace's 4th **OAuth** source (class A) and the first non-Google source
whose access tokens expire (2h): consent runs a **PKCE S256** loopback flow
(`src/auth/x/pkce.ts` — RFC 7636 `code_verifier`/`code_challenge`; `src/auth/x/consent.ts`),
never a client-secret-only exchange. Access tokens refresh **proactively** inside
`resolveCredential` (`src/auth/x/oauth.ts`) rather than through the choke point's
Google-only 401-retry (the Source is `refreshable: false`). Fixed MVP scopes:
`tweet.read users.read tweet.write offline.access` (`src/auth/x/consent.ts`).

`x_post_create` (POST `/2/tweets`) is a **public-surface write** — the same threat
class as a GitHub issue or a YouTube comment — so it is gated in a fixed order
(`src/policy/x-post-allowlist.ts`):

1. `SAFESPACE_TIER=write` (proxy tier filter).
2. A valid X OAuth credential (`requireX`; scopes fixed at consent).
3. **`SAFESPACE_X_POST_ACCOUNTS` post-account allowlist** — a two-layer env config
   (`SAFESPACE_X_POST_ACCOUNTS` / `..._EXTRA`) of numeric X **user ids** (usernames
   rotate, so the stable numeric id is required; validated `^[0-9]{1,32}$`).
   **Default empty = HARD-DENY** (the public-surface deny-default idiom, matching
   the YouTube-comment and GitHub-write allowlists — the opposite of the private
   `SAFESPACE_RECIPIENT_ALLOW` default). Denial raises
   `-32056 x_post_denied_by_policy`; the account id is never echoed.
4. **F3a outbound secret-shape scan** + the standard `outboundSanitize` REJECT
   pipeline (`tools/egress.ts enforceXPostEgressGates`) on the post text.

Before any of the above, a **local weighted-280 precheck** (`src/tools/handlers/x.ts`)
rejects an over-limit post with **zero network calls**: URLs cost 23 weighted
characters each (`https?://\S+`), CJK/Hangul/fullwidth/emoji code points cost 2,
everything else costs 1 (`X_WEIGHTED_MAX = 280`).

Operational X API failures raise `-32054 x_api_failed` with a **closed-set**
`reason` — the status code alone decides it (`429`→`rate_limited`, `401`→
`consent_required`, everything else→`api_error`), **never** the X error body's
free-text `title`/`detail` (`src/auth/x/client.ts`). No token, refresh token, or
user id is echoed. The request body is allowlist-constructed (`{text}` only — no
reply/quote fields), so a caller cannot smuggle extra API parameters through.

---

## Secret handling

OAuth tokens live behind a `SecretBackend` interface (`src/auth/`), selected by
`$SAFESPACE_SECRET_BACKEND` (strict `keychain`|`file`; default `keychain` on
macOS, `file` elsewhere):

- **`KeychainBackend`** — macOS Keychain via the OS Security framework.
- **`FileBackend`** — encrypted-at-rest token file (**AES-256-GCM**, **scrypt**
  key derivation) for Linux/headless/portable use, with two modes:
  - **Passphrase mode** (`SAFESPACE_SECRET_PASSPHRASE` set) — the key is derived
    from your passphrase; **no key material sits at rest**.
  - **Key-file mode** (default, no passphrase) — tokens are encrypted, but the
    key sits beside the ciphertext. Protection is **file-permission-bound to
    your OS user (`0600`)** — it is **not** robust against whole-directory or
    backup capture. The server warns about this on startup; set a passphrase for
    no-key-at-rest protection. **Under `SAFESPACE_AUTONOMOUS=true` the server
    refuses to start in this mode** unless `SAFESPACE_ALLOW_KEYFILE_AT_REST=true`
    (v1.55 F6 — see §5c).
  - A corrupt/undecryptable store → `secret_store_corrupt` (`-32031`), recovered
    by re-running consent.

Additional guarantees:
- **Tokens are never logged**, never placed in error `data`, never hashed into
  `args_hash`.
- `ToolContext` exposes `getAccessToken()` as a **getter, not a field** — so an
  accidental `JSON.stringify` of a context (logging, audit, JSON-RPC error)
  cannot serialize the bearer token (functions are dropped by `JSON.stringify`).

### Cryptographic algorithm pinning (no algorithm-confusion surface)
SafeSpace's keyed-MAC / signature surface — the inbound **bearer-token hash**, the
inbound **webhook signature verification** (Slack/LINE), and the tamper-evident
**audit MAC chain** — pins **HMAC-SHA256** at compile time (`src/crypto-algorithms.ts`).
The algorithm is **never** read from a request header, a token field, or config; it is
not caller-controllable. Critically, SafeSpace has **no JWT/JOSE `alg`-header decode
path** — so there is no HS-vs-RS confusion and no `none` downgrade to defend against;
the live algorithm-confusion attack surface is already zero. The pin exists to **keep**
it zero: a regression (a future connector inlining a weaker algorithm, or making one
configurable) trips a sentinel test (`src/crypto-algorithms.test.ts`) rather than
silently weakening a MAC. Non-keyed content digests (dedup keys, args-hash stamps,
passphrase fingerprints) are out of scope — they are not authentication.

### OAuth scopes — least-privilege per API
SafeSpace requests the **narrowest scope sufficient** for each API's implemented
tools (`tools/registry/scopes.ts`): `gmail.modify` + `gmail.send` +
`gmail.labels` + `gmail.settings.basic` (the v1.51 filter scope — **not** the
broader `gmail.settings.sharing`, which would grant forwarding-address / delegate
management; SafeSpace exposes filters only), `documents`/`calendar.events`/
`spreadsheets`/`tasks`, `contacts`, and `youtube.force-ssl` (**not** full `youtube`,
which would grant upload + channel management — locked-rejected). `youtube.force-ssl`
is the single management scope behind both the comment writes and the v1.48
playlist writes (`playlists.*` + `playlistItems.*`), so playlists added no new scope.
The `contacts` scope was **upgraded** from `contacts.readonly` in v1.50 to
authorize the People write tools (`contacts_create` / `contacts_update`); it is
the narrowest scope that can write — there is no contacts write-only scope. A
contact email later resolved into `gmail_send` (`SAFESPACE_RECIPIENT_ALLOW_CONTACTS`)
still passes the recipient-allowlist OUTPUT gate, so write access to contacts
cannot bypass the send allowlist (the v1.15 "you trust your own Contacts" trust
boundary is unchanged).

The one deliberate exception is **Drive**: the full `drive` scope is required
because no narrower Google scope grants permission-modification on *arbitrary*
files the user references by ID (`drive.file` only covers app-created files).
This is documented at `scopes.ts:10-16`. The privilege **tier** is the runtime
authorization gate over *which tools* are callable; OAuth scope governs *which
APIs* the account consented to.

**Opt-in scope expansion — YouTube Analytics monetary (v1.61).** The most
sensitive YouTube-Analytics datum — *revenue* (estimatedRevenue, ad revenue, CPM,
monetized playbacks) — is gated behind an explicit deployment-mode flag
`SAFESPACE_YOUTUBE_ANALYTICS_MONETARY` (**strict-truthy**: the literal lowercase
`"true"`; any other value is OFF). The flag is the single switch that (a) makes
the consent ceremony additionally request the narrow `yt-analytics-monetary.readonly`
scope, and (b) unlocks the revenue metrics in `youtube_analytics_query`'s metric
allowlist. With the flag **unset** (the default) the monetary scope is **never
requested** — a deployment that does not opt in never holds a revenue-capable
token (minimum privilege at the OAuth layer, not only the handler) — and the
revenue metrics are not in the effective allowlist, so a revenue metric is
rejected. A typo / misconfig evaluates to OFF: the failure direction is toward
*less* access, never toward silently exposing revenue. `youtube_analytics_query`
remains own-channel-only (`ids=channel==MINE` is forced) and read-only regardless.

**Google Forms (v1.62 read, v1.63 write) — responses are UNTRUSTED + the write
gate excludes nested SSRF.** The read tools (`forms_get`, `forms_list_responses`,
`forms_get_response`) treat **form responses as attacker-influenced free text** —
anyone with the form link can submit arbitrary content — so the response payload
(answers + `respondentEmail`) rides the **same inbound sanitize pipeline**
(`<untrusted-source>` wrap) as an inbound email body or a Drive document; there is
no handler-local sanitize and no `SKIP_FIELDS` carve-out. `formId` / `responseId`
are url-safe-regex validated, and the `time_after` response filter is
allowlist-constructed (`timestamp >= <RFC3339>`), never a raw filter string.

v1.63 added the write tools (`forms_create`, `forms_modify`) and **upgraded the
scope** `forms.body.readonly` → full `forms.body` (the v1.50 contacts pattern;
re-consent; the read tools stay satisfied via the pre-loaded SCOPE_HIERARCHY;
`forms.responses.readonly` is unchanged — responses stay read-only). `forms_create`
is title-only (constructs `{info:{title}}` explicitly). `forms_modify`
(`forms.batchUpdate`) enforces a POSITIVE top-level request-type allowlist
(`createItem`/`deleteItem`/`moveItem`/`updateItem`/`updateFormInfo`/`updateSettings`)
**plus a bounded deep recursive scan** of each `createItem`/`updateItem` item tree
that rejects the whole request if it contains `sourceUri` (an external image URL
Google fetches = **SSRF**, the Sheets `IMAGE` / Slides `createImage` class — it can
nest inside `imageItem` OR `questionItem.image`, hence the deep scan rather than a
top-level key check), `imageItem`, `videoItem`, or `fileUploadQuestion` (provisions
a Drive folder). v1 supports text-based items only; the image/video/upload surface
is a deliberate later gated cycle. The write tools are `min_tier: write`, so the F1
universal write-burst limiter already covers them.

---

## Audit

Every tool call writes a structured JSONL audit row (`src/audit.ts`):
- **8 forensic channels** (comment-post, calendar-mutation, docs-modify,
  comment-delete, tasks-mutation, sheets-mutation, playlist-mutation,
  video-mutation) carry per-operation metadata.
- Sensitive targets (recipient emails, document/task/comment IDs) are
  **HMAC-SHA256 hashed** with a per-install salt
  (`~/.config/safespace/audit-salt`, mode `0600`).
- The human **`operator`** (plaintext, from `$SAFESPACE_OPERATOR_ID`) and the
  Google `account` email (plaintext by design) identify who acted.
- **No plaintext message bodies, comment text, or content payloads** ever reach
  the audit row — only hashes, counts, and policy decisions.
- `safespace audit {recent,stats,deletes,policy-decisions,suspicious}` surfaces
  the log for review.

---

## Known limitations / out of scope

- **Model B multi-tenancy** (shared server, auth gateway, non-stdio transport,
  per-session policy/tier, scoped `selfEmails`) — designed-for but **not built**;
  see the trust-boundary section.
- **Homoglyph coverage** is a curated map (Latin/Cyrillic/Greek/Armenian).
  Full UTS #39 confusables vendoring and Hebrew look-alikes are deliberately
  deferred (`docs/CARRY-FORWARD.md`) pending a concrete observed bypass.
- SafeSpace constrains the **agent**, not a malicious host or the credential
  holder.

---

_For the full security-control design and rationale, see `docs/DESIGN.md`
and `docs/CHANGELOG.md`._
