// MCP error code table per docs/DESIGN.md §MCP Error Code Table (Issue 5A).
// SECURITY NOTE: account_not_found / refresh_token_invalid recovery hints
// surface the email back to Claude on purpose (so Claude can render the
// `safespace consent <email>` recovery command). Revisit when this becomes
// open-source / shared-context.

export type ErrorName =
  | "sanitize_failed"
  | "tool_not_found"
  | "keychain_locked"
  | "account_not_found"
  | "scope_mismatch"
  | "rate_limited"
  | "refresh_token_invalid"
  | "file_too_large"
  | "file_unsupported_binary"
  | "system_label_forbidden"
  | "label_limit_exceeded"
  | "share_role_forbidden"
  | "share_target_forbidden"
  | "share_expiration_required"
  | "share_expiration_forbidden"
  | "share_denied_by_policy"
  | "recipient_denied_by_policy"
  | "batch_too_large"
  | "download_stalled"
  | "recipient_lookup_failed"
  | "comment_target_denied_by_policy"
  | "video_target_denied_by_policy"
  | "youtube_quota_exceeded"
  | "comment_burst_limit_exceeded"
  | "search_burst_limit_exceeded"
  | "outbound_sanitize_rejected"
  | "value_render_option_rejected"
  | "formula_rejected"
  | "tasks_delete_denied_by_policy"
  | "secret_store_corrupt"
  | "write_burst_limit_exceeded"
  | "destructive_denied_in_autonomous_mode"
  | "tainted_recipient_denied"
  | "outbound_secret_rejected"
  | "url_blocked_by_policy"
  | "web_fetch_failed"
  // ── `*_api_failed` brand set — FROZEN as of v1.118 (pack step 3, arch-review F8) ──
  // The per-connector `*_api_failed` names — the class-B service-token cluster below
  // (line / telegram / discord / slack / mattermost) PLUS the class-A OAuth connectors
  // further down (github_api_failed / notion_api_failed / x_api_failed) — form a CLOSED
  // 8-member set. Rationale: every connector so far minted its OWN brand code, growing
  // this global, closed error taxonomy LINEARLY with connectors, across two hand-synced
  // growth points (here + `ServiceTokenErrorName` in
  // tools/handlers/service-token-fetch.ts). The set is now FROZEN: a FUTURE connector
  // must NOT add a 9th `*_api_failed` name — it reuses a shared generic code to be
  // designed at that time through the owner gate. Enforced by the sentinel in
  // errors.test.ts ("*_api_failed brand set — FROZEN"); adding a new brand name here
  // fails that sentinel until the freeze is revisited at the owner gate.
  // (Work-order note: pack step 3 named 7 members and omitted notion_api_failed; the
  // ERROR_CODES table below is the source of truth — the real frozen set is these 8.)
  | "line_api_failed"
  | "telegram_api_failed"
  | "discord_api_failed"
  | "slack_api_failed"
  | "mattermost_api_failed"
  | "send_approval_required"
  | "github_api_failed"
  | "github_write_denied_by_policy"
  | "github_merge_denied_by_policy"
  | "github_approve_denied_by_policy"
  | "path_blocked_by_policy"
  | "fs_read_failed"
  | "notion_api_failed"
  | "x_api_failed"
  | "x_post_denied_by_policy"
  | "egress_destination_blocked"
  | "internal_routing_error"
  | "telegram_ack_denied_in_autonomous_mode";

/** B6.1-B — the FROZEN `*_api_failed` brand set as a TYPE, derived from the union
 *  above by suffix (template-literal Extract) so it can NEVER drift from ErrorName:
 *  adding a 9th `*_api_failed` member up there automatically widens this type and
 *  fails the errors.test.ts freeze sentinel. The authoritative statement of the
 *  client-layer error-mapping CONTRACT (who maps, where, and the three deliberate
 *  handler-level exceptions) lives in src/auth/http/connector-error-contract.ts. */
export type ConnectorApiFailedName = Extract<ErrorName, `${string}_api_failed`>;

interface Spec {
  code: number;
  recovery: string;
}

export const ERROR_CODES: Record<ErrorName, Spec> = {
  sanitize_failed:       { code: -32000, recovery: "Content processing failed, possibly an unusual format. Try a different search query." },
  tool_not_found:        { code: -32001, recovery: "This tool is not enabled; check the whitelist." },
  // v1.37 BLOCKER 1: recovery copy GENERALIZED (B9 LOCKED). Covers BOTH the
  // macOS Keychain-locked case AND the encrypted FileBackend missing-passphrase
  // / unreadable-key-file case, WITHOUT naming which backend is active to a
  // remote caller (operator-facing guidance, not a backend oracle). Still
  // mentions "Keychain" so existing recovery-copy assertions hold.
  keychain_locked:       { code: -32002, recovery: "Token storage is temporarily inaccessible (the macOS Keychain is locked, or the SAFESPACE_SECRET_PASSPHRASE required by the encrypted token file is not set). Unlock the Keychain or set the passphrase, then retry." },
  account_not_found:     { code: -32003, recovery: "That account is not authorized yet; run `safespace consent <email>`." },
  scope_mismatch:        { code: -32004, recovery: "The tool needs new permissions (v1.12 added the `documents` scope; v1.13 added `calendar.events`; v1.15 added `contacts.readonly`; v1.16 Phase 1a added `youtube.readonly`; v1.16 Phase 2a added `youtube.force-ssl`; v1.19 Phase 1a added `tasks`; v1.20 Phase 1a added `spreadsheets`; v1.45 added `calendar.freebusy` + `calendar.calendarlist.readonly`; v1.50 upgraded `contacts.readonly` to full `contacts` (write); v1.51 added `gmail.settings.basic` (Gmail filters); v1.59 added `yt-analytics.readonly` (YouTube Analytics read-only); v1.60 added `presentations` (Google Slides); v1.61 added `yt-analytics-monetary.readonly` (YouTube Analytics revenue read-only; requested only when opt-in SAFESPACE_YOUTUBE_ANALYTICS_MONETARY=true); v1.62 added `forms.body.readonly` + `forms.responses.readonly` (Google Forms read-only); v1.63 upgraded `forms.body.readonly` to `forms.body` (Forms write: create/edit forms)). Run `safespace consent <email> --re-auth` to re-authorize (the --re-auth flag is required so Google shows the consent screen again to add the new scopes)." },
  rate_limited:          { code: -32005, recovery: "API rate limit reached; retry later." },
  refresh_token_invalid: { code: -32006, recovery: "Authorization expired or revoked; re-run `safespace consent <email>`. A very common cause is a Google OAuth app left in 'Testing' publishing status — Google expires those refresh tokens after 7 days. Fix it once: in the Google Cloud Console, publish your OAuth consent screen to 'In production' (the 'unverified app' prompt is expected for a self-hosted client you authored — click Advanced then 'Go to app'; NO Google verification is required), or set the user type to 'Internal' on Google Workspace. See the README 'Google Cloud OAuth client' note." },
  file_too_large:        { code: -32007, recovery: "File exceeds the 5 MB cap and cannot be downloaded. Open it directly in the Drive web UI." },
  file_unsupported_binary: { code: -32008, recovery: "This file type (PDF / image / binary) is not parsed in v1. Open it in the Drive web UI." },
  // -32009 (send_disabled), -32010 (modify_disabled), -32013 (share_disabled)
  // removed in v2.0. Tier-based tools/list filter in proxy.ts replaces the
  // kill-switch model — Claude never sees a tool above the current tier.
  system_label_forbidden:  { code: -32011, recovery: "Destructive system labels such as TRASH / SPAM cannot be ADDED through this tool. To trash a message or mark it spam, use the Gmail web UI. REMOVING these two labels (e.g. rescuing a message from the trash) is allowed." },
  label_limit_exceeded:    { code: -32012, recovery: "addLabelIds and removeLabelIds are each capped at 10 per call. Split into multiple calls, or use the Gmail web UI for bulk operations." },
  share_role_forbidden:    { code: -32014, recovery: "drive_share_file only allows the reader / commenter roles. Write roles (writer / owner / organizer / fileOrganizer) are not exposed; use the Drive web UI instead." },
  share_target_forbidden:  { code: -32015, recovery: "share_type=anyone requires SAFESPACE_TIER=share. Set SAFESPACE_TIER to share in .env and retry. Note: at tier=share EVERY account loaded by this server can create public links, so do not load high-risk accounts (e.g. procurement) at this tier." },
  share_expiration_required: { code: -32016, recovery: "share_type=user requires expiration_days (1-365). The Google API mandates an expiration on user/group permissions; permanent shares to a specific email are not allowed." },
  share_expiration_forbidden: { code: -32017, recovery: "share_type=anyone (anyone with the link) does not support expiration_days - the Google API does not allow expirations on the anyone permission. For auto-expiry, use share_type=user to invite a specific email instead." },
  share_denied_by_policy:    { code: -32018, recovery: "This file is outside the drive-whitelist.json allowlist, so the share is structurally refused. Add the file parent folder ID (or the file ID itself) to ${PLUGIN_DATA}/safespace/drive-whitelist.json, or re-run /safespace-setup to configure it via the wizard. To temporarily disable the whitelist mechanism, delete the drive-whitelist.json file (reverts to the v2.0 tier-only gate behavior)." },
  recipient_denied_by_policy: { code: -32019, recovery: "The recipient is not in the SAFESPACE_RECIPIENT_ALLOW allowlist. Add SAFESPACE_RECIPIENT_ALLOW=@domain.com,alice@email.com to .env, or start the session with SAFESPACE_RECIPIENT_ALLOW_EXTRA=... claude for a per-session addition. To turn this gate off entirely, delete the SAFESPACE_RECIPIENT_ALLOW line from .env (reverts to the v2.1 behavior, no recipient gate)." },
  batch_too_large:           { code: -32020, recovery: "A single batch call is capped at 100 message IDs (a local prompt-injection blast-radius cap; the Gmail API itself allows 1000). Split into multiple calls, or use the Gmail web UI for bulk operations." },
  download_stalled:          { code: -32021, recovery: "Download stalled; retry once, and check the network if it persists." },
  // v1.15 Phase 3 — gmail_send / calendar_create_event contact-lookup integration.
  // Recovery message is INTENTIONALLY generic: per docs/v1.15-contacts-api.md
  // §11 hook #6, error data MUST NOT echo the queried name or matched emails
  // (would convert the rejection into a contact-enumeration oracle reachable
  // by a prompt-injected Claude). errorData carries ONLY {ambiguous, match_count}
  // when ambiguity triggered the failure — never display_name / email_addresses.
  recipient_lookup_failed:   { code: -32022, recovery: "Contact lookup returned no match or was ambiguous. Use `contacts_search` to find the exact email, then pass that directly to gmail_send / calendar_create_event." },
  // v1.16 Phase 1b — Google YouTube Data API v3.
  // Code -32024 (`youtube_quota_exceeded`) shipped Phase 1b for the daily
  // quota exhaustion class. Code -32026 (`search_burst_limit_exceeded`)
  // shipped Phase 1b for `youtube_search` over-burn protection.
  //
  // v1.16 Phase 2a — Phase 2 write-tier reserved codes -32023 + -32025
  // shipped HERE (Phase 2a infrastructure cycle). Phase 2b will USE these
  // codes from the comment-post / comment-reply handlers (the modules
  // src/policy/youtube-comment-targets.ts + youtube-comment-burst.ts ship
  // in this Phase 2a PR; handler wiring follows in Phase 2b).
  //
  // Recovery messages are INTENTIONALLY generic — per docs/v1.16-youtube-api.md
  // §8 (no PII echo): comment_target_denied_by_policy does NOT echo the
  // rejected video_id / channel_id / playlist_id (would convert the
  // rejection into a probe oracle reachable from prompt-injected Claude).
  comment_target_denied_by_policy: { code: -32023, recovery: "Comment write target is not in SAFESPACE_YOUTUBE_COMMENT_TARGETS allowlist. Add the target as `video:<11-char-id>` / `channel:<UC...22>` / `playlist:<PL... | UU... | LL... | OL... | FL... | RD...>` to the env var, or post directly via the YouTube UI. Default empty = no comment writes permitted even when youtube.force-ssl scope is granted." },
  // v1.106 — youtube_video_update target deny. No video_id is echoed (PII-oracle
  // defense, mirrors comment_target_denied_by_policy -32023 / github_write -32042).
  video_target_denied_by_policy: { code: -32052, recovery: "Video-metadata write target is not in the SAFESPACE_YOUTUBE_VIDEO_TARGETS allowlist. A video's title / description is the most public, identity-defining text on your channel, so editing it is deny-default (like comment writes): add the target as `video:<11-char-id>` (comma-separated) to SAFESPACE_YOUTUBE_VIDEO_TARGETS in your .env, or per-session via SAFESPACE_YOUTUBE_VIDEO_TARGETS_EXTRA, or edit directly via YouTube Studio. Default empty = no video-metadata writes permitted even when youtube.force-ssl scope is granted. The target video id is not echoed." },
  youtube_quota_exceeded:    { code: -32024, recovery: "YouTube API daily quota exhausted. Quota resets at midnight Pacific Time. Future calls today will fail; revisit tomorrow OR request a quota increase via Google Cloud Console." },
  comment_burst_limit_exceeded: { code: -32025, recovery: "YouTube comment-write burst limit reached for this MCP session (covers both youtube_video_comment_post and youtube_comment_reply). Restart Claude or set SAFESPACE_YOUTUBE_COMMENT_BURST_LIMIT higher (max 100). The limit caps prompt-injection blast radius — raise deliberately." },
  search_burst_limit_exceeded: { code: -32026, recovery: "youtube_search burst limit reached for this MCP session (each call = 100 quota units; cap protects against prompt-injection loops). Restart Claude (= new MCP session) OR raise SAFESPACE_YOUTUBE_SEARCH_BURST_LIMIT (max 100). The limit caps quota over-burn — raise deliberately." },
  // v1.16 Phase 2b — outbound sanitize pipeline rejection (src/sanitize/outbound.ts).
  // Applies to PUBLIC text being POSTED via SafeSpace (youtube_video_comment_post /
  // youtube_comment_reply). REJECT (not strip) zero-width chars, length-cap,
  // wrapper-close pattern, truncate-marker literal, inbound warning-preamble
  // pattern. Discriminator in errorData.reason ∈ {zero_width, length_exceeded,
  // wrapper_close, truncate_marker, warning_preamble}. See docs/v1.16-youtube-api.md
  // §9 + sec-rev hook #13.
  //
  // Recovery message is INTENTIONALLY generic — no echo of the rejected text
  // (would convert the rejection into a probe oracle for a prompt-injected
  // Claude). errorData carries ONLY the reason enum + a class-level detail
  // string; no payload content.
  outbound_sanitize_rejected: { code: -32027, recovery: "Outbound text rejected by SafeSpace sanitize policy. Common causes: contains zero-width characters (potential evasion attempt), exceeds the 10000-byte YouTube comment limit, or contains a SafeSpace control sequence (`</untrusted-source-...>`, `<safespace-truncated/>`, or the inbound warning preamble). Rewrite the text without these patterns and retry." },
  // v1.20 Phase 1b-1 — sheets_get_values value_render_option allowlist
  // (design §2.1 + §11 Q4 LOCKED + sec-rev hook #20). The Google Sheets
  // value_render_option enum has three values {FORMATTED_VALUE,
  // UNFORMATTED_VALUE, FORMULA}; SafeSpace allowlists only the first two.
  // FORMULA rendering would leak user secrets (paired-sheet IDs, external
  // service tokens via IMPORTRANGE referrer, named-cell references). When
  // the handler rejects, errorData carries `reason: "formula_rendering_rejected"`
  // (closed-enum discriminator mirroring v1.16 `-32027 outbound_sanitize_rejected`).
  //
  // Recovery message is INTENTIONALLY generic — does NOT echo the rejected
  // value (no PII echo per design §10 hook #13 / cross-API invariant).
  value_render_option_rejected: { code: -32028, recovery: "value_render_option=FORMULA is not allowed (design section 11 Q4 LOCKED - formula content leak). Use FORMATTED_VALUE or UNFORMATTED_VALUE instead." },
  // v1.21 Phase 1b — sheets_update_values + sheets_batch_update formula REJECT
  // list (`src/sheets/formula-reject.ts`). Applied to cell strings starting
  // with `=`/`+` when `value_input_option === "USER_ENTERED"`. 11 functions
  // REJECTED case-insensitively (post-NFKC normalize) — IMPORTRANGE / IMPORTXML
  // / IMPORTHTML / IMPORTDATA / IMPORTFEED (SSRF cross-sheet/external fetch),
  // HYPERLINK (phishing-link injection), GOOGLEFINANCE / GOOGLETRANSLATE
  // (external API fetch), IMAGE (SSRF via image URL fetched with sheet-owner
  // identity), WEBSERVICE (Excel-compat external fetch), LAMBDA (one-step
  // nested bypass closure P3). errorData carries closed-enum
  // `reason: "formula_rejected"` (single-value discriminator mirroring -32027
  // / -32028 precedent) + separate `rejected_formula_function: string` field
  // carrying the UPPERCASED function name (bounded value space — no PII echo
  // risk; 11-item closed set).
  //
  // Recovery message is INTENTIONALLY generic — does NOT echo the rejected
  // cell content (cross-API NO-PII invariant per design §10 hook #13).
  formula_rejected: { code: -32029, recovery: "Formula function rejected by SAFESPACE_SHEETS_REJECT_LIST (design section 3 / Q2 LOCKED - SSRF + phishing + external-fetch attack surface). Use a non-external formula, or set value_input_option to RAW (the formula will be stored as a string)." },
  // v1.37 BLOCKER 1 (B5 LOCKED) — encrypted FileBackend NON-retryable failure
  // class: GCM auth-tag failure (wrong passphrase OR tamper — deliberately
  // CONFLATED so the error is not an oracle), bad magic, truncated/unknown
  // header, or decrypted-payload-not-JSON. Distinct from keychain_locked
  // (-32002, the RETRYABLE locked/missing-passphrase class). -32030 is RESERVED
  // for the BLOCKER 4 policy layer (roadmap Q9), so this takes -32031.
  //
  // Recovery is INTENTIONALLY generic and carries NO key material / path /
  // ciphertext / wrong-passphrase-vs-tamper distinction (cross-cycle no-leak
  // invariant; the auth-tag failure is conflated by design — §4.5).
  secret_store_corrupt: { code: -32031, recovery: "The encrypted token file is corrupt or cannot be decrypted (wrong passphrase, tampering, or file damage). Re-run `safespace consent <email>` to re-authorize." },
  tasks_delete_denied_by_policy: { code: -32030, recovery: "Tasks delete target is not in the SAFESPACE_TASKS_DELETE_TARGETS allowlist — this delete's tasklist is not permitted. Add it as `tasklist:<tasklist-id>` to SAFESPACE_TASKS_DELETE_TARGETS (persistent) or SAFESPACE_TASKS_DELETE_TARGETS_EXTRA (shell-only), or delete via the Google Tasks UI. Default unset = all deletes allowed (tier still gates); the allowlist is opt-in tightening." },
  // v1.52 F1 (Autonomy Hardening) — universal write/delete burst guard
  // (policy/write-burst.ts). Sliding-window rate cap on state-changing calls;
  // READS ARE EXEMPT. errorData.reason ∈ {write, delete} (closed-enum
  // discriminator mirroring -32027/-32028/-32029). Recovery is generic — NO
  // payload / tool / target echo; mirrors the youtube session-burst codes
  // -32025/-32026.
  write_burst_limit_exceeded: { code: -32032, recovery: "Write/delete burst limit reached for this MCP session (blast-radius cap for autonomous agents; errorData.reason ∈ {write,delete}). Wait for the rolling window to clear, raise SAFESPACE_WRITE_BURST_LIMIT / SAFESPACE_DELETE_BURST_LIMIT, or restart Claude. The cap bounds runaway-loop damage from an unattended agent — raise it deliberately." },
  // v1.54 F4 (Autonomy Hardening) — permanent-delete hard-deny under autonomous
  // mode (policy/autonomous-mode.ts enforceAutonomousDeleteDeny). When
  // SAFESPACE_AUTONOMOUS=true the soft "confirm with the user first" control on
  // permanent-delete tools is meaningless (no human present), so the proxy
  // denies them structurally — BEFORE the SDK call, before the F1 burst counter.
  // Reuses F1's PERMANENT_DELETE_TOOLS set (tasks_delete / youtube_comment_delete
  // / youtube_playlist_delete / calendar_delete_event / gmail_delete_draft);
  // RECOVERABLE mutations (write bucket) are unaffected. Recovery is generic — NO
  // tool / target echo (the tool name is already on the audit row); mirrors the
  // no-PII-echo convention of the other policy-deny codes.
  destructive_denied_in_autonomous_mode: { code: -32033, recovery: "Permanent-delete denied: autonomous mode (SAFESPACE_AUTONOMOUS=true) hard-denies non-recoverable deletes because no human is present to confirm them. Recoverable mutations are unaffected. To perform this delete, run it from an interactive (non-autonomous) session — unset SAFESPACE_AUTONOMOUS — or delete via the corresponding Google web UI." },
  // v1.57 F3b-gate (Autonomy Hardening) — under autonomous mode, a gmail send/draft
  // whose recipient first appeared inside untrusted BODY content this session
  // (policy/tainted-source, v1.56) is DENIED, not just flagged. Orthogonal to the
  // F2 recipient allowlist: even an allowlisted recipient is denied if its value is
  // tainted-source (provenance ⟂ membership). No-echo (errorData `{}`); the audit
  // row already carries the hashed recipient + the v1.56 `tainted_source` flag.
  tainted_recipient_denied: { code: -32034, recovery: "Recipient denied: autonomous mode (SAFESPACE_AUTONOMOUS=true) blocks sending to an address that first appeared inside untrusted content this session (it may be an address a malicious document or email told the agent to use). To send to this recipient, do it from an interactive (non-autonomous) session after confirming the address is legitimate." },
  // v1.57 F3a (Autonomy Hardening) — under autonomous mode, a gmail send/draft body
  // containing a mechanically-recognizable secret SHAPE (a private-key block or a
  // provider API-key) is REJECTED before the SDK call. errorData.reason carries the
  // shape CLASS (e.g. "private_key" / "aws_key") — a bounded closed-set value, NOT
  // the matched secret bytes (no-echo, mirrors formula-reject's function-name echo).
  outbound_secret_rejected: { code: -32035, recovery: "Outbound body rejected: autonomous mode (SAFESPACE_AUTONOMOUS=true) blocks sending a message whose body contains a recognizable secret (private key or API key). errorData.reason names the shape class, not the value. If this is a deliberate secret send, do it from an interactive (non-autonomous) session." },
  // v1.65 Phase C (web-fetch keyless connector) — the SSRF URL gate REJECTED this
  // fetch. errorData.reason is a closed-set UrlBlockReason (scheme_not_allowed /
  // host_not_in_allowlist / private_or_reserved_ip / redirect_blocked /
  // too_many_redirects / content_type_not_allowed / malformed_url / url_too_long)
  // — NEVER a resolved IP, response byte, or env value (no-echo, mirrors -32019 /
  // -32030). See src/policy/url-gate.ts + docs/v1.65-web-fetch-connector.md §4/§7.
  url_blocked_by_policy: { code: -32036, recovery: "web_fetch was blocked by SafeSpace's SSRF URL gate (errorData.reason names the cause: a non-http(s) scheme, a non-default port, a host not in SAFESPACE_WEBFETCH_ALLOW, a private/internal/metadata IP address, a disallowed redirect, too many redirects, or a non-text content type). Only public http(s) text resources on ports 80/443 are fetchable. If you set SAFESPACE_WEBFETCH_ALLOW (or run with SAFESPACE_AUTONOMOUS=true), add the host to the allowlist." },
  // v1.65 Phase C — OPERATIONAL fetch failure (a policy-CLEAN URL that still did
  // not retrieve). Kept distinct from -32036 so a typo'd / down domain is never
  // mislabeled a policy block. errorData.reason ∈ {dns_resolution_failed,
  // connection_failed, timeout, read_error}. No-echo.
  web_fetch_failed: { code: -32037, recovery: "web_fetch could not retrieve the URL (errorData.reason: DNS lookup failed, the connection failed, it timed out, or the body could not be read). The URL passed the safety gate — this is a network/availability issue, not a policy block. Check the URL is reachable and retry." },
  // v1.66 Phase C (PR 2) — LINE OA (class-B service-token) operational / token
  // failure. errorData.reason ∈ {no_token, auth_failed, rate_limited,
  // invalid_recipient, api_error} (closed set; NO token / recipient id echoed).
  // Unlike a Google 401 there is no OAuth re-consent recovery — the operator
  // (re)configures the channel token with `safespace line set-token`.
  line_api_failed: { code: -32038, recovery: "A LINE Messaging API call failed (errorData.reason: no_token = no channel access token configured — run `safespace line set-token` or set SAFESPACE_LINE_CHANNEL_TOKEN; auth_failed = the token was rejected, reconfigure it; rate_limited = slow down; invalid_recipient = the `to` id was rejected by LINE; api_error = other API failure). No token or recipient id is echoed." },
  // v1.68 — Telegram Bot (class-B service-token) operational / token failure.
  // errorData.reason ∈ {no_token, auth_failed, rate_limited, invalid_recipient,
  // api_error} (closed set; NO token / request URL / recipient id echoed — the bot
  // token is a URL path segment, so the URL must never surface).
  telegram_api_failed: { code: -32039, recovery: "A Telegram Bot API call failed (errorData.reason: no_token = no bot token configured — run `safespace telegram set-token` or set SAFESPACE_TELEGRAM_BOT_TOKEN; auth_failed = the token was rejected, reconfigure it; rate_limited = slow down; invalid_recipient = the `chat_id` was rejected by Telegram on a send; not_found = a read (getUpdates) target was not found; api_error = other API failure). No token, recipient id, or URL is echoed." },
  // v1.69 — Discord Bot (class-B service-token) operational / token failure.
  // errorData.reason ∈ {no_token, auth_failed, rate_limited, invalid_recipient,
  // api_error} (closed set; NO token / channel id / response body echoed).
  discord_api_failed: { code: -32040, recovery: "A Discord Bot API call failed (errorData.reason: no_token = no bot token configured — run `safespace discord set-token` or set SAFESPACE_DISCORD_BOT_TOKEN; auth_failed = the token was rejected, reconfigure it; rate_limited = slow down; invalid_recipient = the `channel_id` was rejected by Discord; api_error = other API failure). No token or channel id is echoed." },
  slack_api_failed: { code: -32049, recovery: "A Slack Bot API call failed (errorData.reason: no_token = no bot token configured — run `safespace slack set-token` or set SAFESPACE_SLACK_BOT_TOKEN; auth_failed = the token was rejected, reconfigure it; rate_limited = slow down; invalid_recipient = the `channel` was rejected by Slack; api_error = other API failure). No token or channel id is echoed." },
  // v1.107 — Mattermost (self-hosted class-B). `no_server_url` is unique to it (the
  // configured https:// server URL is missing/invalid). No token, URL, or channel id echoed.
  mattermost_api_failed: { code: -32053, recovery: "A Mattermost API call failed (errorData.reason: no_server_url = SAFESPACE_MATTERMOST_SERVER_URL is unset or not a valid https:// URL — set it to your server's base URL; no_token = no bot token configured — run `safespace mattermost set-token` or set SAFESPACE_MATTERMOST_BOT_TOKEN; auth_failed = the token was rejected, reconfigure it; rate_limited = slow down; not_found = the team/channel/post was not found or the bot lacks access; invalid_recipient = the `channel_id` was rejected; api_error = other API failure). No token, server URL, or id is echoed." },
  send_approval_required: { code: -32050, recovery: "Supervised mode (SAFESPACE_REQUIRE_SEND_APPROVAL) is ON and this outbound message send has not been approved by the owner. SafeSpace recorded the pending send (errorData.pending_id): review it with `safespace send list`, approve it with `safespace send approve <pending_id>`, then RETRY the identical send (same tool, recipients, and body) — it goes through exactly once. Changing the recipients or the body needs a fresh approval. errorData.reason: awaiting_approval = a new pending send was recorded; store_error = the pending-sends store is unreadable (fail-closed — nothing was sent). The message body is NEVER echoed (it is held locally in pending-sends.json for your review)." },
  github_api_failed: { code: -32041, recovery: "A GitHub API call failed (errorData.reason: no_token = no GitHub account authorized — run `safespace consent <login> --provider github`; auth_failed = the token was rejected or lacks a required scope, re-authorize; rate_limited = GitHub API rate limit, slow down; not_found = the repo / issue / PR does not exist, or your token predates the v1.83 `repo`-scope upgrade and can't see private repos — re-run `safespace consent <login> --provider github --re-auth` to grant `repo`; api_error = other API failure). No token is echoed." },
  // v1.71 — GitHub WRITE target allowlist (PUBLIC-surface default-deny, gate #3 of 4;
  // mirrors comment_target_denied_by_policy -32023). The owner/repo is NEVER echoed
  // (PII-oracle defense). errorData.reason ∈ {no_allowlist, not_in_allowlist}.
  github_write_denied_by_policy: { code: -32042, recovery: "The GitHub write target (owner/repo) is not in the SAFESPACE_GITHUB_WRITE_TARGETS allowlist. GitHub writes are DEFAULT-DENY (a PUBLIC surface): add the repo as `owner/repo` (comma-separated, case-insensitive) to SAFESPACE_GITHUB_WRITE_TARGETS in your .env, or per-session via SAFESPACE_GITHUB_WRITE_TARGETS_EXTRA. Default empty = no GitHub writes permitted even with the `repo` scope + write tier. The target repo is not echoed." },
  // v1.82 — github_merge_pull_request target gate. SEPARATE from -32042 because merging
  // to a default branch is IRREVERSIBLE (a higher bar than opening a PR). The target
  // repo is NEVER echoed (PII-oracle defense). errorData.reason ∈ {no_allowlist, not_in_allowlist}.
  github_merge_denied_by_policy: { code: -32046, recovery: "The GitHub merge target (owner/repo) is not in the SAFESPACE_GITHUB_MERGE_TARGETS allowlist. Merging a pull request is IRREVERSIBLE, so it has its OWN default-deny allowlist (separate from SAFESPACE_GITHUB_WRITE_TARGETS): add the repo as `owner/repo` (comma-separated, case-insensitive) to SAFESPACE_GITHUB_MERGE_TARGETS in your .env, or per-session via SAFESPACE_GITHUB_MERGE_TARGETS_EXTRA. Default empty = no merges permitted even when the repo is write-allowlisted. The target repo is not echoed." },
  // v1.90 — github_create_pull_request_review APPROVE-event gate. SEPARATE from -32042
  // because an APPROVE vouches for a PR and (under branch protection) can UNBLOCK a merge —
  // a higher bar than a COMMENT / REQUEST_CHANGES review (which stay on the WRITE allowlist
  // → -32042). The target repo is NEVER echoed. errorData.reason ∈ {no_allowlist, not_in_allowlist}.
  github_approve_denied_by_policy: { code: -32048, recovery: "The GitHub approve target (owner/repo) is not in the SAFESPACE_GITHUB_APPROVE_TARGETS allowlist. Submitting an APPROVE review vouches for a pull request and can UNBLOCK its merge under branch protection, so it has its OWN default-deny allowlist (separate from SAFESPACE_GITHUB_WRITE_TARGETS, which still gates COMMENT / REQUEST_CHANGES reviews): add the repo as `owner/repo` (comma-separated, case-insensitive) to SAFESPACE_GITHUB_APPROVE_TARGETS in your .env, or per-session via SAFESPACE_GITHUB_APPROVE_TARGETS_EXTRA. Default empty = no approvals permitted even when the repo is write-allowlisted. The target repo is not echoed." },
  // v1.75 — fs_read path gate (class-C keyless; the filesystem analogue of
  // url_blocked_by_policy -32036). The requested path is NEVER echoed (anti-oracle).
  // errorData.reason ∈ {no_allowlist, not_in_allowlist}.
  path_blocked_by_policy: { code: -32043, recovery: "fs_read was blocked by SafeSpace's path gate. fs_read is DEFAULT-DENY: it reads ONLY files under a directory listed in SAFESPACE_FS_READ_ROOTS (comma-separated ABSOLUTE paths in your .env, or per-session via SAFESPACE_FS_READ_ROOTS_EXTRA). errorData.reason=no_allowlist means no roots are configured (nothing is readable); not_in_allowlist means the path (after resolving symlinks + `..`) is outside every allowed root. The requested path is not echoed." },
  // v1.75 — fs_read operational failure (the path passed the gate but the read
  // failed). errorData.reason ∈ {not_found, not_a_file, too_large, not_text, read_error}.
  fs_read_failed: { code: -32044, recovery: "fs_read could not read the file (errorData.reason: not_found = no such file under the allowed root; not_a_file = it is a directory/device; too_large = over the 5 MB cap; not_text = binary / not valid UTF-8 [fs_read returns text only]; read_error = an OS read error). The path passed the safety gate — this is a file-availability/type issue, not a policy block." },
  // v1.77 — Notion API call failure. v1.78: Notion is now an OAuth source. errorData.reason
  // ∈ {no_token, auth_failed, rate_limited, not_found, api_error}. No token / id is echoed.
  notion_api_failed: { code: -32045, recovery: "A Notion API call failed (errorData.reason: no_token = no Notion workspace authorized — run `safespace consent --provider notion`; auth_failed = the token was rejected or the integration lacks access to the page/database (share the page with the integration in Notion); rate_limited = Notion API rate limit, slow down; not_found = the page/database/block does not exist or is not shared with the integration; api_error = other API failure). No token or id is echoed." },
  // v1.113 — X (Twitter) OAuth provider (class A). v1.114 adds rate_limited (HTTP 429 from
  // the tools client). errorData.reason ∈ {api_error, consent_required, no_account,
  // rate_limited}. consent_required covers invalid_grant / expired-or-revoked refresh OR
  // a 401 from api.x.com (re-run `safespace consent --provider x`); no_account = no stored
  // token for the resolved user; rate_limited = X API rate limit, slow down. No token /
  // refresh_token / user id is echoed.
  x_api_failed: { code: -32054, recovery: "An X (Twitter) API call failed (errorData.reason: no_account = no X account authorized — run `safespace consent --provider x`; consent_required = the refresh token was rejected or expired, or api.x.com returned 401 — re-run `safespace consent --provider x`; rate_limited = X API rate limit, slow down; api_error = other API failure). No token, refresh token, or user id is echoed." },
  // v1.115 — X post-create account allowlist (PUBLIC-surface default-deny, gate for
  // x_post_create). The posting account id is NEVER echoed (PII-oracle defense).
  // errorData.reason ∈ {no_allowlist, not_in_allowlist}. Code -32056 (skip -32055 —
  // reserved by an in-flight PR).
  x_post_denied_by_policy: { code: -32056, recovery: "The X posting account is not in the SAFESPACE_X_POST_ACCOUNTS allowlist. X posts are DEFAULT-DENY (a PUBLIC surface): add the account as a numeric user id (comma-separated) to SAFESPACE_X_POST_ACCOUNTS in your .env, or per-session via SAFESPACE_X_POST_ACCOUNTS_EXTRA. Default empty = no X posts permitted even with write tier + consent. The account id is not echoed." },
  // v1.88 — a SafeSpace-owned outbound fetch targeted a host NOT in the enforced
  // egress-destination registry (policy/egress-destinations.ts) for that connector.
  // This is an INTERNAL invariant breach (a connector bug or a path-injection host
  // escape, e.g. a path turning `api.github.com` into `...@evil.com`), not a normal
  // API failure. errorData.host = the blocked hostname ONLY (a fixed known value,
  // not PII; the full URL — which can hold a token, e.g. Telegram's — is NEVER echoed).
  egress_destination_blocked: { code: -32047, recovery: "A SafeSpace outbound request was blocked because its destination host is not in the enforced egress-destination registry for that connector (errorData.host = the blocked hostname). This is a defense-in-depth backstop against a connector targeting an unexpected host (a bug or a host-injection escape), not a user-configurable allowlist — the expected provider hosts are fixed in code. If this fires for a legitimate host, the registry in policy/egress-destinations.ts is out of date with the connector. Run `safespace doctor --posture` to see the registered destinations." },
  // v1.112.8 / v1.115.3 — fail-closed source routing / provider-guard / envelope
  // invariant tripwires. A should-never-fire internal misconfiguration (unknown
  // ToolDef.source, a handler that received the wrong credential kind/provider,
  // or an envelope choke-point / resolveCredential invariant breach).
  // errorData.reason ∈ {unknown_source, credential_mismatch, invariant_violation,
  // egress_gate_not_fired} (closed set). NEVER echoes the bogus source string, which
  // credential kind/provider arrived, or which invariant fired — those details must not
  // reach a client. -32054 is reserved by an in-flight X-connector PR; this takes -32055.
  internal_routing_error: { code: -32055, recovery: "Internal source-routing misconfiguration; this is a bug — report it. errorData.reason ∈ {unknown_source, credential_mismatch, invariant_violation, egress_gate_not_fired}. Not a user-actionable condition (no tool args or env can fix it)." },
  // v1.128 Q5-B — autonomous deployments must not ACK the Telegram inbox.
  // Advancing getUpdates `offset` permanently confirms update_id < offset
  // (at-most-once). Do NOT overload F4's delete-bucket. The offset value is
  // NEVER echoed. min_tier stays read.
  telegram_ack_denied_in_autonomous_mode: { code: -32057, recovery: "telegram_get_updates with an offset is denied in autonomous mode (SAFESPACE_AUTONOMOUS=true): advancing the cursor permanently ACKs the Telegram inbox (at-most-once). Omit offset to re-read the current batch without confirming it, or run this call from an interactive (non-autonomous) session. errorData.reason=offset_present. The offset value is not echoed." },
};

export class MCPError extends Error {
  readonly errorName: ErrorName;
  readonly errorData: Record<string, unknown>;

  constructor(errorName: ErrorName, data: Record<string, unknown> = {}) {
    super(errorName);
    this.errorName = errorName;
    this.errorData = data;
    this.name = "MCPError";
  }

  /** v1.24 Phase 1 — numeric MCPError code accessor for the
   *  `error_code` audit row stamping (Item 2). Mirrors the lookup in
   *  `toJsonRpc()` so both surfaces read from the same ERROR_CODES
   *  source of truth. Adding new MCPError names ALWAYS extends
   *  `ERROR_CODES` first (TypeScript-enforced via ErrorName union),
   *  so this getter cannot return undefined. */
  get code(): number {
    return ERROR_CODES[this.errorName].code;
  }

  toJsonRpc(): { code: number; message: string; data: Record<string, unknown> } {
    const spec = ERROR_CODES[this.errorName];
    return {
      code: spec.code,
      message: this.errorName,
      data: { recovery: spec.recovery, ...this.errorData },
    };
  }
}
