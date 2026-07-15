// v1.95 — the Slack Bot handler (the FOURTH class-B SERVICE-TOKEN connector tool,
// after v1.66 LINE + v1.68 Telegram + v1.69 Discord).
//
// docs-archive/v1.95-slack-connector.md §3. slack_send_message posts ONE text message
// to a known Slack conversation (channel / group / DM / user) via the Web API
// chat.postMessage method.
//
// SERVICE-TOKEN: this handler reads the bot token via requireServiceToken(ctx)
// (handlers/shared.ts) — the R6 narrow that throws if the credential is not the
// service-token kind — and uses it ONLY inline when building the Authorization header
// (never stored). It NEVER calls requireOAuth (no Google account). The cross-cutting
// envelope (tier / write-burst / sanitize / audit) is applied by withNonOAuthContext
// around it.
//
// EGRESS (B6.1 wave A1 — PIPELINE-FIRED): the egress gate — secret-shape (F3a) on the
// body + the Slack recipient allowlist on `channel` — is fired by withNonOAuthContext
// via this tool's egress descriptor (tools/egress-pipeline.ts) BEFORE this handler
// runs. The gate input is the RAW text (the agent-authored content, exactly what the
// pre-A1 handler passed); escapeSlackText below is purely for Slack's wire
// interpretation, never a substitute for the secret-shape scan. The handler must NOT
// invoke the gate itself (a double fire would double requireSendApproval + the denial
// audit rows); the call-site sentinel (egress-callsite.test.ts) enforces both
// directions.
//
// AUTH IS A HEADER, NOT A URL (like Discord): Slack uses `Authorization: Bearer <token>`
// against the fixed host slack.com — the token is NOT a URL path segment, so there is no
// token-in-URL leak surface. The token is never logged/echoed; the helper maps failures
// to a closed-set reason and never reads/echoes the request URL/headers/body.
//
// MENTION / LINK-INJECTION GUARD (the Slack-specific abuse surface): Slack's special
// control sequences — `<!channel>` `<!here>` `<!everyone>` `<@U…>` `<#C…>` `<url|text>` —
// are ALL delimited by literal `<` and `>`. The handler ALWAYS escapes `&` `<` `>` (Slack's
// own documented text escaping; `&` FIRST so it is not double-escaped), so any such
// sequence in attacker-influenced `text` becomes INERT literal text — the bot can
// broadcast-ping nobody and inject no link, regardless of what the text says. This is an
// allowlist-construction guarantee (always escape, never derive from input), the Slack
// analogue of Discord's allowed_mentions:{parse:[]}. The body carries ONLY `channel` +
// `text` (no `link_names`, no `blocks`/`attachments`) → nothing Slack unfurls or fetches
// server-side from a constructed field (no SSRF-by-proxy).
//
// ERROR MODEL (the Slack-specific delta): chat.postMessage returns HTTP 200 even on a
// LOGICAL failure, with `{ok:false, error:"…"}` in the body. The shared service-token
// fetch normally resolves on any 2xx + discards the body, so this handler passes a
// `checkBody` seam that reads+parses the JSON body and maps `ok:false` → a closed-set
// reason (never echoing the `error` string). LINE/Telegram/Discord pass no checkBody →
// their body-discard path is byte-identical.

import { SLACK_CHANNEL_ID_RE } from "../../policy/slack-recipient-allowlist";
import { slackApiGet } from "../../auth/slack/client";
import type { ToolContext } from "../types";
import { postServiceTokenJson, type ServiceTokenReason } from "./service-token-fetch";
import { assertEgressHost } from "../../policy/egress-destinations";
import { requireServiceToken } from "./shared";

/** Slack Web API base — a fixed, trusted host (no SSRF surface; `channel` + `text` are in
 *  the request body, not the URL; auth is a Bearer header). */
const SLACK_API = "https://slack.com/api";

/** Slack chat.postMessage text hard limit (the API rejects > 40000 with msg_too_long;
 *  we reject locally first so an oversize body never leaves the process). */
const SLACK_TEXT_MAX = 40000;

/** Test-injection seam (shared by the Slack send + read handlers) — production leaves it
 *  undefined (→ the real global fetch). Tests inject a stub to assert validation / egress /
 *  shaping / error mapping without a network. */
export interface SlackDeps {
  fetchImpl?: typeof fetch;
}

/** Map a non-2xx HTTP status to the closed-set reason. Slack signals most logical
 *  failures via a 200 body (see checkBody below); this covers the genuine HTTP-level
 *  failures (429 throttling, 5xx, an edge auth rejection). */
function mapStatusToReason(status: number): ServiceTokenReason {
  if (status === 401 || status === 403) return "auth_failed";
  if (status === 429) return "rate_limited";
  return "api_error";
}

/** Map a Slack `{ok:false, error}` body to the closed-set reason. The `error` STRING is
 *  read only to classify — it is NEVER echoed (it can name the channel/user). */
function mapSlackBodyError(error: string): ServiceTokenReason {
  switch (error) {
    case "not_authed":
    case "invalid_auth":
    case "account_inactive":
    case "token_revoked":
    case "token_expired":
    case "no_permission":
    case "ekm_access_denied":
      return "auth_failed";
    case "channel_not_found":
    case "not_in_channel":
    case "is_archived":
    case "user_not_found":
    case "cannot_dm_bot":
    case "restricted_action":
      return "invalid_recipient";
    case "rate_limited":
    case "ratelimited":
      return "rate_limited";
    default:
      return "api_error";
  }
}

/** The checkBody seam (the Slack delta): chat.postMessage returns 200 even on failure.
 *  Returns null on success (`ok:true`) and a closed-set reason otherwise. A non-object /
 *  missing `ok` is treated as a failure (`api_error`) — fail closed, never a false 2xx. */
function checkSlackBody(parsed: unknown): ServiceTokenReason | null {
  const ok = (parsed as { ok?: unknown } | null)?.ok;
  if (ok === true) return null;
  const error = (parsed as { error?: unknown } | null)?.error;
  return mapSlackBodyError(typeof error === "string" ? error : "");
}

/** Escape Slack's three special characters so any control sequence in agent text is
 *  inert. Order matters: `&` first, else `<`→`&lt;` would have its `&` re-escaped. */
function escapeSlackText(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/** B6.1 wave A1 — the slack_send_message arg validator, extracted so ONE pure function
 *  serves both call sites (single source, no drift): the pipeline's egress descriptor
 *  (`extract` in tools/egress-pipeline.ts, which runs BEFORE this handler) and the
 *  handler below. Returns the RAW text (the gate input; escaping is wire-only, applied
 *  later in the handler). Throws the tool's plain-Error validation messages; echoes
 *  the RULE, never the value.
 *
 *  1. Conversation id well-formedness — a well-formed id Slack later rejects →
 *     slack_api_failed{invalid_recipient}. The fixed alphabet also forecloses
 *     `#name`/`@name` addressing (IDs only).
 *  2. Text body: non-empty + the Slack character limit. */
export function validateSlackSendArgs(
  args: Record<string, unknown>,
): { channel: string; text: string } {
  const channel = args.channel;
  if (typeof channel !== "string" || !SLACK_CHANNEL_ID_RE.test(channel)) {
    throw new Error(
      "slack_send_message: 'channel' must be a Slack conversation id (channel C…, group G…, DM D…, or user U…/W…)",
    );
  }
  const text = args.text;
  if (typeof text !== "string" || text.length === 0) {
    throw new Error("slack_send_message: 'text' must be a non-empty string");
  }
  if (text.length > SLACK_TEXT_MAX) {
    throw new Error(
      `slack_send_message: 'text' exceeds the ${SLACK_TEXT_MAX}-character Slack limit`,
    );
  }
  return { channel, text };
}

export async function slackSendMessage(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: SlackDeps = {},
): Promise<unknown> {
  // 1. Validate args. The pipeline already validated them via this SAME function (the
  //    egress descriptor's extract, BEFORE this handler); this call is defense-in-depth
  //    + the unit-test surface (pure, identical result — cheap re-validation).
  const { channel, text } = validateSlackSendArgs(args);

  // 2. Send. The token is read inline from the service-token credential and placed in the
  //    Authorization header (never the URL, never logged/echoed).
  const token = requireServiceToken(ctx).token();
  const url = `${SLACK_API}/chat.postMessage`;
  // v1.88 — destination backstop: assert the host is the registered slack host before the
  // fetch (throws -32047 echoing the host only).
  assertEgressHost(new URL(url).hostname, "slack");
  // Allowlist-constructed body: channel + ESCAPED text only — no link_names, no
  // blocks/attachments → no auto-link/mention and nothing Slack unfurls from a
  // constructed field. checkBody handles the 200+ok:false logical-failure model while the
  // shared helper keeps the hard timeout + body-stream bound (v1.69.1 / v1.95 C1).
  await postServiceTokenJson({
    url,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      Authorization: `Bearer ${token}`,
    },
    body: { channel, text: escapeSlackText(text) },
    mapStatus: mapStatusToReason,
    checkBody: checkSlackBody,
    errorName: "slack_api_failed",
    fetchImpl: deps.fetchImpl,
  });

  // Success. The returned fields are all trusted/constructed (no upstream content) but
  // flow through the source's sanitize tree-walk in the choke point regardless.
  return { channel, sent: true, message_type: "text" };
}

/* ── READ (v1.97) — the FIRST class-B service-token read ──────────────────────────────
 * Each read: requireServiceToken (R6 narrow) → validate id/limit/cursor → slackApiGet (the
 * hardened GET client: host-pinned, byte-capped, 200-but-ok:false → closed-set reason,
 * returns parsed JSON) → CURATED shaper (pick only safe fields, never the raw object).
 * INBOUND content (channel names, message text, topic/purpose) is the highest
 * prompt-injection surface — it is left OUT of SLACK_SKIP_FIELDS so the choke point's
 * sanitize tree-walk wraps it as an untrusted source; opaque ids/timestamps/cursors ARE in
 * skipFields so the agent gets them raw for follow-up calls (tools/source.ts). */

const READ_LIMIT_DEFAULT = 50;
const READ_LIMIT_MAX = 200; // bounded page (context protection; Slack allows up to 1000)
const CURSOR_MAX = 1024; // opaque Slack pagination cursor — bounded

function clampLimit(raw: unknown): number {
  const n = typeof raw === "number" && Number.isFinite(raw) && raw >= 1 ? raw : READ_LIMIT_DEFAULT;
  return Math.floor(Math.min(n, READ_LIMIT_MAX));
}

/** An optional opaque pagination cursor (Slack-issued; the agent passes it back). */
function optionalCursor(args: Record<string, unknown>): string | undefined {
  const v = args.cursor;
  if (v === undefined) return undefined;
  if (typeof v !== "string" || v.length === 0 || v.length > CURSOR_MAX) {
    throw new Error(`slack: 'cursor' must be a non-empty string ≤ ${CURSOR_MAX} chars`);
  }
  return v;
}

/** An optional Slack `ts` lower-bound — conversations.history returns only messages AFTER
 *  it (the "poll for new since last seen" filter). Opaque + bounded, treated like the
 *  cursor. Unlike Telegram's offset this is a REPLAY-SAFE filter — re-passing the same ts is
 *  idempotent and ACKs/drops nothing. */
function optionalOldest(args: Record<string, unknown>): string | undefined {
  const v = args.oldest;
  if (v === undefined) return undefined;
  if (typeof v !== "string" || v.length === 0 || v.length > CURSOR_MAX) {
    throw new Error(`slack_read_messages: 'oldest' must be a non-empty Slack ts string ≤ ${CURSOR_MAX} chars`);
  }
  return v;
}

type Obj = Record<string, unknown>;
const asObj = (v: unknown): Obj | null =>
  v && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : null;

/** A conversations.list channel → curated shape. `name`/`topic`/`purpose` are user-authored
 *  (they WRAP); `id` + booleans/counts are opaque/controlled (id is in skipFields). */
function shapeChannel(v: unknown): Obj {
  const o = asObj(v) ?? {};
  return {
    id: o.id,
    name: o.name,
    is_private: o.is_private === true,
    is_archived: o.is_archived === true,
    is_member: o.is_member === true,
    num_members: typeof o.num_members === "number" ? o.num_members : undefined,
    topic: asObj(o.topic)?.value,
    purpose: asObj(o.purpose)?.value,
  };
}

/** A conversations.history message → curated shape. `text` is the HIGHEST prompt-injection
 *  surface (it WRAPS); `user`/`ts`/`thread_ts`/`type` are opaque/controlled (in skipFields). */
function shapeMessage(v: unknown): Obj {
  const o = asObj(v) ?? {};
  return {
    type: o.type,
    user: o.user,
    text: typeof o.text === "string" ? o.text : "",
    ts: o.ts,
    thread_ts: o.thread_ts,
    reply_count: typeof o.reply_count === "number" ? o.reply_count : undefined,
  };
}

function nextCursor(data: Obj): string | null {
  const meta = asObj(data.response_metadata);
  const c = meta?.next_cursor;
  return typeof c === "string" && c.length > 0 ? c : null;
}

/** conversations.list — the channels/conversations the bot can see (READ). */
export async function slackListChannels(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: SlackDeps = {},
): Promise<unknown> {
  const token = requireServiceToken(ctx).token();
  const data = await slackApiGet({
    token,
    method: "conversations.list",
    query: {
      types: "public_channel,private_channel",
      exclude_archived: "true",
      limit: clampLimit(args.limit),
      cursor: optionalCursor(args),
    },
    fetchImpl: deps.fetchImpl,
  });
  return {
    channels: Array.isArray(data.channels) ? data.channels.map(shapeChannel) : [],
    next_cursor: nextCursor(data),
  };
}

/** conversations.history — the messages in a channel (READ). The channel must be a valid
 *  id (the bot must be a member); the message text is sanitize-wrapped by the choke point. */
export async function slackReadMessages(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: SlackDeps = {},
): Promise<unknown> {
  const token = requireServiceToken(ctx).token();
  const channel = args.channel;
  if (typeof channel !== "string" || !SLACK_CHANNEL_ID_RE.test(channel)) {
    throw new Error(
      "slack_read_messages: 'channel' must be a Slack conversation id (channel C…, group G…, DM D…)",
    );
  }
  const data = await slackApiGet({
    token,
    method: "conversations.history",
    query: { channel, limit: clampLimit(args.limit), cursor: optionalCursor(args), oldest: optionalOldest(args) },
    fetchImpl: deps.fetchImpl,
  });
  return {
    channel,
    messages: Array.isArray(data.messages) ? data.messages.map(shapeMessage) : [],
    has_more: data.has_more === true,
    next_cursor: nextCursor(data),
  };
}

/* ── READ (v1.104) — the workspace directory (users.list + users.info) ────────────────────
 * The PII posture is the design center. EMAIL is asymmetric: the BULK users.list shape OMITS
 * it (no one call exfiltrates a whole workspace's emails — the bulk-export concern); the
 * SINGLE-user users.info shape includes it (an intentional, scoped lookup). Either way `email`
 * is left OUT of SLACK_SKIP_FIELDS so the choke point wraps it as an untrusted source. `phone`
 * / `title` / `status_text` are never shaped at all. Opaque `id` + the controlled bools/`tz`
 * are in skipFields → raw for follow-up. The bot token must carry users:read (+ users:read.email
 * for the info email); a missing scope surfaces as slack_api_failed{auth_failed}. */

/** Slack USER ids only (U… member, W… enterprise-grid). Narrower than SLACK_CHANNEL_ID_RE
 *  (which also accepts C/D/G) so users.info can never be pointed at a channel/group id. */
const SLACK_USER_ID_RE = /^[UW][A-Z0-9]{6,20}$/;

/** A Slack member object → curated shape. `name`/`real_name`/`display_name` are user-authored
 *  (they WRAP); `id` + the bools + `tz` are opaque/controlled (in skipFields). `email` is
 *  surfaced ONLY when `includeEmail` (users.info), and even then it WRAPS (PII, not skipped). */
function shapeUser(v: unknown, includeEmail: boolean): Obj {
  const o = asObj(v) ?? {};
  const profile = asObj(o.profile) ?? {};
  const shaped: Obj = {
    id: o.id,
    name: o.name,
    real_name: profile.real_name ?? o.real_name,
    display_name: profile.display_name,
    is_bot: o.is_bot === true,
    is_admin: o.is_admin === true,
    deleted: o.deleted === true,
    tz: typeof o.tz === "string" ? o.tz : undefined,
  };
  if (includeEmail) shaped.email = profile.email;
  return shaped;
}

/** users.list — the workspace members the bot can see (READ). NO email in the bulk shape. */
export async function slackUsersList(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: SlackDeps = {},
): Promise<unknown> {
  const token = requireServiceToken(ctx).token();
  const data = await slackApiGet({
    token,
    method: "users.list",
    query: { limit: clampLimit(args.limit), cursor: optionalCursor(args) },
    fetchImpl: deps.fetchImpl,
  });
  return {
    users: Array.isArray(data.members) ? data.members.map((m) => shapeUser(m, false)) : [],
    next_cursor: nextCursor(data),
  };
}

/** users.info — a single member by user id (READ). The shape INCLUDES the wrapped email. */
export async function slackUserInfo(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: SlackDeps = {},
): Promise<unknown> {
  const token = requireServiceToken(ctx).token();
  const user = args.user;
  if (typeof user !== "string" || !SLACK_USER_ID_RE.test(user)) {
    throw new Error("slack_user_info: 'user' must be a Slack user id (U…/W…)");
  }
  const data = await slackApiGet({
    token,
    method: "users.info",
    query: { user },
    fetchImpl: deps.fetchImpl,
  });
  return shapeUser(data.user, true);
}
