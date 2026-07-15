// v1.68 — the Telegram Bot handler (the SECOND class-B SERVICE-TOKEN connector tool,
// after v1.66 LINE).
//
// docs/v1.68-telegram-connector.md §3. telegram_send_message sends ONE text message to
// a known Telegram chat (user / group / channel) via the Bot API sendMessage endpoint.
//
// SERVICE-TOKEN: this handler reads the bot token via requireServiceToken(ctx)
// (handlers/shared.ts) — the R6 narrow that throws if the credential is not the
// service-token kind — and uses it ONLY inline when building the request URL (never
// stored). It NEVER calls requireOAuth (no Google account). The cross-cutting envelope
// (tier / write-burst / sanitize / audit) is applied by withNonOAuthContext around it.
//
// EGRESS (B6.1 wave A1 — PIPELINE-FIRED): the egress gate — secret-shape (F3a) on the
// body + the Telegram recipient allowlist on `chat_id` — is fired by
// withNonOAuthContext via this tool's egress descriptor (tools/egress-pipeline.ts)
// BEFORE this handler runs. The handler must NOT invoke the gate itself (a double fire
// would double requireSendApproval + the denial audit rows); the call-site sentinel
// (egress-callsite.test.ts) enforces both directions.
//
// TOKEN-IN-URL (the Telegram-specific invariant — docs §1): unlike LINE's Bearer
// header, Telegram puts the bot token in the request URL PATH
// (https://api.telegram.org/bot<TOKEN>/sendMessage). The host is HARDCODED (no SSRF —
// chat_id/text go in the BODY) but the URL string CONTAINS the secret, so NO error path
// may echo the URL: status maps to a closed-set reason, the response body is never read,
// and a network throw becomes a generic api_error.
//
// SSRF: only type:"text" is constructible — the body is allowlist-constructed
// { chat_id, text } with NO parse_mode / media / URL field, so Telegram fetches nothing
// server-side (no SSRF-by-proxy) and there is no formatting-entity injection.

import { TELEGRAM_CHAT_ID_RE } from "../../policy/telegram-recipient-allowlist";
import type { ToolContext } from "../types";
import { postServiceTokenJson } from "./service-token-fetch";
import { assertEgressHost } from "../../policy/egress-destinations";
import { requireServiceToken } from "./shared";
import { telegramApiGet } from "../../auth/telegram/client";

/** Telegram Bot API host — a fixed, trusted host (no SSRF surface; the token is a
 *  path segment, the user-controlled chat_id/text are in the body). */
const TELEGRAM_API_HOST = "https://api.telegram.org";

/** Telegram sendMessage text limit. */
const TELEGRAM_TEXT_MAX = 4096;

/** Test-injection seam (shared by the Telegram send + read handlers) — production leaves
 *  it undefined (→ the real global fetch). Tests inject a stub to assert validation /
 *  egress / shaping / error mapping without a network. */
export interface TelegramDeps {
  fetchImpl?: typeof fetch;
}

function mapStatusToReason(
  status: number,
): "auth_failed" | "rate_limited" | "invalid_recipient" | "api_error" {
  if (status === 401 || status === 403) return "auth_failed";
  if (status === 429) return "rate_limited";
  if (status === 400) return "invalid_recipient";
  return "api_error";
}

/** B6.1 wave A1 — the telegram_send_message arg validator, extracted so ONE pure
 *  function serves both call sites (single source, no drift): the pipeline's egress
 *  descriptor (`extract` in tools/egress-pipeline.ts, which runs BEFORE this handler)
 *  and the handler below. Throws the tool's plain-Error validation messages; echoes
 *  the RULE, never the value.
 *
 *  1. Chat id well-formedness — a well-formed id Telegram later rejects (400) →
 *     telegram_api_failed{invalid_recipient} (distinct from this fail-fast check).
 *  2. Text body: non-empty + the Telegram character limit. */
export function validateTelegramSendArgs(
  args: Record<string, unknown>,
): { chat_id: string; text: string } {
  const chat_id = args.chat_id;
  if (typeof chat_id !== "string" || !TELEGRAM_CHAT_ID_RE.test(chat_id)) {
    throw new Error(
      "telegram_send_message: 'chat_id' must be a numeric chat id (e.g. 123456789 or " +
        "-1001234567890) or a public @username",
    );
  }
  const text = args.text;
  if (typeof text !== "string" || text.length === 0) {
    throw new Error("telegram_send_message: 'text' must be a non-empty string");
  }
  if (text.length > TELEGRAM_TEXT_MAX) {
    throw new Error(
      `telegram_send_message: 'text' exceeds the ${TELEGRAM_TEXT_MAX}-character Telegram limit`,
    );
  }
  return { chat_id, text };
}

export async function telegramSendMessage(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: TelegramDeps = {},
): Promise<unknown> {
  // 1. Validate args. The pipeline already validated them via this SAME function (the
  //    egress descriptor's extract, BEFORE this handler); this call is defense-in-depth
  //    + the unit-test surface (pure, identical result — cheap re-validation).
  const { chat_id, text } = validateTelegramSendArgs(args);

  // 2. Send. The token is read inline from the service-token credential and placed in
  //    the URL PATH (Telegram's auth model). The URL string therefore CONTAINS the
  //    secret — it is built here and NEVER logged / stored / echoed in any error.
  const token = requireServiceToken(ctx).token();
  const url = `${TELEGRAM_API_HOST}/bot${token}/sendMessage`;
  // v1.88 — destination backstop: assert the host is the registered telegram host
  // before the fetch. new URL(url).hostname strips the bot-token path → the -32047
  // echoes the host ONLY, never the token-bearing URL.
  assertEgressHost(new URL(url).hostname, "telegram");
  // Send via the shared service-token fetch (hard timeout + response-body cleanup +
  // closed-set error mapping; v1.69.1). The URL holds the bot token → it (like the body)
  // is never echoed by the helper on any error. Allowlist-constructed body: ONLY
  // chat_id + a text message, NO parse_mode / media → no SSRF-by-proxy + no entity
  // injection.
  await postServiceTokenJson({
    url,
    headers: { "Content-Type": "application/json" },
    body: { chat_id, text },
    mapStatus: mapStatusToReason,
    errorName: "telegram_api_failed",
    fetchImpl: deps.fetchImpl,
  });

  // Success. The returned fields are all trusted/constructed (no upstream content) but
  // flow through the source's sanitize tree-walk in the choke point regardless.
  return { chat_id, sent: true, message_type: "text" };
}

/* ── READ (v1.98) — Telegram's FIRST read: the inbound poll-inbox ─────────────────────
 * telegram_get_updates pulls new inbound updates (allowed_updates fixed to ["message"])
 * via the Bot API getUpdates → telegramApiGet (the hardened GET client: token-in-path
 * no-leak, byte-capped, {ok:false,error_code} → closed reason, returns parsed JSON) →
 * CURATED shaper. INBOUND user content (message text, sender names/username, chat title)
 * is left OUT of TELEGRAM_SKIP_FIELDS so the choke point's sanitize tree-walk WRAPS it as
 * untrusted; the opaque Telegram ids/timestamps are NUMERIC → sanitize passes numbers
 * through untouched (no skip entry needed; see tools/source.ts).
 *
 * CURSOR / ACK (the Telegram-specific semantics): getUpdates(offset=N) CONFIRMS and DROPS
 * updates with update_id < N on Telegram's servers — an irreversible, AT-MOST-ONCE
 * delivery cursor over the bot's ephemeral 24h buffer (NOT deletion of user-stored data,
 * so this stays min_tier:read). SafeSpace holds NO cursor state: the agent reads
 * `next_offset` from the response and passes it back as `offset` on the next poll.
 * `timeout=0` (no long-poll) and `allowed_updates=["message"]` are SERVER-FIXED constants
 * (never agent params) — bounding the held connection and the parsed shape. */

const UPDATES_LIMIT_DEFAULT = 50;
const UPDATES_LIMIT_MAX = 100; // Telegram's getUpdates limit cap (context protection)

function clampUpdatesLimit(raw: unknown): number {
  const n = typeof raw === "number" && Number.isFinite(raw) && raw >= 1 ? raw : UPDATES_LIMIT_DEFAULT;
  return Math.floor(Math.min(n, UPDATES_LIMIT_MAX));
}

/** The optional update_id cursor — the agent passes back a prior `next_offset`. An integer
 *  (Telegram's update_id space); echoes the RULE, never the value. */
function optionalOffset(args: Record<string, unknown>): number | undefined {
  const v = args.offset;
  if (v === undefined) return undefined;
  if (typeof v !== "number" || !Number.isInteger(v)) {
    throw new Error("telegram_get_updates: 'offset' must be an integer update_id (a prior next_offset)");
  }
  return v;
}

type TgObj = Record<string, unknown>;
const asTgObj = (v: unknown): TgObj | null =>
  v && typeof v === "object" && !Array.isArray(v) ? (v as TgObj) : null;

/** A Telegram User → curated shape. `first_name`/`last_name`/`username` WRAP (PII /
 *  injection); `id` is a NUMBER (untouched by sanitize). */
function shapeTgUser(v: unknown): TgObj | undefined {
  const o = asTgObj(v);
  if (o === null) return undefined;
  return { id: o.id, is_bot: o.is_bot === true, first_name: o.first_name, last_name: o.last_name, username: o.username };
}

/** A Telegram Chat → curated shape. `title`/`username` WRAP; `type` is a controlled enum
 *  (in TELEGRAM_SKIP_FIELDS); `id` is a NUMBER. */
function shapeTgChat(v: unknown): TgObj | undefined {
  const o = asTgObj(v);
  if (o === null) return undefined;
  return { id: o.id, type: o.type, title: o.title, username: o.username };
}

/** A Telegram message → curated shape. `text` is the highest injection surface (WRAPS). */
function shapeTgMessage(v: unknown): TgObj | undefined {
  const o = asTgObj(v);
  if (o === null) return undefined;
  return {
    message_id: o.message_id,
    date: o.date,
    text: typeof o.text === "string" ? o.text : "",
    from: shapeTgUser(o.from),
    chat: shapeTgChat(o.chat),
  };
}

/** Max update_id in the batch + 1 — the cursor the agent passes back as `offset` to ACK
 *  this batch and fetch the next. null on an empty batch (nothing to advance past). */
function nextOffset(result: unknown[]): number | null {
  let max = -Infinity;
  for (const u of result) {
    const id = asTgObj(u)?.update_id;
    if (typeof id === "number" && id > max) max = id;
  }
  return max === -Infinity ? null : max + 1;
}

/** getUpdates — poll the bot's inbound update queue (READ). See the cursor/ACK note above:
 *  advancing `offset` irreversibly confirms prior updates (at-most-once delivery). */
export async function telegramGetUpdates(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: TelegramDeps = {},
): Promise<unknown> {
  const token = requireServiceToken(ctx).token();
  const data = await telegramApiGet({
    token,
    method: "getUpdates",
    query: {
      offset: optionalOffset(args),
      limit: clampUpdatesLimit(args.limit),
      timeout: 0, // server-fixed: no long-poll (would compete with the abort timer)
      allowed_updates: JSON.stringify(["message"]), // server-fixed: bound the parsed shape
    },
    fetchImpl: deps.fetchImpl,
  });
  const result = Array.isArray(data.result) ? data.result : [];
  return {
    updates: result.map((u) => {
      const o = asTgObj(u) ?? {};
      return { update_id: o.update_id, message: shapeTgMessage(o.message) };
    }),
    next_offset: nextOffset(result),
  };
}
