// v1.69 — the Discord Bot handler (the THIRD class-B SERVICE-TOKEN connector tool,
// after v1.66 LINE + v1.68 Telegram).
//
// docs/v1.69-discord-connector.md §3. discord_send_message posts ONE text message to a
// known Discord channel via the REST create-message endpoint.
//
// SERVICE-TOKEN: this handler reads the bot token via requireServiceToken(ctx)
// (handlers/shared.ts) — the R6 narrow that throws if the credential is not the
// service-token kind — and uses it ONLY inline when building the Authorization header
// (never stored). It NEVER calls requireOAuth (no Google account). The cross-cutting
// envelope (tier / write-burst / sanitize / audit) is applied by withNonOAuthContext
// around it.
//
// EGRESS (B6.1 wave A1 — PIPELINE-FIRED): the egress gate — secret-shape (F3a) on the
// body + the Discord recipient allowlist on `channel_id` — is fired by
// withNonOAuthContext via this tool's egress descriptor (tools/egress-pipeline.ts)
// BEFORE this handler runs. The handler must NOT invoke the gate itself (a double fire
// would double requireSendApproval + the denial audit rows); the call-site sentinel
// (egress-callsite.test.ts) enforces both directions.
//
// AUTH IS A HEADER, NOT A URL (cleaner than Telegram): Discord uses
// `Authorization: Bot <token>` (the mandatory `Bot ` scheme prefix) against the fixed
// host discord.com — the token is NOT a URL path segment, so Telegram's token-in-URL
// leak surface does not exist here. The token is still never logged/echoed; the handler
// maps the HTTP status to a closed-set reason and never reads/echoes the response body
// (it can carry channel/guild detail).
//
// MENTION-INJECTION GUARD (the Discord-specific abuse surface): the body ALWAYS sends
// `allowed_mentions: { parse: [] }`, so an `@everyone`/`@here`/role mention inside
// attacker-influenced `content` is rendered as INERT TEXT — the bot can ping nobody via
// the body, regardless of what the text says. This is an allowlist-construction
// guarantee (the field is always set, never derived from input), the Discord analogue
// of Telegram sending no parse_mode. No embeds/components/attachments are constructible
// → nothing Discord fetches server-side (no SSRF-by-proxy).

import { DISCORD_CHANNEL_ID_RE } from "../../policy/discord-recipient-allowlist";
import type { ToolContext } from "../types";
import { postServiceTokenJson } from "./service-token-fetch";
import { assertEgressHost } from "../../policy/egress-destinations";
import { requireServiceToken } from "./shared";

/** Discord REST API base — a fixed, trusted host (no SSRF surface; channel_id is a
 *  digit-validated path segment, content is in the body). */
const DISCORD_API = "https://discord.com/api/v10";

/** Discord message content limit. */
const DISCORD_CONTENT_MAX = 2000;

/** Test-injection seam — production leaves it undefined (→ the real global fetch).
 *  Tests inject a stub to assert validation / egress / error mapping without a
 *  network. Mirrors TelegramDeps. */
export interface DiscordSendDeps {
  fetchImpl?: typeof fetch;
}

function mapStatusToReason(
  status: number,
): "auth_failed" | "rate_limited" | "invalid_recipient" | "api_error" {
  if (status === 401 || status === 403) return "auth_failed";
  if (status === 429) return "rate_limited";
  // 400 (malformed) or 404 (unknown channel) — the channel target was rejected.
  if (status === 400 || status === 404) return "invalid_recipient";
  return "api_error";
}

/** B6.1 wave A1 — the discord_send_message arg validator, extracted so ONE pure
 *  function serves both call sites (single source, no drift): the pipeline's egress
 *  descriptor (`extract` in tools/egress-pipeline.ts, which runs BEFORE this handler)
 *  and the handler below. Throws the tool's plain-Error validation messages; echoes
 *  the RULE, never the value.
 *
 *  1. Channel id well-formedness — a well-formed id Discord later rejects (404) →
 *     discord_api_failed{invalid_recipient} (distinct from this fail-fast check).
 *     Digit-only also forecloses any path traversal via the channel_id URL segment.
 *  2. Content body: non-empty + the Discord character limit. */
export function validateDiscordSendArgs(
  args: Record<string, unknown>,
): { channel_id: string; content: string } {
  const channel_id = args.channel_id;
  if (typeof channel_id !== "string" || !DISCORD_CHANNEL_ID_RE.test(channel_id)) {
    throw new Error(
      "discord_send_message: 'channel_id' must be a numeric Discord channel id (17–20 digits)",
    );
  }
  const content = args.content;
  if (typeof content !== "string" || content.length === 0) {
    throw new Error("discord_send_message: 'content' must be a non-empty string");
  }
  if (content.length > DISCORD_CONTENT_MAX) {
    throw new Error(
      `discord_send_message: 'content' exceeds the ${DISCORD_CONTENT_MAX}-character Discord limit`,
    );
  }
  return { channel_id, content };
}

export async function discordSendMessage(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: DiscordSendDeps = {},
): Promise<unknown> {
  // 1. Validate args. The pipeline already validated them via this SAME function (the
  //    egress descriptor's extract, BEFORE this handler); this call is defense-in-depth
  //    + the unit-test surface (pure, identical result — cheap re-validation).
  const { channel_id, content } = validateDiscordSendArgs(args);

  // 2. Send. The token is read inline from the service-token credential and placed in
  //    the Authorization header (never the URL, never logged/echoed).
  const token = requireServiceToken(ctx).token();
  const url = `${DISCORD_API}/channels/${channel_id}/messages`;
  // v1.88 — destination backstop: assert the host is the registered discord host
  // before the fetch (channel_id is in the path; throws -32047 echoing the host only).
  assertEgressHost(new URL(url).hostname, "discord");
  // Send via the shared service-token fetch (hard timeout + response-body cleanup +
  // closed-set error mapping; v1.69.1). The Bot token is in the headers → it (like the
  // body) is never echoed by the helper on any error. Allowlist-constructed body:
  // content + an ALWAYS-empty mention parse set → no embeds/attachments (no remote-URL
  // fetch) and `allowed_mentions.parse:[]` renders any @everyone/@here/role mention inert.
  await postServiceTokenJson({
    url,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bot ${token}`,
    },
    body: { content, allowed_mentions: { parse: [] } },
    mapStatus: mapStatusToReason,
    errorName: "discord_api_failed",
    fetchImpl: deps.fetchImpl,
  });

  // Success. The returned fields are all trusted/constructed (no upstream content) but
  // flow through the source's sanitize tree-walk in the choke point regardless.
  return { channel_id, sent: true, message_type: "text" };
}
