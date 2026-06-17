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
// EGRESS: the handler calls the centralized enforceDiscordEgressGates (tools/egress.ts)
// BEFORE the SDK call (the B3 handler-called posture, consistent with gmail_send /
// line_push_message / telegram_send_message): secret-shape (F3a) on the body + the
// Discord recipient allowlist on `channel_id`.
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
import { enforceDiscordEgressGates } from "../egress";
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

export async function discordSendMessage(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: DiscordSendDeps = {},
): Promise<unknown> {
  // 1. Validate the channel id (well-formedness). Plain Error (bad input) — mirrors the
  //    telegram_send_message / line_push_message convention; echoes the RULE, never the
  //    value. A well-formed id Discord later rejects (404) → discord_api_failed
  //    {invalid_recipient} below (distinct from this fail-fast input check). Digit-only
  //    also forecloses any path traversal via the channel_id URL segment.
  const channel_id = args.channel_id;
  if (typeof channel_id !== "string" || !DISCORD_CHANNEL_ID_RE.test(channel_id)) {
    throw new Error(
      "discord_send_message: 'channel_id' must be a numeric Discord channel id (17–20 digits)",
    );
  }

  // 2. Validate the content body.
  const content = args.content;
  if (typeof content !== "string" || content.length === 0) {
    throw new Error("discord_send_message: 'content' must be a non-empty string");
  }
  if (content.length > DISCORD_CONTENT_MAX) {
    throw new Error(
      `discord_send_message: 'content' exceeds the ${DISCORD_CONTENT_MAX}-character Discord limit`,
    );
  }

  // 3. Egress gates (handler-called, B3 posture): secret-shape (F3a) on the body then
  //    the Discord recipient allowlist on `channel_id`. Throws -32035 / -32019 on denial.
  await enforceDiscordEgressGates(ctx, {
    tool: "discord_send_message",
    channel_id,
    body: content,
  });

  // 4. Send. The token is read inline from the service-token credential and placed in
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
