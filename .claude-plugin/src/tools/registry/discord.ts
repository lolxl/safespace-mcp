// v1.69 — Discord Bot tool definitions (the THIRD service-token, non-Google connector,
// after v1.66 LINE + v1.68 Telegram). Assembled by ./index.ts.
// docs/v1.69-discord-connector.md §2.
//
// `source: "discord"` opts these tools out of the Google-OAuth choke point: the proxy
// reads `sourceFor(def).authModel === "service-token"` (!== "oauth") and routes them
// through `withNonOAuthContext`. `requiredScopes: []` (no OAuth — the bot token is read
// from the service-token store). `min_tier: "share"` (an egress send to a recipient —
// the gmail_send / line / telegram tier). `direction: "outbound-write"` marks it for the
// egress gates — PIPELINE-FIRED via the def's descriptor field (B6.1 wave A1): the
// non-OAuth choke point runs extract → gate (tools/egress-pipeline.ts) BEFORE the handler.

import { discordEgressDescriptor } from "../egress-pipeline";
import * as handlers from "../handlers";
import type { ToolDef } from "./types";

export const discordTools: Record<string, ToolDef> = {
  discord_send_message: {
    name: "discord_send_message",
    description:
      "Send a text message to a Discord channel via a Discord Bot (WRITE / egress; uses " +
      "the configured bot token, no Google account). Pass `channel_id` (a numeric " +
      "Discord channel id, 17–20 digits) and `content` (≤ 2000 chars). Only plain TEXT " +
      "is sent — no embeds, components, or attachments, and `@everyone`/`@here`/role " +
      "mentions in the text are rendered inert (they never ping). The channel is gated " +
      "by the SAFESPACE_DISCORD_RECIPIENT_ALLOW allowlist and the outbound secret-shape " +
      "guard. Requires a bot token configured via `safespace discord set-token` or " +
      "SAFESPACE_DISCORD_BOT_TOKEN.",
    inputSchema: {
      type: "object",
      properties: {
        channel_id: {
          type: "string",
          description:
            "The Discord channel id — a numeric snowflake (17–20 digits). The bot must " +
            "be a member of the channel's server with permission to send messages.",
        },
        content: {
          type: "string",
          description: "The message text (1–2000 characters).",
        },
      },
      required: ["channel_id", "content"],
      additionalProperties: false,
    },
    requiredScopes: [],
    handler: handlers.discordSendMessage,
    min_tier: "share",
    source: "discord",
    direction: "outbound-write",
    egress: discordEgressDescriptor,
  },
};
