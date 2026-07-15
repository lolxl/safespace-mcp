// v1.66 Phase C PR 2 — LINE Official Account tool definitions (the FIRST
// service-token, non-Google connector). Assembled by ./index.ts.
// docs/v1.66-line-oa-connector.md §6.
//
// `source: "line"` opts these tools out of the Google-OAuth choke point: the proxy
// reads `sourceFor(def).authModel === "service-token"` (!== "oauth") and routes them
// through `withNonOAuthContext`. `requiredScopes: []` (no OAuth — the channel access
// token is read from the service-token store). `min_tier: "share"` (an egress send to
// a recipient — the gmail_send tier). `direction: "outbound-write"` marks it for the
// egress gates — PIPELINE-FIRED via the def's descriptor field (B6.1 wave A1): the
// non-OAuth choke point runs extract → gate (tools/egress-pipeline.ts) BEFORE the handler.

import { lineEgressDescriptor } from "../egress-pipeline";
import * as handlers from "../handlers";
import type { ToolDef } from "./types";

export const lineTools: Record<string, ToolDef> = {
  line_push_message: {
    name: "line_push_message",
    description:
      "Send a text message to a LINE user, group, or room via a LINE Official " +
      "Account (WRITE / egress; uses the configured channel access token, no Google " +
      "account). Pass `to` (a LINE id: U/C/R + 32 hex) and `text` (≤ 5000 chars). " +
      "Only plain TEXT is sent — image/sticker/flex messages are not supported (they " +
      "would let a remote URL be fetched server-side). The recipient is gated by the " +
      "SAFESPACE_LINE_RECIPIENT_ALLOW allowlist and the outbound secret-shape guard. " +
      "Requires a channel token configured via `safespace line set-token` or " +
      "SAFESPACE_LINE_CHANNEL_TOKEN.",
    inputSchema: {
      type: "object",
      properties: {
        to: {
          type: "string",
          description:
            "The LINE recipient id — a user (U…), group (C…), or room (R…) id, each " +
            "32 hex chars. Obtained out-of-band (no inbound webhook this version).",
        },
        text: {
          type: "string",
          description: "The message text (1–5000 characters).",
        },
      },
      required: ["to", "text"],
      additionalProperties: false,
    },
    requiredScopes: [],
    handler: handlers.linePushMessage,
    min_tier: "share",
    source: "line",
    direction: "outbound-write",
    egress: lineEgressDescriptor,
  },
};
