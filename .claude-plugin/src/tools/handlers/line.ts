// v1.66 Phase C PR 2 — the LINE Official Account handler (the first class-B
// SERVICE-TOKEN connector tool).
//
// docs/v1.66-line-oa-connector.md §6. line_push_message sends ONE text message to a
// known LINE id (user / group / room) via the Messaging API push endpoint.
//
// SERVICE-TOKEN: this handler reads the channel access token via
// requireServiceToken(ctx) (handlers/shared.ts) — the R6 narrow that throws if the
// credential is not the service-token kind — and uses it ONLY inline when building
// the Authorization header (never stored). It NEVER calls requireOAuth (no Google
// account). The cross-cutting envelope (tier / write-burst / sanitize / audit) is
// applied by withNonOAuthContext around this handler.
//
// EGRESS: the handler calls the centralized enforceLineEgressGates (tools/egress.ts)
// BEFORE the SDK call (the B3 handler-called posture, consistent with gmail_send):
// secret-shape (F3a) on the body + the LINE recipient allowlist on `to`.
//
// SSRF: the API host (api.line.me) is HARDCODED — the user-controlled `to`/`text` go
// in the request BODY, never the URL, so there is no SSRF surface (contrast web_fetch
// whose URL is user-supplied). Only `type:"text"` messages are constructible:
// image/sticker/flex/template messages carry external URLs LINE fetches server-side
// (SSRF-by-proxy) and are structurally impossible to send here (allowlist-construction).

import { LINE_ID_RE } from "../../policy/line-recipient-allowlist";
import { enforceLineEgressGates } from "../egress";
import type { ToolContext } from "../types";
import { postServiceTokenJson } from "./service-token-fetch";
import { assertEgressHost } from "../../policy/egress-destinations";
import { requireServiceToken } from "./shared";

/** LINE Messaging API push endpoint — a fixed, trusted host (no SSRF surface). */
const LINE_PUSH_URL = "https://api.line.me/v2/bot/message/push";

/** LINE text-message character limit (Messaging API). */
const LINE_TEXT_MAX = 5000;

/** Test-injection seam — production leaves it undefined (→ the real global fetch).
 *  Tests inject a stub to assert validation / egress / error mapping without a
 *  network. */
export interface LinePushDeps {
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

export async function linePushMessage(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: LinePushDeps = {},
): Promise<unknown> {
  // 1. Validate the recipient id (well-formedness). Plain Error (bad input) —
  //    mirrors the web_fetch handler's arg-validation convention; echoes the RULE,
  //    never the value. A well-formed id LINE later rejects (400) → line_api_failed
  //    {invalid_recipient} below (distinct from this fail-fast input check).
  const to = args.to;
  if (typeof to !== "string" || !LINE_ID_RE.test(to)) {
    throw new Error(
      "line_push_message: 'to' must be a valid LINE id (U/C/R followed by 32 hex chars)",
    );
  }

  // 2. Validate the text body.
  const text = args.text;
  if (typeof text !== "string" || text.length === 0) {
    throw new Error("line_push_message: 'text' must be a non-empty string");
  }
  if (text.length > LINE_TEXT_MAX) {
    throw new Error(
      `line_push_message: 'text' exceeds the ${LINE_TEXT_MAX}-character LINE limit`,
    );
  }

  // 3. Egress gates (handler-called, B3 posture): secret-shape (F3a) on the body
  //    then the LINE recipient allowlist on `to`. Throws -32035 / -32019 on denial.
  await enforceLineEgressGates(ctx, { tool: "line_push_message", to, body: text });

  // 4. Send. Token read inline from the service-token credential; never stored.
  const token = requireServiceToken(ctx).token();
  // Send via the shared service-token fetch (hard timeout + response-body cleanup +
  // closed-set error mapping; v1.69.1). Allowlist-constructed body: ONLY a single
  // type:"text" message — no image/flex/template can be smuggled in → no SSRF-by-proxy.
  // v1.88 — destination backstop: assert the host is the registered line host
  // before the fetch (throws -32047, echoing the host only — never the URL).
  assertEgressHost(new URL(LINE_PUSH_URL).hostname, "line");
  await postServiceTokenJson({
    url: LINE_PUSH_URL,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: { to, messages: [{ type: "text", text }] },
    mapStatus: mapStatusToReason,
    errorName: "line_api_failed",
    fetchImpl: deps.fetchImpl,
  });

  // Success. The returned fields are all trusted/constructed (no upstream content),
  // but flow through the source's sanitize tree-walk in the choke point regardless.
  return { to, sent: true, message_type: "text" };
}
