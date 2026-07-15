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
// EGRESS (B6.1 wave A1 — PIPELINE-FIRED): the egress gate — secret-shape (F3a) on the
// body + the LINE recipient allowlist on `to` — is fired by withNonOAuthContext via
// this tool's egress descriptor (tools/egress-pipeline.ts) BEFORE this handler runs.
// The handler must NOT invoke the gate itself (a double fire would double
// requireSendApproval + the denial audit rows); the call-site sentinel
// (egress-callsite.test.ts) enforces both directions.
//
// SSRF: the API host (api.line.me) is HARDCODED — the user-controlled `to`/`text` go
// in the request BODY, never the URL, so there is no SSRF surface (contrast web_fetch
// whose URL is user-supplied). Only `type:"text"` messages are constructible:
// image/sticker/flex/template messages carry external URLs LINE fetches server-side
// (SSRF-by-proxy) and are structurally impossible to send here (allowlist-construction).

import { LINE_ID_RE } from "../../policy/line-recipient-allowlist";
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

/** B6.1 wave A1 — the line_push_message arg validator, extracted so ONE pure function
 *  serves both call sites (single source, no drift): the pipeline's egress descriptor
 *  (`extract` in tools/egress-pipeline.ts, which runs BEFORE this handler) and the
 *  handler below. Throws the tool's plain-Error validation messages; echoes the RULE,
 *  never the value.
 *
 *  1. Recipient id well-formedness — a well-formed id LINE later rejects (400) →
 *     line_api_failed{invalid_recipient} (distinct from this fail-fast input check).
 *  2. Text body: non-empty + the LINE character limit. */
export function validateLineSendArgs(
  args: Record<string, unknown>,
): { to: string; text: string } {
  const to = args.to;
  if (typeof to !== "string" || !LINE_ID_RE.test(to)) {
    throw new Error(
      "line_push_message: 'to' must be a valid LINE id (U/C/R followed by 32 hex chars)",
    );
  }
  const text = args.text;
  if (typeof text !== "string" || text.length === 0) {
    throw new Error("line_push_message: 'text' must be a non-empty string");
  }
  if (text.length > LINE_TEXT_MAX) {
    throw new Error(
      `line_push_message: 'text' exceeds the ${LINE_TEXT_MAX}-character LINE limit`,
    );
  }
  return { to, text };
}

export async function linePushMessage(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: LinePushDeps = {},
): Promise<unknown> {
  // 1. Validate args. The pipeline already validated them via this SAME function (the
  //    egress descriptor's extract, BEFORE this handler); this call is defense-in-depth
  //    + the unit-test surface (pure, identical result — cheap re-validation).
  const { to, text } = validateLineSendArgs(args);

  // 2. Send. Token read inline from the service-token credential; never stored.
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
