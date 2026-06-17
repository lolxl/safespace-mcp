// v1.65 Phase C — the web_fetch handler (the first KEYLESS connector tool).
//
// docs/v1.65-web-fetch-connector.md §3/§5. web_fetch retrieves the text content
// of an http(s) URL through the SSRF gate (policy/url-gate.ts) and returns it.
//
// KEYLESS: this handler NEVER reads `ctx.credential` — there is no Google account,
// no OAuth token, no `requireOAuth`. The cross-cutting envelope (tier / write-burst
// / sanitize `<untrusted-source>` wrap / audit) is applied by `withKeylessContext`
// around this handler; ALL the connector-specific security (scheme / private-IP /
// redirect / size / content-type) lives in the gate. The handler is deliberately
// thin: validate the one arg, call the gate, map a stray error.
//
// The returned object's string fields (`url` / `final_url` / `content_type` /
// `content`) are ALL attacker-influenced (a redirect can rewrite `final_url`; the
// origin controls `content_type` + `content`) → they are sanitize-wrapped by the
// shared tree-walk with the web-fetch Source's EMPTY skipFields, so every field
// wraps (no opaque-key carve-out).

import { fetchThroughGate, mapWebFetchError } from "../../policy/url-gate";
import type { ToolContext } from "../types";

/** Test-injection seam — production leaves it undefined (→ the real SSRF-gated
 *  `fetchThroughGate`). Tests inject a stub to assert the handler's validation +
 *  error mapping without standing up a network. */
export interface WebFetchDeps {
  fetch?: typeof fetchThroughGate;
}

export async function webFetchHandler(
  _ctx: ToolContext,
  args: Record<string, unknown>,
  deps: WebFetchDeps = {},
): Promise<unknown> {
  const url = args.url;
  if (typeof url !== "string" || url.trim() === "") {
    // Plain Error (bad input) — not an MCPError; mirrors the handler-side
    // arg-validation convention (forms `requireUrlSafeId`, etc.).
    throw new Error("web_fetch: 'url' must be a non-empty string");
  }
  const fetcher = deps.fetch ?? fetchThroughGate;
  try {
    return await fetcher(url.trim());
  } catch (err) {
    // The gate throws MCPErrors (-32036 / -32037 / -32007); mapWebFetchError
    // passes those through and wraps any unexpected non-MCPError as a generic
    // operational failure (never leaks the raw error string).
    throw mapWebFetchError(err);
  }
}
