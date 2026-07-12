// v1.115.1 — shared gated fetch for X process-owned HTTP (token endpoint +
// users/me + any future OAuth-path call). Deduplicates the byte-identical helper
// that lived in oauth.ts + consent.ts:
//   - assertEgressHost("x") BEFORE dispatch
//   - User-Agent: safespace-mcp
//   - 15s AbortController timeout, cleared in finally
//
// The tools client (client.ts) keeps its richer request core (bounded-read +
// MCPError status mapping) — this module is the OAuth-path pin only.

import { assertEgressHost } from "../../policy/egress-destinations";

const USER_AGENT = "safespace-mcp";
const NETWORK_TIMEOUT_MS = 15_000;

/** X's OAuth `error` field is a fixed lowercase-underscore enum
 *  (`invalid_grant`, `invalid_request`, …). Surface ONLY a value matching this
 *  shape so a reflected body can never leak into a thrown message. */
export const X_ERROR_CODE_RE = /^[a-z_]{1,64}$/;

/**
 * Gated fetch against an X host. Pins the destination via `assertEgressHost`
 * BEFORE dispatch, injects the SafeSpace User-Agent, and bounds the call with a
 * 15s AbortController (timer cleared in finally). Callers supply the fetch impl
 * (global in production; injected in tests — the injected impl ignores the
 * AbortSignal).
 */
export async function xFetch(
  fetchImpl: typeof fetch,
  url: string,
  init: RequestInit & { headers: Record<string, string> },
): Promise<Response> {
  // assertEgressHost BEFORE dispatch — every X process-owned fetch must pin the host.
  assertEgressHost(new URL(url).hostname, "x");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), NETWORK_TIMEOUT_MS);
  try {
    return await fetchImpl(url, {
      ...init,
      headers: { "User-Agent": USER_AGENT, ...init.headers },
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}
