// v1.69.1 — the shared class-B service-token egress fetch (LINE / Telegram / Discord).
//
// docs/v1.69.1-service-token-fetch-hardening.md. Before v1.69.1 each of the three
// service-token connector handlers (line.ts / telegram.ts / discord.ts) carried a
// BYTE-IDENTICAL `fetch → catch→api_error → !res.ok→map(status)` block, and NONE of them
// bounded the request: a hung upstream connection would stall the MCP tool slot
// indefinitely (the v1.69 security/code review's shared LOW across all three), and the
// unread response body held the socket open. This helper centralizes that block ONCE,
// adding the two robustness fixes so all three connectors inherit them and cannot drift:
//
//   1. A hard request TIMEOUT (AbortController). On timeout the AbortError is caught the
//      same way a DNS/connection failure is — mapped to the closed-set `api_error`
//      reason (no new error reason; the connectors' reason sets are unchanged).
//   2. The response body is DISCARDED (`res.body?.cancel()`) on every path — the
//      connectors construct their own trusted success shape and never read it, so
//      cancelling releases the socket for reuse.
//
// BEHAVIOR-PRESERVING: for a fast-responding upstream the observable behavior is
// byte-identical to pre-v1.69.1 (same success/throw, same closed-set reasons) — the
// timeout only changes the previously-unbounded hung-connection case (∞ → api_error).
//
// SECURITY: this helper NEVER reads, logs, or echoes the URL (which can hold a token for
// Telegram), the headers (which can hold a Bearer/Bot token), or the body. On any
// failure it throws ONLY `errorName{reason}` with a closed-set reason — never the raw
// error, the status text, or the response body.

import { MCPError } from "../../errors";

/** The closed-set operational reason shared by the class-B service-token connectors.
 *  (`no_token` is produced earlier, in each Source's resolveCredential — not here.) */
export type ServiceTokenReason =
  | "auth_failed"
  | "rate_limited"
  | "invalid_recipient"
  | "api_error";

/** The `*_api_failed` MCPError names of the class-B service-token connectors. */
export type ServiceTokenErrorName =
  | "line_api_failed"
  | "telegram_api_failed"
  | "discord_api_failed"
  | "slack_api_failed"
  | "mattermost_api_failed";

/** Default request timeout (ms). Mirrors the v1.65 web-fetch connector's 10 s default. */
export const SERVICE_TOKEN_TIMEOUT_MS = 10_000;

export interface ServiceTokenPostOptions {
  /** The fully-built endpoint URL (may contain a token path segment, e.g. Telegram). */
  url: string;
  /** Request headers (may contain an Authorization token, e.g. LINE/Discord). */
  headers: Record<string, string>;
  /** The request body OBJECT — the helper JSON-serializes it (allowlist-constructed by
   *  the caller; the helper adds nothing). */
  body: unknown;
  /** Map a non-ok HTTP status to the connector's closed-set reason. */
  mapStatus: (status: number) => ServiceTokenReason;
  /** The connector's `*_api_failed` MCPError name. */
  errorName: ServiceTokenErrorName;
  /** Test seam — production passes undefined → the real global fetch. */
  fetchImpl?: typeof fetch;
  /** Override the request timeout (default {@link SERVICE_TOKEN_TIMEOUT_MS}). */
  timeoutMs?: number;
  /** v1.95 (C1) — OPTIONAL body-level success check, for connectors (Slack) that return
   *  HTTP 200 even on a logical failure (`{ok:false, error}` in the body). When provided,
   *  the helper READS + JSON-parses the response body (under the SAME timeout) and calls
   *  this with the parsed value: return `null` if the response is a success, or a
   *  closed-set {@link ServiceTokenReason} to fail with. When ABSENT (LINE/Telegram/
   *  Discord) the body is discarded unread — byte-identical to the pre-v1.95 behavior.
   *  The callback receives ONLY the parsed RESPONSE body, never the token-bearing
   *  url/headers. */
  checkBody?: (parsedBody: unknown) => ServiceTokenReason | null;
}

/** POST a JSON body to a class-B service-token endpoint with a hard request timeout,
 *  closed-set error mapping, and response-body handling. Resolves on success; throws
 *  `errorName{reason}` on a timeout / network failure (`api_error`) or a non-ok status
 *  (`mapStatus(status)`). Without `checkBody` the response body is discarded unread (the
 *  connector builds its own trusted success shape); with `checkBody` (Slack) the body is
 *  read + parsed UNDER THE TIMEOUT and consulted for a 200-but-logically-failed response.
 *  NEVER echoes the URL / headers / request body / raw error / response body. */
export async function postServiceTokenJson(opts: ServiceTokenPostOptions): Promise<void> {
  const doFetch = opts.fetchImpl ?? fetch;
  // Serialize the body BEFORE the try: a non-serializable body (a caller bug — a
  // circular ref / BigInt) is a programming error that should surface as a clear
  // synchronous throw, NOT be caught and masked as a network `api_error`.
  const serializedBody = JSON.stringify(opts.body);
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), opts.timeoutMs ?? SERVICE_TOKEN_TIMEOUT_MS);
  let res: Response;
  try {
    res = await doFetch(opts.url, {
      method: "POST",
      headers: opts.headers,
      body: serializedBody,
      signal: ac.signal,
    });
  } catch {
    // Network failure (DNS / connection reset) OR the timeout firing (AbortError). NEVER
    // leak the raw error, the URL (can hold a token), or the body — collapse to api_error.
    clearTimeout(timer);
    throw new MCPError(opts.errorName, { reason: "api_error" });
  }

  // v1.95 (C1) — body-checking connectors (Slack: HTTP 200 can still be a logical
  // failure). READ + parse the body UNDER THE SAME timer (a hung body stream is bounded
  // by `ac`/`timer`, which we only clear AFTER the read), then classify. A read / parse
  // failure → fail closed (`api_error`), never echoing the raw body.
  if (opts.checkBody) {
    let parsed: unknown;
    try {
      const raw = await res.text();
      parsed = raw === "" ? null : JSON.parse(raw);
    } catch {
      clearTimeout(timer);
      throw new MCPError(opts.errorName, { reason: "api_error" });
    }
    clearTimeout(timer);
    // A genuine HTTP-level failure (e.g. 429 throttle) still maps off the status, ahead
    // of the body check. The `res.text()` above already consumed the body (releasing the
    // socket) regardless of status, so throwing here leaves no dangling stream.
    if (!res.ok) {
      throw new MCPError(opts.errorName, { reason: opts.mapStatus(res.status) });
    }
    const reason = opts.checkBody(parsed);
    if (reason !== null) {
      throw new MCPError(opts.errorName, { reason });
    }
    return;
  }

  clearTimeout(timer);
  // No checkBody — the connectors never read the response body, so cancel it (a
  // best-effort socket release, NOT a timeout-guarded step; the timer is already cleared).
  // Runs on the ok and non-ok paths (where `res` exists); a fetch throw never reaches
  // here, so there is no orphaned `res` to cancel.
  res.body?.cancel().catch(() => undefined);
  if (!res.ok) {
    // Map the HTTP status to a closed-set reason; NEVER echo the response body (it can
    // contain the recipient/channel/guild detail) or the request URL.
    throw new MCPError(opts.errorName, { reason: opts.mapStatus(res.status) });
  }
}
