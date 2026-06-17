// v1.98 — the hardened Telegram Bot API READ helper (mirrors auth/slack/client.ts).
//
// Telegram's FIRST read client. The outbound telegram_send_message rides the
// body-discarding postServiceTokenJson (tools/handlers/service-token-fetch.ts); a READ
// (getUpdates) needs the parsed JSON, so it gets this dedicated GET client — the proven
// auth/slack/client.ts pattern, reusing the shared auth/http/bounded-read.ts byte cap.
//
// SECURITY / no-leak — TOKEN-IN-URL (the Telegram-specific invariant, unlike Slack's
// Bearer header): Telegram places the bot token in the request URL PATH
// (https://api.telegram.org/bot<TOKEN>/getUpdates). The URL string therefore CONTAINS the
// secret, so the no-echo discipline is LOAD-BEARING here — a careless URL echo would leak
// the token. On ANY failure this throws ONLY telegram_api_failed{reason} with a CLOSED-SET
// reason — never the URL, the raw error, the status text, or the response body.
//   - the host is HARDCODED api.telegram.org + assertEgressHost backstops before the fetch
//     (new URL(url).hostname strips the token path → -32047 echoes the host only).
//   - `method` is a fixed closed-union string (never user input) → no path-injection SSRF.
//   - a hard AbortController timeout (cleared after the bounded read) + a streaming byte cap.
//   - Telegram's failure model: {ok:false, error_code, description}. After the parse,
//     ok !== true maps the numeric error_code to a closed-set reason; `description` is read
//     ONLY to be ignored (it can name a chat/user → NEVER echoed).

import { MCPError } from "../../errors";
import { assertEgressHost } from "../../policy/egress-destinations";
import { MAX_RESPONSE_BYTES, readBounded } from "../http/bounded-read";

const TELEGRAM_API = "https://api.telegram.org";
const DEFAULT_TIMEOUT_MS = 10_000;

/** The closed-set operational reason for a read telegram_api_failed (-32039). `no_token`
 *  is produced earlier by the telegram Source's resolveCredential — not here. */
export type TelegramReadReason = "auth_failed" | "rate_limited" | "not_found" | "api_error";

/** Map a Telegram HTTP status / `error_code` (they share HTTP semantics) to the closed-set
 *  reason. 401/403 → auth_failed; 429 → rate_limited; 404 → not_found; else api_error. */
function mapCodeToReason(code: number): TelegramReadReason {
  if (code === 401 || code === 403) return "auth_failed";
  if (code === 429) return "rate_limited";
  if (code === 404) return "not_found";
  return "api_error";
}

/** The Telegram Bot API read methods this client serves. A closed UNION (not `string`) so a
 *  caller can never pass a user-derived method into the token-bearing URL path (compile-time
 *  SSRF guard; defense-in-depth atop assertEgressHost). Extend as read methods are added. */
export type TelegramReadMethod = "getUpdates";

export interface TelegramGetOptions {
  /** The bot token (read inline from the service-token credential by the handler). Placed
   *  in the URL PATH — see the no-leak note above. */
  token: string;
  /** The Bot API method — a fixed constant from the closed union, never user input. */
  method: TelegramReadMethod;
  /** Query params; undefined values are dropped, the rest URL-encoded. */
  query?: Record<string, string | number | undefined>;
  /** Test seam — production passes undefined → the real global fetch. */
  fetchImpl?: typeof fetch;
  /** Override the request timeout (default {@link DEFAULT_TIMEOUT_MS}). */
  timeoutMs?: number;
}

/** GET a Telegram Bot API method and return the parsed `{ok:true, result, …}` body. Throws
 *  telegram_api_failed{reason} on a timeout / network failure (`api_error`), a non-ok HTTP
 *  status (`mapCodeToReason`), an oversized response (`api_error`), unparseable JSON
 *  (`api_error`), or a `{ok:false, error_code}` body. NEVER echoes the token, the URL (it
 *  holds the token), or the response body. */
export async function telegramApiGet(opts: TelegramGetOptions): Promise<Record<string, unknown>> {
  const doFetch = opts.fetchImpl ?? fetch;
  // TOKEN-IN-PATH: the URL string contains the secret — built here, NEVER echoed in any
  // thrown error (only {reason} surfaces).
  const url = new URL(`${TELEGRAM_API}/bot${opts.token}/${opts.method}`);
  // Destination backstop: hostname strips the bot-token path → -32047 echoes the host only.
  assertEgressHost(url.hostname, "telegram");
  if (opts.query) {
    for (const [k, v] of Object.entries(opts.query)) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }
  }
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  let res: Response;
  try {
    res = await doFetch(url.toString(), { method: "GET", signal: ac.signal });
  } catch {
    clearTimeout(timer);
    throw new MCPError("telegram_api_failed", { reason: "api_error" });
  }
  // Fast-reject an oversized response by its declared Content-Length…
  const len = Number(res.headers.get("content-length"));
  if (Number.isFinite(len) && len > MAX_RESPONSE_BYTES) {
    clearTimeout(timer);
    res.body?.cancel().catch(() => undefined);
    throw new MCPError("telegram_api_failed", { reason: "api_error" });
  }
  // …but ALSO bound the ACTUAL read (a chunked / absent-Content-Length body bypasses the
  // header check). The read stays under the timer, which we only clear after it completes.
  let text: string;
  try {
    text = await readBounded(res, MAX_RESPONSE_BYTES);
  } catch {
    clearTimeout(timer);
    throw new MCPError("telegram_api_failed", { reason: "api_error" });
  }
  clearTimeout(timer);
  if (!res.ok) {
    throw new MCPError("telegram_api_failed", { reason: mapCodeToReason(res.status) });
  }
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new MCPError("telegram_api_failed", { reason: "api_error" });
  }
  const obj = body && typeof body === "object" && !Array.isArray(body) ? (body as Record<string, unknown>) : null;
  if (obj === null) throw new MCPError("telegram_api_failed", { reason: "api_error" });
  // Telegram signals a logical failure with {ok:false, error_code, description}; classify
  // the numeric error_code into the closed set (the description can name a chat/user → NEVER
  // echo it).
  if (obj.ok !== true) {
    const code = typeof obj.error_code === "number" ? obj.error_code : 0;
    throw new MCPError("telegram_api_failed", { reason: mapCodeToReason(code) });
  }
  return obj;
}
