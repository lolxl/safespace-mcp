// v1.97 — the hardened Slack Web API READ helper (mirrors auth/notion/client.ts).
//
// docs-archive/v1.97-slack-read.md §2. The FIRST class-B service-token READ: the outbound
// `postServiceTokenJson` (tools/handlers/service-token-fetch.ts) deliberately DISCARDS the
// response body, so reads — which need the parsed JSON — get this dedicated GET client (the
// proven auth/notion/client.ts pattern). A shared `getServiceTokenJson` for service-token
// reads is deferred until a 2nd service-token reader exists (the sample-size-1 lesson).
//
// SECURITY / no-leak:
//   - the bot token is placed ONLY in the Authorization header, never logged or echoed; on
//     ANY failure this throws ONLY `slack_api_failed{reason}` with a CLOSED-SET reason —
//     never the raw error, the status text, or the response body.
//   - the host is HARDCODED `slack.com` + `assertEgressHost` backstops before the fetch;
//     `method` is a fixed Web-API method string (caller-supplied from a constant, never
//     user input) and the query is URL-encoded via URLSearchParams → no SSRF / traversal.
//   - a hard AbortController timeout (cleared after the bounded body read) + a streaming
//     byte cap (context protection) bound a hung / oversized upstream.
//   - Slack's quirk: chat/Web-API methods return HTTP 200 even on a LOGICAL failure
//     (`{ok:false, error}`); after the 2xx + parse, `ok !== true` maps the `error` STRING
//     to a closed-set reason (never echoed).

import { MCPError } from "../../errors";
import { assertEgressHost } from "../../policy/egress-destinations";
import { MAX_RESPONSE_BYTES, readBounded } from "../http/bounded-read";

const SLACK_API = "https://slack.com/api";
const USER_AGENT = "safespace-mcp";
const DEFAULT_TIMEOUT_MS = 10_000;

/** The closed-set operational reason for a read `slack_api_failed` (-32049). */
export type SlackReadReason = "auth_failed" | "rate_limited" | "not_found" | "api_error";

/** Map a non-ok HTTP status to the closed-set reason (429 throttle, 5xx, edge auth). */
function mapStatusToReason(status: number): SlackReadReason {
  if (status === 401 || status === 403) return "auth_failed";
  if (status === 429) return "rate_limited";
  return "api_error";
}

/** Map a Slack 200-but-`{ok:false}` `error` string to the closed-set reason. The string is
 *  read only to classify — NEVER echoed (it can name the channel/user). */
function mapBodyError(error: string): SlackReadReason {
  switch (error) {
    case "not_authed":
    case "invalid_auth":
    case "account_inactive":
    case "token_revoked":
    case "token_expired":
    case "no_permission":
    case "missing_scope":
    case "not_allowed_token_type":
      return "auth_failed";
    case "channel_not_found":
    case "not_in_channel":
    case "user_not_found":
    case "is_archived":
      return "not_found";
    case "rate_limited":
    case "ratelimited":
      return "rate_limited";
    default:
      return "api_error";
  }
}

/** The Slack Web API read methods this client serves. A closed UNION (not `string`) so a
 *  caller can never pass a user-derived method into the URL path (compile-time SSRF guard;
 *  defense-in-depth atop `assertEgressHost`). Extend as read methods are added. */
export type SlackReadMethod = "conversations.list" | "conversations.history" | "users.list" | "users.info";

export interface SlackGetOptions {
  /** The bot token (read inline from the service-token credential by the handler). */
  token: string;
  /** The Slack Web API method — a fixed constant from the closed union, never user input. */
  method: SlackReadMethod;
  /** Query params; undefined values are dropped, the rest URL-encoded. */
  query?: Record<string, string | number | undefined>;
  /** Test seam — production passes undefined → the real global fetch. */
  fetchImpl?: typeof fetch;
  /** Override the request timeout (default {@link DEFAULT_TIMEOUT_MS}). */
  timeoutMs?: number;
}

/** GET a Slack Web API method and return the parsed `{ok:true, …}` body. Throws
 *  `slack_api_failed{reason}` on a timeout / network failure (`api_error`), a non-ok HTTP
 *  status (`mapStatusToReason`), an oversized response (`api_error`), unparseable JSON
 *  (`api_error`), or a 200-but-`{ok:false}` body (`mapBodyError`). NEVER echoes the token,
 *  the URL, or the response body. */
export async function slackApiGet(opts: SlackGetOptions): Promise<Record<string, unknown>> {
  const doFetch = opts.fetchImpl ?? fetch;
  const url = new URL(`${SLACK_API}/${opts.method}`);
  // Destination backstop: assert the host is the registered slack host BEFORE the fetch
  // (throws -32047, echoing the host only). No-op on the normal slack.com.
  assertEgressHost(url.hostname, "slack");
  if (opts.query) {
    for (const [k, v] of Object.entries(opts.query)) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }
  }
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  let res: Response;
  try {
    res = await doFetch(url.toString(), {
      method: "GET",
      headers: { Authorization: `Bearer ${opts.token}`, "User-Agent": USER_AGENT },
      signal: ac.signal,
    });
  } catch {
    clearTimeout(timer);
    throw new MCPError("slack_api_failed", { reason: "api_error" });
  }
  // Fast-reject an oversized response by its declared Content-Length…
  const len = Number(res.headers.get("content-length"));
  if (Number.isFinite(len) && len > MAX_RESPONSE_BYTES) {
    clearTimeout(timer);
    res.body?.cancel().catch(() => undefined);
    throw new MCPError("slack_api_failed", { reason: "api_error" });
  }
  // …but ALSO bound the ACTUAL read (a chunked / absent-Content-Length body bypasses the
  // header check). The read stays under the timer, which we only clear after it completes.
  let text: string;
  try {
    text = await readBounded(res, MAX_RESPONSE_BYTES);
  } catch {
    clearTimeout(timer);
    throw new MCPError("slack_api_failed", { reason: "api_error" });
  }
  clearTimeout(timer);
  if (!res.ok) {
    throw new MCPError("slack_api_failed", { reason: mapStatusToReason(res.status) });
  }
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new MCPError("slack_api_failed", { reason: "api_error" });
  }
  const obj = body && typeof body === "object" && !Array.isArray(body) ? (body as Record<string, unknown>) : null;
  if (obj === null) throw new MCPError("slack_api_failed", { reason: "api_error" });
  // Slack signals a logical failure with a 200 + {ok:false, error}; classify the error
  // string into the closed set (never echo it).
  if (obj.ok !== true) {
    throw new MCPError("slack_api_failed", {
      reason: mapBodyError(typeof obj.error === "string" ? obj.error : ""),
    });
  }
  return obj;
}
