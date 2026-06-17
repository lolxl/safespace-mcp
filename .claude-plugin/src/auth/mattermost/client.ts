// v1.107 — the hardened Mattermost REST v4 READ helper (mirrors auth/slack/client.ts).
//
// Differences from the Slack client:
//   - the host is NOT a fixed constant — it is the OWNER-configured base URL
//     (auth/mattermost/base-url.ts), resolved here and pinned by `assertEgressHost`.
//   - Mattermost uses REAL HTTP status codes (no Slack-style 200-but-`{ok:false}`), so
//     failure classification is status-code only — no response-body error parsing.
//
// SECURITY / no-leak:
//   - the bot token is placed ONLY in the Authorization header, never logged or echoed;
//     ANY failure throws ONLY `mattermost_api_failed{reason}` with a CLOSED-SET reason —
//     never the raw error, status text, response body, server URL, or token.
//   - the destination host is pinned by `assertEgressHost(host, "mattermost")` (the live
//     configured host) BEFORE the fetch — a connector bug or a path that escapes the host
//     is blocked (-32047, host-only echo).
//   - `path` is constructed by the handler from a CLOSED set of endpoint templates with
//     MATTERMOST_ID_RE-validated ids (anchored `[a-z0-9]{26}`, no `/`/`.`/`@`), so an id
//     can neither traverse the path nor escape the host; the query is URL-encoded.
//   - a hard AbortController timeout (cleared after the bounded body read) + a streaming
//     byte cap (context protection) bound a hung / oversized upstream.

import { MCPError } from "../../errors";
import { assertEgressHost } from "../../policy/egress-destinations";
import { MAX_RESPONSE_BYTES, readBounded } from "../http/bounded-read";
import { requireMattermostBaseUrl } from "./base-url";

const USER_AGENT = "safespace-mcp";
const DEFAULT_TIMEOUT_MS = 10_000;

/** The closed-set operational reason for a `mattermost_api_failed` (-32053). */
export type MattermostReadReason = "auth_failed" | "rate_limited" | "not_found" | "api_error";

/** Map a non-2xx HTTP status to the closed-set reason. Mattermost returns proper codes:
 *  401/403 auth, 404 not-found, 429 throttle, everything else generic. */
function mapStatusToReason(status: number): MattermostReadReason {
  if (status === 401 || status === 403) return "auth_failed";
  if (status === 404) return "not_found";
  if (status === 429) return "rate_limited";
  return "api_error";
}

export interface MattermostGetOptions {
  /** The bot token (read inline from the service-token credential by the handler). */
  token: string;
  /** The REST path AFTER `/api/v4/` (handler-built from a closed template + validated
   *  ids), e.g. `users/me/teams` or `channels/<id>/posts`. NEVER raw user input. */
  path: string;
  /** Query params; undefined values are dropped, the rest URL-encoded. */
  query?: Record<string, string | number | undefined>;
  /** Test seam — production passes undefined → the real global fetch. */
  fetchImpl?: typeof fetch;
  /** Override the request timeout (default {@link DEFAULT_TIMEOUT_MS}). */
  timeoutMs?: number;
}

/** GET a Mattermost REST v4 endpoint and return the parsed JSON body (an object or an
 *  array — Mattermost list endpoints return a top-level array). Throws
 *  `mattermost_api_failed{reason}`: `no_server_url` (via requireMattermostBaseUrl) when
 *  the server URL is unset/invalid; `api_error` on timeout / network / oversize /
 *  unparseable; the status-mapped reason on a non-2xx. NEVER echoes the token, URL, or body. */
export async function mattermostApiGet(opts: MattermostGetOptions): Promise<unknown> {
  const base = requireMattermostBaseUrl(); // throws mattermost_api_failed{no_server_url}
  const doFetch = opts.fetchImpl ?? fetch;
  const url = new URL(`${base}/api/v4/${opts.path}`);
  // Destination backstop: the host MUST equal the configured server host (throws -32047,
  // echoing the host only). Fail-closed if the URL is somehow not the configured host.
  assertEgressHost(url.hostname, "mattermost");
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
    throw new MCPError("mattermost_api_failed", { reason: "api_error" });
  }
  const len = Number(res.headers.get("content-length"));
  if (Number.isFinite(len) && len > MAX_RESPONSE_BYTES) {
    clearTimeout(timer);
    res.body?.cancel().catch(() => undefined);
    throw new MCPError("mattermost_api_failed", { reason: "api_error" });
  }
  let text: string;
  try {
    text = await readBounded(res, MAX_RESPONSE_BYTES);
  } catch {
    clearTimeout(timer);
    throw new MCPError("mattermost_api_failed", { reason: "api_error" });
  }
  clearTimeout(timer);
  if (!res.ok) {
    throw new MCPError("mattermost_api_failed", { reason: mapStatusToReason(res.status) });
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new MCPError("mattermost_api_failed", { reason: "api_error" });
  }
}
