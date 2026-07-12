// v1.114 / v1.115 — the hardened X (Twitter) REST helpers (mirrors auth/notion/client.ts /
// auth/github/client.ts). The X OAuth tools use these for authenticated GETs/POSTs
// against `https://api.x.com{path}`.
//
// SECURITY / no-leak:
//   - the bearer token is placed ONLY in the Authorization header, never logged or
//     echoed; on ANY failure this throws ONLY `x_api_failed{reason}` with a CLOSED-SET
//     reason — never the raw error, the status text, or the response body (X error
//     bodies are RFC-7807-style `{type,title,detail,status}` free text).
//   - the host is HARDCODED `api.x.com`; `path` is a closed set the handlers pass
//     (never caller-constructed from agent input), and params are URL-encoded via
//     URLSearchParams, so there is no SSRF / path-traversal surface.
//   - a hard AbortController timeout (cleared in finally) bounds a hung upstream; a
//     streaming byte cap bounds an oversized response (context protection).
//   - POST bodies are caller-constructed (allowlist-built by the handler); never
//     echoed on failure.

import { MCPError } from "../../errors";
import { assertEgressHost } from "../../policy/egress-destinations";
import { MAX_RESPONSE_BYTES, readBounded } from "../http/bounded-read";

const X_API = "https://api.x.com";
const DEFAULT_TIMEOUT_MS = 15_000;

/** The closed-set operational reasons this client produces. `no_account` is produced
 *  earlier (by the x Source's resolveCredential), not here. */
export type XApiReason = "rate_limited" | "consent_required" | "api_error";

/** Map an HTTP status to the closed-set reason. Status code ONLY — never the X error
 *  body's free-text `title`/`detail`. 429 → rate_limited; 401 → consent_required
 *  (re-run consent); 403 and everything else → api_error (X uses 403 for permission /
 *  duplicate issues; no detail echoed). */
function mapStatusToReason(status: number): XApiReason {
  if (status === 429) return "rate_limited";
  if (status === 401) return "consent_required";
  return "api_error";
}

/** Shared request path for GET + POST. NEVER echoes token / URL / body / response. */
async function xApiRequest(opts: {
  method: "GET" | "POST";
  path: string;
  params?: Record<string, string>;
  body?: unknown;
  accessToken: string;
  fetchImpl?: typeof fetch;
}): Promise<unknown> {
  const doFetch = opts.fetchImpl ?? fetch;
  const url = new URL(X_API + opts.path);
  // Destination backstop: assert the final host is the registered x host BEFORE the
  // fetch (catches a path-injection host escape; throws -32047, echoing the host only).
  assertEgressHost(url.hostname, "x");
  if (opts.params) {
    for (const [k, v] of Object.entries(opts.params)) {
      url.searchParams.set(k, v);
    }
  }
  const headers: Record<string, string> = {
    Authorization: `Bearer ${opts.accessToken}`,
    Accept: "application/json",
  };
  // Serialize BEFORE the try: a non-serializable body is a caller bug that should
  // surface as a clear synchronous throw, not be masked as a network api_error.
  let serializedBody: string | undefined;
  if (opts.body !== undefined) {
    serializedBody = JSON.stringify(opts.body);
    headers["Content-Type"] = "application/json";
  }
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), DEFAULT_TIMEOUT_MS);
  let res: Response;
  try {
    res = await doFetch(url.toString(), {
      method: opts.method,
      headers,
      body: serializedBody,
      signal: ac.signal,
    });
  } catch {
    // Network failure (DNS / reset) OR the timeout firing (AbortError). NEVER leak the
    // raw error or the URL — collapse to api_error.
    throw new MCPError("x_api_failed", { reason: "api_error" });
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    res.body?.cancel().catch(() => undefined);
    // Status code ONLY decides the reason — never surface RFC-7807 title/detail free text.
    throw new MCPError("x_api_failed", { reason: mapStatusToReason(res.status) });
  }
  // Fast-reject an oversized response by its declared Content-Length (cheap)…
  const len = Number(res.headers.get("content-length"));
  if (Number.isFinite(len) && len > MAX_RESPONSE_BYTES) {
    res.body?.cancel().catch(() => undefined);
    throw new MCPError("x_api_failed", { reason: "api_error" });
  }
  // …but ALSO bound the ACTUAL read: a chunked / absent-Content-Length response would
  // bypass the header check above and let res.json() buffer unboundedly.
  let text: string;
  try {
    text = await readBounded(res, MAX_RESPONSE_BYTES);
  } catch {
    throw new MCPError("x_api_failed", { reason: "api_error" });
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new MCPError("x_api_failed", { reason: "api_error" });
  }
}

/**
 * Authenticated GET against `https://api.x.com{path}`.
 *
 * @param path - API path beginning with "/" (closed set from handlers, never agent-built)
 * @param params - query string params (URL-encoded); empty object OK
 * @param accessToken - bearer token (read inline from the oauth credential by the handler)
 * @param fetchImpl - test seam; production leaves undefined → real global fetch
 *
 * Throws `x_api_failed{reason}` on timeout / network failure (`api_error`), non-ok
 * status (`mapStatusToReason`), oversized response (`api_error`), or unparseable JSON
 * (`api_error`). NEVER echoes the token, the URL, the query, or the response body.
 */
export async function xApiGet(
  path: string,
  params: Record<string, string>,
  accessToken: string,
  fetchImpl?: typeof fetch,
): Promise<unknown> {
  return xApiRequest({ method: "GET", path, params, accessToken, fetchImpl });
}

/**
 * Authenticated POST against `https://api.x.com{path}` with an allowlist-constructed
 * JSON body (e.g. `{text}` for `POST /2/tweets`).
 *
 * Same hardening + no-leak as {@link xApiGet}. NEVER echoes the token, the URL, the
 * request body, or the response body. Status mapping: 429 → rate_limited; 401 →
 * consent_required; 403 / other !ok → api_error.
 */
export async function xApiPost(
  path: string,
  body: Record<string, unknown>,
  accessToken: string,
  fetchImpl?: typeof fetch,
): Promise<unknown> {
  return xApiRequest({ method: "POST", path, body, accessToken, fetchImpl });
}
