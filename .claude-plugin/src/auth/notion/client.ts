// v1.77 — the hardened Notion REST helper (mirrors auth/github/client.ts).
//
// B6.1-B — this client IS the connector's error mapper (`notion_api_failed`, closed-set
// reasons): the contract is stated in src/auth/http/connector-error-contract.ts.
//
// docs/v1.77-notion-connector.md §3. A single place that performs an authenticated
// request to `https://api.notion.com{path}` and RETURNS the parsed JSON (the read tools
// need the body). GET (notionApiGet) for get_page / get_block_children / get_database;
// POST + JSON body (notionApiPost) for search / query_database.
//
// SECURITY / no-leak:
//   - the bearer token is placed ONLY in the Authorization header, never logged or
//     echoed; on ANY failure this throws ONLY `notion_api_failed{reason}` with a
//     CLOSED-SET reason — never the raw error, the status text, or the response body
//     (a 404 body can disclose object-existence detail).
//   - the host is HARDCODED `api.notion.com`; `path` is interpolated by the caller from
//     anchored-UUID-validated ids (handlers/notion.ts), and the query is URL-encoded via
//     URLSearchParams, so there is no SSRF / path-traversal surface.
//   - a hard AbortController timeout (cleared in finally) bounds a hung upstream; a
//     streaming byte cap bounds an oversized response (context protection).

import { MCPError } from "../../errors";
import { assertEgressHost } from "../../policy/egress-destinations";
import { MAX_RESPONSE_BYTES, readBounded } from "../http/bounded-read";

const NOTION_API = "https://api.notion.com";
/** Pinned Notion API version (stable). Sent on every request. */
const NOTION_VERSION = "2022-06-28";
const USER_AGENT = "safespace-mcp";
const DEFAULT_TIMEOUT_MS = 10_000;

/** The closed-set operational reason for a `notion_api_failed` (-32045). `no_token` is
 *  produced earlier, by the notion Source's resolveCredential — not here. */
export type NotionApiReason = "auth_failed" | "rate_limited" | "not_found" | "api_error";

/** Map an HTTP status to the closed-set reason. Notion: 401 unauthorized + 403
 *  restricted_resource → auth_failed; 404 object_not_found → not_found; 429 → rate_limited;
 *  400 validation_error and everything else → api_error. */
function mapStatusToReason(status: number): NotionApiReason {
  if (status === 401 || status === 403) return "auth_failed";
  if (status === 429) return "rate_limited";
  if (status === 404) return "not_found";
  return "api_error";
}

export interface NotionGetOptions {
  /** The bearer token (read inline from the service-token credential by the handler). */
  token: string;
  /** The API path, beginning with "/", built from validated ids by the caller. */
  path: string;
  /** Optional query params; undefined values are dropped, the rest URL-encoded. */
  query?: Record<string, string | number | undefined>;
  /** Test seam — production passes undefined → the real global fetch. */
  fetchImpl?: typeof fetch;
  /** Override the request timeout (default {@link DEFAULT_TIMEOUT_MS}). */
  timeoutMs?: number;
}

export interface NotionPostOptions {
  token: string;
  path: string;
  /** The request body OBJECT — allowlist-constructed by the caller; JSON-serialized here. */
  body: unknown;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

/** The shared GET/POST/PATCH core: one place with the hardened request (host hardcoded,
 *  Bearer + Notion-Version + UA, AbortController timeout, streaming byte cap,
 *  status→closed-set reason). NEVER echoes the token, URL, or response body. */
async function notionApiRequest(opts: {
  token: string;
  method: "GET" | "POST" | "PATCH";
  path: string;
  query?: Record<string, string | number | undefined>;
  body?: unknown;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}): Promise<unknown> {
  const doFetch = opts.fetchImpl ?? fetch;
  const url = new URL(NOTION_API + opts.path);
  // v1.88 — destination backstop: assert the final host is the registered notion
  // host BEFORE the fetch (catches a path-injection host escape; throws -32047,
  // echoing the host only). No-op on the normal api.notion.com.
  assertEgressHost(url.hostname, "notion");
  if (opts.query) {
    for (const [k, v] of Object.entries(opts.query)) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }
  }
  const headers: Record<string, string> = {
    Authorization: `Bearer ${opts.token}`,
    "Notion-Version": NOTION_VERSION,
    "User-Agent": USER_AGENT,
  };
  // Serialize BEFORE the try: a non-serializable body is a caller bug that should surface
  // as a clear synchronous throw, not be masked as a network api_error.
  let serializedBody: string | undefined;
  if (opts.body !== undefined) {
    serializedBody = JSON.stringify(opts.body);
    headers["Content-Type"] = "application/json";
  }
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
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
    throw new MCPError("notion_api_failed", { reason: "api_error" });
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    res.body?.cancel().catch(() => undefined);
    throw new MCPError("notion_api_failed", { reason: mapStatusToReason(res.status) });
  }
  // Fast-reject an oversized response by its declared Content-Length (cheap)…
  const len = Number(res.headers.get("content-length"));
  if (Number.isFinite(len) && len > MAX_RESPONSE_BYTES) {
    res.body?.cancel().catch(() => undefined);
    throw new MCPError("notion_api_failed", { reason: "api_error" });
  }
  // …but ALSO bound the ACTUAL read: a chunked / absent-Content-Length response would
  // bypass the header check above and let res.json() buffer unboundedly.
  let text: string;
  try {
    text = await readBounded(res, MAX_RESPONSE_BYTES);
  } catch {
    throw new MCPError("notion_api_failed", { reason: "api_error" });
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new MCPError("notion_api_failed", { reason: "api_error" });
  }
}

/** GET an api.notion.com resource and return the parsed JSON. Throws
 *  `notion_api_failed{reason}` on a timeout / network failure (`api_error`), a non-ok
 *  status (`mapStatusToReason`), an oversized response (`api_error`), or unparseable JSON
 *  (`api_error`). NEVER echoes the token, the URL, or the response body. */
export async function notionApiGet(opts: NotionGetOptions): Promise<unknown> {
  return notionApiRequest({ ...opts, method: "GET" });
}

/** POST an allowlist-constructed JSON body to api.notion.com (search / database query /
 *  create page) and return the parsed JSON. Same hardening + no-leak as {@link notionApiGet}. */
export async function notionApiPost(opts: NotionPostOptions): Promise<unknown> {
  return notionApiRequest({ ...opts, method: "POST" });
}

/** PATCH an allowlist-constructed JSON body to api.notion.com (v1.96 WRITE: update a
 *  page's properties / append block children) and return the parsed JSON. Same hardening
 *  + no-leak as {@link notionApiGet}. */
export async function notionApiPatch(opts: NotionPostOptions): Promise<unknown> {
  return notionApiRequest({ ...opts, method: "PATCH" });
}
