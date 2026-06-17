// v1.70 (G4) — the hardened GitHub REST GET helper (the G2-deferred file).
//
// The READ analogue of tools/handlers/service-token-fetch.ts `postServiceTokenJson`:
// a single place that performs an authenticated `GET https://api.github.com{path}`,
// with the same robustness + no-leak discipline, but RETURNS the parsed JSON (the
// read tools need the body, unlike the service-token POSTs which discard it).
//
// SECURITY / no-leak:
//   - the bearer token is placed ONLY in the Authorization header, never logged or
//     echoed; on ANY failure this throws ONLY `github_api_failed{reason}` with a
//     CLOSED-SET reason — never the raw error, the status text, or the response body
//     (a 404 body can disclose private-repo existence; a 403 body carries detail).
//   - the host is HARDCODED `api.github.com` — `path` is interpolated by the caller
//     from anchored-regex-validated segments (handlers/github.ts), and the query is
//     URL-encoded via `URLSearchParams`, so there is no SSRF / path-traversal surface.
//   - a hard AbortController timeout (cleared in finally) bounds a hung upstream;
//     a Content-Length guard bounds an oversized response (context protection).

import { MCPError } from "../../errors";
import { assertEgressHost } from "../../policy/egress-destinations";
import { MAX_RESPONSE_BYTES, readBounded } from "../http/bounded-read";

const GITHUB_API = "https://api.github.com";
const USER_AGENT = "safespace-mcp";
const DEFAULT_TIMEOUT_MS = 10_000;

/** The closed-set operational reason for a `github_api_failed` (-32041). `no_token`
 *  is produced earlier, by the github Source's resolveCredential — not here. */
export type GithubApiReason = "auth_failed" | "rate_limited" | "not_found" | "api_error";

/** Map an HTTP status to the closed-set reason. A GitHub 403 is overloaded: a
 *  primary rate-limit (`X-RateLimit-Remaining: 0`) vs a permission/scope denial —
 *  distinguish by the header so a rate-limited caller is told to slow down rather
 *  than to re-authorize. */
function mapStatusToReason(status: number, rateLimitRemaining: string | null): GithubApiReason {
  if (status === 401) return "auth_failed";
  if (status === 403) return rateLimitRemaining === "0" ? "rate_limited" : "auth_failed";
  if (status === 429) return "rate_limited";
  if (status === 404) return "not_found";
  return "api_error";
}

export interface GithubGetOptions {
  /** The bearer token (read inline from the oauth credential by the handler). */
  token: string;
  /** The API path, beginning with "/", built from validated segments by the caller
   *  (e.g. `/repos/{owner}/{repo}/issues/{number}`). */
  path: string;
  /** Optional query params; undefined values are dropped, the rest URL-encoded. */
  query?: Record<string, string | number | undefined>;
  /** Test seam — production passes undefined → the real global fetch. */
  fetchImpl?: typeof fetch;
  /** Override the request timeout (default {@link DEFAULT_TIMEOUT_MS}). */
  timeoutMs?: number;
}

/** v1.71 — the write (POST/PATCH) options. `body` is an allowlist-constructed JSON
 *  object the caller already validated/sanitized (handlers/github.ts); it is
 *  `JSON.stringify`'d here. */
export interface GithubWriteOptions {
  token: string;
  method: "POST" | "PATCH" | "PUT";
  path: string;
  body: unknown;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

/** The shared GET/POST/PATCH/PUT core: one place with the hardened request (host
 *  hardcoded, Bearer + UA + Accept + API-version, AbortController timeout, streaming
 *  byte cap, status→closed-set reason). NEVER echoes the token, URL, or response body. */
async function githubApiRequest(opts: {
  token: string;
  method: "GET" | "POST" | "PATCH" | "PUT";
  path: string;
  query?: Record<string, string | number | undefined>;
  body?: unknown;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}): Promise<unknown> {
  const doFetch = opts.fetchImpl ?? fetch;
  const url = new URL(GITHUB_API + opts.path);
  // v1.88 — destination backstop: a path that escaped the host (`…@evil.com`)
  // would change url.hostname; assert it is the registered github host BEFORE the
  // fetch (throws -32047, echoing the host only). No-op on the normal api.github.com.
  assertEgressHost(url.hostname, "github");
  if (opts.query) {
    for (const [k, v] of Object.entries(opts.query)) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }
  }
  const headers: Record<string, string> = {
    Authorization: `Bearer ${opts.token}`,
    Accept: "application/vnd.github+json",
    "User-Agent": USER_AGENT,
    "X-GitHub-Api-Version": "2022-11-28",
  };
  // Serialize BEFORE the try: a non-serializable body is a caller bug that should
  // surface as a clear synchronous throw, not be masked as a network api_error.
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
    throw new MCPError("github_api_failed", { reason: "api_error" });
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    res.body?.cancel().catch(() => undefined);
    throw new MCPError("github_api_failed", {
      reason: mapStatusToReason(res.status, res.headers.get("x-ratelimit-remaining")),
    });
  }
  // Fast-reject an oversized response by its declared Content-Length (cheap)…
  const len = Number(res.headers.get("content-length"));
  if (Number.isFinite(len) && len > MAX_RESPONSE_BYTES) {
    res.body?.cancel().catch(() => undefined);
    throw new MCPError("github_api_failed", { reason: "api_error" });
  }
  // …but ALSO bound the ACTUAL read: a chunked / absent-Content-Length response
  // would bypass the header check above and let res.json() buffer unboundedly.
  let text: string;
  try {
    text = await readBounded(res, MAX_RESPONSE_BYTES);
  } catch {
    throw new MCPError("github_api_failed", { reason: "api_error" });
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new MCPError("github_api_failed", { reason: "api_error" });
  }
}

/** GET an api.github.com resource and return the parsed JSON. Throws
 *  `github_api_failed{reason}` on a timeout / network failure (`api_error`), a non-ok
 *  status (`mapStatusToReason`), an oversized response (`api_error`), or unparseable
 *  JSON (`api_error`). NEVER echoes the token, the URL, or the response body. */
export async function githubApiGet(opts: GithubGetOptions): Promise<unknown> {
  return githubApiRequest({ ...opts, method: "GET" });
}

/** v1.71 — POST/PATCH an allowlist-constructed JSON body to api.github.com and return
 *  the created/updated resource JSON. Same hardening + no-leak as {@link githubApiGet}. */
export async function githubApiWrite(opts: GithubWriteOptions): Promise<unknown> {
  return githubApiRequest({
    token: opts.token,
    method: opts.method,
    path: opts.path,
    body: opts.body,
    fetchImpl: opts.fetchImpl,
    timeoutMs: opts.timeoutMs,
  });
}
