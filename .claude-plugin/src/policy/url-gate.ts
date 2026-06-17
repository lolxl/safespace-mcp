// v1.65 Phase C — the SSRF URL gate for the web-fetch keyless connector.
//
// docs/v1.65-web-fetch-connector.md §4. web-fetch is the first class-C keyless
// source: it has no upstream account, so the new security surface SafeSpace OWNS
// is the outbound HTTP request itself. This module is that surface.
//
// THE THREAT: an AI agent (possibly acting on prompt-injected instructions from
// untrusted content it already read) asks web_fetch to retrieve a URL. Without a
// gate, that URL can target the host's own loopback, the cloud metadata endpoint
// (169.254.169.254 → IAM credentials), a RFC1918 LAN box, or a `file://`-style
// scheme — the classic Server-Side Request Forgery pivot. The gate fails CLOSED
// at every step.
//
// WHY node:dns + node:https.request (not fetch / curl): to defend SSRF we must
// OWN the three steps an off-the-shelf client does for you invisibly — DNS
// resolution, which IP we connect to, and redirect following. So we resolve the
// host ourselves, validate every resolved address, PIN a validated IP at connect
// (closing the DNS-rebinding window between check and connect), and follow
// redirects MANUALLY, re-running the whole gate on each hop.
//
// Errors carry a CLOSED-SET `reason` (never a resolved IP, response body, or env
// value) — same no-leak discipline as -32019 / -32030.

import * as dnsPromises from "node:dns/promises";
import * as http from "node:http";
import * as https from "node:https";
import * as net from "node:net";
import { MCPError } from "../errors";
import {
  ENV_AUTONOMOUS,
  ENV_WEBFETCH_ALLOW,
  ENV_WEBFETCH_ALLOW_EXTRA,
  ENV_WEBFETCH_MAX_BYTES,
  ENV_WEBFETCH_TIMEOUT_MS,
} from "../config";

export const WEBFETCH_MAX_BYTES_DEFAULT = 5 * 1024 * 1024; // 5 MB (mirrors Drive)
export const WEBFETCH_TIMEOUT_MS_DEFAULT = 10_000;
export const WEBFETCH_MAX_URL_BYTES = 2048;
export const MAX_REDIRECTS = 5;

const ALLOWED_SCHEMES: ReadonlySet<string> = new Set(["http:", "https:"]);
// Port allowlist (sec-rev H1) — only the web's default ports. `url.port` is "" for
// the scheme default (WHATWG normalizes :80/http and :443/https away); "80"/"443"
// catch an explicit cross-scheme port. This blocks SSRF to internal services on
// non-standard ports of a genuinely-PUBLIC IP (Redis 6379, SSH 22, k8s 6443, …) —
// the IP passes the range block but the port would reach internal infra.
const ALLOWED_PORTS: ReadonlySet<string> = new Set(["", "80", "443"]);
// The actual HTTP redirect status codes — NOT the whole 3xx range (304 Not
// Modified / 300 Multiple Choices are not followable redirects). sec-rev M2.
const REDIRECT_STATUSES: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);

/** Closed-set rejection reasons for `-32036 url_blocked_by_policy`. Never echoes
 *  a resolved IP / response byte / env value — the reason is the only detail. */
export type UrlBlockReason =
  | "malformed_url"
  | "url_too_long"
  | "scheme_not_allowed"
  | "port_not_allowed"
  | "host_not_in_allowlist"
  | "private_or_reserved_ip"
  | "redirect_blocked"
  | "too_many_redirects"
  | "content_type_not_allowed";

/** Closed-set reasons for `-32037 web_fetch_failed` (OPERATIONAL failure — a
 *  policy-clean URL that just didn't fetch). Kept distinct from a policy BLOCK so
 *  a typo'd domain is never mislabeled "blocked by policy". */
export type FetchFailReason =
  | "dns_resolution_failed"
  | "connection_failed"
  | "timeout"
  | "read_error";

function blocked(reason: UrlBlockReason): MCPError {
  return new MCPError("url_blocked_by_policy", { reason });
}
function fetchFailed(reason: FetchFailReason): MCPError {
  return new MCPError("web_fetch_failed", { reason });
}

export interface WebFetchResult {
  /** The URL the caller asked for (pre-redirect). */
  url: string;
  /** The URL the body actually came from (after any redirects). */
  final_url: string;
  status: number;
  content_type: string;
  content: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// IP range blocking — the security core. Pure + exhaustively unit-tested.
// ─────────────────────────────────────────────────────────────────────────────

function ipv4Octets(addr: string): [number, number, number, number] | null {
  const parts = addr.split(".");
  if (parts.length !== 4) return null;
  const oct: number[] = [];
  for (const p of parts) {
    // Reject empty / non-digit / >3-digit forms. On the isBlockedIpv4 path net.isIP
    // already validated the dotted-quad shape; on the expandIpv6ToBytes embedded-v4
    // path it has NOT, so this re-parse is the actual validation there.
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (n < 0 || n > 255) return null;
    oct.push(n);
  }
  return oct as [number, number, number, number];
}

/** True if a dotted-quad IPv4 string is in a private / reserved / loopback /
 *  link-local (incl. cloud metadata 169.254.169.254) / CGNAT / TEST-NET /
 *  multicast / reserved range. Fails CLOSED on an unparseable input. */
export function isBlockedIpv4(addr: string): boolean {
  const o = ipv4Octets(addr);
  if (!o) return true;
  const [a, b, c] = o;
  if (a === 0) return true; // 0.0.0.0/8 "this network"
  if (a === 10) return true; // 10/8 private
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64/10 CGNAT
  if (a === 127) return true; // 127/8 loopback
  if (a === 169 && b === 254) return true; // 169.254/16 link-local (+ metadata)
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16/12 private
  if (a === 192 && b === 0 && c === 0) return true; // 192.0.0/24 IETF
  if (a === 192 && b === 0 && c === 2) return true; // 192.0.2/24 TEST-NET-1
  if (a === 192 && b === 168) return true; // 192.168/16 private
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18/15 benchmark
  if (a === 198 && b === 51 && c === 100) return true; // 198.51.100/24 TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return true; // 203.0.113/24 TEST-NET-3
  if (a >= 224 && a <= 239) return true; // 224/4 multicast
  if (a >= 240) return true; // 240/4 reserved (incl 255.255.255.255 broadcast)
  return false;
}

/** Expand any valid IPv6 string (incl. `::` compression and a trailing embedded
 *  dotted-quad like `::ffff:127.0.0.1`) to its 16 bytes. null on malformed. */
export function expandIpv6ToBytes(input: string): Uint8Array | null {
  const addr = input.split("%")[0]!; // strip zone id
  if (addr.length === 0) return null;

  // A trailing embedded IPv4 (`::ffff:1.2.3.4`) → rewrite as two hex groups.
  let work = addr;
  const lastColon = work.lastIndexOf(":");
  const tail = lastColon >= 0 ? work.slice(lastColon + 1) : work;
  if (tail.includes(".")) {
    const v4 = ipv4Octets(tail);
    if (!v4) return null;
    const hex = ((v4[0] << 8) | v4[1]).toString(16) + ":" + ((v4[2] << 8) | v4[3]).toString(16);
    work = work.slice(0, lastColon + 1) + hex;
  }

  const halves = work.split("::");
  if (halves.length > 2) return null; // more than one "::" is illegal

  const parseGroups = (s: string): number[] | null => {
    if (s === "") return [];
    const groups = s.split(":");
    const out: number[] = [];
    for (const g of groups) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };

  const left = parseGroups(halves[0]!);
  const right = halves.length === 2 ? parseGroups(halves[1]!) : [];
  if (left === null || right === null) return null;

  let hextets: number[];
  if (halves.length === 2) {
    const fill = 8 - left.length - right.length;
    if (fill < 0) return null;
    hextets = [...left, ...new Array(fill).fill(0), ...right];
  } else {
    hextets = left;
  }
  if (hextets.length !== 8) return null;

  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    bytes[i * 2] = (hextets[i]! >> 8) & 0xff;
    bytes[i * 2 + 1] = hextets[i]! & 0xff;
  }
  return bytes;
}

/** True if an IPv6 string is loopback / unspecified / ULA / link-local /
 *  multicast / documentation / NAT64 / discard, OR is an IPv4-mapped address
 *  whose embedded IPv4 is itself blocked. Fails CLOSED on malformed input. */
export function isBlockedIpv6(addr: string): boolean {
  const b = expandIpv6ToBytes(addr);
  if (!b) return true;

  // ::  unspecified  and  ::1 loopback
  const allZeroExceptLast = b.slice(0, 15).every((x) => x === 0);
  if (allZeroExceptLast && (b[15] === 0 || b[15] === 1)) return true;

  // IPv4-mapped ::ffff:0:0/96 → re-check the embedded IPv4.
  const mappedPrefix = b.slice(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff;
  if (mappedPrefix) {
    return isBlockedIpv4(`${b[12]}.${b[13]}.${b[14]}.${b[15]}`);
  }

  if ((b[0]! & 0xfe) === 0xfc) return true; // fc00::/7 unique-local
  if (b[0] === 0xfe && (b[1]! & 0xc0) === 0x80) return true; // fe80::/10 link-local
  if (b[0] === 0xff) return true; // ff00::/8 multicast
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return true; // 2001:db8::/32 doc
  if (b[0] === 0x01 && b.slice(1, 8).every((x) => x === 0)) return true; // 100::/64 discard
  // 64:ff9b::/96 NAT64 — embedded IPv4 could be private; block the prefix.
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) return true;
  return false;
}

/** True if `addr` (a v4 or v6 literal) must NOT be connected to. A non-IP input
 *  fails CLOSED (returns true) — the resolver must hand us a real address. */
export function isBlockedAddress(addr: string): boolean {
  const fam = net.isIP(addr);
  if (fam === 4) return isBlockedIpv4(addr);
  if (fam === 6) return isBlockedIpv6(addr);
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Host allowlist (Q4) + content-type allowlist.
// ─────────────────────────────────────────────────────────────────────────────

function parseAllowlist(env: NodeJS.ProcessEnv): string[] {
  const raw = `${env[ENV_WEBFETCH_ALLOW] ?? ""},${env[ENV_WEBFETCH_ALLOW_EXTRA] ?? ""}`;
  return raw
    .split(",")
    .map((s) => s.trim().toLowerCase().replace(/^@/, "")) // accept `@example.com` or `example.com`
    .filter((s) => s.length > 0);
}

/** Posture summary of the web_fetch host allowlist — COUNTS ONLY (never the host
 *  values; mirrors the no-PII-echo invariant the other connectors' summaries
 *  hold). Empty (unset) = "off" → allow-all interactive / deny-all autonomous
 *  (see `hostAllowed`). For `safespace doctor --posture`. */
export function webfetchAllowlistSummary(
  env: NodeJS.ProcessEnv = process.env,
): { kind: "off" | "active"; count: number } {
  const count = parseAllowlist(env).length;
  return count === 0 ? { kind: "off", count: 0 } : { kind: "active", count };
}

/** Host-allowlist decision (Q4). Empty allowlist = ALLOW any host that passes
 *  the SSRF gate — UNLESS autonomous mode, where empty = DENY ALL (F2 idiom). A
 *  set allowlist matches an exact host or any subdomain of an entry. */
export function hostAllowed(host: string, env: NodeJS.ProcessEnv): boolean {
  const entries = parseAllowlist(env);
  const h = host.toLowerCase();
  if (entries.length === 0) {
    return env[ENV_AUTONOMOUS] !== "true";
  }
  return entries.some((dom) => h === dom || h.endsWith(`.${dom}`));
}

const ALLOWED_CONTENT_TYPE_RE =
  /^(text\/|application\/(json|xml|xhtml\+xml|ld\+json)\b|application\/[a-z0-9.+-]*\+(json|xml)\b)/i;

/** True if a response Content-Type is text-ish (text/*, JSON, XML families). The
 *  keyless connector is a TEXT reader — binary (image/pdf/octet-stream) is out so
 *  blobs never reach the LLM context. A missing/blank type is rejected. */
export function isAllowedContentType(contentType: string | undefined): boolean {
  if (!contentType) return false;
  return ALLOWED_CONTENT_TYPE_RE.test(contentType.trim());
}

// ─────────────────────────────────────────────────────────────────────────────
// Resolve + validate one URL (scheme → allowlist → resolve → block). Returns a
// VALIDATED address to pin at connect.
// ─────────────────────────────────────────────────────────────────────────────

export interface ResolvedAddr {
  address: string;
  family: number;
}

export type LookupFn = (host: string) => Promise<ResolvedAddr[]>;

export const defaultLookup: LookupFn = async (host) => {
  try {
    const res = await dnsPromises.lookup(host, { all: true });
    return res.map((r) => ({ address: r.address, family: r.family }));
  } catch {
    throw fetchFailed("dns_resolution_failed");
  }
};

/** Validate ONE URL and return a pinned, validated address. Rejects on scheme,
 *  allowlist, or ANY resolved address being private/reserved (strict: if a host
 *  round-robins [public, private] we refuse rather than gamble on which we hit). */
export async function assertUrlAllowed(
  url: URL,
  lookup: LookupFn,
  env: NodeJS.ProcessEnv,
): Promise<ResolvedAddr> {
  if (!ALLOWED_SCHEMES.has(url.protocol)) throw blocked("scheme_not_allowed");
  // sec-rev H1 — re-checked on EVERY hop (assertUrlAllowed runs per redirect), so a
  // redirect to `…:22` / `…:6379` is blocked just like the entry URL.
  if (!ALLOWED_PORTS.has(url.port)) throw blocked("port_not_allowed");
  const host = url.hostname.replace(/^\[|\]$/g, ""); // strip IPv6 literal brackets
  if (!hostAllowed(host, env)) throw blocked("host_not_in_allowlist");

  const litFamily = net.isIP(host);
  const addrs: ResolvedAddr[] =
    litFamily !== 0 ? [{ address: host, family: litFamily }] : await lookup(host);

  if (addrs.length === 0) throw blocked("private_or_reserved_ip"); // can't validate → fail closed
  for (const a of addrs) {
    if (isBlockedAddress(a.address)) throw blocked("private_or_reserved_ip");
  }
  return addrs[0]!;
}

// ─────────────────────────────────────────────────────────────────────────────
// The low-level single-request primitive (pinned IP, manual redirect). Injectable
// so the redirect / content-type / size-cap orchestration in fetchThroughGate is
// tested with REAL code against a fake transport.
// ─────────────────────────────────────────────────────────────────────────────

export interface RawResponse {
  status: number;
  headers: Record<string, string | undefined>;
  /** Set when status is a 3xx redirect with a Location header. */
  location?: string;
  /** Stream of body chunks (only read for a terminal 2xx response). */
  body: AsyncIterable<Uint8Array>;
  /** Tear down the underlying connection — called when the body is abandoned
   *  (a redirect we follow, a rejected content-type, an oversize/slow body) so a
   *  socket is never left dangling. Optional: a fake transport may omit it. */
  destroy?: () => void;
}

export type HttpGetOnceFn = (
  url: URL,
  pinned: ResolvedAddr,
  opts: { timeoutMs: number },
) => Promise<RawResponse>;

/** Production transport: ONE GET against the PINNED validated IP (closes the
 *  DNS-rebinding window — we never re-resolve), presenting the original hostname
 *  for `Host` + TLS SNI. Manual redirect (auto-follow OFF). */
export const defaultHttpGetOnce: HttpGetOnceFn = (url, pinned, opts) => {
  return new Promise<RawResponse>((resolve, reject) => {
    const isHttps = url.protocol === "https:";
    const mod = isHttps ? https : http;
    const port = url.port || (isHttps ? "443" : "80");
    const reqOpts: https.RequestOptions = {
      host: pinned.address, // ← connect to the VALIDATED ip, not the hostname
      port: Number(port),
      method: "GET",
      path: `${url.pathname}${url.search}`,
      headers: { Host: url.host, Accept: "*/*", "User-Agent": "SafeSpace-web-fetch/1" },
      // Present the real hostname for SNI + certificate validation while the TCP
      // connection targets the pinned IP.
      servername: isHttps ? url.hostname.replace(/^\[|\]$/g, "") : undefined,
    };
    // A single settle-guard: the response, the connect/header timeout, and a socket
    // error race; whichever wins settles, the rest no-op. The BODY-read phase is
    // bounded separately inside readCapped (sec-rev M1) via the `destroy` hook
    // below, so this timer covers only connect + headers (no lingering timer on a
    // redirect/reject path that abandons the body).
    let settled = false;
    const req = mod.request(reqOpts, (res) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const location = res.headers.location;
      resolve({
        status: res.statusCode ?? 0,
        headers: res.headers as Record<string, string | undefined>,
        location: typeof location === "string" ? location : undefined,
        body: res as unknown as AsyncIterable<Uint8Array>,
        destroy: () => req.destroy(),
      });
    });
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      req.destroy();
      reject(fetchFailed("timeout"));
    }, opts.timeoutMs);
    req.on("error", (e) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(e instanceof MCPError ? e : fetchFailed("connection_failed"));
    });
    req.end();
  });
};

async function readCapped(
  body: AsyncIterable<Uint8Array>,
  maxBytes: number,
  opts: { timeoutMs?: number; destroy?: () => void } = {},
): Promise<string> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  // sec-rev M1 — bound the BODY-read phase (the connect/header timeout was already
  // cleared when headers arrived). On the deadline we tear down the socket, which
  // errors the for-await; `timedOut` distinguishes that from a generic read error.
  let timedOut = false;
  const timer =
    opts.timeoutMs !== undefined
      ? setTimeout(() => {
          timedOut = true;
          opts.destroy?.();
        }, opts.timeoutMs)
      : undefined;
  try {
    for await (const chunk of body) {
      total += chunk.length;
      if (total > maxBytes) {
        opts.destroy?.(); // stop pulling a giant body — close the socket
        throw new MCPError("file_too_large");
      }
      chunks.push(chunk);
    }
  } catch (e) {
    if (timedOut) throw fetchFailed("timeout");
    if (e instanceof MCPError) throw e;
    throw fetchFailed("read_error");
  } finally {
    if (timer) clearTimeout(timer);
  }
  return Buffer.concat(chunks).toString("utf-8");
}

// ─────────────────────────────────────────────────────────────────────────────
// The gate orchestration — validate → fetch → re-gate every redirect → cap.
// ─────────────────────────────────────────────────────────────────────────────

export interface UrlGateDeps {
  lookup?: LookupFn;
  httpGetOnce?: HttpGetOnceFn;
  env?: NodeJS.ProcessEnv;
  maxBytes?: number;
  timeoutMs?: number;
}

function readMaxBytes(env: NodeJS.ProcessEnv): number {
  const raw = env[ENV_WEBFETCH_MAX_BYTES];
  const n = raw ? Number.parseInt(raw, 10) : NaN;
  return Number.isFinite(n) && n > 0 ? n : WEBFETCH_MAX_BYTES_DEFAULT;
}
function readTimeoutMs(env: NodeJS.ProcessEnv): number {
  const raw = env[ENV_WEBFETCH_TIMEOUT_MS];
  const n = raw ? Number.parseInt(raw, 10) : NaN;
  return Number.isFinite(n) && n > 0 ? n : WEBFETCH_TIMEOUT_MS_DEFAULT;
}

/** Fetch a URL through the full SSRF gate. Throws `-32036` (policy block),
 *  `-32037` (operational fetch failure), or `-32007` (oversize). The IP actually
 *  connected to is validated on EVERY hop (pinning + per-redirect re-gate). */
export async function fetchThroughGate(
  rawUrl: string,
  deps: UrlGateDeps = {},
): Promise<WebFetchResult> {
  const lookup = deps.lookup ?? defaultLookup;
  const httpGetOnce = deps.httpGetOnce ?? defaultHttpGetOnce;
  const env = deps.env ?? process.env;
  const maxBytes = deps.maxBytes ?? readMaxBytes(env);
  const timeoutMs = deps.timeoutMs ?? readTimeoutMs(env);

  if (Buffer.byteLength(rawUrl, "utf8") > WEBFETCH_MAX_URL_BYTES) throw blocked("url_too_long");
  let current: URL;
  try {
    current = new URL(rawUrl);
  } catch {
    throw blocked("malformed_url");
  }

  const originalUrl = current.toString();
  let redirects = 0;
  // Bounded loop: each iteration re-runs the FULL gate on `current`, so a
  // redirect to a private IP / bad scheme is caught exactly like the entry URL.
  for (;;) {
    const pinned = await assertUrlAllowed(current, lookup, env);
    const resp = await httpGetOnce(current, pinned, { timeoutMs });

    // sec-rev M2 — only the actual redirect codes follow; a redirect status with
    // NO Location is a malformed redirect → blocked, not a misclassified failure.
    if (REDIRECT_STATUSES.has(resp.status)) {
      resp.destroy?.(); // we won't read this hop's body — release the socket
      if (!resp.location) throw blocked("redirect_blocked");
      redirects += 1;
      // Follows AT MOST MAX_REDIRECTS redirects (the (N+1)th is blocked) — curl
      // `--max-redirs` semantics: 5 redirects followed = up to 6 requests total.
      // Every followed hop is fully re-gated above, so this bound is loop-safety,
      // not the security boundary.
      if (redirects > MAX_REDIRECTS) throw blocked("too_many_redirects");
      let next: URL;
      try {
        next = new URL(resp.location, current); // resolve relative redirects
      } catch {
        throw blocked("redirect_blocked");
      }
      current = next;
      continue;
    }

    const contentType = resp.headers["content-type"];
    if (!isAllowedContentType(contentType)) {
      resp.destroy?.(); // rejected body is never read — release the socket
      throw blocked("content_type_not_allowed");
    }
    const content = await readCapped(resp.body, maxBytes, { timeoutMs, destroy: resp.destroy });
    return {
      url: originalUrl,
      final_url: current.toString(),
      status: resp.status,
      content_type: (contentType ?? "").trim(),
      content,
    };
  }
}

/** The web-fetch Source's error mapper (`Source.mapError`). The gate already
 *  throws MCPErrors (-32036 / -32037 / -32007); an unexpected non-MCPError is
 *  wrapped as a generic operational failure — never as a policy block, and never
 *  leaking the raw error string. */
export function mapWebFetchError(err: unknown): Error {
  if (err instanceof MCPError) return err;
  return fetchFailed("connection_failed");
}
