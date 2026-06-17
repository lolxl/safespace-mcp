// v1.73 — Model B PR-1: the opt-in Streamable HTTP transport.
//
// SCOPE: transport plumbing ONLY. The server speaks MCP Streamable HTTP over
// LOOPBACK, opt-in (default stays stdio = Model A byte-identical), STATEFUL
// (one session per connection), with DNS-rebinding protection. The single-operator
// semantics are UNCHANGED — there is NO per-connection operator identity yet
// (that is PR-2). Until PR-2, do NOT bind beyond loopback / a trusted tailnet:
// there is no per-request auth. See docs/v1.73-model-b-transport.md.
//
// The envelope is untouched: each session connects a FRESH createMcpServer(), so
// every tools/call over HTTP runs the exact same tier filter + per-call gates +
// sanitize + audit as the stdio path.
import { randomUUID } from "node:crypto";
import {
  createServer as createHttpServer,
  type IncomingMessage,
  type Server as HttpServer,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { ENV_HTTP_BIND, ENV_HTTP_PORT, ENV_TRANSPORT, ENV_TLS_TERMINATED, readStrictTruthy } from "../config";
import {
  ConnectionOperatorResolver,
  type OperatorContext,
  type OperatorResolver,
} from "../identity/operator-context";
import type {
  OperatorEntry,
  OperatorRegistryProvider,
} from "../identity/operator-registry";
import { tailscaleWhois } from "../identity/tailscale-whois";

/** The single fixed endpoint the transport serves. */
export const MCP_PATH = "/mcp";

/** Hard cap on a POST body. An MCP tools/call args dict is small; this bounds
 *  memory against an unbounded-body abuse on the listener. */
const MAX_BODY_BYTES = 4 * 1024 * 1024; // 4 MB

/** Default bind — LOOPBACK. The code NEVER defaults to 0.0.0.0; a non-loopback
 *  bind must be the operator's explicit `SAFESPACE_HTTP_BIND` choice. */
export const DEFAULT_BIND = "127.0.0.1";

export interface HttpServerConfig {
  /** Listener port. `0` = OS-assigned ephemeral (tests read the actual port back). */
  readonly port: number;
  /** Bind address (loopback by default). */
  readonly bind: string;
  /** Extra allow-listed `host:port` values for DNS-rebind validation (beyond the
   *  loopback aliases derived from bind+port). Empty in PR-1. */
  readonly extraAllowedHosts?: readonly string[];
  /** v1.74 PR-2b / v1.80 PR-3 — the operator-registry PROVIDER (REQUIRED: http =
   *  Model B = operator auth). A verified tailnet login → operator policy; an
   *  unregistered login is refused (default-deny). proxy.ts performs the initial
   *  fail-loud load via `createRegistryProvider`; `current()` hot-reloads on file
   *  change, and THIS transport re-resolves every session's login per request, so
   *  a registry edit (revocation / tier change / `allowedAccounts` change)
   *  applies on the operator's next request — no restart. Tests wrap a static
   *  registry as `{ current: async () => registry }`. */
  readonly registry: OperatorRegistryProvider;
  /** v1.74 PR-2b — resolve a connection's verified tailnet login from its peer
   *  `ip:port` (default: the tailscaled LocalAPI WhoIs). Injectable for tests. */
  readonly whois?: (peerAddr: string) => Promise<string | null>;
  /** v1.74 PR-2b — the per-connection identity ANCHOR that binds a session to its
   *  originating peer (default: the socket remote IP — the non-forgeable tailnet
   *  IP↔identity binding). Injectable so a test can simulate distinct peers over
   *  loopback (where every connection shares 127.0.0.1). */
  readonly peerKeyImpl?: (req: IncomingMessage) => string;
  /** v1.93 A1 — the operator-auth source. `"tailscale"` (default) resolves the
   *  login via WhoIs from the peer IP; `"token"` resolves it from the request's
   *  `Authorization: Bearer` via `resolveTokenLogin`. Either way the resolved login
   *  feeds the SAME default-deny registry lookup. */
  readonly authMode?: "tailscale" | "token";
  /** v1.93 A1 — resolve a request's bearer token → a registered login (or null).
   *  REQUIRED when `authMode === "token"` (startHttpServer fails loud otherwise).
   *  proxy.ts binds the loaded token store + per-install salt into this closure;
   *  tests inject a stub. */
  readonly resolveTokenLogin?: (req: IncomingMessage) => Promise<string | null>;
}

/** A handle on a started HTTP transport — the actual bound port + a close(). */
export interface HttpServerHandle {
  readonly port: number;
  close(): Promise<void>;
}

/** v1.73 — transport selection. `SAFESPACE_TRANSPORT=http` opts into the HTTP
 *  listener; ANY other value (unset, "stdio", a typo) → stdio = Model A. Read LIVE
 *  (never snapshot). */
export function transportMode(): "stdio" | "http" {
  return process.env[ENV_TRANSPORT] === "http" ? "http" : "stdio";
}

/** v1.73 — resolve the HTTP listener config from env (the PRODUCTION path; throws
 *  fail-loud if the port is missing/invalid). Bind defaults to LOOPBACK.
 *
 *  NOTE: a production listener needs a real port, so `0` is rejected here. The
 *  ephemeral `port: 0` (OS-assigned) path is test-only — those callers construct an
 *  `HttpServerConfig` directly and pass it to `startHttpServer`, bypassing this. */
export function resolveHttpConfigFromEnv(): { port: number; bind: string } {
  const portRaw = process.env[ENV_HTTP_PORT];
  const port = portRaw != null && portRaw !== "" ? Number(portRaw) : NaN;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(
      `[safespace] ${ENV_HTTP_PORT} must be an integer port 1-65535 when ${ENV_TRANSPORT}=http (got ${portRaw ?? "unset"})`,
    );
  }
  // `|| DEFAULT_BIND`: an empty string also falls back to loopback. NEVER 0.0.0.0.
  const bind = process.env[ENV_HTTP_BIND] || DEFAULT_BIND;
  return { port, bind };
}

function isLoopback(bind: string): boolean {
  return bind === "127.0.0.1" || bind === "::1" || bind === "localhost";
}

/** Build the DNS-rebind `allowedHosts` set: the bind+port, plus the loopback
 *  aliases a client might send as the Host header when the listener is loopback. */
export function buildAllowedHosts(
  bind: string,
  port: number,
  extra: readonly string[] = [],
): string[] {
  const hosts = new Set<string>([`${bind}:${port}`]);
  if (isLoopback(bind)) {
    hosts.add(`127.0.0.1:${port}`);
    hosts.add(`localhost:${port}`);
    hosts.add(`[::1]:${port}`);
  }
  for (const e of extra) hosts.add(e);
  return [...hosts];
}

/** v1.74 PR-2b — format a connection's remote `address`/`port` as the `ip:port` the
 *  Tailscale LocalAPI WhoIs expects. IPv6 needs `[addr]:port`; an IPv4 connection
 *  surfacing as IPv4-mapped IPv6 (`::ffff:x.x.x.x`) over a dual-stack socket is
 *  unwrapped to the plain IPv4 the daemon expects (a raw `::1:port` would never
 *  parse → fail-closed → a legit IPv6 peer silently denied). Pure + exported so the
 *  formatting is unit-testable without a real IPv6 socket. */
export function formatWhoisAddr(address: string, port: number): string {
  let addr = address;
  if (addr.startsWith("::ffff:") && addr.includes(".")) addr = addr.slice(7);
  return addr.includes(":") ? `[${addr}]:${port}` : `${addr}:${port}`;
}

class BodyTooLargeError extends Error {}

/** Collect a request body up to MAX_BODY_BYTES, parse JSON. Empty body → undefined.
 *  Throws BodyTooLargeError on oversize, Error("invalid_json") on a parse failure. */
function readJsonBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let aborted = false;
    req.on("data", (chunk: Buffer) => {
      if (aborted) return;
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        aborted = true;
        reject(new BodyTooLargeError());
        // DRAIN (discard) the remainder rather than destroying the socket — memory
        // stays bounded (no further chunk is buffered) AND the request finishes so
        // the caller's 413 reaches the client cleanly (destroy → ECONNRESET).
        req.resume();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (aborted) return;
      const raw = Buffer.concat(chunks).toString("utf8");
      if (raw.length === 0) {
        resolve(undefined);
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error("invalid_json"));
      }
    });
    req.on("error", reject);
  });
}

/** Minimal JSON-RPC error response. NEVER echoes internals — fixed messages only. */
function jsonRpcError(res: ServerResponse, status: number, message: string): void {
  if (res.headersSent) return;
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32000, message }, id: null }));
}

function sessionIdOf(req: IncomingMessage): string | undefined {
  const v = req.headers["mcp-session-id"];
  return Array.isArray(v) ? v[0] : v;
}

/** Start the Streamable HTTP transport (STATEFUL). Binds `config.bind`/`config.port`
 *  and serves `/mcp`. Each new session connects a fresh `createServer()`. Returns a
 *  handle with the actual bound port + close(). */
export async function startHttpServer(
  createServer: (operator?: OperatorResolver) => Server,
  config: HttpServerConfig,
): Promise<HttpServerHandle> {
  // Each session stores its transport + the peer ANCHOR it was initialized from
  // (so a session id can only be exercised from the peer that authenticated it),
  // plus — v1.80 PR-3 — the session's verified tailnet LOGIN and its CURRENT
  // OperatorContext. The login is re-resolved against the hot-reloadable
  // registry on EVERY request: a removed operator 403s (revocation = next
  // request); a tier / allowedAccounts change refreshes `context`, which the
  // session's supplier-based ConnectionOperatorResolver reads per call. The
  // IDENTITY (login/peer) never changes mid-session — only registry-side policy.
  interface SessionRecord {
    readonly transport: StreamableHTTPServerTransport;
    readonly peerKey: string;
    readonly login: string;
    /** The session's CURRENT operator policy, boxed so the supplier-based
     *  resolver (which closes over the box BEFORE the transport exists) and
     *  the per-request refresh share one mutable cell without a forward
     *  reference to the record itself (sec-rev v1.80 LOW-1). */
    readonly contextBox: { context: OperatorContext };
  }
  const transports = new Map<string, SessionRecord>();
  const contextOf = (entry: OperatorEntry): OperatorContext => ({
    operatorId: entry.operatorId,
    tier: entry.tier,
    // A registry `[]` means ZERO allowed accounts (deny all resolution), NOT
    // `null` (= "unrestricted", the Model-A value) — the registry always sets an
    // array, so the confinement consumer must not collapse `[]` into null.
    allowedAccounts: entry.allowedAccounts,
    // v1.92 — per-operator F1 burst caps (absent in the registry → null → the F1
    // gate falls back to the global env default for this operator).
    writeBurstLimit: entry.writeBurstLimit ?? null,
    deleteBurstLimit: entry.deleteBurstLimit ?? null,
  });
  // Answer the generic 403 + tear the session down (drop it from the map and close
  // the transport, which frees any open SSE stream). onclose's map-delete is a no-op
  // after the delete here; close() is best-effort. Returns null so callers can
  // `return denyAndTeardown(...) === null` in one line. ONE teardown impl, shared by
  // every per-request revocation branch so they cannot drift apart.
  const denyAndTeardown = (sid: string, record: SessionRecord, res: ServerResponse): null => {
    jsonRpcError(res, 403, "forbidden");
    transports.delete(sid);
    void record.transport.close().catch(() => {});
    return null;
  };
  // v1.80 PR-3 — the per-request re-resolution for an EXISTING session. Returns
  // the refreshed record, or null after answering 403 + tearing the session down
  // (the operator was removed from the registry — revocation bites HERE, before
  // any MCP dispatch, so no new MCP error code is needed).
  const reresolveOrRevoke = async (
    sid: string,
    record: SessionRecord,
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<SessionRecord | null> => {
    // v1.94 A2 — token mode: re-resolve the request's bearer token on EVERY request
    // (the token IS re-presented on every HTTP request, unlike a per-connection peer
    // IP). Two properties this buys, both load-bearing once the bind is relaxed:
    //   1. REVOCATION bites an OPEN session — a revoked/expired token (gone from the
    //      store, or past expiry) 403s its next request, not just its next connection
    //      (the A1 gap). resolveTokenLogin re-reads the store + checks expiry, so both
    //      cases fall out for free.
    //   2. It is the REAL per-request identity anchor under token auth: behind a
    //      reverse proxy every request shares the proxy's source IP, so the peerKey
    //      binding (checked by the caller) collapses to a constant and cannot tell two
    //      operators apart — requiring the token to still resolve to THIS session's
    //      login is what prevents one operator's token from driving another's session.
    // Tailscale mode is UNTOUCHED (the non-forgeable peer IP is already the
    // per-connection anchor; adding a per-request WhoIs would change behavior + cost
    // for existing tailnet deployments) → default tailscale stays byte-identical.
    if (authMode === "token") {
      // FAIL CLOSED on ANY error: the resolver already catches its own store I/O and
      // returns null (proxy.ts), but a future resolver impl that throws must STILL deny
      // + tear down here — never propagate to the outer 500 handler, which would skip
      // teardown (orphan session) and answer a non-403 (sec-rev A2 NIT-1).
      let login: string | null;
      try {
        login = await config.resolveTokenLogin!(req);
      } catch {
        return denyAndTeardown(sid, record, res);
      }
      if (login === null || login !== record.login) return denyAndTeardown(sid, record, res);
    }
    const registry = await config.registry.current();
    const entry = registry.lookupByTailnetLogin(record.login);
    if (!entry) return denyAndTeardown(sid, record, res);
    // Concurrent requests on the same session may race this write — that is an
    // intentional last-write-wins: contextOf() always snapshots a VALID,
    // currently-registered entry (a removal takes the branch above), so the
    // race can only choose between two valid policy versions, never widen.
    record.contextBox.context = contextOf(entry);
    return record;
  };
  // v1.74 PR-2b — operator-auth dependencies. `whois` resolves a connection's
  // verified tailnet login (default: tailscaled LocalAPI); `peerKeyOf` is the
  // session-binding anchor; `peerAddrOf` is the real socket `ip:port` handed to
  // WhoIs (always the real socket, even when peerKeyOf is injected in a test).
  const whois = config.whois ?? tailscaleWhois;
  const peerKeyOf =
    config.peerKeyImpl ?? ((req: IncomingMessage) => req.socket?.remoteAddress ?? "");
  // The real socket address handed to WhoIs (always the real socket, even when
  // peerKeyOf is injected in a test).
  const whoisAddrOf = (req: IncomingMessage) =>
    formatWhoisAddr(req.socket?.remoteAddress ?? "", req.socket?.remotePort ?? 0);
  // v1.93 A1 — the per-init login resolver. `tailscale` (default) → WhoIs on the
  // peer IP; `token` → the bearer-token resolver. Either way the resolved login
  // feeds the SAME default-deny registry lookup. Fail LOUD at startup if token mode
  // has no resolver — a misconfigured deployment must never fall back to a weaker
  // path (defense-in-depth; proxy.ts already validates + supplies the resolver).
  const authMode = config.authMode ?? "tailscale";
  if (authMode === "token" && !config.resolveTokenLogin) {
    throw new Error(
      "[safespace] SAFESPACE_AUTH=token requires the agent-tokens resolver — refusing to start",
    );
  }
  const resolveLogin = (req: IncomingMessage): Promise<string | null> =>
    authMode === "token" ? config.resolveTokenLogin!(req) : whois(whoisAddrOf(req));
  // allowedHosts depends on the ACTUAL bound port (config.port may be 0). Set
  // synchronously right after listen(), before any request can arrive (the caller
  // only learns the port from the returned handle). The handler closes over this.
  //
  // FAIL-CLOSED sentinel (sec-rev v1.73 M1): start with a value that matches NO real
  // Host header rather than `[]`. Today a transport is only ever constructed inside
  // the request callback (which can't fire before the post-listen assignment below),
  // so production always uses the populated list — but if a future refactor inserted
  // an `await` between listen() and that assignment, this makes the window reject ALL
  // hosts (fail closed) instead of risking an empty-allowedHosts fail-open.
  let allowedHosts: string[] = ["safespace.invalid:0"];

  const httpServer: HttpServer = createHttpServer(async (req, res) => {
    const url = new URL(req.url ?? "/", `http://${config.bind}`);
    if (url.pathname !== MCP_PATH) {
      jsonRpcError(res, 404, "not found");
      return;
    }

    try {
      if (req.method === "POST") {
        let body: unknown;
        try {
          body = await readJsonBody(req);
        } catch (e) {
          if (e instanceof BodyTooLargeError) {
            jsonRpcError(res, 413, "request body too large");
            return;
          }
          jsonRpcError(res, 400, "invalid json");
          return;
        }
        const peerKey = peerKeyOf(req);
        const sid = sessionIdOf(req);
        const existing = sid ? transports.get(sid) : undefined;
        let transport: StreamableHTTPServerTransport;
        if (existing) {
          // Session-peer binding: a session is bound to the peer that
          // authenticated it. A leaked/guessed session id presented from a
          // DIFFERENT tailnet peer (a different operator) is refused — the
          // session id alone cannot carry one operator's authority to another
          // (defense-in-depth atop the unguessable UUID; the non-forgeable
          // tailnet IP↔identity is the anchor).
          if (existing.peerKey !== peerKey) {
            jsonRpcError(res, 403, "forbidden");
            return;
          }
          // v1.80 PR-3 — re-resolve against the CURRENT registry (revocation /
          // policy change applies on this request; null = already answered 403).
          if ((await reresolveOrRevoke(sid!, existing, req, res)) === null) return;
          transport = existing.transport;
        } else if (!sid && isInitializeRequest(body)) {
          // A connection with no resolvable peer anchor cannot be authenticated
          // OR session-bound — refuse (sec-rev NIT-1: never create a session keyed
          // on an empty peerKey, which two undefined-address connections would
          // otherwise share). Defense-in-depth; unreachable for a real tailnet/TCP
          // connection (which always has a remote address).
          if (!peerKey) {
            jsonRpcError(res, 403, "forbidden");
            return;
          }
          // ── AUTH (default-deny) ── resolve + verify the connection's operator
          // identity — WhoIs from the peer IP, or (SAFESPACE_AUTH=token) the
          // bearer token — BEFORE building a server. No verified identity OR an
          // unregistered login → the SAME generic 403 (no oracle distinguishing
          // "no identity" / "bad token" / "not registered"). The session never
          // reaches createMcpServer, so an unauthenticated peer touches ZERO
          // envelope. v1.80 PR-3: session-init reads provider.current() — an operator
          // ADDED to the registry file can connect without a restart.
          const login = await resolveLogin(req);
          if (!login) {
            jsonRpcError(res, 403, "forbidden");
            return;
          }
          const entry = (await config.registry.current()).lookupByTailnetLogin(login);
          if (!entry) {
            jsonRpcError(res, 403, "forbidden");
            return;
          }
          // The per-session operator context — THIS operator's tier + accounts
          // drive the envelope (tools/list filter, per-call gates, audit
          // `operator`). v1.80 PR-3: the BOX holds the session's mutable policy
          // — the per-request re-resolution refreshes it from the hot-reloaded
          // registry, and the supplier-based resolver reads the CURRENT value
          // per call. A box (not the record) is what the supplier closes over,
          // so no forward reference to the not-yet-constructed transport exists
          // (sec-rev v1.80 LOW-1).
          const contextBox = { context: contextOf(entry) };
          const resolver = new ConnectionOperatorResolver(() => contextBox.context);
          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            // DNS-rebinding protection: reject a request whose Host header isn't
            // allow-listed (defeats a malicious browser page POSTing to localhost).
            enableDnsRebindingProtection: true,
            allowedHosts,
            onsessioninitialized: (newSid) => {
              // `transport` is assigned by the time any request can initialize a
              // session (onsessioninitialized fires from handleRequest, below).
              transports.set(newSid, { transport, peerKey, login, contextBox });
            },
          });
          transport.onclose = () => {
            // A half-open session (closed before onsessioninitialized → sessionId
            // still undefined) was never added to the map, so there is nothing to
            // delete; its transport + the Server it connected reference only each
            // other and are GC-collected — no map retention, no leak (code-rev LOW-2).
            const id = transport.sessionId;
            if (id) transports.delete(id);
          };
          // A FRESH server per session, built WITH this operator's resolver — the
          // envelope is identical to stdio but scoped to THIS operator's identity.
          await createServer(resolver).connect(transport);
        } else {
          jsonRpcError(res, 400, "no valid session");
          return;
        }
        await transport.handleRequest(req, res, body);
      } else if (req.method === "GET" || req.method === "DELETE") {
        const sid = sessionIdOf(req);
        const existing = sid ? transports.get(sid) : undefined;
        if (!existing) {
          jsonRpcError(res, 400, "no valid session");
          return;
        }
        // Same session-peer binding as the POST path (above).
        if (existing.peerKey !== peerKeyOf(req)) {
          jsonRpcError(res, 403, "forbidden");
          return;
        }
        // v1.80 PR-3 — same per-request re-resolution as the POST path (a revoked
        // operator's open SSE stream / DELETE is refused too). v1.94 A2: in token
        // mode this also re-checks the bearer (so a held-open SSE stream's next
        // GET/DELETE is refused after the token is revoked).
        if ((await reresolveOrRevoke(sid!, existing, req, res)) === null) return;
        await existing.transport.handleRequest(req, res);
      } else {
        res.writeHead(405, { Allow: "GET, POST, DELETE" }).end();
      }
    } catch {
      // Defensive: a handler/transport throw never leaks a stack to the wire.
      jsonRpcError(res, 500, "internal error");
    }
  });

  await new Promise<void>((resolve) => httpServer.listen(config.port, config.bind, resolve));
  const port = (httpServer.address() as AddressInfo).port;
  allowedHosts = buildAllowedHosts(config.bind, port, config.extraAllowedHosts);
  // stderr — never stdout. bind+port are not secret; no token/identity echoed.
  // (The size is the INITIAL registry's; v1.80 hot-reload logs each reload.)
  const initialSize = (await config.registry.current()).size;
  // v1.93 A1 — name the ACTUAL auth source so startup output isn't misleading
  // during incident response when SAFESPACE_AUTH=token.
  const authSource =
    authMode === "token"
      ? "bearer token (agent-tokens) → operators registry"
      : "Tailscale WhoIs → operators registry";
  // v1.94 A2 — don't print the unconditional "NEVER 0.0.0.0" hint when the operator
  // has DELIBERATELY bound all interfaces AND attested an upstream TLS proxy: that
  // banner would contradict the (now-permitted) shape during incident response
  // (sec-rev A2 NIT-2). The gate, not the log line, is the authority either way.
  const allInterfaces = config.bind === "0.0.0.0" || config.bind === "::";
  const bindNote =
    allInterfaces && readStrictTruthy(ENV_TLS_TERMINATED)
      ? "all-interfaces bind attested via SAFESPACE_TLS_TERMINATED — front it with your own TLS proxy"
      : "bind the tailscale interface — NEVER 0.0.0.0";
  console.error(
    `[safespace] MCP Streamable HTTP transport on http://${config.bind}:${port}${MCP_PATH} (operator auth: ${authSource} [${initialSize} operator(s), hot-reloaded on change], default-deny; ${bindNote})`,
  );

  return {
    port,
    close: () =>
      new Promise<void>((resolve, reject) =>
        // close() stops accepting new connections — sufficient for PR-1's loopback
        // scope. (code-rev LOW-1 suggested closeAllConnections() for deterministic
        // SSE-stream teardown, but Bun — the runtime — ships it as an incompatible
        // stub that leaves the server stopped so the following close() throws
        // ERR_SERVER_NOT_RUNNING; the SSE-drain refinement defers to the Bun-native
        // HTTP path. ERR_SERVER_NOT_RUNNING [already stopped] is treated as success.)
        httpServer.close((err) =>
          err && (err as NodeJS.ErrnoException).code !== "ERR_SERVER_NOT_RUNNING"
            ? reject(err)
            : resolve(),
        ),
      ),
  };
}
