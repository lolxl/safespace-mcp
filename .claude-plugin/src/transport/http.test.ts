import { afterEach, describe, expect, test } from "bun:test";
import { request as httpRequest } from "node:http";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { ENV_HTTP_BIND, ENV_HTTP_PORT, ENV_TRANSPORT } from "../config";
import { createMcpServer } from "../server";
import {
  buildAllowedHosts,
  DEFAULT_BIND,
  formatWhoisAddr,
  type HttpServerConfig,
  resolveHttpConfigFromEnv,
  startHttpServer,
  transportMode,
} from "./http";
import { parseOperatorRegistry } from "../identity/operator-registry";

// ── PR-2b operator-auth fixtures ──
// A registry with a share-tier operator (alice — the default authed identity for
// the v1.73 e2e/security tests, so the full tool surface is visible) + a read-tier
// operator (bob, for the per-operator-tier proof).
const TEST_REGISTRY = parseOperatorRegistry(
  JSON.stringify({
    operators: [
      { tailnetLogin: "alice@example.com", operatorId: "alice", tier: "share", allowedAccounts: [] },
      { tailnetLogin: "bob@example.com", operatorId: "bob", tier: "read", allowedAccounts: [] },
    ],
  }),
);
/** The default authed connection for tests that are NOT about auth: alice (share). */
const okWhois = async (): Promise<string | null> => "alice@example.com";
/** v1.80 PR-3 — the transport now takes a hot-reloading PROVIDER. Tests that are
 *  not about reload wrap the static registry; the registry-change tests below
 *  build a mutable provider inline (the provider's own mtime/keep-last-good
 *  mechanics are unit-tested in operator-registry.test.ts). */
function staticProvider(reg: typeof TEST_REGISTRY) {
  return { current: async () => reg };
}
/** Build a startHttpServer config with auth wired (registry + an injected WhoIs). */
function authConfig(extra: Partial<HttpServerConfig> = {}): HttpServerConfig {
  return {
    port: 0,
    bind: "127.0.0.1",
    registry: staticProvider(TEST_REGISTRY),
    whois: okWhois,
    ...extra,
  };
}

// ── Transport selection (unit; reads env via the config constants so the
// config drift sentinel's "no SAFESPACE_ literal" rule is never tripped) ──
describe("transport selection", () => {
  afterEach(() => {
    delete process.env[ENV_TRANSPORT];
    delete process.env[ENV_HTTP_PORT];
    delete process.env[ENV_HTTP_BIND];
  });

  test("transportMode: stdio by default; http ONLY on the exact 'http'", () => {
    delete process.env[ENV_TRANSPORT];
    expect(transportMode()).toBe("stdio");
    process.env[ENV_TRANSPORT] = "HTTP"; // case-sensitive — not http
    expect(transportMode()).toBe("stdio");
    process.env[ENV_TRANSPORT] = "tcp";
    expect(transportMode()).toBe("stdio");
    process.env[ENV_TRANSPORT] = "http";
    expect(transportMode()).toBe("http");
  });

  test("resolveHttpConfigFromEnv: bind defaults to LOOPBACK, never 0.0.0.0", () => {
    process.env[ENV_HTTP_PORT] = "7332";
    expect(resolveHttpConfigFromEnv()).toEqual({ port: 7332, bind: "127.0.0.1" });
    expect(DEFAULT_BIND).toBe("127.0.0.1");
    process.env[ENV_HTTP_BIND] = ""; // empty string → still loopback (|| default)
    expect(resolveHttpConfigFromEnv().bind).toBe("127.0.0.1");
    process.env[ENV_HTTP_BIND] = "0.0.0.0"; // only ever an EXPLICIT operator choice
    expect(resolveHttpConfigFromEnv().bind).toBe("0.0.0.0");
  });

  test("resolveHttpConfigFromEnv: throws (fail-loud) on a missing/invalid port", () => {
    delete process.env[ENV_HTTP_PORT];
    expect(() => resolveHttpConfigFromEnv()).toThrow();
    process.env[ENV_HTTP_PORT] = "notaport";
    expect(() => resolveHttpConfigFromEnv()).toThrow();
    process.env[ENV_HTTP_PORT] = "70000"; // out of range
    expect(() => resolveHttpConfigFromEnv()).toThrow();
    process.env[ENV_HTTP_PORT] = "0"; // 0 is not a valid LISTEN port here
    expect(() => resolveHttpConfigFromEnv()).toThrow();
  });

  test("buildAllowedHosts: loopback aliases for a 127.0.0.1 bind", () => {
    const hosts = buildAllowedHosts("127.0.0.1", 7332);
    expect(hosts).toContain("127.0.0.1:7332");
    expect(hosts).toContain("localhost:7332");
    // a non-loopback bind does NOT get the localhost alias auto-added
    const remote = buildAllowedHosts("10.0.0.5", 7332);
    expect(remote).toContain("10.0.0.5:7332");
    expect(remote).not.toContain("localhost:7332");
  });

  test("formatWhoisAddr: IPv4 plain, IPv6 bracketed, IPv4-mapped unwrapped (PR-2b)", () => {
    // IPv4 (the tailnet 100.x case) — plain ip:port.
    expect(formatWhoisAddr("100.64.0.1", 5000)).toBe("100.64.0.1:5000");
    expect(formatWhoisAddr("127.0.0.1", 80)).toBe("127.0.0.1:80");
    // Genuine IPv6 → [bracketed]:port (a raw `::1:port` would never parse).
    expect(formatWhoisAddr("::1", 5000)).toBe("[::1]:5000");
    expect(formatWhoisAddr("fd7a:115c:a1e0::1", 443)).toBe("[fd7a:115c:a1e0::1]:443");
    // IPv4-mapped IPv6 over a dual-stack socket → unwrapped to the plain IPv4.
    expect(formatWhoisAddr("::ffff:100.64.0.1", 5000)).toBe("100.64.0.1:5000");
  });
});

// ── e2e + security over a real loopback listener (ephemeral port) ──
describe("startHttpServer — Streamable HTTP over loopback", () => {
  test("an MCP client connects + lists the tier-filtered tools over HTTP", async () => {
    const handle = await startHttpServer(createMcpServer, authConfig());
    try {
      const client = new Client({ name: "v1.73-e2e-test", version: "1.0.0" });
      const transport = new StreamableHTTPClientTransport(
        new URL(`http://127.0.0.1:${handle.port}/mcp`),
      );
      await client.connect(transport);
      const { tools } = await client.listTools();
      // tools/list needs no account — proves the full handshake + the envelope's
      // tier filter flow end-to-end over HTTP (gmail_search is a read-tier tool).
      expect(tools.length).toBeGreaterThan(0);
      expect(tools.some((t) => t.name === "gmail_search")).toBe(true);
      await client.close();
    } finally {
      await handle.close();
    }
  });

  test("DNS-rebind protection: a POST with a non-allow-listed Host is rejected", async () => {
    const handle = await startHttpServer(createMcpServer, authConfig());
    try {
      const init = initializeBody();
      // Spoofed Host (a DNS-rebinding attacker's domain) → the SDK rejects (403).
      const evil = await rawPost(handle.port, init, { Host: "evil.example.com" });
      expect(evil.status).toBe(403);
      // The matching loopback Host is accepted (200) — proves we didn't just break it.
      const ok = await rawPost(handle.port, init, { Host: `127.0.0.1:${handle.port}` });
      expect(ok.status).toBe(200);
    } finally {
      await handle.close();
    }
  });

  test("a non-/mcp path 404s; a non-init POST without a session 400s; a huge body 413s", async () => {
    const handle = await startHttpServer(createMcpServer, authConfig());
    const host = `127.0.0.1:${handle.port}`;
    try {
      const notFound = await rawPost(handle.port, { jsonrpc: "2.0" }, { Host: host }, "/nope");
      expect(notFound.status).toBe(404);

      // A well-formed but non-initialize request with no session id → 400.
      const noSession = await rawPost(
        handle.port,
        { jsonrpc: "2.0", method: "tools/list", id: 1 },
        { Host: host },
      );
      expect(noSession.status).toBe(400);

      // Oversize body → 413, before any transport/session work (bounded buffering).
      const huge = "x".repeat(4 * 1024 * 1024 + 1024);
      const tooBig = await rawPostRaw(handle.port, huge, { Host: host });
      expect(tooBig.status).toBe(413);
    } finally {
      await handle.close();
    }
  });

  test("DELETE without a session → 400; an unsupported method (PUT) → 405", async () => {
    const handle = await startHttpServer(createMcpServer, authConfig());
    const host = `127.0.0.1:${handle.port}`;
    try {
      // DELETE/GET are session-routing methods — without a valid session id → 400.
      const del = await rawRequest(handle.port, "DELETE", "", { Host: host });
      expect(del.status).toBe(400);
      // Any other method on /mcp → 405 (Allow: GET, POST, DELETE).
      const put = await rawRequest(handle.port, "PUT", "{}", { Host: host });
      expect(put.status).toBe(405);
    } finally {
      await handle.close();
    }
  });
});

// ── operator auth (PR-2b: Tailscale WhoIs → registry, default-deny) ──
describe("startHttpServer — operator auth (PR-2b)", () => {
  test("an unidentified peer (WhoIs → no identity) is refused 403", async () => {
    const handle = await startHttpServer(
      createMcpServer,
      authConfig({ whois: async () => null }),
    );
    const host = `127.0.0.1:${handle.port}`;
    try {
      // The init never reaches createMcpServer — no anonymous operator.
      const res = await rawPost(handle.port, initializeBody(), { Host: host });
      expect(res.status).toBe(403);
    } finally {
      await handle.close();
    }
  });

  test("a verified but UNREGISTERED login is refused 403 (default-deny)", async () => {
    const handle = await startHttpServer(
      createMcpServer,
      authConfig({ whois: async () => "mallory@example.com" }),
    );
    const host = `127.0.0.1:${handle.port}`;
    try {
      // Same generic 403 as no-identity — no oracle distinguishing the two.
      const res = await rawPost(handle.port, initializeBody(), { Host: host });
      expect(res.status).toBe(403);
    } finally {
      await handle.close();
    }
  });

  test("a registered READ-tier operator sees only read tools (per-operator tier drives tools/list)", async () => {
    const handle = await startHttpServer(
      createMcpServer,
      authConfig({ whois: async () => "bob@example.com" }), // bob = read tier
    );
    try {
      const client = new Client({ name: "v1.74-2b-test", version: "1.0.0" });
      const transport = new StreamableHTTPClientTransport(
        new URL(`http://127.0.0.1:${handle.port}/mcp`),
      );
      await client.connect(transport);
      const names = (await client.listTools()).tools.map((t) => t.name);
      // bob's REGISTRY tier (read) — not the process $SAFESPACE_TIER — drives the
      // filter: a write tool is hidden, a read tool is visible. The multi-operator
      // payoff: one process, per-operator surfaces.
      expect(names).toContain("gmail_search");
      expect(names).not.toContain("gmail_send");
      await client.close();
    } finally {
      await handle.close();
    }
  });

  test("a connection with no resolvable peer anchor is refused 403 (no empty-key session)", async () => {
    const handle = await startHttpServer(
      createMcpServer,
      authConfig({ peerKeyImpl: () => "" }), // simulate an undefined remote address
    );
    const host = `127.0.0.1:${handle.port}`;
    try {
      // Even with a valid WhoIs identity, an unanchored peer can't be session-bound.
      const res = await rawPost(handle.port, initializeBody(), { Host: host });
      expect(res.status).toBe(403);
    } finally {
      await handle.close();
    }
  });

  test("a session id reused from a DIFFERENT peer is refused 403 (session-peer binding)", async () => {
    const handle = await startHttpServer(
      createMcpServer,
      // Simulate distinct tailnet peers over loopback via an injected anchor.
      authConfig({ peerKeyImpl: (req) => String(req.headers["x-test-peer"] ?? "") }),
    );
    const host = `127.0.0.1:${handle.port}`;
    try {
      // peerA authenticates + initializes a session.
      const init = await rawPost(handle.port, initializeBody(), {
        Host: host,
        "x-test-peer": "peerA",
      });
      expect(init.status).toBe(200);
      const sid = init.sessionId;
      expect(sid).toBeDefined();

      // The SAME session id presented from peerB → 403 (bound to peerA).
      const fromB = await rawRequest(handle.port, "DELETE", "", {
        Host: host,
        "x-test-peer": "peerB",
        "mcp-session-id": sid as string,
      });
      expect(fromB.status).toBe(403);

      // The same session id from peerA → NOT 403 (the owner is allowed through).
      const fromA = await rawRequest(handle.port, "DELETE", "", {
        Host: host,
        "x-test-peer": "peerA",
        "mcp-session-id": sid as string,
      });
      expect(fromA.status).not.toBe(403);
    } finally {
      await handle.close();
    }
  });
});

// ── v1.93 A1: token-mode operator auth (off-tailnet bearer tokens, loopback) ──
describe("startHttpServer — operator auth, token mode (v1.93 A1)", () => {
  test("a valid bearer token → registered login → session inits (200)", async () => {
    // whois forced to null, so a 200 can ONLY be the token path authenticating.
    const handle = await startHttpServer(
      createMcpServer,
      authConfig({
        authMode: "token",
        whois: async () => null,
        resolveTokenLogin: async (req) =>
          req.headers.authorization === "Bearer good" ? "alice@example.com" : null,
      }),
    );
    const host = `127.0.0.1:${handle.port}`;
    try {
      const res = await rawPost(handle.port, initializeBody(), { Host: host, Authorization: "Bearer good" });
      expect(res.status).toBe(200);
    } finally {
      await handle.close();
    }
  });

  test("a missing OR bad token → the SAME generic 403 (no oracle)", async () => {
    const handle = await startHttpServer(
      createMcpServer,
      authConfig({
        authMode: "token",
        whois: async () => null,
        resolveTokenLogin: async (req) =>
          req.headers.authorization === "Bearer good" ? "alice@example.com" : null,
      }),
    );
    const host = `127.0.0.1:${handle.port}`;
    try {
      expect((await rawPost(handle.port, initializeBody(), { Host: host })).status).toBe(403);
      expect(
        (await rawPost(handle.port, initializeBody(), { Host: host, Authorization: "Bearer bad" })).status,
      ).toBe(403);
    } finally {
      await handle.close();
    }
  });

  test("a valid token mapping to an UNREGISTERED login → 403 (registry default-deny)", async () => {
    const handle = await startHttpServer(
      createMcpServer,
      authConfig({
        authMode: "token",
        whois: async () => null,
        resolveTokenLogin: async () => "mallory@example.com", // resolves, but not registered
      }),
    );
    const host = `127.0.0.1:${handle.port}`;
    try {
      expect(
        (await rawPost(handle.port, initializeBody(), { Host: host, Authorization: "Bearer x" })).status,
      ).toBe(403);
    } finally {
      await handle.close();
    }
  });

  test("token mode WITHOUT a resolver refuses to start (fail-loud)", async () => {
    await expect(
      startHttpServer(createMcpServer, authConfig({ authMode: "token", resolveTokenLogin: undefined })),
    ).rejects.toThrow();
  });

  test("default mode is unchanged — WhoIs still authenticates (no token needed)", async () => {
    const handle = await startHttpServer(createMcpServer, authConfig()); // authMode undefined → tailscale
    const host = `127.0.0.1:${handle.port}`;
    try {
      expect((await rawPost(handle.port, initializeBody(), { Host: host })).status).toBe(200);
    } finally {
      await handle.close();
    }
  });
});

// ── v1.80 PR-3: registry hot-reload at the transport (revocation = next request) ──
describe("startHttpServer — registry hot-reload (v1.80 PR-3)", () => {
  const WITHOUT_ALICE = parseOperatorRegistry(
    JSON.stringify({
      operators: [
        { tailnetLogin: "bob@example.com", operatorId: "bob", tier: "read", allowedAccounts: [] },
      ],
    }),
  );
  const ALICE_READ = parseOperatorRegistry(
    JSON.stringify({
      operators: [
        { tailnetLogin: "alice@example.com", operatorId: "alice", tier: "read", allowedAccounts: [] },
      ],
    }),
  );

  /** A provider whose registry the test swaps mid-session — the transport must
   *  observe the CURRENT value per request (the real provider's mtime mechanics
   *  are unit-tested in operator-registry.test.ts). */
  function mutableProvider(initial: typeof TEST_REGISTRY) {
    const box = { reg: initial };
    return { box, provider: { current: async () => box.reg } };
  }

  test("a REMOVED operator's live session 403s on the next request and is torn down", async () => {
    const { box, provider } = mutableProvider(TEST_REGISTRY);
    const handle = await startHttpServer(createMcpServer, authConfig({ registry: provider }));
    const host = `127.0.0.1:${handle.port}`;
    try {
      // alice authenticates + initializes a session.
      const init = await rawPost(handle.port, initializeBody(), { Host: host });
      expect(init.status).toBe(200);
      const sid = init.sessionId as string;
      expect(sid).toBeDefined();

      // The registry is edited: alice is REMOVED (revocation).
      box.reg = WITHOUT_ALICE;

      // Her very next request on the LIVE session → the same generic 403.
      const after = await rawPost(
        handle.port,
        { jsonrpc: "2.0", method: "tools/list", id: 2 },
        { Host: host, "mcp-session-id": sid },
      );
      expect(after.status).toBe(403);

      // And the session was torn down — replaying the id is now an unknown
      // session (400), not a live transport.
      const replay = await rawPost(
        handle.port,
        { jsonrpc: "2.0", method: "tools/list", id: 3 },
        { Host: host, "mcp-session-id": sid },
      );
      expect(replay.status).toBe(400);
    } finally {
      await handle.close();
    }
  });

  test("a TIER change applies to a live session on the next call (share → read hides write tools)", async () => {
    const { box, provider } = mutableProvider(TEST_REGISTRY); // alice = share
    const handle = await startHttpServer(createMcpServer, authConfig({ registry: provider }));
    try {
      const client = new Client({ name: "v1.80-reload-test", version: "1.0.0" });
      const transport = new StreamableHTTPClientTransport(
        new URL(`http://127.0.0.1:${handle.port}/mcp`),
      );
      await client.connect(transport);
      const before = (await client.listTools()).tools.map((t) => t.name);
      expect(before).toContain("gmail_send"); // share tier sees write tools

      // The registry is edited: alice is downgraded share → read.
      box.reg = ALICE_READ;

      const after = (await client.listTools()).tools.map((t) => t.name);
      expect(after).toContain("gmail_search");
      expect(after).not.toContain("gmail_send"); // next call observes the new tier
      await client.close();
    } finally {
      await handle.close();
    }
  });

  test("a REMOVED operator's DELETE/GET path is refused too (the SSE/teardown route re-resolves)", async () => {
    const { box, provider } = mutableProvider(TEST_REGISTRY);
    const handle = await startHttpServer(createMcpServer, authConfig({ registry: provider }));
    const host = `127.0.0.1:${handle.port}`;
    try {
      const init = await rawPost(handle.port, initializeBody(), { Host: host });
      expect(init.status).toBe(200);
      const sid = init.sessionId as string;

      box.reg = WITHOUT_ALICE; // alice revoked

      // The non-POST session route (DELETE here; GET shares the same guard)
      // re-resolves and refuses with the same generic 403.
      const del = await rawRequest(handle.port, "DELETE", "", {
        Host: host,
        "mcp-session-id": sid,
      });
      expect(del.status).toBe(403);
    } finally {
      await handle.close();
    }
  });

  test("an ADDED operator connects WITHOUT a restart (session-init reads the current registry)", async () => {
    const { box, provider } = mutableProvider(WITHOUT_ALICE); // alice not registered yet
    const handle = await startHttpServer(createMcpServer, authConfig({ registry: provider }));
    const host = `127.0.0.1:${handle.port}`;
    try {
      // alice (the okWhois identity) is refused while unregistered.
      const denied = await rawPost(handle.port, initializeBody(), { Host: host });
      expect(denied.status).toBe(403);

      // The registry is edited: alice is added.
      box.reg = TEST_REGISTRY;

      const ok = await rawPost(handle.port, initializeBody(), { Host: host });
      expect(ok.status).toBe(200);
      expect(ok.sessionId).toBeDefined();
    } finally {
      await handle.close();
    }
  });
});

// ── v1.94 A2: per-request token re-check (revocation bites an OPEN session) ──
describe("startHttpServer — per-request token re-check (v1.94 A2)", () => {
  /** A token resolver whose answer the test swaps mid-session. authMode=token +
   *  whois→null, so identity comes ONLY from this resolver, which the transport
   *  re-runs on EVERY request (the property under test). */
  function tokenConfig(box: { login: string | null }): HttpServerConfig {
    return authConfig({
      authMode: "token",
      whois: async () => null,
      resolveTokenLogin: async () => box.login,
    });
  }

  test("a REVOKED token 403s the open session's next request and tears it down", async () => {
    const box = { login: "alice@example.com" as string | null };
    const handle = await startHttpServer(createMcpServer, tokenConfig(box));
    const host = `127.0.0.1:${handle.port}`;
    try {
      const init = await rawPost(handle.port, initializeBody(), {
        Host: host,
        Authorization: "Bearer good",
      });
      expect(init.status).toBe(200);
      const sid = init.sessionId as string;
      expect(sid).toBeDefined();

      // The token is revoked (gone from the store / expired) → resolver returns null.
      // The registry is UNTOUCHED (alice still registered), so a 403 here can ONLY be
      // the per-request TOKEN re-check firing — not the registry re-resolution.
      box.login = null;

      const after = await rawPost(
        handle.port,
        { jsonrpc: "2.0", method: "tools/list", id: 2 },
        { Host: host, "mcp-session-id": sid, Authorization: "Bearer good" },
      );
      expect(after.status).toBe(403);

      // Torn down — replaying the id is now an unknown session (400), not a live one.
      const replay = await rawPost(
        handle.port,
        { jsonrpc: "2.0", method: "tools/list", id: 3 },
        { Host: host, "mcp-session-id": sid, Authorization: "Bearer good" },
      );
      expect(replay.status).toBe(400);
    } finally {
      await handle.close();
    }
  });

  test("a token swapped to a DIFFERENT registered login → 403 (session bound to its login)", async () => {
    // bob IS registered, but the session was opened as alice. Behind a reverse proxy
    // every request shares the proxy's source IP, so the peerKey binding cannot tell
    // two operators apart — the token→login match is what refuses to carry alice's
    // session over to bob (the cross-operator session-hijack defense under token auth).
    const box = { login: "alice@example.com" as string | null };
    const handle = await startHttpServer(createMcpServer, tokenConfig(box));
    const host = `127.0.0.1:${handle.port}`;
    try {
      const init = await rawPost(handle.port, initializeBody(), {
        Host: host,
        Authorization: "Bearer alice",
      });
      expect(init.status).toBe(200);
      const sid = init.sessionId as string;

      box.login = "bob@example.com"; // a valid, registered — but DIFFERENT — operator

      const after = await rawPost(
        handle.port,
        { jsonrpc: "2.0", method: "tools/list", id: 2 },
        { Host: host, "mcp-session-id": sid, Authorization: "Bearer bob" },
      );
      expect(after.status).toBe(403);

      // Torn down on a login mismatch too (symmetric with the revocation case) —
      // replaying the id is now an unknown session (400), not a live transport.
      const replay = await rawPost(
        handle.port,
        { jsonrpc: "2.0", method: "tools/list", id: 3 },
        { Host: host, "mcp-session-id": sid, Authorization: "Bearer bob" },
      );
      expect(replay.status).toBe(400);
    } finally {
      await handle.close();
    }
  });

  test("the DELETE/GET route re-checks the token too (a held-open SSE's next request)", async () => {
    const box = { login: "alice@example.com" as string | null };
    const handle = await startHttpServer(createMcpServer, tokenConfig(box));
    const host = `127.0.0.1:${handle.port}`;
    try {
      const init = await rawPost(handle.port, initializeBody(), {
        Host: host,
        Authorization: "Bearer good",
      });
      expect(init.status).toBe(200);
      const sid = init.sessionId as string;

      box.login = null; // token revoked

      const del = await rawRequest(handle.port, "DELETE", "", {
        Host: host,
        "mcp-session-id": sid,
        Authorization: "Bearer good",
      });
      expect(del.status).toBe(403);
    } finally {
      await handle.close();
    }
  });

  test("a STABLE token keeps the session alive across requests (re-check is not over-eager)", async () => {
    const box = { login: "alice@example.com" as string | null };
    const handle = await startHttpServer(createMcpServer, tokenConfig(box));
    const host = `127.0.0.1:${handle.port}`;
    try {
      const init = await rawPost(handle.port, initializeBody(), {
        Host: host,
        Authorization: "Bearer good",
      });
      expect(init.status).toBe(200);
      const sid = init.sessionId as string;

      // token unchanged → the follow-up tools/list is served (the session lives), so
      // the per-request re-check does not spuriously refuse the legitimate happy path.
      const after = await rawPost(
        handle.port,
        { jsonrpc: "2.0", method: "tools/list", id: 2 },
        { Host: host, "mcp-session-id": sid, Authorization: "Bearer good" },
      );
      expect(after.status).toBe(200);
    } finally {
      await handle.close();
    }
  });

  test("a resolver that THROWS mid-session → 403 + teardown (fail closed, not a 500)", async () => {
    // sec-rev A2 NIT-1: a resolver exception must NOT propagate to the outer 500
    // handler (which would skip teardown + answer a non-403). The re-check catches it
    // and denies + tears down, exactly like a null/mismatched login.
    const box = { login: "alice@example.com" as string | null, fail: false };
    const handle = await startHttpServer(
      createMcpServer,
      authConfig({
        authMode: "token",
        whois: async () => null,
        resolveTokenLogin: async () => {
          if (box.fail) throw new Error("store read blew up");
          return box.login;
        },
      }),
    );
    const host = `127.0.0.1:${handle.port}`;
    try {
      const init = await rawPost(handle.port, initializeBody(), {
        Host: host,
        Authorization: "Bearer good",
      });
      expect(init.status).toBe(200);
      const sid = init.sessionId as string;

      box.fail = true; // the next re-resolution throws

      const after = await rawPost(
        handle.port,
        { jsonrpc: "2.0", method: "tools/list", id: 2 },
        { Host: host, "mcp-session-id": sid, Authorization: "Bearer good" },
      );
      expect(after.status).toBe(403); // denyAndTeardown, NOT a propagated 500

      // torn down → replaying the id is an unknown session (400).
      const replay = await rawPost(
        handle.port,
        { jsonrpc: "2.0", method: "tools/list", id: 3 },
        { Host: host, "mcp-session-id": sid, Authorization: "Bearer good" },
      );
      expect(replay.status).toBe(400);
    } finally {
      await handle.close();
    }
  });
});

// ── helpers ──
function initializeBody(): Record<string, unknown> {
  return {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "raw-test", version: "1.0.0" },
    },
  };
}

interface RawResult {
  status: number;
  /** The `mcp-session-id` response header (present on a successful init). */
  sessionId?: string;
}

function rawPost(
  port: number,
  body: unknown,
  headers: Record<string, string>,
  path = "/mcp",
): Promise<RawResult> {
  return rawPostRaw(port, JSON.stringify(body), headers, path);
}

function rawPostRaw(
  port: number,
  body: string,
  headers: Record<string, string>,
  path = "/mcp",
): Promise<RawResult> {
  return rawRequest(port, "POST", body, headers, path);
}

function rawRequest(
  port: number,
  method: string,
  body: string,
  headers: Record<string, string>,
  path = "/mcp",
): Promise<RawResult> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path,
        method,
        headers: {
          "Content-Type": "application/json",
          // Streamable HTTP requires the client to accept both JSON + SSE.
          Accept: "application/json, text/event-stream",
          ...headers,
        },
      },
      (res) => {
        // drain so the socket frees; we only assert on status (+ the session id).
        res.on("data", () => {});
        res.on("end", () => {
          const sid = res.headers["mcp-session-id"];
          resolve({
            status: res.statusCode ?? 0,
            sessionId: Array.isArray(sid) ? sid[0] : sid,
          });
        });
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}
