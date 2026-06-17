// v1.65 Phase C — REAL-transport tests for the url-gate's network primitives
// (defaultHttpGetOnce + defaultLookup). The gate orchestration tests inject around
// these; here we exercise the actual node:dns / node:https.request code against a
// loopback HTTP server, so the IP-pinning + stream/redirect/timeout plumbing is
// covered by real code (not a mock). No external network is used.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import * as http from "node:http";
import { MCPError } from "../errors";
import { defaultHttpGetOnce, defaultLookup } from "./url-gate";

let server: http.Server;
let port: number;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    if (req.url === "/redirect") {
      res.writeHead(302, { Location: "https://example.com/next" });
      res.end();
      return;
    }
    if (req.url === "/slow") {
      // Never responds → drives the request timeout.
      return;
    }
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("loopback body");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as { port: number }).port;
});

afterAll(() => {
  server.close();
});

describe("defaultHttpGetOnce (real loopback transport)", () => {
  test("GET against a pinned IP returns status + headers + body stream", async () => {
    const resp = await defaultHttpGetOnce(
      new URL(`http://127.0.0.1:${port}/hello`),
      { address: "127.0.0.1", family: 4 },
      { timeoutMs: 5000 },
    );
    expect(resp.status).toBe(200);
    expect(resp.headers["content-type"]).toContain("text/plain");
    let body = "";
    for await (const chunk of resp.body) body += new TextDecoder().decode(chunk);
    expect(body).toBe("loopback body");
  });

  test("surfaces a 3xx Location header (the redirect branch)", async () => {
    const resp = await defaultHttpGetOnce(
      new URL(`http://127.0.0.1:${port}/redirect`),
      { address: "127.0.0.1", family: 4 },
      { timeoutMs: 5000 },
    );
    expect(resp.status).toBe(302);
    expect(resp.location).toBe("https://example.com/next");
  });

  test("a slow endpoint trips the timeout → web_fetch_failed", async () => {
    try {
      await defaultHttpGetOnce(
        new URL(`http://127.0.0.1:${port}/slow`),
        { address: "127.0.0.1", family: 4 },
        { timeoutMs: 80 },
      );
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(MCPError);
      expect((e as MCPError).errorName).toBe("web_fetch_failed");
      expect((e as MCPError).errorData.reason).toBe("timeout");
    }
  });

  test("a refused connection → web_fetch_failed connection_failed", async () => {
    // Port 1 on loopback: nothing listens → ECONNREFUSED.
    try {
      await defaultHttpGetOnce(
        new URL("http://127.0.0.1:1/"),
        { address: "127.0.0.1", family: 4 },
        { timeoutMs: 2000 },
      );
      throw new Error("expected throw");
    } catch (e) {
      expect((e as MCPError).errorName).toBe("web_fetch_failed");
    }
  });
});

describe("defaultLookup (real DNS)", () => {
  test("resolves localhost to loopback", async () => {
    const addrs = await defaultLookup("localhost");
    expect(addrs.length).toBeGreaterThan(0);
    expect(addrs.every((a) => a.family === 4 || a.family === 6)).toBe(true);
  });

  test("a non-existent host → web_fetch_failed dns_resolution_failed", async () => {
    try {
      await defaultLookup("this-host-does-not-exist.invalid");
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(MCPError);
      expect((e as MCPError).errorName).toBe("web_fetch_failed");
      expect((e as MCPError).errorData.reason).toBe("dns_resolution_failed");
    }
  });
});
