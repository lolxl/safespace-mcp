// v1.70 (G4) — the hardened GitHub REST GET helper: URL/header construction,
// HTTP-status → closed-set reason mapping (incl. the 403 rate-limit-vs-auth split),
// network/timeout → api_error, and the no-leak guarantee (the token never appears in
// a thrown error). Fully mocked at the fetch seam.

import { describe, expect, test } from "bun:test";
import { githubApiGet, githubApiWrite } from "./client";

function stub(status: number, body: unknown = {}, headers: Record<string, string> = {}) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const impl = (async (url: unknown, init?: unknown) => {
    calls.push({ url: String(url), init: (init ?? {}) as RequestInit });
    return new Response(JSON.stringify(body), { status, headers });
  }) as unknown as typeof fetch;
  return { impl, calls };
}

describe("githubApiGet — request construction + success", () => {
  test("builds the api.github.com URL with query, sends the bearer + UA + Accept", async () => {
    const s = stub(200, { ok: 1 });
    const out = await githubApiGet({
      token: "gho_TOK",
      path: "/repos/o/r/issues",
      query: { state: "open", per_page: 30, page: undefined },
      fetchImpl: s.impl,
    });
    expect(out).toEqual({ ok: 1 });
    expect(s.calls[0]!.url).toBe("https://api.github.com/repos/o/r/issues?state=open&per_page=30");
    const h = s.calls[0]!.init.headers as Record<string, string>;
    expect(h.Authorization).toBe("Bearer gho_TOK");
    expect(h.Accept).toBe("application/vnd.github+json");
    expect(h["User-Agent"]).toBe("safespace-mcp");
    expect(h["X-GitHub-Api-Version"]).toBe("2026-03-10");
  });
});

describe("githubApiGet — status → closed-set reason", () => {
  const cases: Array<[number, Record<string, string>, string]> = [
    [401, {}, "auth_failed"],
    [403, { "x-ratelimit-remaining": "0" }, "rate_limited"],
    [403, { "x-ratelimit-remaining": "57" }, "auth_failed"],
    [403, {}, "auth_failed"],
    [429, {}, "rate_limited"],
    [404, {}, "not_found"],
    [500, {}, "api_error"],
    [422, {}, "api_error"],
  ];
  for (const [status, headers, reason] of cases) {
    test(`${status}${headers["x-ratelimit-remaining"] ? ` (rl=${headers["x-ratelimit-remaining"]})` : ""} → ${reason}`, async () => {
      const s = stub(status, { message: "err detail must not leak" }, headers);
      await expect(githubApiGet({ token: "gho_TOK", path: "/x", fetchImpl: s.impl })).rejects.toMatchObject({
        errorName: "github_api_failed",
        errorData: { reason },
      });
    });
  }

  test("a non-ok response body is NEVER echoed in the error", async () => {
    const s = stub(404, { message: "private repo SECRET-NAME exists" });
    let thrown: unknown;
    await githubApiGet({ token: "gho_TOK", path: "/x", fetchImpl: s.impl }).catch((e) => { thrown = e; });
    expect(JSON.stringify(thrown)).not.toContain("SECRET-NAME");
  });
});

describe("githubApiGet — network + no-leak", () => {
  test("a network/timeout failure → api_error (the raw error never surfaces)", async () => {
    const impl = (async () => { throw new Error("ECONNRESET at https://api.github.com with token gho_TOK"); }) as unknown as typeof fetch;
    let thrown: unknown;
    await githubApiGet({ token: "gho_TOK", path: "/x", fetchImpl: impl }).catch((e) => { thrown = e; });
    expect(thrown).toMatchObject({ errorName: "github_api_failed", errorData: { reason: "api_error" } });
    // the token must not leak via the thrown error
    expect(JSON.stringify(thrown)).not.toContain("gho_TOK");
  });

  test("an oversized Content-Length → api_error (context-protection cap)", async () => {
    const s = stub(200, { ok: 1 }, { "content-length": String(6 * 1024 * 1024) });
    await expect(githubApiGet({ token: "gho_TOK", path: "/x", fetchImpl: s.impl })).rejects.toMatchObject({
      errorData: { reason: "api_error" },
    });
  });

  test("a header-less (chunked) oversized body is STILL capped → api_error (no bypass)", async () => {
    // A streamed Response carries no Content-Length header, so the header check
    // can't see the size — the streaming byte cap must catch it.
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        const mb = new TextEncoder().encode("x".repeat(1024 * 1024));
        for (let i = 0; i < 6; i++) c.enqueue(mb); // 6 MB > 5 MB cap
        c.close();
      },
    });
    const impl = (async () => new Response(stream, { status: 200 })) as unknown as typeof fetch;
    await expect(githubApiGet({ token: "gho_TOK", path: "/x", fetchImpl: impl })).rejects.toMatchObject({
      errorData: { reason: "api_error" },
    });
  });

  test("unparseable JSON → api_error", async () => {
    const impl = (async () => new Response("{not json", { status: 200 })) as unknown as typeof fetch;
    await expect(githubApiGet({ token: "gho_TOK", path: "/x", fetchImpl: impl })).rejects.toMatchObject({
      errorData: { reason: "api_error" },
    });
  });
});

describe("githubApiWrite (v1.71) — POST/PATCH", () => {
  test("POST sends the method + JSON body + Content-Type, returns the parsed resource", async () => {
    const s = stub(201, { number: 7, created: true });
    const out = await githubApiWrite({ token: "gho_TOK", method: "POST", path: "/repos/o/r/issues", body: { title: "t" }, fetchImpl: s.impl });
    expect(out).toEqual({ number: 7, created: true });
    expect(s.calls[0]!.url).toBe("https://api.github.com/repos/o/r/issues");
    const init = s.calls[0]!.init;
    expect(init.method).toBe("POST");
    expect(String(init.body)).toBe(JSON.stringify({ title: "t" }));
    expect((init.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer gho_TOK");
  });

  test("PATCH works the same way", async () => {
    const s = stub(200, { number: 7, state: "closed" });
    await githubApiWrite({ token: "gho_TOK", method: "PATCH", path: "/repos/o/r/issues/7", body: { state: "closed" }, fetchImpl: s.impl });
    expect(s.calls[0]!.init.method).toBe("PATCH");
  });

  test("a non-ok write status maps to the closed-set reason (422 → api_error)", async () => {
    const s = stub(422, { message: "Validation failed" });
    await expect(githubApiWrite({ token: "gho_TOK", method: "POST", path: "/x", body: {}, fetchImpl: s.impl })).rejects.toMatchObject({
      errorName: "github_api_failed",
      errorData: { reason: "api_error" },
    });
  });

  test("a non-serializable body throws SYNCHRONOUSLY (a caller bug — not masked as api_error)", async () => {
    const s = stub(201, {});
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    await expect(githubApiWrite({ token: "gho_TOK", method: "POST", path: "/x", body: circular, fetchImpl: s.impl })).rejects.toThrow(/circular|JSON/i);
    expect(s.calls).toHaveLength(0); // never reached the fetch
  });

  // v1.88 — the egress-destination backstop fires on a path that escapes the host.
  test("a host-escaping path (`@evil.com`) is BLOCKED before the fetch (-32047)", async () => {
    const s = stub(200, {});
    await expect(
      githubApiGet({ token: "gho_TOK", path: "@evil.com/repos", fetchImpl: s.impl }),
    ).rejects.toMatchObject({ errorName: "egress_destination_blocked", errorData: { host: "evil.com" } });
    expect(s.calls).toHaveLength(0); // the assert ran BEFORE any fetch
  });
});
