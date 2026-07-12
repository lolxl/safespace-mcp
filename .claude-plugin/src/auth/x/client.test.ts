// v1.114 — the hardened X REST GET helper: URL/header construction, HTTP-status →
// closed-set reason mapping, network/timeout → api_error, bounded-read wiring, and the
// no-leak guarantee (token / query / RFC-7807 free text never appear in a thrown error).
// Fully mocked at the fetch seam (no network).

import { describe, expect, test } from "bun:test";
import { MCPError } from "../../errors";
import { xApiGet, xApiPost } from "./client";

function stub(status: number, body: unknown = {}, headers: Record<string, string> = {}) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const impl = (async (url: unknown, init?: unknown) => {
    calls.push({ url: String(url), init: (init ?? {}) as RequestInit });
    return new Response(JSON.stringify(body), { status, headers });
  }) as unknown as typeof fetch;
  return { impl, calls };
}

describe("xApiGet — request construction + success", () => {
  test("builds the api.x.com URL with params, sends Bearer + Accept json", async () => {
    const s = stub(200, { data: { id: "1", username: "u" } });
    const out = await xApiGet(
      "/2/users/me",
      { "user.fields": "id,username,name,description,created_at" },
      "x-access-TOKEN",
      s.impl,
    );
    expect(out).toEqual({ data: { id: "1", username: "u" } });
    expect(s.calls[0]!.url).toBe(
      "https://api.x.com/2/users/me?user.fields=id%2Cusername%2Cname%2Cdescription%2Ccreated_at",
    );
    const h = s.calls[0]!.init.headers as Record<string, string>;
    expect(h.Authorization).toBe("Bearer x-access-TOKEN");
    expect(h.Accept).toBe("application/json");
    expect(s.calls[0]!.init.method ?? "GET").toBe("GET");
  });

  test("empty params produces no query string", async () => {
    const s = stub(200, { ok: 1 });
    await xApiGet("/2/users/me", {}, "tok", s.impl);
    expect(s.calls[0]!.url).toBe("https://api.x.com/2/users/me");
  });
});

describe("xApiGet — status → closed-set reason", () => {
  const cases: Array<[number, string]> = [
    [429, "rate_limited"],
    [401, "consent_required"],
    [403, "api_error"],
    [404, "api_error"],
    [500, "api_error"],
    [422, "api_error"],
  ];
  for (const [status, reason] of cases) {
    test(`${status} → ${reason}`, async () => {
      const s = stub(status, {
        type: "about:blank",
        title: "err detail must not leak",
        detail: "SECRET-DETAIL free text",
        status,
      });
      let err: unknown;
      try {
        await xApiGet("/2/users/me", {}, "tok", s.impl);
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(MCPError);
      const mcp = err as MCPError;
      expect(mcp.errorName).toBe("x_api_failed");
      expect(mcp.errorData).toEqual({ reason });
      // Exact closed shape — upstream RFC-7807 free-text fields must never ride along.
      expect(mcp.errorData).not.toHaveProperty("title");
      expect(mcp.errorData).not.toHaveProperty("detail");
      expect(Object.keys(mcp.errorData)).toEqual(["reason"]);
    });
  }

  test("a non-ok RFC-7807 body title/detail is NEVER echoed in the error", async () => {
    const s = stub(500, {
      type: "about:blank",
      title: "Internal Error SECRET-TITLE",
      detail: "leaky free-text SECRET-DETAIL",
      status: 500,
    });
    let thrown: unknown;
    await xApiGet("/2/users/me", {}, "tok", s.impl).catch((e) => {
      thrown = e;
    });
    const s_ = JSON.stringify(thrown);
    expect(s_).not.toContain("SECRET-TITLE");
    expect(s_).not.toContain("SECRET-DETAIL");
    expect(s_).not.toContain("leaky");
  });
});

describe("xApiGet — network + bounded-read + no-leak", () => {
  test("a network/timeout failure → api_error (the raw error never surfaces)", async () => {
    const impl = (async () => {
      throw new Error("ECONNRESET at https://api.x.com with token x-access-TOKEN query=evil");
    }) as unknown as typeof fetch;
    let thrown: unknown;
    await xApiGet("/2/users/me", { query: "secret-query" }, "x-access-TOKEN", impl).catch(
      (e) => {
        thrown = e;
      },
    );
    expect(thrown).toMatchObject({
      errorName: "x_api_failed",
      errorData: { reason: "api_error" },
    });
    expect(JSON.stringify(thrown)).not.toContain("x-access-TOKEN");
    expect(JSON.stringify(thrown)).not.toContain("secret-query");
  });

  test("an oversized Content-Length → api_error (context-protection cap)", async () => {
    const s = stub(200, { ok: 1 }, { "content-length": String(6 * 1024 * 1024) });
    await expect(xApiGet("/2/users/me", {}, "tok", s.impl)).rejects.toMatchObject({
      errorData: { reason: "api_error" },
    });
  });

  test("a header-less (chunked) oversized body is STILL capped via readBounded → api_error", async () => {
    // A streamed Response carries no Content-Length header, so the header check
    // can't see the size — the streaming byte cap (readBounded) must catch it.
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        const mb = new TextEncoder().encode("x".repeat(1024 * 1024));
        for (let i = 0; i < 6; i++) c.enqueue(mb); // 6 MB > 5 MB cap
        c.close();
      },
    });
    const impl = (async () => new Response(stream, { status: 200 })) as unknown as typeof fetch;
    await expect(xApiGet("/2/users/me", {}, "tok", impl)).rejects.toMatchObject({
      errorData: { reason: "api_error" },
    });
  });

  test("unparseable JSON → api_error", async () => {
    const impl = (async () => new Response("{not json", { status: 200 })) as unknown as typeof fetch;
    await expect(xApiGet("/2/users/me", {}, "tok", impl)).rejects.toMatchObject({
      errorData: { reason: "api_error" },
    });
  });

  test("a host-escaping path (`@evil.com`) is BLOCKED before the fetch (-32047)", async () => {
    const s = stub(200, {});
    await expect(xApiGet("@evil.com/2/users/me", {}, "tok", s.impl)).rejects.toMatchObject({
      errorName: "egress_destination_blocked",
      errorData: { host: "evil.com" },
    });
    expect(s.calls).toHaveLength(0); // the assert ran BEFORE any fetch
  });
});

describe("xApiPost — request construction + success", () => {
  test("POSTs JSON body to api.x.com with Bearer + Content-Type + Accept", async () => {
    const s = stub(201, { data: { id: "123", text: "hello" } });
    const out = await xApiPost("/2/tweets", { text: "hello" }, "x-post-TOKEN", s.impl);
    expect(out).toEqual({ data: { id: "123", text: "hello" } });
    expect(s.calls[0]!.url).toBe("https://api.x.com/2/tweets");
    expect(s.calls[0]!.init.method).toBe("POST");
    const h = s.calls[0]!.init.headers as Record<string, string>;
    expect(h.Authorization).toBe("Bearer x-post-TOKEN");
    expect(h.Accept).toBe("application/json");
    expect(h["Content-Type"]).toBe("application/json");
    expect(s.calls[0]!.init.body).toBe(JSON.stringify({ text: "hello" }));
  });
});

describe("xApiPost — status → closed-set reason", () => {
  const cases: Array<[number, string]> = [
    [429, "rate_limited"],
    [401, "consent_required"],
    [403, "api_error"],
    [404, "api_error"],
    [500, "api_error"],
  ];
  for (const [status, reason] of cases) {
    test(`${status} → ${reason}`, async () => {
      const s = stub(status, {
        title: "err detail must not leak",
        detail: "SECRET-DETAIL free text",
      });
      let err: unknown;
      try {
        await xApiPost("/2/tweets", { text: "t" }, "tok", s.impl);
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(MCPError);
      const mcp = err as MCPError;
      expect(mcp.errorName).toBe("x_api_failed");
      expect(mcp.errorData).toEqual({ reason });
      expect(mcp.errorData).not.toHaveProperty("title");
      expect(mcp.errorData).not.toHaveProperty("detail");
      expect(Object.keys(mcp.errorData)).toEqual(["reason"]);
    });
  }

  test("error path never echoes token or post text", async () => {
    const s = stub(500, { title: "nope" });
    let thrown: unknown;
    await xApiPost("/2/tweets", { text: "secret-post-body" }, "super-secret-x-token", s.impl).catch(
      (e) => {
        thrown = e;
      },
    );
    const s_ = JSON.stringify(thrown);
    expect(s_).not.toContain("super-secret-x-token");
    expect(s_).not.toContain("secret-post-body");
  });
});
