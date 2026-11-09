// v1.77 — the hardened Notion REST helper: URL/header construction, GET + POST, the
// status→closed-set-reason table, timeout/network → api_error, the oversized-response cap,
// and the token-never-leaked guard. Mirrors auth/github/client.test.ts.

import { describe, expect, test } from "bun:test";
import { MCPError } from "../../errors";
import { notionApiGet, notionApiPost } from "./client";

function fetchStub(body: unknown, status = 200, headers: Record<string, string> = {}) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const impl = (async (url: unknown, init?: unknown) => {
    calls.push({ url: String(url), init: (init ?? {}) as RequestInit });
    return new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers });
  }) as unknown as typeof fetch;
  return { impl, calls };
}

describe("notionApiGet/Post — construction + auth headers", () => {
  test("GET builds the URL + Bearer + Notion-Version headers, returns parsed JSON", async () => {
    const f = fetchStub({ ok: true });
    const out = await notionApiGet({ token: "ntn_TOK", path: "/v1/pages/abc", query: { page_size: 30 }, fetchImpl: f.impl });
    expect(f.calls[0]!.url).toBe("https://api.notion.com/v1/pages/abc?page_size=30");
    const h = f.calls[0]!.init.headers as Record<string, string>;
    expect(h.Authorization).toBe("Bearer ntn_TOK");
    expect(h["Notion-Version"]).toBe("2026-03-11");
    expect(out).toEqual({ ok: true });
  });

  test("POST serializes the body + sets Content-Type", async () => {
    const f = fetchStub({ results: [] });
    await notionApiPost({ token: "t", path: "/v1/search", body: { query: "x", page_size: 10 }, fetchImpl: f.impl });
    expect(f.calls[0]!.init.method).toBe("POST");
    expect(JSON.parse(String(f.calls[0]!.init.body))).toEqual({ query: "x", page_size: 10 });
    expect((f.calls[0]!.init.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
  });
});

describe("notionApi — status → closed-set reason", () => {
  const cases: Array<[number, string]> = [
    [401, "auth_failed"],
    [403, "auth_failed"],
    [404, "not_found"],
    [429, "rate_limited"],
    [400, "api_error"],
    [500, "api_error"],
  ];
  for (const [status, reason] of cases) {
    test(`${status} → ${reason}`, async () => {
      await expect(notionApiGet({ token: "t", path: "/v1/pages/x", fetchImpl: fetchStub({ message: "e" }, status).impl })).rejects.toMatchObject({
        errorName: "notion_api_failed",
        errorData: { reason },
      });
    });
  }

  test("a network failure → api_error (never leaks the raw error)", async () => {
    const impl = (async () => {
      throw new Error("ECONNRESET tok=ntn_TOK");
    }) as unknown as typeof fetch;
    const err = await notionApiGet({ token: "ntn_TOK", path: "/v1/pages/x", fetchImpl: impl }).catch((e) => e);
    expect(err).toBeInstanceOf(MCPError);
    expect((err as MCPError).errorData.reason).toBe("api_error");
    expect(JSON.stringify(err)).not.toContain("ntn_TOK");
  });

  test("an oversized (Content-Length) response → api_error", async () => {
    const f = fetchStub({ big: true }, 200, { "content-length": String(6 * 1024 * 1024) });
    await expect(notionApiGet({ token: "t", path: "/v1/pages/x", fetchImpl: f.impl })).rejects.toMatchObject({
      errorName: "notion_api_failed",
      errorData: { reason: "api_error" },
    });
  });

  test("unparseable JSON → api_error", async () => {
    const f = fetchStub("not json{", 200);
    await expect(notionApiGet({ token: "t", path: "/v1/pages/x", fetchImpl: f.impl })).rejects.toMatchObject({
      errorName: "notion_api_failed",
      errorData: { reason: "api_error" },
    });
  });
});

describe("notionApi — no-leak", () => {
  test("the token never appears in a thrown error on a non-ok status", async () => {
    const err = await notionApiGet({ token: "ntn_SUPER_SECRET", path: "/v1/pages/x", fetchImpl: fetchStub({ message: "denied" }, 403).impl }).catch((e) => e);
    expect(JSON.stringify(err)).not.toContain("ntn_SUPER_SECRET");
    expect(JSON.stringify(err)).not.toContain("denied"); // response body never echoed
  });
});
