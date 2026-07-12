// v1.115.1 — the shared gated xFetch helper: egress pin BEFORE dispatch,
// User-Agent injection, and AbortController timeout (cleared in finally).

import { describe, expect, test } from "bun:test";
import { X_ERROR_CODE_RE, xFetch } from "./http";

describe("xFetch — gated dispatch", () => {
  test("assertEgressHost runs BEFORE fetch (host-escape never dispatches)", async () => {
    const calls: string[] = [];
    const impl = (async (url: unknown) => {
      calls.push(String(url));
      return new Response("{}", { status: 200 });
    }) as unknown as typeof fetch;
    await expect(
      xFetch(impl, "https://api.x.com@evil.com/2/oauth2/token", {
        method: "POST",
        headers: { Accept: "application/json" },
      }),
    ).rejects.toMatchObject({
      errorName: "egress_destination_blocked",
      errorData: { host: "evil.com" },
    });
    expect(calls).toHaveLength(0);
  });

  test("pins api.x.com, injects User-Agent, preserves caller headers", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const impl = (async (url: unknown, init?: unknown) => {
      calls.push({ url: String(url), init: (init ?? {}) as RequestInit });
      return new Response("{}", { status: 200 });
    }) as unknown as typeof fetch;
    const res = await xFetch(impl, "https://api.x.com/2/oauth2/token", {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: "Basic abc",
      },
      body: "grant_type=refresh_token",
    });
    expect(res.status).toBe(200);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://api.x.com/2/oauth2/token");
    const h = calls[0]!.init.headers as Record<string, string>;
    expect(h["User-Agent"]).toBe("safespace-mcp");
    expect(h.Accept).toBe("application/json");
    expect(h.Authorization).toBe("Basic abc");
    expect(calls[0]!.init.method).toBe("POST");
    expect(calls[0]!.init.signal).toBeInstanceOf(AbortSignal);
  });

  test("caller User-Agent wins over the default (spread order)", async () => {
    const calls: Array<{ init: RequestInit }> = [];
    const impl = (async (_url: unknown, init?: unknown) => {
      calls.push({ init: (init ?? {}) as RequestInit });
      return new Response("{}", { status: 200 });
    }) as unknown as typeof fetch;
    await xFetch(impl, "https://api.x.com/2/users/me", {
      method: "GET",
      headers: { "User-Agent": "test-override", Accept: "application/json" },
    });
    const h = calls[0]!.init.headers as Record<string, string>;
    expect(h["User-Agent"]).toBe("test-override");
  });
});

describe("X_ERROR_CODE_RE", () => {
  test("accepts fixed lowercase-underscore enum codes", () => {
    expect(X_ERROR_CODE_RE.test("invalid_grant")).toBe(true);
    expect(X_ERROR_CODE_RE.test("invalid_request")).toBe(true);
    expect(X_ERROR_CODE_RE.test("a")).toBe(true);
  });
  test("rejects reflected free text / mixed case / separators", () => {
    expect(X_ERROR_CODE_RE.test("Invalid_Grant")).toBe(false);
    expect(X_ERROR_CODE_RE.test("evil secret")).toBe(false);
    expect(X_ERROR_CODE_RE.test("a/b")).toBe(false);
    expect(X_ERROR_CODE_RE.test("")).toBe(false);
  });
});
