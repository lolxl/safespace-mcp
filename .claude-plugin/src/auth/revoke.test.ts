import { describe, expect, test } from "bun:test";
import { revokeRefreshToken } from "./revoke";

// Cast pattern matches refresh.test.ts: Bun's `typeof fetch` requires a
// `preconnect` property that mock functions don't supply, so we cast.
type FetchFn = typeof fetch;

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { "Content-Type": "application/json", ...(init.headers ?? {}) },
  });
}

describe("revokeRefreshToken", () => {
  test("200 OK → resolves void", async () => {
    let calledUrl = "";
    let calledBody = "";
    const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
      calledUrl = String(url);
      calledBody = String((init as RequestInit | undefined)?.body ?? "");
      return new Response("", { status: 200 });
    }) as unknown as FetchFn;
    await expect(revokeRefreshToken("rt-abc", { fetchImpl })).resolves.toBeUndefined();
    expect(calledUrl).toBe("https://oauth2.googleapis.com/revoke");
    expect(calledBody).toBe("token=rt-abc");
  });

  test("POSTs token form-encoded (RFC 7009 §2.1)", async () => {
    let method = "";
    let contentType = "";
    let body = "";
    const fetchImpl = (async (_url: string | URL | Request, init?: RequestInit) => {
      const i = init as RequestInit;
      method = i?.method ?? "";
      contentType = String((i?.headers as Record<string, string>)?.["Content-Type"] ?? "");
      body = String(i?.body ?? "");
      return new Response("", { status: 200 });
    }) as unknown as FetchFn;
    await revokeRefreshToken("rt-xyz", { fetchImpl });
    expect(method).toBe("POST");
    expect(contentType).toBe("application/x-www-form-urlencoded");
    expect(body).toBe("token=rt-xyz");
  });

  test("400 with error: invalid_token → resolves (idempotent)", async () => {
    const fetchImpl = (async () =>
      jsonResponse({ error: "invalid_token", error_description: "token rt-xxx was already revoked" }, { status: 400 })) as unknown as FetchFn;
    await expect(revokeRefreshToken("rt-xxx", { fetchImpl })).resolves.toBeUndefined();
  });

  test("400 with unrelated error code → throws google_revoke_endpoint_400", async () => {
    const fetchImpl = (async () =>
      jsonResponse({ error: "invalid_request" }, { status: 400 })) as unknown as FetchFn;
    await expect(revokeRefreshToken("rt", { fetchImpl })).rejects.toThrow(/google_revoke_endpoint_400/);
  });

  test("500 → throws google_revoke_endpoint_500", async () => {
    const fetchImpl = (async () =>
      new Response("internal error", { status: 500 })) as unknown as FetchFn;
    await expect(revokeRefreshToken("rt", { fetchImpl })).rejects.toThrow(/google_revoke_endpoint_500/);
  });

  test("non-JSON 4xx body → throws with status code only", async () => {
    const fetchImpl = (async () =>
      new Response("<html>nope</html>", { status: 403, headers: { "Content-Type": "text/html" } })) as unknown as FetchFn;
    await expect(revokeRefreshToken("rt", { fetchImpl })).rejects.toThrow(/google_revoke_endpoint_403/);
  });

  test("error_description containing token fragment does NOT leak to thrown message", async () => {
    const fetchImpl = (async () =>
      jsonResponse(
        { error: "server_error", error_description: "internal: rt-leaked-token-rt-xyz" },
        { status: 500 },
      )) as unknown as FetchFn;
    let caught: Error | undefined;
    try {
      await revokeRefreshToken("rt-secret-payload", { fetchImpl });
    } catch (e) {
      caught = e as Error;
    }
    expect(caught).toBeDefined();
    expect(caught!.message).toBe("google_revoke_endpoint_500");
    expect(caught!.message).not.toContain("rt-leaked");
    expect(caught!.message).not.toContain("rt-secret");
  });

  test("network error → propagates", async () => {
    const fetchImpl = (async () => {
      throw new Error("ECONNREFUSED");
    }) as unknown as FetchFn;
    await expect(revokeRefreshToken("rt", { fetchImpl })).rejects.toThrow(/ECONNREFUSED/);
  });

  test("AbortSignal is wired (10s timeout setup)", async () => {
    let signalSeen: AbortSignal | undefined;
    const fetchImpl = (async (_url: string | URL | Request, init?: RequestInit) => {
      signalSeen = (init as RequestInit | undefined)?.signal as AbortSignal | undefined;
      return new Response("", { status: 200 });
    }) as unknown as FetchFn;
    await revokeRefreshToken("rt", { fetchImpl });
    expect(signalSeen).toBeDefined();
    expect(signalSeen!.aborted).toBe(false);
  });
});
