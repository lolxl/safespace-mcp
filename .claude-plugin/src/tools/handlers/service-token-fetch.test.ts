// v1.69.1 — the shared service-token egress fetch: timeout, body cleanup, closed-set
// error mapping, and the no-leak guarantee. The network is mocked at the fetch seam.

import { describe, expect, test } from "bun:test";
import {
  postServiceTokenJson,
  type ServiceTokenReason,
} from "./service-token-fetch";

const mapStatus = (s: number): ServiceTokenReason => {
  if (s === 401 || s === 403) return "auth_failed";
  if (s === 429) return "rate_limited";
  if (s === 400 || s === 404) return "invalid_recipient";
  return "api_error";
};

/** A recording stub returning a duck-typed Response (the helper reads only ok/status/
 *  body.cancel). */
function recordingFetch(resInit: { ok: boolean; status: number }) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  let cancelled = false;
  const impl = (async (url: unknown, init?: unknown) => {
    calls.push({ url: String(url), init: (init ?? {}) as RequestInit });
    return {
      ok: resInit.ok,
      status: resInit.status,
      body: { cancel: () => { cancelled = true; return Promise.resolve(); } },
    } as unknown as Response;
  }) as unknown as typeof fetch;
  return { impl, calls, wasCancelled: () => cancelled };
}

describe("postServiceTokenJson — happy path + construction", () => {
  test("POSTs JSON with the headers + an abort signal; resolves on 2xx", async () => {
    const f = recordingFetch({ ok: true, status: 200 });
    await postServiceTokenJson({
      url: "https://api.example.com/send",
      headers: { "Content-Type": "application/json", Authorization: "Bearer x" },
      body: { hello: "world" },
      mapStatus,
      errorName: "line_api_failed",
      fetchImpl: f.impl,
    });
    expect(f.calls).toHaveLength(1);
    const { url, init } = f.calls[0]!;
    expect(url).toBe("https://api.example.com/send");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer x");
    expect(JSON.parse(init.body as string)).toEqual({ hello: "world" });
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  test("discards (cancels) the response body on success", async () => {
    const f = recordingFetch({ ok: true, status: 200 });
    await postServiceTokenJson({
      url: "u", headers: {}, body: {}, mapStatus, errorName: "line_api_failed", fetchImpl: f.impl,
    });
    expect(f.wasCancelled()).toBe(true);
  });
});

describe("postServiceTokenJson — error mapping", () => {
  for (const [status, reason] of [
    [401, "auth_failed"],
    [429, "rate_limited"],
    [404, "invalid_recipient"],
    [500, "api_error"],
  ] as const) {
    test(`non-ok ${status} → ${reason} + body cancelled`, async () => {
      const f = recordingFetch({ ok: false, status });
      await expect(
        postServiceTokenJson({ url: "u", headers: {}, body: {}, mapStatus, errorName: "telegram_api_failed", fetchImpl: f.impl }),
      ).rejects.toMatchObject({ errorName: "telegram_api_failed", errorData: { reason } });
      expect(f.wasCancelled()).toBe(true); // socket released even on the error path
    });
  }

  test("network throw → api_error (raw error swallowed)", async () => {
    const impl = (async () => { throw new Error("ECONNREFUSED 10.0.0.1"); }) as unknown as typeof fetch;
    await expect(
      postServiceTokenJson({ url: "u", headers: {}, body: {}, mapStatus, errorName: "discord_api_failed", fetchImpl: impl }),
    ).rejects.toMatchObject({ errorName: "discord_api_failed", errorData: { reason: "api_error" } });
  });
});

describe("postServiceTokenJson — timeout (the v1.69.1 hardening)", () => {
  test("a hung connection aborts after timeoutMs → api_error (never stalls)", async () => {
    // A fetch that never resolves until its abort signal fires.
    const hangingFetch = ((_url: unknown, init?: { signal?: AbortSignal }) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
      })) as unknown as typeof fetch;
    const start = Date.now();
    await expect(
      postServiceTokenJson({
        url: "u", headers: {}, body: {}, mapStatus, errorName: "line_api_failed",
        fetchImpl: hangingFetch, timeoutMs: 20,
      }),
    ).rejects.toMatchObject({ errorName: "line_api_failed", errorData: { reason: "api_error" } });
    // It returned promptly (bounded by the timeout), not hung.
    expect(Date.now() - start).toBeLessThan(2000);
  });
});

describe("postServiceTokenJson — never echoes url / headers / body / raw error", () => {
  type ErrLike = { errorName?: string; errorData?: unknown; message?: unknown };
  const blob = (e: ErrLike) => JSON.stringify({ n: e.errorName, d: e.errorData, m: String(e.message) });
  const SECRET = "super-secret-token-12345";

  test("non-ok error carries no token from url/headers/body", async () => {
    const f = recordingFetch({ ok: false, status: 401 });
    const err = (await postServiceTokenJson({
      url: `https://api.example.com/bot${SECRET}/send`,
      headers: { Authorization: `Bot ${SECRET}` },
      body: { secret: SECRET },
      mapStatus, errorName: "discord_api_failed", fetchImpl: f.impl,
    }).catch((e) => e)) as ErrLike;
    expect(blob(err)).not.toContain(SECRET);
  });

  test("network throw carries no token even if the raw error embeds it", async () => {
    const impl = (async () => { throw new Error(`connect failed to bot${SECRET}/send`); }) as unknown as typeof fetch;
    const err = (await postServiceTokenJson({
      url: `https://api.example.com/bot${SECRET}/send`, headers: {}, body: {},
      mapStatus, errorName: "telegram_api_failed", fetchImpl: impl,
    }).catch((e) => e)) as ErrLike;
    expect(blob(err)).not.toContain(SECRET);
  });
});

// v1.95 (C1) — the optional checkBody seam (Slack: HTTP 200 can still be a logical
// failure). When provided, the helper READS + parses the body under the timeout and
// consults checkBody; when ABSENT, the body is discarded unread (byte-identical).
describe("postServiceTokenJson — checkBody seam (v1.95)", () => {
  /** A stub returning a REAL Response (so res.text() works for the body-read path). */
  function bodyFetch(status: number, body: string) {
    const calls: Array<{ url: string }> = [];
    const impl = (async (url: unknown) => {
      calls.push({ url: String(url) });
      return new Response(body, { status });
    }) as unknown as typeof fetch;
    return { impl, calls };
  }

  test("reads + parses the body and resolves when checkBody returns null", async () => {
    const f = bodyFetch(200, `{"ok":true,"ts":"1.2"}`);
    let seen: unknown;
    await postServiceTokenJson({
      url: "u", headers: {}, body: {}, mapStatus, errorName: "slack_api_failed",
      fetchImpl: f.impl,
      checkBody: (parsed) => { seen = parsed; return null; },
    });
    expect(seen).toEqual({ ok: true, ts: "1.2" }); // checkBody got the parsed RESPONSE body
  });

  test("throws errorName{reason} when checkBody returns a reason (200-but-failed)", async () => {
    const f = bodyFetch(200, `{"ok":false,"error":"channel_not_found"}`);
    await expect(
      postServiceTokenJson({
        url: "u", headers: {}, body: {}, mapStatus, errorName: "slack_api_failed",
        fetchImpl: f.impl,
        checkBody: () => "invalid_recipient",
      }),
    ).rejects.toMatchObject({ errorName: "slack_api_failed", errorData: { reason: "invalid_recipient" } });
  });

  test("a genuine non-ok HTTP status maps off the status, ahead of checkBody", async () => {
    let checkBodyCalled = false;
    const f = bodyFetch(429, `{"ok":false,"error":"ratelimited"}`);
    await expect(
      postServiceTokenJson({
        url: "u", headers: {}, body: {}, mapStatus, errorName: "slack_api_failed",
        fetchImpl: f.impl,
        checkBody: () => { checkBodyCalled = true; return null; },
      }),
    ).rejects.toMatchObject({ errorName: "slack_api_failed", errorData: { reason: "rate_limited" } });
    expect(checkBodyCalled).toBe(false); // HTTP-status failure short-circuits the body check
  });

  test("a non-JSON 200 body → api_error (fail closed, never a false success)", async () => {
    const f = bodyFetch(200, "<html>maintenance</html>");
    await expect(
      postServiceTokenJson({
        url: "u", headers: {}, body: {}, mapStatus, errorName: "slack_api_failed",
        fetchImpl: f.impl,
        checkBody: () => null, // never reached — the parse fails first
      }),
    ).rejects.toMatchObject({ errorName: "slack_api_failed", errorData: { reason: "api_error" } });
  });

  test("the body READ is bounded by the timeout (a hung body stream → api_error)", async () => {
    // The fetch resolves immediately, but res.text() never resolves until the abort fires
    // — exercising that clearTimeout happens AFTER the read (C1 hardening), not before.
    const hungBodyFetch = ((_url: unknown, init?: { signal?: AbortSignal }) => {
      const signal = init?.signal;
      return Promise.resolve({
        ok: true,
        status: 200,
        text: () =>
          new Promise<string>((_res, rej) => {
            signal?.addEventListener("abort", () => rej(new Error("aborted")));
          }),
      } as unknown as Response);
    }) as unknown as typeof fetch;
    const start = Date.now();
    await expect(
      postServiceTokenJson({
        url: "u", headers: {}, body: {}, mapStatus, errorName: "slack_api_failed",
        fetchImpl: hungBodyFetch, timeoutMs: 20,
        checkBody: () => null,
      }),
    ).rejects.toMatchObject({ errorName: "slack_api_failed", errorData: { reason: "api_error" } });
    expect(Date.now() - start).toBeLessThan(2000); // returned promptly, not hung
  });

  test("WITHOUT checkBody the body is discarded unread (byte-identical legacy path)", async () => {
    // The legacy stub has no .text() — proving the no-checkBody path never reads the body.
    const f = recordingFetch({ ok: true, status: 200 });
    await postServiceTokenJson({
      url: "u", headers: {}, body: {}, mapStatus, errorName: "discord_api_failed", fetchImpl: f.impl,
    });
    expect(f.wasCancelled()).toBe(true); // cancelled, not read
  });
});
