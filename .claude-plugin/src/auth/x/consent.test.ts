// v1.113 — the X OAuth 2.0 PKCE consent flow (auth-critical).
//
// The browser-open is stubbed (openImpl) to drive the REAL loopback callback server via
// the global fetch; the api.x.com token exchange + users/me go through an injected
// fetchImpl (NO real network). The SecretBackend is the platform-independent file
// backend in a tmpdir. Mirrors auth/notion/consent.test.ts — but X has TWO network
// calls (token + identity) + PKCE + optional confidential Basic auth.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { xConsent, X_SCOPES } from "./consent";
import {
  __resetXBackendForTests,
  addXAccount,
  readXAccounts,
  readXActiveAccount,
  readXToken,
  writeXToken,
  tokenPayloadFromGrant,
} from "./oauth";

const TOKEN_URL = "https://api.x.com/2/oauth2/token";
const USER_URL_PREFIX = "https://api.x.com/2/users/me";
const USER_ID = "1111111111111111111";
const USER_OTHER = "9999999999999999999";
const ACCESS = "ACCESS_SECRET_TOKEN_must_never_leak";
const REFRESH = "REFRESH_SECRET_TOKEN_must_never_leak";
const CLIENT_SECRET = "fake-client-secret-must-never-leak";

let tmpDir: string;
const saved: Record<string, string | undefined> = {};
const ENV = [
  "SAFESPACE_CONFIG_DIR",
  "SAFESPACE_SECRET_BACKEND",
  "SAFESPACE_OPERATOR_ID",
  "SAFESPACE_SECRET_PASSPHRASE",
  "SAFESPACE_X_CLIENT_ID",
  "SAFESPACE_X_CLIENT_SECRET",
];

beforeEach(async () => {
  for (const k of ENV) saved[k] = process.env[k];
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-xc-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  process.env.SAFESPACE_SECRET_BACKEND = "file";
  delete process.env.SAFESPACE_OPERATOR_ID;
  delete process.env.SAFESPACE_SECRET_PASSPHRASE;
  process.env.SAFESPACE_X_CLIENT_ID = "x-fake-client-id";
  process.env.SAFESPACE_X_CLIENT_SECRET = CLIENT_SECRET;
  __resetXBackendForTests();
});

afterEach(async () => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
  __resetXBackendForTests();
  await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
});

/** An injected fetch that answers the token exchange + users/me; records the url + init. */
function makeFetch(opts: {
  token?: Record<string, unknown>;
  tokenStatus?: number;
  user?: Record<string, unknown>;
  userStatus?: number;
} = {}): {
  fetchImpl: typeof fetch;
  calls: Array<{ url: string; init: RequestInit }>;
} {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
    const u = typeof url === "string" ? url : url.toString();
    calls.push({ url: u, init: init ?? {} });
    if (u === TOKEN_URL) {
      return new Response(
        JSON.stringify(
          opts.token ?? {
            access_token: ACCESS,
            refresh_token: REFRESH,
            expires_in: 7200,
            scope: X_SCOPES,
            token_type: "bearer",
          },
        ),
        { status: opts.tokenStatus ?? 200, headers: { "content-type": "application/json" } },
      );
    }
    if (u.startsWith(USER_URL_PREFIX)) {
      return new Response(
        JSON.stringify(
          opts.user ?? { data: { id: USER_ID, username: "alice" } },
        ),
        { status: opts.userStatus ?? 200, headers: { "content-type": "application/json" } },
      );
    }
    throw new Error(`unexpected fetch in test: ${u}`);
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

/** openImpl that drives the real loopback callback: parse redirect_uri + state out of the
 *  authorize URL and fire the browser's redirect. */
function driveCallback(opts: { error?: string } = {}): (authUrl: string) => void {
  return (authUrl: string) => {
    queueMicrotask(async () => {
      const u = new URL(authUrl);
      const redirectUri = u.searchParams.get("redirect_uri");
      const state = u.searchParams.get("state");
      if (!redirectUri || !state) return;
      const q = opts.error ? `error=${opts.error}` : `code=test_auth_code&state=${state}`;
      await fetch(`${redirectUri}?${q}`).catch(() => undefined);
    });
  };
}

describe("xConsent — happy path", () => {
  test("exchanges the code, fetches users/me, persists account + token payload", async () => {
    const { fetchImpl, calls } = makeFetch();
    const result = await xConsent({ fetchImpl, openImpl: driveCallback() });
    expect(result).toEqual({ userId: USER_ID, username: "alice" });
    expect(await readXAccounts()).toEqual([{ id: USER_ID, username: "alice" }]);
    expect(await readXActiveAccount()).toBe(USER_ID);
    const tok = await readXToken(USER_ID);
    expect(tok).not.toBeNull();
    expect(tok!.access_token).toBe(ACCESS);
    expect(tok!.refresh_token).toBe(REFRESH);
    expect(tok!.expires_at).toBeGreaterThan(Date.now());
    // TWO network calls: token + identity.
    expect(calls.map((c) => c.url.split("?")[0])).toEqual([TOKEN_URL, USER_URL_PREFIX]);
  });

  test("token-exchange clamps a huge expires_in (10_000_000 → 86400s)", async () => {
    const before = Date.now();
    const { fetchImpl } = makeFetch({
      token: {
        access_token: ACCESS,
        refresh_token: REFRESH,
        expires_in: 10_000_000,
        scope: "tweet.read users.read tweet.write offline.access",
        token_type: "bearer",
      },
    });
    await xConsent({ fetchImpl, openImpl: driveCallback() });
    const tok = await readXToken(USER_ID);
    expect(tok).not.toBeNull();
    expect(tok!.expires_at).toBeGreaterThanOrEqual(before + 86_400 * 1000);
    expect(tok!.expires_at).toBeLessThanOrEqual(Date.now() + 86_400 * 1000 + 2_000);
  });

  test("token-exchange clamps near-zero expires_in (0 → 60s) and defaults absent → 7200s", async () => {
    const before = Date.now();
    const { fetchImpl: zeroImpl } = makeFetch({
      token: {
        access_token: ACCESS,
        refresh_token: REFRESH,
        expires_in: 0,
        token_type: "bearer",
      },
    });
    await xConsent({ fetchImpl: zeroImpl, openImpl: driveCallback() });
    const zeroTok = await readXToken(USER_ID);
    expect(zeroTok!.expires_at).toBeGreaterThanOrEqual(before + 60 * 1000);
    expect(zeroTok!.expires_at).toBeLessThanOrEqual(Date.now() + 60 * 1000 + 2_000);

    // Fresh account for the absent case (re-consent updates the same user).
    const beforeAbsent = Date.now();
    const { fetchImpl: absentImpl } = makeFetch({
      token: {
        access_token: ACCESS,
        refresh_token: REFRESH,
        // no expires_in
        token_type: "bearer",
      },
    });
    await xConsent({ fetchImpl: absentImpl, openImpl: driveCallback() });
    const absentTok = await readXToken(USER_ID);
    expect(absentTok!.expires_at).toBeGreaterThanOrEqual(beforeAbsent + 7200 * 1000);
    expect(absentTok!.expires_at).toBeLessThanOrEqual(Date.now() + 7200 * 1000 + 2_000);
  });

  test("consent ADDS a 2nd account without clobbering the 1st + makes it active", async () => {
    await addXAccount({ id: USER_OTHER, username: "prior" });
    await writeXToken(USER_OTHER, tokenPayloadFromGrant({
      access_token: "prior-access", refresh_token: "prior-refresh", expires_in: 7200,
    }));
    const { fetchImpl } = makeFetch(); // returns USER_ID / alice
    await xConsent({ fetchImpl, openImpl: driveCallback() });
    const ids = (await readXAccounts()).map((a) => a.id).sort();
    expect(ids).toEqual([USER_ID, USER_OTHER].sort());
    expect(await readXActiveAccount()).toBe(USER_ID);
    expect((await readXToken(USER_OTHER))!.access_token).toBe("prior-access");
  });

  test("confidential client: exchange uses HTTP Basic (secret in the header, NOT the body)", async () => {
    const { fetchImpl, calls } = makeFetch();
    await xConsent({ fetchImpl, openImpl: driveCallback() });
    const init = calls[0]!.init;
    const auth = (init.headers as Record<string, string>).Authorization;
    expect(auth).toBe(
      `Basic ${Buffer.from(`x-fake-client-id:${CLIENT_SECRET}`).toString("base64")}`,
    );
    const body = String(init.body);
    expect(body).toContain("authorization_code");
    expect(body).toContain("code_verifier=");
    expect(body).not.toContain(CLIENT_SECRET);
    expect(body).not.toContain("client_id="); // confidential → client_id is in Basic, not body
  });

  test("public client (no secret): client_id goes in the form body, no Basic header", async () => {
    delete process.env.SAFESPACE_X_CLIENT_SECRET;
    const { fetchImpl, calls } = makeFetch();
    await xConsent({ fetchImpl, openImpl: driveCallback() });
    const init = calls[0]!.init;
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBeUndefined();
    const body = String(init.body);
    expect(body).toContain("client_id=x-fake-client-id");
    expect(body).toContain("code_verifier=");
  });

  test("the authorize URL carries PKCE S256 + scopes + state + loopback redirect, NEVER the secret/verifier", async () => {
    let captured = "";
    const openImpl = (authUrl: string) => {
      captured = authUrl;
      queueMicrotask(async () => {
        const u = new URL(authUrl);
        await fetch(
          `${u.searchParams.get("redirect_uri")}?code=c&state=${u.searchParams.get("state")}`,
        ).catch(() => undefined);
      });
    };
    const { fetchImpl } = makeFetch();
    await xConsent({ fetchImpl, openImpl });
    const u = new URL(captured);
    expect(u.origin + u.pathname).toBe("https://x.com/i/oauth2/authorize");
    expect(u.searchParams.get("client_id")).toBe("x-fake-client-id");
    expect(u.searchParams.get("response_type")).toBe("code");
    expect(u.searchParams.get("scope")).toBe(X_SCOPES);
    expect(u.searchParams.get("code_challenge_method")).toBe("S256");
    expect(u.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(u.searchParams.get("redirect_uri")).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/callback$/);
    expect(u.searchParams.get("state")).toBeTruthy();
    expect(captured).not.toContain(CLIENT_SECRET);
    expect(captured).not.toContain("code_verifier");
  });
});

describe("xConsent — token never leaks", () => {
  test("the tokens are written ONLY to the SecretBackend, never the account file", async () => {
    const { fetchImpl } = makeFetch();
    await xConsent({ fetchImpl, openImpl: driveCallback() });
    const accountRaw = await fs.readFile(path.join(tmpDir, "x-account.json"), "utf8");
    expect(accountRaw).not.toContain(ACCESS);
    expect(accountRaw).not.toContain(REFRESH);
    expect((await readXToken(USER_ID))!.access_token).toBe(ACCESS);
  });

  test("console output never echoes the tokens", async () => {
    const lines: string[] = [];
    const orig = console.error;
    console.error = ((...a: unknown[]) => {
      lines.push(a.map(String).join(" "));
    }) as typeof console.error;
    try {
      const { fetchImpl } = makeFetch();
      await xConsent({ fetchImpl, openImpl: driveCallback() });
    } finally {
      console.error = orig;
    }
    const text = lines.join("\n");
    expect(text).not.toContain(ACCESS);
    expect(text).not.toContain(REFRESH);
    expect(text).toContain("@alice");
  });
});

describe("xConsent — failure paths (nothing persisted; prior consent survives)", () => {
  test("token-exchange error → surfaces ONLY the sanitized code, never error_description", async () => {
    const { fetchImpl } = makeFetch({
      token: { error: "invalid_grant", error_description: "REFLECTED_SECRET_VALUE" },
    });
    let msg = "";
    await xConsent({ fetchImpl, openImpl: driveCallback() }).catch((e) => {
      msg = (e as Error).message;
    });
    expect(msg).toContain("x token exchange failed: invalid_grant");
    expect(msg).not.toContain("REFLECTED_SECRET_VALUE");
    expect(await readXAccounts()).toEqual([]);
  });

  test("token-exchange non-2xx → throws, nothing persisted", async () => {
    const { fetchImpl } = makeFetch({ token: { error: "invalid_client" }, tokenStatus: 401 });
    await xConsent({ fetchImpl, openImpl: driveCallback() }).catch(() => undefined);
    expect(await readXAccounts()).toEqual([]);
    expect(await readXToken(USER_ID)).toBeNull();
  });

  test("identity check with no valid user id → throws, nothing persisted", async () => {
    const { fetchImpl } = makeFetch({ user: { data: { id: "not-numeric", username: "alice" } } });
    await expect(xConsent({ fetchImpl, openImpl: driveCallback() })).rejects.toThrow(/user id/);
    expect(await readXAccounts()).toEqual([]);
  });

  test("user denied (callback ?error=) → throws; never exchanges", async () => {
    const { fetchImpl, calls } = makeFetch();
    await expect(
      xConsent({ fetchImpl, openImpl: driveCallback({ error: "access_denied" }) }),
    ).rejects.toBeInstanceOf(Error);
    expect(calls).toEqual([]);
    expect(await readXAccounts()).toEqual([]);
  });

  test("D2: a mid-flow failure does NOT destroy a PRIOR (different) x account", async () => {
    await addXAccount({ id: USER_OTHER, username: "prior" });
    await writeXToken(USER_OTHER, tokenPayloadFromGrant({
      access_token: "PRIOR_ACCESS", refresh_token: "PRIOR_REFRESH", expires_in: 7200,
    }));
    const { fetchImpl } = makeFetch({ token: { error: "invalid_grant" } });
    await xConsent({ fetchImpl, openImpl: driveCallback() }).catch(() => undefined);
    expect((await readXAccounts()).map((a) => a.id)).toEqual([USER_OTHER]);
    expect((await readXToken(USER_OTHER))!.access_token).toBe("PRIOR_ACCESS");
    expect(await readXToken(USER_ID)).toBeNull();
  });
});

describe("xConsent — pre-flight rejects (no network)", () => {
  test("missing SAFESPACE_X_CLIENT_ID → throws before any network", async () => {
    delete process.env.SAFESPACE_X_CLIENT_ID;
    const { fetchImpl, calls } = makeFetch();
    await expect(xConsent({ fetchImpl, openImpl: driveCallback() })).rejects.toThrow(
      /SAFESPACE_X_CLIENT_ID/,
    );
    expect(calls).toEqual([]);
  });
});
