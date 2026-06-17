// v1.78 (Notion B) — the Notion public-integration OAuth consent flow (auth-critical).
//
// The browser-open is stubbed (openImpl) to drive the REAL loopback callback server via
// the global fetch; the api.notion.com token exchange goes through an injected fetchImpl
// (NO real network). The SecretBackend is the platform-independent file backend in a
// tmpdir. Mirrors auth/github/consent.test.ts — but Notion has ONE network call (the
// workspace identity comes back IN the token response) + a Basic-auth exchange.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { notionConsent } from "./consent";
import {
  __resetNotionBackendForTests,
  addNotionAccount,
  readNotionAccounts,
  readNotionActiveWorkspace,
  readNotionToken,
  writeNotionToken,
} from "./oauth";

const TOKEN_URL = "https://api.notion.com/v1/oauth/token";
const WS_ID = "11111111-1111-1111-1111-111111111111";
const WS_OTHER = "99999999-9999-9999-9999-999999999999";
const NTN = "ntn_THE_SECRET_TOKEN_VALUE_must_never_leak";
const CLIENT_SECRET = "fake-client-secret-must-never-leak";

let tmpDir: string;
const saved: Record<string, string | undefined> = {};
const ENV = [
  "SAFESPACE_CONFIG_DIR",
  "SAFESPACE_SECRET_BACKEND",
  "SAFESPACE_OPERATOR_ID",
  "SAFESPACE_SECRET_PASSPHRASE",
  "NOTION_CLIENT_ID",
  "NOTION_CLIENT_SECRET",
];

beforeEach(async () => {
  for (const k of ENV) saved[k] = process.env[k];
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-ntnc-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  process.env.SAFESPACE_SECRET_BACKEND = "file";
  delete process.env.SAFESPACE_OPERATOR_ID;
  delete process.env.SAFESPACE_SECRET_PASSPHRASE;
  process.env.NOTION_CLIENT_ID = "notion-fake-client-id";
  process.env.NOTION_CLIENT_SECRET = CLIENT_SECRET;
  __resetNotionBackendForTests();
});

afterEach(async () => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
  __resetNotionBackendForTests();
  await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
});

/** An injected fetch that answers the token exchange; records the url + init it saw. */
function makeFetch(opts: { token?: Record<string, unknown>; tokenStatus?: number } = {}): {
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
            access_token: NTN,
            token_type: "bearer",
            workspace_id: WS_ID,
            workspace_name: "My Team",
            bot_id: "bot-1",
          },
        ),
        { status: opts.tokenStatus ?? 200, headers: { "content-type": "application/json" } },
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

describe("notionConsent — happy path", () => {
  test("exchanges the code, persists workspace account + token (ONE network call)", async () => {
    const { fetchImpl, calls } = makeFetch();
    const result = await notionConsent({ fetchImpl, openImpl: driveCallback() });
    expect(result).toEqual({ workspaceId: WS_ID, workspaceName: "My Team" });
    expect(await readNotionAccounts()).toEqual([{ workspaceId: WS_ID, workspaceName: "My Team" }]);
    expect(await readNotionActiveWorkspace()).toBe(WS_ID); // newly-consented is active
    expect(await readNotionToken(WS_ID)).toBe(NTN);
    expect(calls.map((c) => c.url)).toEqual([TOKEN_URL]); // no separate identity call
  });

  test("consent ADDS a 2nd workspace without clobbering the 1st + makes it active", async () => {
    // a prior consented workspace (active)
    await addNotionAccount({ workspaceId: WS_OTHER, workspaceName: "Prior" });
    await writeNotionToken(WS_OTHER, "prior-tok");
    const { fetchImpl } = makeFetch(); // returns WS_ID / "My Team"
    await notionConsent({ fetchImpl, openImpl: driveCallback() });
    const ids = (await readNotionAccounts()).map((a) => a.workspaceId).sort();
    expect(ids).toEqual([WS_ID, WS_OTHER].sort()); // BOTH present
    expect(await readNotionActiveWorkspace()).toBe(WS_ID); // the newly-consented is active
    expect(await readNotionToken(WS_OTHER)).toBe("prior-tok"); // the prior token is untouched
  });

  test("the exchange uses HTTP Basic auth (secret in the header, NOT the body)", async () => {
    const { fetchImpl, calls } = makeFetch();
    await notionConsent({ fetchImpl, openImpl: driveCallback() });
    const init = calls[0]!.init;
    const auth = (init.headers as Record<string, string>).Authorization;
    expect(auth).toBe(`Basic ${Buffer.from(`notion-fake-client-id:${CLIENT_SECRET}`).toString("base64")}`);
    const body = String(init.body);
    expect(body).toContain("authorization_code");
    expect(body).not.toContain(CLIENT_SECRET); // the secret is in the header, never the body
  });

  test("the authorize URL carries client_id + response_type + owner + state + loopback redirect, NEVER the secret", async () => {
    let captured = "";
    const openImpl = (authUrl: string) => {
      captured = authUrl;
      queueMicrotask(async () => {
        const u = new URL(authUrl);
        await fetch(`${u.searchParams.get("redirect_uri")}?code=c&state=${u.searchParams.get("state")}`).catch(() => undefined);
      });
    };
    const { fetchImpl } = makeFetch();
    await notionConsent({ fetchImpl, openImpl });
    const u = new URL(captured);
    expect(u.origin + u.pathname).toBe("https://api.notion.com/v1/oauth/authorize");
    expect(u.searchParams.get("client_id")).toBe("notion-fake-client-id");
    expect(u.searchParams.get("response_type")).toBe("code");
    expect(u.searchParams.get("owner")).toBe("user");
    expect(u.searchParams.get("redirect_uri")).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/callback$/);
    expect(u.searchParams.get("state")).toBeTruthy();
    expect(captured).not.toContain(CLIENT_SECRET);
  });
});

describe("notionConsent — token never leaks", () => {
  test("the token is written ONLY to the SecretBackend, never the account file", async () => {
    const { fetchImpl } = makeFetch();
    await notionConsent({ fetchImpl, openImpl: driveCallback() });
    const accountRaw = await fs.readFile(path.join(tmpDir, "notion-account.json"), "utf8");
    expect(accountRaw).not.toContain(NTN);
    expect(await readNotionToken(WS_ID)).toBe(NTN);
  });

  test("console output never echoes the token", async () => {
    const lines: string[] = [];
    const orig = console.error;
    console.error = ((...a: unknown[]) => { lines.push(a.map(String).join(" ")); }) as typeof console.error;
    try {
      const { fetchImpl } = makeFetch();
      await notionConsent({ fetchImpl, openImpl: driveCallback() });
    } finally {
      console.error = orig;
    }
    expect(lines.join("\n")).not.toContain(NTN);
  });
});

describe("notionConsent — failure paths (nothing persisted; prior consent survives)", () => {
  test("token-exchange error → surfaces ONLY the sanitized code, never error_description", async () => {
    const { fetchImpl } = makeFetch({
      token: { error: "invalid_grant", error_description: "REFLECTED_SECRET_VALUE" },
    });
    let msg = "";
    await notionConsent({ fetchImpl, openImpl: driveCallback() }).catch((e) => {
      msg = (e as Error).message;
    });
    expect(msg).toContain("notion token exchange failed: invalid_grant");
    expect(msg).not.toContain("REFLECTED_SECRET_VALUE");
    expect(await readNotionAccounts()).toEqual([]);
  });

  test("token-exchange non-2xx → throws, nothing persisted", async () => {
    const { fetchImpl } = makeFetch({ token: { error: "invalid_client" }, tokenStatus: 401 });
    await notionConsent({ fetchImpl, openImpl: driveCallback() }).catch(() => undefined);
    expect(await readNotionAccounts()).toEqual([]);
    expect(await readNotionToken(WS_ID)).toBeNull();
  });

  test("a response with no valid workspace_id → throws, nothing persisted", async () => {
    const { fetchImpl } = makeFetch({ token: { access_token: NTN, workspace_id: "not-a-uuid" } });
    await expect(notionConsent({ fetchImpl, openImpl: driveCallback() })).rejects.toThrow(/workspace_id/);
    expect(await readNotionAccounts()).toEqual([]);
  });

  test("user denied (callback ?error=) → throws; never exchanges", async () => {
    const { fetchImpl, calls } = makeFetch();
    await expect(
      notionConsent({ fetchImpl, openImpl: driveCallback({ error: "access_denied" }) }),
    ).rejects.toBeInstanceOf(Error);
    expect(calls).toEqual([]);
    expect(await readNotionAccounts()).toEqual([]);
  });

  test("D2: a mid-flow failure does NOT destroy a PRIOR (different) notion workspace", async () => {
    await addNotionAccount({ workspaceId: WS_OTHER, workspaceName: "Prior" });
    await writeNotionToken(WS_OTHER, "PRIOR_TOKEN");
    // a fresh attempt (for WS_ID) that fails at the exchange (before any token write) —
    // cleanupWorkspaceId stays null → the prior WS_OTHER consent is untouched, and the
    // failed WS_ID is never added.
    const { fetchImpl } = makeFetch({ token: { error: "invalid_grant" } });
    await notionConsent({ fetchImpl, openImpl: driveCallback() }).catch(() => undefined);
    expect((await readNotionAccounts()).map((a) => a.workspaceId)).toEqual([WS_OTHER]);
    expect(await readNotionToken(WS_OTHER)).toBe("PRIOR_TOKEN");
    expect(await readNotionToken(WS_ID)).toBeNull();
  });
});

describe("notionConsent — pre-flight rejects (no network)", () => {
  test("missing NOTION_CLIENT_ID / SECRET → throws before any network", async () => {
    delete process.env.NOTION_CLIENT_ID;
    const { fetchImpl, calls } = makeFetch();
    await expect(notionConsent({ fetchImpl, openImpl: driveCallback() })).rejects.toThrow(
      /NOTION_CLIENT_ID and NOTION_CLIENT_SECRET/,
    );
    expect(calls).toEqual([]);
  });
});
