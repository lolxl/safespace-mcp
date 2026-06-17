// v1.70 (G3) — the GitHub OAuth App consent flow (auth-critical: a new OAuth flow).
//
// The browser-open is stubbed (openImpl) to drive the REAL loopback callback server
// (a real Bun.serve) via the global fetch, exactly as the Google consent.test.ts D2
// path drives it through the Bun.spawn stub. The github.com / api.github.com calls go
// through an injected fetchImpl so NO real network call is made. The SecretBackend is
// the platform-independent file backend in a tmpdir (mirrors store.test.ts).

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { githubConsent } from "./consent";
import {
  __resetGithubBackendForTests,
  readGithubAccount,
  readGithubToken,
  writeGithubAccount,
  writeGithubToken,
} from "./store";

const TOKEN_URL = "https://github.com/login/oauth/access_token";
const USER_URL = "https://api.github.com/user";
const GHO = "gho_THE_SECRET_TOKEN_VALUE_must_never_leak";

let tmpDir: string;
const saved: Record<string, string | undefined> = {};
const ENV = [
  "SAFESPACE_CONFIG_DIR",
  "SAFESPACE_SECRET_BACKEND",
  "SAFESPACE_OPERATOR_ID",
  "SAFESPACE_SECRET_PASSPHRASE",
  "GITHUB_CLIENT_ID",
  "GITHUB_CLIENT_SECRET",
];

beforeEach(async () => {
  for (const k of ENV) saved[k] = process.env[k];
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-ghc-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  process.env.SAFESPACE_SECRET_BACKEND = "file"; // platform-independent
  delete process.env.SAFESPACE_OPERATOR_ID;
  delete process.env.SAFESPACE_SECRET_PASSPHRASE;
  process.env.GITHUB_CLIENT_ID = "Iv1.fakeclientid";
  process.env.GITHUB_CLIENT_SECRET = "fake-client-secret-must-never-leak";
  __resetGithubBackendForTests();
});

afterEach(async () => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
  __resetGithubBackendForTests();
  await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
});

/** An injected fetch that answers the token-exchange + /user calls; records the
 *  URLs it saw so a test can assert which endpoints were reached. */
function makeFetch(opts: {
  token?: Record<string, unknown>;
  tokenStatus?: number;
  user?: Record<string, unknown>;
  userStatus?: number;
} = {}): { fetchImpl: typeof fetch; calls: string[] } {
  const calls: string[] = [];
  const fetchImpl = (async (url: string | URL | Request) => {
    const u = typeof url === "string" ? url : url.toString();
    calls.push(u);
    if (u === TOKEN_URL) {
      return new Response(
        JSON.stringify(opts.token ?? { access_token: GHO, scope: "read:user,repo", token_type: "bearer" }),
        { status: opts.tokenStatus ?? 200, headers: { "content-type": "application/json" } },
      );
    }
    if (u === USER_URL) {
      return new Response(JSON.stringify(opts.user ?? { login: "octocat", id: 1 }), {
        status: opts.userStatus ?? 200,
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`unexpected fetch in test: ${u}`);
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

/** An openImpl that drives the real loopback callback server: parse redirect_uri +
 *  state out of the authorize URL and fire the browser's redirect. */
function driveCallback(opts: { code?: string; error?: string } = {}): (authUrl: string) => void {
  return (authUrl: string) => {
    queueMicrotask(async () => {
      const u = new URL(authUrl);
      const redirectUri = u.searchParams.get("redirect_uri");
      const state = u.searchParams.get("state");
      if (!redirectUri || !state) return;
      const q = opts.error
        ? `error=${opts.error}`
        : `code=${opts.code ?? "test_auth_code"}&state=${state}`;
      await fetch(`${redirectUri}?${q}`).catch(() => undefined);
    });
  };
}

describe("githubConsent — happy path", () => {
  test("exchanges the code, verifies identity, persists account + token", async () => {
    const { fetchImpl, calls } = makeFetch();
    const result = await githubConsent("octocat", { fetchImpl, openImpl: driveCallback() });
    expect(result).toEqual({ login: "octocat", scopes: ["read:user", "repo"] });
    expect(await readGithubAccount()).toEqual({ login: "octocat", scopes: ["read:user", "repo"] });
    expect(await readGithubToken("octocat")).toBe(GHO);
    expect(calls).toEqual([TOKEN_URL, USER_URL]); // exchange THEN identity
  });

  test("login is matched case-insensitively; the CANONICAL API login is persisted", async () => {
    const { fetchImpl } = makeFetch({ user: { login: "OctoCat" } });
    const result = await githubConsent("octocat", { fetchImpl, openImpl: driveCallback() });
    expect(result.login).toBe("OctoCat");
    expect((await readGithubAccount())?.login).toBe("OctoCat");
    expect(await readGithubToken("OctoCat")).toBe(GHO);
  });

  test("the authorize URL carries client_id + scope + state + loopback redirect, NEVER the client_secret", async () => {
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
    await githubConsent("octocat", { fetchImpl, openImpl });
    const u = new URL(captured);
    expect(u.origin + u.pathname).toBe("https://github.com/login/oauth/authorize");
    expect(u.searchParams.get("client_id")).toBe("Iv1.fakeclientid");
    expect(u.searchParams.get("scope")).toBe("read:user repo");
    expect(u.searchParams.get("redirect_uri")).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/callback$/);
    expect(u.searchParams.get("state")).toBeTruthy();
    expect(captured).not.toContain("fake-client-secret-must-never-leak");
  });
});

describe("githubConsent — token never leaks", () => {
  test("the token is written ONLY to the SecretBackend, never the account file", async () => {
    const { fetchImpl } = makeFetch();
    await githubConsent("octocat", { fetchImpl, openImpl: driveCallback() });
    const accountRaw = await fs.readFile(path.join(tmpDir, "github-account.json"), "utf8");
    expect(accountRaw).not.toContain(GHO);
    expect(await readGithubToken("octocat")).toBe(GHO); // sanity: it DID land in the backend
  });

  test("console output never echoes the token", async () => {
    const lines: string[] = [];
    const orig = console.error;
    console.error = ((...a: unknown[]) => { lines.push(a.map(String).join(" ")); }) as typeof console.error;
    try {
      const { fetchImpl } = makeFetch();
      await githubConsent("octocat", { fetchImpl, openImpl: driveCallback() });
    } finally {
      console.error = orig;
    }
    expect(lines.join("\n")).not.toContain(GHO);
  });
});

describe("githubConsent — failure paths (nothing persisted; prior consent survives)", () => {
  test("login_mismatch (consented as a different user) → throws, nothing persisted", async () => {
    const { fetchImpl } = makeFetch({ user: { login: "someone-else" } });
    await expect(githubConsent("octocat", { fetchImpl, openImpl: driveCallback() })).rejects.toThrow(
      /login_mismatch/,
    );
    expect(await readGithubAccount()).toBeNull();
    expect(await readGithubToken("octocat")).toBeNull();
    expect(await readGithubToken("someone-else")).toBeNull();
  });

  test("scope shortfall → throws naming the missing scope; /user never reached", async () => {
    const { fetchImpl, calls } = makeFetch({ token: { access_token: GHO, scope: "read:user" } });
    await expect(githubConsent("octocat", { fetchImpl, openImpl: driveCallback() })).rejects.toThrow(
      /did not grant required scopes: repo/,
    );
    expect(calls).toEqual([TOKEN_URL]); // bailed before identity
    expect(await readGithubAccount()).toBeNull();
    expect(await readGithubToken("octocat")).toBeNull();
  });

  test("token-exchange error → surfaces ONLY the GitHub error code, never error_description", async () => {
    const { fetchImpl, calls } = makeFetch({
      token: { error: "bad_verification_code", error_description: "REFLECTED_SECRET_VALUE" },
    });
    let msg = "";
    await githubConsent("octocat", { fetchImpl, openImpl: driveCallback() }).catch((e) => {
      msg = (e as Error).message;
    });
    expect(msg).toContain("github token exchange failed: bad_verification_code");
    expect(msg).not.toContain("REFLECTED_SECRET_VALUE");
    expect(calls).toEqual([TOKEN_URL]);
    expect(await readGithubAccount()).toBeNull();
  });

  test("token-exchange non-2xx → throws HTTP status, no body reflected", async () => {
    const { fetchImpl } = makeFetch({ token: { whatever: "x" }, tokenStatus: 401 });
    await expect(githubConsent("octocat", { fetchImpl, openImpl: driveCallback() })).rejects.toThrow(
      /github token exchange failed \(HTTP 401\)/,
    );
  });

  test("identity check non-2xx → throws, nothing persisted", async () => {
    const { fetchImpl } = makeFetch({ userStatus: 403, user: {} });
    await expect(githubConsent("octocat", { fetchImpl, openImpl: driveCallback() })).rejects.toThrow(
      /github identity check failed \(HTTP 403\)/,
    );
    expect(await readGithubAccount()).toBeNull();
  });

  test("user denied (callback ?error=) → throws oauth_denied; never exchanges", async () => {
    const { fetchImpl, calls } = makeFetch();
    await expect(
      githubConsent("octocat", { fetchImpl, openImpl: driveCallback({ error: "access_denied" }) }),
    ).rejects.toThrow(/oauth_denied/);
    expect(calls).toEqual([]);
    expect(await readGithubAccount()).toBeNull();
  });

  test("D2: a mid-flow failure does NOT destroy a PRIOR github consent", async () => {
    await writeGithubToken("octocat", "PRIOR_TOKEN");
    await writeGithubAccount({ login: "octocat", scopes: ["read:user", "repo"] });
    // a fresh consent attempt that fails at the identity step (after exchange,
    // before the token write) — persistedLogin stays null → no cleanup.
    const { fetchImpl } = makeFetch({ userStatus: 500, user: {} });
    await expect(githubConsent("octocat", { fetchImpl, openImpl: driveCallback() })).rejects.toThrow(
      /identity check failed/,
    );
    expect(await readGithubAccount()).toEqual({ login: "octocat", scopes: ["read:user", "repo"] });
    expect(await readGithubToken("octocat")).toBe("PRIOR_TOKEN");
  });
});

describe("githubConsent — pre-flight rejects (no network)", () => {
  test("missing GITHUB_CLIENT_ID / SECRET → throws before any network", async () => {
    delete process.env.GITHUB_CLIENT_ID;
    const { fetchImpl, calls } = makeFetch();
    await expect(githubConsent("octocat", { fetchImpl, openImpl: driveCallback() })).rejects.toThrow(
      /GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET/,
    );
    expect(calls).toEqual([]);
  });

  test("invalid expected login → throws before any network", async () => {
    const { fetchImpl, calls } = makeFetch();
    await expect(githubConsent("bad login!", { fetchImpl, openImpl: driveCallback() })).rejects.toThrow(
      /invalid github login/,
    );
    expect(calls).toEqual([]);
  });
});
