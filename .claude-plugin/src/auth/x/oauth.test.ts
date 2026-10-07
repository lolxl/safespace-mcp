// v1.113 — the X multi-account store + rotation-safe proactive refresh + the x
// Source's resolveAccount resolution. File backend + temp dir.
// Network is NEVER hit: refresh uses an injected fetchImpl.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { MCPError } from "../../errors";
import { x } from "../../tools/source";
import {
  __clearXRefreshInFlightForTests,
  __resetXBackendForTests,
  __setXFetchImplForTests,
  REFRESH_SKEW_MS,
  X_USER_ID_RE,
  addXAccount,
  clampExpiresIn,
  clearXToken,
  findXAccount,
  getValidAccessToken,
  readXAccounts,
  readXActiveAccount,
  readXStore,
  readXToken,
  removeXAccount,
  setXActiveAccount,
  tokenPayloadFromGrant,
  writeXToken,
} from "./oauth";

const USER_A = "1111111111111111111";
const USER_B = "2222222222222222222";
const TOKEN_URL = "https://api.x.com/2/oauth2/token";

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
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-x-store-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  process.env.SAFESPACE_SECRET_BACKEND = "file";
  delete process.env.SAFESPACE_OPERATOR_ID;
  delete process.env.SAFESPACE_SECRET_PASSPHRASE;
  process.env.SAFESPACE_X_CLIENT_ID = "x-fake-client-id";
  process.env.SAFESPACE_X_CLIENT_SECRET = "x-fake-secret";
  __resetXBackendForTests();
  __setXFetchImplForTests(null);
  __clearXRefreshInFlightForTests();
});

afterEach(async () => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
  __resetXBackendForTests();
  __setXFetchImplForTests(null);
  __clearXRefreshInFlightForTests();
  await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
});

function makeRefreshFetch(opts: {
  body?: Record<string, unknown>;
  status?: number;
  count?: { n: number };
} = {}): typeof fetch {
  return (async (url: string | URL | Request) => {
    const u = typeof url === "string" ? url : url.toString();
    if (opts.count) opts.count.n++;
    if (u !== TOKEN_URL) throw new Error(`unexpected fetch in test: ${u}`);
    return new Response(
      JSON.stringify(
        opts.body ?? {
          access_token: "new-access",
          refresh_token: "new-refresh",
          expires_in: 7200,
          scope: "tweet.read users.read tweet.write offline.access",
          token_type: "bearer",
        },
      ),
      { status: opts.status ?? 200, headers: { "content-type": "application/json" } },
    );
  }) as unknown as typeof fetch;
}

describe("x multi-account store", () => {
  test("addXAccount adds + activates; a 2nd add keeps the 1st (multi)", async () => {
    expect(await readXAccounts()).toEqual([]);
    expect((await addXAccount({ id: USER_A, username: "alice" })).wasNew).toBe(true);
    expect((await addXAccount({ id: USER_B, username: "bob" })).wasNew).toBe(true);
    const accounts = await readXAccounts();
    expect(accounts.map((a) => a.id).sort()).toEqual([USER_A, USER_B].sort());
    expect(await readXActiveAccount()).toBe(USER_B);
  });

  test("re-adding an existing account upserts the username (wasNew false) + reactivates", async () => {
    await addXAccount({ id: USER_A, username: "alice" });
    await addXAccount({ id: USER_B, username: "bob" });
    const r = await addXAccount({ id: USER_A, username: "alice_renamed" });
    expect(r.wasNew).toBe(false);
    const accounts = await readXAccounts();
    expect(accounts).toHaveLength(2);
    expect(accounts.find((a) => a.id === USER_A)?.username).toBe("alice_renamed");
    expect(await readXActiveAccount()).toBe(USER_A);
  });

  test("removeXAccount removes one + clears active if it pointed there", async () => {
    await addXAccount({ id: USER_A, username: "alice" });
    await addXAccount({ id: USER_B, username: "bob" });
    await removeXAccount(USER_B);
    expect((await readXAccounts()).map((a) => a.id)).toEqual([USER_A]);
    expect(await readXActiveAccount()).toBeNull();
    await removeXAccount(USER_A);
    expect(await readXAccounts()).toEqual([]);
  });

  test("setXActiveAccount switches; rejects an unknown account", async () => {
    await addXAccount({ id: USER_A, username: "alice" });
    await addXAccount({ id: USER_B, username: "bob" });
    await setXActiveAccount(USER_A);
    expect(await readXActiveAccount()).toBe(USER_A);
    await expect(setXActiveAccount("9999999999999999999")).rejects.toThrow(/not a stored/);
  });

  test("a corrupt file → empty store; active naming a missing account → null", async () => {
    await fs.mkdir(tmpDir, { recursive: true });
    await fs.writeFile(path.join(tmpDir, "x-account.json"), "{ not json");
    expect(await readXStore()).toEqual({ accounts: [], active: null });
    await fs.writeFile(
      path.join(tmpDir, "x-account.json"),
      JSON.stringify({ accounts: [{ id: USER_A, username: "alice" }], active: USER_B }),
    );
    expect(await readXActiveAccount()).toBeNull();
  });

  test("token isolation: each account's token is independent", async () => {
    await writeXToken(USER_A, tokenPayloadFromGrant({
      access_token: "tok-A", refresh_token: "ref-A", expires_in: 7200,
    }));
    await writeXToken(USER_B, tokenPayloadFromGrant({
      access_token: "tok-B", refresh_token: "ref-B", expires_in: 7200,
    }));
    expect((await readXToken(USER_A))!.access_token).toBe("tok-A");
    expect((await readXToken(USER_B))!.access_token).toBe("tok-B");
    await clearXToken(USER_A);
    expect(await readXToken(USER_A)).toBeNull();
    expect((await readXToken(USER_B))!.access_token).toBe("tok-B");
  });

  test("token helpers reject a non-numeric user id (key-injection guard)", async () => {
    await expect(readXToken("a:b")).rejects.toThrow(/user id/);
    await expect(
      writeXToken("a:b", tokenPayloadFromGrant({ access_token: "x", refresh_token: "y" })),
    ).rejects.toThrow(/user id/);
    await expect(clearXToken("../etc")).rejects.toThrow(/user id/);
  });

  test("token payload is NEVER written to the account file", async () => {
    await addXAccount({ id: USER_A, username: "alice" });
    await writeXToken(USER_A, tokenPayloadFromGrant({
      access_token: "SECRET_ACCESS", refresh_token: "SECRET_REFRESH", expires_in: 7200,
    }));
    const raw = await fs.readFile(path.join(tmpDir, "x-account.json"), "utf8");
    expect(raw).not.toContain("SECRET_ACCESS");
    expect(raw).not.toContain("SECRET_REFRESH");
  });
});

describe("findXAccount (pure)", () => {
  const accounts = [
    { id: USER_A, username: "alice" },
    { id: USER_B, username: "bob" },
  ];
  test("matches an exact id", () => {
    expect(findXAccount(USER_A, accounts)).toEqual(accounts[0]!);
  });
  test("matches a unique username (case-insensitive)", () => {
    expect(findXAccount("ALICE", accounts)).toEqual(accounts[0]!);
  });
  test("returns 'ambiguous' for a duplicated username", () => {
    const dup = [...accounts, { id: "3333333333333333333", username: "alice" }];
    expect(findXAccount("alice", dup)).toBe("ambiguous");
  });
  test("returns null for an unknown id/username", () => {
    expect(findXAccount("ghost", accounts)).toBeNull();
  });
  test("X_USER_ID_RE accepts a numeric snowflake, rejects junk", () => {
    expect(X_USER_ID_RE.test(USER_A)).toBe(true);
    expect(X_USER_ID_RE.test("not-a-number")).toBe(false);
    expect(X_USER_ID_RE.test("a:b")).toBe(false);
  });
});

describe("getValidAccessToken — proactive refresh + rotation + single-flight", () => {
  test("a fresh token is returned without a network call", async () => {
    await writeXToken(USER_A, tokenPayloadFromGrant({
      access_token: "fresh-access",
      refresh_token: "fresh-refresh",
      expires_in: 7200,
    }));
    const count = { n: 0 };
    __setXFetchImplForTests(makeRefreshFetch({ count }));
    const tok = await getValidAccessToken(USER_A);
    expect(tok).toBe("fresh-access");
    expect(count.n).toBe(0);
  });

  test("an near-expiry token is proactively refreshed (rotation-safe WITH new refresh)", async () => {
    await writeXToken(USER_A, {
      access_token: "old-access",
      refresh_token: "old-refresh",
      expires_at: Date.now() + REFRESH_SKEW_MS - 1_000, // within the skew window
      scope: "tweet.read",
    });
    __setXFetchImplForTests(makeRefreshFetch({
      body: {
        access_token: "rotated-access",
        refresh_token: "rotated-refresh",
        expires_in: 7200,
        token_type: "bearer",
      },
    }));
    const tok = await getValidAccessToken(USER_A);
    expect(tok).toBe("rotated-access");
    const stored = await readXToken(USER_A);
    expect(stored!.access_token).toBe("rotated-access");
    expect(stored!.refresh_token).toBe("rotated-refresh"); // rotated
  });

  test("rotation-safe: if the response omits refresh_token, the old one is kept", async () => {
    await writeXToken(USER_A, {
      access_token: "old-access",
      refresh_token: "KEEP_ME",
      expires_at: Date.now() + 1_000, // within skew
      scope: "tweet.read",
    });
    __setXFetchImplForTests(makeRefreshFetch({
      body: {
        access_token: "new-access-only",
        // no refresh_token
        expires_in: 7200,
        token_type: "bearer",
      },
    }));
    const tok = await getValidAccessToken(USER_A);
    expect(tok).toBe("new-access-only");
    const stored = await readXToken(USER_A);
    expect(stored!.refresh_token).toBe("KEEP_ME");
  });

  test("single-flight: two concurrent resolve calls → exactly ONE token-endpoint request", async () => {
    await writeXToken(USER_A, {
      access_token: "old-access",
      refresh_token: "old-refresh",
      expires_at: Date.now() + 1_000,
      scope: "tweet.read",
    });
    const count = { n: 0 };
    // Slow the fetch so both callers overlap while the first is in-flight.
    const slowFetch = (async (url: string | URL | Request, init?: RequestInit) => {
      count.n++;
      await new Promise((r) => setTimeout(r, 50));
      return makeRefreshFetch({
        body: {
          access_token: "once-access",
          refresh_token: "once-refresh",
          expires_in: 7200,
          token_type: "bearer",
        },
      })(url, init);
    }) as unknown as typeof fetch;
    __setXFetchImplForTests(slowFetch);
    const [a, b] = await Promise.all([
      getValidAccessToken(USER_A),
      getValidAccessToken(USER_A),
    ]);
    expect(a).toBe("once-access");
    expect(b).toBe("once-access");
    expect(count.n).toBe(1);
  });

  test("invalid_grant → x_api_failed{consent_required}; stored token is NOT deleted", async () => {
    await writeXToken(USER_A, {
      access_token: "old-access",
      refresh_token: "spent-refresh",
      expires_at: Date.now() + 1_000,
      scope: "tweet.read",
    });
    __setXFetchImplForTests(makeRefreshFetch({
      body: { error: "invalid_grant", error_description: "REFLECTED_SECRET" },
      status: 400,
    }));
    let err: unknown;
    try {
      await getValidAccessToken(USER_A);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(MCPError);
    expect((err as MCPError).errorName).toBe("x_api_failed");
    expect((err as MCPError).errorData.reason).toBe("consent_required");
    // Stored token survives (recovery = re-consent, not silent wipe).
    const stored = await readXToken(USER_A);
    expect(stored).not.toBeNull();
    expect(stored!.refresh_token).toBe("spent-refresh");
    // No secret leak in the error.
    expect(JSON.stringify((err as MCPError).errorData)).not.toContain("REFLECTED_SECRET");
    expect(JSON.stringify((err as MCPError).errorData)).not.toContain("spent-refresh");
  });

  test("no stored token → x_api_failed{no_account}", async () => {
    await expect(getValidAccessToken(USER_A)).rejects.toMatchObject({
      errorName: "x_api_failed",
      errorData: { reason: "no_account" },
    });
  });

  test("refresh clamps a huge expires_in so proactive refresh can still fire", async () => {
    const before = Date.now();
    await writeXToken(USER_A, {
      access_token: "old-access",
      refresh_token: "old-refresh",
      expires_at: Date.now() + 1_000,
      scope: "tweet.read",
    });
    __setXFetchImplForTests(makeRefreshFetch({
      body: {
        access_token: "clamped-access",
        refresh_token: "clamped-refresh",
        expires_in: 10_000_000, // far past 86400s max
        token_type: "bearer",
      },
    }));
    const tok = await getValidAccessToken(USER_A);
    expect(tok).toBe("clamped-access");
    const stored = await readXToken(USER_A);
    // 86400s max → expires_at within ~1 day, not years out.
    expect(stored!.expires_at).toBeGreaterThanOrEqual(before + 86_400 * 1000);
    expect(stored!.expires_at).toBeLessThanOrEqual(Date.now() + 86_400 * 1000 + 2_000);
  });

  test("refresh clamps a near-zero expires_in up to 60s", async () => {
    const before = Date.now();
    await writeXToken(USER_A, {
      access_token: "old-access",
      refresh_token: "old-refresh",
      expires_at: Date.now() + 1_000,
      scope: "tweet.read",
    });
    __setXFetchImplForTests(makeRefreshFetch({
      body: {
        access_token: "short-access",
        refresh_token: "short-refresh",
        expires_in: 0,
        token_type: "bearer",
      },
    }));
    await getValidAccessToken(USER_A);
    const stored = await readXToken(USER_A);
    expect(stored!.expires_at).toBeGreaterThanOrEqual(before + 60 * 1000);
    expect(stored!.expires_at).toBeLessThanOrEqual(Date.now() + 60 * 1000 + 2_000);
  });
});

describe("clampExpiresIn / tokenPayloadFromGrant — expires_in clamp", () => {
  test("0 → 60; 10_000_000 → 86400; NaN/absent → 7200", () => {
    expect(clampExpiresIn(0)).toBe(60);
    expect(clampExpiresIn(10_000_000)).toBe(86_400);
    expect(clampExpiresIn(NaN)).toBe(7200);
    expect(clampExpiresIn(undefined)).toBe(7200);
    expect(clampExpiresIn(7200)).toBe(7200);
    expect(clampExpiresIn(60)).toBe(60);
    expect(clampExpiresIn(86_400)).toBe(86_400);
  });

  test("tokenPayloadFromGrant applies the same clamp to expires_at math", () => {
    const before = Date.now();
    const low = tokenPayloadFromGrant({
      access_token: "a",
      refresh_token: "r",
      expires_in: 0,
    });
    expect(low.expires_at).toBeGreaterThanOrEqual(before + 60 * 1000);
    expect(low.expires_at).toBeLessThanOrEqual(Date.now() + 60 * 1000 + 50);

    const high = tokenPayloadFromGrant({
      access_token: "a",
      refresh_token: "r",
      expires_in: 10_000_000,
    });
    expect(high.expires_at).toBeGreaterThanOrEqual(before + 86_400 * 1000);
    expect(high.expires_at).toBeLessThanOrEqual(Date.now() + 86_400 * 1000 + 50);

    const absent = tokenPayloadFromGrant({
      access_token: "a",
      refresh_token: "r",
    });
    expect(absent.expires_at).toBeGreaterThanOrEqual(before + 7200 * 1000);
    expect(absent.expires_at).toBeLessThanOrEqual(Date.now() + 7200 * 1000 + 50);

    const nan = tokenPayloadFromGrant({
      access_token: "a",
      refresh_token: "r",
      expires_in: Number.NaN,
    });
    expect(nan.expires_at).toBeGreaterThanOrEqual(before + 7200 * 1000);
    expect(nan.expires_at).toBeLessThanOrEqual(Date.now() + 7200 * 1000 + 50);
  });
});

describe("x.resolveAccount — resolution (over the real store)", () => {
  async function seed(): Promise<void> {
    await addXAccount({ id: USER_A, username: "alice" });
    await addXAccount({ id: USER_B, username: "bob" }); // active = B
  }
  const resolve = (deps: Record<string, unknown>) =>
    (x as { resolveAccount: (t: undefined, d: unknown) => Promise<{ accountId: string }> }).resolveAccount(
      undefined,
      deps,
    );

  test("explicit account_id by user id resolves it", async () => {
    await seed();
    expect((await resolve({ explicitAccountId: USER_A })).accountId).toBe(USER_A);
  });

  test("explicit account_id by USERNAME resolves to the user id", async () => {
    await seed();
    expect((await resolve({ explicitAccountId: "alice" })).accountId).toBe(USER_A);
  });

  test("no explicit → the active account", async () => {
    await seed();
    expect((await resolve({})).accountId).toBe(USER_B);
  });

  test("no explicit, no active → the per-source last-used", async () => {
    await addXAccount({ id: USER_A, username: "alice" });
    await addXAccount({ id: USER_B, username: "bob" });
    await removeXAccount(USER_B); // clears active; USER_A remains, active = null
    expect(await readXActiveAccount()).toBeNull();
    expect((await resolve({ lastUsed: USER_A })).accountId).toBe(USER_A);
  });

  test("nothing resolvable → account_not_found{no_active_account}", async () => {
    await expect(resolve({})).rejects.toMatchObject({
      errorName: "account_not_found",
      errorData: { reason: "no_active_account" },
    });
  });

  test("an unknown explicit name → account_not_found echoing the INPUT (no oracle)", async () => {
    await seed();
    await expect(resolve({ explicitAccountId: "ghost" })).rejects.toMatchObject({
      errorName: "account_not_found",
      errorData: { email: "ghost" },
    });
  });
});

describe("x.resolveCredential — proactive refresh wiring", () => {
  test("returns an oauth credential whose getter never serializes the token", async () => {
    await writeXToken(USER_A, tokenPayloadFromGrant({
      access_token: "LIVE_SECRET_TOKEN",
      refresh_token: "LIVE_REFRESH",
      expires_in: 7200,
    }));
    const cred = await x.resolveCredential(undefined, { accountId: USER_A });
    expect(cred.kind).toBe("oauth");
    if (cred.kind !== "oauth") return;
    expect(cred.provider).toBe("x");
    expect(cred.accountId).toBe(USER_A);
    expect(cred.getAccessToken()).toBe("LIVE_SECRET_TOKEN");
    expect(JSON.stringify(cred)).not.toContain("LIVE_SECRET_TOKEN");
    expect(JSON.stringify(cred)).not.toContain("LIVE_REFRESH");
  });
});
