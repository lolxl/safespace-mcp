// Perf hot-path cycle — in-memory TokenSet cache on refreshAccessToken.
//
// with-context.ts calls refreshAccessToken on EVERY tool call; the cache lets a
// still-valid token short-circuit the SecretBackend read (Keychain hit /
// FileBackend scrypt). These tests pin the cache contract: hit within validity,
// bypass on force, invalidate clears, near-expiry re-refreshes, refreshed tokens
// are re-cached. The global preload (test-utils.ts) resets the cache per test.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  _resetTokenCacheForTests,
  invalidateTokenCache,
  refreshAccessToken,
  type RefreshDeps,
  type TokenSet,
} from "./refresh";

const ENV_BACKUP = {
  id: process.env.GOOGLE_CLIENT_ID,
  secret: process.env.GOOGLE_CLIENT_SECRET,
};

beforeEach(() => {
  process.env.GOOGLE_CLIENT_ID = "fake-client-id";
  process.env.GOOGLE_CLIENT_SECRET = "fake-client-secret";
  _resetTokenCacheForTests();
});

afterEach(() => {
  process.env.GOOGLE_CLIENT_ID = ENV_BACKUP.id;
  process.env.GOOGLE_CLIENT_SECRET = ENV_BACKUP.secret;
});

function validTokenSet(overrides: Partial<TokenSet> = {}): TokenSet {
  return {
    refresh_token: "rt",
    access_token: "at",
    expires_at: Date.now() + 30 * 60_000, // 30 min — comfortably inside the buffer
    scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
    obtained_at: Date.now(),
    ...overrides,
  };
}

/** Deps whose getToken / setToken / fetch invocations are counted. */
function countingDeps(initial: Record<string, TokenSet>) {
  const store = new Map<string, string>();
  for (const [e, t] of Object.entries(initial)) store.set(e, JSON.stringify(t));
  const calls = { get: 0, set: 0, fetch: 0 };
  const deps: RefreshDeps = {
    async getToken(email) {
      calls.get++;
      return store.get(email) ?? null;
    },
    async setToken(email, json) {
      calls.set++;
      store.set(email, json);
    },
    async deleteToken(email) {
      store.delete(email);
    },
    async removeAccount() {},
    fetchImpl: (async () => {
      calls.fetch++;
      return new Response(
        JSON.stringify({ access_token: "new-at", expires_in: 3600 }),
        { status: 200 },
      );
    }) as unknown as typeof fetch,
  };
  return { deps, calls, store };
}

describe("refreshAccessToken — in-memory TokenSet cache (perf hot-path)", () => {
  test("second call within validity returns cached WITHOUT a backend read", async () => {
    const { deps, calls } = countingDeps({ "a@x.com": validTokenSet() });
    const first = await refreshAccessToken("a@x.com", deps);
    expect(calls.get).toBe(1);
    const second = await refreshAccessToken("a@x.com", deps);
    expect(calls.get).toBe(1); // memo hit — getToken NOT called again
    expect(calls.fetch).toBe(0);
    expect(second.access_token).toBe(first.access_token);
  });

  test("force:true bypasses the memo and issues a network refresh", async () => {
    const { deps, calls } = countingDeps({ "a@x.com": validTokenSet() });
    await refreshAccessToken("a@x.com", deps); // populates memo
    expect(calls.fetch).toBe(0);
    const out = await refreshAccessToken("a@x.com", { ...deps, force: true });
    expect(calls.fetch).toBe(1); // force always refreshes despite a valid memo
    expect(out.access_token).toBe("new-at");
  });

  test("invalidateTokenCache forces the next call back to the backend", async () => {
    const { deps, calls } = countingDeps({ "a@x.com": validTokenSet() });
    await refreshAccessToken("a@x.com", deps);
    expect(calls.get).toBe(1);
    invalidateTokenCache("a@x.com");
    await refreshAccessToken("a@x.com", deps);
    expect(calls.get).toBe(2); // memo cleared → backend read again
  });

  test("a near-expiry cached set is NOT served from memo (triggers refresh)", async () => {
    // 10s out → inside the 60s REFRESH_BUFFER_MS → must refresh, not serve.
    const { deps, calls } = countingDeps({
      "a@x.com": validTokenSet({ expires_at: Date.now() + 10_000 }),
    });
    const out = await refreshAccessToken("a@x.com", deps);
    expect(calls.fetch).toBe(1);
    expect(out.access_token).toBe("new-at");
    // the freshly-refreshed (valid) set is now memoized → no second network call
    const out2 = await refreshAccessToken("a@x.com", deps);
    expect(calls.fetch).toBe(1);
    expect(out2.access_token).toBe("new-at");
  });

  test("a forced refresh failing with invalid_grant clears the cache (no stale hit)", async () => {
    const store = new Map<string, string>([
      ["a@x.com", JSON.stringify(validTokenSet())],
    ]);
    let removed = false;
    const deps: RefreshDeps = {
      async getToken(e) {
        return store.get(e) ?? null;
      },
      async setToken(e, j) {
        store.set(e, j);
      },
      async deleteToken(e) {
        store.delete(e);
      },
      async removeAccount() {
        removed = true;
      },
      fetchImpl: (async () =>
        new Response(JSON.stringify({ error: "invalid_grant" }), {
          status: 400,
        })) as unknown as typeof fetch,
    };
    // Seed the memo with a valid token.
    await refreshAccessToken("a@x.com", deps);
    // Forced refresh fails with invalid_grant → cleanup must clear the memo too.
    await expect(
      refreshAccessToken("a@x.com", { ...deps, force: true }),
    ).rejects.toThrow();
    expect(removed).toBe(true);
    // The memo was cleared: a subsequent non-force call finds no backing token
    // and throws account_not_found. A surviving stale memo would have returned
    // the old (now-revoked) token instead.
    await expect(refreshAccessToken("a@x.com", deps)).rejects.toThrow();
  });

  test("distinct emails are cached independently", async () => {
    const { deps, calls } = countingDeps({
      "a@x.com": validTokenSet({ access_token: "at-a" }),
      "b@x.com": validTokenSet({ access_token: "at-b" }),
    });
    expect((await refreshAccessToken("a@x.com", deps)).access_token).toBe("at-a");
    expect((await refreshAccessToken("b@x.com", deps)).access_token).toBe("at-b");
    expect(calls.get).toBe(2);
    // second round: both served from memo
    expect((await refreshAccessToken("a@x.com", deps)).access_token).toBe("at-a");
    expect((await refreshAccessToken("b@x.com", deps)).access_token).toBe("at-b");
    expect(calls.get).toBe(2);
  });
});
