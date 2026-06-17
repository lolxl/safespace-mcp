import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { MCPError } from "../errors";
import { refreshAccessToken, type RefreshDeps, type TokenSet } from "./refresh";

const ENV_BACKUP = {
  id: process.env.GOOGLE_CLIENT_ID,
  secret: process.env.GOOGLE_CLIENT_SECRET,
};

beforeEach(() => {
  process.env.GOOGLE_CLIENT_ID = "fake-client-id";
  process.env.GOOGLE_CLIENT_SECRET = "fake-client-secret";
});

afterEach(() => {
  process.env.GOOGLE_CLIENT_ID = ENV_BACKUP.id;
  process.env.GOOGLE_CLIENT_SECRET = ENV_BACKUP.secret;
});

interface FakeKc {
  store: Map<string, string>;
  removed: Set<string>;
  setToken: NonNullable<RefreshDeps["setToken"]>;
  getToken: NonNullable<RefreshDeps["getToken"]>;
  deleteToken: NonNullable<RefreshDeps["deleteToken"]>;
  removeAccount: NonNullable<RefreshDeps["removeAccount"]>;
}

function makeKc(initial: Record<string, TokenSet> = {}): FakeKc {
  const store = new Map<string, string>();
  const removed = new Set<string>();
  for (const [email, ts] of Object.entries(initial)) {
    store.set(email, JSON.stringify(ts));
  }
  return {
    store,
    removed,
    async getToken(email: string) {
      return store.get(email) ?? null;
    },
    async setToken(email: string, json: string) {
      store.set(email, json);
    },
    async deleteToken(email: string) {
      store.delete(email);
    },
    async removeAccount(email: string) {
      removed.add(email);
    },
  };
}

function freshTokenSet(overrides: Partial<TokenSet> = {}): TokenSet {
  return {
    refresh_token: "old-refresh-token",
    access_token: "old-access-token",
    expires_at: Date.now() + 30 * 60_000,
    scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
    obtained_at: Date.now(),
    ...overrides,
  };
}

function expiredTokenSet(overrides: Partial<TokenSet> = {}): TokenSet {
  return freshTokenSet({ expires_at: Date.now() - 1_000, ...overrides });
}

describe("refreshAccessToken — skip-when-valid", () => {
  test("returns cached TokenSet without fetch when expires_at is fresh", async () => {
    const kc = makeKc({ "alice@example.com": freshTokenSet() });
    let fetchCalls = 0;
    const fetchImpl = (async () => {
      fetchCalls++;
      return new Response("{}");
    }) as unknown as typeof fetch;
    const result = await refreshAccessToken("alice@example.com", { ...kc, fetchImpl });
    expect(fetchCalls).toBe(0);
    expect(result.access_token).toBe("old-access-token");
  });

  test("triggers fetch when expires_at is within the 60s buffer", async () => {
    const kc = makeKc({
      "alice@example.com": freshTokenSet({ expires_at: Date.now() + 30_000 }),
    });
    let fetchCalls = 0;
    const fetchImpl = (async () => {
      fetchCalls++;
      return new Response(
        JSON.stringify({ access_token: "new-at", expires_in: 3600 }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as unknown as typeof fetch;
    const result = await refreshAccessToken("alice@example.com", { ...kc, fetchImpl });
    expect(fetchCalls).toBe(1);
    expect(result.access_token).toBe("new-at");
  });
});

describe("refreshAccessToken — mutex coalescing", () => {
  test("two parallel calls for the same email coalesce to one fetch", async () => {
    const kc = makeKc({ "alice@example.com": expiredTokenSet() });
    let fetchCalls = 0;
    const fetchImpl = (async () => {
      fetchCalls++;
      await new Promise((r) => setTimeout(r, 10));
      return new Response(
        JSON.stringify({ access_token: "new-at", expires_in: 3600 }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;
    const [a, b] = await Promise.all([
      refreshAccessToken("alice@example.com", { ...kc, fetchImpl }),
      refreshAccessToken("alice@example.com", { ...kc, fetchImpl }),
    ]);
    expect(fetchCalls).toBe(1);
    expect(a.access_token).toBe("new-at");
    expect(b.access_token).toBe("new-at");
  });

  test("different emails do not share the mutex", async () => {
    const kc = makeKc({
      "a@example.com": expiredTokenSet(),
      "b@example.com": expiredTokenSet(),
    });
    let fetchCalls = 0;
    const fetchImpl = (async () => {
      fetchCalls++;
      return new Response(
        JSON.stringify({ access_token: `new-at-${fetchCalls}`, expires_in: 3600 }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;
    await Promise.all([
      refreshAccessToken("a@example.com", { ...kc, fetchImpl }),
      refreshAccessToken("b@example.com", { ...kc, fetchImpl }),
    ]);
    expect(fetchCalls).toBe(2);
  });
});

describe("refreshAccessToken — refresh_token rotation write-back", () => {
  test("when Google returns a new refresh_token, it gets persisted to keychain", async () => {
    const kc = makeKc({ "alice@example.com": expiredTokenSet() });
    const fetchImpl = (async () =>
      new Response(
        JSON.stringify({
          access_token: "new-at",
          expires_in: 3600,
          refresh_token: "rotated-refresh-token",
        }),
        { status: 200 },
      )) as unknown as typeof fetch;
    const result = await refreshAccessToken("alice@example.com", { ...kc, fetchImpl });
    expect(result.refresh_token).toBe("rotated-refresh-token");
    const persisted = JSON.parse(kc.store.get("alice@example.com")!) as TokenSet;
    expect(persisted.refresh_token).toBe("rotated-refresh-token");
  });

  test("when Google does NOT return a new refresh_token, the old one is preserved", async () => {
    const kc = makeKc({ "alice@example.com": expiredTokenSet() });
    const fetchImpl = (async () =>
      new Response(
        JSON.stringify({ access_token: "new-at", expires_in: 3600 }),
        { status: 200 },
      )) as unknown as typeof fetch;
    const result = await refreshAccessToken("alice@example.com", { ...kc, fetchImpl });
    expect(result.refresh_token).toBe("old-refresh-token");
    const persisted = JSON.parse(kc.store.get("alice@example.com")!) as TokenSet;
    expect(persisted.refresh_token).toBe("old-refresh-token");
  });
});

describe("refreshAccessToken — invalid_grant cleanup", () => {
  test("on invalid_grant: deleteToken + removeAccount fire, throws refresh_token_invalid", async () => {
    const kc = makeKc({ "alice@example.com": expiredTokenSet() });
    const fetchImpl = (async () =>
      new Response(
        JSON.stringify({
          error: "invalid_grant",
          error_description: "Token has been expired or revoked.",
        }),
        { status: 400 },
      )) as unknown as typeof fetch;
    let caught: unknown;
    try {
      await refreshAccessToken("alice@example.com", { ...kc, fetchImpl });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(MCPError);
    const json = (caught as MCPError).toJsonRpc();
    expect(json.message).toBe("refresh_token_invalid");
    expect(json.data.email).toBe("alice@example.com");
    expect(kc.store.has("alice@example.com")).toBe(false);
    expect(kc.removed.has("alice@example.com")).toBe(true);
  });

  test("error_description from Google MUST NOT appear in MCPError.data (token-leak guard)", async () => {
    const kc = makeKc({ "alice@example.com": expiredTokenSet() });
    const leakedFragment = "ya29.LEAKED-TOKEN-FRAGMENT";
    const fetchImpl = (async () =>
      new Response(
        JSON.stringify({
          error: "invalid_grant",
          error_description: `Token expired. context: ${leakedFragment}`,
        }),
        { status: 401 },
      )) as unknown as typeof fetch;
    let caught: MCPError | null = null;
    try {
      await refreshAccessToken("alice@example.com", { ...kc, fetchImpl });
    } catch (e) {
      caught = e as MCPError;
    }
    expect(caught).not.toBeNull();
    const serialized = JSON.stringify(caught!.toJsonRpc());
    expect(serialized).not.toContain(leakedFragment);
    expect(serialized).not.toContain("ya29.");
  });
});

describe("refreshAccessToken — missing/corrupt cache", () => {
  test("throws account_not_found when no cached token exists", async () => {
    const kc = makeKc({});
    const fetchImpl = (async () => new Response("{}")) as unknown as typeof fetch;
    await expect(
      refreshAccessToken("alice@example.com", { ...kc, fetchImpl }),
    ).rejects.toMatchObject({ errorName: "account_not_found" });
  });

  test("throws account_not_found and deletes the corrupt entry on bad JSON", async () => {
    const kc = makeKc();
    kc.store.set("alice@example.com", "{not valid json");
    const fetchImpl = (async () => new Response("{}")) as unknown as typeof fetch;
    await expect(
      refreshAccessToken("alice@example.com", { ...kc, fetchImpl }),
    ).rejects.toMatchObject({ errorName: "account_not_found" });
    expect(kc.store.has("alice@example.com")).toBe(false);
  });
});

describe("refreshAccessToken — error mapping for non-invalid_grant", () => {
  test("503 from Google does NOT delete tokens (transient failure, retry later)", async () => {
    const kc = makeKc({ "alice@example.com": expiredTokenSet() });
    const fetchImpl = (async () =>
      new Response("upstream down", { status: 503 })) as unknown as typeof fetch;
    await expect(
      refreshAccessToken("alice@example.com", { ...kc, fetchImpl }),
    ).rejects.toThrow(/google_token_endpoint_503/);
    expect(kc.store.has("alice@example.com")).toBe(true);
    expect(kc.removed.has("alice@example.com")).toBe(false);
  });
});
