// v1.14 Phase 1 — `withAllAccounts` helper tests.
// Covers design §12 helper-test table (10 scenarios) + sec-rev §11 hooks
// where the helper itself is the binding gate.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { MCPError } from "../errors";
import type { TokenSet } from "../auth/refresh";
import {
  withAllAccounts,
  type WithAllAccountsDeps,
} from "./with-all-accounts";
import { requireOAuth } from "./handlers/shared";

const ENV_BACKUP = {
  id: process.env.GOOGLE_CLIENT_ID,
  secret: process.env.GOOGLE_CLIENT_SECRET,
};

beforeEach(() => {
  process.env.GOOGLE_CLIENT_ID = "fake";
  process.env.GOOGLE_CLIENT_SECRET = "fake";
});

afterEach(() => {
  process.env.GOOGLE_CLIENT_ID = ENV_BACKUP.id;
  process.env.GOOGLE_CLIENT_SECRET = ENV_BACKUP.secret;
});

function freshTokenSet(overrides: Partial<TokenSet> = {}): TokenSet {
  return {
    refresh_token: "rt",
    access_token: "old-access-token",
    expires_at: Date.now() + 30 * 60_000,
    scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
    obtained_at: Date.now(),
    ...overrides,
  };
}

interface FakeFixture {
  store: Map<string, string>;
  removed: Set<string>;
  index: { accounts: Array<{ email: string; scopes?: string[] }> };
  innerAuditCalls: Array<Record<string, unknown>>;
  outerAuditCalls: Array<Record<string, unknown>>;
  deps: WithAllAccountsDeps;
}

function makeFixture(opts: {
  emails?: string[];
  tokens?: Record<string, TokenSet>;
  scopesPerAccount?: Record<string, string[]>;
} = {}): FakeFixture {
  const emails = opts.emails ?? ["alice@example.com"];
  const tokens =
    opts.tokens ?? Object.fromEntries(emails.map((e) => [e, freshTokenSet()]));
  const store = new Map<string, string>();
  const removed = new Set<string>();
  for (const [e, ts] of Object.entries(tokens)) store.set(e, JSON.stringify(ts));
  const index = {
    accounts: emails.map((e) => ({
      email: e,
      scopes:
        opts.scopesPerAccount?.[e] ??
        ["https://www.googleapis.com/auth/gmail.readonly"],
    })),
  };
  const innerAuditCalls: Array<Record<string, unknown>> = [];
  const outerAuditCalls: Array<Record<string, unknown>> = [];

  const deps: WithAllAccountsDeps = {
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
    fetchImpl: (async () => new Response("{}", { status: 200 })) as unknown as typeof fetch,
    loadIndexImpl: async () => index,
    auditEndImpl: async (ctx) => {
      innerAuditCalls.push({ ...ctx });
    },
    auditAggregateImpl: async (ctx) => {
      outerAuditCalls.push({ ...ctx });
    },
  };

  return { store, removed, index, innerAuditCalls, outerAuditCalls, deps };
}

const SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"];

describe("withAllAccounts — fan-out + aggregation", () => {
  test("#1: single account success → 1 success, 0 failures", async () => {
    const fx = makeFixture({ emails: ["alice@example.com"] });
    const out = await withAllAccounts<{ messages: string[] }>(
      "gmail_search_all",
      { query: "x" },
      async (ctx) => ({ messages: [`m-${requireOAuth(ctx).accountId}`] }),
      {},
      fx.deps,
    );
    expect(out.successes).toHaveLength(1);
    expect(out.failures).toHaveLength(0);
    expect(out.successes[0]?.account_email).toBe("alice@example.com");
  });

  test("#2: 3 accounts all succeed → 3 sub-results, FRESH sanitize nonce per sub-result (sec-rev hook 1)", async () => {
    const fx = makeFixture({
      emails: ["a@x.com", "b@x.com", "c@x.com"],
    });
    const out = await withAllAccounts<{ snippet: string }>(
      "gmail_search_all",
      { query: "x" },
      async (ctx) => ({ snippet: `body-from-${requireOAuth(ctx).accountId}` }),
      {},
      fx.deps,
    );
    expect(out.successes).toHaveLength(3);
    // Each sub-result wrapped by real `sanitize()` (no override in deps) →
    // each wrapper carries an independent 16-hex nonce. Extract from the
    // wrapped snippet and assert distinctness.
    const nonceRe = /<untrusted-source-([0-9a-f]{16})/;
    const nonces = out.successes.map((s) => {
      const wrapped = (s as unknown as { snippet: string }).snippet;
      const m = nonceRe.exec(wrapped);
      expect(m).not.toBeNull();
      return m![1];
    });
    expect(new Set(nonces).size).toBe(3);
  });

  test("#3: 1 fails (UpstreamError httpStatus=401), 2 succeed", async () => {
    const fx = makeFixture({
      emails: ["a@x.com", "b@x.com", "c@x.com"],
    });
    const out = await withAllAccounts<{ messages: string[] }>(
      "gmail_search_all",
      { query: "x" },
      async (ctx) => {
        const cred = requireOAuth(ctx);
        if (cred.accountId === "b@x.com") {
          const err = new Error("google_api_unauthorized_gmail_search_all") as Error & {
            httpStatus?: number;
          };
          err.httpStatus = 401;
          throw err;
        }
        return { messages: [`m-${cred.accountId}`] };
      },
      {},
      fx.deps,
    );
    expect(out.successes).toHaveLength(2);
    expect(out.failures).toHaveLength(1);
    expect(out.failures[0]?.account_email).toBe("b@x.com");
    expect(out.failures[0]?.error.code).toBe("upstream_error");
    expect(out.failures[0]?.error.message).toContain("google_api_401_gmail_search_all");
  });

  test("#4: all fail → 0 successes, N failures, aggregate still resolves", async () => {
    const fx = makeFixture({ emails: ["a@x.com", "b@x.com"] });
    const out = await withAllAccounts<{ messages: string[] }>(
      "gmail_search_all",
      { query: "x" },
      async () => {
        throw new MCPError("rate_limited");
      },
      {},
      fx.deps,
    );
    expect(out.successes).toHaveLength(0);
    expect(out.failures).toHaveLength(2);
    expect(out.failures.every((f) => f.error.code === "rate_limited")).toBe(true);
  });

  test("#5: empty accounts.json → empty aggregate (NOT an error)", async () => {
    const fx = makeFixture({ emails: [] });
    const out = await withAllAccounts<{ messages: string[] }>(
      "gmail_search_all",
      { query: "x" },
      async () => ({ messages: [] }),
      {},
      fx.deps,
    );
    expect(out.successes).toHaveLength(0);
    expect(out.failures).toHaveLength(0);
    // Still emits the outer aggregate row with zero counts (forensic clarity).
    expect(fx.outerAuditCalls).toHaveLength(1);
    expect(fx.outerAuditCalls[0]).toMatchObject({
      tool: "gmail_search_all",
      accountCountQueried: 0,
      accountCountSucceeded: 0,
      accountCountFailed: 0,
    });
  });

  test("#6: `accounts` filter subset → only filtered accounts queried", async () => {
    const fx = makeFixture({
      emails: ["a@x.com", "b@x.com", "c@x.com"],
    });
    const visited: string[] = [];
    const out = await withAllAccounts<{ ok: true }>(
      "gmail_search_all",
      { query: "x", accounts: ["b@x.com"] },
      async (ctx) => {
        visited.push(requireOAuth(ctx).accountId);
        return { ok: true };
      },
      { accounts: ["b@x.com"] },
      fx.deps,
    );
    expect(visited).toEqual(["b@x.com"]);
    expect(out.successes).toHaveLength(1);
    expect(out.successes[0]?.account_email).toBe("b@x.com");
  });

  test("#7: `accounts` filter with non-existent → `account_not_found` failure (sec-rev hook 7)", async () => {
    // Two REAL accounts in fixture. The failure message MUST NOT mention
    // either of them — only echo the caller's input email (anti-enumeration).
    const fx = makeFixture({ emails: ["real-account-a@x.com", "real-account-b@x.com"] });
    const out = await withAllAccounts<{ ok: true }>(
      "gmail_search_all",
      { query: "x", accounts: ["ghost@x.com"] },
      async () => ({ ok: true }),
      { accounts: ["ghost@x.com"] },
      fx.deps,
    );
    expect(out.successes).toHaveLength(0);
    expect(out.failures).toHaveLength(1);
    expect(out.failures[0]).toEqual({
      account_email: "ghost@x.com",
      error: { code: "account_not_found", message: "account_not_found" },
    });
    // Anti-enumeration: failure message must not leak any real account email.
    expect(out.failures[0]?.error.message).not.toContain("real-account-a@x.com");
    expect(out.failures[0]?.error.message).not.toContain("real-account-b@x.com");
  });

  test("#8: malformed `accounts` entry (CRLF/path) → reject BEFORE fan-out (sec-rev hook 5)", async () => {
    const fx = makeFixture({ emails: ["a@x.com"] });
    let fanOutTouched = false;
    // CRLF injection attempt
    await expect(
      withAllAccounts<{ ok: true }>(
        "gmail_search_all",
        { query: "x", accounts: ["a@x.com\r\nDELETE"] },
        async () => {
          fanOutTouched = true;
          return { ok: true };
        },
        { accounts: ["a@x.com\r\nDELETE"] },
        fx.deps,
      ),
    ).rejects.toThrow(/'accounts' entries must each match/);
    // Path-shape
    await expect(
      withAllAccounts<{ ok: true }>(
        "gmail_search_all",
        { query: "x", accounts: ["../etc/passwd"] },
        async () => {
          fanOutTouched = true;
          return { ok: true };
        },
        { accounts: ["../etc/passwd"] },
        fx.deps,
      ),
    ).rejects.toThrow(/'accounts' entries must each match/);
    expect(fanOutTouched).toBe(false);
    // Each pre-fan-out rejection emits exactly one terminal error row (no account,
    // no per-account rows) and no aggregate row.
    expect(fx.innerAuditCalls).toHaveLength(2);
    for (const row of fx.innerAuditCalls) {
      expect(row.status).toBe("error");
      expect(row.email).toBeNull();
    }
    expect(fx.outerAuditCalls).toHaveLength(0);
  });

  test("#9: concurrent invocations on same account — refreshInFlight mutex (sec-rev hook 6)", async () => {
    // Force-expired token so refresh path runs. Use a counting fetchImpl
    // to verify refresh.ts's refreshInFlight Map coalesces concurrent
    // calls on the same email.
    const expired = freshTokenSet({ expires_at: Date.now() - 1 });
    const fx = makeFixture({
      emails: ["a@x.com"],
      tokens: { "a@x.com": expired },
    });
    let fetchCount = 0;
    fx.deps.fetchImpl = (async () => {
      fetchCount += 1;
      // Slight delay so both refreshes overlap in time.
      await new Promise((r) => setTimeout(r, 20));
      return new Response(
        JSON.stringify({
          access_token: "fresh",
          expires_in: 3600,
          refresh_token: "rt",
          scope: SCOPES.join(" "),
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as unknown as typeof fetch;

    const [out1, out2] = await Promise.all([
      withAllAccounts<{ ok: true }>(
        "gmail_search_all",
        { query: "1" },
        async () => ({ ok: true }),
        {},
        fx.deps,
      ),
      withAllAccounts<{ ok: true }>(
        "gmail_search_all",
        { query: "2" },
        async () => ({ ok: true }),
        {},
        fx.deps,
      ),
    ]);
    expect(out1.successes).toHaveLength(1);
    expect(out2.successes).toHaveLength(1);
    // Mutex coalesces the in-flight refresh → only ONE network refresh.
    expect(fetchCount).toBe(1);
  });

  test("#10: per-account scope mismatch → `scope_mismatch` failure; sub-call never reaches fn() (sec-rev hook 3)", async () => {
    const fx = makeFixture({
      emails: ["a@x.com", "b@x.com"],
      scopesPerAccount: {
        "a@x.com": ["https://www.googleapis.com/auth/gmail.readonly"],
        // b lacks gmail.readonly
        "b@x.com": ["https://www.googleapis.com/auth/gmail.send"],
      },
    });
    let fnCalls = 0;
    const out = await withAllAccounts<{ ok: true }>(
      "gmail_search_all",
      { query: "x" },
      async (ctx) => {
        fnCalls += 1;
        expect(requireOAuth(ctx).accountId).toBe("a@x.com"); // b should never reach here
        return { ok: true };
      },
      {},
      fx.deps,
    );
    expect(fnCalls).toBe(1);
    expect(out.successes).toHaveLength(1);
    expect(out.failures).toHaveLength(1);
    expect(out.failures[0]).toEqual({
      account_email: "b@x.com",
      error: { code: "scope_mismatch", message: "scope_mismatch" },
    });
  });
});

describe("withAllAccounts — audit shape (design §8, sec-rev hooks 4 + 11)", () => {
  test("emits 1 outer aggregate row + N inner rows; counts match", async () => {
    const fx = makeFixture({
      emails: ["a@x.com", "b@x.com", "c@x.com"],
    });
    await withAllAccounts<{ ok: true }>(
      "gmail_search_all",
      { query: "x" },
      async (ctx) => {
        if (requireOAuth(ctx).accountId === "c@x.com") throw new MCPError("rate_limited");
        return { ok: true };
      },
      {},
      fx.deps,
    );
    // Inner audit rows: 1 per sub-call INCLUDING the failure (sec-rev hook 11).
    expect(fx.innerAuditCalls).toHaveLength(3);
    const okRows = fx.innerAuditCalls.filter((r) => r.status === "ok");
    const failRows = fx.innerAuditCalls.filter((r) => r.status === "error");
    expect(okRows).toHaveLength(2);
    expect(failRows).toHaveLength(1);
    expect(failRows[0]?.email).toBe("c@x.com");
    // Outer aggregate: counts match inner rows (sec-rev hook 4).
    expect(fx.outerAuditCalls).toHaveLength(1);
    expect(fx.outerAuditCalls[0]).toMatchObject({
      accountCountQueried: 3,
      accountCountSucceeded: 2,
      accountCountFailed: 1,
    });
  });

  test("inner audit row args_hash uses synthetic per-sub-call args (design §8 M3)", async () => {
    // Same outer args except different `accounts?` → different outer hash.
    // Inner row's hash is derived from outer-MINUS-accounts PLUS account_id,
    // so two calls with same `query` produce IDENTICAL inner hashes per
    // account regardless of the outer `accounts?` value.
    const fx1 = makeFixture({ emails: ["a@x.com"] });
    const fx2 = makeFixture({ emails: ["a@x.com"] });
    await withAllAccounts<{ ok: true }>(
      "gmail_search_all",
      { query: "same-query" },
      async () => ({ ok: true }),
      {},
      fx1.deps,
    );
    await withAllAccounts<{ ok: true }>(
      "gmail_search_all",
      { query: "same-query", accounts: ["a@x.com"] },
      async () => ({ ok: true }),
      { accounts: ["a@x.com"] },
      fx2.deps,
    );
    // Inner hashes for the same account + same query must match.
    expect(fx1.innerAuditCalls[0]?.argsHash).toBe(fx2.innerAuditCalls[0]?.argsHash);
    // Outer hashes differ (one includes `accounts`).
    expect(fx1.outerAuditCalls[0]?.argsHash).not.toBe(
      fx2.outerAuditCalls[0]?.argsHash,
    );
  });

  // v1.111 (#2) — forensic parity with the single-account choke point. The inner
  // row for a per-account FAILURE that threw a real MCPError now carries the precise
  // numeric error_code + the Source id; both branches carry source. Without the
  // error_code, the suspicious / policy-decisions readers (which key off it) were
  // blind to *_all per-account failures.
  test("#2: inner rows carry source on both branches + numeric error_code on failure", async () => {
    const fx = makeFixture({ emails: ["a@x.com", "c@x.com"] });
    await withAllAccounts<{ ok: true }>(
      "gmail_search_all",
      { query: "x" },
      async (ctx) => {
        if (requireOAuth(ctx).accountId === "c@x.com") throw new MCPError("rate_limited"); // -32005
        return { ok: true };
      },
      {},
      fx.deps,
    );
    const okRow = fx.innerAuditCalls.find((r) => r.status === "ok")!;
    const failRow = fx.innerAuditCalls.find((r) => r.status === "error")!;
    expect(okRow.source).toBe("google-workspace");
    expect(failRow.source).toBe("google-workspace");
    // the precise code, not absent — rate_limited.
    expect(failRow.errorCode).toBe(new MCPError("rate_limited").code);
    // ok rows have no errorCode (presence-as-signal, mirrors with-context.ts).
    expect(okRow.errorCode).toBeUndefined();
  });

  // v1.111 (#2) — a PRE-CALL plan failure (scope_mismatch, never reaches fn())
  // reaches forensic parity too: its inner row carries the numeric code.
  test("#2: pre-call scope_mismatch inner row carries the numeric error_code", async () => {
    const fx = makeFixture({
      emails: ["a@x.com"],
      // granted a real-but-unrelated scope → does NOT satisfy the required gmail.readonly
      scopesPerAccount: { "a@x.com": ["https://www.googleapis.com/auth/drive.readonly"] },
    });
    await withAllAccounts<{ ok: true }>(
      "gmail_search_all",
      { query: "x" },
      async () => ({ ok: true }),
      {},
      fx.deps,
    );
    const failRow = fx.innerAuditCalls.find((r) => r.status === "error")!;
    expect(failRow).toBeDefined();
    expect(failRow.errorCode).toBe(new MCPError("scope_mismatch").code); // -32004
    expect(failRow.source).toBe("google-workspace");
  });
});

describe("withAllAccounts — does NOT mutate lastUsedAccount (design §3)", () => {
  test("getLastUsed unchanged after cross-account call", async () => {
    const { _resetLastUsedForTests, getLastUsed, setLastUsed } = await import(
      "./with-context"
    );
    _resetLastUsedForTests();
    setLastUsed("pre-existing@x.com");
    const fx = makeFixture({ emails: ["a@x.com", "b@x.com"] });
    await withAllAccounts<{ ok: true }>(
      "gmail_search_all",
      { query: "x" },
      async () => ({ ok: true }),
      {},
      fx.deps,
    );
    expect(getLastUsed()).toBe("pre-existing@x.com");
    _resetLastUsedForTests();
  });
});

describe("withAllAccounts — failure-mapping gap tests (T1-T4)", () => {
  test("T1: refreshAccessToken throws MCPError(account_not_found) mid-call → failure for that account, others succeed", async () => {
    // Two accounts; for `b@x.com` make `getToken` return null so refresh.ts
    // throws MCPError("account_not_found") inside the fan-out (not in the
    // pre-flight subset check).
    const fx = makeFixture({ emails: ["a@x.com", "b@x.com"] });
    const origGetToken = fx.deps.getToken!;
    fx.deps.getToken = async (email: string) => {
      if (email === "b@x.com") return null;
      return origGetToken(email);
    };
    const out = await withAllAccounts<{ ok: true }>(
      "gmail_search_all",
      { query: "x" },
      async () => ({ ok: true }),
      {},
      fx.deps,
    );
    expect(out.successes).toHaveLength(1);
    expect(out.successes[0]?.account_email).toBe("a@x.com");
    expect(out.failures).toHaveLength(1);
    expect(out.failures[0]).toMatchObject({
      account_email: "b@x.com",
      error: { code: "account_not_found" },
    });
  });

  test("T2: pre-flight account_not_found does NOT trigger refresh (fetchCount === 0 for ghost)", async () => {
    // Count getToken calls per email — proxy for refresh attempts.
    const fx = makeFixture({ emails: ["a@x.com"] });
    const tokenFetchCounts = new Map<string, number>();
    const origGetToken = fx.deps.getToken!;
    fx.deps.getToken = async (email: string) => {
      tokenFetchCounts.set(email, (tokenFetchCounts.get(email) ?? 0) + 1);
      return origGetToken(email);
    };
    const out = await withAllAccounts<{ ok: true }>(
      "gmail_search_all",
      { query: "x", accounts: ["ghost@x.com"] },
      async () => ({ ok: true }),
      { accounts: ["ghost@x.com"] },
      fx.deps,
    );
    expect(out.failures).toHaveLength(1);
    expect(out.failures[0]?.error.code).toBe("account_not_found");
    // Pre-flight rejection MUST NOT trigger any refresh attempt for the ghost.
    expect(tokenFetchCounts.get("ghost@x.com") ?? 0).toBe(0);
  });

  test("T3: unknown MCPError name (keychain_locked) → upstream_error code", async () => {
    const fx = makeFixture({ emails: ["a@x.com"] });
    const out = await withAllAccounts<{ ok: true }>(
      "gmail_search_all",
      { query: "x" },
      async () => {
        throw new MCPError("keychain_locked");
      },
      {},
      fx.deps,
    );
    expect(out.successes).toHaveLength(0);
    expect(out.failures).toHaveLength(1);
    expect(out.failures[0]?.error.code).toBe("upstream_error");
  });

  test("T4: aggregate audit row fires even when ALL accounts fail", async () => {
    const fx = makeFixture({ emails: ["a@x.com", "b@x.com"] });
    await withAllAccounts<{ ok: true }>(
      "gmail_search_all",
      { query: "x" },
      async () => {
        throw new MCPError("rate_limited");
      },
      {},
      fx.deps,
    );
    // Outer aggregate row MUST be emitted exactly once even with zero successes.
    expect(fx.outerAuditCalls).toHaveLength(1);
    expect(fx.outerAuditCalls[0]).toMatchObject({
      accountCountQueried: 2,
      accountCountSucceeded: 0,
      accountCountFailed: 2,
    });
  });
});

describe("withAllAccounts — v1.64 B6 R10 closure (gates)", () => {
  const AUTO_BACKUP = process.env.SAFESPACE_AUTONOMOUS;
  afterEach(() => {
    if (AUTO_BACKUP === undefined) delete process.env.SAFESPACE_AUTONOMOUS;
    else process.env.SAFESPACE_AUTONOMOUS = AUTO_BACKUP;
  });

  test("read-only `_all` tools are NOT burst/autonomy gated even in autonomous mode (gates are no-ops → byte-identical)", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true"; // strictest mode...
    const fx = makeFixture({ emails: ["a@x.com"] });
    // gmail_search_all is min_tier:read → classifyWriteTool → "exempt"; it is not
    // a PERMANENT_DELETE tool → F4 no-op. The read fans out normally.
    const out = await withAllAccounts<{ messages: string[] }>(
      "gmail_search_all",
      { query: "x" },
      async (ctx) => ({ messages: [requireOAuth(ctx).accountId] }),
      {},
      fx.deps,
    );
    expect(out.successes).toHaveLength(1);
  });

  test("R10 gate closure: the F4 autonomous-delete gate fires at the fan-out boundary (a future *_all permanent-delete is gated by construction)", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    const fx = makeFixture({ emails: ["a@x.com"] });
    // withAllAccounts is generic over `tool`. Passing a real PERMANENT_DELETE_TOOLS
    // member (youtube_playlist_delete) exercises the F4 gate wired at the top of
    // the helper: it throws -32033 BEFORE any fan-out — the autonomy gap R10
    // described, now closed. (No `*_all` permanent-delete tool exists today, so
    // this is the only way to pin the wiring.)
    await expect(
      withAllAccounts<Record<string, never>>(
        "youtube_playlist_delete",
        {},
        async () => ({}),
        {},
        fx.deps,
      ),
    ).rejects.toThrow(MCPError);
    // Gate fired BEFORE fan-out → no per-account rows; one terminal error row
    // carrying the F4 code, no account.
    expect(fx.innerAuditCalls).toHaveLength(1);
    expect(fx.innerAuditCalls[0]!.email).toBeNull();
    expect(fx.innerAuditCalls[0]!.errorCode).toBe(new MCPError("destructive_denied_in_autonomous_mode").code);
    expect(fx.outerAuditCalls).toHaveLength(0);
  });
});

describe("withAllAccounts — fan-out set", () => {
  test("fan-out reaches every consented account", async () => {
    const fx = makeFixture({ emails: ["alice@example.com", "bob@example.com"] });
    const out = await withAllAccounts<{ ok: boolean }>(
      "gmail_search_all",
      { query: "x" },
      async () => ({ ok: true }),
      {},
      fx.deps,
    );
    expect(out.successes.map((s) => s.account_email).sort()).toEqual([
      "alice@example.com",
      "bob@example.com",
    ]);
  });
});

describe("withAllAccounts — unregistered-tool tripwire (v1.119 sec-rev)", () => {
  test("an unregistered tool name → internal_routing_error BEFORE any fan-out (the per-account scope check can never be silently skipped)", async () => {
    const fx = makeFixture({ emails: ["a@x.com"] });
    let thrown: unknown;
    try {
      await withAllAccounts(
        "definitely_not_a_registered_tool",
        {},
        async () => ({}),
        {},
        fx.deps,
      );
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(MCPError);
    expect((thrown as MCPError).errorName).toBe("internal_routing_error");
    // Fail-closed BEFORE any I/O: no inner rows, no aggregate row.
    expect(fx.innerAuditCalls).toHaveLength(0);
    expect(fx.outerAuditCalls).toHaveLength(0);
  });
});
