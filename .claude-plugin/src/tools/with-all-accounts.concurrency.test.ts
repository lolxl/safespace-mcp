// Perf hot-path cycle — bounded parallelism in the cross-account fan-out.
//
// The `_all` middleware previously ran every consented account's
// refresh + SDK call in one tick (`plans.map` + `Promise.all`). With many
// accounts that is a thundering herd (N simultaneous token refreshes + upstream
// calls). The fan-out is now capped at MAX_ACCOUNT_FANOUT (6), order-preserving.
// These tests pin: the cap binds for large sets, small sets stay fully parallel,
// and result/audit order is unchanged.

import { describe, expect, test } from "bun:test";
import { withAllAccounts, type WithAllAccountsDeps } from "./with-all-accounts";
import { requireOAuth } from "./handlers/shared";

const SCOPE = "https://www.googleapis.com/auth/gmail.readonly";

function makeAccounts(n: number) {
  return Array.from({ length: n }, (_, i) => ({ email: `u${i}@x.com`, scopes: [SCOPE] }));
}

function baseDeps(accounts: Array<{ email: string; scopes: string[] }>): WithAllAccountsDeps {
  return {
    loadIndexImpl: async () => ({ accounts }),
    getToken: async () =>
      JSON.stringify({
        refresh_token: "rt",
        access_token: "at",
        expires_at: Date.now() + 30 * 60_000,
        scopes: [SCOPE],
        obtained_at: Date.now(),
      }),
    setToken: async () => {},
    deleteToken: async () => {},
    removeAccount: async () => {},
    auditEndImpl: (async () => {}) as WithAllAccountsDeps["auditEndImpl"],
    auditAggregateImpl: (async () => {}) as WithAllAccountsDeps["auditAggregateImpl"],
    sanitizeImpl: ((v: unknown) => v) as WithAllAccountsDeps["sanitizeImpl"],
  };
}

/** Run withAllAccounts with a fn that records peak concurrency. */
async function runWithConcurrencyProbe(n: number) {
  const accounts = makeAccounts(n);
  let active = 0;
  let maxActive = 0;
  const res = await withAllAccounts(
    "gmail_search_all",
    {},
    async (ctx) => {
      const cred = requireOAuth(ctx);
      active++;
      maxActive = Math.max(maxActive, active);
      await new Promise((r) => setTimeout(r, 5));
      active--;
      return { messages: [] as unknown[], probed_email: cred.accountId };
    },
    {},
    baseDeps(accounts),
  );
  return { res, maxActive, accounts };
}

describe("withAllAccounts — bounded fan-out concurrency (perf hot-path)", () => {
  test("15 accounts: peak concurrency is capped at 6, all succeed, order preserved", async () => {
    const { res, maxActive, accounts } = await runWithConcurrencyProbe(15);
    expect(res.successes.length).toBe(15);
    expect(res.failures.length).toBe(0);
    expect(maxActive).toBeLessThanOrEqual(6); // the cap binds (would be 15 unbounded)
    expect(maxActive).toBeGreaterThanOrEqual(2); // still genuinely parallel
    // result order matches account order (deterministic audit/aggregation)
    expect(res.successes.map((s) => s.account_email)).toEqual(accounts.map((a) => a.email));
  });

  test("a set at-or-below the cap runs fully parallel (cap does not bind)", async () => {
    // Deterministic, not timing-dependent: each worker's `active++` runs
    // synchronously (before its first `await`), so all 4 workers increment the
    // counter in the same tick that Array.from spawns them — the peak is 4
    // regardless of timer scheduling / CI load.
    const { res, maxActive } = await runWithConcurrencyProbe(4);
    expect(res.successes.length).toBe(4);
    expect(maxActive).toBe(4);
  });

  test("zero consented accounts → empty result, no fan-out work", async () => {
    const res = await withAllAccounts(
      "gmail_search_all",
      {},
      async () => {
        throw new Error("fn must not run when there are no accounts");
      },
      {},
      baseDeps([]),
    );
    expect(res.successes).toEqual([]);
    expect(res.failures).toEqual([]);
  });
});
