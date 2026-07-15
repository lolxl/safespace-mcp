// v1.120 (F6 step 2) — envelope-parity tests for the cross-account `_all` fan-out.
//
// Pins the ToolContext-parity surface of the per-account sub-call: it carries `tier`
// (resolved once per fan-out, deps.tier ?? currentTier()) and its OWN `audit` sink (a
// per-sub-call createAuditAccumulator()), whose recorded forensic fields ride onto
// THAT account's inner audit row — mirroring the single-account choke point
// (with-context.ts). Byte-identical for every existing caller (no `_all` handler
// records anything today).
//
// v1.121 (B6.1 wave C) — the sub-call now runs the REAL ToolContext (the former shim
// is deleted); these tests also pin the per-sub-call egress tripwire + the
// `sanitize:"applied"` stamp on EXECUTED inner rows (owner-locked Q2).
//
// APPEND-ONLY: this file re-implements the makeFixture harness locally rather than
// touching with-all-accounts.test.ts.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { MCPError } from "../errors";
import type { TokenSet } from "../auth/refresh";
import { __resetWriteBurstForTests } from "../policy/write-burst";
import { currentTier } from "../tier";
import {
  withAllAccounts,
  type WithAllAccountsDeps,
} from "./with-all-accounts";
import { requireOAuth } from "./handlers/shared";

const ENV_BACKUP = {
  id: process.env.GOOGLE_CLIENT_ID,
  secret: process.env.GOOGLE_CLIENT_SECRET,
  tier: process.env.SAFESPACE_TIER,
  operator: process.env.SAFESPACE_OPERATOR_ID,
};

beforeEach(() => {
  process.env.GOOGLE_CLIENT_ID = "fake";
  process.env.GOOGLE_CLIENT_SECRET = "fake";
});

afterEach(() => {
  process.env.GOOGLE_CLIENT_ID = ENV_BACKUP.id;
  process.env.GOOGLE_CLIENT_SECRET = ENV_BACKUP.secret;
  if (ENV_BACKUP.tier === undefined) delete process.env.SAFESPACE_TIER;
  else process.env.SAFESPACE_TIER = ENV_BACKUP.tier;
  if (ENV_BACKUP.operator === undefined) delete process.env.SAFESPACE_OPERATOR_ID;
  else process.env.SAFESPACE_OPERATOR_ID = ENV_BACKUP.operator;
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
  innerAuditCalls: Array<Record<string, unknown>>;
  outerAuditCalls: Array<Record<string, unknown>>;
  deps: WithAllAccountsDeps;
}

function makeFixture(opts: { emails?: string[]; scopes?: string[] } = {}): FakeFixture {
  const emails = opts.emails ?? ["alice@example.com"];
  // v1.121 (B6.1 wave C) — per-account granted scopes, overridable so the new
  // scope_mismatch / gmail_send fixtures can pick the scope the plan needs.
  const scopes = opts.scopes ?? ["https://www.googleapis.com/auth/gmail.readonly"];
  const store = new Map<string, string>();
  for (const e of emails) store.set(e, JSON.stringify(freshTokenSet({ scopes })));
  const index = {
    accounts: emails.map((e) => ({
      email: e,
      scopes,
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
    async removeAccount() {},
    fetchImpl: (async () => new Response("{}", { status: 200 })) as unknown as typeof fetch,
    loadIndexImpl: async () => index,
    auditEndImpl: async (ctx) => {
      innerAuditCalls.push({ ...ctx });
    },
    auditAggregateImpl: async (ctx) => {
      outerAuditCalls.push({ ...ctx });
    },
  };

  return { innerAuditCalls, outerAuditCalls, deps };
}

/** The base inner-row key set for an EXECUTED sub-call (keys whose value is NOT
 *  undefined). v1.121 (B6.1 wave C) — now includes `sanitize` (stamped "applied" on
 *  every EXECUTED inner row; PLAN-FAILURE rows omit it). */
const BASE_OK_ROW_KEYS = [
  "argsHash",
  "durationMs",
  "email",
  "operator",
  "sanitize",
  "source",
  "status",
  "tool",
].sort();

function definedKeys(row: Record<string, unknown>): string[] {
  return Object.keys(row)
    .filter((k) => row[k] !== undefined)
    .sort();
}

describe("withAllAccounts — envelope parity (F6 step 2): tier", () => {
  test("subCtx.tier reflects deps.tier when provided (write)", async () => {
    const fx = makeFixture({ emails: ["a@x.com"] });
    let seenTier: string | undefined;
    await withAllAccounts<{ ok: true }>(
      "gmail_search_all",
      { query: "x" },
      async (ctx) => {
        seenTier = ctx.tier;
        return { ok: true };
      },
      {},
      { ...fx.deps, tier: "write" },
    );
    expect(seenTier).toBe("write");
  });

  test("subCtx.tier falls back to currentTier() when deps.tier absent (Model A)", async () => {
    process.env.SAFESPACE_TIER = "share";
    // Sanity: the process source the single-account path also reads.
    expect(currentTier()).toBe("share");
    const fx = makeFixture({ emails: ["a@x.com"] });
    let seenTier: string | undefined;
    await withAllAccounts<{ ok: true }>(
      "gmail_search_all",
      { query: "x" },
      async (ctx) => {
        seenTier = ctx.tier;
        return { ok: true };
      },
      {},
      fx.deps, // no deps.tier
    );
    expect(seenTier).toBe("share");
  });
});

describe("withAllAccounts — envelope parity (F6 step 2): per-account audit sink", () => {
  test("a recorded meta rides onto THAT account's inner row and NOT another's (per-sub-call accumulator isolation)", async () => {
    const fx = makeFixture({ emails: ["a@x.com", "b@x.com"] });
    await withAllAccounts<{ ok: true }>(
      "gmail_search_all",
      { query: "x" },
      async (ctx) => {
        if (requireOAuth(ctx).accountId === "a@x.com") {
          ctx.audit.record("commentPostMeta", {
            target_video_hash: "sha256:vid-a",
            comment_length: 3,
            policy_decision: "allowed",
          });
        } else {
          ctx.audit.record("calendarMutationMeta", {
            target_event_hash: "sha256:evt-b",
            policy_decision: "allowed",
          });
        }
        return { ok: true };
      },
      {},
      fx.deps,
    );
    const rowA = fx.innerAuditCalls.find((r) => r.email === "a@x.com")!;
    const rowB = fx.innerAuditCalls.find((r) => r.email === "b@x.com")!;
    // A's meta landed on A's row only.
    expect(rowA.commentPostMeta).toEqual({
      target_video_hash: "sha256:vid-a",
      comment_length: 3,
      policy_decision: "allowed",
    });
    expect(rowA.calendarMutationMeta).toBeUndefined();
    // B's meta landed on B's row only — no cross-account bleed.
    expect(rowB.calendarMutationMeta).toEqual({
      target_event_hash: "sha256:evt-b",
      policy_decision: "allowed",
    });
    expect(rowB.commentPostMeta).toBeUndefined();
  });

  test("recording two meta channels in one sub-call warns via console.error and the call still succeeds", async () => {
    const fx = makeFixture({ emails: ["a@x.com"] });
    const origError = console.error;
    const warnings: string[] = [];
    console.error = (...args: unknown[]) => {
      warnings.push(args.map(String).join(" "));
    };
    try {
      const out = await withAllAccounts<{ ok: true }>(
        "gmail_search_all",
        { query: "x" },
        async (ctx) => {
          ctx.audit.record("commentPostMeta", {
            target_video_hash: "sha256:vid",
            comment_length: 1,
            policy_decision: "allowed",
          });
          ctx.audit.record("calendarMutationMeta", {
            target_event_hash: "sha256:evt",
            policy_decision: "allowed",
          });
          return { ok: true };
        },
        {},
        fx.deps,
      );
      // Call still succeeds (warn-not-throw contract, mirrors with-context.ts).
      expect(out.successes).toHaveLength(1);
    } finally {
      console.error = origError;
    }
    // The mutex warn fired exactly once, naming the tool + both channel labels.
    const hit = warnings.find((w) => w.includes("set multiple audit metas"));
    expect(hit).toBeDefined();
    expect(hit).toContain("gmail_search_all");
    expect(hit).toContain("commentPost");
    expect(hit).toContain("calendarMutation");
  });
});

describe("withAllAccounts — envelope parity (F6 step 2): byte-identity when nothing recorded", () => {
  test("a plain (record-nothing) sub-call's inner row carries NO new defined fields", async () => {
    const fx = makeFixture({ emails: ["a@x.com"] });
    await withAllAccounts<{ ok: true }>(
      "gmail_search_all",
      { query: "x" },
      async () => ({ ok: true }),
      {},
      fx.deps,
    );
    expect(fx.innerAuditCalls).toHaveLength(1);
    const row = fx.innerAuditCalls[0]!;
    expect(row.status).toBe("ok");
    // The spread of the all-undefined forensic envelope adds no DEFINED field —
    // auditEnd serializes only defined fields, so the row stays byte-identical.
    expect(definedKeys(row)).toEqual(BASE_OK_ROW_KEYS);
  });

  test("a failing (record-nothing) sub-call's inner row adds only errorCode over the base set", async () => {
    const fx = makeFixture({ emails: ["a@x.com"] });
    await withAllAccounts<{ ok: true }>(
      "gmail_search_all",
      { query: "x" },
      async () => {
        throw new MCPError("rate_limited");
      },
      {},
      fx.deps,
    );
    const row = fx.innerAuditCalls.find((r) => r.status === "error")!;
    expect(row).toBeDefined();
    // rate_limited carries no whitelisted forensic fields → errorForensics stays
    // undefined; the only added defined field over the base set is errorCode.
    expect(definedKeys(row)).toEqual([...BASE_OK_ROW_KEYS, "errorCode"].sort());
    expect(row.errorCode).toBe(new MCPError("rate_limited").code);
  });
});

describe("withAllAccounts — B6.1 wave C: sanitize stamp + per-sub-call egress tripwire", () => {
  // gmail_send (tests iv/v) goes through the F1 write-burst counter at the fan-out
  // boundary; reset it per test so the lenient 60/min bucket can never bleed across
  // tests (mirrors with-context.test.ts / egress-tripwire.test.ts).
  beforeEach(() => {
    __resetWriteBurstForTests();
  });

  test("(i) an EXECUTED ok inner row stamps sanitize:\"applied\"", async () => {
    const fx = makeFixture({ emails: ["a@x.com"] });
    await withAllAccounts<{ ok: true }>(
      "gmail_search_all",
      { query: "x" },
      async () => ({ ok: true }),
      {},
      fx.deps,
    );
    const row = fx.innerAuditCalls.find((r) => r.status === "ok")!;
    expect(row).toBeDefined();
    expect(row.sanitize).toBe("applied");
  });

  test("(ii) an EXECUTED error inner row (fn throws) stamps sanitize:\"applied\"", async () => {
    const fx = makeFixture({ emails: ["a@x.com"] });
    await withAllAccounts<{ ok: true }>(
      "gmail_search_all",
      { query: "x" },
      async () => {
        throw new MCPError("rate_limited");
      },
      {},
      fx.deps,
    );
    const row = fx.innerAuditCalls.find((r) => r.status === "error")!;
    expect(row).toBeDefined();
    expect(row.sanitize).toBe("applied");
  });

  test("(iii) a PLAN-FAILURE inner row (scope_mismatch, never executed) has NO sanitize field", async () => {
    // Account granted a real-but-unrelated scope → does NOT satisfy gmail.readonly,
    // so buildPlan short-circuits to scope_mismatch BEFORE any handler runs.
    const fx = makeFixture({
      emails: ["a@x.com"],
      scopes: ["https://www.googleapis.com/auth/drive.readonly"],
    });
    await withAllAccounts<{ ok: true }>(
      "gmail_search_all",
      { query: "x" },
      async () => ({ ok: true }),
      {},
      fx.deps,
    );
    const row = fx.innerAuditCalls.find((r) => r.status === "error")!;
    expect(row).toBeDefined();
    // Forensic parity still carries errorCode, but NO sanitize (no execution → no
    // sanitize semantics) — the field is absent, not defined.
    expect(row.errorCode).toBe(new MCPError("scope_mismatch").code);
    expect("sanitize" in row).toBe(false);
    expect(row.sanitize).toBeUndefined();
  });

  test("(iv) egress tripwire: a direction:\"outbound-write\" tool whose fn omits egressGateFired → per-account failure carrying the internal_routing_error code on its inner row", async () => {
    // gmail_send is a REGISTERED direction:"outbound-write" tool (same real-tool
    // pinning pattern as the R10 gate test). gmail.send granted → plan is `ready` and
    // the fn EXECUTES; F1/F4 are no-ops in the non-autonomous test env (gmail_send is a
    // write not a permanent-delete; one call is far under the lenient write-burst cap).
    const fx = makeFixture({
      emails: ["a@x.com"],
      scopes: ["https://www.googleapis.com/auth/gmail.send"],
    });
    const out = await withAllAccounts<{ ok: true }>(
      "gmail_send",
      { to: "x@y.com", subject: "s", body: "b" },
      async () => ({ ok: true }), // does NOT set ctx.egressGateFired
      {},
      fx.deps,
    );
    // The tripwire trips INSIDE the per-account try → a per-account failure, never
    // thrown out of the helper (best-effort contract preserved).
    expect(out.successes).toHaveLength(0);
    expect(out.failures).toHaveLength(1);
    const row = fx.innerAuditCalls.find((r) => r.status === "error")!;
    expect(row).toBeDefined();
    expect(row.errorCode).toBe(new MCPError("internal_routing_error").code);
  });

  test("(v) egress tripwire: the same tool whose fn DOES set ctx.egressGateFired → success", async () => {
    const fx = makeFixture({
      emails: ["a@x.com"],
      scopes: ["https://www.googleapis.com/auth/gmail.send"],
    });
    const out = await withAllAccounts<{ ok: true }>(
      "gmail_send",
      { to: "x@y.com", subject: "s", body: "b" },
      async (ctx) => {
        ctx.egressGateFired = true;
        return { ok: true };
      },
      {},
      fx.deps,
    );
    expect(out.successes).toHaveLength(1);
    expect(out.failures).toHaveLength(0);
  });
});
