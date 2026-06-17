// v1.27 Phase 2 Item 2 (NEW-10) — 7-channel mutex throw-vs-warn contract
// sentinel (v1.48 B4 added the 7th channel, playlistMutationMeta; this test
// exercises a representative 2-meta collision, which still holds).
//
// Q2 LOCKED Option C (per docs/v1.27-audit-tightening.md §2.2 + §6 Q2):
// the mutex assertion in with-context.ts:auditEnd finally block emits
// `console.error` and does NOT throw when 2+ audit metas are set per call.
//
// This sentinel file STRUCTURALLY PINS the warn-not-throw contract so a
// future PR that flips `console.error` → `throw new Error(...)` MUST fail
// these tests and force a re-design conversation (security implications
// for hook #7 audit-on-failure invariant + finally-block throw propagation
// engine-dependence — see expanded source comment in with-context.ts).
//
// Companion to the existing v1.17 / v1.19 / v1.20 mutex tests in
// with-context.test.ts (which assert the warn MESSAGE format + audit row
// FIELD propagation). This file's distinct focus: the CALL-COUNT contract
// (0 / 1 / 2 / 3 metas → warning count + throw status + audit row
// emission count).

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type { TokenSet } from "../auth/refresh";
import type { ToolContext } from "./types";
import {
  _resetLastUsedForTests,
  withToolContext,
  type WithContextDeps,
} from "./with-context";

const ENV_BACKUP = {
  id: process.env.GOOGLE_CLIENT_ID,
  secret: process.env.GOOGLE_CLIENT_SECRET,
};

let tmpDir: string;
let prevConfigDir: string | undefined;

beforeEach(async () => {
  process.env.GOOGLE_CLIENT_ID = "fake";
  process.env.GOOGLE_CLIENT_SECRET = "fake";
  _resetLastUsedForTests();
  prevConfigDir = process.env.SAFESPACE_CONFIG_DIR;
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-v127-p2-mutex-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
});

afterEach(async () => {
  process.env.GOOGLE_CLIENT_ID = ENV_BACKUP.id;
  process.env.GOOGLE_CLIENT_SECRET = ENV_BACKUP.secret;
  _resetLastUsedForTests();
  if (prevConfigDir === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevConfigDir;
  await fs.rm(tmpDir, { recursive: true, force: true });
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

function makeDeps(): WithContextDeps {
  const emails = ["alice@example.com"];
  const tokens: Record<string, TokenSet> = Object.fromEntries(
    emails.map((e) => [e, freshTokenSet()]),
  );
  const store = new Map<string, string>();
  for (const [e, ts] of Object.entries(tokens)) store.set(e, JSON.stringify(ts));
  const index = { accounts: emails.map((e) => ({ email: e })) };
  return {
    async getToken(email: string) {
      return store.get(email) ?? null;
    },
    async setToken(email: string, json: string) {
      store.set(email, json);
    },
    async deleteToken(email: string) {
      store.delete(email);
    },
    async removeAccount() {
      /* noop */
    },
    fetchImpl: (async () => new Response("{}", { status: 200 })) as unknown as typeof fetch,
    loadIndexImpl: async () => index,
  };
}

async function readAuditLines(): Promise<Array<Record<string, unknown>>> {
  const content = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
  return content
    .split("\n")
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}

async function waitForAudit(): Promise<void> {
  await new Promise((r) => setTimeout(r, 20));
}

describe("v1.27 Phase 2 Item 2 (NEW-10) — mutex warn-not-throw contract (Q2 LOCKED Option C)", () => {
  test("0 metas → no warning + no throw + audit row emitted", async () => {
    // Setup: handler that calls NO recorders.
    const deps = makeDeps();
    const errors: string[] = [];
    const restore = console.error;
    console.error = ((...args: unknown[]) => {
      errors.push(args.map((a) => String(a)).join(" "));
    }) as typeof console.error;

    let threw: unknown;
    try {
      try {
        await withToolContext(
          "gmail_search",
          { query: "x", account_id: "alice@example.com" },
          async () => ({ ok: true }),
          deps,
        );
      } catch (e) {
        threw = e;
      }
      await waitForAudit();
    } finally {
      console.error = restore;
    }

    // No throw (audit-on-failure invariant — hook #7).
    expect(threw).toBeUndefined();
    // No mutex warning (the message contains the literal "multiple audit metas").
    expect(errors.filter((e) => e.includes("multiple audit metas"))).toHaveLength(0);
    // Audit row STILL emitted.
    const records = await readAuditLines();
    expect(records).toHaveLength(1);
    expect(records[0]!.tool).toBe("gmail_search");
  });

  test("1 meta → no warning + no throw + audit row carries that channel's fields", async () => {
    const deps = makeDeps();
    const errors: string[] = [];
    const restore = console.error;
    console.error = ((...args: unknown[]) => {
      errors.push(args.map((a) => String(a)).join(" "));
    }) as typeof console.error;

    const SHASH = "3".repeat(64);
    let threw: unknown;
    try {
      try {
        await withToolContext(
          "sheets_create",
          { account_id: "alice@example.com" },
          async (ctx: ToolContext) => {
            ctx.audit.record("sheetsMutationMeta", {
              target_spreadsheet_id_hash: SHASH,
              operation: "create",
              policy_decision: "allowed",
            });
            return { ok: true };
          },
          deps,
        );
      } catch (e) {
        threw = e;
      }
      await waitForAudit();
    } finally {
      console.error = restore;
    }

    expect(threw).toBeUndefined();
    expect(errors.filter((e) => e.includes("multiple audit metas"))).toHaveLength(0);
    const records = await readAuditLines();
    expect(records).toHaveLength(1);
    expect(records[0]!.target_spreadsheet_id_hash).toBe(SHASH);
    expect(records[0]!.operation).toBe("create");
  });

  test("2 metas → console.error fires (NOT throw) + audit row STILL emitted with BOTH channels' fields", async () => {
    // The Q2 LOCKED Option C contract pin: a double-record bug must not
    // BLOCK the audit append (hook #7 audit-on-failure invariant).
    const deps = makeDeps();
    const errors: string[] = [];
    const restore = console.error;
    console.error = ((...args: unknown[]) => {
      errors.push(args.map((a) => String(a)).join(" "));
    }) as typeof console.error;

    const VHASH = "v".repeat(64);
    const SHASH = "s".repeat(64);
    let threw: unknown;
    try {
      try {
        await withToolContext(
          "synthetic_v127_p2_double_meta",
          { account_id: "alice@example.com" },
          async (ctx: ToolContext) => {
            ctx.audit.record("commentPostMeta", {
              target_video_hash: VHASH,
              comment_length: 5,
              policy_decision: "allowed",
            });
            ctx.audit.record("sheetsMutationMeta", {
              target_spreadsheet_id_hash: SHASH,
              operation: "create",
              policy_decision: "allowed",
            });
            return { ok: true };
          },
          deps,
        );
      } catch (e) {
        threw = e;
      }
      await waitForAudit();
    } finally {
      console.error = restore;
    }

    // CONTRACT: NO throw — mutex MUST NOT reject the auditEnd promise / propagate
    // out of the finally block. This is the load-bearing assertion that a
    // future PR flipping `console.error` → `throw` would trip.
    expect(threw).toBeUndefined();

    // Mutex warning fired exactly once.
    const warnings = errors.filter((e) => e.includes("multiple audit metas"));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("commentPost");
    expect(warnings[0]).toContain("sheetsMutation");

    // Audit row STILL written (hook #7 invariant) — both channels' fields
    // flattened onto the row (forensic double-presence signal per Q2 LOCK
    // Option C rationale documented in with-context.ts).
    const records = await readAuditLines();
    expect(records).toHaveLength(1);
    expect(records[0]!.target_video_hash).toBe(VHASH);
    expect(records[0]!.target_spreadsheet_id_hash).toBe(SHASH);
  });

  test("3 metas → console.error fires (NOT throw) + audit row STILL emitted with ALL 3 channels' fields", async () => {
    // Extreme-case sentinel: even 3 simultaneous metas (improbable in
    // practice — would require 3 buggy recorder calls in one handler) must
    // not BLOCK the audit append. Pins the contract beyond the minimum
    // 2-meta double-record scenario.
    const deps = makeDeps();
    const errors: string[] = [];
    const restore = console.error;
    console.error = ((...args: unknown[]) => {
      errors.push(args.map((a) => String(a)).join(" "));
    }) as typeof console.error;

    const VHASH = "v".repeat(64);
    const THASH = "t".repeat(64);
    const SHASH = "s".repeat(64);
    let threw: unknown;
    try {
      try {
        await withToolContext(
          "synthetic_v127_p2_triple_meta",
          { account_id: "alice@example.com" },
          async (ctx: ToolContext) => {
            ctx.audit.record("commentPostMeta", {
              target_video_hash: VHASH,
              comment_length: 5,
              policy_decision: "allowed",
            });
            ctx.audit.record("tasksMutationMeta", {
              target_tasklist_hash: THASH,
              operation: "create",
              policy_decision: "allowed",
            });
            ctx.audit.record("sheetsMutationMeta", {
              target_spreadsheet_id_hash: SHASH,
              operation: "create",
              policy_decision: "allowed",
            });
            return { ok: true };
          },
          deps,
        );
      } catch (e) {
        threw = e;
      }
      await waitForAudit();
    } finally {
      console.error = restore;
    }

    expect(threw).toBeUndefined();

    // Mutex warning fired exactly once — names all 3 channel labels in
    // registry-declaration order (commentPost / tasksMutation / sheetsMutation —
    // paired with v1.27 Phase 1 Item 4 iteration-order sentinel).
    const warnings = errors.filter((e) => e.includes("multiple audit metas"));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("commentPost");
    expect(warnings[0]).toContain("tasksMutation");
    expect(warnings[0]).toContain("sheetsMutation");

    // Audit row STILL written — all 3 channels' fields flattened.
    const records = await readAuditLines();
    expect(records).toHaveLength(1);
    expect(records[0]!.target_video_hash).toBe(VHASH);
    expect(records[0]!.target_tasklist_hash).toBe(THASH);
    expect(records[0]!.target_spreadsheet_id_hash).toBe(SHASH);
  });

  test("2 metas with DIFFERENT policy_decision values → last-iterated channel wins (registry order)", async () => {
    // v1.28 Phase 1 Item 2 (NEW-2) CONTRACT PIN — NOT a behavior change.
    //
    // Documents the bytewise consequence of Q2 LOCK Option C
    // (warn-not-throw) when 2 metas collide on a flat field. The serialize
    // loop in `auditEnd` runs `Object.assign(row, channelOutput)` per
    // channel in `AUDIT_META_CHANNELS` declaration order — the LAST
    // iterated channel's overlapping field WINS.
    //
    // Today's declaration order (pinned by v1.27 Phase 1 Item 4
    // iteration-order sentinel in `audit.metamap-sentinel.test.ts`):
    //   commentPostMeta → calendarMutationMeta → docsModifyMeta →
    //   commentDeleteMeta → tasksMutationMeta → sheetsMutationMeta (LAST)
    //
    // Therefore sheetsMutationMeta's `policy_decision: "allowed"` wins
    // over commentPostMeta's `policy_decision: "denied_outbound_sanitize_rejected"`.
    // The denied state is OVERWRITTEN at the audit-row level — forensic
    // visibility of the denial is LOST when a mutex violation collides on
    // a flat field. Both per-channel hash fields (`target_video_hash` /
    // `target_spreadsheet_id_hash`) survive because they DON'T collide
    // (distinct field names per channel).
    //
    // A future PR shifting `AUDIT_META_CHANNELS` declaration order OR
    // changing collision semantics (e.g., to "keep first non-allowed
    // value") MUST fail this sentinel and force re-locking Q2.
    //
    // Cross-defense: paired with the v1.27 Phase 1 Item 4 iteration-order
    // sentinel — if a future PR bumps a 7th channel, BOTH sentinels need
    // updating (intentional double-cover; registry order is load-bearing
    // for the mutex collision contract).
    const deps = makeDeps();
    const errors: string[] = [];
    const restore = console.error;
    console.error = ((...args: unknown[]) => {
      errors.push(args.map((a) => String(a)).join(" "));
    }) as typeof console.error;

    const VHASH = "v".repeat(64);
    const SHASH = "s".repeat(64);
    try {
      await withToolContext(
        "synthetic_v128_p1_collision",
        { account_id: "alice@example.com" },
        async (ctx: ToolContext) => {
          ctx.audit.record("commentPostMeta", {
            target_video_hash: VHASH,
            comment_length: 5,
            policy_decision: "denied_outbound_sanitize_rejected",
          });
          ctx.audit.record("sheetsMutationMeta", {
            target_spreadsheet_id_hash: SHASH,
            operation: "create",
            policy_decision: "allowed",
          });
          return { ok: true };
        },
        deps,
      );
      await waitForAudit();
    } finally {
      console.error = restore;
    }

    // Mutex warning fired (Q2 LOCK Option C contract).
    expect(errors.filter((e) => e.includes("multiple audit metas"))).toHaveLength(1);

    // BOTH per-channel hash fields survived (no overwrite collision —
    // distinct field names per channel).
    const records = await readAuditLines();
    expect(records).toHaveLength(1);
    expect(records[0]!.target_video_hash).toBe(VHASH);
    expect(records[0]!.target_spreadsheet_id_hash).toBe(SHASH);

    // CRITICAL CONTRACT PIN: `policy_decision` collided — sheetsMutationMeta
    // (LAST in AUDIT_META_CHANNELS declaration order) wins.
    // commentPostMeta's `denied_outbound_sanitize_rejected` is OVERWRITTEN
    // to `allowed`. Bytewise consequence of Q2 LOCK Option C: forensic
    // visibility of the denied decision is LOST when a mutex violation
    // collides on a flat field.
    expect(records[0]!.policy_decision).toBe("allowed");
  });
});
