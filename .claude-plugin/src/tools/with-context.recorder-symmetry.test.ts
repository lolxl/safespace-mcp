// v1.64 Phase B (B1 — audit facade) — audit-sink coverage sentinel.
//
// REPLACES the v1.27 Phase 2 "recorder symmetry" sentinel. That test forced
// every AUDIT_META_CHANNELS key to have a matching `record<Pascal>Meta` closure
// on ToolContext (layer (d) of the 4-layer drift defense). B1 removed the 10
// `record*` closures in favour of ONE `ctx.audit.record(channel, meta)` sink, so
// that symmetry is now enforced at COMPILE TIME by `AuditSinkChannels extends
// MetaMap` (types.ts): a channel added to MetaMap is automatically a valid
// `ctx.audit.record` channel — there is no separate recorder to forget.
//
// What remains worth pinning at RUNTIME is the behavioural contract the old
// drift defense ultimately protected: every registered meta channel, recorded
// through the sink, actually lands on the audit row. A registry channel the
// with-context sink failed to route (e.g. a future refactor that special-cased
// some channels) would fail the end-to-end loop below — re-establishing the
// drift defense at the layer that matters now. Plus a guard that the 10 legacy
// `record*` closures are truly gone (the facade migration did not leave a
// half-migrated ctx).

import { describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { AUDIT_META_CHANNELS, __drainAuditWrites } from "../audit";
import type { TokenSet } from "../auth/refresh";
import type { AuditChannel, ToolContext } from "./types";
import {
  _resetLastUsedForTests,
  withToolContext,
  type WithContextDeps,
} from "./with-context";

const ENV_BACKUP = {
  id: process.env.GOOGLE_CLIENT_ID,
  secret: process.env.GOOGLE_CLIENT_SECRET,
};

function freshTokenSet(): TokenSet {
  return {
    refresh_token: "rt",
    access_token: "old-access-token",
    expires_at: Date.now() + 30 * 60_000,
    scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
    obtained_at: Date.now(),
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

/** The legacy recorder name a channel key USED to map to (pre-v1.64). */
function legacyRecorderNameFor(channelKey: string): string {
  return "record" + channelKey.charAt(0).toUpperCase() + channelKey.slice(1);
}

async function withTmpEnv<T>(fn: (tmpDir: string) => Promise<T>): Promise<T> {
  process.env.GOOGLE_CLIENT_ID = "fake";
  process.env.GOOGLE_CLIENT_SECRET = "fake";
  _resetLastUsedForTests();
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-v164-sink-"));
  const prevConfigDir = process.env.SAFESPACE_CONFIG_DIR;
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  try {
    return await fn(tmpDir);
  } finally {
    process.env.GOOGLE_CLIENT_ID = ENV_BACKUP.id ?? "";
    process.env.GOOGLE_CLIENT_SECRET = ENV_BACKUP.secret ?? "";
    _resetLastUsedForTests();
    if (prevConfigDir === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
    else process.env.SAFESPACE_CONFIG_DIR = prevConfigDir;
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
}

describe("v1.64 Phase B (B1) — ctx.audit is the single recording surface", () => {
  test("ctx exposes one ctx.audit.record function; the 10 legacy record* closures are gone", async () => {
    await withTmpEnv(async () => {
      let capturedCtx: ToolContext | undefined;
      await withToolContext(
        "gmail_search",
        { query: "probe", account_id: "alice@example.com" },
        async (ctx: ToolContext) => {
          capturedCtx = ctx;
          return { ok: true };
        },
        makeDeps(),
      );
      const ctx = capturedCtx as ToolContext;
      expect(ctx.audit).toBeDefined();
      expect(typeof ctx.audit.record).toBe("function");
      // The facade migration must be complete — no half-migrated ctx still
      // carrying a per-channel record* closure alongside the new sink.
      const asRecord = ctx as unknown as Record<string, unknown>;
      for (const channelKey of Object.keys(AUDIT_META_CHANNELS)) {
        expect(asRecord[legacyRecorderNameFor(channelKey)]).toBeUndefined();
      }
      expect(asRecord.recordResolvedRecipientHash).toBeUndefined();
      expect(asRecord.recordTaintedSource).toBeUndefined();
      expect(asRecord.recordOutboundSecretShape).toBeUndefined();
    });
  });

  test("EVERY AUDIT_META_CHANNELS channel routes through ctx.audit.record onto the audit row", async () => {
    // The behavioural successor to the v1.27 symmetry sentinel: a registry meta
    // channel the with-context sink fails to thread onto the row fails here.
    for (const [channelKey, entry] of Object.entries(AUDIT_META_CHANNELS)) {
      await withTmpEnv(async (tmpDir) => {
        const marker = `sink_probe_${channelKey}`;
        await withToolContext(
          "gmail_search",
          { query: "probe", account_id: "alice@example.com" },
          async (ctx: ToolContext) => {
            // Record this channel via the sink with just its flatHash field set.
            ctx.audit.record(
              channelKey as AuditChannel,
              { [entry.flatHash]: marker } as never,
            );
            return { ok: true };
          },
          makeDeps(),
        );
        // auditEnd is fire-and-forget (`void auditEnd(...)`); wait for the queued append.
        await __drainAuditWrites();
        const content = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
        const rows = content.split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l));
        const row = rows[rows.length - 1]! as Record<string, unknown>;
        // The channel's flatHash field landed on the row → sink → MetaMapStore →
        // auditEnd bridge → serialize all wired for this channel.
        expect(row[entry.flatHash]).toBe(marker);
      });
    }
  });

  test("the 3 SCALAR channels route through ctx.audit.record onto the audit row", async () => {
    // Completes the sink-coverage sentinel: the meta-channel loop above covers
    // the 7 AUDIT_META_CHANNELS; this pins the 3 scalar channels end-to-end too,
    // so a future scalar added to AuditSinkChannels without a `case` in the
    // with-context sink (silently falling through to the meta default branch)
    // fails here. Scalars are independent row fields (no mutual exclusion), so
    // one call records all three.
    await withTmpEnv(async (tmpDir) => {
      await withToolContext(
        "gmail_search",
        { query: "probe", account_id: "alice@example.com" },
        async (ctx: ToolContext) => {
          ctx.audit.record("resolvedRecipientHash", "deadbeefcafe");
          ctx.audit.record("taintedSource");
          ctx.audit.record("outboundSecretShape", "private_key");
          return { ok: true };
        },
        makeDeps(),
      );
      await __drainAuditWrites();
      const content = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
      const rows = content.split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l));
      const row = rows[rows.length - 1]! as Record<string, unknown>;
      expect(row.resolved_recipient_hash).toBe("deadbeefcafe");
      expect(row.tainted_source).toBe(true);
      expect(row.outbound_secret_shape).toBe("private_key");
    });
  });
});
