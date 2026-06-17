// v1.99 — the pending-send store: fingerprint stability/sensitivity, fail-loud parse, and the
// load-time prune of expired records (so stale plaintext bodies don't linger). Pure functions +
// a tmp SAFESPACE_CONFIG_DIR for the file roundtrip.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  approvePending,
  computeFingerprint,
  createPending,
  findAndRemovePending,
  findApprovedByFingerprint,
  loadPendingSends,
  parsePendingSends,
  pendingSendsPath,
} from "./send-approval-store";

describe("computeFingerprint", () => {
  test("is deterministic + dedups/sorts recipients (order & dupes don't change the send)", () => {
    const a = computeFingerprint("gmail_send", ["x@a.com", "y@b.com"], "hi", "");
    const b = computeFingerprint("gmail_send", ["y@b.com", "x@a.com", "x@a.com"], "hi", "");
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  test("changes with tool / body / recipient-set / operator (each is bound)", () => {
    const base = computeFingerprint("gmail_send", ["x@a.com"], "hi", "");
    expect(computeFingerprint("slack_send_message", ["x@a.com"], "hi", "")).not.toBe(base); // tool
    expect(computeFingerprint("gmail_send", ["x@a.com"], "HI", "")).not.toBe(base); // body
    expect(computeFingerprint("gmail_send", ["x@a.com", "z@c.com"], "hi", "")).not.toBe(base); // recipient set
    expect(computeFingerprint("gmail_send", ["x@a.com"], "hi", "op@a")).not.toBe(base); // operator
  });
});

describe("parsePendingSends — fail-loud", () => {
  test("rejects non-JSON / wrong shape / bad field", () => {
    expect(() => parsePendingSends("{ bad")).toThrow(/invalid/);
    expect(() => parsePendingSends(JSON.stringify({ pending: "no" }))).toThrow(/pending.*must be an array/);
    expect(() => parsePendingSends(JSON.stringify({ pending: [{ pending_id: "short" }] }))).toThrow(/pending_id/);
    expect(() =>
      parsePendingSends(JSON.stringify({ pending: [{ pending_id: "a".repeat(32), fingerprint: "f".repeat(64), tool: "gmail_send", recipients: ["x"], body: "b", operator: "", created_at: "2026-01-01T00:00:00Z", expires_at: "2026-01-02T00:00:00Z", status: "bogus" }] })),
    ).toThrow(/status/);
    const dup = { pending_id: "a".repeat(32), fingerprint: "f".repeat(64), tool: "gmail_send", recipients: ["x"], body: "b", operator: "", created_at: "2026-01-01T00:00:00Z", expires_at: "2026-01-02T00:00:00Z", status: "approved" };
    expect(() => parsePendingSends(JSON.stringify({ pending: [dup, dup] }))).toThrow(/duplicate/);
  });

  test("accepts a well-formed record", () => {
    const recs = parsePendingSends(
      JSON.stringify({
        pending: [
          { pending_id: "a".repeat(32), fingerprint: "f".repeat(64), tool: "gmail_send", recipients: ["x@a.com"], body: "b", operator: "", created_at: "2026-01-01T00:00:00Z", expires_at: "2026-01-02T00:00:00Z", status: "approved" },
        ],
      }),
    );
    expect(recs).toHaveLength(1);
    expect(recs[0]!.status).toBe("approved");
  });
});

describe("store roundtrip (tmp config dir)", () => {
  const ENV = ["SAFESPACE_CONFIG_DIR"];
  const saved: Record<string, string | undefined> = {};
  let tmpDir: string;
  beforeEach(async () => {
    for (const k of ENV) saved[k] = process.env[k];
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-sastore-"));
    process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  });
  afterEach(async () => {
    for (const k of ENV) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k]!;
    }
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  test("a missing file → empty store", async () => {
    expect(await loadPendingSends(pendingSendsPath(), Date.now())).toEqual([]);
  });

  test("create → approve → find → remove(consume)", async () => {
    const now = 1_000_000;
    const fp = computeFingerprint("gmail_send", ["a@x.com"], "hi", "");
    const id = await createPending(pendingSendsPath(), { fingerprint: fp, tool: "gmail_send", recipients: ["a@x.com"], body: "hi", operator: "" }, now, 60_000);
    let recs = await loadPendingSends(pendingSendsPath(), now);
    expect(findApprovedByFingerprint(recs, fp)).toBeUndefined(); // still pending
    await approvePending(pendingSendsPath(), id, now);
    recs = await loadPendingSends(pendingSendsPath(), now);
    expect(findApprovedByFingerprint(recs, fp)?.pending_id).toBe(id);
    expect((await findAndRemovePending(pendingSendsPath(), id, now))?.pending_id).toBe(id);
    expect(await loadPendingSends(pendingSendsPath(), now)).toHaveLength(0);
  });

  test("expired records are PRUNED at load (stale plaintext doesn't linger)", async () => {
    const now = 1_000_000;
    await createPending(pendingSendsPath(), { fingerprint: "f".repeat(64), tool: "gmail_send", recipients: ["a@x.com"], body: "secret", operator: "" }, now, 10_000);
    // before expiry → present; after expiry → pruned
    expect(await loadPendingSends(pendingSendsPath(), now + 5_000)).toHaveLength(1);
    expect(await loadPendingSends(pendingSendsPath(), now + 20_000)).toHaveLength(0);
  });

  test("MAX_RECORDS cap: createPending FAILS CLOSED (throws) when the store is full", async () => {
    const now = 1_000_000;
    const full = Array.from({ length: 1000 }, (_, i) => ({
      pending_id: i.toString(16).padStart(32, "0"),
      fingerprint: "f".repeat(64),
      tool: "gmail_send",
      recipients: ["a@x.com"],
      body: "b",
      operator: "",
      created_at: new Date(now).toISOString(),
      expires_at: new Date(now + 60_000).toISOString(),
      status: "pending",
    }));
    await fs.mkdir(tmpDir, { recursive: true });
    await fs.writeFile(pendingSendsPath(), JSON.stringify({ pending: full }), { mode: 0o600 });
    await expect(
      createPending(
        pendingSendsPath(),
        { fingerprint: "e".repeat(64), tool: "gmail_send", recipients: ["b@x.com"], body: "c", operator: "" },
        now,
        60_000,
      ),
    ).rejects.toThrow(/full/);
  });
});
