// v1.102 (W0) — durable inbox store tests: dedup, monotonic seq across prune, TTL +
// count-cap retention, the stateless cursor + oldest_seq gap signal, fail-loud parse.

import { afterEach, describe, expect, test } from "bun:test";
import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  appendInboxMessage,
  inboxCounts,
  loadInbox,
  parseInbox,
  readInbox,
} from "./inbox-store";
import type { InboxMsg } from "./types";

const HOUR = 60 * 60 * 1000;
const created: string[] = [];

function tmpFile(): string {
  const p = path.join(os.tmpdir(), `inbox-test-${crypto.randomBytes(8).toString("hex")}.json`);
  created.push(p);
  return p;
}

afterEach(async () => {
  for (const p of created.splice(0)) await fs.rm(p, { force: true });
});

function msg(text: string): InboxMsg {
  return { provider_message_id: "m1", ts: "1.0", sender_id: "U1", sender_name: null, channel_id: "C1", text };
}

describe("appendInboxMessage", () => {
  test("persists a row with seq 1 and the verified msg", async () => {
    const f = tmpFile();
    const now = 1_700_000_000_000;
    const { row, deduped } = await appendInboxMessage(f, { provider: "slack", event_id: "Ev1", msg: msg("hi") }, now);
    expect(deduped).toBe(false);
    expect(row.seq).toBe(1);
    expect(row.provider).toBe("slack");
    expect(row.event_id).toBe("Ev1");
    expect(row.msg.text).toBe("hi");
    const store = await loadInbox(f, now);
    expect(store.rows).toHaveLength(1);
    expect(store.next_seq).toBe(2);
  });

  test("DEDUP: a retry of the same (provider, event_id) does not create a second row", async () => {
    const f = tmpFile();
    const now = 1_700_000_000_000;
    const first = await appendInboxMessage(f, { provider: "slack", event_id: "Ev1", msg: msg("hi") }, now);
    const retry = await appendInboxMessage(f, { provider: "slack", event_id: "Ev1", msg: msg("hi again") }, now + 1000);
    expect(retry.deduped).toBe(true);
    expect(retry.row.seq).toBe(first.row.seq);
    const store = await loadInbox(f, now + 1000);
    expect(store.rows).toHaveLength(1);
    expect(store.next_seq).toBe(2); // a dedup hit consumes no seq
  });

  test("same event_id under a DIFFERENT provider is not a dup", async () => {
    const f = tmpFile();
    const now = 1_700_000_000_000;
    await appendInboxMessage(f, { provider: "slack", event_id: "X", msg: msg("a") }, now);
    const r2 = await appendInboxMessage(f, { provider: "telegram", event_id: "X", msg: msg("b") }, now);
    expect(r2.deduped).toBe(false);
    expect(r2.row.seq).toBe(2);
  });

  test("seq is monotonic across distinct appends", async () => {
    const f = tmpFile();
    const now = 1_700_000_000_000;
    const a = await appendInboxMessage(f, { provider: "slack", event_id: "E1", msg: msg("1") }, now);
    const b = await appendInboxMessage(f, { provider: "slack", event_id: "E2", msg: msg("2") }, now);
    const c = await appendInboxMessage(f, { provider: "slack", event_id: "E3", msg: msg("3") }, now);
    expect([a.row.seq, b.row.seq, c.row.seq]).toEqual([1, 2, 3]);
  });
});

describe("retention", () => {
  test("TTL: an expired row is never loaded/served", async () => {
    const f = tmpFile();
    const now = 1_700_000_000_000;
    await appendInboxMessage(f, { provider: "slack", event_id: "Old", msg: msg("old") }, now, HOUR);
    // 2h later the 1h-TTL row is expired
    const store = await loadInbox(f, now + 2 * HOUR);
    expect(store.rows).toHaveLength(0);
    // next_seq is preserved across the full prune → the cursor never resets
    expect(store.next_seq).toBe(2);
  });

  test("seq stays monotonic AFTER a full TTL prune (no reset)", async () => {
    const f = tmpFile();
    const now = 1_700_000_000_000;
    await appendInboxMessage(f, { provider: "slack", event_id: "E1", msg: msg("1") }, now, HOUR);
    // append after the first expired → must get seq 2, not seq 1
    const later = await appendInboxMessage(f, { provider: "slack", event_id: "E2", msg: msg("2") }, now + 2 * HOUR);
    expect(later.row.seq).toBe(2);
  });

  test("count cap drops the lowest-seq rows", async () => {
    const f = tmpFile();
    const now = 1_700_000_000_000;
    // Build a store at the cap directly (cheaper than 1000 appends).
    const rows = Array.from({ length: 1000 }, (_v, i) => ({
      seq: i + 1,
      provider: "slack" as const,
      event_id: `E${i + 1}`,
      received_at: new Date(now).toISOString(),
      expires_at: new Date(now + HOUR).toISOString(),
      msg: msg(`m${i + 1}`),
    }));
    await fs.writeFile(f, JSON.stringify({ next_seq: 1001, rows }, null, 2));
    const r = await appendInboxMessage(f, { provider: "slack", event_id: "E1001", msg: msg("newest") }, now, HOUR);
    expect(r.row.seq).toBe(1001);
    const store = await loadInbox(f, now);
    expect(store.rows).toHaveLength(1000);
    expect(Math.min(...store.rows.map((x) => x.seq))).toBe(2); // seq 1 dropped
    expect(store.rows.some((x) => x.seq === 1001)).toBe(true); // newest kept
  });
});

describe("readInbox — stateless cursor + gap signal", () => {
  async function seed(f: string, now: number) {
    await appendInboxMessage(f, { provider: "slack", event_id: "E1", msg: msg("one") }, now);
    await appendInboxMessage(f, { provider: "slack", event_id: "E2", msg: msg("two") }, now);
    await appendInboxMessage(f, { provider: "telegram", event_id: "T1", msg: msg("tg") }, now);
  }

  test("after_seq=0 returns this provider's rows ascending + max_seq", async () => {
    const f = tmpFile();
    const now = 1_700_000_000_000;
    await seed(f, now);
    const r = await readInbox(f, "slack", 0, 50, now);
    expect(r.messages.map((m) => m.event_id)).toEqual(["E1", "E2"]);
    expect(r.max_seq).toBe(2);
    expect(r.oldest_seq).toBe(1);
  });

  test("after_seq advances the cursor (only newer rows)", async () => {
    const f = tmpFile();
    const now = 1_700_000_000_000;
    await seed(f, now);
    const r = await readInbox(f, "slack", 1, 50, now);
    expect(r.messages.map((m) => m.event_id)).toEqual(["E2"]);
    expect(r.max_seq).toBe(2);
  });

  test("provider filter isolates each provider's rows", async () => {
    const f = tmpFile();
    const now = 1_700_000_000_000;
    await seed(f, now);
    const tg = await readInbox(f, "telegram", 0, 50, now);
    expect(tg.messages.map((m) => m.event_id)).toEqual(["T1"]);
  });

  test("limit caps the page; max_seq is the last returned", async () => {
    const f = tmpFile();
    const now = 1_700_000_000_000;
    await seed(f, now);
    const r = await readInbox(f, "slack", 0, 1, now);
    expect(r.messages).toHaveLength(1);
    expect(r.max_seq).toBe(1);
  });

  test("no new rows → max_seq echoes afterSeq", async () => {
    const f = tmpFile();
    const now = 1_700_000_000_000;
    await seed(f, now);
    const r = await readInbox(f, "slack", 9, 50, now);
    expect(r.messages).toHaveLength(0);
    expect(r.max_seq).toBe(9);
  });

  test("oldest_seq is null for an empty provider", async () => {
    const f = tmpFile();
    const now = 1_700_000_000_000;
    await seed(f, now);
    const r = await readInbox(f, "line", 0, 50, now);
    expect(r.oldest_seq).toBeNull();
  });

  test("GAP: a stale cursor below oldest_seq is detectable", async () => {
    const f = tmpFile();
    const now = 1_700_000_000_000;
    // seq 1 expired & pruned; only seq 2 remains
    await appendInboxMessage(f, { provider: "slack", event_id: "E1", msg: msg("gone") }, now, HOUR);
    await appendInboxMessage(f, { provider: "slack", event_id: "E2", msg: msg("kept") }, now + 2 * HOUR, 10 * HOUR);
    const r = await readInbox(f, "slack", 0, 50, now + 2 * HOUR);
    expect(r.oldest_seq).toBe(2);
    // agent held after_seq=0; 0 < oldest_seq - 1 (=1) → a gap occurred
    expect(0 < (r.oldest_seq! - 1)).toBe(true);
  });
});

describe("inboxCounts", () => {
  test("counts non-expired rows per provider", async () => {
    const f = tmpFile();
    const now = 1_700_000_000_000;
    await appendInboxMessage(f, { provider: "slack", event_id: "E1", msg: msg("a") }, now);
    await appendInboxMessage(f, { provider: "slack", event_id: "E2", msg: msg("b") }, now);
    await appendInboxMessage(f, { provider: "telegram", event_id: "T1", msg: msg("c") }, now);
    const counts = await inboxCounts(f, now);
    expect(counts).toEqual({ slack: 2, line: 0, telegram: 1 });
  });
});

describe("parseInbox — fail-loud", () => {
  test("missing file → empty store", async () => {
    const store = await loadInbox(tmpFile(), Date.now());
    expect(store).toEqual({ next_seq: 1, rows: [] });
  });
  test("non-JSON throws", () => {
    expect(() => parseInbox("not json {")).toThrow();
  });
  test("a row seq >= next_seq throws", () => {
    const bad = JSON.stringify({ next_seq: 1, rows: [{ seq: 1, provider: "slack", event_id: "E", received_at: new Date().toISOString(), expires_at: new Date().toISOString(), msg: msg("x") }] });
    expect(() => parseInbox(bad)).toThrow();
  });
  test("an unknown provider throws", () => {
    const bad = JSON.stringify({ next_seq: 2, rows: [{ seq: 1, provider: "myspace", event_id: "E", received_at: new Date().toISOString(), expires_at: new Date().toISOString(), msg: msg("x") }] });
    expect(() => parseInbox(bad)).toThrow();
  });
  test("a duplicate (provider, event_id) in the file throws", () => {
    const r = (seq: number) => ({ seq, provider: "slack", event_id: "DUP", received_at: new Date().toISOString(), expires_at: new Date().toISOString(), msg: msg("x") });
    const bad = JSON.stringify({ next_seq: 3, rows: [r(1), r(2)] });
    expect(() => parseInbox(bad)).toThrow();
  });
});
