// v1.89 — tamper-evident audit hash-chain tests.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  auditEnd,
  canonicalJson,
  chainGenesis,
  computeRowMac,
  getOrCreateAuditSalt,
  __resetChainState,
  type AuditEndContext,
} from "./audit";
import { verifyChain } from "./cli/audit/verify";

let tmpDir: string;
let prevEnv: string | undefined;
const auditPath = () => path.join(tmpDir, "audit.jsonl");

beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-chain-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  __resetChainState();
});
afterEach(async () => {
  if (prevEnv === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevEnv;
  await fs.rm(tmpDir, { recursive: true, force: true });
});

const ctx = (tool: string): AuditEndContext => ({
  tool,
  email: "alice@example.com",
  argsHash: `sha256:${tool}`,
  status: "ok",
  durationMs: 1,
});

async function writeRows(n: number): Promise<void> {
  for (let i = 0; i < n; i++) await auditEnd(ctx(`tool_${i}`));
}
async function readLines(): Promise<Array<Record<string, unknown>>> {
  const raw = await fs.readFile(auditPath(), "utf8");
  return raw.split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l));
}
async function writeLines(rows: Array<Record<string, unknown>>): Promise<void> {
  await fs.writeFile(auditPath(), rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
}

describe("canonicalJson", () => {
  test("sorts object keys recursively (order-independent)", () => {
    const a = canonicalJson({ b: 1, a: { d: 2, c: 3 } });
    const b = canonicalJson({ a: { c: 3, d: 2 }, b: 1 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":{"c":3,"d":2},"b":1}');
  });
  test("preserves array order", () => {
    expect(canonicalJson({ x: [3, 1, 2] })).toBe('{"x":[3,1,2]}');
  });
});

describe("computeRowMac", () => {
  const salt = Buffer.from("0".repeat(64), "hex");
  test("deterministic for the same inputs", () => {
    expect(computeRowMac(salt, "p", { a: 1 })).toBe(computeRowMac(salt, "p", { a: 1 }));
  });
  test("changes with prevMac (the chain link) and with content", () => {
    const base = computeRowMac(salt, "p1", { a: 1 });
    expect(computeRowMac(salt, "p2", { a: 1 })).not.toBe(base);
    expect(computeRowMac(salt, "p1", { a: 2 })).not.toBe(base);
  });
  test("key order does not change the MAC (canonicalized)", () => {
    expect(computeRowMac(salt, "p", { a: 1, b: 2 })).toBe(computeRowMac(salt, "p", { b: 2, a: 1 }));
  });
  test("a different salt yields a different MAC (HMAC-keyed forgery resistance)", () => {
    const other = crypto.randomBytes(32);
    expect(computeRowMac(other, "p", { a: 1 })).not.toBe(computeRowMac(salt, "p", { a: 1 }));
  });
});

describe("auditEnd stamps + links the chain", () => {
  test("every row carries a row_mac; each links to the previous (genesis first)", async () => {
    await writeRows(3);
    const rows = await readLines();
    expect(rows).toHaveLength(3);
    const salt = await getOrCreateAuditSalt();
    let prev = chainGenesis();
    for (const r of rows) {
      expect(typeof r.row_mac).toBe("string");
      const { row_mac, ...rest } = r;
      expect(computeRowMac(salt, prev, rest)).toBe(row_mac as string); // recomputes
      prev = row_mac as string;
    }
  });
});

describe("verifyChain", () => {
  test("an intact chain verifies (ok, N rows, tip = last mac)", async () => {
    await writeRows(4);
    const rows = await readLines();
    const salt = await getOrCreateAuditSalt();
    const r = await verifyChain(auditPath(), salt);
    expect(r.ok).toBe(true);
    expect(r.chainedRows).toBe(4);
    expect(r.tipMac).toBe(rows[3]!.row_mac as string);
    expect(r.brokenAt).toBeNull();
  });

  test("EDITING a row's content breaks the chain at that row", async () => {
    await writeRows(4);
    const rows = await readLines();
    rows[1]!.tool = "tampered"; // edit content, leave row_mac as-is
    await writeLines(rows);
    const r = await verifyChain(auditPath(), await getOrCreateAuditSalt());
    expect(r.ok).toBe(false);
    expect(r.brokenAt).toBe(2); // 1-based: the 2nd row
    expect(r.reason).toBe("mac_mismatch");
  });

  test("DELETING a middle row breaks the chain (the next row's prev no longer matches)", async () => {
    await writeRows(4);
    const rows = await readLines();
    rows.splice(1, 1); // delete row #2
    await writeLines(rows);
    const r = await verifyChain(auditPath(), await getOrCreateAuditSalt());
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("mac_mismatch");
  });

  test("INSERTING an unhashed row mid-chain is flagged", async () => {
    await writeRows(3);
    const rows = await readLines();
    rows.splice(1, 0, { ts: "x", tool: "injected" }); // no row_mac
    await writeLines(rows);
    const r = await verifyChain(auditPath(), await getOrCreateAuditSalt());
    expect(r.ok).toBe(false);
    expect(r.brokenAt).toBe(2);
    expect(r.reason).toBe("unhashed_after_chain");
  });

  test("a forged row recomputed with the WRONG salt fails under the real salt (HMAC keying)", async () => {
    await writeRows(3);
    const rows = await readLines();
    const wrongSalt = crypto.randomBytes(32);
    rows[1]!.tool = "evil";
    const { row_mac: _o, ...rest } = rows[1]!;
    rows[1]!.row_mac = computeRowMac(wrongSalt, rows[0]!.row_mac as string, rest); // attacker re-MACs without the key
    await writeLines(rows);
    const r = await verifyChain(auditPath(), await getOrCreateAuditSalt());
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("mac_mismatch");
  });

  test("a legacy unhashed PREFIX is tolerated; the chain verifies from the first hashed row", async () => {
    // Simulate pre-upgrade rows (no row_mac), then start the chain.
    await writeLines([{ ts: "t0", tool: "legacy_a" }, { ts: "t1", tool: "legacy_b" }]);
    await writeRows(2); // appends 2 chained rows after the legacy prefix
    const r = await verifyChain(auditPath(), await getOrCreateAuditSalt());
    // NOTE: writeRows starts from genesis (fresh process lastMac=undefined → readChainTip
    // finds no row_mac in the legacy tail → genesis), so the 2 new rows form a valid chain.
    expect(r.ok).toBe(true);
    expect(r.legacyRows).toBe(2);
    expect(r.chainedRows).toBe(2);
  });

  test("HONEST BOUNDARY: tail truncation is NOT detected (internal chain stays consistent)", async () => {
    await writeRows(4);
    const rows = await readLines();
    rows.pop(); // truncate the last row
    await writeLines(rows);
    const r = await verifyChain(auditPath(), await getOrCreateAuditSalt());
    expect(r.ok).toBe(true); // undetectable from inside the file — needs the out-of-band tip
    expect(r.chainedRows).toBe(3);
  });
});
