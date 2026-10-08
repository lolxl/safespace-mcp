// v1.89 — tamper-evident audit hash-chain tests.

import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test";
import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  auditEnd,
  auditRecipientDeniedEvent,
  auditSendApprovalEvent,
  canonicalJson,
  chainGenesis,
  computeRowMac,
  getOrCreateAuditSalt,
  auditChainCommitmentPath,
  readStrictCommitment,
  STRICT_MARKER_EVENT,
  strictChainGenesis,
  __drainAuditWrites,
  __resetChainState,
  type AuditEndContext,
} from "./audit";
import { verifyChain } from "./cli/audit/verify";
import { cliChainGenesis, walkStrictChain } from "./audit/cli-chain";

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
/** A log written before strict chains: `n` rows chained from the v1 genesis. */
async function writeV1Chain(n: number): Promise<void> {
  const salt = await getOrCreateAuditSalt();
  let prev = chainGenesis();
  const rows: Array<Record<string, unknown>> = [];
  for (let i = 0; i < n; i++) {
    const row: Record<string, unknown> = { ts: `2026-01-0${i + 1}T00:00:00.000Z`, tool: `v1_${i}`, status: "ok" };
    row.row_mac = computeRowMac(salt, prev, row);
    prev = row.row_mac as string;
    rows.push(row);
  }
  await writeLines(rows);
}
/** A fresh simulated server process (resumes from the file). */
async function restart(): Promise<void> {
  await __drainAuditWrites();
  __resetChainState();
}

describe("canonicalJson", () => {
  test("sorts object keys recursively (order-independent)", () => {
    const a = canonicalJson({ b: 1, a: { d: 2, c: 3 } });
    const b = canonicalJson({ a: { c: 3, d: 2 }, b: 1 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":{"c":3,"d":2},"b":1}');
  });
  test("keeps an own __proto__ member (as JSON.parse yields it) in the output", () => {
    const parsed = JSON.parse('{"a":1,"__proto__":{"x":1}}') as Record<string, unknown>;
    expect(canonicalJson(parsed)).toBe('{"__proto__":{"x":1},"a":1}');
    expect(canonicalJson(parsed)).not.toBe(canonicalJson({ a: 1 }));
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
  test("golden vector: rows already written keep their MAC (pinned before the __proto__ fix)", () => {
    const row = { ts: "2026-10-07T00:00:00.000Z", tool: "gmail_send", status: "ok", meta: { z: [1, { b: 2, a: "x" }], a: null, constructor: "c" }, n: 3.5 };
    expect(computeRowMac(Buffer.alloc(32, 9), "safespace-audit-chain/genesis/v1", row)).toBe(
      "c195fa4b25c5686d28ed978c99e0b30195d16f38dd31b57fa0d34e816cc3a62a",
    );
  });

  test("a different salt yields a different MAC (HMAC-keyed forgery resistance)", () => {
    const other = crypto.randomBytes(32);
    expect(computeRowMac(other, "p", { a: 1 })).not.toBe(computeRowMac(salt, "p", { a: 1 }));
  });
});

describe("auditEnd stamps + links the chain", () => {
  test("every row carries a row_mac; each links to the previous (strict genesis first)", async () => {
    await writeRows(3);
    const rows = await readLines();
    expect(rows).toHaveLength(3);
    const salt = await getOrCreateAuditSalt();
    let prev = strictChainGenesis();
    for (const r of rows) {
      expect(typeof r.row_mac).toBe("string");
      const { row_mac, ...rest } = r;
      expect(computeRowMac(salt, prev, rest)).toBe(row_mac as string); // recomputes
      prev = row_mac as string;
    }
  });
});

describe("strict chains (v2 genesis, or a v1 chain after its marker)", () => {
  test("a v1 log ending in an unchained approve row: restart, marker once, verify intact", async () => {
    await writeV1Chain(2);
    await fs.appendFile(auditPath(), JSON.stringify({ ts: "t", event: "send_approval_approved", pending_id: "old" }) + "\n");
    await restart();
    await auditEnd(ctx("gmail_search"));
    await restart();
    await auditEnd(ctx("gmail_send"));
    const r = await verifyChain(auditPath(), await getOrCreateAuditSalt());
    expect(r).toMatchObject({ ok: true, chainedRows: 5, unchainedEventRows: 1 });
    expect((await readLines()).filter((x) => x.event === STRICT_MARKER_EVENT)).toHaveLength(1);
  });

  test("after the marker, an inserted unchained event row is a break", async () => {
    await writeV1Chain(2);
    await restart();
    await writeRows(2);
    await fs.appendFile(auditPath(), JSON.stringify({ ts: "t", event: "send_approval_approved" }) + "\n");
    await auditEnd(ctx("gmail_send"));
    const r = await verifyChain(auditPath(), await getOrCreateAuditSalt());
    expect(r).toMatchObject({ ok: false, reason: "unhashed_in_strict_chain", brokenAt: 6 });
  });

  for (const [label, setup] of [
    ["a fresh (v2) chain", async () => writeRows(2)],
    ["a v1 chain after its marker", async () => { await writeV1Chain(1); await restart(); await writeRows(2); }],
  ] as const) {
    test(`relabel attack on the tail row of ${label} is detected after a restart`, async () => {
      await setup();
      const rows = await readLines();
      const tail: Record<string, unknown> = { ...rows[rows.length - 1]!, tool: "edited", event: "send_approval_approved" };
      delete tail.row_mac;
      await writeLines([...rows.slice(0, -1), tail]);
      await restart();
      await auditEnd(ctx("drive_search"));
      const r = await verifyChain(auditPath(), await getOrCreateAuditSalt());
      expect(r).toMatchObject({ ok: false, reason: "unhashed_in_strict_chain", brokenAt: rows.length });
    });
  }

  test("an unchained or unauthenticated marker is not a marker", async () => {
    await writeV1Chain(2);
    await fs.appendFile(auditPath(), JSON.stringify({ ts: "t", event: STRICT_MARKER_EVENT }) + "\n");
    await fs.appendFile(auditPath(), JSON.stringify({ ts: "t", event: STRICT_MARKER_EVENT, row_mac: "0".repeat(64) }) + "\n");
    await fs.appendFile(auditPath(), JSON.stringify({ ts: "t", event: "send_approval_approved" }) + "\n");
    // Still a tolerant v1 chain (only the forged MAC line breaks it) — and the server still owes its marker.
    const lines = (await fs.readFile(auditPath(), "utf8")).split("\n").filter((l) => l.length > 0);
    await fs.writeFile(auditPath(), [lines[0], lines[1], lines[2], lines[4]].join("\n") + "\n");
    expect(await verifyChain(auditPath(), await getOrCreateAuditSalt())).toMatchObject({ ok: true, unchainedEventRows: 2 });
    await restart();
    await auditEnd(ctx("gmail_search"));
    const markers = (await readLines()).filter((x) => x.event === STRICT_MARKER_EVENT && typeof x.row_mac === "string");
    expect(markers).toHaveLength(1);
  });

  test("deleting the marker breaks the chain", async () => {
    await writeV1Chain(2);
    await restart();
    await writeRows(2);
    const rows = await readLines();
    await writeLines(rows.filter((x) => x.event !== STRICT_MARKER_EVENT));
    const r = await verifyChain(auditPath(), await getOrCreateAuditSalt());
    expect(r).toMatchObject({ ok: false, reason: "mac_mismatch", brokenAt: 3 });
  });
});

describe("the strict commitment beside the salt (audit-chain.json)", () => {
  const verifyCommitted = async () =>
    verifyChain(auditPath(), await getOrCreateAuditSalt(), undefined, await readStrictCommitment());

  test("a fresh log commits to v2 after its first row; verify holds it", async () => {
    await writeRows(2);
    expect(await readStrictCommitment()).toMatchObject({ strict: "v2" });
    expect(await verifyCommitted()).toMatchObject({ ok: true, chainedRows: 2 });
  });

  test("an upgraded v1 log commits to its marker's MAC", async () => {
    await writeV1Chain(2);
    await restart();
    await writeRows(1);
    const marker = (await readLines()).find((x) => x.event === STRICT_MARKER_EVENT)!;
    expect(await readStrictCommitment()).toMatchObject({ strict: "v1", marker_mac: marker.row_mac as string });
    expect(await verifyCommitted()).toMatchObject({ ok: true, chainedRows: 4 });
  });

  test("stripping the only row of a v2 log and restarting is a break", async () => {
    await writeRows(1);
    const [row] = await readLines();
    const edited: Record<string, unknown> = { ...row!, tool: "edited", event: "send_approval_approved" };
    delete edited.row_mac;
    await writeLines([edited]);
    await restart();
    await auditEnd(ctx("drive_search"));
    expect(await verifyCommitted()).toMatchObject({ ok: false, reason: "strict_commitment_broken", brokenAt: 1 });
    const rows = await readLines();
    expect(rows.some((x) => x.event === STRICT_MARKER_EVENT)).toBe(false);
    const { row_mac, ...rest } = rows[1]!; // the new row restarts at v2, never v1
    expect(computeRowMac(await getOrCreateAuditSalt(), strictChainGenesis(), rest)).toBe(row_mac as string);
  });

  test("stripping every row of an upgraded v1 log and restarting is a break", async () => {
    await writeV1Chain(2);
    await restart();
    await writeRows(2);
    const stripped = (await readLines()).map((x) => {
      const y = { ...x, event: "send_approval_approved" };
      delete (y as Record<string, unknown>).row_mac;
      return y;
    });
    await writeLines(stripped);
    await restart();
    await auditEnd(ctx("drive_search"));
    expect(await verifyCommitted()).toMatchObject({ ok: false, reason: "strict_commitment_broken" });
    const markers = (await readLines()).filter((x) => x.event === STRICT_MARKER_EVENT && typeof x.row_mac === "string");
    expect(markers).toHaveLength(0); // no second marker once committed
  });

  test("cutting an upgraded log back past its marker is a break", async () => {
    await writeV1Chain(2);
    await restart();
    await writeRows(2);
    const rows = await readLines();
    await writeLines(rows.slice(0, 2));
    expect(await verifyCommitted()).toMatchObject({ ok: false, reason: "strict_commitment_broken" });
  });

  test("the commitment is never overwritten", async () => {
    await writeRows(1);
    await fs.writeFile(auditPath(), "");
    await writeV1Chain(1);
    await restart();
    await writeRows(1);
    expect(await readStrictCommitment()).toMatchObject({ strict: "v2" });
    expect(await verifyCommitted()).toMatchObject({ ok: false, reason: "strict_commitment_broken" });
  });

  test("emptying or replacing a committed v2 log is a break, also after the server writes again", async () => {
    await writeRows(2);
    await fs.writeFile(auditPath(), "");
    expect(await verifyCommitted()).toMatchObject({ ok: false, reason: "strict_commitment_broken" });
    await fs.writeFile(auditPath(), "not json\n");
    expect(await verifyCommitted()).toMatchObject({ ok: false, reason: "strict_commitment_broken" });
    await fs.writeFile(auditPath(), "");
    await restart();
    await writeRows(1); // a new v2 chain cannot stand in for the committed first row
    expect(await verifyCommitted()).toMatchObject({ ok: false, reason: "strict_commitment_broken" });
  });

  test("an unreadable commitment: the server keeps writing, verify reports it", async () => {
    await fs.mkdir(path.dirname(auditChainCommitmentPath()), { recursive: true });
    await fs.mkdir(auditChainCommitmentPath()); // EISDIR on read
    await writeRows(2);
    expect(await readLines()).toHaveLength(2);
    expect(await verifyCommitted()).toMatchObject({ ok: false, reason: "strict_commitment_broken" });
  });

  test("a fresh log holding only a crashed partial first line starts a v2 chain", async () => {
    await fs.writeFile(auditPath(), '{"ts":"x","tool":"hal');
    await writeRows(1);
    expect(await readStrictCommitment()).toMatchObject({ strict: "v2" });
    expect(await fs.readFile(auditPath(), "utf8")).not.toContain(STRICT_MARKER_EVENT);
  });

  test("a fresh log's committed first row whose append failed is re-appended exactly", async () => {
    await getOrCreateAuditSalt();
    await fs.writeFile(auditPath(), "", { mode: 0o400 });
    await auditEnd(ctx("first_call")); // committed, append fails
    const c = await readStrictCommitment();
    expect(c).toMatchObject({ strict: "v2", marker_row: { tool: "first_call" } });
    await fs.chmod(auditPath(), 0o600);
    await auditEnd(ctx("second_call"));
    const rows = await readLines();
    expect(rows.map((r) => r.tool)).toEqual(["first_call", "second_call"]);
    expect(rows[0]!.row_mac).toBe((c as { marker_mac: string }).marker_mac);
    expect(await verifyCommitted()).toMatchObject({ ok: true, chainedRows: 2 });
  });

  test("the commitment is written before the first row: if it cannot be, no row is written", async () => {
    await getOrCreateAuditSalt();
    await fs.writeFile(auditPath(), "", { mode: 0o600 });
    await fs.chmod(tmpDir, 0o500); // the commitment (temp file + link) cannot be created
    try {
      await writeRows(1);
    } finally {
      await fs.chmod(tmpDir, 0o700);
    }
    expect(await fs.readFile(auditPath(), "utf8")).toBe("");
    expect(await readStrictCommitment()).toBeNull();
    expect((await fs.readdir(tmpDir)).filter((f) => f.endsWith(".tmp"))).toEqual([]);
    await restart();
    await writeRows(1); // retried on the next write
    expect(await readStrictCommitment()).toMatchObject({ strict: "v2" });
    expect(await verifyCommitted()).toMatchObject({ ok: true, chainedRows: 1 });
  });

  test("a committed marker whose append failed is re-appended exactly on the next start", async () => {
    await writeV1Chain(2);
    await restart();
    await fs.chmod(auditPath(), 0o400); // the commitment lands, the marker append fails
    try {
      await writeRows(1);
    } finally {
      await fs.chmod(auditPath(), 0o600);
    }
    const c = await readStrictCommitment();
    expect(c).toMatchObject({ strict: "v1" });
    expect((await readLines()).some((x) => x.event === STRICT_MARKER_EVENT)).toBe(false);
    await restart();
    await writeRows(1);
    const marker = (await readLines()).find((x) => x.event === STRICT_MARKER_EVENT)!;
    expect(marker.row_mac).toBe((c as { marker_mac: string }).marker_mac);
    expect(await verifyCommitted()).toMatchObject({ ok: true, chainedRows: 4 });
  });

  test("a committed row that landed without its landed record: the next start records it", async () => {
    await writeRows(2);
    await fs.rm(`${auditChainCommitmentPath()}.landed`); // as if publishing it had failed
    await restart();
    await writeRows(1); // records the landing (the committed row is in the log)
    await fs.writeFile(auditPath(), "");
    await restart();
    await writeRows(1); // must NOT bring the committed first row back
    expect(await verifyCommitted()).toMatchObject({ ok: false, reason: "strict_commitment_broken" });
  });

  test("a commitment whose recorded row or predecessor disagrees is a break", async () => {
    await writeRows(2);
    const c = JSON.parse(await fs.readFile(auditChainCommitmentPath(), "utf8"));
    await fs.rm(auditChainCommitmentPath());
    await fs.writeFile(auditChainCommitmentPath(), JSON.stringify({ ...c, prev_mac: "0".repeat(64) }));
    expect(await verifyCommitted()).toMatchObject({ ok: false, reason: "strict_commitment_broken", brokenAt: 1 });
  });

  test("a filesystem without hard links: the commitment is still created and rows keep coming", async () => {
    const link = spyOn(fs, "link").mockImplementation(async () => {
      throw Object.assign(new Error("operation not supported"), { code: "ENOTSUP" });
    });
    try {
      await writeRows(3);
    } finally {
      link.mockRestore();
    }
    expect(await readLines()).toHaveLength(3);
    expect(await readStrictCommitment()).toMatchObject({ strict: "v2" });
    expect(await verifyCommitted()).toMatchObject({ ok: true, chainedRows: 3 });
  });

  test("a failing landed record never stops audit rows; the next start records it", async () => {
    const real = fs.link.bind(fs);
    const link = spyOn(fs, "link").mockImplementation(async (from, to) => {
      if (String(to).endsWith(".landed")) throw Object.assign(new Error("denied"), { code: "EACCES" });
      return real(from, to);
    });
    try {
      await writeRows(3);
    } finally {
      link.mockRestore();
    }
    expect(await readLines()).toHaveLength(3);
    await restart();
    await writeRows(1);
    await expect(fs.access(`${auditChainCommitmentPath()}.landed`)).resolves.toBeNull();
    expect(await verifyCommitted()).toMatchObject({ ok: true, chainedRows: 4 });
  });

  test("a transient landed failure is retried by the next write in the same process", async () => {
    const real = fs.link.bind(fs);
    let fail = true;
    const link = spyOn(fs, "link").mockImplementation(async (from, to) => {
      if (fail && String(to).endsWith(".landed")) throw Object.assign(new Error("busy"), { code: "EIO" });
      return real(from, to);
    });
    try {
      await writeRows(1);
      fail = false;
      await writeRows(1); // retries the record
    } finally {
      link.mockRestore();
    }
    await fs.writeFile(auditPath(), ""); // emptied before any restart
    await restart();
    await writeRows(1);
    expect(await verifyCommitted()).toMatchObject({ ok: false, reason: "strict_commitment_broken" });
  });

  test("an older log ending in unchained rows: a failed marker append is re-appended on restart", async () => {
    await writeV1Chain(2);
    await fs.appendFile(auditPath(), JSON.stringify({ ts: "t", event: "send_approval_approved" }) + "\n");
    await restart();
    await fs.chmod(auditPath(), 0o400); // commitment lands, the marker append fails
    try {
      await writeRows(1);
    } finally {
      await fs.chmod(auditPath(), 0o600);
    }
    expect(await readStrictCommitment()).toMatchObject({ strict: "v1", rows_after_prev: 1 });
    await restart();
    await writeRows(1);
    expect((await readLines()).filter((x) => x.event === STRICT_MARKER_EVENT)).toHaveLength(1);
    expect(await verifyCommitted()).toMatchObject({ ok: true, unchainedEventRows: 1 });
  });

  test("a record without rows_after_prev (an earlier build) still gets its marker re-appended", async () => {
    await writeV1Chain(2);
    await fs.appendFile(auditPath(), JSON.stringify({ ts: "t", event: "send_approval_approved" }) + "\n");
    await restart();
    await fs.chmod(auditPath(), 0o400);
    try {
      await writeRows(1);
    } finally {
      await fs.chmod(auditPath(), 0o600);
    }
    const c = JSON.parse(await fs.readFile(auditChainCommitmentPath(), "utf8"));
    delete c.rows_after_prev;
    await fs.rm(auditChainCommitmentPath());
    await fs.writeFile(auditChainCommitmentPath(), JSON.stringify(c));
    await restart();
    await writeRows(1);
    expect((await readLines()).filter((x) => x.event === STRICT_MARKER_EVENT)).toHaveLength(1);
    expect(await verifyCommitted()).toMatchObject({ ok: true });
  });

  test("verify --json reports strictLanded while a commitment exists", async () => {
    await writeRows(1);
    const out: string[] = [];
    const io = { out: (l: string) => out.push(l), err: () => {} };
    const { runCli } = await import("./cli");
    await runCli(["audit", "verify", "--json"], io);
    expect(JSON.parse(out[0]!)).toMatchObject({ ok: true, strictLanded: true });
    await fs.rm(`${auditChainCommitmentPath()}.landed`);
    out.length = 0;
    await runCli(["audit", "verify", "--json"], io);
    expect(JSON.parse(out[0]!)).toMatchObject({ ok: true, strictLanded: false });
    process.exitCode = 0;
  });

  test("a rewritten log after a missing landed record does not get the committed row back", async () => {
    await writeV1Chain(2);
    await restart();
    await writeRows(2);
    await fs.rm(`${auditChainCommitmentPath()}.landed`);
    const rows = await readLines();
    // drop the marker, keep the later rows as unchained events
    const rewritten = [rows[0]!, rows[1]!, ...rows.slice(3).map((x) => { const y = { ...x, event: "e" }; delete (y as Record<string, unknown>).row_mac; return y; })];
    await writeLines(rewritten);
    await restart();
    await writeRows(1);
    expect((await readLines()).some((x) => x.event === STRICT_MARKER_EVENT)).toBe(false);
    expect(await verifyCommitted()).toMatchObject({ ok: false, reason: "strict_commitment_broken" });
  });

  test("an unreadable or altered commitment file is a break", async () => {
    await writeRows(1);
    await fs.writeFile(auditChainCommitmentPath(), "{not json");
    expect(await verifyCommitted()).toMatchObject({ ok: false, reason: "strict_commitment_broken", brokenAt: 1 });
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

  test("ADDING a __proto__ member to a past row breaks the chain at that row", async () => {
    await writeRows(3);
    const lines = (await fs.readFile(auditPath(), "utf8")).split("\n");
    lines[1] = '{"__proto__":{"edited":true},' + lines[1]!.slice(1);
    await fs.writeFile(auditPath(), lines.join("\n"));
    const r = await verifyChain(auditPath(), await getOrCreateAuditSalt());
    expect(r.ok).toBe(false);
    expect(r.brokenAt).toBe(2);
    expect(r.reason).toBe("mac_mismatch");
  });

  test("ADDING a __proto__ member inside a nested object breaks the chain at that row", async () => {
    const salt = await getOrCreateAuditSalt();
    const row: Record<string, unknown> = { ts: "t", tool: "x", meta: { a: 1 } };
    row.row_mac = computeRowMac(salt, chainGenesis(), row);
    const line = JSON.stringify(row).replace('"meta":{"a":1}', '"meta":{"__proto__":{"edited":true},"a":1}');
    await fs.writeFile(auditPath(), line + "\n");
    const r = await verifyChain(auditPath(), salt);
    expect(r).toMatchObject({ ok: false, brokenAt: 1, reason: "mac_mismatch" });
  });

  test("ADDING a __proto__ member to a CLI-chain row breaks the strict walk", async () => {
    const salt = await getOrCreateAuditSalt();
    const file = path.join(tmpDir, "audit-cli.jsonl");
    const row: Record<string, unknown> = { ts: "t", tool: "web_fetch", status: "ok" };
    row.row_mac = computeRowMac(salt, cliChainGenesis(), row);
    await fs.writeFile(file, '{"__proto__":{"edited":true},' + JSON.stringify(row).slice(1) + "\n");
    expect(await walkStrictChain(file, salt, cliChainGenesis())).toMatchObject({ ok: false, brokenAt: 1, reason: "mac_mismatch" });
  });

  test("an errorForensics value that is not a scalar is not copied into the row", async () => {
    const forensics = JSON.parse('{"rejected_formula_function":{"__proto__":{"x":1}},"rejected_formula_nested":true}');
    await auditEnd({ ...ctx("sheets_update_values"), status: "error", errorForensics: forensics });
    const [row] = await readLines();
    expect("rejected_formula_function" in row!).toBe(false);
    expect(row!.rejected_formula_nested).toBe(true);
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
    expect(r.reason).toBe("unhashed_in_strict_chain");
  });

  test("a v1 chain: an unhashed row with no event field mid-chain is flagged", async () => {
    await writeV1Chain(3);
    const rows = await readLines();
    rows.splice(1, 0, { ts: "x", tool: "injected" });
    await writeLines(rows);
    const r = await verifyChain(auditPath(), await getOrCreateAuditSalt());
    expect(r).toMatchObject({ ok: false, brokenAt: 2, reason: "unhashed_after_chain" });
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

  test("a legacy unhashed PREFIX is tolerated; the chain starts at v1 with the strict marker", async () => {
    // Simulate pre-chain rows (no row_mac), then start the chain.
    await writeLines([{ ts: "t0", tool: "legacy_a" }, { ts: "t1", tool: "legacy_b" }]);
    await writeRows(2); // the marker, then 2 chained rows after the legacy prefix
    const r = await verifyChain(auditPath(), await getOrCreateAuditSalt());
    expect(r).toMatchObject({ ok: true, legacyRows: 2, chainedRows: 3 });
    const rows = await readLines();
    expect(rows.filter((x) => x.event === STRICT_MARKER_EVENT)).toHaveLength(1);
    expect(rows[2]!.event).toBe(STRICT_MARKER_EVENT);
  });

  test("an unhashed PREFIX before a strict chain is flagged", async () => {
    await writeRows(2);
    const rows = await readLines();
    await writeLines([{ ts: "t0", event: "x" }, ...rows]);
    const r = await verifyChain(auditPath(), await getOrCreateAuditSalt());
    expect(r).toMatchObject({ ok: false, brokenAt: 1, reason: "unhashed_in_strict_chain" });
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

  // v1.111 (#3) — an unchained row carrying an `event` field, interleaved AFTER the
  // chain started, is a LEGITIMATELY-unchained row (the CLI's send-approval
  // approved/denied actions; a separate writer process). It must be TOLERATED, not
  // reported as a false BROKEN. (Contrast: the "INSERTING an unhashed row mid-chain"
  // test above — a row with NO event field — stays a break.)
  test("a v1 chain: an unchained EVENT row interleaved mid-chain is TOLERATED (not false-BROKEN)", async () => {
    await writeV1Chain(2); // 2 chained rows of a pre-strict log
    const rows = await readLines();
    // a CLI send-approval row: has `event`, no `row_mac` (a separate writer process)
    rows.splice(1, 0, { ts: "t", event: "send_approval_approved", tool: "gmail_send" });
    await writeLines(rows);
    const r = await verifyChain(auditPath(), await getOrCreateAuditSalt());
    expect(r.ok).toBe(true);
    expect(r.chainedRows).toBe(2);
    expect(r.unchainedEventRows).toBe(1);
    expect(r.brokenAt).toBeNull();
  });

  // v1.111 (#3) — the server-process forensic appenders (recipient-denied, share,
  // webhook, cross-account) now join the tamper-evident chain, closing the deletion
  // gap on exactly the denial rows an attacker would strip. The appender row carries
  // a row_mac and the chain verifies end-to-end through it.
  test("server-process appender rows join the chain (recipient-denied chained + verifies)", async () => {
    await auditEnd(ctx("gmail_search"));
    await auditRecipientDeniedEvent({
      tool: "gmail_send",
      email: "alice@example.com",
      rejected_recipient_hashes: [],
      rejected_count: 1,
      total_recipients: 1,
      duration_ms: 1,
    });
    await auditEnd(ctx("gmail_search"));
    const rows = await readLines();
    expect(rows).toHaveLength(3);
    expect(rows[1]!.event).toBe("recipient_denied_by_policy");
    expect(rows.every((r) => typeof r.row_mac === "string")).toBe(true); // appender now chained
    const r = await verifyChain(auditPath(), await getOrCreateAuditSalt());
    expect(r.ok).toBe(true);
    expect(r.chainedRows).toBe(3);
    expect(r.unchainedEventRows).toBe(0);
  });

  // Every send-approval row joins the WRITING process's chain (the server's here); the
  // CLI's approved/denied go to audit-cli.jsonl (audit-cli-chain.test.ts). A legacy
  // unchained approved row in an existing log is still tolerated by verify.
  test("send-approval rows join the server chain; an unchained approve row in a strict chain is a break", async () => {
    const base = {
      pending_id: "p1",
      tool: "gmail_send",
      fingerprint: "fp",
      recipients: ["x@example.com"],
      operator: "",
    };
    await auditEnd(ctx("gmail_search"));
    await auditSendApprovalEvent({ ...base, event: "pending" });
    await auditSendApprovalEvent({ ...base, event: "approved" });
    // In a strict chain an unchained approve row (as older CLI versions wrote) is a break.
    await fs.appendFile(auditPath(), JSON.stringify({ ts: "2026-01-01T00:00:00.000Z", event: "send_approval_denied", pending_id: "old" }) + "\n");
    await auditEnd(ctx("gmail_search"));
    const rows = await readLines();
    const pending = rows.find((r) => r.event === "send_approval_pending")!;
    const approved = rows.find((r) => r.event === "send_approval_approved")!;
    expect(typeof pending.row_mac).toBe("string");
    expect(typeof approved.row_mac).toBe("string");
    const r = await verifyChain(auditPath(), await getOrCreateAuditSalt());
    expect(r).toMatchObject({ ok: false, brokenAt: 4, reason: "unhashed_in_strict_chain" });
  });

  test("public-write pending records target_hash, never the target plaintext", async () => {
    await auditSendApprovalEvent({
      event: "pending",
      pending_id: "p2",
      tool: "x_post_create",
      fingerprint: "fp2",
      recipients: [],
      operator: "",
      target: { kind: "x_post", account_id: "2244994945" },
    });
    const rows = await readLines();
    const pending = rows.find((r) => r.event === "send_approval_pending" && r.pending_id === "p2")!;
    expect(typeof pending.target_hash).toBe("string");
    expect((pending.target_hash as string)).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(pending)).not.toContain("2244994945");
    expect(pending.account_id).toBeUndefined();
  });
});
