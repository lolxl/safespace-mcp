// Two audit chains: audit.jsonl (the server) and audit-cli.jsonl (CLI processes), plus
// the server's anchors of the CLI chain's verified tip. docs/AUDIT-CHAIN.md.
//
// A "process" here is simulated by `__resetChainState()` (fresh per-process state) and
// `setAuditChainRole()`.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  __drainAuditWrites,
  __resetChainState,
  auditEnd,
  auditSendApprovalEvent,
  getOrCreateAuditSalt,
  setAuditChainRole,
  type AuditEndContext,
} from "./audit";
import { runCli, type CliIO } from "./cli";
import { cliChainGenesis, countRows, rawLines, READ_CHUNK, resumeTip, walkStrictChain } from "./audit/cli-chain";
import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";

let tmpDir: string;
let prevEnv: string | undefined;
let prevExitCode: number;
const serverFile = () => path.join(tmpDir, "audit.jsonl");
const cliFile = () => path.join(tmpDir, "audit-cli.jsonl");

beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  prevExitCode = (process.exitCode as number | undefined) ?? 0;
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-cli-chain-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
});
afterEach(async () => {
  await __drainAuditWrites();
  __resetChainState();
  process.exitCode = prevExitCode;
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

/** Start a fresh simulated process in `role`. */
async function asProcess(role: "server" | "cli"): Promise<void> {
  await __drainAuditWrites();
  __resetChainState();
  setAuditChainRole(role);
}

async function lines(file: string): Promise<Array<Record<string, unknown>>> {
  try {
    const text = await fs.readFile(file, "utf8");
    return text.split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}

function capture(): { io: CliIO; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return { io: { out: (l) => out.push(l), err: (l) => err.push(l) }, out, err };
}

async function verifyJson(): Promise<Record<string, unknown>> {
  const { io, out } = capture();
  await runCli(["audit", "verify", "--json"], io);
  return JSON.parse(out[0]!);
}

/** server row -> exec rows -> next server process row. */
async function serverThenCliThenServer(): Promise<void> {
  await asProcess("server");
  await auditEnd(ctx("gmail_search"));
  await asProcess("cli");
  await auditEnd(ctx("web_fetch"));
  await auditEnd(ctx("fs_read"));
  await asProcess("server");
  await auditEnd(ctx("gmail_send"));
}

describe("two chain files", () => {
  test("a CLI process writes audit-cli.jsonl (chained), never audit.jsonl", async () => {
    await asProcess("cli");
    await auditEnd(ctx("web_fetch"));
    await auditSendApprovalEvent({ event: "approved", pending_id: "p", tool: "gmail_send", fingerprint: "f", recipients: [], operator: "" });
    expect(await lines(serverFile())).toEqual([]);
    const rows = await lines(cliFile());
    expect(rows.map((r) => r.tool)).toEqual(["web_fetch", "gmail_send"]);
    expect(rows.every((r) => typeof r.row_mac === "string")).toBe(true);
  });

  test("server -> exec -> server: both chains and the anchor verify", async () => {
    await serverThenCliThenServer();
    const server = await lines(serverFile());
    expect(server.map((r) => r.event ?? r.tool)).toEqual(["gmail_search", "cli_chain_anchor", "gmail_send"]);
    const r = await verifyJson();
    expect(r.ok).toBe(true);
    expect(r.cli).toMatchObject({ ok: true, chainedRows: 2, anchors: 1, anchorsMissing: 0 });
  });

  test("editing a CLI row breaks the CLI chain", async () => {
    await serverThenCliThenServer();
    const text = await fs.readFile(cliFile(), "utf8");
    await fs.writeFile(cliFile(), text.replace('"tool":"fs_read"', '"tool":"fs_reed"'));
    const r = await verifyJson();
    expect(r.ok).toBe(false);
    expect(r.cli).toMatchObject({ ok: false, reason: "mac_mismatch", brokenAt: 2 });
  });

  for (const [label, damage] of [
    ["deleted", () => fs.rm(cliFile())],
    ["emptied", () => fs.writeFile(cliFile(), "")],
    ["cut to its first row", async () => {
      const [first] = (await fs.readFile(cliFile(), "utf8")).split("\n");
      await fs.writeFile(cliFile(), first + "\n");
    }],
  ] as const) {
    test(`an anchored CLI file ${label} -> cli_anchor_missing`, async () => {
      await serverThenCliThenServer();
      await damage();
      const r = await verifyJson();
      expect(r.ok).toBe(false);
      expect(r.cli).toMatchObject({ ok: false, reason: "cli_anchor_missing", anchorsMissing: 1 });
    });
  }

  test("a junk tail does not suppress the anchor; removing it and deleting the file is caught", async () => {
    await asProcess("cli");
    await auditEnd(ctx("web_fetch"));
    await fs.appendFile(cliFile(), "{}\n"); // attacker junk before the next server start
    await asProcess("server");
    await auditEnd(ctx("gmail_search"));
    const anchor = (await lines(serverFile())).find((r) => r.event === "cli_chain_anchor")!;
    expect(typeof anchor.cli_tip_mac).toBe("string"); // the verified prefix's tip
    await fs.rm(cliFile());
    expect((await verifyJson()).cli).toMatchObject({ reason: "cli_anchor_missing" });
  });

  test("a CLI file in which nothing verifies gets no anchor; the strict walk still fails verify", async () => {
    await fs.writeFile(cliFile(), "{}\n");
    await asProcess("server");
    await auditEnd(ctx("gmail_search"));
    expect((await lines(serverFile())).some((r) => r.event === "cli_chain_anchor")).toBe(false);
    const r = await verifyJson();
    expect(r.ok).toBe(false);
    expect(r.cli).toMatchObject({ reason: "unhashed_row" });
  });

  test("a CLI row still being written: the verified prefix is sealed now, the completed row later", async () => {
    await asProcess("cli");
    await auditEnd(ctx("web_fetch"));
    await auditEnd(ctx("fs_read"));
    const full = await fs.readFile(cliFile(), "utf8");
    const cut = full.length - 20;
    await fs.writeFile(cliFile(), full.slice(0, cut)); // second row half-written
    await asProcess("server");
    await auditEnd(ctx("gmail_search"));
    const cliRows = () => lines(cliFile());
    let anchors = (await lines(serverFile())).filter((r) => r.event === "cli_chain_anchor");
    expect(anchors.map((a) => a.cli_tip_mac)).toEqual([(await (async () => {
      const t = await fs.readFile(cliFile(), "utf8");
      return JSON.parse(t.split("\n")[0]!).row_mac;
    })())]);
    await fs.writeFile(cliFile(), full); // the write completes
    await auditEnd(ctx("gmail_send")); // same server process retries
    anchors = (await lines(serverFile())).filter((r) => r.event === "cli_chain_anchor");
    expect(anchors.map((a) => a.cli_tip_mac)).toEqual([(await cliRows())[0]!.row_mac, (await cliRows())[1]!.row_mac]);
    expect((await verifyJson()).ok).toBe(true);
  });

  test("an unterminated junk tail cannot suppress sealing; cutting the sealed rows is caught", async () => {
    await asProcess("cli");
    await auditEnd(ctx("web_fetch"));
    await auditEnd(ctx("fs_read"));
    await fs.appendFile(cliFile(), "x");
    await asProcess("server");
    await auditEnd(ctx("gmail_search"));
    await auditEnd(ctx("gmail_send"));
    const anchors = (await lines(serverFile())).filter((r) => r.event === "cli_chain_anchor");
    expect(anchors).toHaveLength(1); // the verified tip, sealed once (no spam)
    const [first] = (await fs.readFile(cliFile(), "utf8")).split("\n");
    await fs.writeFile(cliFile(), first + "\n");
    expect((await verifyJson()).cli).toMatchObject({ reason: "cli_anchor_missing" });
  });

  test("a failed anchor append is retried by the next server write", async () => {
    if ((process.getuid?.() ?? 1) === 0) return; // permission test is meaningless as root
    await asProcess("cli");
    await auditEnd(ctx("web_fetch"));
    await fs.writeFile(serverFile(), "");
    await fs.chmod(serverFile(), 0o400);
    await asProcess("server");
    await auditEnd(ctx("gmail_search")); // append fails (logged, swallowed)
    await fs.chmod(serverFile(), 0o600);
    await auditEnd(ctx("gmail_send"));
    const server = await lines(serverFile());
    expect(server.map((r) => r.event ?? r.tool)).toEqual(["cli_chain_anchor", "gmail_send"]);
    expect((await verifyJson()).ok).toBe(true);
  });

  test("an unreadable CLI file stays due past the retry cap and is sealed once readable", async () => {
    await asProcess("cli");
    await auditEnd(ctx("web_fetch"));
    await fs.chmod(cliFile(), 0o000);
    await asProcess("server");
    for (let i = 0; i < 25; i++) await auditEnd(ctx("gmail_search"));
    await fs.chmod(cliFile(), 0o600);
    expect((await lines(serverFile())).some((r) => r.event === "cli_chain_anchor")).toBe(false);
    await auditEnd(ctx("gmail_send"));
    expect((await lines(serverFile())).filter((r) => r.event === "cli_chain_anchor")).toHaveLength(1);
    await fs.rm(cliFile());
    expect((await verifyJson()).cli).toMatchObject({ ok: false, reason: "cli_anchor_missing" });
  });

  test("two anchors of one deleted tip are both reported missing", async () => {
    await serverThenCliThenServer();
    await asProcess("server");
    await auditEnd(ctx("gmail_search"));
    await fs.rm(cliFile());
    expect((await verifyJson()).cli).toMatchObject({ anchors: 2, anchorsMissing: 2 });
  });

  test("a first CLI row still being written defers the anchor (no permanent failure)", async () => {
    await fs.writeFile(cliFile(), '{"partial');
    await asProcess("server");
    await auditEnd(ctx("gmail_search"));
    expect((await lines(serverFile())).some((r) => r.event === "cli_chain_anchor")).toBe(false);
  });

  test("repeated anchors of one tip (restarts with no new CLI rows) verify", async () => {
    await serverThenCliThenServer();
    await asProcess("server");
    await auditEnd(ctx("gmail_search"));
    const r = await verifyJson();
    expect(r.ok).toBe(true);
    expect(r.cli).toMatchObject({ anchors: 2, anchorsMissing: 0 });
  });

  test("after a junk line, several CLI processes keep chaining; removing the junk repairs it", async () => {
    await asProcess("cli");
    await auditEnd(ctx("web_fetch"));
    await fs.appendFile(cliFile(), "not json\n");
    for (const tool of ["fs_read", "gmail_search", "drive_search"]) {
      await asProcess("cli");
      await auditEnd(ctx(tool));
    }
    const text = await fs.readFile(cliFile(), "utf8");
    await fs.writeFile(cliFile(), text.replace("not json\n", ""));
    expect((await verifyJson()).cli).toMatchObject({ ok: true, chainedRows: 4 });
  });

  test("a fork from overlapping CLI processes is repaired by removing ONE row", async () => {
    await asProcess("cli");
    await auditEnd(ctx("web_fetch")); // A
    const afterA = await fs.readFile(cliFile(), "utf8");
    await auditEnd(ctx("fs_read")); // B (prev A)
    const lineB = (await fs.readFile(cliFile(), "utf8")).slice(afterA.length);
    await fs.writeFile(cliFile(), afterA);
    await asProcess("cli");
    await auditEnd(ctx("gmail_search")); // C (prev A)
    await fs.appendFile(cliFile(), lineB); // file: A, C, B — B and C both chain to A
    await asProcess("cli");
    await auditEnd(ctx("drive_search")); // D: B does not authenticate after C, so D chains to C
    expect((await verifyJson()).cli).toMatchObject({ ok: false, reason: "mac_mismatch", brokenAt: 3 });
    const rows = (await fs.readFile(cliFile(), "utf8")).split("\n").filter((l) => l.length > 0);
    await fs.writeFile(cliFile(), [rows[0], rows[1], rows[3]].join("\n") + "\n"); // drop B
    expect((await verifyJson()).cli).toMatchObject({ ok: true, chainedRows: 3 });
  });

  test("a forged {row_mac: <older MAC>} line is not resumed from (deleting B stays detectable)", async () => {
    await asProcess("cli");
    await auditEnd(ctx("web_fetch")); // A
    const macA = (await lines(cliFile()))[0]!.row_mac;
    await auditEnd(ctx("fs_read")); // B
    await fs.appendFile(cliFile(), JSON.stringify({ row_mac: macA }) + "\n");
    await asProcess("cli");
    await auditEnd(ctx("gmail_search")); // C must chain to B, not to the forged A
    const rows = (await fs.readFile(cliFile(), "utf8")).split("\n").filter((l) => l.length > 0);
    await fs.writeFile(cliFile(), [rows[0], rows[3]].join("\n") + "\n"); // attacker drops B + forgery
    expect((await verifyJson()).cli).toMatchObject({ ok: false, reason: "mac_mismatch", brokenAt: 2 });
    await fs.writeFile(cliFile(), [rows[0], rows[1], rows[3]].join("\n") + "\n"); // drop only the forgery
    expect((await verifyJson()).cli).toMatchObject({ ok: true, chainedRows: 3 });
  });

  test("a replayed older row after a forged predecessor is not resumed from (deleting C stays detectable)", async () => {
    await asProcess("cli");
    await auditEnd(ctx("web_fetch")); // A
    await auditEnd(ctx("fs_read")); // B
    await auditEnd(ctx("gmail_search")); // C
    const [rowA, rowB] = (await fs.readFile(cliFile(), "utf8")).split("\n");
    const macA = JSON.parse(rowA!).row_mac;
    await fs.appendFile(cliFile(), JSON.stringify({ row_mac: macA }) + "\n" + rowB + "\n"); // B now "authenticates"
    await asProcess("cli");
    await auditEnd(ctx("drive_search")); // D must chain to C, not to the replayed B
    const rows = (await fs.readFile(cliFile(), "utf8")).split("\n").filter((l) => l.length > 0);
    await fs.writeFile(cliFile(), [rows[0], rows[1], rows[5]].join("\n") + "\n"); // attacker drops C + plants
    expect((await verifyJson()).cli).toMatchObject({ ok: false, reason: "mac_mismatch", brokenAt: 3 });
    await fs.writeFile(cliFile(), [rows[0], rows[1], rows[2], rows[5]].join("\n") + "\n"); // drop only the plants
    expect((await verifyJson()).cli).toMatchObject({ ok: true, chainedRows: 4 });
  });

  test("a valid last row missing only its newline is resumed from and terminated", async () => {
    await asProcess("cli");
    await auditEnd(ctx("web_fetch"));
    await auditEnd(ctx("fs_read"));
    const t = await fs.readFile(cliFile(), "utf8");
    await fs.writeFile(cliFile(), t.slice(0, -1));
    await asProcess("cli");
    await auditEnd(ctx("gmail_search"));
    expect((await verifyJson()).cli).toMatchObject({ ok: true, chainedRows: 3 });
  });

  test("the server continues past a partial final line in audit.jsonl", async () => {
    await asProcess("server");
    await auditEnd(ctx("gmail_search"));
    await fs.appendFile(serverFile(), '{"ts":"x","tool":"half');
    await asProcess("server");
    await auditEnd(ctx("gmail_send"));
    const raw = await fs.readFile(serverFile(), "utf8");
    await fs.writeFile(serverFile(), raw.replace('{"ts":"x","tool":"half\n', ""));
    expect((await verifyJson()).ok).toBe(true);
  });

  test("a CLI write never glues onto a partial final line", async () => {
    await asProcess("cli");
    await auditEnd(ctx("web_fetch"));
    await fs.appendFile(cliFile(), '{"partial');
    await asProcess("cli");
    await auditEnd(ctx("fs_read"));
    const raw = await fs.readFile(cliFile(), "utf8");
    expect(raw.split("\n")[1]).toBe('{"partial');
    await fs.writeFile(cliFile(), raw.replace('{"partial\n', ""));
    expect((await verifyJson()).cli).toMatchObject({ ok: true, chainedRows: 2 });
  });

  test("a CLI process resumes from the verified prefix: removing a junk line repairs the chain", async () => {
    await asProcess("cli");
    await auditEnd(ctx("web_fetch"));
    await fs.appendFile(cliFile(), "not json\n");
    await asProcess("cli");
    await auditEnd(ctx("fs_read")); // chained from web_fetch's MAC, not genesis
    const text = await fs.readFile(cliFile(), "utf8");
    await fs.writeFile(cliFile(), text.replace("not json\n", ""));
    const r = await verifyJson();
    expect(r.ok).toBe(true);
    expect(r.cli).toMatchObject({ chainedRows: 2 });
  });

  test("the CLI walk is strict: an inserted unhashed event row breaks it", async () => {
    await asProcess("cli");
    await auditEnd(ctx("web_fetch"));
    await fs.appendFile(cliFile(), JSON.stringify({ ts: "2026-01-01T00:00:00.000Z", event: "send_approval_approved" }) + "\n");
    expect((await verifyJson()).cli).toMatchObject({ ok: false, reason: "unhashed_row", brokenAt: 2 });
  });

  test("an incomplete final CLI line fails verify", async () => {
    await asProcess("cli");
    await auditEnd(ctx("web_fetch"));
    const text = await fs.readFile(cliFile(), "utf8");
    await fs.writeFile(cliFile(), text.slice(0, -1)); // newline stripped
    expect((await verifyJson()).cli).toMatchObject({ ok: false, reason: "incomplete_tail" });
  });

  test("a CLI file copied over audit.jsonl breaks at row 1 (distinct genesis)", async () => {
    await asProcess("cli");
    await auditEnd(ctx("web_fetch"));
    await fs.copyFile(cliFile(), serverFile());
    const r = await verifyJson();
    expect(r).toMatchObject({ ok: false, brokenAt: 1, reason: "mac_mismatch" });
  });

  test("an unchained cli_chain_anchor row inserted into audit.jsonl is not an anchor", async () => {
    await asProcess("server");
    await auditEnd(ctx("gmail_search"));
    await fs.appendFile(serverFile(), JSON.stringify({ event: "cli_chain_anchor", cli_tip_mac: "f".repeat(64) }) + "\n");
    const r = await verifyJson();
    expect(r).toMatchObject({ ok: false, reason: "unhashed_in_strict_chain" }); // and no anchor counted:
    expect("cli" in r).toBe(false);
  });

  test("the server resumes from a valid last row missing only its newline", async () => {
    await asProcess("server");
    await auditEnd(ctx("gmail_search"));
    await auditEnd(ctx("gmail_send"));
    const t = await fs.readFile(serverFile(), "utf8");
    await fs.writeFile(serverFile(), t.slice(0, -1));
    await asProcess("server");
    await auditEnd(ctx("drive_search"));
    expect(await verifyJson()).toMatchObject({ ok: true, chainedRows: 3 });
  });

  test("a planted or replayed server line cannot steer the restart point", async () => {
    await asProcess("server");
    await auditEnd(ctx("gmail_search")); // A
    await auditEnd(ctx("gmail_send")); // B
    await auditEnd(ctx("drive_search")); // C
    const [rowA, rowB] = (await fs.readFile(serverFile(), "utf8")).split("\n");
    const macA = JSON.parse(rowA!).row_mac;
    await fs.appendFile(serverFile(), JSON.stringify({ row_mac: macA }) + "\n" + rowB + "\n");
    await asProcess("server");
    await auditEnd(ctx("drive_list")); // D must chain to C
    const rows = (await fs.readFile(serverFile(), "utf8")).split("\n").filter((l) => l.length > 0);
    await fs.writeFile(serverFile(), [rows[0], rows[1], rows[5]].join("\n") + "\n"); // drop C + plants
    expect(await verifyJson()).toMatchObject({ ok: false, reason: "mac_mismatch" });
    await fs.writeFile(serverFile(), [rows[0], rows[1], rows[2], rows[5]].join("\n") + "\n"); // drop the plants
    expect(await verifyJson()).toMatchObject({ ok: true, chainedRows: 4 });
  });

  test("relabel attack on a server tail row is still detected after a restart", async () => {
    await asProcess("server");
    await auditEnd(ctx("gmail_search"));
    await auditEnd(ctx("gmail_send"));
    const rows = await lines(serverFile());
    const tail: Record<string, unknown> = { ...rows[1]!, tool: "edited", event: "send_approval_approved" };
    delete tail.row_mac;
    await fs.writeFile(serverFile(), JSON.stringify(rows[0]) + "\n" + JSON.stringify(tail) + "\n");
    await asProcess("server");
    await auditEnd(ctx("drive_search"));
    expect((await verifyJson()).ok).toBe(false);
  });

  test("relabel attack on a server tail row with its newline removed is still detected", async () => {
    await asProcess("server");
    await auditEnd(ctx("gmail_search"));
    await auditEnd(ctx("gmail_send"));
    const rows = await lines(serverFile());
    const tail: Record<string, unknown> = { ...rows[1]!, tool: "edited", event: "send_approval_approved" };
    delete tail.row_mac;
    await fs.writeFile(serverFile(), JSON.stringify(rows[0]) + "\n" + JSON.stringify(tail));
    await asProcess("server");
    await auditEnd(ctx("drive_search"));
    expect((await verifyJson()).ok).toBe(false);
  });

  test("relabel attack followed by a large push and a replayed row is still detected", async () => {
    await asProcess("server");
    await auditEnd(ctx("gmail_search"));
    await auditEnd(ctx("gmail_send"));
    const raw0 = await fs.readFile(serverFile(), "utf8");
    const [rowA] = raw0.split("\n");
    const rows = await lines(serverFile());
    const tail: Record<string, unknown> = { ...rows[1]!, tool: "edited", event: "send_approval_approved" };
    delete tail.row_mac;
    const push = "z".repeat(70000) + "\n" + rowA + "\n";
    await fs.writeFile(serverFile(), rowA + "\n" + JSON.stringify(tail) + "\n" + push);
    await asProcess("server");
    await auditEnd(ctx("drive_search"));
    const raw = await fs.readFile(serverFile(), "utf8");
    await fs.writeFile(serverFile(), raw.replace(push, ""));
    expect((await verifyJson()).ok).toBe(false);
  });

  test("relabel attack padded to a very long line is still detected", async () => {
    await asProcess("server");
    await auditEnd(ctx("gmail_search"));
    await auditEnd(ctx("gmail_send"));
    const rows = await lines(serverFile());
    const tail: Record<string, unknown> = { ...rows[1]!, tool: "edited", event: "send_approval_approved" };
    delete tail.row_mac;
    const padded = "{" + " ".repeat(2 * 1024 * 1024) + JSON.stringify(tail).slice(1);
    await fs.writeFile(serverFile(), JSON.stringify(rows[0]) + "\n" + padded + "\n");
    await asProcess("server");
    await auditEnd(ctx("drive_search"));
    expect((await verifyJson()).ok).toBe(false);
  });

  test("a lone carriage return splits lines for the writer exactly as for verify", async () => {
    await asProcess("server");
    await auditEnd(ctx("gmail_search"));
    await auditEnd(ctx("gmail_send"));
    const rows = await lines(serverFile());
    const tail: Record<string, unknown> = { ...rows[1]!, tool: "edited", event: "send_approval_approved" };
    delete tail.row_mac;
    const CR = String.fromCharCode(13);
    await fs.writeFile(serverFile(), JSON.stringify(rows[0]) + "\n" + JSON.stringify(tail) + CR + '{"event":"x"}\n');
    await asProcess("server");
    await auditEnd(ctx("drive_search"));
    expect((await verifyJson()).ok).toBe(false);
  });

  test("verify reports a row too deeply nested to canonicalize as a mismatch", async () => {
    await asProcess("server");
    await auditEnd(ctx("gmail_search"));
    await fs.appendFile(serverFile(), '{"row_mac":"00","x":' + "[".repeat(200000) + "]".repeat(200000) + "}\n");
    expect(await verifyJson()).toMatchObject({ ok: false, reason: "mac_mismatch", brokenAt: 2 });
  });

  test("a row too deeply nested to canonicalize does not end the resume walk", async () => {
    await asProcess("cli");
    await auditEnd(ctx("web_fetch")); // A
    const deep = '{"row_mac":"00","x":' + "[".repeat(200000) + "]".repeat(200000) + "}\n";
    await fs.appendFile(cliFile(), deep);
    await asProcess("cli");
    await auditEnd(ctx("fs_read")); // B, chains to A
    await asProcess("cli");
    await auditEnd(ctx("gmail_search")); // C must chain to B, not to A
    const raw = await fs.readFile(cliFile(), "utf8");
    await fs.writeFile(cliFile(), raw.replace(deep, ""));
    expect((await verifyJson()).cli).toMatchObject({ ok: true, chainedRows: 3 });
  });

  test("a CRLF split across a read-chunk boundary is one line ending", async () => {
    const rowLength = async (k: number): Promise<number> => {
      await fs.rm(cliFile(), { force: true });
      await asProcess("cli");
      await auditEnd(ctx("t".repeat(k)));
      return (await fs.readFile(cliFile(), "utf8")).length - 1;
    };
    const l1 = await rowLength(1);
    const perChar = (await rowLength(2)) - l1;
    await rowLength(1 + (READ_CHUNK - 1 - l1) / perChar); // the row ends at the read chunk's last byte
    const row = (await fs.readFile(cliFile(), "utf8")).slice(0, -1);
    expect(row.length).toBe(READ_CHUNK - 1);
    const CR = String.fromCharCode(13);
    await fs.writeFile(cliFile(), row + CR + "\n");
    const salt = await getOrCreateAuditSalt();
    expect(await walkStrictChain(cliFile(), salt, cliChainGenesis())).toMatchObject({ ok: true, chainedRows: 1 });
    expect(await resumeTip(cliFile(), salt, cliChainGenesis())).toBe(JSON.parse(row).row_mac);
  });

  test("a row holding U+2028 / U+2029 is one row for the writers and for verify", async () => {
    await asProcess("server");
    await auditEnd(ctx("gmail_search\u2028x\u2029y"));
    await asProcess("server");
    await auditEnd(ctx("gmail_send"));
    const raw = await fs.readFile(serverFile(), "utf8");
    expect(raw.includes("\u2028")).toBe(true); // JSON.stringify leaves it raw
    expect(await verifyJson()).toMatchObject({ ok: true, chainedRows: 2 });
  });

  test("rawLines splits \\r / \\n line endings exactly as node:readline does", async () => {
    const CR = String.fromCharCode(13);
    const alphabet = ["a", "b", " ", "\t", "\n", CR, CR + "\n", "{}"];
    let seed = 7;
    // 32-bit LCG in exact integer arithmetic, sampled from its high bits (the low bits of a
    // power-of-two LCG cycle quickly, and a float product would lose precision).
    const rand = (n: number) => ((seed = (Math.imul(seed, 1103515245) + 12345) >>> 0) >>> 16) % n;
    // Fixed edge cases first (a "\r" ending a 64 KiB chunk, then something other than
    // "\n"; a file ending in a lone "\r", after text or as an empty last line), then random
    // multi-chunk files.
    const C = READ_CHUNK;
    const texts = ["x".repeat(C - 1) + CR + "y\n", "x".repeat(C - 1) + CR + CR + "y", "abc" + CR, "abc\n" + CR];
    // Leading, trailing and whitespace-only lines, terminated and at the end of the file,
    // inside a chunk and straddling the first boundary.
    texts.push("  abc  \n", " \t", "a \n \t\n", "\t\n  ", "x".repeat(C - 1) + " \n", "x".repeat(C - 1) + " \t");
    // Multi-byte characters straddling the first read chunk (2-, 3- and 4-byte UTF-8),
    // terminated and at the end of the file: the stream must decode across chunks.
    for (const [pad, ch] of [[C - 1, "\u00e9"], [C - 2, "\u20ac"], [C - 3, "\u{1f600}"]] as const) {
      texts.push("x".repeat(pad) + ch + "\n", "x".repeat(pad) + ch);
    }
    for (let round = 0; round < 40; round++) {
      let text = "";
      const target = 60000 + rand(140000); // spans several 64 KiB read chunks
      while (text.length < target) text += alphabet[rand(alphabet.length)]!.repeat(1 + rand(rand(4) === 0 ? 70000 : 5));
      texts.push(text);
    }
    // Guard the generator itself: the random files must use the whole alphabet.
    const randomText = texts.slice(-40).join("");
    for (const piece of alphabet) expect(randomText.includes(piece)).toBe(true);
    // Exhaustive boundary sweep: every string of up to 4 chars over {a, \n, \r}, with the
    // first (or second) 64 KiB read chunk ending at each position inside it (x-padding in
    // front, so a line may span two or three chunks). The string is also the end of the
    // file, so every end-of-file case is covered too.
    let shorts = [""];
    for (let len = 1; len <= 4; len++) {
      shorts = shorts.flatMap((p) => ["a", "\n", CR].map((c) => p + c));
      for (const short of shorts) {
        for (let cut = 0; cut <= len; cut++) {
          for (const pad of [C, 2 * C]) texts.push("x".repeat(pad - cut) + short);
        }
      }
    }
    // The boundary cases above assume the runtime honours READ_CHUNK as the read size.
    const probe = path.join(tmpDir, "chunk-probe.txt");
    await fs.writeFile(probe, "x".repeat(3 * C));
    for await (const c of createReadStream(probe, { encoding: "utf8", highWaterMark: C })) {
      expect((c as string).length).toBe(C);
      break;
    }
    for (const [round, text] of texts.entries()) {
      const file = path.join(tmpDir, `split-${round}.txt`);
      await fs.writeFile(file, text);
      const ours: string[] = [];
      const complete: boolean[] = [];
      for await (const line of rawLines(file)) {
        ours.push(line.text);
        complete.push(line.complete);
      }
      const theirs: string[] = [];
      for await (const t of createInterface({ input: createReadStream(file, { encoding: "utf8" }), crlfDelay: Infinity })) {
        theirs.push(t);
      }
      expect(ours).toEqual(theirs); // empty lines included: the strict walk counts them
      const endsWithBreak = text.endsWith("\n") || text.endsWith(CR);
      expect(complete).toEqual(ours.map((_, i) => i < ours.length - 1 || endsWithBreak));
    }
  });

  test("countRows equals the non-empty lines rawLines yields, across chunk boundaries", async () => {
    const CR = String.fromCharCode(13);
    const C = READ_CHUNK;
    const texts = ["", "\n", CR, CR + "\n", "a", "a\n\n b " + CR + CR + "\nc", "x".repeat(C - 1) + CR + "\ny", "\u00e9".repeat(C)];
    let shorts = [""];
    for (let len = 1; len <= 4; len++) {
      shorts = shorts.flatMap((p) => ["a", "\n", CR].map((c) => p + c));
      for (const short of shorts) for (let cut = 0; cut <= len; cut++) texts.push("x".repeat(C - cut) + short);
    }
    for (const [i, text] of texts.entries()) {
      const file = path.join(tmpDir, `count-${i}.txt`);
      await fs.writeFile(file, text);
      let expected = 0;
      for await (const { text: t } of rawLines(file)) if (t.length > 0) expected++;
      expect(await countRows(file)).toBe(expected);
    }
    expect(await countRows(path.join(tmpDir, "absent.jsonl"))).toBe(0);
  });

  test("resumeTip: a missing file is genesis; any other read error throws", async () => {
    const salt = Buffer.alloc(32, 1);
    expect(await resumeTip(path.join(tmpDir, "absent.jsonl"), salt, "g")).toBe("g");
    await fs.mkdir(path.join(tmpDir, "a-dir"));
    await expect(resumeTip(path.join(tmpDir, "a-dir"), salt, "g")).rejects.toThrow();
  });

  test("a large junk block plus a planted line cannot steer the server restart", async () => {
    await asProcess("server");
    await auditEnd(ctx("gmail_search")); // A
    await auditEnd(ctx("gmail_send")); // B
    const macA = (await lines(serverFile()))[0]!.row_mac;
    const plant = "x".repeat(70000) + "\n" + JSON.stringify({ row_mac: macA }) + "\n";
    await fs.appendFile(serverFile(), plant);
    await asProcess("server");
    await auditEnd(ctx("drive_search")); // must chain to B
    const raw = await fs.readFile(serverFile(), "utf8");
    await fs.writeFile(serverFile(), raw.replace(plant, ""));
    expect(await verifyJson()).toMatchObject({ ok: true, chainedRows: 3 });
  });

  test("a valid tail row padded to a very long line is resumed from", async () => {
    await asProcess("server");
    await auditEnd(ctx("gmail_search"));
    await auditEnd(ctx("gmail_send"));
    const raw = await fs.readFile(serverFile(), "utf8");
    const [rowA, rowB] = raw.split("\n");
    await fs.writeFile(serverFile(), rowA + "\n{" + " ".repeat(2 * 1024 * 1024) + rowB!.slice(1) + "\n");
    await asProcess("server");
    await auditEnd(ctx("drive_search"));
    expect(await verifyJson()).toMatchObject({ ok: true, chainedRows: 3 });
  });

  test("a very long junk line is passed over by both writers", async () => {
    await asProcess("cli");
    await auditEnd(ctx("web_fetch"));
    const junk = "y".repeat(1024 * 1024 + 10) + "\n";
    await fs.appendFile(cliFile(), junk);
    await asProcess("cli");
    await auditEnd(ctx("fs_read"));
    const raw = await fs.readFile(cliFile(), "utf8");
    await fs.writeFile(cliFile(), raw.replace(junk, ""));
    expect((await verifyJson()).cli).toMatchObject({ ok: true, chainedRows: 2 });
  });

  test("a >64 KB junk line at the server tail is passed over: removing it repairs the chain", async () => {
    await asProcess("server");
    await auditEnd(ctx("gmail_search"));
    const junk = "x".repeat(70000) + "\n";
    await fs.appendFile(serverFile(), junk);
    await asProcess("server");
    await auditEnd(ctx("gmail_send"));
    const raw = await fs.readFile(serverFile(), "utf8");
    await fs.writeFile(serverFile(), raw.replace(junk, ""));
    expect(await verifyJson()).toMatchObject({ ok: true, chainedRows: 2 });
  });

  test("no CLI file: verify output has no `cli` key and the text report is unchanged", async () => {
    await asProcess("server");
    await auditEnd(ctx("gmail_search"));
    const r = await verifyJson();
    expect("cli" in r).toBe(false);
    const { io, out } = capture();
    await runCli(["audit", "verify"], io);
    expect(out[0]).toMatch(/^audit chain INTACT — 1 chained row verified$/);
    expect(out.some((l) => l.includes("CLI chain"))).toBe(false);
  });
});

describe("readers with both files", () => {
  test("recent merges both files by ts and marks CLI rows", async () => {
    const tick = () => new Promise((r) => setTimeout(r, 5)); // distinct millisecond ts
    await asProcess("server");
    await auditEnd(ctx("gmail_search"));
    await tick();
    await asProcess("cli");
    await auditEnd(ctx("web_fetch"));
    await tick();
    await asProcess("server");
    await auditEnd(ctx("gmail_send"));
    const { io, out } = capture();
    await runCli(["audit", "recent", "--json"], io);
    const rows = out.map((l) => JSON.parse(l));
    expect(rows.map((r) => r.tool)).toEqual(["gmail_search", "web_fetch", "gmail_send"]);
    expect(rows.map((r) => r.source_file ?? "server")).toEqual(["server", "cli", "server"]);
  });

  test("CEF export tags CLI rows with their source file; JSONL rows stay unchanged", async () => {
    await serverThenCliThenServer();
    const cef = capture();
    await runCli(["audit", "export", "--format", "cef"], cef.io);
    expect(cef.out.filter((l) => l.includes("safespaceSourceFile=cli"))).toHaveLength(2);
    const jsonl = capture();
    await runCli(["audit", "export"], jsonl.io);
    const cliRows = await lines(cliFile());
    expect(jsonl.out.slice(-2)).toEqual(cliRows.map((r) => JSON.stringify(r)));
  });

  test("status counts both files and shows the latest real call", async () => {
    await serverThenCliThenServer();
    const { io, out } = capture();
    await runCli(["status", "--json"], io);
    const s = JSON.parse(out[0]!);
    expect(s.audit_line_count).toBe(3); // gmail_search, anchor, gmail_send
    expect(s.audit_cli_line_count).toBe(2);
    expect(s.last_audit_entry.tool).toBe("gmail_send");
  });

  test("status ignores an unterminated final line when comparing both files", async () => {
    await serverThenCliThenServer();
    await fs.appendFile(serverFile(), JSON.stringify({ ts: "9999-01-01T00:00:00.000Z", tool: "half_written" }));
    const { io, out } = capture();
    await runCli(["status", "--json"], io);
    expect(JSON.parse(out[0]!).last_audit_entry.tool).toBe("gmail_send");
  });

  test("status with no CLI file keeps today's shape", async () => {
    await asProcess("server");
    await auditEnd(ctx("gmail_search"));
    const { io, out } = capture();
    await runCli(["status", "--json"], io);
    expect("audit_cli_line_count" in JSON.parse(out[0]!)).toBe(false);
  });
});
