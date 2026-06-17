// v1.89 — `safespace audit verify` CLI tests (exit code + render + --json).

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { CliError, type CliIO } from "../../cli";
import { auditEnd, __resetChainState, type AuditEndContext } from "../../audit";
import { runAuditVerify } from "./verify";

let tmp: string;
let prevEnv: string | undefined;
let prevExitCode: number;

beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  tmp = await fs.mkdtemp(path.join(tmpdir(), "audit-verify-"));
  process.env.SAFESPACE_CONFIG_DIR = tmp;
  prevExitCode = (process.exitCode as number | undefined) ?? 0;
  process.exitCode = 0;
  __resetChainState();
});
afterEach(async () => {
  if (prevEnv === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevEnv;
  process.exitCode = prevExitCode;
  await fs.rm(tmp, { recursive: true, force: true });
});

function captureIO(): { io: CliIO; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return { io: { out: (l) => out.push(l), err: (l) => err.push(l) }, out, err };
}
const auditFile = () => path.join(tmp, "audit.jsonl");
const ctx = (tool: string): AuditEndContext => ({
  tool, email: "alice@example.com", argsHash: `sha256:${tool}`, status: "ok", durationMs: 1,
});
async function writeRows(n: number): Promise<void> {
  for (let i = 0; i < n; i++) await auditEnd(ctx(`t${i}`));
}

describe("runAuditVerify", () => {
  test("intact chain → exit 0, prints INTACT + the tip MAC", async () => {
    await writeRows(3);
    const cap = captureIO();
    await runAuditVerify([], cap.io);
    expect(process.exitCode).toBe(0);
    const joined = cap.out.join("\n");
    expect(joined).toContain("INTACT");
    expect(joined).toContain("3 chained rows");
    expect(joined).toContain("tip MAC:");
  });

  test("--json on an intact chain → {ok:true,...}", async () => {
    await writeRows(2);
    const cap = captureIO();
    await runAuditVerify(["--json"], cap.io);
    expect(process.exitCode).toBe(0);
    const parsed = JSON.parse(cap.out[0]!);
    expect(parsed.ok).toBe(true);
    expect(parsed.chainedRows).toBe(2);
    expect(typeof parsed.tipMac).toBe("string");
    expect(parsed.brokenAt).toBeNull();
  });

  test("a tampered row → exit 1, prints BROKEN at the right row", async () => {
    await writeRows(3);
    const rows = (await fs.readFile(auditFile(), "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l));
    rows[0]!.tool = "tampered";
    await fs.writeFile(auditFile(), rows.map((r: object) => JSON.stringify(r)).join("\n") + "\n");
    const cap = captureIO();
    await runAuditVerify([], cap.io);
    expect(process.exitCode).toBe(1);
    expect(cap.err.join("\n")).toContain("BROKEN at row #1");
  });

  test("--json on a tampered chain → {ok:false, brokenAt, reason}", async () => {
    await writeRows(3);
    const rows = (await fs.readFile(auditFile(), "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l));
    rows.splice(1, 1); // delete a middle row
    await fs.writeFile(auditFile(), rows.map((r: object) => JSON.stringify(r)).join("\n") + "\n");
    const cap = captureIO();
    await runAuditVerify(["--json"], cap.io);
    expect(process.exitCode).toBe(1);
    const parsed = JSON.parse(cap.out[0]!);
    expect(parsed.ok).toBe(false);
    expect(parsed.reason).toBe("mac_mismatch");
  });

  test("an empty / no-chain file → exit 0, 'nothing to verify'", async () => {
    const cap = captureIO();
    await runAuditVerify([], cap.io);
    expect(process.exitCode).toBe(0);
    expect(cap.out.join("\n")).toContain("nothing to verify");
  });

  test("unknown flag → CliError", async () => {
    const cap = captureIO();
    await expect(runAuditVerify(["--bogus"], cap.io)).rejects.toBeInstanceOf(CliError);
  });
});
