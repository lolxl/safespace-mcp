// v1.33 Phase 1 (a)+(c) -- audit suspicious --include-homoglyph-attacks
// per-script breakdown of denied_formula_rejected rows (docs 4.3, hooks #10 #11).
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { runCli, type CliIO } from "../../cli";

let tmp: string;
let prevEnv: string | undefined;
let prevExit: typeof process.exitCode;
beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  prevExit = process.exitCode;
  tmp = await fs.mkdtemp(path.join(tmpdir(), "audit-susp-homo-"));
  process.env.SAFESPACE_CONFIG_DIR = tmp;
});
afterEach(async () => {
  if (prevEnv === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevEnv;
  process.exitCode = prevExit;
  await fs.rm(tmp, { recursive: true, force: true });
});
function captureIO(): { io: CliIO; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return { io: { out: (l) => out.push(l), err: (l) => err.push(l) }, out, err };
}
function recentTs(secAgo: number): string {
  return new Date(Date.now() - secAgo * 1000).toISOString();
}
async function writeAuditLines(lines: object[]): Promise<void> {
  await fs.writeFile(path.join(tmp, "audit.jsonl"), lines.map((l) => JSON.stringify(l)).join("\n") + "\n", { mode: 0o600 });
}
function row(extra: Record<string, unknown>): Record<string, unknown> {
  return {
    ts: recentTs(60), tool: "sheets_update_values", account: "a@example.com",
    args_hash: "f".repeat(64), status: "error", duration_ms: 7,
    target_spreadsheet_id_hash: "e".repeat(64), operation: "update_values",
    policy_decision: "denied_formula_rejected", rejected_formula_function: "IMPORTRANGE",
    error_code: -32029, ...extra,
  };
}
describe("v1.33 (a)+(c) -- audit suspicious --include-homoglyph-attacks", () => {
  test("flag accepted (no CliError)", async () => {
    await writeAuditLines([row({})]);
    const { io } = captureIO();
    await expect(runCli(["audit", "suspicious", "--include-homoglyph-attacks", "--threshold", "100"], io)).resolves.toBeUndefined();
  });
  test("JSON breakdown buckets rows by coarse script", async () => {
    await writeAuditLines([
      row({}),
      row({ rejected_formula_homoglyph_source: String.fromCharCode(0x0406) }), // Cyrillic
      row({ rejected_formula_homoglyph_source: String.fromCharCode(0x0391) }), // Greek
      row({ rejected_formula_homoglyph_source: String.fromCharCode(0x202e) }), // bidi RLO
      row({ rejected_formula_homoglyph_source: String.fromCharCode(0x200b) }), // ZWSP -> invisible_other
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious", "--include-homoglyph-attacks", "--threshold", "100", "--json"], io);
    const parsed = JSON.parse(out.find((l) => l.startsWith("{"))!) as { homoglyph_attacks?: Record<string, number> };
    expect(parsed.homoglyph_attacks).toEqual({ ascii: 1, cyrillic: 1, greek: 1, bidi: 1, invisible_other: 1 });
  });
  test("aggregate-only: raw source bytes NEVER appear", async () => {
    await writeAuditLines([row({ rejected_formula_homoglyph_source: String.fromCharCode(0x0406) })]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious", "--include-homoglyph-attacks", "--threshold", "100", "--json"], io);
    expect(out.join("\n")).not.toContain(String.fromCharCode(0x0406));
  });
  test("flag OFF -> NO homoglyph_attacks key (byte-identical to v1.32)", async () => {
    await writeAuditLines([row({ rejected_formula_homoglyph_source: String.fromCharCode(0x0406) })]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious", "--threshold", "100", "--json"], io);
    const parsed = JSON.parse(out.find((l) => l.startsWith("{"))!) as { homoglyph_attacks?: unknown };
    expect(parsed.homoglyph_attacks).toBeUndefined();
  });
  test("table renders breakdown section under the flag", async () => {
    await writeAuditLines([row({}), row({ rejected_formula_homoglyph_source: String.fromCharCode(0x0406) })]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious", "--include-homoglyph-attacks", "--threshold", "100"], io);
    const text = out.join("\n");
    expect(text).toContain("denied_formula_rejected breakdown");
    expect(text).toContain("cyrillic");
    expect(text).toContain("ascii");
  });
});
