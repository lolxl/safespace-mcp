// v1.33 Phase 1 (b) -- audit recent forensic surfacing of
// rejected_formula_homoglyph_source (docs section 4.2, hooks #1 #2).
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { runCli, type CliIO } from "../../cli";

let tmp: string;
let prevEnv: string | undefined;
beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  tmp = await fs.mkdtemp(path.join(tmpdir(), "audit-recent-forensic-"));
  process.env.SAFESPACE_CONFIG_DIR = tmp;
});
afterEach(async () => {
  if (prevEnv === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevEnv;
  await fs.rm(tmp, { recursive: true, force: true });
});
function captureIO(): { io: CliIO; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return { io: { out: (l) => out.push(l), err: (l) => err.push(l) }, out, err };
}
async function writeAuditLines(lines: object[]): Promise<void> {
  await fs.writeFile(path.join(tmp, "audit.jsonl"), lines.map((l) => JSON.stringify(l)).join("\n") + "\n", { mode: 0o600 });
}
const HOMO = String.fromCharCode(0x0456, 0x0430); // Cyrillic i + a
const HOMO_ROW = {
  ts: "2026-05-24T14:02:11.444Z", tool: "sheets_update_values", account: "a@example.com",
  args_hash: "f".repeat(64), status: "error", duration_ms: 12,
  target_spreadsheet_id_hash: "e".repeat(64), operation: "update_values",
  policy_decision: "denied_formula_rejected", rejected_formula_function: "IMPORTRANGE",
  rejected_formula_homoglyph_source: HOMO, error_code: -32029,
};
const ASCII_ROW = {
  ts: "2026-05-24T14:03:11.444Z", tool: "sheets_update_values", account: "a@example.com",
  args_hash: "a".repeat(64), status: "error", duration_ms: 9,
  target_spreadsheet_id_hash: "d".repeat(64), operation: "update_values",
  policy_decision: "denied_formula_rejected", rejected_formula_function: "IMPORTXML", error_code: -32029,
};
describe("v1.33 (b) -- audit recent forensic surfacing", () => {
  test("JSON emits rejected_formula_homoglyph_source VERBATIM", async () => {
    await writeAuditLines([HOMO_ROW]);
    const { io, out } = captureIO();
    await runCli(["audit", "recent", "--json"], io);
    const parsed = JSON.parse(out.find((l) => l.startsWith("{"))!) as Record<string, unknown>;
    expect(parsed.rejected_formula_homoglyph_source).toBe(HOMO);
    expect(parsed.rejected_formula_function).toBe("IMPORTRANGE");
  });
  test("JSON: ASCII REJECT row has NO homoglyph field (PRESENCE-as-signal)", async () => {
    await writeAuditLines([ASCII_ROW]);
    const { io, out } = captureIO();
    await runCli(["audit", "recent", "--json"], io);
    const parsed = JSON.parse(out.find((l) => l.startsWith("{"))!) as Record<string, unknown>;
    expect(parsed.rejected_formula_homoglyph_source).toBeUndefined();
  });
  test("table appends ASCII-escaped U+XXXX hint; raw bytes NEVER rendered", async () => {
    await writeAuditLines([HOMO_ROW]);
    const { io, out } = captureIO();
    await runCli(["audit", "recent"], io);
    const text = out.join("\n");
    expect(text).toContain("denied_formula_rejected");
    expect(text).toContain("(homoglyph:U+");
    expect(text).not.toContain(String.fromCharCode(0x0456));
    expect(text).not.toContain(String.fromCharCode(0x0430));
  });
  test("table: ASCII REJECT row shows policy WITHOUT homoglyph hint", async () => {
    await writeAuditLines([ASCII_ROW]);
    const { io, out } = captureIO();
    await runCli(["audit", "recent"], io);
    const text = out.join("\n");
    expect(text).toContain("denied_formula_rejected");
    expect(text).not.toContain("homoglyph:");
  });
});

// v1.41 -- rejected_formula_nested discriminator surfacing.
const NESTED_ROW = {
  ts: "2026-05-24T14:04:11.444Z", tool: "sheets_update_values", account: "a@example.com",
  args_hash: "b".repeat(64), status: "error", duration_ms: 7,
  target_spreadsheet_id_hash: "c".repeat(64), operation: "update_values",
  policy_decision: "denied_formula_rejected", rejected_formula_function: "IMPORTRANGE",
  rejected_formula_nested: true, error_code: -32029,
};
describe("v1.41 (b) -- audit recent nested-smuggle surfacing", () => {
  test("JSON emits rejected_formula_nested === true on a nested REJECT", async () => {
    await writeAuditLines([NESTED_ROW]);
    const { io, out } = captureIO();
    await runCli(["audit", "recent", "--json"], io);
    const parsed = JSON.parse(out.find((l) => l.startsWith("{"))!) as Record<string, unknown>;
    expect(parsed.rejected_formula_nested).toBe(true);
    expect(parsed.rejected_formula_function).toBe("IMPORTRANGE");
  });
  test("JSON: direct REJECT row has NO nested field (PRESENCE-as-signal)", async () => {
    await writeAuditLines([ASCII_ROW]);
    const { io, out } = captureIO();
    await runCli(["audit", "recent", "--json"], io);
    const parsed = JSON.parse(out.find((l) => l.startsWith("{"))!) as Record<string, unknown>;
    expect(parsed.rejected_formula_nested).toBeUndefined();
  });
  test("table appends (nested) marker on a nested REJECT row", async () => {
    await writeAuditLines([NESTED_ROW]);
    const { io, out } = captureIO();
    await runCli(["audit", "recent"], io);
    const text = out.join("\n");
    expect(text).toContain("denied_formula_rejected");
    expect(text).toContain("(nested)");
  });
  test("table: direct REJECT row shows policy WITHOUT (nested) marker", async () => {
    await writeAuditLines([ASCII_ROW]);
    const { io, out } = captureIO();
    await runCli(["audit", "recent"], io);
    const text = out.join("\n");
    expect(text).toContain("denied_formula_rejected");
    expect(text).not.toContain("(nested)");
  });
});
