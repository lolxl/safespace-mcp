// v1.91 — `safespace audit export` CLI tests: jsonl passthrough, --since
// filtering, CEF formatting + severity, and the CEF line-injection defense
// (the security-critical surface — an un-escaped newline / `|` / `=` in a field
// value must NOT forge a second CEF record or extra header field / pair).
//
// Control characters in test payloads are built via String.fromCharCode (NOT
// "\r" / "\n" escapes) — a literal control escape in this source is mangled /
// truncated by the repo's Write+opencc hook chain. Pure-ASCII source, real
// control byte only at runtime.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { CliError, type CliIO } from "../../cli";
import { runAuditExport } from "./export";

const LF = String.fromCharCode(10);
const CR = String.fromCharCode(13);
const NUL = String.fromCharCode(0);
const LS = String.fromCharCode(0x2028); // Unicode LINE SEPARATOR
const PS = String.fromCharCode(0x2029); // Unicode PARAGRAPH SEPARATOR

let tmp: string;
let prevEnv: string | undefined;

beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  tmp = await fs.mkdtemp(path.join(tmpdir(), "audit-export-"));
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
const auditFile = () => path.join(tmp, "audit.jsonl");
/** Write raw audit rows directly (bypassing the chain writer) so a test can
 *  craft exact field values, including injection payloads. */
async function writeRaw(rows: Array<Record<string, unknown>>): Promise<void> {
  await fs.writeFile(auditFile(), rows.map((r) => JSON.stringify(r)).join(LF) + LF);
}

describe("runAuditExport — jsonl (default)", () => {
  test("passes each row through verbatim, one JSON line per row", async () => {
    const rows = [
      { ts: "2026-06-14T01:00:00.000Z", tool: "gmail_send", account: "a@x.com", status: "ok", row_mac: "deadbeef" },
      { ts: "2026-06-14T02:00:00.000Z", tool: "drive_search", account: "a@x.com", status: "ok", row_mac: "cafef00d" },
    ];
    await writeRaw(rows);
    const cap = captureIO();
    await runAuditExport([], cap.io);
    expect(cap.out).toHaveLength(2);
    expect(JSON.parse(cap.out[0]!)).toEqual(rows[0]!);
    expect(JSON.parse(cap.out[1]!)).toEqual(rows[1]!);
    // row_mac survives the export (SIEM can store the chain tip).
    expect(JSON.parse(cap.out[1]!).row_mac).toBe("cafef00d");
  });

  test("--since keeps only rows on/after the date", async () => {
    await writeRaw([
      { ts: "2026-06-10T00:00:00.000Z", tool: "old", status: "ok" },
      { ts: "2026-06-14T00:00:00.000Z", tool: "new", status: "ok" },
    ]);
    const cap = captureIO();
    await runAuditExport(["--since", "2026-06-12"], cap.io);
    expect(cap.out).toHaveLength(1);
    expect(JSON.parse(cap.out[0]!).tool).toBe("new");
  });

  test("a row with no/unparseable ts is KEPT under --since (over-inclusive)", async () => {
    await writeRaw([
      { tool: "no_ts", status: "ok" },
      { ts: "not-a-date", tool: "bad_ts", status: "ok" },
      { ts: "2026-06-14T00:00:00.000Z", tool: "ok_ts", status: "ok" },
    ]);
    const cap = captureIO();
    await runAuditExport(["--since", "2026-06-13"], cap.io);
    expect(cap.out.map((l) => JSON.parse(l).tool)).toEqual(["no_ts", "bad_ts", "ok_ts"]);
  });

  test("empty / missing file → nothing on stdout, a note on stderr", async () => {
    const cap = captureIO();
    await runAuditExport([], cap.io);
    expect(cap.out).toHaveLength(0);
    expect(cap.err.join(LF)).toContain("no audit entries");
  });
});

describe("runAuditExport — cef", () => {
  test("standard tool row → CEF header + vetted extension, severity 3", async () => {
    await writeRaw([
      { ts: "2026-06-14T01:00:00.000Z", tool: "gmail_send", account: "a@x.com", status: "ok", run_id: "abc123" },
    ]);
    const cap = captureIO();
    await runAuditExport(["--format", "cef"], cap.io);
    expect(cap.out).toHaveLength(1);
    const line = cap.out[0]!;
    expect(line.startsWith("CEF:0|SafeSpace|safespace-mcp|")).toBe(true);
    // header: …|<version>|gmail_send|tool call|3|<extension>
    expect(line).toContain("|gmail_send|tool call|3|");
    expect(line).toContain("safespaceTool=gmail_send");
    expect(line).toContain("suser=a@x.com");
    expect(line).toContain("rt=2026-06-14T01:00:00.000Z");
    expect(line).toContain("safespaceRunId=abc123");
  });

  test("severity: policy denial → 8, error → 6, normal → 3", async () => {
    await writeRaw([
      { event: "share_denied_by_policy", file_id: "f1" },
      { ts: "t", tool: "drive_search", status: "error", error_code: -32000 },
      { ts: "t", tool: "drive_search", status: "ok" },
    ]);
    const cap = captureIO();
    await runAuditExport(["--format", "cef"], cap.io);
    expect(cap.out[0]!).toContain("|share_denied_by_policy|audit event|8|");
    expect(cap.out[1]!).toContain("|tool call|6|");
    expect(cap.out[2]!).toContain("|tool call|3|");
  });

  test("policy_decision containing 'denied' → severity 8", async () => {
    await writeRaw([{ ts: "t", tool: "drive_share_file", status: "ok", policy_decision: "share_denied" }]);
    const cap = captureIO();
    await runAuditExport(["--format", "cef"], cap.io);
    expect(cap.out[0]!).toContain("|tool call|8|");
  });

  test("event-shape row with no `tool` uses `event` as signatureId", async () => {
    await writeRaw([{ event: "cross_account_aggregate", account_count_queried: 3 }]);
    const cap = captureIO();
    await runAuditExport(["--format", "cef"], cap.io);
    expect(cap.out[0]!).toContain("|cross_account_aggregate|audit event|3|");
  });

  test("only vetted fields are emitted (no blind dump of unknown keys)", async () => {
    await writeRaw([
      { ts: "t", tool: "gmail_send", status: "ok", some_unvetted_field: "SHOULD_NOT_APPEAR" },
    ]);
    const cap = captureIO();
    await runAuditExport(["--format", "cef"], cap.io);
    expect(cap.out[0]!).not.toContain("SHOULD_NOT_APPEAR");
    expect(cap.out[0]!).not.toContain("some_unvetted_field");
  });
});

describe("runAuditExport — CEF injection defense", () => {
  test("a newline in a field value cannot forge a second CEF record", async () => {
    await writeRaw([
      { ts: "t", tool: "drive_share_file", status: "ok", policy_decision: "ok" + LF + "CEF:0|EvilVendor|x|9|forged" },
    ]);
    const cap = captureIO();
    await runAuditExport(["--format", "cef"], cap.io);
    // Exactly ONE record emitted; the embedded newline was collapsed to a space.
    expect(cap.out).toHaveLength(1);
    const line = cap.out[0]!;
    expect(line.includes(LF)).toBe(false);
    // The forged "CEF:0|" payload survives only as inert text inside the value,
    // never at the start of a new line. The LF collapsed to a single space, so
    // the whole payload stays inside the one extension pair.
    expect(line.startsWith("CEF:0|SafeSpace|")).toBe(true);
    expect(line.indexOf("CEF:0|EvilVendor")).toBeGreaterThan(0); // not line-start
    expect(line).toContain("safespacePolicyDecision=ok CEF:0|EvilVendor|x|9|forged");
  });

  test("a pipe in a header field is escaped (no forged header field)", async () => {
    await writeRaw([{ ts: "t", tool: "evil|tool|name", status: "ok" }]);
    const cap = captureIO();
    await runAuditExport(["--format", "cef"], cap.io);
    const line = cap.out[0]!;
    expect(line).toContain("|evil\\|tool\\|name|tool call|");
  });

  test("`=` and `\\` in an extension value are escaped (no forged pair)", async () => {
    await writeRaw([{ ts: "t", tool: "gmail_send", status: "ok", policy_decision: "a=b\\c" }]);
    const cap = captureIO();
    await runAuditExport(["--format", "cef"], cap.io);
    const line = cap.out[0]!;
    // backslash → \\ , equals → \= ; the raw "a=b" never appears as a bare pair.
    expect(line).toContain("safespacePolicyDecision=a\\=b\\\\c");
  });

  test("CR and NUL control bytes are collapsed to spaces (no truncation/reframe)", async () => {
    await writeRaw([{ ts: "t", tool: "gmail_send", status: "ok", policy_decision: "x" + CR + NUL + "y" }]);
    const cap = captureIO();
    await runAuditExport(["--format", "cef"], cap.io);
    const line = cap.out[0]!;
    expect(cap.out).toHaveLength(1);
    expect(line.includes(CR)).toBe(false);
    expect(line.includes(NUL)).toBe(false);
    // CR→space and NUL→space ⇒ "x" + two spaces + "y".
    expect(line).toContain("safespacePolicyDecision=x  y");
  });

  test("Unicode line separators (U+2028 / U+2029) cannot reframe the record", async () => {
    await writeRaw([{ ts: "t", tool: "gmail_send", status: "ok", policy_decision: "x" + LS + "y" + PS + "z" }]);
    const cap = captureIO();
    await runAuditExport(["--format", "cef"], cap.io);
    const line = cap.out[0]!;
    // A Unicode-aware CEF/syslog parser could split on LS/PS — they must be gone.
    expect(cap.out).toHaveLength(1);
    expect(line.includes(LS)).toBe(false);
    expect(line.includes(PS)).toBe(false);
    expect(line).toContain("safespacePolicyDecision=x y z");
  });
});

describe("runAuditExport — flag validation", () => {
  test("unknown flag → CliError", async () => {
    const cap = captureIO();
    await expect(runAuditExport(["--bogus"], cap.io)).rejects.toBeInstanceOf(CliError);
  });
  test("--format with an invalid value → CliError", async () => {
    const cap = captureIO();
    await expect(runAuditExport(["--format", "xml"], cap.io)).rejects.toBeInstanceOf(CliError);
  });
  test("--format with no value → CliError", async () => {
    const cap = captureIO();
    await expect(runAuditExport(["--format"], cap.io)).rejects.toBeInstanceOf(CliError);
  });
  test("--since with no value → CliError", async () => {
    const cap = captureIO();
    await expect(runAuditExport(["--since"], cap.io)).rejects.toBeInstanceOf(CliError);
  });
  test("--since with a non-ISO date → CliError", async () => {
    const cap = captureIO();
    await expect(runAuditExport(["--since", "yesterday"], cap.io)).rejects.toBeInstanceOf(CliError);
  });
});
