import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { CliError, runCli, type CliIO } from "../../cli";

let tmp: string;
let prevEnv: string | undefined;

beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  tmp = await fs.mkdtemp(path.join(tmpdir(), "audit-stats-"));
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
  return {
    io: { out: (l) => out.push(l), err: (l) => err.push(l) },
    out,
    err,
  };
}

async function writeAuditLines(lines: object[]): Promise<void> {
  const body = lines.map((l) => JSON.stringify(l)).join("\n") + "\n";
  await fs.writeFile(path.join(tmp, "audit.jsonl"), body, { mode: 0o600 });
}

describe("audit stats", () => {
  test("grouping by tool / account / policy_decision", async () => {
    await writeAuditLines([
      { ts: "2026-05-24T10:00:00Z", tool: "gmail_search", account: "a@example.com", status: "ok" },
      { ts: "2026-05-24T10:01:00Z", tool: "gmail_search", account: "b@example.com", status: "ok" },
      { ts: "2026-05-24T10:02:00Z", tool: "drive_search", account: "a@example.com", status: "ok" },
      { ts: "2026-05-24T10:03:00Z", tool: "calendar_delete_event", account: "a@example.com", status: "ok", policy_decision: "allowed" },
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "stats"], io);
    const text = out.join("\n");
    expect(text).toContain("total rows: 4");
    expect(text).toContain("gmail_search");
    expect(text).toMatch(/gmail_search\s+2/);
    expect(text).toMatch(/drive_search\s+1/);
    expect(text).toMatch(/a@example\.com\s+3/);
    expect(text).toMatch(/allowed\s+1/);
  });

  test("--since strict ISO parse filters rows pre-cutoff", async () => {
    await writeAuditLines([
      { ts: "2026-05-20T10:00:00Z", tool: "gmail_search", account: "a@example.com", status: "ok" },
      { ts: "2026-05-24T10:00:00Z", tool: "drive_search", account: "a@example.com", status: "ok" },
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "stats", "--since", "2026-05-22"], io);
    const text = out.join("\n");
    expect(text).toContain("total rows: 1");
    expect(text).toContain("drive_search");
    expect(text).not.toContain("gmail_search");
  });

  test("--since 'yesterday' → CliError pre-read (hook #3)", async () => {
    const { io } = captureIO();
    await expect(runCli(["audit", "stats", "--since", "yesterday"], io)).rejects.toBeInstanceOf(CliError);
  });

  test("--since '2026/05/21' (wrong delimiter) → CliError", async () => {
    const { io } = captureIO();
    await expect(runCli(["audit", "stats", "--since", "2026/05/21"], io)).rejects.toBeInstanceOf(CliError);
  });

  test("--json mode emits structured output", async () => {
    await writeAuditLines([
      { ts: "2026-05-24T10:00:00Z", tool: "gmail_search", account: "a@example.com", status: "ok" },
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "stats", "--json"], io);
    const line = out.find((l) => l.startsWith("{"));
    expect(line).toBeDefined();
    const parsed = JSON.parse(line!) as { total: number; by_tool: Record<string, number> };
    expect(parsed.total).toBe(1);
    expect(parsed.by_tool.gmail_search).toBe(1);
  });

  test("empty file → total 0", async () => {
    const { io, out } = captureIO();
    await runCli(["audit", "stats"], io);
    expect(out.join("\n")).toContain("total rows: 0");
  });
});
