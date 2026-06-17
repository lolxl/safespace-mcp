// v1.58 F5 — `safespace audit sessions` tests
// (docs/v1.58-f5-session-anomaly-audit.md §7). Covers: run_id grouping,
// per-session aggregation, the anomaly verdict (HIGH / MEDIUM / NONE),
// --anomalous-only, --json, the (no run_id) legacy bucket, and the no-echo rule.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import type { CliIO } from "../../cli";
import { runAuditSessions } from "./sessions";

let tmp: string;
let prevEnv: string | undefined;

beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  tmp = await fs.mkdtemp(path.join(tmpdir(), "audit-sessions-"));
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

async function writeRows(lines: object[]): Promise<void> {
  const body = lines.map((l) => JSON.stringify(l)).join("\n") + "\n";
  await fs.writeFile(path.join(tmp, "audit.jsonl"), body, { mode: 0o600 });
}

function row(runId: string, over: Record<string, unknown> = {}): object {
  return {
    ts: new Date().toISOString(),
    run_id: runId,
    tool: "gmail_search",
    account: "a@example.com",
    operator: "ops@example.com",
    status: "ok",
    duration_ms: 10,
    ...over,
  };
}

function jsonOut(out: string[]): {
  total_sessions: number;
  anomalous_sessions: number;
  sessions: Array<Record<string, unknown>>;
} {
  return JSON.parse(out[0]!);
}

describe("audit sessions — grouping + aggregation", () => {
  test("groups rows by run_id and tallies calls / denials / deletes / flags", async () => {
    await writeRows([
      row("aaa", { ts: "2026-06-05T01:00:00Z" }),
      row("aaa", { status: "error", error_code: -32019, ts: "2026-06-05T01:01:00Z" }),
      row("aaa", {
        tool: "gmail_send",
        tainted_source: true,
        ts: "2026-06-05T01:02:00Z",
      }),
      row("bbb", { tool: "gmail_send", ts: "2026-06-05T02:00:00Z" }),
    ]);
    const { io, out } = captureIO();
    await runAuditSessions(["--json"], io);
    const j = jsonOut(out);
    expect(j.total_sessions).toBe(2);
    const aaa = j.sessions.find((s) => s.run_id === "aaa")!;
    expect(aaa.calls).toBe(3);
    expect(aaa.denials).toBe(1);
    expect(aaa.tainted_source).toBe(1);
    expect(aaa.first_ts).toBe("2026-06-05T01:00:00Z");
    expect(aaa.last_ts).toBe("2026-06-05T01:02:00Z");
  });

  test("permanent-delete tally reuses classifyDestructive (a tasks_delete row counts)", async () => {
    await writeRows([
      row("aaa", {
        tool: "tasks_delete",
        status: "ok",
        tasksMutationMeta: { operation: "delete" },
        target_tasklist_hash: "h",
      }),
    ]);
    const { io, out } = captureIO();
    await runAuditSessions(["--json"], io);
    expect(jsonOut(out).sessions[0]!.permanent_deletes).toBe(1);
  });

  test("pre-v1.58 rows (no run_id) bucket under '(no run_id)'", async () => {
    await writeRows([{ ts: "2026-06-05T01:00:00Z", tool: "gmail_search", status: "ok" }]);
    const { io, out } = captureIO();
    await runAuditSessions(["--json"], io);
    expect(jsonOut(out).sessions[0]!.run_id).toBe("(no run_id)");
  });
});

describe("audit sessions — anomaly verdict", () => {
  test("HIGH on a tainted-source egress", async () => {
    await writeRows([row("h1", { tool: "gmail_send", tainted_source: true })]);
    const { io, out } = captureIO();
    await runAuditSessions(["--json"], io);
    const s = jsonOut(out).sessions[0]!;
    expect(s.verdict).toBe("HIGH");
    expect((s.reasons as string[]).join(" ")).toContain("tainted-source");
  });

  test("HIGH on an outbound secret-shape", async () => {
    await writeRows([row("h2", { tool: "gmail_send", outbound_secret_shape: "private_key" })]);
    const { io, out } = captureIO();
    await runAuditSessions(["--json"], io);
    expect(jsonOut(out).sessions[0]!.verdict).toBe("HIGH");
  });

  test("MEDIUM on a denial spike (≥ threshold)", async () => {
    const rows = Array.from({ length: 5 }, (_, i) =>
      row("m1", { status: "error", error_code: -32019, ts: `2026-06-05T01:0${i}:00Z` }),
    );
    await writeRows(rows);
    const { io, out } = captureIO();
    await runAuditSessions(["--denial-threshold", "5", "--json"], io);
    const s = jsonOut(out).sessions[0]!;
    expect(s.verdict).toBe("MEDIUM");
    expect((s.reasons as string[]).join(" ")).toContain("denial spike");
  });

  test("NONE for a quiet, clean session", async () => {
    await writeRows([row("n1"), row("n1")]);
    const { io, out } = captureIO();
    await runAuditSessions(["--json"], io);
    expect(jsonOut(out).sessions[0]!.verdict).toBe("NONE");
  });

  test("HIGH outranks MEDIUM (a session with both a tainted egress AND a denial spike → HIGH)", async () => {
    const rows = [
      row("x", { tool: "gmail_send", tainted_source: true }),
      ...Array.from({ length: 6 }, () => row("x", { status: "error", error_code: -32019 })),
    ];
    await writeRows(rows);
    const { io, out } = captureIO();
    await runAuditSessions(["--json"], io);
    expect(jsonOut(out).sessions[0]!.verdict).toBe("HIGH");
  });
});

describe("audit sessions — flags + output", () => {
  test("--anomalous-only filters to flagged sessions", async () => {
    await writeRows([
      row("clean"),
      row("bad", { tool: "gmail_send", tainted_source: true }),
    ]);
    const { io, out } = captureIO();
    await runAuditSessions(["--anomalous-only", "--json"], io);
    const j = jsonOut(out);
    expect(j.total_sessions).toBe(2);
    expect(j.anomalous_sessions).toBe(1);
    expect(j.sessions).toHaveLength(1);
    expect(j.sessions[0]!.run_id).toBe("bad");
  });

  test("--limit caps the number of sessions shown", async () => {
    await writeRows([
      row("s1", { ts: "2026-06-05T01:00:00Z" }),
      row("s2", { ts: "2026-06-05T02:00:00Z" }),
      row("s3", { ts: "2026-06-05T03:00:00Z" }),
    ]);
    const { io, out } = captureIO();
    await runAuditSessions(["--limit", "2", "--json"], io);
    const j = jsonOut(out);
    expect(j.total_sessions).toBe(3);
    expect(j.sessions).toHaveLength(2);
    // most-recent-first ordering
    expect(j.sessions[0]!.run_id).toBe("s3");
  });

  test("table output never echoes per-row content (no recipient / no secret bytes)", async () => {
    await writeRows([
      row("t", {
        tool: "gmail_send",
        outbound_secret_shape: "private_key",
        // these would be a leak if F5 echoed row content — it must NOT:
        rejected_recipient_hashes: ["deadbeef"],
        args_hash: "sha256:secret",
      }),
    ]);
    const { io, out } = captureIO();
    await runAuditSessions([], io);
    const text = out.join("\n");
    expect(text).not.toContain("deadbeef");
    expect(text).not.toContain("sha256:secret");
    // it DOES surface the aggregate class name (not bytes) — that is intended
    expect(text).toContain("outbound_secret_shape: 1");
  });

  test("empty audit → 'no sessions found'", async () => {
    await writeRows([]);
    const { io, out } = captureIO();
    await runAuditSessions([], io);
    expect(out.join("\n")).toContain("no sessions found");
  });

  test("unknown flag → CliError", async () => {
    const { io } = captureIO();
    await expect(runAuditSessions(["--bogus"], io)).rejects.toThrow(/unknown flag/);
  });
});
