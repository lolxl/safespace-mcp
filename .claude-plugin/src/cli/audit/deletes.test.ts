import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { CliError, runCli, type CliIO } from "../../cli";

let tmp: string;
let prevEnv: string | undefined;
let prevExitCode: number;

beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  tmp = await fs.mkdtemp(path.join(tmpdir(), "audit-deletes-"));
  process.env.SAFESPACE_CONFIG_DIR = tmp;
  // v1.24 Phase 2 Item 3 — `runAuditDeletes` now sets process.exitCode
  // (mirror v1.23 `audit suspicious` Q3 LOCK). Save/restore so tests
  // that assert on it cannot leak a non-zero exit into the test runner
  // exit. process.exitCode is `number` (Node 22+ widened typing accepts
  // string|null too); narrow to `number` for save/restore.
  prevExitCode = (process.exitCode as number | undefined) ?? 0;
  process.exitCode = 0;
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

/** Build a destructive-event row (status=ok, deletion succeeded). */
function deleteRow(kind: "youtube" | "calendar", offsetMin: number): object {
  const ts = new Date(Date.now() - offsetMin * 60_000).toISOString();
  if (kind === "youtube") {
    return {
      ts,
      tool: "youtube_comment_delete",
      account: "a@example.com",
      status: "ok",
      duration_ms: 100,
      target_comment_id_hash: "1".repeat(64),
      policy_decision: "deleted",
    };
  }
  return {
    ts,
    tool: "calendar_delete_event",
    account: "a@example.com",
    status: "ok",
    duration_ms: 120,
    target_event_hash: "2".repeat(64),
    policy_decision: "allowed",
  };
}

/** Build a tier-denied delete attempt (status=error). MUST be excluded
 *  from the density alert count per sec-rev M-2. */
function tierDeniedRow(offsetMin: number): object {
  const ts = new Date(Date.now() - offsetMin * 60_000).toISOString();
  return {
    ts,
    tool: "youtube_comment_delete",
    account: "a@example.com",
    status: "error",
    duration_ms: 5,
    target_comment_id_hash: "3".repeat(64),
    policy_decision: "denied_tier",
  };
}

/** v1.19 Phase 2b — tasks_delete destructive row (status=ok, deletion succeeded).
 *  sec-M3 LOCKED: discriminate by operation === "delete" (NOT
 *  policy_decision === "deleted"; policy_decision stays binary
 *  allowed|denied_tier for tasksMutationMeta). */
function tasksDeleteRow(offsetMin: number): object {
  const ts = new Date(Date.now() - offsetMin * 60_000).toISOString();
  return {
    ts,
    tool: "tasks_delete",
    account: "a@example.com",
    status: "ok",
    duration_ms: 80,
    target_tasklist_hash: "4".repeat(64),
    target_task_hash: "5".repeat(64),
    operation: "delete",
    policy_decision: "allowed",
  };
}

/** v1.19 Phase 2b — tasks_delete tier-denied attempt (status=error). MUST be
 *  excluded from the density alert count. */
function tasksDeleteTierDeniedRow(offsetMin: number): object {
  const ts = new Date(Date.now() - offsetMin * 60_000).toISOString();
  return {
    ts,
    tool: "tasks_delete",
    account: "a@example.com",
    status: "error",
    duration_ms: 4,
    target_tasklist_hash: "6".repeat(64),
    target_task_hash: "7".repeat(64),
    operation: "delete",
    policy_decision: "denied_tier",
  };
}

/** v1.19 Phase 2b — tasks_create destructive=false row (operation=create).
 *  MUST NOT count as destructive even though the channel is tasksMutation. */
function tasksCreateRow(offsetMin: number): object {
  const ts = new Date(Date.now() - offsetMin * 60_000).toISOString();
  return {
    ts,
    tool: "tasks_create",
    account: "a@example.com",
    status: "ok",
    duration_ms: 80,
    target_tasklist_hash: "8".repeat(64),
    operation: "create",
    policy_decision: "allowed",
  };
}

/** v1.49 — youtube_playlist_delete destructive row (status=ok, PERMANENT).
 *  Discriminated by operation === "playlist_delete" (playlistMutationMeta.
 *  policy_decision is binary allowed|denied_tier; mirror tasks_delete sec-M3). */
function playlistDeleteRow(offsetMin: number): object {
  const ts = new Date(Date.now() - offsetMin * 60_000).toISOString();
  return {
    ts,
    tool: "youtube_playlist_delete",
    account: "a@example.com",
    status: "ok",
    duration_ms: 90,
    target_playlist_hash: "9".repeat(64),
    operation: "playlist_delete",
    policy_decision: "allowed",
  };
}

/** v1.49 — youtube_playlist_item_remove row (operation=playlist_item_remove).
 *  RECOVERABLE (re-insert) → MUST NOT count as destructive even though the
 *  channel is playlistMutation and it carries target_playlist_hash. */
function playlistItemRemoveRow(offsetMin: number): object {
  const ts = new Date(Date.now() - offsetMin * 60_000).toISOString();
  return {
    ts,
    tool: "youtube_playlist_item_remove",
    account: "a@example.com",
    status: "ok",
    duration_ms: 70,
    target_playlist_hash: "a".repeat(64),
    operation: "playlist_item_remove",
    policy_decision: "allowed",
  };
}

/** v1.49 — youtube_playlist_delete tier-denied attempt (status=error). MUST be
 *  excluded from the density alert count. */
function playlistDeleteTierDeniedRow(offsetMin: number): object {
  const ts = new Date(Date.now() - offsetMin * 60_000).toISOString();
  return {
    ts,
    tool: "youtube_playlist_delete",
    account: "a@example.com",
    status: "error",
    duration_ms: 4,
    target_playlist_hash: "b".repeat(64),
    operation: "playlist_delete",
    policy_decision: "denied_tier",
  };
}

describe("audit deletes", () => {
  test("sec-M2 sentinel: 5 successful + 3 tier-denied at threshold=5 → ALERT", async () => {
    const rows = [
      deleteRow("youtube", 1),
      deleteRow("youtube", 2),
      deleteRow("youtube", 3),
      deleteRow("calendar", 4),
      deleteRow("calendar", 5),
      tierDeniedRow(6),
      tierDeniedRow(7),
      tierDeniedRow(8),
    ];
    await writeAuditLines(rows);
    const { io, out } = captureIO();
    await runCli(["audit", "deletes", "--threshold", "5"], io);
    const text = out.join("\n");
    // ALERT must fire on count=5 (NOT 8 — tier-denied excluded):
    expect(text).toContain("total destructive:       5");
    expect(text).toContain("ALERT");
  });

  test("sec-M2 sentinel: same rows at threshold=8 → NO ALERT (denials excluded)", async () => {
    const rows = [
      deleteRow("youtube", 1),
      deleteRow("youtube", 2),
      deleteRow("youtube", 3),
      deleteRow("calendar", 4),
      deleteRow("calendar", 5),
      tierDeniedRow(6),
      tierDeniedRow(7),
      tierDeniedRow(8),
    ];
    await writeAuditLines(rows);
    const { io, out } = captureIO();
    await runCli(["audit", "deletes", "--threshold", "8"], io);
    const text = out.join("\n");
    // Count remains 5 (denials never counted); 5 < 8 → no ALERT:
    expect(text).toContain("total destructive:       5");
    expect(text).not.toContain("ALERT");
    expect(text).toContain("OK");
  });

  test("--window 1h excludes events older than 1h", async () => {
    const rows = [
      deleteRow("youtube", 30),   // 30 min ago — in window
      deleteRow("youtube", 90),   // 90 min ago — out of window
      deleteRow("calendar", 120), // 2 hours ago — out
    ];
    await writeAuditLines(rows);
    const { io, out } = captureIO();
    await runCli(["audit", "deletes", "--window", "1h", "--threshold", "1"], io);
    expect(out.join("\n")).toContain("total destructive:       1");
  });

  test("--window Nm (minutes; ≥60m to clear 1h floor) accepted", async () => {
    const rows = [deleteRow("youtube", 10)];
    await writeAuditLines(rows);
    const { io, out } = captureIO();
    // Window range is 1h-720h per design Q4. 60m = 1h is the floor; values
    // below the floor (e.g., 30m = 0.5h) correctly error pre-read.
    await runCli(["audit", "deletes", "--window", "60m", "--threshold", "1"], io);
    expect(out.join("\n")).toContain("total destructive:       1");
  });

  test("--window 30m → CliError (below 1h floor)", async () => {
    const { io } = captureIO();
    await expect(runCli(["audit", "deletes", "--window", "30m"], io)).rejects.toBeInstanceOf(CliError);
  });

  test("--window Nd (days) accepted", async () => {
    const rows = [deleteRow("youtube", 60 * 24)]; // 1 day ago
    await writeAuditLines(rows);
    const { io, out } = captureIO();
    await runCli(["audit", "deletes", "--window", "2d", "--threshold", "1"], io);
    expect(out.join("\n")).toContain("total destructive:       1");
  });

  test("--window 0h → CliError", async () => {
    const { io } = captureIO();
    await expect(runCli(["audit", "deletes", "--window", "0h"], io)).rejects.toBeInstanceOf(CliError);
  });

  test("--window 1y → CliError (unsupported unit)", async () => {
    const { io } = captureIO();
    await expect(runCli(["audit", "deletes", "--window", "1y"], io)).rejects.toBeInstanceOf(CliError);
  });

  test("--window 1.5h → CliError (non-integer)", async () => {
    const { io } = captureIO();
    await expect(runCli(["audit", "deletes", "--window", "1.5h"], io)).rejects.toBeInstanceOf(CliError);
  });

  test("--window 721h → CliError (above 720h cap, design Q4)", async () => {
    const { io } = captureIO();
    await expect(runCli(["audit", "deletes", "--window", "721h"], io)).rejects.toBeInstanceOf(CliError);
  });

  test("--window 1w → CliError (unsupported unit)", async () => {
    const { io } = captureIO();
    await expect(runCli(["audit", "deletes", "--window", "1w"], io)).rejects.toBeInstanceOf(CliError);
  });

  test("--threshold 0 → CliError", async () => {
    const { io } = captureIO();
    await expect(runCli(["audit", "deletes", "--threshold", "0"], io)).rejects.toBeInstanceOf(CliError);
  });

  test("--threshold 'abc' → CliError", async () => {
    const { io } = captureIO();
    await expect(runCli(["audit", "deletes", "--threshold", "abc"], io)).rejects.toBeInstanceOf(CliError);
  });

  test("aggregate-only output (sec hook #6): hash fields NEVER echoed", async () => {
    await writeAuditLines([deleteRow("youtube", 1), deleteRow("calendar", 2)]);
    const { io, out } = captureIO();
    await runCli(["audit", "deletes", "--threshold", "1"], io);
    const text = out.join("\n");
    // Per-row hash MUST NOT appear in deletes output:
    expect(text).not.toContain("1".repeat(64));
    expect(text).not.toContain("2".repeat(64));
    // Aggregates only:
    expect(text).toContain("youtube_comment_delete:");
    expect(text).toContain("calendar_delete_event:");
  });

  test("--json mode includes alert boolean", async () => {
    await writeAuditLines([deleteRow("youtube", 1)]);
    const { io, out } = captureIO();
    await runCli(["audit", "deletes", "--threshold", "1", "--json"], io);
    const line = out.find((l) => l.startsWith("{"));
    expect(line).toBeDefined();
    const parsed = JSON.parse(line!) as {
      alert: boolean;
      total: number;
      youtube_comment_delete: number;
    };
    expect(parsed.alert).toBe(true);
    expect(parsed.total).toBe(1);
    expect(parsed.youtube_comment_delete).toBe(1);
  });

  test("empty audit.jsonl → 0 destructive, no ALERT", async () => {
    const { io, out } = captureIO();
    await runCli(["audit", "deletes"], io);
    const text = out.join("\n");
    expect(text).toContain("total destructive:       0");
    expect(text).not.toContain("ALERT");
  });

  /* ── drive_delete_file (permanent) counted; drive_trash_file (recoverable) + failures excluded ── */

  test("drive_delete_file ok rows counted; drive_trash_file / error rows / allowlist denials excluded", async () => {
    const at = (m: number): string => new Date(Date.now() - m * 60_000).toISOString();
    const base = { account: "a@example.com", duration_ms: 50 };
    await writeAuditLines([
      { ...base, ts: at(1), tool: "drive_delete_file", status: "ok" },
      { ...base, ts: at(2), tool: "drive_delete_file", status: "ok" },
      { ...base, ts: at(3), tool: "drive_delete_file", status: "error", error_code: -32060 },
      { ...base, ts: at(4), tool: "drive_trash_file", status: "ok" },
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "deletes", "--threshold", "5"], io);
    const text = out.join("\n");
    expect(text).toContain("drive_delete_file:       2");
    expect(text).toContain("total destructive:       2");
  });

  /* ── v1.19 Phase 2b — tasks_delete extension to density alert ── */

  test("v1.19 sec-H2 — 3-tool destructive mix (youtube + calendar + tasks) at threshold=3 → ALERT", async () => {
    await writeAuditLines([
      deleteRow("youtube", 1),
      deleteRow("calendar", 2),
      tasksDeleteRow(3),
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "deletes", "--threshold", "3"], io);
    const text = out.join("\n");
    expect(text).toContain("youtube_comment_delete:  1");
    expect(text).toContain("calendar_delete_event:   1");
    expect(text).toContain("tasks_delete:            1");
    expect(text).toContain("total destructive:       3");
    expect(text).toContain("ALERT");
  });

  test("v1.19 sec-H2 — tasks_delete tier-denied attempts (operation=delete + status=error) EXCLUDED from count", async () => {
    await writeAuditLines([
      tasksDeleteRow(1),
      tasksDeleteTierDeniedRow(2),
      tasksDeleteTierDeniedRow(3),
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "deletes", "--threshold", "1"], io);
    const text = out.join("\n");
    // Only the status=ok row counts; 2 tier-denied excluded
    expect(text).toContain("tasks_delete:            1");
    expect(text).toContain("total destructive:       1");
  });

  test("v1.19 sec-H2 — tasks_create / tasks_update NOT counted as destructive (operation discriminator)", async () => {
    // Even though tasksMutationMeta carries target_tasklist_hash on ALL 3
    // operations, only operation==="delete" rows count as destructive.
    await writeAuditLines([tasksCreateRow(1), tasksCreateRow(2)]);
    const { io, out } = captureIO();
    await runCli(["audit", "deletes", "--threshold", "1"], io);
    const text = out.join("\n");
    expect(text).toContain("tasks_delete:            0");
    expect(text).toContain("total destructive:       0");
    expect(text).not.toContain("ALERT");
  });

  test("v1.19 sec-H2 — --json mode emits tasks_delete count", async () => {
    await writeAuditLines([tasksDeleteRow(1)]);
    const { io, out } = captureIO();
    await runCli(["audit", "deletes", "--threshold", "1", "--json"], io);
    const line = out.find((l) => l.startsWith("{"));
    expect(line).toBeDefined();
    const parsed = JSON.parse(line!) as {
      tasks_delete: number;
      total: number;
      alert: boolean;
    };
    expect(parsed.tasks_delete).toBe(1);
    expect(parsed.total).toBe(1);
    expect(parsed.alert).toBe(true);
  });

  /* ── v1.49 — youtube_playlist_delete extension to density alert ── */

  test("v1.49 — 4-tool destructive mix (youtube comment + calendar + tasks + playlist) at threshold=4 → ALERT", async () => {
    await writeAuditLines([
      deleteRow("youtube", 1),
      deleteRow("calendar", 2),
      tasksDeleteRow(3),
      playlistDeleteRow(4),
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "deletes", "--threshold", "4"], io);
    const text = out.join("\n");
    expect(text).toContain("youtube_comment_delete:  1");
    expect(text).toContain("calendar_delete_event:   1");
    expect(text).toContain("tasks_delete:            1");
    expect(text).toContain("youtube_playlist_delete: 1");
    expect(text).toContain("total destructive:       4");
    expect(text).toContain("ALERT");
  });

  test("v1.49 — playlist_item_remove (recoverable) NOT counted as destructive", async () => {
    // Even though playlistMutationMeta carries target_playlist_hash on ALL ops,
    // only operation==="playlist_delete" counts. Removal is re-insertable.
    await writeAuditLines([playlistItemRemoveRow(1), playlistItemRemoveRow(2)]);
    const { io, out } = captureIO();
    await runCli(["audit", "deletes", "--threshold", "1"], io);
    const text = out.join("\n");
    expect(text).toContain("youtube_playlist_delete: 0");
    expect(text).toContain("total destructive:       0");
    expect(text).not.toContain("ALERT");
  });

  test("v1.49 — playlist_delete tier-denied attempts (status=error) EXCLUDED from count", async () => {
    await writeAuditLines([
      playlistDeleteRow(1),
      playlistDeleteTierDeniedRow(2),
      playlistDeleteTierDeniedRow(3),
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "deletes", "--threshold", "1"], io);
    const text = out.join("\n");
    expect(text).toContain("youtube_playlist_delete: 1");
    expect(text).toContain("total destructive:       1");
  });

  test("v1.49 — --json mode emits youtube_playlist_delete count", async () => {
    await writeAuditLines([playlistDeleteRow(1)]);
    const { io, out } = captureIO();
    await runCli(["audit", "deletes", "--threshold", "1", "--json"], io);
    const line = out.find((l) => l.startsWith("{"));
    expect(line).toBeDefined();
    const parsed = JSON.parse(line!) as {
      youtube_playlist_delete: number;
      total: number;
      alert: boolean;
    };
    expect(parsed.youtube_playlist_delete).toBe(1);
    expect(parsed.total).toBe(1);
    expect(parsed.alert).toBe(true);
  });

  /* ── v1.24 Phase 2 Item 3 — exit-code parity with `audit suspicious` ── */

  test("v1.24 Item 3 — ALERT path sets process.exitCode = 1 (above threshold)", async () => {
    // 5 destructive rows, threshold=3 → 5 ≥ 3 → ALERT
    await writeAuditLines([
      deleteRow("youtube", 1),
      deleteRow("youtube", 2),
      deleteRow("youtube", 3),
      deleteRow("calendar", 4),
      deleteRow("calendar", 5),
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "deletes", "--threshold", "3"], io);
    expect(out.join("\n")).toContain("ALERT");
    expect(process.exitCode).toBe(1);
  });

  test("v1.24 Item 3 — ALERT path at exact threshold (boundary) sets process.exitCode = 1", async () => {
    // 3 destructive rows, threshold=3 → 3 ≥ 3 → ALERT
    await writeAuditLines([
      deleteRow("youtube", 1),
      deleteRow("calendar", 2),
      tasksDeleteRow(3),
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "deletes", "--threshold", "3"], io);
    expect(out.join("\n")).toContain("ALERT");
    expect(process.exitCode).toBe(1);
  });

  test("v1.24 Item 3 — OK path explicitly sets process.exitCode = 0 (below threshold)", async () => {
    // 2 destructive rows, threshold=5 → 2 < 5 → OK
    await writeAuditLines([deleteRow("youtube", 1), deleteRow("calendar", 2)]);
    const { io, out } = captureIO();
    await runCli(["audit", "deletes", "--threshold", "5"], io);
    expect(out.join("\n")).toContain("OK");
    expect(process.exitCode).toBe(0);
  });

  test("v1.24 Item 3 — OK path resets exit code to 0 (no leak from prior runs)", async () => {
    // Simulate a prior CLI run leaving non-zero exit code on the process
    process.exitCode = 7;
    await writeAuditLines([deleteRow("youtube", 1)]);
    const { io } = captureIO();
    await runCli(["audit", "deletes", "--threshold", "5"], io);
    // Below threshold (1 < 5) → OK → exit code must be explicitly 0,
    // overwriting the prior 7.
    expect(process.exitCode).toBe(0);
  });

  test("v1.24 Item 3 — ALERT path overwrites prior non-zero exit code", async () => {
    // Re-entrancy isolation: prior process.exitCode does not leak even
    // when ALERT also fires (different code path than the OK reset above).
    process.exitCode = 7;
    await writeAuditLines([deleteRow("youtube", 1), deleteRow("calendar", 2)]);
    const { io } = captureIO();
    await runCli(["audit", "deletes", "--threshold", "1"], io);
    expect(process.exitCode).toBe(1);
  });

  test("v1.24 Item 3 — USAGE help text mentions exit-code contract", async () => {
    // Invalid flag triggers USAGE in the CliError message — must include the
    // v1.24 Phase 2 parity note matching `audit suspicious` USAGE wording.
    const { io } = captureIO();
    try {
      await runCli(["audit", "deletes", "--bogus"], io);
      throw new Error("expected CliError");
    } catch (e) {
      expect(e).toBeInstanceOf(CliError);
      expect(String((e as CliError).message)).toContain(
        "ALERT exits non-zero",
      );
    }
  });
});
