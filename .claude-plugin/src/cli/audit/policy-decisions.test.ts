import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { AUDIT_META_CHANNELS } from "../../audit";
import { CliError, runCli, type CliIO } from "../../cli";

let tmp: string;
let prevEnv: string | undefined;

beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  tmp = await fs.mkdtemp(path.join(tmpdir(), "audit-pd-"));
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

describe("audit policy-decisions", () => {
  test("union iteration across 5 channels (sec-M3 dynamic + v1.19 Phase 2b tasksMutation)", async () => {
    await writeAuditLines([
      // commentPost row (allowed)
      {
        ts: "2026-05-24T10:00:00Z",
        tool: "youtube_video_comment_post",
        account: "a@example.com",
        status: "ok",
        target_video_hash: "v".repeat(64),
        comment_length: 10,
        policy_decision: "allowed",
      },
      // calendarMutation row (allowed)
      {
        ts: "2026-05-24T10:01:00Z",
        tool: "calendar_update_event",
        account: "a@example.com",
        status: "ok",
        target_event_hash: "e".repeat(64),
        policy_decision: "allowed",
      },
      // docsModify row (denied_tier)
      {
        ts: "2026-05-24T10:02:00Z",
        tool: "docs_modify_structured",
        account: "a@example.com",
        status: "error",
        target_document_id_hash: "d".repeat(64),
        modification_count: 1,
        request_types_csv: "insertText",
        policy_decision: "denied_tier",
      },
      // commentDelete row (deleted)
      {
        ts: "2026-05-24T10:03:00Z",
        tool: "youtube_comment_delete",
        account: "a@example.com",
        status: "ok",
        target_comment_id_hash: "c".repeat(64),
        policy_decision: "deleted",
      },
      // v1.19 Phase 2b — tasksMutation row (allowed; operation=create)
      {
        ts: "2026-05-24T10:04:00Z",
        tool: "tasks_create",
        account: "a@example.com",
        status: "ok",
        target_tasklist_hash: "t".repeat(64),
        operation: "create",
        policy_decision: "allowed",
      },
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "policy-decisions"], io);
    const text = out.join("\n");
    // All 5 channel labels present (from registry):
    for (const entry of Object.values(AUDIT_META_CHANNELS)) {
      expect(text).toContain(`channel: ${entry.label}`);
    }
    // Decisions from each channel surfaced (commentPost + calendarMutation +
    // tasksMutation all show "allowed" — count is 3):
    expect(text).toMatch(/allowed\s+\d/);
    expect(text).toMatch(/denied_tier\s+1/);
    expect(text).toMatch(/deleted\s+1/);
  });

  test("sec-M3 sentinel: unknown channel handled gracefully (v1.19+ drift)", async () => {
    await writeAuditLines([
      // Row with policy_decision but no recognized channel discriminator
      // (no target_video_hash / target_event_hash / target_document_id_hash /
      // target_comment_id_hash, no nested meta key from registry):
      {
        ts: "2026-05-24T10:00:00Z",
        tool: "future_v1_19_tool",
        account: "a@example.com",
        status: "ok",
        policy_decision: "future_decision_value",
      },
    ]);
    const { io, out, err } = captureIO();
    await runCli(["audit", "policy-decisions"], io);
    const text = out.join("\n");
    // Stderr warning fires:
    expect(err.join("\n")).toMatch(/future drift/);
    expect(err.join("\n")).toContain("future_decision_value");
    // Output renders the unknown channel section:
    expect(text).toContain("channel: unknown");
    expect(text).toContain("future_decision_value");
  });

  test("--since filters cutoff-pre rows", async () => {
    await writeAuditLines([
      {
        ts: "2026-05-20T10:00:00Z",
        tool: "youtube_video_comment_post",
        account: "a@example.com",
        status: "ok",
        target_video_hash: "v".repeat(64),
        comment_length: 5,
        policy_decision: "allowed",
      },
      {
        ts: "2026-05-24T10:00:00Z",
        tool: "youtube_video_comment_post",
        account: "a@example.com",
        status: "ok",
        target_video_hash: "v".repeat(64),
        comment_length: 5,
        policy_decision: "denied_burst_limit",
      },
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "policy-decisions", "--since", "2026-05-22"], io);
    const text = out.join("\n");
    expect(text).toContain("denied_burst_limit");
    expect(text).not.toMatch(/allowed\s+1/);
  });

  test("--since malformed → CliError pre-read", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["audit", "policy-decisions", "--since", "not-a-date"], io),
    ).rejects.toBeInstanceOf(CliError);
  });

  test("--json mode emits per-channel structure", async () => {
    await writeAuditLines([
      {
        ts: "2026-05-24T10:00:00Z",
        tool: "youtube_video_comment_post",
        account: "a@example.com",
        status: "ok",
        target_video_hash: "v".repeat(64),
        comment_length: 5,
        policy_decision: "allowed",
      },
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "policy-decisions", "--json"], io);
    const line = out.find((l) => l.startsWith("{"));
    expect(line).toBeDefined();
    const parsed = JSON.parse(line!) as { channels: Record<string, Record<string, number>> };
    expect(parsed.channels.commentPost?.allowed).toBe(1);
  });

  test("empty file → 5 channels show '(no occurrences in window)'", async () => {
    const { io, out } = captureIO();
    await runCli(["audit", "policy-decisions"], io);
    const text = out.join("\n");
    expect(text).toContain("(no occurrences in window)");
  });

  /* ── v1.19 Phase 2b — registry-driven flattened-row detector tests ── */

  test("v1.19 sec-H1 — flattened tasksMutation row (target_tasklist_hash) classified via registry-driven flatHash", async () => {
    await writeAuditLines([
      // Phase 2b flattened tasksMutation row — discriminated by
      // AUDIT_META_CHANNELS.tasksMutationMeta.flatHash === "target_tasklist_hash"
      {
        ts: "2026-05-24T10:00:00Z",
        tool: "tasks_update",
        account: "a@example.com",
        status: "ok",
        target_tasklist_hash: "t".repeat(64),
        target_task_hash: "u".repeat(64),
        operation: "update",
        policy_decision: "allowed",
      },
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "policy-decisions"], io);
    const text = out.join("\n");
    // tasksMutation channel section MUST appear with the allowed count.
    expect(text).toContain("channel: tasksMutation");
    expect(text).toMatch(/allowed\s+1/);
    // NOT bucketed under "unknown" (registry-driven detection worked).
    expect(text).not.toContain("channel: unknown");
  });

  test("v1.19 sec-H1 — tasks_delete row (operation=delete) classified into tasksMutation channel + policy_decision=allowed", async () => {
    await writeAuditLines([
      {
        ts: "2026-05-24T10:00:00Z",
        tool: "tasks_delete",
        account: "a@example.com",
        status: "ok",
        target_tasklist_hash: "t".repeat(64),
        target_task_hash: "d".repeat(64),
        operation: "delete",
        policy_decision: "allowed",
      },
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "policy-decisions"], io);
    const text = out.join("\n");
    expect(text).toContain("channel: tasksMutation");
    // policy_decision is "allowed" (binary; NOT "deleted" — that pattern is
    // v1.17 commentDeleteMeta only). Discrimination uses operation enum.
    expect(text).toMatch(/allowed\s+1/);
    expect(text).not.toContain("deleted");
  });

  test("v1.19 — registry-driven flattened-detector handles all 5 channels (sec-L4 drift closure)", async () => {
    // Synthetic: a row carrying ONLY the channel's flatHash field (no nested
    // meta) should be classified via the registry-driven loop. Verifies the
    // refactor closes the v1.18 sec-L4 hard-coded switch drift class.
    await writeAuditLines([
      // commentPostMeta flatHash
      {
        ts: "2026-05-24T10:00:00Z",
        tool: "youtube_video_comment_post",
        account: "a@example.com",
        status: "ok",
        target_video_hash: "v".repeat(64),
        policy_decision: "allowed",
      },
      // calendarMutationMeta flatHash
      {
        ts: "2026-05-24T10:01:00Z",
        tool: "calendar_delete_event",
        account: "a@example.com",
        status: "ok",
        target_event_hash: "e".repeat(64),
        policy_decision: "allowed",
      },
      // docsModifyMeta flatHash
      {
        ts: "2026-05-24T10:02:00Z",
        tool: "docs_modify_structured",
        account: "a@example.com",
        status: "ok",
        target_document_id_hash: "d".repeat(64),
        policy_decision: "allowed",
      },
      // commentDeleteMeta flatHash
      {
        ts: "2026-05-24T10:03:00Z",
        tool: "youtube_comment_delete",
        account: "a@example.com",
        status: "ok",
        target_comment_id_hash: "c".repeat(64),
        policy_decision: "deleted",
      },
      // tasksMutationMeta flatHash (v1.19 Phase 2b — registry-driven discovery)
      {
        ts: "2026-05-24T10:04:00Z",
        tool: "tasks_create",
        account: "a@example.com",
        status: "ok",
        target_tasklist_hash: "t".repeat(64),
        operation: "create",
        policy_decision: "allowed",
      },
      // sheetsMutationMeta flatHash (v1.20 Phase 1b-2 — FIRST production test
      // of v1.19 path-(b) registry refactor: policy-decisions.ts auto-detects
      // the new channel via AUDIT_META_CHANNELS.sheetsMutationMeta.flatHash
      // with ZERO code edit at the policy-decisions site).
      {
        ts: "2026-05-24T10:05:00Z",
        tool: "sheets_create",
        account: "a@example.com",
        status: "ok",
        target_spreadsheet_id_hash: "s".repeat(64),
        operation: "create",
        policy_decision: "allowed",
      },
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "policy-decisions"], io);
    const text = out.join("\n");
    // NONE bucketed under unknown — all 6 flatHash names recognized.
    expect(text).not.toContain("channel: unknown");
    // All 6 channel sections rendered.
    for (const entry of Object.values(AUDIT_META_CHANNELS)) {
      expect(text).toContain(`channel: ${entry.label}`);
    }
  });

  test("v1.20 Phase 1b-2 — sheetsMutation flattened row (target_spreadsheet_id_hash) auto-discovered via registry-driven flatHash WITHOUT any policy-decisions.ts edit (Risk 7 production test from design §11)", async () => {
    // This is the FIRST production validation of the v1.19 path-(b)
    // AUDIT_META_CHANNELS registry refactor. v1.19 was the refactor
    // (replacing the hard-coded 4-name switch with registry-driven
    // iteration); v1.20 Phase 1b-2 is the production test that adding a 6th
    // channel ONLY requires the registry entry — no change to
    // policy-decisions.ts.
    //
    // If this test ever fails, it means the registry-driven discovery
    // regressed (drift class re-opened); the fix is to restore the
    // detectChannel() function in policy-decisions.ts to iterate
    // AUDIT_META_CHANNELS via entry.flatHash.
    await writeAuditLines([
      // Phase 1b-2 sheets_create flattened row — discriminated by
      // AUDIT_META_CHANNELS.sheetsMutationMeta.flatHash ===
      // "target_spreadsheet_id_hash"
      {
        ts: "2026-05-25T10:00:00Z",
        tool: "sheets_create",
        account: "a@example.com",
        status: "ok",
        target_spreadsheet_id_hash: "s".repeat(64),
        operation: "create",
        policy_decision: "allowed",
      },
      // Phase 1b-2 sheets_append_values flattened row — same flatHash;
      // target_range_hash also present (additional discriminator).
      {
        ts: "2026-05-25T10:01:00Z",
        tool: "sheets_append_values",
        account: "a@example.com",
        status: "ok",
        target_spreadsheet_id_hash: "s".repeat(64),
        target_range_hash: "r".repeat(64),
        operation: "append_values",
        policy_decision: "allowed",
      },
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "policy-decisions"], io);
    const text = out.join("\n");
    // sheetsMutation channel section MUST appear (registry-driven discovery
    // worked) — NOT bucketed under "unknown".
    expect(text).toContain("channel: sheetsMutation");
    expect(text).not.toContain("channel: unknown");
    // policy_decision allowed count = 2 (both flattened rows classified
    // under the sheetsMutation channel).
    expect(text).toMatch(/allowed\s+2/);
  });
});

describe("audit dispatch", () => {
  test("unknown audit subcommand → CliError", async () => {
    const { io } = captureIO();
    await expect(runCli(["audit", "bogus"], io)).rejects.toBeInstanceOf(CliError);
  });

  test("`audit` with no sub → CliError with USAGE", async () => {
    const { io } = captureIO();
    await expect(runCli(["audit"], io)).rejects.toThrow(/recent\|stats\|deletes\|policy-decisions/);
  });
});
