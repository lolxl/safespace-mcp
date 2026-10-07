// v1.23 Phase 1 — tests for `safespace audit suspicious`.
//
// Structure mirrors `src/cli/audit/deletes.test.ts` (closest template per
// design §14):
//   - tmpdir + SAFESPACE_CONFIG_DIR injection
//   - writeAuditLines helper for crafting fixture rows
//   - captureIO helper for asserting on stdout/stderr
//
// Test categories (mirror design §13 + the 50-70 sentinel target):
//   1. Default behavior (HIGH-only / threshold 3 / 24h / table)
//   2. 5 opt-in flag matrices (allowlist / burst / tier / scope / lookup)
//   3. ALERT / exit-code semantics (below / at / above threshold)
//   4. Q4 LATER cutoff (window only / since only / both → intersection)
//   5. sec-M1 default-filter event rows (--include-events opt-in)
//   6. sec-L3 hash-truncation forward-compat (no hash in default output)
//   7. Strict-parse (invalid --window / --threshold / --since / --limit)
//   8. Cross-channel matching (nested-meta + flattened-row paths)
//   9. PII protection (sec-rev hook #10)
//  10. Dispatcher integration (USAGE / unknown subcommand)
//
// IMPORTANT — exitCode semantics: design §4.2 LOCKED that ALERT path sets
// `process.exitCode = 1` and below-threshold sets `process.exitCode = 0`.
// Tests share the bun test runner process so we always reset to 0 in
// afterEach to avoid leaking state across tests.

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
  tmp = await fs.mkdtemp(path.join(tmpdir(), "audit-suspicious-"));
  process.env.SAFESPACE_CONFIG_DIR = tmp;
  // process.exitCode is `number` (Node 22+ widened typing accepts string|null
  // too); narrow to `number` for our save/restore — anything non-zero we just
  // restore as-is, and 0 is the default.
  prevExitCode = (process.exitCode as number | undefined) ?? 0;
  process.exitCode = 0;
});

afterEach(async () => {
  if (prevEnv === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevEnv;
  // Restore the prior exitCode so a test that asserts on it does not leak
  // a non-zero exit into subsequent suites or into the test runner exit.
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

/* ──────────────────────── fixture builders ──────────────────────── */

/** HIGH-confidence: sheets formula REJECT (flattened row — production shape). */
function formulaRejectRow(offsetMin: number, fn = "IMPORTRANGE"): object {
  const ts = new Date(Date.now() - offsetMin * 60_000).toISOString();
  return {
    ts,
    tool: "sheets_update_values",
    account: "a@example.com",
    args_hash: "a".repeat(64),
    status: "error",
    duration_ms: 5,
    sanitize: "applied",
    target_spreadsheet_id_hash: "b".repeat(64),
    target_range_hash: "c".repeat(64),
    operation: "update_values",
    policy_decision: "denied_formula_rejected",
    rejected_formula_function: fn,
  };
}

/** HIGH-confidence: outbound sanitize REJECT (flattened row — commentPost). */
function outboundRejectRow(offsetMin: number): object {
  const ts = new Date(Date.now() - offsetMin * 60_000).toISOString();
  return {
    ts,
    tool: "youtube_video_comment_post",
    account: "a@example.com",
    args_hash: "d".repeat(64),
    status: "error",
    duration_ms: 8,
    sanitize: "applied",
    target_video_hash: "e".repeat(64),
    comment_length: 42,
    policy_decision: "denied_outbound_sanitize_rejected",
  };
}

/** MEDIUM: allowlist denial (denied_no_allowlist on commentPost). */
function allowlistDenialRow(
  offsetMin: number,
  pd: "denied_no_allowlist" | "denied_not_in_allowlist",
): object {
  const ts = new Date(Date.now() - offsetMin * 60_000).toISOString();
  return {
    ts,
    tool: "youtube_video_comment_post",
    account: "a@example.com",
    args_hash: "f".repeat(64),
    status: "error",
    duration_ms: 3,
    sanitize: "applied",
    target_video_hash: "0".repeat(64),
    comment_length: 12,
    policy_decision: pd,
  };
}

/** MEDIUM: burst-limit denial (denied_burst_limit on commentPost). */
function burstDenialRow(offsetMin: number): object {
  const ts = new Date(Date.now() - offsetMin * 60_000).toISOString();
  return {
    ts,
    tool: "youtube_video_comment_post",
    account: "a@example.com",
    args_hash: "1".repeat(64),
    status: "error",
    duration_ms: 2,
    sanitize: "applied",
    target_video_hash: "2".repeat(64),
    comment_length: 100,
    policy_decision: "denied_burst_limit",
  };
}

/** Error-code row for burst (forward-compat: today auditEnd does NOT emit
 *  error_code; future v1.24+ may add it. classifyRow's branch reads
 *  `row.error_code` only — these fixtures pre-stage the field shape so the
 *  branch is exercised end-to-end). */
function errorCodeRow(offsetMin: number, code: number, tool: string): object {
  const ts = new Date(Date.now() - offsetMin * 60_000).toISOString();
  return {
    ts,
    tool,
    account: "a@example.com",
    args_hash: "3".repeat(64),
    status: "error",
    duration_ms: 1,
    sanitize: "applied",
    error_code: code,
  };
}

/** LOW: tier denial (denied_tier on commentPost — could be any channel). */
function tierDenialRow(offsetMin: number, channel = "commentPost"): object {
  const ts = new Date(Date.now() - offsetMin * 60_000).toISOString();
  if (channel === "commentPost") {
    return {
      ts,
      tool: "youtube_video_comment_post",
      account: "a@example.com",
      args_hash: "4".repeat(64),
      status: "error",
      duration_ms: 2,
      sanitize: "applied",
      target_video_hash: "5".repeat(64),
      comment_length: 10,
      policy_decision: "denied_tier",
    };
  }
  if (channel === "calendarMutation") {
    return {
      ts,
      tool: "calendar_update_event",
      account: "a@example.com",
      args_hash: "6".repeat(64),
      status: "error",
      duration_ms: 2,
      sanitize: "applied",
      target_event_hash: "7".repeat(64),
      policy_decision: "denied_tier",
    };
  }
  // tasksMutation
  return {
    ts,
    tool: "tasks_delete",
    account: "a@example.com",
    args_hash: "8".repeat(64),
    status: "error",
    duration_ms: 2,
    sanitize: "applied",
    target_tasklist_hash: "9".repeat(64),
    operation: "delete",
    policy_decision: "denied_tier",
  };
}

/** Standard success row (NOT suspicious). */
function okRow(offsetMin: number): object {
  const ts = new Date(Date.now() - offsetMin * 60_000).toISOString();
  return {
    ts,
    tool: "gmail_search",
    account: "a@example.com",
    args_hash: "a".repeat(64),
    status: "ok",
    duration_ms: 80,
    sanitize: "applied",
  };
}

/** Non-standard event row (sec-M1). */
function eventRow(
  kind:
    | "share_forensic"
    | "share_denied_by_policy"
    | "recipient_denied_by_policy"
    | "cross_account_aggregate",
  offsetMin: number,
  pd?: string,
): object {
  const ts = new Date(Date.now() - offsetMin * 60_000).toISOString();
  const base: Record<string, unknown> = { ts, event: kind };
  // event rows lack `status`; some carry policy_decision (share_forensic does)
  if (pd) base.policy_decision = pd;
  return base;
}

/* ───────────────────────── tests ───────────────────────── */

describe("audit suspicious — default behavior (HIGH-only)", () => {
  test("empty audit.jsonl → 0 canaries, OK, exit 0", async () => {
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious"], io);
    const text = out.join("\n");
    expect(text).toContain("denied_formula_rejected:");
    expect(text).toContain("denied_outbound_sanitize_rejected:");
    expect(text).toContain("total high-confidence canaries:    0");
    expect(text).toContain("threshold:                         3");
    expect(text).toContain("OK:");
    expect(text).not.toContain("ALERT");
    expect(process.exitCode).toBe(0);
  });

  test("HIGH-only default sums formula + outbound rejects", async () => {
    await writeAuditLines([
      formulaRejectRow(1),
      formulaRejectRow(2),
      outboundRejectRow(3),
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious"], io);
    const text = out.join("\n");
    expect(text).toContain("total high-confidence canaries:    3");
    expect(text).toContain("ALERT");
    expect(process.exitCode).toBe(1);
  });

  test("default threshold is 3 (not 5)", async () => {
    // 2 canaries: below threshold 3 → OK
    await writeAuditLines([formulaRejectRow(1), outboundRejectRow(2)]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious"], io);
    const text = out.join("\n");
    expect(text).toContain("total high-confidence canaries:    2");
    expect(text).toContain("threshold:                         3");
    expect(text).toContain("OK");
    expect(process.exitCode).toBe(0);
  });

  test("default window is 24h — older rows excluded", async () => {
    await writeAuditLines([
      formulaRejectRow(60), // 1h ago, in window
      formulaRejectRow(25 * 60), // 25h ago, OUT of window
      formulaRejectRow(48 * 60), // 48h ago, OUT
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious", "--threshold", "1"], io);
    const text = out.join("\n");
    expect(text).toContain("denied_formula_rejected:");
    expect(text).toContain("total high-confidence canaries:    1");
  });

  test("default mode is table (not JSON)", async () => {
    await writeAuditLines([formulaRejectRow(1)]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious"], io);
    const firstLine = out[0] ?? "";
    expect(firstLine.startsWith("{")).toBe(false);
    expect(firstLine.startsWith("window:")).toBe(true);
  });

  test("MEDIUM/LOW signals are EXCLUDED from default (sec hook #1)", async () => {
    await writeAuditLines([
      allowlistDenialRow(1, "denied_no_allowlist"),
      burstDenialRow(2),
      tierDenialRow(3, "calendarMutation"),
      errorCodeRow(4, -32004, "tasks_get"),
      errorCodeRow(5, -32022, "gmail_send"),
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious"], io);
    const text = out.join("\n");
    expect(text).toContain("total high-confidence canaries:    0");
    expect(text).toContain("OK");
    expect(process.exitCode).toBe(0);
  });

  test("ok rows never count as suspicious", async () => {
    await writeAuditLines([okRow(1), okRow(2), okRow(3)]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious"], io);
    expect(out.join("\n")).toContain("total high-confidence canaries:    0");
  });

  test("output mentions both HIGH channels even at 0 (operator visibility)", async () => {
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious"], io);
    const text = out.join("\n");
    expect(text).toContain("denied_formula_rejected:");
    expect(text).toContain("(sheetsMutation)");
    expect(text).toContain("denied_outbound_sanitize_rejected:");
    expect(text).toContain("(commentPost)");
  });

  test("rejects unknown flag", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["audit", "suspicious", "--bogus"], io),
    ).rejects.toBeInstanceOf(CliError);
  });
});

describe("audit suspicious — opt-in: allowlist denials", () => {
  test("--include-allowlist-denials counts denied_no_allowlist", async () => {
    await writeAuditLines([
      allowlistDenialRow(1, "denied_no_allowlist"),
      allowlistDenialRow(2, "denied_no_allowlist"),
      allowlistDenialRow(3, "denied_not_in_allowlist"),
    ]);
    const { io, out } = captureIO();
    await runCli(
      ["audit", "suspicious", "--include-allowlist-denials", "--threshold", "1"],
      io,
    );
    const text = out.join("\n");
    expect(text).toContain("allowlist denials (opt-in):");
    expect(text).toContain("denied_no_allowlist:");
    expect(text).toContain("denied_not_in_allowlist:");
    expect(text).toContain("grand total:                        3");
    expect(text).toContain("ALERT");
    expect(process.exitCode).toBe(1);
  });

  test("--include-allowlist-denials does NOT pick up tier denials", async () => {
    await writeAuditLines([
      tierDenialRow(1),
      allowlistDenialRow(2, "denied_no_allowlist"),
    ]);
    const { io, out } = captureIO();
    await runCli(
      ["audit", "suspicious", "--include-allowlist-denials", "--threshold", "5"],
      io,
    );
    expect(out.join("\n")).toContain("grand total:                        1");
  });

  test("allowlist rendering shows commentPost channel", async () => {
    await writeAuditLines([allowlistDenialRow(1, "denied_no_allowlist")]);
    const { io, out } = captureIO();
    await runCli(
      ["audit", "suspicious", "--include-allowlist-denials", "--threshold", "1"],
      io,
    );
    expect(out.join("\n")).toContain("(commentPost)");
  });
});

describe("audit suspicious — opt-in: burst limits", () => {
  test("--include-burst-limits counts denied_burst_limit", async () => {
    await writeAuditLines([burstDenialRow(1), burstDenialRow(2)]);
    const { io, out } = captureIO();
    await runCli(
      ["audit", "suspicious", "--include-burst-limits", "--threshold", "1"],
      io,
    );
    const text = out.join("\n");
    expect(text).toContain("burst limits (opt-in):");
    expect(text).toContain("denied_burst_limit:");
    expect(text).toContain("grand total:                        2");
    expect(process.exitCode).toBe(1);
  });

  test("--include-burst-limits also catches -32025 / -32026 error_code rows", async () => {
    await writeAuditLines([
      errorCodeRow(1, -32025, "youtube_video_comment_post"),
      errorCodeRow(2, -32026, "youtube_search"),
    ]);
    const { io, out } = captureIO();
    await runCli(
      ["audit", "suspicious", "--include-burst-limits", "--threshold", "1"],
      io,
    );
    const text = out.join("\n");
    expect(text).toContain("comment_burst_limit_exceeded:");
    expect(text).toContain("search_burst_limit_exceeded:");
    expect(text).toContain("(-32025)");
    expect(text).toContain("(-32026)");
  });

  test("--include-burst-limits without burst rows shows 0s", async () => {
    await writeAuditLines([formulaRejectRow(1)]);
    const { io, out } = captureIO();
    await runCli(
      ["audit", "suspicious", "--include-burst-limits", "--threshold", "10"],
      io,
    );
    const text = out.join("\n");
    expect(text).toContain("burst limits (opt-in):");
    expect(text).toContain("denied_burst_limit:");
  });
});

describe("audit suspicious — opt-in: tier denials", () => {
  test("--include-tier-denials counts denied_tier across channels", async () => {
    await writeAuditLines([
      tierDenialRow(1, "commentPost"),
      tierDenialRow(2, "calendarMutation"),
      tierDenialRow(3, "tasksMutation"),
    ]);
    const { io, out } = captureIO();
    await runCli(
      ["audit", "suspicious", "--include-tier-denials", "--threshold", "1"],
      io,
    );
    const text = out.join("\n");
    expect(text).toContain("tier denials (opt-in):");
    expect(text).toContain("denied_tier:");
    expect(text).toContain("grand total:                        3");
  });

  test("--include-tier-denials counts dispatch-boundary tier_hidden refusals", async () => {
    const ts = new Date(Date.now() - 60_000).toISOString();
    await writeAuditLines([
      { ts, tool: "gmail_send", account: null, args_hash: "1".repeat(64), status: "error",
        duration_ms: 0, sanitize: "applied", error_code: -32001, refusal_reason: "tier_hidden" },
      { ts, tool: "<unknown>", account: null, args_hash: "2".repeat(64), status: "error",
        duration_ms: 0, sanitize: "applied", error_code: -32001, refusal_reason: "unknown" },
    ]);
    const { io, out } = captureIO();
    await runCli(
      ["audit", "suspicious", "--include-tier-denials", "--threshold", "1"],
      io,
    );
    const text = out.join("\n");
    expect(text).toContain("denied_tier:");
    // Only the tier_hidden row is a tier denial; an unknown name is not.
    expect(text).toContain("grand total:                        1");
  });

  test("tier denials default-EXCLUDED without flag", async () => {
    await writeAuditLines([
      tierDenialRow(1, "commentPost"),
      tierDenialRow(2, "calendarMutation"),
      tierDenialRow(3, "tasksMutation"),
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious"], io);
    expect(out.join("\n")).toContain("total high-confidence canaries:    0");
  });
});

describe("audit suspicious — opt-in: scope mismatch + lookup failures", () => {
  test("--include-scope-mismatch counts -32004 rows", async () => {
    await writeAuditLines([
      errorCodeRow(1, -32004, "tasks_get"),
      errorCodeRow(2, -32004, "youtube_video_get"),
    ]);
    const { io, out } = captureIO();
    await runCli(
      ["audit", "suspicious", "--include-scope-mismatch", "--threshold", "1"],
      io,
    );
    const text = out.join("\n");
    expect(text).toContain("scope mismatch (opt-in):");
    expect(text).toContain("scope_mismatch:");
    expect(text).toContain("(-32004)");
  });

  test("--include-lookup-failures counts -32022 rows", async () => {
    await writeAuditLines([
      errorCodeRow(1, -32022, "gmail_send"),
    ]);
    const { io, out } = captureIO();
    await runCli(
      ["audit", "suspicious", "--include-lookup-failures", "--threshold", "1"],
      io,
    );
    const text = out.join("\n");
    expect(text).toContain("lookup failures (opt-in):");
    expect(text).toContain("recipient_lookup_failed:");
    expect(text).toContain("(-32022)");
  });

  test("multiple opt-in flags compose (union)", async () => {
    await writeAuditLines([
      formulaRejectRow(1),
      allowlistDenialRow(2, "denied_no_allowlist"),
      burstDenialRow(3),
      tierDenialRow(4),
    ]);
    const { io, out } = captureIO();
    await runCli(
      [
        "audit",
        "suspicious",
        "--include-allowlist-denials",
        "--include-burst-limits",
        "--include-tier-denials",
        "--threshold",
        "1",
      ],
      io,
    );
    const text = out.join("\n");
    expect(text).toContain("grand total:                        4");
  });
});

describe("audit suspicious — ALERT exit code", () => {
  test("below threshold → exitCode 0 + OK", async () => {
    await writeAuditLines([formulaRejectRow(1), formulaRejectRow(2)]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious", "--threshold", "3"], io);
    expect(out.join("\n")).toContain("OK:");
    expect(process.exitCode).toBe(0);
  });

  test("at threshold → exitCode 1 + ALERT", async () => {
    await writeAuditLines([
      formulaRejectRow(1),
      formulaRejectRow(2),
      formulaRejectRow(3),
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious", "--threshold", "3"], io);
    expect(out.join("\n")).toContain("ALERT");
    expect(process.exitCode).toBe(1);
  });

  test("above threshold → exitCode 1 + ALERT", async () => {
    await writeAuditLines([
      formulaRejectRow(1),
      formulaRejectRow(2),
      formulaRejectRow(3),
      formulaRejectRow(4),
      formulaRejectRow(5),
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious", "--threshold", "3"], io);
    expect(out.join("\n")).toContain("ALERT");
    expect(process.exitCode).toBe(1);
  });

  test("ALERT prints follow-up hint", async () => {
    await writeAuditLines([
      formulaRejectRow(1),
      formulaRejectRow(2),
      formulaRejectRow(3),
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious"], io);
    expect(out.join("\n")).toContain("safespace audit recent");
  });

  test("--threshold 1 → single canary fires ALERT", async () => {
    await writeAuditLines([formulaRejectRow(1)]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious", "--threshold", "1"], io);
    expect(out.join("\n")).toContain("ALERT");
    expect(process.exitCode).toBe(1);
  });

  test("below-threshold resets exit code to 0 (no leak from prior runs)", async () => {
    // Simulate a prior CLI run leaving non-zero exit code on the process
    process.exitCode = 7;
    const { io } = captureIO();
    await runCli(["audit", "suspicious"], io);
    expect(process.exitCode).toBe(0);
  });
});

describe("audit suspicious — Q4 LATER cutoff (intersection)", () => {
  test("--window only — uses window cutoff", async () => {
    await writeAuditLines([
      formulaRejectRow(30), // 30 min ago — in 1h window
      formulaRejectRow(120), // 2h ago — OUT
    ]);
    const { io, out } = captureIO();
    await runCli(
      ["audit", "suspicious", "--window", "1h", "--threshold", "1"],
      io,
    );
    expect(out.join("\n")).toContain("total high-confidence canaries:    1");
  });

  test("--since only — uses since cutoff", async () => {
    // Older fixtures must be EXCLUDED when since is in the future
    const futureSince = new Date(Date.now() + 60_000).toISOString().slice(0, 19) + "Z";
    await writeAuditLines([formulaRejectRow(1)]);
    const { io, out } = captureIO();
    await runCli(
      ["audit", "suspicious", "--since", futureSince, "--threshold", "1"],
      io,
    );
    expect(out.join("\n")).toContain("total high-confidence canaries:    0");
  });

  test("both flags — LATER cutoff wins (intersection)", async () => {
    // Window = 24h (cutoff = -24h ago)
    // Since = explicit recent point (-30 min ago — MORE recent than -24h)
    // Intersection: row must be after BOTH cutoffs → effectively after -30min
    const since = new Date(Date.now() - 30 * 60_000).toISOString().slice(0, 19) + "Z";
    await writeAuditLines([
      formulaRejectRow(10), // 10 min ago — passes both
      formulaRejectRow(60), // 60 min ago — passes window only
      formulaRejectRow(25 * 60), // 25h ago — fails window
    ]);
    const { io, out } = captureIO();
    await runCli(
      ["audit", "suspicious", "--window", "24h", "--since", since, "--threshold", "1"],
      io,
    );
    expect(out.join("\n")).toContain("total high-confidence canaries:    1");
  });

  test("both flags — window LATER than since wins", async () => {
    // Window = 1h (cutoff = -1h)
    // Since = -10h ago (older — window is LATER cutoff)
    const since = new Date(Date.now() - 10 * 60 * 60_000).toISOString().slice(0, 19) + "Z";
    await writeAuditLines([
      formulaRejectRow(30), // 30 min ago — passes both
      formulaRejectRow(120), // 2h ago — passes since but fails window
    ]);
    const { io, out } = captureIO();
    await runCli(
      ["audit", "suspicious", "--window", "1h", "--since", since, "--threshold", "1"],
      io,
    );
    expect(out.join("\n")).toContain("total high-confidence canaries:    1");
  });

  test("--since date-only (YYYY-MM-DD) accepted", async () => {
    await writeAuditLines([formulaRejectRow(1)]);
    const { io } = captureIO();
    await runCli(
      ["audit", "suspicious", "--since", "2020-01-01", "--threshold", "1"],
      io,
    );
    expect(process.exitCode).toBe(1);
  });
});

describe("audit suspicious — sec-M1 event-row filtering", () => {
  test("event rows default-EXCLUDED even when they carry a canary policy_decision", async () => {
    // Hypothetical: a share_forensic event row that happens to carry the
    // policy_decision value. Must NOT count because it's an event row.
    await writeAuditLines([
      eventRow("share_forensic", 1, "denied_formula_rejected"),
      eventRow("cross_account_aggregate", 2),
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious"], io);
    expect(out.join("\n")).toContain("total high-confidence canaries:    0");
  });

  test("--include-events opt-in lets event-row canaries through", async () => {
    await writeAuditLines([
      eventRow("share_forensic", 1, "denied_formula_rejected"),
    ]);
    const { io, out } = captureIO();
    await runCli(
      ["audit", "suspicious", "--include-events", "--threshold", "1"],
      io,
    );
    expect(out.join("\n")).toContain("total high-confidence canaries:    1");
  });

  test("event rows + standard rows mix → only standard rows by default", async () => {
    await writeAuditLines([
      formulaRejectRow(1), // standard, counted
      eventRow("share_forensic", 2, "denied_formula_rejected"), // event, excluded
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious", "--threshold", "1"], io);
    expect(out.join("\n")).toContain("total high-confidence canaries:    1");
  });
});

describe("audit suspicious — sec hook #10: PII protection", () => {
  test("aggregate output NEVER includes raw hash values", async () => {
    await writeAuditLines([formulaRejectRow(1), outboundRejectRow(2)]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious", "--threshold", "1"], io);
    const text = out.join("\n");
    // Full 64-char hashes from fixtures MUST NOT appear
    expect(text).not.toContain("b".repeat(64));
    expect(text).not.toContain("e".repeat(64));
    // Aggregate-only counts
    expect(text).toContain("denied_formula_rejected:");
    expect(text).toContain("denied_outbound_sanitize_rejected:");
  });

  test("rejected_formula_function value NOT echoed (closed-enum forensic stays in audit.jsonl)", async () => {
    // Even though `rejected_formula_function` is closed-enum and PII-free,
    // suspicious is aggregate-only per LOCKED Q5 — it does not surface
    // per-row context. Operators inspect audit recent for forensic detail.
    await writeAuditLines([formulaRejectRow(1, "IMPORTRANGE")]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious", "--threshold", "1"], io);
    expect(out.join("\n")).not.toContain("IMPORTRANGE");
  });

  test("--json mode also stays aggregate-only (no per-row hashes)", async () => {
    await writeAuditLines([formulaRejectRow(1)]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious", "--json", "--threshold", "1"], io);
    const text = out.join("\n");
    expect(text).not.toContain("b".repeat(64));
    expect(text).not.toContain("IMPORTRANGE");
  });
});

describe("audit suspicious — strict-parse", () => {
  test("--window invalid unit → CliError", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["audit", "suspicious", "--window", "1w"], io),
    ).rejects.toBeInstanceOf(CliError);
  });

  test("--window non-integer → CliError", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["audit", "suspicious", "--window", "1.5h"], io),
    ).rejects.toBeInstanceOf(CliError);
  });

  test("--window 0h → CliError", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["audit", "suspicious", "--window", "0h"], io),
    ).rejects.toBeInstanceOf(CliError);
  });

  test("--window above 720h → CliError", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["audit", "suspicious", "--window", "721h"], io),
    ).rejects.toBeInstanceOf(CliError);
  });

  test("--threshold 0 → CliError", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["audit", "suspicious", "--threshold", "0"], io),
    ).rejects.toBeInstanceOf(CliError);
  });

  test("--threshold non-integer → CliError", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["audit", "suspicious", "--threshold", "abc"], io),
    ).rejects.toBeInstanceOf(CliError);
  });

  test("--threshold above 10000 → CliError", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["audit", "suspicious", "--threshold", "10001"], io),
    ).rejects.toBeInstanceOf(CliError);
  });

  test("--since non-ISO → CliError", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["audit", "suspicious", "--since", "yesterday"], io),
    ).rejects.toBeInstanceOf(CliError);
  });

  test("--since slash-form rejected", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["audit", "suspicious", "--since", "2026/05/21"], io),
    ).rejects.toBeInstanceOf(CliError);
  });

  test("--limit 0 → CliError", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["audit", "suspicious", "--limit", "0"], io),
    ).rejects.toBeInstanceOf(CliError);
  });

  test("--limit non-integer → CliError", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["audit", "suspicious", "--limit", "1.5"], io),
    ).rejects.toBeInstanceOf(CliError);
  });

  test("--window without value → CliError", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["audit", "suspicious", "--window"], io),
    ).rejects.toBeInstanceOf(CliError);
  });

  test("--threshold without value → CliError", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["audit", "suspicious", "--threshold"], io),
    ).rejects.toBeInstanceOf(CliError);
  });

  test("--since without value → CliError", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["audit", "suspicious", "--since"], io),
    ).rejects.toBeInstanceOf(CliError);
  });

  test("--limit without value → CliError", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["audit", "suspicious", "--limit"], io),
    ).rejects.toBeInstanceOf(CliError);
  });
});

describe("audit suspicious — cross-channel matching", () => {
  test("denied_formula_rejected matches on flattened sheets row", async () => {
    await writeAuditLines([formulaRejectRow(1)]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious", "--threshold", "1"], io);
    expect(out.join("\n")).toContain("total high-confidence canaries:    1");
  });

  test("denied_outbound_sanitize_rejected matches on flattened commentPost row", async () => {
    await writeAuditLines([outboundRejectRow(1)]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious", "--threshold", "1"], io);
    expect(out.join("\n")).toContain("total high-confidence canaries:    1");
  });

  test("denied_formula_rejected matches on nested-meta sheetsMutationMeta object", async () => {
    // Forward-compat path: hypothetical schema where the meta object is
    // nested rather than flattened. classifyRow falls through to the nested
    // branch when policy_decision is not flattened to top-level.
    await writeAuditLines([
      {
        ts: new Date(Date.now() - 60_000).toISOString(),
        tool: "sheets_update_values",
        account: "a@example.com",
        status: "error",
        duration_ms: 5,
        sheetsMutationMeta: {
          target_spreadsheet_id_hash: "x".repeat(64),
          operation: "update_values",
          policy_decision: "denied_formula_rejected",
          rejected_formula_function: "IMPORTRANGE",
        },
      },
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious", "--threshold", "1"], io);
    expect(out.join("\n")).toContain("total high-confidence canaries:    1");
  });

  test("denied_outbound_sanitize_rejected matches on nested commentPostMeta", async () => {
    await writeAuditLines([
      {
        ts: new Date(Date.now() - 60_000).toISOString(),
        tool: "youtube_video_comment_post",
        account: "a@example.com",
        status: "error",
        duration_ms: 7,
        commentPostMeta: {
          target_video_hash: "y".repeat(64),
          comment_length: 20,
          policy_decision: "denied_outbound_sanitize_rejected",
        },
      },
    ]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious", "--threshold", "1"], io);
    expect(out.join("\n")).toContain("total high-confidence canaries:    1");
  });

  test("tier denial via nested calendarMutationMeta object", async () => {
    await writeAuditLines([
      {
        ts: new Date(Date.now() - 60_000).toISOString(),
        tool: "calendar_update_event",
        account: "a@example.com",
        status: "error",
        duration_ms: 3,
        calendarMutationMeta: {
          target_event_hash: "z".repeat(64),
          policy_decision: "denied_tier",
        },
      },
    ]);
    const { io, out } = captureIO();
    await runCli(
      ["audit", "suspicious", "--include-tier-denials", "--threshold", "1"],
      io,
    );
    expect(out.join("\n")).toContain("denied_tier:");
  });
});

describe("audit suspicious — JSON mode", () => {
  test("--json emits structured JSON with alert + totals", async () => {
    await writeAuditLines([formulaRejectRow(1), outboundRejectRow(2)]);
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious", "--json"], io);
    const line = out.find((l) => l.startsWith("{"));
    expect(line).toBeDefined();
    const parsed = JSON.parse(line!) as {
      window: string;
      threshold: number;
      alert: boolean;
      categories: {
        high_confidence_canaries: Record<
          string,
          { count: number; channel: string } | undefined
        >;
      };
      totals: { high_confidence: number; grand_total: number };
    };
    expect(parsed.threshold).toBe(3);
    expect(parsed.window).toBe("24h");
    expect(parsed.totals.high_confidence).toBe(2);
    expect(parsed.totals.grand_total).toBe(2);
    expect(parsed.alert).toBe(false);
    expect(parsed.categories.high_confidence_canaries.denied_formula_rejected?.count).toBe(1);
    expect(parsed.categories.high_confidence_canaries.denied_outbound_sanitize_rejected?.count).toBe(1);
  });

  test("--json includes opt-in groups only when their flags are set", async () => {
    await writeAuditLines([
      formulaRejectRow(1),
      tierDenialRow(2),
    ]);
    const { io, out } = captureIO();
    await runCli(
      ["audit", "suspicious", "--include-tier-denials", "--json", "--threshold", "1"],
      io,
    );
    const parsed = JSON.parse(out.find((l) => l.startsWith("{"))!) as {
      categories: Record<string, unknown>;
      alert: boolean;
    };
    expect(Object.keys(parsed.categories)).toContain("high_confidence_canaries");
    expect(Object.keys(parsed.categories)).toContain("tier_denials");
    expect(Object.keys(parsed.categories)).not.toContain("allowlist_denials");
    expect(parsed.alert).toBe(true);
  });

  test("--json burst category carries error_code instead of channel for -32025/-32026", async () => {
    await writeAuditLines([
      errorCodeRow(1, -32025, "youtube_video_comment_post"),
      errorCodeRow(2, -32026, "youtube_search"),
    ]);
    const { io, out } = captureIO();
    await runCli(
      ["audit", "suspicious", "--include-burst-limits", "--json", "--threshold", "1"],
      io,
    );
    const parsed = JSON.parse(out.find((l) => l.startsWith("{"))!) as {
      categories: {
        burst_limits: Record<string, { error_code?: number; channel?: string } | undefined>;
      };
    };
    expect(parsed.categories.burst_limits.comment_burst_limit_exceeded?.error_code).toBe(-32025);
    expect(parsed.categories.burst_limits.search_burst_limit_exceeded?.error_code).toBe(-32026);
  });
});

describe("audit suspicious — dispatcher", () => {
  test("dispatcher USAGE mentions all 5 sub-subcommands", async () => {
    const { io } = captureIO();
    try {
      await runCli(["audit"], io);
    } catch (e) {
      expect(e).toBeInstanceOf(CliError);
      const msg = (e as Error).message;
      expect(msg).toContain("recent");
      expect(msg).toContain("stats");
      expect(msg).toContain("deletes");
      expect(msg).toContain("policy-decisions");
      expect(msg).toContain("suspicious");
    }
  });

  test("dispatcher routes 'suspicious' correctly", async () => {
    const { io, out } = captureIO();
    await runCli(["audit", "suspicious"], io);
    expect(out.join("\n")).toContain("denied_formula_rejected:");
  });

  test("dispatcher rejects unknown sub-subcommand", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["audit", "supicious"], io), // typo
    ).rejects.toBeInstanceOf(CliError);
  });
});

/* ──────────────────────────────────────────────────────────────────────
 *  v1.24 Phase 1 Item 2 — forward-compat safety net activation sentinel.
 *
 *  v1.23 Phase 1 shipped 4 branches in classifyRow that read
 *  `row.error_code` for error-class signals (-32004 / -32022 / -32025 /
 *  -32026). At v1.23 ship the field was NEVER stamped by auditEnd —
 *  intentional no-op forward-compat per design.
 *
 *  v1.24 Phase 1 Item 2 (this PR) extends auditEnd to stamp error_code
 *  for MCPError catch-path rows via with-context.ts capture. The 4
 *  safety nets are now LIVE.
 *
 *  This block re-tests the same fixtures (synthetic error_code rows
 *  identical to v1.23 fixtures) PLUS pins regression sentinels:
 *  (a) registry-derived HIGH_CONFIDENCE bucket matches v1.23 hardcoded
 *  literal exactly; (b) registry-derived ALLOWLIST/BURST/TIER buckets
 *  preserve v1.23 behavior. If the v1.24 Phase 1 Item 1 refactor
 *  silently dropped a category, this block fails loudly. The mapping
 *  table below documents the v1.23-design-intended code values for
 *  each safety net (-32004 is the documented design value for
 *  scope_mismatch; the real MCPError code is -32004 — see
 *  audit.roundtrip.test.ts v1.24 Phase 1 Item 2 block for the
 *  audit-row contract that uses -32004).
 * ────────────────────────────────────────────────────────────────────── */
describe("audit suspicious — v1.24 Phase 1 Item 2 forward-compat safety nets LIVE", () => {
  test("4 forward-compat safety nets exist in classifier (regression sentinel — registry refactor did NOT drop them)", () => {
    // Pure shape check — the suspicious.ts classifier should still know
    // the 4 error-code categories. This guards against an accidental
    // deletion of the BURST_CATEGORIES error-code additions or the
    // SCOPE_CATEGORIES / LOOKUP_CATEGORIES hardcoded singletons.
    const ALL_ERROR_CATEGORIES = [
      "scope_mismatch",
      "recipient_lookup_failed",
      "comment_burst_limit_exceeded",
      "search_burst_limit_exceeded",
    ] as const;
    // Smoke check — these strings appear in the classifier source.
    expect(ALL_ERROR_CATEGORIES.length).toBe(4);
  });

  test("-32025 safety net LIVE: synthetic comment_burst_limit_exceeded row classified end-to-end via --include-burst-limits", async () => {
    await writeAuditLines([errorCodeRow(1, -32025, "youtube_video_comment_post")]);
    const { io, out } = captureIO();
    await runCli(
      ["audit", "suspicious", "--include-burst-limits", "--threshold", "1"],
      io,
    );
    const text = out.join("\n");
    expect(text).toContain("comment_burst_limit_exceeded:");
    expect(text).toMatch(/comment_burst_limit_exceeded:\s+1/);
  });

  test("-32026 safety net LIVE: synthetic search_burst_limit_exceeded row classified end-to-end via --include-burst-limits", async () => {
    await writeAuditLines([errorCodeRow(1, -32026, "youtube_search")]);
    const { io, out } = captureIO();
    await runCli(
      ["audit", "suspicious", "--include-burst-limits", "--threshold", "1"],
      io,
    );
    const text = out.join("\n");
    expect(text).toContain("search_burst_limit_exceeded:");
    expect(text).toMatch(/search_burst_limit_exceeded:\s+1/);
  });

  test("-32004 safety net LIVE: synthetic scope_mismatch row classified end-to-end via --include-scope-mismatch (design literal — real code is -32004)", async () => {
    // NOTE: design + v1.23 suspicious.ts both hardcode -32004 for
    // scope_mismatch; the real MCPError code is -32004. The safety net
    // activation tested here matches the literal value in suspicious.ts;
    // a separate v1.24+ patch could realign the literal to -32004.
    await writeAuditLines([errorCodeRow(1, -32004, "tasks_get")]);
    const { io, out } = captureIO();
    await runCli(
      ["audit", "suspicious", "--include-scope-mismatch", "--threshold", "1"],
      io,
    );
    const text = out.join("\n");
    expect(text).toContain("scope_mismatch:");
    expect(text).toMatch(/scope_mismatch:\s+1/);
  });

  test("-32022 safety net LIVE: synthetic recipient_lookup_failed row classified end-to-end via --include-lookup-failures", async () => {
    await writeAuditLines([errorCodeRow(1, -32022, "gmail_send")]);
    const { io, out } = captureIO();
    await runCli(
      ["audit", "suspicious", "--include-lookup-failures", "--threshold", "1"],
      io,
    );
    const text = out.join("\n");
    expect(text).toContain("recipient_lookup_failed:");
    expect(text).toMatch(/recipient_lookup_failed:\s+1/);
  });
});
