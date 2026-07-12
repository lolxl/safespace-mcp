// v1.87 — per-connector egress posture tests.

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { classifyEgress, evaluateEgressPosture, type EgressRow } from "./egress-posture";
import { __internal as recipientInternal } from "./recipient-allowlist";
import { __internal as tasksInternal } from "./tasks-delete-targets";
import { __internal as ytInternal } from "./youtube-comment-targets";
import { __internal as ghWriteInternal } from "./github-write-targets";
import { __internal as ghMergeInternal } from "./github-merge-targets";
import { __internal as ghApproveInternal } from "./github-approve-targets";
import { __internal as xPostInternal } from "./x-post-allowlist";
import { __internal as fsInternal } from "./fs-gate";

// Every egress env var the aggregator reads — snapshot + clear so a test is
// hermetic, and reset the CACHED allowlist singletons so a stale cache can't
// leak a prior env across the boundary.
const ENV_VARS = [
  "SAFESPACE_AUTONOMOUS",
  "SAFESPACE_RECIPIENT_ALLOW", "SAFESPACE_RECIPIENT_ALLOW_EXTRA",
  "SAFESPACE_TASKS_DELETE_TARGETS", "SAFESPACE_TASKS_DELETE_TARGETS_EXTRA",
  "SAFESPACE_YOUTUBE_COMMENT_TARGETS", "SAFESPACE_YOUTUBE_COMMENT_TARGETS_EXTRA",
  "SAFESPACE_LINE_RECIPIENT_ALLOW", "SAFESPACE_LINE_RECIPIENT_ALLOW_EXTRA",
  "SAFESPACE_TELEGRAM_RECIPIENT_ALLOW", "SAFESPACE_TELEGRAM_RECIPIENT_ALLOW_EXTRA",
  "SAFESPACE_DISCORD_RECIPIENT_ALLOW", "SAFESPACE_DISCORD_RECIPIENT_ALLOW_EXTRA",
  "SAFESPACE_GITHUB_WRITE_TARGETS", "SAFESPACE_GITHUB_WRITE_TARGETS_EXTRA",
  "SAFESPACE_GITHUB_MERGE_TARGETS", "SAFESPACE_GITHUB_MERGE_TARGETS_EXTRA",
  "SAFESPACE_GITHUB_APPROVE_TARGETS", "SAFESPACE_GITHUB_APPROVE_TARGETS_EXTRA",
  "SAFESPACE_X_POST_ACCOUNTS", "SAFESPACE_X_POST_ACCOUNTS_EXTRA",
  "SAFESPACE_FS_READ_ROOTS", "SAFESPACE_FS_READ_ROOTS_EXTRA",
  "SAFESPACE_WEBFETCH_ALLOW", "SAFESPACE_WEBFETCH_ALLOW_EXTRA",
] as const;

function resetCaches(): void {
  recipientInternal.resetSingletons();
  tasksInternal.resetSingletons();
  ytInternal.resetSingletons();
  ghWriteInternal.resetSingletons();
  ghMergeInternal.resetSingletons();
  ghApproveInternal.resetSingletons();
  xPostInternal.resetSingletons();
  fsInternal.resetSingletons();
}

const saved: Record<string, string | undefined> = {};
beforeEach(() => {
  for (const v of ENV_VARS) {
    saved[v] = process.env[v];
    delete process.env[v];
  }
  resetCaches();
});
afterEach(() => {
  for (const v of ENV_VARS) {
    if (saved[v] === undefined) delete process.env[v];
    else process.env[v] = saved[v];
  }
  resetCaches();
});

describe("classifyEgress (pure)", () => {
  test("configured → pass, restricted with the count", () => {
    const r = classifyEgress("x", true, 3, "allow", false);
    expect(r.status).toBe("pass");
    expect(r.detail).toBe("restricted — 3 entries allowlisted");
  });
  test("configured count=1 → singular 'entry'", () => {
    expect(classifyEgress("x", true, 1, "deny", true).detail).toBe("restricted — 1 entry allowlisted");
  });
  test("off→deny unset → pass deny-all (regardless of autonomous)", () => {
    for (const auto of [false, true]) {
      const r = classifyEgress("x", false, 0, "deny", auto);
      expect(r.status).toBe("pass");
      expect(r.detail).toContain("deny-all");
    }
  });
  test("off→allow unset + autonomous → pass deny-all", () => {
    const r = classifyEgress("x", false, 0, "allow", true);
    expect(r.status).toBe("pass");
    expect(r.detail).toContain("deny-all");
    expect(r.detail).toContain("autonomous");
  });
  test("off→allow unset + interactive → WARN open (the one actionable signal)", () => {
    const r = classifyEgress("x", false, 0, "allow", false);
    expect(r.status).toBe("warn");
    expect(r.detail).toContain("OPEN");
    expect(r.detail).toContain("SAFESPACE_AUTONOMOUS");
  });
});

const rowOf = (rows: EgressRow[], name: string): EgressRow => rows.find((r) => r.connector.startsWith(name))!;

describe("evaluateEgressPosture", () => {
  test("enumerates all 15 connectors", async () => {
    const rows = await evaluateEgressPosture();
    expect(rows.length).toBe(15);
    for (const name of ["recipient", "tasks-delete", "youtube-comment", "youtube-video", "line", "telegram", "discord", "slack", "mattermost", "github-write", "github-merge", "github-approve", "x-post", "fs-read", "web-fetch"]) {
      expect(rows.some((r) => r.connector.startsWith(name)), name).toBe(true);
    }
  });

  test("all-unset + INTERACTIVE: off→allow = OPEN warn, off→deny = deny-all pass", async () => {
    const rows = await evaluateEgressPosture();
    // off→allow lists, unset + not autonomous → warn
    for (const n of ["recipient", "tasks-delete", "line", "telegram", "discord", "slack", "mattermost", "web-fetch"]) {
      expect(rowOf(rows, n).status, n).toBe("warn");
    }
    // off→deny lists, unset → pass (deny-all)
    for (const n of ["youtube-comment", "youtube-video", "github-write", "github-merge", "github-approve", "x-post", "fs-read"]) {
      expect(rowOf(rows, n).status, n).toBe("pass");
    }
  });

  test("all-unset + AUTONOMOUS: every connector deny-all → pass", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    resetCaches();
    const rows = await evaluateEgressPosture();
    expect(rows.every((r) => r.status === "pass")).toBe(true);
  });

  test("a populated allowlist → restricted pass with the count", async () => {
    process.env.SAFESPACE_GITHUB_WRITE_TARGETS = "owner/repo";
    resetCaches();
    const row = rowOf(await evaluateEgressPosture(), "github-write");
    expect(row.status).toBe("pass");
    expect(row.detail).toBe("restricted — 1 entry allowlisted");
  });

  test("x-post populated allowlist → restricted pass with the count", async () => {
    process.env.SAFESPACE_X_POST_ACCOUNTS = "2244994945";
    resetCaches();
    const row = rowOf(await evaluateEgressPosture(), "x-post");
    expect(row.status).toBe("pass");
    expect(row.detail).toBe("restricted — 1 entry allowlisted");
  });

  test("NO-PII-ECHO: the actual allowlist VALUES never appear in any row", async () => {
    process.env.SAFESPACE_RECIPIENT_ALLOW = "topsecret@evil.example";
    process.env.SAFESPACE_GITHUB_WRITE_TARGETS = "megacorp/secret-repo";
    process.env.SAFESPACE_X_POST_ACCOUNTS = "999888777666";
    process.env.SAFESPACE_WEBFETCH_ALLOW = "internal.corp.example";
    resetCaches();
    const joined = (await evaluateEgressPosture()).map((r) => `${r.connector} ${r.detail}`).join("\n");
    expect(joined).not.toContain("topsecret");
    expect(joined).not.toContain("evil.example");
    expect(joined).not.toContain("megacorp");
    expect(joined).not.toContain("secret-repo");
    expect(joined).not.toContain("999888777666");
    expect(joined).not.toContain("internal.corp");
  });
});
