// v1.87 — per-connector egress posture tests.

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { classifyEgress, evaluateEgressPosture, type EgressRow } from "./egress-posture";
import { __internal as recipientInternal } from "./recipient-allowlist";
import { __internal as tasksInternal } from "./tasks-delete-targets";
import { __internal as driveDeleteInternal } from "./drive-delete-targets";
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
  "SAFESPACE_DRIVE_DELETE_TARGETS", "SAFESPACE_DRIVE_DELETE_TARGETS_EXTRA",
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
  driveDeleteInternal.resetSingletons();
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
  test("enumerates all 16 connectors", async () => {
    const rows = await evaluateEgressPosture();
    expect(rows.length).toBe(16);
    for (const name of ["recipient", "tasks-delete", "drive-delete", "youtube-comment", "youtube-video", "line", "telegram", "discord", "slack", "mattermost", "github-write", "github-merge", "github-approve", "x-post", "fs-read", "web-fetch"]) {
      expect(rows.some((r) => r.connector.startsWith(name)), name).toBe(true);
    }
  });

  test("all-unset + INTERACTIVE: off→allow = OPEN warn, off→deny = deny-all pass", async () => {
    const rows = await evaluateEgressPosture();
    // off→allow lists, unset + not autonomous → warn
    for (const n of ["recipient", "tasks-delete", "drive-delete", "line", "telegram", "discord", "slack", "mattermost", "web-fetch"]) {
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

  test("drive-delete populated allowlist → restricted pass with the count, ids never echoed", async () => {
    process.env.SAFESPACE_DRIVE_DELETE_TARGETS = "folder:1FolderSecretAAAAAAAAAAAA,file:1FileSecretAAAAAAAAAAAAAA";
    resetCaches();
    const row = rowOf(await evaluateEgressPosture(), "drive-delete");
    expect(row.status).toBe("pass");
    expect(row.detail).toBe("restricted — 2 entries allowlisted");
    expect(row.detail).not.toContain("Secret");
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

// Pack-step-2 byte-identity PIN: the 5 service-token rows are being re-derived from
// SERVICE_TOKEN_PACKS. This locks their exact ORDER + exact detail strings so the
// derivation cannot silently drift the `doctor --posture` output. Hermetic over ALL 5
// connectors' recipient env vars (the outer ENV_VARS list omits slack + mattermost).
describe("service-token posture rows — byte-identity pin (pack step 2)", () => {
  const ST_VARS = [
    "SAFESPACE_LINE_RECIPIENT_ALLOW", "SAFESPACE_LINE_RECIPIENT_ALLOW_EXTRA",
    "SAFESPACE_TELEGRAM_RECIPIENT_ALLOW", "SAFESPACE_TELEGRAM_RECIPIENT_ALLOW_EXTRA",
    "SAFESPACE_DISCORD_RECIPIENT_ALLOW", "SAFESPACE_DISCORD_RECIPIENT_ALLOW_EXTRA",
    "SAFESPACE_SLACK_RECIPIENT_ALLOW", "SAFESPACE_SLACK_RECIPIENT_ALLOW_EXTRA",
    "SAFESPACE_MATTERMOST_RECIPIENT_ALLOW", "SAFESPACE_MATTERMOST_RECIPIENT_ALLOW_EXTRA",
  ] as const;
  const stSaved: Record<string, string | undefined> = {};
  beforeEach(() => {
    for (const v of ST_VARS) { stSaved[v] = process.env[v]; delete process.env[v]; }
  });
  afterEach(() => {
    for (const v of ST_VARS) {
      if (stSaved[v] === undefined) delete process.env[v];
      else process.env[v] = stSaved[v];
    }
  });

  const OPEN = "OPEN (unset + interactive → unrestricted; set the allowlist or enable SAFESPACE_AUTONOMOUS)";

  test("order is line, telegram, discord, slack, mattermost at indices 5..9 (after drive-delete)", async () => {
    const rows = await evaluateEgressPosture();
    expect(rows.slice(5, 10).map((r) => r.connector)).toEqual([
      "line", "telegram", "discord", "slack", "mattermost",
    ]);
  });

  test("all-unset + interactive → each service-token row is warn/OPEN (exact detail)", async () => {
    const rows = await evaluateEgressPosture();
    for (const name of ["line", "telegram", "discord", "slack", "mattermost"]) {
      const row = rows.find((r) => r.connector === name)!;
      expect(row.status, name).toBe("warn");
      expect(row.detail, name).toBe(OPEN);
    }
  });

  test("a populated line allowlist → restricted pass with the exact count string", async () => {
    process.env.SAFESPACE_LINE_RECIPIENT_ALLOW = "U" + "0".repeat(32);
    const row = (await evaluateEgressPosture()).find((r) => r.connector === "line")!;
    expect(row.status).toBe("pass");
    expect(row.detail).toBe("restricted — 1 entry allowlisted");
  });
});
