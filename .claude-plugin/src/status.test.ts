import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  runDoctor,
  runPosture,
  runStatus,
  tildePath,
  type CliIO,
} from "./status";
// runPosture's egress section loads the cached allowlist singletons; reset them
// around those tests so a populated cache can't leak into another test file.
import { __internal as recipientInternal } from "./policy/recipient-allowlist";
import { createPending, pendingSendsPath } from "./auth/send-approval-store";
import { __internal as tasksInternal } from "./policy/tasks-delete-targets";
import { __internal as ytInternal } from "./policy/youtube-comment-targets";
import { __internal as ghWriteInternal } from "./policy/github-write-targets";
import { __internal as ghMergeInternal } from "./policy/github-merge-targets";
import { __internal as fsInternal } from "./policy/fs-gate";

function resetEgressCaches(): void {
  recipientInternal.resetSingletons();
  tasksInternal.resetSingletons();
  ytInternal.resetSingletons();
  ghWriteInternal.resetSingletons();
  ghMergeInternal.resetSingletons();
  fsInternal.resetSingletons();
}

let tmpDir: string;
let prevConfigDir: string | undefined;
let prevTier: string | undefined;

function captureIO(): { io: CliIO; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: { out: (line) => out.push(line), err: (line) => err.push(line) },
    out,
    err,
  };
}

const ENTRY_ALICE = {
  email: "alice@example.com",
  scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
  added_at: "2026-05-01T00:00:00.000Z",
  last_used_at: null as string | null,
};

const ENTRY_BOB = {
  email: "bob@example.com",
  scopes: ["https://www.googleapis.com/auth/gmail.send"],
  added_at: "2026-05-02T00:00:00.000Z",
  last_used_at: null,
};

async function setup(opts: {
  accounts?: object;
  env?: string;
  envMode?: number;
  audit?: string[];
  salt?: Buffer;
  saltMode?: number;
  active?: string;
}): Promise<void> {
  if (opts.accounts) {
    await fs.writeFile(path.join(tmpDir, "accounts.json"), JSON.stringify(opts.accounts), { mode: 0o600 });
  }
  if (opts.env !== undefined) {
    await fs.writeFile(path.join(tmpDir, ".env"), opts.env, { mode: opts.envMode ?? 0o600 });
  }
  if (opts.audit) {
    await fs.writeFile(path.join(tmpDir, "audit.jsonl"), opts.audit.join("\n") + "\n", { mode: 0o600 });
  }
  if (opts.salt) {
    await fs.writeFile(path.join(tmpDir, "audit-salt"), opts.salt, { mode: opts.saltMode ?? 0o600 });
  }
  if (opts.active !== undefined) {
    await fs.writeFile(path.join(tmpDir, "active-account"), opts.active, { mode: 0o600 });
  }
}

// Stub probe — fixed version so dep tests don't depend on the host's $PATH.
const STUB_PROBE = async (_cmd: string): Promise<string | null> => "1.0.0-test";
const ALL_MISSING_PROBE = async (_cmd: string): Promise<string | null> => null;

beforeEach(async () => {
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-status-"));
  await fs.chmod(tmpDir, 0o700);
  prevConfigDir = process.env.SAFESPACE_CONFIG_DIR;
  prevTier = process.env.SAFESPACE_TIER;
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  delete process.env.SAFESPACE_TIER;
});

afterEach(async () => {
  if (prevConfigDir === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevConfigDir;
  if (prevTier === undefined) delete process.env.SAFESPACE_TIER;
  else process.env.SAFESPACE_TIER = prevTier;
  await fs.rm(tmpDir, { recursive: true, force: true });
});

// ----- tildePath -----

describe("tildePath", () => {
  test("replaces $HOME prefix with ~/", () => {
    const home = os.homedir();
    expect(tildePath(home)).toBe("~");
    expect(tildePath(path.join(home, "foo", "bar"))).toBe("~" + path.sep + path.join("foo", "bar"));
  });

  test("leaves non-home paths unchanged", () => {
    expect(tildePath("/tmp/safespace-test")).toBe("/tmp/safespace-test");
  });
});

// ----- runStatus -----

describe("runStatus", () => {
  test("text output shows config dir, tier, account count, audit count", async () => {
    await setup({
      accounts: { version: 2, accounts: [ENTRY_ALICE, ENTRY_BOB] },
      audit: [
        '{"ts":"2026-05-10T00:00:00.000Z","tool":"gmail_search","account":"alice@example.com"}',
        '{"ts":"2026-05-12T00:00:00.000Z","tool":"gmail_send","account":"alice@example.com"}',
      ],
      active: "alice@example.com\n",
    });
    const cap = captureIO();
    const report = await runStatus({}, cap.io);

    expect(report.accountCount).toBe(2);
    expect(report.activeAccount).toBe("alice@example.com");
    expect(report.lastAuditEntry).toEqual({
      ts: "2026-05-12T00:00:00.000Z",
      tool: "gmail_send",
    });
    expect(report.auditLineCount).toBe(2);

    const joined = cap.out.join("\n");
    expect(joined).toContain("accounts:   2 registered");
    expect(joined).toContain("active: alice@example.com");
    expect(joined).toContain("gmail_send"); // tool from last line
    expect(joined).toContain("audit log:  2 entries");
  });

  test("--json output replaces $HOME with ~/", async () => {
    const home = os.homedir();
    const homeDir = await fs.mkdtemp(path.join(home, ".safespace-test-"));
    try {
      await fs.chmod(homeDir, 0o700);
      process.env.SAFESPACE_CONFIG_DIR = homeDir;
      await fs.writeFile(
        path.join(homeDir, "accounts.json"),
        JSON.stringify({ version: 2, accounts: [ENTRY_ALICE] }),
        { mode: 0o600 },
      );
      const cap = captureIO();
      await runStatus({ json: true }, cap.io);
      const parsed = JSON.parse(cap.out[0]!);
      expect(parsed.config_dir.startsWith("~")).toBe(true);
      expect(parsed.config_dir.includes(home)).toBe(false);
      expect(parsed.account_count).toBe(1);
    } finally {
      await fs.rm(homeDir, { recursive: true, force: true });
    }
  });

  test("audit last entry extracts ONLY ts + tool (not account or argsHash)", async () => {
    await setup({
      audit: [
        '{"ts":"2026-05-10T00:00:00.000Z","tool":"gmail_send","account":"alice@example.com","argsHash":"sha256:abc","duration_ms":42}',
      ],
    });
    const cap = captureIO();
    const report = await runStatus({}, cap.io);
    expect(report.lastAuditEntry).toEqual({
      ts: "2026-05-10T00:00:00.000Z",
      tool: "gmail_send",
    });
    const lastCallLine = cap.out.find((l) => l.startsWith("last call:")) ?? "";
    expect(lastCallLine).not.toContain("alice@example.com");
    expect(lastCallLine).not.toContain("sha256");
  });

  test("active-account with email NOT in accounts.json still reads (raw value preserved)", async () => {
    await setup({
      accounts: { version: 2, accounts: [ENTRY_ALICE] },
      active: "ghost@example.com\n",
    });
    const cap = captureIO();
    const report = await runStatus({}, cap.io);
    expect(report.activeAccount).toBe("ghost@example.com");
  });

  test("corrupt active-account file returns null (no echo of bad content)", async () => {
    await setup({
      accounts: { version: 2, accounts: [ENTRY_ALICE] },
      active: "not an email\n",
    });
    const cap = captureIO();
    const report = await runStatus({}, cap.io);
    expect(report.activeAccount).toBeNull();
  });
});

// ----- runDoctor -----

describe("runDoctor — shallow happy path", () => {
  test("all checks pass when config is correct", async () => {
    await setup({
      accounts: { version: 2, accounts: [ENTRY_ALICE] },
      env: "GOOGLE_CLIENT_ID=test\nGOOGLE_CLIENT_SECRET=synthetic\n",
      envMode: 0o600,
      salt: crypto.randomBytes(32),
      active: "alice@example.com\n",
    });
    process.env.SAFESPACE_TIER = "read";
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    expect(report.status).toBe("ok");
    const failures = report.checks.filter((c) => c.status === "fail");
    expect(failures).toEqual([]);
  });
});

describe("runDoctor — win32 NTFS ACL (S5)", () => {
  test("POSIX-meaningless modes report 'n/a (NTFS ACL)' and PASS, not a spurious fail", async () => {
    // 0o644 would FAIL on POSIX; on win32 node's synthetic mode bits never reflect
    // 0o600, so the mode check must report n/a + pass instead of false-failing.
    await setup({
      accounts: { version: 2, accounts: [ENTRY_ALICE] },
      env: "GOOGLE_CLIENT_ID=test\n",
      envMode: 0o644,
      salt: crypto.randomBytes(32),
      active: "alice@example.com\n",
    });
    process.env.SAFESPACE_TIER = "read";
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE, platform: "win32" }, cap.io);
    const env = report.checks.find((c) => c.name === "env_file");
    expect(env?.status).toBe("pass");
    expect(env?.value).toBe("n/a (NTFS ACL)");
    const cfg = report.checks.find((c) => c.name === "config_dir");
    expect(cfg?.status).toBe("pass");
    expect(cfg?.value).toBe("n/a (NTFS ACL)");
    const salt = report.checks.find((c) => c.name === "audit_salt");
    expect(salt?.status).toBe("pass");
    expect(salt?.value).toBe("n/a (NTFS ACL), 32 bytes"); // size stays verified
  });

  test("existence + size checks stay authoritative on win32 (only MODE is relaxed)", async () => {
    await setup({
      accounts: { version: 2, accounts: [ENTRY_ALICE] },
      salt: crypto.randomBytes(16), // wrong size
      saltMode: 0o644,
    });
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE, platform: "win32" }, cap.io);
    const env = report.checks.find((c) => c.name === "env_file");
    expect(env?.status).toBe("fail");
    expect(env?.value).toBe("missing"); // missing still fails on win32
    const salt = report.checks.find((c) => c.name === "audit_salt");
    expect(salt?.status).toBe("fail");
    expect(salt?.value).toBe("wrong size (expected 32 bytes)"); // size still fails
  });

  test("POSIX platform still enforces modes (the win32 relaxation is platform-gated)", async () => {
    await setup({
      accounts: { version: 2, accounts: [ENTRY_ALICE] },
      env: "GOOGLE_CLIENT_ID=test\n",
      envMode: 0o644,
    });
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE, platform: "linux" }, cap.io);
    const env = report.checks.find((c) => c.name === "env_file");
    expect(env?.status).toBe("fail");
    expect(env?.value).toBe("wrong mode (expected 0o600)");
  });
});

describe("runDoctor — failure cases", () => {
  test("missing .env -> FAIL", async () => {
    await setup({
      accounts: { version: 2, accounts: [ENTRY_ALICE] },
    });
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const envCheck = report.checks.find((c) => c.name === "env_file");
    expect(envCheck?.status).toBe("fail");
    expect(envCheck?.value).toBe("missing");
  });

  test("wrong .env mode -> FAIL", async () => {
    await setup({
      accounts: { version: 2, accounts: [ENTRY_ALICE] },
      env: "GOOGLE_CLIENT_ID=test\n",
      envMode: 0o644,
    });
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const envCheck = report.checks.find((c) => c.name === "env_file");
    expect(envCheck?.status).toBe("fail");
    expect(envCheck?.value).toBe("wrong mode (expected 0o600)");
  });

  test("corrupt accounts.json -> FAIL with sentinel (no content echo)", async () => {
    await fs.writeFile(path.join(tmpDir, "accounts.json"), "{not json", { mode: 0o600 });
    await setup({ env: "GOOGLE_CLIENT_ID=test\n" });
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const acc = report.checks.find((c) => c.name === "accounts_json");
    expect(acc?.status).toBe("fail");
    expect(acc?.value).toBe("corrupt or invalid schema");
    // Output should NOT contain the corrupt content
    expect(cap.out.join("\n")).not.toContain("{not");
  });

  test("active-account points to email not in accounts.json -> FAIL (no email echo)", async () => {
    await setup({
      accounts: { version: 2, accounts: [ENTRY_ALICE] },
      env: "GOOGLE_CLIENT_ID=test\n",
      active: "ghost@example.com\n",
    });
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const active = report.checks.find((c) => c.name === "active_account");
    expect(active?.status).toBe("fail");
    // H-3: value must NOT echo the wrong email
    expect(active?.value).toBe("points to an email not in accounts.json");
    expect(active?.value).not.toContain("ghost@example.com");
  });

  test("invalid SAFESPACE_TIER -> FAIL with fixed message (no env-value echo)", async () => {
    process.env.SAFESPACE_TIER = "SECRET-CANARY-TIER-VALUE";
    await setup({
      accounts: { version: 2, accounts: [ENTRY_ALICE] },
      env: "GOOGLE_CLIENT_ID=test\n",
    });
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const tier = report.checks.find((c) => c.name === "tier");
    expect(tier?.status).toBe("fail");
    expect(tier?.value).toBe("invalid value (expected: read|write|share|unset)");
    // M-3: env value must NEVER appear in output or in report
    expect(cap.out.join("\n")).not.toContain("SECRET-CANARY-TIER-VALUE");
    expect(JSON.stringify(report)).not.toContain("SECRET-CANARY-TIER-VALUE");
  });

  test("audit-salt wrong size -> FAIL", async () => {
    await setup({
      accounts: { version: 2, accounts: [ENTRY_ALICE] },
      env: "GOOGLE_CLIENT_ID=test\n",
      salt: Buffer.alloc(16), // wrong size
    });
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const salt = report.checks.find((c) => c.name === "audit_salt");
    expect(salt?.status).toBe("fail");
    expect(salt?.value).toContain("wrong size");
  });

  test("missing deps -> FAIL per dep", async () => {
    await setup({
      accounts: { version: 2, accounts: [ENTRY_ALICE] },
      env: "GOOGLE_CLIENT_ID=test\n",
    });
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: ALL_MISSING_PROBE }, cap.io);
    for (const cmd of ["bun", "claude", "jq"]) {
      const c = report.checks.find((c) => c.name === cmd);
      expect(c?.status).toBe("fail");
      expect(c?.value).toBe("missing");
    }
  });
});

describe("runDoctor — --json output", () => {
  test("emits a single valid JSON object with status field", async () => {
    await setup({
      accounts: { version: 2, accounts: [ENTRY_ALICE] },
      env: "GOOGLE_CLIENT_ID=test\n",
    });
    const cap = captureIO();
    await runDoctor({ versionProbe: STUB_PROBE, json: true }, cap.io);
    expect(cap.out).toHaveLength(1);
    const parsed = JSON.parse(cap.out[0]!);
    expect(parsed.status).toMatch(/^(ok|warn|fail)$/);
    expect(Array.isArray(parsed.checks)).toBe(true);
    for (const c of parsed.checks) {
      expect(c.name).toBeDefined();
      expect(c.status).toMatch(/^(pass|warn|fail)$/);
    }
  });

  test("--json output never contains .env content (C-1 canary)", async () => {
    // Plant a unique canary in .env content AND in corrupt accounts.json bytes,
    // run doctor with --json, assert canary never appears in any output stream.
    await fs.writeFile(
      path.join(tmpDir, ".env"),
      "GOOGLE_CLIENT_SECRET=SECRET-CANARY-IN-ENV-CONTENT\n",
      { mode: 0o600 },
    );
    await fs.writeFile(
      path.join(tmpDir, "accounts.json"),
      "BEARER_CANARY-IN-JSON-PARSE not valid json",
      { mode: 0o600 },
    );
    const cap = captureIO();
    await runDoctor({ versionProbe: STUB_PROBE, json: true }, cap.io);
    const fullOutput = cap.out.join("\n") + "\n" + cap.err.join("\n");
    expect(fullOutput).not.toContain("SECRET-CANARY-IN-ENV-CONTENT");
    expect(fullOutput).not.toContain("CANARY-IN-JSON-PARSE");
    expect(fullOutput).not.toContain("BEARER");
  });
});

describe("runDoctor — --deep", () => {
  test("without --deep, no keychain checks are emitted", async () => {
    await setup({
      accounts: { version: 2, accounts: [ENTRY_ALICE] },
      env: "GOOGLE_CLIENT_ID=test\n",
    });
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const keychainChecks = report.checks.filter((c) => c.name.startsWith("keychain:"));
    expect(keychainChecks).toEqual([]);
  });

  // Positive --deep test would require either real Keychain access (flaky in
  // CI) or a getToken seam (not currently exposed). H-1's design — value is
  // always "found" or "missing", never the token string — is enforced by the
  // structure of runDoctor itself (search the source for the comment block).
});

// v1.8.2 #7 — pending_restart check.
describe("runDoctor — pending_restart", () => {
  test("no marker → pass with info value (fresh install / upgrade case)", async () => {
    await setup({ accounts: { version: 2, accounts: [ENTRY_ALICE] } });
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const check = report.checks.find((c) => c.name === "pending_restart");
    expect(check).toBeDefined();
    expect(check!.status).toBe("pass");
    expect(check!.value).toMatch(/no proxy startup marker/);
  });

  test("marker present + no policy files modified → pass", async () => {
    await setup({ accounts: { version: 2, accounts: [ENTRY_ALICE] } });
    // Write marker AFTER any setup-side file writes so the marker is newest.
    await new Promise((r) => setTimeout(r, 10));
    const { writeStartupMarker } = await import("./startup-marker");
    await writeStartupMarker(tmpDir);

    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const check = report.checks.find((c) => c.name === "pending_restart");
    expect(check).toBeDefined();
    expect(check!.status).toBe("pass");
    expect(check!.value).toMatch(/none \(proxy started/);
  });

  test("marker older than .env → warn names .env", async () => {
    await setup({ accounts: { version: 2, accounts: [ENTRY_ALICE] } });
    // Marker first.
    const { writeStartupMarker } = await import("./startup-marker");
    await writeStartupMarker(tmpDir);

    // Sleep so the next write produces a definitively newer mtime.
    await new Promise((r) => setTimeout(r, 50));
    await fs.writeFile(path.join(tmpDir, ".env"), "SAFESPACE_TIER=write\n", { mode: 0o600 });

    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const check = report.checks.find((c) => c.name === "pending_restart");
    expect(check).toBeDefined();
    expect(check!.status).toBe("warn");
    expect(check!.value).toContain(".env");
    expect(check!.value).toMatch(/restart Claude Code/);
  });

  test("marker older than drive-whitelist.json → warn names whitelist file", async () => {
    await setup({ accounts: { version: 2, accounts: [ENTRY_ALICE] } });
    const { writeStartupMarker } = await import("./startup-marker");
    await writeStartupMarker(tmpDir);

    await new Promise((r) => setTimeout(r, 50));
    // Valid v1 whitelist shape with valid Drive ID (saveWhitelist's regex
    // requires 20+ char [A-Za-z0-9_-]).
    const validWhitelist = {
      schema_version: 1,
      updated_at: new Date().toISOString(),
      entries: [
        {
          type: "folder",
          id: "1aBcDeFgHiJkLmNoPqRs00",
          label: "test",
          added_at: new Date().toISOString(),
        },
      ],
    };
    await fs.writeFile(
      path.join(tmpDir, "drive-whitelist.json"),
      JSON.stringify(validWhitelist, null, 2) + "\n",
      { mode: 0o600 },
    );

    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const check = report.checks.find((c) => c.name === "pending_restart");
    expect(check).toBeDefined();
    expect(check!.status).toBe("warn");
    expect(check!.value).toContain("drive-whitelist.json");
  });

  test("marker older than BOTH → warn names both files", async () => {
    await setup({ accounts: { version: 2, accounts: [ENTRY_ALICE] } });
    const { writeStartupMarker } = await import("./startup-marker");
    await writeStartupMarker(tmpDir);

    await new Promise((r) => setTimeout(r, 50));
    await fs.writeFile(path.join(tmpDir, ".env"), "SAFESPACE_TIER=write\n", { mode: 0o600 });
    const validWhitelist = {
      schema_version: 1,
      updated_at: new Date().toISOString(),
      entries: [],
    };
    await fs.writeFile(
      path.join(tmpDir, "drive-whitelist.json"),
      JSON.stringify(validWhitelist) + "\n",
      { mode: 0o600 },
    );

    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const check = report.checks.find((c) => c.name === "pending_restart");
    expect(check).toBeDefined();
    expect(check!.status).toBe("warn");
    expect(check!.value).toContain(".env");
    expect(check!.value).toContain("drive-whitelist.json");
  });

  test("absent policy files (post-marker fresh install) → pass", async () => {
    // setup() creates accounts.json but nothing else by default.
    await setup({ accounts: { version: 2, accounts: [ENTRY_ALICE] } });
    const { writeStartupMarker } = await import("./startup-marker");
    await writeStartupMarker(tmpDir);

    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const check = report.checks.find((c) => c.name === "pending_restart");
    expect(check!.status).toBe("pass");
    // No file mentions — marker exists, all policy files absent.
    expect(check!.value).toMatch(/none \(proxy started/);
  });
});

/* ──────────────────────────────────────────────────────────────────────
 *  v1.18 Phase 1 — doctor env-var surfacing
 *
 *  4 new rows: youtube_comment_targets, youtube_comment_burst_limit,
 *  youtube_search_burst_limit, recipient_allow_contacts.
 *
 *  Output discipline: values are FIXED sentinel strings. NEVER echo raw
 *  env-var content (sec-rev hook #7) — env vars may be attacker-
 *  controlled via parent process per status.ts M-3 carry-forward.
 * ────────────────────────────────────────────────────────────────────── */
describe("runDoctor — v1.18 env-var surfacing", () => {
  // Env-var state that may pollute across tests — save/restore per case.
  const ENV_KEYS = [
    "SAFESPACE_YOUTUBE_COMMENT_TARGETS",
    "SAFESPACE_YOUTUBE_COMMENT_TARGETS_EXTRA",
    "SAFESPACE_YOUTUBE_COMMENT_BURST_LIMIT",
    "SAFESPACE_YOUTUBE_SEARCH_BURST_LIMIT",
    "SAFESPACE_RECIPIENT_ALLOW_CONTACTS",
    "SAFESPACE_YOUTUBE_ANALYTICS_MONETARY",
  ] as const;
  let envBackup: Record<string, string | undefined> = {};

  beforeEach(async () => {
    envBackup = {};
    for (const k of ENV_KEYS) {
      envBackup[k] = process.env[k];
      delete process.env[k];
    }
    // Reset the youtube-comment-targets module singleton (cached state).
    const { __internal } = await import("./policy/youtube-comment-targets");
    __internal.resetSingletons();
    await setup({ accounts: { version: 2, accounts: [ENTRY_ALICE] } });
  });

  afterEach(async () => {
    for (const k of ENV_KEYS) {
      if (envBackup[k] === undefined) delete process.env[k];
      else process.env[k] = envBackup[k];
    }
    const { __internal } = await import("./policy/youtube-comment-targets");
    __internal.resetSingletons();
  });

  test("youtube_comment_targets: env unset → off sentinel (no raw echo)", async () => {
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const check = report.checks.find((c) => c.name === "youtube_comment_targets");
    expect(check).toBeDefined();
    expect(check!.status).toBe("pass");
    expect(check!.value).toBe("off (default-empty hard-deny; all comment writes refused)");
  });

  test("youtube_comment_targets: env set with valid entries → N entries (M parsed, K rejected)", async () => {
    process.env.SAFESPACE_YOUTUBE_COMMENT_TARGETS = "video:dQw4w9WgXcQ,channel:UCabcdefghijklmnopqrstuv";
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const check = report.checks.find((c) => c.name === "youtube_comment_targets");
    expect(check!.value).toBe("2 entries (2 parsed, 0 rejected)");
    // NEVER echo the raw entry strings.
    expect(check!.value).not.toContain("dQw4w9WgXcQ");
    expect(check!.value).not.toContain("UCabcdefghijklmnopqrstuv");
  });

  test("youtube_comment_targets: env set with mix of valid + malformed → counts both (no raw echo)", async () => {
    process.env.SAFESPACE_YOUTUBE_COMMENT_TARGETS =
      "video:dQw4w9WgXcQ,garbage:abc,channel:UCabcdefghijklmnopqrstuv,not-a-token";
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const check = report.checks.find((c) => c.name === "youtube_comment_targets");
    expect(check!.value).toBe("2 entries (2 parsed, 2 rejected)");
    expect(check!.value).not.toContain("garbage");
    expect(check!.value).not.toContain("not-a-token");
  });

  test("youtube_comment_burst_limit: env unset → '10 (default)'", async () => {
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const check = report.checks.find((c) => c.name === "youtube_comment_burst_limit");
    expect(check).toBeDefined();
    expect(check!.value).toBe("10 (default)");
  });

  test("youtube_comment_burst_limit: env override → 'N (env override)' (clamped value)", async () => {
    process.env.SAFESPACE_YOUTUBE_COMMENT_BURST_LIMIT = "25";
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const check = report.checks.find((c) => c.name === "youtube_comment_burst_limit");
    expect(check!.value).toBe("25 (env override)");
  });

  test("youtube_comment_burst_limit: env above MAX → clamped to 100 (no raw echo)", async () => {
    process.env.SAFESPACE_YOUTUBE_COMMENT_BURST_LIMIT = "9999";
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const check = report.checks.find((c) => c.name === "youtube_comment_burst_limit");
    expect(check!.value).toBe("100 (env override)");
    expect(check!.value).not.toContain("9999");
  });

  test("youtube_search_burst_limit: env unset → '20 (default)'", async () => {
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const check = report.checks.find((c) => c.name === "youtube_search_burst_limit");
    expect(check).toBeDefined();
    expect(check!.value).toBe("20 (default)");
  });

  test("youtube_search_burst_limit: env override → 'N (env override)' (clamped)", async () => {
    process.env.SAFESPACE_YOUTUBE_SEARCH_BURST_LIMIT = "50";
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const check = report.checks.find((c) => c.name === "youtube_search_burst_limit");
    expect(check!.value).toBe("50 (env override)");
  });

  test("youtube_search_burst_limit: env attacker payload → falls back to default, NO raw echo", async () => {
    // M-3 sec-rev: env vars may be attacker-controlled. Bad input must NEVER
    // reach the doctor output verbatim. The parser falls back to default 20
    // for non-numeric input, then displays the post-clamp value.
    process.env.SAFESPACE_YOUTUBE_SEARCH_BURST_LIMIT = "ATTACKER_PAYLOAD_NEVER_DISPLAYED";
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const check = report.checks.find((c) => c.name === "youtube_search_burst_limit");
    // env IS set (so "env override" suffix appears) but value is the clamped default.
    expect(check!.value).toBe("20 (env override)");
    expect(check!.value).not.toContain("ATTACKER_PAYLOAD");
  });

  test("recipient_allow_contacts: env unset → 'off'", async () => {
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const check = report.checks.find((c) => c.name === "recipient_allow_contacts");
    expect(check).toBeDefined();
    expect(check!.value).toBe("off");
  });

  test("recipient_allow_contacts: env literal 'true' → 'on (name→email lookup enabled)'", async () => {
    process.env.SAFESPACE_RECIPIENT_ALLOW_CONTACTS = "true";
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const check = report.checks.find((c) => c.name === "recipient_allow_contacts");
    expect(check!.value).toBe("on (name→email lookup enabled)");
  });

  test("recipient_allow_contacts: 'True' / 'TRUE' / '1' / 'yes' → 'off' (strict-truthy)", async () => {
    for (const v of ["True", "TRUE", "1", "yes", "on"]) {
      process.env.SAFESPACE_RECIPIENT_ALLOW_CONTACTS = v;
      const cap = captureIO();
      const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
      const check = report.checks.find((c) => c.name === "recipient_allow_contacts");
      expect(check!.value).toBe("off");
      // Raw env value MUST NOT appear in output.
      expect(check!.value).not.toContain(v);
    }
  });

  test("all 4 v1.18 rows present in doctor output (regression sentinel)", async () => {
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const names = report.checks.map((c) => c.name);
    expect(names).toContain("youtube_comment_targets");
    expect(names).toContain("youtube_comment_burst_limit");
    expect(names).toContain("youtube_search_burst_limit");
    expect(names).toContain("recipient_allow_contacts");
  });

  // v1.61 — youtube_analytics_monetary opt-in surfacing (mirror
  // recipient_allow_contacts: strict-truthy, sentinel value, no raw echo).
  test("youtube_analytics_monetary: env unset → 'off'", async () => {
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const check = report.checks.find((c) => c.name === "youtube_analytics_monetary");
    expect(check).toBeDefined();
    expect(check!.status).toBe("pass");
    expect(check!.value).toBe("off");
  });

  test("youtube_analytics_monetary: env literal 'true' → 'on (revenue metrics enabled)'", async () => {
    process.env.SAFESPACE_YOUTUBE_ANALYTICS_MONETARY = "true";
    const cap = captureIO();
    const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
    const check = report.checks.find((c) => c.name === "youtube_analytics_monetary");
    expect(check!.value).toBe("on (revenue metrics enabled)");
  });

  test("youtube_analytics_monetary: 'True' / '1' / 'yes' → 'off' (strict-truthy, no raw echo)", async () => {
    for (const v of ["True", "TRUE", "1", "yes", "on"]) {
      process.env.SAFESPACE_YOUTUBE_ANALYTICS_MONETARY = v;
      const cap = captureIO();
      const report = await runDoctor({ versionProbe: STUB_PROBE }, cap.io);
      const check = report.checks.find((c) => c.name === "youtube_analytics_monetary");
      expect(check!.value).toBe("off");
      expect(check!.value).not.toContain(v);
    }
  });
});

// ----- runPosture (v1.86 enforced-mode hardening posture) -----

describe("runPosture", () => {
  const POSTURE_VARS = [
    "SAFESPACE_ENFORCED",
    "SAFESPACE_AUTONOMOUS",
    "SAFESPACE_SECRET_BACKEND",
    "SAFESPACE_SECRET_PASSPHRASE",
    "SAFESPACE_TRANSPORT",
    "SAFESPACE_HTTP_BIND",
    "SAFESPACE_REQUIRE_SEND_APPROVAL",
    "SAFESPACE_CONFIG_DIR",
  ];
  afterEach(() => {
    for (const v of POSTURE_VARS) delete process.env[v];
    // runPosture's egress section loads the cached allowlist singletons — reset so
    // a populated cache can't leak into another test file.
    resetEgressCaches();
  });

  // The all-pass deployment: enforced + autonomous + keychain + stdio.
  function hardened(): void {
    process.env.SAFESPACE_ENFORCED = "true";
    process.env.SAFESPACE_AUTONOMOUS = "true";
    process.env.SAFESPACE_SECRET_BACKEND = "keychain";
  }
  const checkOf = (report: { checks: { name: string; status: string; value?: string }[] }, name: string) =>
    report.checks.find((c) => c.name === name)!;

  test("enforced on + fully hardened → summary ok, all gates pass", async () => {
    hardened();
    const cap = captureIO();
    const report = await runPosture({}, cap.io);
    expect(report.status).toBe("ok");
    expect(checkOf(report, "enforced_mode").status).toBe("pass");
    expect(checkOf(report, "autonomous_mode").status).toBe("pass");
    expect(checkOf(report, "token_at_rest").status).toBe("pass");
    expect(checkOf(report, "http_bind").status).toBe("pass"); // n/a (stdio) → pass
  });

  test("enforced OFF (gates would pass) → enforced_mode warn, summary warn", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    process.env.SAFESPACE_SECRET_BACKEND = "keychain";
    // SAFESPACE_ENFORCED unset.
    const cap = captureIO();
    const report = await runPosture({}, cap.io);
    expect(checkOf(report, "enforced_mode").status).toBe("warn");
    expect(checkOf(report, "enforced_mode").value).toContain("off");
    expect(report.status).toBe("warn");
  });

  test("enforced on + a failing gate → summary fail", async () => {
    process.env.SAFESPACE_ENFORCED = "true";
    process.env.SAFESPACE_AUTONOMOUS = "true";
    process.env.SAFESPACE_SECRET_BACKEND = "file"; // KEY-FILE mode → token_at_rest fail
    const cap = captureIO();
    const report = await runPosture({}, cap.io);
    expect(report.status).toBe("fail");
    expect(checkOf(report, "token_at_rest").status).toBe("fail");
  });

  test("text output prints the external-layers NOTE (honest 'verify externally')", async () => {
    hardened();
    const cap = captureIO();
    await runPosture({}, cap.io);
    const joined = cap.out.join("\n");
    expect(joined).toContain("note:");
    expect(joined).toContain("DEPLOYMENT-EXTERNAL");
    expect(joined).toContain("SOLE-EGRESS.md");
  });

  test("--json carries the external_layers note + the checks", async () => {
    hardened();
    const cap = captureIO();
    await runPosture({ json: true }, cap.io);
    expect(cap.out.length).toBe(1);
    const parsed = JSON.parse(cap.out[0]!);
    expect(parsed.status).toBe("ok");
    expect(parsed.external_layers).toContain("SOLE-EGRESS.md");
    expect(parsed.checks.some((c: { name: string }) => c.name === "enforced_mode")).toBe(true);
  });

  test("supervised mode OFF (default) → send_approval row present, 'off'", async () => {
    // SAFESPACE_REQUIRE_SEND_APPROVAL unset → the gate is the default no-op.
    const cap = captureIO();
    const report = await runPosture({}, cap.io);
    const row = checkOf(report, "send_approval");
    expect(row.status).toBe("pass");
    expect(row.value).toContain("off");
  });

  test("supervised mode ON → send_approval row 'on' with the pending count, NEVER the body/recipient", async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "posture-supervised-"));
    process.env.SAFESPACE_CONFIG_DIR = tmp;
    process.env.SAFESPACE_REQUIRE_SEND_APPROVAL = "true";
    await createPending(
      pendingSendsPath(),
      { fingerprint: "f".repeat(64), tool: "gmail_send", recipients: ["secret-recip@example.com"], body: "SECRET_BODY_XYZ", operator: "" },
      Date.now(),
      60_000,
    );
    const cap = captureIO();
    const report = await runPosture({}, cap.io);
    const row = checkOf(report, "send_approval");
    expect(row.status).toBe("pass");
    expect(row.value).toContain("on");
    expect(row.value).toContain("1 pending");
    // no-PII-echo (the load-bearing posture invariant): the pending body + recipient
    // must NEVER appear in the posture row — counts/posture words only.
    expect(row.value).not.toContain("SECRET_BODY_XYZ");
    expect(row.value).not.toContain("secret-recip@example.com");
    await fs.rm(tmp, { recursive: true, force: true });
  });

  test("supervised mode ON + a corrupt store → 'pending count unavailable', posture still passes", async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "posture-supervised-bad-"));
    process.env.SAFESPACE_CONFIG_DIR = tmp;
    process.env.SAFESPACE_REQUIRE_SEND_APPROVAL = "true";
    await fs.writeFile(pendingSendsPath(), "{ not valid json", { mode: 0o600 });
    const cap = captureIO();
    const report = await runPosture({}, cap.io);
    const row = checkOf(report, "send_approval");
    expect(row.status).toBe("pass"); // a corrupt store never FAILS the posture
    expect(row.value).toContain("unavailable");
    await fs.rm(tmp, { recursive: true, force: true });
  });
});

// ----- runPosture egress section (v1.87) — uses web-fetch (UNCACHED, reads env
// per call) so these assertions need no allowlist-singleton reset. -----
describe("runPosture — egress enumeration", () => {
  const VARS = ["SAFESPACE_ENFORCED", "SAFESPACE_AUTONOMOUS", "SAFESPACE_SECRET_BACKEND", "SAFESPACE_WEBFETCH_ALLOW"];
  // beforeEach too — clear any AUTONOMOUS/WEBFETCH leaked from a prior test/file so
  // the off→allow web-fetch row is deterministically OPEN when we expect it; reset
  // the cached allowlist singletons so this section neither reads nor leaks a stale
  // cache (the egress enumeration loads tasks-delete / github / fs / recipient).
  beforeEach(() => {
    for (const v of VARS) delete process.env[v];
    resetEgressCaches();
  });
  afterEach(() => {
    for (const v of VARS) delete process.env[v];
    resetEgressCaches();
  });

  test("the report carries per-connector egress: rows", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    process.env.SAFESPACE_SECRET_BACKEND = "keychain";
    const cap = captureIO();
    const report = await runPosture({}, cap.io);
    expect(report.checks.some((c) => c.name === "egress:web-fetch")).toBe(true);
    expect(report.checks.some((c) => c.name.startsWith("egress:github-write"))).toBe(true);
  });

  test("the report carries the egress-DESTINATION registry rows (v1.88)", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    process.env.SAFESPACE_SECRET_BACKEND = "keychain";
    const cap = captureIO();
    const report = await runPosture({}, cap.io);
    const gh = report.checks.find((c) => c.name === "egress-dest:github")!;
    expect(gh.status).toBe("pass");
    expect(gh.value).toContain("api.github.com");
    expect(gh.value).toContain("enforced");
    const goog = report.checks.find((c) => c.name === "egress-dest:google-workspace")!;
    expect(goog.value).toContain("declared");
  });

  test("an OPEN egress (web-fetch unset + interactive) surfaces as a warn row", async () => {
    process.env.SAFESPACE_SECRET_BACKEND = "keychain";
    // interactive (autonomous unset) + WEBFETCH_ALLOW unset → web-fetch OPEN.
    const cap = captureIO();
    const report = await runPosture({}, cap.io);
    const wf = report.checks.find((c) => c.name === "egress:web-fetch")!;
    expect(wf.status).toBe("warn");
    expect(wf.value).toContain("OPEN");
    // Summary is FAIL here — interactive mode also fails the autonomous_mode GATE
    // (an egress can only be OPEN when autonomous is off, which is itself a gate
    // failure). The egress rows add per-connector DETAIL, not a new top-line verdict.
    expect(report.status).toBe("fail");
  });

  test("autonomous flips the same web-fetch row to deny-all pass", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    process.env.SAFESPACE_SECRET_BACKEND = "keychain";
    const cap = captureIO();
    const report = await runPosture({}, cap.io);
    const wf = report.checks.find((c) => c.name === "egress:web-fetch")!;
    expect(wf.status).toBe("pass");
    expect(wf.value).toContain("deny-all");
  });
});
