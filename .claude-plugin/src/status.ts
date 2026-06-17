// v2.0 PR-3: `safespace status` (informational) + `safespace doctor`
// (diagnostic checks).
//
// SECURITY ASSUMPTIONS (sec-rev, 2026-05-17):
//   - NEVER print .env content. The doctor only stat()s the file to check mode.
//   - NEVER print raw Keychain values. `--deep` flow uses (getToken !== null)
//     as a boolean only; the result string never reaches output (H-1).
//   - NEVER include native Error.message in output. JSON parse errors can
//     echo file content; mirror keychain.ts pattern — emit fixed status
//     codes only (C-1).
//   - NEVER interpolate SAFESPACE_TIER env value into output. Attacker-
//     controlled; could be set to a token blob via parent process (M-3).
//   - audit.jsonl is tail-read (last 512 bytes); we extract only `ts` + `tool`
//     fields from the last line — NOT `account`, `argsHash`, or anything else
//     (L-3, M-2).
//   - active-account is read via readActive() which validates against EMAIL_RE.
//     A corrupt file returns null → check silently skips, never echoes the
//     raw file content (H-3).
//   - --json output replaces $HOME prefix with `~/` to avoid leaking the OS
//     username via paths (H-2). Human-readable text output keeps full paths.

import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { execFile } from "node:child_process";
import { readActive } from "./auth/active";
import { configDir } from "./auth/keychain";
// v1.37 BLOCKER 1: doctor --deep token ping reads via the SecretBackend facade.
import { getToken } from "./auth/token-store";
import { isContactLookupEnabled } from "./policy/contact-lookup";
import { isYoutubeAnalyticsMonetaryEnabled } from "./policy/youtube-analytics-monetary";
import { WHITELIST_FILENAME, loadWhitelist } from "./policy/drive-whitelist";
import { getAllowlistState, summarizeAllowlist } from "./policy/recipient-allowlist";
import { getCommentBurstLimit } from "./policy/youtube-comment-burst";
import {
  getCommentTargetAllowlistState,
  parseCommentTargets,
  summarizeCommentTargetAllowlist,
} from "./policy/youtube-comment-targets";
import { getYoutubeSearchBurstLimit } from "./policy/youtube-search-burst";
import { isEnforcedMode, evaluateEnforcedGates } from "./policy/enforced-mode";
import { enabledWebhookProviders, webhookEnabled } from "./transport/webhook";
import { hasWebhookSigningSecret } from "./auth/webhook-secret-store";
import { inboxCounts, inboxPath } from "./webhook/inbox-store";
import { evaluateEgressPosture } from "./policy/egress-posture";
import { EGRESS_DESTINATIONS } from "./policy/egress-destinations";
import { isSendApprovalMode } from "./policy/send-approval";
import { listPending, pendingSendsPath } from "./auth/send-approval-store";
import { readStartupMarker } from "./startup-marker";
import {
  ENV_TIER,
  ENV_YOUTUBE_COMMENT_TARGETS,
  ENV_YOUTUBE_COMMENT_TARGETS_EXTRA,
  ENV_YOUTUBE_COMMENT_BURST_LIMIT,
  ENV_YOUTUBE_SEARCH_BURST_LIMIT,
} from "./config";

const ACCOUNTS_FILE = "accounts.json";
const ENV_FILE = ".env";
const AUDIT_FILE = "audit.jsonl";
const SALT_FILE = "audit-salt";
const SALT_SIZE_BYTES = 32;
const AUDIT_TAIL_BYTES = 512; // M-2: tail-read window; covers ~3 typical audit lines

const EMAIL_RE = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

// ----- public types -----

export type CheckStatus = "pass" | "warn" | "fail";

export interface CheckResult {
  name: string;
  status: CheckStatus;
  /** Fixed sentinel string — NEVER attacker-controlled content. */
  value?: string;
}

export interface DoctorReport {
  status: "ok" | "warn" | "fail";
  checks: CheckResult[];
}

export interface StatusReport {
  configDir: string;
  tier: "read" | "write" | "share" | "unset";
  accountCount: number;
  activeAccount: string | null;
  lastAuditEntry: { ts: string; tool: string } | null;
  auditLineCount: number;
}

export interface CliIO {
  out: (line: string) => void;
  err: (line: string) => void;
}

export interface DoctorOptions {
  deep?: boolean;
  json?: boolean;
  /** Test seam — Bun.spawn-based version probes are awkward in unit tests. */
  versionProbe?: (cmd: string) => Promise<string | null>;
  /** Test seam (v1.110 PR 1c, S5) — defaults to process.platform. On "win32"
   *  the POSIX file-mode checks report "n/a (NTFS ACL)" instead of failing. */
  platform?: NodeJS.Platform;
}

export interface StatusOptions {
  json?: boolean;
}

export interface PostureOptions {
  json?: boolean;
}

// ----- tilde-path helper (H-2) -----

/** Replace `$HOME` prefix with `~/` so JSON output doesn't leak the OS
 *  username. Used ONLY in --json output. Human-readable text output keeps
 *  the full path (it's not meant for forwarding). */
export function tildePath(p: string): string {
  const home = os.homedir();
  if (p === home) return "~";
  if (p.startsWith(home + path.sep)) return "~" + p.slice(home.length);
  return p;
}

// ----- safe stat (mode-only; never reads content) -----

interface FileStat {
  exists: boolean;
  mode: number;
  size: number;
}

async function safeStat(p: string): Promise<FileStat> {
  try {
    const s = await fs.stat(p);
    return { exists: true, mode: s.mode & 0o777, size: s.size };
  } catch {
    return { exists: false, mode: 0, size: 0 };
  }
}

// v1.110 PR 1c (S5) — POSIX file-mode posture is meaningless on Windows: NTFS
// uses ACLs, not 0o600/0o700 permission bits, and node's fs.stat() reports a
// synthetic mode whose low 9 bits never equal 0o600/0o700. So on win32 every
// mode check in runDoctor would spuriously FAIL. modeVerdict collapses that: on
// win32 it reports "n/a (NTFS ACL)" and passes; on POSIX it does the real
// comparison, byte-identical to the pre-1.110 inline `=== expected` checks.
// Existence / schema / size checks are platform-independent and stay authoritative.
function modeVerdict(
  actual: number,
  expected: number,
  platform: NodeJS.Platform,
): { ok: boolean; value: string } {
  if (platform === "win32") return { ok: true, value: "n/a (NTFS ACL)" };
  return actual === expected
    ? { ok: true, value: `0o${expected.toString(8)}` }
    : { ok: false, value: `wrong mode (expected 0o${expected.toString(8)})` };
}

// ----- accounts.json reader (mirrors keychain.ts:readJsonIndex; sec-rev C-1) -----

interface AccountsSummary {
  ok: boolean;
  version?: 1 | 2;
  count?: number;
  emails?: string[];
}

async function readAccountsSummary(): Promise<AccountsSummary> {
  const p = path.join(configDir(), ACCOUNTS_FILE);
  try {
    const raw = await fs.readFile(p, "utf8");
    const parsed = JSON.parse(raw) as unknown;
    const v = (parsed as { version?: unknown } | null)?.version;
    if (
      parsed &&
      typeof parsed === "object" &&
      (v === 1 || v === 2) &&
      Array.isArray((parsed as { accounts?: unknown }).accounts)
    ) {
      const accounts = (parsed as { accounts: Array<{ email?: unknown }> }).accounts;
      const emails: string[] = [];
      for (const a of accounts) {
        if (a && typeof a.email === "string" && EMAIL_RE.test(a.email)) {
          emails.push(a.email);
        }
        // Silently skip malformed entries — never echo the bad value (C-1).
      }
      return { ok: true, version: v as 1 | 2, count: emails.length, emails };
    }
    return { ok: false };
  } catch {
    // C-1: discard native error message entirely. JSON parse errors can
    // include a fragment of the file content (e.g. `Unexpected token 'B',
    // "BEARER tok"... is not valid JSON`).
    return { ok: false };
  }
}

// ----- audit.jsonl tail-read (M-2, L-3) -----

async function tailReadLastAuditEntry(): Promise<{
  lineCount: number;
  lastEntry: { ts: string; tool: string } | null;
}> {
  const p = path.join(configDir(), AUDIT_FILE);
  const stat = await safeStat(p);
  if (!stat.exists || stat.size === 0) return { lineCount: 0, lastEntry: null };

  let fh: fs.FileHandle | null = null;
  try {
    fh = await fs.open(p, "r");
    // M-2: read only the last AUDIT_TAIL_BYTES, not the full file.
    const start = Math.max(0, stat.size - AUDIT_TAIL_BYTES);
    const len = stat.size - start;
    const buf = Buffer.alloc(len);
    await fh.read(buf, 0, len, start);
    const text = buf.toString("utf8");
    const lines = text.split("\n").filter((l) => l.length > 0);
    const lastLine = lines[lines.length - 1];
    let lastEntry: { ts: string; tool: string } | null = null;
    if (lastLine) {
      try {
        const obj = JSON.parse(lastLine) as unknown;
        // L-3: extract ONLY ts + tool. Ignore account / argsHash / args.
        if (
          obj &&
          typeof obj === "object" &&
          typeof (obj as { ts?: unknown }).ts === "string" &&
          typeof (obj as { tool?: unknown }).tool === "string"
        ) {
          lastEntry = {
            ts: (obj as { ts: string }).ts,
            tool: (obj as { tool: string }).tool,
          };
        }
      } catch {
        // C-1: parse failure → no entry, no error echo.
        lastEntry = null;
      }
    }

    // Line count via newline-byte scan; doesn't buffer parsed JSON objects.
    let lineCount = 0;
    const counterBuf = Buffer.alloc(8192);
    let pos = 0;
    while (pos < stat.size) {
      const remaining = stat.size - pos;
      const toRead = Math.min(remaining, counterBuf.length);
      await fh.read(counterBuf, 0, toRead, pos);
      for (let i = 0; i < toRead; i++) {
        if (counterBuf[i] === 0x0a) lineCount++;
      }
      pos += toRead;
    }
    // Final line without trailing newline still counts.
    if (stat.size > 0) {
      const lastByteBuf = Buffer.alloc(1);
      await fh.read(lastByteBuf, 0, 1, stat.size - 1);
      if (lastByteBuf[0] !== 0x0a) lineCount++;
    }

    return { lineCount, lastEntry };
  } catch {
    return { lineCount: 0, lastEntry: null };
  } finally {
    if (fh) await fh.close().catch(() => undefined);
  }
}

// ----- tier read (M-3: never echo env value) -----

function readTier(): "read" | "write" | "share" | "unset" {
  const raw = process.env[ENV_TIER];
  if (raw === undefined || raw === "") return "unset";
  if (raw === "read" || raw === "write" || raw === "share") return raw;
  return "unset"; // sentinel — actual invalid case detected by tierIsValidInEnv
}

function tierIsValidInEnv(): boolean {
  const raw = process.env[ENV_TIER];
  if (raw === undefined || raw === "") return true; // unset is valid (defaults to read)
  return raw === "read" || raw === "write" || raw === "share";
}

// ----- dependency version probe -----

const PROBE_TIMEOUT_MS = 5000; // L3 (#61 review): cap a misbehaving binary's hang

async function defaultVersionProbe(cmd: string): Promise<string | null> {
  // execFile (NOT a shell) runs `<cmd> --version` with a hard timeout that kills a
  // misbehaving binary — interactive REPL, network-fetching shim — so `doctor` can't hang
  // forever (L3 #61). `cmd` is drawn from a fixed internal tool list, never user input, so
  // there is no argument-injection surface even without a shell.
  return new Promise<string | null>((resolve) => {
    execFile(cmd, ["--version"], { timeout: PROBE_TIMEOUT_MS }, (err, stdout, stderr) => {
      // err is set on ENOENT (not installed), non-zero exit, OR timeout → no version.
      if (err) { resolve(null); return; }
      // L1 (#61): merge stdout + stderr — some tools print --version to stderr
      // (older Unix utilities, certain Go binaries). Take the first non-empty line.
      const combined = (stdout + "\n" + stderr)
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean);
      resolve(combined[0] ?? null);
    });
  });
}

// ----- runStatus -----

export async function runStatus(opts: StatusOptions, io: CliIO): Promise<StatusReport> {
  const cfg = configDir();
  const tier = readTier();
  const accountsSummary = await readAccountsSummary();
  const activeAccount = await readActive(); // H-3: EMAIL_RE-validated
  const audit = await tailReadLastAuditEntry();

  const report: StatusReport = {
    configDir: cfg,
    tier,
    accountCount: accountsSummary.count ?? 0,
    activeAccount,
    lastAuditEntry: audit.lastEntry,
    auditLineCount: audit.lineCount,
  };

  if (opts.json) {
    // L-4: single top-level JSON.stringify call.
    // H-2: replace home prefix in path field.
    io.out(
      JSON.stringify({
        config_dir: tildePath(report.configDir),
        tier: report.tier,
        account_count: report.accountCount,
        active_account: report.activeAccount,
        last_audit_entry: report.lastAuditEntry, // {ts, tool} only — L-3
        audit_line_count: report.auditLineCount,
      }),
    );
  } else {
    io.out(`config dir: ${report.configDir}`);
    io.out(`tier:       ${report.tier === "unset" ? "unset (defaults to read)" : report.tier}`);
    const activeSuffix = activeAccount ? ` (active: ${activeAccount})` : "";
    io.out(`accounts:   ${report.accountCount} registered${activeSuffix}`);
    if (report.lastAuditEntry) {
      io.out(`last call:  ${report.lastAuditEntry.ts} (${report.lastAuditEntry.tool})`);
    } else {
      io.out(`last call:  (no audit entries)`);
    }
    io.out(`audit log:  ${report.auditLineCount} entries`);
  }

  return report;
}

// ----- runDoctor -----

function summarize(checks: CheckResult[]): "ok" | "warn" | "fail" {
  if (checks.some((c) => c.status === "fail")) return "fail";
  if (checks.some((c) => c.status === "warn")) return "warn";
  return "ok";
}

export async function runDoctor(opts: DoctorOptions, io: CliIO): Promise<DoctorReport> {
  const probe = opts.versionProbe ?? defaultVersionProbe;
  const platform = opts.platform ?? process.platform;
  const checks: CheckResult[] = [];

  // Dep versions
  for (const cmd of ["bun", "claude", "jq"] as const) {
    const v = await probe(cmd);
    checks.push({
      name: cmd,
      status: v === null ? "fail" : "pass",
      value: v ?? "missing",
    });
  }

  // Tier validity (M-3: never echo env value)
  const tierValid = tierIsValidInEnv();
  checks.push({
    name: "tier",
    status: tierValid ? "pass" : "fail",
    value: tierValid
      ? (process.env[ENV_TIER] ?? "unset (defaults to read)")
      : "invalid value (expected: read|write|share|unset)",
  });

  // Config dir mode. TOCTOU note (L-1 sec-rev, #61 review): the mode check
  // here is read-only — `doctor` reports findings and never auto-fixes. If a
  // future maintainer adds auto-repair (chmod 0o700 on detected drift), the
  // stat→chmod gap becomes a real race and the check must be revisited.
  const cfg = configDir();
  const cfgStat = await safeStat(cfg);
  const cfgMode = modeVerdict(cfgStat.mode, 0o700, platform);
  checks.push({
    name: "config_dir",
    status: cfgStat.exists && cfgMode.ok ? "pass" : "fail",
    value: !cfgStat.exists ? "missing" : cfgMode.value,
  });

  // .env mode (NEVER reads content)
  const envStat = await safeStat(path.join(cfg, ENV_FILE));
  const envMode = modeVerdict(envStat.mode, 0o600, platform);
  checks.push({
    name: "env_file",
    status: !envStat.exists ? "fail" : envMode.ok ? "pass" : "fail",
    value: !envStat.exists ? "missing" : envMode.value,
  });

  // accounts.json: mode + schema
  const accountsPath = path.join(cfg, ACCOUNTS_FILE);
  const accountsStat = await safeStat(accountsPath);
  const accountsMode = modeVerdict(accountsStat.mode, 0o600, platform);
  const accountsSummary = await readAccountsSummary();
  if (!accountsStat.exists) {
    checks.push({ name: "accounts_json", status: "fail", value: "missing" });
  } else if (!accountsMode.ok) {
    checks.push({ name: "accounts_json", status: "fail", value: accountsMode.value });
  } else if (!accountsSummary.ok) {
    checks.push({ name: "accounts_json", status: "fail", value: "corrupt or invalid schema" });
  } else {
    checks.push({
      name: "accounts_json",
      status: "pass",
      value: `v${accountsSummary.version}, ${accountsSummary.count} account(s)`,
    });
  }

  // audit.jsonl mode (if exists; missing is OK — first run has no audit yet)
  const auditStat = await safeStat(path.join(cfg, AUDIT_FILE));
  if (auditStat.exists) {
    const auditMode = modeVerdict(auditStat.mode, 0o600, platform);
    checks.push({
      name: "audit_jsonl",
      status: auditMode.ok ? "pass" : "fail",
      value: auditMode.value,
    });
  }

  // audit-salt: mode + size 32 bytes (if exists; missing is OK — created lazily)
  const saltStat = await safeStat(path.join(cfg, SALT_FILE));
  if (saltStat.exists) {
    const saltMode = modeVerdict(saltStat.mode, 0o600, platform);
    if (!saltMode.ok) {
      checks.push({ name: "audit_salt", status: "fail", value: saltMode.value });
    } else if (saltStat.size !== SALT_SIZE_BYTES) {
      checks.push({
        name: "audit_salt",
        status: "fail",
        value: `wrong size (expected ${SALT_SIZE_BYTES} bytes)`,
      });
    } else {
      checks.push({ name: "audit_salt", status: "pass", value: `${saltMode.value}, 32 bytes` });
    }
  }

  // v2.1: drive-whitelist.json state. Three doctor outcomes:
  //   - absent → INFO ("policy off; tier=share fully open")
  //   - loaded with N>=0 entries → PASS (with entry count + mode check)
  //   - malformed → FAIL (fail-safe to default-deny per spec)
  // Mode is checked first; if wrong, that's the FAIL (matches .env / audit
  // patterns). loadWhitelist never echoes content into errors, so reporting
  // its error string is safe (see drive-whitelist.ts validateWhitelistFile
  // sec-rev invariant).
  const whitelistPath = path.join(cfg, WHITELIST_FILENAME);
  const whitelistStat = await safeStat(whitelistPath);
  const whitelistMode = modeVerdict(whitelistStat.mode, 0o600, platform);
  if (!whitelistStat.exists) {
    checks.push({
      name: "drive_whitelist",
      status: "pass",
      value: "absent (policy off; tier=share fully open per v2.0 behavior)",
    });
  } else if (!whitelistMode.ok) {
    checks.push({
      name: "drive_whitelist",
      status: "fail",
      value: whitelistMode.value,
    });
  } else {
    const state = await loadWhitelist(cfg);
    if (state.kind === "malformed") {
      checks.push({
        name: "drive_whitelist",
        status: "fail",
        value: `malformed: ${state.error}`,
      });
    } else if (state.kind === "loaded") {
      const folderCount = state.file.entries.filter((e) => e.type === "folder").length;
      const fileCount = state.file.entries.filter((e) => e.type === "file").length;
      const total = state.file.entries.length;
      checks.push({
        name: "drive_whitelist",
        status: "pass",
        value:
          total === 0
            ? "0 entries (default-deny — all share calls will be refused)"
            : `${total} entries (${folderCount} folder, ${fileCount} file)`,
      });
    }
  }

  // v2.2: Recipient allowlist 3-line report. Counts only, NEVER entries —
  // mirrors v2.1's "no policy state leakage" pattern. summarizeAllowlist()
  // is the only API path used here (it returns counts); we never call
  // parseAllowlistTokens directly, so ParseResult.rejected values cannot
  // leak through this check (sec-rev PR-A MEDIUM #1 mitigation).
  const allowlistState = await getAllowlistState();
  const allowlistSummary = summarizeAllowlist(allowlistState);
  if (allowlistSummary.kind === "off") {
    checks.push({
      name: "recipient_allow",
      status: "pass",
      value: "unset (policy off; gmail_send + drive_share_file user fully open per v2.1 behavior)",
    });
  } else {
    checks.push({
      name: "recipient_allow",
      status: "pass",
      value:
        allowlistSummary.allow_count === 0
          ? "0 entries (default-deny base — only self-send + EXTRA allowed)"
          : `${allowlistSummary.allow_count} entries (${allowlistSummary.allow_domain_count} domain, ${allowlistSummary.allow_email_count} email)`,
    });
  }
  checks.push({
    name: "recipient_allow_extra",
    status: "pass",
    value:
      allowlistSummary.extra_count === 0
        ? "(none)"
        : `${allowlistSummary.extra_count} entries — session-only (${allowlistSummary.extra_domain_count} domain, ${allowlistSummary.extra_email_count} email)`,
  });
  checks.push({
    name: "self_send_implicit",
    status: "pass",
    value: `${allowlistSummary.self_implicit_count} emails from accounts.json`,
  });

  // v1.18 Phase 1 — surface 4 v1.15-Phase-3 + v1.16 env vars that gate the
  // most dangerous write surfaces (YouTube comment writes + name→email
  // contact lookup). Mirrors the recipient_allow* + drive_whitelist
  // 3-line pattern: counts ONLY, never raw env-var content (sec-rev
  // hook #7 — env vars may be attacker-controlled via parent process per
  // status.ts M-3 carry-forward).
  //
  // youtube_comment_targets: cached state via getCommentTargetAllowlistState()
  // gives us parsed count + active/off discrimination. Re-parse env directly
  // to get rejected count (cached state drops it after the load-once warn).
  const commentTargetState = getCommentTargetAllowlistState();
  const commentTargetSummary = summarizeCommentTargetAllowlist(commentTargetState);
  if (commentTargetSummary.kind === "off") {
    checks.push({
      name: "youtube_comment_targets",
      status: "pass",
      value: "off (default-empty hard-deny; all comment writes refused)",
    });
  } else {
    // Re-parse to compute rejected count. NEVER echo the rejected token
    // strings — counts only. parseCommentTargets is pure + cheap.
    const baseParsed = parseCommentTargets(process.env[ENV_YOUTUBE_COMMENT_TARGETS]);
    const extraParsed = parseCommentTargets(process.env[ENV_YOUTUBE_COMMENT_TARGETS_EXTRA]);
    const rejectedCount = baseParsed.rejected.length + extraParsed.rejected.length;
    checks.push({
      name: "youtube_comment_targets",
      status: "pass",
      value: `${commentTargetSummary.count} entries (${commentTargetSummary.count} parsed, ${rejectedCount} rejected)`,
    });
  }

  // youtube_comment_burst_limit + youtube_search_burst_limit: display the
  // CLAMPED post-parse value (parser bounds-checks 1-100). Out-of-range raw
  // values cannot reach this surface — parser fell back to default.
  const commentBurst = getCommentBurstLimit();
  checks.push({
    name: "youtube_comment_burst_limit",
    status: "pass",
    value:
      process.env[ENV_YOUTUBE_COMMENT_BURST_LIMIT] === undefined
        ? `${commentBurst} (default)`
        : `${commentBurst} (env override)`,
  });
  const searchBurst = getYoutubeSearchBurstLimit();
  checks.push({
    name: "youtube_search_burst_limit",
    status: "pass",
    value:
      process.env[ENV_YOUTUBE_SEARCH_BURST_LIMIT] === undefined
        ? `${searchBurst} (default)`
        : `${searchBurst} (env override)`,
  });

  // recipient_allow_contacts: strict-truthy ("true" literal only — see
  // contact-lookup.ts). Display "on" / "off" sentinels — NEVER the raw
  // env value (could be set to "true\nALLOW_ARBITRARY_CMD=…" via parent).
  checks.push({
    name: "recipient_allow_contacts",
    status: "pass",
    value: isContactLookupEnabled() ? "on (name→email lookup enabled)" : "off",
  });

  // v1.61 youtube_analytics_monetary: strict-truthy ("true" literal only — see
  // youtube-analytics-monetary.ts). Display "on" / "off" sentinels — NEVER the
  // raw env value. "on" means the consent ceremony requests the revenue scope
  // AND youtube_analytics_query unlocks the revenue metrics; "off" (default) is
  // byte-identical to v1.59 (no revenue access).
  checks.push({
    name: "youtube_analytics_monetary",
    status: "pass",
    value: isYoutubeAnalyticsMonetaryEnabled() ? "on (revenue metrics enabled)" : "off",
  });

  // v1.8.2 #7: pending_restart — proxy reads .env + drive-whitelist.json
  // at startup (env via `bun --env-file=`, whitelist via load-once cache).
  // Changes after proxy start don't take effect until Claude Code restarts.
  // We detect this by comparing the proxy startup marker to file mtimes.
  // The startup marker filename is hidden in startup-marker.ts; no policy
  // file content is read here (only stat()), preserving the "doctor never
  // echoes policy values" invariant.
  const startupMarker = await readStartupMarker(cfg);
  if (startupMarker === null) {
    // Marker absent on fresh install (proxy hasn't run yet) or post-upgrade
    // (pre-v1.8.2 proxy never wrote one). Both are benign — informational
    // pass rather than warn so doctor doesn't shout on every fresh install.
    // The actually-bad state (marker exists + files newer) is the warn below.
    checks.push({
      name: "pending_restart",
      status: "pass",
      value: "no proxy startup marker yet (first run, or upgrade from pre-v1.8.2)",
    });
  } else {
    const filesToCheck: Array<{ name: string; path: string }> = [
      { name: "drive-whitelist.json", path: whitelistPath },
      { name: ".env", path: path.join(cfg, ENV_FILE) },
    ];
    const pending: string[] = [];
    for (const f of filesToCheck) {
      try {
        const s = await fs.stat(f.path);
        if (s.mtime.getTime() > startupMarker.getTime()) {
          pending.push(f.name);
        }
      } catch {
        /* file absent — not pending */
      }
    }
    const markerTs = startupMarker.toISOString().slice(0, 19);
    if (pending.length === 0) {
      checks.push({
        name: "pending_restart",
        status: "pass",
        value: `none (proxy started ${markerTs})`,
      });
    } else {
      checks.push({
        name: "pending_restart",
        status: "warn",
        value: `${pending.join(", ")} modified after proxy started (${markerTs}) — restart Claude Code to pick up changes`,
      });
    }
  }

  // active-account: if present, must reference an email in accounts.json (H-3)
  const active = await readActive(); // EMAIL_RE-validated; corrupt → null
  if (active !== null) {
    const inIndex = accountsSummary.ok && (accountsSummary.emails ?? []).includes(active);
    checks.push({
      name: "active_account",
      status: inIndex ? "pass" : "fail",
      value: inIndex
        ? `valid (${active})`
        : "points to an email not in accounts.json", // do NOT echo the wrong email value
    });
  }

  // --deep: per-account Keychain ping (H-1, M-1)
  if (opts.deep && accountsSummary.ok && accountsSummary.emails) {
    for (const email of accountsSummary.emails) {
      let found = false;
      try {
        // M-1: getToken returns the full token JSON briefly. We immediately
        // coerce to a boolean — never name the intermediate `token` and
        // never let it flow into output. The string is GC-eligible after
        // this line. Heap-resident for milliseconds.
        found = (await getToken(email)) !== null;
      } catch {
        // getToken throws MCPError("keychain_locked") with NO native message.
        // Render as "missing" to keep the check value a fixed string.
        found = false;
      }
      checks.push({
        name: `keychain:${email}`,
        status: found ? "pass" : "fail",
        value: found ? "found" : "missing",
      });
    }
  }

  const report: DoctorReport = { status: summarize(checks), checks };

  if (opts.json) {
    // L-4: single top-level JSON.stringify; never string-concat output.
    // H-2: NO paths leak in JSON (doctor JSON has no path fields by design).
    io.out(JSON.stringify(report));
  } else {
    for (const c of checks) {
      const tag = c.status === "pass" ? "[PASS]" : c.status === "warn" ? "[WARN]" : "[FAIL]";
      const valueSuffix = c.value !== undefined ? `: ${c.value}` : "";
      io.out(`${tag} ${c.name}${valueSuffix}`);
    }
    io.out("");
    io.out(`summary: ${report.status.toUpperCase()}`);
  }

  return report;
}

// ----- runPosture (v1.86 — enforced-mode hardening posture) -----

// The honest "what SafeSpace can't check" reminder (docs/SOLE-EGRESS.md). Always
// surfaced so a green posture is never read as "sole egress" — these layers are
// DEPLOYMENT-EXTERNAL. Emitted as a NOTE (not a CheckResult) so it never pollutes
// the pass/warn/fail roll-up with a perpetual warn.
const EXTERNAL_LAYERS_NOTE =
  "SafeSpace verifies its OWN hardening knobs only. The network egress lockdown " +
  "(the load-bearing one), the agent runtime sandbox, and provider IP-pinning are " +
  "DEPLOYMENT-EXTERNAL — SafeSpace cannot check them. Verify them per docs/SOLE-EGRESS.md.";

/** `safespace doctor --posture` — report the enforced-mode hardening posture: the
 *  SAFESPACE_ENFORCED flag state + the three refuse-to-start gates (the SAME gate
 *  evaluation the startup guard uses), plus the honest external-layers reminder.
 *  Read-only; runs identically under stdio (Model A) and http (Model B). */
export async function runPosture(opts: PostureOptions, io: CliIO): Promise<DoctorReport> {
  const checks: CheckResult[] = [];

  const enforced = isEnforcedMode();
  checks.push({
    name: "enforced_mode",
    status: enforced ? "pass" : "warn",
    value: enforced ? "on (refuse-to-start active)" : "off (gates reported, not enforced)",
  });

  for (const g of evaluateEnforcedGates()) {
    checks.push({
      name: g.name,
      // CheckResult has no "n/a"; an inapplicable gate (http_bind under stdio) is
      // not a problem → render as pass, with the value making "n/a" explicit so it
      // never reads as a verified green.
      status: g.status === "n/a" ? "pass" : g.status,
      value: g.detail,
    });
  }

  // v1.100 — supervised send-approval posture (the v1.99 opt-in gate). On = outbound
  // message sends are held for owner approval; off = the default (NOT a deficiency —
  // most deployments run unsupervised / autonomous). Shows the pending COUNT only;
  // NEVER a pending body/recipient (no-PII-echo, like the egress rows).
  const supervised = isSendApprovalMode();
  let supervisedValue: string;
  if (!supervised) {
    supervisedValue = "off (sends are not gated by per-send approval — the default)";
  } else {
    let pending: string;
    try {
      pending = `${(await listPending(pendingSendsPath(), Date.now())).length} pending`;
    } catch {
      pending = "pending count unavailable (store unreadable)";
    }
    supervisedValue = `on — outbound message sends require owner approval (${pending})`;
  }
  checks.push({ name: "send_approval", status: "pass", value: supervisedValue });

  // v1.102 (W0) — inbound webhook listener posture. Disabled under Model A
  // (SAFESPACE_WEBHOOK_PORT unset) → no inbound surface, never implies one exists. When
  // enabled: which providers are wired, whether each signing secret is present, and the
  // inbox COUNT per provider (counts only — NEVER a body/sender, like the egress rows).
  // A corrupt store → "unavailable", never fails the posture (v1.87/v1.101 precedent).
  if (!webhookEnabled()) {
    checks.push({
      name: "webhook",
      status: "pass",
      value: "disabled (SAFESPACE_WEBHOOK_PORT unset — no inbound webhook surface)",
    });
  } else {
    const providers = enabledWebhookProviders();
    const secretParts: string[] = [];
    for (const p of providers) {
      let present = false;
      try {
        present = await hasWebhookSigningSecret(p);
      } catch {
        present = false;
      }
      secretParts.push(`${p} secret ${present ? "present" : "MISSING"}`);
    }
    let counts: string;
    try {
      const c = await inboxCounts(inboxPath(), Date.now());
      counts = providers.map((p) => `${p}:${c[p]}`).join(", ");
    } catch {
      counts = "count unavailable (store unreadable)";
    }
    const anyMissing = secretParts.some((s) => s.includes("MISSING"));
    checks.push({
      name: "webhook",
      status: anyMissing ? "warn" : "pass",
      value: `on — providers: ${providers.join(", ")}; ${secretParts.join("; ")}; inbox ${counts}`,
    });
  }

  // Per-connector egress/access allowlist enumeration (v1.87) — what can actually
  // reach/leave through this deployment. Rows carry COUNTS only, never contents.
  // An OPEN (off→allow + unset + interactive) connector is the one warn here.
  for (const e of await evaluateEgressPosture()) {
    checks.push({ name: `egress:${e.connector}`, status: e.status, value: e.detail });
  }

  // Egress-DESTINATION registry (v1.88) — the complementary "SafeSpace → provider"
  // direction: every external host SafeSpace's OWN process connects to. Informational
  // (always pass); `enforced` = runtime-gated at the fetch chokepoint, `declared` =
  // listed-but-ungatable (the googleapis SDK / the dynamic web-fetch url-gate own it).
  for (const d of EGRESS_DESTINATIONS) {
    checks.push({
      name: `egress-dest:${d.connector}`,
      status: "pass",
      value: `${d.hosts.join(", ")} (${d.enforcement}${d.note ? ` — ${d.note}` : ""})`,
    });
  }

  const report: DoctorReport = { status: summarize(checks), checks };

  if (opts.json) {
    io.out(JSON.stringify({ ...report, external_layers: EXTERNAL_LAYERS_NOTE }));
  } else {
    for (const c of checks) {
      const tag = c.status === "pass" ? "[PASS]" : c.status === "warn" ? "[WARN]" : "[FAIL]";
      const valueSuffix = c.value !== undefined ? `: ${c.value}` : "";
      io.out(`${tag} ${c.name}${valueSuffix}`);
    }
    io.out("");
    io.out(`note: ${EXTERNAL_LAYERS_NOTE}`);
    io.out("");
    io.out(`summary: ${report.status.toUpperCase()}`);
  }

  return report;
}
