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

import * as path from "node:path";
import { readActive } from "./auth/active";
import { configDir } from "./auth/keychain";
import {
  type StatusReport,
  type StatusOptions,
  type CliIO,
  tildePath,
  readTier,
  readAccountsSummary,
  tailReadLastAuditEntry,
  AUDIT_FILE,
  AUDIT_CLI_FILE,
  safeStat,
} from "./status/shared";

// ----- public surface (the status/ split is internal; importers use `./status`) -----
export type {
  CheckStatus,
  CheckResult,
  DoctorReport,
  StatusReport,
  CliIO,
  DoctorOptions,
  StatusOptions,
  PostureOptions,
} from "./status/shared";
export { tildePath } from "./status/shared";
export { runDoctor } from "./status/doctor";
export { runPosture } from "./status/posture";

// ----- runStatus -----

export async function runStatus(opts: StatusOptions, io: CliIO): Promise<StatusReport> {
  const cfg = configDir();
  const tier = readTier();
  const accountsSummary = await readAccountsSummary();
  const activeAccount = await readActive(); // H-3: EMAIL_RE-validated
  // With audit-cli.jsonl present, compare both files' latest real call (64 KB tails,
  // skipping anchor/event lines); without it, today's single-file read.
  const hasCli = (await safeStat(path.join(cfg, AUDIT_CLI_FILE))).exists;
  const audit = hasCli
    ? await tailReadLastAuditEntry({ file: AUDIT_FILE, tailBytes: 65536, scanBack: true })
    : await tailReadLastAuditEntry();
  const cliAudit = hasCli
    ? await tailReadLastAuditEntry({ file: AUDIT_CLI_FILE, tailBytes: 65536, scanBack: true })
    : null;
  const lastEntry =
    cliAudit?.lastEntry && (!audit.lastEntry || cliAudit.lastEntry.ts > audit.lastEntry.ts)
      ? cliAudit.lastEntry
      : audit.lastEntry;

  const report: StatusReport = {
    configDir: cfg,
    tier,
    accountCount: accountsSummary.count ?? 0,
    activeAccount,
    lastAuditEntry: lastEntry,
    auditLineCount: audit.lineCount,
    ...(cliAudit ? { auditCliLineCount: cliAudit.lineCount } : {}),
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
        ...(report.auditCliLineCount !== undefined ? { audit_cli_line_count: report.auditCliLineCount } : {}),
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
    io.out(
      report.auditCliLineCount === undefined
        ? `audit log:  ${report.auditLineCount} entries`
        : `audit log:  ${report.auditLineCount} entries (audit.jsonl) + ${report.auditCliLineCount} (audit-cli.jsonl)`,
    );
  }

  return report;
}
