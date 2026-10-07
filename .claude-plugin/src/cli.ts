#!/usr/bin/env bun
// CLI dispatch.
// Wired so far:
//   2     consent <email> [--re-auth]
//   5.6   account-list, account-switch <email>
// Planned: 5.7 account-revoke, Step 6 audit.
//
// Security-review fix #4 (Step 2): validate email argv against a strict regex
// before passing it anywhere downstream (mirrors auth/active.ts).

import * as path from "node:path";
import { clearActive, readActive, writeActive } from "./auth/active";
import { consent } from "./auth/consent";
// v1.70 (G3): the GitHub OAuth source — `--provider github` variants of the
// OAuth-account commands + the github login validator.
import { GITHUB_LOGIN_RE } from "./auth/github/store";
import {
  runGithubAccountList,
  runGithubAccountRevoke,
  runGithubAccountSwitch,
  runGithubConsent,
} from "./cli/github";
import {
  configDir,
  loadIndex,
  removeAccount,
  type AccountsIndex,
} from "./auth/keychain";
// v1.37 BLOCKER 1: account-revoke reads/deletes tokens via the SecretBackend facade.
import { deleteToken, getToken } from "./auth/token-store";
import { revokeRefreshToken } from "./auth/revoke";
import { runSendCmd } from "./cli/send";
import { runAuditCmd } from "./cli/audit";
import { runLineCmd } from "./cli/line";
import { runTelegramCmd } from "./cli/telegram";
import { runDiscordCmd } from "./cli/discord";
import { runSlackCmd } from "./cli/slack";
import { runMattermostCmd } from "./cli/mattermost";
import {
  runNotionAccountList,
  runNotionAccountRevoke,
  runNotionAccountSwitch,
  runNotionConsent,
} from "./cli/notion";
import {
  runXAccountList,
  runXAccountRevoke,
  runXAccountSwitch,
  runXConsent,
} from "./cli/x";
import { runRecipientCmd } from "./cli/recipient";
import { runWhitelistCmd } from "./cli/whitelist";
import { migrateV2, MigrationError } from "./migrate";
import { runDoctor, runPosture, runStatus, tildePath } from "./status";
import { IMPLEMENTED_TOOLS, TOOL_REGISTRY } from "./tools/registry";
import { dispatchTool, isSingleAccountOAuth } from "./tools/dispatch";
import { envOperatorContext } from "./identity/operator-context";
import { retiredCliRefusal } from "./policy/retired-settings";

const EMAIL_RE = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

const USAGE = "usage: safespace <consent|account-list|account-switch|account-revoke|audit|migrate-v2|status|doctor|whitelist|recipient|send|line|telegram|discord|slack|mattermost|exec> ... (notion is an OAuth source: use `consent --provider notion`)";

export interface CliIO {
  /** stdout sink. Tests override to capture output. */
  out: (line: string) => void;
  /** stderr sink. */
  err: (line: string) => void;
}

const DEFAULT_IO: CliIO = {
  out: (line) => console.log(line),
  err: (line) => console.error(line),
};

/** Throw to surface a CLI usage error; caller decides how to render
 *  (process.exit in the top-level shim, or assert in tests). */
export class CliError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CliError";
  }
}

/** Run a tool with the same auth / sanitize / audit middleware the MCP server uses.
 *
 * Injection seam for tests — lets test suites stub the handler stack without
 * setting up Keychain + accounts.json + Google API mocks for every CLI
 * dispatch test. Production defaults to `dispatchTool` (tools/dispatch.ts), the
 * routing the MCP server uses, minus the server's tier and connector gates.
 *
 * `opts.raw` toggles the `--raw` escape hatch (skip sanitize wrap; non-LLM
 * consumers only). Auth / kill-switch / audit / 401-retry still run. */
interface RunToolOptions {
  raw?: boolean;
}
export type RunToolFn = (
  toolName: string,
  args: Record<string, unknown>,
  opts?: RunToolOptions,
) => Promise<unknown>;

// Same routing as the MCP server (tools/dispatch.ts): cross-account, non-OAuth and
// OAuth tools each reach their own choke point, so every call writes its audit row.
// `exec` deliberately bypasses the tier and connector gates the server applies.
const DEFAULT_RUN_TOOL: RunToolFn = async (toolName, args, opts) => {
  const def = TOOL_REGISTRY[toolName];
  if (!def) throw new CliError(`unknown tool: ${toolName}`);
  return dispatchTool(toolName, args, def, envOperatorContext(), { skipSanitize: opts?.raw });
};

export interface CliDeps {
  /** Override the handler stack for `exec` (test seam). */
  runTool?: RunToolFn;
}

/** Pull an optional `--provider google|github|notion|x` flag out of an arg list
 *  (default `google`), returning the provider + the remaining args. v1.70 (G3):
 *  OAuth accounts share the `consent` mental model across providers via a FLAG, not
 *  new subcommands. An unknown value fails LOUD (a typo can't silently fall back to
 *  google and consent the wrong provider). v1.113 adds `x`. */
function extractProvider(rest: string[]): {
  provider: "google" | "github" | "notion" | "x";
  rest: string[];
} {
  const out: string[] = [];
  let provider: "google" | "github" | "notion" | "x" = "google";
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === "--provider") {
      const v = rest[++i];
      if (v !== "google" && v !== "github" && v !== "notion" && v !== "x") {
        throw new CliError("--provider must be 'google', 'github', 'notion', or 'x'");
      }
      provider = v;
    } else {
      out.push(rest[i]!);
    }
  }
  return { provider, rest: out };
}

export async function runCli(
  argv: string[],
  io: CliIO = DEFAULT_IO,
  deps: CliDeps = {},
): Promise<void> {
  // Before any subcommand: a retired setting that changed which stored secrets the
  // CLI reads (SAFESPACE_OPERATOR_ID) stops every subcommand, `doctor` included.
  const retired = retiredCliRefusal();
  if (retired !== null) throw new CliError(retired);

  const [subcommand, ...rest] = argv;

  if (subcommand === "consent") {
    const { provider, rest: r } = extractProvider(rest);
    if (provider === "github") {
      const login = r[0];
      if (!login || !GITHUB_LOGIN_RE.test(login)) {
        throw new CliError("usage: safespace consent <login> --provider github\n       login must match ^[A-Za-z0-9-]{1,39}$");
      }
      await runGithubConsent(login, io);
      return;
    }
    if (provider === "notion") {
      // Notion consent takes NO positional — the workspace is discovered from the OAuth
      // response (there is no pre-known id to type/match). Single-workspace v1.
      await runNotionConsent(io);
      return;
    }
    if (provider === "x") {
      // X consent takes NO positional — the user is discovered via GET /2/users/me.
      await runXConsent(io);
      return;
    }
    const email = r[0];
    if (!email || !EMAIL_RE.test(email)) {
      throw new CliError("usage: safespace consent <email> [--re-auth]\n       email must be a valid address");
    }
    const reAuth = r.includes("--re-auth");
    await consent(email, { reAuth });
    return;
  }

  if (subcommand === "account-list") {
    const { provider } = extractProvider(rest);
    if (provider === "github") {
      await runGithubAccountList(io);
      return;
    }
    if (provider === "notion") {
      await runNotionAccountList(io);
      return;
    }
    if (provider === "x") {
      await runXAccountList(io);
      return;
    }
    await runAccountList(io);
    return;
  }

  if (subcommand === "account-switch") {
    const { provider, rest: r } = extractProvider(rest);
    if (provider === "github") {
      const login = r[0];
      if (!login || !GITHUB_LOGIN_RE.test(login)) {
        throw new CliError("usage: safespace account-switch <login> --provider github\n       login must match ^[A-Za-z0-9-]{1,39}$");
      }
      await runGithubAccountSwitch(login, io);
      return;
    }
    if (provider === "notion") {
      // v1.79 multi-workspace: a <id-or-name> positional selects which to activate.
      await runNotionAccountSwitch(r[0], io);
      return;
    }
    if (provider === "x") {
      // Multi-account: a <id-or-username> positional selects which to activate.
      await runXAccountSwitch(r[0], io);
      return;
    }
    const email = r[0];
    if (!email || !EMAIL_RE.test(email)) {
      throw new CliError("usage: safespace account-switch <email>\n       email must be a valid address");
    }
    await runAccountSwitch(email, io);
    return;
  }

  if (subcommand === "account-revoke") {
    const { provider, rest: r } = extractProvider(rest);
    if (provider === "github") {
      const login = r[0];
      if (!login || !GITHUB_LOGIN_RE.test(login)) {
        throw new CliError("usage: safespace account-revoke <login> --provider github\n       login must match ^[A-Za-z0-9-]{1,39}$");
      }
      await runGithubAccountRevoke(login, io);
      return;
    }
    if (provider === "notion") {
      // v1.79 multi-workspace: a <id-or-name> positional selects which to revoke.
      await runNotionAccountRevoke(r[0], io);
      return;
    }
    if (provider === "x") {
      // Multi-account: a <id-or-username> positional selects which to revoke.
      await runXAccountRevoke(r[0], io);
      return;
    }
    const email = r[0];
    if (!email || !EMAIL_RE.test(email)) {
      throw new CliError("usage: safespace account-revoke <email>\n       email must be a valid address");
    }
    await runAccountRevoke(email, io);
    return;
  }

  if (subcommand === "audit") {
    await runAuditCmd(rest, io);
    return;
  }

  if (subcommand === "send") {
    await runSendCmd(rest, io);
    return;
  }

  if (subcommand === "migrate-v2") {
    await runMigrateV2(rest, io);
    return;
  }

  if (subcommand === "status") {
    await runStatusCmd(rest, io);
    return;
  }

  if (subcommand === "doctor") {
    await runDoctorCmd(rest, io);
    return;
  }

  if (subcommand === "whitelist") {
    await runWhitelistCmd(rest, io);
    return;
  }

  if (subcommand === "recipient") {
    await runRecipientCmd(rest, io);
    return;
  }

  if (subcommand === "line") {
    await runLineCmd(rest, io);
    return;
  }

  if (subcommand === "telegram") {
    await runTelegramCmd(rest, io);
    return;
  }

  if (subcommand === "discord") {
    await runDiscordCmd(rest, io);
    return;
  }

  if (subcommand === "slack") {
    await runSlackCmd(rest, io);
    return;
  }

  if (subcommand === "mattermost") {
    await runMattermostCmd(rest, io);
    return;
  }

  if (subcommand === "exec") {
    await runExec(rest, io, deps.runTool ?? DEFAULT_RUN_TOOL);
    return;
  }

  if (!subcommand) throw new CliError(USAGE);
  throw new CliError(`unknown subcommand: ${subcommand}`);
}

/** `safespace exec <tool> [--account <email>] --params <json>`
 *
 * Runs an MCP tool from the CLI, sharing the full auth / sanitize / audit
 * middleware stack. Output is a single JSON line on stdout (machine-readable).
 *
 * Why a CLI mirror of the MCP layer: lets non-Claude clients (cron jobs,
 * Python scripts, shell pipelines) consume Google Workspace data through the
 * same security boundary as Claude does. Handler path is identical — no
 * second implementation, no second auth flow. */
async function runExec(rest: string[], io: CliIO, runTool: RunToolFn): Promise<void> {
  const [toolName, ...flags] = rest;
  const usage =
    "usage: safespace exec <tool> [--account <email>] [--raw] --params <json>\n" +
    `       valid tools: ${[...IMPLEMENTED_TOOLS].sort().join(", ")}`;

  if (!toolName) throw new CliError(usage);
  if (!IMPLEMENTED_TOOLS.has(toolName)) {
    throw new CliError(
      `unknown tool: ${toolName}\n` +
      `       valid tools: ${[...IMPLEMENTED_TOOLS].sort().join(", ")}`,
    );
  }

  let account: string | undefined;
  let paramsJson: string | undefined;
  let raw = false;
  for (let i = 0; i < flags.length; i++) {
    const f = flags[i];
    if (f === "--account") {
      account = flags[++i];
      if (!account || !EMAIL_RE.test(account)) {
        throw new CliError("--account must be a valid email address");
      }
    } else if (f === "--params") {
      paramsJson = flags[++i];
      if (paramsJson === undefined) {
        throw new CliError("--params requires a JSON string argument");
      }
    } else if (f === "--raw") {
      raw = true;
    } else {
      throw new CliError(`unknown flag: ${f}\n       ${usage}`);
    }
  }
  // Both "no --params" and "--params ''" must surface the same actionable
  // message (otherwise the empty-string case falls into the JSON.parse
  // catch and renders as "parse error: Unexpected end of JSON input").
  if (paramsJson === undefined || paramsJson === "") {
    throw new CliError(`--params <json> is required\n       ${usage}`);
  }

  // Prototype pollution note: V8's JSON.parse creates an own property named
  // "__proto__" rather than mutating Object.prototype, so `{...params}` is
  // safe to spread. Comment retained for security-audit traceability.
  let params: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(paramsJson);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("must be a JSON object (not array / null / primitive)");
    }
    params = parsed as Record<string, unknown>;
  } catch (e) {
    throw new CliError(
      `--params parse error: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  // Force --account flag as the sole source of account routing — passing
  // `account_id` inside --params would silently override the flag (or vice
  // versa, depending on merge order). Reject explicitly to avoid surprise.
  if ("account_id" in params) {
    throw new CliError(
      "use the --account flag, not 'account_id' inside --params\n" +
      "       e.g. safespace exec <tool> --account <email> --params '...'",
    );
  }

  // `--account` and `--raw` exist only on the single-account OAuth path; refuse them
  // elsewhere instead of silently ignoring them.
  const def = TOOL_REGISTRY[toolName]!;
  if ((account || raw) && !isSingleAccountOAuth(def)) {
    throw new CliError(
      `${account ? "--account" : "--raw"} applies only to single-account OAuth tools; ` +
        `${toolName} is ${def.cross_account ? "a cross-account tool" : "not an OAuth tool"}`,
    );
  }

  const argsForHandler: Record<string, unknown> = account
    ? { ...params, account_id: account }
    : params;

  // Loud stderr warning every time --raw is used so it can't quietly slip
  // into a script that later forwards output to an LLM. The audit log also
  // records `sanitize: "bypassed"` for post-hoc grep-ability.
  if (raw) {
    io.err(
      "warning: --raw bypasses the <untrusted-source> sanitize wrap. " +
      "Only safe when the caller is NOT an LLM. Audit: sanitize=bypassed.",
    );
  }

  const result = await runTool(toolName, argsForHandler, { raw });

  // JSON.stringify can throw on BigInt / cycles / non-stringifiable types.
  // Surface as a CliError so the failure mode is explicit (otherwise the
  // top-level shim catches the raw TypeError + exits with no stdout). For
  // the 5 current handlers this can't happen, but sanitize.walk() returns
  // `unknown` and makes no JSON-serializability guarantee for future tools.
  let serialized: string;
  try {
    serialized = JSON.stringify(result);
  } catch (e) {
    throw new CliError(
      `result serialization failed: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
  io.out(serialized);
}

async function runAccountList(io: CliIO): Promise<void> {
  const idx = await loadIndex();
  if (idx.accounts.length === 0) {
    io.out("(no accounts; run `safespace consent <email>` to add one)");
    return;
  }
  const active = await readActive();
  // Fixed-width columns formatted via a shared helper so the header and rows
  // are guaranteed to align (5.6 code-rev HIGH: padStart on a numeric column
  // created off-by-N offsets vs the static header string).
  const EMAIL_W = 40, SCOPES_W = 6, DATE_W = 20;
  const formatRow = (marker: string, email: string, scopes: string, added: string, lastUsed: string) =>
    `${marker}${email.padEnd(EMAIL_W).slice(0, EMAIL_W)} ${scopes.padEnd(SCOPES_W).slice(0, SCOPES_W)}  ${added.padEnd(DATE_W).slice(0, DATE_W)} ${lastUsed.padEnd(DATE_W).slice(0, DATE_W)}`;
  io.out(formatRow("  ", "EMAIL", "SCOPES", "ADDED", "LAST USED"));
  for (const a of idx.accounts) {
    const marker = a.email === active ? "* " : "  ";
    io.out(formatRow(
      marker,
      a.email,
      String(a.scopes.length),
      (a.added_at || "").slice(0, 19),
      a.last_used_at ?? "-",
    ));
  }
  if (active) {
    // Resolve the actual path the CLI reads from — under plugin installs this
    // is `${CLAUDE_PLUGIN_DATA}/safespace/active-account`, not the legacy
    // `~/.config/safespace/active-account` that earlier builds hardcoded.
    io.out(`\n* = active account (from ${tildePath(path.join(configDir(), "active-account"))})`);
  }
}

/** Throws CliError if email is absent from accounts.json. Shared by
 *  account-switch and account-revoke (5.7 code-rev LOW). */
function assertEmailInIndex(email: string, idx: AccountsIndex): void {
  if (!idx.accounts.some((a) => a.email === email)) {
    throw new CliError(
      `account not found: ${email}\n       run \`safespace account-list\` to see registered accounts`,
    );
  }
}

async function runAccountSwitch(email: string, io: CliIO): Promise<void> {
  const idx = await loadIndex();
  assertEmailInIndex(email, idx);
  await writeActive(email);
  io.out(`active account set to ${email}`);
}

/** Parse a Keychain token JSON blob and pull out the refresh_token, emitting
 *  exactly one stderr warning per failure mode (5.7 sec-rev HIGH / code-rev MED:
 *  the previous if/catch/else-if structure could emit two warnings on the
 *  corrupt-JSON path). Returns the token string on success, null otherwise. */
function extractRefreshToken(
  tokenJson: string | null,
  email: string,
  io: CliIO,
): string | null {
  if (!tokenJson) {
    io.err(`warning: no Keychain entry for ${email}; skipping remote revoke`);
    return null;
  }
  let parsed: { refresh_token?: unknown };
  try {
    parsed = JSON.parse(tokenJson) as { refresh_token?: unknown };
  } catch {
    io.err(`warning: Keychain entry for ${email} could not be parsed; skipping remote revoke`);
    return null;
  }
  if (typeof parsed.refresh_token !== "string" || !parsed.refresh_token) {
    io.err(`warning: no refresh_token in Keychain for ${email}; skipping remote revoke`);
    return null;
  }
  return parsed.refresh_token;
}

/** `safespace account-revoke <email>` — revoke refresh_token at Google,
 *  then wipe local state (Keychain entry, accounts.json row, active-account
 *  file if it pointed here).
 *
 *  Order is deliberate, two-stage:
 *    Stage 1 (remote): revoke FIRST at Google. A delete-first failure would
 *      leave a valid refresh_token in Google's grants list with no way to
 *      revoke it from this CLI. If the revoke fails, we bail and leave local
 *      state untouched so the user can retry. (Once-revoke-then-crash-before-
 *      cleanup is self-healing: refresh.ts handles `invalid_grant` from the
 *      rotated token by deleting local state.)
 *    Stage 2 (local): removeAccount BEFORE deleteToken. accounts.json is the
 *      destination of truth for what tools can see; dropping its row first
 *      means a failure between the two leaves an orphan Keychain entry that
 *      no tool call can reach (no row → account_not_found) instead of an
 *      orphan accounts.json row pointing at a missing token. Re-running
 *      account-revoke cleans the orphan. (#21)
 *
 *  Idempotent edges (warn-only, cleanup still proceeds):
 *   - Keychain has no entry — nothing to revoke, just drop the index row.
 *   - Keychain JSON corrupt — same; user already lost the token anyway.
 *   - Valid JSON but no refresh_token field — same.
 *   - Google replies 400 invalid_token — handled by revoke.ts as success.
 *
 *  Errors that DO bail (no local cleanup):
 *   - Keychain locked: getToken throws MCPError("keychain_locked"). We
 *     deliberately do not wrap it — bailing lets the user unlock and retry
 *     so the remote revoke runs. Local state stays consistent with remote.
 *   - Revoke endpoint network failure / non-idempotent 4xx-5xx. */
async function runAccountRevoke(email: string, io: CliIO): Promise<void> {
  const idx = await loadIndex();
  assertEmailInIndex(email, idx);

  // getToken may throw MCPError("keychain_locked") — intentionally not caught
  // here so cleanup is skipped and the user can unlock Keychain + retry.
  const tokenJson = await getToken(email);
  const refreshToken = extractRefreshToken(tokenJson, email, io);
  if (refreshToken) {
    await revokeRefreshToken(refreshToken);
  }

  // Order: remove from index FIRST, then drop the Keychain entry.
  // Reverse order would leave an orphan index entry if Keychain delete
  // succeeded but removeAccount threw (e.g. ENOSPC during atomic write
  // of accounts.json) — confusing operator state.
  // deleteToken is idempotent and already swallows errors (keychain.ts
  // catches), so its failure after a successful removeAccount is
  // harmless: the Keychain entry becomes orphan but unreachable. No row
  // in accounts.json → withToolContext returns account_not_found → no
  // tool call ever loads the orphan token. The token is also already
  // revoked at Google (Stage 1 succeeded), so it's a dead credential
  // server-side. To clean up the dead Keychain entry: re-run
  // `safespace consent <email>` (overwrites with a fresh entry) or
  // delete manually via Keychain Access.app. NOTE: re-running
  // `safespace account-revoke <email>` will NOT clean it — the
  // assertEmailInIndex check rejects because the row is already gone. (#21)
  await removeAccount(email);
  await deleteToken(email);

  const active = await readActive();
  if (active === email) {
    await clearActive();
    io.out(`revoked: ${email} (was active; active account cleared)`);
  } else {
    io.out(`revoked: ${email}`);
  }
}

async function runMigrateV2(rest: string[], io: CliIO): Promise<void> {
  const dryRun = rest.includes("--dry-run");
  const forceSaltMismatch = rest.includes("--force-salt-mismatch");
  // Reject unknown flags so typos like --dryrun don't silently no-op into a
  // real migration. The user must type one of the documented flags or none.
  const KNOWN = new Set(["--dry-run", "--force-salt-mismatch"]);
  for (const arg of rest) {
    if (!KNOWN.has(arg)) {
      throw new CliError(
        `unknown flag: ${arg}\n       usage: safespace migrate-v2 [--dry-run] [--force-salt-mismatch]`,
      );
    }
  }
  try {
    const report = await migrateV2({ dryRun, forceSaltMismatch });
    io.out(`sources: read=${report.sources.read} send=${report.sources.send}`);
    io.out(`accounts merged: ${report.accountsMerged}`);
    io.out(`audit lines: ${report.auditLinesMerged}`);
    if (report.saltMismatch) {
      io.out(`salt mismatch: yes (forensic comparison broken across sources)`);
    }
    for (const w of report.warnings) io.err(`warning: ${w}`);
    // Sec-rev v2.0 PR-3 (unrequested finding): replace $HOME prefix with `~/`
    // so the path doesn't leak the OS username if the user pastes this output
    // somewhere shared (CI log, bug report, Slack).
    const targetDisplay = tildePath(report.target);
    if (report.dryRun) {
      io.out(`dry-run complete; target: ${targetDisplay}`);
    } else {
      io.out(`migration complete; new config dir: ${targetDisplay}`);
      io.out(`legacy sources renamed to *.migrated/ (manual cleanup OK once you've verified the new dir works)`);
    }
  } catch (e) {
    if (e instanceof MigrationError) throw new CliError(e.message);
    throw e;
  }
}

async function runStatusCmd(rest: string[], io: CliIO): Promise<void> {
  const KNOWN = new Set(["--json"]);
  for (const arg of rest) {
    if (!KNOWN.has(arg)) {
      throw new CliError(`unknown flag: ${arg}\n       usage: safespace status [--json]`);
    }
  }
  await runStatus({ json: rest.includes("--json") }, io);
}

async function runDoctorCmd(rest: string[], io: CliIO): Promise<void> {
  const KNOWN = new Set(["--deep", "--json", "--posture"]);
  for (const arg of rest) {
    if (!KNOWN.has(arg)) {
      throw new CliError(
        `unknown flag: ${arg}\n       usage: safespace doctor [--deep] [--json] [--posture]\n` +
          `       --deep:    also pings macOS Keychain per registered account (~50ms each).\n` +
          `       --posture: report the hardening posture (hardening settings, connectors, egress allowlists).`,
      );
    }
  }
  const json = rest.includes("--json");
  // --posture is its own focused report (the hardening posture), not the full
  // diagnostic; --deep is irrelevant to it (no Keychain ping).
  const report = rest.includes("--posture")
    ? await runPosture({ json }, io)
    : await runDoctor({ deep: rest.includes("--deep"), json }, io);
  // Non-zero exit on fail so cron/CI consumers can `&& ...` after `safespace doctor`.
  if (report.status === "fail") {
    process.exitCode = 1;
  }
}

/* ───────── top-level shim ───────── */
// `import.meta.main` distinguishes the entrypoint from imports, so tests
// can import this module without triggering the dispatch.
if (import.meta.main) {
  try {
    await runCli(process.argv.slice(2));
  } catch (e) {
    // Both CliError (usage) and other thrown errors (MCPError from auth,
    // unexpected I/O, etc) render as a one-line message — never a raw
    // stack trace, even for unexpected types. Stack would leak filesystem
    // paths and internal structure to terminal scrollback. (sec-rev 5.6 LOW)
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`error: ${msg}`);
    // exitCode, not exit(): the choke points write their final audit row without
    // awaiting it, and exit() would kill that write. The success path already ends
    // by letting the event loop drain.
    process.exitCode = 1;
  }
}
