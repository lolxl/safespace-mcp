// v2.0 PR-2b-2: one-shot migration from the v1.x two-profile layout
// (`safespace-read/` + `safespace-send/` under ${CLAUDE_PLUGIN_DATA}) into the
// v2.0 single-profile `safespace/` dir. Invoked via `safespace migrate-v2`.
//
// SECURITY ASSUMPTIONS (sec-rev, 2026-05-17):
//   - .env files may contain GOOGLE_CLIENT_SECRET. NEVER include file paths
//     or content in error messages — only sentinel codes (C1).
//   - All file writes use {mode: 0o600}, all mkdir uses {mode: 0o700} (C2).
//   - --rollback is intentionally NOT shipped (C3): post-migration use of
//     safespace/ may mutate last_used_at; a "clean undo" is illusory.
//     Users wanting to revert can manually `mv safespace-{read,send}.migrated/`.
//   - audit.jsonl files are NOT sorted by ts (H1): timestamp sort lets a
//     crafted future/past entry sort into the wrong place. Each source's
//     append order is preserved; a `migration_boundary` JSON record
//     separates the two source streams.
//   - Refuses if any source audit.jsonl was modified within 60s (H2 —
//     proxy may still hold an open fd; renaming would silently lose writes).
//   - Refuses on SAFESPACE audit-salt mismatch unless --force-salt-mismatch (H4):
//     historical email_hash values across the two profiles aren't comparable.

import * as fs from "node:fs/promises";
import * as path from "node:path";
import { countRows } from "./audit/cli-chain";
import type { AccountEntry, AccountsIndex } from "./auth/keychain";
import {
  deriveTierFromLegacyEnv,
  rewriteEnvWithDerivedTier,
  type TierDerivation,
} from "./tier";

export class MigrationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MigrationError";
  }
}

export interface MigrationOptions {
  dryRun?: boolean;
  forceSaltMismatch?: boolean;
  /** Override the parent dir for testing. Defaults to ${CLAUDE_PLUGIN_DATA}. */
  parentDir?: string;
}

export interface MigrationReport {
  dryRun: boolean;
  sources: { read: boolean; send: boolean };
  target: string;
  accountsMerged: number;
  auditLinesMerged: number;
  saltMismatch: boolean;
  applied: boolean;
  warnings: string[];
  /**
   * Set when migrate-v2 auto-derived a SAFESPACE_TIER from v1.x legacy
   * `SAFESPACE_ENABLE_*` flags found in the migrated .env. Null when no
   * derivation applied (no legacy flags, OR an explicit SAFESPACE_TIER
   * was already present, OR no .env existed in either source).
   *
   * Populated in both dry-run and real runs so the user can preview.
   */
  tierDerived: TierDerivation | null;
}

// ----- constants -----

const LOCK_TTL_MS = 30 * 60 * 1000; // M3: migration can take minutes on large audit files
const RECENT_WRITE_MS = 60 * 1000;  // H2: source audit.jsonl mtime threshold
const STAGING_DIR = "safespace.tmp";
const TARGET_DIR = "safespace";
const READ_DIR = "safespace-read";
const SEND_DIR = "safespace-send";
const LOCK_FILE = ".migrate-v2.lock";
const SALT_FILE = "audit-salt";
const ENV_FILE = ".env";
const ACCOUNTS_FILE = "accounts.json";
const AUDIT_FILE = "audit.jsonl";
const ACTIVE_FILE = "active-account";
const SALT_MISMATCH_MARKER = "salt-mismatch.warning";

function parentDirOf(opts: MigrationOptions): string {
  if (opts.parentDir) return opts.parentDir;
  const dataDir = process.env.CLAUDE_PLUGIN_DATA;
  if (dataDir) return dataDir;
  throw new MigrationError(
    "CLAUDE_PLUGIN_DATA is not set; safespace migrate-v2 only supports plugin installs",
  );
}

// ----- main entry -----

export async function migrateV2(opts: MigrationOptions = {}): Promise<MigrationReport> {
  const dataDir = parentDirOf(opts);
  const lockPath = path.join(dataDir, LOCK_FILE);
  const targetPath = path.join(dataDir, TARGET_DIR);
  const stagingPath = path.join(dataDir, STAGING_DIR);
  const readPath = path.join(dataDir, READ_DIR);
  const sendPath = path.join(dataDir, SEND_DIR);

  const release = await acquireMigrationLock(lockPath);
  try {
    // H3 (inside lock — self-review H-NEW-1, 2026-05-17): unconditionally
    // remove any stranded staging dir. It may contain a plaintext .env from
    // a prior killed run. Must run AFTER lock acquisition: while another
    // process holds the lock, its staging dir is owned (not stranded), and
    // we must not blow it away.
    await fs.rm(stagingPath, { recursive: true, force: true });

    // M4: existence pre-flight BEFORE reading accounts, so we never trigger
    // ensureConfigDir() side-effects on missing source dirs.
    const sources = {
      read: await pathExists(readPath),
      send: await pathExists(sendPath),
    };
    if (!sources.read && !sources.send) {
      throw new MigrationError(
        `no legacy source dirs found at ${readPath} or ${sendPath}; nothing to migrate`,
      );
    }

    // Pre-flight: target must not already contain migrated data.
    const targetAccountsPath = path.join(targetPath, ACCOUNTS_FILE);
    if (await pathExists(targetAccountsPath)) {
      const targetIndex = await readAccountsAt(targetAccountsPath);
      if (targetIndex && targetIndex.accounts.length > 0) {
        throw new MigrationError(
          `${targetPath} already contains migrated data (${targetIndex.accounts.length} account(s)); refusing to overwrite`,
        );
      }
    }

    // H2: proxy-running detection via audit.jsonl mtime. A live proxy holding
    // an open fd on the source audit file would lose any in-flight writes when
    // we rename the source dir; force the user to stop the server first.
    for (const [name, srcExists, srcPath] of [
      ["safespace-read", sources.read, readPath],
      ["safespace-send", sources.send, sendPath],
    ] as const) {
      if (!srcExists) continue;
      const auditPath = path.join(srcPath, AUDIT_FILE);
      if (!(await pathExists(auditPath))) continue;
      const stat = await fs.stat(auditPath);
      const ageMs = Date.now() - stat.mtimeMs;
      if (ageMs < RECENT_WRITE_MS) {
        throw new MigrationError(
          `${name}/audit.jsonl was modified ${Math.round(ageMs / 1000)}s ago; stop the safespace MCP server before running migrate-v2`,
        );
      }
    }

    // Read accounts directly (bypass loadIndex to avoid ensureConfigDir side
    // effect on source paths — M4).
    const accountsByEmail = new Map<string, AccountEntry>();
    for (const [exists, srcPath] of [
      [sources.read, readPath],
      [sources.send, sendPath],
    ] as const) {
      if (!exists) continue;
      const indexPath = path.join(srcPath, ACCOUNTS_FILE);
      const idx = await readAccountsAt(indexPath);
      if (!idx) continue;
      for (const entry of idx.accounts) {
        const existing = accountsByEmail.get(entry.email);
        accountsByEmail.set(
          entry.email,
          existing ? mergeAccountEntries(existing, entry) : entry,
        );
      }
    }

    // H4: salt mismatch is forensically destructive. Default = refuse.
    const saltMismatch = await checkSaltMismatch(readPath, sendPath, sources);
    if (saltMismatch && !opts.forceSaltMismatch) {
      throw new MigrationError(
        "SAFESPACE audit salts differ between safespace-read/ and safespace-send/. " +
          "Historical email_hash values from the two profiles are not comparable across the boundary. " +
          "Re-run with --force-salt-mismatch to proceed (a salt-mismatch.warning marker will be written).",
      );
    }

    // Count audit lines for the report (cheap second pass — we re-stream
    // during write to avoid holding both files in memory at once).
    let auditLinesMerged = 0;
    for (const [exists, srcPath] of [
      [sources.read, readPath],
      [sources.send, sendPath],
    ] as const) {
      if (!exists) continue;
      const auditPath = path.join(srcPath, AUDIT_FILE);
      if (await pathExists(auditPath)) {
        auditLinesMerged += await countLines(auditPath);
      }
    }

    const warnings: string[] = [];
    if (saltMismatch) {
      warnings.push(
        "salt-mismatch: historical email_hash values are not comparable across migration boundary",
      );
    }

    // Tier derivation peek: read the .env we'd carry across (send preferred,
    // read fallback) and check whether v1.x legacy flags need to become a
    // SAFESPACE_TIER= line. Computed up-front so dry-run reports it too.
    // C1: previewEnvTierDerivation never echoes content on failure.
    const tierDerived = await previewEnvTierDerivation(readPath, sendPath, sources);
    if (tierDerived) {
      // Warning surfaces flag NAMES only (per TierDerivation contract);
      // no .env value content reaches this string.
      warnings.push(
        `auto-derived SAFESPACE_TIER=${tierDerived.derivedTier} from legacy ` +
          `${tierDerived.legacyFlagsFound.join(", ")} (commented out in migrated .env)`,
      );
    }

    const report: MigrationReport = {
      dryRun: !!opts.dryRun,
      sources,
      target: targetPath,
      accountsMerged: accountsByEmail.size,
      auditLinesMerged,
      saltMismatch,
      applied: false,
      warnings,
      tierDerived,
    };

    if (opts.dryRun) return report;

    // Real run — staging write (all C1/C2 mitigations inside).
    await writeStagingDir(stagingPath, {
      accounts: Array.from(accountsByEmail.values()),
      readPath,
      sendPath,
      sources,
      saltMismatch,
      tierDerived,
    });

    // Atomic rename (L2: catch EXDEV cross-fs case).
    try {
      await fs.rename(stagingPath, targetPath);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      await fs.rm(stagingPath, { recursive: true, force: true }).catch(() => undefined);
      if (code === "EXDEV") {
        throw new MigrationError(
          `${targetPath} is on a different filesystem from ${stagingPath}; the parent dir must be a single mount`,
        );
      }
      throw new MigrationError(`atomic rename failed (code: ${code ?? "unknown"})`);
    }

    // Mark sources as .migrated/ (recoverable manually if user changes mind).
    for (const [name, exists, src] of [
      ["safespace-read", sources.read, readPath],
      ["safespace-send", sources.send, sendPath],
    ] as const) {
      if (!exists) continue;
      const dst = `${src}.migrated`;
      try {
        await fs.rename(src, dst);
      } catch (e) {
        const code = (e as NodeJS.ErrnoException).code ?? "unknown";
        warnings.push(
          `${name}/ could not be renamed to ${name}.migrated/ (code: ${code}); rename manually to avoid confusion on next migrate-v2 run`,
        );
      }
    }

    report.applied = true;
    report.warnings = warnings;
    return report;
  } finally {
    await release();
  }
}

// ----- helpers -----

async function pathExists(p: string): Promise<boolean> {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

/** Rows of an audit file as the audit readers count them (`countRows`); 0 when unreadable. */
async function countLines(p: string): Promise<number> {
  try {
    return await countRows(p);
  } catch {
    return 0;
  }
}

/** Direct accounts.json reader that does NOT call ensureConfigDir (M4).
 *  Accepts both v1 and v2 schemas (the v1 reader guard from PR-2b-1 #57). */
async function readAccountsAt(p: string): Promise<AccountsIndex | null> {
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
      return parsed as AccountsIndex;
    }
    return null;
  } catch {
    return null;
  }
}

function mergeAccountEntries(a: AccountEntry, b: AccountEntry): AccountEntry {
  // Same email (caller invariant). Union of scopes (sorted for determinism),
  // earliest added_at, latest last_used_at.
  const scopes = Array.from(new Set([...a.scopes, ...b.scopes])).sort();
  const addedAt = a.added_at < b.added_at ? a.added_at : b.added_at;
  let lastUsed: string | null;
  if (a.last_used_at === null) lastUsed = b.last_used_at;
  else if (b.last_used_at === null) lastUsed = a.last_used_at;
  else lastUsed = a.last_used_at > b.last_used_at ? a.last_used_at : b.last_used_at;
  return { email: a.email, scopes, added_at: addedAt, last_used_at: lastUsed };
}

async function checkSaltMismatch(
  readPath: string,
  sendPath: string,
  sources: { read: boolean; send: boolean },
): Promise<boolean> {
  if (!sources.read || !sources.send) return false;
  const readSalt = await readBufferOrNull(path.join(readPath, SALT_FILE));
  const sendSalt = await readBufferOrNull(path.join(sendPath, SALT_FILE));
  if (!readSalt || !sendSalt) return false;
  return !readSalt.equals(sendSalt);
}

async function readBufferOrNull(p: string): Promise<Buffer | null> {
  try {
    return await fs.readFile(p);
  } catch {
    return null;
  }
}

interface StagingOpts {
  accounts: AccountEntry[];
  readPath: string;
  sendPath: string;
  sources: { read: boolean; send: boolean };
  saltMismatch: boolean;
  /** Pre-computed by migrateV2; threaded into copyEnvSafely to avoid re-reading .env. */
  tierDerived: TierDerivation | null;
}

async function writeStagingDir(stagingPath: string, opts: StagingOpts): Promise<void> {
  try {
    // C2: 0o700 dir, 0o600 files everywhere.
    await fs.mkdir(stagingPath, { recursive: true, mode: 0o700 });

    const index: AccountsIndex = { version: 2, accounts: opts.accounts };
    await fs.writeFile(
      path.join(stagingPath, ACCOUNTS_FILE),
      JSON.stringify(index, null, 2),
      { mode: 0o600 },
    );

    await writeMergedAudit(stagingPath, opts);
    await copyEnvSafely(stagingPath, opts);
    await copySaltSafely(stagingPath, opts);
    await copyActiveAccountSafely(stagingPath, opts);

    if (opts.saltMismatch) {
      const body =
        `# safespace audit salt mismatch\n` +
        `# generated by safespace migrate-v2 on ${new Date().toISOString()}\n` +
        `# safespace-read/audit-salt and safespace-send/audit-salt differed.\n` +
        `# Historical target_email_hash values are not comparable across the migration boundary.\n` +
        `# Forensic queries that depend on hash equality across sources will produce false negatives.\n`;
      await fs.writeFile(path.join(stagingPath, SALT_MISMATCH_MARKER), body, { mode: 0o600 });
    }
  } catch (e) {
    // M2: any failure inside staging -> cleanup + sanitized error. Never
    // include path or content in the message (.env may have been partially
    // written; the path itself is fine in dir-failure cases but we strip
    // uniformly for consistency).
    await fs.rm(stagingPath, { recursive: true, force: true }).catch(() => undefined);
    if (e instanceof MigrationError) throw e;
    const code = (e as NodeJS.ErrnoException).code ?? "unknown";
    throw new MigrationError(`staging write failed (code: ${code})`);
  }
}

async function writeMergedAudit(stagingPath: string, opts: StagingOpts): Promise<void> {
  const targetAuditPath = path.join(stagingPath, AUDIT_FILE);
  // H1: preserve per-source append order; no sort. Boundary lines mark
  // provenance explicitly.
  const fh = await fs.open(targetAuditPath, "w", 0o600);
  try {
    for (const [name, exists, srcPath] of [
      ["safespace-read", opts.sources.read, opts.readPath],
      ["safespace-send", opts.sources.send, opts.sendPath],
    ] as const) {
      if (!exists) continue;
      const auditPath = path.join(srcPath, AUDIT_FILE);
      if (!(await pathExists(auditPath))) continue;
      const boundary =
        JSON.stringify({
          event: "migration_boundary",
          source: name,
          migrated_at: new Date().toISOString(),
          note: `audit lines below this point came from ${name}/audit.jsonl`,
        }) + "\n";
      await fh.write(boundary);
      const content = await fs.readFile(auditPath, "utf8");
      if (content.length > 0) {
        await fh.write(content.endsWith("\n") ? content : content + "\n");
      }
    }
  } finally {
    await fh.close();
  }
}

async function copyEnvSafely(stagingPath: string, opts: StagingOpts): Promise<void> {
  // Prefer send (drive-full scope = primary). C1: never include path or
  // content in error messages.
  let src: string | null = null;
  if (opts.sources.send) {
    const p = path.join(opts.sendPath, ENV_FILE);
    if (await pathExists(p)) src = p;
  }
  if (!src && opts.sources.read) {
    const p = path.join(opts.readPath, ENV_FILE);
    if (await pathExists(p)) src = p;
  }
  if (!src) return;
  let content: string | null = null;
  try {
    content = await fs.readFile(src, "utf8");
    // If migrateV2 detected v1.x legacy flags, transform the content: comment
    // them out + append SAFESPACE_TIER=<derived>. Otherwise verbatim copy.
    // The rewrite is a pure string transform — no secret-content leakage.
    const finalContent = opts.tierDerived
      ? rewriteEnvWithDerivedTier(content, opts.tierDerived.derivedTier)
      : content;
    await fs.writeFile(path.join(stagingPath, ENV_FILE), finalContent, { mode: 0o600 });
  } catch {
    throw new MigrationError("failed to copy .env into staging directory");
  } finally {
    content = null; // narrow the in-memory window for plaintext secret
  }
}

async function previewEnvTierDerivation(
  readPath: string,
  sendPath: string,
  sources: { read: boolean; send: boolean },
): Promise<TierDerivation | null> {
  // Same source-preference order as copyEnvSafely so the preview matches
  // what actually lands on disk. C1: on read failure, return null silently
  // — the real-run copyEnvSafely will surface a sanitized MigrationError.
  let src: string | null = null;
  if (sources.send) {
    const p = path.join(sendPath, ENV_FILE);
    if (await pathExists(p)) src = p;
  }
  if (!src && sources.read) {
    const p = path.join(readPath, ENV_FILE);
    if (await pathExists(p)) src = p;
  }
  if (!src) return null;
  let content: string | null = null;
  try {
    content = await fs.readFile(src, "utf8");
    return deriveTierFromLegacyEnv(content);
  } catch {
    return null;
  } finally {
    content = null;
  }
}

async function copySaltSafely(stagingPath: string, opts: StagingOpts): Promise<void> {
  let src: string | null = null;
  if (opts.sources.send) {
    const p = path.join(opts.sendPath, SALT_FILE);
    if (await pathExists(p)) src = p;
  }
  if (!src && opts.sources.read) {
    const p = path.join(opts.readPath, SALT_FILE);
    if (await pathExists(p)) src = p;
  }
  if (!src) return;
  try {
    const buf = await fs.readFile(src);
    await fs.writeFile(path.join(stagingPath, SALT_FILE), buf, { mode: 0o600 });
  } catch {
    throw new MigrationError("failed to copy audit-salt into staging directory");
  }
}

/** Self-review H-NEW-2 (2026-05-17): preserve the user's `safespace
 *  account-switch` selection across migration. Without this, post-migration
 *  the new safespace/ dir has no active-account file and the user must
 *  re-run account-switch. Prefer send (same primary-profile reasoning as .env). */
async function copyActiveAccountSafely(stagingPath: string, opts: StagingOpts): Promise<void> {
  let src: string | null = null;
  if (opts.sources.send) {
    const p = path.join(opts.sendPath, ACTIVE_FILE);
    if (await pathExists(p)) src = p;
  }
  if (!src && opts.sources.read) {
    const p = path.join(opts.readPath, ACTIVE_FILE);
    if (await pathExists(p)) src = p;
  }
  if (!src) return;
  try {
    const content = await fs.readFile(src, "utf8");
    await fs.writeFile(path.join(stagingPath, ACTIVE_FILE), content, { mode: 0o600 });
  } catch {
    throw new MigrationError("failed to copy active-account into staging directory");
  }
}

// ----- lock (mirrors consent.ts acquireConsentLock, with longer TTL) -----

async function acquireMigrationLock(lockPath: string): Promise<() => Promise<void>> {
  await fs.mkdir(path.dirname(lockPath), { recursive: true, mode: 0o700 });
  let fh: fs.FileHandle;
  try {
    fh = await fs.open(lockPath, "wx", 0o600);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    if (!(await isStaleMigrationLock(lockPath))) {
      throw new MigrationError(
        `migration already in progress; if no other process is running, delete ${lockPath}`,
      );
    }
    await fs.unlink(lockPath).catch(() => undefined);
    try {
      fh = await fs.open(lockPath, "wx", 0o600);
    } catch (e2) {
      if ((e2 as NodeJS.ErrnoException).code === "EEXIST") {
        throw new MigrationError("another process claimed the migration lock; retry shortly");
      }
      throw e2;
    }
  }
  try {
    await fh.write(`${process.pid}\n`);
  } catch (e) {
    await fh.close().catch(() => undefined);
    await fs.unlink(lockPath).catch(() => undefined);
    throw e;
  }
  return async () => {
    await fh.close().catch(() => undefined);
    await fs.unlink(lockPath).catch(() => undefined);
  };
}

async function isStaleMigrationLock(lockPath: string): Promise<boolean> {
  try {
    const stat = await fs.stat(lockPath);
    if (Date.now() - stat.mtimeMs < LOCK_TTL_MS) return false;
    const content = await fs.readFile(lockPath, "utf8").catch(() => "");
    const pid = parseInt(content.trim(), 10);
    if (!Number.isFinite(pid) || pid <= 0) return true;
    try {
      process.kill(pid, 0);
      return false;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "EPERM") return false;
      return true;
    }
  } catch {
    return false;
  }
}
