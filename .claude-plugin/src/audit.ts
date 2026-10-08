// Audit JSONL writer — minimal append-only logger to
// ~/.config/safespace/audit.jsonl. Step 5.8 stub; Step 6 will add a CLI
// reader (`safespace audit`) and rotation.
//
// SECURITY: NEVER record tokens, raw args, or response content — only
// metadata (tool name, account email, args sha256 hash, status,
// duration_ms). The audit log answers "did SafeSpace send this tool
// call?" — not "what was in the message." A leaked audit file should
// not leak secrets or user content.
//
// `account` is plaintext email by design (sec-rev 5.8 LOW): the audit's
// primary value is "which account sent this call" for per-account
// debugging when Step 5.9 `gmail_send` misfires. Hashing the email
// would destroy that value. Single-user self-use scope; 0o600 + 0o700
// dir is the protection. Revisit before open-sourcing.
//
// Failure mode: audit writes are best-effort. An I/O error during
// append MUST NOT crash the tool call (the user already got their
// result); we log to stderr and continue. Audit is observability,
// not correctness.

import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { configDir } from "./auth/keychain";
import { AUDIT_HMAC_ALG } from "./crypto-algorithms";
import { auditCliPath, cliChainGenesis, endsMidLine, resumeServerChain, resumeTip, walkStrictChain } from "./audit/cli-chain";
// The per-channel forensic metadata registry was extracted to ./audit/meta-channels
// (a PURE leaf) to break the reader -> writer import edge — the read-side CLI
// consumers now import the registry without pulling this chain writer onto their
// path. auditEnd consumes AUDIT_META_CHANNELS (the serialize dispatch) + the channel
// meta types (AuditEndContext fields). `export *` below re-exports every meta symbol
// so external `from "../audit"` imports stay unchanged (audit.ts is the barrel).
import {
  AUDIT_META_CHANNELS,
  type CommentPostAuditMeta,
  type CalendarMutationAuditMeta,
  type DocsModifyAuditMeta,
  type CommentDeleteAuditMeta,
  type TasksMutationAuditMeta,
  type SheetsMutationAuditMeta,
  type PlaylistMutationAuditMeta,
  type VideoMutationAuditMeta,
} from "./audit/meta-channels";
export * from "./audit/meta-channels";
// The bare forensic/policy appenders live in ./audit/events (a sibling leaf). They
// call appendChainedRow (exported below) — a RUNTIME-SAFE cycle:
// those are hoisted function declarations used only inside the appender bodies
// (see audit/events.ts). Re-exported so external `from "../audit"` imports of the
// appenders stay unchanged (audit.ts is the barrel).
export * from "./audit/events";

const AUDIT_FILE = "audit.jsonl";
const AUDIT_SALT_FILE = "audit-salt";

// v1.58 F5 — per-PROCESS run id, generated once at module load and stamped on
// every audit row (the session grouping key for `safespace audit sessions`). A
// restart = a new run by definition (the token cache, F1 burst counters, the
// v1.56 tainted set all reset on restart — run_id shares that boundary). 16 hex
// (64 bits), same shape as the sanitize nonce. Carries NO PII / no secret — a
// random id; it identifies the run, not who-did-what (the row already shows that).
const RUN_ID = crypto.randomBytes(8).toString("hex");

/** The current process's audit run id (stamped on every row as `run_id`).
 *  Exposed so tests can assert auditEnd stamped it. */
export function getRunId(): string {
  return RUN_ID;
}

function auditPath(): string {
  return path.join(configDir(), AUDIT_FILE);
}

function auditSaltPath(): string {
  return path.join(configDir(), AUDIT_SALT_FILE);
}

/** The strict-chain commitment for audit.jsonl, kept beside the salt (outside the log):
 *  `{"strict":"v2"}` or `{"strict":"v1","marker_mac":…}`. Written ONCE (exclusive create)
 *  by the server, once the chain it commits to is on disk; never overwritten. `audit
 *  verify` holds the log to it, so stripping every row's MAC (which would otherwise read
 *  as a pre-chain prefix) or cutting the log back past the marker is a break.
 *  docs/AUDIT-CHAIN.md. */
export type StrictCommitment = {
  strict: "v1" | "v2";
  /** The MAC of the chain's marker row, which `verify` requires to be in the log. */
  marker_mac: string;
  /** The marker row and its predecessor, so a marker whose append failed can be
   *  re-appended exactly (same content, same MAC). */
  prev_mac?: string;
  marker_row?: Record<string, unknown>;
  /** How many JSON rows followed `prev_mac` in the log when the row was committed (an
   *  older log may end in unchained rows): the row is re-appended only while that is
   *  still the case. */
  rows_after_prev?: number;
};
const AUDIT_CHAIN_COMMITMENT_FILE = "audit-chain.json";

export function auditChainCommitmentPath(): string {
  return path.join(configDir(), AUDIT_CHAIN_COMMITMENT_FILE);
}

/** True when the committed row's landing has been recorded (`audit verify` warns when a
 *  commitment exists without it). */
export async function strictCommitmentLanded(): Promise<boolean> {
  return landedExists();
}

/** Created (once) after the committed row is on disk. Until it exists a restart may
 *  re-append the committed row (its append may have failed); once it exists it never does,
 *  so a log emptied or cut back later cannot get its first row back and pass verify. */
function auditChainLandedPath(): string {
  return `${auditChainCommitmentPath()}.landed`;
}

/** The commitment, null when there is none, or "invalid" when the file exists but is not
 *  one (verify treats that as a break; the writer leaves it alone). */
export async function readStrictCommitment(): Promise<StrictCommitment | null | "invalid"> {
  let text: string;
  try {
    text = await fs.readFile(auditChainCommitmentPath(), "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
    return "invalid"; // unreadable: the writer treats it as committed, verify reports it
  }
  try {
    const v = JSON.parse(text) as Record<string, unknown>;
    if (v && (v.strict === "v1" || v.strict === "v2") && typeof v.marker_mac === "string") {
      const c: StrictCommitment = { strict: v.strict, marker_mac: v.marker_mac };
      if (typeof v.prev_mac === "string") c.prev_mac = v.prev_mac;
      if (v.marker_row && typeof v.marker_row === "object" && !Array.isArray(v.marker_row)) {
        c.marker_row = v.marker_row as Record<string, unknown>;
      }
      if (typeof v.rows_after_prev === "number") c.rows_after_prev = v.rows_after_prev;
      return c;
    }
  } catch {
    // fall through
  }
  return "invalid";
}

async function writeStrictCommitmentOnce(c: StrictCommitment): Promise<void> {
  if (!(await publishOnce(auditChainCommitmentPath(), JSON.stringify(c) + "\n"))) {
    // Another commitment is already there (a concurrent writer, or an earlier attempt):
    // abandon this write; the next one re-reads the file and follows that commitment.
    throw new Error("a strict commitment already exists; resuming from it on the next write");
  }
}

/** fsync a file; errors propagate (a row that may not be durable must not be recorded as
 *  landed). */
async function syncFile(p: string): Promise<void> {
  const fh = await fs.open(p, "r");
  try {
    await fh.sync();
  } finally {
    await fh.close();
  }
}

/** fsync a directory, best-effort (not every platform can sync a directory). */
async function syncDir(p: string): Promise<void> {
  let fh: fs.FileHandle | null = null;
  try {
    fh = await fs.open(p, "r");
    await fh.sync();
  } catch {
    // best-effort
  } finally {
    await fh?.close().catch(() => {});
  }
}

async function landedExists(): Promise<boolean> {
  try {
    await fs.access(auditChainLandedPath());
    return true;
  } catch {
    return false;
  }
}

/** Write `text` to `target` once: in full (and synced) to a private temp file, then
 *  published with link(2), which never replaces an existing file — a crash leaves either
 *  no file or a complete one — and the directory synced. An existing file is left alone.
 *  True when this call created it. */
async function publishOnce(target: string, text: string): Promise<boolean> {
  const tmp = `${target}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  const fh = await fs.open(tmp, "wx", 0o600);
  try {
    await fh.writeFile(text);
    await fh.sync();
  } finally {
    await fh.close();
  }
  let created = true;
  try {
    await fs.link(tmp, target);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "EEXIST") created = false;
    else if (code === "ENOTSUP" || code === "EPERM" || code === "EXDEV" || code === "ENOSYS" || code === "EOPNOTSUPP") {
      // A filesystem without hard links: exclusive-create the target itself (one server
      // writes this config dir; a crash mid-write leaves a partial file, which verify
      // reports and the writer leaves alone).
      created = await publishByRename(tmp, target);
    } else throw e;
  } finally {
    await fs.rm(tmp, { force: true }).catch(() => {}); // a leftover temp file is harmless
  }
  await syncDir(path.dirname(target));
  return created;
}

/** The no-hard-link fallback: rename the complete, synced temp file into place, but only if
 *  the target does not exist yet (one server writes this config dir; two at once is the
 *  documented anomaly). The content still appears atomically — never a partial file. */
async function publishByRename(tmp: string, target: string): Promise<boolean> {
  try {
    await fs.access(target);
    return false;
  } catch {
    await fs.rename(tmp, target);
    return true;
  }
}

/** Record that the committed row reached the log (the log synced first). A failure here
 *  is logged and retried by every later write (and the next start); it never stops audit
 *  rows. */
async function recordLanded(logPath: string): Promise<void> {
  try {
    await syncFile(logPath);
    await publishOnce(auditChainLandedPath(), "");
    landedDue = false;
  } catch (e) {
    landedDue = true;
    if (!landedFailureReported) {
      landedFailureReported = true;
      console.error(`[safespace] audit chain: recording that the committed row landed failed (retried by each later write): ${e instanceof Error ? e.message : String(e)}`);
    }
  }
}

/** Read the install-time HMAC salt for email hashing in audit logs, creating
 *  it on first call. The salt is 32 random bytes, raw. Stored 0o600 in
 *  configDir. Without the salt, an attacker who exfiltrated the audit log
 *  could run a dictionary attack against unsalted email hashes (sec-rev
 *  v1.2 PR-1 Q6, 2026-05-16).
 *
 *  Salt lives on disk (not env var) so it survives shell history rotations
 *  and isn't accidentally `set | grep`'d into a log. Per-install, not
 *  per-account — emails hashed under one salt are linkable across accounts
 *  within the same install, but not across installs (cross-install rainbow
 *  table attacks foreclosed). Single-user self-use scope.
 *
 *  Concurrent-safe: open with O_EXCL on creation; if it loses the race, fall
 *  back to reading the file the winner wrote. */
export async function getOrCreateAuditSalt(): Promise<Buffer> {
  const p = auditSaltPath();
  try {
    return await fs.readFile(p);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
  }
  await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
  const salt = crypto.randomBytes(32);
  try {
    const fh = await fs.open(p, "wx", 0o600);
    try {
      await fh.write(salt);
    } finally {
      await fh.close();
    }
    return salt;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") {
      // Concurrent create: another process wrote first. Read theirs.
      return await fs.readFile(p);
    }
    throw e;
  }
}

/** HMAC-SHA256 hash of a target email for audit logs. Full 32-byte digest
 *  (hex-encoded = 64 chars); not truncated per sec-rev v1.2 PR-1 Q6
 *  (truncation below input keyspace size enables collision shortcuts).
 *
 *  Returns null when email is null — `share_type=anyone` shares have no
 *  target email, and the audit row should distinguish "no target" from
 *  "target hashed to all-zero" (which would be a coincidence). */
export async function hashTargetEmail(email: string | null): Promise<string | null> {
  if (email === null) return null;
  const salt = await getOrCreateAuditSalt();
  return crypto.createHmac(AUDIT_HMAC_ALG, salt).update(email).digest("hex");
}

// ── v1.89 — tamper-evident audit hash-chain (HMAC-keyed) ───────────────────
//
// docs/AUDIT-CHAIN.md. Every audit row carries a `row_mac` =
// HMAC-SHA256(audit-salt, prev_mac ‖ canonicalJson(row-without-row_mac)). Because
// each MAC folds in the PREVIOUS row's MAC, editing / deleting / inserting any past
// row breaks the chain at that point — detectable by `safespace audit verify`.
//
// KEYED, not plain: the MAC uses the per-install `audit-salt` (stored OUTSIDE
// audit.jsonl), so an attacker who can READ or EDIT the log but NOT the salt cannot
// forge a valid chain (a backup leak, a log-shipping pipeline, a lower-priv user,
// an offline disk image — the F6 threat model).
//
// HONEST BOUNDARY (do not oversell, mirrors F6): the chain detects tampering of
// PAST rows by someone WITHOUT the salt. It does NOT defend against (a) a same-host
// attacker who can read the salt and recompute the whole chain forward, nor (b) TAIL
// TRUNCATION (deleting the last N rows leaves the remaining chain internally
// consistent) — truncation detection needs the tip MAC recorded out-of-band, which
// `verify` prints for exactly that purpose.
//
// ONE WRITER PER CHAIN FILE: the running `lastMac` is per-process. audit.jsonl is
// written only by the stdio server; rows from a `safespace` CLI process go to
// audit-cli.jsonl, a separate chain (audit/cli-chain.ts). Two server processes on one
// config dir, or two CLI processes writing at once, fork that file's chain — which
// `verify` surfaces as a break (correctly: it IS an anomaly).

/** The prev-mac seed for the FIRST chained row. Fixed, non-secret labels — the salt
 *  provides the secrecy. v2 marks a STRICT chain (every line chained; a fresh audit.jsonl
 *  starts here); v1 is a chain begun before strict chains, which `audit verify` tolerates
 *  unchained event rows in until its first chained `STRICT_MARKER_EVENT` row. */
const CHAIN_GENESIS = "safespace-audit-chain/genesis/v1";
const CHAIN_GENESIS_STRICT = "safespace-audit-chain/genesis/v2";
/** The event of the row the server writes once into a v1 chain: from it on, the chain is
 *  strict. docs/AUDIT-CHAIN.md. */
export const STRICT_MARKER_EVENT = "audit_chain_strict";

let cachedSalt: Buffer | null = null;
/** True while this server process still owes a v1 audit.jsonl its strict marker row. */
let strictMarkerDue = false;
/** True while this server process still owes the `.landed` record of its committed row. */
let landedDue = false;
/** Whether this process already reported a failing `.landed` record (reported once). */
let landedFailureReported = false;
/** JSON rows after the resumed tip (recorded in the commitment as `rows_after_prev`). */
let rowsAfterTip = 0;
/** Which strict chain this server process's log is (or becomes, with its marker). */
let strictKind: "v1" | "v2" = "v2";
/** The committed marker row this server process must re-append (its earlier append failed
 *  after the commitment was written), or null. */
let committedMarkerRow: Record<string, unknown> | null = null;
/** The current chain tip (this process's last written row_mac). `undefined` until
 *  the first write lazily reads the file tail (continues an existing chain across a
 *  restart; CHAIN_GENESIS when the file is empty / has no chained tail). */
let lastMac: string | undefined;
/** The CLI chain's tip in this process (audit-cli.jsonl), resumed from that file's
 *  VERIFIED prefix on the first CLI write. */
let cliLastMac: string | undefined;
/** True until this server process has anchored the CLI chain's tip (or found nothing to
 *  anchor). See `serverCliAnchor`. */
let cliAnchorDue = true;
/** The CLI tip this server process last sealed, and how many anchor walks it has spent
 *  while the CLI file's tail was unfinished (bounded so a planted partial line cannot make
 *  every server write walk the file). */
let lastAnchoredCliTip: string | null = null;
let cliAnchorRetries = 0;
const CLI_ANCHOR_MAX_RETRIES = 20;
/** True once this process has checked audit.jsonl for a partial final line. */
let serverTailChecked = false;

/** Which chain file this process writes. "server" (the default) = audit.jsonl; "cli"
 *  = audit-cli.jsonl. `runCli` sets "cli" first thing; a process keeps one role. */
export type AuditChainRole = "server" | "cli";
let chainRole: AuditChainRole = "server";

export function setAuditChainRole(role: AuditChainRole): void {
  chainRole = role;
}

export function auditChainRole(): AuditChainRole {
  return chainRole;
}

async function chainSalt(): Promise<Buffer> {
  if (cachedSalt === null) cachedSalt = await getOrCreateAuditSalt();
  return cachedSalt;
}

/** Deterministic JSON: object keys sorted recursively so the MAC reproduces at
 *  verify time regardless of insertion order (arrays keep order; primitives as-is).
 *  Audit payloads carry only string/number/boolean/nested-object fields — never
 *  `undefined` (which `JSON.stringify` would silently drop), so the serialization is
 *  total over the input domain. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value));
}
function sortKeysDeep(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeysDeep);
  if (v !== null && typeof v === "object") {
    const src = v as Record<string, unknown>;
    // Null prototype: an own key named "__proto__" (what JSON.parse yields for one) must be
    // stored as data, not hit the prototype setter and vanish from the MAC input.
    const out: Record<string, unknown> = Object.create(null);
    for (const k of Object.keys(src).sort()) out[k] = sortKeysDeep(src[k]);
    return out;
  }
  return v;
}

/** The chain MAC for a row: HMAC-SHA256(salt, prevMac ‖ "\n" ‖ canonicalJson(row)).
 *  `row` MUST NOT contain `row_mac` (a MAC can't hash itself); the verifier strips
 *  it before recomputing. Exported so `audit verify` recomputes identically. */
export function computeRowMac(
  salt: Buffer,
  prevMac: string,
  rowWithoutMac: Record<string, unknown>,
): string {
  return crypto
    .createHmac(AUDIT_HMAC_ALG, salt)
    .update(prevMac)
    .update("\n")
    .update(canonicalJson(rowWithoutMac))
    .digest("hex");
}

/** The audit-chain genesis seed (the prev-mac of the first chained row). */
export function chainGenesis(): string {
  return CHAIN_GENESIS;
}

export function strictChainGenesis(): string {
  return CHAIN_GENESIS_STRICT;
}

// A per-process write mutex: the chain needs SERIAL writes (each row folds in the
// previous row's MAC), so concurrent auditEnd calls (async tools) must not
// race to read-tip-then-append. Each call awaits its own segment, so a caller that
// `await`s auditEnd sees its row durably written.
let writeTail: Promise<void> = Promise.resolve();
function runExclusive<T>(fn: () => Promise<T>): Promise<T> {
  // Run `fn` after the previous write REGARDLESS of its outcome: a PRIOR write's
  // failure must NOT block the queue (best-effort audit). The rejection branch
  // `() => fn()` discards the prior error and starts fresh (rather than relying on
  // `fn` ignoring an injected reason arg). Do NOT "simplify" to `.then(fn)` — that
  // would deadlock the chain on any single audit failure.
  const result = writeTail.then(fn, () => fn());
  writeTail = result.then(
    () => {},
    () => {},
  );
  return result;
}

/** Reset the in-memory chain state and the role. TEST-ONLY (the per-process state
 *  would otherwise leak across tests that share the module). Await
 *  `__drainAuditWrites()` first when a write may still be in flight. */
export function __resetChainState(): void {
  cachedSalt = null;
  lastMac = undefined;
  cliLastMac = undefined;
  cliAnchorDue = true;
  lastAnchoredCliTip = null;
  cliAnchorRetries = 0;
  strictMarkerDue = false;
  committedMarkerRow = null;
  landedDue = false;
  landedFailureReported = false;
  rowsAfterTip = 0;
  strictKind = "v2";
  serverTailChecked = false;
  chainRole = "server";
  writeTail = Promise.resolve();
}

/** Resolve once every queued audit write has finished. TEST-ONLY. */
export function __drainAuditWrites(): Promise<void> {
  return writeTail;
}

/** The server's anchor of the CLI chain: on the first chained server write in a process,
 *  seal the CLI chain's VERIFIED tip into audit.jsonl so deleting, emptying or cutting
 *  audit-cli.jsonl is detectable (`verify` checks every anchor's MAC is still present).
 *  `anchor` is the row to append (null when nothing new to seal: no CLI file, nothing
 *  verifiable, or the tip already sealed). `done` is false while the file's final line is
 *  unfinished or it cannot be read: the verified prefix is sealed NOW (an appended partial
 *  line cannot suppress sealing) and later writes retry, bounded, to seal the completed
 *  tail. A file in which nothing verifies is not anchored — junk alone protects nothing,
 *  and the strict walk already fails verify while it is there. */
async function serverCliAnchor(salt: Buffer): Promise<{ anchor: Record<string, unknown> | null; done: boolean }> {
  const walk = await walkStrictChain(auditCliPath(), salt, cliChainGenesis());
  if (!walk.exists) return { anchor: null, done: true };
  const unfinished = walk.reason === "read_error" || walk.reason === "incomplete_tail";
  // A file that cannot be read at all stays due without a cap: the cap must not let a
  // temporarily unreadable file go unsealed for good.
  const unreadable = walk.reason === "read_error" && walk.tipMac === null;
  const done = !unfinished || (!unreadable && ++cliAnchorRetries >= CLI_ANCHOR_MAX_RETRIES);
  if (walk.tipMac === null || walk.tipMac === lastAnchoredCliTip) return { anchor: null, done };
  return {
    anchor: { ts: new Date().toISOString(), run_id: RUN_ID, event: "cli_chain_anchor", cli_tip_mac: walk.tipMac },
    done,
  };
}

/** Append one row as a link in this process's tamper-evident chain: audit.jsonl in
 *  the "server" role, audit-cli.jsonl in the "cli" role (see `setAuditChainRole`).
 *  Serialized through the per-process write mutex, folding in the previous chained
 *  row's MAC and stamping `row_mac`. Best-effort — any error is logged (with
 *  `label`) and swallowed so a broken audit file never fails a tool call. Every audit
 *  row goes through here; nothing is appended unchained.
 *
 *  MUTATES `payload` (adds `row_mac`). The MAC is computed over the payload
 *  BEFORE `row_mac` is added (a MAC can't hash itself); on a successful append
 *  `lastMac` advances, so a FAILED append leaves the chain unbroken (the row
 *  simply never existed). The target dir/path are resolved at CALL time (not
 *  lazily inside the mutex) so a deferred write can't drift if the config dir
 *  changed in the meantime (it never does in production; this keeps concurrent
 *  tests with per-test dirs from cross-contaminating). */
export async function appendChainedRow(payload: Record<string, unknown>, label: string): Promise<void> {
  // Role, directory and path are resolved at CALL time (not inside the mutex), so a
  // queued write never lands in the other chain file.
  const role = chainRole;
  const targetDir = configDir();
  const targetPath = role === "cli" ? auditCliPath() : auditPath();
  try {
    await runExclusive(async () => {
      const salt = await chainSalt();
      await fs.mkdir(targetDir, { recursive: true, mode: 0o700 });
      if (role === "cli") {
        // Resume from the tip of the chain traced forward from genesis (forged, replayed,
        // junk and losing-fork lines are skipped), so after a break later rows keep chaining
        // one after another and removing the one bad row repairs the chain.
        if (cliLastMac === undefined) cliLastMac = await resumeTip(targetPath, salt, cliChainGenesis());
        const rowMac = computeRowMac(salt, cliLastMac, payload);
        payload.row_mac = rowMac;
        // Never glue onto a partial final line.
        const sep = (await endsMidLine(targetPath)) ? "\n" : "";
        await fs.appendFile(targetPath, sep + JSON.stringify(payload) + "\n", { mode: 0o600 });
        cliLastMac = rowMac;
        return;
      }
      // Continue the chain across a restart from the tip traced forward from its genesis
      // (forged, replayed, junk and unchained lines are skipped; `resumeServerChain`).
      if (lastMac === undefined) {
        const commitment = await readStrictCommitment();
        const valid = commitment !== null && commitment !== "invalid" ? commitment : null;
        const r = await resumeServerChain(
          targetPath, salt, CHAIN_GENESIS, CHAIN_GENESIS_STRICT, STRICT_MARKER_EVENT, valid?.marker_mac,
        );
        // Every strict chain holds one committed row (beside the salt, written BEFORE the row
        // is appended): in a fresh log its first row (chained from the v2 genesis); in an
        // older log a marker row after the existing chain. The commitment is never re-made
        // and never answered with a second marker: if the log no longer matches it, verify
        // reports it.
        strictMarkerDue = commitment === null && r.markerMac === null;
        if (commitment === null && r.markerMac !== null) {
          // A marker on disk without its commitment (written by an earlier build): adopt it,
          // and record that it landed (it is in the log).
          await writeStrictCommitmentOnce({ strict: r.version === 2 ? "v2" : "v1", marker_mac: r.markerMac });
          await recordLanded(targetPath);
        }
        const landed = await landedExists();
        if (valid !== null && !landed && r.committedSeen) {
          // The committed row is in the log but its landing was never recorded: record it now
          // (the log is synced first), so a later emptied log cannot regain the row.
          await recordLanded(targetPath);
        }
        // A committed row whose append failed: re-append that exact row when it never landed
        // and the log still ends where it was to go.
        // Re-append only when the log ends exactly where the row was to go: the same rows after
        // that tip as when it was committed. Anything else means the log moved on or was
        // rewritten — then nothing is re-appended and verify reports the missing row.
        committedMarkerRow =
          valid !== null && !landed && !r.committedSeen && valid.marker_row !== undefined &&
          valid.prev_mac === r.tip &&
          // records from builds before `rows_after_prev` carry no count: no count check
          (valid.rows_after_prev === undefined || r.rowsAfterTip === valid.rows_after_prev)
            ? valid.marker_row
            : null;
        // Under a v2 commitment a log with no chained row is never read as a pre-chain
        // prefix: the chain restarts at v2 (verify reports the missing marker).
        lastMac =
          commitment !== null && commitment !== "invalid" && commitment.strict === "v2" && r.version === null
            ? CHAIN_GENESIS_STRICT
            : r.tip;
        strictKind = r.tip === CHAIN_GENESIS_STRICT || r.version === 2 ? "v2" : "v1";
        rowsAfterTip = r.rowsAfterTip;
      }
      // Never glue onto a partial final line (checked once per server process: it is the
      // only writer of this file afterwards).
      let sep = serverTailChecked ? "" : (await endsMidLine(targetPath)) ? "\n" : "";
      // Each append advances the chain only once its row is on disk, so a failed append
      // is retried by the next write.
      const append = async (row: Record<string, unknown>): Promise<void> => {
        const rowMac = computeRowMac(salt, lastMac as string, row);
        row.row_mac = rowMac;
        await fs.appendFile(targetPath, sep + JSON.stringify(row) + "\n", { mode: 0o600 });
        sep = "";
        lastMac = rowMac;
      };
      // A committed row whose append failed earlier goes first, exactly as committed.
      if (committedMarkerRow !== null) {
        const row = { ...committedMarkerRow };
        await append(row);
        committedMarkerRow = null;
        await recordLanded(targetPath);
        if (row.event === "cli_chain_anchor") lastAnchoredCliTip = row.cli_tip_mac as string;
      }
      // The CLI anchor (and a v1 log's marker) are written BEFORE the row that triggered
      // them, so the server's last line stays a real call (and the marker is never the tail).
      let anchor: Record<string, unknown> | null = null;
      let anchorDone = true;
      if (cliAnchorDue) ({ anchor, done: anchorDone } = await serverCliAnchor(salt));
      const queue: Array<Record<string, unknown>> = anchor !== null ? [anchor, payload] : [payload];
      if (strictMarkerDue) {
        // Commit the chain's first strict row BEFORE appending it: in a fresh log that is the
        // first row itself (chained from the v2 genesis); in an older log, a marker row.
        const prev = lastMac as string;
        const first =
          strictKind === "v2" && prev === CHAIN_GENESIS_STRICT
            ? queue.shift()!
            : { ts: new Date().toISOString(), run_id: RUN_ID, event: STRICT_MARKER_EVENT };
        const committed = { ...first };
        await writeStrictCommitmentOnce({
          strict: strictKind,
          marker_mac: computeRowMac(salt, prev, committed),
          prev_mac: prev,
          marker_row: committed,
          rows_after_prev: rowsAfterTip,
        });
        strictMarkerDue = false;
        committedMarkerRow = committed; // re-appended by the next write if this append fails
        await append(first);
        committedMarkerRow = null;
        await recordLanded(targetPath);
      }
      for (const row of queue) await append(row);
      if (landedDue) await recordLanded(targetPath);
      if (anchor !== null) lastAnchoredCliTip = anchor.cli_tip_mac as string;
      if (anchorDone) cliAnchorDue = false;
      serverTailChecked = true;
    });
  } catch (e) {
    // A failed append may have left a partial line, or may even have written its row:
    // re-check the tail and re-walk the file on the next write, so it continues from the
    // file's real tip (and re-derives any committed row still owed).
    serverTailChecked = false;
    if (role === "cli") cliLastMac = undefined;
    else {
      lastMac = undefined;
      committedMarkerRow = null;
      strictMarkerDue = false;
    }
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`[safespace] ${label} append failed: ${msg}`);
  }
}

export interface AuditStartContext {
  tool: string;
  /** The Google account this call ran under, OR `null` for a KEYLESS connector
   *  (v1.65 web-fetch) that has no account. Serialized to the row's `account`
   *  field verbatim; the `source` field disambiguates a keyless `account:null`
   *  from any Google row. Widened from `string` in v1.65 — additive + byte-stable
   *  for every Google call (which always passes a real email). */
  email: string | null;
  argsHash: string;
}

export function auditStart(_ctx: AuditStartContext): void {
  // Intentional no-op: the only durable record is `auditEnd` so each tool
  // call produces exactly one JSONL line (write-amplification doesn't help
  // when status is the field we care about). Kept as a function so Step 6
  // can wire pre-call tracing without churning the with-context call site.
}

/** v1.33 (d) — non-PII forensic fields safe to gap-fill from a thrown
 *  MCPError's data onto the audit row when a handler threw WITHOUT recording
 *  the per-channel meta. ONLY closed-set, non-PII fields. Adding a field here
 *  REQUIRES a PII review (docs/v1.33-audit-cli-forensics.md §6 hook #6):
 *    - rejected_formula_function          — UPPERCASE name from the closed
 *                                           11-item REJECT set (never content).
 *    - rejected_formula_homoglyph_source  — ≤256 confuser/invisible codepoints
 *                                           (closed set; capped per sec-L1).
 *    - rejected_formula_nested            — literal `true` (closed; bare flag,
 *                                           no payload, no PII). v1.41. */
export const AUDIT_ERROR_FORENSIC_WHITELIST = [
  "rejected_formula_function",
  "rejected_formula_nested",
  "rejected_formula_homoglyph_source",
] as const;

/** v1.33 (d) — pick the whitelisted forensic fields from an MCPError's data
 *  for the audit-row gap-fill safety net. Returns undefined when none present
 *  so the `errorForensics` field stays ABSENT (PRESENCE-as-signal). NEVER
 *  copies arbitrary error data — only the closed-set whitelist above. */
export function pickAuditErrorForensics(
  data: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (!data) return undefined;
  let out: Record<string, unknown> | undefined;
  for (const k of AUDIT_ERROR_FORENSIC_WHITELIST) {
    if (data[k] !== undefined) {
      (out ??= {})[k] = data[k];
    }
  }
  return out;
}

export interface AuditEndContext extends AuditStartContext {
  status: "ok" | "error";
  durationMs: number;
  /** v1.64 Phase B (B0 relabel) — the Source connector id for this call,
   *  threaded from `TOOL_REGISTRY[tool].source` by with-context.ts. Like
   *  `operator` / `run_id`, an ALWAYS-PRESENT base field (auditEnd defaults it
   *  to "google-workspace"), NOT presence-as-signal — an absent key would
   *  conflate "Google" with "field stripped", defeating the per-Source
   *  forensic attribution the safety-gateway thesis depends on once a non-
   *  Google connector exists. ZERO new audit channel (a row field, not an
   *  AUDIT_META_CHANNELS entry). */
  source?: string;
  /** "applied" (default — MCP / safespace exec) or "bypassed" (--raw escape
   *  hatch for non-LLM consumers like cron jobs / Python CLIs). Recorded
   *  explicitly on every line so log readers can grep `"sanitize":"bypassed"`
   *  without having to interpret absence-of-field. */
  sanitize?: "applied" | "bypassed";
  /** v1.16 Phase 2b — comment-post forensic detail. Set via
   *  `ctx.audit.record("commentPostMeta", …)`. ABSENT for non-comment-post tools (the
   *  field's PRESENCE itself signals "this is a comment-post call"). */
  commentPostMeta?: CommentPostAuditMeta;
  /** v1.17 Phase 1 — calendar-mutation forensic detail. Set via
   *  `ctx.audit.record("calendarMutationMeta", …)`. ABSENT for non-calendar-mutation
   *  tools (the field's PRESENCE itself signals "this is a calendar
   *  update/delete/respond call"). Distinct from `commentPostMeta` so log
   *  greps can filter independently. */
  calendarMutationMeta?: CalendarMutationAuditMeta;
  /** v1.17 Phase 2 — docs_modify_structured forensic detail. Set via
   *  `ctx.audit.record("docsModifyMeta", …)`. ABSENT for non-docs-modify tools (the
   *  field's PRESENCE itself signals "this is a docs_modify_structured
   *  call"). Distinct from `commentPostMeta` / `calendarMutationMeta` so
   *  log greps can filter independently. The 4 metas (commentPost /
   *  calendarMutation / docsModify / commentDelete) are mutually exclusive
   *  per call (runtime-asserted in with-context.ts auditEnd finally block). */
  docsModifyMeta?: DocsModifyAuditMeta;
  /** v1.17 Phase 3 — youtube_comment_delete forensic detail. Set via
   *  `ctx.audit.record("commentDeleteMeta", …)`. ABSENT for non-delete tools (the
   *  field's PRESENCE itself signals "this is a comment-delete call";
   *  distinct from `commentPostMeta` so log greps `commentDeleteMeta` vs
   *  `commentPostMeta` cleanly separate the two operations). The 5 metas
   *  (commentPost / calendarMutation / docsModify / commentDelete /
   *  tasksMutation) are mutually exclusive per call (runtime-asserted in
   *  with-context.ts auditEnd finally block — see hook B Phase 3 prompt). */
  commentDeleteMeta?: CommentDeleteAuditMeta;
  /** v1.19 Phase 2b — tasks_create / tasks_update / tasks_delete forensic
   *  detail. Set via `ctx.audit.record("tasksMutationMeta", …)`. ABSENT for non-tasks-
   *  mutation tools (the field's PRESENCE itself signals "this is a tasks
   *  mutation call"; the `operation` field discriminates create vs update
   *  vs delete within the channel). The 5 metas (commentPost /
   *  calendarMutation / docsModify / commentDelete / tasksMutation) are
   *  mutually exclusive per call (runtime-asserted in with-context.ts
   *  auditEnd finally block). */
  tasksMutationMeta?: TasksMutationAuditMeta;
  /** v1.20 Phase 1b-2 — sheets_create / sheets_append_values forensic detail.
   *  Set via `ctx.audit.record("sheetsMutationMeta", …)`. ABSENT for non-sheets-mutation
   *  tools (the field's PRESENCE itself signals "this is a sheets mutation
   *  call"; the `operation` field discriminates create vs append_values within
   *  the channel). The 6 metas (commentPost / calendarMutation / docsModify /
   *  commentDelete / tasksMutation / sheetsMutation) are mutually exclusive
   *  per call (runtime-asserted in with-context.ts auditEnd finally block).
   *
   *  `sheets_create` calls the recorder TWICE in the success path (mirror v1.17
   *  docsModifyMeta last-write-wins pattern): first BEFORE the SDK with
   *  `target_spreadsheet_id_hash = sha256("<pending-create>")` (forensic
   *  survives SDK 5xx), then AFTER SDK success with the real spreadsheet ID
   *  hash — see design §5 2-step pattern. */
  sheetsMutationMeta?: SheetsMutationAuditMeta;
  /** v1.48 B4 — the 3 non-destructive YouTube playlist WRITE tools
   *  (youtube_playlist_create / youtube_playlist_update /
   *  youtube_playlist_item_insert) forensic detail. Set via
   *  `ctx.audit.record("playlistMutationMeta", …)`. ABSENT for non-playlist-mutation tools
   *  (the field's PRESENCE itself signals "this is a playlist mutation call";
   *  the `operation` field discriminates create vs update vs item_insert within
   *  the channel). Now 8 metas mutually exclusive per call (runtime-asserted in
   *  with-context.ts auditEnd finally block). `youtube_playlist_create` calls
   *  the recorder TWICE in the success path (mirror sheets_create 2-step). */
  playlistMutationMeta?: PlaylistMutationAuditMeta;
  /** v1.106 — populated for `youtube_video_update` (videos.update snippet
   *  metadata) forensic detail. Set via `ctx.audit.record("videoMutationMeta", …)`.
   *  ABSENT for non-video-mutation tools (the field's PRESENCE signals "this is a
   *  video-metadata mutation call"). Now 8 metas mutually exclusive per call
   *  (runtime-asserted in with-context.ts auditEnd finally block). */
  videoMutationMeta?: VideoMutationAuditMeta;
  /** v1.15 Phase 3 — populated for tools that perform contact-lookup
   *  (gmail_send / calendar_create_event) AND actually resolved AT LEAST ONE
   *  name to an email in this call. Format: plain SHA-256 hex of the
   *  comma-joined sorted resolved emails (matching the `args_hash` algorithm
   *  per docs/v1.15-contacts-api.md §7 + sec-rev hook #11). NEVER HMAC —
   *  HMAC is reserved for `target_email_hash` in `share_forensic` and
   *  `rejected_recipient_hashes` in `recipient_denied_by_policy` rows. The
   *  algorithm divergence is intentional: those HMAC fields hide identities
   *  to make per-install dictionary attacks infeasible; `resolved_recipient_hash`
   *  is a forensic pivot key for "did Claude actually see this email?" and
   *  needs to match the plain-SHA-256 convention shared with `args_hash`.
   *
   *  Multi-recipient semantics: for gmail_send with multiple to/cc/bcc, the
   *  hash is over the canonical form `sortedEmails.join(",")` — i.e., one
   *  hash per CALL, not per RECIPIENT. Trades per-recipient resolvability for
   *  schema simplicity (one field per row). Investigator who needs per-
   *  recipient identification re-runs `contacts_lookup_email` against the
   *  same (account, name) — see §7 "Audit vs response divergence (Phase 3)".
   *
   *  ABSENT when no contact-lookup resolution occurred this call (caller
   *  passed only emails). Distinguishes "did NOT use the resolver" from
   *  "resolver returned a hash that matches the args" — both forensically
   *  relevant. */
  resolvedRecipientHash?: string;
  /** v1.56 F3b — `true` when a gmail egress recipient first appeared inside
   *  untrusted BODY content recorded this session (policy/tainted-source).
   *  Emitted to JSONL as `tainted_source: true`. ABSENT otherwise (presence-as-
   *  signal; the row is byte-stable for every non-tainted call). Observability
   *  only — the send is NOT blocked by this flag in v1.56. */
  taintedSource?: boolean;
  /** v1.57 F3a — the secret-shape CLASS (e.g. "private_key") when an INTERACTIVE
   *  gmail body matched a secret shape (under autonomous the handler throws
   *  `-32035` instead). Emitted to JSONL as `outbound_secret_shape: <class>`.
   *  ABSENT otherwise (presence-as-signal; byte-stable). The value is a bounded
   *  closed-set class, never the matched secret bytes. Observability only. */
  outboundSecretShape?: string;
  /** v1.24 Phase 1 — Item 2: when `status === "error"` AND the thrown
   *  error is an MCPError, the numeric code (matches MCPError codes in
   *  errors.ts: -32000 ... -32029). Emitted to JSONL as
   *  `error_code: number`. ABSENT on success rows (status === "ok") and
   *  ABSENT on error rows when the thrown error is a plain `Error`
   *  (non-MCPError) — PRESENCE-as-signal preserves the "didn't try" vs
   *  "tried and failed with specific code" discrimination, mirrors v1.15
   *  Phase 3 `resolvedRecipientHash` / v1.16 Phase 2b `commentPostMeta`
   *  patterns. Activates 4 v1.23 Phase 1 forward-compat safety nets in
   *  `cli/audit/suspicious.ts` (-32025 / -32026 / -32007 / -32022). Q3
   *  LOCKED — MCPError-only at design close. */
  errorCode?: number;
  /** v1.33 (d) — whitelisted forensic fields lifted from a thrown MCPError's
   *  data (via `pickAuditErrorForensics`) for the audit-row GAP-FILL safety
   *  net. ABSENT unless an MCPError carrying whitelisted forensic fields was
   *  thrown. `auditEnd` gap-fills ONLY keys not already emitted by a channel
   *  serialize — collision-safe + byte-stable no-op for handlers that record
   *  their meta (e.g. the 2 sheets formula-reject handlers). See
   *  docs/v1.33-audit-cli-forensics.md §4.4. */
  errorForensics?: Record<string, unknown>;
  /** Why a call was refused at the dispatch boundary, before any choke point ran.
   *  Row-only: the client always gets the same `tool_not_found` for all three, so
   *  this adds no tier/connector oracle. ABSENT on every dispatched call. */
  refusalReason?: RefusalReason;
  /** HMAC (audit salt) of a caller-supplied tool name that is not in the registry.
   *  The raw name is agent-controlled free text and is never written. */
  toolNameHmac?: string;
}

export type RefusalReason = "unknown" | "tier_hidden" | "connector_hidden";

/** Errors whose terminal audit row has already been written by the layer that threw
 *  them. A caller wrapping that layer checks this so a failure is never logged twice. */
const AUDITED_ERRORS = new WeakSet<object>();

export function markErrorAudited(err: unknown): void {
  if (typeof err === "object" && err !== null) AUDITED_ERRORS.add(err);
}

export function isErrorAudited(err: unknown): boolean {
  return typeof err === "object" && err !== null && AUDITED_ERRORS.has(err);
}

/** Tool label written for a refused name that is not in the registry. */
export const UNKNOWN_TOOL_LABEL = "<unknown>";

/** HMAC-SHA256 of a caller-supplied unknown tool name, same salt and algorithm as
 *  `hashTargetEmail`. */
export async function hashUnknownToolName(name: string): Promise<string> {
  const salt = await getOrCreateAuditSalt();
  return crypto.createHmac(AUDIT_HMAC_ALG, salt).update(name).digest("hex");
}

/** Append one JSON line per call. POSIX `appendFile` is atomic for
 *  buffers smaller than the page size, so concurrent tool calls produce
 *  interleaved-by-line records that are never partially corrupted.
 *
 *  Best-effort: any error is logged to stderr and swallowed so a broken
 *  audit file (full disk, permission flipped) cannot make a tool call
 *  fail. The user already has their data. */
export async function auditEnd(ctx: AuditEndContext): Promise<void> {
  // v1.15 Phase 3 — `resolved_recipient_hash` is emitted ONLY when set so
  // the field's PRESENCE is itself the forensic signal ("this call did a
  // name→email resolution"). Always-emit with `null` would conflate "didn't
  // try" with "tried, got 0/ambiguous" — handlers that throw
  // recipient_lookup_failed before resolution NEVER reach here in the ok
  // path, and the field stays absent on error rows too.
  const payload: Record<string, unknown> = {
    ts: new Date().toISOString(),
    // v1.58 F5 — per-process run id (ALWAYS present, the session grouping key).
    run_id: RUN_ID,
    tool: ctx.tool,
    // v1.64 Phase B (B0) — the Source connector this call belongs to. ALWAYS
    // emitted, defaults "google-workspace" (the run_id / operator precedent of
    // an always-present base field). Attributes a call to its Source before any
    // non-Google connector exists; NOT presence-as-signal.
    source: ctx.source ?? "google-workspace",
    account: ctx.email,
    // Always null: the per-operator label (SAFESPACE_OPERATOR_ID) was retired. Kept
    // so the row shape that readers and exports expect does not change.
    operator: null,
    args_hash: ctx.argsHash,
    status: ctx.status,
    duration_ms: ctx.durationMs,
    sanitize: ctx.sanitize ?? "applied",
  };
  if (ctx.resolvedRecipientHash !== undefined) {
    payload.resolved_recipient_hash = ctx.resolvedRecipientHash;
  }
  // v1.56 F3b — emit ONLY when set (presence-as-signal). The value is always the
  // literal `true`; absence is the "not tainted" signal, so the row stays
  // byte-stable for every non-tainted call.
  if (ctx.taintedSource === true) {
    payload.tainted_source = true;
  }
  // v1.57 F3a — emit ONLY when set; the value is the closed-set shape class.
  if (ctx.outboundSecretShape !== undefined) {
    payload.outbound_secret_shape = ctx.outboundSecretShape;
  }
  // v1.25 Phase 2 Item 2 — registry-driven `serialize` dispatch replaces 6
  // manual per-channel write blocks (commentPostMeta / calendarMutationMeta /
  // docsModifyMeta / commentDeleteMeta / tasksMutationMeta / sheetsMutationMeta).
  //
  // Closes v1.19 NEW-3 "manual 4th site" drift class PERMANENTLY at the
  // TypeScript-enforced level: every channel in AUDIT_META_CHANNELS declares
  // a `serialize` function via the `satisfies` clause, so adding a 7th channel
  // without a `serialize` fails compile. Sites 1-3 of the v1.19 NEW-3 checklist
  // (registry entry / localMetas key / recorder fn) were already TypeScript-
  // enforced; site 4 (this auditEnd write block) was the last hand-maintained
  // surface — now structurally eliminated.
  //
  // Each channel's `serialize(meta)` produces a `Record<string, unknown>`
  // containing exactly the JSONL row fields that channel contributes — field
  // ORDER mirrors the v1.24 manual write blocks for byte-stability across the
  // refactor. The 6-channel mutual-exclusion runtime assertion in
  // `with-context.ts` still applies — only one `ctx.<channel>Meta` is set per
  // call, so this loop hits at most one channel per `auditEnd` invocation.
  //
  // Q3 LOCKED — v1.22 audit roundtrip tests (`src/audit.roundtrip.test.ts`)
  // STAY UNCHANGED as the regression net. Layer 1 (satisfies clause) enforces
  // site 4 EXISTS; Layer 2 (roundtrip tests) enforces site 4 EMITS THE RIGHT
  // BYTES per channel MAX + MIN field-set. Belt-and-braces defense — if a
  // future shape refactor changes the TypeScript surface, Layer 2 still pins
  // the behavioral output contract.
  //
  // Forensic field PRESENCE-as-signal pattern preserved per v1.15-v1.21:
  // optional fields (e.g. parent_comment_id_hash / rsvp_response /
  // target_task_hash / target_range_hash) only appear on the row when the
  // recorder set them — ABSENCE is itself the discriminator. The per-channel
  // `serialize` functions handle the conditional inclusion (see audit.ts
  // AUDIT_META_CHANNELS).
  const ctxRecord = ctx as unknown as Record<string, unknown>;
  for (const [channelKey, entry] of Object.entries(AUDIT_META_CHANNELS)) {
    const meta = ctxRecord[channelKey];
    if (meta !== undefined) {
      Object.assign(payload, entry.serialize(meta));
    }
  }
  // v1.24 Phase 1 Item 2 — MCPError numeric code stamping. Emitted ONLY when
  // ctx.errorCode is defined; PRESENCE-as-signal mirrors v1.15 Phase 3
  // resolved_recipient_hash + v1.16 Phase 2b commentPostMeta patterns.
  // ABSENT on success rows AND on error rows where the thrown error was a
  // plain `Error` (non-MCPError). Activates 4 forward-compat safety nets in
  // cli/audit/suspicious.ts (-32025 / -32026 / -32007 / -32022). Q3 LOCKED.
  if (ctx.errorCode !== undefined) {
    payload.error_code = ctx.errorCode;
  }
  // Presence-as-signal, like error_code: only dispatch-boundary refusals carry these.
  if (ctx.refusalReason !== undefined) {
    payload.refusal_reason = ctx.refusalReason;
  }
  if (ctx.toolNameHmac !== undefined) {
    payload.tool_name_hmac = ctx.toolNameHmac;
  }
  // v1.33 (d) — error_code catch-path forensic GAP-FILL safety net. When a
  // handler threw an MCPError carrying whitelisted forensic fields (e.g.
  // rejected_formula_function / rejected_formula_homoglyph_source) but did NOT
  // record the per-channel meta, copy those fields onto the row. GAP-FILL ONLY
  // (`!(k in payload)`) — NEVER overwrites a value the channel serialize loop
  // above already emitted, so for the current 2 sheets handlers (which DO
  // record sheetsMutationMeta) this is a provable no-op and the row stays
  // BYTE-IDENTICAL to v1.32. Defends future drift (a new handler that throws
  // formula_rejected without recording the meta). See
  // docs/v1.33-audit-cli-forensics.md §4.4 + sec-rev hooks #5 + #6.
  // Scalar values only: the whitelisted fields are strings / `true`, and a scalar cannot
  // carry object keys into the row (so no written row holds an own "__proto__" member
  // whose MAC the canonical form would have to change for).
  if (ctx.errorForensics) {
    for (const [k, v] of Object.entries(ctx.errorForensics)) {
      if (!(k in payload) && (typeof v === "string" || typeof v === "number" || typeof v === "boolean")) {
        payload[k] = v;
      }
    }
  }
  // v1.89 — append as a link in the tamper-evident chain (each MAC folds in the
  // previous chained row's MAC). The shared `appendChainedRow` serializes through
  // the per-process write mutex, computes the MAC over the payload BEFORE adding
  // `row_mac`, and advances `lastMac` ONLY on a successful append — so a FAILED
  // append leaves the chain unbroken (the row simply never existed). Best-effort:
  // any error is logged to stderr (captured by the MCP runtime as server log, not
  // surfaced to Claude) and swallowed so a broken audit file never fails a call.
  await appendChainedRow(payload, "audit");
}
