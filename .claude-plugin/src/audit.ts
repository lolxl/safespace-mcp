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
// SINGLE-WRITER assumption: the running `lastMac` is per-process. Both supported
// topologies are single-writer (Model A = one stdio process; Model B = one
// in-process container). Two processes appending to the same file would fork the
// chain — which `verify` would surface as a break (correctly: it IS an anomaly).

/** The prev-mac seed for the FIRST chained row (and the restart point when the file
 *  has no chained tail). A fixed, non-secret label — the salt provides the secrecy. */
const CHAIN_GENESIS = "safespace-audit-chain/genesis/v1";

let cachedSalt: Buffer | null = null;
/** The current chain tip (this process's last written row_mac). `undefined` until
 *  the first write lazily reads the file tail (continues an existing chain across a
 *  restart; CHAIN_GENESIS when the file is empty / has no chained tail). */
let lastMac: string | undefined;

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
    const out: Record<string, unknown> = {};
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

// A per-process write mutex: the chain needs SERIAL writes (each row folds in the
// previous row's MAC), so concurrent auditEnd calls (Model B, async tools) must not
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

/** Read the chain tip (last row's `row_mac`) from the file tail — once per process,
 *  to continue an existing chain across a restart. Bounded tail read (rows are ~1 KB;
 *  16 KB covers the last row with huge margin). Missing file / unparseable tail / no
 *  `row_mac` (empty or all-legacy file) → CHAIN_GENESIS (the chain (re)starts here). */
async function readChainTip(targetPath: string): Promise<string> {
  try {
    const stat = await fs.stat(targetPath);
    if (stat.size === 0) return CHAIN_GENESIS;
    // 64 KB tail — audit rows are ~1 KB (bounded metadata: hashes, counts, enums,
    // whitelisted forensic fields), so this is a ~64× margin over a single row. A
    // (pathological, unreached-in-practice) row LARGER than the window would make
    // the last line parse fail → genesis re-seed on the next write → which `verify`
    // surfaces as a break, not a silent hole.
    const TAIL = 65536;
    const start = Math.max(0, stat.size - TAIL);
    const fh = await fs.open(targetPath, "r");
    try {
      const buf = Buffer.alloc(stat.size - start);
      await fh.read(buf, 0, buf.length, start);
      // The file ends with "\n"; the LAST non-empty segment is the complete last row
      // (a leading partial segment from the window boundary is ignored).
      const lines = buf.toString("utf8").split("\n").filter((l) => l.length > 0);
      const last = lines[lines.length - 1];
      if (last !== undefined) {
        const parsed = JSON.parse(last) as Record<string, unknown>;
        if (typeof parsed.row_mac === "string") return parsed.row_mac;
      }
    } finally {
      await fh.close();
    }
  } catch {
    // ENOENT / parse failure / read error → start a fresh chain at genesis.
  }
  return CHAIN_GENESIS;
}

/** Reset the in-memory chain state. TEST-ONLY (the per-process `lastMac` would
 *  otherwise leak across tests that share the module). */
export function __resetChainState(): void {
  cachedSalt = null;
  lastMac = undefined;
  writeTail = Promise.resolve();
}

export interface AuditShareEventContext {
  tool: "drive_share_file" | "drive_unshare_file";
  email: string;
  file_id: string;
  share_type: "anyone" | "user";
  role?: "reader" | "commenter";
  /** HMAC-SHA256 of target email (full 64-char hex). null for share_type=anyone. */
  target_email_hash: string | null;
  expiration_iso: string | null;
  granted_permission_id: string | null;
}

/** Append one forensic JSONL line to audit.jsonl for a share / unshare call.
 *
 *  Supplementary to the standard `auditEnd` line that with-context writes
 *  on every tool call. Both lines share `tool` + `account` fields so a log
 *  reader can correlate them, but only this one carries the share-specific
 *  forensic detail (which file, what role, who got access).
 *
 *  `event: "share_forensic"` is the discriminator — readers can grep
 *  `'"event":"share_forensic"'` for the audit detail without colliding
 *  with the standard call lines (which never carry `event`). */
export async function auditShareEvent(ctx: AuditShareEventContext): Promise<void> {
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    tool: ctx.tool,
    account: ctx.email,
    event: "share_forensic",
    file_id: ctx.file_id,
    share_type: ctx.share_type,
    role: ctx.role ?? null,
    target_email_hash: ctx.target_email_hash,
    expiration_iso: ctx.expiration_iso,
    granted_permission_id: ctx.granted_permission_id,
  }) + "\n";
  try {
    await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
    await fs.appendFile(auditPath(), line, { mode: 0o600 });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`[safespace] audit share event append failed: ${msg}`);
  }
}

// Intentionally excludes target_email, share_type, role: the call was
// refused before those inputs were validated upstream. Adding any of
// those fields here would break the v2.1 spec invariant — see
// docs/DESIGN.md v2.1 Addendum "What the audit log records".
export interface AuditShareDeniedContext {
  email: string;
  file_id: string;
  ancestors_walked: number;
  duration_ms: number;
}

/** Append one forensic JSONL line for a drive_share_file call that was
 *  REFUSED by the v2.1 whitelist policy. The call never reached the API —
 *  intentionally, no target_email or share_type or role is recorded,
 *  because the user's intent at those fields was never validated.
 *
 *  `event: "share_denied_by_policy"` discriminator parallels
 *  `share_forensic`. Both lines share tool + account + file_id so a log
 *  reader can correlate denials with subsequent retries. */
export async function auditShareDeniedEvent(
  ctx: AuditShareDeniedContext,
): Promise<void> {
  const line =
    JSON.stringify({
      ts: new Date().toISOString(),
      tool: "drive_share_file",
      account: ctx.email,
      event: "share_denied_by_policy",
      file_id: ctx.file_id,
      ancestors_walked: ctx.ancestors_walked,
      duration_ms: ctx.duration_ms,
    }) + "\n";
  try {
    await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
    await fs.appendFile(auditPath(), line, { mode: 0o600 });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`[safespace] audit share-denied append failed: ${msg}`);
  }
}

// Intentionally excludes plaintext recipients, share_type, role: the call
// was refused at the v2.2 recipient gate; the rejected addresses are
// recorded only as HMAC-SHA256 hashes (same audit-salt as v1.2 share_forensic
// target_email_hash) so a log reader can correlate "denied to X" with
// "successful send to X" without storing plaintext.
export interface AuditRecipientDeniedContext {
  tool:
    | "drive_share_file"
    | "gmail_send"
    | "gmail_create_draft"
    | "line_push_message"
    | "telegram_send_message"
    | "discord_send_message"
    | "slack_send_message"
    | "mattermost_send_message";
  // v1.66 — `string | null`: a class-B connector (LINE) has no Google account, so
  // the denied event's `account` field is null (the `tool` disambiguates it).
  email: string | null;
  /** HMAC-SHA256 hex of each rejected recipient. Length may be less than
   *  `rejected_count` if any hash computation failed (treated as fail-closed
   *  — the recipient was still rejected; just no hash for it). The delta
   *  is observable via `rejected_count - rejected_recipient_hashes.length`. */
  rejected_recipient_hashes: string[];
  rejected_count: number;
  total_recipients: number;
  duration_ms: number;
}

/** Append one forensic JSONL line for a call refused by the v2.2 recipient
 *  allowlist. Same swallow-errors pattern as auditShareEvent /
 *  auditShareDeniedEvent — never block on append failure. */
export async function auditRecipientDeniedEvent(
  ctx: AuditRecipientDeniedContext,
): Promise<void> {
  const line =
    JSON.stringify({
      ts: new Date().toISOString(),
      tool: ctx.tool,
      account: ctx.email,
      event: "recipient_denied_by_policy",
      rejected_recipient_hashes: ctx.rejected_recipient_hashes,
      rejected_count: ctx.rejected_count,
      total_recipients: ctx.total_recipients,
      duration_ms: ctx.duration_ms,
    }) + "\n";
  try {
    await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
    await fs.appendFile(auditPath(), line, { mode: 0o600 });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`[safespace] audit recipient-denied append failed: ${msg}`);
  }
}

/** v1.99 — a send-approval gate decision (OPT-IN supervised mode). Records the tool, the
 *  pending id, the send fingerprint, the operator, and each recipient as an HMAC-SHA256 HASH
 *  — NEVER the body (which lives only in pending-sends.json for the owner's local review). Same
 *  swallow-errors / bare-append pattern as auditRecipientDeniedEvent (these forensic lines sit
 *  outside the v1.89 row_mac chain). `event` ∈ pending (blocked, awaiting approval) / consumed
 *  (an approved send went through) / approved|denied (the owner's CLI action). */
export interface AuditSendApprovalContext {
  event: "pending" | "consumed" | "approved" | "denied";
  pending_id: string;
  tool: string;
  fingerprint: string;
  recipients: string[];
  /** "" = Model A → recorded as null. */
  operator: string;
}

export async function auditSendApprovalEvent(ctx: AuditSendApprovalContext): Promise<void> {
  const hashes = (
    await Promise.all(ctx.recipients.map((r) => hashTargetEmail(r).catch(() => null)))
  ).filter((h): h is string => h !== null);
  const line =
    JSON.stringify({
      ts: new Date().toISOString(),
      tool: ctx.tool,
      event: `send_approval_${ctx.event}`,
      pending_id: ctx.pending_id,
      fingerprint: ctx.fingerprint,
      recipient_hashes: hashes,
      operator: ctx.operator === "" ? null : ctx.operator,
    }) + "\n";
  try {
    await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
    await fs.appendFile(auditPath(), line, { mode: 0o600 });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`[safespace] audit send-approval append failed: ${msg}`);
  }
}

/** v1.102 (W0) — an inbound-webhook receipt forensic line (the first public surface).
 *  Records the provider, sha256(event_id), verified=true, and whether the row was newly
 *  persisted (false on a dedup hit) — NEVER the body, the sender, or the raw event_id.
 *  Same swallow-errors / bare-append pattern as auditSendApprovalEvent (outside the
 *  v1.89 row_mac chain). `run_id` groups receipts within a process session (F5). */
export interface AuditWebhookReceiptContext {
  provider: string;
  event_id: string;
  persisted: boolean;
}

export async function auditWebhookReceiptEvent(ctx: AuditWebhookReceiptContext): Promise<void> {
  const event_id_hash = crypto.createHash("sha256").update(ctx.event_id).digest("hex");
  const line =
    JSON.stringify({
      ts: new Date().toISOString(),
      event: "webhook_receipt",
      provider: ctx.provider,
      event_id_hash,
      verified: true,
      persisted: ctx.persisted,
      run_id: RUN_ID,
    }) + "\n";
  try {
    await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
    await fs.appendFile(auditPath(), line, { mode: 0o600 });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`[safespace] audit webhook-receipt append failed: ${msg}`);
  }
}

/** v1.102 (W0) — a COUNTS-ONLY rejected-receipt forensic line (security MISSED-4): a
 *  forged / bad-signature flood must leave a trail (it's the only way an operator sees
 *  they're being probed on the public surface), but emitting one line per rejected
 *  request would let the flood fill the log. The listener aggregates rejects into a
 *  fixed 60 s rolling window and emits ONE line per window with the count — NO body, NO
 *  source, NO event-id, NO reason. */
export async function auditWebhookRejectedEvent(provider: string, count: number): Promise<void> {
  const line =
    JSON.stringify({
      ts: new Date().toISOString(),
      event: "webhook_rejected",
      provider,
      count,
      run_id: RUN_ID,
    }) + "\n";
  try {
    await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
    await fs.appendFile(auditPath(), line, { mode: 0o600 });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`[safespace] audit webhook-rejected append failed: ${msg}`);
  }
}

// v1.14 Phase 1: cross-account aggregate audit row.
// See docs/v1.14-cross-account-search.md §8 — per-call we emit:
//   - 1 outer row (this fn, `event: "cross_account_aggregate"`)
//   - N inner rows (existing `auditEnd`, one per per-account sub-call,
//     INCLUDING failures with `status: "failed"`)
// The outer + inner rows correlate via the outer `args_hash` (SHA256 of the
// full outer args including `accounts?` filter) and the time window. Account
// counts (`account_count_*`) are integers, NEVER identities — anti-enumeration.
export interface AuditCrossAccountAggregateContext {
  tool: string;
  argsHash: string;
  accountCountQueried: number;
  accountCountSucceeded: number;
  accountCountFailed: number;
}

/** Append one forensic JSONL line for a cross-account `_all` tool call.
 *
 *  Same swallow-errors pattern as auditShareEvent / auditShareDeniedEvent /
 *  auditRecipientDeniedEvent — never block on append failure.
 *
 *  `event: "cross_account_aggregate"` discriminator parallels existing
 *  forensic event lines so a log reader can grep cross-account calls
 *  separately from the standard per-account `auditEnd` lines. NO plaintext
 *  identities are recorded here — the per-account `account` field belongs
 *  on the inner rows (`auditEnd`). */
export async function auditCrossAccountAggregate(
  ctx: AuditCrossAccountAggregateContext,
): Promise<void> {
  const line =
    JSON.stringify({
      ts: new Date().toISOString(),
      tool: ctx.tool,
      event: "cross_account_aggregate",
      args_hash: ctx.argsHash,
      account_count_queried: ctx.accountCountQueried,
      account_count_succeeded: ctx.accountCountSucceeded,
      account_count_failed: ctx.accountCountFailed,
    }) + "\n";
  try {
    await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
    await fs.appendFile(auditPath(), line, { mode: 0o600 });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`[safespace] audit cross-account-aggregate append failed: ${msg}`);
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
  /** v1.36 BLOCKER 2 (audit actor) — the human operator who drove this call,
   *  resolved from $SAFESPACE_OPERATOR_ID (identity/operator-id.ts). Distinct
   *  from `email` (the Google account): one operator may drive several
   *  accounts; one account may be co-managed by several operators. Optional so
   *  existing callers / single-user installs need no change — `auditEnd` emits
   *  `operator: null` when unset (Q4 zero-impact default). Plaintext on the row
   *  (Q3), mirroring `account`. See docs/v1.36-identity-tenancy-layer.md §5.1. */
  operator?: string | null;
}

export function auditStart(_ctx: AuditStartContext): void {
  // Intentional no-op: the only durable record is `auditEnd` so each tool
  // call produces exactly one JSONL line (write-amplification doesn't help
  // when status is the field we care about). Kept as a function so Step 6
  // can wire pre-call tracing without churning the with-context call site.
}

/** v1.16 Phase 2b — Comment-post audit metadata channel for the
 *  youtube_video_comment_post / youtube_comment_reply handlers.
 *
 *  Captured via `ctx.audit.record("commentPostMeta", …)` (with-context.ts; see
 *  ToolContext in types.ts). Threaded into the standard `auditEnd()` JSONL
 *  row — these fields appear on the SAME line as the per-call row, NOT as
 *  a separate event. Mirrors v1.15 Phase 3 `resolved_recipient_hash` shape
 *  (output channel + conditional field emission).
 *
 *  Field semantics (per docs/v1.16-youtube-api.md §7 Phase 2 audit):
 *
 *    target_video_hash — plain SHA-256 (NOT HMAC) hex of args.video_id.
 *      Forensic pivot: "which videos did Claude attempt to post on".
 *      Plain SHA-256 matches the `args_hash` algorithm convention; HMAC is
 *      reserved for the `target_email_hash` family (share_forensic /
 *      recipient_denied_by_policy) where dictionary-attack defense
 *      matters more than algorithm uniformity. Video IDs are 11-char
 *      opaque base64-ish handles — keyspace is large enough that an
 *      unsalted hash is not meaningfully dictionary-attackable.
 *
 *    parent_comment_id_hash — plain SHA-256 hex of args.parent_comment_id
 *      (youtube_comment_reply ONLY). Per-thread forensic pivot — pairs
 *      with `target_video_hash` to correlate replies. ABSENT on
 *      `youtube_video_comment_post` rows (top-level comments have no
 *      parent comment ID).
 *
 *    comment_length — integer length of args.text (NOT bytes; raw
 *      character count). Quota + anti-spam forensic trail. Plaintext
 *      comment text NEVER appears in audit. Forensic question "what did
 *      Claude actually post?" requires inspecting the live YouTube
 *      comment (visible to anyone with the comment URL).
 *
 *    policy_decision — locked enum:
 *      "allowed"                              — all 4 gates passed; SDK call
 *                                               succeeded; counter incremented
 *      "denied_no_allowlist"                  — env var unset/empty (state.kind="off")
 *      "denied_not_in_allowlist"              — target resolved but not in allowlist
 *      "denied_tier"                          — proxy tier gate (defense-in-depth;
 *                                               normally caught by tools/list filter)
 *      "denied_burst_limit"                   — per-session counter exceeded
 *      "denied_outbound_sanitize_rejected"    — outbound sanitize raised
 *
 *  ABSENT (field-not-emitted) when the call is NOT a comment-post tool —
 *  pre-Phase-2b tools never set these and auditEnd skips them. */
export interface CommentPostAuditMeta {
  target_video_hash: string;
  parent_comment_id_hash?: string;
  comment_length: number;
  policy_decision:
    | "allowed"
    | "denied_no_allowlist"
    | "denied_not_in_allowlist"
    | "denied_tier"
    | "denied_burst_limit"
    | "denied_outbound_sanitize_rejected";
}

/** v1.17 Phase 1 — Calendar-mutation audit metadata channel for the
 *  calendar_update_event / calendar_delete_event / calendar_respond handlers.
 *
 *  Captured via `ctx.audit.record("calendarMutationMeta", …)` (with-context.ts; see
 *  ToolContext in types.ts). Threaded into the standard `auditEnd()` JSONL
 *  row — these fields appear on the SAME line as the per-call row, NOT as
 *  a separate event. Mirrors v1.16 Phase 2b `commentPostMeta` shape (output
 *  channel + conditional field emission). Field PRESENCE itself signals
 *  "this is a calendar-mutation call" (mirror v1.15 / v1.16 PRESENCE-as-signal
 *  pattern; see docs/v1.17-deferred-completion.md §5 + §8 hook #7).
 *
 *  Field semantics (per docs/v1.17-deferred-completion.md §5):
 *
 *    target_event_hash — plain SHA-256 (NOT HMAC) hex of args.event_id.
 *      Forensic correlation key across update/delete/respond sessions —
 *      "which event was touched". Plain SHA-256 matches the `args_hash`
 *      algorithm convention; HMAC is reserved for the `target_email_hash`
 *      family where the keyspace is small enough that dictionary attacks
 *      matter. Calendar event IDs are large opaque server-generated
 *      handles — unsalted hash is not meaningfully attackable.
 *
 *    policy_decision — small enum for v1.17 Phase 1 (no allowlist / burst
 *      gates on Calendar mutation):
 *        "allowed"                            — tier+scope passed; SDK call
 *                                               initiated (forensically
 *                                               recorded BEFORE the SDK
 *                                               call per hook #7 — survives
 *                                               SDK 5xx failure)
 *        "denied_tier"                        — proxy tier gate caught a
 *                                               write tool at tier=read
 *                                               (defense-in-depth)
 *        "denied_outbound_sanitize_rejected"  — reserved for future Phase
 *                                               1c+; not emitted in Phase 1
 *
 *    rsvp_response — closed-enum RSVP value passed to calendar_respond.
 *      EMITTED ONLY by calendar_respond (never by calendar_update_event /
 *      calendar_delete_event — those leave it undefined). Closes the
 *      forensic gap identified in PR #138 pre-merge review sec-M1: prior
 *      impl recorded `target_event_hash + policy_decision` but log readers
 *      could NOT tell which RSVP value Claude attempted. Per design §5
 *      this field is part of the calendar_respond audit row. Closed-enum
 *      value (no PII) — same {accepted|declined|tentative|needsAction} set
 *      validated by the handler at the API boundary. ABSENT on update/
 *      delete rows; PRESENCE itself disambiguates "this is a respond row".
 *
 *  ABSENT (field-not-emitted) when the call is NOT a calendar-mutation
 *  tool — pre-v1.17 tools never set this and auditEnd skips it. */
export interface CalendarMutationAuditMeta {
  target_event_hash: string;
  policy_decision:
    | "allowed"
    | "denied_tier"
    | "denied_outbound_sanitize_rejected";
  /** PR #138 sec-M1 — RSVP value for calendar_respond ONLY. Other 2 calendar
   *  mutation tools (update / delete) MUST NOT set this. Closed-enum,
   *  no PII. */
  rsvp_response?: "accepted" | "declined" | "tentative" | "needsAction";
}

/** v1.17 Phase 2 — Docs-modify audit metadata channel for the
 *  docs_modify_structured handler. Captured via `ctx.audit.record("docsModifyMeta", …)`
 *  (with-context.ts; see ToolContext in types.ts). Threaded into the
 *  standard `auditEnd()` JSONL row — these fields appear on the SAME line
 *  as the per-call row, NOT as a separate event. Mirrors v1.16 / v1.17
 *  Phase 1 PRESENCE-as-signal pattern (field presence on the row signals
 *  "this is a docs-modify call"; mutually exclusive with `commentPostMeta`
 *  and `calendarMutationMeta` per call).
 *
 *  Field semantics (per docs/v1.17-deferred-completion.md §5):
 *
 *    target_document_id_hash — plain SHA-256 (NOT HMAC) hex of args.document_id.
 *      Forensic correlation key — "which doc was edited". Plain SHA-256
 *      matches the args_hash algorithm convention; HMAC is reserved for the
 *      target_email_hash family (share_forensic / recipient_denied_by_policy)
 *      where the keyspace is small enough that dictionary attacks matter.
 *      Doc IDs are large opaque server-generated handles — unsalted hash is
 *      not meaningfully attackable.
 *
 *    modification_count — integer (requests.length). Forensic question
 *      "how many requests did Claude batch in this call?".
 *
 *    request_types_csv — comma-joined request type names IN CALLER-SUPPLIED
 *      ORDER (NOT sorted). Order is forensically relevant per design §5 +
 *      F15: "did replaceAllText run before or after deleteContentRange?"
 *      changes what was actually mutated. Sorting would destroy this. Caller
 *      may legitimately have N occurrences of same type — duplicates
 *      preserved.
 *
 *    total_text_replacements — integer (sum of occurrencesChanged across
 *      all replaceAllText requests in the batch, captured from Google's
 *      replies[i].replaceAllText.occurrencesChanged). Forensic question
 *      "did Claude rewrite the whole doc?" answerable from audit alone (no
 *      hard cap; audit visibility IS the defense per design §2.4 + §8 hook
 *      #12). ABSENT when no replaceAllText was in the batch OR when the SDK
 *      call failed before a reply was available (denied_tier rows, SDK 5xx
 *      with no reply body).
 *
 *    policy_decision — small enum for v1.17 Phase 2:
 *      "allowed"                            — tier+per-request gates passed;
 *                                             SDK call initiated (forensically
 *                                             recorded BEFORE the SDK call per
 *                                             hook #7 — survives SDK 5xx)
 *      "denied_tier"                        — proxy tier gate caught a write
 *                                             tool at tier=read (defense-in-depth)
 *      "denied_outbound_sanitize_rejected"  — reserved forward-compat; not
 *                                             emitted in Phase 2 (no outbound
 *                                             sanitize on docs surface today)
 *
 *  ABSENT (field-not-emitted) when the call is NOT docs_modify_structured —
 *  pre-v1.17-Phase-2 tools never set this and auditEnd skips it. */
export interface DocsModifyAuditMeta {
  target_document_id_hash: string;
  modification_count: number;
  request_types_csv: string;
  total_text_replacements?: number;
  policy_decision:
    | "allowed"
    | "denied_tier"
    | "denied_outbound_sanitize_rejected";
}

/** v1.17 Phase 3 — Comment-delete audit metadata channel for the
 *  youtube_comment_delete handler. Captured via `ctx.audit.record("commentDeleteMeta", …)`
 *  (with-context.ts; see ToolContext in types.ts). Threaded into the standard
 *  `auditEnd()` JSONL row — these fields appear on the SAME line as the
 *  per-call row, NOT as a separate event. Mirrors v1.16 / v1.17 Phase 1+2
 *  PRESENCE-as-signal pattern (field presence on the row signals "this is a
 *  comment-DELETE call"; mutually exclusive with `commentPostMeta` /
 *  `calendarMutationMeta` / `docsModifyMeta` per call).
 *
 *  Why a NEW field vs union into `commentPostMeta.policy_decision` (per
 *  design §5 + §8 hook #13): conflating two semantically distinct operations
 *  (post vs delete) into the same `commentPostMeta.policy_decision` enum
 *  would break audit forensic queries (`grep commentPostMeta` for posts vs
 *  `grep commentDeleteMeta` for deletes). PRESENCE-as-signal pattern:
 *  `commentDeleteMeta` PRESENT on a row signals "this is a comment-delete
 *  row", `commentPostMeta` PRESENT signals "this is a comment-post row".
 *  Mutually exclusive per call (enforced via with-context.ts runtime
 *  assertion — see hook B from Phase 3 prompt).
 *
 *  Field semantics (per docs/v1.17-deferred-completion.md §2.5 + §5):
 *
 *    target_comment_id_hash — plain SHA-256 (NOT HMAC) hex of args.comment_id.
 *      Forensic correlation key — "which comment was deleted". Matches v1.16
 *      `target_video_hash` convention (plain SHA-256 on opaque server-generated
 *      IDs; HMAC reserved for the small-keyspace email family).
 *
 *    policy_decision — small enum for v1.17 Phase 3:
 *        "deleted"      — tier+scope passed; SDK call initiated (forensically
 *                         recorded BEFORE the SDK call per hook #7 — survives
 *                         SDK 5xx failure). "deleted" semantically distinguishes
 *                         from `commentPostMeta`'s "allowed" — same channel
 *                         conceptually (gates passed) but different operation.
 *        "denied_tier"  — proxy tier gate caught the write tool at tier=read
 *                         (defense-in-depth; recovery-bypass per §2.5 +
 *                         §8 hook #4 does NOT cover tier — tier is the floor).
 *
 *  ABSENT (field-not-emitted) when the call is NOT youtube_comment_delete —
 *  pre-v1.17-Phase-3 tools never set this and auditEnd skips emission. */
export interface CommentDeleteAuditMeta {
  target_comment_id_hash: string;
  policy_decision: "deleted" | "denied_tier";
}

/** v1.19 Phase 2b — `TasksMutationAuditMeta` for tasks_create / tasks_update /
 *  tasks_delete. Captured via `ctx.audit.record("tasksMutationMeta", …)` (with-context.ts;
 *  see ToolContext in types.ts). Threaded into the standard `auditEnd()` JSONL
 *  row — these fields appear on the SAME line as the per-call row, NOT as a
 *  separate event. Mirrors v1.17 Phase 1+2+3 PRESENCE-as-signal pattern
 *  (field presence on the row signals "this is a tasks mutation call";
 *  mutually exclusive with the other 4 metas per call).
 *
 *  Field semantics (per docs/v1.19-tasks-api.md §6):
 *
 *    target_tasklist_hash — plain SHA-256 (NOT HMAC) hex of args.tasklist_id.
 *      Forensic correlation key — "which task list was touched". Plain SHA-256
 *      matches the args_hash algorithm convention; HMAC is reserved for the
 *      target_email_hash family.
 *
 *      Minor leak ack (sec-L1 from design): tasklist IDs include the sentinel
 *      value "@default" (well-known constant). An audit-log reader can
 *      recognize SHA256("@default") rows, which leaks "user used default
 *      tasklist" — minor signal; acceptable trade-off vs HMAC complexity.
 *      Mirrors v1.16 target_video_hash plain-SHA-256 rationale.
 *
 *    target_task_hash — plain SHA-256 hex of args.task_id. ABSENT on `create`
 *      (no task ID yet) — the field PRESENCE itself signals
 *      "this is an update or delete row, not a create row" at the audit-log
 *      reader layer (in addition to `operation` enum).
 *
 *    operation — closed enum, discriminates the tasks mutation rows:
 *      "create" | "update" | "delete" | "move" | "clear". The first three
 *      are v1.19 Phase 2b; "move"/"clear" are the v1.47 surface-completion
 *      tools (tasks.tasks.move / tasks.tasks.clear), both ABOVE-board
 *      non-permanent ops riding this SAME channel (NOT a new audit channel —
 *      a value-union extension, like the v1.32 forensic field). Only
 *      "delete" drives the v1.18 deletes density alert (`safespace audit
 *      deletes`) — see classifyDestructive 3rd branch; move/clear are NOT
 *      destructive-delete and correctly do not inflate it.
 *
 *    policy_decision — small enum, binary shape matching
 *      calendarMutationMeta / docsModifyMeta:
 *        "allowed"      — tier+scope passed; SDK call initiated (forensically
 *                          recorded BEFORE the SDK call per design §8 hook #7
 *                          — survives SDK 5xx failure)
 *        "denied_tier"  — proxy tier gate caught a write tool at tier=read
 *                          (defense-in-depth)
 *
 *      NOTE (sec-M3 clarification from design §6): `tasks_delete` rows use
 *      `operation === "delete"` (NOT `policy_decision === "deleted"`) to
 *      discriminate delete operations. Intentionally diverges from v1.17
 *      `commentDeleteMeta` (which used policy_decision="deleted" because it
 *      had no dedicated `operation` field). Future channels should follow
 *      the v1.19 pattern (binary policy_decision + separate operation enum).
 *
 *  ABSENT (field-not-emitted) when the call is NOT a tasks mutation tool —
 *  pre-v1.19-Phase-2b tools never set this and auditEnd skips emission. */
export interface TasksMutationAuditMeta {
  target_tasklist_hash: string;
  target_task_hash?: string;
  operation: "create" | "update" | "delete" | "move" | "clear";
  policy_decision: "allowed" | "denied_tier" | "denied_target_not_in_allowlist";
}

/** v1.20 Phase 1b-2 — `SheetsMutationAuditMeta` for sheets_create /
 *  sheets_append_values. Captured via `ctx.audit.record("sheetsMutationMeta", …)`
 *  (with-context.ts; see ToolContext in types.ts). Threaded into the standard
 *  `auditEnd()` JSONL row — these fields appear on the SAME line as the
 *  per-call row, NOT as a separate event. Mirrors v1.17 Phase 1+2+3 / v1.19
 *  Phase 2b PRESENCE-as-signal pattern (field presence on the row signals
 *  "this is a sheets mutation call"; mutually exclusive with the other 5
 *  metas per call).
 *
 *  Field semantics (per docs/v1.20-sheets-api.md §5):
 *
 *    target_spreadsheet_id_hash — plain SHA-256 (NOT HMAC) hex of
 *      args.spreadsheet_id (`sheets_append_values`) OR of the spreadsheet_id
 *      assigned by Google (`sheets_create`, patched in post-SDK).
 *
 *      For `sheets_create` the audit-before-SDK pattern emits a sentinel
 *      `"<pending-create>"` value first (forensic survives 5xx); on SDK
 *      success the recorder is called again with the real ID hash
 *      (last-write-wins via with-context.ts).
 *
 *      Minor leak ack (sec-L1 from design): spreadsheet IDs are ~40-100-char
 *      Drive file IDs; opaque enough that hash-recognition attacks are not
 *      practical. Plain SHA-256 matches the `args_hash` algorithm convention;
 *      HMAC is reserved for `target_email_hash` family. Mirrors v1.16
 *      target_video_hash / v1.19 target_tasklist_hash plain-SHA-256 rationale.
 *
 *    target_range_hash — plain SHA-256 hex of the normalized A1-notation
 *      `range` string. ABSENT on `create` (no range yet). PRESENT on
 *      `append_values` (and Phase 2c update_values / batch_update). Hashing
 *      is over the POST-strict-parse canonical form.
 *
 *    operation — closed enum (Phase 1b-2 ships 2; remaining values reserved
 *      for Phase 2c+):
 *        "create"           — sheets_create
 *        "append_values"    — sheets_append_values
 *        "update_values"    — Phase 2c
 *        "batch_update"     — Phase 2c
 *
 *      Drives nothing today (no sheets delete tool); included for parity
 *      with v1.19 tasksMutationMeta + future audit deletes discriminator.
 *
 *    policy_decision — small enum, binary shape matching
 *      calendarMutationMeta / docsModifyMeta / tasksMutationMeta:
 *        "allowed"      — tier+scope passed; SDK call initiated (forensically
 *                          recorded BEFORE the SDK call per design §5 +
 *                          v1.17 §8 hook #7 / v1.19 §10 hook #11 —
 *                          survives SDK 5xx failure).
 *        "denied_tier"  — proxy tier gate caught a write tool at tier=read
 *                          (defense-in-depth; normally caught by tools/list
 *                          filter).
 *
 *      FORMULA-rejection rows are recorded via -32028 MCPError + thrown
 *      pre-meta; they do NOT set sheetsMutationMeta at all (the read-tier
 *      `value_render_option=FORMULA` rejection happens in sheets_get_values,
 *      which is read tier and never records sheets-mutation meta anyway).
 *
 *  ABSENT (field-not-emitted) when the call is NOT a sheets mutation tool —
 *  pre-v1.20-Phase-1b-2 tools never set this and auditEnd skips emission. */
export interface SheetsMutationAuditMeta {
  target_spreadsheet_id_hash: string;
  target_range_hash?: string;
  operation: "create" | "append_values" | "update_values" | "batch_update";
  /** v1.21 Phase 1b extension — adds `denied_formula_rejected` enum value.
   *  Emitted when `sheets_update_values` or `sheets_batch_update` rejects a
   *  USER_ENTERED cell whose outer function is in the 11-function REJECT
   *  list (`src/sheets/formula-reject.ts`). Forensic correlation key with
   *  the new -32029 MCPError row. */
  policy_decision: "allowed" | "denied_tier" | "denied_formula_rejected";
  /** v1.21 Phase 1b — ONLY for batch_update; CSV of allowed request types
   *  in caller-supplied ORDER (mirror v1.17 docsModifyMeta convention).
   *  Forensically relevant per design §2.2 Order preservation — "did
   *  deleteSheet run before addSheet?" affects which sheetIds were valid
   *  mid-batch. Duplicate types preserved. */
  request_types_csv?: string;
  /** v1.21 Phase 1b — ONLY for batch_update; cumulative cell-write count
   *  across all updateCells + repeatCell requests in the batch. Mirror v1.17
   *  `total_text_replacements` blast-radius pattern. Forensically answerable
   *  "did Claude rewrite the whole sheet?" from audit alone. */
  total_cell_writes?: number;
  /** v1.21 Phase 1b — ONLY when policy_decision === "denied_formula_rejected".
   *  UPPERCASED function name from the closed 11-item REJECT set (e.g.,
   *  "IMPORTRANGE"). Bounded value space — no PII echo concern. Operator-
   *  facing forensic — answers "which function did the offending call try
   *  to invoke". Mirror v1.21 -32029 errorData.rejected_formula_function. */
  rejected_formula_function?: string;
  /** v1.32 Phase 2 — OPTIONAL forensic field. PRESENT only when
   *  policy_decision === "denied_formula_rejected" AND the rejected cell
   *  used non-ASCII source bytes (Default_Ignorable / Bidi / Cyrillic /
   *  Greek) that `applyHomoglyphPipeline` transformed. ABSENT on pure-ASCII
   *  REJECTs — preserves audit row bytes IDENTICAL to v1.31 for the ASCII
   *  attack family (Q3 LOCK fully preserved; PRESENCE-as-signal mirror
   *  v1.24 `error_code?` + v1.20 `target_range_hash?`).
   *
   *  Carries the LITERAL pre-normalize UTF-8 bytes (in input order) that
   *  the homoglyph pipeline rewrote — the dedicated forensic axis that lets
   *  an operator distinguish a user-typo / autocomplete ASCII REJECT (LOW
   *  signal) from a prompt-injection-driven homoglyph smuggle (HIGH signal),
   *  WITHOUT conflating attack-source with the canonical ASCII
   *  `rejected_formula_function` (Q4 LOCK preserves single-token grouping
   *  for `safespace audit suspicious`). Closes v1.30 INFO-2 carry-forward.
   *
   *  Audit log viewers MUST handle Unicode (jq / vim / less are all native
   *  UTF-8). The captured bytes are ONLY the chars `applyHomoglyphPipeline`
   *  transformed — a narrow predefined codepoint set (~44 Cyrillic/Greek
   *  confusers in HOMOGLYPH_MAP + ~79 invisible chars in DEFAULT_IGNORABLE_RE /
   *  BIDI_OVERRIDE_RE) — captured anywhere in the cell (INCLUDING inside a
   *  REJECTED function's quoted arguments, e.g. `=IMPORTRANGE("і","і")` →
   *  "іі"). Arbitrary cell content (ASCII text / numbers / URLs / name+phone
   *  PII) CANNOT reach this field: ASCII hits the pipeline fast-path and
   *  non-homoglyph non-ASCII is passed through untransformed, so neither is
   *  accumulated. Size is bounded by the per-cell 50KB cap. See design §3.6 +
   *  §3.7 (NOTE: §3.7's "identifier chars only" framing is imprecise — the
   *  real bound is the homoglyph-class codepoint set, not the FORMULA_PREFIX_RE
   *  function-name match scope; corrected here per v1.32 Phase 2 sec review M1). */
  rejected_formula_homoglyph_source?: string;
  /** v1.41 — OPTIONAL forensic discriminator. PRESENT (`true`) only when
   *  policy_decision === "denied_formula_rejected" AND the REJECT fired on
   *  the STEP 5 nested/sibling scanner (a wrapper smuggle like
   *  `=SUM(IMPORTRANGE(...))` / `=A1+IMPORTRANGE(...)`) rather than the STEP 4
   *  direct outer-name match. ABSENT on direct attacks — preserves audit row
   *  bytes IDENTICAL to v1.40 for the dominant direct-attack family
   *  (PRESENCE-as-signal, mirror `rejected_formula_homoglyph_source?`).
   *  Literal `true`; its presence is the signal — a bare flag with no payload
   *  and no PII. Serialized AFTER rejected_formula_function and BEFORE
   *  rejected_formula_homoglyph_source (Q3 LOCK forensic order). */
  rejected_formula_nested?: true;
}

/** v1.48 B4 — `PlaylistMutationAuditMeta` for the 3 non-destructive YouTube
 *  playlist WRITE tools (`youtube_playlist_create` / `youtube_playlist_update`
 *  / `youtube_playlist_item_insert`). Captured via
 *  `ctx.audit.record("playlistMutationMeta", …)` (with-context.ts; see ToolContext in
 *  types.ts). Threaded into the standard `auditEnd()` JSONL row — these fields
 *  appear on the SAME line as the per-call row, NOT as a separate event.
 *  Mirrors the v1.19 tasksMutation / v1.20 sheetsMutation PRESENCE-as-signal
 *  pattern (field presence on the row signals "this is a playlist mutation
 *  call"; mutually exclusive with the other 6 metas per call).
 *
 *  Why a NEW channel (not a value-union into an existing one, unlike v1.46/
 *  v1.47): there is no pre-existing YouTube-playlist channel. `commentPostMeta`
 *  is comment-shaped (`target_video_hash` + `comment_length`); reusing it for
 *  playlists would be a semantic mismatch. The 7th channel is the honest shape.
 *
 *  Field semantics (per docs/v1.48-youtube-playlists.md §3):
 *
 *    target_playlist_hash — plain SHA-256 (NOT HMAC) hex. Present on EVERY row:
 *      update / item_insert hash `args.playlist_id`; create uses the
 *      `sheets_create` 2-step (sha256("<pending-create>") BEFORE the SDK call,
 *      then the real `res.data.id` hash AFTER success — Map last-write-wins).
 *      Always-present ⇒ it is the channel `flatHash` for the
 *      `cli/audit/policy-decisions.ts` auto-discovery.
 *
 *    target_video_hash — plain SHA-256 hex of args.video_id. PRESENT ONLY on
 *      `playlist_item_insert`; its PRESENCE discriminates item-insert rows from
 *      create/update rows (in addition to the `operation` enum).
 *
 *    operation — closed enum discriminating the playlist mutation rows:
 *      v1.48 non-destructive: "playlist_create" | "playlist_update" |
 *      "playlist_item_insert". v1.49 destructive slice extends this union with
 *      "playlist_item_remove" (RECOVERABLE — re-insert) + "playlist_delete"
 *      (PERMANENT — no YouTube playlist trash). This is a value-union extension
 *      of the SAME channel (v1.47 tasks move/clear precedent), NOT a new
 *      channel: the serializer emits `operation` generically so it is UNCHANGED
 *      and `AUDIT_META_CHANNELS` stays 7. Only `cli/audit/deletes.ts`
 *      `classifyDestructive` gains a branch — for "playlist_delete" ONLY
 *      (matched via `operation`, NOT `policy_decision`, mirror tasks_delete
 *      sec-M3); "playlist_item_remove" is recoverable so it is deliberately NOT
 *      counted, exactly like tasks_clear / tasks_move.
 *
 *    policy_decision — binary, matching tasksMutation / calendarMutation:
 *        "allowed"     — tier+scope passed; SDK call initiated (recorded BEFORE
 *                         the SDK call so it survives an SDK 5xx).
 *        "denied_tier" — proxy tier gate caught a write tool at tier=read
 *                         (defense-in-depth). */
export interface PlaylistMutationAuditMeta {
  target_playlist_hash: string;
  target_video_hash?: string;
  operation:
    | "playlist_create"
    | "playlist_update"
    | "playlist_item_insert"
    | "playlist_item_remove"
    | "playlist_delete";
  policy_decision: "allowed" | "denied_tier";
}

/** v1.106 — `VideoMutationAuditMeta` for the `youtube_video_update` tool
 *  (videos.update snippet metadata: title / description / tags). Captured via
 *  `ctx.audit.record("videoMutationMeta", …)` (with-context.ts; see ToolContext
 *  in types.ts). Threaded into the standard `auditEnd()` JSONL row — same line
 *  as the per-call row, NOT a separate event. Mirrors the PRESENCE-as-signal
 *  pattern (field presence on the row signals "this is a video-metadata mutation
 *  call"; mutually exclusive with the other 7 metas per call).
 *
 *  Why a NEW (8th) channel, not a value-union into an existing one: there is no
 *  pre-existing video-METADATA-write channel. `commentPostMeta` is comment-shaped
 *  (`target_video_hash` + `comment_length`) and PRESENT signals "comment-post
 *  row"; `playlistMutationMeta` is playlist-shaped (`target_playlist_hash`
 *  always-present). A video-metadata write is video-shaped but neither — the 8th
 *  channel is the honest shape (same reasoning v1.48 added the 7th for playlists).
 *
 *  Field semantics:
 *    target_video_hash — plain SHA-256 (NOT HMAC) hex of args.video_id. Present on
 *      EVERY row ⇒ it is the channel `flatHash` for cli/audit/policy-decisions.ts.
 *    operation — single-value enum "video_update" (the channel's one operation;
 *      a closed enum for forensic-grep symmetry with the playlist/tasks channels).
 *    title_length / description_length / tag_count — non-identifying integers
 *      (NEVER the plaintext title/description/tags); title_length always present,
 *      description_length present only when a description was supplied, tag_count
 *      present only when tags were supplied (PRESENCE mirrors the optional fields).
 *      These are the PRE-sanitize INPUT lengths (the raw-length convention shared by
 *      commentPost/playlist); outboundSanitize REJECTS rather than shortening, so on
 *      the allowed path they match what is sent modulo a rare NFC char-count shift.
 *    policy_decision — "allowed" (tier+scope+target+sanitize passed; recorded
 *      BEFORE the SDK call so it survives an SDK 5xx) | "denied_tier" (proxy tier
 *      gate caught a write tool at tier=read, defense-in-depth) |
 *      "denied_outbound_sanitize_rejected" (a field failed the 6-step REJECT).
 *      The target-allowlist + F3a denials throw an MCPError (-32052 / -32035) and
 *      are captured via the row's errorCode (github-write model), NOT here. */
export interface VideoMutationAuditMeta {
  target_video_hash: string;
  operation: "video_update";
  title_length: number;
  description_length?: number;
  tag_count?: number;
  policy_decision:
    | "allowed"
    | "denied_tier"
    | "denied_outbound_sanitize_rejected";
}

/** v1.18 Phase 1 — centralized registry for the audit-meta channels.
 *
 *  Maps the `AuditEndContext` field name (the "ctx-side key") to its
 *  per-channel metadata: the short channel label used in mutual-exclusion
 *  warnings + the flattened-row hash field name used by `cli/audit/
 *  policy-decisions.ts` to discriminate flattened audit rows.
 *
 *  v1.19 Phase 2b refactor (sec-L4 drift class closure): registry value
 *  expanded from bare `string` to `{label, flatHash}` so the flattened-row
 *  detector in `policy-decisions.ts` becomes fully registry-driven. Adding
 *  a 6th channel auto-extends both branches without hand-edit drift.
 *
 *  Sentinel test (`audit.test.ts`) pins length === 6 (was 5 pre-v1.20, was
 *  4 pre-v1.19). Adding a 7th channel forces re-acknowledgment at FOUR call
 *  sites — ALL FOUR now TypeScript-enforced as of v1.25 Phase 2:
 *    1. add the entry here (TypeScript-enforced via `satisfies Record<…>`),
 *    2. add the corresponding key to the `localMetas` object in
 *       `with-context.ts`'s finally block (TypeScript enforces this via
 *       `Record<keyof typeof AUDIT_META_CHANNELS, unknown>`),
 *    3. add the optional field to `AuditEndContext` + the recorder helper
 *       on `ToolContext`,
 *    4. v1.25 Phase 2 Item 2 — site 4 is now TypeScript-enforced: declare
 *       a `serialize: (meta) => Record<string, unknown>` on the registry
 *       entry; the satisfies clause requires it. `auditEnd()` iterates
 *       AUDIT_META_CHANNELS and dispatches automatically. Closes v1.19
 *       NEW-3 PERMANENTLY at compile time. Belt-and-braces regression net
 *       (v1.22 audit roundtrip tests; Q3 LOCKED v1.25 §2.2) stays UNTOUCHED.
 *  See docs/v1.18-operational-quality.md §2.3 + sec-rev hook #8 +
 *  docs/v1.19-tasks-api.md §6 + docs/v1.25-multi-item-batch.md §2.2. */
/** v1.24 Phase 1 — per-channel suspicious-decision classification (Item 1).
 *  Locked Q2 Option A — nested-object per-channel value shape.
 *
 *  Each channel declares which of its `policy_decision` enum values map to
 *  the suspicious-track confidence buckets in `cli/audit/suspicious.ts`:
 *
 *    - high              — HIGH-confidence direct REJECT signals; on by default
 *    - medium_allowlist  — MEDIUM allowlist denials; opt-in
 *    - medium_burst      — MEDIUM burst-limit denials; opt-in
 *    - low_tier          — LOW tier denials; opt-in
 *
 *  Adding a new audit-meta channel OR a new `policy_decision` value to an
 *  existing channel is the SAME edit site — extend the channel's
 *  `suspiciousDecisions` here, and `cli/audit/suspicious.ts` classifier
 *  picks it up automatically (closes the 4th hardcoded-enum drift site
 *  flagged at v1.23 Q5 LOCKED). Error-code class signals (scope_mismatch
 *  / recipient_lookup_failed / *_burst_limit_exceeded) STAY hardcoded in
 *  suspicious.ts — they are top-level MCPError codes, NOT per-channel
 *  `policy_decision` values. */
export type SuspiciousClassification = {
  high?: ReadonlyArray<string>;
  medium_allowlist?: ReadonlyArray<string>;
  medium_burst?: ReadonlyArray<string>;
  low_tier?: ReadonlyArray<string>;
};

/** v1.27 Phase 1 Item 3 (NEW-11) — phantom-typed registry-key ↔ meta-type
 *  pairing. Single source of truth: each KEY MUST match a channel name in
 *  `AUDIT_META_CHANNELS`, each VALUE is that channel's concrete meta
 *  interface. Order matches `AUDIT_META_CHANNELS` declaration order for
 *  symmetry.
 *
 *  Strengthens v1.25 Phase 2's `SerializeFn = (meta: unknown) → …` typing
 *  (which left the registry-key ↔ meta-type pairing as a code-review
 *  convention) into a compile-time invariant via the mapped-type
 *  satisfies clause on `AUDIT_META_CHANNELS` (see below).
 *
 *  Closes v1.25 Phase 2 dual-review security DEFER-1 observation: prior
 *  shape required hand-cast `meta as ConcreteAuditMeta` in each
 *  serialize fn body — a copy-paste cross-key error (e.g., a serialize
 *  body for `commentPostMeta` accidentally written against
 *  `CalendarMutationAuditMeta`) compiled silently and produced malformed
 *  audit rows at runtime, surfaced only via field probe (or never if the
 *  channel path was untested).
 *
 *  Adding a 7th channel:
 *    1. add the entry to `AUDIT_META_CHANNELS`
 *    2. add the corresponding `MetaMap` entry (TypeScript-enforced —
 *       missing → "Property 'xMeta' is missing in type 'MetaMap'")
 *    3. typing the serialize fn parameter with a different channel's
 *       meta interface fails compile ("Type '(meta: WrongMeta) → …' is
 *       not assignable to type 'SerializeFn<MetaMap["xMeta"]>'") */
export interface MetaMap {
  commentPostMeta: CommentPostAuditMeta;
  calendarMutationMeta: CalendarMutationAuditMeta;
  docsModifyMeta: DocsModifyAuditMeta;
  commentDeleteMeta: CommentDeleteAuditMeta;
  tasksMutationMeta: TasksMutationAuditMeta;
  sheetsMutationMeta: SheetsMutationAuditMeta;
  playlistMutationMeta: PlaylistMutationAuditMeta;
  videoMutationMeta: VideoMutationAuditMeta;
}

/** v1.25 Phase 2 Item 2 — per-channel `serialize` function type. Pure
 *  mapping from meta-input to JSONL-output field record (Q2 LOCKED:
 *  pure-return vs mutation). Each channel implements its own
 *  serialize fn; `auditEnd` iterates the registry and `Object.assign`s
 *  the result into the row payload. Closes v1.19 NEW-3 "manual 4th
 *  site" drift class PERMANENTLY at the TypeScript-enforced level —
 *  the satisfies clause requires every channel to declare `serialize`,
 *  so adding a 7th channel without a serialize fn fails compile.
 *
 *  Belt-and-braces layer: v1.22 audit roundtrip tests stay UNCHANGED
 *  as a regression net (Q3 LOCKED). Layer 1 (this satisfies clause)
 *  enforces site 4 EXISTS; Layer 2 (roundtrip tests) enforces site 4
 *  EMITS THE RIGHT FIELDS for every channel's MAX + MIN field-set.
 *
 *  v1.27 Phase 1 Item 3 (NEW-11) — parameterized over the meta type `M`
 *  (was `SerializeFn = (meta: unknown) => …` in v1.25 Phase 2). Combined
 *  with the `{[K in keyof MetaMap]: {…serialize: SerializeFn<MetaMap[K]>}}`
 *  mapped-type satisfies clause on AUDIT_META_CHANNELS, this strengthens
 *  registry-key ↔ meta-type pairing from a code-review convention to a
 *  COMPILE-TIME invariant. Each per-channel impl is INTENTIONALLY left
 *  with parameter type `unknown` (+ inline `const m = meta as
 *  ConcreteAuditMeta` cast) to preserve Q3 LOCK regression-net
 *  compatibility: `(meta: unknown) => R` is contravariantly assignable to
 *  the narrow expected `(meta: MetaMap[K]) => R`, but a WRONG-narrow
 *  copy-paste like `(meta: CalendarMutationAuditMeta) => R` under the
 *  `commentPostMeta` key fails the satisfies clause. The compile-time
 *  contract works without changing function bodies or the auditEnd
 *  dispatch loop. */
// v1.28 Phase 1 Item 4 (NEW-6) — SerializeFn<M> parameterization convention:
// Parameterized on the META type directly via `<M>` (NOT on the registry
// KEY `<K extends keyof MetaMap>`). The v1.27 design doc §2.3 lines 387-389
// specified `SerializeFn<K extends keyof MetaMap> = (meta: MetaMap[K]) => R`
// (KEY-parameterized form). Shipped form `SerializeFn<M> = (meta: M) => R`
// (META-parameterized form) is PHANTOM-TYPE EQUIVALENT to design at the
// satisfies clause expansion below — both expand to
// `(meta: MetaMap[K]) => Record<string, unknown>` for each channel entry
// via mapped-type substitution:
//   - design <K>:    SerializeFn<K>             with K = "commentPostMeta"
//                    → (meta: MetaMap["commentPostMeta"]) => R
//                    = (meta: CommentPostAuditMeta) => R
//   - shipped <M>:   SerializeFn<MetaMap["commentPostMeta"]>
//                    → (meta: CommentPostAuditMeta) => R
//
// META-parameterized form chosen because:
//   - The function signature itself doesn't reference MetaMap — the
//     meta-type is the natural function parameter.
//   - `<K>` would require every per-channel impl reference to use
//     `SerializeFn<"commentPostMeta">` (key-based), coupling function-type
//     references to registry string literals.
//   - Mapped-type expansion on the satisfies clause does all the heavy
//     lifting regardless of the parameterization choice.
//
// Anchor for future extensions (e.g., async variant): an async SerializeFn
// would mirror the <M> shape as
//   `type AsyncSerializeFn<M> = (meta: M) => Promise<Record<string, unknown>>`
// — same satisfies-clause expansion holds. Future v1.29+ extension MUST
// preserve META-form so the composable async variant stays clean (a
// KEY-parameterized async variant would conflate type parameters).
//
// `audit.metamap-sentinel.test.ts` carries the runtime sentinel + the
// `SerializeFn<MetaMap["commentPostMeta"]>` probe assignment that pins
// the type-alias surface so a future PR cannot silently flatten
// `SerializeFn` back to non-generic.
export type SerializeFn<M> = (meta: M) => Record<string, unknown>;

export const AUDIT_META_CHANNELS = {
  commentPostMeta: {
    label: "commentPost",
    flatHash: "target_video_hash",
    // v1.24 Phase 1 Item 1 — commentPost canary classifications.
    suspiciousDecisions: {
      high: ["denied_outbound_sanitize_rejected"],
      medium_allowlist: ["denied_no_allowlist", "denied_not_in_allowlist"],
      medium_burst: ["denied_burst_limit"],
      low_tier: ["denied_tier"],
    },
    // v1.25 Phase 2 Item 2 — serialize maps CommentPostAuditMeta → JSONL
    // row fields. Field ORDER mirrors the v1.24 manual write block (lines
    // 880-888) for byte-stability across the refactor. parent_comment_id_hash
    // is conditional (ABSENT on top-level post; PRESENT on reply).
    //
    // v1.27 Phase 1 Item 3 — `meta: unknown` parameter signature INTENTIONALLY
    // RETAINED for Q3 LOCK regression-net compatibility (per-channel narrow
    // params would collapse to an intersection under `Object.entries` iteration
    // and break `audit.serialize-refactor.test.ts`'s `entry.serialize(unknown)`
    // call pattern). The channel-key ↔ meta-type pairing IS enforced at the
    // SATISFIES CLAUSE LEVEL via `SerializeFn<MetaMap["commentPostMeta"]>` —
    // TypeScript contravariance accepts the WIDE `(meta: unknown) => R` impl
    // as assignable to the NARROW expected `(meta: CommentPostAuditMeta) => R`,
    // BUT a WRONG-NARROW impl (e.g., copy-pasted `(meta: CalendarMutationAuditMeta)`
    // under this `commentPostMeta` key) FAILS the satisfies clause cleanly.
    // Drift surface closed at the registry declaration without churning the
    // function body.
    serialize: (meta: unknown): Record<string, unknown> => {
      const m = meta as CommentPostAuditMeta;
      const out: Record<string, unknown> = {
        target_video_hash: m.target_video_hash,
        comment_length: m.comment_length,
        policy_decision: m.policy_decision,
      };
      if (m.parent_comment_id_hash !== undefined) {
        out.parent_comment_id_hash = m.parent_comment_id_hash;
      }
      return out;
    },
  },
  calendarMutationMeta: {
    label: "calendarMutation",
    flatHash: "target_event_hash",
    suspiciousDecisions: { low_tier: ["denied_tier"] },
    // v1.25 Phase 2 Item 2 — serialize maps CalendarMutationAuditMeta. Field
    // ORDER mirrors v1.24 manual write block (lines 896-906). rsvp_response
    // is ONLY set by calendar_respond (ABSENT on update/delete rows).
    // v1.27 Phase 1 Item 3 — `meta: unknown` retained per Q3 LOCK rationale
    // documented on `commentPostMeta.serialize`; satisfies clause enforces
    // channel-key ↔ meta-type pairing at the registry declaration level.
    serialize: (meta: unknown): Record<string, unknown> => {
      const m = meta as CalendarMutationAuditMeta;
      const out: Record<string, unknown> = {
        target_event_hash: m.target_event_hash,
        policy_decision: m.policy_decision,
      };
      if (m.rsvp_response !== undefined) {
        out.rsvp_response = m.rsvp_response;
      }
      return out;
    },
  },
  docsModifyMeta: {
    label: "docsModify",
    flatHash: "target_document_id_hash",
    suspiciousDecisions: { low_tier: ["denied_tier"] },
    // v1.25 Phase 2 Item 2 — serialize maps DocsModifyAuditMeta. Field ORDER
    // mirrors v1.24 manual write block (lines 917-931). total_text_replacements
    // is ABSENT when no replaceAllText was in the batch OR when SDK failed
    // before a reply was available.
    // v1.27 Phase 1 Item 3 — `meta: unknown` retained per Q3 LOCK rationale
    // documented on `commentPostMeta.serialize`.
    serialize: (meta: unknown): Record<string, unknown> => {
      const m = meta as DocsModifyAuditMeta;
      const out: Record<string, unknown> = {
        target_document_id_hash: m.target_document_id_hash,
        modification_count: m.modification_count,
        request_types_csv: m.request_types_csv,
        policy_decision: m.policy_decision,
      };
      if (m.total_text_replacements !== undefined) {
        out.total_text_replacements = m.total_text_replacements;
      }
      return out;
    },
  },
  commentDeleteMeta: {
    label: "commentDelete",
    flatHash: "target_comment_id_hash",
    suspiciousDecisions: { low_tier: ["denied_tier"] },
    // v1.25 Phase 2 Item 2 — serialize maps CommentDeleteAuditMeta. Field
    // ORDER mirrors v1.24 manual write block (lines 940-944).
    // v1.27 Phase 1 Item 3 — `meta: unknown` retained per Q3 LOCK rationale
    // documented on `commentPostMeta.serialize`.
    serialize: (meta: unknown): Record<string, unknown> => {
      const m = meta as CommentDeleteAuditMeta;
      return {
        target_comment_id_hash: m.target_comment_id_hash,
        policy_decision: m.policy_decision,
      };
    },
  },
  // v1.19 Phase 2b — 5th channel. flatHash = "target_tasklist_hash" (present
  // on ALL 3 tasks mutation rows — create / update / delete; target_task_hash
  // is ABSENT on create rows so it would not be a reliable discriminator).
  tasksMutationMeta: {
    label: "tasksMutation",
    flatHash: "target_tasklist_hash",
    suspiciousDecisions: { low_tier: ["denied_tier"] },
    // v1.25 Phase 2 Item 2 — serialize maps TasksMutationAuditMeta. Field
    // ORDER mirrors v1.24 manual write block (lines 961-972). target_task_hash
    // is ABSENT on `create` rows (no task ID yet at create time).
    // v1.27 Phase 1 Item 3 — `meta: unknown` retained per Q3 LOCK rationale
    // documented on `commentPostMeta.serialize`.
    serialize: (meta: unknown): Record<string, unknown> => {
      const m = meta as TasksMutationAuditMeta;
      const out: Record<string, unknown> = {
        target_tasklist_hash: m.target_tasklist_hash,
        operation: m.operation,
        policy_decision: m.policy_decision,
      };
      if (m.target_task_hash !== undefined) {
        out.target_task_hash = m.target_task_hash;
      }
      return out;
    },
  },
  // v1.20 Phase 1b-2 — 6th channel. flatHash = "target_spreadsheet_id_hash"
  // (present on ALL sheets mutation rows — create / append_values; the future
  // Phase 2c update_values / batch_update will also carry it).
  // target_range_hash is ABSENT on create rows so it would NOT be a reliable
  // discriminator. FIRST production test of v1.19 path-(b) registry refactor
  // — `cli/audit/policy-decisions.ts` auto-discovers this channel via
  // `entry.flatHash` with ZERO code edit at the policy-decisions site.
  sheetsMutationMeta: {
    label: "sheetsMutation",
    flatHash: "target_spreadsheet_id_hash",
    // v1.24 Phase 1 Item 1 — sheets denied_formula_rejected is the FIRST
    // HIGH-confidence canary outside commentPost (v1.21 introduced; v1.23
    // suspicious.ts hardcoded it; v1.24 moves it to the registry).
    suspiciousDecisions: {
      high: ["denied_formula_rejected"],
      low_tier: ["denied_tier"],
    },
    // v1.25 Phase 2 Item 2 — serialize maps SheetsMutationAuditMeta. Field
    // ORDER mirrors v1.24 manual write block. All 5 optional fields are
    // ABSENT on the relevant non-applicable rows per the v1.21 + v1.20 +
    // v1.32 conditional emission contract:
    //   target_range_hash                — ABSENT on `create` rows.
    //   request_types_csv                — ONLY on `batch_update` rows.
    //   total_cell_writes                — ONLY on `batch_update` rows that
    //                                      touched cells via updateCells /
    //                                      repeatCell.
    //   rejected_formula_function        — ONLY when policy_decision ===
    //                                      "denied_formula_rejected".
    //   rejected_formula_homoglyph_source — v1.32 Phase 2; ONLY when a
    //                                      denied_formula_rejected row's cell
    //                                      used non-ASCII (homoglyph / bidi /
    //                                      Default_Ignorable) source bytes.
    //                                      PRESENCE-as-signal — ABSENT on
    //                                      ASCII REJECTs (Q3 LOCK byte-stable).
    // v1.27 Phase 1 Item 3 — `meta: unknown` retained per Q3 LOCK rationale
    // documented on `commentPostMeta.serialize`.
    serialize: (meta: unknown): Record<string, unknown> => {
      const m = meta as SheetsMutationAuditMeta;
      const out: Record<string, unknown> = {
        target_spreadsheet_id_hash: m.target_spreadsheet_id_hash,
        operation: m.operation,
        policy_decision: m.policy_decision,
      };
      if (m.target_range_hash !== undefined) {
        out.target_range_hash = m.target_range_hash;
      }
      if (m.request_types_csv !== undefined) {
        out.request_types_csv = m.request_types_csv;
      }
      if (m.total_cell_writes !== undefined) {
        out.total_cell_writes = m.total_cell_writes;
      }
      if (m.rejected_formula_function !== undefined) {
        out.rejected_formula_function = m.rejected_formula_function;
      }
      // v1.41 — emit the nested-smuggle discriminator AFTER
      // rejected_formula_function and BEFORE rejected_formula_homoglyph_source
      // (Q3 LOCK forensic order: function → nested → homoglyph). PRESENCE-as-
      // signal: ABSENT on direct STEP 4 attacks → audit row bytes stay
      // IDENTICAL to v1.40 for the direct-attack family. ORDER pinned by the
      // Category I serialize sentinel (formula-reject.integration).
      if (m.rejected_formula_nested !== undefined) {
        out.rejected_formula_nested = m.rejected_formula_nested;
      }
      // v1.32 Phase 2 — emit the forensic homoglyph-source bytes AFTER
      // rejected_formula_function for forensic visual locality (auditor reads
      // the canonical function name THEN the original transformed bytes).
      // PRESENCE-as-signal: ABSENT on pure-ASCII REJECTs → audit row bytes
      // stay IDENTICAL to v1.31 for the ASCII attack family (Q3 LOCK). ORDER
      // pinned by the Category I serialize sentinel (formula-reject.integration).
      if (m.rejected_formula_homoglyph_source !== undefined) {
        out.rejected_formula_homoglyph_source =
          m.rejected_formula_homoglyph_source;
      }
      return out;
    },
  },
  // v1.48 B4 — 7th channel. flatHash = "target_playlist_hash" (present on ALL
  // playlist mutation rows — create uses the sheets_create 2-step sentinel→real
  // so the field is reliable on create too; target_video_hash is ABSENT on
  // create/update so it would NOT be a reliable discriminator). The
  // policy-decisions + suspicious CLIs auto-discover this channel via
  // entry.flatHash / entry.suspiciousDecisions — ZERO CLI code edit.
  playlistMutationMeta: {
    label: "playlistMutation",
    flatHash: "target_playlist_hash",
    suspiciousDecisions: { low_tier: ["denied_tier"] },
    // v1.48 — serialize maps PlaylistMutationAuditMeta. Field ORDER:
    // target_playlist_hash → operation → policy_decision → target_video_hash
    // (optional, ONLY on playlist_item_insert). `meta: unknown` retained per
    // the Q3 LOCK rationale documented on `commentPostMeta.serialize`.
    serialize: (meta: unknown): Record<string, unknown> => {
      const m = meta as PlaylistMutationAuditMeta;
      const out: Record<string, unknown> = {
        target_playlist_hash: m.target_playlist_hash,
        operation: m.operation,
        policy_decision: m.policy_decision,
      };
      if (m.target_video_hash !== undefined) {
        out.target_video_hash = m.target_video_hash;
      }
      return out;
    },
  },
  videoMutationMeta: {
    label: "videoMutation",
    flatHash: "target_video_hash",
    // canary: only `low_tier` is declared here. `denied_outbound_sanitize_rejected`
    // is a HIGH canary, but it is matched channel-AGNOSTICALLY by suspicious.ts's
    // flattened `pdTop === "denied_outbound_sanitize_rejected"` branch (so a
    // video_update reject is still counted) — re-declaring it in `high` would
    // DOUBLE-COUNT, because collectByBucket("high") (unlike low_tier) is not
    // Set-deduped. `denied_tier` IS deduped, so declaring it is safe + correct
    // (mirrors the playlistMutation channel, which also declares only low_tier).
    suspiciousDecisions: {
      low_tier: ["denied_tier"],
    },
    // v1.106 — serialize maps VideoMutationAuditMeta. Field ORDER:
    // target_video_hash → operation → title_length → policy_decision, then the
    // two optional length fields (description_length / tag_count) when present.
    // `meta: unknown` retained per the Q3 LOCK rationale on commentPostMeta.serialize.
    serialize: (meta: unknown): Record<string, unknown> => {
      const m = meta as VideoMutationAuditMeta;
      const out: Record<string, unknown> = {
        target_video_hash: m.target_video_hash,
        operation: m.operation,
        title_length: m.title_length,
        policy_decision: m.policy_decision,
      };
      if (m.description_length !== undefined) {
        out.description_length = m.description_length;
      }
      if (m.tag_count !== undefined) {
        out.tag_count = m.tag_count;
      }
      return out;
    },
  },
  // v1.27 Phase 1 Item 3 (NEW-11) — `satisfies` clause switched from
  // `Record<string, {…serialize: SerializeFn}>` to a MAPPED TYPE
  // `{[K in keyof MetaMap]: {…serialize: SerializeFn<MetaMap[K]>}}`. This
  // projects EACH registry key K to a unique entry shape where the
  // serialize function's parameter type is `MetaMap[K]`. Net effect:
  // registry-key ↔ meta-type pairing is now a compile-time invariant.
  //
  // Failure modes the mapped-type catches at compile:
  //   - adding a 7th channel `xMeta` to AUDIT_META_CHANNELS without
  //     extending MetaMap → "Property 'xMeta' is missing in type
  //     'MetaMap'" (because the satisfies expected type has an exact
  //     `[K in keyof MetaMap]` index set)
  //   - typing serialize with the wrong channel's meta interface (e.g.
  //     copy-pasted `(meta: CalendarMutationAuditMeta) => …` under the
  //     `commentPostMeta` key) → "Type '(meta: CalendarMutationAuditMeta)
  //     => …' is not assignable to type
  //     'SerializeFn<MetaMap[\"commentPostMeta\"]>'" (narrow params
  //     incompatible under contravariance check)
  //
  // Closes v1.25 Phase 2 dual-review DEFER-1 security observation +
  // LOW-2 code review observation. Q3 LOCK regression net preserved:
  // per-channel impls retain `(meta: unknown)` + inline `as` cast (their
  // wider param signature is contravariantly assignable to the narrow
  // expected `SerializeFn<MetaMap[K]>`), so function BODIES stay
  // byte-identical and the v1.22/v1.24/v1.25 regression tests pass
  // UNCHANGED.
} as const satisfies {
  [K in keyof MetaMap]: {
    label: string;
    flatHash: string;
    suspiciousDecisions?: SuspiciousClassification;
    // v1.25 Phase 2 Item 2 — REQUIRED on every channel. The satisfies clause
    // enforces presence at compile time: omitting `serialize` from a new
    // channel fails TypeScript. Closes v1.19 NEW-3 manual 4th site PERMANENTLY.
    //
    // v1.27 Phase 1 Item 3 (NEW-11) — parameterized over `MetaMap[K]` via
    // arrow-property syntax. TypeScript contravariance accepts a WIDE
    // `(meta: unknown) => R` impl as assignable to NARROW
    // `SerializeFn<MetaMap[K]> = (meta: MetaMap[K]) => R` — which is why
    // the per-channel impl signatures stay `(meta: unknown)` for Q3 LOCK
    // regression-net compatibility (the v1.25 Phase 2
    // `audit.serialize-refactor.test.ts` iterates the registry and calls
    // `entry.serialize(unknown)`; narrow impl params would collapse to an
    // INTERSECTION under iteration and break the test).
    //
    // The contract is still tightened from convention to compile-time
    // invariant: a future PR that types a serialize fn with the WRONG
    // narrow meta interface (e.g., copy-pasted
    // `(meta: CalendarMutationAuditMeta) => R` under the `commentPostMeta`
    // key) FAILS the satisfies clause — `(meta: CalendarMutationAuditMeta)
    // => R` is NOT assignable to `SerializeFn<MetaMap["commentPostMeta"]>
    // = (meta: CommentPostAuditMeta) => R` (incompatible parameter types).
    // Wrong-cross-key drift surface closed at the registry declaration.
    serialize: SerializeFn<MetaMap[K]>;
  };
};

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
    // v1.36 BLOCKER 2 — human operator actor. ALWAYS emitted (like `account`),
    // `null` when unset so single-user rows stay byte-stable except for this one
    // added field (Q4). Plaintext (Q3). NOT presence-as-signal: an absent key
    // would conflate "single-user" with "field stripped", defeating the
    // who-did-what forensic value in a co-management deployment.
    operator: ctx.operator ?? null,
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
  if (ctx.errorForensics) {
    for (const [k, v] of Object.entries(ctx.errorForensics)) {
      if (!(k in payload)) payload[k] = v;
    }
  }
  // v1.89 — stamp the tamper-evident chain MAC and append, SERIALIZED through the
  // write mutex (the MAC folds in the previous row's MAC, so writes must not race to
  // read-tip-then-append). The MAC is computed over the payload BEFORE `row_mac` is
  // added (a MAC can't hash itself); on a successful append `lastMac` advances, so a
  // FAILED append leaves the chain unbroken (the row simply never existed).
  // Resolve the target path at CALL time (not lazily inside the mutex): the row
  // belongs to the config dir active when auditEnd was invoked, and the write mutex
  // can defer the actual append — a lazily-resolved path could drift if
  // SAFESPACE_CONFIG_DIR changed in the meantime (it never does in production; this
  // also keeps concurrent tests with per-test dirs from cross-contaminating).
  const targetDir = configDir();
  const targetPath = auditPath();
  try {
    await runExclusive(async () => {
      const salt = await chainSalt();
      if (lastMac === undefined) lastMac = await readChainTip(targetPath);
      const rowMac = computeRowMac(salt, lastMac, payload);
      payload.row_mac = rowMac;
      const line = JSON.stringify(payload) + "\n";
      await fs.mkdir(targetDir, { recursive: true, mode: 0o700 });
      await fs.appendFile(targetPath, line, { mode: 0o600 });
      lastMac = rowMac;
    });
  } catch (e) {
    // stderr is captured by the MCP runtime as server log, not surfaced
    // to Claude. Acceptable channel for ops-side visibility.
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`[safespace] audit append failed: ${msg}`);
  }
}
