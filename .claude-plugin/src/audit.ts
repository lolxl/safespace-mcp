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
// call appendChainedRow / appendBareRow (exported below) — a RUNTIME-SAFE cycle:
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

/** Append one row to audit.jsonl as a link in the v1.89 tamper-evident chain:
 *  serialized through the per-process write mutex, folding in the previous chained
 *  row's MAC and stamping `row_mac`. Best-effort — any error is logged (with
 *  `label`) and swallowed so a broken audit file never fails a tool call.
 *
 *  SERVER-PROCESS callers ONLY. The single-writer chain assumes ONE appending
 *  process; the `safespace` CLI is a SEPARATE writer, so its rows must stay
 *  unchained (see `appendBareRow`) — a second writer extending the chain would
 *  fork it. `verify` tolerates the CLI's unchained `event:` rows.
 *
 *  MUTATES `payload` (adds `row_mac`). The MAC is computed over the payload
 *  BEFORE `row_mac` is added (a MAC can't hash itself); on a successful append
 *  `lastMac` advances, so a FAILED append leaves the chain unbroken (the row
 *  simply never existed). The target dir/path are resolved at CALL time (not
 *  lazily inside the mutex) so a deferred write can't drift if the config dir
 *  changed in the meantime (it never does in production; this keeps concurrent
 *  tests with per-test dirs from cross-contaminating). */
export async function appendChainedRow(payload: Record<string, unknown>, label: string): Promise<void> {
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
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`[safespace] ${label} append failed: ${msg}`);
  }
}

/** Append one row to audit.jsonl WITHOUT chaining it (no `row_mac`). For rows
 *  written by a process that is NOT the single chain writer — today only the
 *  `safespace` CLI's send-approval approved/denied actions (cli/send.ts). These
 *  rows carry an `event` field, which `verify` uses to tolerate them as
 *  legitimately-unchained (rather than a chain break). Same best-effort
 *  swallow-errors contract as `appendChainedRow`. */
export async function appendBareRow(payload: Record<string, unknown>, label: string): Promise<void> {
  const line = JSON.stringify(payload) + "\n";
  try {
    await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
    await fs.appendFile(auditPath(), line, { mode: 0o600 });
  } catch (e) {
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
  // v1.89 — append as a link in the tamper-evident chain (each MAC folds in the
  // previous chained row's MAC). The shared `appendChainedRow` serializes through
  // the per-process write mutex, computes the MAC over the payload BEFORE adding
  // `row_mac`, and advances `lastMac` ONLY on a successful append — so a FAILED
  // append leaves the chain unbroken (the row simply never existed). Best-effort:
  // any error is logged to stderr (captured by the MCP runtime as server log, not
  // surfaced to Claude) and swallowed so a broken audit file never fails a call.
  await appendChainedRow(payload, "audit");
}
