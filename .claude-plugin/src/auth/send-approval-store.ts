// v1.99 — the enforced send-approval store (OPT-IN supervised mode,
// SAFESPACE_REQUIRE_SEND_APPROVAL). When supervised mode is on, an agent's outbound message
// SEND cannot proceed until the owner approves THAT EXACT send out-of-band
// (`safespace send approve <id>`). This store holds the pending/approved records in
// `pending-sends.json` (configDir, 0o600).
//
// FINGERPRINT (anti bait-and-switch): each record is keyed by
// sha256(tool ‖ [canonical target] ‖ sorted+deduped recipients ‖ on-wire body ‖ operator) —
// so an approval binds to the EXACT tool+target+recipients+content the owner reviewed;
// changing any of them needs a fresh approval. The target element is PRESENT only when the
// send carries a typed public-surface target (v1.128 Q3-B); human-sends omit it so their
// fingerprint stays the 4-tuple (byte-identical store format). One-time CONSUME on send
// prevents replay.
//
// AT REST: unlike a hashes-only store, this one holds the outgoing BODY in
// plaintext — the owner must SEE what they approve. It is the owner's own outgoing message
// (0o600 + configDir 0o700) and is NEVER echoed in an MCPError / doctor / audit (the audit
// records a recipient HASH + the fingerprint, never the body).

import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { configDir } from "./keychain";

const STORE_FILE = "pending-sends.json";
/** Default record TTL (24h) — stale plaintext bodies don't linger at rest. */
export const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
const PENDING_ID_RE = /^[0-9a-f]{32}$/;
const FINGERPRINT_RE = /^[0-9a-f]{64}$/;
const MAX_RECORDS = 1000; // blast-radius cap — a runaway agent can't fill the disk with pendings.

export type SendStatus = "pending" | "approved";

/** Closed typed target for irretractable public writes (v1.128 Q3-B). Unknown
 *  keys are rejected at parse. Human-sends omit this field. */
export type ApprovalTarget =
  | { readonly kind: "youtube_video"; readonly video_id: string }
  | { readonly kind: "youtube_comment"; readonly parent_comment_id: string }
  | { readonly kind: "x_post"; readonly account_id: string }
  | { readonly kind: "drive_share"; readonly file_id: string; readonly share_type: "anyone"; readonly role: string };

const TARGET_KEYS: Record<ApprovalTarget["kind"], readonly string[]> = {
  youtube_video: ["kind", "video_id"],
  youtube_comment: ["kind", "parent_comment_id"],
  x_post: ["kind", "account_id"],
  drive_share: ["kind", "file_id", "share_type", "role"],
};

export interface PendingSend {
  readonly pending_id: string;
  readonly fingerprint: string;
  readonly tool: string;
  readonly recipients: string[];
  readonly body: string;
  /** Operator binding. Always "" since the multi-operator transport was removed;
   *  kept in the fingerprint so existing pending records stay valid. */
  readonly operator: string;
  /** Present only for public-surface gated writes; absent on human-sends. */
  readonly target?: ApprovalTarget;
  readonly created_at: string;
  readonly expires_at: string;
  status: SendStatus;
}

export function pendingSendsPath(): string {
  return path.join(configDir(), STORE_FILE);
}

/** A fresh opaque pending id (128 bits hex). */
export function generatePendingId(): string {
  return crypto.randomBytes(16).toString("hex");
}

/** Stable JSON object for a typed target (locked key order per kind). */
export function canonicalizeTarget(target: ApprovalTarget): ApprovalTarget {
  switch (target.kind) {
    case "youtube_video":
      return { kind: "youtube_video", video_id: target.video_id };
    case "youtube_comment":
      return { kind: "youtube_comment", parent_comment_id: target.parent_comment_id };
    case "x_post":
      return { kind: "x_post", account_id: target.account_id };
    case "drive_share":
      return { kind: "drive_share", file_id: target.file_id, share_type: "anyone", role: target.role };
  }
}

/** One-line owner-visible target for `safespace send list` / approve. */
export function formatApprovalTarget(target: ApprovalTarget): string {
  switch (target.kind) {
    case "youtube_video":
      return `video_id=${target.video_id}`;
    case "youtube_comment":
      return `parent_comment_id=${target.parent_comment_id}`;
    case "x_post":
      return `account_id=${target.account_id}`;
    case "drive_share":
      return `file_id=${target.file_id} share_type=anyone role=${target.role}`;
  }
}

/** The stable per-send fingerprint. Recipients are deduped + sorted (order/dupes don't change
 *  the send); the body is hashed AS-IS (the on-wire bytes — NO normalization, so two distinct
 *  bodies can never collide). `operator` is always "" (kept so pending
 *  records stay valid). `target` is the 5th element ONLY when present — omitted human-sends keep
 *  the 4-tuple so existing pending records stay valid. */
export function computeFingerprint(
  tool: string,
  recipients: string[],
  body: string,
  operator: string,
  target?: ApprovalTarget,
): string {
  const recips = Array.from(new Set(recipients)).sort();
  const canonical =
    target === undefined
      ? JSON.stringify([tool, recips, body, operator])
      : JSON.stringify([tool, canonicalizeTarget(target), recips, body, operator]);
  return crypto.createHash("sha256").update(canonical).digest("hex");
}

function fail(msg: string): never {
  throw new Error(`[safespace] pending-sends store invalid: ${msg}`);
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === "string");
}

/** Parse + validate raw pending-sends.json into records. Pure (no I/O). Throws on the FIRST
 *  violation — fail-loud, so a corrupt store never silently serves (when the flag is ON, the
 *  gate treats a throw here as FAIL-CLOSED: no send). Errors reference the entry index, never
 *  the body. */
export function parsePendingSends(raw: string): PendingSend[] {
  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch {
    fail("not valid JSON");
  }
  if (doc == null || typeof doc !== "object" || Array.isArray(doc)) {
    fail("top-level must be an object with a `pending` array");
  }
  const pending = (doc as { pending?: unknown }).pending;
  if (!Array.isArray(pending)) fail("`pending` must be an array");

  const seen = new Set<string>();
  return pending.map((rawEntry, i): PendingSend => {
    if (rawEntry == null || typeof rawEntry !== "object" || Array.isArray(rawEntry)) {
      fail(`entry #${i} must be an object`);
    }
    const e = rawEntry as Record<string, unknown>;
    if (typeof e.pending_id !== "string" || !PENDING_ID_RE.test(e.pending_id)) {
      fail(`entry #${i}: \`pending_id\` must be 32 lowercase hex chars`);
    }
    if (typeof e.fingerprint !== "string" || !FINGERPRINT_RE.test(e.fingerprint)) {
      fail(`entry #${i}: \`fingerprint\` must be 64 lowercase hex chars`);
    }
    if (typeof e.tool !== "string" || e.tool.length === 0) fail(`entry #${i}: \`tool\` must be a non-empty string`);
    if (!isStringArray(e.recipients)) fail(`entry #${i}: \`recipients\` must be a string array`);
    if (typeof e.body !== "string") fail(`entry #${i}: \`body\` must be a string`);
    if (typeof e.operator !== "string") fail(`entry #${i}: \`operator\` must be a string`);
    if (typeof e.created_at !== "string" || Number.isNaN(Date.parse(e.created_at))) {
      fail(`entry #${i}: \`created_at\` must be an ISO 8601 timestamp`);
    }
    if (typeof e.expires_at !== "string" || Number.isNaN(Date.parse(e.expires_at))) {
      fail(`entry #${i}: \`expires_at\` must be an ISO 8601 timestamp`);
    }
    if (e.status !== "pending" && e.status !== "approved") {
      fail(`entry #${i}: \`status\` must be "pending" or "approved"`);
    }
    const target = e.target === undefined ? undefined : parseApprovalTarget(e.target, `entry #${i}: \`target\``);
    if (seen.has(e.pending_id)) fail(`entry #${i}: duplicate pending_id`);
    seen.add(e.pending_id);
    return {
      pending_id: e.pending_id,
      fingerprint: e.fingerprint,
      tool: e.tool,
      recipients: e.recipients,
      body: e.body,
      operator: e.operator,
      ...(target !== undefined ? { target } : {}),
      created_at: e.created_at,
      expires_at: e.expires_at,
      status: e.status,
    };
  });
}

function parseApprovalTarget(raw: unknown, where: string): ApprovalTarget {
  if (raw == null || typeof raw !== "object" || Array.isArray(raw)) {
    fail(`${where} must be an object`);
  }
  const e = raw as Record<string, unknown>;
  const kind = e.kind;
  if (kind !== "youtube_video" && kind !== "youtube_comment" && kind !== "x_post" && kind !== "drive_share") {
    fail(`${where}.kind is not a closed kind`);
  }
  for (const k of Object.keys(e)) {
    if (!TARGET_KEYS[kind].includes(k)) fail(`${where} has unknown key`);
  }
  const need = (field: string): string => {
    const v = e[field];
    if (typeof v !== "string" || v.length === 0) fail(`${where}.${field} must be a non-empty string`);
    return v;
  };
  if (kind === "youtube_video") return { kind, video_id: need("video_id") };
  if (kind === "youtube_comment") return { kind, parent_comment_id: need("parent_comment_id") };
  if (kind === "x_post") return { kind, account_id: need("account_id") };
  if (e.share_type !== "anyone") fail(`${where}.share_type must be "anyone"`);
  const role = need("role");
  if (role !== "reader" && role !== "commenter") fail(`${where}.role must be reader or commenter`);
  return { kind: "drive_share", file_id: need("file_id"), share_type: "anyone", role };
}

/** Read + parse the store, PRUNING records whose `expires_at` has passed (so stale plaintext
 *  bodies don't accumulate). A MISSING file yields an EMPTY store. Throws (fail-loud) on a
 *  corrupt/unreadable file — the gate maps that to FAIL-CLOSED when the flag is on. */
export async function loadPendingSends(filePath: string, now: number): Promise<PendingSend[]> {
  let raw: string;
  try {
    raw = await fs.readFile(filePath, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return [];
    fail("cannot read the pending-sends file at the configured path");
  }
  return parsePendingSends(raw).filter((r) => Date.parse(r.expires_at) > now);
}

function serialize(records: PendingSend[]): string {
  return JSON.stringify({ pending: records }, null, 2) + "\n";
}

async function writeStore(filePath: string, records: PendingSend[]): Promise<void> {
  await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
  await fs.writeFile(filePath, serialize(records), { mode: 0o600 });
}

/** Find the FIRST approved, non-expired record matching `fingerprint` (the load already pruned
 *  expired). Returns undefined if none — the caller then creates a pending record. */
export function findApprovedByFingerprint(records: PendingSend[], fingerprint: string): PendingSend | undefined {
  return records.find((r) => r.status === "approved" && r.fingerprint === fingerprint);
}

/** Append a new PENDING record (the gate's "first attempt, no approval yet" path) and return
 *  its id. Pruning happens at load; a fresh-load count cap bounds the blast radius. */
export async function createPending(
  filePath: string,
  rec: {
    fingerprint: string;
    tool: string;
    recipients: string[];
    body: string;
    operator: string;
    target?: ApprovalTarget;
  },
  now: number,
  ttlMs: number,
): Promise<string> {
  const records = await loadPendingSends(filePath, now);
  if (records.length >= MAX_RECORDS) {
    throw new Error(`pending-sends store is full (${MAX_RECORDS}) — approve/deny or wait for expiry`);
  }
  const pending_id = generatePendingId();
  const target = rec.target === undefined ? undefined : parseApprovalTarget(rec.target, "`target`");
  records.push({
    pending_id,
    fingerprint: rec.fingerprint,
    tool: rec.tool,
    recipients: rec.recipients,
    body: rec.body,
    operator: rec.operator,
    ...(target !== undefined ? { target } : {}),
    created_at: new Date(now).toISOString(),
    expires_at: new Date(now + ttlMs).toISOString(),
    status: "pending",
  });
  await writeStore(filePath, records);
  return pending_id;
}

/** Atomically (a SINGLE load) find an APPROVED record by fingerprint, remove it, persist, and
 *  return it — the gate's one-time consume. Returns null if no approved match. The in-process
 *  withLock serializes gate callers; a cross-process CLI write between this load and write is
 *  benign (the end state is still correct — at worst a send is re-blocked, fail-safe). */
export async function consumeApprovedByFingerprint(
  filePath: string,
  fingerprint: string,
  now: number,
): Promise<PendingSend | null> {
  const records = await loadPendingSends(filePath, now);
  const rec = findApprovedByFingerprint(records, fingerprint);
  if (rec === undefined) return null;
  await writeStore(filePath, records.filter((r) => r.pending_id !== rec.pending_id));
  return rec;
}

/** Atomically (a SINGLE load) find a record by id, remove it, persist, and return it — the
 *  `deny` CLI (so the denial is audited with the removed record's fields, with NO
 *  list-then-remove TOCTOU window). Returns null if absent. */
export async function findAndRemovePending(
  filePath: string,
  pending_id: string,
  now: number,
): Promise<PendingSend | null> {
  const records = await loadPendingSends(filePath, now);
  const rec = records.find((r) => r.pending_id === pending_id);
  if (rec === undefined) return null;
  await writeStore(filePath, records.filter((r) => r.pending_id !== pending_id));
  return rec;
}

/** Flip a pending record to approved (the `approve` CLI). Returns the record, or null if no
 *  such (non-expired) pending id. Re-approving an already-approved id is idempotent. */
export async function approvePending(filePath: string, pending_id: string, now: number): Promise<PendingSend | null> {
  const records = await loadPendingSends(filePath, now);
  const rec = records.find((r) => r.pending_id === pending_id);
  if (rec === undefined) return null;
  rec.status = "approved";
  await writeStore(filePath, records);
  return rec;
}

/** List the (non-expired) records for the `list` CLI. */
export async function listPending(filePath: string, now: number): Promise<PendingSend[]> {
  return loadPendingSends(filePath, now);
}
