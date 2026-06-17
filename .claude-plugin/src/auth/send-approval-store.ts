// v1.99 — the enforced send-approval store (OPT-IN supervised mode,
// SAFESPACE_REQUIRE_SEND_APPROVAL). When supervised mode is on, an agent's outbound message
// SEND cannot proceed until the owner approves THAT EXACT send out-of-band
// (`safespace send approve <id>`). This store holds the pending/approved records in
// `pending-sends.json` (configDir, 0o600).
//
// FINGERPRINT (anti bait-and-switch): each record is keyed by
// sha256(tool ‖ sorted+deduped recipients ‖ on-wire body ‖ operator) — so an approval binds to
// the EXACT tool+recipients+content the owner reviewed; changing any of them needs a fresh
// approval. One-time CONSUME on send prevents replay.
//
// AT REST: unlike agent-tokens.json (hashes only), this store holds the outgoing BODY in
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

export interface PendingSend {
  readonly pending_id: string;
  readonly fingerprint: string;
  readonly tool: string;
  readonly recipients: string[];
  readonly body: string;
  /** Model B operator binding ("" = Model A → byte-identical). */
  readonly operator: string;
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

/** The stable per-send fingerprint. Recipients are deduped + sorted (order/dupes don't change
 *  the send); the body is hashed AS-IS (the on-wire bytes — NO normalization, so two distinct
 *  bodies can never collide). `operator` binds the approval to the calling operator (Model B;
 *  "" = Model A). */
export function computeFingerprint(
  tool: string,
  recipients: string[],
  body: string,
  operator: string,
): string {
  const recips = Array.from(new Set(recipients)).sort();
  const canonical = JSON.stringify([tool, recips, body, operator]);
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
    if (seen.has(e.pending_id)) fail(`entry #${i}: duplicate pending_id`);
    seen.add(e.pending_id);
    return {
      pending_id: e.pending_id,
      fingerprint: e.fingerprint,
      tool: e.tool,
      recipients: e.recipients,
      body: e.body,
      operator: e.operator,
      created_at: e.created_at,
      expires_at: e.expires_at,
      status: e.status,
    };
  });
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
  rec: { fingerprint: string; tool: string; recipients: string[]; body: string; operator: string },
  now: number,
  ttlMs: number,
): Promise<string> {
  const records = await loadPendingSends(filePath, now);
  if (records.length >= MAX_RECORDS) {
    throw new Error(`pending-sends store is full (${MAX_RECORDS}) — approve/deny or wait for expiry`);
  }
  const pending_id = generatePendingId();
  records.push({
    pending_id,
    fingerprint: rec.fingerprint,
    tool: rec.tool,
    recipients: rec.recipients,
    body: rec.body,
    operator: rec.operator,
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
