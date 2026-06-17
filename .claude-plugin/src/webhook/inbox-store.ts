// v1.102 (W0) — the durable inbox store. Mirrors auth/send-approval-store.ts:
// inbox.json under configDir (0o600, dir 0o700), fail-loud parse, an in-process
// withLock serializing every store access, prune on write + (in-memory) on read.
//
// docs/v1.102-webhook-listener.md section 4 + 4.2:
//   - DEDUP on (provider, event_id) — absorbs the provider retries; a missing
//     event_id never reaches here (the verify module rejects it).
//   - A MONOTONIC seq cursor (a persisted top-level counter, NOT max(rows.seq)) so
//     it never goes backward across a full prune — the agent stateless after_seq
//     cursor (matching v1.98) stays valid.
//   - RETENTION = age TTL (default 24 h) + a count cap, pruned on the WRITE path (the
//     high-volume writer) so the file stays bounded between reads; reads prune in
//     memory so the agent never sees an expired row (no read-side write — a read-tier
//     tool must not mutate the store).
//   - CONCURRENCY (4.1): the listener persist + the tool read both go through the ONE
//     module withLock → no torn read, no prune-then-write race. Writes are atomic
//     (temp + rename) so even a cross-process CLI reader never sees a partial file.
//   - The store holds the signature-VERIFIED raw normalized msg; sanitize runs on READ
//     at the existing choke point (the webhook Source skipFields), never here.

import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { configDir } from "../auth/keychain";
import type { InboxMsg, InboxRow, WebhookProvider } from "./types";

const STORE_FILE = "inbox.json";
/** Default row TTL (24 h) — mirrors the Telegram server buffer + send-approval. */
export const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
/** Count cap — a blast-radius bound so a flood cannot fill the disk between reads. */
const MAX_ROWS = 1000;
const PROVIDERS: ReadonlySet<string> = new Set(["slack", "line", "telegram"]);

/** The on-disk shape: a persisted monotonic counter + the rows. next_seq only ever
 *  increases (survives a full prune), so a pruned-empty store does NOT reset the
 *  cursor the agent holds. */
export interface InboxStore {
  next_seq: number;
  rows: InboxRow[];
}

/** What the listener hands the store for one verified message. */
export interface InboxAppend {
  readonly provider: WebhookProvider;
  readonly event_id: string;
  readonly msg: InboxMsg;
}

export function inboxPath(): string {
  return path.join(configDir(), STORE_FILE);
}

function fail(msg: string): never {
  throw new Error(`[safespace] inbox store invalid: ${msg}`);
}

// ── in-process serialization (one chain; mirrors send-approval withLock) ──
let chain: Promise<unknown> = Promise.resolve();
function withLock<T>(fn: () => Promise<T>): Promise<T> {
  const run = chain.then(fn, fn);
  chain = run.catch(() => {});
  return run;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return v != null && typeof v === "object" && !Array.isArray(v);
}

function dedupKey(provider: string, eventId: string): string {
  return JSON.stringify([provider, eventId]);
}

function parseMsg(v: unknown, where: string): InboxMsg {
  if (!isObject(v)) fail(`${where}: msg must be an object`);
  const m = v as Record<string, unknown>;
  for (const k of ["provider_message_id", "ts", "sender_id", "channel_id", "text"] as const) {
    if (typeof m[k] !== "string") fail(`${where}: msg.${k} must be a string`);
  }
  if (m.sender_name !== null && typeof m.sender_name !== "string") {
    fail(`${where}: msg.sender_name must be a string or null`);
  }
  return {
    provider_message_id: m.provider_message_id as string,
    ts: m.ts as string,
    sender_id: m.sender_id as string,
    sender_name: (m.sender_name as string | null) ?? null,
    channel_id: m.channel_id as string,
    text: m.text as string,
  };
}

/** Parse + validate raw inbox.json. Pure (no I/O). Throws on the FIRST violation —
 *  fail-loud, so a corrupt store never silently serves. */
export function parseInbox(raw: string): InboxStore {
  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch {
    fail("not valid JSON");
  }
  if (!isObject(doc)) fail("top-level must be an object");
  const d = doc as Record<string, unknown>;
  const nextSeq = d.next_seq;
  if (typeof nextSeq !== "number" || !Number.isInteger(nextSeq) || nextSeq < 1) {
    fail("next_seq must be a positive integer");
  }
  if (!Array.isArray(d.rows)) fail("rows must be an array");
  const seen = new Set<string>();
  const rows = d.rows.map((rawRow, i): InboxRow => {
    if (!isObject(rawRow)) fail(`row ${i} must be an object`);
    const e = rawRow as Record<string, unknown>;
    if (typeof e.seq !== "number" || !Number.isInteger(e.seq) || e.seq < 1) fail(`row ${i}: seq must be a positive integer`);
    if (e.seq >= nextSeq) fail(`row ${i}: seq must be < next_seq`);
    if (typeof e.provider !== "string" || !PROVIDERS.has(e.provider)) fail(`row ${i}: provider must be known`);
    if (typeof e.event_id !== "string" || e.event_id.length === 0) fail(`row ${i}: event_id must be a non-empty string`);
    if (typeof e.received_at !== "string" || Number.isNaN(Date.parse(e.received_at))) fail(`row ${i}: received_at must be ISO 8601`);
    if (typeof e.expires_at !== "string" || Number.isNaN(Date.parse(e.expires_at))) fail(`row ${i}: expires_at must be ISO 8601`);
    const key = dedupKey(e.provider, e.event_id);
    if (seen.has(key)) fail(`row ${i}: duplicate (provider, event_id)`);
    seen.add(key);
    return {
      seq: e.seq,
      provider: e.provider as WebhookProvider,
      event_id: e.event_id,
      received_at: e.received_at,
      expires_at: e.expires_at,
      msg: parseMsg(e.msg, `row ${i}`),
    };
  });
  return { next_seq: nextSeq, rows };
}

/** Read + parse the store, pruning TTL-expired rows in memory (the write path persists
 *  the compaction). A MISSING file yields an EMPTY store. Throws on a corrupt file. */
export async function loadInbox(filePath: string, now: number): Promise<InboxStore> {
  let raw: string;
  try {
    raw = await fs.readFile(filePath, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return { next_seq: 1, rows: [] };
    fail("cannot read the inbox file at the configured path");
  }
  const store = parseInbox(raw);
  store.rows = store.rows.filter((r) => Date.parse(r.expires_at) > now);
  return store;
}

function serialize(store: InboxStore): string {
  return JSON.stringify(store, null, 2) + "\n";
}

/** Atomic write (temp + rename): a reader (incl. a cross-process CLI) never sees a
 *  partial file. 0o600 + dir 0o700, mirroring send-approval. */
async function writeStore(filePath: string, store: InboxStore): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const tmp = `${filePath}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  await fs.writeFile(tmp, serialize(store), { mode: 0o600 });
  await fs.rename(tmp, filePath);
}

/** Persist ONE verified message. DEDUP on (provider, event_id): a retry of an
 *  already-stored event returns the existing row WITHOUT a second write. Assigns the
 *  next monotonic seq, prunes by count cap (drops the lowest-seq rows), writes
 *  atomically. Serialized via withLock against reads. */
export function appendInboxMessage(
  filePath: string,
  input: InboxAppend,
  now: number,
  ttlMs: number = DEFAULT_TTL_MS,
): Promise<{ row: InboxRow; deduped: boolean }> {
  return withLock(async () => {
    const store = await loadInbox(filePath, now);
    const existing = store.rows.find((r) => r.provider === input.provider && r.event_id === input.event_id);
    if (existing) return { row: existing, deduped: true };
    const row: InboxRow = {
      seq: store.next_seq,
      provider: input.provider,
      event_id: input.event_id,
      received_at: new Date(now).toISOString(),
      expires_at: new Date(now + ttlMs).toISOString(),
      msg: input.msg,
    };
    store.next_seq += 1;
    store.rows.push(row);
    if (store.rows.length > MAX_ROWS) {
      store.rows.sort((a, b) => a.seq - b.seq);
      store.rows = store.rows.slice(store.rows.length - MAX_ROWS);
    }
    await writeStore(filePath, store);
    return { row, deduped: false };
  });
}

/** The shape inbox_read returns: rows after the cursor + the new cursor tip + the gap
 *  signal (4.2 / security MED-4). */
export interface InboxReadResult {
  readonly messages: InboxRow[];
  /** Max seq of the RETURNED rows (or the input afterSeq when none) — next cursor. */
  readonly max_seq: number;
  /** Lowest seq still retained for this provider, or null when none. When
   *  afterSeq < oldest_seq - 1 the agent KNOWS a prune-gap dropped unread messages. */
  readonly oldest_seq: number | null;
}

/** Read this provider rows with seq > afterSeq, ascending, capped at limit. Prunes
 *  expired rows in memory. Serialized via withLock. Does NOT write. */
export function readInbox(
  filePath: string,
  provider: WebhookProvider,
  afterSeq: number,
  limit: number,
  now: number,
): Promise<InboxReadResult> {
  return withLock(async () => {
    const store = await loadInbox(filePath, now);
    const forProvider = store.rows.filter((r) => r.provider === provider);
    const oldest_seq = forProvider.length > 0 ? Math.min(...forProvider.map((r) => r.seq)) : null;
    const fresh = forProvider.filter((r) => r.seq > afterSeq).sort((a, b) => a.seq - b.seq).slice(0, limit);
    const last = fresh.at(-1);
    return { messages: fresh, max_seq: last ? last.seq : afterSeq, oldest_seq };
  });
}

/** Count of non-expired rows per provider — for doctor --posture (counts only). Throws
 *  on a corrupt store; the caller maps it to "unavailable" without failing the posture. */
export async function inboxCounts(filePath: string, now: number): Promise<Record<WebhookProvider, number>> {
  return withLock(async () => {
    const store = await loadInbox(filePath, now);
    const counts: Record<WebhookProvider, number> = { slack: 0, line: 0, telegram: 0 };
    for (const r of store.rows) counts[r.provider] += 1;
    return counts;
  });
}
