// v2.1 — Drive share whitelist policy module.
//
// Loads + queries the `drive-whitelist.json` config at
// ${CLAUDE_PLUGIN_DATA}/safespace/drive-whitelist.json and decides whether
// a given file_id is allowed to be shared. See docs/DESIGN.md v2.1 Addendum
// for full spec including threat model + edge case decisions.
//
// PR-A scope: load / save / query / cache. NO integration into
// drive_share_file handler yet — that's PR-B. This module is loaded but
// unused after PR-A merges.
//
// Sec-rev invariants this module owns:
//   - File mode 0o600 preserved through atomic write (mktemp → rename(2)).
//   - Malformed JSON fails to "file present, entries: []" semantics
//     (default-deny), never crashes the proxy.
//   - Drive ID regex anchored at write time, NOT read time (don't reject
//     entries on load just because regex tightened later).
//   - Ancestor walk depth-limited to MAX_WALK_DEPTH (10) regardless of
//     cache state — cycles cannot cause unbounded API calls.
//   - Negative cache entries respect TTL like positive ones.

import { promises as fs } from "node:fs";
import * as path from "node:path";

export const WHITELIST_FILENAME = "drive-whitelist.json";
export const MAX_WALK_DEPTH = 10;
export const DEFAULT_CACHE_CAPACITY = 1000;
export const DEFAULT_CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

// Drive file/folder IDs are opaque alphanumeric+_- strings, typically 33+ chars.
// We accept 20+ to be safe against future format changes while rejecting
// obvious typos / empty strings / shell metacharacter injection attempts.
const DRIVE_ID_REGEX = /^[A-Za-z0-9_-]{20,}$/;

// ----- types -----

export type WhitelistEntryType = "folder" | "file";

export interface WhitelistEntry {
  type: WhitelistEntryType;
  id: string;
  label: string;
  added_at: string; // ISO 8601 UTC
}

export interface WhitelistFile {
  schema_version: 1;
  updated_at: string;
  entries: WhitelistEntry[];
}

export type WhitelistState =
  | { kind: "absent" } // no file → policy OFF (v2.0 behavior)
  | { kind: "malformed"; error: string } // file present but unparseable → fail-safe default-deny
  | { kind: "loaded"; file: WhitelistFile };

export type ShareDecisionReason =
  | "policy_off"
  | "direct_match"
  | "ancestor_match"
  | "default_deny_empty"
  | "default_deny_malformed"
  | "default_deny_autonomous" // v1.53 F2 — absent whitelist + autonomous mode
  | "no_match"
  | "depth_limit"
  | "walk_failed";

export interface ShareDecision {
  allowed: boolean;
  reason: ShareDecisionReason;
  matchedId?: string;
  ancestorsWalked: number;
}

// Injected to avoid coupling this module to the Drive SDK client. The
// driveShareFile handler passes a real implementation; tests pass stubs.
export type AncestorFetcher = (fileId: string) => Promise<
  | { kind: "ok"; parents: string[]; resolvedTargetId?: string }
  | { kind: "not_found" }
>;

// ----- ID validation -----

export function isValidDriveId(id: string): boolean {
  return typeof id === "string" && DRIVE_ID_REGEX.test(id);
}

// ----- load / save -----

function whitelistPath(configDir: string): string {
  return path.join(configDir, WHITELIST_FILENAME);
}

export async function loadWhitelist(configDir: string): Promise<WhitelistState> {
  const filePath = whitelistPath(configDir);

  let raw: string;
  try {
    raw = await fs.readFile(filePath, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return { kind: "absent" };
    }
    // Non-ENOENT read errors (EACCES, EISDIR, etc.) come from the OS, not
    // from file CONTENT — safe to surface in the error string (sec-rev LOW
    // F2: the canary test covers JSON parse / validation paths; this OS-
    // error path cannot contain whitelist values because the file wasn't
    // successfully read).
    return { kind: "malformed", error: `read failed: ${(err as Error).message}` };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { kind: "malformed", error: "JSON parse failed" };
  }

  const validation = validateWhitelistFile(parsed);
  if (!validation.ok) {
    return { kind: "malformed", error: validation.error };
  }

  return { kind: "loaded", file: validation.file };
}

interface ValidationOk {
  ok: true;
  file: WhitelistFile;
}
interface ValidationErr {
  ok: false;
  error: string;
}

// Sec-rev requirement: error messages name FIELDS, never echo VALUES, so a
// malformed file with secret-adjacent garbage doesn't surface via stderr.
function validateWhitelistFile(input: unknown): ValidationOk | ValidationErr {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return { ok: false, error: "root is not an object" };
  }
  const obj = input as Record<string, unknown>;

  if (obj.schema_version !== 1) {
    return { ok: false, error: "schema_version must be 1" };
  }
  if (typeof obj.updated_at !== "string") {
    return { ok: false, error: "updated_at must be string" };
  }
  if (!Array.isArray(obj.entries)) {
    return { ok: false, error: "entries must be array" };
  }

  const entries: WhitelistEntry[] = [];
  for (let i = 0; i < obj.entries.length; i++) {
    const e = obj.entries[i];
    if (typeof e !== "object" || e === null || Array.isArray(e)) {
      return { ok: false, error: `entry index out-of-shape` };
    }
    const entry = e as Record<string, unknown>;
    if (entry.type !== "folder" && entry.type !== "file") {
      return { ok: false, error: "entry type must be folder or file" };
    }
    if (typeof entry.id !== "string" || entry.id.length === 0) {
      return { ok: false, error: "entry id must be non-empty string" };
    }
    // Note: id format NOT regex-checked here. Validation happens at write
    // time (saveWhitelist via isValidDriveId). Loading is lenient so a
    // future regex tightening doesn't brick existing configs.
    if (typeof entry.label !== "string") {
      return { ok: false, error: "entry label must be string" };
    }
    if (typeof entry.added_at !== "string") {
      return { ok: false, error: "entry added_at must be string" };
    }
    entries.push({
      type: entry.type,
      id: entry.id,
      label: entry.label,
      added_at: entry.added_at,
    });
  }

  return {
    ok: true,
    file: {
      schema_version: 1,
      updated_at: obj.updated_at,
      entries,
    },
  };
}

// Atomic write: tmp sibling at mode 0o600 → rename(2). On macOS APFS rename
// is atomic on same filesystem. Tmp file inherits 0o600 across the rename.
export async function saveWhitelist(
  configDir: string,
  file: WhitelistFile,
): Promise<void> {
  // Validate Drive IDs at write time. Loading is lenient (see above) but
  // writing enforces the regex so corrupted entries never enter the file.
  for (const entry of file.entries) {
    if (!isValidDriveId(entry.id)) {
      throw new Error(
        `invalid Drive ID format (entry index rejected at write time)`,
      );
    }
  }

  const target = whitelistPath(configDir);
  await fs.mkdir(configDir, { recursive: true, mode: 0o700 });

  const tmpPath = `${target}.write.${randomSuffix()}`;
  const content = JSON.stringify(file, null, 2) + "\n";

  // 'wx' = O_WRONLY | O_CREAT | O_EXCL — atomic create-only at mode 0o600.
  const fh = await fs.open(tmpPath, "wx", 0o600);
  try {
    await fh.writeFile(content, { encoding: "utf8" });
  } finally {
    await fh.close();
  }

  try {
    await fs.rename(tmpPath, target);
  } catch (err) {
    await fs.unlink(tmpPath).catch(() => {});
    throw err;
  }
}

function randomSuffix(): string {
  // 8 hex chars — filename uniqueness only (not cryptographic).
  return Math.floor(Math.random() * 0xffffffff)
    .toString(16)
    .padStart(8, "0");
}

// ----- LRU cache with per-entry TTL -----

interface CacheEntry {
  ancestors: Set<string>;
  expiresAt: number;
}

export class AncestorCache {
  private readonly capacity: number;
  private readonly ttlMs: number;
  private readonly data: Map<string, CacheEntry> = new Map();
  private hitCount = 0;
  private missCount = 0;

  constructor(
    capacity: number = DEFAULT_CACHE_CAPACITY,
    ttlMs: number = DEFAULT_CACHE_TTL_MS,
  ) {
    this.capacity = capacity;
    this.ttlMs = ttlMs;
  }

  /** Returns cached ancestors if present and unexpired; touches LRU recency.
   * Returns undefined on miss or expiry. */
  get(fileId: string): Set<string> | undefined {
    const entry = this.data.get(fileId);
    if (entry === undefined) {
      this.missCount++;
      return undefined;
    }
    if (Date.now() >= entry.expiresAt) {
      this.data.delete(fileId);
      this.missCount++;
      return undefined;
    }
    // LRU touch: re-insert moves key to tail of Map iteration order.
    this.data.delete(fileId);
    this.data.set(fileId, entry);
    this.hitCount++;
    return entry.ancestors;
  }

  /** Inserts ancestors for fileId. Evicts LRU head when at capacity. */
  set(fileId: string, ancestors: Set<string>): void {
    if (this.data.has(fileId)) {
      this.data.delete(fileId); // refresh recency
    } else if (this.data.size >= this.capacity) {
      const oldest = this.data.keys().next().value;
      if (oldest !== undefined) {
        this.data.delete(oldest);
      }
    }
    this.data.set(fileId, {
      ancestors: new Set(ancestors),
      expiresAt: Date.now() + this.ttlMs,
    });
  }

  size(): number {
    return this.data.size;
  }
  hits(): number {
    return this.hitCount;
  }
  misses(): number {
    return this.missCount;
  }
  clear(): void {
    this.data.clear();
    this.hitCount = 0;
    this.missCount = 0;
  }
}

// ----- query -----

interface EntryIndex {
  folders: Set<string>;
  files: Set<string>;
  empty: boolean;
}

function indexEntries(file: WhitelistFile): EntryIndex {
  const folders = new Set<string>();
  const files = new Set<string>();
  for (const e of file.entries) {
    if (e.type === "folder") folders.add(e.id);
    else files.add(e.id);
  }
  return { folders, files, empty: file.entries.length === 0 };
}

/** Main share-decision function. Pure: takes state + fetcher + optional
 * cache, returns a decision. Does NOT throw — all error paths produce a
 * deny ShareDecision with a reason.
 *
 * Sec-rev invariants:
 *   - state.kind === "absent" → allowed:true (policy off) — UNLESS v1.53 F2
 *     autonomous mode is on, in which case absent → allowed:false
 *     (deny-by-default; an unconfigured whitelist shares nothing under autonomy)
 *   - state.kind === "malformed" → allowed:false (fail-safe deny)
 *   - state.kind === "loaded" && entries=[] → allowed:false
 *   - walk halts at MAX_WALK_DEPTH regardless of cache contents
 *   - fetcher "not_found" → deny, NOT cached (so retry is possible)
 *   - fetcher throws → deny, NOT cached */
export async function checkShareAllowed(
  fileId: string,
  state: WhitelistState,
  fetcher: AncestorFetcher,
  cache?: AncestorCache,
  autonomous = false,
): Promise<ShareDecision> {
  if (state.kind === "absent") {
    // v1.53 F2: autonomous/strict mode flips the absent=allow default to deny.
    if (autonomous) {
      return { allowed: false, reason: "default_deny_autonomous", ancestorsWalked: 0 };
    }
    return { allowed: true, reason: "policy_off", ancestorsWalked: 0 };
  }
  if (state.kind === "malformed") {
    return { allowed: false, reason: "default_deny_malformed", ancestorsWalked: 0 };
  }

  const idx = indexEntries(state.file);
  if (idx.empty) {
    return { allowed: false, reason: "default_deny_empty", ancestorsWalked: 0 };
  }

  // Direct file match — no ancestor walk needed.
  if (idx.files.has(fileId)) {
    return {
      allowed: true,
      reason: "direct_match",
      matchedId: fileId,
      ancestorsWalked: 0,
    };
  }

  // Cache check before walking. Cache stores the ancestor set seen on a
  // prior walk for this fileId; we re-check that set against the (possibly
  // updated within this same proxy run? no — read-once-at-startup) whitelist.
  const cached = cache?.get(fileId);
  if (cached !== undefined) {
    for (const ancestorId of cached) {
      if (idx.folders.has(ancestorId)) {
        return {
          allowed: true,
          reason: "ancestor_match",
          matchedId: ancestorId,
          ancestorsWalked: cached.size,
        };
      }
    }
    return { allowed: false, reason: "no_match", ancestorsWalked: cached.size };
  }

  // BFS walk over parent graph. Drive permits multi-parent; visit each node
  // at most once via `visited` set. `walked` counts NODES DEQUEUED (= fetcher
  // calls). Sec-rev fix: incrementing per-parent (inner loop) lets a chain
  // of shortcuts (each with parents=[] + resolvedTargetId pointing to the
  // next shortcut) drive unbounded fetches because `walked` would never
  // increment. Counting per-dequeue bounds BOTH parent walks and shortcut
  // chains at MAX_WALK_DEPTH fetcher calls.
  const visited = new Set<string>();
  const queue: string[] = [fileId];
  let walked = 0;
  let matchedFolder: string | undefined;
  let walkFailed = false;

  while (queue.length > 0 && walked < MAX_WALK_DEPTH) {
    const current = queue.shift()!;
    if (visited.has(current)) continue;
    visited.add(current);
    walked++; // count one fetcher call per dequeue (see comment above).

    let result: Awaited<ReturnType<AncestorFetcher>>;
    try {
      result = await fetcher(current);
    } catch {
      walkFailed = true;
      break;
    }

    if (result.kind === "not_found") {
      walkFailed = true;
      break;
    }

    // Shortcut resolution: target's parents are what we want. Each shortcut
    // hop costs one outer-loop iteration so the depth limit applies.
    if (result.resolvedTargetId !== undefined && !visited.has(result.resolvedTargetId)) {
      queue.push(result.resolvedTargetId);
    }

    for (const parentId of result.parents) {
      if (idx.folders.has(parentId)) {
        matchedFolder = parentId;
        break;
      }
      if (!visited.has(parentId)) {
        queue.push(parentId);
      }
    }
    if (matchedFolder !== undefined) break;
  }

  if (walkFailed) {
    // Don't cache — retry should be possible.
    return { allowed: false, reason: "walk_failed", ancestorsWalked: walked };
  }

  if (matchedFolder !== undefined) {
    if (cache !== undefined) {
      const ancestors = new Set(visited);
      ancestors.delete(fileId);
      ancestors.add(matchedFolder);
      cache.set(fileId, ancestors);
    }
    return {
      allowed: true,
      reason: "ancestor_match",
      matchedId: matchedFolder,
      ancestorsWalked: walked,
    };
  }

  if (walked >= MAX_WALK_DEPTH) {
    // Don't cache depth_limit — a future whitelist change could make
    // shallower lookups succeed, and we don't want a stale "denied" sticking.
    return { allowed: false, reason: "depth_limit", ancestorsWalked: walked };
  }

  // Negative cache: fully resolved, nothing matched. Cache so subsequent
  // calls on the same fileId skip the API.
  if (cache !== undefined) {
    const ancestors = new Set(visited);
    ancestors.delete(fileId);
    cache.set(fileId, ancestors);
  }
  return { allowed: false, reason: "no_match", ancestorsWalked: walked };
}

// ----- per-process singletons (load-once, MCP-restart-clears) -----
//
// The whitelist is read once at proxy startup and stays loaded for the
// process lifetime. To pick up edits the user must restart Claude Code —
// same model as SAFESPACE_TIER. The cache singleton has the same lifetime.
//
// Tests can reset these via __internal.resetSingletons.

let cachedStatePromise: Promise<WhitelistState> | undefined;
let cachedAncestorCache: AncestorCache | undefined;

/** Returns the per-process WhitelistState, loading on first call. Subsequent
 *  calls share the same Promise (so concurrent calls don't race). */
export function getWhitelistState(configDir: string): Promise<WhitelistState> {
  if (cachedStatePromise === undefined) {
    cachedStatePromise = loadWhitelist(configDir);
  }
  return cachedStatePromise;
}

/** Returns the per-process LRU ancestor cache. Lazy-init at default
 *  capacity (1000) + TTL (10 min). */
export function getAncestorCache(): AncestorCache {
  if (cachedAncestorCache === undefined) {
    cachedAncestorCache = new AncestorCache();
  }
  return cachedAncestorCache;
}

// Test-only exports — do NOT use outside this module's tests. These are
// pure functions; calling them directly doesn't bypass any security
// invariant (state.kind is what gates checkShareAllowed), but reaching for
// them in PR-B/-C / handlers / wizard would skip the load-time state-
// machine wrapping and be a code smell. Use loadWhitelist + checkShareAllowed
// from production code.
/** @internal */
export const __internal = {
  validateWhitelistFile,
  indexEntries,
  DRIVE_ID_REGEX,
  resetSingletons: () => {
    cachedStatePromise = undefined;
    cachedAncestorCache = undefined;
  },
};
