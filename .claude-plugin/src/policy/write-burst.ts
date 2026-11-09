// v1.52 F1 — universal write/delete burst guard (Autonomy Hardening track).
//
// docs/v1.52-autonomy-hardening.md §4.1. Closes the runaway-loop gap (P1): of
// the ~75 MCP tools only youtube comment/search had any rate cap. F1 bounds the
// NUMBER of state-changing calls in a rolling window.
//
//   - READS ARE COMPLETELY EXEMPT (owner-locked): min_tier === "read" has zero
//     blast radius, so e.g. a 200-message Gmail order-scan is never throttled.
//   - Only write + permanent-delete calls are counted, in two INDEPENDENT
//     buckets (the delete bucket is tighter).
//
// Q2 LOCKED = sliding-window rate (NOT a hard session-count): a long LEGITIMATE
// unattended run is not killed; only a tight berserk loop trips it.
//
// Increment-BEFORE-permit semantics (mirrors youtube-search-burst, not
// comment-burst): a call that is throttled does NOT consume budget, but a call
// that is PERMITTED records its timestamp before the SDK call — so a retry-storm
// at this gate cannot bypass the cap.
//
// Composes with the existing per-call batch caps (e.g. gmail batch ≤100 msgs):
// F1 bounds call-rate, the batch caps bound items-per-call → together they bound
// total items per window. F1 deliberately counts CALLS, not items.
//
// Limits reuse makeBurstLimitReader (policy/burst.ts) and are LENIENT by default
// so interactive use is unaffected; F2 (v1.53, SAFESPACE_AUTONOMOUS) will tighten
// them for unattended deployments. Per-call env resolution (uncached) → an
// operator can raise a cap mid-session without an MCP restart.

import { makeBurstLimitReader } from "./burst";
import { MCPError } from "../errors";
import type { Tier } from "../tier";
import { ENV_WRITE_BURST_LIMIT, ENV_DELETE_BURST_LIMIT } from "../config";

// Rolling-window length. A fixed constant (the two LIMITS are the operator
// knobs); 60s is the natural "calls per minute" window. Exposed via __internal
// for tests.
const WINDOW_MS = 60_000;

// Lenient interactive defaults (F2 tightens). MAX is high because this is a
// per-MINUTE rate, not the ~per-session counts the youtube bursts cap at 100.
const WRITE_BURST_DEFAULT = 60;
const DELETE_BURST_DEFAULT = 20;
// The bounds the env readers clamp to.
export const BURST_MIN = 1;
export const BURST_MAX = 100_000;

/** Per-call write-bucket limit (state-changing calls per rolling window).
 *  SAFESPACE_WRITE_BURST_LIMIT; bad/missing → default 60; clamp [1, 100000]. */
export const getWriteBurstLimit: () => number = makeBurstLimitReader({
  envVar: ENV_WRITE_BURST_LIMIT,
  defaultLimit: WRITE_BURST_DEFAULT,
  min: BURST_MIN,
  max: BURST_MAX,
});

/** Per-call delete-bucket limit (permanent-deletes per rolling window, tighter).
 *  SAFESPACE_DELETE_BURST_LIMIT; bad/missing → default 20; clamp [1, 100000]. */
export const getDeleteBurstLimit: () => number = makeBurstLimitReader({
  envVar: ENV_DELETE_BURST_LIMIT,
  defaultLimit: DELETE_BURST_DEFAULT,
  min: BURST_MIN,
  max: BURST_MAX,
});

// PERMANENT-delete tool names → the (tighter) delete bucket. Aligned with the
// `safespace audit deletes` classifier (cli/audit/deletes.ts: tasks_delete /
// youtube_comment_delete / youtube_playlist_delete / calendar_delete_event)
// PLUS gmail_delete_draft (drafts bypass Trash = permanent) and drive_delete_file
// (files.delete bypasses the trash). RECOVERABLE
// mutations are deliberately NOT here — they fall in the write bucket:
// youtube_playlist_item_remove (re-add), gmail trash/archive (recoverable),
// gmail_delete_filter (recreate), tasks_clear (hide), drive_unshare_file
// (recovery action), drive_trash_file (30-day Drive trash). F4 (v1.54) reuses this exact set for its autonomous-mode
// hard-deny.
export const PERMANENT_DELETE_TOOLS: ReadonlySet<string> = new Set([
  "tasks_delete",
  "youtube_comment_delete",
  "youtube_playlist_delete",
  "calendar_delete_event",
  "gmail_delete_draft",
  "drive_delete_file",
]);

export type WriteBurstBucket = "exempt" | "write" | "delete";

/** Classify a tool into a burst bucket. Reads (min_tier === "read") and unknown
 *  tools (undefined min_tier — should not happen for a real tool) are EXEMPT.
 *  Permanent-delete tools → "delete"; all other state-changing tools → "write". */
export function classifyWriteTool(
  toolName: string,
  minTier: Tier | undefined,
): WriteBurstBucket {
  if (minTier === undefined || minTier === "read") return "exempt";
  if (PERMANENT_DELETE_TOOLS.has(toolName)) return "delete";
  return "write";
}

// ── sliding-window state ────────────────────────────────────────────────────
// One process-wide pair of windows (one operator per process). Reset on MCP server
// restart — no durable state; restart IS the recovery path.
let writes: number[] = [];
let deletes: number[] = [];

function pruned(arr: number[], now: number): number[] {
  const cutoff = now - WINDOW_MS;
  return arr.filter((t) => t > cutoff);
}

/** Enforce the burst window for ONE counted call. No-op for "exempt". Throws
 *  MCPError("write_burst_limit_exceeded", { reason }) BEFORE the SDK call when the
 *  rolling window is full; otherwise records the call timestamp
 *  (increment-before-permit). `now` is injectable for tests. */
export function enforceWriteBurst(bucket: WriteBurstBucket, now: number = Date.now()): void {
  if (bucket === "exempt") return;
  if (bucket === "delete") {
    deletes = pruned(deletes, now);
    if (deletes.length >= getDeleteBurstLimit()) {
      throw new MCPError("write_burst_limit_exceeded", { reason: "delete" });
    }
    deletes.push(now);
    return;
  }
  writes = pruned(writes, now);
  if (writes.length >= getWriteBurstLimit()) {
    throw new MCPError("write_burst_limit_exceeded", { reason: "write" });
  }
  writes.push(now);
}

export function getWriteBurstCounts(now: number = Date.now()): { write: number; delete: number } {
  return { write: pruned(writes, now).length, delete: pruned(deletes, now).length };
}

export function __resetWriteBurstForTests(): void {
  if (process.env.NODE_ENV !== "test" && process.env.BUN_ENV !== "test") {
    throw new Error("__resetWriteBurstForTests is for tests only");
  }
  writes = [];
  deletes = [];
}

/** @internal */
export const __internal = {
  WINDOW_MS,
  WRITE_BURST_DEFAULT,
  DELETE_BURST_DEFAULT,
  BURST_MIN,
  BURST_MAX,
};
