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
// Exported so the operator registry validates per-operator overrides against the
// SAME bounds the env readers clamp to (v1.92 per-operator quotas).
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
// PLUS gmail_delete_draft (drafts bypass Trash = permanent). RECOVERABLE
// mutations are deliberately NOT here — they fall in the write bucket:
// youtube_playlist_item_remove (re-add), gmail trash/archive (recoverable),
// gmail_delete_filter (recreate), tasks_clear (hide), drive_unshare_file
// (recovery action). F4 (v1.54) reuses this exact set for its autonomous-mode
// hard-deny.
export const PERMANENT_DELETE_TOOLS: ReadonlySet<string> = new Set([
  "tasks_delete",
  "youtube_comment_delete",
  "youtube_playlist_delete",
  "calendar_delete_event",
  "gmail_delete_draft",
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

// ── per-OPERATOR sliding-window state (v1.92) ──────────────────────────────
// Was a pair of module-level arrays (per-PROCESS). Now a Map keyed by the calling
// operator, so on a shared Model-B deployment one operator's burst can't exhaust
// another's budget. Model A (single operator, operatorId null) maps to ONE shared
// sentinel bucket → byte-identical to the pre-v1.92 process-wide pair.
//
// The sentinel key contains `<`/`>`, which are OUTSIDE isValidOperatorId's
// `^[A-Za-z0-9_.-]{1,64}$` (operator-registry.ts), so it can NEVER collide with a
// real registered operatorId.
//
// Reset on MCP server restart (= new session) — no durable state; restart IS the
// recovery path. Map size is bounded by the registered-operator count
// (operators.json is default-deny + small; the key is never attacker-derived), so
// there is no unbounded growth and this cycle does no active eviction — a
// churned-out operator's empty bucket simply persists until restart.
const MODEL_A_BUCKET = "<model-a>";

/** The per-call operator scope the burst gate keys on. STRUCTURAL (not an import
 *  of OperatorContext) so the policy module stays decoupled from identity —
 *  OperatorContext is assignable to it. The choke point passes its resolved
 *  context; Model A / direct callers pass the default (null operator → the shared
 *  sentinel bucket; no per-operator overrides → the global env defaults). */
export interface BurstOperator {
  readonly operatorId: string | null;
  /** Per-operator write-bucket cap (registry override); null/undefined → the
   *  global env default (`getWriteBurstLimit()`). Already validated to
   *  [BURST_MIN, BURST_MAX] at registry parse. */
  readonly writeBurstLimit?: number | null;
  /** Per-operator delete-bucket cap; null/undefined → the global env default. */
  readonly deleteBurstLimit?: number | null;
}
const MODEL_A_OP: BurstOperator = { operatorId: null };

// bucketKey → the operator's two rolling-window timestamp arrays (ms of recent
// PERMITTED calls).
const buckets = new Map<string, { write: number[]; delete: number[] }>();

function bucketFor(op: BurstOperator): { write: number[]; delete: number[] } {
  // operatorId is null (Model A) or a non-empty validated id; `||` also folds a
  // defensive empty string into the sentinel.
  const key = op.operatorId || MODEL_A_BUCKET;
  let b = buckets.get(key);
  if (b === undefined) {
    b = { write: [], delete: [] };
    buckets.set(key, b);
  }
  return b;
}

function pruned(arr: number[], now: number): number[] {
  const cutoff = now - WINDOW_MS;
  return arr.filter((t) => t > cutoff);
}

/** Enforce the burst window for ONE counted call, in the CALLING OPERATOR's
 *  bucket. No-op for "exempt". Throws MCPError("write_burst_limit_exceeded",
 *  { reason }) BEFORE the SDK call when that operator's rolling window is full;
 *  otherwise records the call timestamp (increment-before-permit). The per-operator
 *  cap is the registry override when set, else the global env default. `op`
 *  defaults to the Model-A scope and `now` is injectable — so a one-arg caller
 *  stays byte-identical to the pre-v1.92 process-wide form. */
export function enforceWriteBurst(
  bucket: WriteBurstBucket,
  op: BurstOperator = MODEL_A_OP,
  now: number = Date.now(),
): void {
  if (bucket === "exempt") return;
  const b = bucketFor(op);
  if (bucket === "delete") {
    b.delete = pruned(b.delete, now);
    if (b.delete.length >= (op.deleteBurstLimit ?? getDeleteBurstLimit())) {
      throw new MCPError("write_burst_limit_exceeded", { reason: "delete" });
    }
    b.delete.push(now);
    return;
  }
  // bucket === "write"
  b.write = pruned(b.write, now);
  if (b.write.length >= (op.writeBurstLimit ?? getWriteBurstLimit())) {
    throw new MCPError("write_burst_limit_exceeded", { reason: "write" });
  }
  b.write.push(now);
}

/** Diagnostic: an operator's current in-window counts (after pruning at `now`).
 *  Defaults to the Model-A scope. */
export function getWriteBurstCounts(
  op: BurstOperator = MODEL_A_OP,
  now: number = Date.now(),
): { write: number; delete: number } {
  const b = buckets.get(op.operatorId || MODEL_A_BUCKET);
  if (b === undefined) return { write: 0, delete: 0 };
  return {
    write: pruned(b.write, now).length,
    delete: pruned(b.delete, now).length,
  };
}

/** Test-only state reset. Gated to test env so a stray production call throws. */
export function __resetWriteBurstForTests(): void {
  if (process.env.NODE_ENV !== "test" && process.env.BUN_ENV !== "test") {
    throw new Error("__resetWriteBurstForTests is for tests only");
  }
  buckets.clear();
}

/** @internal */
export const __internal = {
  WINDOW_MS,
  WRITE_BURST_DEFAULT,
  DELETE_BURST_DEFAULT,
  BURST_MIN,
  BURST_MAX,
  MODEL_A_BUCKET,
};
