// v1.16 Phase 2a — SAFESPACE_YOUTUBE_COMMENT_BURST_LIMIT per-session counter.
//
// Multi-gate write-protection — this is gate #4 of 4 for the Phase 2b
// `youtube_video_comment_post` and `youtube_comment_reply` handlers
// (NOT shipped yet; this module is Phase 2a infrastructure):
//
//   1. SAFESPACE_TIER=write
//   2. OAuth scope = youtube.force-ssl
//   3. target ∈ SAFESPACE_YOUTUBE_COMMENT_TARGETS (youtube-comment-targets.ts)
//   4. THIS MODULE — per-session burst counter (default 10, range 1-100)
//
// Default cap 10. Reduces prompt-injection blast radius from quota-max
// ~200 comment-posts/day (50 quota units × 200 = 10000u daily quota) down
// to 10 (~95% reduction). Counter is per-process (= per MCP server
// lifetime = per Claude session). Reset on MCP server restart — no
// durable state.
//
// Env var: SAFESPACE_YOUTUBE_COMMENT_BURST_LIMIT (integer, range 1-100,
// default 10). Out-of-range / parse-failure / missing → default 10.
// Out-of-range HIGH → clamped to MAX 100. Out-of-range LOW → fallback to
// DEFAULT 10 (NOT clamped to MIN 1, mirrors search-burst-limit pattern;
// "0" is treated as "operator made a mistake, fall back to safe default"
// not "operator wanted 0 = no comments allowed").
//
// Counter semantics — Phase 2b handler responsibility:
//   - Check FIRST (read counter, compare to limit) — if at limit, throw
//     `comment_burst_limit_exceeded` (-32025) BEFORE the SDK call.
//   - Increment ON SUCCESS only — failed SDK calls (network, 4xx, 5xx) do
//     NOT consume budget. Asymmetric vs search-burst (which increments
//     before the SDK call to prevent retry-storm bypass at a higher-cost
//     gate); comment-burst is the 4th gate AFTER the allowlist check, so
//     retry-storm is bounded upstream. Phase 2b spec locks this; this
//     module provides BOTH primitives (`checkBurst` for the pre-check
//     and `incrementBurst` for the post-success step).
//
// See docs/v1.16-youtube-api.md §13 Risk 3 + §11 sec-rev hook #18.

import { makeBurstLimitReader } from "./burst";
import { ENV_YOUTUBE_COMMENT_BURST_LIMIT } from "../config";

const COMMENT_BURST_DEFAULT = 10;
const COMMENT_BURST_MIN = 1;
const COMMENT_BURST_MAX = 100;

/** Read + clamp the burst limit from env. Range 1-100; bad values
 *  (non-integer / out-of-range / parse failure) fall back to default 10.
 *  Per-call resolution (NOT cached) so env-var override mid-session
 *  applies on the next call — operator can raise the cap without restart.
 *  Mirrors `getYoutubeSearchBurstLimit`. v1.40: the parser body is the shared
 *  `makeBurstLimitReader` (policy/burst.ts); behavior is byte-identical to the
 *  prior inline implementation. */
export const getCommentBurstLimit: () => number = makeBurstLimitReader({
  envVar: ENV_YOUTUBE_COMMENT_BURST_LIMIT,
  defaultLimit: COMMENT_BURST_DEFAULT,
  min: COMMENT_BURST_MIN,
  max: COMMENT_BURST_MAX,
});

/* ── per-session counter state ─────────────────────────────────────────
 *
 * Module-level integer. Reset on MCP server restart (= new Claude
 * session). No durable state — restart IS the recovery path.
 *
 * Phase 2b handler will check + (optionally) increment via the helpers
 * below. Exposed `getCommentBurstCount` for diagnostic / audit use. */
let commentsPostedThisSession = 0;

export function getCommentBurstCount(): number {
  return commentsPostedThisSession;
}

/** Check whether a comment-post is permitted under the current burst
 *  counter + env-var limit. Returns { ok, current, limit } — handler is
 *  responsible for throwing `comment_burst_limit_exceeded` when ok=false.
 *
 *  Does NOT increment. Increment via `incrementCommentBurst()` after the
 *  SDK call succeeds (Phase 2b spec; this module exposes both primitives).
 *  Pre-check separation lets the handler include the burst-limit gate in
 *  audit denial decisions without consuming counter budget. */
export function checkCommentBurst(): { ok: boolean; current: number; limit: number } {
  const limit = getCommentBurstLimit();
  if (commentsPostedThisSession >= limit) {
    return { ok: false, current: commentsPostedThisSession, limit };
  }
  return { ok: true, current: commentsPostedThisSession, limit };
}

/** Increment the per-session counter. Phase 2b handler calls this AFTER
 *  the SDK comment-post succeeds (success-only semantics, per design §13
 *  Risk 3 + hook #18). */
export function incrementCommentBurst(): void {
  commentsPostedThisSession++;
}

/** Test-only counter reset. Gated to NODE_ENV / BUN_ENV === "test" so a
 *  stray production call throws loudly. Mirrors
 *  `__resetYoutubeSearchCounterForTest` in handlers.ts. */
export function __resetCommentBurstForTest(): void {
  if (process.env.NODE_ENV !== "test" && process.env.BUN_ENV !== "test") {
    throw new Error("__resetCommentBurstForTest is for tests only");
  }
  commentsPostedThisSession = 0;
}

// Test-only constants exposed for sentinel tests.
/** @internal */
export const __internal = {
  COMMENT_BURST_DEFAULT,
  COMMENT_BURST_MIN,
  COMMENT_BURST_MAX,
};
