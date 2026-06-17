// v1.18 Phase 1 — SAFESPACE_YOUTUBE_SEARCH_BURST_LIMIT per-session counter,
// extracted verbatim from handlers.ts:3817-3862 (v1.16 inline parser).
//
// Extraction rationale (v1.18 design §2.1 code-A3): the v1.18 `safespace
// doctor` env-var surfacing needs to read the post-clamp burst limit
// without importing from `src/tools/handlers.ts`. A `src/cli/` →
// `src/tools/` import would pull the entire handler graph into the CLI
// bundle (auth + sanitize + every Google SDK client). Hoisting the
// 30-LoC parser into `src/policy/` (alongside `youtube-comment-burst.ts`)
// keeps the dependency direction clean: CLI ← policy, tools ← policy.
//
// Behavior is UNCHANGED from the v1.16 inline implementation. Test the
// extraction by comparing this module's output to a fixture-identical
// inline parser; the existing `handlers.test.ts` burst-limit tests
// continue to run unchanged against the call site in handlers.ts.
//
// Per-process integer counter `youtubeSearchesThisSession`. Caps prompt-
// injection-driven `youtube_search` loops at the most expensive READ tool
// (100 quota units / call). Default cap 20 = 2000u = 20% of daily quota,
// still within budget yet caps over-burn.
//
// Counter resets on MCP server restart (= new Claude session). No durable
// state — restart IS the recovery path.
//
// Env var: SAFESPACE_YOUTUBE_SEARCH_BURST_LIMIT (integer, range 1-100,
// default 20). Out-of-range / parse-failure / missing → default 20.
// Out-of-range HIGH → clamped to MAX 100. Out-of-range LOW → fallback to
// DEFAULT 20 (NOT clamped to MIN 1; "0" is treated as "operator made a
// mistake, fall back to safe default" not "operator wanted 0 = no
// searches allowed"). Mirrors `youtube-comment-burst.ts` exactly.
//
// See docs/v1.16-youtube-api.md §4 + §13 Risk 3 + §11 sec-rev hook #19.

import { makeBurstLimitReader } from "./burst";
import { ENV_YOUTUBE_SEARCH_BURST_LIMIT } from "../config";

const YOUTUBE_SEARCH_BURST_DEFAULT = 20;
const YOUTUBE_SEARCH_BURST_MIN = 1;
const YOUTUBE_SEARCH_BURST_MAX = 100;

/** Read + clamp the burst limit from env. Range 1-100; bad values
 *  (non-integer / out-of-range / parse failure) fall back to default 20.
 *  Per-call resolution (NOT cached) so env-var override mid-session
 *  applies on the next call — operator can raise the cap without restart.
 *  v1.40: the parser body is the shared `makeBurstLimitReader`
 *  (policy/burst.ts); behavior is byte-identical to the prior inline impl. */
export const getYoutubeSearchBurstLimit: () => number = makeBurstLimitReader({
  envVar: ENV_YOUTUBE_SEARCH_BURST_LIMIT,
  defaultLimit: YOUTUBE_SEARCH_BURST_DEFAULT,
  min: YOUTUBE_SEARCH_BURST_MIN,
  max: YOUTUBE_SEARCH_BURST_MAX,
});

// Test-only constants exposed for sentinel tests.
/** @internal */
export const __internal = {
  YOUTUBE_SEARCH_BURST_DEFAULT,
  YOUTUBE_SEARCH_BURST_MIN,
  YOUTUBE_SEARCH_BURST_MAX,
};
