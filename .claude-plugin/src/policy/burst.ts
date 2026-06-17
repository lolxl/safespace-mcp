// v1.40 — shared burst-limit parser (DRY of the two YouTube burst modules).
//
// `youtube-comment-burst.ts` (getCommentBurstLimit, default 10) and
// `youtube-search-burst.ts` (getYoutubeSearchBurstLimit, default 20) carried a
// byte-identical env-var parser: read env -> trim -> parseInt(base 10) ->
// (non-finite OR < min) => default -> (> max) => clamp to max -> else the
// parsed value. The ONLY differences were the env-var name and the default.
// This module factors that parser out; each call site keeps its own
// constants + (for comment-burst) its own counter machinery untouched.
//
// Scope note (design v1.40 §4, Q4 = (a) parser-only): ONLY the limit parser is
// shared here. The counter machinery is deliberately NOT folded — the two
// gates have different increment semantics (comment = increment ON SUCCESS,
// in this policy dir; search = increment BEFORE the SDK call, inline in
// tools/handlers/youtube.ts) and folding them would conflate two intentional
// designs. See youtube-comment-burst.ts:25-34.
//
// Behavior contract (preserved verbatim from both prior parsers):
//   - env unset / non-string / whitespace-only        -> defaultLimit
//   - non-integer / parse failure (NaN) / value < min  -> defaultLimit
//       (NOT clamped to min: "0" or "-5" is treated as an operator mistake ->
//        safe default, not "0 = disable". Mirrors the prior LOW-fallback.)
//   - value > max                                      -> max (clamped)
//   - otherwise                                        -> the parsed value
//   - Number.parseInt's leading-numeric leniency is preserved (e.g. "12abc"
//     -> 12), since the same Number.parseInt(raw, 10) is used.
//   - Per-call resolution (NOT cached): an env override mid-session applies on
//     the next call, so an operator can raise the cap without an MCP restart.

/** Build a per-call burst-limit reader bound to one env var + default.
 *  Pure aside from the `process.env` read; the returned fn takes no args and
 *  never throws. `min` defaults to 1, `max` to 100 (the range both YouTube
 *  burst gates use). */
export function makeBurstLimitReader(opts: {
  envVar: string;
  defaultLimit: number;
  min?: number;
  max?: number;
}): () => number {
  const { envVar, defaultLimit } = opts;
  const min = opts.min ?? 1;
  const max = opts.max ?? 100;
  return function readBurstLimit(): number {
    const raw = process.env[envVar];
    if (typeof raw !== "string" || raw.trim() === "") {
      return defaultLimit;
    }
    const parsed = Number.parseInt(raw, 10);
    if (!Number.isFinite(parsed) || parsed < min) {
      return defaultLimit;
    }
    if (parsed > max) {
      return max;
    }
    return parsed;
  };
}
