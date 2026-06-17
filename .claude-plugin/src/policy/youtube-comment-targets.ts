// v1.16 Phase 2a — SAFESPACE_YOUTUBE_COMMENT_TARGETS allowlist module.
//
// Multi-gate write-protection — this is gate #3 of 4 for the Phase 2b
// `youtube_video_comment_post` and `youtube_comment_reply` handlers (which
// have NOT shipped yet; this module is Phase 2a infrastructure):
//
//   1. SAFESPACE_TIER=write    (existing tier check; no new code)
//   2. OAuth scope = youtube.force-ssl (existing scopeSatisfies; gated by
//                                       Phase 2a's SCOPE_HIERARCHY 2nd key)
//   3. THIS MODULE — target ∈ SAFESPACE_YOUTUBE_COMMENT_TARGETS (default-empty
//      = HARD-DENY even with scope + tier granted)
//   4. SAFESPACE_YOUTUBE_COMMENT_BURST_LIMIT (per-session counter; see
//      youtube-comment-burst.ts)
//
// Format: comma-separated typed-prefix entries (locked, per design §4.1.1):
//   - `video:<11-char>`                — exactly 11 URL-safe-base64 chars
//   - `channel:UC<22-char>`            — UC prefix + 22 URL-safe-base64 chars (24 total)
//   - `playlist:(PL|UU|LL|OL|FL|RD)<1-64>` — prefix + 1-64 URL-safe-base64 chars
//
// Case sensitivity: prefix MUST be lowercase (`video:` / `channel:` / `playlist:`).
// Mixed-case (`Video:`, `CHANNEL:`) rejected — `Video:abc...` is a config
// error, not a casing quirk to silently accept.
//
// Two-layer model (mirrors recipient-allowlist.ts):
//   - SAFESPACE_YOUTUBE_COMMENT_TARGETS         (persistent; configured in safespace.env)
//   - SAFESPACE_YOUTUBE_COMMENT_TARGETS_EXTRA   (shell-only; per-session)
//
// WARN-ONCE: if _TARGETS_EXTRA set but _TARGETS unset, emit ONE console.error
// at module load (mirror recipient-allowlist.ts:242-247). NEVER per-call
// (would leak via audit-log volume + spam stderr).
//
// Default-empty hard-deny: env var unset OR set to "" OR set to whitespace-
// only OR set to malformed-only — all yield empty Set, ALL comment writes
// are rejected with `comment_target_denied_by_policy` (-32023). This
// mirrors v2.2 SAFESPACE_RECIPIENT_ALLOW default-deny and v2.1
// drive-whitelist.json default-deny.
//
// Sec-rev hooks owned by this module:
//   #9  (default-empty hard-denies even with scope granted)
//   #10 (target resolution gate)
//   §4.1.1 parser rules locked: case-sensitive prefix, per-type regex,
//   DoS cap on playlist payload (64 char), dedup, whitespace tolerance.
//
// See docs/v1.16-youtube-api.md §4.1 + §4.1.1.

import {
  ENV_YOUTUBE_COMMENT_TARGETS as ENV_TARGETS,
  ENV_YOUTUBE_COMMENT_TARGETS_EXTRA as ENV_TARGETS_EXTRA,
} from "../config";

export { ENV_TARGETS, ENV_TARGETS_EXTRA };

// ----- types -----

export type CommentTargetType = "video" | "channel" | "playlist";

export interface ParsedCommentTarget {
  type: CommentTargetType;
  id: string;
}

export interface CommentTargetParseResult {
  ok: ParsedCommentTarget[];
  rejected: string[];
}

export type CommentTargetAllowlistState =
  | { kind: "off" }
  | { kind: "active"; targets: ParsedCommentTarget[] };

export interface CommentTargetAllowlistSummary {
  kind: "off" | "active";
  count: number;
  video_count: number;
  channel_count: number;
  playlist_count: number;
}

// ----- regex per-type (locked) -----

// Per design §4.1.1 — each payload regex anchored + DoS-bounded length.
// Same charset (URL-safe base64 alphabet + `-` + `_`) across all three —
// YouTube's documented ID format.
const VIDEO_RE = /^[A-Za-z0-9_-]{11}$/;
const CHANNEL_RE = /^UC[A-Za-z0-9_-]{22}$/;
// Playlist prefix is one of: PL / UU / LL / OL / FL / RD (Google's known
// prefixes; UU is the uploads playlist convention used by youtube_channel_uploads).
// Length cap 64 = DoS guard (otherwise `playlist:PL` + 1 MB of `A`s would
// pass any unbounded regex).
const PLAYLIST_RE = /^(?:PL|UU|LL|OL|FL|RD)[A-Za-z0-9_-]{1,64}$/;

// ----- parsing -----

/** Parse a comma-separated typed-prefix allowlist string.
 *
 *  Rules (per design §4.1.1):
 *    - Tokens are case-sensitive on prefix (lowercase only).
 *    - Per-type regex validates the payload AFTER the colon.
 *    - Exactly ONE colon — extra colons reject (`video:abc:def`).
 *    - Whitespace inside a token rejects (`video:abc def` after trim still
 *      has internal whitespace, which the per-type regex denies).
 *    - Whitespace AROUND a token is trimmed (`  video:abc  ` ok).
 *    - Whitespace-only token rejects loudly (`,  ,` between real entries —
 *      empty filter handles outer commas, but a non-empty whitespace token
 *      doesn't reach the regex; we treat the filter as "ignore empty after
 *      trim" not "ignore whitespace-only" — matching recipient-allowlist.ts).
 *    - Duplicate (post-trim) tokens dedupped via a seen-Set.
 *
 *  Returns parsed entries + rejected tokens (for stderr-warning at load). */
export function parseCommentTargets(input: string | undefined): CommentTargetParseResult {
  const result: CommentTargetParseResult = { ok: [], rejected: [] };
  if (input === undefined) return result;

  // Per recipient-allowlist.ts convention: split + trim + filter empty.
  // Trailing/multiple commas are tolerated as human-friendly editing.
  const tokens = input
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t.length > 0);

  const seen = new Set<string>();
  for (const token of tokens) {
    if (seen.has(token)) continue;
    seen.add(token);

    // Exact one-colon split. indexOf finds the FIRST colon; we require the
    // prefix to be one of the three known lowercase keywords and the
    // remainder (the payload) to contain NO additional colon — that's
    // enforced by the per-type regex below (none of the three regexes
    // permit `:` in the payload class `[A-Za-z0-9_-]`).
    const colonIdx = token.indexOf(":");
    if (colonIdx < 1 || colonIdx === token.length - 1) {
      result.rejected.push(token);
      continue;
    }
    const prefix = token.slice(0, colonIdx);
    const payload = token.slice(colonIdx + 1);

    let parsed: ParsedCommentTarget | null = null;
    // Case-sensitive prefix match. `Video:` / `CHANNEL:` / etc. fall through
    // to rejection (loud config error, not silent normalization).
    if (prefix === "video" && VIDEO_RE.test(payload)) {
      parsed = { type: "video", id: payload };
    } else if (prefix === "channel" && CHANNEL_RE.test(payload)) {
      parsed = { type: "channel", id: payload };
    } else if (prefix === "playlist" && PLAYLIST_RE.test(payload)) {
      parsed = { type: "playlist", id: payload };
    }

    if (parsed === null) {
      result.rejected.push(token);
      continue;
    }
    result.ok.push(parsed);
  }

  return result;
}

// ----- matching -----

/** Check whether a (type, id) tuple is in the current allowlist state.
 *
 *  Default-deny semantics:
 *    - state.kind === "off" → false (env not set; HARD-DENY is the safe
 *      default for write tier — opposite of recipient-allowlist's "off
 *      means policy off"). Per design §4.1 — default-empty MUST hard-deny.
 *    - state.kind === "active" + tuple matches any entry → true.
 *    - Otherwise → false.
 *
 *  NOTE: This is asymmetric vs `isRecipientAllowed` (which returns true on
 *  state.kind === "off"). Comment-writes are a higher-risk surface
 *  (PUBLIC + PERMANENT vs trusted recipient) and the design locked
 *  default-deny. See design §4.1 + sec-rev hook #9. */
export function isCommentTargetAllowed(
  type: CommentTargetType,
  id: string,
  state: CommentTargetAllowlistState,
): boolean {
  if (state.kind === "off") return false;
  if (typeof id !== "string" || id.length === 0) return false;
  for (const entry of state.targets) {
    if (entry.type === type && entry.id === id) return true;
  }
  return false;
}

// ----- summary (for doctor / debugging — no values exposed) -----

export function summarizeCommentTargetAllowlist(
  state: CommentTargetAllowlistState,
): CommentTargetAllowlistSummary {
  if (state.kind === "off") {
    return {
      kind: "off",
      count: 0,
      video_count: 0,
      channel_count: 0,
      playlist_count: 0,
    };
  }
  let video = 0;
  let channel = 0;
  let playlist = 0;
  for (const t of state.targets) {
    if (t.type === "video") video++;
    else if (t.type === "channel") channel++;
    else if (t.type === "playlist") playlist++;
  }
  return {
    kind: "active",
    count: state.targets.length,
    video_count: video,
    channel_count: channel,
    playlist_count: playlist,
  };
}

// ----- state building (pure helper, no env / no console) -----

/** Build a CommentTargetAllowlistState from raw env-var strings.
 *
 *  Off semantics (mirrors recipient-allowlist.ts:198 distinction):
 *    - Both undefined → off (policy not configured).
 *    - Either non-undefined (incl. "") → active (explicit default-deny when
 *      the value yields zero valid entries).
 *
 *  Merges base + extra entries into a deduplicated list (dedup key:
 *  `${type}:${id}`). */
export function buildCommentTargetAllowlistState(
  targetsEnv: string | undefined,
  extraEnv: string | undefined,
): CommentTargetAllowlistState {
  if (targetsEnv === undefined && extraEnv === undefined) {
    return { kind: "off" };
  }
  const baseParsed = parseCommentTargets(targetsEnv);
  const extraParsed = parseCommentTargets(extraEnv);
  const merged: ParsedCommentTarget[] = [];
  const seenKey = new Set<string>();
  for (const t of [...baseParsed.ok, ...extraParsed.ok]) {
    const key = `${t.type}:${t.id}`;
    if (seenKey.has(key)) continue;
    seenKey.add(key);
    merged.push(t);
  }
  return { kind: "active", targets: merged };
}

// ----- per-process singleton (load-once, MCP-restart-clears) -----

let cachedState: CommentTargetAllowlistState | undefined;
let warnEmitted = false;

/** Load the allowlist state once per process. Subsequent calls return the
 *  cached state. Mirrors recipient-allowlist.ts's load-once pattern.
 *
 *  WARN-ONCE side effect: if _TARGETS_EXTRA is set without _TARGETS, emit
 *  ONE console.error at first call (not every call). Test reset clears the
 *  warn flag so the warning fires again under controlled env. */
export function getCommentTargetAllowlistState(): CommentTargetAllowlistState {
  if (cachedState !== undefined) return cachedState;

  const targetsEnv = process.env[ENV_TARGETS];
  const extraEnv = process.env[ENV_TARGETS_EXTRA];

  // WARN-ONCE: _EXTRA set, _TARGETS unset. Mirror recipient-allowlist.ts
  // wording shape — operator likely forgot to set the base config. Stderr
  // (NOT stdout) so it surfaces in Claude Code's MCP-subprocess log
  // without polluting JSON-RPC stream.
  if (
    !warnEmitted &&
    targetsEnv === undefined &&
    typeof extraEnv === "string" &&
    extraEnv.length > 0
  ) {
    console.error(
      "[safespace] WARNING: SAFESPACE_YOUTUBE_COMMENT_TARGETS_EXTRA is set " +
        "but SAFESPACE_YOUTUBE_COMMENT_TARGETS is not. Comment-write allowlist " +
        "is in default-deny mode with EXTRA only. If you intended to leave the " +
        "allowlist OFF, also unset SAFESPACE_YOUTUBE_COMMENT_TARGETS_EXTRA.",
    );
    warnEmitted = true;
  }

  // Also stderr-log any malformed tokens from EITHER env var. Single warn
  // at module load (NOT per-call). Per design §4.1.1 — do NOT silently drop
  // malformed entries (silent drop hides config error).
  const baseParsed = parseCommentTargets(targetsEnv);
  const extraParsed = parseCommentTargets(extraEnv);
  for (const rej of [...baseParsed.rejected, ...extraParsed.rejected]) {
    // Token text is operator-supplied config, NOT attacker-controlled at
    // this point (process env). Safe to log verbatim — same convention as
    // drive-whitelist.ts startup warnings.
    console.error(
      `[safespace] WARNING: SAFESPACE_YOUTUBE_COMMENT_TARGETS rejected malformed entry: ${rej}`,
    );
  }

  cachedState = buildCommentTargetAllowlistState(targetsEnv, extraEnv);

  // If env was set (active state) but yielded zero valid entries, warn
  // loudly — operator likely intended at least one entry. Hard-deny still
  // applies; this is operator-visibility, not a behavior change.
  if (cachedState.kind === "active" && cachedState.targets.length === 0) {
    console.error(
      "[safespace] WARNING: SAFESPACE_YOUTUBE_COMMENT_TARGETS is set but " +
        "yielded 0 valid entries — comment writes will be hard-denied. Check " +
        "syntax: comma-separated `video:<11-char>` / `channel:UC<22-char>` / " +
        "`playlist:<prefix><1-64-char>`.",
    );
  }

  return cachedState;
}

// Test-only — do NOT use outside this module's tests.
/** @internal */
export const __internal = {
  VIDEO_RE,
  CHANNEL_RE,
  PLAYLIST_RE,
  resetSingletons: (): void => {
    cachedState = undefined;
    warnEmitted = false;
  },
};
