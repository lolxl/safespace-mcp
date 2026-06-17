// v1.106 — SAFESPACE_YOUTUBE_VIDEO_TARGETS allowlist module.
//
// Gate #3 of the `youtube_video_update` (videos.update snippet metadata) write
// chain, the deny-default target allowlist that confines WHICH of the owner's
// videos the agent may re-title / re-describe / re-tag:
//
//   1. SAFESPACE_TIER=write          (existing tier check; defense-in-depth in handler)
//   2. OAuth scope youtube.force-ssl (existing scopeSatisfies; same scope as the
//                                     comment / playlist writes — ZERO new scope)
//   3. THIS MODULE — videoId ∈ SAFESPACE_YOUTUBE_VIDEO_TARGETS (default-empty =
//      HARD-DENY even with scope + tier granted)
//   4. 6-step outboundSanitize per field + F3a secret-shape (in the handler / egress gate)
//
// WHY deny-default (off→DENY), unlike the playlist writes (off→no-allowlist):
//   A video's title + description is the MOST public, identity-defining text on
//   the channel — far more visible than a playlist title (plumbing) — so a
//   prompt-injected agent rewriting a flagship video's title with a phishing
//   line is a real attack. This mirrors the public-surface deny-default of
//   `youtube-comment-targets.ts` + the github write/merge/approve gates, the
//   OPPOSITE of the off→allow service-token recipient lists.
//
// Format: comma-separated typed-prefix entries (deliberately `video:<id>` ONLY):
//   - `video:<11-char>`  — exactly 11 URL-safe-base64 chars
//
// `channel:` / `playlist:` are REJECTED here (loud config error), unlike
// youtube-comment-targets which accepts all three. A video-metadata write
// targets ONE owned video by id; a `channel:` allowlist entry would require
// resolving the video's channelId via a videos.list pre-fetch (TOCTOU + extra
// quota) — the same resolution the comment first-cut deferred. Video-only keeps
// the gate pre-fetch-free.
//
// Two-layer model (mirrors youtube-comment-targets.ts / recipient-allowlist.ts):
//   - SAFESPACE_YOUTUBE_VIDEO_TARGETS         (persistent; configured in safespace.env)
//   - SAFESPACE_YOUTUBE_VIDEO_TARGETS_EXTRA   (shell-only; per-session)
//
// Default-empty hard-deny: env var unset OR "" OR whitespace-only OR
// malformed-only → empty Set, ALL video-metadata writes rejected with
// `video_target_denied_by_policy` (-32052).

import {
  ENV_YOUTUBE_VIDEO_TARGETS as ENV_TARGETS,
  ENV_YOUTUBE_VIDEO_TARGETS_EXTRA as ENV_TARGETS_EXTRA,
} from "../config";

export { ENV_TARGETS, ENV_TARGETS_EXTRA };

// ----- types -----

export interface VideoTargetParseResult {
  ok: string[]; // video ids
  rejected: string[];
}

export type VideoTargetAllowlistState =
  | { kind: "off" }
  | { kind: "active"; videoIds: ReadonlySet<string> };

export interface VideoTargetAllowlistSummary {
  kind: "off" | "active";
  count: number;
}

// ----- regex (locked) -----

// Same charset (YouTube's documented 11-char video-ID format) as the
// youtube-comment-targets `video:` payload + the handler's YOUTUBE_VIDEO_ID_RE.
const VIDEO_RE = /^[A-Za-z0-9_-]{11}$/;

// ----- parsing -----

/** Parse a comma-separated `video:<id>` allowlist string. Case-sensitive
 *  `video:` prefix only; any other prefix (`channel:` / `playlist:` / bare
 *  id / extra colon) is rejected loudly (config error, not silent drop). */
export function parseVideoTargets(input: string | undefined): VideoTargetParseResult {
  const result: VideoTargetParseResult = { ok: [], rejected: [] };
  if (input === undefined) return result;

  const tokens = input
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t.length > 0);

  const seen = new Set<string>();
  for (const token of tokens) {
    if (seen.has(token)) continue;
    seen.add(token);

    const colonIdx = token.indexOf(":");
    if (colonIdx < 1 || colonIdx === token.length - 1) {
      result.rejected.push(token);
      continue;
    }
    const prefix = token.slice(0, colonIdx);
    const payload = token.slice(colonIdx + 1);

    // Case-sensitive `video:` only. `Video:` / `channel:` / `playlist:` reject.
    if (prefix === "video" && VIDEO_RE.test(payload)) {
      result.ok.push(payload);
    } else {
      result.rejected.push(token);
    }
  }

  return result;
}

// ----- matching -----

/** Default-deny: `off` → false (env unset = HARD-DENY, the public-surface
 *  posture); `active` + id ∈ set → true. Asymmetric vs the service-token
 *  recipient lists (off→allow) — same as youtube-comment-targets. */
export function isVideoTargetAllowed(
  videoId: string,
  state: VideoTargetAllowlistState,
): boolean {
  if (state.kind === "off") return false;
  if (typeof videoId !== "string" || videoId.length === 0) return false;
  return state.videoIds.has(videoId);
}

// ----- summary (count-only, no values — for doctor --posture) -----

export function summarizeVideoTargetAllowlist(
  state: VideoTargetAllowlistState,
): VideoTargetAllowlistSummary {
  if (state.kind === "off") return { kind: "off", count: 0 };
  return { kind: "active", count: state.videoIds.size };
}

// ----- state building (pure helper, no env / no console) -----

/** Off semantics: both env vars undefined → off (policy not configured).
 *  Either non-undefined (incl. "") → active (explicit default-deny even when
 *  the value yields zero valid entries). Merges base + extra, deduped. */
export function buildVideoTargetAllowlistState(
  targetsEnv: string | undefined,
  extraEnv: string | undefined,
): VideoTargetAllowlistState {
  if (targetsEnv === undefined && extraEnv === undefined) {
    return { kind: "off" };
  }
  const baseParsed = parseVideoTargets(targetsEnv);
  const extraParsed = parseVideoTargets(extraEnv);
  const videoIds = new Set<string>();
  for (const id of [...baseParsed.ok, ...extraParsed.ok]) {
    videoIds.add(id);
  }
  return { kind: "active", videoIds };
}

// ----- per-process singleton (load-once, MCP-restart-clears) -----

let cachedState: VideoTargetAllowlistState | undefined;
let warnEmitted = false;

/** Load the allowlist state once per process. Mirrors youtube-comment-targets.ts:
 *  WARN-ONCE on _EXTRA-without-base + per-malformed-token stderr at load. */
export function getVideoTargetAllowlistState(): VideoTargetAllowlistState {
  if (cachedState !== undefined) return cachedState;

  const targetsEnv = process.env[ENV_TARGETS];
  const extraEnv = process.env[ENV_TARGETS_EXTRA];

  if (
    !warnEmitted &&
    targetsEnv === undefined &&
    typeof extraEnv === "string" &&
    extraEnv.length > 0
  ) {
    console.error(
      "[safespace] WARNING: SAFESPACE_YOUTUBE_VIDEO_TARGETS_EXTRA is set " +
        "but SAFESPACE_YOUTUBE_VIDEO_TARGETS is not. Video-metadata-write allowlist " +
        "is in default-deny mode with EXTRA only. If you intended to leave the " +
        "allowlist OFF, also unset SAFESPACE_YOUTUBE_VIDEO_TARGETS_EXTRA.",
    );
    warnEmitted = true;
  }

  const baseParsed = parseVideoTargets(targetsEnv);
  const extraParsed = parseVideoTargets(extraEnv);
  for (const rej of [...baseParsed.rejected, ...extraParsed.rejected]) {
    console.error(
      `[safespace] WARNING: SAFESPACE_YOUTUBE_VIDEO_TARGETS rejected malformed entry: ${rej}`,
    );
  }

  cachedState = buildVideoTargetAllowlistState(targetsEnv, extraEnv);

  if (cachedState.kind === "active" && cachedState.videoIds.size === 0) {
    console.error(
      "[safespace] WARNING: SAFESPACE_YOUTUBE_VIDEO_TARGETS is set but " +
        "yielded 0 valid entries — video-metadata writes will be hard-denied. " +
        "Check syntax: comma-separated `video:<11-char-id>`.",
    );
  }

  return cachedState;
}

// Test-only — do NOT use outside this module's tests.
/** @internal */
export const __internal = {
  VIDEO_RE,
  resetSingletons: (): void => {
    cachedState = undefined;
    warnEmitted = false;
  },
};
