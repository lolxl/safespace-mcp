// YouTube — extracted verbatim from the former monolithic
// src/tools/handlers.ts (mechanical per-API split; function bodies byte-identical).
// Re-exported via ./index.ts so existing `./handlers` import paths are unchanged.

import { MCPError } from "../../errors";
import {
  youtubeClientFromToken,
  youtubeAnalyticsClientFromToken,
} from "../../google-api/client";
import { toGoogleError } from "../../google-api/errors";
import { getYoutubeSearchBurstLimit } from "../../policy/youtube-search-burst";
import { isYoutubeAnalyticsMonetaryEnabled } from "../../policy/youtube-analytics-monetary";
import type { ToolContext } from "../types";
import type { VideoMutationAuditMeta } from "../../audit";
// B6.1 wave A2b — the comment allowlist / burst PRE-check / outbound-sanitize gate +
// the video-update allowlist / per-field sanitize / F3a gate MOVED to the pipeline-
// fired composite wrappers (tools/egress.ts, fired by withToolContext via each tool's
// egress descriptor). The handlers keep ONLY the success-only burst INCREMENT + read
// the gate's sanitized bytes off ctx.egress (requireEgressResult).
import { incrementCommentBurst } from "../../policy/youtube-comment-burst";
import { requireEgressResult } from "../egress-pipeline";

import { requireGoogle, clampYoutubeMaxResults, sha256Hex, HEADER_INJECTION_RE } from "./shared";

/** YouTube channel-ID format. `UC` prefix + 22 URL-safe chars = 24 total.
 *  Anchored regex BEFORE any `.slice()` transform (sec-rev hook #6 / §11). */
const YOUTUBE_CHANNEL_ID_RE = /^UC[A-Za-z0-9_-]{22}$/;

/** YouTube video-ID format. Exactly 11 URL-safe chars (YouTube documented
 *  format). Anchored regex BEFORE SDK call — rejects path traversal, CRLF
 *  injection, length-DoS at the handler boundary. */
const YOUTUBE_VIDEO_ID_RE = /^[A-Za-z0-9_-]{11}$/;

/** ALLOWLIST for `youtube_video_get(parts)` — default-deny. Closed set
 *  prevents silent attack-surface expansion when Google adds new parts
 *  (or when a contributor "tidies up" by switching to a denylist).
 *  Mirrors `share_role_forbidden` defense-in-depth pattern. */
const YOUTUBE_VIDEO_GET_ALLOWED_PARTS: ReadonlySet<string> = new Set([
  "snippet",
  "statistics",
  "contentDetails",
  "status",
  "topicDetails",
]);

/** ALLOWLIST for `youtube_search(video_type)`. Closed set; rejects any
 *  other value at handler boundary BEFORE SDK call (sec-rev hook #6). */
const YOUTUBE_SEARCH_TYPE_ALLOWED: ReadonlySet<string> = new Set([
  "video",
  "channel",
  "playlist",
]);

/** ALLOWLIST for `youtube_video_comments_list(order)`. Same posture. */
const YOUTUBE_COMMENTS_ORDER_ALLOWED: ReadonlySet<string> = new Set([
  "time",
  "relevance",
]);

const YOUTUBE_CHANNEL_UPLOADS_DEFAULT_MAX = 5;
const YOUTUBE_CHANNEL_UPLOADS_MAX_CAP = 50;

const YOUTUBE_SEARCH_DEFAULT_MAX = 10;
const YOUTUBE_SEARCH_MAX_CAP = 50;

const YOUTUBE_COMMENTS_DEFAULT_MAX = 20;
const YOUTUBE_COMMENTS_MAX_CAP = 100;

/** Total leaf cap for `youtube_video_comments_list` — top-level + nested
 *  replies combined. Threads can have 100 × 5-50 = 500-5000 leaves;
 *  handler counts during walk, truncates beyond the cap, and injects the
 *  inbound `<safespace-truncated/>` marker (per `patterns.ts:60`).
 *  Design §4 + §11 hook #1 (UGC injection-surface cap). */
const MAX_TOTAL_COMMENT_LEAVES = 500;

let youtubeSearchesThisSession = 0;

/** Test-only counter reset. Gated to NODE_ENV / BUN_ENV === "test" so a
 *  stray production call to this fn throws loudly. Mirrors
 *  `__resetPeopleWarmingForTest`. */
export function __resetYoutubeSearchCounterForTest(): void {
  if (process.env.NODE_ENV !== "test" && process.env.BUN_ENV !== "test") {
    throw new Error("__resetYoutubeSearchCounterForTest is for tests only");
  }
  youtubeSearchesThisSession = 0;
}

/** `youtube_channel_uploads` — SINGLE-ACCOUNT.
 *
 *  YouTube has no direct "channel uploads" endpoint. Locked pattern:
 *  `playlistItems.list({playlistId: 'UU' + channel_id.slice(2)})`. The
 *  uploads playlist ID for channel `UCxxx` is `UUxxx` — verified property
 *  of YouTube's playlist-ID convention.
 *
 *  CRITICAL ORDER (sec-rev hook #6 / §11): regex on `channel_id` runs
 *  BEFORE `.slice(2)`. A malformed channel_id (path traversal / CRLF / wrong
 *  prefix) is rejected at the handler boundary, never reaches `.slice` or
 *  the SDK.
 *
 *  Quota: `playlistItems.list` = 1 unit / call. */
export async function youtubeChannelUploads(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  if (typeof args.channel_id !== "string") {
    throw new Error("youtube_channel_uploads: 'channel_id' must be a string");
  }
  // Regex BEFORE the slice — defense against path traversal / CRLF in
  // caller-supplied `channel_id`. See design §4 + sec-rev hook #6.
  if (!YOUTUBE_CHANNEL_ID_RE.test(args.channel_id)) {
    throw new Error(
      "youtube_channel_uploads: 'channel_id' must match /^UC[A-Za-z0-9_-]{22}$/ (24-char YouTube channel-ID format; e.g., 'UCxxxxxxxxxxxxxxxxxxxxxx')",
    );
  }
  const channelId = args.channel_id;
  // Uploads-playlist trick — replace the `UC` prefix with `UU` to get the
  // auto-generated uploads playlist for that channel. See design §13 Risk 6
  // for why we deliberately depend on this YouTube convention rather than
  // hitting a deprecation-prone `activities` / `channelSections` endpoint.
  const uploadsPlaylistId = "UU" + channelId.slice(2);

  const maxResults = clampYoutubeMaxResults(
    args.max_results,
    YOUTUBE_CHANNEL_UPLOADS_DEFAULT_MAX,
    YOUTUBE_CHANNEL_UPLOADS_MAX_CAP,
  );

  try {
    const yt = youtubeClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await yt.playlistItems.list({
      playlistId: uploadsPlaylistId,
      part: ["snippet", "contentDetails"],
      maxResults,
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "youtube_channel_uploads", email: requireGoogle(ctx).accountId });
  }
}

/** `youtube_video_get` — SINGLE-ACCOUNT.
 *
 *  `video_id` validated handler-side BEFORE SDK call (sec-rev hook #6).
 *  `parts` is ALLOWLIST default-deny (design §4 + sec-rev pre-merge patch
 *  sec-M3): only `snippet` / `statistics` / `contentDetails` / `status` /
 *  `topicDetails` accepted. Future Google-added parts (`fileDetails`,
 *  `liveStreamingDetails`, `recordingDetails`, etc.) are rejected at the
 *  handler boundary; widening the allowlist requires a sec-rev cycle.
 *
 *  Quota: `videos.list` = 1 unit / call. */
export async function youtubeVideoGet(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  if (typeof args.video_id !== "string") {
    throw new Error("youtube_video_get: 'video_id' must be a string");
  }
  if (!YOUTUBE_VIDEO_ID_RE.test(args.video_id)) {
    throw new Error(
      "youtube_video_get: 'video_id' must match /^[A-Za-z0-9_-]{11}$/ (11-char YouTube video-ID format; e.g., 'dQw4w9WgXcQ')",
    );
  }
  const videoId = args.video_id;

  // Parts ALLOWLIST gate — default-deny. Reject any value outside the
  // closed set. Mirrors share_role_forbidden defense-in-depth pattern;
  // closed-set semantics prevent silent attack-surface expansion if Google
  // adds new parts later. See design §4 + §11 hook (parts ALLOWLIST).
  let parts: string[];
  if (args.parts === undefined) {
    parts = ["snippet", "statistics"];
  } else {
    if (!Array.isArray(args.parts)) {
      throw new Error("youtube_video_get: 'parts' must be an array of strings");
    }
    if (args.parts.length === 0) {
      throw new Error("youtube_video_get: 'parts' must be a non-empty array");
    }
    const validated: string[] = [];
    for (const p of args.parts) {
      if (typeof p !== "string") {
        throw new Error(
          "youtube_video_get: 'parts' entries must each be a string",
        );
      }
      if (!YOUTUBE_VIDEO_GET_ALLOWED_PARTS.has(p)) {
        throw new Error(
          `youtube_video_get: 'parts' value '${p}' not in allowlist. Allowed: snippet / statistics / contentDetails / status / topicDetails`,
        );
      }
      validated.push(p);
    }
    parts = validated;
  }

  try {
    const yt = youtubeClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await yt.videos.list({
      id: [videoId],
      part: parts,
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "youtube_video_get", email: requireGoogle(ctx).accountId });
  }
}

/** `youtube_search` — SINGLE-ACCOUNT; PER-SESSION BURST-LIMITED.
 *
 *  THE MOST EXPENSIVE READ TOOL — 100 quota units / call. 20 calls in one
 *  session = 2000u = 20% of daily quota. The per-session burst limit
 *  (default 20, override via `SAFESPACE_YOUTUBE_SEARCH_BURST_LIMIT`)
 *  rejects the 21st call with `search_burst_limit_exceeded` (-32026)
 *  BEFORE the SDK is invoked — quota is NOT burned on the rejection.
 *
 *  Counter is per-MCP-process; restart = new session = counter reset.
 *  No durable state. See design §11 hook #19, §13 Risk 3.
 *
 *  Quota: `search.list` = **100 units / call**. Description includes the
 *  literal substring "100 units" (LOW-1 brittleness intentional; any
 *  rewording is a sec-rev event per design §11 hook #4). */
export async function youtubeSearch(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  if (typeof args.query !== "string") {
    throw new Error("youtube_search: 'query' must be a string");
  }
  if (!args.query.trim()) {
    throw new Error("youtube_search requires a non-empty 'query' string");
  }
  const query = args.query;

  let videoType: "video" | "channel" | "playlist" = "video";
  if (args.video_type !== undefined) {
    if (typeof args.video_type !== "string") {
      throw new Error("youtube_search: 'video_type' must be a string");
    }
    if (!YOUTUBE_SEARCH_TYPE_ALLOWED.has(args.video_type)) {
      throw new Error(
        `youtube_search: 'video_type' value '${args.video_type}' not in allowlist. Allowed: video / channel / playlist`,
      );
    }
    videoType = args.video_type as "video" | "channel" | "playlist";
  }

  const maxResults = clampYoutubeMaxResults(
    args.max_results,
    YOUTUBE_SEARCH_DEFAULT_MAX,
    YOUTUBE_SEARCH_MAX_CAP,
  );

  // Burst-limit gate — BEFORE incrementing the counter, BEFORE any SDK call.
  // Reject the 21st (default) call in the same MCP session. Quota NOT
  // burned on the rejection. Operator override via env var.
  const burstLimit = getYoutubeSearchBurstLimit();
  if (youtubeSearchesThisSession >= burstLimit) {
    throw new MCPError("search_burst_limit_exceeded", {
      tool: "youtube_search",
      limit: burstLimit,
    });
  }
  // Increment BEFORE the SDK call so a 401 / network failure still consumes
  // the budget — prevents retry-storms from exceeding budget via failed
  // attempts. Operator can restart MCP server to reset.
  youtubeSearchesThisSession++;

  try {
    const yt = youtubeClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await yt.search.list({
      q: query,
      part: ["snippet"],
      maxResults,
      type: [videoType],
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "youtube_search", email: requireGoogle(ctx).accountId });
  }
}

/** Count the total number of leaf comment items (top-level threads +
 *  nested replies). Used by `youtube_video_comments_list` to enforce
 *  `MAX_TOTAL_COMMENT_LEAVES` before sanitize is invoked.
 *
 *  Returns `{ items, truncated }` — `items` is the (possibly truncated)
 *  thread array; `truncated` indicates whether the cap was reached.
 *  When truncated, the final element is replaced by a synthetic marker
 *  comment whose `topLevelComment.snippet.textDisplay` is the inbound
 *  `TRUNCATE_MARKER` string (per `patterns.ts:60` convention). */
function applyCommentLeafCap(
  items: unknown[],
  cap: number,
): { items: unknown[]; truncated: boolean } {
  let leaves = 0;
  const kept: unknown[] = [];
  for (const thread of items) {
    if (!thread || typeof thread !== "object") {
      kept.push(thread);
      continue;
    }
    // Top-level comment counts as 1 leaf.
    let threadLeaves = 1;
    const t = thread as { replies?: { comments?: unknown[] } };
    const replies = t.replies?.comments;
    if (Array.isArray(replies)) {
      threadLeaves += replies.length;
    }
    if (leaves + threadLeaves > cap) {
      // Cap would be exceeded by adding this thread — stop here. The
      // `truncated` flag tells the caller to inject the truncate marker.
      return { items: kept, truncated: true };
    }
    leaves += threadLeaves;
    kept.push(thread);
  }
  return { items: kept, truncated: false };
}

/** `youtube_video_comments_list` — SINGLE-ACCOUNT; HIGHEST UGC SURFACE.
 *
 *  Comments are public attacker-controlled UGC at unbounded scale (any
 *  YouTube viewer worldwide). Per-call sanitize wrap on
 *  `comment.snippet.textDisplay` / `textOriginal` / `authorDisplayName` /
 *  `authorChannelUrl` / `authorProfileImageUrl` is non-negotiable (sec-rev
 *  hook #1).
 *
 *  Leaf cap: `MAX_TOTAL_COMMENT_LEAVES = 500`. Threads can have
 *  100 × 5-50 = 500-5000 leaves; handler counts during walk, truncates
 *  beyond the cap, and the response array's final element is replaced by
 *  a synthetic marker comment containing `<safespace-truncated/>`
 *  (per `patterns.ts:60`). The marker text passes through sanitize unchanged
 *  per the wrap pipeline (it's defined as the truncation sentinel).
 *
 *  Quota: `commentThreads.list` = 1 unit / call. */
export async function youtubeVideoCommentsList(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  if (typeof args.video_id !== "string") {
    throw new Error("youtube_video_comments_list: 'video_id' must be a string");
  }
  if (!YOUTUBE_VIDEO_ID_RE.test(args.video_id)) {
    throw new Error(
      "youtube_video_comments_list: 'video_id' must match /^[A-Za-z0-9_-]{11}$/ (11-char YouTube video-ID format)",
    );
  }
  const videoId = args.video_id;

  let order: "time" | "relevance" = "time";
  if (args.order !== undefined) {
    if (typeof args.order !== "string") {
      throw new Error("youtube_video_comments_list: 'order' must be a string");
    }
    if (!YOUTUBE_COMMENTS_ORDER_ALLOWED.has(args.order)) {
      throw new Error(
        `youtube_video_comments_list: 'order' value '${args.order}' not in allowlist. Allowed: time / relevance`,
      );
    }
    order = args.order as "time" | "relevance";
  }

  const maxResults = clampYoutubeMaxResults(
    args.max_results,
    YOUTUBE_COMMENTS_DEFAULT_MAX,
    YOUTUBE_COMMENTS_MAX_CAP,
  );

  try {
    const yt = youtubeClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await yt.commentThreads.list({
      videoId,
      part: ["snippet", "replies"],
      maxResults,
      order,
    });

    // Enforce total-leaf cap. Note: cap is applied to the data RETURNED
    // from Google — `maxResults` clamps thread count, not nested-reply
    // count. A single thread with 200+ replies could still exceed
    // MAX_TOTAL_COMMENT_LEAVES. Truncation injects a synthetic marker
    // thread so caller is signalled.
    const rawItems = res.data.items ?? [];
    const { items, truncated } = applyCommentLeafCap(
      rawItems,
      MAX_TOTAL_COMMENT_LEAVES,
    );
    const result: {
      kind?: string;
      etag?: string;
      nextPageToken?: string;
      items: unknown[];
    } = {
      ...(res.data.kind !== undefined && res.data.kind !== null
        ? { kind: res.data.kind }
        : {}),
      ...(res.data.etag !== undefined && res.data.etag !== null
        ? { etag: res.data.etag }
        : {}),
      ...(res.data.nextPageToken !== undefined && res.data.nextPageToken !== null
        ? { nextPageToken: res.data.nextPageToken }
        : {}),
      items,
    };
    if (truncated) {
      // Inject a synthetic marker thread. Sanitize will see this as a
      // string leaf under `textDisplay` and wrap it — that's fine; the
      // wrap shows callers exactly where truncation occurred. The bare
      // `<safespace-truncated/>` substring inside the wrapper is still
      // the structural sentinel (`patterns.ts:60` TRUNCATE_MARKER).
      result.items.push({
        synthetic: true,
        snippet: {
          topLevelComment: {
            snippet: {
              textDisplay:
                "<safespace-truncated/> further comment threads omitted by SafeSpace MAX_TOTAL_COMMENT_LEAVES cap (500).",
              authorDisplayName: "safespace",
            },
          },
        },
      });
    }
    return result;
  } catch (err) {
    throw toGoogleError(err, { tool: "youtube_video_comments_list", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.16 Phase 2b: YouTube comment WRITE tier (2 tools) ─────────
 *
 * The most security-sensitive surface in SafeSpace history:
 *   - PUBLIC + PERMANENT — visible to potentially millions of viewers
 *   - Tied to the user's real YouTube channel identity (post-as-me)
 *   - Subject to YouTube anti-spam (sustained abuse can shadow-ban)
 *
 * Tools:
 *   - youtube_video_comment_post   (top-level comment via commentThreads.insert)
 *   - youtube_comment_reply        (reply via comments.insert)
 *
 * 4-gate enforcement (ALL must pass) per design §4 + §9:
 *   1. SAFESPACE_TIER=write       — proxy.ts tools/list filter (registry
 *                                    min_tier:"write"); handler ALSO checks
 *                                    defense-in-depth via `ctx.tier`
 *   2. OAuth scope youtube.force-ssl — withToolContext via requiredScopes;
 *                                       SCOPE_HIERARCHY 2nd KEY entry shipped
 *                                       Phase 2a (with-context.ts)
 *   3. SAFESPACE_YOUTUBE_COMMENT_TARGETS allowlist — module-level singleton
 *                                                     (youtube-comment-targets.ts)
 *   4. SAFESPACE_YOUTUBE_COMMENT_BURST_LIMIT counter — pre-call check +
 *                                                       success-only increment
 *                                                       (youtube-comment-burst.ts)
 *
 * Plus: outbound sanitize on args.text BEFORE constructing the requestBody.
 *
 * NEGATIVE sentinel pattern (per design §9 + sec-rev hook #11):
 *   - youtube_video_comment_post   → 15-field forbidden list (commentThreads.insert)
 *   - youtube_comment_reply        → 11-field forbidden list (comments.insert)
 * Handlers construct requestBody LITERALLY from allowlisted fields ONLY —
 * never spread args / pass-through caller-supplied requestBody. Tests assert
 * positive (keys ⊆ allowlist) AND negative (per-field absence).
 *
 * Burst counter timing (pre-call check, success-only increment) per design
 * hook #18 + the Phase 2a module's spec comment. Pre-call READ + post-success
 * INCREMENT lets a denied call (allowlist miss, sanitize reject) NOT consume
 * burst budget — the gate is about visible posts, not just attempts. Failed
 * SDK calls (network error, 4xx, 5xx) also do NOT consume budget — retry
 * storms are bounded upstream by the allowlist + outbound sanitize gates.
 *
 * Audit (per design §7 Phase 2 audit):
 *   - On allow + SDK success: ctx.audit.record("commentPostMeta", { target_video_hash,
 *     comment_length, policy_decision: "allowed", parent_comment_id_hash? })
 *     fires BEFORE the handler returns. The `finally`-scoped auditEnd in
 *     with-context.ts threads these into the standard JSONL row.
 *   - On denial: ctx.audit.record("commentPostMeta", ...) with the matching denied_* value
 *     fires BEFORE the throw. auditEnd captures with status="error" +
 *     policy_decision discriminator.
 *   - Plaintext comment text NEVER reaches audit. comment_length is the
 *     non-identifying integer; target_video_hash + parent_comment_id_hash
 *     are plain SHA-256 (irreversible). Forensic question "what did Claude
 *     actually post?" requires inspecting the live YouTube comment.
 *
 * NO PII echo in MCPError data (per design §8 + v1.15 sec-I1 pattern) —
 * recovery messages do NOT echo rejected video_id / text content (would
 * convert the rejection into a probe oracle for a prompt-injected Claude).
 *
 * See docs/v1.16-youtube-api.md §4 (Phase 2), §7 (audit), §9 (NEGATIVE
 * sentinel + outbound sanitize), §11 (sec-rev hooks #9-#15 + #18). */

/** YouTube comment-ID format. Per design §4 + comment-targets.ts payload
 *  regex shape. 1-256 chars URL-safe-base64 + `.` + `-`. Length cap = DoS
 *  guard against `comment_id` of 1MB of `A`s slipping into the SDK call. */
const YOUTUBE_COMMENT_ID_RE = /^[A-Za-z0-9_.\-]{1,256}$/;

/** Static scope constant for the Phase 2b write tools. SCOPE_HIERARCHY in
 *  with-context.ts has the 2nd KEY entry `youtube.force-ssl → [force-ssl,
 *  youtube]` shipped Phase 2a; an account that consented to force-ssl
 *  satisfies this requirement, AND an account that consented to the broader
 *  `youtube` scope (locked rejected for SafeSpace) would also satisfy it. */
const YOUTUBE_FORCE_SSL_SCOPE_HANDLERS =
  "https://www.googleapis.com/auth/youtube.force-ssl";

/** B6.1 wave A2b — the SINGLE-SOURCE youtube_video_comment_post input validator:
 *  video_id (11-char) + non-empty text + optional channel_id (24-char). Messages
 *  VERBATIM from the pre-A2b inline block. Called by BOTH the pipeline descriptor's
 *  `extract` (tools/egress-pipeline.ts — the production gate input) and the handler
 *  below (defense-in-depth re-run of the same pure check), so the two can never
 *  drift. Never echoes video_id / text. */
export function validateYoutubeCommentPostArgs(args: Record<string, unknown>): {
  videoId: string;
  text: string;
  channelId?: string;
} {
  if (typeof args.video_id !== "string") {
    throw new Error("youtube_video_comment_post: 'video_id' must be a string");
  }
  if (!YOUTUBE_VIDEO_ID_RE.test(args.video_id)) {
    throw new Error(
      "youtube_video_comment_post: 'video_id' must match /^[A-Za-z0-9_-]{11}$/ (11-char YouTube video-ID format)",
    );
  }
  if (typeof args.text !== "string") {
    throw new Error("youtube_video_comment_post: 'text' must be a string");
  }
  if (args.text.trim().length === 0) {
    throw new Error(
      "youtube_video_comment_post requires a non-empty 'text' string",
    );
  }
  let channelId: string | undefined;
  if (args.channel_id !== undefined) {
    if (typeof args.channel_id !== "string") {
      throw new Error(
        "youtube_video_comment_post: 'channel_id' (optional) must be a string when provided",
      );
    }
    if (!YOUTUBE_CHANNEL_ID_RE.test(args.channel_id)) {
      throw new Error(
        "youtube_video_comment_post: 'channel_id' must match /^UC[A-Za-z0-9_-]{22}$/ (24-char YouTube channel-ID format)",
      );
    }
    channelId = args.channel_id;
  }
  return channelId === undefined
    ? { videoId: args.video_id, text: args.text }
    : { videoId: args.video_id, text: args.text, channelId };
}

/**
 * `youtube_video_comment_post` — WRITE TIER. POST a top-level comment to
 * a YouTube video. PUBLIC + PERMANENT + identity-tied + spam-sensitive.
 *
 * Gate order (FAIL-FAST sequencing):
 *   1. Input validation (video_id regex, text non-empty, channel_id regex
 *      if present) — RAW shape errors throw plain `Error` (NOT MCPError). SINGLE-
 *      SOURCE validateYoutubeCommentPostArgs, which the pipeline's `extract` also
 *      ran; re-run here for defense-in-depth (pure, identical result).
 *   2. Tier check — defense-in-depth (proxy normally hides write tools at
 *      tier=read; if a caller bypasses, we catch + audit + throw here).
 *   3. Egress gate — PIPELINE-FIRED (B6.1 wave A2b): the default-empty hard-deny
 *      comment allowlist → per-session burst PRE-check → 6-step outbound-sanitize
 *      REJECT all run at the withToolContext choke point via this tool's egress
 *      descriptor (enforceYoutubeCommentEgressGates, tools/egress.ts) BEFORE this
 *      handler; the handler reads the gate's SANITIZED text off ctx.egress and must
 *      NOT call the gate (anti-double-fire, egress-callsite.test.ts).
 *   4. Construct requestBody LITERALLY (NEGATIVE sentinel: 15-forbidden).
 *   5. SDK call commentThreads.insert.
 *   6. ON SUCCESS — increment burst counter (success-only STAYS here); audit
 *      allowed metadata is recorded BEFORE the SDK call.
 *
 * Quota cost: 50 units / call (commentThreads.insert). Audit records
 * via `target_video_hash` + `comment_length` + `policy_decision`. */
export async function youtubeVideoCommentPost(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. Input validation (defense-in-depth; the pipeline's extract already ran
  //        the SAME validator) ─────────────────────────────────────────
  const { videoId, text, channelId } = validateYoutubeCommentPostArgs(args);
  const videoHash = sha256Hex(videoId);
  const textLen = text.length;

  // ─── 2. Tier check (defense-in-depth) ──────────────────────────────
  // Proxy normally hides write tools at tier=read (registry min_tier="write"
  // gates tools/list). If a caller bypasses (cross-version drift, malformed
  // MCP client), catch here. Audit + throw.
  const tier = ctx.tier;
  if (tier === "read") {
    ctx.audit.record("commentPostMeta", {
      target_video_hash: videoHash,
      comment_length: textLen,
      policy_decision: "denied_tier",
    });
    // Re-use the existing scope_mismatch shape rather than introducing a
    // new code — proxy never serves write tools at tier=read so this branch
    // is exceptional, not a normal user-visible state.
    throw new MCPError("scope_mismatch", {
      tool: "youtube_video_comment_post",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  // ─── 3. Egress gate is PIPELINE-FIRED ──────────────────────────────
  // The allowlist → burst PRE-check → outbound-sanitize gate now runs at the
  // withToolContext choke point via this tool's egress descriptor (B6.1 wave A2b,
  // enforceYoutubeCommentEgressGates in tools/egress.ts) BEFORE this handler; the
  // handler must NOT call the gate itself (anti-double-fire — egress-callsite.test.ts).
  // Read the gate's SANITIZED text off ctx.egress — the vetted bytes for the wire
  // (never a local recomputation; no TOCTOU).
  const sanitizedText = requireEgressResult(ctx, "youtube-comment").body;

  // ─── 4. Construct requestBody LITERALLY ────────────────────────────
  // ALLOWED keys (per design §9 + sec-rev hook #11):
  //   snippet.videoId
  //   snippet.channelId          (optional caller-supplied)
  //   snippet.topLevelComment.snippet.textOriginal
  // 15-FIELD NEGATIVE SENTINEL (see registry/handler test for the list).
  // Type liberalized to `any` to satisfy googleapis loose Schema$CommentThread
  // typing without spreading caller-supplied keys.
  const innerSnippet: { textOriginal: string } = {
    textOriginal: sanitizedText,
  };
  const topLevelComment: { snippet: typeof innerSnippet } = {
    snippet: innerSnippet,
  };
  const outerSnippet: {
    videoId: string;
    topLevelComment: typeof topLevelComment;
    channelId?: string;
  } = {
    videoId,
    topLevelComment,
  };
  if (channelId !== undefined) {
    outerSnippet.channelId = channelId;
  }
  // googleapis loose typing — Schema$CommentThread accepts arbitrary fields;
  // construct literally to ENFORCE positive-allowlist at the type system level.
  const requestBody = {
    snippet: outerSnippet,
  };

  // ─── 5. Record allow-meta BEFORE the SDK call ─────────────────────
  // FORENSIC COMPLETENESS: record meta BEFORE SDK call. policy_decision="allowed"
  // because the tier check (here) AND the pipeline-fired egress gate (allowlist +
  // burst + outbound sanitize) passed. If SDK throws (Google 5xx, network), the
  // meta is already captured — the audit row shows what Claude attempted + the
  // failure status. Per design §7 + PR #135 pre-merge review INFO-4 reconciliation.
  ctx.audit.record("commentPostMeta", {
    target_video_hash: videoHash,
    comment_length: textLen,
    policy_decision: "allowed",
  });

  // ─── 6. SDK call (burst counter increments only on real success) ──
  try {
    const yt = youtubeClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await yt.commentThreads.insert({
      part: ["snippet"],
      requestBody,
    });
    // Success-only — keep the increment INSIDE the try block so a thrown
    // SDK call does NOT consume burst budget (allowlist + sanitize bounded
    // the retry storm upstream).
    incrementCommentBurst();
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "youtube_video_comment_post", email: requireGoogle(ctx).accountId });
  }
}

/** YouTube videoCategory id format — a small numeric string ("22", "27", …).
 *  videos.update with part=snippet REQUIRES categoryId (REPLACE semantics). */
const YOUTUBE_CATEGORY_ID_RE = /^[0-9]{1,3}$/;

/** Blast-radius cap on the tags array (DoS guard on a 1e6-element array).
 *  YouTube enforces its own ~500-char total-tag limit server-side. */
const YOUTUBE_VIDEO_MAX_TAGS = 50;

/** B6.1 wave A2b — the SINGLE-SOURCE youtube_video_update input validator: video_id
 *  (11-char) + non-empty title + numeric category_id + optional description / tags
 *  (shape + 50-entry cap + non-empty entries). Messages VERBATIM from the pre-A2b
 *  inline block. Called by BOTH the pipeline descriptor's `extract`
 *  (tools/egress-pipeline.ts) and the handler below (defense-in-depth re-run), so the
 *  two can never drift. Never echoes the field values. */
export function validateYoutubeVideoUpdateArgs(args: Record<string, unknown>): {
  videoId: string;
  title: string;
  categoryId: string;
  description?: string;
  tags?: string[];
} {
  if (typeof args.video_id !== "string") {
    throw new Error("youtube_video_update: 'video_id' must be a string");
  }
  if (!YOUTUBE_VIDEO_ID_RE.test(args.video_id)) {
    throw new Error(
      "youtube_video_update: 'video_id' must match /^[A-Za-z0-9_-]{11}$/ (11-char YouTube video-ID format)",
    );
  }
  if (typeof args.title !== "string") {
    throw new Error("youtube_video_update: 'title' must be a string");
  }
  if (args.title.trim().length === 0) {
    throw new Error("youtube_video_update requires a non-empty 'title' string");
  }
  if (typeof args.category_id !== "string") {
    throw new Error("youtube_video_update: 'category_id' must be a string");
  }
  if (!YOUTUBE_CATEGORY_ID_RE.test(args.category_id)) {
    throw new Error(
      "youtube_video_update: 'category_id' must be a numeric YouTube videoCategory id (e.g., '22'). Read the current value via youtube_video_get parts=snippet.",
    );
  }
  let description: string | undefined;
  if (args.description !== undefined) {
    if (typeof args.description !== "string") {
      throw new Error(
        "youtube_video_update: 'description' (optional) must be a string when provided",
      );
    }
    description = args.description;
  }
  let tags: string[] | undefined;
  if (args.tags !== undefined) {
    if (!Array.isArray(args.tags)) {
      throw new Error(
        "youtube_video_update: 'tags' (optional) must be an array of strings when provided",
      );
    }
    if (args.tags.length > YOUTUBE_VIDEO_MAX_TAGS) {
      throw new Error(
        `youtube_video_update: 'tags' exceeds ${YOUTUBE_VIDEO_MAX_TAGS} entries (blast-radius guard)`,
      );
    }
    for (const t of args.tags) {
      if (typeof t !== "string") {
        throw new Error("youtube_video_update: every 'tags' entry must be a string");
      }
      if (t.trim().length === 0) {
        throw new Error("youtube_video_update: 'tags' entries must be non-empty strings");
      }
    }
    tags = args.tags as string[];
  }
  return {
    videoId: args.video_id,
    title: args.title,
    categoryId: args.category_id,
    ...(description !== undefined ? { description } : {}),
    ...(tags !== undefined ? { tags } : {}),
  };
}

/**
 * `youtube_video_update` — WRITE TIER. Update a video's PUBLIC snippet metadata
 * (title / description / tags) on a video YOUR channel owns (videos.update 403s
 * for videos you do not own). PUBLIC + identity-tied — a video's title /
 * description is the most visible, identity-defining text on the channel.
 *
 * REPLACE-by-part: SafeSpace sends ONLY `part: ["snippet"]`, so status /
 * privacy / madeForKids are STRUCTURALLY untouchable (no premature-publish /
 * unpublish path in v1). The snippet is constructed LITERALLY: `title` +
 * `category_id` are REQUIRED (the API mandates both when writing snippet);
 * `description` / `tags` are optional and OMITTING them CLEARS the existing
 * value — pass every field you want to keep. NO pre-fetch (avoids TOCTOU; read
 * current values via youtube_video_get parts=snippet first).
 *
 * Gate order (FAIL-FAST):
 *   1. Input validation (video_id / category_id regex; title non-empty;
 *      description/tags shape) — plain Error, SINGLE-SOURCE validateYoutubeVideoUpdateArgs
 *      (the pipeline's extract ran it too; re-run here defense-in-depth).
 *   2. Tier check (defense-in-depth) — record denied_tier, throw scope_mismatch.
 *   3. Egress gate — PIPELINE-FIRED (B6.1 wave A2b): the SAFESPACE_YOUTUBE_VIDEO_TARGETS
 *      default-deny target allowlist (miss → -32052, NO video_id echo) → per-field
 *      outboundSanitize (-32027) → F3a secret-shape on the combined text (-32035) all
 *      run at the withToolContext choke point via this tool's egress descriptor
 *      (enforceYoutubeVideoUpdateEgressGates, tools/egress.ts) BEFORE this handler; the
 *      handler reads the per-field SANITIZED snippet off ctx.egress (must NOT call the
 *      gate — anti-double-fire, egress-callsite.test.ts).
 *   4. Construct requestBody LITERALLY (NEGATIVE sentinel: snippet keys ⊆
 *      {title, categoryId, description?, tags?}; NO status, NO arbitrary keys).
 *   5. Record videoMutationMeta allowed BEFORE the SDK call.
 *   6. SDK videos.update. F1 universal write-burst auto-covers at the choke
 *      point (write-tier → write bucket).
 *
 * Quota: videos.update = 50 units / call. Audit records target_video_hash +
 * operation='video_update' + title_length (+ description_length / tag_count when
 * supplied) + policy_decision (NEVER the plaintext title/description/tags). */
export async function youtubeVideoUpdate(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. Input validation (defense-in-depth; the pipeline's extract already ran
  //        the SAME validator) ─────────────────────────────────────────
  const { videoId, title, categoryId, description, tags } = validateYoutubeVideoUpdateArgs(args);
  const videoHash = sha256Hex(videoId);

  // The forensic-meta builder reused at the tier-denial + allow exit points so the
  // shape stays 1:1 with the audit channel (typed off `VideoMutationAuditMeta` minus
  // policy_decision, so it can't drift from the interface). title_length always
  // present; description_length / tag_count PRESENT only when supplied (mirrors the
  // optional snippet fields).
  // NOTE: lengths are the PRE-sanitize INPUT lengths. outboundSanitize REJECTS rather
  // than silently shortening, so on the `allowed` path these match what is sent (modulo
  // a rare NFC char-count shift) — never the plaintext. Same raw-length convention as
  // the comment / playlist channels. (The sanitize-reject denial row is recorded by the
  // pipeline gate, tools/egress.ts, with the same baseMeta shape.)
  const baseMeta = (): Omit<VideoMutationAuditMeta, "policy_decision"> => {
    const m: Omit<VideoMutationAuditMeta, "policy_decision"> = {
      target_video_hash: videoHash,
      operation: "video_update",
      title_length: title.length,
    };
    if (description !== undefined) m.description_length = description.length;
    if (tags !== undefined) m.tag_count = tags.length;
    return m;
  };

  // ─── 2. Tier check (defense-in-depth) ──────────────────────────────
  if (ctx.tier === "read") {
    ctx.audit.record("videoMutationMeta", { ...baseMeta(), policy_decision: "denied_tier" });
    throw new MCPError("scope_mismatch", {
      tool: "youtube_video_update",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  // ─── 3. Egress gate is PIPELINE-FIRED ──────────────────────────────
  // The target allowlist → per-field outbound-sanitize → F3a secret-shape gate now
  // runs at the withToolContext choke point via this tool's egress descriptor (B6.1
  // wave A2b, enforceYoutubeVideoUpdateEgressGates in tools/egress.ts) BEFORE this
  // handler; the handler reads the gate's per-field SANITIZED snippet off ctx.egress
  // and must NOT call the gate (anti-double-fire — egress-callsite.test.ts).
  const out = requireEgressResult(ctx, "youtube-video-update");

  // ─── 4. Construct requestBody LITERALLY (NEGATIVE sentinel) ─────────
  // snippet keys ⊆ {title, categoryId, description?, tags?}. NO status part is
  // ever sent (part is ["snippet"] only) ⇒ privacyStatus / madeForKids cannot be
  // changed. `id` is top-level (the video to update), not a snippet field. The
  // free-text fields are the PIPELINE's vetted (sanitized) bytes read off ctx.egress;
  // category_id is the handler's own validated digit-only value (never sanitized).
  const snippet: {
    title: string;
    categoryId: string;
    description?: string;
    tags?: string[];
  } = {
    title: out.title,
    categoryId,
  };
  if (out.description !== undefined) snippet.description = out.description;
  if (out.tags !== undefined) snippet.tags = [...out.tags];
  const requestBody = { id: videoId, snippet };

  // ─── 5. Record allow-meta BEFORE the SDK call (forensic completeness) ─
  ctx.audit.record("videoMutationMeta", { ...baseMeta(), policy_decision: "allowed" });

  // ─── 6. SDK call ────────────────────────────────────────────────────
  try {
    const yt = youtubeClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await yt.videos.update({
      part: ["snippet"],
      requestBody,
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "youtube_video_update", email: requireGoogle(ctx).accountId });
  }
}

/** B6.1 wave A2b — the SINGLE-SOURCE youtube_comment_reply input validator:
 *  parent_comment_id (1-256 char) + caller-supplied video_id (11-char, TOCTOU
 *  divergence) + non-empty text. Messages VERBATIM from the pre-A2b inline block.
 *  Called by BOTH the pipeline descriptor's `extract` (tools/egress-pipeline.ts) and
 *  the handler below (defense-in-depth re-run), so the two can never drift. Never
 *  echoes the field values. */
export function validateYoutubeCommentReplyArgs(args: Record<string, unknown>): {
  parentCommentId: string;
  videoId: string;
  text: string;
} {
  if (typeof args.parent_comment_id !== "string") {
    throw new Error(
      "youtube_comment_reply: 'parent_comment_id' must be a string",
    );
  }
  if (!YOUTUBE_COMMENT_ID_RE.test(args.parent_comment_id)) {
    throw new Error(
      "youtube_comment_reply: 'parent_comment_id' must match /^[A-Za-z0-9_.\\-]{1,256}$/ (YouTube comment ID; length cap 256 = DoS guard)",
    );
  }
  if (typeof args.video_id !== "string") {
    // TOCTOU divergence: caller MUST supply video_id to close the resolution
    // window. Per design §4 + code-H4 patch.
    throw new Error(
      "youtube_comment_reply: 'video_id' (videoId of the parent comment's video) must be a string. SafeSpace requires caller-supplied video_id to avoid TOCTOU resolution. If you don't know it, call youtube_video_comments_list to look up the parent comment.",
    );
  }
  if (!YOUTUBE_VIDEO_ID_RE.test(args.video_id)) {
    throw new Error(
      "youtube_comment_reply: 'video_id' must match /^[A-Za-z0-9_-]{11}$/ (11-char YouTube video-ID format)",
    );
  }
  if (typeof args.text !== "string") {
    throw new Error("youtube_comment_reply: 'text' must be a string");
  }
  if (args.text.trim().length === 0) {
    throw new Error("youtube_comment_reply requires a non-empty 'text' string");
  }
  return {
    parentCommentId: args.parent_comment_id,
    videoId: args.video_id,
    text: args.text,
  };
}

/**
 * `youtube_comment_reply` — WRITE TIER. Reply to an existing YouTube
 * top-level comment. SAME public-permanent-identity-spam risk profile
 * as youtube_video_comment_post.
 *
 * Reply gate DIVERGENCE from comment_post (per design §4 + code-H4 patch):
 * caller MUST supply BOTH `parent_comment_id` AND `video_id` (the videoId
 * of the parent comment's video). Handler does NOT resolve parent →
 * video to AVOID:
 *   (a) the TOCTOU window between resolution and post,
 *   (b) the extra quota unit per reply (comments.list lookup),
 *   (c) cross-account resolution-cache leak class (v1.15 sec-M5).
 *
 * If caller-supplied video_id doesn't match parent comment's actual video,
 * the post succeeds but is misrouted to a wrong allowlist gate — accepted
 * UX tradeoff. Audit row records BOTH `parent_comment_id_hash` +
 * `target_video_hash` so forensic correlation is possible.
 *
 * Same 4-gate + outbound sanitize architecture as comment_post; only
 * difference: SDK endpoint is `comments.insert` (not `commentThreads.insert`)
 * and the NEGATIVE sentinel is shorter (11 forbidden fields vs 15) — the
 * comments resource has fewer Google-controlled metadata fields than the
 * top-level commentThreads wrapper.
 *
 * Quota cost: 50 units / call (comments.insert). */
export async function youtubeCommentReply(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. Input validation (defense-in-depth; the pipeline's extract already ran
  //        the SAME validator) ─────────────────────────────────────────
  const { parentCommentId, videoId, text } = validateYoutubeCommentReplyArgs(args);
  const videoHash = sha256Hex(videoId);
  const parentHash = sha256Hex(parentCommentId);
  const textLen = text.length;

  // ─── 2. Tier check (defense-in-depth) ──────────────────────────────
  const tier = ctx.tier;
  if (tier === "read") {
    ctx.audit.record("commentPostMeta", {
      target_video_hash: videoHash,
      parent_comment_id_hash: parentHash,
      comment_length: textLen,
      policy_decision: "denied_tier",
    });
    throw new MCPError("scope_mismatch", {
      tool: "youtube_comment_reply",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  // ─── 3. Egress gate is PIPELINE-FIRED ──────────────────────────────
  // The allowlist → burst PRE-check → outbound-sanitize gate (which carries
  // parent_comment_id_hash on its DENIAL rows) runs at the withToolContext choke
  // point via this tool's egress descriptor (B6.1 wave A2b,
  // enforceYoutubeCommentEgressGates in tools/egress.ts) BEFORE this handler; the
  // handler reads the gate's SANITIZED text off ctx.egress and must NOT call the
  // gate (anti-double-fire — egress-callsite.test.ts).
  const sanitizedText = requireEgressResult(ctx, "youtube-comment").body;

  // ─── 4. Construct requestBody LITERALLY ────────────────────────────
  // ALLOWED keys for comments.insert (per design §9 + Phase 2b
  // implementer responsibility):
  //   snippet.parentId          (REQUIRED for replies — opposite valence
  //                              from commentThreads.insert where parentId
  //                              is FORBIDDEN; see design §9 footnote)
  //   snippet.textOriginal
  // 11-FIELD NEGATIVE SENTINEL: all the same identity-smuggling /
  // state-fake / back-date defenses as commentThreads.insert, minus the
  // `topLevelComment.*` / `replies` / `snippet.channelId` / `snippet.videoId`
  // wrapper-level fields that don't exist on the bare comment resource.
  const innerSnippet: { parentId: string; textOriginal: string } = {
    parentId: parentCommentId,
    textOriginal: sanitizedText,
  };
  const requestBody = {
    snippet: innerSnippet,
  };

  // ─── 5. Record allow-meta BEFORE the SDK call ─────────────────────
  // FORENSIC COMPLETENESS: record meta BEFORE SDK call. policy_decision="allowed"
  // because the tier check (here) AND the pipeline-fired egress gate (allowlist +
  // burst + outbound sanitize) passed. If SDK throws (Google 5xx, network), the
  // meta is already captured — the audit row shows what Claude attempted + the
  // failure status. Per design §7 + PR #135 pre-merge review INFO-4 reconciliation.
  ctx.audit.record("commentPostMeta", {
    target_video_hash: videoHash,
    parent_comment_id_hash: parentHash,
    comment_length: textLen,
    policy_decision: "allowed",
  });

  // ─── 6. SDK call (burst counter increments only on real success) ──
  try {
    const yt = youtubeClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await yt.comments.insert({
      part: ["snippet"],
      requestBody,
    });
    // Success-only — keep the increment INSIDE the try block so a thrown
    // SDK call does NOT consume burst budget.
    incrementCommentBurst();
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "youtube_comment_reply", email: requireGoogle(ctx).accountId });
  }
}

// Re-export YOUTUBE_FORCE_SSL_SCOPE_HANDLERS so its presence is reachable in
// type-narrow tooling. The Phase 2b handlers don't need it imported elsewhere;
// constant declared above for clarity. Intentionally not re-exported to keep
// the surface narrow (registry.ts has its own YOUTUBE_FORCE_SSL constant).
export const __YOUTUBE_FORCE_SSL_SCOPE_HANDLERS_INTERNAL = YOUTUBE_FORCE_SSL_SCOPE_HANDLERS;

/**
 * `youtube_comment_delete` — WRITE TIER. v1.17 Phase 3.
 * Delete a YouTube comment authored by the consenting account.
 * PERMANENTLY IRREVERSIBLE — YouTube has NO comment trash recovery
 * (asymmetric with Drive's 30-day trash; see design §10 Q4 + §11 Risk 5).
 *
 * Recovery > Policy bypass (per design §2.5 + §8 hook #4 — scope LIMITED):
 *   SKIPS  → SAFESPACE_YOUTUBE_COMMENT_TARGETS allowlist (Phase 2b gate #3)
 *   SKIPS  → SAFESPACE_YOUTUBE_COMMENT_BURST_LIMIT counter (Phase 2b gate #4)
 *   ENFORCED → SAFESPACE_TIER=write or higher (gate #1; tier is the floor —
 *              §10 Q4 LOCKED, retires CLAUDE.md L218 read-tier carry-forward)
 *   ENFORCED → youtube.force-ssl scope (gate #2; below the proxy pre-check
 *              boundary, scope_mismatch raises if missing)
 *
 * Rationale for the bypass: "brakes always work" — if Phase 2b accidentally
 * posted a wrong comment (despite the 4-gate model), the operator MUST be
 * able to delete it even if the target is no longer in (or never was in)
 * the allowlist. A storm of deletes can only undo a storm of posts
 * (bounded by the Phase 2a 10-per-session post counter). Burst counter
 * intentionally NOT consumed: counter only counts posts.
 *
 * Rationale for write-tier (NOT read like `drive_unshare_file`): YouTube
 * comment delete destroys the comment AND its audit trail; deletion is
 * immediately + permanently irreversible. Drive unshare REMOVES access
 * (de-grants); content unchanged + re-shareable. Asymmetry intentional —
 * see design §10 Q4 + Phase 3 prompt HOOK A (recovery-impossibility
 * accepted; no `comment_text_sha256` audit field because that would
 * require pre-fetch which contradicts design §2.5 TOCTOU prohibition).
 *
 * NO pre-fetch (`comments.list({id})`) before delete:
 *   (a) TOCTOU window — comment author could change between list + delete
 *   (b) extra quota unit per delete (50 → 51)
 *   (c) cross-account resolution-cache leak class (v1.15 sec-M5)
 * Google API only allows deleting your OWN comments (403 otherwise); we
 * let that 403 surface via toGoogleError rather than pre-checking.
 *
 * SDK call: `youtube.comments.delete({ id: commentId })`. Google returns
 * 204 No Content on success. Quota cost: 50 units / delete.
 *
 * Audit row: NEW `commentDeleteMeta` channel (NOT a union into
 * `commentPostMeta.policy_decision` — per design §5 + §8 hook #13 the
 * PRESENCE of `commentDeleteMeta` discriminates delete rows from post rows
 * in audit log greps). Field schema: `{target_comment_id_hash (plain
 * SHA-256), policy_decision: "deleted"}`. NO video_id resolution (would
 * re-introduce TOCTOU per v1.16 code-H4); only the comment_id hash. NO
 * comment-text hash per Phase 3 HOOK A. NO PII echo in error data per
 * design §8 hook #8. */
export async function youtubeCommentDelete(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. Input validation (BEFORE tier check; matches v1.16 Phase 2b
  //        + v1.17 Phase 1/2 precedent — RAW shape errors throw plain
  //        Error, not MCPError) ──────────────────────────────────────
  if (typeof args.comment_id !== "string") {
    throw new Error("youtube_comment_delete: 'comment_id' must be a string");
  }
  if (!YOUTUBE_COMMENT_ID_RE.test(args.comment_id)) {
    // Per design §8 hook #11 — opaque-ID path-segment validation BEFORE
    // the comment_id flows into the SDK's URL path (defense against
    // path-traversal smuggling / CRLF / NUL / too-long DoS). The regex
    // matches v1.16's YOUTUBE_COMMENT_ID_RE used by
    // youtube_comment_reply.parent_comment_id (already-shipped pattern).
    throw new Error(
      "youtube_comment_delete: 'comment_id' must match /^[A-Za-z0-9_.\\-]{1,256}$/ (YouTube comment ID; length cap 256 = DoS guard)",
    );
  }
  const commentId = args.comment_id;
  const commentHash = sha256Hex(commentId);

  // ─── 2. Tier check (defense-in-depth; recovery-bypass is scope LIMITED
  //        — bypasses allowlist + burst ONLY, NOT tier) ──────────────
  // §10 Q4 LOCKED: youtube_comment_delete is min_tier=write (NOT read
  // like drive_unshare_file). The proxy normally hides write tools at
  // tier=read via the IMPLEMENTED_TOOLS + min_tier filter; if a caller
  // bypasses (malformed MCP client, cross-version drift), catch here.
  // Audit row carries `policy_decision: "denied_tier"` for forensic
  // correlation with subsequent retries. Per design §8 hook #7 — emit
  // meta BEFORE the throw so the auditEnd finally block has the data.
  const tier = ctx.tier;
  if (tier === "read") {
    ctx.audit.record("commentDeleteMeta", {
      target_comment_id_hash: commentHash,
      policy_decision: "denied_tier",
    });
    // Re-use scope_mismatch shape rather than introducing a new error
    // code — proxy never serves write tools at tier=read so this branch
    // is exceptional, not a normal user-visible state. Mirrors
    // youtube_video_comment_post / calendar_delete_event tier-denial
    // pattern. NO PII echo (commentId NEVER in errorData per §8 hook #8).
    throw new MCPError("scope_mismatch", {
      tool: "youtube_comment_delete",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  // ─── 3. NO allowlist check (bypass per design §2.5 + §8 hook #4) ──
  // Intentional: youtube_comment_delete carries NO egress descriptor, so the
  // pipeline-fired comment allowlist gate (enforceYoutubeCommentEgressGates in
  // tools/egress.ts, which youtube_video_comment_post / youtube_comment_reply now
  // route through — B6.1 wave A2b) does NOT run for a delete. Recovery > Policy: a
  // mis-posted comment must be deletable even if the target is no longer in (or
  // never was in) the SAFESPACE_YOUTUBE_COMMENT_TARGETS allowlist.

  // ─── 4. NO burst-counter check (bypass per design §2.5 + §8 hook #4) ─
  // Intentional: neither the pipeline gate's burst PRE-check nor the post-success
  // increment (both in the post/reply path) is consulted here. The burst counter
  // counts POSTS only; deletes can only undo posts (bounded by the Phase 2a
  // 10-per-session post limit).

  // ─── 5. Record audit meta BEFORE the SDK call ─────────────────────
  // FORENSIC COMPLETENESS: record meta BEFORE SDK call (mirror v1.16
  // PR #135 INFO-4 + v1.17 Phase 1/2 reconciliation pattern). If the SDK
  // throws (Google 5xx, network, 403 not-your-comment), the meta is
  // already captured — the audit row shows what Claude ATTEMPTED to
  // delete + the failure status. policy_decision="deleted" semantically
  // signals "all SafeSpace gates passed; SDK call initiated" — the
  // semantic distinction from "allowed" is documented in CommentDeleteAuditMeta.
  // Plaintext comment text NEVER passes through this channel per HOOK A.
  ctx.audit.record("commentDeleteMeta", {
    target_comment_id_hash: commentHash,
    policy_decision: "deleted",
  });

  // ─── 6. SDK call ──────────────────────────────────────────────────
  // youtube.comments.delete returns 204 No Content on success. Google
  // API rejects deletes of other people's comments with 403 (we don't
  // pre-check); rejects unknown comment_id with 404. mapGoogleError maps
  // both to typed MCPError surfaces.
  try {
    const yt = youtubeClientFromToken(requireGoogle(ctx).getAccessToken());
    await yt.comments.delete({ id: commentId });
    // Return shape: explicit {deleted: true, comment_id} so the MCP
    // response is unambiguous (Google's 204 has no body to surface).
    // Matches drive_unshare_file + calendar_delete_event shape convention.
    return { deleted: true, comment_id: commentId };
  } catch (err) {
    throw toGoogleError(err, { tool: "youtube_comment_delete", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.48 B4 — YouTube playlists (5 tools, non-destructive) ─────────
 *
 * 2 READ (playlists.list / playlistItems.list, on youtube.readonly) + 3 WRITE
 * (playlists.insert / playlists.update / playlistItems.insert, on
 * youtube.force-ssl, min_tier=write). ZERO new OAuth scope — force-ssl shipped
 * v1.16 Phase 2a and covers playlists.* + playlistItems.* writes.
 *
 * Locked posture (docs/v1.48-youtube-playlists.md §2):
 *   - tier + force-ssl scope ONLY. NO SAFESPACE_YOUTUBE_PLAYLIST_TARGETS
 *     allowlist, NO burst counter — a playlist is a channel-OWNED object, not a
 *     public-broadcast spam vector like a comment (so the comment-targets
 *     hard-deny does NOT apply). Quota cost (50u/write) is surfaced in each
 *     WRITE tool description so a runaway loop is visible.
 *   - playlist_create defaults privacyStatus="private"; caller may set the
 *     closed enum {private,unlisted,public}.
 *   - title: HEADER_INJECTION_RE + byte cap. description: byte cap ONLY (body
 *     content — mirror drive_rename_file / drive_create_file). NO full 6-step
 *     outbound-sanitize (that is the comment public-broadcast surface only).
 *   - requestBody constructed LITERALLY from allowlisted inputs — NEVER spread
 *     caller args. playlistItems cross-channel fields are never sent.
 *   - WRITE handlers: tier re-check (defense-in-depth) → audit denied_tier +
 *     reuse scope_mismatch; record allow-meta BEFORE the SDK call (survives a
 *     5xx). NO new error code — validation throws plain Error.
 *   - audit: playlistMutationMeta channel (operation enum discriminates).
 *
 * The DESTRUCTIVE playlist tools (playlistItems.delete remove + playlists.delete)
 * shipped in v1.49 (youtubePlaylistItemRemove / youtubePlaylistDelete below) —
 * same tier+force-ssl floor, NO allowlist/burst (recovery-bias). The `operation`
 * enum is value-unioned with "playlist_item_remove" + "playlist_delete"; only
 * the PERMANENT playlists.delete adds a `classifyDestructive` branch (the
 * recoverable item-remove is not counted). */

/** YouTube playlist-ID format. Known prefixes (PL user playlists / UU uploads /
 *  LL likes / OL / FL / RD) + 1-64 URL-safe chars. Same shape as
 *  youtube-comment-targets.ts PLAYLIST_RE; anchored + length-capped DoS guard,
 *  validated handler-side BEFORE the ID flows into the SDK URL path. */
const YOUTUBE_PLAYLIST_ID_RE = /^(?:PL|UU|LL|OL|FL|RD)[A-Za-z0-9_-]{1,64}$/;

/** v1.49 — YouTube playlist-ITEM ID format. Opaque base64url-ish string
 *  (sometimes dotted, e.g. "PLxxxx.yyyy"); NOT the same as the playlist ID and
 *  NOT the video ID. Anchored + length-capped (128 = DoS guard) BEFORE the id
 *  flows into the playlistItems.delete SDK URL path. Same character family as
 *  the v1.16 YOUTUBE_COMMENT_ID_RE (capped 128 vs 256 — playlistItem ids run
 *  ~60-80 chars). */
const YOUTUBE_PLAYLIST_ITEM_ID_RE = /^[A-Za-z0-9_.\-]{1,128}$/;

/** ALLOWLIST for playlist privacyStatus — closed set, default-deny on any other
 *  value at the handler boundary (mirror the youtube_search video_type
 *  allowlist). Create defaults to the SAFEST value, "private". */
const YOUTUBE_PLAYLIST_PRIVACY_ALLOWED: ReadonlySet<string> = new Set([
  "private",
  "unlisted",
  "public",
]);

/** SafeSpace DoS byte-caps. NOT the authoritative limit — YouTube enforces
 *  150-char title / 5000-char description server-side; these caps only stop a
 *  multi-MB title/description from reaching the SDK. char-limit × 4 ≈ worst-case
 *  UTF-8 so legitimate multibyte (CJK) titles are not rejected here. */
const PLAYLIST_TITLE_MAX_BYTES = 600;
const PLAYLIST_DESCRIPTION_MAX_BYTES = 20000;

const YOUTUBE_PLAYLIST_LIST_DEFAULT_MAX = 25;
const YOUTUBE_PLAYLIST_LIST_MAX_CAP = 50;

/** Sentinel value hashed into the create 2-step pre-call audit row (mirror
 *  sheets_create) — the playlist ID does not exist until the SDK returns, so
 *  the pre-call row carries this placeholder; the post-success call overrides
 *  it with the real `res.data.id` hash (Map last-write-wins). */
const PLAYLIST_PENDING_CREATE = "<pending-create>";

/** `youtube_playlists_list` — SINGLE-ACCOUNT, READ. List playlists owned by
 *  the consenting account (`mine: true`) OR a given channel's public playlists
 *  (`channel_id`). Quota: playlists.list = 1 unit / call. */
export async function youtubePlaylistsList(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  let channelId: string | undefined;
  if (args.channel_id !== undefined) {
    if (typeof args.channel_id !== "string") {
      throw new Error(
        "youtube_playlists_list: 'channel_id' (optional) must be a string when provided",
      );
    }
    if (!YOUTUBE_CHANNEL_ID_RE.test(args.channel_id)) {
      throw new Error(
        "youtube_playlists_list: 'channel_id' must match /^UC[A-Za-z0-9_-]{22}$/ (24-char YouTube channel-ID format)",
      );
    }
    channelId = args.channel_id;
  }
  const maxResults = clampYoutubeMaxResults(
    args.max_results,
    YOUTUBE_PLAYLIST_LIST_DEFAULT_MAX,
    YOUTUBE_PLAYLIST_LIST_MAX_CAP,
  );
  // Exactly one of {mine, channelId} — channel_id absent ⇒ list MY playlists.
  const params: {
    part: string[];
    maxResults: number;
    mine?: boolean;
    channelId?: string;
  } = { part: ["snippet", "status", "contentDetails"], maxResults };
  if (channelId !== undefined) params.channelId = channelId;
  else params.mine = true;

  try {
    const yt = youtubeClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await yt.playlists.list(params);
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "youtube_playlists_list", email: requireGoogle(ctx).accountId });
  }
}

/** `youtube_playlist_items_list` — SINGLE-ACCOUNT, READ. List the items
 *  (videos) in a playlist. Quota: playlistItems.list = 1 unit / call. */
export async function youtubePlaylistItemsList(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  if (typeof args.playlist_id !== "string") {
    throw new Error("youtube_playlist_items_list: 'playlist_id' must be a string");
  }
  if (!YOUTUBE_PLAYLIST_ID_RE.test(args.playlist_id)) {
    throw new Error(
      "youtube_playlist_items_list: 'playlist_id' must match /^(?:PL|UU|LL|OL|FL|RD)[A-Za-z0-9_-]{1,64}$/ (YouTube playlist-ID format)",
    );
  }
  const playlistId = args.playlist_id;
  const maxResults = clampYoutubeMaxResults(
    args.max_results,
    YOUTUBE_PLAYLIST_LIST_DEFAULT_MAX,
    YOUTUBE_PLAYLIST_LIST_MAX_CAP,
  );

  try {
    const yt = youtubeClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await yt.playlistItems.list({
      playlistId,
      part: ["snippet", "contentDetails"],
      maxResults,
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "youtube_playlist_items_list", email: requireGoogle(ctx).accountId });
  }
}

/** `youtube_playlist_create` — WRITE TIER. Create a new playlist on the
 *  consenting account's channel. Defaults privacyStatus="private". 2-step audit
 *  meta (mirror sheets_create). requestBody LITERAL. Quota: playlists.insert =
 *  50 units / call. */
export async function youtubePlaylistCreate(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. Input validation ────────────────────────────────────────────
  if (typeof args.title !== "string") {
    throw new Error("youtube_playlist_create: 'title' must be a string");
  }
  if (args.title.trim().length === 0) {
    throw new Error("youtube_playlist_create requires a non-empty 'title' string");
  }
  if (HEADER_INJECTION_RE.test(args.title)) {
    throw new Error(
      "youtube_playlist_create: 'title' contains forbidden control characters (CR/LF/NUL/NEL/U+2028/U+2029)",
    );
  }
  if (Buffer.byteLength(args.title, "utf8") > PLAYLIST_TITLE_MAX_BYTES) {
    throw new Error(
      `youtube_playlist_create: 'title' exceeds ${PLAYLIST_TITLE_MAX_BYTES} bytes UTF-8`,
    );
  }
  const title = args.title;

  let description: string | undefined;
  if (args.description !== undefined) {
    if (typeof args.description !== "string") {
      throw new Error(
        "youtube_playlist_create: 'description' (optional) must be a string when provided",
      );
    }
    // NO HEADER_INJECTION_RE — description is body content (mirror
    // drive_rename_file / drive_create_file description handling).
    if (Buffer.byteLength(args.description, "utf8") > PLAYLIST_DESCRIPTION_MAX_BYTES) {
      throw new Error(
        `youtube_playlist_create: 'description' exceeds ${PLAYLIST_DESCRIPTION_MAX_BYTES} bytes UTF-8`,
      );
    }
    description = args.description;
  }

  let privacyStatus = "private";
  if (args.privacy_status !== undefined) {
    if (typeof args.privacy_status !== "string") {
      throw new Error(
        "youtube_playlist_create: 'privacy_status' (optional) must be a string when provided",
      );
    }
    if (!YOUTUBE_PLAYLIST_PRIVACY_ALLOWED.has(args.privacy_status)) {
      throw new Error(
        `youtube_playlist_create: 'privacy_status' value '${args.privacy_status}' not in allowlist. Allowed: private / unlisted / public`,
      );
    }
    privacyStatus = args.privacy_status;
  }

  // ─── 2. Tier check (defense-in-depth) ──────────────────────────────
  const tier = ctx.tier;
  if (tier === "read") {
    ctx.audit.record("playlistMutationMeta", {
      target_playlist_hash: sha256Hex(PLAYLIST_PENDING_CREATE),
      operation: "playlist_create",
      policy_decision: "denied_tier",
    });
    throw new MCPError("scope_mismatch", {
      tool: "youtube_playlist_create",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  // ─── 3. Record allow-meta BEFORE the SDK call (2-step: sentinel) ────
  ctx.audit.record("playlistMutationMeta", {
    target_playlist_hash: sha256Hex(PLAYLIST_PENDING_CREATE),
    operation: "playlist_create",
    policy_decision: "allowed",
  });

  // ─── 4. Construct requestBody LITERALLY ────────────────────────────
  const snippet: { title: string; description?: string } = { title };
  if (description !== undefined) snippet.description = description;
  const requestBody = { snippet, status: { privacyStatus } };

  // ─── 5. SDK call ───────────────────────────────────────────────────
  try {
    const yt = youtubeClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await yt.playlists.insert({
      part: ["snippet", "status"],
      requestBody,
    });
    // 2-step: re-record with the REAL created playlist id hash (Google
    // assigns the id on create — overrides the sentinel; last-write-wins).
    if (typeof res.data.id === "string") {
      ctx.audit.record("playlistMutationMeta", {
        target_playlist_hash: sha256Hex(res.data.id),
        operation: "playlist_create",
        policy_decision: "allowed",
      });
    }
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "youtube_playlist_create", email: requireGoogle(ctx).accountId });
  }
}

/** `youtube_playlist_update` — WRITE TIER. Update a playlist's title /
 *  description / privacy. playlists.update is REPLACE semantics: `title` is
 *  REQUIRED (omitting it 400s) and omitting `description` CLEARS it — the caller
 *  must pass the fields it wants to keep. No pre-fetch (avoids TOCTOU + saves a
 *  quota unit). requestBody LITERAL. Quota: playlists.update = 50 units / call. */
export async function youtubePlaylistUpdate(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. Input validation ────────────────────────────────────────────
  if (typeof args.playlist_id !== "string") {
    throw new Error("youtube_playlist_update: 'playlist_id' must be a string");
  }
  if (!YOUTUBE_PLAYLIST_ID_RE.test(args.playlist_id)) {
    throw new Error(
      "youtube_playlist_update: 'playlist_id' must match /^(?:PL|UU|LL|OL|FL|RD)[A-Za-z0-9_-]{1,64}$/ (YouTube playlist-ID format)",
    );
  }
  const playlistId = args.playlist_id;

  if (typeof args.title !== "string") {
    throw new Error(
      "youtube_playlist_update: 'title' must be a string (playlists.update is REPLACE semantics — title is required)",
    );
  }
  if (args.title.trim().length === 0) {
    throw new Error("youtube_playlist_update requires a non-empty 'title' string");
  }
  if (HEADER_INJECTION_RE.test(args.title)) {
    throw new Error(
      "youtube_playlist_update: 'title' contains forbidden control characters (CR/LF/NUL/NEL/U+2028/U+2029)",
    );
  }
  if (Buffer.byteLength(args.title, "utf8") > PLAYLIST_TITLE_MAX_BYTES) {
    throw new Error(
      `youtube_playlist_update: 'title' exceeds ${PLAYLIST_TITLE_MAX_BYTES} bytes UTF-8`,
    );
  }
  const title = args.title;

  let description: string | undefined;
  if (args.description !== undefined) {
    if (typeof args.description !== "string") {
      throw new Error(
        "youtube_playlist_update: 'description' (optional) must be a string when provided",
      );
    }
    if (Buffer.byteLength(args.description, "utf8") > PLAYLIST_DESCRIPTION_MAX_BYTES) {
      throw new Error(
        `youtube_playlist_update: 'description' exceeds ${PLAYLIST_DESCRIPTION_MAX_BYTES} bytes UTF-8`,
      );
    }
    description = args.description;
  }

  let privacyStatus: string | undefined;
  if (args.privacy_status !== undefined) {
    if (typeof args.privacy_status !== "string") {
      throw new Error(
        "youtube_playlist_update: 'privacy_status' (optional) must be a string when provided",
      );
    }
    if (!YOUTUBE_PLAYLIST_PRIVACY_ALLOWED.has(args.privacy_status)) {
      throw new Error(
        `youtube_playlist_update: 'privacy_status' value '${args.privacy_status}' not in allowlist. Allowed: private / unlisted / public`,
      );
    }
    privacyStatus = args.privacy_status;
  }

  // ─── 2. Tier check (defense-in-depth) ──────────────────────────────
  const tier = ctx.tier;
  if (tier === "read") {
    ctx.audit.record("playlistMutationMeta", {
      target_playlist_hash: sha256Hex(playlistId),
      operation: "playlist_update",
      policy_decision: "denied_tier",
    });
    throw new MCPError("scope_mismatch", {
      tool: "youtube_playlist_update",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  // ─── 3. Record allow-meta BEFORE the SDK call ──────────────────────
  ctx.audit.record("playlistMutationMeta", {
    target_playlist_hash: sha256Hex(playlistId),
    operation: "playlist_update",
    policy_decision: "allowed",
  });

  // ─── 4. Construct requestBody LITERALLY. `id` is REQUIRED by
  //        playlists.update. `status` part included ONLY when privacy_status
  //        supplied (otherwise privacy is left untouched). ────────────────
  const snippet: { title: string; description?: string } = { title };
  if (description !== undefined) snippet.description = description;
  const requestBody: {
    id: string;
    snippet: typeof snippet;
    status?: { privacyStatus: string };
  } = { id: playlistId, snippet };
  const part = ["snippet"];
  if (privacyStatus !== undefined) {
    requestBody.status = { privacyStatus };
    part.push("status");
  }

  // ─── 5. SDK call ───────────────────────────────────────────────────
  try {
    const yt = youtubeClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await yt.playlists.update({ part, requestBody });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "youtube_playlist_update", email: requireGoogle(ctx).accountId });
  }
}

/** `youtube_playlist_item_insert` — WRITE TIER. Add a video to a playlist.
 *  Audit meta carries both target_playlist_hash + target_video_hash.
 *  requestBody LITERAL. Quota: playlistItems.insert = 50 units / call. */
export async function youtubePlaylistItemInsert(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. Input validation ────────────────────────────────────────────
  if (typeof args.playlist_id !== "string") {
    throw new Error("youtube_playlist_item_insert: 'playlist_id' must be a string");
  }
  if (!YOUTUBE_PLAYLIST_ID_RE.test(args.playlist_id)) {
    throw new Error(
      "youtube_playlist_item_insert: 'playlist_id' must match /^(?:PL|UU|LL|OL|FL|RD)[A-Za-z0-9_-]{1,64}$/ (YouTube playlist-ID format)",
    );
  }
  const playlistId = args.playlist_id;

  if (typeof args.video_id !== "string") {
    throw new Error("youtube_playlist_item_insert: 'video_id' must be a string");
  }
  if (!YOUTUBE_VIDEO_ID_RE.test(args.video_id)) {
    throw new Error(
      "youtube_playlist_item_insert: 'video_id' must match /^[A-Za-z0-9_-]{11}$/ (11-char YouTube video-ID format)",
    );
  }
  const videoId = args.video_id;

  let position: number | undefined;
  if (args.position !== undefined) {
    if (
      typeof args.position !== "number" ||
      !Number.isInteger(args.position) ||
      args.position < 0
    ) {
      throw new Error(
        "youtube_playlist_item_insert: 'position' (optional) must be a non-negative integer when provided",
      );
    }
    position = args.position;
  }

  const playlistHash = sha256Hex(playlistId);
  const videoHash = sha256Hex(videoId);

  // ─── 2. Tier check (defense-in-depth) ──────────────────────────────
  const tier = ctx.tier;
  if (tier === "read") {
    ctx.audit.record("playlistMutationMeta", {
      target_playlist_hash: playlistHash,
      target_video_hash: videoHash,
      operation: "playlist_item_insert",
      policy_decision: "denied_tier",
    });
    throw new MCPError("scope_mismatch", {
      tool: "youtube_playlist_item_insert",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  // ─── 3. Record allow-meta BEFORE the SDK call ──────────────────────
  ctx.audit.record("playlistMutationMeta", {
    target_playlist_hash: playlistHash,
    target_video_hash: videoHash,
    operation: "playlist_item_insert",
    policy_decision: "allowed",
  });

  // ─── 4. Construct requestBody LITERALLY ────────────────────────────
  const snippet: {
    playlistId: string;
    resourceId: { kind: string; videoId: string };
    position?: number;
  } = {
    playlistId,
    resourceId: { kind: "youtube#video", videoId },
  };
  if (position !== undefined) snippet.position = position;
  const requestBody = { snippet };

  // ─── 5. SDK call ───────────────────────────────────────────────────
  try {
    const yt = youtubeClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await yt.playlistItems.insert({
      part: ["snippet"],
      requestBody,
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "youtube_playlist_item_insert", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.49 B4 — YouTube playlists (2 tools, destructive slice) ─────────
 *
 * youtube_playlist_item_remove (playlistItems.delete — RECOVERABLE: re-insert) +
 * youtube_playlist_delete (playlists.delete — PERMANENT: YouTube has NO playlist
 * trash). Both WRITE (min_tier=write), on the existing youtube.force-ssl scope —
 * ZERO new OAuth scope. Locked posture (docs/v1.49-youtube-playlist-destructive.md
 * §2, inherited from v1.48 §2/§6):
 *   - tier + force-ssl scope ONLY. NO SAFESPACE_YOUTUBE_PLAYLIST_TARGETS
 *     allowlist, NO burst counter — a playlist is channel-OWNED. playlist_delete
 *     mirrors youtube_comment_delete's recovery-bias: write-tier is the floor
 *     (deletion destroys content + audit evidence), scope enforced, but NO
 *     allowlist blocks an operator from cleaning up their OWN channel.
 *   - NO pre-fetch on either (avoids TOCTOU + saves a quota unit). Google
 *     rejects deleting items/playlists you don't own with 403 — we let it
 *     surface via toGoogleError.
 *   - Audit: the SAME playlistMutationMeta channel; operation value-union
 *     "playlist_item_remove" / "playlist_delete"; target_playlist_hash present
 *     on both (item_remove requires playlist_id as the forensic anchor since the
 *     SDK keys off the opaque playlist_item_id only — mirror youtube_comment_reply
 *     requiring video_id). Record allow-meta BEFORE the SDK call (survives 5xx);
 *     tier-denial records denied_tier BEFORE the throw. NO new error code.
 *   - classifyDestructive (safespace audit deletes) counts ONLY playlist_delete
 *     (permanent); playlist_item_remove is recoverable so it is excluded. */

/**
 * `youtube_playlist_item_remove` — WRITE TIER. Remove a single video (playlist
 * ITEM) from a playlist. RECOVERABLE (re-add via youtube_playlist_item_insert).
 * `playlist_item_id` is the SDK delete key (the `id` of an entry from
 * youtube_playlist_items_list); `playlist_id` is required as the forensic audit
 * anchor + caller-intent clarity (the SDK call does NOT use it; no pre-fetch to
 * verify membership — TOCTOU-free, mirror youtube_comment_reply's caller-supplied
 * video_id). SDK: `playlistItems.delete({ id })` → 204 No Content.
 * Quota: 50 units / call. Audit: operation="playlist_item_remove",
 * target_playlist_hash = sha256(playlist_id), NO target_video_hash. */
export async function youtubePlaylistItemRemove(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. Input validation ────────────────────────────────────────────
  if (typeof args.playlist_id !== "string") {
    throw new Error("youtube_playlist_item_remove: 'playlist_id' must be a string");
  }
  if (!YOUTUBE_PLAYLIST_ID_RE.test(args.playlist_id)) {
    throw new Error(
      "youtube_playlist_item_remove: 'playlist_id' must match /^(?:PL|UU|LL|OL|FL|RD)[A-Za-z0-9_-]{1,64}$/ (YouTube playlist-ID format)",
    );
  }
  const playlistId = args.playlist_id;

  if (typeof args.playlist_item_id !== "string") {
    throw new Error(
      "youtube_playlist_item_remove: 'playlist_item_id' must be a string",
    );
  }
  if (!YOUTUBE_PLAYLIST_ITEM_ID_RE.test(args.playlist_item_id)) {
    throw new Error(
      "youtube_playlist_item_remove: 'playlist_item_id' must match /^[A-Za-z0-9_.\\-]{1,128}$/ (YouTube playlist-item ID; length cap 128 = DoS guard)",
    );
  }
  const playlistItemId = args.playlist_item_id;
  const playlistHash = sha256Hex(playlistId);

  // ─── 2. Tier check (defense-in-depth) ──────────────────────────────
  const tier = ctx.tier;
  if (tier === "read") {
    ctx.audit.record("playlistMutationMeta", {
      target_playlist_hash: playlistHash,
      operation: "playlist_item_remove",
      policy_decision: "denied_tier",
    });
    throw new MCPError("scope_mismatch", {
      tool: "youtube_playlist_item_remove",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  // ─── 3. Record allow-meta BEFORE the SDK call (survives SDK 5xx) ────
  ctx.audit.record("playlistMutationMeta", {
    target_playlist_hash: playlistHash,
    operation: "playlist_item_remove",
    policy_decision: "allowed",
  });

  // ─── 4. SDK call (playlistItems.delete returns 204 No Content) ──────
  try {
    const yt = youtubeClientFromToken(requireGoogle(ctx).getAccessToken());
    await yt.playlistItems.delete({ id: playlistItemId });
    // Synthesize an explicit body (Google's 204 has none) — mirror
    // youtube_comment_delete / drive_unshare_file shape convention.
    return { deleted: true, playlist_item_id: playlistItemId };
  } catch (err) {
    throw toGoogleError(err, { tool: "youtube_playlist_item_remove", email: requireGoogle(ctx).accountId });
  }
}

/**
 * `youtube_playlist_delete` — WRITE TIER. Delete an ENTIRE playlist.
 * PERMANENTLY IRREVERSIBLE — YouTube has NO playlist trash (asymmetric with
 * Drive's 30-day trash). Mirror youtube_comment_delete:
 *   ENFORCED  → SAFESPACE_TIER=write or higher (tier is the floor — deletion
 *               destroys content + audit evidence) + youtube.force-ssl scope.
 *   NO gate   → no target allowlist, no burst counter (recovery-bias: an
 *               operator must be able to clean up their OWN channel).
 * NO pre-fetch (playlists.list before delete) — avoids TOCTOU + saves a quota
 * unit. Google rejects deleting playlists you don't own with 403; we let it
 * surface via toGoogleError. SDK: `playlists.delete({ id })` → 204 No Content.
 * Quota: 50 units / call. Audit: operation="playlist_delete",
 * target_playlist_hash = sha256(playlist_id); counted in `safespace audit
 * deletes` via the v1.49 classifyDestructive branch. */
export async function youtubePlaylistDelete(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. Input validation ────────────────────────────────────────────
  if (typeof args.playlist_id !== "string") {
    throw new Error("youtube_playlist_delete: 'playlist_id' must be a string");
  }
  if (!YOUTUBE_PLAYLIST_ID_RE.test(args.playlist_id)) {
    throw new Error(
      "youtube_playlist_delete: 'playlist_id' must match /^(?:PL|UU|LL|OL|FL|RD)[A-Za-z0-9_-]{1,64}$/ (YouTube playlist-ID format)",
    );
  }
  const playlistId = args.playlist_id;
  const playlistHash = sha256Hex(playlistId);

  // ─── 2. Tier check (defense-in-depth; recovery-bias is scope LIMITED —
  //        tier is the floor, NOT bypassed) ──────────────────────────────
  const tier = ctx.tier;
  if (tier === "read") {
    ctx.audit.record("playlistMutationMeta", {
      target_playlist_hash: playlistHash,
      operation: "playlist_delete",
      policy_decision: "denied_tier",
    });
    throw new MCPError("scope_mismatch", {
      tool: "youtube_playlist_delete",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  // ─── 3. NO allowlist / NO burst (recovery-bias per §2; intentional) ──

  // ─── 4. Record allow-meta BEFORE the SDK call (survives SDK 5xx; the
  //        forensic row shows what Claude ATTEMPTED to delete) ───────────
  ctx.audit.record("playlistMutationMeta", {
    target_playlist_hash: playlistHash,
    operation: "playlist_delete",
    policy_decision: "allowed",
  });

  // ─── 5. SDK call (playlists.delete returns 204 No Content) ─────────
  try {
    const yt = youtubeClientFromToken(requireGoogle(ctx).getAccessToken());
    await yt.playlists.delete({ id: playlistId });
    return { deleted: true, playlist_id: playlistId };
  } catch (err) {
    throw toGoogleError(err, { tool: "youtube_playlist_delete", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.17 Phase 1 — Calendar mutation tier (3 tools) ─────────
 *
 * calendar_update_event / calendar_delete_event / calendar_respond — WRITE
 * TIER. First mutation-tier work in SafeSpace history (Calendar create-only
 * before v1.17). All 3 reuse the v1.13 Phase 2 `calendar.events` scope (NO
 * re-consent ceremony). See docs/v1.17-deferred-completion.md §2.1-2.3.
 *
 * Hard-coded `sendUpdates="none"` invariant carries forward from v1.13 Phase 2
 * across all 3 tools (design §10 Q1 LOCKED + §8 hook #1). Caller cannot
 * override — registry `additionalProperties:false` rejects at schema layer,
 * handler builds URL params literally.
 *
 * Sec-rev hooks (per design §8) addressed in Phase 1:
 *   #1   sendUpdates="none" literal — all 3 handlers; sentinel tests assert
 *        URL params.sendUpdates === "none" lowercase exact (NOT "None" /
 *        "NONE" / undefined).
 *   #2   calendar_update_event 20-field NEGATIVE sentinel + per-attendee
 *        allowlist {email, displayName} only. Construct requestBody LITERALLY
 *        from the 6-key allowlist (summary / description / location / start /
 *        end / attendees) — NEVER spread args. Sentinel tests assert positive
 *        (keys ⊆ allowlist) AND negative (none of 20 forbidden fields).
 *   #6   Phase 3 contact-lookup extends to calendar_update_event attendees —
 *        same SAFESPACE_RECIPIENT_ALLOW_CONTACTS env var, same
 *        resolveRecipientsViaContactLookup helper, same recipient_lookup_failed
 *        (-32022) on miss / ambiguity. Audit row gains resolved_recipient_hash
 *        when resolution occurred (reuses v1.15 Phase 3 field; no schema add).
 *   #7   Audit-on-denial invariant — recordCalendarMutationMeta called
 *        BEFORE the SDK call so forensic fields (target_event_hash +
 *        policy_decision="allowed") survive SDK 5xx. Tier-denial path records
 *        meta then throws. Mirror of v1.16 PR #135 INFO-4 reconciliation.
 *   #8   No PII echo in error data — Error messages reference RULE
 *        violations (e.g., "event_id must match ...") NEVER the raw value.
 *        Generic recovery messages on tier denial.
 *   #9   calendar_respond non-self deep-equality — handler pre-fetches via
 *        events.get, then rebuilds attendees list where non-self entries are
 *        byte-for-byte identical to pre-fetch (same key set, same per-key
 *        values). Self entry has ALL pre-fetched keys preserved with ONLY
 *        responseStatus mutated. Length-match alone insufficient — sentinel
 *        test asserts deep equality.
 *  #10   calendar_delete_event min_tier=write — registry enforces; handler
 *        tier-check is defense-in-depth (mirror v1.16 youtube_video_comment_post
 *        pattern).
 *  #11   Opaque-ID path-segment validation — CALENDAR_EVENT_ID_MUTATION_RE
 *        (stricter, length-capped {1,128} variant; distinct from the
 *        existing length-uncapped CALENDAR_EVENT_ID_RE on v1.13 read tier)
 *        applied BEFORE event_id flows into URL path. Defense against
 *        path-traversal smuggling (e.g., event_id="abc/../../etc/passwd")
 *        AND DoS via oversized IDs.
 *
 * Deferred to Phase 1c+ (per design §11 Risk 3 + sec-rev carry-forward):
 *   - ETag / If-Match optimistic concurrency on update_event + respond (TOCTOU
 *     get-then-patch race window is accepted out-of-scope).
 *   - Single-field start/end on update_event (current Phase 1 requires BOTH
 *     if either is supplied — caller reads existing via calendar_get_event).
 *
 * SECURITY: googleapis SDK accepts the FULL Schema$Event shape for
 * events.patch — handler MUST construct requestBody LITERALLY from
 * allowlisted inputs. NEVER spread or pass-through caller-supplied
 * requestBody. Tests pin this with positive (allowlist) + negative
 * (per-forbidden-field) assertions. */

/* ───────── v1.59: youtube_analytics_query (READ) ─────────
 *
 * YouTube Analytics API v2 `reports.query` over the channel's OWN analytics.
 * Scope: yt-analytics.readonly (non-monetary). v1.61 adds an OPT-IN monetary
 * (revenue) tier — see ANALYTICS_MONETARY_METRICS + the effective-allowlist union
 * below. Design docs/v1.59-youtube-analytics.md + docs/v1.61-youtube-analytics-monetary.md.
 *
 * SECURITY POSTURE (all allowlist-constructed — never a raw query pass-through):
 *   - `ids` is FORCED to "channel==MINE" — there is NO code path to query an
 *     arbitrary channel id (own-channel-only invariant, Q3).
 *   - metrics / dimensions validated against curated CLOSED sets; an unknown
 *     value is rejected with the RULE (the allowed list), never echoed-as-value.
 *     Revenue metrics are in the allowlist ONLY when the v1.61 monetary opt-in
 *     flag is set (default OFF → revenue rejected, byte-identical to v1.59).
 *   - filters is an OBJECT with a fixed 3-key allowlist {video, country, playlist},
 *     each format-gated, then constructed into the `key==value;…` string — the
 *     caller can never supply a raw filter string or an unlisted key.
 *   - dates strict YYYY-MM-DD; max_results clamped; sort must be a requested metric.
 */

// Curated CLOSED allowlists (non-monetary). Extend per request; an unlisted
// value is rejected. The monetary metrics live in ANALYTICS_MONETARY_METRICS
// below and are unioned in ONLY when the v1.61 opt-in flag is set.
const ANALYTICS_METRICS: ReadonlySet<string> = new Set([
  "views",
  "estimatedMinutesWatched",
  "averageViewDuration",
  "averageViewPercentage",
  "subscribersGained",
  "subscribersLost",
  "likes",
  "dislikes",
  "comments",
  "shares",
  "videosAddedToPlaylists",
  "videosRemovedFromPlaylists",
  "annotationClickThroughRate",
  "annotationCloseRate",
  "cardClickRate",
  "cardTeaserClickRate",
]);

// v1.61 — MONETARY (revenue) metrics. These require the
// `yt-analytics-monetary.readonly` scope (NOT in the base v1.59 scope) and are
// unlocked into the metric allowlist ONLY when
// SAFESPACE_YOUTUBE_ANALYTICS_MONETARY=true (strict-truthy). With the flag unset
// (the default) these are NOT in the effective allowlist, so a revenue metric is
// rejected by the existing validateNameList gate with the RULE, never echoed as
// the value — byte-identical to v1.59. Closed set, extend-on-request (Q3).
// docs/v1.61-youtube-analytics-monetary.md §1.2.
const ANALYTICS_MONETARY_METRICS: ReadonlySet<string> = new Set([
  "estimatedRevenue",
  "estimatedAdRevenue",
  "estimatedRedPartnerRevenue",
  "grossRevenue",
  "cpm",
  "playbackBasedCpm",
  "adImpressions",
  "monetizedPlaybacks",
]);
const ANALYTICS_DIMENSIONS: ReadonlySet<string> = new Set([
  "day",
  "month",
  "video",
  "playlist",
  "country",
  "insightTrafficSourceType",
  "deviceType",
  "subscribedStatus",
  "ageGroup",
  "gender",
]);
const ANALYTICS_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const ANALYTICS_VIDEO_ID_RE = /^[A-Za-z0-9_-]{11}$/;
const ANALYTICS_COUNTRY_RE = /^[A-Z]{2}$/;
const ANALYTICS_PLAYLIST_ID_RE = /^[A-Za-z0-9_-]{12,64}$/;

/** Validate a comma-separated name list against a closed allowlist; returns the
 *  trimmed names. Rejects an empty list or any unlisted name (rule-not-value). */
function validateNameList(
  raw: unknown,
  field: string,
  allowed: ReadonlySet<string>,
  required: boolean,
): string[] {
  // Separate the two failure modes for readability: absence vs wrong-type/empty.
  if (raw === undefined) {
    if (!required) return [];
    throw new Error(`youtube_analytics_query requires a non-empty '${field}' (comma-separated)`);
  }
  if (typeof raw !== "string" || raw.trim().length === 0) {
    throw new Error(
      `youtube_analytics_query: '${field}' must be a non-empty comma-separated string${required ? "" : " (or omitted)"}`,
    );
  }
  const names = raw.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
  if (names.length === 0) throw new Error(`youtube_analytics_query: '${field}' yielded no names`);
  for (const n of names) {
    if (!allowed.has(n)) {
      // Echo the RULE (the allowed list), NOT the rejected value (design §6 /
      // v1.45 freebusy echo-rule-not-value). The allowed list lets the caller
      // self-correct without turning the gate into a value-reflection surface.
      throw new Error(
        `youtube_analytics_query: unsupported ${field} value — allowed ${field}: ${[...allowed].join(", ")}`,
      );
    }
  }
  return names;
}

/** Build the `filters` string from the fixed 3-key allowlist object. */
function buildAnalyticsFilters(raw: unknown): string | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error("youtube_analytics_query: 'filters' must be an object {video?, country?, playlist?}");
  }
  const f = raw as Record<string, unknown>;
  const parts: string[] = [];
  if (f.video !== undefined) {
    if (typeof f.video !== "string" || !ANALYTICS_VIDEO_ID_RE.test(f.video)) {
      throw new Error("youtube_analytics_query: filters.video must be an 11-char video id");
    }
    parts.push(`video==${f.video}`);
  }
  if (f.country !== undefined) {
    if (typeof f.country !== "string" || !ANALYTICS_COUNTRY_RE.test(f.country)) {
      throw new Error("youtube_analytics_query: filters.country must be an ISO-3166 alpha-2 code (e.g. US)");
    }
    parts.push(`country==${f.country}`);
  }
  if (f.playlist !== undefined) {
    if (typeof f.playlist !== "string" || !ANALYTICS_PLAYLIST_ID_RE.test(f.playlist)) {
      throw new Error("youtube_analytics_query: filters.playlist must be a playlist id");
    }
    parts.push(`playlist==${f.playlist}`);
  }
  return parts.length > 0 ? parts.join(";") : undefined;
}

export async function youtubeAnalyticsQuery(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // v1.61 — the EFFECTIVE metric allowlist: base, plus the revenue metrics ONLY
  // when the monetary opt-in flag is set. Read at call-time (not module load) so
  // the flag is honored per-process. With the flag unset this is exactly
  // ANALYTICS_METRICS → revenue metrics are rejected (byte-identical to v1.59).
  const allowedMetrics: ReadonlySet<string> = isYoutubeAnalyticsMonetaryEnabled()
    ? new Set([...ANALYTICS_METRICS, ...ANALYTICS_MONETARY_METRICS])
    : ANALYTICS_METRICS;
  const metrics = validateNameList(args.metrics, "metrics", allowedMetrics, true);
  const dimensions = validateNameList(args.dimensions, "dimensions", ANALYTICS_DIMENSIONS, false);

  const startDate = args.start_date;
  const endDate = args.end_date;
  if (typeof startDate !== "string" || !ANALYTICS_DATE_RE.test(startDate)) {
    throw new Error("youtube_analytics_query: 'start_date' must be YYYY-MM-DD");
  }
  if (typeof endDate !== "string" || !ANALYTICS_DATE_RE.test(endDate)) {
    throw new Error("youtube_analytics_query: 'end_date' must be YYYY-MM-DD");
  }

  const filters = buildAnalyticsFilters(args.filters);

  // sort (optional) — must reference one of the requested metrics (± "-" prefix).
  let sort: string | undefined;
  if (args.sort !== undefined) {
    if (typeof args.sort !== "string") throw new Error("youtube_analytics_query: 'sort' must be a string");
    const bare = args.sort.startsWith("-") ? args.sort.slice(1) : args.sort;
    if (!metrics.includes(bare)) {
      throw new Error("youtube_analytics_query: 'sort' must be one of the requested metrics (optionally prefixed with '-')");
    }
    sort = args.sort;
  }

  // max_results clamp [1, 200]. Reuse the shared YouTube clamp (default 200, cap 200).
  const maxResults =
    args.max_results === undefined ? undefined : clampYoutubeMaxResults(args.max_results, 200, 200);

  try {
    const yta = youtubeAnalyticsClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await yta.reports.query({
      ids: "channel==MINE", // FORCED — own channel only (Q3)
      startDate,
      endDate,
      metrics: metrics.join(","),
      ...(dimensions.length > 0 ? { dimensions: dimensions.join(",") } : {}),
      ...(filters !== undefined ? { filters } : {}),
      ...(sort !== undefined ? { sort } : {}),
      ...(maxResults !== undefined ? { maxResults } : {}),
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "youtube_analytics_query", email: requireGoogle(ctx).accountId });
  }
}

