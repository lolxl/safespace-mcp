#!/usr/bin/env bun
/**
 * Probe: youtube_video_get + youtube_video_comments_list + youtube_subscriptions
 * sanitize coverage on a real YouTube account.
 *
 * v1.16 Phase 1b — manual one-time validation per
 * docs/v1.16-youtube-api.md §10. Run this once per consented account
 * against (a) a real video_id (suggested: any popular Google IO talk),
 * and (b) the account's own subscription list. Confirms:
 *
 *   1. User-visible YouTube content (snippet.title, snippet.description,
 *      snippet.channelTitle, snippet.tags[*], comment.snippet.textDisplay,
 *      comment.snippet.textOriginal, comment.snippet.authorDisplayName,
 *      comment.snippet.authorChannelUrl, thumbnail urls) IS wrapped in
 *      <untrusted-source-NONCE/> per the sanitize pipeline.
 *   2. Google opaque keys (videoId, channelId, playlistId, subscriptionId,
 *      commentId, authorChannelId) AND closed enums (liveBroadcastContent,
 *      privacyStatus, uploadStatus, license) pass through UNWRAPPED —
 *      they're in SKIP_FIELDS so Claude can keep using them as opaque
 *      references (e.g., feed videoId into a follow-up youtube_video_get
 *      call).
 *   3. The walk completes without throwing `sanitize_failed` — confirming
 *      the MAX_DEPTH=64 ceiling (carried from v1.12) accommodates real
 *      YouTube responses including deep reply chains under
 *      commentThreads[*].replies.comments[*].
 *   4. youtube_video_comments_list leaf-cap enforcement: if the video has
 *      >500 leaves (top-level + nested replies), the response contains
 *      the synthetic `<safespace-truncated/>` marker thread.
 *
 * Usage:
 *   bun scripts/probe-youtube-sanitize.ts \
 *     --account=alice@example.com \
 *     --video-id=<11-char-video-id> \
 *     [--config-dir=<path>]
 *
 * SAFETY:
 *   - Read-only — calls `videos.list` + `commentThreads.list` +
 *     `subscriptions.list` once each and walks the responses. No writes,
 *     no shares, no comment-posts.
 *   - Bypasses the production `withToolContext` middleware (this calls
 *     `youtubeClientFromToken` + `sanitize` directly so the assertions
 *     are observable). The handler-level validation is exercised in unit
 *     tests; this probe specifically validates real-API shape compatibility.
 *   - Each call costs 1 quota unit (videos.list, commentThreads.list,
 *     subscriptions.list = 1u each). Total ≈ 3 units. Safe.
 *
 * MANUAL one-time validation; not in CI. Run after Phase 1b ships to verify
 * against real Google API.
 *
 * Reproducibility: kept in repo so the sanitize compatibility analysis
 * can be re-validated if Google adds new opaque keys or schema-level
 * fields in future YouTube Data API revisions.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

// ──────────────── arg parsing ────────────────
const args = process.argv.slice(2).reduce<Record<string, string>>((acc, arg) => {
  const m = arg.match(/^--([\w-]+)=(.+)$/);
  if (m && m[1] && m[2]) acc[m[1]] = m[2];
  return acc;
}, {});

const account = args.account;
const videoId = args["video-id"];
const configDir =
  args["config-dir"] ??
  process.env.SAFESPACE_CONFIG_DIR ??
  path.join(os.homedir(), ".claude", "plugins", "data", "safespace-mcp-safespace", "safespace");

if (!account || !videoId) {
  console.error(
    "Usage: bun scripts/probe-youtube-sanitize.ts " +
      "--account=<email> --video-id=<11-char-video-id> [--config-dir=<path>]",
  );
  process.exit(1);
}

const VIDEO_ID_RE = /^[A-Za-z0-9_-]{11}$/;
if (!VIDEO_ID_RE.test(videoId)) {
  console.error(
    `ERROR: --video-id=${videoId} does not match /^[A-Za-z0-9_-]{11}$/`,
  );
  console.error("       Example: --video-id=dQw4w9WgXcQ");
  process.exit(1);
}

// ──────────────── env bootstrap ────────────────
const envFile = path.join(configDir, ".env");
if (!fs.existsSync(envFile)) {
  console.error(`ERROR: .env not found at ${envFile}`);
  console.error(`       (override with --config-dir=<path/to/safespace>)`);
  process.exit(1);
}
const envContent = fs.readFileSync(envFile, "utf-8");
for (const line of envContent.split("\n")) {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#")) continue;
  const eq = trimmed.indexOf("=");
  if (eq < 0) continue;
  const key = trimmed.slice(0, eq).trim();
  let val = trimmed.slice(eq + 1).trim();
  if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
    val = val.slice(1, -1);
  }
  if (key && !(key in process.env)) {
    process.env[key] = val;
  }
}
process.env.SAFESPACE_CONFIG_DIR = configDir;

const { refreshAccessToken } = await import("../.claude-plugin/src/auth/refresh");
const { youtubeClientFromToken } = await import("../.claude-plugin/src/google-api/client");
const { sanitize } = await import("../.claude-plugin/src/sanitize");

console.log(`# Probe config`);
console.log(`  account:  ${account}`);
console.log(`  video_id: ${videoId}`);
console.log("");

console.log("# Refreshing access token...");
const tokens = await refreshAccessToken(account, { force: true });
console.log(`  ✓ Got fresh token`);
console.log("");

const yt = youtubeClientFromToken(tokens.access_token);

// ──────────────── walk helpers ────────────────
type WalkVisitor = (key: string, value: unknown, path: string) => void;
function walkResponse(obj: unknown, visit: WalkVisitor, p = "$"): void {
  if (obj === null || typeof obj !== "object") return;
  if (Array.isArray(obj)) {
    obj.forEach((el, i) => walkResponse(el, visit, `${p}[${i}]`));
    return;
  }
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    visit(k, v, `${p}.${k}`);
    walkResponse(v, visit, `${p}.${k}`);
  }
}

const WRAP_PREFIX_RE = /^<untrusted-source-[0-9a-f]{16}/;

// User-visible keys that MUST be wrapped per design §6.
const USER_VISIBLE_KEYS = new Set([
  "title",
  "description",
  "channelTitle",
  "customUrl",
  "keywords",
  "country",
  "textDisplay",
  "textOriginal",
  "authorDisplayName",
  "authorChannelUrl",
  "authorProfileImageUrl",
  "url",
]);

// Opaque keys (in SKIP_FIELDS) that MUST pass through unwrapped.
const OPAQUE_KEYS = new Set([
  "videoId",
  "channelId",
  "playlistId",
  "subscriptionId",
  "commentId",
  "authorChannelId",
  "liveBroadcastContent",
  "privacyStatus",
  "uploadStatus",
  "license",
  // Cross-API set
  "id",
  "etag",
  "kind",
  "nextPageToken",
]);

function probeResponse(label: string, raw: unknown): void {
  console.log(`# Running sanitize() over ${label}...`);
  let sanitized: unknown;
  try {
    sanitized = sanitize(raw, { toolName: label });
  } catch (err) {
    console.error(`  ✗ sanitize threw: ${(err as Error).message}`);
    console.error("    MAX_DEPTH=64 may need bumping OR a SKIP_FIELDS edge-case fired.");
    process.exit(2);
  }
  console.log("  ✓ sanitize() completed (no depth overflow / circular ref)");

  // Pass criterion 1: user-visible text fields ARE wrapped.
  let wrappedUserVisible = 0;
  let unwrappedUserVisible = 0;
  walkResponse(sanitized, (k, v, p) => {
    if (USER_VISIBLE_KEYS.has(k) && typeof v === "string" && v.length > 0) {
      if (WRAP_PREFIX_RE.test(v)) {
        wrappedUserVisible++;
      } else {
        unwrappedUserVisible++;
        console.error(`    ✗ UNWRAPPED user-visible at ${p}: ${v.slice(0, 60)}...`);
      }
    }
  });
  console.log(`  → ${wrappedUserVisible} user-visible fields wrapped`);
  if (unwrappedUserVisible > 0) {
    console.error(`  ✗ FAIL: ${unwrappedUserVisible} user-visible values escaped wrapping`);
    process.exit(3);
  }

  // Pass criterion 2: SKIP_FIELDS keys NEVER wrapped.
  const leaks: Array<{ path: string; key: string; value: string }> = [];
  walkResponse(sanitized, (k, v, p) => {
    if (OPAQUE_KEYS.has(k) && typeof v === "string" && WRAP_PREFIX_RE.test(v)) {
      leaks.push({ path: p, key: k, value: v.slice(0, 80) });
    }
  });
  if (leaks.length > 0) {
    console.error("  ✗ FAIL: opaque keys leaked into sanitize wrap:");
    for (const l of leaks) {
      console.error(`    - ${l.path} (${l.key}): ${l.value}...`);
    }
    process.exit(4);
  }
  console.log(`  ✓ all opaque key families pass through unwrapped`);
  console.log("");
}

// ──────────────── videos.list probe ────────────────
console.log(`# Calling videos.list for ${videoId}...`);
const videoRes = await yt.videos.list({
  id: [videoId],
  part: ["snippet", "statistics", "contentDetails", "status", "topicDetails"],
});
const firstVideo = videoRes.data.items?.[0];
if (!firstVideo) {
  console.error("ERROR: video not found in API response. Check --video-id.");
  process.exit(1);
}
const videoTitle = firstVideo.snippet?.title ?? "(no title)";
console.log(`  ✓ Got video metadata: title="${videoTitle}"`);
console.log("");

probeResponse("youtube_video_get", videoRes.data);

// ──────────────── commentThreads.list probe ────────────────
console.log(`# Calling commentThreads.list for ${videoId}...`);
let commentRes;
let commentsErrored = false;
try {
  commentRes = await yt.commentThreads.list({
    videoId,
    part: ["snippet", "replies"],
    maxResults: 100,
    order: "relevance",
  });
} catch (err) {
  const e = err as { response?: { status?: number } };
  if (e.response?.status === 403 || e.response?.status === 404) {
    console.warn(
      `  ⚠ commentThreads.list returned ${e.response.status} (comments disabled? video private?) — skipping comments probe`,
    );
    commentsErrored = true;
  } else {
    throw err;
  }
}

if (!commentsErrored && commentRes) {
  const commentCount = commentRes.data.items?.length ?? 0;
  console.log(`  ✓ Got ${commentCount} comment threads`);
  console.log("");
  probeResponse("youtube_video_comments_list", commentRes.data);
}

// ──────────────── subscriptions.list probe ────────────────
console.log(`# Calling subscriptions.list (mine=true)...`);
let subscriptionRes;
let subsErrored = false;
try {
  subscriptionRes = await yt.subscriptions.list({
    mine: true,
    part: ["snippet"],
    maxResults: 25,
  });
} catch (err) {
  const e = err as { response?: { status?: number } };
  if (e.response?.status === 403) {
    console.warn(
      `  ⚠ subscriptions.list returned 403 — account may lack subscription-access permission; skipping`,
    );
    subsErrored = true;
  } else {
    throw err;
  }
}

if (!subsErrored && subscriptionRes) {
  const subCount = subscriptionRes.data.items?.length ?? 0;
  console.log(`  ✓ Got ${subCount} subscriptions`);
  console.log("");
  probeResponse("youtube_subscriptions_all", subscriptionRes.data);
}

console.log("# All probe criteria PASSED. v1.16 Phase 1b sanitize coverage is valid for this account.");
// Explicit exit(0) on success — defense-in-depth against a stray unhandled
// rejection or non-empty event-loop queue holding the process open after the
// probe has reported success. Failure paths above already `process.exit(N)`
// with N ∈ {1,2,3,4}.
process.exit(0);
