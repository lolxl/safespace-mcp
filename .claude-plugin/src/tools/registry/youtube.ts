// Youtube tool definitions — extracted verbatim from the former
// monolithic src/tools/registry.ts TOOL_REGISTRY (mechanical per-API split).
// Assembled in original key order by ./index.ts.

import type { ToolDef } from "./types";
import * as handlers from "../handlers";
// B6.1 wave A2b — the pipeline-fired egress descriptors for the 3 youtube write
// tools (withToolContext runs extract → gate pre-handler; the gate's sanitized
// text/fields ride ctx.egress — the handler wires THAT).
import {
  youtubeCommentPostEgressDescriptor,
  youtubeCommentReplyEgressDescriptor,
  youtubeVideoUpdateEgressDescriptor,
} from "../egress-pipeline";
import {
  YOUTUBE_READONLY,
  YOUTUBE_FORCE_SSL,
  YT_ANALYTICS_READONLY,
} from "./scopes";

export const youtubeTools: Record<string, ToolDef> = {
  youtube_channel_uploads: {
    name: "youtube_channel_uploads",
    description:
      "List recent uploads from a YouTube channel (READ OPERATION). Uses the auto-generated uploads playlist (`UU` + channel-id-suffix) via playlistItems.list. channel_id MUST match /^UC[A-Za-z0-9_-]{22}$/ — 24-char YouTube channel-ID format (validated handler-side before SDK call to reject path traversal / CRLF). Returns Google's playlistItems response with snippet + contentDetails for each upload. User-visible text (snippet.title, snippet.description, snippet.channelTitle) is sanitize-wrapped; opaque IDs (videoId, channelId, playlistId) pass through unwrapped. Quota: playlistItems.list = 1 unit / call.",
    inputSchema: {
      type: "object",
      properties: {
        channel_id: {
          type: "string",
          description:
            "YouTube channel ID (24 chars: 'UC' + 22 url-safe chars; e.g., 'UCxxxxxxxxxxxxxxxxxxxxxx'). Get from a channel URL OR from youtube_subscriptions_all results.",
        },
        max_results: {
          type: "integer",
          minimum: 1,
          maximum: 50,
          default: 5,
          description:
            "Maximum number of uploads to return (default 5, hard cap 50 enforced at handler boundary).",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["channel_id"],
      additionalProperties: false,
    },
    requiredScopes: [YOUTUBE_READONLY],
    handler: handlers.youtubeChannelUploads,
    min_tier: "read",
  },
  youtube_video_get: {
    name: "youtube_video_get",
    description:
      "Get metadata for a single YouTube video (READ OPERATION). video_id MUST match /^[A-Za-z0-9_-]{11}$/ — 11-char YouTube video-ID format (validated handler-side before SDK call). parts is an ALLOWLIST (default-deny): only `snippet` / `statistics` / `contentDetails` / `status` / `topicDetails` accepted; default ['snippet','statistics']. Any other value (incl. future Google-added parts like `fileDetails` / `liveStreamingDetails`) rejected at the handler boundary. User-visible text (snippet.title, snippet.description, snippet.channelTitle, snippet.tags[]) is sanitize-wrapped; opaque IDs (videoId, channelId) + closed enums (privacyStatus, uploadStatus, license, liveBroadcastContent) pass through unwrapped. Quota: videos.list = 1 unit / call.",
    inputSchema: {
      type: "object",
      properties: {
        video_id: {
          type: "string",
          description:
            "YouTube video ID (11 url-safe chars; e.g., 'dQw4w9WgXcQ'). NOT a URL — paste just the id segment from the video's URL.",
        },
        parts: {
          type: "array",
          items: {
            type: "string",
            enum: ["snippet", "statistics", "contentDetails", "status", "topicDetails"],
          },
          minItems: 1,
          description:
            "Which parts of the video resource to include. ALLOWLIST: snippet / statistics / contentDetails / status / topicDetails. Default ['snippet','statistics'].",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["video_id"],
      additionalProperties: false,
    },
    requiredScopes: [YOUTUBE_READONLY],
    handler: handlers.youtubeVideoGet,
    min_tier: "read",
  },
  youtube_search: {
    name: "youtube_search",
    description:
      "Search YouTube for videos / channels / playlists (READ OPERATION). EXPENSIVE: each call costs 100 units of the daily YouTube quota (default 10,000 units / day = max ~100 search calls / day; the rest of YouTube tools cost 1 unit each). Per-session burst limit (default 20, override via SAFESPACE_YOUTUBE_SEARCH_BURST_LIMIT range 1-100): the 21st search in the same MCP session rejects with `search_burst_limit_exceeded` (-32026) BEFORE invoking the SDK — counter resets on MCP server restart. video_type ALLOWLIST: 'video' (default) / 'channel' / 'playlist'. max_results clamped 1-50 (default 10). Returns Google's search.list response with snippet fields per result. User-visible text (title, description, channelTitle) is sanitize-wrapped; opaque IDs pass through unwrapped.",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "Free-text search query.",
        },
        max_results: {
          type: "integer",
          minimum: 1,
          maximum: 50,
          default: 10,
          description:
            "Maximum number of results (default 10, hard cap 50 enforced at handler boundary).",
        },
        video_type: {
          type: "string",
          enum: ["video", "channel", "playlist"],
          default: "video",
          description:
            "Result type. Default 'video'. ALLOWLIST: video / channel / playlist (rejected at handler boundary if any other value supplied).",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["query"],
      additionalProperties: false,
    },
    requiredScopes: [YOUTUBE_READONLY],
    handler: handlers.youtubeSearch,
    min_tier: "read",
  },
  youtube_video_comments_list: {
    name: "youtube_video_comments_list",
    description:
      "List comment threads on a YouTube video (READ OPERATION). HIGHEST UGC injection-surface in SafeSpace — comments are wholly attacker-controlled by ANY YouTube viewer worldwide. Per-leaf sanitize-wrap on textDisplay / textOriginal / authorDisplayName / authorChannelUrl / authorProfileImageUrl is non-negotiable. video_id MUST match /^[A-Za-z0-9_-]{11}$/ (validated handler-side). order ALLOWLIST: 'time' (default) / 'relevance'. max_results clamped 1-100 (default 20; per-thread cap, NOT per-author). Total leaf cap MAX_TOTAL_COMMENT_LEAVES=500 enforced handler-side: comments beyond the cap are truncated and a synthetic <safespace-truncated/> marker thread is appended to signal the truncation. Quota: commentThreads.list = 1 unit / call.",
    inputSchema: {
      type: "object",
      properties: {
        video_id: {
          type: "string",
          description:
            "YouTube video ID (11 url-safe chars; e.g., 'dQw4w9WgXcQ').",
        },
        max_results: {
          type: "integer",
          minimum: 1,
          maximum: 100,
          default: 20,
          description:
            "Maximum number of top-level comment threads (default 20, hard cap 100 = Google API max).",
        },
        order: {
          type: "string",
          enum: ["time", "relevance"],
          default: "time",
          description: "Sort order. ALLOWLIST: time / relevance. Default 'time'.",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["video_id"],
      additionalProperties: false,
    },
    requiredScopes: [YOUTUBE_READONLY],
    handler: handlers.youtubeVideoCommentsList,
    min_tier: "read",
  },
  youtube_video_comment_post: {
    name: "youtube_video_comment_post",
    description:
      "Post a top-level comment to a YouTube video (WRITE OPERATION, PUBLIC + PERMANENT). ALWAYS ask the user for explicit confirmation before calling this tool. PUBLIC comment, visible to anyone who can view the video; tied to your YouTube channel identity; cannot be retracted programmatically — recovery requires youtube_comment_delete (Phase 3, not yet shipped); deletion non-instant due to Google caching. YouTube may shadow-ban based on posting patterns; comments may be deleted by Google moderation independently — SafeSpace does NOT mitigate YouTube anti-spam (out of scope). 4-gate enforcement: (1) SAFESPACE_TIER=write or share + (2) youtube.force-ssl scope + (3) SAFESPACE_YOUTUBE_COMMENT_TARGETS allowlist (default empty = no comment writes permitted even when scope is granted; add `video:<11-char>` / `channel:UC<22>` / `playlist:<prefix><1-64>` entries) + (4) per-session burst limit SAFESPACE_YOUTUBE_COMMENT_BURST_LIMIT (default 10, range 1-100; counter resets on MCP server restart). Comment text passes 6-step outbound sanitize (rejects zero-width chars / control sequences / over-length text >10000 bytes). Allowlist first-cut: only direct `video:<id>` matches accepted (channel: / playlist: resolution deferred). Quota cost: 50 units / call. Every call emits an audit row with target_video_hash + comment_length + policy_decision (NEVER the plaintext text).",
    inputSchema: {
      type: "object",
      properties: {
        video_id: {
          type: "string",
          pattern: "^[A-Za-z0-9_-]{11}$",
          description:
            "YouTube video ID (11 url-safe chars; e.g., 'dQw4w9WgXcQ'). MUST appear in SAFESPACE_YOUTUBE_COMMENT_TARGETS as `video:<id>`.",
        },
        text: {
          type: "string",
          minLength: 1,
          maxLength: 10000,
          description:
            "Comment text. 1-10000 bytes UTF-8. Outbound sanitize rejects zero-width chars / SafeSpace control sequences.",
        },
        channel_id: {
          type: "string",
          pattern: "^UC[A-Za-z0-9_-]{22}$",
          description:
            "Optional: post AS this brand channel (must be a channel you own). Validated handler-side before SDK call.",
        },
        account_id: {
          type: "string",
          description:
            "Email of the posting account; defaults to the most recently used account.",
        },
      },
      required: ["video_id", "text"],
      additionalProperties: false,
    },
    requiredScopes: [YOUTUBE_FORCE_SSL],
    // B6.1 wave A2b — pipeline-fired egress (extract → enforceYoutubeCommentEgressGates).
    direction: "outbound-write",
    egress: youtubeCommentPostEgressDescriptor,
    handler: handlers.youtubeVideoCommentPost,
    min_tier: "write",
  },
  youtube_video_update: {
    name: "youtube_video_update",
    description:
      "Update a video's PUBLIC snippet metadata — title / description / tags — on a video YOUR channel owns (WRITE OPERATION, PUBLIC, reversible). ALWAYS ask the user for explicit confirmation before calling this tool. The title/description is the most visible, identity-defining text on your channel. REPLACE SEMANTICS: title + category_id are REQUIRED, and OMITTING description or tags CLEARS the existing value — pass every field you want to keep. SafeSpace reads the current values for you NOWHERE (no pre-fetch, avoids TOCTOU): call youtube_video_get parts=snippet first to get the current title / category_id / description / tags. SafeSpace sends ONLY part=snippet, so the video's privacy / publish status / made-for-kids flag CANNOT be changed by this tool. 4-gate enforcement: (1) SAFESPACE_TIER=write or share + (2) youtube.force-ssl scope + (3) SAFESPACE_YOUTUBE_VIDEO_TARGETS allowlist (DEFAULT EMPTY = no video-metadata writes permitted even when scope is granted; add `video:<11-char-id>` entries, comma-separated; per-session via SAFESPACE_YOUTUBE_VIDEO_TARGETS_EXTRA) + (4) each field passes 6-step outbound sanitize (rejects zero-width chars / SafeSpace control sequences / over-length) plus a secret-shape scan (rejects a leaked private-key / API-key shape under autonomous mode). videos.update only edits videos you own (403 otherwise). Quota cost: 50 units / call. Audit records target_video_hash + operation='video_update' + title_length (+ description_length / tag_count when supplied) + policy_decision (NEVER the plaintext title/description/tags).",
    inputSchema: {
      type: "object",
      properties: {
        video_id: {
          type: "string",
          pattern: "^[A-Za-z0-9_-]{11}$",
          description:
            "YouTube video ID (11 url-safe chars) of a video you own. MUST appear in SAFESPACE_YOUTUBE_VIDEO_TARGETS as `video:<id>`.",
        },
        title: {
          type: "string",
          minLength: 1,
          maxLength: 10000,
          description:
            "New video title (REQUIRED — REPLACE semantics). YouTube enforces a 100-char limit. Get the current title via youtube_video_get parts=snippet.",
        },
        category_id: {
          type: "string",
          pattern: "^[0-9]{1,3}$",
          description:
            "YouTube videoCategory id (REQUIRED by the API when writing snippet; e.g., '22' = People & Blogs). Read the current value via youtube_video_get parts=snippet.",
        },
        description: {
          type: "string",
          maxLength: 10000,
          description:
            "New video description (OPTIONAL — OMITTING it CLEARS the existing description). Multi-line allowed.",
        },
        tags: {
          type: "array",
          items: { type: "string", minLength: 1 },
          maxItems: 50,
          description:
            "New tags (OPTIONAL — OMITTING the array CLEARS existing tags). YouTube enforces a ~500-char total limit server-side.",
        },
        account_id: {
          type: "string",
          description:
            "Email of the owning account; defaults to the most recently used account.",
        },
      },
      required: ["video_id", "title", "category_id"],
      additionalProperties: false,
    },
    requiredScopes: [YOUTUBE_FORCE_SSL],
    // B6.1 wave A2b — pipeline-fired egress (extract → enforceYoutubeVideoUpdateEgressGates).
    direction: "outbound-write",
    egress: youtubeVideoUpdateEgressDescriptor,
    handler: handlers.youtubeVideoUpdate,
    min_tier: "write",
  },
  youtube_comment_reply: {
    name: "youtube_comment_reply",
    description:
      "Post a REPLY to an existing YouTube comment (WRITE OPERATION, PUBLIC + PERMANENT — see youtube_video_comment_post for full warnings). ALWAYS ask the user for explicit confirmation before calling this tool. CALLER MUST supply video_id (the videoId of the parent comment's video) — SafeSpace requires this to avoid TOCTOU resolution and to gate the reply through the same allowlist check as the original post. If you don't know the video_id, call youtube_video_comments_list first to look it up. Same 4-gate enforcement as youtube_video_comment_post (tier + scope + SAFESPACE_YOUTUBE_COMMENT_TARGETS allowlist on the caller-supplied video_id + per-session burst limit). Outbound sanitize on the reply text. Quota cost: 50 units / call. Audit records target_video_hash + parent_comment_id_hash + comment_length + policy_decision.",
    inputSchema: {
      type: "object",
      properties: {
        parent_comment_id: {
          type: "string",
          pattern: "^[A-Za-z0-9_.\\-]{1,256}$",
          description:
            "YouTube comment ID of the parent (top-level) comment to reply to. Length capped 256 chars.",
        },
        video_id: {
          type: "string",
          pattern: "^[A-Za-z0-9_-]{11}$",
          description:
            "YouTube video ID of the parent comment's video (caller-supplied; SafeSpace does NOT resolve from parent_comment_id to avoid TOCTOU). MUST appear in SAFESPACE_YOUTUBE_COMMENT_TARGETS as `video:<id>`.",
        },
        text: {
          type: "string",
          minLength: 1,
          maxLength: 10000,
          description:
            "Reply text. 1-10000 bytes UTF-8. Outbound sanitize rejects zero-width chars / SafeSpace control sequences.",
        },
        account_id: {
          type: "string",
          description:
            "Email of the posting account; defaults to the most recently used account.",
        },
      },
      required: ["parent_comment_id", "video_id", "text"],
      additionalProperties: false,
    },
    requiredScopes: [YOUTUBE_FORCE_SSL],
    // B6.1 wave A2b — pipeline-fired egress (extract → enforceYoutubeCommentEgressGates).
    direction: "outbound-write",
    egress: youtubeCommentReplyEgressDescriptor,
    handler: handlers.youtubeCommentReply,
    min_tier: "write",
  },
  youtube_comment_delete: {
    name: "youtube_comment_delete",
    description:
      "Delete a YouTube comment authored by the consenting account (WRITE OPERATION, PERMANENTLY IRREVERSIBLE — YouTube has NO comment trash recovery, asymmetric with Drive's 30-day trash). ALWAYS ask the user for explicit confirmation before calling this tool. Recovery > Policy bypass: SKIPS the SAFESPACE_YOUTUBE_COMMENT_TARGETS allowlist AND SAFESPACE_YOUTUBE_COMMENT_BURST_LIMIT counter — 'brakes always work' so the operator can always undo a mis-posted comment. STILL ENFORCED: SAFESPACE_TIER=write or higher (tier is the floor — write-tier is required because deletion destroys content + audit evidence in a way `drive_unshare_file` does not) + youtube.force-ssl scope. Google API only allows deleting your OWN comments (returns 403 otherwise). NO pre-fetch (`comments.list({id})`) to avoid TOCTOU resolution. Quota cost: 50 units / call. Audit records target_comment_id_hash (plain SHA-256) + policy_decision='deleted' in a NEW commentDeleteMeta channel distinct from commentPostMeta (post vs delete cleanly separated for forensic log greps).",
    inputSchema: {
      type: "object",
      properties: {
        comment_id: {
          type: "string",
          pattern: "^[A-Za-z0-9_.\\-]{1,256}$",
          description:
            "YouTube comment ID to delete. Length capped 256 chars. MUST be authored by the consenting account (Google returns 403 otherwise).",
        },
        account_id: {
          type: "string",
          description:
            "Email of the deleting account; defaults to the most recently used account.",
        },
      },
      required: ["comment_id"],
      additionalProperties: false,
    },
    requiredScopes: [YOUTUBE_FORCE_SSL],
    handler: handlers.youtubeCommentDelete,
    min_tier: "write",
  },
  // ───────── v1.48 B4 — YouTube playlists (5 tools, non-destructive) ─────────
  youtube_playlists_list: {
    name: "youtube_playlists_list",
    description:
      "List playlists owned by the consenting account (READ OPERATION). With no channel_id, lists YOUR playlists (mine=true); with channel_id (24-char 'UC...' format, validated handler-side), lists that channel's PUBLIC playlists. parts: snippet + status + contentDetails. User-visible text (snippet.title, snippet.description, snippet.channelTitle) is sanitize-wrapped; opaque IDs (playlistId, channelId) + closed enums (privacyStatus) pass through unwrapped. max_results clamped 1-50 (default 25). Quota: playlists.list = 1 unit / call.",
    inputSchema: {
      type: "object",
      properties: {
        channel_id: {
          type: "string",
          pattern: "^UC[A-Za-z0-9_-]{22}$",
          description:
            "Optional: list THIS channel's public playlists (24 chars: 'UC' + 22 url-safe). Omit to list your own playlists.",
        },
        max_results: {
          type: "integer",
          minimum: 1,
          maximum: 50,
          default: 25,
          description:
            "Maximum number of playlists to return (default 25, hard cap 50 enforced at handler boundary).",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: [],
      additionalProperties: false,
    },
    requiredScopes: [YOUTUBE_READONLY],
    handler: handlers.youtubePlaylistsList,
    min_tier: "read",
  },
  youtube_playlist_items_list: {
    name: "youtube_playlist_items_list",
    description:
      "List the items (videos) in a playlist (READ OPERATION). playlist_id MUST match /^(?:PL|UU|LL|OL|FL|RD)[A-Za-z0-9_-]{1,64}$/ (YouTube playlist-ID format; validated handler-side before SDK call). parts: snippet + contentDetails. User-visible text (snippet.title, snippet.description, snippet.channelTitle, snippet.videoOwnerChannelTitle) is sanitize-wrapped; opaque IDs (playlistId, videoId, channelId) pass through unwrapped. max_results clamped 1-50 (default 25). Quota: playlistItems.list = 1 unit / call.",
    inputSchema: {
      type: "object",
      properties: {
        playlist_id: {
          type: "string",
          pattern: "^(?:PL|UU|LL|OL|FL|RD)[A-Za-z0-9_-]{1,64}$",
          description:
            "YouTube playlist ID (e.g., 'PLxxxxxxxx'). Get it from youtube_playlists_list or a playlist URL.",
        },
        max_results: {
          type: "integer",
          minimum: 1,
          maximum: 50,
          default: 25,
          description:
            "Maximum number of items to return (default 25, hard cap 50 enforced at handler boundary).",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["playlist_id"],
      additionalProperties: false,
    },
    requiredScopes: [YOUTUBE_READONLY],
    handler: handlers.youtubePlaylistItemsList,
    min_tier: "read",
  },
  youtube_playlist_create: {
    name: "youtube_playlist_create",
    description:
      "Create a new playlist on your channel (WRITE OPERATION, non-destructive). Defaults privacy_status='private' (the playlist is NOT public unless you explicitly set 'public'). title is REQUIRED (control chars CR/LF/NUL/NEL/U+2028/U+2029 rejected; SafeSpace byte-cap 600 = DoS guard, YouTube enforces its 150-char limit). description is OPTIONAL (byte-cap 20000). privacy_status ALLOWLIST: private (default) / unlisted / public. Gated by SAFESPACE_TIER=write + youtube.force-ssl scope (NO target allowlist — a playlist is channel-owned, not a public-broadcast surface like a comment). Quota: playlists.insert = 50 units / call. Audit records target_playlist_hash + operation='playlist_create' (NEVER the plaintext title/description).",
    inputSchema: {
      type: "object",
      properties: {
        title: {
          type: "string",
          minLength: 1,
          description:
            "Playlist title (1-600 bytes UTF-8; control characters rejected). YouTube enforces a 150-char limit server-side.",
        },
        description: {
          type: "string",
          description: "Optional playlist description (up to 20000 bytes UTF-8).",
        },
        privacy_status: {
          type: "string",
          enum: ["private", "unlisted", "public"],
          default: "private",
          description:
            "Visibility. ALLOWLIST: private (default) / unlisted / public. Rejected at the handler boundary if any other value supplied.",
        },
        account_id: {
          type: "string",
          description: "Email of the owning account; defaults to the most recently used account.",
        },
      },
      required: ["title"],
      additionalProperties: false,
    },
    requiredScopes: [YOUTUBE_FORCE_SSL],
    handler: handlers.youtubePlaylistCreate,
    min_tier: "write",
  },
  youtube_playlist_update: {
    name: "youtube_playlist_update",
    description:
      "Update a playlist's title / description / privacy (WRITE OPERATION, non-destructive, reversible). REPLACE SEMANTICS: title is REQUIRED (omitting it errors), and omitting description CLEARS it — pass every field you want to keep. playlist_id MUST match the YouTube playlist-ID format. privacy is changed ONLY when privacy_status is supplied (otherwise left untouched). NO pre-fetch (avoids TOCTOU). Gated by SAFESPACE_TIER=write + youtube.force-ssl scope. Quota: playlists.update = 50 units / call. Audit records target_playlist_hash + operation='playlist_update'.",
    inputSchema: {
      type: "object",
      properties: {
        playlist_id: {
          type: "string",
          pattern: "^(?:PL|UU|LL|OL|FL|RD)[A-Za-z0-9_-]{1,64}$",
          description: "YouTube playlist ID to update (must be a playlist you own).",
        },
        title: {
          type: "string",
          minLength: 1,
          description:
            "New playlist title (REQUIRED — playlists.update is replace-semantics; 1-600 bytes UTF-8, control chars rejected).",
        },
        description: {
          type: "string",
          description:
            "New description (up to 20000 bytes UTF-8). OMITTING this CLEARS the existing description (replace semantics).",
        },
        privacy_status: {
          type: "string",
          enum: ["private", "unlisted", "public"],
          description:
            "Optional new visibility. ALLOWLIST: private / unlisted / public. Omit to leave privacy unchanged.",
        },
        account_id: {
          type: "string",
          description: "Email of the owning account; defaults to the most recently used account.",
        },
      },
      required: ["playlist_id", "title"],
      additionalProperties: false,
    },
    requiredScopes: [YOUTUBE_FORCE_SSL],
    handler: handlers.youtubePlaylistUpdate,
    min_tier: "write",
  },
  youtube_playlist_item_insert: {
    name: "youtube_playlist_item_insert",
    description:
      "Add a video to a playlist (WRITE OPERATION, non-destructive — reversible via the YouTube UI or v1.49 remove). playlist_id + video_id REQUIRED (both validated handler-side before SDK call). position OPTIONAL (non-negative integer; inserts at that 0-based index). Gated by SAFESPACE_TIER=write + youtube.force-ssl scope. Quota: playlistItems.insert = 50 units / call. Audit records target_playlist_hash + target_video_hash + operation='playlist_item_insert'.",
    inputSchema: {
      type: "object",
      properties: {
        playlist_id: {
          type: "string",
          pattern: "^(?:PL|UU|LL|OL|FL|RD)[A-Za-z0-9_-]{1,64}$",
          description: "YouTube playlist ID to add the video to (must be a playlist you own).",
        },
        video_id: {
          type: "string",
          pattern: "^[A-Za-z0-9_-]{11}$",
          description: "YouTube video ID (11 url-safe chars; e.g., 'dQw4w9WgXcQ').",
        },
        position: {
          type: "integer",
          minimum: 0,
          description: "Optional 0-based insert position. Omit to append to the end.",
        },
        account_id: {
          type: "string",
          description: "Email of the owning account; defaults to the most recently used account.",
        },
      },
      required: ["playlist_id", "video_id"],
      additionalProperties: false,
    },
    requiredScopes: [YOUTUBE_FORCE_SSL],
    handler: handlers.youtubePlaylistItemInsert,
    min_tier: "write",
  },
  // ───────── v1.49 B4 — YouTube playlists (2 tools, destructive slice) ────────
  youtube_playlist_item_remove: {
    name: "youtube_playlist_item_remove",
    description:
      "Remove a single video from a playlist (WRITE OPERATION, RECOVERABLE — re-add with youtube_playlist_item_insert). playlist_item_id REQUIRED — this is the playlist-ITEM id (NOT the video id; get it from youtube_playlist_items_list, each item's `id`). playlist_id REQUIRED — the playlist the item belongs to (used for the forensic audit hash + caller-intent clarity; SafeSpace does NOT pre-fetch to verify the item belongs to it, avoiding TOCTOU). Both validated handler-side before the SDK call. Gated by SAFESPACE_TIER=write + youtube.force-ssl scope (NO target allowlist — a playlist is channel-owned, not a public-broadcast surface). Quota: playlistItems.delete = 50 units / call. Audit records target_playlist_hash + operation='playlist_item_remove' (NOT counted in the `safespace audit deletes` density alert — removal is recoverable).",
    inputSchema: {
      type: "object",
      properties: {
        playlist_id: {
          type: "string",
          pattern: "^(?:PL|UU|LL|OL|FL|RD)[A-Za-z0-9_-]{1,64}$",
          description:
            "YouTube playlist ID the item belongs to (must be a playlist you own). Recorded as the forensic audit hash.",
        },
        playlist_item_id: {
          type: "string",
          pattern: "^[A-Za-z0-9_.\\-]{1,128}$",
          description:
            "YouTube playlist-ITEM ID to remove (the `id` of an entry from youtube_playlist_items_list — NOT the video id). Length capped 128 = DoS guard.",
        },
        account_id: {
          type: "string",
          description: "Email of the owning account; defaults to the most recently used account.",
        },
      },
      required: ["playlist_id", "playlist_item_id"],
      additionalProperties: false,
    },
    requiredScopes: [YOUTUBE_FORCE_SSL],
    handler: handlers.youtubePlaylistItemRemove,
    min_tier: "write",
  },
  youtube_playlist_delete: {
    name: "youtube_playlist_delete",
    description:
      "Delete an entire playlist you own (WRITE OPERATION, PERMANENTLY IRREVERSIBLE — YouTube has NO playlist trash recovery, asymmetric with Drive's 30-day trash). ALWAYS ask the user for explicit confirmation before calling this tool. Deletes the playlist + all its item associations permanently (the videos themselves are NOT deleted, but the curated collection is gone). ENFORCED: SAFESPACE_TIER=write or higher (tier is the floor — deletion destroys content + audit evidence) + youtube.force-ssl scope. NO target allowlist + NO burst counter (recovery-bias: an operator must be able to clean up their OWN channel — mirrors youtube_comment_delete). NO pre-fetch (avoids TOCTOU). Google API only allows deleting your OWN playlists (403 otherwise). Quota: playlists.delete = 50 units / call. Audit records target_playlist_hash + operation='playlist_delete' (counted in the `safespace audit deletes` density alert).",
    inputSchema: {
      type: "object",
      properties: {
        playlist_id: {
          type: "string",
          pattern: "^(?:PL|UU|LL|OL|FL|RD)[A-Za-z0-9_-]{1,64}$",
          description: "YouTube playlist ID to delete PERMANENTLY (must be a playlist you own).",
        },
        account_id: {
          type: "string",
          description: "Email of the owning account; defaults to the most recently used account.",
        },
      },
      required: ["playlist_id"],
      additionalProperties: false,
    },
    requiredScopes: [YOUTUBE_FORCE_SSL],
    handler: handlers.youtubePlaylistDelete,
    min_tier: "write",
  },
  youtube_analytics_query: {
    name: "youtube_analytics_query",
    description:
      "Query YOUR OWN YouTube channel's analytics (READ OPERATION; YouTube Analytics API v2 reports.query). Returns rows of channel metrics (views, watch-time, subscriber deltas, engagement, traffic) over a date range — the data the channel owner cares about, which the youtube_* Data tools cannot surface. ALWAYS scoped to your own channel (ids=channel==MINE — there is NO way to query another channel). metrics + dimensions are ALLOWLISTS (default-deny: an unlisted name is rejected). Dates are strict YYYY-MM-DD. filters is a fixed 3-key object {video, country, playlist}, each format-validated (no raw filter strings). Requires the yt-analytics.readonly scope (re-consent: `safespace consent <email> --re-auth`). NON-monetary by default (no revenue). REVENUE metrics (estimatedRevenue, estimatedAdRevenue, cpm, monetizedPlaybacks, …) are an OPT-IN: set SAFESPACE_YOUTUBE_ANALYTICS_MONETARY=true, then re-consent (this additionally requests the yt-analytics-monetary.readonly scope); otherwise a revenue metric is rejected. Quota: ~1 unit / call.",
    inputSchema: {
      type: "object",
      properties: {
        metrics: {
          type: "string",
          description:
            "Comma-separated metric names (ALLOWLIST). e.g. 'views,estimatedMinutesWatched,subscribersGained'. Allowed: views / estimatedMinutesWatched / averageViewDuration / averageViewPercentage / subscribersGained / subscribersLost / likes / dislikes / comments / shares / videosAddedToPlaylists / videosRemovedFromPlaylists / annotationClickThroughRate / annotationCloseRate / cardClickRate / cardTeaserClickRate.",
        },
        start_date: {
          type: "string",
          description: "Inclusive start date, strict YYYY-MM-DD (e.g. '2026-05-01').",
        },
        end_date: {
          type: "string",
          description: "Inclusive end date, strict YYYY-MM-DD (e.g. '2026-05-28').",
        },
        dimensions: {
          type: "string",
          description:
            "Optional comma-separated dimension names (ALLOWLIST). e.g. 'day' or 'video'. Allowed: day / month / video / playlist / country / insightTrafficSourceType / deviceType / subscribedStatus / ageGroup / gender.",
        },
        filters: {
          type: "object",
          properties: {
            video: { type: "string", description: "Restrict to one video (11-char id)." },
            country: { type: "string", description: "Restrict to one country (ISO-3166 alpha-2, e.g. 'US')." },
            playlist: { type: "string", description: "Restrict to one playlist (id)." },
          },
          additionalProperties: false,
          description:
            "Optional filters. Fixed 3-key allowlist; each value is format-validated and built into the API filter string (no raw filter strings accepted).",
        },
        sort: {
          type: "string",
          description:
            "Optional sort: one of the requested metrics, optionally prefixed with '-' for descending (e.g. '-views').",
        },
        max_results: {
          type: "integer",
          minimum: 1,
          maximum: 200,
          description: "Maximum rows to return (clamped to [1, 200]).",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["metrics", "start_date", "end_date"],
      additionalProperties: false,
    },
    requiredScopes: [YT_ANALYTICS_READONLY],
    handler: handlers.youtubeAnalyticsQuery,
    min_tier: "read",
  },
};
