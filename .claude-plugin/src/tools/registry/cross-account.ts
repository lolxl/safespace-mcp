// Cross tool definitions — extracted verbatim from the former
// monolithic src/tools/registry.ts TOOL_REGISTRY (mechanical per-API split).
// Assembled in original key order by ./index.ts.

import type { ToolDef } from "./types";
import * as handlers from "../handlers";
import type { ToolContext } from "../types";
import type { WithAllAccountsDeps } from "../with-all-accounts";
import {
  GMAIL_READONLY,
  DRIVE_READONLY,
  YOUTUBE_READONLY,
  TASKS,
} from "./scopes";

// Lift the tier off the cross-account sentinel into the deps the `_all` handlers
// forward to withAllAccounts. The shim's `ctx` IS the sentinel server.ts built.
// Type-only imports → no runtime cycle through with-all-accounts → registry.
function sentinelDeps(ctx: ToolContext): WithAllAccountsDeps {
  // v1.120 (F6 step 2) — forward the sentinel's ToolContext `tier` (`currentTier()`
  // at the choke point) so each per-account sub-context gets tier parity with the
  // single-account choke point.
  return { tier: ctx.tier };
}

export const crossAccountTools: Record<string, ToolDef> = {
  gmail_search_all: {
    name: "gmail_search_all",
    description:
      "Search Gmail across ALL consented accounts (or a subset via `accounts`). Best-effort cross-account fan-out: returns per-account successes + per-account failure markers (so a stale-token account doesn't block the others). Uses gmail.readonly scope (same as gmail_search; no new consent). Per-account max_results default 25 / cap 50. Active-account state (lastUsedAccount) is NOT touched by this tool. Each per-account result is sanitize-wrapped with its OWN fresh nonce (cross-account untrusted content cannot impersonate another account's wrapper). For exhaustive pagination of one account's results, use single-account `gmail_search` with that account's nextPageToken.",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "Gmail search syntax (same as gmail_search), e.g. 'from:alice@example.com subject:budget'.",
        },
        max_results: {
          type: "integer",
          minimum: 1,
          maximum: 50,
          default: 25,
          description: "Per-account max results (default 25, hard cap 50 enforced at handler boundary).",
        },
        accounts: {
          type: "array",
          items: { type: "string" },
          description: "Optional subset of consented account emails to query. Omit (or pass an empty array) for all consented accounts. Entries not in accounts.json surface as `account_not_found` failures (does NOT leak which accounts DO exist).",
        },
      },
      required: ["query"],
      additionalProperties: false,
    },
    requiredScopes: [GMAIL_READONLY],
    // Shim — cross-account handler ignores ctx (proxy passes a sentinel
    // for cross_account tools). See registry.ts ToolDef.cross_account JSDoc.
    handler: async (ctx, args) => handlers.gmailSearchAll(args, sentinelDeps(ctx)),
    min_tier: "read",
    cross_account: true,
  },
  drive_search_all: {
    name: "drive_search_all",
    description:
      "Search Google Drive across ALL consented accounts (or a subset via `accounts`). Best-effort cross-account fan-out: returns per-account successes + per-account failure markers (so a stale-token account doesn't block the others). Uses drive.readonly scope (same as drive_search; no new consent). Uses Drive query grammar (NOT Gmail's `from:` syntax): e.g. `name contains 'invoice'`, `mimeType = 'application/pdf'`. Per-account max_results default 25 / cap 50. Active-account state (lastUsedAccount) is NOT touched by this tool. Each per-account result is sanitize-wrapped with its OWN fresh nonce (cross-account untrusted content cannot impersonate another account's wrapper). The v2.1 Drive whitelist (drive-whitelist.json) is NOT consulted (read-only tool; whitelist gates `drive_share_file` only). For exhaustive pagination of one account's results, use single-account `drive_search` with that account's nextPageToken.",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description:
            "Drive query, e.g. `name contains 'invoice' and mimeType = 'application/pdf'`. See https://developers.google.com/drive/api/guides/search-files for syntax.",
        },
        max_results: {
          type: "integer",
          minimum: 1,
          maximum: 50,
          default: 25,
          description: "Per-account max results (default 25, hard cap 50 enforced at handler boundary).",
        },
        accounts: {
          type: "array",
          items: { type: "string" },
          description: "Optional subset of consented account emails to query. Omit (or pass an empty array) for all consented accounts. Entries not in accounts.json surface as `account_not_found` failures (does NOT leak which accounts DO exist).",
        },
      },
      required: ["query"],
      additionalProperties: false,
    },
    requiredScopes: [DRIVE_READONLY],
    // Shim — cross-account handler ignores ctx (proxy passes a sentinel
    // for cross_account tools). See registry.ts ToolDef.cross_account JSDoc.
    handler: async (ctx, args) => handlers.driveSearchAll(args, sentinelDeps(ctx)),
    min_tier: "read",
    cross_account: true,
  },
  youtube_subscriptions_all: {
    name: "youtube_subscriptions_all",
    description:
      "List your YouTube channel subscriptions across ALL consented accounts (or a subset via `accounts`). Cross-account fan-out: returns per-account successes + per-account failure markers (so a stale-token account doesn't block the others). Uses youtube.readonly scope. Returns ONLY your own subscriptions (Google enforces via scope — does NOT inspect other users' subscription lists). Per-account max_results default 25 / cap 50. Active-account state (lastUsedAccount) is NOT touched by this tool. Each per-account result is sanitize-wrapped with its OWN fresh nonce. Quota: subscriptions.list = 1 unit / call × N accounts (cheap).",
    inputSchema: {
      type: "object",
      properties: {
        max_results: {
          type: "integer",
          minimum: 1,
          maximum: 50,
          default: 25,
          description:
            "Per-account max results (default 25, hard cap 50 enforced at handler boundary).",
        },
        accounts: {
          type: "array",
          items: { type: "string" },
          description:
            "Optional subset of consented account emails to query. Omit (or pass an empty array) for all consented accounts. Entries not in accounts.json surface as `account_not_found` failures (does NOT leak which accounts DO exist).",
        },
      },
      required: [],
      additionalProperties: false,
    },
    requiredScopes: [YOUTUBE_READONLY],
    // Shim — cross-account handler ignores ctx (proxy passes a sentinel
    // for cross_account tools). See registry.ts ToolDef.cross_account JSDoc.
    handler: async (ctx, args) => handlers.youtubeSubscriptionsAll(args, sentinelDeps(ctx)),
    min_tier: "read",
    cross_account: true,
  },
  tasks_search_all: {
    name: "tasks_search_all",
    description:
      "Search Google Tasks across ALL consented accounts (or a subset via `accounts`) via client-side title/notes substring filter (READ OPERATION; WRITE TIER NOT REQUIRED). Best-effort cross-account fan-out: returns per-account successes + per-account failure markers (so a stale-token account doesn't block the others). Per-account, queries each account's DEFAULT task list (`@default`) UNLESS `tasklist_id` is supplied — when supplied, the same `tasklist_id` is queried in every account (useful when a shared label/convention is reused across accounts). Tasks API has NO native search parameter; query is case-insensitive substring match against `title` + `notes` (logical OR). Hidden and completed tasks are NEVER returned (handler hard-codes showHidden=false + showCompleted=false). Per-account max_results default 50 / cap 100 (Google's natural ceiling). Active-account state (lastUsedAccount) is NOT touched by this tool. Each per-account result is sanitize-wrapped with its OWN fresh nonce (cross-account untrusted content cannot impersonate another account's wrapper). NOTE: only the default task list per account is searched unless `tasklist_id` is supplied — multi-tasklist scan is deferred to Phase 4+; users with multiple lists per account may not find a known task in a non-default list. Quota: 1 unit per account per call.",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          minLength: 1,
          maxLength: 256,
          description:
            "Case-insensitive substring filter applied client-side against task `title` + `notes` (logical OR). 1-256 chars after handler-side validation.",
        },
        tasklist_id: {
          type: "string",
          description:
            "Optional Tasks API task list identifier. When omitted, queries each account's default list (`@default`). When supplied, MUST match /^[A-Za-z0-9_-]{1,128}$/ (or be the literal `@default`) — applied to EVERY account queried.",
        },
        max_results: {
          type: "integer",
          minimum: 1,
          maximum: 100,
          default: 50,
          description:
            "Per-account max results (default 50, hard cap 100 enforced at handler boundary).",
        },
        accounts: {
          type: "array",
          items: { type: "string" },
          description:
            "Optional subset of consented account emails to query. Omit (or pass an empty array) for all consented accounts. Entries not in accounts.json surface as `account_not_found` failures (does NOT leak which accounts DO exist).",
        },
      },
      required: ["query"],
      additionalProperties: false,
    },
    requiredScopes: [TASKS],
    // Shim — cross-account handler ignores ctx (proxy passes a sentinel
    // for cross_account tools). See registry.ts ToolDef.cross_account JSDoc.
    handler: async (ctx, args) => handlers.tasksSearchAll(args, sentinelDeps(ctx)),
    min_tier: "read",
    cross_account: true,
  },
};
