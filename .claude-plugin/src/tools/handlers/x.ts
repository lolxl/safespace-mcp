// v1.114 / v1.115 — X (Twitter) handlers (the tools of the 4th OAuth source).
//
// READ:  x_get_me · x_search_recent
// WRITE: x_post_create  (PUBLIC surface — default-deny account allowlist + F3a +
//        outboundSanitize + weighted-280 local precheck)
//
// OAUTH (provider x): each handler reads the bearer via requireX(ctx)
// (handlers/shared.ts) — the cross-provider narrow that throws if the credential is not an
// x OAuth credential (a Google/GitHub/Notion bearer can never reach api.x.com) — and
// uses it ONLY inline in the `Authorization: Bearer` header (passed to xApiGet /
// xApiPost), never stored, logged, or echoed. The cross-cutting envelope (account
// resolve / tier / sanitize wrap / audit) is applied by withToolContext around it.
//
// THE ENVELOPE IS THE POINT: free-text name / description / tweet text are
// attacker-influenced on READ (inbound wrap). On WRITE, agent-authored text is
// gated by enforceXPostEgressGates before it leaves the process.
//
// Paths are a closed set (never agent-constructed). Query text for x_search_recent is
// a caller-authored search string on a READ call — validated for length only, never
// sanitized (it is not an egress surface).

import { xApiGet, xApiPost } from "../../auth/x/client";
import type { ToolContext } from "../types";
import { enforceXPostEgressGates } from "../egress";
import { requireX } from "./shared";

/** Test-injection seam — production leaves it undefined (→ the real global fetch).
 *  Mirrors NotionReadDeps; the handler forwards it to xApiGet / xApiPost. */
export interface XReadDeps {
  fetchImpl?: typeof fetch;
}

const QUERY_MIN = 1;
const QUERY_MAX = 512;
const MAX_RESULTS_DEFAULT = 10;
const MAX_RESULTS_MIN = 10;
const MAX_RESULTS_MAX = 100;

/** X weighted character limit (URLs = 23; CJK/fullwidth/emoji ranges = 2; else 1). */
export const X_WEIGHTED_MAX = 280;

/** URL shapes X counts as a single 23-weight unit (mirrors t.co weighting). */
const URL_RE = /https?:\/\/\S+/g;

/** Code points that count as 2 under X's weighted length (CJK / Hangul / fullwidth /
 *  emoji / astral ideograph planes — aligned with twitter-text ranges). */
function isWeight2CodePoint(cp: number): boolean {
  return (
    (cp >= 0x1100 && cp <= 0x115f) || // Hangul Jamo
    (cp >= 0x2329 && cp <= 0x232a) ||
    (cp >= 0x2e80 && cp <= 0x303e) || // CJK radicals / punctuation
    (cp >= 0x3040 && cp <= 0xa4cf) || // Hiragana / Katakana / CJK / Yi
    (cp >= 0xac00 && cp <= 0xd7a3) || // Hangul syllables
    (cp >= 0xf900 && cp <= 0xfaff) || // CJK compatibility ideographs
    (cp >= 0xfe10 && cp <= 0xfe19) ||
    (cp >= 0xfe30 && cp <= 0xfe6f) ||
    (cp >= 0xff00 && cp <= 0xff60) || // fullwidth
    (cp >= 0xffe0 && cp <= 0xffe6) ||
    (cp >= 0x1f000 && cp <= 0x1fffd) || // emoji / symbols
    (cp >= 0x20000 && cp <= 0x2fffd) || // CJK Ext B+
    (cp >= 0x30000 && cp <= 0x3fffd)
  );
}

/**
 * X weighted length of `text`. URLs (`https?://\S+`) cost 23 each; remaining code
 * points in CJK/fullwidth/emoji ranges cost 2; everything else costs 1.
 * Exported for unit tests.
 */
export function xWeightedLength(text: string): number {
  // Replace each URL with a placeholder of weight 23, then score the rest.
  // The placeholder is a single control char that is SKIPPED during scoring —
  // its URL's full 23 was already added in the replace callback.
  const PLACEHOLDER = "\u0001";
  let weight = 0;
  const withoutUrls = text.replace(URL_RE, () => {
    weight += 23;
    return PLACEHOLDER;
  });
  for (const ch of withoutUrls) {
    if (ch === PLACEHOLDER) continue; // already counted as 23
    const cp = ch.codePointAt(0)!;
    weight += isWeight2CodePoint(cp) ? 2 : 1;
  }
  return weight;
}

/** Clamp max_results to the X recent-search window [10, 100]; default 10. */
function clampMaxResults(raw: unknown): number {
  if (typeof raw !== "number" || !Number.isFinite(raw)) return MAX_RESULTS_DEFAULT;
  const n = Math.floor(raw);
  if (n < MAX_RESULTS_MIN) return MAX_RESULTS_MIN;
  if (n > MAX_RESULTS_MAX) return MAX_RESULTS_MAX;
  return n;
}

/** GET /2/users/me — the authenticated X user. */
export async function xGetMe(
  ctx: ToolContext,
  _args: Record<string, unknown>,
  deps: XReadDeps = {},
): Promise<unknown> {
  const cred = requireX(ctx);
  return xApiGet(
    "/2/users/me",
    { "user.fields": "id,username,name,description,created_at" },
    cred.getAccessToken(),
    deps.fetchImpl,
  );
}

/** GET /2/tweets/search/recent — recent tweets matching a caller-authored query. */
export async function xSearchRecent(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: XReadDeps = {},
): Promise<unknown> {
  const cred = requireX(ctx);
  const query = args.query;
  if (typeof query !== "string" || query.length < QUERY_MIN || query.length > QUERY_MAX) {
    // Length-only validation — never echo the query text (PII / intent).
    throw new Error(`x: 'query' must be a string of ${QUERY_MIN}–${QUERY_MAX} characters`);
  }
  const maxResults = clampMaxResults(args.max_results);
  return xApiGet(
    "/2/tweets/search/recent",
    {
      query,
      max_results: String(maxResults),
      "tweet.fields": "id,text,created_at,author_id",
    },
    cred.getAccessToken(),
    deps.fetchImpl,
  );
}

/**
 * POST /2/tweets — create a post (WRITE, PUBLIC surface).
 *
 * Order (locked):
 *   1. requireX (cross-provider backstop)
 *   2. validate text (string, non-empty) + weighted-280 precheck (NO network)
 *   3. enforceXPostEgressGates (allowlist → F3a → outboundSanitize)
 *   4. xApiPost with allowlist-constructed body `{text}` only
 *
 * Never echoes the post text, account id, or token in any error.
 */
export async function xPostCreate(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: XReadDeps = {},
): Promise<unknown> {
  const cred = requireX(ctx);

  const text = args.text;
  if (typeof text !== "string" || text.length === 0) {
    // Rule only — never echo the value.
    throw new Error("x_post_create: 'text' must be a non-empty string");
  }
  // Weighted-280 precheck BEFORE any egress / network work.
  if (xWeightedLength(text) > X_WEIGHTED_MAX) {
    throw new Error(
      `x_post_create: 'text' exceeds the ${X_WEIGHTED_MAX} weighted-character limit`,
    );
  }

  // Allowlist (resolved account id) → F3a → outboundSanitize. Returns sanitized text.
  const sanitized = enforceXPostEgressGates(ctx, cred.accountId, text);

  // Allowlist-constructed body: `text` ONLY (no reply/quote params this PR).
  return xApiPost(
    "/2/tweets",
    { text: sanitized },
    cred.getAccessToken(),
    deps.fetchImpl,
  );
}
