/**
 * v1.11 Phase 1b — googleapis SDK client factories.
 *
 * Returns Gmail / Drive clients that share an authenticated OAuth2Client
 * (built by `getAuthClient`). Phase 2 tool migrations will call these.
 *
 * Both factories accept the same `email` + optional `AuthDeps` so a single
 * tool call can construct one Gmail client OR one Drive client (or both,
 * via two calls — the OAuth2Client is per-call, NOT pooled). Pooling would
 * complicate cache invalidation on token rotation and is not needed at the
 * personal-use scale we target.
 */

import {
  google,
  type calendar_v3,
  type docs_v1,
  type forms_v1,
  type slides_v1,
  type drive_v3,
  type gmail_v1,
  type people_v1,
  type sheets_v4,
  type tasks_v1,
  type youtube_v3,
  type youtubeAnalytics_v2,
} from "googleapis";
import type { OAuth2Client } from "googleapis-common";
import { getAuthClient, type AuthDeps } from "./auth";

/**
 * Phase 2 tool migration path — sync factory that builds an OAuth2Client
 * directly from an access token. Use when the caller already has a fresh
 * access token (e.g., from `ctx.getAccessToken()` inside a `withToolContext`
 * handler, where the middleware already refreshed).
 *
 * Does NOT call `refreshAccessToken` — the token MUST be fresh. 401 retries
 * are handled at the middleware layer (`with-context.ts:148`), which catches
 * `UpstreamError.httpStatus === 401` and force-refreshes before re-running
 * the handler.
 */
export function gmailClientFromToken(accessToken: string): gmail_v1.Gmail {
  const oauth = new google.auth.OAuth2();
  oauth.setCredentials({ access_token: accessToken, token_type: "Bearer" });
  return google.gmail({ version: "v1", auth: oauth });
}

export function driveClientFromToken(accessToken: string): drive_v3.Drive {
  const oauth = new google.auth.OAuth2();
  oauth.setCredentials({ access_token: accessToken, token_type: "Bearer" });
  return google.drive({ version: "v3", auth: oauth });
}

/**
 * v1.12 Phase 1b — Google Docs API client factory. Same shape as
 * `gmailClientFromToken` / `driveClientFromToken`. Required by
 * `docs_get_content` (structured-tree read) and `docs_create` (new doc).
 *
 * Scope: `https://www.googleapis.com/auth/documents` (full read+write+create).
 * See `docs/v1.12-docs-api.md` §2 for why the full scope is taken upfront
 * rather than starting with `documents.readonly`.
 */
export function docsClientFromToken(accessToken: string): docs_v1.Docs {
  const oauth = new google.auth.OAuth2();
  oauth.setCredentials({ access_token: accessToken, token_type: "Bearer" });
  return google.docs({ version: "v1", auth: oauth });
}

/**
 * v1.60 — Google Slides API v1 client factory (10th). Same shape as
 * `docsClientFromToken`; completes the Docs/Sheets/Slides trio. Scope:
 * `presentations` (bundled read+write). Required by `slides_get` (read) +
 * `slides_create` / `slides_modify` (write). See docs/v1.60-slides.md §1.
 */
export function slidesClientFromToken(accessToken: string): slides_v1.Slides {
  const oauth = new google.auth.OAuth2();
  oauth.setCredentials({ access_token: accessToken, token_type: "Bearer" });
  return google.slides({ version: "v1", auth: oauth });
}

/**
 * v1.62 — Google Forms API v1 client factory (11th). Same shape as
 * `docsClientFromToken`. Required by the read-only slice `forms_get`
 * (forms.get) + `forms_list_responses` / `forms_get_response`
 * (forms.responses.*). Scopes: `forms.body.readonly` (structure) +
 * `forms.responses.readonly` (responses). See docs/v1.62-forms-readonly.md §1.
 */
export function formsClientFromToken(accessToken: string): forms_v1.Forms {
  const oauth = new google.auth.OAuth2();
  oauth.setCredentials({ access_token: accessToken, token_type: "Bearer" });
  return google.forms({ version: "v1", auth: oauth });
}

/**
 * v1.13 Phase 1b — Google Calendar API client factory. Same shape as
 * `gmailClientFromToken` / `driveClientFromToken` / `docsClientFromToken`.
 * Required by `calendar_list_events` + `calendar_get_event` (Phase 1) and
 * `calendar_create_event` (Phase 2).
 *
 * Scope: `https://www.googleapis.com/auth/calendar.events` (read + write
 * events; does NOT grant Calendar admin / ACL / sharing). See
 * `docs/v1.13-calendar-api.md` §2 for why this scope was chosen over
 * `calendar.readonly` (would force a second re-consent for Phase 2) and
 * over full `calendar` (admin scope, far beyond SafeSpace's surface needs).
 */
export function calendarClientFromToken(accessToken: string): calendar_v3.Calendar {
  const oauth = new google.auth.OAuth2();
  oauth.setCredentials({ access_token: accessToken, token_type: "Bearer" });
  return google.calendar({ version: "v3", auth: oauth });
}

/**
 * v1.15 Phase 1b — Google People (Contacts) API client factory. Same shape as
 * `gmailClientFromToken` / `driveClientFromToken` / `docsClientFromToken` /
 * `calendarClientFromToken`. Required by `contacts_search` /
 * `contacts_lookup_email` / `contacts_get`.
 *
 * Scope: `https://www.googleapis.com/auth/contacts.readonly` (read-only,
 * personal contacts ONLY — does NOT cover other-contacts auto-harvested
 * from Gmail headers, and does NOT cover Workspace directory). See
 * `docs/v1.15-contacts-api.md` §3 for why `contacts.readonly` was chosen
 * over full `contacts` (Phase 2 write surface is deferred) and over
 * `contacts.other.readonly` / `directory.readonly` (locked rejected §14).
 */
export function peopleClientFromToken(accessToken: string): people_v1.People {
  const oauth = new google.auth.OAuth2();
  oauth.setCredentials({ access_token: accessToken, token_type: "Bearer" });
  return google.people({ version: "v1", auth: oauth });
}

/**
 * v1.16 Phase 1b — Google YouTube Data API v3 client factory. Same shape as
 * `gmailClientFromToken` / `driveClientFromToken` / `docsClientFromToken` /
 * `calendarClientFromToken` / `peopleClientFromToken`. Required by
 * `youtube_subscriptions_all` / `youtube_channel_uploads` / `youtube_video_get`
 * / `youtube_search` / `youtube_video_comments_list`.
 *
 * Scope: `https://www.googleapis.com/auth/youtube.readonly` (read-only;
 * covers subscriptions / uploads / videos / search / comments READ). Phase 2
 * write tools (comment-post) will require `youtube.force-ssl`; see
 * docs/v1.16-youtube-api.md §3 for the per-phase scope split.
 *
 * Note: YouTube Data API has a daily quota (default 10,000 units / day) —
 * `youtube_search` alone costs 100 units / call. v1.16 Phase 1b adds a
 * per-session burst limit on `youtube_search` (`SAFESPACE_YOUTUBE_SEARCH_BURST_LIMIT`,
 * default 20) to cap quota over-burn from prompt-injection loops. See
 * docs/v1.16-youtube-api.md §13 Risk 3.
 */
export function youtubeClientFromToken(accessToken: string): youtube_v3.Youtube {
  const oauth = new google.auth.OAuth2();
  oauth.setCredentials({ access_token: accessToken, token_type: "Bearer" });
  return google.youtube({ version: "v3", auth: oauth });
}

/**
 * v1.59 — YouTube Analytics API v2 client factory (9th factory). Same shape as
 * `youtubeClientFromToken`, a DIFFERENT API: `reports.query` over the channel's
 * own analytics. Scope: `yt-analytics.readonly` (non-monetary). Required by
 * `youtube_analytics_query` (read tier). See docs/v1.59-youtube-analytics.md §1.
 */
export function youtubeAnalyticsClientFromToken(
  accessToken: string,
): youtubeAnalytics_v2.Youtubeanalytics {
  const oauth = new google.auth.OAuth2();
  oauth.setCredentials({ access_token: accessToken, token_type: "Bearer" });
  return google.youtubeAnalytics({ version: "v2", auth: oauth });
}

/**
 * v1.19 Phase 1b — Google Tasks API client factory. Same shape as
 * `gmailClientFromToken` / `driveClientFromToken` / `docsClientFromToken` /
 * `calendarClientFromToken` / `peopleClientFromToken` / `youtubeClientFromToken`.
 * Required by `tasks_lists` / `tasks_list` / `tasks_get` (Phase 1b read tier)
 * and `tasks_create` / `tasks_update` / `tasks_delete` (Phase 2b write tier).
 *
 * Scope: `https://www.googleapis.com/auth/tasks` (full read + write, including
 * delete). See `docs/v1.19-tasks-api.md` §3 + Q1 LOCKED for why the bundled
 * scope is taken upfront rather than splitting `tasks.readonly` then upgrading
 * to `tasks` later (v1.13 calendar.events precedent; Tasks is heavily write-
 * oriented). Granting only `tasks.readonly` would still work for the 3 Phase 1b
 * read tools, but the second re-consent ceremony for Phase 2b has poor ROI.
 *
 * Note: Tasks API has a generous daily quota (~50,000 reads / day default).
 * No per-session burst limit applied — Tasks read patterns are not search-
 * heavy (no `youtube_search` equivalent at 100 units / call).
 */
export function tasksClientFromToken(accessToken: string): tasks_v1.Tasks {
  const oauth = new google.auth.OAuth2();
  oauth.setCredentials({ access_token: accessToken, token_type: "Bearer" });
  return google.tasks({ version: "v1", auth: oauth });
}

/**
 * v1.20 Phase 1b-1 — Google Sheets API client factory. **8th SDK client**.
 * Same shape as `gmailClientFromToken` / `driveClientFromToken` /
 * `docsClientFromToken` / `calendarClientFromToken` / `peopleClientFromToken` /
 * `youtubeClientFromToken` / `tasksClientFromToken`. Required by
 * `sheets_get_values` / `sheets_get_metadata` (Phase 1b-1 read tier) and
 * `sheets_create` / `sheets_append_values` (Phase 1b-2 write tier).
 *
 * Scope: `https://www.googleapis.com/auth/spreadsheets` (full read + write).
 * v1.20 §3 Q1 LOCKED — bundled scope, mirrors v1.13 calendar.events +
 * v1.19 tasks precedent (Sheets is heavily write-oriented for personal
 * automation; the split readonly + Phase-2-upgrade pattern from v1.15/v1.16
 * is intentionally NOT applied — two re-consent ceremonies for what amounts
 * to one logical cycle has poor ROI). SCOPE_HIERARCHY (with-context.ts)
 * encodes `spreadsheets.readonly ⊂ spreadsheets` for future-proofing.
 *
 * Note: Sheets API uses a quota model distinct from YouTube — 300 read +
 * 60 write requests / minute / project by default. No per-session burst
 * limit applied at the handler level Phase 1b-1; revisit Phase 1b-2 if
 * `sheets_append_values` / `sheets_create` patterns show abuse.
 */
export function sheetsClientFromToken(accessToken: string): sheets_v4.Sheets {
  const oauth = new google.auth.OAuth2();
  oauth.setCredentials({ access_token: accessToken, token_type: "Bearer" });
  return google.sheets({ version: "v4", auth: oauth });
}

/**
 * v1.11 Phase 3 PR-1 — token-only OAuth2Client factory for callers that need
 * `.request()` (raw HTTP) instead of an SDK service binding. The googleapis
 * SDK has no batch helper for Gmail, so `gmail_modify_messages_batch` calls
 * `oauth.request({url:"https://gmail.googleapis.com/batch/gmail/v1", ...})`
 * directly — the Bearer token is auto-attached by google-auth-library, and
 * the gaxios transporter (Bun-mocked in tests) routes the multipart body.
 *
 * Sibling to `gmailClientFromToken` / `driveClientFromToken`. Same fast-path:
 * no Keychain re-read, no refresh — caller provides a fresh access token
 * from `ctx.getAccessToken()`. Middleware handles 401 retry.
 */
export function oauth2ClientFromToken(accessToken: string): OAuth2Client {
  const oauth = new google.auth.OAuth2();
  oauth.setCredentials({ access_token: accessToken, token_type: "Bearer" });
  return oauth;
}

/**
 * Standalone factory — used for non-middleware callers (CLI, scripts) that
 * don't have access to a pre-refreshed token. Calls `refreshAccessToken`
 * internally via `getAuthClient`, which reads Keychain fresh. Inside tool
 * handlers wrapped by `withToolContext`, prefer `gmailClientFromToken` —
 * the middleware already refreshed the token, and calling refresh again
 * here would be wasted work + duplicate Keychain reads.
 */
export async function getGmailClient(
  email: string,
  deps?: AuthDeps,
): Promise<gmail_v1.Gmail> {
  const auth = await getAuthClient(email, deps);
  return google.gmail({ version: "v1", auth });
}

export async function getDriveClient(
  email: string,
  deps?: AuthDeps,
): Promise<drive_v3.Drive> {
  const auth = await getAuthClient(email, deps);
  return google.drive({ version: "v3", auth });
}
