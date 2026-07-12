// Barrel for the per-API registry split (mechanical refactor of the former
// monolithic src/tools/registry.ts). Public export surface is unchanged:
// ToolDef, the OAuth scope constants, TOOL_REGISTRY, IMPLEMENTED_TOOLS,
// computeScopeUnion. TOOL_REGISTRY key order is reassembled byte-for-byte
// (cross-account tools stay interleaved exactly as before, so tools/list
// output is identical).
import type { ToolDef } from "./types";
import { gmailTools } from "./gmail";
import { driveTools } from "./drive";
import { docsTools } from "./docs";
import { formsTools } from "./forms";
import { calendarTools } from "./calendar";
import { contactsTools } from "./contacts";
import { youtubeTools } from "./youtube";
import { tasksTools } from "./tasks";
import { sheetsTools } from "./sheets";
import { slidesTools } from "./slides";
import { githubTools } from "./github";
import { webTools } from "./web";
import { fsTools } from "./fs";
import { inboxTools } from "./inbox";
import { lineTools } from "./line";
import { telegramTools } from "./telegram";
import { discordTools } from "./discord";
import { slackTools } from "./slack";
import { mattermostTools } from "./mattermost";
import { notionTools } from "./notion";
import { xTools } from "./x";
import { crossAccountTools } from "./cross-account";

export type { ToolDef } from "./types";
export {
  GMAIL_READONLY,
  GMAIL_LABELS,
  GMAIL_MODIFY,
  GMAIL_SEND,
  DRIVE_READONLY,
  DRIVE,
  DOCUMENTS_READONLY,
  DOCUMENTS,
  PRESENTATIONS_READONLY,
  PRESENTATIONS,
  FORMS_BODY_READONLY,
  FORMS_RESPONSES_READONLY,
  FORMS_BODY,
  CALENDAR_EVENTS_READONLY,
  CALENDAR_EVENTS,
  CALENDAR_FREEBUSY,
  CALENDAR_CALENDARLIST_READONLY,
  CONTACTS_READONLY,
  YOUTUBE_READONLY,
  YOUTUBE_FORCE_SSL,
  TASKS,
  SPREADSHEETS,
} from "./scopes";

// Superset of all tool defs (key order irrelevant here — reordered below).
const FRAGMENTS: Record<string, ToolDef> = {
  ...gmailTools,
  ...driveTools,
  ...docsTools,
  ...calendarTools,
  ...contactsTools,
  ...youtubeTools,
  ...tasksTools,
  ...sheetsTools,
  ...slidesTools,
  ...formsTools,
  ...githubTools,
  ...webTools,
  ...fsTools,
  ...inboxTools,
  ...lineTools,
  ...telegramTools,
  ...discordTools,
  ...slackTools,
  ...mattermostTools,
  ...notionTools,
  ...xTools,
  ...crossAccountTools,
};

// Exact original insertion order (interleaved cross-account preserved).
const TOOL_ORDER: readonly string[] = [
  "gmail_search",
  "gmail_list_labels",
  "gmail_create_label",
  "gmail_get_message",
  "gmail_modify_message",
  "gmail_modify_messages_batch",
  "gmail_send",
  "gmail_create_draft",
  "gmail_list_drafts",
  "gmail_get_draft",
  "gmail_delete_draft",
  "gmail_get_thread",
  "gmail_get_attachment",
  "gmail_list_filters",
  "gmail_create_filter",
  "gmail_delete_filter",
  "drive_search",
  "drive_get_file_content",
  "drive_share_file",
  "drive_unshare_file",
  "drive_create_folder",
  "drive_move_file",
  "drive_list_permissions",
  "drive_create_file",
  "drive_copy_file",
  "drive_rename_file",
  "docs_get_content",
  "docs_create",
  "docs_append_text",
  "docs_modify_structured",
  "calendar_list_events",
  "calendar_get_event",
  "calendar_query_freebusy",
  "calendar_list_calendars",
  "gmail_search_all",
  "drive_search_all",
  "calendar_create_event",
  "calendar_update_event",
  "calendar_delete_event",
  "calendar_respond",
  "contacts_search",
  "contacts_lookup_email",
  "contacts_get",
  "contacts_create",
  "contacts_update",
  "youtube_subscriptions_all",
  "youtube_channel_uploads",
  "youtube_video_get",
  "youtube_search",
  "youtube_video_comments_list",
  "youtube_video_comment_post",
  "youtube_video_update",
  "youtube_comment_reply",
  "youtube_comment_delete",
  "youtube_playlists_list",
  "youtube_playlist_items_list",
  "youtube_playlist_create",
  "youtube_playlist_update",
  "youtube_playlist_item_insert",
  "youtube_playlist_item_remove",
  "youtube_playlist_delete",
  "youtube_analytics_query",
  "sheets_get_values",
  "sheets_get_metadata",
  "sheets_create",
  "sheets_update_values",
  "sheets_batch_update",
  "sheets_append_values",
  "slides_get",
  "slides_create",
  "slides_modify",
  "forms_get",
  "forms_list_responses",
  "forms_get_response",
  "forms_create",
  "forms_modify",
  "tasks_lists",
  "tasks_list",
  "tasks_get",
  "tasks_search_all",
  "tasks_create",
  "tasks_update",
  "tasks_delete",
  "tasks_move",
  "tasks_clear",
  // v1.70 (G4) — the 2nd OAuth source: GitHub read tools (api.github.com).
  "github_list_repos",
  "github_list_issues",
  "github_get_issue",
  "github_get_pull_request",
  "github_list_issue_comments",
  // v1.71 — GitHub WRITE tools (PUBLIC-surface egress; default-deny repo allowlist).
  "github_create_issue",
  "github_create_issue_comment",
  "github_update_issue",
  // v1.81 — open a pull request (same public-surface egress slice).
  "github_create_pull_request",
  // v1.82 — merge a PR (IRREVERSIBLE; its own default-deny merge allowlist).
  "github_merge_pull_request",
  // v1.90 — submit a PR review (APPROVE rides its own default-deny approve allowlist;
  // COMMENT / REQUEST_CHANGES ride the write allowlist).
  "github_create_pull_request_review",
  // v1.84 — set the label set on an issue/PR (triage).
  "github_set_issue_labels",
  // v1.76 — GitHub READ deepening (repo / PR list / PR files / commits / file content).
  "github_get_repo",
  "github_list_pull_requests",
  "github_list_pull_request_files",
  "github_list_commits",
  "github_get_commit",
  "github_get_file_content",
  // v1.65 Phase C — the first keyless, non-Google connector.
  "web_fetch",
  // v1.75 — the second keyless connector (host filesystem read).
  "fs_read",
  // v1.102 (W0) — the inbound webhook inbox READ (keyless; populated by the listener).
  "inbox_read",
  // v1.66 Phase C PR 2 — the first service-token, non-Google connector (LINE OA).
  "line_push_message",
  // v1.68 — the second service-token, non-Google connector (Telegram Bot).
  "telegram_send_message",
  // v1.98 — Telegram READ (the inbound poll-inbox; the 2nd service-token READ).
  "telegram_get_updates",
  // v1.69 — the third service-token, non-Google connector (Discord Bot).
  "discord_send_message",
  // v1.95 — the fourth service-token, non-Google connector (Slack Bot).
  "slack_send_message",
  // v1.97 — Slack READ (the first service-token READ).
  "slack_list_channels",
  "slack_read_messages",
  // v1.104 — Slack READ: the workspace directory (users.*).
  "slack_users_list",
  "slack_user_info",
  // v1.107 — the fifth service-token connector + the FIRST self-hosted one (Mattermost).
  "mattermost_send_message",
  "mattermost_list_teams",
  "mattermost_list_channels",
  "mattermost_read_messages",
  // v1.77 — the fourth service-token connector + the FIRST that READS (Notion).
  "notion_search",
  "notion_get_page",
  "notion_get_block_children",
  "notion_query_database",
  "notion_get_database",
  // v1.96 — Notion WRITE (text-only, egress-gated).
  "notion_create_page",
  "notion_append_blocks",
  "notion_update_page",
  // v1.114 — X (Twitter) READ (the first tools of the 4th OAuth source).
  "x_get_me",
  "x_post_create",
  "x_search_recent",
];

export const TOOL_REGISTRY: Record<string, ToolDef> = Object.fromEntries(
  // FRAGMENTS[name] is always defined: TOOL_ORDER is exactly the fragments'
  // key set (registry.test.ts asserts the union). The `!` satisfies
  // noUncheckedIndexedAccess without a whole-object cast.
  TOOL_ORDER.map((name) => [name, FRAGMENTS[name]!]),
);

// Tools exposed to MCP `tools/list` and accepted at dispatch (server.ts). v1.85
// (D7) — DERIVED from TOOL_ORDER, the single source of truth: every ordered tool is
// implemented, so the formerly hand-maintained 111-name duplicate is gone. To add a
// tool, add it to its connector fragment + TOOL_ORDER and it is exposed automatically.
// (To register-but-hide a tool, drop it from TOOL_ORDER rather than reintroducing a
// second list.)
export const IMPLEMENTED_TOOLS: ReadonlySet<string> = new Set(TOOL_ORDER);

export function computeScopeUnion(): string[] {
  return [
    ...new Set(Object.values(TOOL_REGISTRY).flatMap((t) => t.requiredScopes as string[])),
  ].sort();
}
