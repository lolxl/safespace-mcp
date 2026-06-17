import { describe, expect, test } from "bun:test";
import { computeScopeUnion, IMPLEMENTED_TOOLS, TOOL_REGISTRY } from "./registry";

describe("TOOL_REGISTRY", () => {
  test("declares all v1.21 Phase 1b tools (Sheets Phase 2c write tier added: sheets_update_values + sheets_batch_update)", () => {
    expect(Object.keys(TOOL_REGISTRY).sort()).toEqual([
      "calendar_create_event",
      "calendar_delete_event",
      "calendar_get_event",
      "calendar_list_calendars",
      "calendar_list_events",
      "calendar_query_freebusy",
      "calendar_respond",
      "calendar_update_event",
      "contacts_create",
      "contacts_get",
      "contacts_lookup_email",
      "contacts_search",
      "contacts_update",
      "discord_send_message",
      "docs_append_text",
      "docs_create",
      "docs_get_content",
      "docs_modify_structured",
      "drive_copy_file",
      "drive_create_file",
      "drive_create_folder",
      "drive_get_file_content",
      "drive_list_permissions",
      "drive_move_file",
      "drive_rename_file",
      "drive_search",
      "drive_search_all",
      "drive_share_file",
      "drive_unshare_file",
      "forms_create",
      "forms_get",
      "forms_get_response",
      "forms_list_responses",
      "forms_modify",
      "fs_read",
      "github_create_issue",
      "github_create_issue_comment",
      "github_create_pull_request",
      "github_create_pull_request_review",
      "github_get_commit",
      "github_get_file_content",
      "github_get_issue",
      "github_get_pull_request",
      "github_get_repo",
      "github_list_commits",
      "github_list_issue_comments",
      "github_list_issues",
      "github_list_pull_request_files",
      "github_list_pull_requests",
      "github_list_repos",
      "github_merge_pull_request",
      "github_set_issue_labels",
      "github_update_issue",
      "gmail_create_draft",
      "gmail_create_filter",
      "gmail_create_label",
      "gmail_delete_draft",
      "gmail_delete_filter",
      "gmail_get_attachment",
      "gmail_get_draft",
      "gmail_get_message",
      "gmail_get_thread",
      "gmail_list_drafts",
      "gmail_list_filters",
      "gmail_list_labels",
      "gmail_modify_message",
      "gmail_modify_messages_batch",
      "gmail_search",
      "gmail_search_all",
      "gmail_send",
      "inbox_read",
      "line_push_message",
      "mattermost_list_channels",
      "mattermost_list_teams",
      "mattermost_read_messages",
      "mattermost_send_message",
      "notion_append_blocks",
      "notion_create_page",
      "notion_get_block_children",
      "notion_get_database",
      "notion_get_page",
      "notion_query_database",
      "notion_search",
      "notion_update_page",
      "sheets_append_values",
      "sheets_batch_update",
      "sheets_create",
      "sheets_get_metadata",
      "sheets_get_values",
      "sheets_update_values",
      "slack_list_channels",
      "slack_read_messages",
      "slack_send_message",
      "slack_user_info",
      "slack_users_list",
      "slides_create",
      "slides_get",
      "slides_modify",
      "tasks_clear",
      "tasks_create",
      "tasks_delete",
      "tasks_get",
      "tasks_list",
      "tasks_lists",
      "tasks_move",
      "tasks_search_all",
      "tasks_update",
      "telegram_get_updates",
      "telegram_send_message",
      "web_fetch",
      "youtube_analytics_query",
      "youtube_channel_uploads",
      "youtube_comment_delete",
      "youtube_comment_reply",
      "youtube_playlist_create",
      "youtube_playlist_delete",
      "youtube_playlist_item_insert",
      "youtube_playlist_item_remove",
      "youtube_playlist_items_list",
      "youtube_playlist_update",
      "youtube_playlists_list",
      "youtube_search",
      "youtube_subscriptions_all",
      "youtube_video_comment_post",
      "youtube_video_comments_list",
      "youtube_video_get",
      "youtube_video_update",
    ]);
  });

  // v1.19 Phase 1b — Tasks read tier (3 tools, bundled `tasks` scope).
  test("v1.19 Phase 1b — tasks_lists requires tasks; min_tier=read; additionalProperties:false", () => {
    expect(TOOL_REGISTRY.tasks_lists?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/tasks",
    ]);
    expect(TOOL_REGISTRY.tasks_lists?.min_tier).toBe("read");
    const schema = TOOL_REGISTRY.tasks_lists?.inputSchema as {
      additionalProperties?: unknown;
    };
    expect(schema?.additionalProperties).toBe(false);
  });

  test("v1.19 Phase 1b — tasks_list requires tasks; min_tier=read; additionalProperties:false; tasklist_id required", () => {
    expect(TOOL_REGISTRY.tasks_list?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/tasks",
    ]);
    expect(TOOL_REGISTRY.tasks_list?.min_tier).toBe("read");
    const schema = TOOL_REGISTRY.tasks_list?.inputSchema as {
      additionalProperties?: unknown;
      required?: string[];
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required?.sort()).toEqual(["tasklist_id"]);
  });

  test("v1.19 Phase 1b — tasks_get requires tasks; min_tier=read; additionalProperties:false; tasklist_id + task_id required", () => {
    expect(TOOL_REGISTRY.tasks_get?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/tasks",
    ]);
    expect(TOOL_REGISTRY.tasks_get?.min_tier).toBe("read");
    const schema = TOOL_REGISTRY.tasks_get?.inputSchema as {
      additionalProperties?: unknown;
      required?: string[];
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required?.sort()).toEqual(["task_id", "tasklist_id"]);
  });

  test("v1.19 Phase 1b — all 3 tasks read-tier tools in IMPLEMENTED_TOOLS", () => {
    expect(IMPLEMENTED_TOOLS.has("tasks_lists")).toBe(true);
    expect(IMPLEMENTED_TOOLS.has("tasks_list")).toBe(true);
    expect(IMPLEMENTED_TOOLS.has("tasks_get")).toBe(true);
  });

  // v1.19 Phase 2a — cross-account search.
  test("v1.19 Phase 2a — tasks_search_all requires tasks; min_tier=read; cross_account=true; additionalProperties:false", () => {
    expect(TOOL_REGISTRY.tasks_search_all?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/tasks",
    ]);
    expect(TOOL_REGISTRY.tasks_search_all?.min_tier).toBe("read");
    expect(TOOL_REGISTRY.tasks_search_all?.cross_account).toBe(true);
    const schema = TOOL_REGISTRY.tasks_search_all?.inputSchema as {
      additionalProperties?: unknown;
      required?: string[];
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required?.sort()).toEqual(["query"]);
  });

  test("v1.19 Phase 2a — tasks_search_all in IMPLEMENTED_TOOLS", () => {
    expect(IMPLEMENTED_TOOLS.has("tasks_search_all")).toBe(true);
  });

  test("v1.52 F1 — every cross_account tool is min_tier:read (burst-guard bypass invariant)", () => {
    // The cross-account dispatch branch (proxy.ts) bypasses `withToolContext`,
    // and therefore the v1.52 F1 write/delete burst guard. That bypass is only
    // SAFE because cross-account tools are all read-tier (reads are exempt from
    // the guard anyway). Pin the invariant so a future cross-account
    // WRITE/DELETE tool cannot silently escape the burst cap by routing through
    // the cross-account branch. The `${name}:` prefix makes a violation name
    // the offending tool in the failure diff.
    const crossAccount = Object.entries(TOOL_REGISTRY).filter(
      ([, def]) => def.cross_account === true,
    );
    expect(crossAccount.length).toBeGreaterThan(0);
    for (const [name, def] of crossAccount) {
      expect(`${name}:${def.min_tier}`).toBe(`${name}:read`);
    }
  });

  // v1.19 Phase 2b — tasks write tier (3 tools — create / update / delete).
  test("v1.19 Phase 2b — tasks_create requires tasks; min_tier=write; additionalProperties:false; tasklist_id+title required", () => {
    expect(TOOL_REGISTRY.tasks_create?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/tasks",
    ]);
    expect(TOOL_REGISTRY.tasks_create?.min_tier).toBe("write");
    const schema = TOOL_REGISTRY.tasks_create?.inputSchema as {
      additionalProperties?: unknown;
      required?: string[];
      properties?: { status?: { enum?: string[] } };
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required?.sort()).toEqual(["tasklist_id", "title"]);
    // sec-rev hook #4 — status enum closed-set
    expect(schema?.properties?.status?.enum?.sort()).toEqual([
      "completed",
      "needsAction",
    ]);
  });

  test("v1.19 Phase 2b — tasks_update requires tasks; min_tier=write; additionalProperties:false; tasklist_id+task_id required", () => {
    expect(TOOL_REGISTRY.tasks_update?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/tasks",
    ]);
    expect(TOOL_REGISTRY.tasks_update?.min_tier).toBe("write");
    const schema = TOOL_REGISTRY.tasks_update?.inputSchema as {
      additionalProperties?: unknown;
      required?: string[];
      properties?: { status?: { enum?: string[] } };
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required?.sort()).toEqual(["task_id", "tasklist_id"]);
    // Same status closed-set as create
    expect(schema?.properties?.status?.enum?.sort()).toEqual([
      "completed",
      "needsAction",
    ]);
  });

  test("v1.19 Phase 2b — tasks_delete requires tasks; min_tier=write (Q4 LOCKED — permanently destructive); additionalProperties:false", () => {
    // §10 Q4 LOCKED — tasks_delete is min_tier=write (mirror v1.17
    // youtube_comment_delete; NOT read like drive_unshare_file). Google
    // Tasks has NO trash; tier is the floor for the most destructive op.
    expect(TOOL_REGISTRY.tasks_delete?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/tasks",
    ]);
    expect(TOOL_REGISTRY.tasks_delete?.min_tier).toBe("write");
    const schema = TOOL_REGISTRY.tasks_delete?.inputSchema as {
      additionalProperties?: unknown;
      required?: string[];
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required?.sort()).toEqual(["task_id", "tasklist_id"]);
  });

  test("v1.19 Phase 2b — tasks_delete description flags PERMANENTLY DESTRUCTIVE + Google has NO trash", () => {
    // Operator-visibility load-bearing (sec-rev hook #13 recovery-
    // impossibility) — any rewording is a sec-rev event.
    const desc = TOOL_REGISTRY.tasks_delete?.description ?? "";
    expect(desc).toContain("PERMANENTLY DESTRUCTIVE");
    expect(desc).toContain("NO trash");
  });

  test("v1.19 Phase 2b — all 3 tasks write-tier tools in IMPLEMENTED_TOOLS", () => {
    expect(IMPLEMENTED_TOOLS.has("tasks_create")).toBe(true);
    expect(IMPLEMENTED_TOOLS.has("tasks_update")).toBe(true);
    expect(IMPLEMENTED_TOOLS.has("tasks_delete")).toBe(true);
  });

  // v1.47 B2 — Tasks surface completion: tasks_move + tasks_clear (write tier,
  // existing `tasks` scope; NO new scope / error code / audit channel).
  test("v1.47 B2 — tasks_move requires tasks; min_tier=write; additionalProperties:false; tasklist_id+task_id required (parent/previous optional)", () => {
    expect(TOOL_REGISTRY.tasks_move?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/tasks",
    ]);
    expect(TOOL_REGISTRY.tasks_move?.min_tier).toBe("write");
    const schema = TOOL_REGISTRY.tasks_move?.inputSchema as {
      additionalProperties?: unknown;
      required?: string[];
      properties?: Record<string, unknown>;
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required?.sort()).toEqual(["task_id", "tasklist_id"]);
    // parent + previous are exposed but OPTIONAL (within-list reparent/reorder);
    // destinationTasklist (cross-list move) is intentionally NOT exposed.
    expect(Object.keys(schema?.properties ?? {}).sort()).toEqual([
      "account_id",
      "parent",
      "previous",
      "task_id",
      "tasklist_id",
    ]);
  });

  test("v1.47 B2 — tasks_clear requires tasks; min_tier=write; additionalProperties:false; tasklist_id required (list-level)", () => {
    expect(TOOL_REGISTRY.tasks_clear?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/tasks",
    ]);
    expect(TOOL_REGISTRY.tasks_clear?.min_tier).toBe("write");
    const schema = TOOL_REGISTRY.tasks_clear?.inputSchema as {
      additionalProperties?: unknown;
      required?: string[];
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required?.sort()).toEqual(["tasklist_id"]);
  });

  test("v1.47 B2 — tasks_clear description flags RECOVERABLE + NOT the delete allowlist", () => {
    // Operator-visibility load-bearing: tasks_clear is bulk-but-recoverable
    // (hides completed tasks, does NOT permanently destroy them). The
    // description MUST distinguish it from the permanently-destructive
    // tasks_delete + state it is NOT gated by SAFESPACE_TASKS_DELETE_TARGETS.
    const desc = TOOL_REGISTRY.tasks_clear?.description ?? "";
    expect(desc).toContain("RECOVERABLE");
    expect(desc).toContain("NOT permanently");
  });

  test("v1.47 B2 — both surface-completion tools in IMPLEMENTED_TOOLS", () => {
    expect(IMPLEMENTED_TOOLS.has("tasks_move")).toBe(true);
    expect(IMPLEMENTED_TOOLS.has("tasks_clear")).toBe(true);
  });

  // v1.108 PR 1b (sec-rev LOW#4) — the fs_read.path cross-platform pre-filter pattern
  // has fragile backslash escaping; COMPILE it from the actual tool def and assert the
  // accept/reject set so the escaping cannot silently drift. (The authoritative gate is
  // policy/fs-gate.ts; this pattern is only a client-side hint.)
  test("v1.108 — fs_read.path pattern accepts POSIX/win32/UNC, rejects relative forms", () => {
    const schema = TOOL_REGISTRY.fs_read?.inputSchema as {
      properties?: { path?: { pattern?: string } };
    };
    const pattern = schema?.properties?.path?.pattern;
    expect(typeof pattern).toBe("string");
    const re = new RegExp(pattern as string);
    for (const ok of ["/srv/shared/notes.md", "C:\\data\\notes.txt", "C:/data/x", "\\\\srv\\share\\f"]) {
      expect(re.test(ok)).toBe(true);
    }
    for (const bad of ["relative/b", "C:foo", "\\foo", "notes.md", ""]) {
      expect(re.test(bad)).toBe(false);
    }
  });

  test("calendar_list_events requires calendar.events.readonly (narrower; satisfied by `calendar.events` via SCOPE_HIERARCHY)", () => {
    expect(TOOL_REGISTRY.calendar_list_events?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/calendar.events.readonly",
    ]);
    expect(TOOL_REGISTRY.calendar_list_events?.min_tier).toBe("read");
  });

  test("calendar_get_event requires calendar.events.readonly (narrower; satisfied by `calendar.events` via SCOPE_HIERARCHY)", () => {
    expect(TOOL_REGISTRY.calendar_get_event?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/calendar.events.readonly",
    ]);
    expect(TOOL_REGISTRY.calendar_get_event?.min_tier).toBe("read");
  });

  // v1.45 (backlog A5) — Calendar free/busy + calendar list (two READ tools,
  // each on a NEW minimum-privilege scope; re-consent ceremony).
  test("v1.45 — calendar_query_freebusy requires calendar.freebusy (NOT calendar.events); min_tier=read; calendar_ids required; additionalProperties:false", () => {
    expect(TOOL_REGISTRY.calendar_query_freebusy?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/calendar.freebusy",
    ]);
    expect(TOOL_REGISTRY.calendar_query_freebusy?.min_tier).toBe("read");
    const schema = TOOL_REGISTRY.calendar_query_freebusy?.inputSchema as {
      additionalProperties?: unknown;
      required?: string[];
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required).toEqual(["calendar_ids"]);
  });

  test("v1.45 — calendar_list_calendars requires calendar.calendarlist.readonly; min_tier=read; no required inputs; additionalProperties:false", () => {
    expect(TOOL_REGISTRY.calendar_list_calendars?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
    ]);
    expect(TOOL_REGISTRY.calendar_list_calendars?.min_tier).toBe("read");
    const schema = TOOL_REGISTRY.calendar_list_calendars?.inputSchema as {
      additionalProperties?: unknown;
      required?: string[];
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required).toEqual([]);
  });

  test("calendar_create_event requires calendar.events (full; readonly cannot insert); min_tier=write", () => {
    // Phase 2 ships within the v1.13 scope envelope from Phase 1a — no
    // re-consent needed for accounts already authorized for v1.13.
    expect(TOOL_REGISTRY.calendar_create_event?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/calendar.events",
    ]);
    expect(TOOL_REGISTRY.calendar_create_event?.min_tier).toBe("write");
  });

  test("calendar_create_event inputSchema has additionalProperties:false (unsupported fields rejected, NOT silent ignore)", () => {
    // sec-rev §7 hook #3 / design patch M-Sec-1: schema layer rejects
    // unknown top-level fields (eventType / recurrence / conferenceData /
    // attachments / etc.) BEFORE reaching the handler. additionalProperties
    // is a load-bearing security gate, not optional polish.
    const schema = TOOL_REGISTRY.calendar_create_event?.inputSchema as {
      additionalProperties?: unknown;
      required?: string[];
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required?.sort()).toEqual(["end", "start", "summary"]);
  });

  // v1.17 Phase 1 — Calendar mutation tier (3 tools, same scope as Phase 2).
  test("v1.17 Phase 1 — calendar_update_event requires calendar.events; min_tier=write; additionalProperties:false", () => {
    expect(TOOL_REGISTRY.calendar_update_event?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/calendar.events",
    ]);
    expect(TOOL_REGISTRY.calendar_update_event?.min_tier).toBe("write");
    const schema = TOOL_REGISTRY.calendar_update_event?.inputSchema as {
      additionalProperties?: unknown;
      required?: string[];
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required).toEqual(["event_id"]);
  });

  test("v1.17 Phase 1 — calendar_delete_event requires calendar.events; min_tier=write (NOT read; destructive op); additionalProperties:false", () => {
    // Design §10 Q4 LOCKED — delete is destructive (no Drive-style 30-day
    // trash recovery via API; web UI only). min_tier=write is the right
    // floor (asymmetry vs drive_unshare_file's read tier intentional).
    expect(TOOL_REGISTRY.calendar_delete_event?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/calendar.events",
    ]);
    expect(TOOL_REGISTRY.calendar_delete_event?.min_tier).toBe("write");
    const schema = TOOL_REGISTRY.calendar_delete_event?.inputSchema as {
      additionalProperties?: unknown;
      required?: string[];
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required).toEqual(["event_id"]);
  });

  test("v1.17 Phase 1 — calendar_respond requires calendar.events; min_tier=write; response enum closed-set", () => {
    expect(TOOL_REGISTRY.calendar_respond?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/calendar.events",
    ]);
    expect(TOOL_REGISTRY.calendar_respond?.min_tier).toBe("write");
    const schema = TOOL_REGISTRY.calendar_respond?.inputSchema as {
      additionalProperties?: unknown;
      required?: string[];
      properties?: { response?: { enum?: string[] } };
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required?.sort()).toEqual(["event_id", "response"]);
    expect(schema?.properties?.response?.enum?.sort()).toEqual([
      "accepted",
      "declined",
      "needsAction",
      "tentative",
    ]);
  });

  test("v1.17 Phase 1 — all 3 calendar mutation tools in IMPLEMENTED_TOOLS", () => {
    // Defense-in-depth: IMPLEMENTED_TOOLS gate is what makes tools/list
    // expose them. Missing entry = tool silently absent.
    const { IMPLEMENTED_TOOLS } = require("./registry");
    expect(IMPLEMENTED_TOOLS.has("calendar_update_event")).toBe(true);
    expect(IMPLEMENTED_TOOLS.has("calendar_delete_event")).toBe(true);
    expect(IMPLEMENTED_TOOLS.has("calendar_respond")).toBe(true);
  });

  test("docs_get_content requires documents.readonly (narrower; satisfied by `documents` via SCOPE_HIERARCHY)", () => {
    expect(TOOL_REGISTRY.docs_get_content?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/documents.readonly",
    ]);
    expect(TOOL_REGISTRY.docs_get_content?.min_tier).toBe("read");
  });

  test("docs_create requires documents (full) — readonly cannot create", () => {
    expect(TOOL_REGISTRY.docs_create?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/documents",
    ]);
    expect(TOOL_REGISTRY.docs_create?.min_tier).toBe("write");
  });

  test("docs_append_text requires documents (full) — readonly cannot write; no new scope vs Phase 1a", () => {
    // Phase 2 ships within the v1.12 scope envelope from Phase 1a — no
    // re-consent needed for accounts already authorized for v1.12.
    expect(TOOL_REGISTRY.docs_append_text?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/documents",
    ]);
    expect(TOOL_REGISTRY.docs_append_text?.min_tier).toBe("write");
  });

  test("drive_share_file requires drive (full) scope", () => {
    // Full Drive scope needed for permissions.create. See registry.ts
    // DRIVE constant comment for why drive.file was ruled out.
    expect(TOOL_REGISTRY.drive_share_file?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/drive",
    ]);
  });

  test("drive_unshare_file requires drive (full) scope", () => {
    // permissions.delete requires drive scope same as permissions.create.
    expect(TOOL_REGISTRY.drive_unshare_file?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/drive",
    ]);
  });

  test("gmail_list_labels requires gmail.labels only (narrower than gmail.readonly)", () => {
    // Google's labels.list endpoint accepts readonly OR labels OR modify.
    // We declare the narrowest matching scope as the authoritative
    // requirement (sec-rev PR-1 HIGH: registry is the source of truth).
    expect(TOOL_REGISTRY.gmail_list_labels?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/gmail.labels",
    ]);
  });

  test("gmail_create_label requires gmail.labels only (write op on label namespace, same scope as list)", () => {
    // labels.create accepts the same gmail.labels scope as labels.list, so
    // adding this tool does NOT widen the consent surface for users who
    // already authorized v1.1 (the scope union is unchanged). min_tier must
    // be "write" — creating a label is a write operation visible in the
    // user's Gmail UI.
    expect(TOOL_REGISTRY.gmail_create_label?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/gmail.labels",
    ]);
    expect(TOOL_REGISTRY.gmail_create_label?.min_tier).toBe("write");
  });

  test("gmail_modify_message requires gmail.modify only", () => {
    // messages.modify requires gmail.modify (or mail.google.com). Declare
    // the narrowest applicable scope. Distinct from gmail.labels (label
    // CRUD at account level) which is insufficient for per-message edits.
    expect(TOOL_REGISTRY.gmail_modify_message?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/gmail.modify",
    ]);
  });

  test("every tool has a non-empty description and an object inputSchema", () => {
    for (const [name, def] of Object.entries(TOOL_REGISTRY)) {
      expect(def.description.length, `${name} description`).toBeGreaterThan(0);
      expect(def.inputSchema, `${name} inputSchema`).toBeDefined();
      expect((def.inputSchema as { type?: string }).type).toBe("object");
    }
  });

  test("gmail_search requires gmail.readonly only", () => {
    expect(TOOL_REGISTRY.gmail_search?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/gmail.readonly",
    ]);
  });

  test("gmail_send requires gmail.send only (not readonly)", () => {
    expect(TOOL_REGISTRY.gmail_send?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/gmail.send",
    ]);
  });

  test("drive tools require drive.readonly", () => {
    expect(TOOL_REGISTRY.drive_search?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/drive.readonly",
    ]);
    expect(TOOL_REGISTRY.drive_get_file_content?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/drive.readonly",
    ]);
  });

  test("contacts_search requires contacts.readonly; min_tier=read", () => {
    expect(TOOL_REGISTRY.contacts_search?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/contacts.readonly",
    ]);
    expect(TOOL_REGISTRY.contacts_search?.min_tier).toBe("read");
  });

  test("contacts_lookup_email requires contacts.readonly; min_tier=read", () => {
    expect(TOOL_REGISTRY.contacts_lookup_email?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/contacts.readonly",
    ]);
    expect(TOOL_REGISTRY.contacts_lookup_email?.min_tier).toBe("read");
  });

  test("contacts_get requires contacts.readonly; min_tier=read", () => {
    expect(TOOL_REGISTRY.contacts_get?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/contacts.readonly",
    ]);
    expect(TOOL_REGISTRY.contacts_get?.min_tier).toBe("read");
  });

  test("v1.16 Phase 1b — youtube_subscriptions_all is cross-account with youtube.readonly + min_tier=read", () => {
    expect(TOOL_REGISTRY.youtube_subscriptions_all?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/youtube.readonly",
    ]);
    expect(TOOL_REGISTRY.youtube_subscriptions_all?.min_tier).toBe("read");
    expect(TOOL_REGISTRY.youtube_subscriptions_all?.cross_account).toBe(true);
  });

  test("v1.16 Phase 1b — youtube single-account tools require youtube.readonly + min_tier=read + NOT cross_account", () => {
    for (const name of [
      "youtube_channel_uploads",
      "youtube_video_get",
      "youtube_search",
      "youtube_video_comments_list",
    ] as const) {
      const def = TOOL_REGISTRY[name];
      expect(def, name).toBeDefined();
      expect(def?.requiredScopes, name).toEqual([
        "https://www.googleapis.com/auth/youtube.readonly",
      ]);
      expect(def?.min_tier, name).toBe("read");
      expect(def?.cross_account ?? false, `${name} not cross_account`).toBe(false);
    }
  });

  test("v1.16 Phase 1b — youtube tools have additionalProperties:false (anti-arg-smuggle)", () => {
    for (const name of [
      "youtube_subscriptions_all",
      "youtube_channel_uploads",
      "youtube_video_get",
      "youtube_search",
      "youtube_video_comments_list",
    ] as const) {
      const def = TOOL_REGISTRY[name];
      expect(def, name).toBeDefined();
      const schema = def?.inputSchema as { additionalProperties?: unknown };
      expect(schema?.additionalProperties, `${name} additionalProperties`).toBe(false);
    }
  });

  test("v1.16 Phase 1b sec-rev hook #4 — youtube_search description includes literal '100 units' quota warning (brittleness intentional per LOW-1)", () => {
    // Tool description MUST flag the 100-unit cost. Any rewording is a
    // sec-rev event (operator-visibility is load-bearing for §13 Risk 3
    // quota exhaustion). See docs/v1.16-youtube-api.md §11 hook #4.
    const desc = TOOL_REGISTRY.youtube_search?.description ?? "";
    expect(desc).toContain("100 units");
  });

  test("v1.16 Phase 1b sec-rev hook #7 — youtube_subscriptions_all description states privacy boundary (only OWN subscriptions)", () => {
    // Per docs/v1.16-youtube-api.md §11 hook #7: prevents caller misreading
    // the response as "subscriptions of arbitrary channels". The substring
    // anchors the privacy claim so a future rewording surfaces in tests.
    const desc = TOOL_REGISTRY.youtube_subscriptions_all?.description ?? "";
    expect(desc).toContain("ONLY your own subscriptions");
  });

  test("v1.16 Phase 2b — youtube comment-write tools require youtube.force-ssl + min_tier=write + NOT cross_account", () => {
    for (const name of [
      "youtube_video_comment_post",
      "youtube_comment_reply",
    ] as const) {
      const def = TOOL_REGISTRY[name];
      expect(def, name).toBeDefined();
      expect(def?.requiredScopes, name).toEqual([
        "https://www.googleapis.com/auth/youtube.force-ssl",
      ]);
      expect(def?.min_tier, name).toBe("write");
      expect(def?.cross_account ?? false, `${name} not cross_account`).toBe(false);
    }
  });

  test("v1.16 Phase 2b — comment-write tools have additionalProperties:false (anti-arg-smuggle)", () => {
    for (const name of [
      "youtube_video_comment_post",
      "youtube_comment_reply",
    ] as const) {
      const schema = TOOL_REGISTRY[name]?.inputSchema as {
        additionalProperties?: unknown;
      };
      expect(schema?.additionalProperties, `${name} additionalProperties`).toBe(
        false,
      );
    }
  });

  test("v1.16 Phase 2b — schemas pin video_id pattern + text length cap (10000)", () => {
    const post = TOOL_REGISTRY.youtube_video_comment_post?.inputSchema as {
      properties?: {
        video_id?: { pattern?: string };
        text?: { maxLength?: number; minLength?: number };
      };
      required?: string[];
    };
    expect(post?.properties?.video_id?.pattern).toBe("^[A-Za-z0-9_-]{11}$");
    expect(post?.properties?.text?.maxLength).toBe(10000);
    expect(post?.properties?.text?.minLength).toBe(1);
    expect(post?.required).toEqual(["video_id", "text"]);

    const reply = TOOL_REGISTRY.youtube_comment_reply?.inputSchema as {
      properties?: {
        parent_comment_id?: { pattern?: string };
        video_id?: { pattern?: string };
        text?: { maxLength?: number };
      };
      required?: string[];
    };
    expect(reply?.properties?.video_id?.pattern).toBe("^[A-Za-z0-9_-]{11}$");
    expect(reply?.properties?.parent_comment_id?.pattern).toBe(
      "^[A-Za-z0-9_.\\-]{1,256}$",
    );
    expect(reply?.properties?.text?.maxLength).toBe(10000);
    // TOCTOU lock: video_id REQUIRED on reply per design §4 + code-H4 patch.
    expect(reply?.required).toEqual(["parent_comment_id", "video_id", "text"]);
  });

  // v1.17 Phase 3 — youtube_comment_delete registry sentinels. Per design
  // §10 Q4 LOCKED: min_tier=write (NOT read like drive_unshare_file's
  // recovery-bias pattern). Per design §8 hook #10 + §2.5: registry asserts
  // write tier; per §8 hook #11: comment_id pattern matches the
  // YOUTUBE_COMMENT_ID_RE shared with youtube_comment_reply.parent_comment_id.
  test("v1.17 Phase 3 — youtube_comment_delete requires youtube.force-ssl + min_tier=write + NOT cross_account", () => {
    const def = TOOL_REGISTRY.youtube_comment_delete;
    expect(def).toBeDefined();
    expect(def?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/youtube.force-ssl",
    ]);
    // §10 Q4 LOCKED — write tier (NOT read); retires CLAUDE.md L218
    // carry-forward. Deletion is destructive + permanently irreversible.
    expect(def?.min_tier).toBe("write");
    expect(def?.cross_account ?? false).toBe(false);
  });

  test("v1.17 Phase 3 — youtube_comment_delete schema has additionalProperties:false + comment_id required + 256-char pattern", () => {
    const schema = TOOL_REGISTRY.youtube_comment_delete?.inputSchema as {
      additionalProperties?: unknown;
      properties?: { comment_id?: { pattern?: string } };
      required?: string[];
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required).toEqual(["comment_id"]);
    // §8 hook #11 — pattern matches v1.16 YOUTUBE_COMMENT_ID_RE shared
    // with youtube_comment_reply.parent_comment_id.
    expect(schema?.properties?.comment_id?.pattern).toBe(
      "^[A-Za-z0-9_.\\-]{1,256}$",
    );
  });

  test("v1.17 Phase 3 — youtube_comment_delete description flags IRREVERSIBLE + Recovery > Policy bypass + tier floor", () => {
    // Operator-visibility load-bearing — literal substring assertions
    // intentional. Any rewording is a sec-rev event (the destructive
    // semantics MUST be visible to the LLM agent reading tools/list).
    const desc = TOOL_REGISTRY.youtube_comment_delete?.description ?? "";
    expect(desc).toContain("PERMANENTLY IRREVERSIBLE");
    expect(desc).toContain("SKIPS");
    expect(desc).toContain("SAFESPACE_YOUTUBE_COMMENT_TARGETS");
    expect(desc).toContain("SAFESPACE_YOUTUBE_COMMENT_BURST_LIMIT");
    expect(desc).toContain("write");
  });

  test("v1.16 Phase 2b sec-rev hook #14/#15 — comment_post description carries PUBLIC + PERMANENT + spam acknowledgments", () => {
    // Sec-rev hooks #14 (anti-spam acknowledgment) + #15 (PUBLIC + PERMANENT
    // standing warnings) — literal substring assertions intentional: any
    // rewording is a sec-rev event (operator-visibility load-bearing).
    const desc = TOOL_REGISTRY.youtube_video_comment_post?.description ?? "";
    expect(desc).toContain("PUBLIC");
    expect(desc).toContain("PERMANENT");
    expect(desc).toContain("YouTube channel identity");
    expect(desc).toContain("shadow-ban");
    expect(desc).toContain("cannot be retracted programmatically");
  });

  // v1.49 B4 — destructive playlist slice (2 tools). Scope/tier/schema +
  // operator-visibility description sentinels.
  test("v1.49 — destructive playlist tools require youtube.force-ssl + min_tier=write + NOT cross_account", () => {
    for (const name of [
      "youtube_playlist_item_remove",
      "youtube_playlist_delete",
    ] as const) {
      const def = TOOL_REGISTRY[name];
      expect(def, name).toBeDefined();
      expect(def?.requiredScopes, name).toEqual([
        "https://www.googleapis.com/auth/youtube.force-ssl",
      ]);
      expect(def?.min_tier, name).toBe("write");
      expect(def?.cross_account ?? false, `${name} not cross_account`).toBe(false);
    }
  });

  test("v1.49 — destructive playlist schemas: additionalProperties:false + required + id patterns", () => {
    const remove = TOOL_REGISTRY.youtube_playlist_item_remove?.inputSchema as {
      additionalProperties?: unknown;
      properties?: {
        playlist_id?: { pattern?: string };
        playlist_item_id?: { pattern?: string };
      };
      required?: string[];
    };
    expect(remove?.additionalProperties).toBe(false);
    // Both ids REQUIRED — playlist_id is the forensic audit anchor (mirror
    // youtube_comment_reply requiring video_id) even though the SDK keys off
    // the item id only.
    expect(remove?.required?.sort()).toEqual(["playlist_id", "playlist_item_id"]);
    expect(remove?.properties?.playlist_id?.pattern).toBe(
      "^(?:PL|UU|LL|OL|FL|RD)[A-Za-z0-9_-]{1,64}$",
    );
    expect(remove?.properties?.playlist_item_id?.pattern).toBe(
      "^[A-Za-z0-9_.\\-]{1,128}$",
    );

    const del = TOOL_REGISTRY.youtube_playlist_delete?.inputSchema as {
      additionalProperties?: unknown;
      properties?: { playlist_id?: { pattern?: string } };
      required?: string[];
    };
    expect(del?.additionalProperties).toBe(false);
    expect(del?.required).toEqual(["playlist_id"]);
    expect(del?.properties?.playlist_id?.pattern).toBe(
      "^(?:PL|UU|LL|OL|FL|RD)[A-Za-z0-9_-]{1,64}$",
    );
  });

  test("v1.49 — youtube_playlist_delete description flags PERMANENT + recovery-bias + tier floor", () => {
    // Operator-visibility load-bearing — literal substrings intentional (any
    // rewording is a sec-rev event; the destructive semantics MUST reach the
    // LLM agent reading tools/list). Mirror youtube_comment_delete sentinels.
    const desc = TOOL_REGISTRY.youtube_playlist_delete?.description ?? "";
    expect(desc).toContain("PERMANENTLY IRREVERSIBLE");
    expect(desc).toContain("NO playlist trash");
    expect(desc).toContain("explicit confirmation");
    expect(desc).toContain("NO target allowlist");
    expect(desc).toContain("write");
  });

  test("v1.49 — youtube_playlist_item_remove description flags RECOVERABLE + not-counted", () => {
    const desc = TOOL_REGISTRY.youtube_playlist_item_remove?.description ?? "";
    expect(desc).toContain("RECOVERABLE");
    expect(desc).toContain("re-add");
    // Distinguishes the item-id from the video-id for the LLM caller.
    expect(desc).toContain("NOT the video id");
  });

  test("contacts tools have additionalProperties:false (anti-arg-smuggle) and required inputs", () => {
    // v1.15 sec-rev hook #9 — `etag` MUST NOT be required input on any read
    // tool. Verify by enumerating: NONE of the 3 contacts read tools accept
    // `etag` in their inputSchema.properties.
    for (const name of ["contacts_search", "contacts_lookup_email", "contacts_get"] as const) {
      const def = TOOL_REGISTRY[name];
      expect(def, name).toBeDefined();
      const schema = def?.inputSchema as {
        additionalProperties?: unknown;
        properties?: Record<string, unknown>;
        required?: string[];
      };
      expect(schema?.additionalProperties, `${name} additionalProperties`).toBe(false);
      expect(schema?.properties?.etag, `${name} etag not in properties`).toBeUndefined();
    }
    // Each tool requires its primary identifier input.
    const search = TOOL_REGISTRY.contacts_search?.inputSchema as { required?: string[] };
    expect(search?.required).toEqual(["query"]);
    const lookup = TOOL_REGISTRY.contacts_lookup_email?.inputSchema as { required?: string[] };
    expect(lookup?.required).toEqual(["name"]);
    const get = TOOL_REGISTRY.contacts_get?.inputSchema as { required?: string[] };
    expect(get?.required).toEqual(["resource_name"]);
  });
});

describe("v1.20 Phase 1b-1 — Sheets read tier (2 tools)", () => {
  test("sheets_get_values requires spreadsheets; min_tier=read; additionalProperties:false; spreadsheet_id+range required", () => {
    expect(TOOL_REGISTRY.sheets_get_values?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/spreadsheets",
    ]);
    expect(TOOL_REGISTRY.sheets_get_values?.min_tier).toBe("read");
    expect(TOOL_REGISTRY.sheets_get_values?.cross_account).toBeUndefined();
    const schema = TOOL_REGISTRY.sheets_get_values?.inputSchema as {
      additionalProperties?: unknown;
      required?: string[];
      properties?: { value_render_option?: { enum?: string[] } };
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required?.sort()).toEqual(["range", "spreadsheet_id"]);
    // sec-rev hook #4 + #20 — value_render_option closed-enum (FORMULA NOT listed)
    expect(schema?.properties?.value_render_option?.enum?.sort()).toEqual([
      "FORMATTED_VALUE",
      "UNFORMATTED_VALUE",
    ]);
  });

  test("sheets_get_values description includes -32028 + design §11 Q4 reference (sec-rev hook #20 acknowledgment)", () => {
    const desc = TOOL_REGISTRY.sheets_get_values?.description ?? "";
    expect(desc).toContain("-32028");
    expect(desc).toContain("design §11 Q4");
    expect(desc).toContain("FORMULA");
  });

  test("sheets_get_metadata requires spreadsheets; min_tier=read; additionalProperties:false; spreadsheet_id required", () => {
    expect(TOOL_REGISTRY.sheets_get_metadata?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/spreadsheets",
    ]);
    expect(TOOL_REGISTRY.sheets_get_metadata?.min_tier).toBe("read");
    expect(TOOL_REGISTRY.sheets_get_metadata?.cross_account).toBeUndefined();
    const schema = TOOL_REGISTRY.sheets_get_metadata?.inputSchema as {
      additionalProperties?: unknown;
      required?: string[];
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required?.sort()).toEqual(["spreadsheet_id"]);
  });

  test("sheets_get_metadata description acknowledges includeGridData HARD-LOCK (sec-rev hook #5)", () => {
    const desc = TOOL_REGISTRY.sheets_get_metadata?.description ?? "";
    expect(desc).toContain("includeGridData");
    expect(desc).toContain("HARD-LOCKED");
  });

  test("both Sheets read-tier tools in IMPLEMENTED_TOOLS", () => {
    expect(IMPLEMENTED_TOOLS.has("sheets_get_values")).toBe(true);
    expect(IMPLEMENTED_TOOLS.has("sheets_get_metadata")).toBe(true);
  });
});

describe("v1.20 Phase 1b-2 — Sheets write tier (2 tools)", () => {
  test("sheets_create requires spreadsheets; min_tier=write; additionalProperties:false; title required", () => {
    expect(TOOL_REGISTRY.sheets_create?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/spreadsheets",
    ]);
    expect(TOOL_REGISTRY.sheets_create?.min_tier).toBe("write");
    expect(TOOL_REGISTRY.sheets_create?.cross_account).toBeUndefined();
    const schema = TOOL_REGISTRY.sheets_create?.inputSchema as {
      additionalProperties?: unknown;
      required?: string[];
      properties?: {
        sheets?: { items?: { additionalProperties?: unknown } };
      };
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required?.sort()).toEqual(["title"]);
    // Nested sheets[i] schema also locks down — additionalProperties:false at
    // every level closes the formula-smuggle path at the schema layer.
    expect(schema?.properties?.sheets?.items?.additionalProperties).toBe(false);
  });

  test("sheets_create description acknowledges 30-field NEGATIVE sentinel + sheets[].data formula-smuggle defense (sec-rev hook #19) + 2-step audit pattern (design §5)", () => {
    const desc = TOOL_REGISTRY.sheets_create?.description ?? "";
    expect(desc).toContain("30-field NEGATIVE sentinel");
    expect(desc).toContain("Formula-smuggle DEFENDED");
    expect(desc).toContain("sheets[].data");
    expect(desc).toContain("2-step audit-before-SDK pattern");
    expect(desc).toContain("design §5");
    expect(desc).toContain("hook #19");
  });

  test("sheets_append_values requires spreadsheets; min_tier=write; additionalProperties:false; spreadsheet_id + range + values required", () => {
    expect(TOOL_REGISTRY.sheets_append_values?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/spreadsheets",
    ]);
    expect(TOOL_REGISTRY.sheets_append_values?.min_tier).toBe("write");
    expect(TOOL_REGISTRY.sheets_append_values?.cross_account).toBeUndefined();
    const schema = TOOL_REGISTRY.sheets_append_values?.inputSchema as {
      additionalProperties?: unknown;
      required?: string[];
      properties?: {
        insert_data_option?: { enum?: string[] };
      };
    };
    // *** sec-rev hook #23: additionalProperties:false rejects caller-supplied
    //     value_input_option at the schema gate BEFORE the handler runs ***
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required?.sort()).toEqual([
      "range",
      "spreadsheet_id",
      "values",
    ]);
    // insert_data_option closed-enum allowlist.
    expect(schema?.properties?.insert_data_option?.enum?.sort()).toEqual([
      "INSERT_ROWS",
      "OVERWRITE",
    ]);
    // No `value_input_option` / `valueInputOption` key — RAW HARD-LOCK is
    // handler-side (Q3 LOCKED). additionalProperties:false enforces this
    // at the schema gate (smuggling rejected pre-handler).
    expect(
      Object.keys(
        (schema?.properties ?? {}) as Record<string, unknown>,
      ).sort(),
    ).not.toContain("value_input_option");
    expect(
      Object.keys(
        (schema?.properties ?? {}) as Record<string, unknown>,
      ).sort(),
    ).not.toContain("valueInputOption");
  });

  test("sheets_append_values description acknowledges RAW HARD-LOCK (sec-rev hook #3 + Q3 LOCKED) + cell content caps (hook #16) + additionalProperties:false (hook #23)", () => {
    const desc = TOOL_REGISTRY.sheets_append_values?.description ?? "";
    expect(desc).toContain("RAW");
    expect(desc).toContain("HARD-LOCKED");
    expect(desc).toContain("hook #3");
    expect(desc).toContain("Q3 LOCKED");
    expect(desc).toContain("50KB");
    expect(desc).toContain("100KB");
    expect(desc).toContain("10000");
    expect(desc).toContain("hook #23");
    expect(desc).toContain("additionalProperties: false");
  });

  test("both Sheets write-tier tools in IMPLEMENTED_TOOLS", () => {
    expect(IMPLEMENTED_TOOLS.has("sheets_create")).toBe(true);
    expect(IMPLEMENTED_TOOLS.has("sheets_append_values")).toBe(true);
  });
});

describe("v1.21 Phase 1b — Sheets Phase 2c (sheets_update_values + sheets_batch_update)", () => {
  test("sheets_update_values requires spreadsheets; min_tier=write; additionalProperties:false", () => {
    expect(TOOL_REGISTRY.sheets_update_values?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/spreadsheets",
    ]);
    expect(TOOL_REGISTRY.sheets_update_values?.min_tier).toBe("write");
    expect(TOOL_REGISTRY.sheets_update_values?.cross_account).toBeUndefined();
    const schema = TOOL_REGISTRY.sheets_update_values?.inputSchema as {
      additionalProperties?: unknown;
      required?: string[];
      properties?: { value_input_option?: { enum?: string[] } };
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required?.sort()).toEqual([
      "range",
      "spreadsheet_id",
      "values",
    ]);
    // value_input_option closed-enum {RAW, USER_ENTERED}
    expect(schema?.properties?.value_input_option?.enum?.sort()).toEqual([
      "RAW",
      "USER_ENTERED",
    ]);
  });

  test("sheets_update_values description acknowledges value_input_option allowlist + formula REJECT + cell caps", () => {
    const desc = TOOL_REGISTRY.sheets_update_values?.description ?? "";
    expect(desc).toContain("RAW (default)");
    expect(desc).toContain("USER_ENTERED");
    expect(desc).toContain("REJECT list");
    expect(desc).toContain("IMPORTRANGE");
    expect(desc).toContain("LAMBDA");
    expect(desc).toContain("-32029");
    expect(desc).toContain("50KB");
    expect(desc).toContain("100KB");
    expect(desc).toContain("10000");
    expect(desc).toContain("Last-write-wins");
  });

  test("sheets_batch_update requires spreadsheets; min_tier=write; additionalProperties:false (top-level + nested requests[])", () => {
    expect(TOOL_REGISTRY.sheets_batch_update?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/spreadsheets",
    ]);
    expect(TOOL_REGISTRY.sheets_batch_update?.min_tier).toBe("write");
    expect(TOOL_REGISTRY.sheets_batch_update?.cross_account).toBeUndefined();
    const schema = TOOL_REGISTRY.sheets_batch_update?.inputSchema as {
      additionalProperties?: unknown;
      required?: string[];
      properties?: {
        requests?: {
          minItems?: number;
          maxItems?: number;
          items?: {
            additionalProperties?: unknown;
            maxProperties?: unknown;
            properties?: Record<string, unknown>;
          };
        };
      };
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required?.sort()).toEqual([
      "requests",
      "spreadsheet_id",
    ]);
    expect(schema?.properties?.requests?.minItems).toBe(1);
    expect(schema?.properties?.requests?.maxItems).toBe(50);
    // P5 hook #20 — requests[] items: additionalProperties:false + maxProperties:1
    expect(schema?.properties?.requests?.items?.additionalProperties).toBe(false);
    expect(schema?.properties?.requests?.items?.maxProperties).toBe(1);
    // Each ALLOWED type has additionalProperties:false
    const itemProps = schema?.properties?.requests?.items?.properties ?? {};
    for (const t of [
      "addSheet",
      "deleteSheet",
      "updateSheetProperties",
      "repeatCell",
      "updateCells",
      "mergeCells",
      "unmergeCells",
    ]) {
      const typeSchema = itemProps[t] as { additionalProperties?: unknown };
      expect(typeSchema?.additionalProperties).toBe(false);
    }
  });

  test("sheets_batch_update description acknowledges 7-type ALLOWLIST + ~47 NEGATIVE sentinel + updateSpreadsheetProperties HARD-REJECT + formula REJECT + FieldMask + cell caps + 50-request cap + includeSpreadsheetInResponse HARD-OMITTED + N4 BLOCKING", () => {
    const desc = TOOL_REGISTRY.sheets_batch_update?.description ?? "";
    // v1.22 Phase 2 NEW-2 — wording sync from "6-type" to "7-type". The
    // ALLOWLIST Set has 7 entries (addSheet / deleteSheet /
    // updateSheetProperties / repeatCell / updateCells / mergeCells /
    // unmergeCells); v1.21 mis-counted mergeCells + unmergeCells as one
    // entry in the description text. Sentinel locks the corrected count
    // against future drift — registry text "7-type" MUST match the actual
    // SHEETS_BATCH_UPDATE_ALLOWED_TYPES Set size in handlers.ts.
    expect(desc).toContain("7-type positive ALLOWLIST");
    expect(desc).toContain("addSheet");
    expect(desc).toContain("deleteSheet");
    expect(desc).toContain("updateSheetProperties");
    expect(desc).toContain("repeatCell");
    expect(desc).toContain("updateCells");
    expect(desc).toContain("mergeCells");
    expect(desc).toContain("unmergeCells");
    expect(desc).toContain("updateSpreadsheetProperties");
    expect(desc).toContain("HARD-REJECTED");
    expect(desc).toContain("importFunctionsExternalUrlAccessAllowed");
    expect(desc).toContain("hook #3");
    expect(desc).toContain("#16");
    expect(desc).toContain("hook #23");
    expect(desc).toContain("formulaValue");
    expect(desc).toContain("errorValue");
    expect(desc).toContain("HARD-REJECTED");
    expect(desc).toContain("FieldMask");
    expect(desc).toContain("hook #19");
    expect(desc).toContain("CLEAR-via-mask");
    expect(desc).toContain("50KB");
    expect(desc).toContain("100KB");
    expect(desc).toContain("10000");
    expect(desc).toContain("50-request cap");
    expect(desc).toContain("includeSpreadsheetInResponse");
    expect(desc).toContain("HARD-OMITTED");
    expect(desc).toContain("hook #15");
    expect(desc).toContain("Last-write-wins");
    // v1.22 Phase 2 NEW-2 sentinel — explicit anti-regression: stale
    // "6-type" wording MUST NOT reappear in the top-level description.
    expect(desc).not.toContain("6-type positive ALLOWLIST");
    expect(desc).not.toContain("6-type allowlist");

    // v1.22 Phase 2 NEW-2 sentinel — also lock the nested `requests`
    // inputSchema property description (the 2nd "X-type allowlist" site).
    const schema = TOOL_REGISTRY.sheets_batch_update?.inputSchema as {
      properties?: {
        requests?: { description?: string };
      };
    };
    const requestsDesc = schema.properties?.requests?.description ?? "";
    expect(requestsDesc).toContain("7-type allowlist");
    expect(requestsDesc).not.toContain("6-type allowlist");
  });

  test("both Sheets Phase 2c tools in IMPLEMENTED_TOOLS", () => {
    expect(IMPLEMENTED_TOOLS.has("sheets_update_values")).toBe(true);
    expect(IMPLEMENTED_TOOLS.has("sheets_batch_update")).toBe(true);
  });
});

describe("v1.46 B1 — Drive file-write (create / copy / rename)", () => {
  const DRIVE = "https://www.googleapis.com/auth/drive";

  test("all 3 tools: DRIVE scope, min_tier=write, additionalProperties:false, in IMPLEMENTED_TOOLS", () => {
    for (const tool of ["drive_create_file", "drive_copy_file", "drive_rename_file"]) {
      expect(TOOL_REGISTRY[tool]?.requiredScopes, `${tool} scope`).toEqual([DRIVE]);
      expect(TOOL_REGISTRY[tool]?.min_tier, `${tool} tier`).toBe("write");
      const schema = TOOL_REGISTRY[tool]?.inputSchema as { additionalProperties?: unknown };
      expect(schema?.additionalProperties, `${tool} additionalProperties`).toBe(false);
      expect(IMPLEMENTED_TOOLS.has(tool), `${tool} implemented`).toBe(true);
    }
  });

  test("drive_create_file requires name + content; declares content/mime_type/parent_id", () => {
    const schema = TOOL_REGISTRY.drive_create_file?.inputSchema as {
      required?: string[];
      properties?: Record<string, unknown>;
    };
    expect(schema?.required?.sort()).toEqual(["content", "name"]);
    expect(schema?.properties?.content).toBeDefined();
    expect(schema?.properties?.mime_type).toBeDefined();
    expect(schema?.properties?.parent_id).toBeDefined();
  });

  test("drive_copy_file + drive_rename_file require only file_id", () => {
    const copy = TOOL_REGISTRY.drive_copy_file?.inputSchema as { required?: string[] };
    const rename = TOOL_REGISTRY.drive_rename_file?.inputSchema as { required?: string[] };
    expect(copy?.required).toEqual(["file_id"]);
    expect(rename?.required).toEqual(["file_id"]);
  });
});

describe("IMPLEMENTED_TOOLS", () => {
  test("is exactly the TOOL_REGISTRY key set (v1.85 D7 — derived from TOOL_ORDER, not a 2nd hand-list)", () => {
    // IMPLEMENTED_TOOLS = new Set(TOOL_ORDER); TOOL_REGISTRY is built from TOOL_ORDER
    // too — so the exposed set is single-sourced. Adding a tool to TOOL_ORDER exposes
    // it; there is no separate IMPLEMENTED_TOOLS list to keep in sync. The canonical
    // tool-name spec lives in the "TOOL_REGISTRY declares all … tools" exhaustive
    // assertion + the size check below.
    expect([...IMPLEMENTED_TOOLS].sort()).toEqual(Object.keys(TOOL_REGISTRY).sort());
  });

  test("every IMPLEMENTED_TOOLS entry exists in TOOL_REGISTRY", () => {
    for (const name of IMPLEMENTED_TOOLS) {
      expect(TOOL_REGISTRY[name], `${name} in registry`).toBeDefined();
    }
  });
});

// v1.50 (backlog B5) — Contacts write tier (contacts_create / contacts_update).
// Full `contacts` scope, min_tier=write, additionalProperties:false.
describe("TOOL_REGISTRY — v1.50 Contacts write tier", () => {
  test("contacts_create requires full `contacts`; min_tier=write; additionalProperties:false; no required fields", () => {
    expect(TOOL_REGISTRY.contacts_create?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/contacts",
    ]);
    expect(TOOL_REGISTRY.contacts_create?.min_tier).toBe("write");
    const schema = TOOL_REGISTRY.contacts_create?.inputSchema as {
      additionalProperties?: unknown;
      required?: unknown;
      properties?: Record<string, unknown>;
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required).toEqual([]);
    // Allowlisted Person field groups are present as schema properties.
    expect(Object.keys(schema?.properties ?? {})).toEqual(
      expect.arrayContaining([
        "names",
        "emailAddresses",
        "phoneNumbers",
        "organizations",
        "addresses",
        "biographies",
        "urls",
        "userDefined",
        "birthdays",
        "account_id",
      ]),
    );
    // NEGATIVE: forbidden Person fields are NOT schema properties.
    for (const f of ["photos", "metadata", "externalIds", "relations", "imClients", "sipAddresses"]) {
      expect(schema?.properties).not.toHaveProperty(f);
    }
  });

  test("contacts_update requires full `contacts`; min_tier=write; additionalProperties:false; resource_name+etag required", () => {
    expect(TOOL_REGISTRY.contacts_update?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/contacts",
    ]);
    expect(TOOL_REGISTRY.contacts_update?.min_tier).toBe("write");
    const schema = TOOL_REGISTRY.contacts_update?.inputSchema as {
      additionalProperties?: unknown;
      required?: unknown;
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required).toEqual(["resource_name", "etag"]);
  });
});

// v1.51 (backlog B3) — Gmail filters (gmail_list_filters / gmail_create_filter
// / gmail_delete_filter). NEW gmail.settings.basic scope; read for list, write
// for create/delete; additionalProperties:false (incl. nested criteria/action).
describe("TOOL_REGISTRY — v1.51 Gmail filters", () => {
  test("gmail_list_filters requires gmail.settings.basic; min_tier=read; NOT cross_account", () => {
    expect(TOOL_REGISTRY.gmail_list_filters?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/gmail.settings.basic",
    ]);
    expect(TOOL_REGISTRY.gmail_list_filters?.min_tier).toBe("read");
    expect(TOOL_REGISTRY.gmail_list_filters?.cross_account ?? false).toBe(false);
  });

  test("gmail_create_filter requires gmail.settings.basic; min_tier=write; criteria+action required; additionalProperties:false (top + nested)", () => {
    expect(TOOL_REGISTRY.gmail_create_filter?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/gmail.settings.basic",
    ]);
    expect(TOOL_REGISTRY.gmail_create_filter?.min_tier).toBe("write");
    const schema = TOOL_REGISTRY.gmail_create_filter?.inputSchema as {
      additionalProperties?: unknown;
      required?: unknown;
      properties?: Record<string, { properties?: Record<string, unknown>; additionalProperties?: unknown }>;
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required).toEqual(["criteria", "action"]);
    // Nested objects also lock additionalProperties:false.
    expect(schema?.properties?.criteria?.additionalProperties).toBe(false);
    expect(schema?.properties?.action?.additionalProperties).toBe(false);
    // KEY safety: the action schema does NOT expose `forward`.
    expect(schema?.properties?.action?.properties).not.toHaveProperty("forward");
    expect(Object.keys(schema?.properties?.action?.properties ?? {})).toEqual(
      expect.arrayContaining(["addLabelIds", "removeLabelIds"]),
    );
    // Criteria exposes the 9 allowlisted match predicates.
    expect(Object.keys(schema?.properties?.criteria?.properties ?? {})).toEqual(
      expect.arrayContaining([
        "from",
        "to",
        "subject",
        "query",
        "negatedQuery",
        "hasAttachment",
        "excludeChats",
        "size",
        "sizeComparison",
      ]),
    );
  });

  test("gmail_delete_filter requires gmail.settings.basic; min_tier=write; id required; additionalProperties:false", () => {
    expect(TOOL_REGISTRY.gmail_delete_filter?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/gmail.settings.basic",
    ]);
    expect(TOOL_REGISTRY.gmail_delete_filter?.min_tier).toBe("write");
    const schema = TOOL_REGISTRY.gmail_delete_filter?.inputSchema as {
      additionalProperties?: unknown;
      required?: unknown;
    };
    expect(schema?.additionalProperties).toBe(false);
    expect(schema?.required).toEqual(["id"]);
  });

  test("all 3 filter tools in IMPLEMENTED_TOOLS", () => {
    expect(IMPLEMENTED_TOOLS.has("gmail_list_filters")).toBe(true);
    expect(IMPLEMENTED_TOOLS.has("gmail_create_filter")).toBe(true);
    expect(IMPLEMENTED_TOOLS.has("gmail_delete_filter")).toBe(true);
  });
});

// v1.62 — Forms read-only slice: forms_get (structure, forms.body.readonly) +
// forms_list_responses / forms_get_response (responses, forms.responses.readonly).
// All read-tier, NOT cross_account; the two scopes are distinct (structure vs
// responses) per design §2.
describe("Forms read-only tools (v1.62)", () => {
  test("forms_get requires forms.body.readonly; min_tier=read; form_id required; additionalProperties:false", () => {
    expect(TOOL_REGISTRY.forms_get?.requiredScopes).toEqual([
      "https://www.googleapis.com/auth/forms.body.readonly",
    ]);
    expect(TOOL_REGISTRY.forms_get?.min_tier).toBe("read");
    expect(TOOL_REGISTRY.forms_get?.cross_account).toBeFalsy();
    const schema = TOOL_REGISTRY.forms_get?.inputSchema as {
      required?: string[];
      additionalProperties?: boolean;
    };
    expect(schema.required).toEqual(["form_id"]);
    expect(schema.additionalProperties).toBe(false);
  });

  test("forms_list_responses + forms_get_response require forms.responses.readonly; min_tier=read", () => {
    for (const t of ["forms_list_responses", "forms_get_response"] as const) {
      expect(TOOL_REGISTRY[t]?.requiredScopes).toEqual([
        "https://www.googleapis.com/auth/forms.responses.readonly",
      ]);
      expect(TOOL_REGISTRY[t]?.min_tier).toBe("read");
      expect(TOOL_REGISTRY[t]?.cross_account).toBeFalsy();
    }
  });

  test("all 3 Forms read tools in IMPLEMENTED_TOOLS", () => {
    expect(IMPLEMENTED_TOOLS.has("forms_get")).toBe(true);
    expect(IMPLEMENTED_TOOLS.has("forms_list_responses")).toBe(true);
    expect(IMPLEMENTED_TOOLS.has("forms_get_response")).toBe(true);
  });
});

// v1.63 — Forms write slice: forms_create (forms.create) + forms_modify
// (forms.batchUpdate). Both require the full forms.body scope, min_tier=write,
// NOT cross_account. See docs/v1.63-forms-write.md.
describe("Forms write tools (v1.63)", () => {
  test("forms_create + forms_modify require forms.body; min_tier=write; not cross_account", () => {
    for (const t of ["forms_create", "forms_modify"] as const) {
      expect(TOOL_REGISTRY[t]?.requiredScopes).toEqual([
        "https://www.googleapis.com/auth/forms.body",
      ]);
      expect(TOOL_REGISTRY[t]?.min_tier).toBe("write");
      expect(TOOL_REGISTRY[t]?.cross_account).toBeFalsy();
    }
  });

  test("forms_create requires title; forms_modify requires form_id+requests; additionalProperties:false", () => {
    const createSchema = TOOL_REGISTRY.forms_create?.inputSchema as {
      required?: string[];
      additionalProperties?: boolean;
    };
    expect(createSchema.required).toEqual(["title"]);
    expect(createSchema.additionalProperties).toBe(false);
    const modifySchema = TOOL_REGISTRY.forms_modify?.inputSchema as {
      required?: string[];
      additionalProperties?: boolean;
    };
    expect(modifySchema.required).toEqual(["form_id", "requests"]);
    expect(modifySchema.additionalProperties).toBe(false);
  });

  test("both Forms write tools in IMPLEMENTED_TOOLS", () => {
    expect(IMPLEMENTED_TOOLS.has("forms_create")).toBe(true);
    expect(IMPLEMENTED_TOOLS.has("forms_modify")).toBe(true);
  });
});

describe("computeScopeUnion", () => {
  test("returns deduplicated sorted union of all required scopes (v1.51: + gmail.settings.basic for the filter tools)", () => {
    expect(computeScopeUnion()).toEqual([
      "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
      "https://www.googleapis.com/auth/calendar.events",
      "https://www.googleapis.com/auth/calendar.events.readonly",
      "https://www.googleapis.com/auth/calendar.freebusy",
      "https://www.googleapis.com/auth/contacts",
      "https://www.googleapis.com/auth/contacts.readonly",
      "https://www.googleapis.com/auth/documents",
      "https://www.googleapis.com/auth/documents.readonly",
      "https://www.googleapis.com/auth/drive",
      "https://www.googleapis.com/auth/drive.readonly",
      "https://www.googleapis.com/auth/forms.body",
      "https://www.googleapis.com/auth/forms.body.readonly",
      "https://www.googleapis.com/auth/forms.responses.readonly",
      "https://www.googleapis.com/auth/gmail.labels",
      "https://www.googleapis.com/auth/gmail.modify",
      "https://www.googleapis.com/auth/gmail.readonly",
      "https://www.googleapis.com/auth/gmail.send",
      "https://www.googleapis.com/auth/gmail.settings.basic",
      "https://www.googleapis.com/auth/presentations",
      "https://www.googleapis.com/auth/spreadsheets",
      "https://www.googleapis.com/auth/tasks",
      "https://www.googleapis.com/auth/youtube.force-ssl",
      "https://www.googleapis.com/auth/youtube.readonly",
      "https://www.googleapis.com/auth/yt-analytics.readonly",
    ]);
  });
});

// v1.64 Phase B (B0 relabel) — the optional ToolDef.direction label. Only
// gmail_send + gmail_create_draft (the outbound egress surface — a draft is a
// latent send) carry "outbound-write"; every other tool leaves it unset. B3
// keys the centralized egress gate off this; until then it is only a label.
describe("v1.64 Phase B (B0) — ToolDef.direction outbound-write labels", () => {
  test("EXACTLY gmail_send + gmail_create_draft + line_push_message are direction:'outbound-write'", () => {
    const outbound = Object.entries(TOOL_REGISTRY)
      .filter(([, def]) => def.direction === "outbound-write")
      .map(([name]) => name)
      .sort();
    // v1.66 Phase C PR 2 — line_push_message joins the egress surface.
    // v1.68 — telegram_send_message joins the egress surface.
    // v1.69 — discord_send_message joins the egress surface.
    // v1.71 — the 3 GitHub WRITE tools join the egress surface (public-surface).
    // v1.81 — github_create_pull_request joins the egress surface.
    // v1.82 — github_merge_pull_request joins the egress surface.
    // v1.84 — github_set_issue_labels joins the egress surface.
    // v1.90 — github_create_pull_request_review joins the egress surface.
    // v1.95 — slack_send_message joins the egress surface.
    // v1.96 — the 3 Notion WRITE tools join the egress surface.
    // v1.107 — mattermost_send_message joins the egress surface.
    expect(outbound).toEqual([
      "discord_send_message",
      "github_create_issue",
      "github_create_issue_comment",
      "github_create_pull_request",
      "github_create_pull_request_review",
      "github_merge_pull_request",
      "github_set_issue_labels",
      "github_update_issue",
      "gmail_create_draft",
      "gmail_send",
      "line_push_message",
      "mattermost_send_message",
      "notion_append_blocks",
      "notion_create_page",
      "notion_update_page",
      "slack_send_message",
      "telegram_send_message",
    ]);
  });

  test("a representative read tool leaves direction unset (no egress gate)", () => {
    expect(TOOL_REGISTRY.gmail_search?.direction).toBeUndefined();
    expect(TOOL_REGISTRY.drive_search?.direction).toBeUndefined();
  });

  test("no tool declares the invalid-but-typeable empty/other direction", () => {
    for (const [name, def] of Object.entries(TOOL_REGISTRY)) {
      if (def.direction !== undefined) {
        expect(`${name}:${def.direction}`).toMatch(/:(inbound-read|outbound-write)$/);
      }
    }
  });
});

describe("v1.66 Phase C PR 2 — line_push_message (LINE service-token connector)", () => {
  test("line_push_message is in IMPLEMENTED_TOOLS", () => {
    expect(IMPLEMENTED_TOOLS.has("line_push_message")).toBe(true);
  });

  test("ToolDef: source 'line', direction outbound-write, min_tier share, no OAuth scope", () => {
    const def = TOOL_REGISTRY.line_push_message!;
    expect(def.source).toBe("line");
    expect(def.direction).toBe("outbound-write");
    expect(def.min_tier).toBe("share");
    expect(def.requiredScopes).toEqual([]); // service-token, no OAuth scope
    expect(def.inputSchema.required).toEqual(["to", "text"]);
    expect(def.inputSchema.additionalProperties).toBe(false);
  });

  test("line_push_message adds NO scope to the consent union (service-token)", () => {
    // The connector authenticates with a channel token, not OAuth — it must not
    // widen the Google consent scope set.
    const union = computeScopeUnion();
    expect(union.some((s) => s.includes("line"))).toBe(false);
  });

});

describe("v1.68 — telegram_send_message (Telegram service-token connector)", () => {
  test("telegram_send_message is in IMPLEMENTED_TOOLS", () => {
    expect(IMPLEMENTED_TOOLS.has("telegram_send_message")).toBe(true);
  });

  test("ToolDef: source 'telegram', direction outbound-write, min_tier share, no OAuth scope", () => {
    const def = TOOL_REGISTRY.telegram_send_message!;
    expect(def.source).toBe("telegram");
    expect(def.direction).toBe("outbound-write");
    expect(def.min_tier).toBe("share");
    expect(def.requiredScopes).toEqual([]); // service-token, no OAuth scope
    expect(def.inputSchema.required).toEqual(["chat_id", "text"]);
    expect(def.inputSchema.additionalProperties).toBe(false);
  });

  test("telegram_send_message adds NO scope to the consent union (service-token)", () => {
    // The connector authenticates with a bot token, not OAuth — it must not widen
    // the Google consent scope set.
    const union = computeScopeUnion();
    expect(union.some((s) => s.includes("telegram"))).toBe(false);
  });

});

describe("v1.69 — discord_send_message (Discord service-token connector)", () => {
  test("discord_send_message is in IMPLEMENTED_TOOLS", () => {
    expect(IMPLEMENTED_TOOLS.has("discord_send_message")).toBe(true);
  });

  test("ToolDef: source 'discord', direction outbound-write, min_tier share, no OAuth scope", () => {
    const def = TOOL_REGISTRY.discord_send_message!;
    expect(def.source).toBe("discord");
    expect(def.direction).toBe("outbound-write");
    expect(def.min_tier).toBe("share");
    expect(def.requiredScopes).toEqual([]); // service-token, no OAuth scope
    expect(def.inputSchema.required).toEqual(["channel_id", "content"]);
    expect(def.inputSchema.additionalProperties).toBe(false);
  });

  test("discord_send_message adds NO scope to the consent union (service-token)", () => {
    const union = computeScopeUnion();
    expect(union.some((s) => s.includes("discord"))).toBe(false);
  });
});

describe("v1.95 — slack_send_message (Slack service-token connector)", () => {
  test("slack_send_message is in IMPLEMENTED_TOOLS", () => {
    expect(IMPLEMENTED_TOOLS.has("slack_send_message")).toBe(true);
  });

  test("ToolDef: source 'slack', direction outbound-write, min_tier share, no OAuth scope", () => {
    const def = TOOL_REGISTRY.slack_send_message!;
    expect(def.source).toBe("slack");
    expect(def.direction).toBe("outbound-write");
    expect(def.min_tier).toBe("share");
    expect(def.requiredScopes).toEqual([]); // service-token, no OAuth scope
    expect(def.inputSchema.required).toEqual(["channel", "text"]);
    expect(def.inputSchema.additionalProperties).toBe(false);
  });

  test("slack_send_message adds NO scope to the consent union (service-token)", () => {
    const union = computeScopeUnion();
    expect(union.some((s) => s.includes("slack"))).toBe(false);
  });
});

describe("v1.97 — Slack READ tools (the first service-token READ)", () => {
  for (const name of ["slack_list_channels", "slack_read_messages", "slack_users_list", "slack_user_info"]) {
    test(`${name}: source 'slack', direction inbound-read, min_tier read, no OAuth scope`, () => {
      const def = TOOL_REGISTRY[name]!;
      expect(IMPLEMENTED_TOOLS.has(name)).toBe(true);
      expect(def.source).toBe("slack");
      expect(def.direction).toBe("inbound-read");
      expect(def.min_tier).toBe("read");
      expect(def.requiredScopes).toEqual([]); // service-token, no OAuth scope
      expect(def.inputSchema.additionalProperties).toBe(false);
    });
  }

  test("slack_read_messages requires `channel`; slack_list_channels has no required args", () => {
    expect(TOOL_REGISTRY.slack_read_messages!.inputSchema.required).toEqual(["channel"]);
    expect(TOOL_REGISTRY.slack_list_channels!.inputSchema.required).toBeUndefined();
  });

  test("v1.104 — slack_user_info requires `user`; slack_users_list has no required args", () => {
    expect(TOOL_REGISTRY.slack_user_info!.inputSchema.required).toEqual(["user"]);
    expect(TOOL_REGISTRY.slack_users_list!.inputSchema.required).toBeUndefined();
  });

  test("127 implemented tools (v1.104 +2 Slack users.*; v1.106 +1 youtube_video_update; v1.107 +4 Mattermost)", () => {
    expect(IMPLEMENTED_TOOLS.size).toBe(127);
  });
});

describe("v1.98 — Telegram READ (the inbound poll-inbox; 2nd service-token READ)", () => {
  test("telegram_get_updates: source 'telegram', direction inbound-read, min_tier read, no OAuth scope", () => {
    const def = TOOL_REGISTRY.telegram_get_updates!;
    expect(IMPLEMENTED_TOOLS.has("telegram_get_updates")).toBe(true);
    expect(def.source).toBe("telegram");
    expect(def.direction).toBe("inbound-read");
    expect(def.min_tier).toBe("read");
    expect(def.requiredScopes).toEqual([]); // service-token, no OAuth scope
    expect(def.inputSchema.additionalProperties).toBe(false);
  });

  test("telegram_get_updates has no required args (offset + limit both optional)", () => {
    expect(TOOL_REGISTRY.telegram_get_updates!.inputSchema.required).toBeUndefined();
  });

  test("slack_read_messages gained an optional `oldest` ts filter (still only `channel` required)", () => {
    const props = TOOL_REGISTRY.slack_read_messages!.inputSchema.properties as Record<string, unknown>;
    expect(props.oldest).toBeDefined();
    expect(TOOL_REGISTRY.slack_read_messages!.inputSchema.required).toEqual(["channel"]);
  });
});

describe("v1.96 — Notion WRITE tools (text-only, egress-gated)", () => {
  for (const name of ["notion_create_page", "notion_append_blocks", "notion_update_page"]) {
    test(`${name}: source 'notion', direction outbound-write, min_tier write, no OAuth scope`, () => {
      const def = TOOL_REGISTRY[name]!;
      expect(IMPLEMENTED_TOOLS.has(name)).toBe(true);
      expect(def.source).toBe("notion");
      expect(def.direction).toBe("outbound-write");
      expect(def.min_tier).toBe("write");
      expect(def.requiredScopes).toEqual([]); // Notion OAuth has no scope param
      expect(def.inputSchema.additionalProperties).toBe(false);
    });
  }

  test("Notion WRITE adds NO scope to the consent union (no Notion scope param)", () => {
    const union = computeScopeUnion();
    expect(union.some((s) => s.includes("notion"))).toBe(false);
  });
});

describe("v1.77/v1.78 — Notion read tools (the 3rd OAuth source as of v1.78)", () => {
  const NOTION_TOOLS = [
    "notion_search",
    "notion_get_page",
    "notion_get_block_children",
    "notion_query_database",
    "notion_get_database",
  ] as const;

  test("all 5 notion tools are registered + implemented", () => {
    for (const t of NOTION_TOOLS) {
      expect(TOOL_REGISTRY[t]).toBeDefined();
      expect(IMPLEMENTED_TOOLS.has(t)).toBe(true);
    }
  });

  test("each is source:notion, min_tier:read, inbound-read, requiredScopes empty", () => {
    for (const t of NOTION_TOOLS) {
      const def = TOOL_REGISTRY[t]!;
      expect(def.source).toBe("notion");
      expect(def.min_tier).toBe("read");
      expect(def.direction).toBe("inbound-read");
      expect(def.requiredScopes).toEqual([]);
      expect(def.cross_account).toBeUndefined();
    }
  });

  test("notion adds NO scope to the google consent union (Notion OAuth has no scope param)", () => {
    const union = computeScopeUnion();
    expect(union.some((s) => s.includes("notion"))).toBe(false);
  });

  test("v1.79 — every notion tool declares an `account_id` param (multi-workspace targeting)", () => {
    for (const t of NOTION_TOOLS) {
      const props = (TOOL_REGISTRY[t]!.inputSchema as { properties: Record<string, unknown> }).properties;
      expect(props.account_id).toBeDefined();
    }
  });
});

describe("v1.70 (G4) — GitHub read tools (the 2nd OAuth source)", () => {
  const GITHUB_TOOLS = [
    "github_list_repos",
    "github_list_issues",
    "github_get_issue",
    "github_get_pull_request",
    "github_list_issue_comments",
  ] as const;

  test("all 5 github tools are registered + implemented", () => {
    for (const t of GITHUB_TOOLS) {
      expect(TOOL_REGISTRY[t]).toBeDefined();
      expect(IMPLEMENTED_TOOLS.has(t)).toBe(true);
    }
  });

  test("each github tool is source:github, min_tier:read, requiredScopes empty", () => {
    for (const t of GITHUB_TOOLS) {
      const def = TOOL_REGISTRY[t]!;
      expect(def.source).toBe("github");
      expect(def.min_tier).toBe("read");
      // GitHub OAuth scopes are flat + enforced at consent / by GitHub — they must
      // NOT leak into the google V1_SCOPES consent union.
      expect(def.requiredScopes).toEqual([]);
      expect(def.direction).toBe("inbound-read");
      expect(def.cross_account).toBeUndefined();
    }
  });

  test("github tools add NO scope to the consent union (flat scopes live at consent)", () => {
    const union = computeScopeUnion();
    expect(union.some((s) => s.includes("read:user") || s.includes("public_repo"))).toBe(false);
  });
});

describe("v1.76 — GitHub READ-deepening tools", () => {
  const READ_DEEPEN_TOOLS = [
    "github_get_repo",
    "github_list_pull_requests",
    "github_list_pull_request_files",
    "github_list_commits",
    "github_get_commit",
    "github_get_file_content",
  ] as const;

  test("all 6 read-deepening tools are registered + implemented", () => {
    for (const t of READ_DEEPEN_TOOLS) {
      expect(TOOL_REGISTRY[t]).toBeDefined();
      expect(IMPLEMENTED_TOOLS.has(t)).toBe(true);
    }
  });

  test("each is source:github, min_tier:read, inbound-read, requiredScopes empty", () => {
    for (const t of READ_DEEPEN_TOOLS) {
      const def = TOOL_REGISTRY[t]!;
      expect(def.source).toBe("github");
      expect(def.min_tier).toBe("read");
      expect(def.direction).toBe("inbound-read");
      expect(def.requiredScopes).toEqual([]);
      expect(def.cross_account).toBeUndefined();
    }
  });

  test("read-deepening adds NO scope to the consent union (ZERO new scope)", () => {
    const union = computeScopeUnion();
    expect(union.some((s) => s.includes("read:user") || s.includes("public_repo") || s.includes("repo"))).toBe(false);
  });
});

describe("v1.66.1 (B6.1a) — R10 sentinel: cross_account tools stay read-tier", () => {
  // R10 (thesis §10): the `_all` cross-account fan-out (`withAllAccounts`) is a
  // SEPARATE choke point NOT yet unified onto the shared pipeline (B6.1 defers that).
  // It runs the F1/F4 gates surgically, but a `*_all` WRITE / outbound tool would be
  // the first exercise of an un-unified, un-egress-gated path. Today "no `*_all`
  // write" is convention; this sentinel makes it CI-ENFORCED — any cross_account tool
  // that is not read-tier (or is outbound-write) fails the build, forcing the B6.1
  // unification conversation BEFORE such a tool can merge.
  test("every cross_account tool is min_tier:'read' and not an outbound direction", () => {
    // Future-proof: reject min_tier other than "read" OR any direction that is not
    // "inbound-read" (catches the current "outbound-write" AND any future outbound
    // direction variant — not just the one literal), so a new outbound `_all` tool
    // can't slip past this gate by using a new direction string.
    const offenders = Object.entries(TOOL_REGISTRY)
      .filter(([, def]) => def.cross_account)
      .filter(
        ([, def]) =>
          def.min_tier !== "read" ||
          (def.direction !== undefined && def.direction !== "inbound-read"),
      )
      .map(([name, def]) => `${name}(min_tier=${def.min_tier},direction=${def.direction ?? "—"})`);
    expect(offenders).toEqual([]);
  });

  test("there ARE cross_account tools (the sentinel is live, not vacuous)", () => {
    const crossAccount = Object.values(TOOL_REGISTRY).filter((def) => def.cross_account);
    expect(crossAccount.length).toBeGreaterThan(0);
  });
});
