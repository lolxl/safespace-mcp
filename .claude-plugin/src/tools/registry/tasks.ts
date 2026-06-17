// Tasks tool definitions — extracted verbatim from the former
// monolithic src/tools/registry.ts TOOL_REGISTRY (mechanical per-API split).
// Assembled in original key order by ./index.ts.

import type { ToolDef } from "./types";
import * as handlers from "../handlers";
import {
  TASKS,
} from "./scopes";

export const tasksTools: Record<string, ToolDef> = {
  tasks_lists: {
    name: "tasks_lists",
    description:
      "List the calling account's Google Tasks task lists (READ OPERATION). Returns {items: TaskList[]} — each TaskList has {id, title, updated, kind: 'tasks#taskList'}. Use this BEFORE `tasks_list` / `tasks_get` / (Phase 2b) `tasks_create` to enumerate available tasklist_ids; the `id` field is the value to pass as `tasklist_id`. Tasks API has no list-of-lists pagination in practice (typical accounts have <10 task lists). Title and other user-typed fields are sanitize-wrapped per the standard <untrusted-source> pipeline; opaque Google keys (id, etag, kind, selfLink) pass through unwrapped.",
    inputSchema: {
      type: "object",
      properties: {
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: [],
      additionalProperties: false,
    },
    requiredScopes: [TASKS],
    handler: handlers.tasksLists,
    min_tier: "read",
  },
  tasks_list: {
    name: "tasks_list",
    description:
      "List tasks within a specific Google Tasks task list (READ OPERATION). Returns {items: Task[], nextPageToken?}. Each Task has user-typed fields (title, notes, due) sanitize-wrapped per the standard <untrusted-source> pipeline; Google opaque keys (id, etag, selfLink, position) pass through unwrapped. The tasklist_id MUST match /^[A-Za-z0-9_-]{1,128}$/ (handler-side validation BEFORE any SDK call — rejects path traversal, CRLF injection, malformed input). Default max_results=50; hard cap at 100 (Google's natural ceiling). show_completed defaults to false (completed tasks are usually clutter; opt-in to surface them). Hidden tasks are NEVER returned (handler hard-codes showHidden=false — Google internal UI state is not surfaced).",
    inputSchema: {
      type: "object",
      properties: {
        tasklist_id: {
          type: "string",
          description:
            "Tasks API task list identifier (e.g., 'MTk5MTI4MTk2OTI2MTY...' or '@default' for the user's default list). Must match /^[A-Za-z0-9_-]{1,128}$/ — obtained from `tasks_lists` response.",
        },
        max_results: {
          type: "integer",
          minimum: 1,
          maximum: 100,
          default: 50,
          description:
            "Maximum number of tasks to return (default 50, handler-side cap at 100 — matches Google's natural ceiling).",
        },
        show_completed: {
          type: "boolean",
          default: false,
          description:
            "When true, completed tasks are included in the result. Default false (completed tasks usually clutter; opt-in). Mirrors the Google web-UI default.",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["tasklist_id"],
      additionalProperties: false,
    },
    requiredScopes: [TASKS],
    handler: handlers.tasksList,
    min_tier: "read",
  },
  tasks_get: {
    name: "tasks_get",
    description:
      "Get a single Google Tasks Task resource by tasklist_id + task_id (READ OPERATION). Returns the raw Task resource verbatim from Tasks API `tasks.get`. Use this after `tasks_list` to fetch full detail (notes, due date, links, etc.) for a specific task. Both `tasklist_id` and `task_id` MUST match /^[A-Za-z0-9_-]{1,128}$/ (handler-side validation BEFORE any SDK call — rejects path traversal, CRLF injection, malformed input). User-typed fields (title, notes, due) are sanitize-wrapped per the standard <untrusted-source> pipeline; opaque keys (id, etag, selfLink, position) and closed enums pass through unwrapped.",
    inputSchema: {
      type: "object",
      properties: {
        tasklist_id: {
          type: "string",
          description:
            "Tasks API task list identifier. Must match /^[A-Za-z0-9_-]{1,128}$/ — obtained from `tasks_lists` response.",
        },
        task_id: {
          type: "string",
          description:
            "Tasks API task identifier. Must match /^[A-Za-z0-9_-]{1,128}$/ — obtained from `tasks_list` response.",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["tasklist_id", "task_id"],
      additionalProperties: false,
    },
    requiredScopes: [TASKS],
    handler: handlers.tasksGet,
    min_tier: "read",
  },
  tasks_create: {
    name: "tasks_create",
    description:
      "Create a new task in a Google Tasks task list (WRITE OPERATION). ALWAYS ask the user for explicit confirmation before calling this tool. Requires SAFESPACE_TIER=write (or share). Returns the created Task resource. 4-key positive ALLOWLIST: only `title` (required) / `notes` / `due` / `status` are accepted; ALL OTHER fields (id, etag, kind, selfLink, position, updated, completed, deleted, hidden, links, webViewLink, parent, previous, taskListId, assignmentInfo) are REJECTED at the handler boundary (15-field NEGATIVE sentinel). Subtask hierarchy (`parent`) and manual positioning (`previous`) deferred to Phase 4+. `due` MUST be RFC 3339 datetime (e.g., 2026-05-25T10:00:00Z; max 32 chars). `status` MUST be one of {needsAction, completed} (case-sensitive). Audit gains target_tasklist_hash + operation='create' + policy_decision.",
    inputSchema: {
      type: "object",
      properties: {
        tasklist_id: {
          type: "string",
          description:
            "Tasks API task list identifier. Must match /^[A-Za-z0-9_-]{1,128}$/ — obtained from `tasks_lists` response.",
        },
        title: {
          type: "string",
          minLength: 1,
          maxLength: 1024,
          description:
            "Task title (REQUIRED). Non-empty after trim; ≤1024 bytes UTF-8.",
        },
        notes: {
          type: "string",
          maxLength: 8192,
          description: "Optional task notes / description. ≤8192 bytes UTF-8.",
        },
        due: {
          type: "string",
          maxLength: 32,
          description:
            "Optional RFC 3339 datetime (e.g., 2026-05-25T10:00:00Z). Strict-parsed pre-SDK; malformed values rejected without echo.",
        },
        status: {
          type: "string",
          enum: ["needsAction", "completed"],
          description:
            "Optional task status — one of {needsAction, completed} (case-sensitive). Defaults to 'needsAction' on Google's side.",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["tasklist_id", "title"],
      additionalProperties: false,
    },
    requiredScopes: [TASKS],
    handler: handlers.tasksCreate,
    min_tier: "write",
  },
  tasks_update: {
    name: "tasks_update",
    description:
      "Partial-update an existing Google Tasks task via tasks.patch (WRITE OPERATION; omitted keys preserved by Google). ALWAYS ask the user for explicit confirmation before calling this tool. Requires SAFESPACE_TIER=write (or share). Same 4-key positive ALLOWLIST as tasks_create (`title` / `notes` / `due` / `status` — all optional patch keys); same 15-field NEGATIVE sentinel. At LEAST ONE allowlisted field MUST be supplied. Status transitions in both directions allowed (`needsAction ↔ completed`); Google auto-handles completed-timestamp clearing on un-complete. CONCURRENCY: last-write-wins. Google Tasks API does NOT support `If-Match` optimistic concurrency (verified against the Tasks v1 Discovery doc — `tasks.tasks.patch` declares no conditional-request metadata; contrast with Calendar `events.patch` which is fully documented for `If-Match`). This is a Google API contract limitation, not a SafeSpace TODO. Audit gains target_tasklist_hash + target_task_hash + operation='update' + policy_decision.",
    inputSchema: {
      type: "object",
      properties: {
        tasklist_id: {
          type: "string",
          description:
            "Tasks API task list identifier. Must match /^[A-Za-z0-9_-]{1,128}$/.",
        },
        task_id: {
          type: "string",
          description:
            "Tasks API task identifier. Must match /^[A-Za-z0-9_-]{1,128}$/.",
        },
        title: {
          type: "string",
          minLength: 1,
          maxLength: 1024,
          description:
            "Optional new task title. Non-empty after trim if supplied; ≤1024 bytes UTF-8.",
        },
        notes: {
          type: "string",
          maxLength: 8192,
          description:
            "Optional new task notes. Empty string permitted (clears notes).",
        },
        due: {
          type: "string",
          maxLength: 32,
          description:
            "Optional new RFC 3339 datetime (e.g., 2026-05-25T10:00:00Z). Strict-parsed pre-SDK.",
        },
        status: {
          type: "string",
          enum: ["needsAction", "completed"],
          description:
            "Optional new task status — one of {needsAction, completed} (case-sensitive).",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["tasklist_id", "task_id"],
      additionalProperties: false,
    },
    requiredScopes: [TASKS],
    handler: handlers.tasksUpdate,
    min_tier: "write",
  },
  tasks_delete: {
    name: "tasks_delete",
    description:
      "PERMANENTLY DESTRUCTIVE — Google Tasks has NO trash recovery, unrecoverable from web UI / mobile / any Google surface. DELETE a Google Tasks task via tasks.delete (WRITE OPERATION). ALWAYS ask the user for explicit confirmation before calling this tool. Requires SAFESPACE_TIER=write (or share) — min_tier=write (NOT read like drive_unshare_file) because delete destroys content AND audit evidence asymmetrically; see docs/v1.19-tasks-api.md §10 Q4. NO allowlist bypass exists (no SAFESPACE_TASKS_DELETE_TARGETS equivalent — tier is the floor + scope is the second gate). NO pre-fetch (TOCTOU + extra quota; mirror v1.17 youtube_comment_delete). Per-call only (no bulk delete; blast-radius bound). Defenses for irreversibility: tier=write floor, per-call audit row with target_task_hash, `safespace audit deletes` density alert counts these. Returns {tasklist_id, task_id, deleted: true}. Audit gains target_tasklist_hash + target_task_hash + operation='delete' + policy_decision.",
    inputSchema: {
      type: "object",
      properties: {
        tasklist_id: {
          type: "string",
          description:
            "Tasks API task list identifier. Must match /^[A-Za-z0-9_-]{1,128}$/.",
        },
        task_id: {
          type: "string",
          description:
            "Tasks API task identifier to delete. Must match /^[A-Za-z0-9_-]{1,128}$/. Deletion is PERMANENTLY irreversible — Google Tasks has NO trash.",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["tasklist_id", "task_id"],
      additionalProperties: false,
    },
    requiredScopes: [TASKS],
    handler: handlers.tasksDelete,
    min_tier: "write",
  },
  tasks_move: {
    name: "tasks_move",
    description:
      "Re-position a Google Tasks task within its list via tasks.move (WRITE OPERATION — NON-destructive). ALWAYS ask the user for explicit confirmation before calling this tool. Requires SAFESPACE_TIER=write (or share). Reparents the task (set `parent` to a sibling task id) and/or reorders it (set `previous` to the task it should follow). Omit `parent` → moved to top level; omit `previous` → moved to first position. Within-list ONLY — cross-list move (Google's destinationTasklist) is intentionally NOT exposed (blast-radius + single-list audit). Nothing is deleted; this is a pure re-positioning. `tasklist_id` + `task_id` REQUIRED, `parent` + `previous` OPTIONAL — all four MUST match /^[A-Za-z0-9_-]{1,128}$/ (handler-side validation BEFORE any SDK call). Returns the moved Task resource. Audit gains target_tasklist_hash + target_task_hash + operation='move' + policy_decision.",
    inputSchema: {
      type: "object",
      properties: {
        tasklist_id: {
          type: "string",
          description:
            "Tasks API task list identifier. Must match /^[A-Za-z0-9_-]{1,128}$/ — obtained from `tasks_lists` response.",
        },
        task_id: {
          type: "string",
          description:
            "Tasks API task identifier to move. Must match /^[A-Za-z0-9_-]{1,128}$/ — obtained from `tasks_list` response.",
        },
        parent: {
          type: "string",
          description:
            "Optional new parent task id (makes the moved task a subtask of it). Must match /^[A-Za-z0-9_-]{1,128}$/. Omit to move the task to the top level of the list.",
        },
        previous: {
          type: "string",
          description:
            "Optional new previous-sibling task id (the moved task is positioned immediately after it). Must match /^[A-Za-z0-9_-]{1,128}$/. Omit to move the task to the first position among its siblings.",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["tasklist_id", "task_id"],
      additionalProperties: false,
    },
    requiredScopes: [TASKS],
    handler: handlers.tasksMove,
    min_tier: "write",
  },
  tasks_clear: {
    name: "tasks_clear",
    description:
      "Bulk-hide ALL completed tasks in a Google Tasks task list via tasks.clear (WRITE OPERATION — BULK but RECOVERABLE). ALWAYS ask the user for explicit confirmation before calling this tool. Requires SAFESPACE_TIER=write (or share). This is Google's web-UI 'Delete completed tasks' action: completed tasks are marked HIDDEN, NOT permanently destroyed (contrast tasks_delete, which Google destroys with NO trash). Hidden tasks are NOT returned by tasks_list (which hard-codes showHidden=false), but they continue to exist on Google's side — so this operation is RECOVERABLE and is NOT gated by the SAFESPACE_TASKS_DELETE_TARGETS allowlist (that allowlist is for the permanently-destructive tasks_delete only). Affects only COMPLETED tasks; needsAction tasks are untouched. `tasklist_id` REQUIRED and MUST match /^[A-Za-z0-9_-]{1,128}$/ (handler-side validation BEFORE any SDK call). Returns {tasklist_id, cleared: true}. Audit gains target_tasklist_hash + operation='clear' + policy_decision (list-level — no single task_id).",
    inputSchema: {
      type: "object",
      properties: {
        tasklist_id: {
          type: "string",
          description:
            "Tasks API task list identifier whose completed tasks will be hidden. Must match /^[A-Za-z0-9_-]{1,128}$/ — obtained from `tasks_lists` response.",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["tasklist_id"],
      additionalProperties: false,
    },
    requiredScopes: [TASKS],
    handler: handlers.tasksClear,
    min_tier: "write",
  },
};
