// Tasks — extracted verbatim from the former monolithic
// src/tools/handlers.ts (mechanical per-API split; function bodies byte-identical).
// Re-exported via ./index.ts so existing `./handlers` import paths are unchanged.

import { MCPError } from "../../errors";
import { tasksClientFromToken } from "../../google-api/client";
import { toGoogleError } from "../../google-api/errors";
import { getTasksDeleteAllowlistState, isTasksDeleteAllowed } from "../../policy/tasks-delete-targets";
import type { ToolContext } from "../types";

import { requireGoogle, TASKLIST_ID_RE, sha256Hex } from "./shared";

const TASK_ID_RE = /^[A-Za-z0-9_-]{1,128}$/;

/** Defense-in-depth caps for `tasks_list` (design §2.2). Google's natural
 * ceiling is `maxResults=100` (per the v1.d.ts comment); SafeSpace clamps
 * lower than Calendar's 100 ceiling? No — Tasks share the same cap. Default
 * is 50 (matches contacts_search posture; Calendar default is 25 — Tasks
 * tend to be smaller, fewer per-list, so a 50 default is generous without
 * being abusive). */
const TASKS_LIST_DEFAULT_MAX = 50;
const TASKS_LIST_CAP = 100;

export async function tasksLists(
  ctx: ToolContext,
  _args: Record<string, unknown>,
): Promise<unknown> {
  // No input args (design §2.1) — `tasks.tasklists.list({})` enumerates the
  // calling account's task lists. Tasks API has no list-of-lists pagination
  // in practice (typical users have <10 task lists; Google does not surface
  // a `pageToken` for tasklists.list in v1).
  try {
    const tasks = tasksClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await tasks.tasklists.list({});
    // Normalize undefined items → [] so callers always see an array (same
    // posture as v1.13 calendar_list_events and v1.15 contacts_search).
    return { items: res.data.items ?? [] };
  } catch (err) {
    throw toGoogleError(err, { tool: "tasks_lists", email: requireGoogle(ctx).accountId });
  }
}

export async function tasksList(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // Validate tasklist_id — design §2.2 + sec-rev hook #5.
  // Echo the RULE, NOT the bad value — same posture as calendar_get_event /
  // contacts_get (sec-rev hook #12 / v1.13 §7 hook #11: error paths must not
  // reflect user-supplied content back to the caller verbatim).
  if (typeof args.tasklist_id !== "string") {
    throw new Error("tasks_list: 'tasklist_id' must be a string");
  }
  if (!TASKLIST_ID_RE.test(args.tasklist_id)) {
    throw new Error(
      "tasks_list: 'tasklist_id' must match /^[A-Za-z0-9_-]{1,128}$/",
    );
  }
  const tasklistId = args.tasklist_id;

  // Defense-in-depth: schema declares max:100 + integer, but non-conforming
  // MCP clients can slip NaN / Infinity / -Infinity past `typeof === "number"`.
  // Match v1.14 driveSearchAll / v1.15 contactsSearch finite-and-positive
  // guard exactly. Infinity → fallback to default (Number.isFinite(Inf) is
  // false), NOT Math.min(Inf, 100) = 100.
  const rawRequested =
    typeof args.max_results === "number"
      ? args.max_results
      : TASKS_LIST_DEFAULT_MAX;
  const requested =
    Number.isFinite(rawRequested) && rawRequested >= 1
      ? rawRequested
      : TASKS_LIST_DEFAULT_MAX;
  const maxResults = Math.floor(Math.min(requested, TASKS_LIST_CAP));

  // showCompleted default false (design §2.2) — completed tasks are usually
  // clutter; opt-in. Matches Google web-UI default behavior.
  const showCompleted = args.show_completed === true;

  try {
    const tasks = tasksClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await tasks.tasks.list({
      tasklist: tasklistId,
      maxResults,
      showCompleted,
      // showHidden LOCKED to false (NOT exposed to caller). Hidden tasks are
      // a Google internal UI state — surfacing them would expose state the
      // user did not consciously mark visible. Design §2.2 "show_completed
      // default false" rationale extends.
      showHidden: false,
    });
    // Normalize undefined items → [] (same posture as tasksLists above).
    return {
      items: res.data.items ?? [],
      nextPageToken: res.data.nextPageToken,
    };
  } catch (err) {
    throw toGoogleError(err, { tool: "tasks_list", email: requireGoogle(ctx).accountId });
  }
}

export async function tasksGet(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // Validate tasklist_id + task_id — design §2.4 + sec-rev hook #5. Both
  // regexes identical {1,128} per the §2.4 sec-L2 tightening.
  if (typeof args.tasklist_id !== "string") {
    throw new Error("tasks_get: 'tasklist_id' must be a string");
  }
  if (!TASKLIST_ID_RE.test(args.tasklist_id)) {
    throw new Error(
      "tasks_get: 'tasklist_id' must match /^[A-Za-z0-9_-]{1,128}$/",
    );
  }
  if (typeof args.task_id !== "string") {
    throw new Error("tasks_get: 'task_id' must be a string");
  }
  if (!TASK_ID_RE.test(args.task_id)) {
    throw new Error(
      "tasks_get: 'task_id' must match /^[A-Za-z0-9_-]{1,128}$/",
    );
  }

  try {
    const tasks = tasksClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await tasks.tasks.get({
      tasklist: args.tasklist_id,
      task: args.task_id,
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "tasks_get", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.19 Phase 2a: tasks_search_all (CROSS-ACCOUNT READ tool) ─────────
 *
 * Pattern-copy of v1.14 gmailSearchAll / driveSearchAll. Fan-out across
 * consented Google accounts via `withAllAccounts` middleware. Per-account
 * fresh sanitize nonce + per-account audit row + 1 outer aggregate row.
 * Best-effort partial-success semantics. See `docs/v1.19-tasks-api.md` §2.3
 * + §8 + §10 hooks #7 / #10.
 *
 * Active-account semantics: cross-account branch in proxy.ts dispatches OUTSIDE
 * `withToolContext`, so `lastUsedAccount` is NOT mutated (design §3 / v1.14
 * binding contract).
 *
 * Client-side filter: Tasks API has NO native query parameter on
 * `tasks.tasks.list`. Per design §2.3 + Q5 LOCKED, the handler fetches
 * tasks per account (up to per-account fetch cap) then applies a case-
 * insensitive substring match against `title` + `notes` (logical OR).
 *
 * Single-tasklist-per-account scan (LOCKED Phase 1, §2.3 + §11 Risk 5):
 * when `tasklist_id` is absent, queries each account's DEFAULT task list
 * (`@default`). Users with multiple tasklists per account get only their
 * default list searched. Multi-tasklist scan deferred to Phase 4+.
 *
 * Per-account args.max_results bounds (per design §2.3):
 *   - Default: 50 per account (matches single-account tasks_list default)
 *   - Hard cap: 100 per account (Google's natural ceiling; design Q5 LOCKED)
 *
 * Sec-rev hooks (per design §10) applied here:
 *   #5  `tasklist_id` regex {1,128} (carry-forward from Phase 1b)
 *   #7  Per-account sanitize nonce isolation (via withAllAccounts internals)
 *  #10  `query` strict-parse + length cap (1-256 chars) BEFORE fan-out
 *  #12  No PII echo — error messages reference the RULE, not the input value
 */

/** Tasks Task requestBody allowlist (design §2.5 + §2.6 + sec-rev hook #2/#3).
 *
 *  Positive ALLOWLIST: handler MUST build `requestBody` literally from these
 *  4 keys ONLY. NEVER `...args` spread. Sentinel test asserts
 *  Object.keys(requestBody).sort() ⊆ ["due", "notes", "status", "title"].
 *
 *  REJECTED (design §2.5 + §12 LOCKED): `parent` (subtask hierarchy) and
 *  `previous` (position hint) — Phase 4+. Reviewers note: earlier review
 *  prompts referenced a 6-key allowlist; that premise was wrong. */
const TASKS_BODY_ALLOWED_KEYS = new Set(["title", "notes", "due", "status"]);

/** Closed-enum sentinel for task status (sec-rev hook #4). Mirrors v1.17
 *  calendar_respond responseStatus closed-set + v1.13 calendar attendees
 *  responseStatus closed-set patterns. */
const TASKS_STATUS_ALLOWED = new Set(["needsAction", "completed"]);

/** RFC 3339 UTC datetime regex (sec-rev hook #14). Strict — handler validates
 *  BEFORE the SDK call so malformed input never reaches Google (defense
 *  against PII echo in Google's error responses; user-supplied raw `due`
 *  would otherwise round-trip into error.message). Pattern matches:
 *
 *    2026-05-25T10:00:00Z
 *    2026-05-25T10:00:00.123Z
 *    2026-05-25T10:00:00+00:00
 *    2026-05-25T10:00:00.999-08:00
 *
 *  Pre-SDK rejection of `"tomorrow"` / `"2026/13/01"` / raw garbage strings
 *  per design §10 hook #14. */
const TASKS_DUE_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?(Z|[+-]\d{2}:\d{2})?$/;

/** DoS guard for `due` strings — RFC 3339 with milliseconds + tz is ≤30 chars;
 *  32 is a snug ceiling. Rejected pre-regex so attacker-controlled megabyte
 *  strings can't reach the regex engine. */
const TASKS_DUE_MAX_LENGTH = 32;

/** Title / notes byte caps (defensive client-side guards). Google's
 *  documented limits are 1024 / 8192 bytes UTF-8. Reject pre-SDK so a
 *  user gets a clear local error instead of an opaque Google 400. */
const TASKS_TITLE_MAX_BYTES = 1024;
const TASKS_NOTES_MAX_BYTES = 8192;

/** Validate the 4-key allowlist subset against caller args and build the
 *  literal requestBody. Shared between `tasks_create` (title required) and
 *  `tasks_update` (all optional; at-least-one required by design §2.6).
 *
 *  RETURNS the cleaned body. THROWS plain `Error` on shape / type / range
 *  / regex / enum violations (matches v1.13/v1.17 raw-shape-error convention).
 *
 *  Design §2.5 + §2.6 LOCKED — both handlers share the same 4-key allowlist
 *  + 15-field NEGATIVE sentinel. Single helper guarantees they cannot drift. */
function buildTasksRequestBody(
  args: Record<string, unknown>,
  tool: "tasks_create" | "tasks_update",
): Record<string, unknown> {
  const body: Record<string, unknown> = {};

  // title — REQUIRED for create; OPTIONAL for update. Non-empty after trim
  // on create per design §2.5. On update, omitting title is fine; passing
  // empty string is rejected as a no-op shape error (avoids accidentally
  // clearing the title via empty-string semantics).
  if (args.title !== undefined) {
    if (typeof args.title !== "string") {
      throw new Error(`${tool}: 'title' must be a string`);
    }
    if (args.title.trim().length === 0) {
      throw new Error(`${tool}: 'title' must be non-empty after trim`);
    }
    if (Buffer.byteLength(args.title, "utf-8") > TASKS_TITLE_MAX_BYTES) {
      throw new Error(
        `${tool}: 'title' exceeds ${TASKS_TITLE_MAX_BYTES} bytes`,
      );
    }
    body.title = args.title;
  } else if (tool === "tasks_create") {
    throw new Error("tasks_create requires non-empty 'title' string");
  }

  // notes — OPTIONAL on both. Empty string permitted (clears notes on update,
  // legitimate use case).
  if (args.notes !== undefined) {
    if (typeof args.notes !== "string") {
      throw new Error(`${tool}: 'notes' must be a string`);
    }
    if (Buffer.byteLength(args.notes, "utf-8") > TASKS_NOTES_MAX_BYTES) {
      throw new Error(
        `${tool}: 'notes' exceeds ${TASKS_NOTES_MAX_BYTES} bytes`,
      );
    }
    body.notes = args.notes;
  }

  // due — OPTIONAL on both. Strict RFC 3339 validation pre-SDK
  // (sec-rev hook #14). Length cap pre-regex (DoS guard). Echo the
  // RULE, NOT the bad value (sec-rev hook #12).
  if (args.due !== undefined) {
    if (typeof args.due !== "string") {
      throw new Error(`${tool}: 'due' must be a string`);
    }
    if (args.due.length > TASKS_DUE_MAX_LENGTH) {
      throw new Error(
        `${tool}: 'due' exceeds ${TASKS_DUE_MAX_LENGTH} chars (RFC 3339 datetime; defense against Google echoing raw input in errors)`,
      );
    }
    if (!TASKS_DUE_RE.test(args.due)) {
      throw new Error(
        `${tool}: 'due' must be RFC 3339 datetime (e.g., 2026-05-25T10:00:00Z)`,
      );
    }
    body.due = args.due;
  }

  // status — OPTIONAL on both. Closed enum (sec-rev hook #4). Reject
  // case-mismatches (`COMPLETED` / `Completed`) + non-string + arbitrary
  // values (`in_progress`). Echo the RULE, NOT the input.
  if (args.status !== undefined) {
    if (typeof args.status !== "string") {
      throw new Error(`${tool}: 'status' must be a string`);
    }
    if (!TASKS_STATUS_ALLOWED.has(args.status)) {
      throw new Error(
        `${tool}: 'status' must be one of {needsAction, completed} (case-sensitive)`,
      );
    }
    body.status = args.status;
  }

  // tasks_update requires AT LEAST ONE patch field — otherwise the call is
  // a no-op and the caller probably meant something else. Per design §2.6
  // "all optional; at least one MUST be supplied".
  if (tool === "tasks_update" && Object.keys(body).length === 0) {
    throw new Error(
      "tasks_update requires at least one of {title, notes, due, status}",
    );
  }

  return body;
}

/** `tasks_create` — create a new task in a tasklist. WRITE TIER.
 *
 *  Allowlist (positive sentinel): 4 keys — `title` / `notes` / `due` / `status`.
 *  NEGATIVE sentinel: 15 forbidden top-level Task fields (design §2.5 +
 *  sec-rev hook #2). Handler builds requestBody LITERALLY — no spread.
 *
 *  Tier check + audit BEFORE SDK call (sec-rev hook #11). Audit row:
 *  `tasksMutationMeta.operation = "create"` + `target_tasklist_hash` SET +
 *  `target_task_hash` ABSENT (task has no ID yet). */
export async function tasksCreate(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. Input validation BEFORE tier check (v1.17 convention) ──
  if (typeof args.tasklist_id !== "string") {
    throw new Error("tasks_create: 'tasklist_id' must be a string");
  }
  if (!TASKLIST_ID_RE.test(args.tasklist_id)) {
    throw new Error(
      "tasks_create: 'tasklist_id' must match /^[A-Za-z0-9_-]{1,128}$/",
    );
  }
  const tasklistId = args.tasklist_id;

  // Build the 4-key allowlisted requestBody. Throws plain Error on shape /
  // range / enum / regex failures (15-field NEGATIVE sentinel is enforced
  // by construction — only the 4 allowed keys are ever copied across).
  const requestBody = buildTasksRequestBody(args, "tasks_create");

  // ─── 2. Tier check (defense-in-depth) ──
  // The proxy normally hides write tools at tier=read; this catches bypass.
  // Audit meta recorded BEFORE the throw so the auditEnd finally block has
  // the data (sec-rev hook #11 forensic-survives-failure pattern).
  const tasklistHash = sha256Hex(tasklistId);
  const tier = ctx.tier;
  if (tier === "read") {
    ctx.audit.record("tasksMutationMeta", {
      target_tasklist_hash: tasklistHash,
      operation: "create",
      policy_decision: "denied_tier",
    });
    throw new MCPError("scope_mismatch", {
      tool: "tasks_create",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  // ─── 3. Record audit meta BEFORE SDK call (hook #11) ──
  // FORENSIC COMPLETENESS: capture BEFORE SDK call so a 500 / network /
  // permission failure still leaves a row showing what Claude attempted.
  // target_task_hash is OMITTED on create — task has no ID yet (Google
  // assigns it server-side).
  ctx.audit.record("tasksMutationMeta", {
    target_tasklist_hash: tasklistHash,
    operation: "create",
    policy_decision: "allowed",
  });

  // ─── 4. SDK call ──
  try {
    const tasks = tasksClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await tasks.tasks.insert({
      tasklist: tasklistId,
      requestBody,
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "tasks_create", email: requireGoogle(ctx).accountId });
  }
}

/** `tasks_update` — partial update of an existing task. WRITE TIER.
 *
 *  Uses `tasks.tasks.patch` (NOT `update`) — omitted keys preserved by Google.
 *  Allowlist + NEGATIVE sentinel identical to `tasks_create`. At least ONE
 *  allowlisted field MUST be supplied; otherwise the call is a no-op shape
 *  error (rejected by `buildTasksRequestBody`).
 *
 *  Tier check + audit BEFORE SDK call. Audit row:
 *  `tasksMutationMeta.operation = "update"` + `target_tasklist_hash` SET +
 *  `target_task_hash` SET (task already exists). */
export async function tasksUpdate(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. Input validation BEFORE tier check ──
  if (typeof args.tasklist_id !== "string") {
    throw new Error("tasks_update: 'tasklist_id' must be a string");
  }
  if (!TASKLIST_ID_RE.test(args.tasklist_id)) {
    throw new Error(
      "tasks_update: 'tasklist_id' must match /^[A-Za-z0-9_-]{1,128}$/",
    );
  }
  if (typeof args.task_id !== "string") {
    throw new Error("tasks_update: 'task_id' must be a string");
  }
  if (!TASK_ID_RE.test(args.task_id)) {
    throw new Error(
      "tasks_update: 'task_id' must match /^[A-Za-z0-9_-]{1,128}$/",
    );
  }
  const tasklistId = args.tasklist_id;
  const taskId = args.task_id;

  // Build the 4-key patch body. Throws if no allowlisted keys supplied
  // (at-least-one-required per design §2.6).
  const requestBody = buildTasksRequestBody(args, "tasks_update");

  // ─── 2. Tier check ──
  const tasklistHash = sha256Hex(tasklistId);
  const taskHash = sha256Hex(taskId);
  const tier = ctx.tier;
  if (tier === "read") {
    ctx.audit.record("tasksMutationMeta", {
      target_tasklist_hash: tasklistHash,
      target_task_hash: taskHash,
      operation: "update",
      policy_decision: "denied_tier",
    });
    throw new MCPError("scope_mismatch", {
      tool: "tasks_update",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  // ─── 3. Record audit meta BEFORE SDK call ──
  ctx.audit.record("tasksMutationMeta", {
    target_tasklist_hash: tasklistHash,
    target_task_hash: taskHash,
    operation: "update",
    policy_decision: "allowed",
  });

  // ─── 4. SDK call — tasks.patch (partial update; omitted keys preserved) ──
  // NOTE: `tasks.tasks.update` would do FULL REPLACEMENT (and Google requires
  // the full Task body); `patch` honors omitted keys. Per design §2.6
  // "tasks.tasks.patch (partial — omitted keys preserved)".
  try {
    const tasks = tasksClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await tasks.tasks.patch({
      tasklist: tasklistId,
      task: taskId,
      requestBody,
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "tasks_update", email: requireGoogle(ctx).accountId });
  }
}

/** `tasks_delete` — PERMANENTLY destroy a task. WRITE TIER.
 *
 *  RECOVERY POSTURE: Google Tasks API has NO trash. Unlike Calendar
 *  (30-day trash) / Drive (trash) / Gmail (trash+spam), a deleted task is
 *  immediately + irreversibly destroyed — unrecoverable from web UI,
 *  mobile, or any other Google surface.
 *
 *  §10 Q4 LOCKED: min_tier=write (mirrors v1.17 youtube_comment_delete).
 *  Asymmetric vs drive_unshare_file (read tier) — unshare removes ACL row
 *  without destroying content; task delete destroys content AND
 *  audit-evidence-of-existence permanently.
 *
 *  NO pre-fetch (TOCTOU + extra quota; mirror v1.17 youtube_comment_delete).
 *  NO bulk delete (blast-radius bound; per design §2.7 + sec-rev hook #6).
 *  NO allowlist bypass (no allowlist exists for tasks_delete; tier is the
 *  only gate above scope).
 *
 *  Audit row: `tasksMutationMeta.operation = "delete"` + both
 *  `target_tasklist_hash` AND `target_task_hash` SET. `safespace audit
 *  deletes` density alert counts this category (sec-rev hook #13). */
export async function tasksDelete(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. Input validation BEFORE tier check ──
  if (typeof args.tasklist_id !== "string") {
    throw new Error("tasks_delete: 'tasklist_id' must be a string");
  }
  if (!TASKLIST_ID_RE.test(args.tasklist_id)) {
    throw new Error(
      "tasks_delete: 'tasklist_id' must match /^[A-Za-z0-9_-]{1,128}$/",
    );
  }
  if (typeof args.task_id !== "string") {
    throw new Error("tasks_delete: 'task_id' must be a string");
  }
  if (!TASK_ID_RE.test(args.task_id)) {
    throw new Error(
      "tasks_delete: 'task_id' must match /^[A-Za-z0-9_-]{1,128}$/",
    );
  }
  const tasklistId = args.tasklist_id;
  const taskId = args.task_id;

  // ─── 2. Tier check ──
  const tasklistHash = sha256Hex(tasklistId);
  const taskHash = sha256Hex(taskId);
  const tier = ctx.tier;
  if (tier === "read") {
    ctx.audit.record("tasksMutationMeta", {
      target_tasklist_hash: tasklistHash,
      target_task_hash: taskHash,
      operation: "delete",
      policy_decision: "denied_tier",
    });
    throw new MCPError("scope_mismatch", {
      tool: "tasks_delete",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  // ─── 2b. Tasks-delete target allowlist (v1.39 BLOCKER 4) ──
  // Opt-in tightening ABOVE the tier gate: when SAFESPACE_TASKS_DELETE_TARGETS
  // is set, only deletes within a listed tasklist are permitted. Default OFF =
  // allow (tier stays the gate) → byte-identical to pre-v1.39 when unset. Gate
  // fires BEFORE the SDK call — no Google request on denial (mirror the
  // youtube_comment_delete denial ordering). Records the denial on the existing
  // tasksMutation channel (hashes only — no plaintext id) before throwing.
  if (!isTasksDeleteAllowed(tasklistId, getTasksDeleteAllowlistState())) {
    ctx.audit.record("tasksMutationMeta", {
      target_tasklist_hash: tasklistHash,
      target_task_hash: taskHash,
      operation: "delete",
      policy_decision: "denied_target_not_in_allowlist",
    });
    throw new MCPError("tasks_delete_denied_by_policy");
  }

  // ─── 3. Record audit meta BEFORE SDK call (PERMANENTLY destructive) ──
  // The task is about to be unrecoverably destroyed; the meta MUST exist
  // before the destructive call so a network / 5xx / 403 failure still
  // leaves forensic evidence of the attempt.
  ctx.audit.record("tasksMutationMeta", {
    target_tasklist_hash: tasklistHash,
    target_task_hash: taskHash,
    operation: "delete",
    policy_decision: "allowed",
  });

  // ─── 4. SDK call — tasks.delete ──
  // Google returns 204 No Content on success. NO pre-fetch (TOCTOU; mirror
  // v1.17 youtube_comment_delete). Return shape synthesized for an
  // unambiguous MCP response (matches calendar_delete_event +
  // youtube_comment_delete convention).
  try {
    const tasks = tasksClientFromToken(requireGoogle(ctx).getAccessToken());
    await tasks.tasks.delete({
      tasklist: tasklistId,
      task: taskId,
    });
    return { tasklist_id: tasklistId, task_id: taskId, deleted: true };
  } catch (err) {
    throw toGoogleError(err, { tool: "tasks_delete", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.47 B2: tasks_move + tasks_clear (WRITE tier — surface completion) ─────────
 *
 * Both ride the EXISTING `tasksMutationMeta` audit channel (operation union
 * extended +move +clear in audit.ts) — NO new channel, NO new error code, NO
 * new scope (both on the existing `tasks` full scope). See
 * `docs/v1.47-tasks-move-clear.md`. Both mirror the tasks_create/update/delete
 * shape: input-validate → tier re-check (denied_tier meta + throw) → record
 * "allowed" meta BEFORE the SDK call (forensic-survives-failure) → SDK call →
 * toGoogleError on failure.
 */

/** `tasks_move` — re-position a task within its list (reparent + reorder). WRITE
 *  TIER, NON-destructive. Uses `tasks.tasks.move`.
 *
 *  Within-list ONLY — `destinationTasklist` (cross-list move) is intentionally
 *  NOT exposed (design §3.5: blast-radius + single-`target_tasklist_hash`
 *  audit). `parent` / `previous` are OPTIONAL positional hints (both task ids,
 *  same regex); omitting `parent` → top level, omitting `previous` → first
 *  position. They are NOT hashed into the audit row — only the acted-upon
 *  `task_id` is (matches the create/update precedent).
 *
 *  Audit row: `operation = "move"` + both `target_tasklist_hash` AND
 *  `target_task_hash` SET. */
export async function tasksMove(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. Input validation BEFORE tier check ──
  if (typeof args.tasklist_id !== "string") {
    throw new Error("tasks_move: 'tasklist_id' must be a string");
  }
  if (!TASKLIST_ID_RE.test(args.tasklist_id)) {
    throw new Error(
      "tasks_move: 'tasklist_id' must match /^[A-Za-z0-9_-]{1,128}$/",
    );
  }
  if (typeof args.task_id !== "string") {
    throw new Error("tasks_move: 'task_id' must be a string");
  }
  if (!TASK_ID_RE.test(args.task_id)) {
    throw new Error(
      "tasks_move: 'task_id' must match /^[A-Za-z0-9_-]{1,128}$/",
    );
  }
  // parent / previous — OPTIONAL. Same TASK_ID_RE (both are task ids).
  // Echo the RULE, NOT the bad value (sec-rev hook #12).
  if (args.parent !== undefined) {
    if (typeof args.parent !== "string") {
      throw new Error("tasks_move: 'parent' must be a string");
    }
    if (!TASK_ID_RE.test(args.parent)) {
      throw new Error(
        "tasks_move: 'parent' must match /^[A-Za-z0-9_-]{1,128}$/",
      );
    }
  }
  if (args.previous !== undefined) {
    if (typeof args.previous !== "string") {
      throw new Error("tasks_move: 'previous' must be a string");
    }
    if (!TASK_ID_RE.test(args.previous)) {
      throw new Error(
        "tasks_move: 'previous' must match /^[A-Za-z0-9_-]{1,128}$/",
      );
    }
  }
  const tasklistId = args.tasklist_id;
  const taskId = args.task_id;

  // ─── 2. Tier check (defense-in-depth) ──
  const tasklistHash = sha256Hex(tasklistId);
  const taskHash = sha256Hex(taskId);
  const tier = ctx.tier;
  if (tier === "read") {
    ctx.audit.record("tasksMutationMeta", {
      target_tasklist_hash: tasklistHash,
      target_task_hash: taskHash,
      operation: "move",
      policy_decision: "denied_tier",
    });
    throw new MCPError("scope_mismatch", {
      tool: "tasks_move",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  // ─── 3. Record audit meta BEFORE SDK call (hook #11) ──
  ctx.audit.record("tasksMutationMeta", {
    target_tasklist_hash: tasklistHash,
    target_task_hash: taskHash,
    operation: "move",
    policy_decision: "allowed",
  });

  // ─── 4. SDK call — tasks.move. `parent` / `previous` only passed when
  // supplied (Google omits → top level / first position). NO
  // destinationTasklist (within-list only). Returns the moved Task. ──
  try {
    const tasks = tasksClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await tasks.tasks.move({
      tasklist: tasklistId,
      task: taskId,
      ...(args.parent !== undefined ? { parent: args.parent } : {}),
      ...(args.previous !== undefined ? { previous: args.previous } : {}),
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "tasks_move", email: requireGoogle(ctx).accountId });
  }
}

/** `tasks_clear` — bulk-hide ALL completed tasks in a list. WRITE TIER,
 *  BULK but RECOVERABLE. Uses `tasks.tasks.clear`.
 *
 *  RECOVERY POSTURE: completed tasks are marked HIDDEN, NOT permanently
 *  destroyed (contrast `tasks_delete`, which Google destroys with NO trash).
 *  Hidden tasks continue to exist on Google's side. Therefore: min_tier=write
 *  (standard floor), and NO `SAFESPACE_TASKS_DELETE_TARGETS`-style allowlist
 *  gate — that allowlist is for the permanently-destructive `tasks_delete`
 *  ONLY (design §3.1).
 *
 *  Audit row: `operation = "clear"` + `target_tasklist_hash` SET +
 *  `target_task_hash` ABSENT (list-level — no single task). Its absence is
 *  itself a discriminator (PRESENCE-as-signal). NOT counted by
 *  `classifyDestructive` (which matches only `operation === "delete"`). */
export async function tasksClear(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. Input validation BEFORE tier check ──
  if (typeof args.tasklist_id !== "string") {
    throw new Error("tasks_clear: 'tasklist_id' must be a string");
  }
  if (!TASKLIST_ID_RE.test(args.tasklist_id)) {
    throw new Error(
      "tasks_clear: 'tasklist_id' must match /^[A-Za-z0-9_-]{1,128}$/",
    );
  }
  const tasklistId = args.tasklist_id;

  // ─── 2. Tier check (defense-in-depth) ──
  const tasklistHash = sha256Hex(tasklistId);
  const tier = ctx.tier;
  if (tier === "read") {
    ctx.audit.record("tasksMutationMeta", {
      target_tasklist_hash: tasklistHash,
      operation: "clear",
      policy_decision: "denied_tier",
    });
    throw new MCPError("scope_mismatch", {
      tool: "tasks_clear",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  // ─── 3. Record audit meta BEFORE SDK call (hook #11) ──
  // target_task_hash OMITTED — list-level operation (no single task id).
  ctx.audit.record("tasksMutationMeta", {
    target_tasklist_hash: tasklistHash,
    operation: "clear",
    policy_decision: "allowed",
  });

  // ─── 4. SDK call — tasks.clear. Google returns 204 No Content on success.
  // Return shape synthesized for an unambiguous MCP response (mirrors the
  // tasks_delete `{...deleted:true}` convention). ──
  try {
    const tasks = tasksClientFromToken(requireGoogle(ctx).getAccessToken());
    await tasks.tasks.clear({ tasklist: tasklistId });
    return { tasklist_id: tasklistId, cleared: true };
  } catch (err) {
    throw toGoogleError(err, { tool: "tasks_clear", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.20 Phase 1b-1: sheets_get_values + sheets_get_metadata (READ tier) ─────────
 *
 * See `docs/v1.20-sheets-api.md` §2.1 / §2.2. Both handlers validate inputs
 * via shared regex constants + A1 strict-parse (sec-rev hooks #1 + #2),
 * apply per-field allowlist gates (hooks #4 + #5 + #20 + #21) BEFORE the
 * SDK call, and map upstream errors via `toGoogleError`.
 *
 * Phase 1b-2 ships the WRITE tools (sheets_create + sheets_append_values)
 * with the 30-field NEGATIVE sentinel + RAW HARD-LOCK + new audit channel.
 */

