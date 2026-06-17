#!/usr/bin/env bun
/**
 * Probe: tasks_lists + tasks_list + tasks_get sanitize coverage on a real
 * Google Tasks account.
 *
 * v1.19 Phase 1b — manual one-time validation per
 * docs/v1.19-tasks-api.md §5. Run this once per consented account against
 * (a) the account's task lists AND (b) a sample tasklist (default `@default`)
 * AND optionally (c) a specific task ID to confirm:
 *
 *   1. User-typed content (title, notes, due, links[*].description,
 *      links[*].link) IS wrapped in <untrusted-source-NONCE/> per the
 *      sanitize pipeline.
 *   2. Google opaque keys (selfLink, position) AND the cross-API shared
 *      opaque keys (id, etag, kind, nextPageToken, webViewLink) pass through
 *      UNWRAPPED — they're in SKIP_FIELDS so Claude can keep using them as
 *      opaque references (e.g., feed `id` into a follow-up `tasks_get` call).
 *   3. The walk completes without throwing `sanitize_failed` — confirming
 *      the MAX_DEPTH=64 ceiling (carried from v1.12) accommodates real Task
 *      resources (Tasks are FLAT — worst-case depth ~3 for links[].description).
 *   4. `updated` (bare key, not `updatedAt`) — verify whether Tasks API uses
 *      the bare form. If `updated` leaf-wrapping is OBSERVED, add `updated`
 *      to SKIP_FIELDS in a follow-up patch (design §5 probe follow-up).
 *
 * Usage:
 *   bun scripts/probe-tasks-sanitize.ts \
 *     --account=alice@example.com \
 *     [--tasklist-id=@default] \
 *     [--task-id=<task-id>] \
 *     [--config-dir=<path>]
 *
 * SAFETY:
 *   - Read-only — calls `tasklists.list` + `tasks.list` + (optional) `tasks.get`
 *     once each and walks the responses. No writes, no shares, no completions.
 *   - Bypasses the production `withToolContext` middleware (this calls
 *     `tasksClientFromToken` + `sanitize` directly so the assertions are
 *     observable). The handler-level validation is exercised in unit tests;
 *     this probe specifically validates real-API shape compatibility.
 *
 * MANUAL one-time validation; not in CI. Run after Phase 1b ships to verify
 * against real Google Tasks API.
 *
 * Reproducibility: kept in repo so the sanitize compatibility analysis can
 * be re-validated if Google adds new opaque keys or schema-level fields in
 * future Tasks API revisions.
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
const tasklistId = args["tasklist-id"] ?? "@default";
const taskId = args["task-id"]; // optional
const configDir =
  args["config-dir"] ??
  process.env.SAFESPACE_CONFIG_DIR ??
  path.join(os.homedir(), ".claude", "plugins", "data", "safespace-mcp-safespace", "safespace");

if (!account) {
  console.error(
    "Usage: bun scripts/probe-tasks-sanitize.ts " +
      "--account=<email> [--tasklist-id=@default] [--task-id=<id>] [--config-dir=<path>]",
  );
  process.exit(1);
}

// Validate tasklist_id format (matches handler regex). `@default` does NOT
// match the {1,128} alphanumeric+`_-` regex — it's a Google sentinel value
// the SDK accepts; allow it explicitly.
const TASKLIST_ID_RE = /^[A-Za-z0-9_-]{1,128}$/;
if (tasklistId !== "@default" && !TASKLIST_ID_RE.test(tasklistId)) {
  console.error(
    `ERROR: --tasklist-id=${tasklistId} does not match /^[A-Za-z0-9_-]{1,128}$/ ` +
      `or the literal '@default' sentinel.`,
  );
  process.exit(1);
}
if (taskId !== undefined && !TASKLIST_ID_RE.test(taskId)) {
  console.error(
    `ERROR: --task-id=${taskId} does not match /^[A-Za-z0-9_-]{1,128}$/`,
  );
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
const { tasksClientFromToken } = await import("../.claude-plugin/src/google-api/client");
const { sanitize } = await import("../.claude-plugin/src/sanitize");

console.log(`# Probe config`);
console.log(`  account:      ${account}`);
console.log(`  tasklist_id:  ${tasklistId}`);
console.log(`  task_id:      ${taskId ?? "(none — will pick first task from tasks.list)"}`);
console.log("");

console.log("# Refreshing access token...");
const tokens = await refreshAccessToken(account, { force: true });
console.log(`  ✓ Got fresh token`);
console.log("");

const tasks = tasksClientFromToken(tokens.access_token);

// ──────────────── tasklists.list (enumerate available lists) ────────────────
console.log("# Calling tasklists.list to enumerate task lists...");
const listsRes = await tasks.tasklists.list({});
const taskLists = listsRes.data.items ?? [];
console.log(`  ✓ Got ${taskLists.length} task list(s)`);
for (const tl of taskLists) {
  console.log(`    - id=${tl.id} title=${tl.title}`);
}
console.log("");

// ──────────────── tasks.list for the specified tasklist ────────────────
console.log(`# Calling tasks.list for tasklist=${tasklistId}...`);
const tasksRes = await tasks.tasks.list({
  tasklist: tasklistId,
  maxResults: 100,
  showCompleted: true,
  showHidden: false,
});
const taskItems = tasksRes.data.items ?? [];
console.log(`  ✓ Got ${taskItems.length} task(s)`);
if (taskItems.length > 0 && taskItems[0]) {
  const t = taskItems[0];
  console.log(`    first task: id=${t.id} title=${t.title?.slice(0, 60)}`);
}
console.log("");

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

// ──────────────── sanitize + assert (tasks.list response) ────────────────
console.log("# Running sanitize() over tasks.list response...");
let sanitizedList: unknown;
try {
  sanitizedList = sanitize(tasksRes.data, { toolName: "tasks_list" });
} catch (err) {
  console.error(`  ✗ sanitize threw on tasks.list response: ${(err as Error).message}`);
  console.error("    MAX_DEPTH=64 may need bumping OR a SKIP_FIELDS edge-case fired.");
  process.exit(2);
}
console.log("  ✓ sanitize() completed (no depth overflow / circular ref)");
console.log("");

// Pass criterion 1: user-typed text fields ARE wrapped.
console.log("# Pass criterion 1: user-typed text fields ARE wrapped");
const USER_VISIBLE_KEYS = new Set([
  "title",          // task title + tasklist title
  "notes",          // task notes (free-form text)
  "due",            // RFC 3339 datetime (user-supplied value)
  "completed",      // RFC 3339 datetime (server-set when status flips)
  "link",           // links[*].link
  "description",    // links[*].description
]);
let wrappedUserVisible = 0;
let unwrappedUserVisible = 0;
walkResponse(sanitizedList, (k, v, p) => {
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
if (wrappedUserVisible === 0) {
  console.warn(
    "  ⚠ WARNING: no user-visible text wrapped — is the tasklist empty?",
  );
}
console.log("");

// Pass criterion 2: SKIP_FIELDS keys NEVER wrapped.
console.log("# Pass criterion 2: SKIP_FIELDS Tasks-API keys NOT wrapped");
const opaqueKeys = [
  "selfLink",        // v1.19 NEW
  "position",        // v1.19 NEW
  "id",              // cross-API (Task.id, TaskList.id)
  "etag",            // cross-API
  "kind",            // cross-API ("tasks#task" / "tasks#taskList")
  "webViewLink",     // cross-API (added on some Task responses since 2024)
];
const leaks: Array<{ path: string; key: string; value: string }> = [];
walkResponse(sanitizedList, (k, v, p) => {
  if (opaqueKeys.includes(k) && typeof v === "string" && WRAP_PREFIX_RE.test(v)) {
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
console.log(`  ✓ all ${opaqueKeys.length} opaque key families pass through unwrapped`);
console.log("");

// Pass criterion 3: implicit — we got here without sanitize_failed.
console.log("# Pass criterion 3: walk completed without sanitize_failed");
console.log("  ✓ implicit pass (sanitize() returned)");
console.log("");

// Pass criterion 4: probe whether `updated` (bare) leaks wrapped — design §5
// follow-up. Tasks API uses bare `updated` (NOT `updatedAt`) for timestamps;
// the cross-API SKIP_FIELDS block covers `updatedAt`/`modifiedTime` variants
// but NOT bare `updated`.
console.log("# Pass criterion 4 (probe): bare `updated` key behavior");
let updatedWrappedCount = 0;
let updatedUnwrappedCount = 0;
walkResponse(sanitizedList, (k, v) => {
  if (k === "updated" && typeof v === "string") {
    if (WRAP_PREFIX_RE.test(v)) {
      updatedWrappedCount++;
    } else {
      updatedUnwrappedCount++;
    }
  }
});
console.log(`  → updated wrapped: ${updatedWrappedCount}; unwrapped: ${updatedUnwrappedCount}`);
if (updatedWrappedCount > 0) {
  console.warn(
    `  ⚠ FOLLOW-UP: bare \`updated\` key is being WRAPPED. Consider adding ` +
      `\`updated\` to SKIP_FIELDS in src/sanitize/patterns.ts so callers can ` +
      `treat it as an opaque timestamp (matches design §5 probe follow-up).`,
  );
}
console.log("");

// ──────────────── sanitize + assert (tasks.get response, optional) ────────────────
if (taskId !== undefined || taskItems.length > 0) {
  const resolvedTaskId = taskId ?? taskItems[0]?.id ?? "";
  if (resolvedTaskId) {
    console.log(`# Calling tasks.get for task=${resolvedTaskId}...`);
    const taskRes = await tasks.tasks.get({
      tasklist: tasklistId,
      task: resolvedTaskId,
    });
    console.log("  ✓ Got single task");
    console.log("");

    console.log("# Running sanitize() over tasks.get response...");
    let sanitizedTask: unknown;
    try {
      sanitizedTask = sanitize(taskRes.data, { toolName: "tasks_get" });
    } catch (err) {
      console.error(`  ✗ sanitize threw on tasks.get response: ${(err as Error).message}`);
      process.exit(2);
    }
    console.log("  ✓ tasks.get sanitize() completed");

    let getWrapped = 0;
    let getUnwrapped = 0;
    walkResponse(sanitizedTask, (k, v, p) => {
      if (USER_VISIBLE_KEYS.has(k) && typeof v === "string" && v.length > 0) {
        if (WRAP_PREFIX_RE.test(v)) {
          getWrapped++;
        } else {
          getUnwrapped++;
          console.error(`    ✗ UNWRAPPED user-visible at ${p}: ${v.slice(0, 60)}...`);
        }
      }
    });
    console.log(`  → tasks.get: ${getWrapped} user-visible wrapped`);
    if (getUnwrapped > 0) {
      console.error(`  ✗ FAIL: ${getUnwrapped} user-visible values escaped wrapping`);
      process.exit(3);
    }
    console.log("");
  }
}

// ──────────────── sanitize tasklists.list response ────────────────
console.log("# Running sanitize() over tasklists.list response...");
let sanitizedTaskLists: unknown;
try {
  sanitizedTaskLists = sanitize(listsRes.data, { toolName: "tasks_lists" });
} catch (err) {
  console.error(`  ✗ sanitize threw on tasklists.list response: ${(err as Error).message}`);
  process.exit(2);
}
let tlWrapped = 0;
let tlUnwrapped = 0;
walkResponse(sanitizedTaskLists, (k, v, p) => {
  if (k === "title" && typeof v === "string" && v.length > 0) {
    if (WRAP_PREFIX_RE.test(v)) {
      tlWrapped++;
    } else {
      tlUnwrapped++;
      console.error(`    ✗ UNWRAPPED tasklist title at ${p}: ${v.slice(0, 60)}...`);
    }
  }
});
console.log(`  → tasklists.list: ${tlWrapped} title fields wrapped`);
if (tlUnwrapped > 0) {
  console.error(`  ✗ FAIL: ${tlUnwrapped} tasklist titles escaped wrapping`);
  process.exit(3);
}
console.log("");

console.log("# All probe criteria PASSED. v1.19 Phase 1b sanitize coverage is valid for this account.");
// Explicit exit(0) on success — defense-in-depth against a stray unhandled
// rejection or non-empty event-loop queue holding the process open after the
// probe has reported success. Failure paths above already `process.exit(N)`
// with N ∈ {1,2,3,4}.
process.exit(0);
