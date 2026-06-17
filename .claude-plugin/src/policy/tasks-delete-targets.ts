// v1.39 BLOCKER 4 — SAFESPACE_TASKS_DELETE_TARGETS allowlist module.
//
// Opt-in tightening ABOVE the tier gate for `tasks_delete` (a permanently
// destructive op with NO recovery/burst bypass — tier is its only gate today,
// per the v1.36 premise correction). When configured, deletes are permitted
// ONLY within a listed tasklist; an unlisted tasklist is denied with
// `tasks_delete_denied_by_policy` (-32030, the reserved BLOCKER 4 code).
//
// Default OFF = ALLOW — the OPPOSITE of youtube-comment-targets' default-deny.
// `tasks_delete` is a PRIVATE, tier-gated surface, so this allowlist is opt-in
// hardening, not a hard wall: unset env ⇒ every delete passes (tier still
// gates) ⇒ byte-identical to pre-v1.39. (youtube-comment defaults DENY because
// it is a PUBLIC, permanent write surface; recipient/drive default ALLOW like
// this one.)
//
// Two-layer model (mirrors recipient-allowlist.ts / youtube-comment-targets.ts):
//   - SAFESPACE_TASKS_DELETE_TARGETS         (persistent; configured in safespace.env)
//   - SAFESPACE_TASKS_DELETE_TARGETS_EXTRA   (shell-only; per-session)
//
// Entry grammar (design §4.1): comma-separated `tasklist:<id>` where <id>
// matches ^[A-Za-z0-9_-]{1,128}$ — IDENTICAL to the tasks_delete handler's
// TASKLIST_ID_RE, so an allowlist entry can never out-permit what the handler
// accepts as input. Case-sensitive lowercase `tasklist:` prefix. Malformed
// entries are dropped with a load-time stderr warning (operator config, NOT
// attacker-controlled at process-env time).
//
// See docs/v1.39-blocker4-tasks-delete-allowlist.md §4.

import { isAutonomousMode } from "./autonomous-mode";
import {
  ENV_TASKS_DELETE_TARGETS as ENV_TARGETS,
  ENV_TASKS_DELETE_TARGETS_EXTRA as ENV_TARGETS_EXTRA,
} from "../config";

export { ENV_TARGETS, ENV_TARGETS_EXTRA };

// ----- types -----

const TASKLIST_RE = /^[A-Za-z0-9_-]{1,128}$/;

export interface TasksDeleteTargetParseResult {
  ok: string[]; // parsed tasklist ids
  rejected: string[]; // raw tokens (for load-time stderr warning)
}

export type TasksDeleteAllowlistState =
  | { kind: "off" }
  | { kind: "active"; tasklists: ReadonlySet<string> };

export interface TasksDeleteAllowlistSummary {
  kind: "off" | "active";
  count: number;
}

// ----- parsing -----

/** Parse a comma-separated `tasklist:<id>` allowlist string. Mirrors
 *  parseCommentTargets: split + trim + filter-empty + dedup; case-sensitive
 *  lowercase `tasklist:` prefix; per-id regex on the payload after the colon.
 *  Returns parsed ids + rejected raw tokens. */
export function parseTasksDeleteTargets(
  input: string | undefined,
): TasksDeleteTargetParseResult {
  const result: TasksDeleteTargetParseResult = { ok: [], rejected: [] };
  if (input === undefined) return result;

  const tokens = input
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t.length > 0);

  const seen = new Set<string>();
  for (const token of tokens) {
    if (seen.has(token)) continue;
    seen.add(token);

    // Exactly one leading-keyword colon; the per-id regex below forbids any
    // additional `:` (payload class is [A-Za-z0-9_-]).
    const colonIdx = token.indexOf(":");
    if (colonIdx < 1 || colonIdx === token.length - 1) {
      result.rejected.push(token);
      continue;
    }
    const prefix = token.slice(0, colonIdx);
    const payload = token.slice(colonIdx + 1);

    // Case-sensitive lowercase prefix (a `Tasklist:` is a config error, not a
    // casing quirk to silently accept).
    if (prefix === "tasklist" && TASKLIST_RE.test(payload)) {
      result.ok.push(payload);
    } else {
      result.rejected.push(token);
    }
  }
  return result;
}

// ----- matching -----

/** Whether deleting within `tasklistId` is permitted under `state`.
 *
 *  Default-ALLOW semantics (INVERTED vs isCommentTargetAllowed):
 *    - state.kind === "off"  → true  (env not set; tasks_delete is private +
 *      tier-gated, so the allowlist is opt-in hardening — off means allow).
 *    - state.kind === "active" + tasklistId listed → true.
 *    - Otherwise → false (active, but the tasklist is not in the allowlist —
 *      including the active-but-empty case, which denies ALL deletes). */
export function isTasksDeleteAllowed(
  tasklistId: string,
  state: TasksDeleteAllowlistState,
): boolean {
  if (state.kind === "off") return true;
  if (typeof tasklistId !== "string" || tasklistId.length === 0) return false;
  return state.tasklists.has(tasklistId);
}

// ----- summary (for doctor / debugging — no ids exposed) -----

export function summarizeTasksDeleteAllowlist(
  state: TasksDeleteAllowlistState,
): TasksDeleteAllowlistSummary {
  if (state.kind === "off") return { kind: "off", count: 0 };
  return { kind: "active", count: state.tasklists.size };
}

// ----- state building (pure helper, no env / no console) -----

/** Build state from raw env strings. Off semantics mirror the siblings:
 *    - Both undefined → off (policy not configured → allow all).
 *    - Either non-undefined (incl. "") → active (explicit; an active state
 *      that yields zero ids denies ALL deletes — the loud-warn case below).
 *  Merges base + extra ids, deduplicated.
 *
 *  v1.53 F2 (`autonomous`): when autonomous/strict mode is on, an
 *  UNCONFIGURED allowlist (both env undefined) returns "active" with an empty
 *  set instead of "off" — so isTasksDeleteAllowed denies ALL deletes (the
 *  existing active-but-empty semantics). The matching logic is UNCHANGED. */
export function buildTasksDeleteAllowlistState(
  targetsEnv: string | undefined,
  extraEnv: string | undefined,
  autonomous = false,
): TasksDeleteAllowlistState {
  if (targetsEnv === undefined && extraEnv === undefined && !autonomous) {
    return { kind: "off" };
  }
  const baseParsed = parseTasksDeleteTargets(targetsEnv);
  const extraParsed = parseTasksDeleteTargets(extraEnv);
  const tasklists = new Set<string>([...baseParsed.ok, ...extraParsed.ok]);
  return { kind: "active", tasklists };
}

// ----- per-process singleton (load-once, MCP-restart-clears) -----

let cachedState: TasksDeleteAllowlistState | undefined;
let warnEmitted = false;

/** Load the allowlist state once per process. Mirrors
 *  getCommentTargetAllowlistState's load-once + warn-once pattern. */
export function getTasksDeleteAllowlistState(): TasksDeleteAllowlistState {
  if (cachedState !== undefined) return cachedState;

  const targetsEnv = process.env[ENV_TARGETS];
  const extraEnv = process.env[ENV_TARGETS_EXTRA];

  // WARN-ONCE: _EXTRA set, base unset. Unlike youtube-comment (where this is
  // still default-deny), here it means the allowlist is now ACTIVE off EXTRA
  // alone — i.e. it FLIPPED from allow-all to deny-unlisted. Worth a loud note.
  if (
    !warnEmitted &&
    targetsEnv === undefined &&
    typeof extraEnv === "string" &&
    extraEnv.length > 0
  ) {
    console.error(
      "[safespace] WARNING: SAFESPACE_TASKS_DELETE_TARGETS_EXTRA is set but " +
        "SAFESPACE_TASKS_DELETE_TARGETS is not. The tasks-delete allowlist is " +
        "now ACTIVE with EXTRA only (deletes outside the listed tasklists are " +
        "denied). To leave it OFF (allow all deletes), also unset " +
        "SAFESPACE_TASKS_DELETE_TARGETS_EXTRA.",
    );
    warnEmitted = true;
  }

  const baseParsed = parseTasksDeleteTargets(targetsEnv);
  const extraParsed = parseTasksDeleteTargets(extraEnv);
  for (const rej of [...baseParsed.rejected, ...extraParsed.rejected]) {
    // Operator-supplied process-env config — safe to log verbatim (same
    // convention as drive-whitelist / youtube-comment startup warnings).
    console.error(
      `[safespace] WARNING: SAFESPACE_TASKS_DELETE_TARGETS rejected malformed entry: ${rej}`,
    );
  }

  const envProvided = targetsEnv !== undefined || extraEnv !== undefined;
  cachedState = buildTasksDeleteAllowlistState(targetsEnv, extraEnv, isAutonomousMode());

  // Active-but-empty: env set but zero valid ids ⇒ ALL deletes denied. Loud
  // operator-visibility (not a behavior change — the deny is intended).
  // Gated on `envProvided` so the misleading "UNSET the variable" advice does
  // NOT fire when the active-empty deny was induced by SAFESPACE_AUTONOMOUS
  // (v1.53 F2) rather than by an operator-set-but-empty env — under autonomous
  // mode the deny is expected and unsetting the (unset) var would not change it.
  if (cachedState.kind === "active" && cachedState.tasklists.size === 0 && envProvided) {
    console.error(
      "[safespace] WARNING: SAFESPACE_TASKS_DELETE_TARGETS is set but yielded 0 " +
        "valid entries — ALL tasks_delete calls will be denied. Check syntax: " +
        "comma-separated `tasklist:<id>` (id matches ^[A-Za-z0-9_-]{1,128}$). To " +
        "allow all deletes, UNSET the variable instead.",
    );
  }

  return cachedState;
}

// Test-only — do NOT use outside this module's tests.
/** @internal */
export const __internal = {
  TASKLIST_RE,
  resetSingletons: (): void => {
    cachedState = undefined;
    warnEmitted = false;
  },
};
