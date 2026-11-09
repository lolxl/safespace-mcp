// SAFESPACE_DRIVE_DELETE_TARGETS allowlist module — gates BOTH `drive_trash_file`
// (recoverable, 30-day trash) and `drive_delete_file` (PERMANENT).
//
// Opt-in tightening ABOVE the tier gate. When configured, a trash/delete is
// permitted ONLY for a listed file, or a file/folder whose own id or ANY ancestor
// folder is listed; anything else is denied with `drive_delete_denied_by_policy`
// (-32060).
//
// Default OFF = ALLOW — the tasks-delete posture (NOT the deny-default public-surface
// allowlists): Drive is a PRIVATE, tier-gated surface, so unset env ⇒ every
// trash/delete passes (tier + F1 burst + F4 autonomous permanent-delete deny still
// gate). Under SAFESPACE_AUTONOMOUS an UNCONFIGURED list flips to active-empty
// (deny all) — F2, same as tasks-delete.
//
// Two-layer model (mirrors tasks-delete-targets.ts):
//   - SAFESPACE_DRIVE_DELETE_TARGETS         (persistent; configured in safespace.env)
//   - SAFESPACE_DRIVE_DELETE_TARGETS_EXTRA   (shell-only; per-session)
//
// Entry grammar: comma-separated `folder:<id>` or `file:<id>`; <id> must satisfy
// `isValidDriveId` (the drive-whitelist rule, ^[A-Za-z0-9_-]{20,}$). Case-sensitive
// lowercase prefix. Malformed entries are dropped with a stderr warning (operator
// config, NOT attacker-controlled at process-env time).
//
// Env is read PER CALL (never frozen at module load — bun runs every test file in
// one process / module cache). The parsed state + warn-once bookkeeping are cached
// keyed on the RESOLVED env values, so a changed env re-parses.
//
// Ancestry is walked FRESH on every decision. This module deliberately does NOT
// use drive-whitelist's AncestorCache: a stale cached ancestry (e.g. the file was
// moved out of a listed folder) must never authorize a delete. Any failure to
// prove containment — fetch error, missing metadata, depth exceeded — DENIES.
// Shortcuts are NOT followed by the fetcher the handler supplies: deleting a
// shortcut removes the shortcut itself, so only its OWN parents count.

import {
  ENV_DRIVE_DELETE_TARGETS as ENV_TARGETS,
  ENV_DRIVE_DELETE_TARGETS_EXTRA as ENV_TARGETS_EXTRA,
} from "../config";
import { isAutonomousMode } from "./autonomous-mode";
import { type AncestorFetcher, isValidDriveId, MAX_WALK_DEPTH } from "./drive-whitelist";

export { ENV_TARGETS, ENV_TARGETS_EXTRA };

// ----- types -----

export interface DriveDeleteTargetParseResult {
  folders: string[];
  files: string[];
  rejected: string[]; // raw tokens (for the stderr warning)
}

export type DriveDeleteAllowlistState =
  | { kind: "off" }
  | { kind: "active"; folders: ReadonlySet<string>; files: ReadonlySet<string> };

export interface DriveDeleteAllowlistSummary {
  kind: "off" | "active";
  count: number;
}

export type DriveDeleteDecisionReason =
  | "policy_off"
  | "direct_match"
  | "ancestor_match"
  | "not_in_allowlist"
  | "ancestry_unverifiable";

export interface DriveDeleteDecision {
  allowed: boolean;
  reason: DriveDeleteDecisionReason;
}

// ----- parsing -----

/** Parse a comma-separated `folder:<id>` / `file:<id>` string: split + trim +
 *  filter-empty + dedup; case-sensitive lowercase prefix; id via isValidDriveId. */
export function parseDriveDeleteTargets(input: string | undefined): DriveDeleteTargetParseResult {
  const result: DriveDeleteTargetParseResult = { folders: [], files: [], rejected: [] };
  if (input === undefined) return result;

  const seen = new Set<string>();
  for (const token of input.split(",").map((t) => t.trim()).filter((t) => t.length > 0)) {
    if (seen.has(token)) continue;
    seen.add(token);

    const colonIdx = token.indexOf(":");
    if (colonIdx < 1 || colonIdx === token.length - 1) {
      result.rejected.push(token);
      continue;
    }
    const prefix = token.slice(0, colonIdx);
    const payload = token.slice(colonIdx + 1);
    if (prefix === "folder" && isValidDriveId(payload)) result.folders.push(payload);
    else if (prefix === "file" && isValidDriveId(payload)) result.files.push(payload);
    else result.rejected.push(token);
  }
  return result;
}

// ----- state building (pure helper, no env / no console) -----

/** Build state from raw env strings. Both undefined → off (unless `autonomous`,
 *  which flips an UNCONFIGURED list to active-empty = deny all, F2). Either
 *  non-undefined (incl. "") → active; an active state with zero valid entries
 *  denies ALL trash/deletes. Merges base + extra, deduplicated. */
export function buildDriveDeleteAllowlistState(
  targetsEnv: string | undefined,
  extraEnv: string | undefined,
  autonomous = false,
): DriveDeleteAllowlistState {
  if (targetsEnv === undefined && extraEnv === undefined && !autonomous) {
    return { kind: "off" };
  }
  const base = parseDriveDeleteTargets(targetsEnv);
  const extra = parseDriveDeleteTargets(extraEnv);
  return {
    kind: "active",
    folders: new Set([...base.folders, ...extra.folders]),
    files: new Set([...base.files, ...extra.files]),
  };
}

// ----- decision -----

/** Whether trashing/deleting `fileId` is permitted under `state`.
 *   - off → allow (no network).
 *   - active → allow iff `fileId` ∈ files, OR `fileId` ∈ folders (a listed folder
 *     itself), OR any ancestor reached by a fresh BFS over `parents` ∈ folders.
 *   - FAIL-CLOSED: fetcher throw / not_found, malformed metadata, or the walk
 *     hitting MAX_WALK_DEPTH with unvisited ancestors left → deny
 *     (`ancestry_unverifiable`). A fully resolved chain with no listed folder →
 *     deny (`not_in_allowlist`).
 *  `walked` counts nodes dequeued (= fetcher calls), bounding the API calls. */
export async function checkDriveDeleteAllowed(
  fileId: string,
  state: DriveDeleteAllowlistState,
  ancestorFetcher: AncestorFetcher,
): Promise<DriveDeleteDecision> {
  if (state.kind === "off") return { allowed: true, reason: "policy_off" };
  if (typeof fileId !== "string" || fileId.length === 0) {
    return { allowed: false, reason: "not_in_allowlist" };
  }
  if (state.files.has(fileId) || state.folders.has(fileId)) {
    return { allowed: true, reason: "direct_match" };
  }
  // No listed folder → no ancestor walk can ever authorize; skip the network.
  if (state.folders.size === 0) return { allowed: false, reason: "not_in_allowlist" };

  const visited = new Set<string>();
  const queue: string[] = [fileId];
  let walked = 0;

  while (queue.length > 0) {
    const current = queue.shift()!;
    if (visited.has(current)) continue;
    if (walked >= MAX_WALK_DEPTH) {
      // An unvisited ancestor remains that we are not allowed to fetch.
      return { allowed: false, reason: "ancestry_unverifiable" };
    }
    visited.add(current);
    walked++;

    let result: Awaited<ReturnType<AncestorFetcher>>;
    try {
      result = await ancestorFetcher(current);
    } catch {
      return { allowed: false, reason: "ancestry_unverifiable" };
    }
    if (result.kind !== "ok" || !Array.isArray(result.parents)) {
      return { allowed: false, reason: "ancestry_unverifiable" };
    }
    for (const parentId of result.parents) {
      if (state.folders.has(parentId)) return { allowed: true, reason: "ancestor_match" };
      if (!visited.has(parentId)) queue.push(parentId);
    }
  }
  return { allowed: false, reason: "not_in_allowlist" };
}

// ----- summary (for doctor — no ids exposed) -----

export function summarizeDriveDeleteAllowlist(
  state: DriveDeleteAllowlistState,
): DriveDeleteAllowlistSummary {
  if (state.kind === "off") return { kind: "off", count: 0 };
  return { kind: "active", count: state.folders.size + state.files.size };
}

// ----- per-call state read (cache keyed on the resolved env) -----

let cacheKey: string | undefined;
let cachedState: DriveDeleteAllowlistState | undefined;

/** Resolve the allowlist state from the CURRENT env. Re-parses (and re-warns) only
 *  when the env values or autonomous flag changed since the last call. */
export function getDriveDeleteAllowlistState(): DriveDeleteAllowlistState {
  const targetsEnv = process.env[ENV_TARGETS];
  const extraEnv = process.env[ENV_TARGETS_EXTRA];
  const autonomous = isAutonomousMode();
  const key = JSON.stringify([targetsEnv ?? null, extraEnv ?? null, autonomous]);
  if (cachedState !== undefined && cacheKey === key) return cachedState;

  if (targetsEnv === undefined && typeof extraEnv === "string" && extraEnv.length > 0) {
    console.error(
      "[safespace] WARNING: SAFESPACE_DRIVE_DELETE_TARGETS_EXTRA is set but " +
        "SAFESPACE_DRIVE_DELETE_TARGETS is not. The drive-delete allowlist is now " +
        "ACTIVE with EXTRA only (trash/deletes outside the listed targets are " +
        "denied). To leave it OFF (allow all), also unset " +
        "SAFESPACE_DRIVE_DELETE_TARGETS_EXTRA.",
    );
  }
  const baseParsed = parseDriveDeleteTargets(targetsEnv);
  const extraParsed = parseDriveDeleteTargets(extraEnv);
  for (const rej of [...baseParsed.rejected, ...extraParsed.rejected]) {
    console.error(
      `[safespace] WARNING: SAFESPACE_DRIVE_DELETE_TARGETS rejected malformed entry: ${rej}`,
    );
  }

  const state = buildDriveDeleteAllowlistState(targetsEnv, extraEnv, autonomous);
  if (
    state.kind === "active" &&
    state.folders.size === 0 &&
    state.files.size === 0 &&
    (targetsEnv !== undefined || extraEnv !== undefined)
  ) {
    console.error(
      "[safespace] WARNING: SAFESPACE_DRIVE_DELETE_TARGETS is set but yielded 0 " +
        "valid entries — ALL drive_trash_file / drive_delete_file calls will be " +
        "denied. Check syntax: comma-separated `folder:<id>` or `file:<id>` (id " +
        "matches ^[A-Za-z0-9_-]{20,}$). To allow all, UNSET the variable instead.",
    );
  }
  cacheKey = key;
  cachedState = state;
  return state;
}

// Test-only — do NOT use outside this module's tests.
/** @internal */
export const __internal = {
  resetSingletons: (): void => {
    cacheKey = undefined;
    cachedState = undefined;
  },
};
