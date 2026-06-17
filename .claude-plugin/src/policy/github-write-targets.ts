// v1.71 — SAFESPACE_GITHUB_WRITE_TARGETS allowlist (the PUBLIC-surface default-deny
// repo gate for GitHub writes). A near-verbatim mirror of
// policy/youtube-comment-targets.ts — GitHub issues/comments/PRs are a PUBLIC surface
// (the same threat class as a YouTube comment), so the gate is DEFAULT-DENY, the
// opposite of the trusted-recipient `recipient-allowlist.ts` (off → allow).
//
// Gate #3 of 4 for github_create_issue / github_create_issue_comment /
// github_update_issue:
//   1. SAFESPACE_TIER=write            (proxy tier filter; no new code)
//   2. OAuth scope = repo              (v1.83; public+private, GitHub enforces it)
//   3. THIS MODULE — owner/repo ∈ SAFESPACE_GITHUB_WRITE_TARGETS (default-empty =
//      HARD-DENY even with scope + write tier) → -32042 github_write_denied_by_policy
//   4. outboundSanitize (per body field) + F3a secret-shape (combined body)
//
// Format: comma-separated `owner/repo` entries. Each segment matches GitHub's
// `^[A-Za-z0-9_.-]{1,100}$` and rejects `..` (no path-traversal smuggling into the
// allowlist). CASE-INSENSITIVE (GitHub logins + repo names are case-insensitive) —
// stored + compared lowercased. This is the ONE deviation from youtube-comment-targets
// (whose YouTube IDs are case-sensitive).
//
// Two-layer (mirrors recipient-allowlist.ts / youtube-comment-targets.ts):
//   - SAFESPACE_GITHUB_WRITE_TARGETS         (persistent; configured in .env)
//   - SAFESPACE_GITHUB_WRITE_TARGETS_EXTRA   (shell-only; per-session)
//
// Default-empty hard-deny: unset / "" / whitespace-only / malformed-only → empty Set,
// ALL writes rejected. WARN-ONCE on _EXTRA-without-base + on malformed tokens at load.

import {
  ENV_GITHUB_WRITE_TARGETS as ENV_TARGETS,
  ENV_GITHUB_WRITE_TARGETS_EXTRA as ENV_TARGETS_EXTRA,
} from "../config";

export { ENV_TARGETS, ENV_TARGETS_EXTRA };

// ----- types -----

export interface ParsedGithubTarget {
  /** lowercased */
  owner: string;
  /** lowercased */
  repo: string;
}

export interface GithubTargetParseResult {
  ok: ParsedGithubTarget[];
  rejected: string[];
}

export type GithubWriteAllowlistState =
  | { kind: "off" }
  | { kind: "active"; targets: ParsedGithubTarget[] };

export interface GithubWriteAllowlistSummary {
  kind: "off" | "active";
  count: number;
}

// ----- segment validation (matches handlers/github.ts OWNER_REPO_RE + the no-`..` rule) -----

const SEGMENT_RE = /^[A-Za-z0-9_.-]{1,100}$/;
function validSegment(s: string): boolean {
  return SEGMENT_RE.test(s) && !s.includes("..");
}

// ----- parsing -----

/** Parse a comma-separated `owner/repo` allowlist string. Trailing/extra commas
 *  tolerated; whitespace around a token trimmed; a token with != 1 slash, or a
 *  segment failing {@link validSegment}, is rejected (loud config error, not silent
 *  drop). Entries are lowercased + deduped. */
export function parseGithubTargets(input: string | undefined): GithubTargetParseResult {
  const result: GithubTargetParseResult = { ok: [], rejected: [] };
  if (input === undefined) return result;

  const tokens = input
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t.length > 0);

  const seen = new Set<string>();
  for (const token of tokens) {
    const parts = token.split("/");
    if (parts.length !== 2 || !validSegment(parts[0]!) || !validSegment(parts[1]!)) {
      result.rejected.push(token);
      continue;
    }
    const owner = parts[0]!.toLowerCase();
    const repo = parts[1]!.toLowerCase();
    const key = `${owner}/${repo}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.ok.push({ owner, repo });
  }
  return result;
}

// ----- matching (default-deny) -----

/** Whether `owner/repo` is in the allowlist. Default-deny: `off` → false (env not
 *  set — HARD-DENY, the safe default for a PUBLIC write surface). Case-insensitive
 *  (the inputs are lowercased before comparison). */
export function isGithubWriteTargetAllowed(
  owner: string,
  repo: string,
  state: GithubWriteAllowlistState,
): boolean {
  if (state.kind === "off") return false;
  if (typeof owner !== "string" || typeof repo !== "string") return false;
  const o = owner.toLowerCase();
  const r = repo.toLowerCase();
  for (const entry of state.targets) {
    if (entry.owner === o && entry.repo === r) return true;
  }
  return false;
}

// ----- summary (doctor/debug — no values exposed) -----

export function summarizeGithubWriteAllowlist(
  state: GithubWriteAllowlistState,
): GithubWriteAllowlistSummary {
  return state.kind === "off"
    ? { kind: "off", count: 0 }
    : { kind: "active", count: state.targets.length };
}

// ----- state building (pure helper, no env / no console) -----

export function buildGithubWriteAllowlistState(
  targetsEnv: string | undefined,
  extraEnv: string | undefined,
): GithubWriteAllowlistState {
  if (targetsEnv === undefined && extraEnv === undefined) {
    return { kind: "off" };
  }
  const baseParsed = parseGithubTargets(targetsEnv);
  const extraParsed = parseGithubTargets(extraEnv);
  const merged: ParsedGithubTarget[] = [];
  const seenKey = new Set<string>();
  for (const t of [...baseParsed.ok, ...extraParsed.ok]) {
    const key = `${t.owner}/${t.repo}`;
    if (seenKey.has(key)) continue;
    seenKey.add(key);
    merged.push(t);
  }
  return { kind: "active", targets: merged };
}

// ----- per-process singleton (load-once, MCP-restart-clears) -----

let cachedState: GithubWriteAllowlistState | undefined;
let warnEmitted = false;

/** Load the allowlist state once per process (mirrors youtube-comment-targets.ts).
 *  WARN-ONCE: _EXTRA set without base, and any malformed token, are stderr-logged
 *  ONCE at first call. */
export function getGithubWriteAllowlistState(): GithubWriteAllowlistState {
  if (cachedState !== undefined) return cachedState;

  const targetsEnv = process.env[ENV_TARGETS];
  const extraEnv = process.env[ENV_TARGETS_EXTRA];

  if (
    !warnEmitted &&
    targetsEnv === undefined &&
    typeof extraEnv === "string" &&
    extraEnv.length > 0
  ) {
    console.error(
      "[safespace] WARNING: SAFESPACE_GITHUB_WRITE_TARGETS_EXTRA is set but " +
        "SAFESPACE_GITHUB_WRITE_TARGETS is not. GitHub-write allowlist is in " +
        "default-deny mode with EXTRA only. If you intended to leave the allowlist " +
        "OFF, also unset SAFESPACE_GITHUB_WRITE_TARGETS_EXTRA.",
    );
    warnEmitted = true;
  }

  const baseParsed = parseGithubTargets(targetsEnv);
  const extraParsed = parseGithubTargets(extraEnv);
  for (const rej of [...baseParsed.rejected, ...extraParsed.rejected]) {
    // Operator-supplied config (process env), NOT attacker-controlled — safe to log.
    console.error(
      `[safespace] WARNING: SAFESPACE_GITHUB_WRITE_TARGETS rejected malformed entry: ${rej}`,
    );
  }

  cachedState = buildGithubWriteAllowlistState(targetsEnv, extraEnv);

  if (cachedState.kind === "active" && cachedState.targets.length === 0) {
    console.error(
      "[safespace] WARNING: SAFESPACE_GITHUB_WRITE_TARGETS is set but yielded 0 valid " +
        "entries — GitHub writes will be hard-denied. Check syntax: comma-separated " +
        "`owner/repo` (e.g. `octocat/Hello-World`).",
    );
  }

  return cachedState;
}

// Test-only.
/** @internal */
export const __internal = {
  SEGMENT_RE,
  resetSingletons: (): void => {
    cachedState = undefined;
    warnEmitted = false;
  },
};
