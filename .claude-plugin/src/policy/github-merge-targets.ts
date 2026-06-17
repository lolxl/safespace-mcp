// v1.82 — SAFESPACE_GITHUB_MERGE_TARGETS: a SEPARATE default-deny allowlist for the
// IRREVERSIBLE github_merge_pull_request. Distinct from SAFESPACE_GITHUB_WRITE_TARGETS
// on purpose: merging to a default branch is a higher bar than opening a PR or
// commenting, so the operator opts a repo into "the agent may MERGE here" on its own
// list (a repo write-allowlisted for issues/PRs is NOT thereby merge-allowlisted).
//
// The PARSE / MATCH / BUILD logic is identical to the write allowlist (same owner/repo
// shape, case-insensitive, two-layer base+EXTRA, default-deny), so this module REUSES
// the pure exports of github-write-targets and adds only the merge-specific env wiring
// + its own per-process singleton + warn-once. (The project keeps a module per gate —
// v1.67 deliberately dropped a shared two-layer helper because the gates' caching /
// warn / default posture diverge — so this is the DRY-within-convention middle ground:
// reuse the pure core, own the stateful surface.)

import {
  ENV_GITHUB_MERGE_TARGETS as ENV_TARGETS,
  ENV_GITHUB_MERGE_TARGETS_EXTRA as ENV_TARGETS_EXTRA,
} from "../config";
import {
  buildGithubWriteAllowlistState,
  type GithubWriteAllowlistState,
  type GithubWriteAllowlistSummary,
  isGithubWriteTargetAllowed,
  parseGithubTargets,
  summarizeGithubWriteAllowlist,
} from "./github-write-targets";

export { ENV_TARGETS, ENV_TARGETS_EXTRA };

/** Whether `owner/repo` is in the MERGE allowlist (default-deny: `off` → false). The
 *  match logic is identical to the write allowlist — only the backing state (built from
 *  the MERGE env vars below) differs. */
export function isGithubMergeTargetAllowed(
  owner: string,
  repo: string,
  state: GithubWriteAllowlistState,
): boolean {
  return isGithubWriteTargetAllowed(owner, repo, state);
}

export function summarizeGithubMergeAllowlist(
  state: GithubWriteAllowlistState,
): GithubWriteAllowlistSummary {
  return summarizeGithubWriteAllowlist(state);
}

// ----- per-process singleton (load-once, MCP-restart-clears) — own state, separate
// from the write-targets singleton so the two allowlists never alias -----

let cachedState: GithubWriteAllowlistState | undefined;
let warnEmitted = false;

/** Load the MERGE allowlist state once per process. WARN-ONCE on _EXTRA-without-base +
 *  on malformed tokens at load (mirrors github-write-targets). */
export function getGithubMergeAllowlistState(): GithubWriteAllowlistState {
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
      "[safespace] WARNING: SAFESPACE_GITHUB_MERGE_TARGETS_EXTRA is set but " +
        "SAFESPACE_GITHUB_MERGE_TARGETS is not. The merge allowlist is in default-deny " +
        "mode with EXTRA only. If you intended to leave merges OFF, also unset " +
        "SAFESPACE_GITHUB_MERGE_TARGETS_EXTRA.",
    );
    warnEmitted = true;
  }

  const baseParsed = parseGithubTargets(targetsEnv);
  const extraParsed = parseGithubTargets(extraEnv);
  for (const rej of [...baseParsed.rejected, ...extraParsed.rejected]) {
    // Operator-supplied config (process env), NOT attacker-controlled — safe to log.
    console.error(
      `[safespace] WARNING: SAFESPACE_GITHUB_MERGE_TARGETS rejected malformed entry: ${rej}`,
    );
  }

  cachedState = buildGithubWriteAllowlistState(targetsEnv, extraEnv);

  if (cachedState.kind === "active" && cachedState.targets.length === 0) {
    console.error(
      "[safespace] WARNING: SAFESPACE_GITHUB_MERGE_TARGETS is set but yielded 0 valid " +
        "entries — merges will be hard-denied. Check syntax: comma-separated " +
        "`owner/repo` (e.g. `octocat/Hello-World`).",
    );
  }

  return cachedState;
}

// Test-only.
/** @internal */
export const __internal = {
  resetSingletons: (): void => {
    cachedState = undefined;
    warnEmitted = false;
  },
};
