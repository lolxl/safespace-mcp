// v1.90 — SAFESPACE_GITHUB_APPROVE_TARGETS: a SEPARATE default-deny allowlist for the
// APPROVE event of github_create_pull_request_review. Distinct from
// SAFESPACE_GITHUB_WRITE_TARGETS on purpose: an APPROVE review VOUCHES for a PR and —
// under branch protection — can UNBLOCK a merge, a strictly higher bar than a COMMENT /
// REQUEST_CHANGES review (which only comment or block). So the operator opts a repo into
// "the agent may APPROVE here" on its own list (a repo write-allowlisted for issues/PRs/
// review-comments is NOT thereby approve-allowlisted). This mirrors the merge allowlist's
// rationale exactly — approve and merge are the two GitHub actions that can advance a PR
// toward landing, so each gets its own opt-in list.
//
// The PARSE / MATCH / BUILD logic is identical to the write allowlist (same owner/repo
// shape, case-insensitive, two-layer base+EXTRA, default-deny), so this module REUSES
// the pure exports of github-write-targets and adds only the approve-specific env wiring
// + its own per-process singleton + warn-once. (Same DRY-within-convention split as
// github-merge-targets.ts: reuse the pure core, own the stateful surface.)

import {
  ENV_GITHUB_APPROVE_TARGETS as ENV_TARGETS,
  ENV_GITHUB_APPROVE_TARGETS_EXTRA as ENV_TARGETS_EXTRA,
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

/** Whether `owner/repo` is in the APPROVE allowlist (default-deny: `off` → false). The
 *  match logic is identical to the write allowlist — only the backing state (built from
 *  the APPROVE env vars below) differs. */
export function isGithubApproveTargetAllowed(
  owner: string,
  repo: string,
  state: GithubWriteAllowlistState,
): boolean {
  return isGithubWriteTargetAllowed(owner, repo, state);
}

export function summarizeGithubApproveAllowlist(
  state: GithubWriteAllowlistState,
): GithubWriteAllowlistSummary {
  return summarizeGithubWriteAllowlist(state);
}

// ----- per-process singleton (load-once, MCP-restart-clears) — own state, separate
// from the write-targets + merge-targets singletons so the allowlists never alias -----

let cachedState: GithubWriteAllowlistState | undefined;
let warnEmitted = false;

/** Load the APPROVE allowlist state once per process. WARN-ONCE on _EXTRA-without-base +
 *  on malformed tokens at load (mirrors github-write-targets / github-merge-targets). */
export function getGithubApproveAllowlistState(): GithubWriteAllowlistState {
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
      "[safespace] WARNING: SAFESPACE_GITHUB_APPROVE_TARGETS_EXTRA is set but " +
        "SAFESPACE_GITHUB_APPROVE_TARGETS is not. The approve allowlist is in default-deny " +
        "mode with EXTRA only. If you intended to leave approvals OFF, also unset " +
        "SAFESPACE_GITHUB_APPROVE_TARGETS_EXTRA.",
    );
    warnEmitted = true;
  }

  const baseParsed = parseGithubTargets(targetsEnv);
  const extraParsed = parseGithubTargets(extraEnv);
  for (const rej of [...baseParsed.rejected, ...extraParsed.rejected]) {
    // Operator-supplied config (process env), NOT attacker-controlled — safe to log.
    console.error(
      `[safespace] WARNING: SAFESPACE_GITHUB_APPROVE_TARGETS rejected malformed entry: ${rej}`,
    );
  }

  cachedState = buildGithubWriteAllowlistState(targetsEnv, extraEnv);

  if (cachedState.kind === "active" && cachedState.targets.length === 0) {
    console.error(
      "[safespace] WARNING: SAFESPACE_GITHUB_APPROVE_TARGETS is set but yielded 0 valid " +
        "entries — approvals will be hard-denied. Check syntax: comma-separated " +
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
