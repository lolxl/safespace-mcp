// v1.70 (G3) — GitHub OAuth scopes (flat).
//
// GitHub scopes are a FLAT space (`read:user`, `public_repo`, `repo`, …) — there
// is no SCOPE_HIERARCHY / URL-prefix machinery like Google's (that lives in the
// leaf auth/scopes.ts and is google-workspace-only, per the thesis §4 demotion).
// So GitHub's scope handling is a tiny set-membership check, kept entirely in
// this leaf module rather than threaded through the generic gateway.
//
// Scope set (v1.83 — upgraded public_repo → repo for private-repo support):
//   - read:user → GET /user (the consent identity step) + profile reads.
//   - repo      → full repository access, PUBLIC *and* PRIVATE (a superset of
//                 public_repo): reads + writes (issue / PR / comment / merge) on
//                 private repos too. Writes/merges to ANY repo stay bounded by the
//                 default-deny SAFESPACE_GITHUB_WRITE_TARGETS / _MERGE_TARGETS
//                 allowlists; private READS are bounded by OAuth consent + tier (no
//                 read allowlist — the egress gates bound what leaves the agent;
//                 v1.83 Q3=a). GitHub OAuth Apps have no finer private scope (per-repo
//                 = a GitHub App / fine-grained PAT, a separate auth model). v1.70
//                 shipped public_repo (minimal); this is the v1.50-style scope upgrade
//                 (re-consent) once a real private-repo need landed.

/** The scope set requested at consent (the GitHub authorize-URL `scope` param). */
export const GITHUB_V1_SCOPES: readonly string[] = ["read:user", "repo"];

/** The scopes we REQUIRE the granted token to carry — identical to the requested
 *  set for the v1 read connector. A consent that granted fewer (the user edited
 *  the grant, or a pre-existing narrower authorization was reused) fails loudly
 *  at consent rather than surfacing as opaque GitHub 403s at tool-call time. */
export const GITHUB_REQUIRED_SCOPES: readonly string[] = GITHUB_V1_SCOPES;

/** The space-separated `scope` value for the authorize URL. GitHub accepts space
 *  (or `+`) separation in the request; it ECHOES granted scopes comma-separated
 *  in the token-exchange response (handled by {@link findMissingGithubScopes}). */
export function githubScopeParam(): string {
  return GITHUB_V1_SCOPES.join(" ");
}

/** Which of `required` are absent from `grantedString`. GitHub's token-exchange
 *  response returns the granted scopes as a COMMA-separated string (e.g.
 *  `"read:user,repo"`); other surfaces use spaces — so we split on either.
 *  Exact-token membership (no substring matching) so required `repo` is never
 *  satisfied by a narrower `public_repo` (a pre-v1.83 grant) or an unrelated token. */
export function findMissingGithubScopes(
  grantedString: string | undefined,
  required: readonly string[],
): string[] {
  const granted = new Set((grantedString ?? "").split(/[\s,]+/).filter(Boolean));
  return required.filter((s) => !granted.has(s));
}
