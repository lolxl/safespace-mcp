// v1.70 (G3) — GitHub flat-scope constants + the missing-scope check.

import { describe, expect, test } from "bun:test";
import {
  GITHUB_REQUIRED_SCOPES,
  GITHUB_V1_SCOPES,
  findMissingGithubScopes,
  githubScopeParam,
} from "./scopes";

describe("GitHub v1 scopes", () => {
  test("requests exactly read:user + repo (v1.83 — private-repo upgrade)", () => {
    expect([...GITHUB_V1_SCOPES]).toEqual(["read:user", "repo"]);
  });

  test("required === requested", () => {
    expect([...GITHUB_REQUIRED_SCOPES]).toEqual([...GITHUB_V1_SCOPES]);
  });

  test("a narrower public_repo does NOT satisfy the required repo scope (re-consent needed)", () => {
    // A pre-v1.83 grant carried only public_repo — exact-token membership means it is
    // missing `repo`, so a stale grant fails loudly at consent rather than 403-ing on
    // private repos at tool-call time.
    expect(findMissingGithubScopes("read:user,public_repo", GITHUB_REQUIRED_SCOPES)).toEqual(["repo"]);
  });

  test("githubScopeParam joins with spaces (authorize-URL form)", () => {
    expect(githubScopeParam()).toBe("read:user repo");
  });
});

describe("findMissingGithubScopes", () => {
  test("empty when comma-separated granted (token-exchange form) covers all", () => {
    expect(findMissingGithubScopes("read:user,repo", GITHUB_REQUIRED_SCOPES)).toEqual([]);
  });

  test("empty when space-separated granted covers all", () => {
    expect(findMissingGithubScopes("read:user repo", GITHUB_REQUIRED_SCOPES)).toEqual([]);
  });

  test("detects a shortfall (user granted fewer than requested)", () => {
    expect(findMissingGithubScopes("read:user", GITHUB_REQUIRED_SCOPES)).toEqual(["repo"]);
  });

  test("undefined granted → all required missing", () => {
    expect(findMissingGithubScopes(undefined, GITHUB_REQUIRED_SCOPES)).toEqual([
      "read:user",
      "repo",
    ]);
  });

  test("empty string granted → all required missing", () => {
    expect(findMissingGithubScopes("", GITHUB_REQUIRED_SCOPES)).toEqual([
      "read:user",
      "repo",
    ]);
  });

  test("exact-token match — a superstring does NOT satisfy (no substring matching)", () => {
    // neither `repository` (superstring) nor `public_repo` (narrower) satisfies `repo`.
    expect(findMissingGithubScopes("repository,public_repo,read:user_y", GITHUB_REQUIRED_SCOPES)).toEqual([
      "read:user",
      "repo",
    ]);
  });

  test("extra granted scopes (e.g. gist / workflow) are ignored, not a shortfall", () => {
    expect(findMissingGithubScopes("read:user,repo,gist,workflow", GITHUB_REQUIRED_SCOPES)).toEqual([]);
  });
});
