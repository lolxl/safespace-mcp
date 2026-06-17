// v1.71 — the GitHub WRITE target allowlist (PUBLIC-surface DEFAULT-DENY).

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  ENV_TARGETS,
  ENV_TARGETS_EXTRA,
  __internal,
  buildGithubWriteAllowlistState,
  getGithubWriteAllowlistState,
  isGithubWriteTargetAllowed,
  parseGithubTargets,
} from "./github-write-targets";

const saved: Record<string, string | undefined> = {};
beforeEach(() => {
  for (const k of [ENV_TARGETS, ENV_TARGETS_EXTRA]) saved[k] = process.env[k];
  for (const k of [ENV_TARGETS, ENV_TARGETS_EXTRA]) delete process.env[k];
  __internal.resetSingletons();
});
afterEach(() => {
  for (const k of [ENV_TARGETS, ENV_TARGETS_EXTRA]) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
  __internal.resetSingletons();
});

describe("parseGithubTargets", () => {
  test("parses owner/repo, lowercases, dedups; tolerates extra commas/whitespace", () => {
    const r = parseGithubTargets("OctoCat/Hello-World, octocat/hello-world ,  a/b ,");
    expect(r.ok).toEqual([
      { owner: "octocat", repo: "hello-world" }, // first wins; the dup is dropped
      { owner: "a", repo: "b" },
    ]);
    expect(r.rejected).toEqual([]);
  });

  test("rejects malformed entries (no slash, extra slash, bad chars, '..')", () => {
    const r = parseGithubTargets("noslash, a/b/c, a b/c, a/.., ../b, a/b");
    expect(r.ok).toEqual([{ owner: "a", repo: "b" }]);
    expect(r.rejected.sort()).toEqual(["../b", "a b/c", "a/..", "a/b/c", "noslash"].sort());
  });

  test("undefined input → empty", () => {
    expect(parseGithubTargets(undefined)).toEqual({ ok: [], rejected: [] });
  });
});

describe("isGithubWriteTargetAllowed — DEFAULT-DENY", () => {
  test("state off (env unset) → ALWAYS false (hard-deny, even a valid repo)", () => {
    expect(isGithubWriteTargetAllowed("octocat", "hello-world", { kind: "off" })).toBe(false);
  });

  test("active + match (case-insensitive) → true", () => {
    const state = buildGithubWriteAllowlistState("octocat/hello-world", undefined);
    expect(isGithubWriteTargetAllowed("octocat", "hello-world", state)).toBe(true);
    expect(isGithubWriteTargetAllowed("OctoCat", "Hello-World", state)).toBe(true); // case-insensitive
  });

  test("active + no match → false", () => {
    const state = buildGithubWriteAllowlistState("octocat/hello-world", undefined);
    expect(isGithubWriteTargetAllowed("octocat", "other-repo", state)).toBe(false);
    expect(isGithubWriteTargetAllowed("someone", "hello-world", state)).toBe(false);
  });

  test("active but ZERO valid entries (env set to garbage) → hard-deny", () => {
    const state = buildGithubWriteAllowlistState("not-a-repo", undefined);
    expect(state.kind).toBe("active");
    expect(isGithubWriteTargetAllowed("anything", "atall", state)).toBe(false);
  });
});

describe("buildGithubWriteAllowlistState — two-layer", () => {
  test("both undefined → off", () => {
    expect(buildGithubWriteAllowlistState(undefined, undefined)).toEqual({ kind: "off" });
  });

  test("base + EXTRA merge + dedup", () => {
    const state = buildGithubWriteAllowlistState("a/b", "c/d, a/b");
    expect(state).toEqual({ kind: "active", targets: [{ owner: "a", repo: "b" }, { owner: "c", repo: "d" }] });
  });

  test('EXTRA only (base undefined) → active (explicit default-deny posture)', () => {
    const state = buildGithubWriteAllowlistState(undefined, "c/d");
    expect(state.kind).toBe("active");
  });
});

describe("getGithubWriteAllowlistState — singleton + env", () => {
  test("env unset → off → every write hard-denied", () => {
    const state = getGithubWriteAllowlistState();
    expect(state.kind).toBe("off");
    expect(isGithubWriteTargetAllowed("octocat", "hello-world", state)).toBe(false);
  });

  test("env set → active + allows the listed repo only", () => {
    process.env[ENV_TARGETS] = "octocat/hello-world";
    __internal.resetSingletons();
    const state = getGithubWriteAllowlistState();
    expect(isGithubWriteTargetAllowed("octocat", "hello-world", state)).toBe(true);
    expect(isGithubWriteTargetAllowed("octocat", "evil", state)).toBe(false);
  });
});
