// v1.115 — the X POST account allowlist (PUBLIC-surface DEFAULT-DENY).

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  ENV_TARGETS,
  ENV_TARGETS_EXTRA,
  __internal,
  buildXPostAllowlistState,
  getXPostAllowlistState,
  isXPostAccountAllowed,
  parseXPostAccounts,
  summarizeXPostAllowlist,
} from "./x-post-allowlist";

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

describe("parseXPostAccounts", () => {
  test("parses numeric ids, dedups; tolerates extra commas/whitespace", () => {
    const r = parseXPostAccounts("2244994945, 2244994945 ,  12 ,");
    expect(r.ok).toEqual(["2244994945", "12"]);
    expect(r.rejected).toEqual([]);
  });

  test("rejects non-digit / empty-after-trim / over-32-digit tokens", () => {
    const long = "1".repeat(33);
    const r = parseXPostAccounts(`noslash, @handle, 12a, ${long}, 42`);
    expect(r.ok).toEqual(["42"]);
    expect(r.rejected.sort()).toEqual(["@handle", "12a", long, "noslash"].sort());
  });

  test("undefined input → empty", () => {
    expect(parseXPostAccounts(undefined)).toEqual({ ok: [], rejected: [] });
  });

  test("1-digit and 32-digit ids accepted", () => {
    const id32 = "9".repeat(32);
    const r = parseXPostAccounts(`0,${id32}`);
    expect(r.ok).toEqual(["0", id32]);
    expect(r.rejected).toEqual([]);
  });
});

describe("isXPostAccountAllowed — DEFAULT-DENY", () => {
  test("state off (env unset) → ALWAYS false (hard-deny, even a valid id)", () => {
    expect(isXPostAccountAllowed("2244994945", { kind: "off" })).toBe(false);
  });

  test("active + match → true", () => {
    const state = buildXPostAllowlistState("2244994945", undefined);
    expect(isXPostAccountAllowed("2244994945", state)).toBe(true);
  });

  test("active + no match → false", () => {
    const state = buildXPostAllowlistState("2244994945", undefined);
    expect(isXPostAccountAllowed("999", state)).toBe(false);
  });

  test("active but ZERO valid entries (env set to garbage) → hard-deny", () => {
    const state = buildXPostAllowlistState("not-an-id", undefined);
    expect(state.kind).toBe("active");
    expect(isXPostAccountAllowed("anything", state)).toBe(false);
  });
});

describe("buildXPostAllowlistState — two-layer", () => {
  test("both undefined → off", () => {
    expect(buildXPostAllowlistState(undefined, undefined)).toEqual({ kind: "off" });
  });

  test("base + EXTRA merge + dedup", () => {
    const state = buildXPostAllowlistState("1", "2, 1");
    expect(state.kind).toBe("active");
    if (state.kind === "active") {
      expect([...state.accountIds].sort()).toEqual(["1", "2"]);
    }
  });

  test("EXTRA only (base undefined) → active (explicit default-deny posture)", () => {
    const state = buildXPostAllowlistState(undefined, "3");
    expect(state.kind).toBe("active");
  });
});

describe("summarizeXPostAllowlist — counts only", () => {
  test("off → count 0; active → size", () => {
    expect(summarizeXPostAllowlist({ kind: "off" })).toEqual({ kind: "off", count: 0 });
    expect(
      summarizeXPostAllowlist({ kind: "active", accountIds: new Set(["1", "2"]) }),
    ).toEqual({ kind: "active", count: 2 });
  });
});

describe("getXPostAllowlistState — singleton + env", () => {
  test("env unset → off → every post hard-denied", () => {
    const state = getXPostAllowlistState();
    expect(state.kind).toBe("off");
    expect(isXPostAccountAllowed("2244994945", state)).toBe(false);
  });

  test("env set → active + allows the listed id only", () => {
    process.env[ENV_TARGETS] = "2244994945";
    __internal.resetSingletons();
    const state = getXPostAllowlistState();
    expect(isXPostAccountAllowed("2244994945", state)).toBe(true);
    expect(isXPostAccountAllowed("999", state)).toBe(false);
  });
});
