// v1.66 Phase C PR 2 — LINE recipient allowlist: id-shape parse, exact match, the
// two-layer env, default-allow vs autonomous deny-by-default.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  ENV_LINE_ALLOW,
  ENV_LINE_ALLOW_EXTRA,
  getLineAllowlistState,
  isLineRecipientAllowed,
  LINE_ID_RE,
  lineAllowlistSummary,
} from "./line-recipient-allowlist";

const U1 = "U" + "0".repeat(32);
const U2 = "U" + "1".repeat(32);
const C1 = "C" + "a".repeat(32);
const R1 = "R" + "f".repeat(32);

const saved: Record<string, string | undefined> = {};
const ENV = [ENV_LINE_ALLOW, ENV_LINE_ALLOW_EXTRA, "SAFESPACE_AUTONOMOUS"];

beforeEach(() => {
  for (const k of ENV) saved[k] = process.env[k];
  for (const k of ENV) delete process.env[k];
});
afterEach(() => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
});

describe("LINE_ID_RE", () => {
  test("accepts U/C/R + 32 hex; rejects malformed", () => {
    expect(LINE_ID_RE.test(U1)).toBe(true);
    expect(LINE_ID_RE.test(C1)).toBe(true);
    expect(LINE_ID_RE.test(R1)).toBe(true);
    expect(LINE_ID_RE.test("U" + "0".repeat(31))).toBe(false); // too short
    expect(LINE_ID_RE.test("X" + "0".repeat(32))).toBe(false); // bad prefix
    expect(LINE_ID_RE.test("U" + "G".repeat(32))).toBe(false); // non-hex
    expect(LINE_ID_RE.test(U1 + "\n")).toBe(false); // CRLF guard (anchored)
    expect(LINE_ID_RE.test("u" + "0".repeat(32))).toBe(false); // lowercase prefix
  });
});

describe("getLineAllowlistState", () => {
  test("unset → off", () => {
    expect(getLineAllowlistState()).toEqual({ kind: "off" });
  });

  test("active = union of ALLOW + EXTRA, malformed tokens dropped", () => {
    process.env[ENV_LINE_ALLOW] = `${U1}, not-an-id , ${C1}`;
    process.env[ENV_LINE_ALLOW_EXTRA] = `${R1}`;
    const state = getLineAllowlistState();
    expect(state.kind).toBe("active");
    if (state.kind !== "active") throw new Error("unreachable");
    expect([...state.ids].sort()).toEqual([U1, C1, R1].sort());
  });

  test("only-malformed tokens → off (no valid id)", () => {
    process.env[ENV_LINE_ALLOW] = "garbage, also-garbage";
    expect(getLineAllowlistState()).toEqual({ kind: "off" });
  });
});

describe("isLineRecipientAllowed", () => {
  test("active: exact membership only", () => {
    process.env[ENV_LINE_ALLOW] = U1;
    const state = getLineAllowlistState();
    expect(isLineRecipientAllowed(U1, state)).toBe(true);
    expect(isLineRecipientAllowed(U2, state)).toBe(false);
  });

  test("off + interactive → ALLOW (default-allow, tier-gated private surface)", () => {
    const state = getLineAllowlistState(); // off
    expect(isLineRecipientAllowed(U1, state)).toBe(true);
  });

  test("off + autonomous → DENY ALL (F2 deny-by-default)", () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    const state = getLineAllowlistState(); // off
    expect(isLineRecipientAllowed(U1, state)).toBe(false);
  });

  test("active + autonomous → still exact membership (allowlist overrides deny-default)", () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    process.env[ENV_LINE_ALLOW] = U1;
    const state = getLineAllowlistState();
    expect(isLineRecipientAllowed(U1, state)).toBe(true);
    expect(isLineRecipientAllowed(U2, state)).toBe(false);
  });
});

describe("lineAllowlistSummary (count-only, never ids)", () => {
  test("off → id_count 0", () => {
    expect(lineAllowlistSummary()).toEqual({ kind: "off", id_count: 0 });
  });
  test("active → id_count, no id values", () => {
    process.env[ENV_LINE_ALLOW] = `${U1},${C1}`;
    expect(lineAllowlistSummary()).toEqual({ kind: "active", id_count: 2 });
  });
});
