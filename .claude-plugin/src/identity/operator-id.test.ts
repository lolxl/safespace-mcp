// v1.36 BLOCKER 2 (audit actor) -- operator-id resolution tests.
//
// resolveOperatorId() reads $SAFESPACE_OPERATOR_ID (Model A: per-operator
// local process; the env var IS the operator identity for Model A -- see
// docs/v1.36-identity-tenancy-layer.md section 4.3 / Q2). Validation regex
// ^[A-Za-z0-9_.-]{1,64}$; unset OR invalid => null (single-user default,
// Q4 zero-impact). Invalid is fail-safe (stderr warn + null), mirroring
// tier.ts currentTier() typo handling: a malformed id never becomes a
// silently-trusted operator.
//
// NOTE: all non-printable / non-ASCII hostile inputs are built via
// String.fromCharCode(N) so this source file stays 100% printable-ASCII
// (no raw control bytes); the regex still sees the real character at runtime.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { isValidOperatorId, resolveOperatorId } from "./operator-id";

const NUL = String.fromCharCode(0);
const TAB = String.fromCharCode(9);
const LF = String.fromCharCode(10);
const CR = String.fromCharCode(13);
const LINE_SEP = String.fromCharCode(0x2028);
const E_ACUTE = String.fromCharCode(0xe9); // non-ASCII letter

let prevEnv: string | undefined;

beforeEach(() => {
  prevEnv = process.env.SAFESPACE_OPERATOR_ID;
});

afterEach(() => {
  if (prevEnv === undefined) delete process.env.SAFESPACE_OPERATOR_ID;
  else process.env.SAFESPACE_OPERATOR_ID = prevEnv;
});

describe("isValidOperatorId -- pure validator (Q2 regex ^[A-Za-z0-9_.-]{1,64}$)", () => {
  test("accepts the four allowed character classes", () => {
    expect(isValidOperatorId("alice")).toBe(true);
    expect(isValidOperatorId("Bob_99")).toBe(true);
    expect(isValidOperatorId("ci.bot-1")).toBe(true);
    expect(isValidOperatorId("A.b_c-D.0")).toBe(true);
  });

  test("accepts boundary lengths 1 and 64", () => {
    expect(isValidOperatorId("a")).toBe(true);
    expect(isValidOperatorId("a".repeat(64))).toBe(true);
  });

  test("rejects empty and overlong (65)", () => {
    expect(isValidOperatorId("")).toBe(false);
    expect(isValidOperatorId("a".repeat(65))).toBe(false);
  });

  test("rejects whitespace / control chars", () => {
    expect(isValidOperatorId("alice bob")).toBe(false); // space
    expect(isValidOperatorId("a" + LF + "b")).toBe(false);
    expect(isValidOperatorId("a" + CR + "b")).toBe(false);
    expect(isValidOperatorId("a" + NUL + "b")).toBe(false);
    expect(isValidOperatorId("a" + LINE_SEP + "b")).toBe(false);
    expect(isValidOperatorId(TAB + "ab")).toBe(false);
  });

  test("rejects injection-y / structural / unicode chars", () => {
    expect(isValidOperatorId("a/b")).toBe(false); // slash
    expect(isValidOperatorId("<script>")).toBe(false); // angle brackets
    expect(isValidOperatorId('a"b')).toBe(false); // quote (JSON-injection-y)
    expect(isValidOperatorId("caf" + E_ACUTE)).toBe(false); // non-ASCII
    expect(isValidOperatorId("ops@team")).toBe(false); // @ (NOT a Google email)
  });
});

describe("resolveOperatorId -- env reader (Q4 unset => null)", () => {
  test("unset env => null (single-user default)", () => {
    delete process.env.SAFESPACE_OPERATOR_ID;
    expect(resolveOperatorId()).toBeNull();
  });

  test("empty string env => null", () => {
    process.env.SAFESPACE_OPERATOR_ID = "";
    expect(resolveOperatorId()).toBeNull();
  });

  test("valid id => returned verbatim", () => {
    process.env.SAFESPACE_OPERATOR_ID = "alice.ops-1";
    expect(resolveOperatorId()).toBe("alice.ops-1");
  });

  test("invalid id => null (fail-safe, no throw)", () => {
    process.env.SAFESPACE_OPERATOR_ID = "has space";
    expect(resolveOperatorId()).toBeNull();
  });

  test("overlong id => null (fail-safe)", () => {
    process.env.SAFESPACE_OPERATOR_ID = "x".repeat(65);
    expect(resolveOperatorId()).toBeNull();
  });

  test("never throws on hostile JSON-injection input", () => {
    process.env.SAFESPACE_OPERATOR_ID = '","account":"evil@x.com';
    expect(() => resolveOperatorId()).not.toThrow();
    expect(resolveOperatorId()).toBeNull();
  });
});
