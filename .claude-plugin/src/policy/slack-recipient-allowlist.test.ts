// v1.95 — Slack recipient allowlist: id-shape parse, exact match, the two-layer env,
// default-allow vs autonomous deny-by-default. Mirrors the Discord/Telegram suites.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  ENV_SK_ALLOW,
  ENV_SK_ALLOW_EXTRA,
  getSlackAllowlistState,
  isSlackRecipientAllowed,
  SLACK_CHANNEL_ID_RE,
  slackAllowlistSummary,
} from "./slack-recipient-allowlist";

const C1 = "C0123456789"; // channel
const C2 = "C9876543210";
const GRP = "G0123456ABC"; // private group
const DM = "D0123456789"; // DM conversation
const USR = "U0123456789"; // user id (DM target)
const MIN = "C012345"; // C + 6 = 7 chars (min)
const MAX = "C01234567890123456789"; // C + 20 chars (max)

const saved: Record<string, string | undefined> = {};
const ENV = [ENV_SK_ALLOW, ENV_SK_ALLOW_EXTRA, "SAFESPACE_AUTONOMOUS"];

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

describe("SLACK_CHANNEL_ID_RE", () => {
  test("accepts channel/group/DM/user ids across the length range", () => {
    expect(SLACK_CHANNEL_ID_RE.test(C1)).toBe(true);
    expect(SLACK_CHANNEL_ID_RE.test(GRP)).toBe(true);
    expect(SLACK_CHANNEL_ID_RE.test(DM)).toBe(true);
    expect(SLACK_CHANNEL_ID_RE.test(USR)).toBe(true);
    expect(SLACK_CHANNEL_ID_RE.test(MIN)).toBe(true);
    expect(SLACK_CHANNEL_ID_RE.test(MAX)).toBe(true);
    expect(SLACK_CHANNEL_ID_RE.test("W0123456789")).toBe(true); // enterprise user id
  });

  test("rejects malformed", () => {
    expect(SLACK_CHANNEL_ID_RE.test("C01234")).toBe(false); // 6 chars (too short)
    expect(SLACK_CHANNEL_ID_RE.test(`C${"0".repeat(21)}`)).toBe(false); // 22 chars (too long)
    expect(SLACK_CHANNEL_ID_RE.test("X0123456789")).toBe(false); // bad prefix
    expect(SLACK_CHANNEL_ID_RE.test("c0123456789")).toBe(false); // lowercase prefix
    expect(SLACK_CHANNEL_ID_RE.test("C012345678z")).toBe(false); // lowercase in body
    expect(SLACK_CHANNEL_ID_RE.test("#general")).toBe(false); // name, not id
    expect(SLACK_CHANNEL_ID_RE.test("@user")).toBe(false); // name, not id
    expect(SLACK_CHANNEL_ID_RE.test(`${C1}\n`)).toBe(false); // CRLF guard (anchored)
    expect(SLACK_CHANNEL_ID_RE.test("C012 3456789")).toBe(false); // whitespace
    expect(SLACK_CHANNEL_ID_RE.test("")).toBe(false); // empty
  });
});

describe("getSlackAllowlistState", () => {
  test("unset → off", () => {
    expect(getSlackAllowlistState()).toEqual({ kind: "off" });
  });

  test("active = union of ALLOW + EXTRA, malformed tokens dropped", () => {
    process.env[ENV_SK_ALLOW] = `${C1}, not-an-id , ${MAX}`;
    process.env[ENV_SK_ALLOW_EXTRA] = `${GRP}`;
    const state = getSlackAllowlistState();
    expect(state.kind).toBe("active");
    if (state.kind !== "active") throw new Error("unreachable");
    expect([...state.ids].sort()).toEqual([C1, MAX, GRP].sort());
  });

  test("only-malformed tokens → off (no valid id)", () => {
    process.env[ENV_SK_ALLOW] = "garbage, #also-garbage";
    expect(getSlackAllowlistState()).toEqual({ kind: "off" });
  });
});

describe("isSlackRecipientAllowed", () => {
  test("active: exact membership only", () => {
    process.env[ENV_SK_ALLOW] = C1;
    const state = getSlackAllowlistState();
    expect(isSlackRecipientAllowed(C1, state)).toBe(true);
    expect(isSlackRecipientAllowed(C2, state)).toBe(false);
  });

  test("off + interactive → ALLOW (default-allow, tier-gated private surface)", () => {
    const state = getSlackAllowlistState(); // off
    expect(isSlackRecipientAllowed(C1, state)).toBe(true);
  });

  test("off + autonomous → DENY ALL (F2 deny-by-default)", () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    const state = getSlackAllowlistState(); // off
    expect(isSlackRecipientAllowed(C1, state)).toBe(false);
  });

  test("active + autonomous → still exact membership (allowlist overrides deny-default)", () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    process.env[ENV_SK_ALLOW] = C1;
    const state = getSlackAllowlistState();
    expect(isSlackRecipientAllowed(C1, state)).toBe(true);
    expect(isSlackRecipientAllowed(C2, state)).toBe(false);
  });
});

describe("slackAllowlistSummary (count-only, never ids)", () => {
  test("off → id_count 0", () => {
    expect(slackAllowlistSummary()).toEqual({ kind: "off", id_count: 0 });
  });
  test("active → id_count, no id values", () => {
    process.env[ENV_SK_ALLOW] = `${C1},${MAX}`;
    expect(slackAllowlistSummary()).toEqual({ kind: "active", id_count: 2 });
  });
});
