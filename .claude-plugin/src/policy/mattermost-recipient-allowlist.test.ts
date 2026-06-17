// v1.107 — Mattermost recipient (channel_id) allowlist.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  ENV_MM_ALLOW,
  ENV_MM_ALLOW_EXTRA,
  MATTERMOST_ID_RE,
  getMattermostAllowlistState,
  isMattermostRecipientAllowed,
  mattermostAllowlistSummary,
} from "./mattermost-recipient-allowlist";
import { ENV_AUTONOMOUS } from "./autonomous-mode";

const VALID = "abcdefghijklmnopqrstuvwxyz"; // 26 chars [a-z0-9]
const VALID2 = "0123456789abcdefghijklmnop";
const ENV_KEYS = [ENV_MM_ALLOW, ENV_MM_ALLOW_EXTRA, ENV_AUTONOMOUS] as const;
let saved: Record<string, string | undefined>;

beforeEach(() => {
  saved = {};
  for (const k of ENV_KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
});
afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

describe("MATTERMOST_ID_RE", () => {
  test("accepts exactly 26 lowercase [a-z0-9]; rejects wrong length / uppercase / separators", () => {
    expect(MATTERMOST_ID_RE.test(VALID)).toBe(true);
    expect(MATTERMOST_ID_RE.test("tooshort")).toBe(false);
    expect(MATTERMOST_ID_RE.test(VALID.toUpperCase())).toBe(false);
    expect(MATTERMOST_ID_RE.test("abc/../../etc/passwd000000")).toBe(false);
    expect(MATTERMOST_ID_RE.test(VALID + "x")).toBe(false);
  });
});

describe("getMattermostAllowlistState", () => {
  test("unset → off", () => {
    expect(getMattermostAllowlistState()).toEqual({ kind: "off" });
  });
  test("valid ids in base + extra → active union, malformed dropped", () => {
    process.env[ENV_MM_ALLOW] = `${VALID}, not-an-id`;
    process.env[ENV_MM_ALLOW_EXTRA] = VALID2;
    const s = getMattermostAllowlistState();
    expect(s.kind).toBe("active");
    expect(mattermostAllowlistSummary().id_count).toBe(2);
  });
});

describe("isMattermostRecipientAllowed (service-token off→allow)", () => {
  test("off + interactive → allow; off + autonomous → deny", () => {
    expect(isMattermostRecipientAllowed(VALID, { kind: "off" })).toBe(true);
    process.env[ENV_AUTONOMOUS] = "true";
    expect(isMattermostRecipientAllowed(VALID, { kind: "off" })).toBe(false);
  });
  test("active → exact membership only", () => {
    process.env[ENV_MM_ALLOW] = VALID;
    const s = getMattermostAllowlistState();
    expect(isMattermostRecipientAllowed(VALID, s)).toBe(true);
    expect(isMattermostRecipientAllowed(VALID2, s)).toBe(false);
  });
});

describe("mattermostAllowlistSummary (count-only, no ids)", () => {
  test("never surfaces an id", () => {
    process.env[ENV_MM_ALLOW] = VALID;
    const sum = mattermostAllowlistSummary();
    expect(sum).toEqual({ kind: "active", id_count: 1 });
    expect(JSON.stringify(sum)).not.toContain(VALID);
  });
});
