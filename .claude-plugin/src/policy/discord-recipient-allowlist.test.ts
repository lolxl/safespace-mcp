// v1.69 — Discord recipient allowlist: channel_id-shape parse, exact match, the
// two-layer env, default-allow vs autonomous deny-by-default. Mirrors the Telegram suite.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  ENV_DC_ALLOW,
  ENV_DC_ALLOW_EXTRA,
  getDiscordAllowlistState,
  isDiscordRecipientAllowed,
  DISCORD_CHANNEL_ID_RE,
  discordAllowlistSummary,
} from "./discord-recipient-allowlist";

const C1 = "123456789012345678"; // 18-digit snowflake
const C2 = "987654321098765432";
const C17 = "12345678901234567"; // 17 digits (min)
const C20 = "12345678901234567890"; // 20 digits (max)

const saved: Record<string, string | undefined> = {};
const ENV = [ENV_DC_ALLOW, ENV_DC_ALLOW_EXTRA, "SAFESPACE_AUTONOMOUS"];

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

describe("DISCORD_CHANNEL_ID_RE", () => {
  test("accepts 17–20-digit snowflakes", () => {
    expect(DISCORD_CHANNEL_ID_RE.test(C1)).toBe(true);
    expect(DISCORD_CHANNEL_ID_RE.test(C17)).toBe(true);
    expect(DISCORD_CHANNEL_ID_RE.test(C20)).toBe(true);
  });

  test("rejects malformed", () => {
    expect(DISCORD_CHANNEL_ID_RE.test("1234567890123456")).toBe(false); // 16 (too short)
    expect(DISCORD_CHANNEL_ID_RE.test("123456789012345678901")).toBe(false); // 21 (too long)
    expect(DISCORD_CHANNEL_ID_RE.test("12345678901234567a")).toBe(false); // non-digit
    expect(DISCORD_CHANNEL_ID_RE.test("-123456789012345678")).toBe(false); // sign
    expect(DISCORD_CHANNEL_ID_RE.test("@my-channel")).toBe(false); // name, not id
    expect(DISCORD_CHANNEL_ID_RE.test(`${C1}\n`)).toBe(false); // CRLF guard (anchored)
    expect(DISCORD_CHANNEL_ID_RE.test("123 456789012345678")).toBe(false); // whitespace
    expect(DISCORD_CHANNEL_ID_RE.test("")).toBe(false); // empty
  });
});

describe("getDiscordAllowlistState", () => {
  test("unset → off", () => {
    expect(getDiscordAllowlistState()).toEqual({ kind: "off" });
  });

  test("active = union of ALLOW + EXTRA, malformed tokens dropped", () => {
    process.env[ENV_DC_ALLOW] = `${C1}, not-an-id , ${C20}`;
    process.env[ENV_DC_ALLOW_EXTRA] = `${C17}`;
    const state = getDiscordAllowlistState();
    expect(state.kind).toBe("active");
    if (state.kind !== "active") throw new Error("unreachable");
    expect([...state.ids].sort()).toEqual([C1, C20, C17].sort());
  });

  test("only-malformed tokens → off (no valid id)", () => {
    process.env[ENV_DC_ALLOW] = "garbage, also-garbage";
    expect(getDiscordAllowlistState()).toEqual({ kind: "off" });
  });
});

describe("isDiscordRecipientAllowed", () => {
  test("active: exact membership only", () => {
    process.env[ENV_DC_ALLOW] = C1;
    const state = getDiscordAllowlistState();
    expect(isDiscordRecipientAllowed(C1, state)).toBe(true);
    expect(isDiscordRecipientAllowed(C2, state)).toBe(false);
  });

  test("off + interactive → ALLOW (default-allow, tier-gated private surface)", () => {
    const state = getDiscordAllowlistState(); // off
    expect(isDiscordRecipientAllowed(C1, state)).toBe(true);
  });

  test("off + autonomous → DENY ALL (F2 deny-by-default)", () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    const state = getDiscordAllowlistState(); // off
    expect(isDiscordRecipientAllowed(C1, state)).toBe(false);
  });

  test("active + autonomous → still exact membership (allowlist overrides deny-default)", () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    process.env[ENV_DC_ALLOW] = C1;
    const state = getDiscordAllowlistState();
    expect(isDiscordRecipientAllowed(C1, state)).toBe(true);
    expect(isDiscordRecipientAllowed(C2, state)).toBe(false);
  });
});

describe("discordAllowlistSummary (count-only, never ids)", () => {
  test("off → id_count 0", () => {
    expect(discordAllowlistSummary()).toEqual({ kind: "off", id_count: 0 });
  });
  test("active → id_count, no id values", () => {
    process.env[ENV_DC_ALLOW] = `${C1},${C20}`;
    expect(discordAllowlistSummary()).toEqual({ kind: "active", id_count: 2 });
  });
});
