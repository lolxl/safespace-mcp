// v1.68 — Telegram recipient allowlist: chat_id-shape parse, exact match, the
// two-layer env, default-allow vs autonomous deny-by-default. Mirrors the LINE suite.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  ENV_TG_ALLOW,
  ENV_TG_ALLOW_EXTRA,
  getTelegramAllowlistState,
  isTelegramRecipientAllowed,
  TELEGRAM_CHAT_ID_RE,
  telegramAllowlistSummary,
} from "./telegram-recipient-allowlist";

const N1 = "123456789"; // private user
const N2 = "987654321";
const G1 = "-1001234567890"; // supergroup / channel
const U1 = "@my_channel"; // public username

const saved: Record<string, string | undefined> = {};
const ENV = [ENV_TG_ALLOW, ENV_TG_ALLOW_EXTRA, "SAFESPACE_AUTONOMOUS"];

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

describe("TELEGRAM_CHAT_ID_RE", () => {
  test("accepts numeric ids (±, -100…) and @username", () => {
    expect(TELEGRAM_CHAT_ID_RE.test(N1)).toBe(true);
    expect(TELEGRAM_CHAT_ID_RE.test(G1)).toBe(true);
    expect(TELEGRAM_CHAT_ID_RE.test("-100")).toBe(true);
    expect(TELEGRAM_CHAT_ID_RE.test(U1)).toBe(true);
    expect(TELEGRAM_CHAT_ID_RE.test("@abcde")).toBe(true); // 5-char username (min)
  });

  test("rejects malformed", () => {
    expect(TELEGRAM_CHAT_ID_RE.test("12.5")).toBe(false); // decimal
    expect(TELEGRAM_CHAT_ID_RE.test("+123")).toBe(false); // leading +
    expect(TELEGRAM_CHAT_ID_RE.test(`${N1}\n`)).toBe(false); // CRLF guard (anchored)
    expect(TELEGRAM_CHAT_ID_RE.test("@abcd")).toBe(false); // username too short (4)
    expect(TELEGRAM_CHAT_ID_RE.test("@1abcd")).toBe(false); // username starts with digit
    expect(TELEGRAM_CHAT_ID_RE.test("@bad-name")).toBe(false); // hyphen not allowed
    expect(TELEGRAM_CHAT_ID_RE.test("abc")).toBe(false); // neither numeric nor @
    expect(TELEGRAM_CHAT_ID_RE.test("")).toBe(false); // empty
    expect(TELEGRAM_CHAT_ID_RE.test("1".repeat(21))).toBe(false); // > 20 digits
    expect(TELEGRAM_CHAT_ID_RE.test("123 456")).toBe(false); // whitespace
  });
});

describe("getTelegramAllowlistState", () => {
  test("unset → off", () => {
    expect(getTelegramAllowlistState()).toEqual({ kind: "off" });
  });

  test("active = union of ALLOW + EXTRA, malformed tokens dropped", () => {
    process.env[ENV_TG_ALLOW] = `${N1}, not-an-id , ${G1}`;
    process.env[ENV_TG_ALLOW_EXTRA] = `${U1}`;
    const state = getTelegramAllowlistState();
    expect(state.kind).toBe("active");
    if (state.kind !== "active") throw new Error("unreachable");
    expect([...state.ids].sort()).toEqual([N1, G1, U1].sort());
  });

  test("only-malformed tokens → off (no valid id)", () => {
    process.env[ENV_TG_ALLOW] = "garbage, also-garbage";
    expect(getTelegramAllowlistState()).toEqual({ kind: "off" });
  });
});

describe("isTelegramRecipientAllowed", () => {
  test("active: exact membership only", () => {
    process.env[ENV_TG_ALLOW] = N1;
    const state = getTelegramAllowlistState();
    expect(isTelegramRecipientAllowed(N1, state)).toBe(true);
    expect(isTelegramRecipientAllowed(N2, state)).toBe(false);
  });

  test("off + interactive → ALLOW (default-allow, tier-gated private surface)", () => {
    const state = getTelegramAllowlistState(); // off
    expect(isTelegramRecipientAllowed(N1, state)).toBe(true);
  });

  test("off + autonomous → DENY ALL (F2 deny-by-default)", () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    const state = getTelegramAllowlistState(); // off
    expect(isTelegramRecipientAllowed(N1, state)).toBe(false);
  });

  test("active + autonomous → still exact membership (allowlist overrides deny-default)", () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    process.env[ENV_TG_ALLOW] = N1;
    const state = getTelegramAllowlistState();
    expect(isTelegramRecipientAllowed(N1, state)).toBe(true);
    expect(isTelegramRecipientAllowed(N2, state)).toBe(false);
  });
});

describe("telegramAllowlistSummary (count-only, never ids)", () => {
  test("off → id_count 0", () => {
    expect(telegramAllowlistSummary()).toEqual({ kind: "off", id_count: 0 });
  });
  test("active → id_count, no id values", () => {
    process.env[ENV_TG_ALLOW] = `${N1},${G1}`;
    expect(telegramAllowlistSummary()).toEqual({ kind: "active", id_count: 2 });
  });
});
