// Additive unit tests for makeServiceTokenRecipientAllowlist (pack-aware factory).

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { LINE_PACK } from "../tools/service-token-pack";
import { makeServiceTokenRecipientAllowlist } from "./service-token-recipient-allowlist";

const U1 = "U" + "0".repeat(32);
const C1 = "C" + "1".repeat(32);
const ENV = [
  LINE_PACK.env.recipientAllow,
  LINE_PACK.env.recipientAllowExtra,
  "SAFESPACE_AUTONOMOUS",
];
const saved: Record<string, string | undefined> = {};

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

describe("makeServiceTokenRecipientAllowlist(LINE_PACK)", () => {
  const al = makeServiceTokenRecipientAllowlist(LINE_PACK);

  test("off when both env layers empty", () => {
    expect(al.getState()).toEqual({ kind: "off" });
    expect(al.summary()).toEqual({ kind: "off", id_count: 0 });
  });

  test("unions persistent + EXTRA; drops malformed tokens", () => {
    process.env[LINE_PACK.env.recipientAllow] = `${U1}, not-an-id`;
    process.env[LINE_PACK.env.recipientAllowExtra] = C1;
    const state = al.getState();
    expect(state.kind).toBe("active");
    if (state.kind === "active") {
      expect(state.ids.has(U1)).toBe(true);
      expect(state.ids.has(C1)).toBe(true);
      expect(state.ids.size).toBe(2);
    }
    expect(al.summary()).toEqual({ kind: "active", id_count: 2 });
  });

  test("off → allow interactive; deny under autonomous (F2)", () => {
    const state = al.getState();
    expect(al.isAllowed(U1, state)).toBe(true);
    process.env.SAFESPACE_AUTONOMOUS = "true";
    expect(al.isAllowed(U1, state)).toBe(false);
  });

  test("active → exact membership only", () => {
    process.env[LINE_PACK.env.recipientAllow] = U1;
    const state = al.getState();
    expect(al.isAllowed(U1, state)).toBe(true);
    expect(al.isAllowed(C1, state)).toBe(false);
  });
});
