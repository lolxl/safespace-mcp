// Additive unit tests for ServiceTokenPack / LINE_PACK (pack step 1) + the
// SERVICE_TOKEN_PACKS completeness sentinel (pack step 2).

import { describe, expect, test } from "bun:test";
import type { ServiceName } from "../auth/service-token-store";
import {
  ENV_LINE_CHANNEL_TOKEN,
  ENV_LINE_RECIPIENT_ALLOW,
  ENV_LINE_RECIPIENT_ALLOW_EXTRA,
} from "../config";
import {
  DISCORD_PACK,
  LINE_PACK,
  MATTERMOST_PACK,
  SERVICE_TOKEN_PACKS,
  SLACK_PACK,
  TELEGRAM_PACK,
  type ServiceTokenPack,
} from "./service-token-pack";

describe("LINE_PACK", () => {
  test("identity + store + errorName match the pre-pack LINE constants", () => {
    expect(LINE_PACK.id).toBe("line");
    expect(LINE_PACK.storeKey).toBe("line");
    expect(LINE_PACK.errorName).toBe("line_api_failed");
  });

  test("env names are the config constants (single source of truth)", () => {
    expect(LINE_PACK.env.recipientAllow).toBe(ENV_LINE_RECIPIENT_ALLOW);
    expect(LINE_PACK.env.recipientAllowExtra).toBe(ENV_LINE_RECIPIENT_ALLOW_EXTRA);
    expect(LINE_PACK.env.token).toBe(ENV_LINE_CHANNEL_TOKEN);
  });

  test("recipient id regex accepts U/C/R + 32 hex and rejects garbage", () => {
    const re = LINE_PACK.recipientIdSpec.regex;
    expect(re.test("U" + "0".repeat(32))).toBe(true);
    expect(re.test("C" + "a".repeat(32))).toBe(true);
    expect(re.test("R" + "f".repeat(32))).toBe(true);
    expect(re.test("X" + "0".repeat(32))).toBe(false);
    expect(re.test("U" + "0".repeat(31))).toBe(false);
    expect(re.test("U" + "0".repeat(32) + "\n")).toBe(false);
  });

  test("skipFields covers the LINE opaque keys previously inlined in source.ts", () => {
    for (const k of ["userId", "groupId", "roomId", "to", "messageId", "quoteToken"]) {
      expect(LINE_PACK.skipFields.has(k)).toBe(true);
    }
  });

  test("cli labels preserve the pre-pack LINE user-facing strings", () => {
    expect(LINE_PACK.cli.commandName).toBe("line");
    expect(LINE_PACK.cli.tokenLabel).toBe("LINE channel access token");
    expect(LINE_PACK.cli.tokenKind).toBe("channel access token");
    expect(LINE_PACK.cli.displayName).toBe("LINE");
    expect(LINE_PACK.cli.allowlistIdNoun).toBe("ids");
    expect(LINE_PACK.cli.usageNote).toBeUndefined();
  });
});

// COMPLETENESS SENTINEL (pack step 2): a 6th service-token connector MUST register its
// pack here or fail CI. The `satisfies Record<ServiceName, …>` literal is the COMPILE-TIME
// gate — adding a member to the ServiceName union without a pack breaks typecheck; the
// runtime assertions gate that SERVICE_TOKEN_PACKS covers EXACTLY that same universe, in a
// distinct-id list, with a well-formed ServiceTokenErrorName per pack.
describe("SERVICE_TOKEN_PACKS completeness", () => {
  // Compile-time exhaustiveness: one pack per ServiceName, no more, no fewer.
  const PACK_BY_ID = {
    line: LINE_PACK,
    telegram: TELEGRAM_PACK,
    discord: DISCORD_PACK,
    slack: SLACK_PACK,
    mattermost: MATTERMOST_PACK,
  } satisfies Record<ServiceName, ServiceTokenPack>;

  test("covers exactly the 5 service-token connectors (the ServiceName universe)", () => {
    expect(SERVICE_TOKEN_PACKS.length).toBe(5);
    const listIds = SERVICE_TOKEN_PACKS.map((p) => p.id).sort();
    const universe = (Object.keys(PACK_BY_ID) as ServiceName[]).sort();
    expect(listIds).toEqual(universe);
  });

  test("every pack id is distinct", () => {
    const ids = SERVICE_TOKEN_PACKS.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  test("the list holds the SAME pack instance registered per id (no drift)", () => {
    for (const pack of SERVICE_TOKEN_PACKS) {
      expect(pack).toBe(PACK_BY_ID[pack.id]);
    }
  });

  test("posture-row order is line, telegram, discord, slack, mattermost", () => {
    expect(SERVICE_TOKEN_PACKS.map((p) => p.id)).toEqual([
      "line", "telegram", "discord", "slack", "mattermost",
    ]);
  });

  test("every pack's errorName is a well-formed `<id>_api_failed` ServiceTokenErrorName", () => {
    const valid = new Set([
      "line_api_failed", "telegram_api_failed", "discord_api_failed",
      "slack_api_failed", "mattermost_api_failed",
    ]);
    for (const pack of SERVICE_TOKEN_PACKS) {
      expect(pack.errorName).toBe(`${pack.id}_api_failed`);
      expect(valid.has(pack.errorName)).toBe(true);
    }
  });

  test("storeKey equals id for every pack (today they coincide)", () => {
    for (const pack of SERVICE_TOKEN_PACKS) {
      expect(pack.storeKey).toBe(pack.id);
    }
  });
});
