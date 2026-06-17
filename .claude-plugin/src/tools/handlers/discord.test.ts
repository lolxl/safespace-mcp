// v1.69 — discordSendMessage handler: text-only construction, the service-token narrow,
// the mention-injection guard (allowed_mentions:{parse:[]}), egress gates, HTTP-status →
// discord_api_failed mapping, and the token-never-leaks guard. The Discord REST API is
// mocked at the fetch seam (no network).

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { ENV_DC_ALLOW, ENV_DC_ALLOW_EXTRA } from "../../policy/discord-recipient-allowlist";
import { NOOP_AUDIT, oauthCred, serviceTokenCred } from "../test-audit";
import type { ToolContext } from "../types";
import { discordSendMessage } from "./discord";

const CHAN = "123456789012345678";
const OTHER = "987654321098765432";

function ctx(token = "bot-tok"): ToolContext {
  return { allowedAccounts: null, credential: serviceTokenCred(() => token), tier: "share", audit: NOOP_AUDIT };
}

/** A fetch stub that records the last call and returns a fixed status. */
function fetchStub(status = 200) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const impl = (async (url: unknown, init?: unknown) => {
    calls.push({ url: String(url), init: (init ?? {}) as RequestInit });
    return new Response(status === 200 ? `{"id":"1"}` : `{"message":"err"}`, { status });
  }) as unknown as typeof fetch;
  return { impl, calls };
}

const saved: Record<string, string | undefined> = {};
const ENV = [ENV_DC_ALLOW, ENV_DC_ALLOW_EXTRA, "SAFESPACE_AUTONOMOUS", "SAFESPACE_CONFIG_DIR"];
let tmpDir: string;

beforeEach(async () => {
  for (const k of ENV) saved[k] = process.env[k];
  for (const k of ENV) delete process.env[k];
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-dc-h-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
});
afterEach(async () => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
  await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
});

describe("discordSendMessage — happy path + construction", () => {
  test("posts to /channels/<id>/messages with the Bot header and an inert mention set", async () => {
    const f = fetchStub(200);
    const out = await discordSendMessage(ctx("secret-tok"), { channel_id: CHAN, content: "hi there" }, { fetchImpl: f.impl });
    expect(out).toEqual({ channel_id: CHAN, sent: true, message_type: "text" });
    expect(f.calls).toHaveLength(1);
    const { url, init } = f.calls[0]!;
    expect(url).toBe(`https://discord.com/api/v10/channels/${CHAN}/messages`);
    expect(init.method).toBe("POST");
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bot secret-tok"); // the "Bot " scheme, in a HEADER
    const body = JSON.parse(init.body as string);
    expect(body).toEqual({ content: "hi there", allowed_mentions: { parse: [] } });
    expect(Object.keys(body).sort()).toEqual(["allowed_mentions", "content"]);
  });
});

describe("discordSendMessage — mention-injection guard", () => {
  test("an @everyone in content still posts with allowed_mentions.parse === [] (no ping)", async () => {
    const f = fetchStub(200);
    process.env[ENV_DC_ALLOW] = CHAN;
    await discordSendMessage(ctx(), { channel_id: CHAN, content: "@everyone @here free nitro" }, { fetchImpl: f.impl });
    const body = JSON.parse(f.calls[0]!.init.body as string);
    // The mention syntax is preserved as literal text but neutered structurally.
    expect(body.content).toContain("@everyone");
    expect(body.allowed_mentions).toEqual({ parse: [] });
  });
});

describe("discordSendMessage — input validation (plain Error, fail-fast)", () => {
  test("rejects a malformed channel_id (never hits Discord)", async () => {
    const f = fetchStub(200);
    await expect(
      discordSendMessage(ctx(), { channel_id: "not-an-id", content: "x" }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/'channel_id' must be a numeric Discord channel id/);
    expect(f.calls).toHaveLength(0);
  });

  test("rejects empty / oversized content", async () => {
    const f = fetchStub(200);
    await expect(
      discordSendMessage(ctx(), { channel_id: CHAN, content: "" }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/non-empty string/);
    await expect(
      discordSendMessage(ctx(), { channel_id: CHAN, content: "x".repeat(2001) }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/2000-character/);
    expect(f.calls).toHaveLength(0);
  });
});

describe("discordSendMessage — credential narrow (R6)", () => {
  test("throws if the credential is not service-token (an OAuth ctx)", async () => {
    const f = fetchStub(200);
    const oauthCtx: ToolContext = { allowedAccounts: null, credential: oauthCred(), tier: "share", audit: NOOP_AUDIT };
    await expect(
      discordSendMessage(oauthCtx, { channel_id: CHAN, content: "x" }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/requires a service-token credential/);
  });
});

describe("discordSendMessage — HTTP status → discord_api_failed reason", () => {
  for (const [status, reason] of [
    [401, "auth_failed"],
    [403, "auth_failed"],
    [429, "rate_limited"],
    [400, "invalid_recipient"],
    [404, "invalid_recipient"],
    [500, "api_error"],
  ] as const) {
    test(`${status} → ${reason}`, async () => {
      const f = fetchStub(status);
      await expect(
        discordSendMessage(ctx(), { channel_id: CHAN, content: "x" }, { fetchImpl: f.impl }),
      ).rejects.toMatchObject({ errorName: "discord_api_failed", errorData: { reason } });
    });
  }

  test("network failure → api_error (no raw error leak)", async () => {
    const impl = (async () => {
      throw new Error("ECONNREFUSED 1.2.3.4");
    }) as unknown as typeof fetch;
    await expect(
      discordSendMessage(ctx(), { channel_id: CHAN, content: "x" }, { fetchImpl: impl }),
    ).rejects.toMatchObject({ errorName: "discord_api_failed", errorData: { reason: "api_error" } });
  });
});

describe("discordSendMessage — the bot token never leaks into errors", () => {
  type ErrLike = { errorName?: string; errorData?: unknown; message?: unknown };
  const errBlob = (err: ErrLike) =>
    JSON.stringify({ name: err.errorName, data: err.errorData, msg: String(err.message) });

  for (const status of [400, 401, 500] as const) {
    test(`HTTP ${status} error carries no token`, async () => {
      const f = fetchStub(status);
      const err = (await discordSendMessage(ctx("super-secret-token"), { channel_id: CHAN, content: "x" }, { fetchImpl: f.impl }).catch((e) => e)) as ErrLike;
      expect(errBlob(err)).not.toContain("super-secret-token");
    });
  }

  test("network throw carries no token", async () => {
    const impl = (async () => {
      throw new Error("connect failed; Authorization: Bot super-secret-token");
    }) as unknown as typeof fetch;
    const err = (await discordSendMessage(ctx("super-secret-token"), { channel_id: CHAN, content: "x" }, { fetchImpl: impl }).catch((e) => e)) as ErrLike;
    expect(errBlob(err)).not.toContain("super-secret-token");
  });
});

describe("discordSendMessage — egress gates", () => {
  test("recipient NOT in an active allowlist → recipient_denied_by_policy (never hits Discord)", async () => {
    process.env[ENV_DC_ALLOW] = OTHER; // active allowlist excluding CHAN
    const f = fetchStub(200);
    await expect(
      discordSendMessage(ctx(), { channel_id: CHAN, content: "x" }, { fetchImpl: f.impl }),
    ).rejects.toMatchObject({ errorName: "recipient_denied_by_policy" });
    expect(f.calls).toHaveLength(0);
  });

  test("recipient IN the allowlist → allowed", async () => {
    process.env[ENV_DC_ALLOW] = CHAN;
    const f = fetchStub(200);
    const out = await discordSendMessage(ctx(), { channel_id: CHAN, content: "x" }, { fetchImpl: f.impl });
    expect(out).toMatchObject({ sent: true });
  });

  test("autonomous + secret-shape body → outbound_secret_rejected (never hits Discord)", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    process.env[ENV_DC_ALLOW] = CHAN; // allow the recipient so secret-shape is the gate
    const f = fetchStub(200);
    const body = "-----BEGIN PRIVATE KEY-----\nMIIEv...\n-----END PRIVATE KEY-----";
    await expect(
      discordSendMessage(ctx(), { channel_id: CHAN, content: body }, { fetchImpl: f.impl }),
    ).rejects.toMatchObject({ errorName: "outbound_secret_rejected" });
    expect(f.calls).toHaveLength(0);
  });
});
