// v1.68 — telegramSendMessage handler: text-only construction, the service-token
// narrow, egress gates, HTTP-status → telegram_api_failed mapping, and the
// token-in-URL leak guard. The Telegram Bot API is mocked at the fetch seam (no network).

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { ENV_TG_ALLOW } from "../../policy/telegram-recipient-allowlist";
import { NOOP_AUDIT, oauthCred, serviceTokenCred } from "../test-audit";
import type { ToolContext } from "../types";
import { telegramSendMessage } from "./telegram";

const CHAT = "123456789";
const OTHER = "987654321";

function ctx(token = "bot-tok"): ToolContext {
  return { credential: serviceTokenCred(() => token), tier: "share", audit: NOOP_AUDIT };
}

/** A fetch stub that records the last call and returns a fixed status. */
function fetchStub(status = 200) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const impl = (async (url: unknown, init?: unknown) => {
    calls.push({ url: String(url), init: (init ?? {}) as RequestInit });
    return new Response(status === 200 ? `{"ok":true}` : `{"ok":false}`, { status });
  }) as unknown as typeof fetch;
  return { impl, calls };
}

const saved: Record<string, string | undefined> = {};
const ENV = [ENV_TG_ALLOW, "SAFESPACE_TELEGRAM_RECIPIENT_ALLOW_EXTRA", "SAFESPACE_AUTONOMOUS", "SAFESPACE_CONFIG_DIR"];
let tmpDir: string;

beforeEach(async () => {
  for (const k of ENV) saved[k] = process.env[k];
  for (const k of ENV) delete process.env[k];
  // egress denial path writes an audit denied-event → give it a tmp config dir.
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-tg-h-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
});
afterEach(async () => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
  await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
});

describe("telegramSendMessage — happy path + construction", () => {
  test("posts a TEXT-only message to sendMessage with the token in the URL path", async () => {
    const f = fetchStub(200);
    const out = await telegramSendMessage(ctx("secret-tok"), { chat_id: CHAT, text: "hi there" }, { fetchImpl: f.impl });
    expect(out).toEqual({ chat_id: CHAT, sent: true, message_type: "text" });
    expect(f.calls).toHaveLength(1);
    const { url, init } = f.calls[0]!;
    // Token is a URL PATH segment; the host is hardcoded.
    expect(url).toBe("https://api.telegram.org/botsecret-tok/sendMessage");
    expect(init.method).toBe("POST");
    const body = JSON.parse(init.body as string);
    // Allowlist-constructed: ONLY chat_id + text, NO parse_mode / media.
    expect(body).toEqual({ chat_id: CHAT, text: "hi there" });
    expect(Object.keys(body).sort()).toEqual(["chat_id", "text"]);
  });

  test("accepts a numeric -100… group id and a @username", async () => {
    const f = fetchStub(200);
    const grp = await telegramSendMessage(ctx(), { chat_id: "-1001234567890", text: "x" }, { fetchImpl: f.impl });
    expect(grp).toMatchObject({ sent: true });
    const usr = await telegramSendMessage(ctx(), { chat_id: "@my_channel", text: "x" }, { fetchImpl: f.impl });
    expect(usr).toMatchObject({ sent: true });
  });
});

describe("telegramSendMessage — input validation (plain Error, fail-fast)", () => {
  test("rejects a malformed chat_id (never hits Telegram)", async () => {
    const f = fetchStub(200);
    await expect(
      telegramSendMessage(ctx(), { chat_id: "not an id", text: "x" }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/'chat_id' must be a numeric chat id/);
    expect(f.calls).toHaveLength(0);
  });

  test("rejects empty / oversized text", async () => {
    const f = fetchStub(200);
    await expect(
      telegramSendMessage(ctx(), { chat_id: CHAT, text: "" }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/non-empty string/);
    await expect(
      telegramSendMessage(ctx(), { chat_id: CHAT, text: "x".repeat(4097) }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/4096-character/);
    expect(f.calls).toHaveLength(0);
  });
});

describe("telegramSendMessage — credential narrow (R6)", () => {
  test("throws if the credential is not service-token (an OAuth ctx)", async () => {
    const f = fetchStub(200);
    const oauthCtx: ToolContext = { credential: oauthCred(), tier: "share", audit: NOOP_AUDIT };
    await expect(
      telegramSendMessage(oauthCtx, { chat_id: CHAT, text: "x" }, { fetchImpl: f.impl }),
    ).rejects.toMatchObject({ errorName: "internal_routing_error", errorData: { reason: "credential_mismatch" } });
  });
});

describe("telegramSendMessage — HTTP status → telegram_api_failed reason", () => {
  for (const [status, reason] of [
    [401, "auth_failed"],
    [403, "auth_failed"],
    [429, "rate_limited"],
    [400, "invalid_recipient"],
    [500, "api_error"],
  ] as const) {
    test(`${status} → ${reason}`, async () => {
      const f = fetchStub(status);
      await expect(
        telegramSendMessage(ctx(), { chat_id: CHAT, text: "x" }, { fetchImpl: f.impl }),
      ).rejects.toMatchObject({ errorName: "telegram_api_failed", errorData: { reason } });
    });
  }

  test("network failure → api_error (no raw error leak)", async () => {
    const impl = (async () => {
      throw new Error("ECONNREFUSED 1.2.3.4");
    }) as unknown as typeof fetch;
    await expect(
      telegramSendMessage(ctx(), { chat_id: CHAT, text: "x" }, { fetchImpl: impl }),
    ).rejects.toMatchObject({ errorName: "telegram_api_failed", errorData: { reason: "api_error" } });
  });
});

describe("telegramSendMessage — the bot token (in the URL) never leaks into errors", () => {
  // The Telegram token is a URL PATH segment, so a careless error path could surface
  // it. Assert the thrown error (name + data + message) never contains the token.
  type ErrLike = { errorName?: string; errorData?: unknown; message?: unknown };
  const errBlob = (err: ErrLike) =>
    JSON.stringify({ name: err.errorName, data: err.errorData, msg: String(err.message) });

  for (const status of [400, 401, 500] as const) {
    test(`HTTP ${status} error carries no token`, async () => {
      const f = fetchStub(status);
      const err = (await telegramSendMessage(ctx("super-secret-token"), { chat_id: CHAT, text: "x" }, { fetchImpl: f.impl }).catch((e) => e)) as ErrLike;
      expect(errBlob(err)).not.toContain("super-secret-token");
    });
  }

  test("network throw carries no token", async () => {
    const impl = (async () => {
      throw new Error("connect failed to https://api.telegram.org/botsuper-secret-token/sendMessage");
    }) as unknown as typeof fetch;
    const err = (await telegramSendMessage(ctx("super-secret-token"), { chat_id: CHAT, text: "x" }, { fetchImpl: impl }).catch((e) => e)) as ErrLike;
    expect(errBlob(err)).not.toContain("super-secret-token");
  });
});

// B6.1 wave A1 — the "telegramSendMessage — egress gates" describe MOVED to
// tools/egress-pipeline.test.ts (same assertions, driven through the pipeline's
// egress descriptor): the gate is now PIPELINE-FIRED (withNonOAuthContext runs
// extract → gate BEFORE the handler), so the handler no longer calls it.
