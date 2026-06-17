// v1.95 — slackSendMessage handler: text-only construction, the service-token narrow,
// the mention/link-injection guard (&<> escaping), egress gates, the chat.postMessage
// 200-but-ok:false error model (checkBody), HTTP-status mapping, and the
// token-never-leaks guard. The Slack Web API is mocked at the fetch seam (no network).

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { ENV_SK_ALLOW, ENV_SK_ALLOW_EXTRA } from "../../policy/slack-recipient-allowlist";
import { NOOP_AUDIT, oauthCred, serviceTokenCred } from "../test-audit";
import type { ToolContext } from "../types";
import { slackSendMessage } from "./slack";

const CHAN = "C0123456789";
const OTHER = "C9876543210";

function ctx(token = "bot-tok"): ToolContext {
  return { allowedAccounts: null, credential: serviceTokenCred(() => token), tier: "share", audit: NOOP_AUDIT };
}

/** A fetch stub that records the last call and returns a fixed status + body. Slack's
 *  chat.postMessage returns 200 even on logical failure ({ok:false, error}); the body is
 *  what the handler's checkBody reads. */
function fetchStub(opts: { status?: number; body?: string } = {}) {
  const status = opts.status ?? 200;
  const body = opts.body ?? `{"ok":true,"ts":"1700000000.000100"}`;
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const impl = (async (url: unknown, init?: unknown) => {
    calls.push({ url: String(url), init: (init ?? {}) as RequestInit });
    return new Response(body, { status });
  }) as unknown as typeof fetch;
  return { impl, calls };
}

const saved: Record<string, string | undefined> = {};
const ENV = [ENV_SK_ALLOW, ENV_SK_ALLOW_EXTRA, "SAFESPACE_AUTONOMOUS", "SAFESPACE_CONFIG_DIR"];
let tmpDir: string;

beforeEach(async () => {
  for (const k of ENV) saved[k] = process.env[k];
  for (const k of ENV) delete process.env[k];
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-sk-h-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
});
afterEach(async () => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
  await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
});

describe("slackSendMessage — happy path + construction", () => {
  test("posts to chat.postMessage with the Bearer header and a channel+text body", async () => {
    const f = fetchStub();
    const out = await slackSendMessage(ctx("secret-tok"), { channel: CHAN, text: "hi there" }, { fetchImpl: f.impl });
    expect(out).toEqual({ channel: CHAN, sent: true, message_type: "text" });
    expect(f.calls).toHaveLength(1);
    const { url, init } = f.calls[0]!;
    expect(url).toBe("https://slack.com/api/chat.postMessage");
    expect(init.method).toBe("POST");
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer secret-tok"); // Bearer scheme, in a HEADER
    const body = JSON.parse(init.body as string);
    expect(body).toEqual({ channel: CHAN, text: "hi there" });
    // Allowlist-constructed: ONLY channel + text — no link_names / blocks / attachments.
    expect(Object.keys(body).sort()).toEqual(["channel", "text"]);
  });
});

describe("slackSendMessage — mention/link-injection guard (&<> escaping)", () => {
  test("control sequences in text are escaped to inert literal text (no ping, no link)", async () => {
    const f = fetchStub();
    process.env[ENV_SK_ALLOW] = CHAN;
    await slackSendMessage(
      ctx(),
      { channel: CHAN, text: "<!everyone> <@U999> <http://evil.test|click> & done" },
      { fetchImpl: f.impl },
    );
    const body = JSON.parse(f.calls[0]!.init.body as string);
    // Every Slack control delimiter is escaped → no live mention/link survives.
    expect(body.text).toBe(
      "&lt;!everyone&gt; &lt;@U999&gt; &lt;http://evil.test|click&gt; &amp; done",
    );
    expect(body.text).not.toContain("<");
    expect(body.text).not.toContain(">");
  });

  test("`&` is escaped FIRST (not double-escaped)", async () => {
    const f = fetchStub();
    process.env[ENV_SK_ALLOW] = CHAN;
    await slackSendMessage(ctx(), { channel: CHAN, text: "a < b & c" }, { fetchImpl: f.impl });
    const body = JSON.parse(f.calls[0]!.init.body as string);
    expect(body.text).toBe("a &lt; b &amp; c"); // not "a &amp;lt; b &amp; c"
  });
});

describe("slackSendMessage — input validation (plain Error, fail-fast)", () => {
  test("rejects a malformed channel (never hits Slack)", async () => {
    const f = fetchStub();
    await expect(
      slackSendMessage(ctx(), { channel: "#general", text: "x" }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/'channel' must be a Slack conversation id/);
    expect(f.calls).toHaveLength(0);
  });

  test("rejects empty / oversized text", async () => {
    const f = fetchStub();
    await expect(
      slackSendMessage(ctx(), { channel: CHAN, text: "" }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/non-empty string/);
    await expect(
      slackSendMessage(ctx(), { channel: CHAN, text: "x".repeat(40001) }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/40000-character/);
    expect(f.calls).toHaveLength(0);
  });
});

describe("slackSendMessage — credential narrow (R6)", () => {
  test("throws if the credential is not service-token (an OAuth ctx)", async () => {
    const f = fetchStub();
    const oauthCtx: ToolContext = { allowedAccounts: null, credential: oauthCred(), tier: "share", audit: NOOP_AUDIT };
    await expect(
      slackSendMessage(oauthCtx, { channel: CHAN, text: "x" }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/requires a service-token credential/);
  });
});

describe("slackSendMessage — 200-but-ok:false body → slack_api_failed reason (checkBody)", () => {
  for (const [error, reason] of [
    ["invalid_auth", "auth_failed"],
    ["token_revoked", "auth_failed"],
    ["channel_not_found", "invalid_recipient"],
    ["not_in_channel", "invalid_recipient"],
    ["rate_limited", "rate_limited"],
    ["something_unknown", "api_error"],
  ] as const) {
    test(`ok:false error '${error}' → ${reason}`, async () => {
      const f = fetchStub({ status: 200, body: `{"ok":false,"error":"${error}"}` });
      await expect(
        slackSendMessage(ctx(), { channel: CHAN, text: "x" }, { fetchImpl: f.impl }),
      ).rejects.toMatchObject({ errorName: "slack_api_failed", errorData: { reason } });
    });
  }

  test("ok:true → success", async () => {
    const f = fetchStub({ status: 200, body: `{"ok":true}` });
    const out = await slackSendMessage(ctx(), { channel: CHAN, text: "x" }, { fetchImpl: f.impl });
    expect(out).toMatchObject({ sent: true });
  });

  test("a 200 with a non-JSON body → api_error (fail closed, never a false success)", async () => {
    const f = fetchStub({ status: 200, body: "<html>maintenance</html>" });
    await expect(
      slackSendMessage(ctx(), { channel: CHAN, text: "x" }, { fetchImpl: f.impl }),
    ).rejects.toMatchObject({ errorName: "slack_api_failed", errorData: { reason: "api_error" } });
  });
});

describe("slackSendMessage — HTTP status → slack_api_failed reason", () => {
  for (const [status, reason] of [
    [401, "auth_failed"],
    [403, "auth_failed"],
    [429, "rate_limited"],
    [500, "api_error"],
  ] as const) {
    test(`${status} → ${reason}`, async () => {
      const f = fetchStub({ status, body: "{}" });
      await expect(
        slackSendMessage(ctx(), { channel: CHAN, text: "x" }, { fetchImpl: f.impl }),
      ).rejects.toMatchObject({ errorName: "slack_api_failed", errorData: { reason } });
    });
  }

  test("network failure → api_error (no raw error leak)", async () => {
    const impl = (async () => {
      throw new Error("ECONNREFUSED 1.2.3.4");
    }) as unknown as typeof fetch;
    await expect(
      slackSendMessage(ctx(), { channel: CHAN, text: "x" }, { fetchImpl: impl }),
    ).rejects.toMatchObject({ errorName: "slack_api_failed", errorData: { reason: "api_error" } });
  });
});

describe("slackSendMessage — the bot token never leaks into errors", () => {
  type ErrLike = { errorName?: string; errorData?: unknown; message?: unknown };
  const errBlob = (err: ErrLike) =>
    JSON.stringify({ name: err.errorName, data: err.errorData, msg: String(err.message) });

  test("a 200 ok:false error carries no token", async () => {
    const f = fetchStub({ status: 200, body: `{"ok":false,"error":"invalid_auth"}` });
    const err = (await slackSendMessage(ctx("super-secret-token"), { channel: CHAN, text: "x" }, { fetchImpl: f.impl }).catch((e) => e)) as ErrLike;
    expect(errBlob(err)).not.toContain("super-secret-token");
  });

  test("network throw carries no token", async () => {
    const impl = (async () => {
      throw new Error("connect failed; Authorization: Bearer super-secret-token");
    }) as unknown as typeof fetch;
    const err = (await slackSendMessage(ctx("super-secret-token"), { channel: CHAN, text: "x" }, { fetchImpl: impl }).catch((e) => e)) as ErrLike;
    expect(errBlob(err)).not.toContain("super-secret-token");
  });
});

describe("slackSendMessage — egress gates", () => {
  test("recipient NOT in an active allowlist → recipient_denied_by_policy (never hits Slack)", async () => {
    process.env[ENV_SK_ALLOW] = OTHER; // active allowlist excluding CHAN
    const f = fetchStub();
    await expect(
      slackSendMessage(ctx(), { channel: CHAN, text: "x" }, { fetchImpl: f.impl }),
    ).rejects.toMatchObject({ errorName: "recipient_denied_by_policy" });
    expect(f.calls).toHaveLength(0);
  });

  test("recipient IN the allowlist → allowed", async () => {
    process.env[ENV_SK_ALLOW] = CHAN;
    const f = fetchStub();
    const out = await slackSendMessage(ctx(), { channel: CHAN, text: "x" }, { fetchImpl: f.impl });
    expect(out).toMatchObject({ sent: true });
  });

  test("autonomous + secret-shape body → outbound_secret_rejected (never hits Slack)", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    process.env[ENV_SK_ALLOW] = CHAN; // allow the recipient so secret-shape is the gate
    const f = fetchStub();
    const body = "-----BEGIN PRIVATE KEY-----\nMIIEv...\n-----END PRIVATE KEY-----";
    await expect(
      slackSendMessage(ctx(), { channel: CHAN, text: body }, { fetchImpl: f.impl }),
    ).rejects.toMatchObject({ errorName: "outbound_secret_rejected" });
    expect(f.calls).toHaveLength(0);
  });
});
