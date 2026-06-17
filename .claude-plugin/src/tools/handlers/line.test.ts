// v1.66 Phase C PR 2 — linePushMessage handler: text-only construction, the
// service-token narrow, egress gates, and HTTP-status → line_api_failed mapping.
// The LINE API is mocked at the fetch seam (no network).

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { MCPError } from "../../errors";
import { ENV_LINE_ALLOW } from "../../policy/line-recipient-allowlist";
import { NOOP_AUDIT, oauthCred, serviceTokenCred } from "../test-audit";
import type { ToolContext } from "../types";
import { linePushMessage } from "./line";

const TO = "U" + "0".repeat(32);
const OTHER = "U" + "9".repeat(32);

function ctx(token = "chan-tok"): ToolContext {
  return { allowedAccounts: null, credential: serviceTokenCred(() => token), tier: "share", audit: NOOP_AUDIT };
}

/** A fetch stub that records the last call and returns a fixed status. */
function fetchStub(status = 200) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const impl = (async (url: unknown, init?: unknown) => {
    calls.push({ url: String(url), init: (init ?? {}) as RequestInit });
    return new Response(status === 200 ? "{}" : `{"message":"err"}`, { status });
  }) as unknown as typeof fetch;
  return { impl, calls };
}

const saved: Record<string, string | undefined> = {};
const ENV = [ENV_LINE_ALLOW, "SAFESPACE_LINE_RECIPIENT_ALLOW_EXTRA", "SAFESPACE_AUTONOMOUS", "SAFESPACE_CONFIG_DIR"];
let tmpDir: string;

beforeEach(async () => {
  for (const k of ENV) saved[k] = process.env[k];
  for (const k of ENV) delete process.env[k];
  // egress denial path writes an audit denied-event → give it a tmp config dir.
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-line-h-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
});
afterEach(async () => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
  await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
});

describe("linePushMessage — happy path + construction", () => {
  test("posts a TEXT-only message to the push endpoint with the bearer token", async () => {
    const f = fetchStub(200);
    const out = await linePushMessage(ctx("secret-tok"), { to: TO, text: "hi there" }, { fetchImpl: f.impl });
    expect(out).toEqual({ to: TO, sent: true, message_type: "text" });
    expect(f.calls).toHaveLength(1);
    const { url, init } = f.calls[0]!;
    expect(url).toBe("https://api.line.me/v2/bot/message/push");
    expect(init.method).toBe("POST");
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer secret-tok");
    const body = JSON.parse(init.body as string);
    expect(body).toEqual({ to: TO, messages: [{ type: "text", text: "hi there" }] });
    // Only a text message type is ever constructed (no SSRF-by-proxy URL fields).
    expect(body.messages[0].type).toBe("text");
    expect(Object.keys(body.messages[0])).toEqual(["type", "text"]);
  });
});

describe("linePushMessage — input validation (plain Error, fail-fast)", () => {
  test("rejects a malformed `to` (never hits LINE)", async () => {
    const f = fetchStub(200);
    await expect(
      linePushMessage(ctx(), { to: "not-a-line-id", text: "x" }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/'to' must be a valid LINE id/);
    expect(f.calls).toHaveLength(0);
  });

  test("rejects empty / oversized text", async () => {
    const f = fetchStub(200);
    await expect(
      linePushMessage(ctx(), { to: TO, text: "" }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/non-empty string/);
    await expect(
      linePushMessage(ctx(), { to: TO, text: "x".repeat(5001) }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/5000-character/);
    expect(f.calls).toHaveLength(0);
  });
});

describe("linePushMessage — credential narrow (R6)", () => {
  test("throws if the credential is not service-token (an OAuth ctx)", async () => {
    const f = fetchStub(200);
    const oauthCtx: ToolContext = { allowedAccounts: null, credential: oauthCred(), tier: "share", audit: NOOP_AUDIT };
    await expect(
      linePushMessage(oauthCtx, { to: TO, text: "x" }, { fetchImpl: f.impl }),
    ).rejects.toThrow(/requires a service-token credential/);
  });
});

describe("linePushMessage — HTTP status → line_api_failed reason", () => {
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
        linePushMessage(ctx(), { to: TO, text: "x" }, { fetchImpl: f.impl }),
      ).rejects.toMatchObject({ errorName: "line_api_failed", errorData: { reason } });
    });
  }

  test("network failure → api_error (no raw error leak)", async () => {
    const impl = (async () => {
      throw new Error("ECONNREFUSED 1.2.3.4");
    }) as unknown as typeof fetch;
    await expect(
      linePushMessage(ctx(), { to: TO, text: "x" }, { fetchImpl: impl }),
    ).rejects.toMatchObject({ errorName: "line_api_failed", errorData: { reason: "api_error" } });
  });
});

describe("linePushMessage — egress gates", () => {
  test("recipient NOT in an active allowlist → recipient_denied_by_policy (never hits LINE)", async () => {
    process.env[ENV_LINE_ALLOW] = OTHER; // active allowlist excluding TO
    const f = fetchStub(200);
    await expect(
      linePushMessage(ctx(), { to: TO, text: "x" }, { fetchImpl: f.impl }),
    ).rejects.toMatchObject({ errorName: "recipient_denied_by_policy" });
    expect(f.calls).toHaveLength(0);
  });

  test("recipient IN the allowlist → allowed", async () => {
    process.env[ENV_LINE_ALLOW] = TO;
    const f = fetchStub(200);
    const out = await linePushMessage(ctx(), { to: TO, text: "x" }, { fetchImpl: f.impl });
    expect(out).toMatchObject({ sent: true });
  });

  test("autonomous + secret-shape body → outbound_secret_rejected (never hits LINE)", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    process.env[ENV_LINE_ALLOW] = TO; // allow the recipient so secret-shape is the gate
    const f = fetchStub(200);
    const body = "-----BEGIN PRIVATE KEY-----\nMIIEv...\n-----END PRIVATE KEY-----";
    await expect(
      linePushMessage(ctx(), { to: TO, text: body }, { fetchImpl: f.impl }),
    ).rejects.toMatchObject({ errorName: "outbound_secret_rejected" });
    expect(f.calls).toHaveLength(0);
  });
});
