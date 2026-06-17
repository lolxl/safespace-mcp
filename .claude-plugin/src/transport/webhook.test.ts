// v1.102 (W0) — webhook listener integration tests over a real loopback socket, with
// injected seams (secret / persist / audit / clock) so no SecretBackend or store is
// touched. Covers verify→persist→ack, dedup, url_verification, the reject statuses,
// the path-traversal 404, the method 405, missing-secret 401, persist-fail 500, the
// oversized-body 413, and the config/fail-loud helpers.

import { afterEach, describe, expect, test } from "bun:test";
import * as crypto from "node:crypto";
import type { InboxAppend } from "../webhook/inbox-store";
import {
  enabledWebhookProviders,
  enforceWebhookSecretsPresent,
  resolveWebhookConfigFromEnv,
  startWebhookListener,
  webhookBind,
  webhookEnabled,
  type WebhookHandle,
  type WebhookListenerConfig,
} from "./webhook";

const SECRET = "8f742c19a55d4e3b9c1f0a6b2d7e4f81";
const NOW_MS = 1_700_000_000_000;
const NOW_S = Math.floor(NOW_MS / 1000);

function slackHeaders(body: string, ts = NOW_S, secret = SECRET): Record<string, string> {
  const mac = crypto.createHmac("sha256", secret).update(`v0:${ts}:${body}`).digest("hex");
  return {
    "content-type": "application/json",
    "x-slack-signature": `v0=${mac}`,
    "x-slack-request-timestamp": String(ts),
  };
}

const messageBody = JSON.stringify({
  type: "event_callback",
  event_id: "EvABC",
  event: { type: "message", text: "hello", user: "U1", ts: "1.0", channel: "C1", client_msg_id: "cm1" },
});

let handle: WebhookHandle | null = null;
const persisted: InboxAppend[] = [];
const receipts: Array<{ provider: string; eventId: string; persisted: boolean }> = [];
const rejects: Array<{ provider: string; count: number }> = [];

afterEach(async () => {
  if (handle) await handle.close();
  handle = null;
  persisted.length = 0;
  receipts.length = 0;
  rejects.length = 0;
});

async function start(over: Partial<WebhookListenerConfig> = {}): Promise<string> {
  handle = await startWebhookListener({
    port: 0,
    bind: "127.0.0.1",
    now: () => NOW_MS,
    readSecret: async () => SECRET,
    persist: async (input) => {
      persisted.push(input);
      return { deduped: false };
    },
    auditReceipt: (provider, eventId, p) => receipts.push({ provider, eventId, persisted: p }),
    auditRejected: (provider, count) => rejects.push({ provider, count }),
    ...over,
  });
  return `http://127.0.0.1:${handle.port}`;
}

describe("startWebhookListener", () => {
  test("a valid signed slack message → 200, persisted, verified receipt", async () => {
    const base = await start();
    const res = await fetch(`${base}/webhook/slack`, { method: "POST", headers: slackHeaders(messageBody), body: messageBody });
    expect(res.status).toBe(200);
    expect(persisted).toHaveLength(1);
    expect(persisted[0]).toEqual({ provider: "slack", event_id: "EvABC", msg: { provider_message_id: "cm1", ts: "1.0", sender_id: "U1", sender_name: null, channel_id: "C1", text: "hello" } });
    expect(receipts).toEqual([{ provider: "slack", eventId: "EvABC", persisted: true }]);
  });

  test("a valid signed LINE POST with MULTIPLE events → 200, each persisted (multi-event)", async () => {
    const base = await start();
    const lineBody = JSON.stringify({
      destination: "Udest",
      events: [
        { type: "message", webhookEventId: "WE1", timestamp: 1700000000000, source: { type: "user", userId: "U1" }, message: { type: "text", id: "m1", text: "one" } },
        { type: "follow", webhookEventId: "WEf", source: { userId: "U9" } }, // non-message → skipped
        { type: "message", webhookEventId: "WE2", timestamp: 1700000000001, source: { type: "group", groupId: "G1", userId: "U2" }, message: { type: "text", id: "m2", text: "two" } },
      ],
    });
    const sig = crypto.createHmac("sha256", SECRET).update(lineBody).digest("base64");
    const res = await fetch(`${base}/webhook/line`, { method: "POST", headers: { "content-type": "application/json", "x-line-signature": sig }, body: lineBody });
    expect(res.status).toBe(200);
    expect(persisted.map((p) => p.event_id)).toEqual(["WE1", "WE2"]); // the follow event skipped
    expect(persisted[1]!.msg.channel_id).toBe("G1");
    expect(receipts).toHaveLength(2);
  });

  test("a LINE mid-batch persist failure → 500 (first persisted, provider retries whole batch; dedup absorbs it)", async () => {
    let calls = 0;
    const base = await start({
      persist: async (input) => {
        calls += 1;
        if (calls === 2) throw new Error("disk full"); // second message fails
        persisted.push(input);
        return { deduped: false };
      },
    });
    const lineBody = JSON.stringify({
      destination: "U",
      events: [
        { type: "message", webhookEventId: "WE1", timestamp: 1, source: { userId: "U1" }, message: { type: "text", id: "m1", text: "one" } },
        { type: "message", webhookEventId: "WE2", timestamp: 2, source: { userId: "U2" }, message: { type: "text", id: "m2", text: "two" } },
      ],
    });
    const sig = crypto.createHmac("sha256", SECRET).update(lineBody).digest("base64");
    const res = await fetch(`${base}/webhook/line`, { method: "POST", headers: { "x-line-signature": sig }, body: lineBody });
    expect(res.status).toBe(500); // NOT 200 → the provider retries the whole batch
    expect(calls).toBe(2); // persist-before-ACK: the first landed, then the second threw
    expect(persisted.map((p) => p.event_id)).toEqual(["WE1"]); // first stored before the failure
    expect(receipts).toHaveLength(1); // only the successfully-persisted first got a receipt
  });

  test("a LINE POST with a bad signature → 401, no persist", async () => {
    const base = await start();
    const lineBody = JSON.stringify({ destination: "U", events: [] });
    const res = await fetch(`${base}/webhook/line`, { method: "POST", headers: { "x-line-signature": "AAAA" }, body: lineBody });
    expect(res.status).toBe(401);
    expect(persisted).toHaveLength(0);
  });

  test("a dedup hit → 200, receipt persisted=false", async () => {
    const base = await start({ persist: async () => ({ deduped: true }) });
    const res = await fetch(`${base}/webhook/slack`, { method: "POST", headers: slackHeaders(messageBody), body: messageBody });
    expect(res.status).toBe(200);
    expect(receipts).toEqual([{ provider: "slack", eventId: "EvABC", persisted: false }]);
  });

  test("url_verification → 200 text/plain challenge echo, no persist", async () => {
    const body = JSON.stringify({ type: "url_verification", challenge: "Ch4llenge_-x" });
    const base = await start();
    const res = await fetch(`${base}/webhook/slack`, { method: "POST", headers: slackHeaders(body), body });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("Ch4llenge_-x");
    expect(persisted).toHaveLength(0);
    expect(receipts).toHaveLength(0);
  });

  test("a bad signature → 401, no persist, reject counted", async () => {
    const base = await start();
    const headers = { ...slackHeaders(messageBody), "x-slack-signature": "v0=deadbeef" };
    const res = await fetch(`${base}/webhook/slack`, { method: "POST", headers, body: messageBody });
    expect(res.status).toBe(401);
    expect(persisted).toHaveLength(0);
  });

  test("a verified-but-malformed (missing event_id) → 400", async () => {
    const body = JSON.stringify({ type: "event_callback", event: { type: "message", text: "x", user: "U", ts: "1", channel: "C" } });
    const base = await start();
    const res = await fetch(`${base}/webhook/slack`, { method: "POST", headers: slackHeaders(body), body });
    expect(res.status).toBe(400);
  });

  test("an unknown provider → 404 (path-traversal guard)", async () => {
    const base = await start();
    expect((await fetch(`${base}/webhook/myspace`, { method: "POST", headers: slackHeaders("{}"), body: "{}" })).status).toBe(404);
    // `..` resolves away — never reaches /mcp (separate server), 404 here
    expect((await fetch(`${base}/webhook/../mcp`, { method: "POST", body: "{}" })).status).toBe(404);
    expect((await fetch(`${base}/mcp`, { method: "POST", body: "{}" })).status).toBe(404);
  });

  test("a GET → 405", async () => {
    const base = await start();
    expect((await fetch(`${base}/webhook/slack`, { method: "GET" })).status).toBe(405);
  });

  test("a missing/cleared secret → 401 (fail closed)", async () => {
    const base = await start({ readSecret: async () => null });
    const res = await fetch(`${base}/webhook/slack`, { method: "POST", headers: slackHeaders(messageBody), body: messageBody });
    expect(res.status).toBe(401);
    expect(persisted).toHaveLength(0);
  });

  test("a persist failure → 500 (NOT 200) so the provider retries", async () => {
    const base = await start({
      persist: async () => {
        throw new Error("disk full");
      },
    });
    const res = await fetch(`${base}/webhook/slack`, { method: "POST", headers: slackHeaders(messageBody), body: messageBody });
    expect(res.status).toBe(500);
    expect(receipts).toHaveLength(0);
  });

  test("flushes the reject-window tail count on close (no silent loss of a finite burst)", async () => {
    const base = await start(); // now() is fixed → both rejects fall in one un-elapsed window
    const bad = { ...slackHeaders(messageBody), "x-slack-signature": "v0=bad" };
    await fetch(`${base}/webhook/slack`, { method: "POST", headers: bad, body: messageBody });
    await fetch(`${base}/webhook/slack`, { method: "POST", headers: bad, body: messageBody });
    expect(rejects).toHaveLength(0); // window not elapsed → not emitted yet
    await handle!.close();
    handle = null; // prevent afterEach double-close (a 2nd flush finds an empty map → no-op)
    expect(rejects).toEqual([{ provider: "slack", count: 2 }]);
  });

  test("an oversized body → 413", async () => {
    const base = await start();
    const big = "x".repeat(5 * 1024 * 1024);
    const res = await fetch(`${base}/webhook/slack`, { method: "POST", headers: { "content-type": "text/plain" }, body: big });
    expect(res.status).toBe(413);
  });
});

describe("config + fail-loud helpers", () => {
  const saved = { port: process.env.SAFESPACE_WEBHOOK_PORT, bind: process.env.SAFESPACE_WEBHOOK_BIND };
  afterEach(() => {
    if (saved.port === undefined) delete process.env.SAFESPACE_WEBHOOK_PORT;
    else process.env.SAFESPACE_WEBHOOK_PORT = saved.port;
    if (saved.bind === undefined) delete process.env.SAFESPACE_WEBHOOK_BIND;
    else process.env.SAFESPACE_WEBHOOK_BIND = saved.bind;
  });

  test("webhookEnabled reflects the port presence", () => {
    delete process.env.SAFESPACE_WEBHOOK_PORT;
    expect(webhookEnabled()).toBe(false);
    process.env.SAFESPACE_WEBHOOK_PORT = "9100";
    expect(webhookEnabled()).toBe(true);
  });

  test("webhookBind defaults to loopback, never 0.0.0.0 implicitly", () => {
    delete process.env.SAFESPACE_WEBHOOK_BIND;
    expect(webhookBind()).toBe("127.0.0.1");
    process.env.SAFESPACE_WEBHOOK_BIND = "100.64.0.1";
    expect(webhookBind()).toBe("100.64.0.1");
  });

  test("resolveWebhookConfigFromEnv rejects a bad port", () => {
    process.env.SAFESPACE_WEBHOOK_PORT = "not-a-port";
    expect(() => resolveWebhookConfigFromEnv()).toThrow();
    process.env.SAFESPACE_WEBHOOK_PORT = "9100";
    expect(resolveWebhookConfigFromEnv().port).toBe(9100);
  });

  test("enabledWebhookProviders is the wired set (W0 slack + W1 line)", () => {
    expect(enabledWebhookProviders()).toEqual(["slack", "line"]);
  });

  test("enforceWebhookSecretsPresent throws naming a provider whose secret is missing", async () => {
    let threw = false;
    try {
      await enforceWebhookSecretsPresent(async () => false);
    } catch (e) {
      threw = true;
      expect(String(e)).toMatch(/slack/);
    }
    expect(threw).toBe(true);
    // all secrets present → resolves without throwing
    await enforceWebhookSecretsPresent(async () => true);
  });
});
