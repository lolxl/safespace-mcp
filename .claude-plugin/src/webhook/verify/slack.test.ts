// v1.102 (W0) — Slack webhook verification tests. The security core: signature
// verify-first, replay window, url_verification handshake, the HIGH-1 forged-`type`
// bypass, and the normalized-message extraction.

import { describe, expect, test } from "bun:test";
import * as crypto from "node:crypto";
import type { IncomingHttpHeaders } from "node:http";
import { handleSlackWebhook, verifySlackSignature } from "./slack";

const SECRET = "8f742c19a55d4e3b9c1f0a6b2d7e4f81";
const NOW_MS = 1_700_000_000_000; // fixed; tests pass nowMs explicitly
const NOW_S = Math.floor(NOW_MS / 1000);

/** Sign a raw body the way Slack does: v0=HMAC-SHA256(secret, `v0:ts:body`). */
function sign(body: string, ts: number, secret = SECRET): IncomingHttpHeaders {
  const mac = crypto.createHmac("sha256", secret).update(`v0:${ts}:${body}`).digest("hex");
  return {
    "x-slack-signature": `v0=${mac}`,
    "x-slack-request-timestamp": String(ts),
  };
}

const messageBody = JSON.stringify({
  type: "event_callback",
  event_id: "Ev0123ABCD",
  event_time: NOW_S,
  team_id: "T0001",
  event: {
    type: "message",
    text: "hello there",
    user: "U12345",
    ts: "1700000000.000100",
    channel: "C09999",
    client_msg_id: "cmid-abc",
  },
});

describe("verifySlackSignature", () => {
  test("accepts a correctly signed body", () => {
    const r = verifySlackSignature(Buffer.from(messageBody), sign(messageBody, NOW_S), SECRET, NOW_MS);
    expect(r.ok).toBe(true);
  });

  test("rejects a tampered body (signature over different bytes)", () => {
    const headers = sign(messageBody, NOW_S);
    const tampered = messageBody.replace("hello there", "evil instruction");
    const r = verifySlackSignature(Buffer.from(tampered), headers, SECRET, NOW_MS);
    expect(r).toEqual({ ok: false, reason: "bad_signature" });
  });

  test("rejects a wrong signing secret", () => {
    const r = verifySlackSignature(Buffer.from(messageBody), sign(messageBody, NOW_S, "wrong-secret"), SECRET, NOW_MS);
    expect(r).toEqual({ ok: false, reason: "bad_signature" });
  });

  test("missing signature header fails closed", () => {
    const r = verifySlackSignature(Buffer.from(messageBody), { "x-slack-request-timestamp": String(NOW_S) }, SECRET, NOW_MS);
    expect(r).toEqual({ ok: false, reason: "missing_signature" });
  });

  test("missing timestamp header fails closed", () => {
    const r = verifySlackSignature(Buffer.from(messageBody), { "x-slack-signature": "v0=abc" }, SECRET, NOW_MS);
    expect(r).toEqual({ ok: false, reason: "missing_signature" });
  });

  test("non-numeric timestamp → bad_timestamp", () => {
    const r = verifySlackSignature(
      Buffer.from(messageBody),
      { "x-slack-signature": "v0=abc", "x-slack-request-timestamp": "not-a-number" },
      SECRET,
      NOW_MS,
    );
    expect(r).toEqual({ ok: false, reason: "bad_timestamp" });
  });

  test("a stale timestamp (> 5 min old) → replay", () => {
    const oldTs = NOW_S - 301;
    const r = verifySlackSignature(Buffer.from(messageBody), sign(messageBody, oldTs), SECRET, NOW_MS);
    expect(r).toEqual({ ok: false, reason: "replay" });
  });

  test("a far-future timestamp (> 5 min ahead) → replay", () => {
    const futTs = NOW_S + 301;
    const r = verifySlackSignature(Buffer.from(messageBody), sign(messageBody, futTs), SECRET, NOW_MS);
    expect(r).toEqual({ ok: false, reason: "replay" });
  });

  test("a timestamp at the window edge (exactly 300s) is accepted", () => {
    const edgeTs = NOW_S - 300;
    const r = verifySlackSignature(Buffer.from(messageBody), sign(messageBody, edgeTs), SECRET, NOW_MS);
    expect(r.ok).toBe(true);
  });
});

describe("handleSlackWebhook — verify-first dispatch", () => {
  test("a valid message event → normalized InboxMsg, with event_id", () => {
    const r = handleSlackWebhook(Buffer.from(messageBody), sign(messageBody, NOW_S), SECRET, NOW_MS);
    expect(r).toEqual({
      kind: "messages",
      messages: [
        {
          event_id: "Ev0123ABCD",
          msg: {
            provider_message_id: "cmid-abc",
            ts: "1700000000.000100",
            sender_id: "U12345",
            sender_name: null,
            channel_id: "C09999",
            text: "hello there",
          },
        },
      ],
    });
  });

  test("falls back to ts for provider_message_id when client_msg_id absent", () => {
    const body = JSON.stringify({
      type: "event_callback",
      event_id: "EvNOID",
      event: { type: "message", text: "hi", user: "U1", ts: "1700000000.5", channel: "C1" },
    });
    const r = handleSlackWebhook(Buffer.from(body), sign(body, NOW_S), SECRET, NOW_MS);
    expect(r.kind).toBe("messages");
    if (r.kind === "messages") expect(r.messages[0]!.msg.provider_message_id).toBe("1700000000.5");
  });

  test("a valid url_verification → challenge echo", () => {
    const body = JSON.stringify({ type: "url_verification", token: "x", challenge: "abc123_-XYZ" });
    const r = handleSlackWebhook(Buffer.from(body), sign(body, NOW_S), SECRET, NOW_MS);
    expect(r).toEqual({ kind: "challenge", challenge: "abc123_-XYZ" });
  });

  test("HIGH-1: a FORGED type:url_verification with NO valid signature is REJECTED (verify-first)", () => {
    const body = JSON.stringify({ type: "url_verification", challenge: "leakme" });
    // No valid signature — an attacker cannot reach the challenge echo.
    const r = handleSlackWebhook(Buffer.from(body), { "x-slack-signature": "v0=deadbeef", "x-slack-request-timestamp": String(NOW_S) }, SECRET, NOW_MS);
    expect(r).toEqual({ kind: "reject", reason: "bad_signature" });
  });

  test("a url_verification with an over-long challenge → reject bad_challenge", () => {
    const challenge = "a".repeat(101);
    const body = JSON.stringify({ type: "url_verification", challenge });
    const r = handleSlackWebhook(Buffer.from(body), sign(body, NOW_S), SECRET, NOW_MS);
    expect(r).toEqual({ kind: "reject", reason: "bad_challenge" });
  });

  test("a url_verification with a non-allowlisted challenge char → reject bad_challenge", () => {
    const body = JSON.stringify({ type: "url_verification", challenge: "abc<script>" });
    const r = handleSlackWebhook(Buffer.from(body), sign(body, NOW_S), SECRET, NOW_MS);
    expect(r).toEqual({ kind: "reject", reason: "bad_challenge" });
  });

  test("an event_callback missing event_id → reject missing_event_id (dedup-evasion guard)", () => {
    const body = JSON.stringify({ type: "event_callback", event: { type: "message", text: "hi", user: "U1", ts: "1.0", channel: "C1" } });
    const r = handleSlackWebhook(Buffer.from(body), sign(body, NOW_S), SECRET, NOW_MS);
    expect(r).toEqual({ kind: "reject", reason: "missing_event_id" });
  });

  test("a message with a subtype (bot_message) → ignore (not persisted)", () => {
    const body = JSON.stringify({ type: "event_callback", event_id: "Ev1", event: { type: "message", subtype: "bot_message", text: "beep", user: "U1", ts: "1.0", channel: "C1" } });
    const r = handleSlackWebhook(Buffer.from(body), sign(body, NOW_S), SECRET, NOW_MS);
    expect(r).toEqual({ kind: "messages", messages: [] });
  });

  test("an empty-text message → ignore", () => {
    const body = JSON.stringify({ type: "event_callback", event_id: "Ev1", event: { type: "message", text: "", user: "U1", ts: "1.0", channel: "C1" } });
    const r = handleSlackWebhook(Buffer.from(body), sign(body, NOW_S), SECRET, NOW_MS);
    expect(r).toEqual({ kind: "messages", messages: [] });
  });

  test("a non-message event type → ignore", () => {
    const body = JSON.stringify({ type: "event_callback", event_id: "Ev1", event: { type: "reaction_added", user: "U1" } });
    const r = handleSlackWebhook(Buffer.from(body), sign(body, NOW_S), SECRET, NOW_MS);
    expect(r).toEqual({ kind: "messages", messages: [] });
  });

  test("a verified but unknown top-level type → ignore", () => {
    const body = JSON.stringify({ type: "app_rate_limited", team_id: "T1" });
    const r = handleSlackWebhook(Buffer.from(body), sign(body, NOW_S), SECRET, NOW_MS);
    expect(r).toEqual({ kind: "messages", messages: [] });
  });

  test("valid signature but non-JSON body → reject invalid_json", () => {
    const raw = "not json {";
    const r = handleSlackWebhook(Buffer.from(raw), sign(raw, NOW_S), SECRET, NOW_MS);
    expect(r).toEqual({ kind: "reject", reason: "invalid_json" });
  });

  test("valid signature but a JSON array (not an object) → reject invalid_payload", () => {
    const raw = JSON.stringify([1, 2, 3]);
    const r = handleSlackWebhook(Buffer.from(raw), sign(raw, NOW_S), SECRET, NOW_MS);
    expect(r).toEqual({ kind: "reject", reason: "invalid_payload" });
  });
});
