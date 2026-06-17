// v1.103 (W1) — LINE webhook verification tests: base64-HMAC verify, the events[]
// multi-event model, source→channel normalization, dedup-id skip, no replay window.

import { describe, expect, test } from "bun:test";
import * as crypto from "node:crypto";
import type { IncomingHttpHeaders } from "node:http";
import { handleLineWebhook, verifyLineSignature } from "./line";

const SECRET = "line-channel-secret-abc123";
const NOW_MS = 1_700_000_000_000;

/** Sign a raw body the LINE way: base64(HMAC-SHA256(channelSecret, body)). */
function sign(body: string, secret = SECRET): IncomingHttpHeaders {
  return { "x-line-signature": crypto.createHmac("sha256", secret).update(body).digest("base64") };
}

function textEvent(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type: "message",
    webhookEventId: "WEvabc",
    timestamp: 1700000000000,
    source: { type: "user", userId: "Uuser1" },
    message: { type: "text", id: "msg1", text: "hello from line" },
    replyToken: "reply-tok-SECRET",
    ...over,
  };
}

function body(events: unknown[], destination = "Udest"): string {
  return JSON.stringify({ destination, events });
}

describe("verifyLineSignature", () => {
  test("accepts a correctly signed body", () => {
    const b = body([textEvent()]);
    expect(verifyLineSignature(Buffer.from(b), sign(b), SECRET)).toEqual({ ok: true });
  });
  test("rejects a tampered body", () => {
    const b = body([textEvent()]);
    const headers = sign(b);
    expect(verifyLineSignature(Buffer.from(b.replace("hello", "evil")), headers, SECRET)).toEqual({ ok: false, reason: "bad_signature" });
  });
  test("rejects a wrong secret", () => {
    const b = body([textEvent()]);
    expect(verifyLineSignature(Buffer.from(b), sign(b, "wrong"), SECRET)).toEqual({ ok: false, reason: "bad_signature" });
  });
  test("missing signature header fails closed", () => {
    const b = body([textEvent()]);
    expect(verifyLineSignature(Buffer.from(b), {}, SECRET)).toEqual({ ok: false, reason: "missing_signature" });
  });
});

describe("handleLineWebhook — multi-event + normalization", () => {
  test("a single text message → one normalized ParsedMessage (never the replyToken)", () => {
    const b = body([textEvent()]);
    const r = handleLineWebhook(Buffer.from(b), sign(b), SECRET, NOW_MS);
    expect(r).toEqual({
      kind: "messages",
      messages: [
        {
          event_id: "WEvabc",
          msg: { provider_message_id: "msg1", ts: "1700000000000", sender_id: "Uuser1", sender_name: null, channel_id: "Uuser1", text: "hello from line" },
        },
      ],
    });
    // the reply token must NEVER appear in the parsed output
    expect(JSON.stringify(r)).not.toContain("reply-tok");
  });

  test("a group source → channel_id is the groupId", () => {
    const b = body([textEvent({ source: { type: "group", groupId: "Ggroup1", userId: "Uuser1" }, webhookEventId: "WEg" })]);
    const r = handleLineWebhook(Buffer.from(b), sign(b), SECRET, NOW_MS);
    expect(r.kind).toBe("messages");
    if (r.kind === "messages") expect(r.messages[0]!.msg.channel_id).toBe("Ggroup1");
  });

  test("a room source → channel_id is the roomId", () => {
    const b = body([textEvent({ source: { type: "room", roomId: "Rroom1", userId: "Uuser1" }, webhookEventId: "WEr" })]);
    const r = handleLineWebhook(Buffer.from(b), sign(b), SECRET, NOW_MS);
    if (r.kind === "messages") expect(r.messages[0]!.msg.channel_id).toBe("Rroom1");
  });

  test("MULTIPLE events in one POST → multiple messages; non-text events between are skipped", () => {
    const b = body([
      textEvent({ webhookEventId: "WE1", message: { type: "text", id: "m1", text: "first" } }),
      { type: "follow", webhookEventId: "WEf", source: { userId: "U2" } }, // skipped
      textEvent({ webhookEventId: "WE2", message: { type: "sticker", id: "s1" } }), // non-text → skipped
      textEvent({ webhookEventId: "WE3", message: { type: "text", id: "m3", text: "third" } }),
    ]);
    const r = handleLineWebhook(Buffer.from(b), sign(b), SECRET, NOW_MS);
    expect(r.kind).toBe("messages");
    if (r.kind === "messages") {
      expect(r.messages.map((m) => m.event_id)).toEqual(["WE1", "WE3"]);
      expect(r.messages.map((m) => m.msg.text)).toEqual(["first", "third"]);
    }
  });

  test("an empty events[] (LINE verify ping) → messages:[] (200, nothing persisted)", () => {
    const b = body([]);
    const r = handleLineWebhook(Buffer.from(b), sign(b), SECRET, NOW_MS);
    expect(r).toEqual({ kind: "messages", messages: [] });
  });

  test("an event missing webhookEventId is SKIPPED (not a whole-batch reject)", () => {
    const noId = textEvent({ message: { type: "text", id: "m", text: "no id" } });
    delete (noId as Record<string, unknown>).webhookEventId;
    const b = body([noId, textEvent({ webhookEventId: "WEok", message: { type: "text", id: "m2", text: "ok" } })]);
    const r = handleLineWebhook(Buffer.from(b), sign(b), SECRET, NOW_MS);
    expect(r.kind).toBe("messages");
    if (r.kind === "messages") expect(r.messages.map((m) => m.event_id)).toEqual(["WEok"]);
  });

  test("an empty-text message is skipped", () => {
    const b = body([textEvent({ message: { type: "text", id: "m", text: "" } })]);
    const r = handleLineWebhook(Buffer.from(b), sign(b), SECRET, NOW_MS);
    expect(r).toEqual({ kind: "messages", messages: [] });
  });

  test("a bad signature → reject bad_signature (no parse)", () => {
    const b = body([textEvent()]);
    const r = handleLineWebhook(Buffer.from(b), { "x-line-signature": "AAAA" }, SECRET, NOW_MS);
    expect(r).toEqual({ kind: "reject", reason: "bad_signature" });
  });

  test("valid signature but non-JSON → reject invalid_json", () => {
    const raw = "not json {";
    const r = handleLineWebhook(Buffer.from(raw), sign(raw), SECRET, NOW_MS);
    expect(r).toEqual({ kind: "reject", reason: "invalid_json" });
  });

  test("valid signature but `events` not an array → reject invalid_payload", () => {
    const raw = JSON.stringify({ destination: "U", events: "nope" });
    const r = handleLineWebhook(Buffer.from(raw), sign(raw), SECRET, NOW_MS);
    expect(r).toEqual({ kind: "reject", reason: "invalid_payload" });
  });
});
