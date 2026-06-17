// v1.103 (W1) — LINE Messaging-API webhook verification.
//
// docs/v1.102-webhook-listener.md §5.2 + §6 (W1). LINE inbound is PUSH-ONLY (no poll
// API), so this is the connector's only inbound path. Differences from Slack (W0):
//   - The signature is base64(HMAC-SHA256(channel_secret, rawbody)) over the RAW body —
//     a bare MAC with NO embedded timestamp, so there is NO replay window: LINE's only
//     replay defence is webhookEventId dedup (the missing-id skip below is load-bearing).
//   - One POST carries an `events[]` ARRAY → 0..N messages (the W1 multi-event model).
//   - No url_verification handshake; LINE's console "verify" sends events:[] → 200.
//   - The signing secret is the LINE *channel secret* — DISTINCT from the channel
//     ACCESS TOKEN the outbound line_push_message uses (a different reserved key).
//
// The reply-token in each event is DELIBERATELY NOT surfaced (it is listener-held
// write-infra, never crosses the read boundary into inbox_read — the agent replies via
// the existing push line_push_message). PURE: no I/O; the secret is passed in.

import * as crypto from "node:crypto";
import type { IncomingHttpHeaders } from "node:http";
import type { InboxMsg, WebhookResult, ParsedMessage } from "../types";
import { headerOf, isObject, timingSafeEqualStr } from "./util";
import { WEBHOOK_SIGNATURE_HMAC_ALG } from "../../crypto-algorithms";

/** Verify the LINE signature over the RAW body. Pure. Missing header or a wrong MAC
 *  fails closed. No timestamp (LINE's signature carries none). */
export function verifyLineSignature(
  rawBody: Buffer,
  headers: IncomingHttpHeaders,
  channelSecret: string,
): { ok: true } | { ok: false; reason: "missing_signature" | "bad_signature" } {
  const sig = headerOf(headers, "x-line-signature");
  if (!sig) return { ok: false, reason: "missing_signature" };
  const expected = crypto.createHmac(WEBHOOK_SIGNATURE_HMAC_ALG, channelSecret).update(rawBody).digest("base64");
  if (!timingSafeEqualStr(sig, expected)) return { ok: false, reason: "bad_signature" };
  return { ok: true };
}

/** Normalize ONE LINE text-message event → a ParsedMessage, or null to skip (not a
 *  text message, or no webhookEventId to dedup on — anomalous for a real event). */
function normalizeLineEvent(ev: unknown): ParsedMessage | null {
  if (!isObject(ev) || ev.type !== "message") return null;
  const message = ev.message;
  if (!isObject(message) || message.type !== "text" || typeof message.text !== "string" || message.text.length === 0) {
    return null;
  }
  // webhookEventId is LINE's per-delivery dedup id — REQUIRED (no id → can't dedup → skip
  // this event rather than reject the whole batch, which may hold valid sibling events).
  const eventId = ev.webhookEventId;
  if (typeof eventId !== "string" || eventId.length === 0) return null;
  const source = isObject(ev.source) ? ev.source : {};
  const userId = typeof source.userId === "string" ? source.userId : "";
  // The conversation: a group/room id when present, else the 1:1 user id.
  const channelId =
    typeof source.groupId === "string"
      ? source.groupId
      : typeof source.roomId === "string"
        ? source.roomId
        : userId;
  const msg: InboxMsg = {
    provider_message_id: typeof message.id === "string" ? message.id : "",
    ts: typeof ev.timestamp === "number" ? String(ev.timestamp) : "",
    sender_id: userId,
    sender_name: null, // a LINE webhook event carries only the userId, no display name
    channel_id: channelId,
    text: message.text,
  };
  return { event_id: eventId, msg };
}

/** Verify-FIRST, then parse the events[] array, then normalize each text message. The
 *  single entry the listener calls for a `POST /webhook/line`. */
export function handleLineWebhook(
  rawBody: Buffer,
  headers: IncomingHttpHeaders,
  channelSecret: string,
  // LINE carries no signed timestamp, so there is no replay window and nowMs is unused.
  // The param exists ONLY to satisfy the shared `Verifier` type (transport/webhook.ts);
  // it is deliberately NOT a hook for a future LINE replay check (LINE can't have one).
  _nowMs: number,
): WebhookResult {
  const v = verifyLineSignature(rawBody, headers, channelSecret);
  if (!v.ok) return { kind: "reject", reason: v.reason };

  let payload: unknown;
  try {
    payload = JSON.parse(rawBody.toString("utf8"));
  } catch {
    return { kind: "reject", reason: "invalid_json" };
  }
  if (!isObject(payload) || !Array.isArray(payload.events)) {
    return { kind: "reject", reason: "invalid_payload" };
  }

  // 0..N text messages; non-message / non-text / id-less events are skipped. An empty
  // events[] (LINE's verify ping) → no messages → 200, nothing persisted.
  const messages: ParsedMessage[] = [];
  for (const ev of payload.events) {
    const parsed = normalizeLineEvent(ev);
    if (parsed) messages.push(parsed);
  }
  return { kind: "messages", messages };
}
