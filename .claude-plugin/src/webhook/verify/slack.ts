// v1.102 (W0) — Slack Events API webhook verification.
//
// docs/v1.102-webhook-listener.md §5.2. The FIRST public, untrusted-remote-caller
// surface SafeSpace has ever had. The load-bearing controls:
//   - VERIFY FIRST, ALWAYS — even for url_verification. Slack signs every Events API
//     request (including the setup handshake), and the listener's fail-loud
//     guarantees the signing secret is present before serving, so there is NO unsigned
//     path. `type` is read ONLY after a valid signature → an attacker cannot forge
//     `type:"url_verification"` to bypass the check (security HIGH-1).
//   - The HMAC is computed over the RAW request bytes (`v0:ts:<rawbody>`), never a
//     re-serialized JSON (re-serialization changes the signed bytes).
//   - timing-safe compare; a 5-minute replay window on the signed timestamp.
//   - A missing/absent signature header fails CLOSED (treated as a wrong one).
//
// PURE: this module does no I/O. The signing secret is read per-request by the
// listener (from the SecretBackend, never cached) and passed in.

import * as crypto from "node:crypto";
import type { IncomingHttpHeaders } from "node:http";
import type { InboxMsg, WebhookResult } from "../types";
import { headerOf, isObject, timingSafeEqualStr } from "./util";
import { WEBHOOK_SIGNATURE_HMAC_ALG } from "../../crypto-algorithms";

/** Slack's recommended replay window: reject a signed timestamp older/newer than 5 min. */
const REPLAY_WINDOW_S = 300;
/** url_verification challenge defence-in-depth: a short token Slack echoes back. */
const MAX_CHALLENGE_LEN = 100;
const CHALLENGE_RE = /^[A-Za-z0-9_-]+$/;

/** Verify the Slack signature over the RAW body. Pure. A missing header, a bad
 *  timestamp, a stale timestamp, or a wrong MAC all fail closed with a closed-set
 *  reason (never echoed to the wire). */
export function verifySlackSignature(
  rawBody: Buffer,
  headers: IncomingHttpHeaders,
  signingSecret: string,
  nowMs: number,
): { ok: true } | { ok: false; reason: "missing_signature" | "bad_timestamp" | "replay" | "bad_signature" } {
  const sig = headerOf(headers, "x-slack-signature");
  const tsRaw = headerOf(headers, "x-slack-request-timestamp");
  if (!sig || !tsRaw) return { ok: false, reason: "missing_signature" };
  const ts = Number(tsRaw);
  if (!Number.isInteger(ts) || ts <= 0) return { ok: false, reason: "bad_timestamp" };
  if (Math.abs(Math.floor(nowMs / 1000) - ts) > REPLAY_WINDOW_S) return { ok: false, reason: "replay" };
  // HMAC over `v0:<ts>:` ‖ rawbody bytes (NOT a re-encoded JSON string).
  const hmac = crypto.createHmac(WEBHOOK_SIGNATURE_HMAC_ALG, signingSecret);
  hmac.update(`v0:${tsRaw}:`);
  hmac.update(rawBody);
  const expected = `v0=${hmac.digest("hex")}`;
  if (!timingSafeEqualStr(sig, expected)) return { ok: false, reason: "bad_signature" };
  return { ok: true };
}

/** Verify-FIRST, then parse, then dispatch on `type`. The single entry the listener
 *  calls for a `POST /webhook/slack`. Returns a {@link WebhookResult} the listener maps
 *  to an HTTP response + a persist/audit action. */
export function handleSlackWebhook(
  rawBody: Buffer,
  headers: IncomingHttpHeaders,
  signingSecret: string,
  nowMs: number,
): WebhookResult {
  // 1. VERIFY (always, including url_verification — there is no pre-auth path).
  const v = verifySlackSignature(rawBody, headers, signingSecret, nowMs);
  if (!v.ok) return { kind: "reject", reason: v.reason };

  // 2. Parse ONLY after a valid signature.
  let payload: unknown;
  try {
    payload = JSON.parse(rawBody.toString("utf8"));
  } catch {
    return { kind: "reject", reason: "invalid_json" };
  }
  if (!isObject(payload)) return { kind: "reject", reason: "invalid_payload" };

  // 3. Dispatch on `type` (read AFTER verify — unforgeable).
  const type = payload.type;

  if (type === "url_verification") {
    // Echo the challenge ONLY (text/plain, in the listener); never persist/sanitize/
    // audit. Defence-in-depth on the reflected value: short + alphanumeric.
    const challenge = payload.challenge;
    if (
      typeof challenge !== "string" ||
      challenge.length === 0 ||
      challenge.length > MAX_CHALLENGE_LEN ||
      !CHALLENGE_RE.test(challenge)
    ) {
      return { kind: "reject", reason: "bad_challenge" };
    }
    return { kind: "challenge", challenge };
  }

  if (type === "event_callback") {
    // event_id is Slack's per-delivery dedup id — REQUIRED (§4 reject-missing-id: a
    // missing id from a real provider is anomalous + would evade dedup).
    const eventId = payload.event_id;
    if (typeof eventId !== "string" || eventId.length === 0) {
      return { kind: "reject", reason: "missing_event_id" };
    }
    const event = payload.event;
    // W0 persists plain user MESSAGE events only: no subtype (skip bot_message /
    // message_changed / message_deleted / …), with non-empty text. Anything else is a
    // verified-but-not-persisted receipt → ignore (200, no store write).
    if (
      !isObject(event) ||
      event.type !== "message" ||
      typeof event.subtype === "string" ||
      typeof event.text !== "string" ||
      event.text.length === 0
    ) {
      return { kind: "messages", messages: [] }; // verified, nothing to persist
    }
    const ts = typeof event.ts === "string" ? event.ts : "";
    const msg: InboxMsg = {
      // client_msg_id is the stable per-message id; fall back to ts (always present on a
      // real message event). If BOTH are absent (malformed) this is "" — harmless: dedup
      // keys on the OUTER event_id (required above), not on provider_message_id.
      provider_message_id: typeof event.client_msg_id === "string" ? event.client_msg_id : ts,
      ts,
      sender_id: typeof event.user === "string" ? event.user : "",
      sender_name: null, // a Slack message event carries only the user id, no display name
      channel_id: typeof event.channel === "string" ? event.channel : "",
      text: event.text,
    };
    return { kind: "messages", messages: [{ event_id: eventId, msg }] };
  }

  // A verified non-message envelope (e.g. app_rate_limited) — acknowledge, don't store.
  return { kind: "messages", messages: [] };
}
