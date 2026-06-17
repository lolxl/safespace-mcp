// v1.102 (W0) — the inbound webhook listener's shared types.
//
// docs/v1.102-webhook-listener.md §4.2: ONE canonical normalized inbox row shape,
// referenced by the verify modules (which produce `InboxMsg`), the inbox store
// (which persists `InboxRow`), the `inbox_read` tool (which returns the curated
// msg), and the `webhook` Source's skipFields. The listener normalizes every
// provider's wire envelope to this shape at receipt, so the store holds ONE shape
// across providers — never three envelope dialects (the §5.3 skipFields pin).

/** The providers the inbox can hold. W0 wires only Slack in the listener; the union
 *  is forward-compatible so W1 (LINE) / W2 (Telegram) add a verify module + a route
 *  WITHOUT a store/type schema change. */
export type WebhookProvider = "slack" | "line" | "telegram";

/** The normalized, agent-facing message — the SAME shape for every provider.
 *  Opaque ids/timestamps are skip-listed by the `webhook` Source (passed raw); the
 *  attacker-influenceable fields (`sender_name`, `text`) are OUT of skipFields → the
 *  read choke point WRAPS them as an untrusted source. */
export interface InboxMsg {
  /** Opaque provider message id (Slack `client_msg_id`/`ts`). skip. */
  readonly provider_message_id: string;
  /** Opaque provider timestamp/cursor (Slack `ts` — looks numeric but is an opaque
   *  ref). skip. */
  readonly ts: string;
  /** Opaque sender id (Slack `user` = `U…`, NOT a display name). skip. */
  readonly sender_id: string;
  /** Sender display name when the provider supplies one (Slack message events carry
   *  only the user id → null). WRAP. */
  readonly sender_name: string | null;
  /** Opaque channel/chat id. skip. */
  readonly channel_id: string;
  /** The message text — the highest prompt-injection surface. WRAP. */
  readonly text: string;
}

/** A persisted inbox row. `seq` is the monotonic server-assigned cursor (the agent
 *  reads `inbox_read(after_seq=N)`); `event_id` is the provider dedup id (REQUIRED —
 *  §4 reject-missing-id). The raw `event_id` lives ONLY here for dedup; the audit
 *  records sha256(event_id), never the raw id. */
export interface InboxRow {
  readonly seq: number;
  readonly provider: WebhookProvider;
  readonly event_id: string;
  readonly received_at: string;
  readonly expires_at: string;
  readonly msg: InboxMsg;
}

/** The outcome of verifying + parsing one webhook POST (a verify module returns this;
 *  the listener maps it to an HTTP response + a store/audit action):
 *   - `challenge`  → 200 echo the (validated) challenge; NEVER persist/sanitize/audit
 *                    (the Slack url_verification handshake — §5.2).
 *   - `event`      → dedup on `event_id`, persist `msg`, audit a verified receipt, 200.
 *   - `ignore`     → verified but not a message we persist (other event type/subtype);
 *                    200, no persist.
 *   - `reject`     → bad/absent signature or malformed; NO persist, counts-only
 *                    rejected audit. `reason` classifies the HTTP status (signature →
 *                    401, post-verify malformed → 400). */
export type WebhookResult =
  | { readonly kind: "challenge"; readonly challenge: string }
  | { readonly kind: "messages"; readonly messages: readonly ParsedMessage[] }
  | { readonly kind: "reject"; readonly reason: WebhookRejectReason };

/** One verified, normalized message to persist: its provider dedup id + the message.
 *  A verifier returns 0..N of these (Slack: 0 or 1 per POST; LINE: 0..N — one POST
 *  carries an events[] array). An empty list = "verified, nothing to persist" (a
 *  non-message event, or LINE's empty verify ping) → 200, no store write. */
export interface ParsedMessage {
  readonly event_id: string;
  readonly msg: InboxMsg;
}

/** Closed set of reject reasons. Signature reasons → HTTP 401; the rest are
 *  post-verify malformed → HTTP 400. NONE is ever echoed to the caller (the wire gets
 *  a bare status), and the rejected audit records only a COUNT, never the reason per
 *  request — the reason is for the in-process status classification only. */
export type WebhookRejectReason =
  | "missing_signature"
  | "bad_timestamp"
  | "replay"
  | "bad_signature"
  | "invalid_json"
  | "invalid_payload"
  | "missing_event_id"
  | "bad_challenge";

/** Signature-class reject reasons map to HTTP 401; all others (post-verify malformed)
 *  map to 400. A bare status only — the reason never reaches the wire. */
export function rejectHttpStatus(reason: WebhookRejectReason): 400 | 401 {
  switch (reason) {
    case "missing_signature":
    case "bad_timestamp":
    case "replay":
    case "bad_signature":
      return 401;
    default:
      return 400;
  }
}
