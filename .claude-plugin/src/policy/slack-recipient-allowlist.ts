// v1.95 — Slack recipient (channel / group / DM / user id) allowlist.
//
// Thin pack instantiation: the per-connector ID regex + the two env-var names live
// on SLACK_PACK; the parse / state / membership / summary logic is the shared
// makeServiceTokenRecipientAllowlist factory. The Slack conversation-id regex stays a
// named export here — tools/handlers/slack.ts imports it for pre-egress syntactic
// validation.
//
//   SAFESPACE_SLACK_RECIPIENT_ALLOW        (persistent)
//   SAFESPACE_SLACK_RECIPIENT_ALLOW_EXTRA  (shell-only, additive, per-session)
//
// POLICY: unset/empty = ALLOW any valid id (a Slack bot post is a PRIVATE,
// tier-gated min_tier "share" surface → OFF=allow, the service-token posture, NOT
// the public youtube-comment deny-default); under SAFESPACE_AUTONOMOUS unset/empty
// DENIES ALL (F2 deny-by-default). See service-token-allowlist.ts for detail.

import { SLACK_PACK } from "../tools/service-token-pack";
import {
  makeServiceTokenRecipientAllowlist,
  type ServiceTokenAllowlistState,
} from "./service-token-recipient-allowlist";

export const ENV_SK_ALLOW = SLACK_PACK.env.recipientAllow;
export const ENV_SK_ALLOW_EXTRA = SLACK_PACK.env.recipientAllowExtra;

/** A Slack conversation target id: a channel `C…`, private group `G…`, DM `D…`, or a
 *  user `U…`/`W…` (a user id addresses a direct message). Slack ids are an uppercase
 *  base-34-ish alphabet [A-Z0-9], typically 9–11 chars; `{6,20}` covers the range with
 *  margin while staying bounded (parity with Discord's bounded `{17,20}`). Anchored +
 *  fixed-alphabet implicitly rejects CR/LF/NUL/`#name`/`@name`/whitespace, and since the
 *  id rides in the request BODY (not a URL path segment for chat.postMessage) there is no
 *  traversal surface — the bound is hygiene, not a path guard. */
export const SLACK_CHANNEL_ID_RE = SLACK_PACK.recipientIdSpec.regex;

export type SlackAllowlistState = ServiceTokenAllowlistState;

const allowlist = makeServiceTokenRecipientAllowlist(SLACK_PACK);

/** Resolve the current Slack allowlist state from the two env layers. */
export function getSlackAllowlistState(): SlackAllowlistState {
  return allowlist.getState();
}

/** Is this Slack conversation id allowed to receive a post? POLICY membership only
 *  (syntactic validity is the handler's job, via SLACK_CHANNEL_ID_RE, before egress). */
export function isSlackRecipientAllowed(id: string, state: SlackAllowlistState): boolean {
  return allowlist.isAllowed(id, state);
}

/** Count-only summary for `safespace status` / `doctor` (never the ids). */
export function slackAllowlistSummary(): { kind: "off" | "active"; id_count: number } {
  return allowlist.summary();
}
