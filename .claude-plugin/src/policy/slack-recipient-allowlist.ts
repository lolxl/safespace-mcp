// v1.95 — Slack recipient (channel / group / DM / user id) allowlist.
//
// The per-connector ID regex + the two env-var names; the parse / state /
// membership / summary logic is the shared policy/service-token-allowlist.ts
// factory. The Slack conversation-id regex stays a named export here —
// tools/handlers/slack.ts imports it for pre-egress syntactic validation.
//
//   SAFESPACE_SLACK_RECIPIENT_ALLOW        (persistent)
//   SAFESPACE_SLACK_RECIPIENT_ALLOW_EXTRA  (shell-only, additive, per-session)
//
// POLICY: unset/empty = ALLOW any valid id (a Slack bot post is a PRIVATE,
// tier-gated min_tier "share" surface → OFF=allow, the service-token posture, NOT
// the public youtube-comment deny-default); under SAFESPACE_AUTONOMOUS unset/empty
// DENIES ALL (F2 deny-by-default). See service-token-allowlist.ts for detail.

import {
  ENV_SLACK_RECIPIENT_ALLOW as ENV_SK_ALLOW,
  ENV_SLACK_RECIPIENT_ALLOW_EXTRA as ENV_SK_ALLOW_EXTRA,
} from "../config";
import {
  makeServiceTokenAllowlist,
  type ServiceTokenAllowlistState,
} from "./service-token-allowlist";

export { ENV_SK_ALLOW, ENV_SK_ALLOW_EXTRA };

/** A Slack conversation target id: a channel `C…`, private group `G…`, DM `D…`, or a
 *  user `U…`/`W…` (a user id addresses a direct message). Slack ids are an uppercase
 *  base-34-ish alphabet [A-Z0-9], typically 9–11 chars; `{6,20}` covers the range with
 *  margin while staying bounded (parity with Discord's bounded `{17,20}`). Anchored +
 *  fixed-alphabet implicitly rejects CR/LF/NUL/`#name`/`@name`/whitespace, and since the
 *  id rides in the request BODY (not a URL path segment for chat.postMessage) there is no
 *  traversal surface — the bound is hygiene, not a path guard. */
export const SLACK_CHANNEL_ID_RE = /^[CDGUW][A-Z0-9]{6,20}$/;

export type SlackAllowlistState = ServiceTokenAllowlistState;

const allowlist = makeServiceTokenAllowlist({
  idRe: SLACK_CHANNEL_ID_RE,
  envAllow: ENV_SK_ALLOW,
  envExtra: ENV_SK_ALLOW_EXTRA,
});

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
