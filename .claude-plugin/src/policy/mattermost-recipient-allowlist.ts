// v1.107 — Mattermost recipient (channel_id) allowlist.
//
// The per-connector ID regex + the two env-var names; the parse / state /
// membership / summary logic is the shared policy/service-token-allowlist.ts
// factory. The Mattermost id regex stays a named export here —
// tools/handlers/mattermost.ts imports it for pre-egress syntactic validation.
//
//   SAFESPACE_MATTERMOST_RECIPIENT_ALLOW        (persistent)
//   SAFESPACE_MATTERMOST_RECIPIENT_ALLOW_EXTRA  (shell-only, additive, per-session)
//
// POLICY: unset/empty = ALLOW any valid id (a Mattermost post is a PRIVATE,
// tier-gated min_tier "share" surface → OFF=allow, the service-token posture, NOT
// the public youtube-comment deny-default); under SAFESPACE_AUTONOMOUS unset/empty
// DENIES ALL (F2 deny-by-default). See service-token-allowlist.ts for detail.

import {
  ENV_MATTERMOST_RECIPIENT_ALLOW as ENV_MM_ALLOW,
  ENV_MATTERMOST_RECIPIENT_ALLOW_EXTRA as ENV_MM_ALLOW_EXTRA,
} from "../config";
import {
  makeServiceTokenAllowlist,
  type ServiceTokenAllowlistState,
} from "./service-token-allowlist";

export { ENV_MM_ALLOW, ENV_MM_ALLOW_EXTRA };

/** A Mattermost id (channel / team / user / post) — exactly 26 lowercase base-32-ish
 *  chars [a-z0-9]. Anchored + fixed-alphabet implicitly rejects CR/LF/NUL/`/`/`.`/`:`/
 *  whitespace, so even where the id rides a URL PATH segment (e.g. GET
 *  /channels/{id}/posts) there is no traversal / host-escape surface. */
export const MATTERMOST_ID_RE = /^[a-z0-9]{26}$/;

export type MattermostAllowlistState = ServiceTokenAllowlistState;

const allowlist = makeServiceTokenAllowlist({
  idRe: MATTERMOST_ID_RE,
  envAllow: ENV_MM_ALLOW,
  envExtra: ENV_MM_ALLOW_EXTRA,
});

/** Resolve the current Mattermost allowlist state from the two env layers. */
export function getMattermostAllowlistState(): MattermostAllowlistState {
  return allowlist.getState();
}

/** Is this Mattermost channel id allowed to receive a post? POLICY membership only
 *  (syntactic validity is the handler's job, via MATTERMOST_ID_RE, before egress). */
export function isMattermostRecipientAllowed(
  id: string,
  state: MattermostAllowlistState,
): boolean {
  return allowlist.isAllowed(id, state);
}

/** Count-only summary for `safespace status` / `doctor` (never the ids). */
export function mattermostAllowlistSummary(): { kind: "off" | "active"; id_count: number } {
  return allowlist.summary();
}
