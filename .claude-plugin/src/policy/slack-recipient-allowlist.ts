// v1.95 — Slack recipient (channel / group / DM / user id) allowlist.
//
// A Slack send targets a conversation by its id (a channel `C…`, a private group `G…`,
// a DM `D…`, or a user `U…`/`W…` for a direct message). The chat.postMessage API also
// accepts a `#channel-name`, but a NAME is mutable + ambiguous and not a stable
// allowlist key, so SafeSpace requires an ID (the same posture as Discord requiring a
// numeric snowflake, not an @name). Slack gets its own allowlist, the SAME two-layer
// env idiom (persistent + shell-only EXTRA) the recipient / LINE / Telegram / Discord
// allowlists use:
//
//   SAFESPACE_SLACK_RECIPIENT_ALLOW        (persistent)
//   SAFESPACE_SLACK_RECIPIENT_ALLOW_EXTRA  (shell-only, additive, per-session)
//
// POLICY (identical posture to LINE / Telegram / Discord):
//   - Default unset/empty = ALLOW any syntactically-valid id. A Slack bot post is a
//     PRIVATE, tier-gated surface (min_tier "share"), so the default is OFF=allow — the
//     service-token posture, NOT the public youtube-comment deny-default.
//   - Under SAFESPACE_AUTONOMOUS an unset/empty allowlist DENIES ALL (the F2
//     deny-by-default idiom — unattended, an un-configured allowlist must not be a
//     blank cheque; mirrors LINE / Telegram / Discord / the v1.65 web-fetch autonomous deny).
//   - When configured, only listed ids pass (exact match).
//
// SECURITY: ids never appear in errors / doctor output (counts only); a denied id is
// HMAC-hashed into the audit denied-event by the egress gate, never echoed.

import { isAutonomousMode } from "./autonomous-mode";
import {
  ENV_SLACK_RECIPIENT_ALLOW as ENV_SK_ALLOW,
  ENV_SLACK_RECIPIENT_ALLOW_EXTRA as ENV_SK_ALLOW_EXTRA,
} from "../config";

export { ENV_SK_ALLOW, ENV_SK_ALLOW_EXTRA };

/** A Slack conversation target id: a channel `C…`, private group `G…`, DM `D…`, or a
 *  user `U…`/`W…` (a user id addresses a direct message). Slack ids are an uppercase
 *  base-34-ish alphabet [A-Z0-9], typically 9–11 chars; `{6,20}` covers the range with
 *  margin while staying bounded (parity with Discord's bounded `{17,20}`). Anchored +
 *  fixed-alphabet implicitly rejects CR/LF/NUL/`#name`/`@name`/whitespace, and since the
 *  id rides in the request BODY (not a URL path segment for chat.postMessage) there is no
 *  traversal surface — the bound is hygiene, not a path guard. */
export const SLACK_CHANNEL_ID_RE = /^[CDGUW][A-Z0-9]{6,20}$/;

export type SlackAllowlistState =
  | { kind: "off" }
  | { kind: "active"; ids: ReadonlySet<string> };

/** Parse a comma-separated env value into the set of syntactically-VALID ids.
 *  Malformed tokens are dropped at parse time (never matched, never echoed). */
function parseIds(raw: string | undefined): string[] {
  if (raw == null || raw.trim() === "") return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "" && SLACK_CHANNEL_ID_RE.test(s));
}

/** Resolve the current allowlist state from the two env layers. `off` when neither
 *  layer yields a valid id; `active` (the union) otherwise. Read per-call (cheap env
 *  reads), like the LINE / Telegram / Discord loaders — no caching, so a shell that
 *  exports the EXTRA var mid-session takes effect on the next call. */
export function getSlackAllowlistState(): SlackAllowlistState {
  const ids = new Set<string>([
    ...parseIds(process.env[ENV_SK_ALLOW]),
    ...parseIds(process.env[ENV_SK_ALLOW_EXTRA]),
  ]);
  return ids.size === 0 ? { kind: "off" } : { kind: "active", ids };
}

/** Is this Slack conversation id allowed to receive a post?
 *   - `active`: exact membership.
 *   - `off`: ALLOW in interactive mode (private tier-gated surface, default-allow);
 *     DENY in autonomous mode (F2 deny-by-default — an un-configured allowlist is not
 *     a blank cheque when unattended).
 *  Syntactic validity of `id` is the handler's job (SLACK_CHANNEL_ID_RE, before egress);
 *  this decides POLICY membership only. */
export function isSlackRecipientAllowed(id: string, state: SlackAllowlistState): boolean {
  if (state.kind === "active") return state.ids.has(id);
  return !isAutonomousMode();
}

/** Count-only summary for `safespace status` / `doctor` (never the ids). */
export function slackAllowlistSummary(): { kind: "off" | "active"; id_count: number } {
  const state = getSlackAllowlistState();
  return state.kind === "off"
    ? { kind: "off", id_count: 0 }
    : { kind: "active", id_count: state.ids.size };
}
