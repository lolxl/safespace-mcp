// v1.107 — Mattermost recipient (channel_id) allowlist.
//
// A Mattermost post targets a channel by its 26-char id. SafeSpace requires the ID (a
// channel NAME is mutable + ambiguous, not a stable allowlist key — the same posture as
// Slack/Discord). Mattermost gets the SAME two-layer env idiom the other service-token
// allowlists use:
//
//   SAFESPACE_MATTERMOST_RECIPIENT_ALLOW        (persistent)
//   SAFESPACE_MATTERMOST_RECIPIENT_ALLOW_EXTRA  (shell-only, additive, per-session)
//
// POLICY (identical to LINE / Telegram / Discord / Slack):
//   - Default unset/empty = ALLOW any syntactically-valid id (a Mattermost post is a
//     PRIVATE, tier-gated surface, min_tier "share" → OFF=allow, the service-token posture).
//   - Under SAFESPACE_AUTONOMOUS an unset/empty allowlist DENIES ALL (F2 deny-by-default).
//   - When configured, only listed ids pass (exact match).
//
// SECURITY: ids never appear in errors / doctor output (counts only); a denied id is
// HMAC-hashed into the audit denied-event by the egress gate, never echoed.

import { isAutonomousMode } from "./autonomous-mode";
import {
  ENV_MATTERMOST_RECIPIENT_ALLOW as ENV_MM_ALLOW,
  ENV_MATTERMOST_RECIPIENT_ALLOW_EXTRA as ENV_MM_ALLOW_EXTRA,
} from "../config";

export { ENV_MM_ALLOW, ENV_MM_ALLOW_EXTRA };

/** A Mattermost id (channel / team / user / post) — exactly 26 lowercase base-32-ish
 *  chars [a-z0-9]. Anchored + fixed-alphabet implicitly rejects CR/LF/NUL/`/`/`.`/`:`/
 *  whitespace, so even where the id rides a URL PATH segment (e.g. GET
 *  /channels/{id}/posts) there is no traversal / host-escape surface. */
export const MATTERMOST_ID_RE = /^[a-z0-9]{26}$/;

export type MattermostAllowlistState =
  | { kind: "off" }
  | { kind: "active"; ids: ReadonlySet<string> };

/** Parse a comma-separated env value into the set of syntactically-VALID ids.
 *  Malformed tokens are dropped at parse time (never matched, never echoed). */
function parseIds(raw: string | undefined): string[] {
  if (raw == null || raw.trim() === "") return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "" && MATTERMOST_ID_RE.test(s));
}

/** Resolve the current allowlist state from the two env layers. Read per-call (cheap
 *  env reads), like the Slack / LINE / Telegram / Discord loaders — no caching. */
export function getMattermostAllowlistState(): MattermostAllowlistState {
  const ids = new Set<string>([
    ...parseIds(process.env[ENV_MM_ALLOW]),
    ...parseIds(process.env[ENV_MM_ALLOW_EXTRA]),
  ]);
  return ids.size === 0 ? { kind: "off" } : { kind: "active", ids };
}

/** Is this Mattermost channel id allowed to receive a post?
 *   - `active`: exact membership.
 *   - `off`: ALLOW in interactive mode (private tier-gated surface); DENY in autonomous
 *     mode (F2 deny-by-default). Syntactic validity is the handler's job (MATTERMOST_ID_RE,
 *     before egress); this decides POLICY membership only. */
export function isMattermostRecipientAllowed(id: string, state: MattermostAllowlistState): boolean {
  if (state.kind === "active") return state.ids.has(id);
  return !isAutonomousMode();
}

/** Count-only summary for `safespace status` / `doctor` (never the ids). */
export function mattermostAllowlistSummary(): { kind: "off" | "active"; id_count: number } {
  const state = getMattermostAllowlistState();
  return state.kind === "off"
    ? { kind: "off", id_count: 0 }
    : { kind: "active", id_count: state.ids.size };
}
