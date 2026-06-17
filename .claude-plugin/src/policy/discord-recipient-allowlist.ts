// v1.69 — Discord recipient (channel_id snowflake) allowlist.
//
// A Discord send targets a channel by its numeric snowflake id; there is no
// `@channel-name` addressing in the REST send API. So Discord gets its own allowlist,
// the SAME two-layer env idiom (persistent + shell-only EXTRA) the recipient / LINE /
// Telegram / v1.65 web-fetch allowlists use:
//
//   SAFESPACE_DISCORD_RECIPIENT_ALLOW        (persistent)
//   SAFESPACE_DISCORD_RECIPIENT_ALLOW_EXTRA  (shell-only, additive, per-session)
//
// POLICY (matches docs/v1.69-discord-connector.md §0 Q4 — identical posture to LINE /
// Telegram):
//   - Default unset/empty = ALLOW any syntactically-valid channel id. A Discord bot
//     post is a PRIVATE, tier-gated surface (min_tier "share"), so the default is
//     OFF=allow — the LINE/Telegram posture, NOT the public youtube-comment deny-default.
//   - Under SAFESPACE_AUTONOMOUS an unset/empty allowlist DENIES ALL (the F2
//     deny-by-default idiom — unattended, an un-configured allowlist must not be a
//     blank cheque; mirrors LINE / Telegram / the v1.65 web-fetch autonomous deny).
//   - When configured, only listed ids pass (exact match).
//
// SECURITY: ids never appear in errors / doctor output (counts only); a denied id is
// HMAC-hashed into the audit denied-event by the egress gate, never echoed.

import { isAutonomousMode } from "./autonomous-mode";
import {
  ENV_DISCORD_RECIPIENT_ALLOW as ENV_DC_ALLOW,
  ENV_DISCORD_RECIPIENT_ALLOW_EXTRA as ENV_DC_ALLOW_EXTRA,
} from "../config";

export { ENV_DC_ALLOW, ENV_DC_ALLOW_EXTRA };

/** A Discord channel target: a numeric snowflake id. Discord snowflakes are 64-bit
 *  (currently 18–19 digits; the 64-bit max is 20 digits), so 17–20 digits covers the
 *  full range with margin. Anchored + digit-only implicitly rejects CR/LF/NUL/`@name`/
 *  path/whitespace/sign (the gmail/LINE recipient-gate invariant) — and since the id
 *  is also a URL path segment in the handler, digit-only forecloses any traversal. */
export const DISCORD_CHANNEL_ID_RE = /^\d{17,20}$/;

export type DiscordAllowlistState =
  | { kind: "off" }
  | { kind: "active"; ids: ReadonlySet<string> };

/** Parse a comma-separated env value into the set of syntactically-VALID ids.
 *  Malformed tokens are dropped at parse time (never matched, never echoed). */
function parseIds(raw: string | undefined): string[] {
  if (raw == null || raw.trim() === "") return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "" && DISCORD_CHANNEL_ID_RE.test(s));
}

/** Resolve the current allowlist state from the two env layers. `off` when neither
 *  layer yields a valid id; `active` (the union) otherwise. Read per-call (cheap env
 *  reads), like the LINE / Telegram loaders — no caching, so a shell that exports the
 *  EXTRA var mid-session takes effect on the next call. */
export function getDiscordAllowlistState(): DiscordAllowlistState {
  const ids = new Set<string>([
    ...parseIds(process.env[ENV_DC_ALLOW]),
    ...parseIds(process.env[ENV_DC_ALLOW_EXTRA]),
  ]);
  return ids.size === 0 ? { kind: "off" } : { kind: "active", ids };
}

/** Is this Discord channel id allowed to receive a post?
 *   - `active`: exact membership.
 *   - `off`: ALLOW in interactive mode (private tier-gated surface, default-allow);
 *     DENY in autonomous mode (F2 deny-by-default — an un-configured allowlist is not
 *     a blank cheque when unattended).
 *  Syntactic validity of `id` is the handler's job (DISCORD_CHANNEL_ID_RE, before
 *  egress); this decides POLICY membership only. */
export function isDiscordRecipientAllowed(
  id: string,
  state: DiscordAllowlistState,
): boolean {
  if (state.kind === "active") return state.ids.has(id);
  return !isAutonomousMode();
}

/** Count-only summary for `safespace status` / `doctor` (never the ids). */
export function discordAllowlistSummary(): { kind: "off" | "active"; id_count: number } {
  const state = getDiscordAllowlistState();
  return state.kind === "off"
    ? { kind: "off", id_count: 0 }
    : { kind: "active", id_count: state.ids.size };
}
