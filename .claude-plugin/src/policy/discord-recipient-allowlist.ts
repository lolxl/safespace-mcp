// v1.69 — Discord recipient (channel_id snowflake) allowlist.
//
// Thin pack instantiation: the per-connector ID regex + the two env-var names live
// on DISCORD_PACK; the parse / state / membership / summary logic is the shared
// makeServiceTokenRecipientAllowlist factory. The Discord snowflake regex stays a
// named export here — tools/handlers/discord.ts imports it for pre-egress syntactic
// validation.
//
//   SAFESPACE_DISCORD_RECIPIENT_ALLOW        (persistent)
//   SAFESPACE_DISCORD_RECIPIENT_ALLOW_EXTRA  (shell-only, additive, per-session)
//
// POLICY: unset/empty = ALLOW any valid channel id (a Discord bot post is a
// PRIVATE, tier-gated min_tier "share" surface → OFF=allow, the LINE/Telegram
// posture, NOT the public youtube-comment deny-default); under SAFESPACE_AUTONOMOUS
// unset/empty DENIES ALL (F2 deny-by-default). See service-token-allowlist.ts.

import { DISCORD_PACK } from "../tools/service-token-pack";
import {
  makeServiceTokenRecipientAllowlist,
  type ServiceTokenAllowlistState,
} from "./service-token-recipient-allowlist";

export const ENV_DC_ALLOW = DISCORD_PACK.env.recipientAllow;
export const ENV_DC_ALLOW_EXTRA = DISCORD_PACK.env.recipientAllowExtra;

/** A Discord channel target: a numeric snowflake id. Discord snowflakes are 64-bit
 *  (currently 18–19 digits; the 64-bit max is 20 digits), so 17–20 digits covers the
 *  full range with margin. Anchored + digit-only implicitly rejects CR/LF/NUL/`@name`/
 *  path/whitespace/sign (the gmail/LINE recipient-gate invariant) — and since the id
 *  is also a URL path segment in the handler, digit-only forecloses any traversal. */
export const DISCORD_CHANNEL_ID_RE = DISCORD_PACK.recipientIdSpec.regex;

export type DiscordAllowlistState = ServiceTokenAllowlistState;

const allowlist = makeServiceTokenRecipientAllowlist(DISCORD_PACK);

/** Resolve the current Discord allowlist state from the two env layers. */
export function getDiscordAllowlistState(): DiscordAllowlistState {
  return allowlist.getState();
}

/** Is this Discord channel id allowed to receive a post? POLICY membership only
 *  (syntactic validity is the handler's job, via DISCORD_CHANNEL_ID_RE, before egress). */
export function isDiscordRecipientAllowed(
  id: string,
  state: DiscordAllowlistState,
): boolean {
  return allowlist.isAllowed(id, state);
}

/** Count-only summary for `safespace status` / `doctor` (never the ids). */
export function discordAllowlistSummary(): { kind: "off" | "active"; id_count: number } {
  return allowlist.summary();
}
