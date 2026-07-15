// v1.68 — Telegram recipient (chat_id / @username) allowlist.
//
// Thin pack instantiation: the per-connector ID regex + the two env-var names live
// on TELEGRAM_PACK; the parse / state / membership / summary logic is the shared
// makeServiceTokenRecipientAllowlist factory. The Telegram chat-id regex stays a
// named export here — tools/handlers/telegram.ts imports it for pre-egress syntactic
// validation.
//
//   SAFESPACE_TELEGRAM_RECIPIENT_ALLOW        (persistent)
//   SAFESPACE_TELEGRAM_RECIPIENT_ALLOW_EXTRA  (shell-only, additive, per-session)
//
// POLICY: unset/empty = ALLOW any valid chat id (a Telegram bot push is a PRIVATE,
// tier-gated min_tier "share" surface → OFF=allow, the LINE posture, NOT the
// public youtube-comment deny-default); under SAFESPACE_AUTONOMOUS unset/empty
// DENIES ALL (F2 deny-by-default). See service-token-allowlist.ts for detail.

import { TELEGRAM_PACK } from "../tools/service-token-pack";
import {
  makeServiceTokenRecipientAllowlist,
  type ServiceTokenAllowlistState,
} from "./service-token-recipient-allowlist";

export const ENV_TG_ALLOW = TELEGRAM_PACK.env.recipientAllow;
export const ENV_TG_ALLOW_EXTRA = TELEGRAM_PACK.env.recipientAllowExtra;

/** A Telegram messaging target. Two LOCKED-accepted shapes (docs §0 Q2):
 *   - a numeric chat id: optional leading `-` (group / supergroup / channel) then
 *     1–20 digits (`-100…` supergroups, positive private-user ids);
 *   - a public `@username`: `@` + a leading letter + 4–31 of `[A-Za-z0-9_]` (the
 *     Telegram handle rule — 5–32 chars EXCLUDING the `@`, first char a letter).
 *  Each alternative is anchored + restricted, so CR/LF/NUL/whitespace/`+`/decimals are
 *  implicitly rejected (the gmail/LINE recipient-gate invariant). */
export const TELEGRAM_CHAT_ID_RE = TELEGRAM_PACK.recipientIdSpec.regex;

export type TelegramAllowlistState = ServiceTokenAllowlistState;

const allowlist = makeServiceTokenRecipientAllowlist(TELEGRAM_PACK);

/** Resolve the current Telegram allowlist state from the two env layers. */
export function getTelegramAllowlistState(): TelegramAllowlistState {
  return allowlist.getState();
}

/** Is this Telegram chat id allowed to receive a push? POLICY membership only
 *  (syntactic validity is the handler's job, via TELEGRAM_CHAT_ID_RE, before egress). */
export function isTelegramRecipientAllowed(
  id: string,
  state: TelegramAllowlistState,
): boolean {
  return allowlist.isAllowed(id, state);
}

/** Count-only summary for `safespace status` / `doctor` (never the ids). */
export function telegramAllowlistSummary(): { kind: "off" | "active"; id_count: number } {
  return allowlist.summary();
}
