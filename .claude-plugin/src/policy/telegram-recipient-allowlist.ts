// v1.68 — Telegram recipient (chat_id / @username) allowlist.
//
// The v2.2 recipient-allowlist (policy/recipient-allowlist.ts) is EMAIL-shaped and the
// v1.66 LINE allowlist is LINE-id-shaped; a Telegram chat target is neither (a signed
// integer chat id, or a public `@username`). So Telegram gets its own allowlist, the
// SAME two-layer env idiom (persistent + shell-only EXTRA) the recipient / LINE / v1.65
// web-fetch allowlists use:
//
//   SAFESPACE_TELEGRAM_RECIPIENT_ALLOW        (persistent)
//   SAFESPACE_TELEGRAM_RECIPIENT_ALLOW_EXTRA  (shell-only, additive, per-session)
//
// POLICY (matches docs/v1.68-telegram-connector.md §0 Q4 — identical posture to LINE):
//   - Default unset/empty = ALLOW any syntactically-valid chat id. A Telegram bot push
//     is a PRIVATE, tier-gated surface (min_tier "share"), so the default is OFF=allow —
//     the tasks-delete / LINE posture, NOT the public youtube-comment deny-default.
//   - Under SAFESPACE_AUTONOMOUS an unset/empty allowlist DENIES ALL (the F2
//     deny-by-default idiom — unattended, an un-configured allowlist must not be a
//     blank cheque; mirrors LINE + the v1.65 web-fetch autonomous deny).
//   - When configured, only listed ids pass (exact match).
//
// SECURITY: ids never appear in errors / doctor output (counts only); a denied id is
// HMAC-hashed into the audit denied-event by the egress gate, never echoed.

import { isAutonomousMode } from "./autonomous-mode";
import {
  ENV_TELEGRAM_RECIPIENT_ALLOW as ENV_TG_ALLOW,
  ENV_TELEGRAM_RECIPIENT_ALLOW_EXTRA as ENV_TG_ALLOW_EXTRA,
} from "../config";

export { ENV_TG_ALLOW, ENV_TG_ALLOW_EXTRA };

/** A Telegram messaging target. Two LOCKED-accepted shapes (docs §0 Q2):
 *   - a numeric chat id: optional leading `-` (group / supergroup / channel) then
 *     1–20 digits (`-100…` supergroups, positive private-user ids);
 *   - a public `@username`: `@` + a leading letter + 4–31 of `[A-Za-z0-9_]` (the
 *     Telegram handle rule — 5–32 chars EXCLUDING the `@`, first char a letter).
 *  Each alternative is anchored + restricted, so CR/LF/NUL/whitespace/`+`/decimals are
 *  implicitly rejected (the gmail/LINE recipient-gate invariant). */
export const TELEGRAM_CHAT_ID_RE = /^(?:-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$/;

export type TelegramAllowlistState =
  | { kind: "off" }
  | { kind: "active"; ids: ReadonlySet<string> };

/** Parse a comma-separated env value into the set of syntactically-VALID ids.
 *  Malformed tokens are dropped at parse time (never matched, never echoed). */
function parseIds(raw: string | undefined): string[] {
  if (raw == null || raw.trim() === "") return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "" && TELEGRAM_CHAT_ID_RE.test(s));
}

/** Resolve the current allowlist state from the two env layers. `off` when neither
 *  layer yields a valid id; `active` (the union) otherwise. Read per-call (cheap env
 *  reads), like the LINE / recipient-allowlist loaders — no caching, so a shell that
 *  exports the EXTRA var mid-session takes effect on the next call. */
export function getTelegramAllowlistState(): TelegramAllowlistState {
  const ids = new Set<string>([
    ...parseIds(process.env[ENV_TG_ALLOW]),
    ...parseIds(process.env[ENV_TG_ALLOW_EXTRA]),
  ]);
  return ids.size === 0 ? { kind: "off" } : { kind: "active", ids };
}

/** Is this Telegram chat id allowed to receive a push?
 *   - `active`: exact membership.
 *   - `off`: ALLOW in interactive mode (private tier-gated surface, default-allow);
 *     DENY in autonomous mode (F2 deny-by-default — an un-configured allowlist is not
 *     a blank cheque when unattended).
 *  Syntactic validity of `id` is the handler's job (TELEGRAM_CHAT_ID_RE, before egress);
 *  this decides POLICY membership only. */
export function isTelegramRecipientAllowed(
  id: string,
  state: TelegramAllowlistState,
): boolean {
  if (state.kind === "active") return state.ids.has(id);
  return !isAutonomousMode();
}

/** Count-only summary for `safespace status` / `doctor` (never the ids). */
export function telegramAllowlistSummary(): { kind: "off" | "active"; id_count: number } {
  const state = getTelegramAllowlistState();
  return state.kind === "off"
    ? { kind: "off", id_count: 0 }
    : { kind: "active", id_count: state.ids.size };
}
