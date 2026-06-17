// v1.66 Phase C PR 2 — LINE recipient (userId / groupId / roomId) allowlist.
//
// The v2.2 recipient-allowlist (policy/recipient-allowlist.ts) is EMAIL-shaped and
// cannot hold a LINE id (an opaque "U"/"C"/"R" + 32 hex). So LINE gets its own
// allowlist, the SAME two-layer env idiom (persistent + shell-only EXTRA) the
// recipient allowlist and the v1.65 web-fetch allow use:
//
//   SAFESPACE_LINE_RECIPIENT_ALLOW        (persistent)
//   SAFESPACE_LINE_RECIPIENT_ALLOW_EXTRA  (shell-only, additive, per-session)
//
// POLICY (matches docs/v1.66-line-oa-connector.md §5):
//   - Default unset/empty = ALLOW any syntactically-valid id. LINE push is a
//     PRIVATE, tier-gated surface (min_tier "share"), so the default is OFF=allow —
//     the tasks-delete posture, NOT the public youtube-comment deny-default.
//   - Under SAFESPACE_AUTONOMOUS an unset/empty allowlist DENIES ALL (the F2
//     deny-by-default idiom — unattended, an un-configured allowlist must not be a
//     blank cheque; mirrors the v1.65 web-fetch autonomous deny).
//   - When configured, only listed ids pass (exact match).
//
// SECURITY: ids never appear in errors / doctor output (counts only); a denied id
// is HMAC-hashed into the audit denied-event by the egress gate, never echoed.

import { isAutonomousMode } from "./autonomous-mode";
import {
  ENV_LINE_RECIPIENT_ALLOW as ENV_LINE_ALLOW,
  ENV_LINE_RECIPIENT_ALLOW_EXTRA as ENV_LINE_ALLOW_EXTRA,
} from "../config";

export { ENV_LINE_ALLOW, ENV_LINE_ALLOW_EXTRA };

/** A LINE messaging target id: user `U…`, group `C…`, or room `R…`, each followed
 *  by 32 lowercase hex chars. Anchored + restricted class implicitly rejects
 *  CR/LF/NUL/path/whitespace (the gmail recipient-gate invariant). */
export const LINE_ID_RE = /^[UCR][0-9a-f]{32}$/;

export type LineAllowlistState =
  | { kind: "off" }
  | { kind: "active"; ids: ReadonlySet<string> };

/** Parse a comma-separated env value into the set of syntactically-VALID ids.
 *  Malformed tokens are dropped at parse time (never matched, never echoed). */
function parseIds(raw: string | undefined): string[] {
  if (raw == null || raw.trim() === "") return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "" && LINE_ID_RE.test(s));
}

/** Resolve the current allowlist state from the two env layers. `off` when neither
 *  layer yields a valid id; `active` (the union) otherwise. Read per-call (cheap
 *  env reads), like the recipient-allowlist's loader — no caching, so a shell that
 *  exports the EXTRA var mid-session takes effect on the next call. */
export function getLineAllowlistState(): LineAllowlistState {
  const ids = new Set<string>([
    ...parseIds(process.env[ENV_LINE_ALLOW]),
    ...parseIds(process.env[ENV_LINE_ALLOW_EXTRA]),
  ]);
  return ids.size === 0 ? { kind: "off" } : { kind: "active", ids };
}

/** Is this LINE recipient id allowed to receive a push?
 *   - `active`: exact membership.
 *   - `off`: ALLOW in interactive mode (private tier-gated surface, default-allow);
 *     DENY in autonomous mode (F2 deny-by-default — an un-configured allowlist is
 *     not a blank cheque when unattended).
 *  Syntactic validity of `id` is the handler's job (validateLineId, before egress);
 *  this decides POLICY membership only. */
export function isLineRecipientAllowed(id: string, state: LineAllowlistState): boolean {
  if (state.kind === "active") return state.ids.has(id);
  return !isAutonomousMode();
}

/** Count-only summary for `safespace status` / `doctor` (never the ids). */
export function lineAllowlistSummary(): { kind: "off" | "active"; id_count: number } {
  const state = getLineAllowlistState();
  return state.kind === "off"
    ? { kind: "off", id_count: 0 }
    : { kind: "active", id_count: state.ids.size };
}
