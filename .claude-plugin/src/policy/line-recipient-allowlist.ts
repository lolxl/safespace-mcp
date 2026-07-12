// v1.66 Phase C PR 2 — LINE recipient (userId / groupId / roomId) allowlist.
//
// The per-connector ID regex + the two env-var names; the parse / state /
// membership / summary logic is the shared policy/service-token-allowlist.ts
// factory (all 5 service-token allowlists were byte-identical except these). The
// LINE id regex stays a named export here — tools/handlers/line.ts imports it for
// pre-egress syntactic validation.
//
//   SAFESPACE_LINE_RECIPIENT_ALLOW        (persistent)
//   SAFESPACE_LINE_RECIPIENT_ALLOW_EXTRA  (shell-only, additive, per-session)
//
// POLICY: unset/empty = ALLOW any valid id (a LINE push is a PRIVATE, tier-gated
// min_tier "share" surface → OFF=allow, the tasks-delete posture, NOT the public
// youtube-comment deny-default); under SAFESPACE_AUTONOMOUS unset/empty DENIES ALL
// (F2 deny-by-default). See service-token-allowlist.ts for the full policy + the
// no-PII-echo contract.

import {
  ENV_LINE_RECIPIENT_ALLOW as ENV_LINE_ALLOW,
  ENV_LINE_RECIPIENT_ALLOW_EXTRA as ENV_LINE_ALLOW_EXTRA,
} from "../config";
import {
  makeServiceTokenAllowlist,
  type ServiceTokenAllowlistState,
} from "./service-token-allowlist";

export { ENV_LINE_ALLOW, ENV_LINE_ALLOW_EXTRA };

/** A LINE messaging target id: user `U…`, group `C…`, or room `R…`, each followed
 *  by 32 lowercase hex chars. Anchored + restricted class implicitly rejects
 *  CR/LF/NUL/path/whitespace (the gmail recipient-gate invariant). */
export const LINE_ID_RE = /^[UCR][0-9a-f]{32}$/;

export type LineAllowlistState = ServiceTokenAllowlistState;

const allowlist = makeServiceTokenAllowlist({
  idRe: LINE_ID_RE,
  envAllow: ENV_LINE_ALLOW,
  envExtra: ENV_LINE_ALLOW_EXTRA,
});

/** Resolve the current LINE allowlist state from the two env layers. */
export function getLineAllowlistState(): LineAllowlistState {
  return allowlist.getState();
}

/** Is this LINE recipient id allowed to receive a push? POLICY membership only
 *  (syntactic validity is the handler's job, via LINE_ID_RE, before egress). */
export function isLineRecipientAllowed(id: string, state: LineAllowlistState): boolean {
  return allowlist.isAllowed(id, state);
}

/** Count-only summary for `safespace status` / `doctor` (never the ids). */
export function lineAllowlistSummary(): { kind: "off" | "active"; id_count: number } {
  return allowlist.summary();
}
