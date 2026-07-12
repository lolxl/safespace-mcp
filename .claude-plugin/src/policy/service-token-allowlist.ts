// Shared factory for the 5 service-token recipient allowlists (LINE / Telegram /
// Discord / Slack / Mattermost). Each was a byte-identical ~80-LoC module
// differing ONLY in its ID regex + two env-var names + the symbol names; this
// collapses the duplicated parse / state / membership / summary logic into one
// place, so a future hardening to the predicate (or a default-posture change) is
// a SINGLE edit, not five — and five copies can no longer drift apart on a
// security-sensitive surface. Mirrors policy/burst.ts `makeBurstLimitReader`.
//
// SECURITY — what stays per-connector: each connector module still OWNS and
// EXPORTS its own ID regex as a named const (the connector handler imports it for
// pre-egress SYNTACTIC validation) and re-exports these functions under its
// connector-specific names. This factory is the pure POLICY membership predicate
// ONLY; the actual egress enforcement (the HMAC-hash of a denied id, the audit
// denied-event, the deny/allow wiring) lives in tools/egress.ts and is untouched.
//
// POLICY (identical across all 5 — the service-token posture):
//   - unset/empty allowlist = ALLOW any syntactically-valid id (a service-token
//     push is a PRIVATE, tier-gated min_tier "share" surface → OFF=allow, NOT the
//     public youtube-comment deny-default);
//   - under SAFESPACE_AUTONOMOUS an unset/empty allowlist DENIES ALL (the F2
//     deny-by-default idiom — an un-configured allowlist is not a blank cheque
//     when unattended; mirrors the v1.65 web-fetch autonomous deny);
//   - when configured, only listed ids pass (exact match).

import { isAutonomousMode } from "./autonomous-mode";

export type ServiceTokenAllowlistState =
  | { kind: "off" }
  | { kind: "active"; ids: ReadonlySet<string> };

export interface ServiceTokenAllowlist {
  /** Resolve the allowlist state from the two env layers (persistent + EXTRA).
   *  Read per-call — no caching, so a shell that exports the EXTRA var mid-session
   *  takes effect on the next call. `off` when neither layer yields a
   *  syntactically-valid id; `active` (their union) otherwise. */
  getState(): ServiceTokenAllowlistState;
  /** POLICY membership only (syntactic validity is the handler's job, via the
   *  connector's own ID regex, before egress): `active` → exact membership;
   *  `off` → ALLOW interactively, DENY under autonomous mode (F2). */
  isAllowed(id: string, state: ServiceTokenAllowlistState): boolean;
  /** Count-only summary for `safespace status` / `doctor` (never the ids). */
  summary(): { kind: "off" | "active"; id_count: number };
}

/** Build the state reader + membership predicate for one service-token connector,
 *  bound to its ID regex + two env-var names. The `idRe` MUST be anchored +
 *  restricted-class (the gmail/LINE recipient-gate invariant — it implicitly
 *  rejects CR/LF/NUL/whitespace/path chars) and MUST NOT carry the global `g` flag
 *  (`.test()` would otherwise become stateful across calls). */
export function makeServiceTokenAllowlist(opts: {
  idRe: RegExp;
  envAllow: string;
  envExtra: string;
}): ServiceTokenAllowlist {
  const { idRe, envAllow, envExtra } = opts;

  // Parse a comma-separated env value into the set of syntactically-VALID ids.
  // Malformed tokens are dropped at parse time (never matched, never echoed).
  const parseIds = (raw: string | undefined): string[] => {
    if (raw == null || raw.trim() === "") return [];
    return raw
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s !== "" && idRe.test(s));
  };

  const getState = (): ServiceTokenAllowlistState => {
    const ids = new Set<string>([
      ...parseIds(process.env[envAllow]),
      ...parseIds(process.env[envExtra]),
    ]);
    return ids.size === 0 ? { kind: "off" } : { kind: "active", ids };
  };

  const isAllowed = (id: string, state: ServiceTokenAllowlistState): boolean => {
    if (state.kind === "active") return state.ids.has(id);
    return !isAutonomousMode();
  };

  const summary = (): { kind: "off" | "active"; id_count: number } => {
    const state = getState();
    return state.kind === "off"
      ? { kind: "off", id_count: 0 }
      : { kind: "active", id_count: state.ids.size };
  };

  return { getState, isAllowed, summary };
}
