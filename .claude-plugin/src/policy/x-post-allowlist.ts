// v1.115 — SAFESPACE_X_POST_ACCOUNTS allowlist (the PUBLIC-surface default-deny
// account gate for X post creation). A near-verbatim mirror of
// policy/github-write-targets.ts — an X post is a PUBLIC surface (the same threat
// class as a GitHub issue / YouTube comment), so the gate is DEFAULT-DENY.
//
// Gate order for x_post_create:
//   1. SAFESPACE_TIER=write            (proxy tier filter; no new code)
//   2. OAuth credential = provider x   (requireX; scopes fixed at consent)
//   3. THIS MODULE — numeric user id ∈ SAFESPACE_X_POST_ACCOUNTS (default-empty =
//      HARD-DENY even with write tier + consent) → -32056 x_post_denied_by_policy
//   4. F3a secret-shape + outboundSanitize (tools/egress.ts enforceXPostEgressGates)
//
// Format: comma-separated X numeric user ids. Validated against `^[0-9]{1,32}$`
// (usernames rotate; the numeric id is the stable identity). Exact match (digits
// only — case is N/A). Whitespace around a token trimmed; trailing/extra commas
// tolerated. Malformed tokens are rejected loudly at load (config error, not
// silent drop).
//
// Two-layer (mirrors github-write-targets / youtube-video-targets):
//   - SAFESPACE_X_POST_ACCOUNTS         (persistent; configured in .env)
//   - SAFESPACE_X_POST_ACCOUNTS_EXTRA   (shell-only; per-session)
//
// Default-empty hard-deny: unset / "" / whitespace-only / malformed-only → empty
// Set (or "off"), ALL posts rejected. WARN-ONCE on _EXTRA-without-base + on
// malformed tokens at load.

import {
  ENV_X_POST_ACCOUNTS as ENV_TARGETS,
  ENV_X_POST_ACCOUNTS_EXTRA as ENV_TARGETS_EXTRA,
} from "../config";

export { ENV_TARGETS, ENV_TARGETS_EXTRA };

// ----- types -----

export interface XPostAccountParseResult {
  ok: string[];
  rejected: string[];
}

export type XPostAllowlistState =
  | { kind: "off" }
  | { kind: "active"; accountIds: ReadonlySet<string> };

export interface XPostAllowlistSummary {
  kind: "off" | "active";
  count: number;
}

// ----- segment validation -----

const ACCOUNT_ID_RE = /^[0-9]{1,32}$/;

// ----- parsing -----

/** Parse a comma-separated numeric user-id allowlist string. Trailing/extra commas
 *  tolerated; whitespace around a token trimmed; a token failing {@link ACCOUNT_ID_RE}
 *  is rejected (loud config error, not silent drop). Entries are deduped. */
export function parseXPostAccounts(input: string | undefined): XPostAccountParseResult {
  const result: XPostAccountParseResult = { ok: [], rejected: [] };
  if (input === undefined) return result;

  const tokens = input
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t.length > 0);

  const seen = new Set<string>();
  for (const token of tokens) {
    if (!ACCOUNT_ID_RE.test(token)) {
      result.rejected.push(token);
      continue;
    }
    if (seen.has(token)) continue;
    seen.add(token);
    result.ok.push(token);
  }
  return result;
}

// ----- matching (default-deny) -----

/** Whether `accountId` is in the allowlist. Default-deny: `off` → false (env not
 *  set — HARD-DENY, the safe default for a PUBLIC write surface). Exact digit match. */
export function isXPostAccountAllowed(
  accountId: string,
  state: XPostAllowlistState,
): boolean {
  if (state.kind === "off") return false;
  if (typeof accountId !== "string") return false;
  return state.accountIds.has(accountId);
}

// ----- summary (doctor/debug — no values exposed) -----

export function summarizeXPostAllowlist(
  state: XPostAllowlistState,
): XPostAllowlistSummary {
  return state.kind === "off"
    ? { kind: "off", count: 0 }
    : { kind: "active", count: state.accountIds.size };
}

// ----- state building (pure helper, no env / no console) -----

export function buildXPostAllowlistState(
  targetsEnv: string | undefined,
  extraEnv: string | undefined,
): XPostAllowlistState {
  if (targetsEnv === undefined && extraEnv === undefined) {
    return { kind: "off" };
  }
  const baseParsed = parseXPostAccounts(targetsEnv);
  const extraParsed = parseXPostAccounts(extraEnv);
  const merged = new Set<string>();
  for (const id of [...baseParsed.ok, ...extraParsed.ok]) {
    merged.add(id);
  }
  return { kind: "active", accountIds: merged };
}

// ----- per-process singleton (load-once, MCP-restart-clears) -----

let cachedState: XPostAllowlistState | undefined;
let warnEmitted = false;

/** Load the allowlist state once per process (mirrors github-write-targets.ts).
 *  WARN-ONCE: _EXTRA set without base, and any malformed token, are stderr-logged
 *  ONCE at first call. */
export function getXPostAllowlistState(): XPostAllowlistState {
  if (cachedState !== undefined) return cachedState;

  const targetsEnv = process.env[ENV_TARGETS];
  const extraEnv = process.env[ENV_TARGETS_EXTRA];

  if (
    !warnEmitted &&
    targetsEnv === undefined &&
    typeof extraEnv === "string" &&
    extraEnv.length > 0
  ) {
    console.error(
      "[safespace] WARNING: SAFESPACE_X_POST_ACCOUNTS_EXTRA is set but " +
        "SAFESPACE_X_POST_ACCOUNTS is not. X-post allowlist is in " +
        "default-deny mode with EXTRA only. If you intended to leave the allowlist " +
        "OFF, also unset SAFESPACE_X_POST_ACCOUNTS_EXTRA.",
    );
    warnEmitted = true;
  }

  const baseParsed = parseXPostAccounts(targetsEnv);
  const extraParsed = parseXPostAccounts(extraEnv);
  for (const rej of [...baseParsed.rejected, ...extraParsed.rejected]) {
    // Operator-supplied config (process env), NOT attacker-controlled — safe to log.
    console.error(
      `[safespace] WARNING: SAFESPACE_X_POST_ACCOUNTS rejected malformed entry: ${rej}`,
    );
  }

  cachedState = buildXPostAllowlistState(targetsEnv, extraEnv);

  if (cachedState.kind === "active" && cachedState.accountIds.size === 0) {
    console.error(
      "[safespace] WARNING: SAFESPACE_X_POST_ACCOUNTS is set but yielded 0 valid " +
        "entries — X posts will be hard-denied. Check syntax: comma-separated " +
        "numeric user ids (e.g. `2244994945`).",
    );
  }

  return cachedState;
}

// Test-only.
/** @internal */
export const __internal = {
  ACCOUNT_ID_RE,
  resetSingletons: (): void => {
    cachedState = undefined;
    warnEmitted = false;
  },
};
