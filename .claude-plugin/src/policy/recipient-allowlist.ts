// v2.2 — Recipient allowlist policy module.
//
// Gates `drive_share_file (share_type=user)` `target_email` and
// `gmail_send` to/cc/bcc against a two-layer env-var allowlist plus the
// implicit self-send set from accounts.json. See docs/DESIGN.md v2.2
// Addendum for the locked spec.
//
// PR-A scope: parse / match / summarize + singleton state loader. NO
// handler integration yet — that's PR-B.
//
// Sec-rev invariants this module owns:
//   - Allowlist values NEVER appear in error messages or doctor output
//     (only counts + categorization).
//   - Bare-domain tokens (`client.com` without `@`) rejected at parse
//     time to prevent ambiguity.
//   - Domain matching is case-insensitive on the domain (RFC 5321 §2.4)
//     and case-sensitive on the localpart (RFC permits localpart case-
//     sensitivity even though most providers fold; defense in depth).
//   - state.kind === "off" returns true (policy off, no break for
//     existing users who haven't set SAFESPACE_RECIPIENT_ALLOW).
//   - state.kind === "active" with empty union returns false except for
//     self-emails (implicit-allow always applies when state is active).

import { loadIndex } from "../auth/keychain";
import { isAutonomousMode } from "./autonomous-mode";
import {
  ENV_RECIPIENT_ALLOW as ENV_ALLOW,
  ENV_RECIPIENT_ALLOW_EXTRA as ENV_ALLOW_EXTRA,
} from "../config";

export { ENV_ALLOW, ENV_ALLOW_EXTRA };

// ----- types -----

export type AllowlistEntry =
  | { kind: "email"; localpart: string; domain: string } // localpart kept as-is; domain lowercased
  | { kind: "domain"; domain: string }; // lowercased

export type AllowlistState =
  | { kind: "off" }
  | {
      kind: "active";
      allow: AllowlistEntry[];
      extra: AllowlistEntry[];
      selfEmails: Set<string>; // exact, case-preserving comparison
    };

export interface AllowlistSummary {
  kind: "off" | "active";
  allow_count: number;
  allow_domain_count: number;
  allow_email_count: number;
  extra_count: number;
  extra_domain_count: number;
  extra_email_count: number;
  self_implicit_count: number;
}

export interface ParseResult {
  ok: AllowlistEntry[];
  rejected: string[]; // tokens that failed parse (for doctor warning, not for error messages)
}

// ----- parsing -----

// Loose email shape — Google validates server-side; we just want to reject
// obvious foot-guns at parse time.
const EMAIL_RE =
  /^[A-Za-z0-9._%+\-]+@([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,})$/;
const DOMAIN_RE =
  /^@([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,})$/;

/** Parse a comma-separated allowlist string into structured entries.
 *  Each non-empty token must be:
 *    - `localpart@domain.tld` — exact email
 *    - `@domain.tld` — domain match
 *  A bare `domain.tld` (no `@` prefix) is rejected as ambiguous.
 *  Empty / whitespace-only tokens are silently skipped (allow trailing
 *  commas + blank entries for human-friendly editing).
 *  Returns parsed entries + a list of rejected tokens (for diagnostics). */
export function parseAllowlistTokens(input: string | undefined): ParseResult {
  const result: ParseResult = { ok: [], rejected: [] };
  if (input === undefined) return result;

  const tokens = input
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t.length > 0);

  for (const token of tokens) {
    const domainMatch = DOMAIN_RE.exec(token);
    if (domainMatch !== null) {
      result.ok.push({ kind: "domain", domain: domainMatch[1]!.toLowerCase() });
      continue;
    }
    const emailMatch = EMAIL_RE.exec(token);
    if (emailMatch !== null) {
      const atIdx = token.indexOf("@");
      result.ok.push({
        kind: "email",
        localpart: token.slice(0, atIdx),
        domain: token.slice(atIdx + 1).toLowerCase(),
      });
      continue;
    }
    result.rejected.push(token);
  }
  return result;
}

// ----- matching -----

/** Check whether a recipient email is allowed by the current state.
 *
 *  Sec-rev invariants:
 *    - state.kind === "off" → always true (policy off; v2.0 behavior).
 *    - state.kind === "active" + recipient in selfEmails → true (implicit).
 *    - state.kind === "active" + recipient matches any entry in
 *      allow ∪ extra → true.
 *    - Otherwise → false.
 *    - Malformed recipient (no `@`, or `@` at start/end) → false.
 *
 *  v1.80 PR-3 (`confineSelfTo`, optional — the B5 `sanitize(…, skipFields)`
 *  3rd-param precedent): under Model B the implicit SELF exemption is
 *  partitioned to the calling operator's `allowedAccounts` — "self" means the
 *  OPERATOR's own accounts, not every account the deployment ever consented.
 *  `null` (the default — Model A / an unconfined operator) is byte-identical
 *  to the 2-arg form. The partition narrows ONLY the implicit self exemption,
 *  NEVER the explicit allow/extra entries (membership ⟂ provenance): an
 *  explicitly-allowlisted recipient stays allowed regardless of confinement.
 *  An EMPTY set = zero self exemption (a registry operator with no OAuth
 *  accounts). Matching stays exact case-preserving: `allowedAccounts` entries
 *  and `selfEmails` come from the SAME source strings (`accounts.json`
 *  emails; the registry cross-check guarantees ⊆). */
export function isRecipientAllowed(
  recipient: string,
  state: AllowlistState,
  confineSelfTo: ReadonlySet<string> | null = null,
): boolean {
  if (state.kind === "off") return true;
  if (typeof recipient !== "string" || recipient.length === 0) return false;

  // Self-send implicit (exact case-preserving match on full email),
  // intersected with the operator's confinement set when one is supplied.
  if (
    state.selfEmails.has(recipient) &&
    (confineSelfTo === null || confineSelfTo.has(recipient))
  ) {
    return true;
  }

  const atIdx = recipient.indexOf("@");
  if (atIdx < 1 || atIdx === recipient.length - 1) return false;
  const recipientLocal = recipient.slice(0, atIdx);
  const recipientDomain = recipient.slice(atIdx + 1).toLowerCase();

  for (const entry of state.allow) {
    if (entryMatches(entry, recipientLocal, recipientDomain)) return true;
  }
  for (const entry of state.extra) {
    if (entryMatches(entry, recipientLocal, recipientDomain)) return true;
  }
  return false;
}

function entryMatches(
  entry: AllowlistEntry,
  recipientLocal: string,
  recipientDomain: string,
): boolean {
  if (entry.kind === "domain") return entry.domain === recipientDomain;
  return entry.localpart === recipientLocal && entry.domain === recipientDomain;
}

// ----- summary (for doctor) -----

export function summarizeAllowlist(state: AllowlistState): AllowlistSummary {
  if (state.kind === "off") {
    return {
      kind: "off",
      allow_count: 0,
      allow_domain_count: 0,
      allow_email_count: 0,
      extra_count: 0,
      extra_domain_count: 0,
      extra_email_count: 0,
      self_implicit_count: 0,
    };
  }
  const allowDomains = state.allow.filter((e) => e.kind === "domain").length;
  const allowEmails = state.allow.length - allowDomains;
  const extraDomains = state.extra.filter((e) => e.kind === "domain").length;
  const extraEmails = state.extra.length - extraDomains;
  return {
    kind: "active",
    allow_count: state.allow.length,
    allow_domain_count: allowDomains,
    allow_email_count: allowEmails,
    extra_count: state.extra.length,
    extra_domain_count: extraDomains,
    extra_email_count: extraEmails,
    self_implicit_count: state.selfEmails.size,
  };
}

// ----- state loading -----

/** Build an AllowlistState from env vars + accounts.json self-emails.
 *  Pure helper (no singleton), useful for tests + the state loader.
 *
 *  `allowEnv` / `extraEnv`:
 *    - undefined → "var not set" (off-policy contribution).
 *    - "" (empty string) → "explicit default-deny" — parses to zero
 *      entries, but contributes to active state.
 *    - non-empty → parsed.
 *
 *  ENV_ALLOW undefined AND ENV_ALLOW_EXTRA undefined → off. Otherwise →
 *  active. (Setting only EXTRA without ALLOW is unusual but valid: "I
 *  want default-deny but with these session-only extras".)
 *
 *  v1.53 F2 (`autonomous`): when autonomous/strict mode is on, an
 *  UNCONFIGURED allowlist (both env undefined) no longer returns "off"
 *  (=allow-all) — it returns "active" with an empty union, so the existing
 *  isRecipientAllowed semantics deny every external recipient while self-
 *  sends (the operator's own accounts — no external blast radius) stay
 *  implicitly allowed. The matching logic is UNCHANGED; only the state
 *  handed to it flips. */
export function buildAllowlistState(
  allowEnv: string | undefined,
  extraEnv: string | undefined,
  selfEmails: Set<string>,
  autonomous = false,
): AllowlistState {
  if (allowEnv === undefined && extraEnv === undefined && !autonomous) {
    return { kind: "off" };
  }
  const allowParsed = parseAllowlistTokens(allowEnv);
  const extraParsed = parseAllowlistTokens(extraEnv);
  return {
    kind: "active",
    allow: allowParsed.ok,
    extra: extraParsed.ok,
    selfEmails: new Set(selfEmails),
  };
}

// ----- per-process singleton (load-once, MCP-restart-clears) -----

let cachedStatePromise: Promise<AllowlistState> | undefined;

export function getAllowlistState(): Promise<AllowlistState> {
  if (cachedStatePromise === undefined) {
    cachedStatePromise = loadAllowlistFromEnvAndDisk();
  }
  return cachedStatePromise;
}

async function loadAllowlistFromEnvAndDisk(): Promise<AllowlistState> {
  let selfEmails: Set<string>;
  try {
    const idx = await loadIndex();
    selfEmails = new Set(idx.accounts.map((a) => a.email));
  } catch {
    // accounts.json missing or unreadable — treat self set as empty.
    // Module continues to function; user has no implicit allow.
    selfEmails = new Set();
  }

  const allowEnv = process.env[ENV_ALLOW];
  const extraEnv = process.env[ENV_ALLOW_EXTRA];

  // Sec-rev (PR-A MEDIUM #2) mitigation: warn the operator when EXTRA is
  // set but ALLOW is not — that's an unusual pattern (default-deny base +
  // session extras) and likely a stale env from a previous session that
  // the user has forgotten about. Print to stderr so it surfaces in
  // Claude Code's MCP-subprocess log without confusing the user's main
  // tool output. Fires at module load (first getAllowlistState() call).
  if (allowEnv === undefined && extraEnv !== undefined && extraEnv.length > 0) {
    console.error(
      "[safespace] WARNING: SAFESPACE_RECIPIENT_ALLOW_EXTRA is set but " +
        "SAFESPACE_RECIPIENT_ALLOW is not. Allowlist is in default-deny " +
        "mode with EXTRA + self-send only. If you intended to leave the " +
        "allowlist OFF, also unset SAFESPACE_RECIPIENT_ALLOW_EXTRA.",
    );
  }

  return buildAllowlistState(allowEnv, extraEnv, selfEmails, isAutonomousMode());
}

// Test-only — do NOT use outside this module's tests.
/** @internal */
export const __internal = {
  EMAIL_RE,
  DOMAIN_RE,
  entryMatches,
  resetSingletons: () => {
    cachedStatePromise = undefined;
  },
};
