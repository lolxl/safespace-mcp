// v1.15 Phase 3 — Opt-in feature gate for gmail_send / calendar_create_event
// contact-lookup integration.
//
// See docs/v1.15-contacts-api.md §9 "Phase 3 design hook" + §11 hook #3.
//
// STRICT-TRUTHY parsing: returns `true` ONLY when the env var is the literal
// string `"true"` (lowercase, no whitespace, no quotes). Every other value
// returns `false` — including `"True"`, `"TRUE"`, `"1"`, `"yes"`, `"on"`,
// `"false"`, the empty string, undefined, and any whitespace-padded variant.
//
// This is INTENTIONALLY stricter than the existing env-var parsing patterns
// in SafeSpace:
//
//   - `SAFESPACE_TIER` uses set-membership against {"read","write","share"};
//     invalid values fall back to "read" with a stderr warning.
//   - `SAFESPACE_RECIPIENT_ALLOW` uses "set vs unset" with no truthy check
//     (any non-undefined value, including "", activates the allowlist).
//
// `SAFESPACE_RECIPIENT_ALLOW_CONTACTS` is intentionally a THIRD pattern
// (literal "true" lowercase) because the failure mode is DIFFERENT:
//
//   - Tier mis-parse fails LOUDLY (wrong-tier rejection at tool surface).
//   - Recipient-allow mis-parse fails LOUDLY (every recipient rejected).
//   - A `SAFESPACE_RECIPIENT_ALLOW_CONTACTS` mis-parse that accidentally
//     evaluated truthy ("True" / "TRUE" / "1" / "yes") would SILENTLY enable
//     name-to-email resolution without user awareness — and the resolved
//     email would then go through the allowlist (which usually passes for
//     known contacts), so the silent feature-enable would never be visible.
//
// Stricter parsing defends against:
//   - Shell autocompletion (`=True`, `=TRUE`).
//   - Dotenv loader case-folding.
//   - Locale-specific upper-casing on Windows shells.
//
// The inconsistency with other env vars is INTENTIONAL and load-bearing.

import { ENV_RECIPIENT_ALLOW_CONTACTS, readStrictTruthy } from "../config";

export { ENV_RECIPIENT_ALLOW_CONTACTS };

/** True iff the opt-in env var is set to the literal lowercase string "true".
 *
 * Returns false for all other values — see the file comment for the rationale
 * on why this is stricter than `SAFESPACE_TIER` / `SAFESPACE_RECIPIENT_ALLOW`. */
export function isContactLookupEnabled(): boolean {
  return readStrictTruthy(ENV_RECIPIENT_ALLOW_CONTACTS);
}
