// v1.20 Phase 1b-1 — A1 notation strict-parse for Google Sheets ranges.
//
// SafeSpace's first cell-level coordinate gate (mirrors v1.19 Phase 1b
// `tasklist_id` / v1.16 Phase 1b `video_id` regex pins, but for a richer
// grammar). Handler-side validation BEFORE any SDK call — malformed input
// fails fast with a clear message rather than hitting Google and returning
// an opaque 400/404.
//
// Used by:
//   - sheets_get_values (Phase 1b-1)
//   - sheets_append_values (Phase 1b-2, write tier)
//   - sheets_update_values (Phase 2c, deferred to v1.21)
//
// See docs/v1.20-sheets-api.md §7 (hostile-input table) and §11 Q6 LOCKED
// for the exact regex specification + threat model.

/**
 * LOCKED regex per design §7 + §11 Q6 (POST-P1+P8+P9 polish).
 *
 * Grammar:
 *   - Sheet name: EITHER quoted form `'<unsafe chars rejected>'` (1-99 chars
 *     between the quotes; rejects `'` / CR / LF / U+2028 / U+2029 inside)
 *     OR unquoted form `[A-Za-z][A-Za-z0-9_]{0,99}` (1-100 chars; ASCII-only;
 *     matches Google's natural unquoted-sheet-name allowlist).
 *   - Bang separator + cell-or-range component: OPTIONAL. Sheet-only forms
 *     (e.g. `Sheet1`) are valid Sheets-API targets — `sheets_append_values`
 *     treats a bare sheet name as "append to first cell of sheet".
 *   - When the cell-or-range component is present, exactly one `!` followed
 *     by ONE of:
 *       (a) single cell or cell-range — column A-ZZZ + row 1-9999999;
 *           row-zero REJECTED at both endpoints (P9 — Sheets has no row 0).
 *       (b) full-column range — `[A-Z]{1,3}:[A-Z]{1,3}` (e.g. `A:Z`)
 *       (c) full-row range — `[1-9]\\d{0,6}:[1-9]\\d{0,6}` (e.g. `1:100`);
 *           row-zero REJECTED at both endpoints.
 *
 * Source-byte safety (P2 — paste-artifact defense): the regex MUST use the
 * literal escape sequences `\\u2028` / `\\u2029` for the Line Separator /
 * Paragraph Separator codepoints (NOT raw bytes). Rendering tools may
 * display these as ordinary whitespace; a sentinel test asserts the SOURCE
 * file contains the literal `\\u2028` / `\\u2029` sequences (not the raw
 * U+2028 / U+2029 codepoints) to defend against future copy-paste drift.
 *
 * ReDoS safety: bounded quantifiers only ({0,99} / {0,6}); NO unbounded
 * `+` / `*` / nested groups with conflicting matches. Sentinel test runs
 * 1500 iterations against a 256-char hostile input within a 1ms budget.
 */
export const A1_RANGE_RE =
  /^(?:'[^'\r\n\u2028\u2029]{1,99}'|[A-Za-z][A-Za-z0-9_]{0,99})(?:!(?:[A-Z]{1,3}[1-9]\d{0,6}(?::[A-Z]{1,3}[1-9]\d{0,6})?|[A-Z]{1,3}:[A-Z]{1,3}|[1-9]\d{0,6}:[1-9]\d{0,6}))?$/;

/**
 * Length cap per design §7 — 256 bytes. Matches v1.19 `due` field precedent.
 * Length-cap is applied BEFORE the regex test to bound the regex input even
 * if a regex catastrophic-backtracking case were ever introduced.
 */
export const A1_MAX_LENGTH = 256;

/**
 * Strict-parse result. `valid` is the single source of truth for callers;
 * `normalized` is the input verbatim Phase 1 (no whitespace collapsing yet —
 * §5 L4 carry-forward defers normalization). Returning the field rather
 * than the raw string future-proofs callers when Phase 1b-2+ adds canonical
 * normalization (e.g., `"Sheet1 ! A1"` → `"Sheet1!A1"`).
 */
export interface A1ParseResult {
  valid: boolean;
  normalized?: string;
}

/**
 * Validate an A1 notation range string. Returns `{valid: false}` on any of:
 *   - non-string input
 *   - empty after type-check
 *   - exceeds A1_MAX_LENGTH (UTF-8 byte length — applied BEFORE regex to
 *     prevent catastrophic backtracking surface, even though the regex is
 *     bounded today)
 *   - fails the LOCKED A1_RANGE_RE match
 *
 * Returns `{valid: true, normalized: <input verbatim>}` on success. Callers
 * MUST destructure `normalized` (NOT re-use their own input string) so a
 * future Phase 1b-2 normalization PR transparently changes the byte-string
 * passed to the SDK.
 */
export function parseA1Range(input: unknown): A1ParseResult {
  if (typeof input !== "string") return { valid: false };
  if (input.length === 0) return { valid: false };
  // Byte-length cap (UTF-8). String.length is UTF-16 code-unit count which
  // diverges from bytes for non-ASCII, but Buffer.byteLength is the
  // attacker-relevant cost — defends against 256-char input expanding to
  // 1024-byte regex work in the worst case.
  if (Buffer.byteLength(input, "utf-8") > A1_MAX_LENGTH) {
    return { valid: false };
  }
  if (!A1_RANGE_RE.test(input)) return { valid: false };
  return { valid: true, normalized: input };
}
