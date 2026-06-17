// v1.30 Phase 1 -- UTS #39-inspired homoglyph normalize + invisible-char STRIP.
//
// Hand-curated minimal subset (Q1 LOCKED Option A + Option E hybrid per
// docs/v1.30-uts39-defense.md section 6) covering ASCII letters in the 11
// REJECT-list function names from src/sheets/formula-reject.ts. Q3 LOCKED
// minimal sec-sensitive scope (Option B full UTS #39 / Option C/D vendoring
// REJECTED -- would require ~250KB confusables table + yearly Unicode update
// cadence + hot-path perf evaluation; warrants its own design pre-PR).
//
// Pipeline semantics (Q2 LOCKED Option C STRIP-then-NORMALIZE per section 6.Q2):
//   STEP A -- STRIP Default_Ignorable codepoints (~70 codepoints; silent fix --
//     no legitimate use in formula identifier; mirrors v1.25 Phase 4 strip
//     semantics; sec-rev hook #8).
//   STEP B -- STRIP Bidi override class (9 codepoints; silent fix --
//     operator-eye log-viewer bypass class; bidi controls have no legitimate
//     use in formula identifier; sec-rev hook #9).
//   STEP C -- NORMALIZE Cyrillic + Greek + Armenian homoglyphs to ASCII (BOTH
//     cases per Phase 0a M2 amendment -- FORMULA_PREFIX_RE extracts BEFORE
//     `.toUpperCase()`, so lowercase Cyrillic U+0456 bypasses if the map only
//     covers uppercase). NORMALIZE is introspection-only: does NOT mutate the
//     value passed to the SDK (Phase 2 wires this -- see section 4.2 hook #3).
//
// v1.35 -- Armenian script added to STEP C (evidence-first; see
// docs/v1.35-homoglyph-scripts.md). 6 high/medium-confidence confusers from
// UTS #39 confusables.txt v17.0.0 (OH U+0555 / U+0585 -> O / o; TIWN U+054F ->
// S; VO U+0578 + RA U+057C -> n; HO U+0570 -> h). The n / h entries close the
// last two zero-coverage REJECT-set letters (neither Cyrillic nor Greek has a
// high-confidence confuser for them). Devanagari has ZERO in-scope Latin
// confusers in confusables.txt -> formally CLOSED. Hebrew (4 RTL candidates)
// + full UTS #39 table vendoring stay DEFERRED (design doc sections 3.1-3.2 + Q5).
//
// INTEGRATION POINT (Phase 2 wires this -- Phase 1 ships module only):
//   src/sheets/formula-reject.ts:validateCellValue will gain a new pre-step
//   that calls applyHomoglyphPipeline() BEFORE the existing STEP 0a
//   zero-width strip + STEP 0 NFKC + STEP 3 regex extract. The CALL-SITE
//   passes the original cell value to the SDK; the transformed string is used
//   ONLY for FORMULA_PREFIX_RE introspection + REJECTED_FUNCTIONS lookup.
//
// ZERO behavior change to production pipeline this phase (Phase 2 territory).
//
// Source-byte purity (sec-rev hook #14):
//   All Cyrillic / Greek / Default_Ignorable / Bidi codepoints written as
//   `\uXXXX` Unicode escape sequences ONLY -- NEVER literal Unicode bytes.
//   Sentinel test pins source-byte absence per v1.25 Phase 4 + v1.21 P2
//   convention (mirrors formula-reject.ts discipline). Comments use the
//   `U+XXXX` text label form (NOT the literal codepoint glyph) so the
//   source file remains grep-friendly + paste-artifact-immune.
//
// Performance (sec-rev hook #5 + Risk 2 <=5% regression budget per section 7):
//   - Fast-path ASCII early-exit via `/[^\x20-\x7E]/.test(s)`. Most legitimate
//     formula cells are pure ASCII; this short-circuits before any regex /
//     Map work.
//   - STEP A + STEP B regexes use bounded character classes; O(N) single-pass
//     via `String.prototype.replace(regex_g)`.
//   - STEP C uses `Map.get(ch)` per char inside a single for-of loop; O(1)
//     per char x O(N) string length. No regex alternation; no backtracking.
//   Baseline benchmark recorded in Phase 1 tests; Phase 2 verifies <=5% delta
//   under the integrated pipeline.
//
// See docs/v1.30-uts39-defense.md section 2 (4-class threat model; Class 4
// NFKC-handled per Phase 0a M1) + section 3.1 (codepoint scope IN per
// Phase 0a M2) + section 6 (Q1-Q5 LOCKED decisions) + section 8 (12 sec-rev
// hooks).
//
// v1.33 sec-L1 -- import the 256-codepoint cap for the forensic homoglyphSource
// buffer (caps the FORENSIC field ONLY; `normalized` security output is NEVER
// capped). See docs/v1.33-audit-cli-forensics.md section 4.1.
import { SHEETS_HOMOGLYPH_SOURCE_MAX_CHARS } from "./limits";

// ============================================================================
// STEP A -- Default_Ignorable codepoint STRIP (silent fix)
// ============================================================================

/**
 * Default_Ignorable_Code_Point set per Unicode 15.x DerivedCoreProperties.
 *
 * Closes Class 2 bypass class -- codepoints with the Default_Ignorable
 * property that are NOT in v1.25 Phase 4's 5-codepoint scope. These render
 * as zero-width / no-glyph and can splice REJECT-list function names
 * invisibly.
 *
 * Concrete bypass (BEFORE v1.30 Phase 2 wiring):
 *   `=I[U+180B]MPORTRANGE("x","y")` -- U+180B MONGOLIAN FREE VARIATION
 *   SELECTOR ONE; Default_Ignorable; NFKC preserves; v1.25 Phase 4 strip
 *   MISSES (not in 5-codepoint scope).
 *
 * Codepoints in scope (~70 across BMP + Supplementary planes):
 *   - U+00AD SOFT HYPHEN (overlaps v1.25 P4; harmless re-strip)
 *   - U+034F COMBINING GRAPHEME JOINER
 *   - U+061C ARABIC LETTER MARK
 *   - U+115F-U+1160 HANGUL CHOSEONG / JUNGSEONG FILLER
 *   - U+17B4-U+17B5 KHMER VOWEL INHERENT AQ / AA
 *   - U+180B-U+180E MONGOLIAN VARIATION SELECTORS + VOWEL SEPARATOR
 *   - U+200B-U+200F (ZWSP / ZWNJ / ZWJ / LRM / RLM -- first 3 overlap v1.25 P4)
 *   - U+202A-U+202E (bidi EMBEDDING / OVERRIDE / POP -- overlap BIDI_OVERRIDE_RE)
 *   - U+2060-U+206F WORD JOINER + invisible operators + deprecated shaping
 *   - U+3164 HANGUL FILLER
 *   - U+FE00-U+FE0F VARIATION SELECTORS 1-16
 *   - U+FEFF ZERO WIDTH NO-BREAK SPACE / BOM (overlaps v1.25 P4)
 *   - U+FFA0 HALFWIDTH HANGUL FILLER
 *   - U+1BCA0-U+1BCA3 SHORTHAND FORMAT controls (supplementary)
 *   - U+1D173-U+1D17A MUSICAL SYMBOL formatting (supplementary)
 *   - U+E0000-U+E007F TAG characters (supplementary; deprecated)
 *   - U+E0100-U+E01EF VARIATION SELECTORS 17-256 (supplementary)
 *
 * Source: Unicode 15.1 DerivedCoreProperties.txt
 * (https://www.unicode.org/Public/15.1.0/ucd/DerivedCoreProperties.txt)
 *
 * Source-byte purity: all codepoints written via `\uXXXX` + `\u{XXXXX}`
 * Unicode escape sequences ONLY; built via `new RegExp(...)` from an escape-
 * sequence string so the source file remains grep-friendly + paste-artifact-
 * immune. Sentinel test pins absence of literal codepoints.
 */
export const DEFAULT_IGNORABLE_RE = new RegExp(
  // All codepoints written via `\uXXXX` + `\u{XXXXX}` JavaScript escape
  // sequences ONLY. SOURCE FILE contains only ASCII bytes; the escape
  // sequences are interpreted at runtime when the string literal is built.
  // Source-byte purity per sec-rev hook #14.
  //
  // BMP codepoints (single character class):
  "[" +
    "\\u00AD" + // SOFT HYPHEN
    "\\u034F" + // COMBINING GRAPHEME JOINER
    "\\u061C" + // ARABIC LETTER MARK
    "\\u115F-\\u1160" + // HANGUL CHOSEONG / JUNGSEONG FILLER
    "\\u17B4-\\u17B5" + // KHMER VOWEL INHERENT AQ / AA
    "\\u180B-\\u180E" + // MONGOLIAN VARIATION SELECTORS + VOWEL SEPARATOR
    "\\u200B-\\u200F" + // ZWSP / ZWNJ / ZWJ / LRM / RLM
    "\\u202A-\\u202E" + // bidi EMBEDDING / OVERRIDE / POP
    "\\u2060-\\u206F" + // WORD JOINER + invisible operators + shaping
    "\\u3164" + // HANGUL FILLER
    "\\uFE00-\\uFE0F" + // VARIATION SELECTORS 1-16
    "\\uFEFF" + // ZERO WIDTH NO-BREAK SPACE / BOM
    "\\uFFA0" + // HALFWIDTH HANGUL FILLER
    "]" +
    // Supplementary plane (require `u` flag for `\u{XXXXX}` syntax):
    "|[\\u{1BCA0}-\\u{1BCA3}]" + // SHORTHAND FORMAT controls
    "|[\\u{1D173}-\\u{1D17A}]" + // MUSICAL SYMBOL formatting
    "|[\\u{E0000}-\\u{E007F}]" + // TAG characters (deprecated)
    "|[\\u{E0100}-\\u{E01EF}]", // VARIATION SELECTORS 17-256
  "gu",
);

// ============================================================================
// STEP B -- Bidi override class STRIP (operator-eye bypass)
// ============================================================================

/**
 * Bidi class override codepoints -- subset of Default_Ignorable but called
 * out separately because the THREAT MODEL is distinct: operator-eye log
 * viewer bypass via reversed-direction rendering, not character splice
 * (Class 3 per docs/v1.30-uts39-defense.md section 2.3).
 *
 * Concrete operator-eye bypass:
 *   Source byte sequence:
 *     `= U+202E G N A R R O P M I U+202C ( "x" , "y" )`
 *   Renders to operator as: `=IMPORTRANGE("x", "y")` (RLO flips visually)
 *   But Sheets evaluator reads source bytes -- Sheets lexer ignores bidi
 *   controls inside identifiers (observed empirically; treats bidi as
 *   whitespace-class). Bypass is operator-eye visibility, not evaluation.
 *
 * 9 codepoints (Unicode 15.x BidiClass in {LRE, RLE, PDF, LRO, RLO, LRI,
 * RLI, FSI, PDI}):
 *   - U+202A LEFT-TO-RIGHT EMBEDDING
 *   - U+202B RIGHT-TO-LEFT EMBEDDING
 *   - U+202C POP DIRECTIONAL FORMATTING
 *   - U+202D LEFT-TO-RIGHT OVERRIDE
 *   - U+202E RIGHT-TO-LEFT OVERRIDE
 *   - U+2066 LEFT-TO-RIGHT ISOLATE
 *   - U+2067 RIGHT-TO-LEFT ISOLATE
 *   - U+2068 FIRST STRONG ISOLATE
 *   - U+2069 POP DIRECTIONAL ISOLATE
 *
 * Note: U+202A-U+202E + U+2066-U+2069 are ALL also matched by
 * DEFAULT_IGNORABLE_RE above (Default_Ignorable property includes bidi
 * controls). STEP B is effectively a redundant strip pinned for
 * documentation clarity + tightness if DEFAULT_IGNORABLE_RE is ever
 * narrowed in v1.31+ (e.g., to drop bidi codepoints to surface them as
 * REJECTs instead of STRIPs). Pipeline order: STEP A first (broader),
 * STEP B second (narrower dedup). Both safe to strip silently per
 * design section 3.1.
 *
 * Source-byte purity: codepoints written via `\uXXXX` escapes in the
 * `new RegExp(...)` string argument.
 */
export const BIDI_OVERRIDE_RE = new RegExp(
  // All codepoints written via `\uXXXX` JavaScript escape sequences ONLY --
  // source-byte purity per sec-rev hook #14.
  "[" +
    "\\u202A-\\u202E" + // LRE / RLE / PDF / LRO / RLO
    "\\u2066-\\u2069" + // LRI / RLI / FSI / PDI
    "]",
  "gu",
);

// ============================================================================
// STEP C -- Cyrillic + Greek + Armenian homoglyph NORMALIZE (introspection-only)
// ============================================================================

/**
 * Cyrillic + Greek + Armenian capital + lowercase lookalikes for ASCII letters
 * present in the 11 REJECT-list function names from src/sheets/formula-reject.ts:
 *
 *   REJECT functions: IMPORTRANGE / IMPORTXML / IMPORTHTML / IMPORTDATA /
 *     IMPORTFEED / HYPERLINK / GOOGLEFINANCE / GOOGLETRANSLATE / IMAGE /
 *     WEBSERVICE / LAMBDA (11 names; v1.21 + v1.25 base).
 *
 *   Unique ASCII letters across the 11 names: {A B C D E F G H I K L M N O
 *     P R S T V W X Y} = 22 uppercase + 22 lowercase = 44 ASCII chars in
 *     scope.
 *
 * Phase 0a M2 amendment (per design section 3.1 + alphabet-coverage meta-test):
 *   FORMULA_PREFIX_RE in formula-reject.ts:218 extracts BEFORE the
 *   `.toUpperCase()` on line 220. A formula like `=[U+0456]mportrange(...)`
 *   (Cyrillic LOWERCASE U+0456) or `=[U+0406]mportrange(...)` (mixed case)
 *   bypasses the safety net if the NORMALIZE map only covers UPPERCASE.
 *   The map MUST therefore cover BOTH cases.
 *
 * Coverage approach (Q1 LOCKED Option A -- conservative hand-curated):
 *   - Per-letter, include the Cyrillic + Greek codepoint(s) that are
 *     VISUALLY-CONFUSABLE with the ASCII letter in common monospace fonts
 *     used by code editors / `safespace audit recent` table output.
 *   - Exclude borderline cases where the visual confusion depends on font
 *     choice (e.g., Cyrillic U+0432 lowercase ve -- looks like a SMALL B
 *     in some fonts but a v-with-loop in others; conservative skip).
 *   - Exclude letters with NO high-confidence confuser in either script
 *     (e.g., ASCII D / F / G / L / R / V / W -- neither Cyrillic nor Greek
 *     has a high-confidence uppercase confuser; documented in
 *     NO_CONFUSER_LETTERS below).
 *
 * Brief explicit guidance: "Be CONSERVATIVE -- omit borderline cases.
 * Better to under-cover than to false-positive on legitimate cells." (v1.30
 * Phase 1 brief). Total map size lands at ~46 entries -- below the design's
 * 70-90 estimate but in the conservative-end zone the brief prefers.
 *
 * Q2 LOCK Option C reminder: NORMALIZE for INTROSPECTION ONLY. The
 * applyHomoglyphPipeline transformed string is used by Phase 2's
 * FORMULA_PREFIX_RE + REJECTED_FUNCTIONS lookup; the ORIGINAL caller-
 * supplied cell value is what gets passed to the Sheets SDK. Preserves
 * audit row byte-stability (Q3 LOCK) and the v1.21 + v1.25 regression net.
 *
 * Source-byte purity (sec-rev hook #14): all map keys written via
 * `String.fromCharCode(0xXXXX)` -- NEVER literal Cyrillic / Greek
 * codepoints in the source file. Sentinel test pins source-byte absence.
 * Mirrors v1.25 Phase 4 + v1.21 P2 convention.
 */
export const HOMOGLYPH_MAP: ReadonlyMap<string, string> = new Map<
  string,
  string
>([
  // --------------------------------------------------------------------------
  // Cyrillic UPPERCASE -> ASCII UPPERCASE (visual look-alikes)
  // --------------------------------------------------------------------------
  [String.fromCharCode(0x0410), "A"], // U+0410 CYRILLIC CAPITAL LETTER A
  [String.fromCharCode(0x0412), "B"], // U+0412 CYRILLIC CAPITAL LETTER VE
  [String.fromCharCode(0x0421), "C"], // U+0421 CYRILLIC CAPITAL LETTER ES
  [String.fromCharCode(0x0415), "E"], // U+0415 CYRILLIC CAPITAL LETTER IE
  [String.fromCharCode(0x041d), "H"], // U+041D CYRILLIC CAPITAL LETTER EN (visually H)
  [String.fromCharCode(0x0406), "I"], // U+0406 CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I (canonical bypass)
  [String.fromCharCode(0x041a), "K"], // U+041A CYRILLIC CAPITAL LETTER KA
  [String.fromCharCode(0x041c), "M"], // U+041C CYRILLIC CAPITAL LETTER EM
  [String.fromCharCode(0x041e), "O"], // U+041E CYRILLIC CAPITAL LETTER O
  [String.fromCharCode(0x0420), "P"], // U+0420 CYRILLIC CAPITAL LETTER ER (visually P)
  [String.fromCharCode(0x0405), "S"], // U+0405 CYRILLIC CAPITAL LETTER DZE (visually S)
  [String.fromCharCode(0x0422), "T"], // U+0422 CYRILLIC CAPITAL LETTER TE
  [String.fromCharCode(0x0425), "X"], // U+0425 CYRILLIC CAPITAL LETTER HA (visually X)
  [String.fromCharCode(0x04ae), "Y"], // U+04AE CYRILLIC CAPITAL LETTER STRAIGHT U (visually Y)

  // --------------------------------------------------------------------------
  // Cyrillic LOWERCASE -> ASCII LOWERCASE (Phase 0a M2 coverage)
  // --------------------------------------------------------------------------
  [String.fromCharCode(0x0430), "a"], // U+0430 CYRILLIC SMALL LETTER A
  [String.fromCharCode(0x0441), "c"], // U+0441 CYRILLIC SMALL LETTER ES
  [String.fromCharCode(0x0435), "e"], // U+0435 CYRILLIC SMALL LETTER IE
  [String.fromCharCode(0x0456), "i"], // U+0456 CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I (Phase 0a M2 canonical)
  [String.fromCharCode(0x043e), "o"], // U+043E CYRILLIC SMALL LETTER O
  [String.fromCharCode(0x0440), "p"], // U+0440 CYRILLIC SMALL LETTER ER (visually p)
  [String.fromCharCode(0x0455), "s"], // U+0455 CYRILLIC SMALL LETTER DZE
  [String.fromCharCode(0x0445), "x"], // U+0445 CYRILLIC SMALL LETTER HA
  [String.fromCharCode(0x0443), "y"], // U+0443 CYRILLIC SMALL LETTER U (visually y)

  // --------------------------------------------------------------------------
  // Greek UPPERCASE -> ASCII UPPERCASE (visual look-alikes)
  // --------------------------------------------------------------------------
  [String.fromCharCode(0x0391), "A"], // U+0391 GREEK CAPITAL LETTER ALPHA
  [String.fromCharCode(0x0392), "B"], // U+0392 GREEK CAPITAL LETTER BETA
  [String.fromCharCode(0x03f9), "C"], // U+03F9 GREEK CAPITAL LUNATE SIGMA (visually C; NFKC would collapse to Sigma U+03A3, but our normalize runs first per design pipeline)
  [String.fromCharCode(0x0395), "E"], // U+0395 GREEK CAPITAL LETTER EPSILON
  [String.fromCharCode(0x0397), "H"], // U+0397 GREEK CAPITAL LETTER ETA
  [String.fromCharCode(0x0399), "I"], // U+0399 GREEK CAPITAL LETTER IOTA
  [String.fromCharCode(0x039a), "K"], // U+039A GREEK CAPITAL LETTER KAPPA
  [String.fromCharCode(0x039c), "M"], // U+039C GREEK CAPITAL LETTER MU
  [String.fromCharCode(0x039d), "N"], // U+039D GREEK CAPITAL LETTER NU
  [String.fromCharCode(0x039f), "O"], // U+039F GREEK CAPITAL LETTER OMICRON
  [String.fromCharCode(0x03a1), "P"], // U+03A1 GREEK CAPITAL LETTER RHO
  [String.fromCharCode(0x03a4), "T"], // U+03A4 GREEK CAPITAL LETTER TAU
  [String.fromCharCode(0x03a7), "X"], // U+03A7 GREEK CAPITAL LETTER CHI
  [String.fromCharCode(0x03a5), "Y"], // U+03A5 GREEK CAPITAL LETTER UPSILON

  // --------------------------------------------------------------------------
  // Greek LOWERCASE -> ASCII LOWERCASE (Phase 0a M2 coverage)
  // --------------------------------------------------------------------------
  [String.fromCharCode(0x03b1), "a"], // U+03B1 GREEK SMALL LETTER ALPHA
  [String.fromCharCode(0x03f2), "c"], // U+03F2 GREEK SMALL LUNATE SIGMA (visually c)
  [String.fromCharCode(0x03b9), "i"], // U+03B9 GREEK SMALL LETTER IOTA
  [String.fromCharCode(0x03bf), "o"], // U+03BF GREEK SMALL LETTER OMICRON
  [String.fromCharCode(0x03c1), "p"], // U+03C1 GREEK SMALL LETTER RHO
  [String.fromCharCode(0x03c4), "t"], // U+03C4 GREEK SMALL LETTER TAU
  [String.fromCharCode(0x03bd), "v"], // U+03BD GREEK SMALL LETTER NU (visually v)

  // --------------------------------------------------------------------------
  // Armenian -> ASCII (v1.35; UTS #39 confusables.txt v17.0.0 evidence; see
  // docs/v1.35-homoglyph-scripts.md section 3.3). HIGH tier = unambiguous
  // circle/letter shapes; MEDIUM tier (VO / RA / HO) closes the n / h
  // zero-coverage gap that neither Cyrillic nor Greek fills. LOW tier
  // (Armenian f / g / w confusers) deferred -- targets stay in NO_CONFUSER_LETTERS.
  // --------------------------------------------------------------------------
  [String.fromCharCode(0x0555), "O"], // U+0555 ARMENIAN CAPITAL LETTER OH (circle; reinforces O)
  [String.fromCharCode(0x054f), "S"], // U+054F ARMENIAN CAPITAL LETTER TIWN (visually S; reinforces S)
  [String.fromCharCode(0x0585), "o"], // U+0585 ARMENIAN SMALL LETTER OH (circle; reinforces o)
  [String.fromCharCode(0x0578), "n"], // U+0578 ARMENIAN SMALL LETTER VO (visually n; closes n gap)
  [String.fromCharCode(0x057c), "n"], // U+057C ARMENIAN SMALL LETTER RA (visually n; closes n gap)
  [String.fromCharCode(0x0570), "h"], // U+0570 ARMENIAN SMALL LETTER HO (visually h; closes h gap)
]);

/**
 * Letters in the 22-letter REJECT-set scope for which we have NO Cyrillic
 * AND NO Greek high-confidence visual confuser. Used by the alphabet-
 * coverage meta-test (Risk 4 forcing function -- if a 12th REJECT function
 * adds a new letter not in this exception list AND not present in
 * HOMOGLYPH_MAP, the meta-test fails loudly).
 *
 * UPPERCASE: D F G L R V W
 * LOWERCASE: b d f g k l m r w
 *
 * v1.35 -- `h` and `n` REMOVED from this set: Armenian now supplies
 * high-confidence confusers (HO U+0570 -> h; VO U+0578 + RA U+057C -> n), so
 * both letters are now COVERED by HOMOGLYPH_MAP. See docs/v1.35-homoglyph-scripts.md.
 *
 * Rationale per letter (conservative; documented for future re-evaluation):
 *   - D / d : no Cyrillic confuser; Greek Delta is triangle-shaped, NOT D.
 *   - F / f : no Cyrillic confuser; no Greek confuser.
 *   - G / g : no Cyrillic confuser; no Greek confuser.
 *   - L / l : no Cyrillic confuser; Greek Lambda is inverted-V, NOT L.
 *   - R / r : no Cyrillic confuser; no Greek confuser.
 *   - V (upper) : no high-confidence; Cyrillic IZHITSA U+0474 is borderline
 *     (looks like V but rare; conservative skip).
 *   - W / w : no Cyrillic or Greek confuser.
 *   - b : Cyrillic U+0432 (ve) is borderline (font-dependent); conservative skip.
 *   - k : Cyrillic U+043A + Greek kappa U+03BA are borderline (subtle serif
 *     differences); conservative skip.
 *   - m : Cyrillic U+043C + Greek mu U+03BC are visually distinct from m
 *     (Greek mu has descender; Cyrillic em has flat-bottom inner V).
 *   - r : no Cyrillic or Greek confuser.
 *
 * Updating this list: if a future PR adds a 12th REJECT function whose name
 * introduces a new letter not in the 22-letter set, BOTH this list AND
 * HOMOGLYPH_MAP must be re-audited together. The meta-test is the forcing
 * function.
 */
export const NO_CONFUSER_LETTERS: ReadonlySet<string> = new Set([
  // UPPERCASE
  "D",
  "F",
  "G",
  "L",
  "R",
  "V",
  "W",
  // LOWERCASE (v1.35: `h` + `n` removed -- now covered by Armenian HOMOGLYPH_MAP)
  "b",
  "d",
  "f",
  "g",
  "k",
  "l",
  "m",
  "r",
  "w",
]);

// ============================================================================
// Pipeline application
// ============================================================================

/**
 * Result of `applyHomoglyphPipeline`.
 *
 * v1.32 Phase 1 -- return-shape extension surfacing the forensic
 * `homoglyphSource` field. PRESENCE-as-signal (mirror v1.24 `errorCode` /
 * v1.27 `MetaMap` patterns):
 *   - `homoglyphSource` ABSENT (`undefined`): the input contained zero
 *     transformable characters (pure ASCII fast-path OR non-ASCII input
 *     with no matching Default_Ignorable / Bidi / Homoglyph chars).
 *   - `homoglyphSource` PRESENT (non-empty string): at least one character
 *     was either STRIPPED (via DEFAULT_IGNORABLE_RE or BIDI_OVERRIDE_RE) or
 *     NORMALIZED (via HOMOGLYPH_MAP). The buffer captures the ORIGINAL
 *     (pre-transformation) bytes from the input, preserved in INPUT byte
 *     order (per docs/v1.32-forensic-field.md section 3 Q2 LOCK Option B
 *     all-transformed-chars).
 *
 * Phase 2 territory: `formula-reject.ts` will surface the value as the
 * audit field `rejected_formula_homoglyph_source` on REJECT path only
 * (introspection-only per design section 6 Q5 LOCK -- SDK still receives
 * the ORIGINAL cell value unchanged). Phase 1 ships the capture; Phase 2
 * wires it through MCPError.data + sheetsMutationMeta.
 */
export interface HomoglyphPipelineResult {
  /**
   * Transformed string used by formula-reject.ts for FORMULA_PREFIX_RE
   * introspection + REJECTED_FUNCTIONS membership check. Always present.
   */
  normalized: string;
  /**
   * Original (pre-transformation) characters that were stripped or
   * normalized by the pipeline, preserved in INPUT byte order. See
   * `HomoglyphPipelineResult` docstring for PRESENCE-as-signal semantics.
   *
   * Phase 1: captured but unused by handlers. Phase 2 will surface this
   * value via the audit field `rejected_formula_homoglyph_source` on the
   * REJECT path ONLY (Q5 LOCK INTROSPECTION refinement -- forensic
   * capture survives a denied write so operators can identify the
   * attack vector without leaking original bytes onto a PASS path).
   */
  homoglyphSource?: string;
}

/**
 * Apply STEP A -> STEP B -> STEP C to input string for formula-reject
 * introspection purposes ONLY.
 *
 * Returns `{normalized, homoglyphSource?}`. The ORIGINAL value is NOT
 * mutated; the caller (Phase 2 formula-reject.ts:validateCellValue)
 * discards the transformed string after Step 4 REJECTED_FUNCTIONS
 * membership lookup -- the cell value passed to the Sheets SDK is the
 * ORIGINAL caller-supplied value. This preserves audit row byte-stability
 * (Q3 LOCK) and the v1.21 + v1.25 regression net.
 *
 * v1.32 Phase 1 -- return shape extended to surface the forensic
 * `homoglyphSource` field (PRESENCE-as-signal). See `HomoglyphPipelineResult`
 * docstring + docs/v1.32-forensic-field.md section 3 Q2 LOCK Option B
 * for the capture contract. ZERO behavior change to runtime: handlers
 * still consume `normalized` only (Phase 1 surfaces the field but does
 * NOT wire it through; Phase 2 will).
 *
 * Pipeline ORDER (Q2 LOCKED + sec-rev hook #10):
 *   STEP A (STRIP Default_Ignorable) -> STEP B (STRIP Bidi) -> STEP C
 *   (NORMALIZE Cyrillic + Greek homoglyphs to ASCII). After this function
 *   returns, formula-reject.ts will still apply STEP 0a (v1.25 zero-width
 *   strip -- harmless now-redundant after STEP A) + STEP 0 (NFKC) + STEP 3
 *   regex + STEP 4 REJECT-set lookup.
 *
 * Why ORDER matters:
 *   - STRIP before NORMALIZE: stripping invisible-char splices first ensures
 *     the resulting identifier is a contiguous codepoint sequence the
 *     NORMALIZE map can operate on.
 *   - STEP A before STEP B: STEP B codepoints (bidi) are a subset of STEP A
 *     codepoints (Default_Ignorable); STEP B is redundant-by-design strip
 *     for documentation clarity (see BIDI_OVERRIDE_RE docstring).
 *   - NORMALIZE before NFKC: per design section 6 Q2 LOCKED Option C --
 *     NFKC handles Class 4 (Fullwidth / Mathematical) per Phase 0a M1
 *     empirical verification; NORMALIZE handles Class 1 (Cyrillic / Greek)
 *     which NFKC does NOT collapse. Order ensures both transformations land.
 *
 * Capture semantics (v1.32 Phase 1):
 *   - Single-pass char-by-char loop replaces the previous 2-regex +
 *     for-of pattern. Each input char is classified into one of:
 *       (a) Default_Ignorable -- STRIP from output + APPEND original to
 *           homoglyphSource buffer
 *       (b) Bidi override -- STRIP from output + APPEND original to
 *           homoglyphSource buffer (redundant with (a) for the 9-codepoint
 *           overlap subset; preserved for documentation clarity per
 *           BIDI_OVERRIDE_RE docstring)
 *       (c) HOMOGLYPH_MAP key -- APPEND mapped ASCII to output + APPEND
 *           original to homoglyphSource buffer
 *       (d) other -- APPEND char as-is to output (no homoglyphSource entry)
 *   - homoglyphSource buffer captures ORIGINAL bytes (not the normalized
 *     ASCII form) in INPUT byte order. PRESENCE-as-signal: empty buffer
 *     yields field-ABSENT return; non-empty yields field-PRESENT.
 *   - For-of iteration walks by Unicode code point (NOT UTF-16 code unit);
 *     all entries in HOMOGLYPH_MAP are BMP-only so single-code-unit chars
 *     compare correctly against Map keys. Supplementary-plane chars (e.g.,
 *     TAG block at U+E0000-U+E007F) test DEFAULT_IGNORABLE_RE per-char.
 *
 * Performance (sec-rev hook #5):
 *   - Fast-path: pure ASCII strings (most common case for legitimate
 *     formula cells) bypass char loop entirely via
 *     `/[^\x20-\x7E]/.test(s)` early-exit -- returns `{normalized: s}`
 *     (no homoglyphSource field; PRESENCE-as-signal).
 *   - Non-ASCII path: single O(N) for-of with O(1) per-char regex test +
 *     O(1) Map lookup. No backtracking; no alternation. Eliminates the
 *     two extra full-string-replace passes from the pre-v1.32 impl.
 *
 * @param s caller-supplied cell value (already type-checked as string by
 *          handler at the SDK boundary)
 * @returns `{normalized, homoglyphSource?}` -- see `HomoglyphPipelineResult`
 *          for PRESENCE-as-signal semantics
 */
export function applyHomoglyphPipeline(s: string): HomoglyphPipelineResult {
  // Fast-path: pure ASCII (most legitimate formulas + cell values).
  // 0x20-0x7E = printable ASCII; everything else falls through to the
  // transformation pipeline. Empty string -> ASCII fast-path -> returns
  // `{normalized: ""}`. PRESENCE-as-signal: homoglyphSource ABSENT.
  if (!/[^\x20-\x7E]/.test(s)) return { normalized: s };

  // Non-ASCII path: single-pass char-by-char loop combining STEP A + STEP B
  // (STRIP Default_Ignorable + Bidi) and STEP C (NORMALIZE Cyrillic/Greek
  // homoglyphs to ASCII) with v1.32 Phase 1 forensic capture.
  //
  // Per-char regex `.test()` against bounded character classes (DEFAULT_
  // IGNORABLE_RE / BIDI_OVERRIDE_RE) is O(1) -- the regex engine matches a
  // single code point against the union of disjunctions in the class. Map
  // lookup is O(1). Net cost: O(N) input length with constant per-char work.
  //
  // for-of iterates by Unicode code point (handles supplementary plane TAG
  // block at U+E0000-U+E007F correctly via surrogate-pair coalescing). All
  // HOMOGLYPH_MAP keys are BMP-only so per-char Map.get(ch) sees the full
  // codepoint as a 1- or 2-code-unit string and looks up against the
  // BMP-keyed Map.
  let normalized = "";
  let homoglyphSource = "";
  // v1.33 sec-L1 -- codepoints captured into homoglyphSource so far. The
  // forensic buffer is capped at SHEETS_HOMOGLYPH_SOURCE_MAX_CHARS (256) to
  // bound the audit-row + MCPError.data field a homoglyph-flood cell can emit
  // (a ~50KB all-confuser cell would otherwise yield a ~25000-char field).
  // `normalized` (the security REJECT-verdict input) is NEVER capped -- it
  // continues to receive ALL transforms below. Deliberate, documented
  // relaxation of v1.32 Q2 LOCK for the pathological flood case only.
  let homoglyphCount = 0;
  for (const ch of s) {
    // Per-char regex testing requires fresh state for `g`-flag regexes.
    // Reset lastIndex; alternative would be a non-`g` clone of the class
    // built once at module load. Reset is simpler and the regex engine
    // amortizes the test() cost regardless.
    DEFAULT_IGNORABLE_RE.lastIndex = 0;
    BIDI_OVERRIDE_RE.lastIndex = 0;
    if (DEFAULT_IGNORABLE_RE.test(ch) || BIDI_OVERRIDE_RE.test(ch)) {
      // STEP A / STEP B -- STRIP from output, capture original for
      // forensic field (PRESENCE-as-signal; capped at 256 per sec-L1).
      if (homoglyphCount < SHEETS_HOMOGLYPH_SOURCE_MAX_CHARS) {
        homoglyphSource += ch;
        homoglyphCount++;
      }
      continue;
    }
    const mapped = HOMOGLYPH_MAP.get(ch);
    if (mapped !== undefined) {
      // STEP C -- NORMALIZE Cyrillic/Greek homoglyph to ASCII (UNCAPPED --
      // security output), capture ORIGINAL char for forensic field (not the
      // mapped ASCII; capped at 256 per sec-L1).
      normalized += mapped;
      if (homoglyphCount < SHEETS_HOMOGLYPH_SOURCE_MAX_CHARS) {
        homoglyphSource += ch;
        homoglyphCount++;
      }
      continue;
    }
    // Pass-through: char is non-ASCII but not in any transform scope
    // (e.g., Cyrillic U+0414 DE has no high-confidence confuser per
    // NO_CONFUSER_LETTERS). No homoglyphSource entry.
    normalized += ch;
  }
  // PRESENCE-as-signal: homoglyphSource ABSENT when buffer is empty (pure
  // pass-through; defensive coverage for non-ASCII inputs that hit zero
  // transform scope). Mirrors v1.24 `errorCode` / v1.27 `MetaMap` patterns.
  return homoglyphSource.length === 0
    ? { normalized }
    : { normalized, homoglyphSource };
}
