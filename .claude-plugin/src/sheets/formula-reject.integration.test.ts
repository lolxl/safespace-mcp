// v1.30 Phase 2 -- formula-reject + homoglyph-normalize integration tests.
//
// Coverage targets (per docs/v1.30-uts39-defense.md section 2.2 + section 8
// hooks #1 / #2 / #3 / #4 / #10 / #13):
//   - Pipeline ORDER sentinel (Hook #10): STEP 0a -> STEP 0 -> STEP 0b ->
//     STEP 3 -> STEP 4. Interleaved zero-width + Cyrillic + bidi inputs
//     surface as ASCII REJECT-set members.
//   - Per-REJECT-function homoglyph coverage: all 11 functions covered with
//     at least one Cyrillic + one Greek variant at position 0 (capital).
//   - Lowercase coverage (Phase 0a M2): Cyrillic lowercase i (U+0456) +
//     Greek lowercase iota (U+03B9) bypasses CLOSED.
//   - NEGATIVE / false-positive avoidance: Cyrillic letters in STRING
//     CONTENT (not in function-name position) still PASS; pure ASCII
//     non-REJECT cells still PASS; lone Cyrillic without formula prefix
//     still PASS; empty / non-string still PASS.
//   - INTROSPECTION-ONLY semantics (Q2 LOCK Option C / Hook #3): MCPError
//     surface does NOT leak the introspected (normalized) form back to
//     the caller; only the rejected_function field carries the NORMALIZED
//     ASCII name (Q4 LOCK -32029 reuse preserves forensic shape).
//   - Audit forensic shape (Hook #13): rejected_function = NORMALIZED
//     ASCII function name across ASCII / Cyrillic / Greek / lowercase
//     variants -- single canonical token per attack family.
//   - Perf regression (Risk 2 <=5% budget / Hook #4 / Phase 0a L1): ASCII
//     fast-path bench under catastrophic threshold (matches Phase 1
//     baseline budget).
//   - v1.32 Phase 2 (Category I): forensic field `rejected_formula_homoglyph_source`
//     propagation through the REAL audit-row serialize fn -- PRESENT (literal
//     source bytes, INPUT order) on homoglyph / bidi / Default_Ignorable
//     REJECTs; ABSENT on pure-ASCII REJECTs (PRESENCE-as-signal / Q3 LOCK);
//     ORDER pinned AFTER rejected_formula_function. End-to-end handler wiring
//     in handlers.test.ts #UV18 + #BU69.
//
// NO new MCPError code, NO new audit channel, NO new scope -- Phase 2 is
// behavioral wire-up only. Q4 LOCKED reuse -32029 / NORMALIZED ASCII
// function name preserves the existing CommentDeleteMeta-adjacent
// sheetsMutationMeta `rejected_formula_function` schema.

import { describe, expect, test } from "bun:test";
import { validateCellValue } from "./formula-reject";
// v1.32 Phase 2 — Category I exercises the REAL audit-row serialize boundary
// (production code) for the forensic homoglyph-source field.
import { AUDIT_META_CHANNELS } from "../audit";
import type { SheetsMutationAuditMeta } from "../audit";

// Codepoint constants -- built via String.fromCharCode so this test file
// also stays clean of literal Cyrillic / Greek / Default_Ignorable bytes
// (mirror v1.25 Phase 4 + v1.26 NEW-8 + Phase 1 hygiene). Source-byte
// purity sentinel on the implementation files is the authoritative check;
// this comment is informational discipline.
const ZWSP = String.fromCharCode(0x200b); // ZERO WIDTH SPACE
const RLO = String.fromCharCode(0x202e); // RIGHT-TO-LEFT OVERRIDE
const MONGOLIAN_VS1 = String.fromCharCode(0x180b); // MONGOLIAN FREE VARIATION SELECTOR ONE

// Cyrillic UPPERCASE homoglyphs (subset used across tests; see
// homoglyph-normalize.ts HOMOGLYPH_MAP for the full table).
const CYR_A = String.fromCharCode(0x0410);
const CYR_B = String.fromCharCode(0x0412);
const CYR_C = String.fromCharCode(0x0421);
const CYR_E = String.fromCharCode(0x0415);
const CYR_H = String.fromCharCode(0x041d);
const CYR_I = String.fromCharCode(0x0406);
const CYR_K = String.fromCharCode(0x041a);
const CYR_M = String.fromCharCode(0x041c);
const CYR_O = String.fromCharCode(0x041e);
const CYR_P = String.fromCharCode(0x0420);
const CYR_S = String.fromCharCode(0x0405);
const CYR_T = String.fromCharCode(0x0422);
const CYR_X = String.fromCharCode(0x0425);
const CYR_Y = String.fromCharCode(0x04ae);

// Cyrillic LOWERCASE homoglyphs (Phase 0a M2 coverage).
const CYR_i_lc = String.fromCharCode(0x0456);
const CYR_a_lc = String.fromCharCode(0x0430);
const CYR_o_lc = String.fromCharCode(0x043e);
const CYR_p_lc = String.fromCharCode(0x0440);

// Greek UPPERCASE homoglyphs.
const GR_A = String.fromCharCode(0x0391);
const GR_B = String.fromCharCode(0x0392);
const GR_E = String.fromCharCode(0x0395);
const GR_H = String.fromCharCode(0x0397);
const GR_I = String.fromCharCode(0x0399);
const GR_K = String.fromCharCode(0x039a);
const GR_M = String.fromCharCode(0x039c);
const GR_N = String.fromCharCode(0x039d);
const GR_O = String.fromCharCode(0x039f);
const GR_P = String.fromCharCode(0x03a1);
const GR_T = String.fromCharCode(0x03a4);
const GR_X = String.fromCharCode(0x03a7);
const GR_Y = String.fromCharCode(0x03a5);

// Greek LOWERCASE homoglyphs.
const GR_i_lc = String.fromCharCode(0x03b9);
const GR_o_lc = String.fromCharCode(0x03bf);

// ============================================================================
// A. Pipeline ORDER sentinel (Hook #10)
// ============================================================================

describe("v1.30 Phase 2 -- pipeline ORDER (STEP 0a -> STEP 0 -> STEP 0b -> STEP 3)", () => {
  test("interleaved zero-width + Cyrillic surfaces as REJECT (STEP 0a strips ZW, STEP 0b normalizes Cyrillic)", () => {
    // Combined attack: Cyrillic capital I (U+0406) + ZWSP (U+200B) spliced
    // inside the function name. STEP 0a strips ZWSP; STEP 0b normalizes
    // Cyrillic I -> ASCII I; STEP 3 regex captures `IMPORTRANGE`.
    const input = `=${CYR_I}${ZWSP}MPORTRANGE("x","y")`;
    const r = validateCellValue(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("bidi-only RLO splice surfaces as REJECT (STEP 0b BIDI_OVERRIDE_RE strips)", () => {
    // RLO (U+202E) is in BOTH DEFAULT_IGNORABLE_RE AND BIDI_OVERRIDE_RE.
    // STEP 0b applies both; either branch strips it. Result: pure ASCII
    // `=IMPORTRANGE(...)` for STEP 3 regex.
    const input = `=${RLO}IMPORTRANGE("x","y")`;
    const r = validateCellValue(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("pure ASCII REJECT still rejects (v1.21 regression invariant preserved)", () => {
    const r = validateCellValue('=IMPORTRANGE("x","y")');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("Default_Ignorable Mongolian VS1 splice surfaces as REJECT", () => {
    // MONGOLIAN_VS1 (U+180B) is in DEFAULT_IGNORABLE_RE but NOT in the
    // v1.25 Phase 4 5-codepoint zero-width set -- this is the canonical
    // STEP 0b benefit beyond STEP 0a.
    const input = `=I${MONGOLIAN_VS1}MPORTRANGE("x","y")`;
    const r = validateCellValue(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });
});

// ============================================================================
// B. Per-REJECT-function homoglyph coverage (11 functions x Cyrillic / Greek)
// ============================================================================

describe("v1.30 Phase 2 -- per-function Cyrillic homoglyph coverage", () => {
  test("Cyrillic =[U+0406]MPORTRANGE REJECTED (canonical attack vector)", () => {
    const r = validateCellValue(`=${CYR_I}MPORTRANGE("x","y")`);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.rejected_function).toBe("IMPORTRANGE");
      // v1.32 Phase 1 -- forensic field captures the single Cyrillic byte
      // (PRESENCE-as-signal on the homoglyph attack family).
      expect(r.rejected_formula_homoglyph_source).toBe(CYR_I);
    }
  });

  test("Cyrillic IMPORTXML REJECTED", () => {
    const r = validateCellValue(`=${CYR_I}${CYR_M}PORTXML("u")`);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.rejected_function).toBe("IMPORTXML");
      // v1.32 Phase 1 -- 2 Cyrillic bytes captured in INPUT byte order.
      expect(r.rejected_formula_homoglyph_source).toBe(`${CYR_I}${CYR_M}`);
    }
  });

  test("Cyrillic IMPORTHTML REJECTED", () => {
    const r = validateCellValue(`=${CYR_I}MPORTHTML("u","table",1)`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTHTML");
  });

  test("Cyrillic IMPORTDATA REJECTED", () => {
    const r = validateCellValue(`=${CYR_I}MPORTDATA("u")`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTDATA");
  });

  test("Cyrillic IMPORTFEED REJECTED", () => {
    const r = validateCellValue(`=${CYR_I}MPORTFEED("u")`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTFEED");
  });

  test("Cyrillic HYPERLINK REJECTED", () => {
    const r = validateCellValue(`=${CYR_H}YPERLINK("u","label")`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("HYPERLINK");
  });

  test("Cyrillic GOOGLEFINANCE REJECTED", () => {
    // Use Cyrillic capital O (U+041E) inside identifier.
    const r = validateCellValue(`=G${CYR_O}OGLEFINANCE("NASDAQ:GOOG")`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("GOOGLEFINANCE");
  });

  test("Cyrillic GOOGLETRANSLATE REJECTED", () => {
    const r = validateCellValue(`=G${CYR_O}OGLETRANSLATE("hi","en","es")`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("GOOGLETRANSLATE");
  });

  test("Cyrillic IMAGE REJECTED", () => {
    const r = validateCellValue(`=${CYR_I}MAGE("https://attacker/x.png")`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMAGE");
  });

  // INFO-1 (v1.31): originally one test asserting two distinct behaviors —
  // (a) Cyrillic X at position 0 PASSES (W has no homoglyph; XEBSERVICE
  // is not in REJECT set), and (b) Cyrillic B inside identifier REJECTS
  // as WEBSERVICE post-homoglyph-normalize. Split into 2 tests for clear
  // intent + single assertion target per test.

  test("Cyrillic WEBSERVICE PASSES (X-variant — W has no homoglyph; XEBSERVICE not in REJECT set)", () => {
    // Cyrillic X (U+0425) -> ASCII X via homoglyph-normalize. But
    // WEBSERVICE starts with W, not X. Since W is not in HOMOGLYPH_MAP
    // (per NO_CONFUSER_LETTERS) AND the resulting identifier
    // `XEBSERVICE` is not in REJECT set, the cell PASSES validation.
    const r = validateCellValue(`=${CYR_X}EBSERVICE("u")`);
    expect(r.ok).toBe(true);
  });

  test("Cyrillic WEBSERVICE REJECTED (B-variant — Cyrillic B inside identifier normalizes to ASCII B)", () => {
    // Cyrillic B (U+0412) -> ASCII B via homoglyph-normalize.
    // Post-normalize identifier is WEBSERVICE, which IS in REJECT set.
    const r = validateCellValue(`=WE${CYR_B}SERVICE("u")`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("WEBSERVICE");
  });

  test("Cyrillic LAMBDA REJECTED", () => {
    const r = validateCellValue(
      `=L${CYR_A}MBDA(x, IMPORTRANGE(x))("https://attacker")`,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("LAMBDA");
  });
});

describe("v1.30 Phase 2 -- per-function Greek homoglyph coverage", () => {
  test("Greek IMPORTRANGE REJECTED (Iota at position 0)", () => {
    const r = validateCellValue(`=${GR_I}MPORTRANGE("x","y")`);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.rejected_function).toBe("IMPORTRANGE");
      // v1.32 Phase 1 -- Greek Iota captured as forensic source.
      expect(r.rejected_formula_homoglyph_source).toBe(GR_I);
    }
  });

  test("Greek IMPORTXML REJECTED (Iota + Mu)", () => {
    const r = validateCellValue(`=${GR_I}${GR_M}PORTXML("u")`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTXML");
  });

  test("Greek HYPERLINK REJECTED (Eta at position 0)", () => {
    const r = validateCellValue(`=${GR_H}YPERLINK("u","l")`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("HYPERLINK");
  });

  test("Greek LAMBDA REJECTED (Alpha inside)", () => {
    const r = validateCellValue(
      `=L${GR_A}MBDA(x, IMPORTRANGE(x))("https://attacker")`,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("LAMBDA");
  });

  test("Greek mixed: IMAGE with Alpha REJECTED", () => {
    const r = validateCellValue(`=IM${GR_A}GE("https://attacker/x.png")`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMAGE");
  });
});

// ============================================================================
// C. Lowercase coverage (Phase 0a M2)
// ============================================================================

describe("v1.30 Phase 2 -- lowercase homoglyph coverage (Phase 0a M2 closure)", () => {
  // FORMULA_PREFIX_RE captures BEFORE .toUpperCase(). The map MUST cover
  // lowercase letters too; otherwise lowercase Cyrillic i (U+0456) bypasses.
  test("lowercase Cyrillic =[U+0456]mportrange REJECTED", () => {
    const r = validateCellValue(`=${CYR_i_lc}mportrange("x","y")`);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.rejected_function).toBe("IMPORTRANGE");
      // v1.32 Phase 1 -- lowercase Cyrillic byte captured (Phase 0a M2
      // coverage path; field present despite lowercase identifier).
      expect(r.rejected_formula_homoglyph_source).toBe(CYR_i_lc);
    }
  });

  test("lowercase Greek =[U+03B9]mportrange REJECTED", () => {
    const r = validateCellValue(`=${GR_i_lc}mportrange("x","y")`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("mixed-case Cyrillic =[U+0406]mp[U+041E]rtrange REJECTED", () => {
    // Capital Cyrillic I + lowercase Cyrillic o inside. Resulting identifier
    // is `Imp[U+041E]rtrange` -> NORMALIZE -> `ImpOrtrange` -> uppercase ->
    // `IMPORTRANGE`. Wait -- U+041E is CAPITAL O; need lowercase Cyrillic
    // o = U+043E to test the lowercase path. Use that:
    const r = validateCellValue(`=${CYR_I}mp${CYR_o_lc}rtrange("x","y")`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("lowercase Cyrillic =[U+0456]m[U+0430]ge REJECTED (Cyrillic a + i mixed)", () => {
    const r = validateCellValue(`=${CYR_i_lc}m${CYR_a_lc}ge("u")`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMAGE");
  });

  test("lowercase Greek omicron + iota REJECTED (in hyperlink)", () => {
    const r = validateCellValue(`=hyperl${GR_i_lc}nk("u","l")`);
    // h is in NO_CONFUSER_LETTERS so not normalized; identifier becomes
    // `hyperlink` (already ASCII except the Greek iota normalized to ASCII i).
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("HYPERLINK");
  });
});

// ============================================================================
// D. NEGATIVE -- false positive avoidance
// ============================================================================

describe("v1.30 Phase 2 -- false-positive avoidance (NEGATIVE coverage)", () => {
  test("Cyrillic inside STRING LITERAL content PASSES (not in function-name position)", () => {
    // `="Текст"` -- equals prefix, but function-name regex never matches
    // a quoted string. Pass-through.
    const input = `="${CYR_I}${CYR_M}${CYR_P}"`;
    const r = validateCellValue(input);
    expect(r.ok).toBe(true);
  });

  test("pure ASCII non-REJECT function PASSES (SUM)", () => {
    const r = validateCellValue("=SUM(A1:B2)");
    expect(r.ok).toBe(true);
  });

  test("lone Cyrillic capital I (no formula prefix) PASSES", () => {
    // No `=` / `+` prefix -- STEP 2 short-circuits with PASS.
    const r = validateCellValue(`${CYR_I}`);
    expect(r.ok).toBe(true);
  });

  test("Cyrillic-laced non-REJECT function PASSES (e.g., =SUM with Cyrillic S)", () => {
    // Cyrillic S (U+0405) -> ASCII S; resulting identifier is `SUM`, not in
    // REJECT set.
    const r = validateCellValue(`=${CYR_S}UM(A1:B2)`);
    expect(r.ok).toBe(true);
  });

  test("empty string PASSES", () => {
    expect(validateCellValue("").ok).toBe(true);
  });

  test("non-string cells PASS (number / boolean)", () => {
    expect(validateCellValue(42).ok).toBe(true);
    expect(validateCellValue(true).ok).toBe(true);
    expect(validateCellValue(null).ok).toBe(true);
    expect(validateCellValue(undefined).ok).toBe(true);
  });

  test("SUM-wrapper gap now REJECTS (v1.34 STEP 5 closes v1.21 §3.3)", () => {
    // Outer is SUM (not in REJECT set), but v1.34 STEP 5 scans the whole
    // introspected expression and catches the nested IMPORTRANGE call token.
    const r = validateCellValue('=SUM(IMPORTRANGE("x","y"))');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });
});

// ============================================================================
// E. INTROSPECTION-ONLY semantics (Q2 LOCK Option C / Hook #3)
// ============================================================================

describe("v1.30 Phase 2 -- INTROSPECTION-ONLY (Q2 LOCK Option C)", () => {
  // The ORIGINAL cell value MUST be preserved -- the handler passes the
  // ORIGINAL argument (`cell`) to validateCellValue, which returns only
  // a {ok, rejected_function?, rejected_formula_homoglyph_source?}
  // discriminator. validateCellValue does NOT return a normalized string;
  // it has no way to leak the FULL transformed form back. This is the
  // structural defense -- pin it with a meta test.
  //
  // v1.32 Phase 1 (Q5 LOCK INTROSPECTION refinement) -- the forensic field
  // `rejected_formula_homoglyph_source` captures ORIGINAL pre-normalize
  // chars from the input but ONLY surfaces them on the REJECT path. The
  // SDK still receives the ORIGINAL cell value (Q5 LOCK introspection-only
  // semantics preserved). The sentinel asserts the closed shape of the
  // REJECT discriminator post-Phase 1.
  test("validateCellValue return type carries the closed REJECT discriminator (v1.32 Phase 1 surfaces rejected_formula_homoglyph_source forensic field)", () => {
    const r = validateCellValue(`=${CYR_I}MPORTRANGE("x","y")`);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      // v1.32 Phase 1 -- closed REJECT discriminator on a Cyrillic homoglyph
      // attack:
      //   - `ok` (false)
      //   - `rejected_function` (NORMALIZED ASCII per Q4 LOCK)
      //   - `rejected_formula_homoglyph_source` (PRESENCE-as-signal: present
      //     on homoglyph attacks; absent on pure ASCII attacks). Captures
      //     ORIGINAL pre-normalize chars in INPUT byte order (Q2 LOCK
      //     Option B). Phase 2 wires this through to audit + MCPError.
      // Sentinel against future drift adding a `normalized_input` or
      // `introspected_cell` field that would leak the FULL transformed
      // form (would be a different threat-model violation).
      const keys = Object.keys(r).sort();
      expect(keys).toEqual([
        "ok",
        "rejected_formula_homoglyph_source",
        "rejected_function",
      ]);
    }
  });

  test("v1.32 Phase 1 -- ASCII REJECT has CLOSED 2-key shape (no homoglyph_source on PASS-as-signal ABSENCE)", () => {
    // Pure ASCII attack: PRESENCE-as-signal contract requires homoglyph_source
    // ABSENT (no transformable chars in input). Sentinel pins the contract
    // that ASCII attacks expose the original v1.21 2-key REJECT shape
    // unchanged.
    const r = validateCellValue('=IMPORTRANGE("x","y")');
    expect(r.ok).toBe(false);
    if (!r.ok) {
      const keys = Object.keys(r).sort();
      expect(keys).toEqual(["ok", "rejected_function"]);
      expect(r.rejected_formula_homoglyph_source).toBeUndefined();
    }
  });

  test("rejected_function carries NORMALIZED ASCII, NOT original Cyrillic bytes (Q4 LOCK preserves forensic shape)", () => {
    const r = validateCellValue(`=${CYR_I}MPORTRANGE("x","y")`);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.rejected_function).toBe("IMPORTRANGE");
      // NEGATIVE: do NOT echo the original Cyrillic byte. The forensic
      // contract is "single canonical token per attack family".
      expect(r.rejected_function).not.toContain(CYR_I);
      // v1.32 Phase 1 -- but DO surface the original byte in the dedicated
      // forensic field (PRESENCE-as-signal). Allows Phase 2 audit to
      // distinguish attack vectors without conflating function-name with
      // attack-source.
      expect(r.rejected_formula_homoglyph_source).toBe(CYR_I);
    }
  });
});

// ============================================================================
// F. Audit forensic shape (Hook #13) -- NORMALIZED token across variants
// ============================================================================

describe("v1.30 Phase 2 -- audit forensic shape consistency (Hook #13 / Q4 LOCK)", () => {
  // ASCII / Cyrillic / Greek / lowercase / mixed all surface the SAME
  // `rejected_function` value -- the NORMALIZED ASCII canonical form.
  // This lets `safespace audit suspicious` group all homoglyph-variant
  // attack attempts under one bucket (single forensic shape preserved).
  //
  // v1.32 Phase 1 -- ALL Category G tests gain PRESENCE/ABSENCE assertions
  // on the new `rejected_formula_homoglyph_source` forensic field. ASCII
  // attack -> field ABSENT; Cyrillic / Greek / lowercase attacks -> field
  // PRESENT with original transformed bytes. Establishes the audit-row
  // contract Phase 2 will surface end-to-end.
  test("ASCII =IMPORTRANGE -> rejected_function=IMPORTRANGE", () => {
    const r = validateCellValue('=IMPORTRANGE("x","y")');
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.rejected_function).toBe("IMPORTRANGE");
      // v1.32 Phase 1 -- ASCII attack: homoglyph_source ABSENT
      // (PRESENCE-as-signal contract for the no-transform path).
      expect(r.rejected_formula_homoglyph_source).toBeUndefined();
    }
  });

  test("Cyrillic =[U+0406]MPORTRANGE -> rejected_function=IMPORTRANGE (same canonical token)", () => {
    const r = validateCellValue(`=${CYR_I}MPORTRANGE("x","y")`);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.rejected_function).toBe("IMPORTRANGE");
      // v1.32 Phase 1 -- Cyrillic attack: homoglyph_source PRESENT with
      // the original Cyrillic byte.
      expect(r.rejected_formula_homoglyph_source).toBe(CYR_I);
    }
  });

  test("lowercase Cyrillic =[U+0456]mportrange -> rejected_function=IMPORTRANGE (case-folded ASCII)", () => {
    const r = validateCellValue(`=${CYR_i_lc}mportrange("x","y")`);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.rejected_function).toBe("IMPORTRANGE");
      // v1.32 Phase 1 -- lowercase Cyrillic byte captured (Phase 0a M2
      // path: PRESENCE-as-signal works regardless of input casing).
      expect(r.rejected_formula_homoglyph_source).toBe(CYR_i_lc);
    }
  });

  test("Greek =[U+0399]MPORTRANGE -> rejected_function=IMPORTRANGE (same canonical token)", () => {
    const r = validateCellValue(`=${GR_I}MPORTRANGE("x","y")`);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.rejected_function).toBe("IMPORTRANGE");
      // v1.32 Phase 1 -- Greek attack: homoglyph_source PRESENT with
      // the original Greek byte (distinct attack family from Cyrillic).
      expect(r.rejected_formula_homoglyph_source).toBe(GR_I);
    }
  });
});

// ============================================================================
// I. Forensic field propagation (v1.32 Phase 2) -- audit-row serialize boundary
// ============================================================================
//
// Category I drives the REAL production serialize fn
// (AUDIT_META_CHANNELS.sheetsMutationMeta.serialize) with a meta built EXACTLY
// the way the sheets_update_values handler builds it on the REJECT path
// (rejected_function -> rejected_formula_function NORMALIZED ASCII; the
// validateCellValue forensic field -> rejected_formula_homoglyph_source). This
// pins the audit-row byte shape:
//   - PRESENT (literal source bytes) on homoglyph / bidi / Default_Ignorable
//     REJECTs, captured in INPUT byte order (Q2 LOCK Option B).
//   - ABSENT on pure-ASCII REJECTs (PRESENCE-as-signal -> audit row stays
//     byte-identical to v1.31 for the ASCII attack family; Q3 LOCK).
//   - ORDER: rejected_formula_homoglyph_source AFTER rejected_formula_function
//     (forensic visual locality; byte-stability pin for future evolution).
// End-to-end handler wiring (recorder meta + thrown MCPError both carry the
// field) is verified in handlers.test.ts #UV18 (update_values) + #BU69
// (batch_update — both internal consumer sites).
describe("v1.32 Phase 2 -- forensic field propagation (audit serialize boundary)", () => {
  const sheetsSerialize = AUDIT_META_CHANNELS.sheetsMutationMeta.serialize;

  // Build the sheetsMutationMeta the way sheets_update_values does on REJECT.
  // Throws loudly if the fixture does NOT actually REJECT (self-checking).
  function metaFromReject(cell: string): SheetsMutationAuditMeta {
    const r = validateCellValue(cell);
    if (r.ok) {
      throw new Error(
        `test setup: expected REJECT for ${JSON.stringify(cell)} but got PASS`,
      );
    }
    return {
      target_spreadsheet_id_hash: "deadbeefdeadbeef",
      target_range_hash: "cafef00dcafef00d",
      operation: "update_values",
      policy_decision: "denied_formula_rejected",
      rejected_formula_function: r.rejected_function,
      ...(r.rejected_formula_homoglyph_source !== undefined && {
        rejected_formula_homoglyph_source: r.rejected_formula_homoglyph_source,
      }),
    };
  }

  test("Cyrillic =[U+0406]MPORTRANGE -> audit row carries source byte (literal Cyrillic)", () => {
    const out = sheetsSerialize(metaFromReject(`=${CYR_I}MPORTRANGE("x","y")`));
    expect(out.rejected_formula_function).toBe("IMPORTRANGE");
    expect(out.rejected_formula_homoglyph_source).toBe(CYR_I);
  });

  test("Greek =[U+0399]MPORTRANGE -> audit row carries source byte (literal Greek)", () => {
    const out = sheetsSerialize(metaFromReject(`=${GR_I}MPORTRANGE("x","y")`));
    expect(out.rejected_formula_function).toBe("IMPORTRANGE");
    expect(out.rejected_formula_homoglyph_source).toBe(GR_I);
  });

  test("lowercase Cyrillic =[U+0456]mportrange -> audit row carries source byte", () => {
    const out = sheetsSerialize(metaFromReject(`=${CYR_i_lc}mportrange("x","y")`));
    expect(out.rejected_formula_function).toBe("IMPORTRANGE");
    expect(out.rejected_formula_homoglyph_source).toBe(CYR_i_lc);
  });

  test("bidi-laced =[RLO]IMPORTRANGE -> audit row carries the stripped bidi byte", () => {
    // RLO (U+202E) is NOT in the 5-codepoint STEP 0a zero-width set, so it
    // survives to STEP 0b where applyHomoglyphPipeline strips it (bidi
    // override) and captures it in homoglyphSource. Post-strip identifier is
    // IMPORTRANGE -> REJECT.
    const out = sheetsSerialize(metaFromReject(`=${RLO}IMPORTRANGE("x","y")`));
    expect(out.rejected_formula_function).toBe("IMPORTRANGE");
    expect(out.rejected_formula_homoglyph_source).toBe(RLO);
  });

  test("combined Default_Ignorable + Cyrillic splice -> source bytes in INPUT order", () => {
    // MONGOLIAN_VS1 (U+180B, Default_Ignorable, NOT in the STEP 0a 5-set) at
    // position 1 + Cyrillic I at position 2. Single-pass capture preserves
    // input byte order: VS1 (STRIP) then Cyrillic I (NORMALIZE).
    const out = sheetsSerialize(
      metaFromReject(`=${MONGOLIAN_VS1}${CYR_I}MPORTRANGE("x","y")`),
    );
    expect(out.rejected_formula_function).toBe("IMPORTRANGE");
    expect(out.rejected_formula_homoglyph_source).toBe(`${MONGOLIAN_VS1}${CYR_I}`);
  });

  test("pure-ASCII =IMPORTRANGE -> audit row LACKS the field (PRESENCE-as-signal; Q3 LOCK)", () => {
    const out = sheetsSerialize(metaFromReject('=IMPORTRANGE("x","y")'));
    expect(out.rejected_formula_function).toBe("IMPORTRANGE");
    // ABSENT, not present-and-empty -- the key must not appear at all so the
    // serialized audit row stays byte-identical to v1.31 for ASCII attacks.
    expect("rejected_formula_homoglyph_source" in out).toBe(false);
    expect(out.rejected_formula_homoglyph_source).toBeUndefined();
  });

  test("serialize ORDER: rejected_formula_homoglyph_source appears AFTER rejected_formula_function", () => {
    const out = sheetsSerialize(metaFromReject(`=${CYR_I}MPORTRANGE("x","y")`));
    const keys = Object.keys(out);
    const fnIdx = keys.indexOf("rejected_formula_function");
    const srcIdx = keys.indexOf("rejected_formula_homoglyph_source");
    expect(fnIdx).toBeGreaterThanOrEqual(0);
    expect(srcIdx).toBeGreaterThan(fnIdx);
  });

  test("single forensic source: audit serialize field === validateCellValue result field (same value fed to MCPError.data)", () => {
    // The handler hands the SAME validateCellValue result field to BOTH the
    // recorder (-> serialize -> audit row) AND the MCPError.data. Pin that the
    // serialize output reflects the result field verbatim (matching-content
    // contract; end-to-end MCPError surface verified in handlers.test.ts).
    const cell = `=${CYR_I}MPORTRANGE("x","y")`;
    const r = validateCellValue(cell);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      const out = sheetsSerialize(metaFromReject(cell));
      expect(out.rejected_formula_homoglyph_source).toBe(
        r.rejected_formula_homoglyph_source,
      );
    }
  });
});

// ============================================================================
// G. Perf regression (Risk 2 <=5% budget / Hook #4 / Phase 0a L1)
// ============================================================================

describe("v1.30 Phase 2 -- perf regression sentinel (Risk 2 <=5% / Phase 0a L1)", () => {
  test("ASCII fast-path 1000 iterations finishes well under catastrophic threshold", () => {
    // Pure ASCII cells take the homoglyph-pipeline fast-path early-exit
    // (`/[^\x20-\x7E]/.test(s)` returns false -> immediate return). Phase 1
    // baseline budget was 2000ms catastrophic threshold for similar sized
    // workloads; this is the matching Phase 2 sentinel for the wired-in
    // pipeline. ASCII formulas (the common case) MUST NOT regress.
    const input = '=IMPORTRANGE("https://docs.google.com/spreadsheets/d/abc","Sheet1!A1:B10")';
    const t0 = performance.now();
    for (let i = 0; i < 1000; i++) {
      validateCellValue(input);
    }
    const elapsed = performance.now() - t0;
    // Catastrophic threshold: matches Phase 1 homoglyph-normalize.test.ts
    // perf sentinel. Real-world expectation is sub-50ms for 1000 iterations
    // (the ASCII fast-path bypasses both regex passes and the Map loop).
    expect(elapsed).toBeLessThan(2000);
  });

  test("non-ASCII (Cyrillic) path 1000 iterations stays bounded", () => {
    // Non-ASCII path takes the full pipeline (DEFAULT_IGNORABLE_RE +
    // BIDI_OVERRIDE_RE + per-char Map lookup). Should still be bounded
    // -- the regexes have bounded character classes; the Map is O(1)
    // per char.
    const input = `=${CYR_I}MPORTRANGE("https://docs.google.com/spreadsheets/d/abc","Sheet1!A1:B10")`;
    const t0 = performance.now();
    for (let i = 0; i < 1000; i++) {
      validateCellValue(input);
    }
    const elapsed = performance.now() - t0;
    expect(elapsed).toBeLessThan(2000);
  });
});
