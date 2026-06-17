// v1.30 Phase 1 -- homoglyph-normalize module tests.
//
// Coverage targets (per docs/v1.30-uts39-defense.md section 8):
//   - Module exports + size sentinels (Hook #14 + Risk 4 forcing function)
//   - ASCII fast-path early-exit (Hook #5 + #7 perf + no-false-positive)
//   - STEP A Default_Ignorable STRIP -- 5+ codepoints individually (Hook #8)
//   - STEP B Bidi override STRIP -- 9 codepoints + STEP A overlap dedup (Hook #9)
//   - STEP C homoglyph NORMALIZE -- Cyrillic + Greek BOTH cases (Phase 0a M2)
//   - Pipeline integration: STRIP-then-NORMALIZE composition + ORDER (Hook #10)
//   - Source-byte purity sentinel: ZERO literal Cyrillic / Greek /
//     Default_Ignorable bytes in source (Hook #14)
//   - Alphabet coverage meta-test: each of 22 ASCII letters in REJECT-set
//     scope has at least one Cyrillic / Greek mapping OR is documented as
//     having no high-confidence confuser (Risk 4 forcing function)
//   - Performance baseline (Risk 2 <=5% regression budget recorded for
//     Phase 2 verification)
//
// NO integration test with formula-reject.ts -- Phase 2 territory.

import { describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  applyHomoglyphPipeline,
  BIDI_OVERRIDE_RE,
  DEFAULT_IGNORABLE_RE,
  HOMOGLYPH_MAP,
  NO_CONFUSER_LETTERS,
} from "./homoglyph-normalize";

// Codepoint constants used across tests. Built via String.fromCharCode so
// THIS test file ALSO stays clean of literal Cyrillic / Greek /
// Default_Ignorable codepoints (mirror v1.25 Phase 4 + v1.26 NEW-8 source-
// byte hygiene; the source-byte sentinel further pins the implementation
// file -- both files use the same discipline).
const SHY = String.fromCharCode(0x00ad); // SOFT HYPHEN
const CGJ = String.fromCharCode(0x034f); // COMBINING GRAPHEME JOINER
const ALM = String.fromCharCode(0x061c); // ARABIC LETTER MARK
const MONGOLIAN_VS1 = String.fromCharCode(0x180b); // MONGOLIAN FREE VARIATION SELECTOR ONE
const ZWSP = String.fromCharCode(0x200b); // ZERO WIDTH SPACE
const ZWNJ = String.fromCharCode(0x200c); // ZERO WIDTH NON-JOINER
const ZWJ = String.fromCharCode(0x200d); // ZERO WIDTH JOINER
const LRM = String.fromCharCode(0x200e); // LEFT-TO-RIGHT MARK
const RLM = String.fromCharCode(0x200f); // RIGHT-TO-LEFT MARK
const LRE = String.fromCharCode(0x202a); // LEFT-TO-RIGHT EMBEDDING
const RLE = String.fromCharCode(0x202b); // RIGHT-TO-LEFT EMBEDDING
const PDF = String.fromCharCode(0x202c); // POP DIRECTIONAL FORMATTING
const LRO = String.fromCharCode(0x202d); // LEFT-TO-RIGHT OVERRIDE
const RLO = String.fromCharCode(0x202e); // RIGHT-TO-LEFT OVERRIDE
const WJ = String.fromCharCode(0x2060); // WORD JOINER
const LRI = String.fromCharCode(0x2066); // LEFT-TO-RIGHT ISOLATE
const RLI = String.fromCharCode(0x2067); // RIGHT-TO-LEFT ISOLATE
const FSI = String.fromCharCode(0x2068); // FIRST STRONG ISOLATE
const PDI = String.fromCharCode(0x2069); // POP DIRECTIONAL ISOLATE
const HANGUL_FILLER = String.fromCharCode(0x3164); // HANGUL FILLER
const VS1 = String.fromCharCode(0xfe00); // VARIATION SELECTOR-1
const BOM = String.fromCharCode(0xfeff); // ZERO WIDTH NO-BREAK SPACE / BOM

// Supplementary plane (require String.fromCodePoint for > U+FFFF).
const TAG_LATIN_A = String.fromCodePoint(0xe0041); // TAG LATIN CAPITAL LETTER A

// Cyrillic homoglyphs (Phase 0a M2 BOTH cases).
const CYRILLIC_I_UPPER = String.fromCharCode(0x0406); // canonical bypass
const CYRILLIC_I_LOWER = String.fromCharCode(0x0456);
const CYRILLIC_A_UPPER = String.fromCharCode(0x0410);
const CYRILLIC_A_LOWER = String.fromCharCode(0x0430);
const CYRILLIC_M_UPPER = String.fromCharCode(0x041c);
const CYRILLIC_O_UPPER = String.fromCharCode(0x041e);
const CYRILLIC_P_UPPER = String.fromCharCode(0x0420);
const CYRILLIC_T_UPPER = String.fromCharCode(0x0422);
const CYRILLIC_X_UPPER = String.fromCharCode(0x0425);

// Greek homoglyphs.
const GREEK_ALPHA_UPPER = String.fromCharCode(0x0391); // -> A
const GREEK_IOTA_UPPER = String.fromCharCode(0x0399); // -> I
const GREEK_RHO_UPPER = String.fromCharCode(0x03a1); // -> P
const GREEK_IOTA_LOWER = String.fromCharCode(0x03b9); // -> i
const GREEK_OMICRON_LOWER = String.fromCharCode(0x03bf); // -> o

// Armenian homoglyphs (v1.35; UTS #39 confusables.txt v17.0.0).
const ARMENIAN_OH_UPPER = String.fromCharCode(0x0555); // -> O
const ARMENIAN_TIWN_UPPER = String.fromCharCode(0x054f); // -> S
const ARMENIAN_OH_LOWER = String.fromCharCode(0x0585); // -> o
const ARMENIAN_VO_LOWER = String.fromCharCode(0x0578); // -> n
const ARMENIAN_RA_LOWER = String.fromCharCode(0x057c); // -> n
const ARMENIAN_HO_LOWER = String.fromCharCode(0x0570); // -> h

// ============================================================================
// A. Module exports + size sentinels
// ============================================================================

describe("v1.30 Phase 1 -- module exports + size sentinels", () => {
  test("DEFAULT_IGNORABLE_RE is RegExp with g + u flags", () => {
    expect(DEFAULT_IGNORABLE_RE).toBeInstanceOf(RegExp);
    expect(DEFAULT_IGNORABLE_RE.flags).toContain("g");
    expect(DEFAULT_IGNORABLE_RE.flags).toContain("u");
  });

  test("BIDI_OVERRIDE_RE is RegExp with g + u flags", () => {
    expect(BIDI_OVERRIDE_RE).toBeInstanceOf(RegExp);
    expect(BIDI_OVERRIDE_RE.flags).toContain("g");
    expect(BIDI_OVERRIDE_RE.flags).toContain("u");
  });

  test("HOMOGLYPH_MAP has expected entry count (50; conservative per brief)", () => {
    // v1.30 shipped 44 conservative Cyrillic + Greek entries. v1.35 adds 6
    // Armenian entries (OH U+0555 / U+0585 -> O / o; TIWN U+054F -> S; VO
    // U+0578 + RA U+057C -> n; HO U+0570 -> h) = 50. Still well below the
    // design's 70-90 estimate. Pinning the exact count is a drift sentinel --
    // additions must be justified per-entry by the rationale convention in
    // HOMOGLYPH_MAP docstring + NO_CONFUSER_LETTERS exception list.
    expect(HOMOGLYPH_MAP.size).toBe(50);
  });

  test("all HOMOGLYPH_MAP values are 1-char ASCII letters (charCode 65-90 or 97-122)", () => {
    for (const value of HOMOGLYPH_MAP.values()) {
      expect(value.length).toBe(1);
      const code = value.charCodeAt(0);
      const isUpper = code >= 65 && code <= 90;
      const isLower = code >= 97 && code <= 122;
      expect(isUpper || isLower).toBe(true);
    }
  });

  test("applyHomoglyphPipeline is a function", () => {
    expect(typeof applyHomoglyphPipeline).toBe("function");
  });

  test("NO_CONFUSER_LETTERS has expected size (7 upper + 9 lower = 16)", () => {
    // v1.35: `h` + `n` dropped from the lowercase exception set -- Armenian
    // now supplies their confusers (HO U+0570 -> h; VO U+0578 + RA U+057C -> n).
    expect(NO_CONFUSER_LETTERS.size).toBe(16);
  });
});

// ============================================================================
// B. ASCII fast-path early-exit
// ============================================================================

describe("v1.30 Phase 1 -- ASCII fast-path (Hook #5 + #7)", () => {
  // v1.32 Phase 1 -- ASCII fast-path returns `{normalized: input}` with
  // homoglyphSource ABSENT (PRESENCE-as-signal: no transformable chars).
  test("pure ASCII formula returns input identical (no transformation)", () => {
    const input = '=IMPORTRANGE("https://x", "A1")';
    expect(applyHomoglyphPipeline(input)).toEqual({ normalized: input });
  });

  test("pure ASCII non-formula returns input identical", () => {
    expect(applyHomoglyphPipeline("=SUM(A1:B2)")).toEqual({
      normalized: "=SUM(A1:B2)",
    });
    expect(applyHomoglyphPipeline("hello world")).toEqual({
      normalized: "hello world",
    });
    expect(applyHomoglyphPipeline("123.45")).toEqual({ normalized: "123.45" });
  });

  test("empty string returns empty (fast-path)", () => {
    expect(applyHomoglyphPipeline("")).toEqual({ normalized: "" });
  });

  test("printable ASCII boundary (0x20 space + 0x7E tilde) preserved", () => {
    // 0x20 SPACE and 0x7E TILDE are inclusive endpoints of the fast-path
    // character class. Verify no false-positive on edge codepoints.
    expect(applyHomoglyphPipeline(" ")).toEqual({ normalized: " " });
    expect(applyHomoglyphPipeline("~")).toEqual({ normalized: "~" });
    expect(applyHomoglyphPipeline(" ~ ")).toEqual({ normalized: " ~ " });
  });

  test("v1.32 Phase 1 -- ASCII fast-path returns NO homoglyphSource field (PRESENCE-as-signal)", () => {
    // Sentinel: pure ASCII MUST yield homoglyphSource ABSENT. PRESENCE-
    // as-signal mirror v1.24 errorCode / v1.27 MetaMap patterns. Field
    // absence on the PASS path is the structural defense -- handlers
    // never see the field on legitimate writes.
    const result = applyHomoglyphPipeline("=IMPORTRANGE");
    expect(result.normalized).toBe("=IMPORTRANGE");
    expect(result.homoglyphSource).toBeUndefined();
    expect(Object.keys(result)).toEqual(["normalized"]);
  });
});

// ============================================================================
// C. STEP A Default_Ignorable STRIP
// ============================================================================

describe("v1.30 Phase 1 -- STEP A Default_Ignorable STRIP (Hook #8)", () => {
  test("U+00AD SOFT HYPHEN stripped (also in v1.25 P4 scope; redundant; harmless)", () => {
    const input = `x${SHY}y`;
    expect(input.replace(DEFAULT_IGNORABLE_RE, "")).toBe("xy");
  });

  test("U+034F COMBINING GRAPHEME JOINER stripped", () => {
    expect(`x${CGJ}y`.replace(DEFAULT_IGNORABLE_RE, "")).toBe("xy");
  });

  test("U+061C ARABIC LETTER MARK stripped", () => {
    expect(`x${ALM}y`.replace(DEFAULT_IGNORABLE_RE, "")).toBe("xy");
  });

  test("U+180B MONGOLIAN FREE VARIATION SELECTOR ONE stripped (Class 2 canonical bypass)", () => {
    // Concrete bypass example from design section 2.2:
    // `=I[U+180B]MPORTRANGE(...)` -- NFKC preserves; v1.25 P4 strip MISSES.
    const input = `=I${MONGOLIAN_VS1}MPORTRANGE("x","y")`;
    expect(input.replace(DEFAULT_IGNORABLE_RE, "")).toBe(
      '=IMPORTRANGE("x","y")',
    );
  });

  test("U+200B-U+200F (ZWSP / ZWNJ / ZWJ / LRM / RLM) all stripped", () => {
    expect(`a${ZWSP}b${ZWNJ}c${ZWJ}d${LRM}e${RLM}f`.replace(
      DEFAULT_IGNORABLE_RE,
      "",
    )).toBe("abcdef");
  });

  test("U+2060 WORD JOINER + U+3164 HANGUL FILLER stripped", () => {
    expect(`x${WJ}${HANGUL_FILLER}y`.replace(DEFAULT_IGNORABLE_RE, "")).toBe(
      "xy",
    );
  });

  test("U+FE00 VARIATION SELECTOR-1 stripped", () => {
    expect(`x${VS1}y`.replace(DEFAULT_IGNORABLE_RE, "")).toBe("xy");
  });

  test("U+FEFF BOM stripped (also in v1.25 P4 scope; redundant; harmless)", () => {
    expect(`x${BOM}y`.replace(DEFAULT_IGNORABLE_RE, "")).toBe("xy");
  });

  test("supplementary plane U+E0041 TAG LATIN CAPITAL LETTER A stripped", () => {
    // Supplementary-plane Default_Ignorable codepoints (TAG block at
    // U+E0000-U+E007F can carry hidden ASCII inside grapheme clusters).
    expect(`x${TAG_LATIN_A}y`.replace(DEFAULT_IGNORABLE_RE, "")).toBe("xy");
  });

  test("regex does NOT match plain ASCII (no false positive)", () => {
    expect("IMPORTRANGE".replace(DEFAULT_IGNORABLE_RE, "")).toBe(
      "IMPORTRANGE",
    );
    expect("=SUM(A1)".replace(DEFAULT_IGNORABLE_RE, "")).toBe("=SUM(A1)");
  });
});

// ============================================================================
// D. STEP B Bidi override STRIP
// ============================================================================

describe("v1.30 Phase 1 -- STEP B Bidi override STRIP (Hook #9)", () => {
  test("U+202E RIGHT-TO-LEFT OVERRIDE stripped", () => {
    expect(`x${RLO}y`.replace(BIDI_OVERRIDE_RE, "")).toBe("xy");
  });

  test("all 9 bidi codepoints (LRE / RLE / PDF / LRO / RLO / LRI / RLI / FSI / PDI) stripped", () => {
    const all = `${LRE}${RLE}${PDF}${LRO}${RLO}${LRI}${RLI}${FSI}${PDI}`;
    expect(`x${all}y`.replace(BIDI_OVERRIDE_RE, "")).toBe("xy");
  });

  test("STEP A + STEP B overlap is safe (double-strip yields same result; no artifact)", () => {
    // U+202E is in BOTH DEFAULT_IGNORABLE_RE and BIDI_OVERRIDE_RE.
    // Running both regexes sequentially must yield the same result as
    // running either alone.
    const input = `=${RLO}IMPORT`;
    const onlyStepA = input.replace(DEFAULT_IGNORABLE_RE, "");
    const onlyStepB = input.replace(BIDI_OVERRIDE_RE, "");
    const both = input
      .replace(DEFAULT_IGNORABLE_RE, "")
      .replace(BIDI_OVERRIDE_RE, "");
    expect(onlyStepA).toBe("=IMPORT");
    expect(onlyStepB).toBe("=IMPORT");
    expect(both).toBe("=IMPORT");
  });

  test("regex does NOT match plain ASCII (no false positive)", () => {
    expect("IMPORTRANGE".replace(BIDI_OVERRIDE_RE, "")).toBe("IMPORTRANGE");
  });
});

// ============================================================================
// E. STEP C homoglyph NORMALIZE (Cyrillic + Greek, BOTH cases per Phase 0a M2)
// ============================================================================

describe("v1.30 Phase 1 -- STEP C Cyrillic UPPERCASE -> ASCII UPPER", () => {
  test("Cyrillic U+0406 (BYELORUSSIAN-UKRAINIAN I) -> ASCII I (canonical 4-cycle gap)", () => {
    expect(HOMOGLYPH_MAP.get(CYRILLIC_I_UPPER)).toBe("I");
  });

  test("Cyrillic U+0410 (A) -> ASCII A", () => {
    expect(HOMOGLYPH_MAP.get(CYRILLIC_A_UPPER)).toBe("A");
  });

  test("Cyrillic U+041C (EM) -> ASCII M", () => {
    expect(HOMOGLYPH_MAP.get(CYRILLIC_M_UPPER)).toBe("M");
  });

  test("Cyrillic U+0420 (ER) -> ASCII P", () => {
    expect(HOMOGLYPH_MAP.get(CYRILLIC_P_UPPER)).toBe("P");
  });

  test("Cyrillic U+0422 (TE) -> ASCII T", () => {
    expect(HOMOGLYPH_MAP.get(CYRILLIC_T_UPPER)).toBe("T");
  });

  test("Cyrillic U+0425 (HA) -> ASCII X", () => {
    expect(HOMOGLYPH_MAP.get(CYRILLIC_X_UPPER)).toBe("X");
  });
});

describe("v1.30 Phase 1 -- STEP C Cyrillic LOWERCASE -> ASCII LOWER (Phase 0a M2)", () => {
  test("Cyrillic U+0456 (BYELORUSSIAN-UKRAINIAN I LOWER) -> ASCII i (Phase 0a M2 canonical)", () => {
    expect(HOMOGLYPH_MAP.get(CYRILLIC_I_LOWER)).toBe("i");
  });

  test("Cyrillic U+0430 (a) -> ASCII a", () => {
    expect(HOMOGLYPH_MAP.get(CYRILLIC_A_LOWER)).toBe("a");
  });
});

describe("v1.30 Phase 1 -- STEP C Greek UPPERCASE -> ASCII UPPER", () => {
  test("Greek U+0391 (ALPHA) -> ASCII A", () => {
    expect(HOMOGLYPH_MAP.get(GREEK_ALPHA_UPPER)).toBe("A");
  });

  test("Greek U+0399 (IOTA) -> ASCII I", () => {
    expect(HOMOGLYPH_MAP.get(GREEK_IOTA_UPPER)).toBe("I");
  });

  test("Greek U+03A1 (RHO) -> ASCII P", () => {
    expect(HOMOGLYPH_MAP.get(GREEK_RHO_UPPER)).toBe("P");
  });
});

describe("v1.30 Phase 1 -- STEP C Greek LOWERCASE -> ASCII LOWER (Phase 0a M2)", () => {
  test("Greek U+03B9 (iota) -> ASCII i", () => {
    expect(HOMOGLYPH_MAP.get(GREEK_IOTA_LOWER)).toBe("i");
  });

  test("Greek U+03BF (omicron) -> ASCII o", () => {
    expect(HOMOGLYPH_MAP.get(GREEK_OMICRON_LOWER)).toBe("o");
  });
});

describe("v1.35 -- STEP C Armenian -> ASCII (UTS #39 confusables.txt v17.0.0)", () => {
  test("Armenian U+0555 (CAPITAL OH) -> ASCII O", () => {
    expect(HOMOGLYPH_MAP.get(ARMENIAN_OH_UPPER)).toBe("O");
  });

  test("Armenian U+054F (CAPITAL TIWN) -> ASCII S", () => {
    expect(HOMOGLYPH_MAP.get(ARMENIAN_TIWN_UPPER)).toBe("S");
  });

  test("Armenian U+0585 (SMALL OH) -> ASCII o", () => {
    expect(HOMOGLYPH_MAP.get(ARMENIAN_OH_LOWER)).toBe("o");
  });

  test("Armenian U+0578 (SMALL VO) -> ASCII n (closes n zero-coverage gap)", () => {
    expect(HOMOGLYPH_MAP.get(ARMENIAN_VO_LOWER)).toBe("n");
  });

  test("Armenian U+057C (SMALL RA) -> ASCII n (second n confuser)", () => {
    expect(HOMOGLYPH_MAP.get(ARMENIAN_RA_LOWER)).toBe("n");
  });

  test("Armenian U+0570 (SMALL HO) -> ASCII h (closes h zero-coverage gap)", () => {
    expect(HOMOGLYPH_MAP.get(ARMENIAN_HO_LOWER)).toBe("h");
  });

  test("Armenian-laced IMPORTRANGE normalizes via applyHomoglyphPipeline (O-fold)", () => {
    // =IMP{Armenian OH}RTRANGE -> =IMPORTRANGE; the Armenian OH folds to O so
    // formula-reject STEP 0b sees IMPORTRANGE in REJECTED_FUNCTIONS.
    const input = `=IMP${ARMENIAN_OH_UPPER}RTRANGE`;
    expect(applyHomoglyphPipeline(input)).toEqual({
      normalized: "=IMPORTRANGE",
      homoglyphSource: ARMENIAN_OH_UPPER,
    });
  });

  test("Armenian VO folds to n inside a lowercase identifier (gap-letter coverage)", () => {
    const input = `importra${ARMENIAN_VO_LOWER}ge`;
    expect(applyHomoglyphPipeline(input)).toEqual({
      normalized: "importrange",
      homoglyphSource: ARMENIAN_VO_LOWER,
    });
  });

  test("Armenian HO folds to h (gap-letter coverage; HYPERLINK-class)", () => {
    const input = `${ARMENIAN_HO_LOWER}yperlink`;
    expect(applyHomoglyphPipeline(input)).toEqual({
      normalized: "hyperlink",
      homoglyphSource: ARMENIAN_HO_LOWER,
    });
  });

  test("composition: Armenian fold + zero-width splice + bidi strip compose in one pass", () => {
    // Armenian OH-fold AND a spliced ZWSP AND a trailing bidi RLO. STEP A/B
    // strip the invisibles, STEP C folds the Armenian -- all in the single
    // pass. Proves v1.35 composes with the v1.25 / v1.30 invisible-char
    // defenses. homoglyphSource captures all three in INPUT byte order.
    const input = `=IMP${ARMENIAN_OH_UPPER}RT${ZWSP}RANGE${RLO}`;
    const result = applyHomoglyphPipeline(input);
    expect(result.normalized).toBe("=IMPORTRANGE");
    expect(result.homoglyphSource).toBe(`${ARMENIAN_OH_UPPER}${ZWSP}${RLO}`);
  });
});

describe("v1.30 Phase 1 -- STEP C multi-char roundtrip via applyHomoglyphPipeline", () => {
  // v1.32 Phase 1 -- non-ASCII inputs return `{normalized, homoglyphSource}`
  // where homoglyphSource captures ORIGINAL transformed chars in INPUT byte
  // order (Q2 LOCK Option B). Existing assertions check `.normalized`;
  // new assertions verify `.homoglyphSource` PRESENCE + content.
  test("Cyrillic I + ASCII MPORTRANGE -> ASCII IMPORTRANGE (single substitution)", () => {
    const input = `${CYRILLIC_I_UPPER}MPORTRANGE`;
    expect(applyHomoglyphPipeline(input)).toEqual({
      normalized: "IMPORTRANGE",
      homoglyphSource: CYRILLIC_I_UPPER,
    });
  });

  test("all-Cyrillic IMPORT (using available Cyrillic confusables) normalizes (partial coverage where confusers exist)", () => {
    // I-M-P-O-R-T : Cyrillic confusers exist for I (U+0406), M (U+041C),
    // P (U+0420), O (U+041E), T (U+0422). No Cyrillic confuser for R
    // (documented in NO_CONFUSER_LETTERS). Result: 5 chars normalize,
    // 1 char passes through (the Cyrillic R-equivalent... there isn't
    // one in our map, so input must use ASCII R). Use ASCII R inline.
    // v1.32 Phase 1 -- homoglyphSource captures the 5 normalized Cyrillic
    // chars in INPUT byte order (Q2 LOCK Option B); ASCII R passes through
    // and is NOT captured.
    const input = `${CYRILLIC_I_UPPER}${CYRILLIC_M_UPPER}${CYRILLIC_P_UPPER}${CYRILLIC_O_UPPER}R${CYRILLIC_T_UPPER}`;
    expect(applyHomoglyphPipeline(input)).toEqual({
      normalized: "IMPORT",
      homoglyphSource: `${CYRILLIC_I_UPPER}${CYRILLIC_M_UPPER}${CYRILLIC_P_UPPER}${CYRILLIC_O_UPPER}${CYRILLIC_T_UPPER}`,
    });
  });

  test("Phase 0a M2 mixed-case: =Cyrillic-I-upper + lowercase ASCII tail -> =I + lowercase tail", () => {
    // Phase 0a M2 forcing function: mixed-case bypass of `.toUpperCase()` step.
    const input = `=${CYRILLIC_I_UPPER}mportrange("...")`;
    expect(applyHomoglyphPipeline(input)).toEqual({
      normalized: '=Importrange("...")',
      homoglyphSource: CYRILLIC_I_UPPER,
    });
  });

  test("Phase 0a M2 all-lowercase: Cyrillic-i-lower + lowercase ASCII -> all ASCII lower", () => {
    const input = `=${CYRILLIC_I_LOWER}mportrange("...")`;
    expect(applyHomoglyphPipeline(input)).toEqual({
      normalized: '=importrange("...")',
      homoglyphSource: CYRILLIC_I_LOWER,
    });
  });
});

// ============================================================================
// F. Pipeline integration (STRIP + NORMALIZE composition; ORDER pinning)
// ============================================================================

describe("v1.30 Phase 1 -- pipeline composition (STRIP + NORMALIZE)", () => {
  test("combined Cyrillic homoglyph + ZWSP splice: =[U+0406][U+200B]MPORTRANGE -> =IMPORTRANGE", () => {
    // v1.32 Phase 1 -- mixed STRIP + NORMALIZE captures both original chars
    // (ZWSP and Cyrillic I) in input byte order: ZWSP appears at position 2
    // in input, after Cyrillic I at position 1. Per Q2 LOCK Option B.
    const input = `=${CYRILLIC_I_UPPER}${ZWSP}MPORTRANGE("x","y")`;
    expect(applyHomoglyphPipeline(input)).toEqual({
      normalized: '=IMPORTRANGE("x","y")',
      homoglyphSource: `${CYRILLIC_I_UPPER}${ZWSP}`,
    });
  });

  test("bidi RLO + Cyrillic homoglyph: [U+202E][U+0406]MPORTRANGE -> IMPORTRANGE", () => {
    // v1.32 Phase 1 -- RLO (STRIP) appears before Cyrillic I (NORMALIZE)
    // in input; homoglyphSource captures both in that order.
    const input = `${RLO}${CYRILLIC_I_UPPER}MPORTRANGE`;
    expect(applyHomoglyphPipeline(input)).toEqual({
      normalized: "IMPORTRANGE",
      homoglyphSource: `${RLO}${CYRILLIC_I_UPPER}`,
    });
  });

  test("Mongolian VS-1 + Greek I-upper splice: I[U+180B][U+0399]MPORT -> IIMPORT", () => {
    // STEP A strips U+180B; STEP C maps Greek U+0399 -> ASCII I.
    // v1.32 Phase 1 -- homoglyphSource captures both VS-1 and Greek I
    // in input byte order (VS-1 first, Greek I second).
    const input = `I${MONGOLIAN_VS1}${GREEK_IOTA_UPPER}MPORT`;
    expect(applyHomoglyphPipeline(input)).toEqual({
      normalized: "IIMPORT",
      homoglyphSource: `${MONGOLIAN_VS1}${GREEK_IOTA_UPPER}`,
    });
  });

  test("pipeline ORDER: STEP A (strip) MUST happen BEFORE STEP C (map)", () => {
    // If STEP C ran first, the per-char Map iteration would see Cyrillic-I
    // as-is and map it -- but the intervening ZWSP between two chars would
    // NOT be removed, causing identifier fragmentation downstream.
    // Verify order by interleaving: [U+0406][ZWSP][U+0406] -> "II"
    // (both Cyrillic-I map to ASCII I; ZWSP between them strips).
    // v1.32 Phase 1 -- homoglyphSource captures all three transformed chars
    // in input byte order: Cyrillic I + ZWSP + Cyrillic I.
    const input = `${CYRILLIC_I_UPPER}${ZWSP}${CYRILLIC_I_UPPER}`;
    expect(applyHomoglyphPipeline(input)).toEqual({
      normalized: "II",
      homoglyphSource: `${CYRILLIC_I_UPPER}${ZWSP}${CYRILLIC_I_UPPER}`,
    });
  });

  test("non-mapped characters pass through (no false-positive on unrecognized Unicode)", () => {
    // Cyrillic U+0414 (DE) is NOT in our map (D has no high-confidence
    // confuser per NO_CONFUSER_LETTERS). Verify it passes through unchanged.
    // v1.32 Phase 1 -- non-ASCII input WITHOUT any transformable chars
    // yields homoglyphSource ABSENT (defensive PRESENCE-as-signal coverage).
    const input = String.fromCharCode(0x0414) + "MPORT";
    expect(applyHomoglyphPipeline(input)).toEqual({ normalized: input });
  });

  test("v1.32 Phase 1 -- non-ASCII without transform yields no homoglyphSource (PRESENCE-as-signal defensive)", () => {
    // Edge case: input is non-ASCII (so fast-path skipped) but contains
    // ZERO chars in the transform scope. Output passes through unchanged
    // AND homoglyphSource is ABSENT. Verifies the empty-buffer ABSENT
    // branch of the PRESENCE-as-signal contract.
    const input = String.fromCharCode(0x0414); // Cyrillic D (no confuser)
    const result = applyHomoglyphPipeline(input);
    expect(result.normalized).toBe(input);
    expect(result.homoglyphSource).toBeUndefined();
    expect(Object.keys(result)).toEqual(["normalized"]);
  });
});

// ============================================================================
// F2. v1.32 Phase 1 -- forensic capture sentinels (PRESENCE-as-signal)
// ============================================================================

describe("v1.32 Phase 1 -- forensic capture (Q2 LOCK Option B all-transformed-chars)", () => {
  // Pin the PRESENCE-as-signal contract + input-byte-order semantics for
  // the new `homoglyphSource` field. Belt-and-suspenders sentinels covering
  // STRIP-only / NORMALIZE-only / mixed cases at the documented Phase 1
  // contract layer (validateCellValue layer; Phase 2 wires audit + MCPError).

  test("STRIP-only attack (ZWSP splice): homoglyphSource = original ZWSP byte", () => {
    const input = `=IMP${ZWSP}ORT`;
    expect(applyHomoglyphPipeline(input)).toEqual({
      normalized: "=IMPORT",
      homoglyphSource: ZWSP,
    });
  });

  test("STRIP-only attack (bidi RLO): homoglyphSource = RLO byte", () => {
    const input = `=${RLO}IMPORT`;
    expect(applyHomoglyphPipeline(input)).toEqual({
      normalized: "=IMPORT",
      homoglyphSource: RLO,
    });
  });

  test("NORMALIZE-only attack (single Cyrillic): homoglyphSource = Cyrillic byte", () => {
    const input = `${CYRILLIC_I_UPPER}MPORT`;
    expect(applyHomoglyphPipeline(input)).toEqual({
      normalized: "IMPORT",
      homoglyphSource: CYRILLIC_I_UPPER,
    });
  });

  test("MIXED STRIP + NORMALIZE: homoglyphSource preserves input byte order (Q2 LOCK)", () => {
    // ZWSP at position 0, Cyrillic I at position 1 -- captured in that order.
    // Reversing or sorting would violate Q2 LOCK Option B.
    const input = `${ZWSP}${CYRILLIC_I_UPPER}MPORT`;
    expect(applyHomoglyphPipeline(input)).toEqual({
      normalized: "IMPORT",
      homoglyphSource: `${ZWSP}${CYRILLIC_I_UPPER}`,
    });
  });

  test("MULTIPLE Cyrillic homoglyphs: homoglyphSource captures ALL in input order", () => {
    // 2 Cyrillic A at positions 0 + 1, both NORMALIZE -> "AA".
    const input = `${CYRILLIC_A_UPPER}${CYRILLIC_A_UPPER}MPORT`;
    expect(applyHomoglyphPipeline(input)).toEqual({
      normalized: "AAMPORT",
      homoglyphSource: `${CYRILLIC_A_UPPER}${CYRILLIC_A_UPPER}`,
    });
  });
});

// ============================================================================
// G. Source-byte purity sentinel (Hook #14)
// ============================================================================

describe("v1.30 Phase 1 -- source-byte purity sentinel (Hook #14)", () => {
  // Mirrors v1.25 Phase 4 + v1.21 P2 + v1.26 NEW-8 source-byte purity
  // convention. Reads the implementation file as RAW BYTES via Buffer
  // (not utf-8 string includes) so even malformed UTF-8 sequences would
  // be caught -- defense-in-depth.
  //
  // The file MUST contain ZERO literal:
  //   - Cyrillic codepoints (U+0400-U+04FF)
  //   - Greek codepoints (U+0370-U+03FF)
  //   - Default_Ignorable codepoints in the v1.30 Phase 1 scope
  //
  // All such codepoints in the source MUST be written via `\uXXXX` JS
  // string escape sequences or `String.fromCharCode(0xXXXX)` so the
  // source file bytes remain ASCII-only for those Unicode blocks.
  // Paste-artifact defense + grep-friendly.

  const sourcePath = path.join(__dirname, "homoglyph-normalize.ts");

  test("source file contains ZERO literal Cyrillic codepoints (U+0400-U+04FF)", () => {
    const buf = fs.readFileSync(sourcePath);
    // UTF-8 encoding of U+0400-U+04FF: 2-byte sequences starting with
    // 0xD0 or 0xD1 (lead bytes). Scan for any 2-byte sequence in the
    // Cyrillic range.
    for (let i = 0; i < buf.length - 1; i++) {
      const b0 = buf[i]!;
      const b1 = buf[i + 1]!;
      // 0xD0 0x80-0xBF = U+0400-U+043F
      // 0xD1 0x80-0xBF = U+0440-U+047F
      // 0xD2 0x80-0x9F = U+0480-U+04AF
      if (
        (b0 === 0xd0 && b1 >= 0x80 && b1 <= 0xbf) ||
        (b0 === 0xd1 && b1 >= 0x80 && b1 <= 0xbf) ||
        (b0 === 0xd2 && b1 >= 0x80 && b1 <= 0x9f)
      ) {
        // Find line number for better error reporting.
        const line = buf.subarray(0, i).filter((b) => b === 0x0a).length + 1;
        const cp =
          b0 === 0xd0
            ? 0x0400 + (b1 - 0x80)
            : b0 === 0xd1
              ? 0x0440 + (b1 - 0x80)
              : 0x0480 + (b1 - 0x80);
        throw new Error(
          `Literal Cyrillic codepoint U+${cp.toString(16).toUpperCase().padStart(4, "0")} found at byte ${i} (line ${line})`,
        );
      }
    }
  });

  test("source file contains ZERO literal Greek codepoints (U+0370-U+03FF)", () => {
    const buf = fs.readFileSync(sourcePath);
    // UTF-8 encoding of U+0370-U+03FF: 2-byte sequences:
    // 0xCD 0xB0-0xBF = U+0370-U+037F
    // 0xCE 0x80-0xBF = U+0380-U+03BF
    // 0xCF 0x80-0xBF = U+03C0-U+03FF
    for (let i = 0; i < buf.length - 1; i++) {
      const b0 = buf[i]!;
      const b1 = buf[i + 1]!;
      if (
        (b0 === 0xcd && b1 >= 0xb0 && b1 <= 0xbf) ||
        (b0 === 0xce && b1 >= 0x80 && b1 <= 0xbf) ||
        (b0 === 0xcf && b1 >= 0x80 && b1 <= 0xbf)
      ) {
        const line = buf.subarray(0, i).filter((b) => b === 0x0a).length + 1;
        const cp =
          b0 === 0xcd
            ? 0x0370 + (b1 - 0xb0)
            : b0 === 0xce
              ? 0x0380 + (b1 - 0x80)
              : 0x03c0 + (b1 - 0x80);
        throw new Error(
          `Literal Greek codepoint U+${cp.toString(16).toUpperCase().padStart(4, "0")} found at byte ${i} (line ${line})`,
        );
      }
    }
  });

  test("source file contains ZERO literal Armenian codepoints (U+0530-U+058F) [v1.35]", () => {
    const buf = fs.readFileSync(sourcePath);
    // UTF-8 encoding of the Armenian block U+0530-U+058F (2-byte sequences):
    //   0xD4 0xB0-0xBF = U+0530-U+053F
    //   0xD5 0x80-0xBF = U+0540-U+057F
    //   0xD6 0x80-0x8F = U+0580-U+058F
    for (let i = 0; i < buf.length - 1; i++) {
      const b0 = buf[i]!;
      const b1 = buf[i + 1]!;
      if (
        (b0 === 0xd4 && b1 >= 0xb0 && b1 <= 0xbf) ||
        (b0 === 0xd5 && b1 >= 0x80 && b1 <= 0xbf) ||
        (b0 === 0xd6 && b1 >= 0x80 && b1 <= 0x8f)
      ) {
        const line = buf.subarray(0, i).filter((b) => b === 0x0a).length + 1;
        const cp =
          b0 === 0xd4
            ? 0x0530 + (b1 - 0xb0)
            : b0 === 0xd5
              ? 0x0540 + (b1 - 0x80)
              : 0x0580 + (b1 - 0x80);
        throw new Error(
          `Literal Armenian codepoint U+${cp.toString(16).toUpperCase().padStart(4, "0")} found at byte ${i} (line ${line})`,
        );
      }
    }
  });

  test("source file contains ZERO literal Default_Ignorable codepoints (v1.30 Phase 1 scope)", () => {
    // String-level check (decoded as utf-8) for the Default_Ignorable set.
    // Reuses the v1.25 Phase 4 + v1.26 NEW-8 byte-indexOf pattern for a
    // subset of the most commonly-pasted invisible codepoints, plus an
    // explicit char-by-char scan for the broader v1.30 Phase 1 scope.
    const buf = fs.readFileSync(sourcePath);
    // v1.25 Phase 4 5 codepoints (UTF-8 byte sequences):
    expect(buf.indexOf(Buffer.from([0xc2, 0xad]))).toBe(-1); // U+00AD
    expect(buf.indexOf(Buffer.from([0xe2, 0x80, 0x8b]))).toBe(-1); // U+200B
    expect(buf.indexOf(Buffer.from([0xe2, 0x80, 0x8c]))).toBe(-1); // U+200C
    expect(buf.indexOf(Buffer.from([0xe2, 0x80, 0x8d]))).toBe(-1); // U+200D
    expect(buf.indexOf(Buffer.from([0xef, 0xbb, 0xbf]))).toBe(-1); // U+FEFF

    // v1.30 Phase 1 NEW Default_Ignorable codepoints:
    expect(buf.indexOf(Buffer.from([0xcd, 0x8f]))).toBe(-1); // U+034F CGJ
    expect(buf.indexOf(Buffer.from([0xd8, 0x9c]))).toBe(-1); // U+061C ALM
    expect(buf.indexOf(Buffer.from([0xe1, 0xa0, 0x8b]))).toBe(-1); // U+180B
    expect(buf.indexOf(Buffer.from([0xe1, 0xa0, 0x8e]))).toBe(-1); // U+180E
    expect(buf.indexOf(Buffer.from([0xe2, 0x80, 0x8e]))).toBe(-1); // U+200E LRM
    expect(buf.indexOf(Buffer.from([0xe2, 0x80, 0x8f]))).toBe(-1); // U+200F RLM
    expect(buf.indexOf(Buffer.from([0xe2, 0x80, 0xaa]))).toBe(-1); // U+202A LRE
    expect(buf.indexOf(Buffer.from([0xe2, 0x80, 0xae]))).toBe(-1); // U+202E RLO
    expect(buf.indexOf(Buffer.from([0xe2, 0x81, 0xa6]))).toBe(-1); // U+2066 LRI
    expect(buf.indexOf(Buffer.from([0xe2, 0x81, 0xa9]))).toBe(-1); // U+2069 PDI
    expect(buf.indexOf(Buffer.from([0xe3, 0x85, 0xa4]))).toBe(-1); // U+3164
    expect(buf.indexOf(Buffer.from([0xef, 0xbe, 0xa0]))).toBe(-1); // U+FFA0
  });
});

// ============================================================================
// H. Alphabet coverage meta-test (Risk 4 forcing function)
// ============================================================================

describe("v1.30 Phase 1 -- alphabet coverage meta-test (Risk 4)", () => {
  // The 22 ASCII letters that appear in the 11-function REJECT-list names.
  // Phase 0a M2: BOTH cases required because FORMULA_PREFIX_RE extracts
  // BEFORE `.toUpperCase()`. 22 upper + 22 lower = 44 ASCII chars in scope.
  const REJECT_SET_LETTERS_UPPER = "ABCDEFGHIKLMNOPRSTVWXY".split("");
  const REJECT_SET_LETTERS_LOWER = REJECT_SET_LETTERS_UPPER.map((c) =>
    c.toLowerCase(),
  );

  test("REJECT-set letter list has exactly 22 unique uppercase letters (drift sentinel)", () => {
    // If a 12th REJECT function adds a new letter, this test fails and
    // forces re-audit of NO_CONFUSER_LETTERS + HOMOGLYPH_MAP per the
    // Risk 4 forcing function convention.
    expect(REJECT_SET_LETTERS_UPPER.length).toBe(22);
    expect(new Set(REJECT_SET_LETTERS_UPPER).size).toBe(22);
  });

  test("every UPPERCASE REJECT-set letter has either >= 1 HOMOGLYPH_MAP entry OR is in NO_CONFUSER_LETTERS", () => {
    // For each ASCII letter in scope, count how many HOMOGLYPH_MAP entries
    // target it. If zero, the letter MUST be in NO_CONFUSER_LETTERS
    // (documented exception). Otherwise the meta-test fails.
    for (const letter of REJECT_SET_LETTERS_UPPER) {
      const mapCount = [...HOMOGLYPH_MAP.values()].filter(
        (v) => v === letter,
      ).length;
      const isException = NO_CONFUSER_LETTERS.has(letter);
      if (mapCount === 0 && !isException) {
        throw new Error(
          `Coverage gap: ASCII letter '${letter}' has NO HOMOGLYPH_MAP entry AND is NOT in NO_CONFUSER_LETTERS. ` +
            `Either add a Cyrillic / Greek mapping OR add '${letter}' to NO_CONFUSER_LETTERS with rationale.`,
        );
      }
      expect(mapCount > 0 || isException).toBe(true);
    }
  });

  test("every LOWERCASE REJECT-set letter has either >= 1 HOMOGLYPH_MAP entry OR is in NO_CONFUSER_LETTERS (Phase 0a M2 forcing function)", () => {
    for (const letter of REJECT_SET_LETTERS_LOWER) {
      const mapCount = [...HOMOGLYPH_MAP.values()].filter(
        (v) => v === letter,
      ).length;
      const isException = NO_CONFUSER_LETTERS.has(letter);
      if (mapCount === 0 && !isException) {
        throw new Error(
          `Coverage gap (Phase 0a M2): ASCII lowercase '${letter}' has NO HOMOGLYPH_MAP entry AND is NOT in NO_CONFUSER_LETTERS. ` +
            `Either add a Cyrillic / Greek mapping OR add '${letter}' to NO_CONFUSER_LETTERS with rationale.`,
        );
      }
      expect(mapCount > 0 || isException).toBe(true);
    }
  });

  test("NO_CONFUSER_LETTERS contains only letters from the 22-letter scope", () => {
    // Defense: if NO_CONFUSER_LETTERS drifts to include letters outside the
    // REJECT-set scope (e.g., J / Q / Z), the meta-test loses its forcing
    // power. Pin the contract.
    const inScope = new Set([
      ...REJECT_SET_LETTERS_UPPER,
      ...REJECT_SET_LETTERS_LOWER,
    ]);
    for (const exception of NO_CONFUSER_LETTERS) {
      expect(inScope.has(exception)).toBe(true);
    }
  });
});

// ============================================================================
// I. Performance baseline (Risk 2 <=5% regression budget)
// ============================================================================

describe("v1.30 Phase 1 -- performance baseline (Risk 2)", () => {
  // Phase 1 records a BASELINE measurement (no formula-reject integration
  // yet). Phase 2 verifies <=5% regression delta under the integrated
  // pipeline. The benchmark targets are loose (any modern machine completes
  // 10k iterations under 500ms) -- the goal is to fail loudly on a
  // catastrophic regression (e.g., 100x slowdown from a regex backtracking
  // bug), not to enforce wall-clock latency.

  test("ASCII fast-path 10000 iterations under 2000ms (catastrophic regression guard)", () => {
    // Budget intentionally loose (~5000x typical) to defend against parallel-
    // load CI flake while still catching a catastrophic regex-backtracking
    // regression (which would balloon by 100-1000x). Phase 2 integration
    // will record a tighter baseline against the integrated pipeline.
    const input = '=IMPORTRANGE("https://x", "A1")';
    const start = performance.now();
    for (let i = 0; i < 10000; i++) {
      applyHomoglyphPipeline(input);
    }
    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(2000);
  });

  test("non-ASCII path 1000 iterations under 2000ms (catastrophic regression guard)", () => {
    // Non-ASCII input forces all 3 pipeline steps to run. 1000 iterations
    // is the work the Phase 2 integration would do for the most-hostile
    // benchmark cell. Budget loose for the same parallel-load reason above.
    const input = `=${CYRILLIC_I_UPPER}${ZWSP}MPORTRANGE("a","b")${RLO}`;
    const start = performance.now();
    for (let i = 0; i < 1000; i++) {
      applyHomoglyphPipeline(input);
    }
    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(2000);
  });
});
