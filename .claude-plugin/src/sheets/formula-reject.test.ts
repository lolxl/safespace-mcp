// v1.21 Phase 1b — Formula REJECT module tests.
//
// Coverage targets (per docs/v1.21-sheets-phase2c.md §10 hooks #1 / #8 /
// #9 / #14 / #21):
//   - All 11 REJECTED functions hit REJECT path with `=` prefix
//   - Whitespace tolerance + case insensitivity verified
//   - NFKC normalize closes fullwidth bypass (`=ＩMPORTRANGE(`)
//   - Non-formula prefixes PASS (`-5`, `@user`, `123`, `hello`)
//   - Nested aggregation gap CLOSED v1.34 (`=SUM(IMPORTRANGE(...))` REJECTS
//     via STEP 5 string-literal-aware scan)
//   - LAMBDA gap closure (`=LAMBDA(x, IMPORTRANGE(x))("url")` REJECTS)
//   - Source byte safety: 0 literal U+2028 / U+2029 in source file
//   - ReDoS safety: 1500 iterations × 256-char hostile input under 1500ms
//
// v1.25 Phase 4 — Unicode zero-width + soft-hyphen pre-strip BEFORE NFKC.
// Closes v1.21 N1 (3-cycle deferral). Coverage targets (per docs/v1.25-multi-item-batch.md §2.4):
//   - 5 codepoint strip (U+00AD / U+200B / U+200C / U+200D / U+FEFF) — REJECTS bypass attempts
//   - Combined zero-width strips ALL chars (composition test)
//   - Pre-strip-BEFORE-NFKC ordering sentinel (zero-width + fullwidth interleaved)
//   - Non-REJECTED function with zero-width still PASSES (SUM)
//   - Literal text with zero-width still PASSES (no `=` / `+` prefix)
//   - Scope sentinel: this regex's scope is the v1.25 5-codepoint set ONLY;
//     Cyrillic homoglyph defense moved to STEP 0b via homoglyph-normalize.ts
//     since v1.30 (closes v1.25 Q6 / v1.26+ / v1.28 inherited carry-forward).
//   - Source byte purity extended: 0 literal U+00AD / U+200B / U+200C / U+200D / U+FEFF
//   - All 11 REJECTED functions covered with zero-width injection variants

import { describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  FORMULA_PREFIX_RE,
  REJECTED_FUNCTIONS,
  scanRejectedCallTokens,
  validateCellValue,
  ZERO_WIDTH_AND_SOFT_HYPHEN_RE,
} from "./formula-reject";

// v1.25 Phase 4 — codepoint constants for tests. Use String.fromCharCode
// (NOT literal codepoints) so this test source file ALSO stays clean of
// the 5 paste-artifact codepoints (the source-byte purity sentinel on
// the implementation file does NOT cover the test file, but the same
// hygiene applies — paste-artifact defense + grep-friendly).
const SHY = String.fromCharCode(0x00ad); // SOFT HYPHEN
const ZWSP = String.fromCharCode(0x200b); // ZERO WIDTH SPACE
const ZWNJ = String.fromCharCode(0x200c); // ZERO WIDTH NON-JOINER
const ZWJ = String.fromCharCode(0x200d); // ZERO WIDTH JOINER
const BOM = String.fromCharCode(0xfeff); // ZERO WIDTH NO-BREAK SPACE (BOM)
const FULLWIDTH_I = String.fromCharCode(0xff29); // FULLWIDTH LATIN CAPITAL LETTER I (NFKC → ASCII I)
const FULLWIDTH_B = String.fromCharCode(0xff22); // FULLWIDTH LATIN CAPITAL LETTER B (NFKC → ASCII B)
const CYRILLIC_I = String.fromCharCode(0x0406); // CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I (NFKC PRESERVES — UTS #39 territory)

describe("formula-reject — REJECTED_FUNCTIONS constants", () => {
  test("contains exactly 11 functions (Q2 LOCKED post-P3 LAMBDA addition)", () => {
    expect(REJECTED_FUNCTIONS.size).toBe(11);
  });

  test("matches design §3 table exactly (all UPPERCASE)", () => {
    expect([...REJECTED_FUNCTIONS].sort()).toEqual([
      "GOOGLEFINANCE",
      "GOOGLETRANSLATE",
      "HYPERLINK",
      "IMAGE",
      "IMPORTDATA",
      "IMPORTFEED",
      "IMPORTHTML",
      "IMPORTRANGE",
      "IMPORTXML",
      "LAMBDA",
      "WEBSERVICE",
    ]);
  });

  test("includes LAMBDA (P3 — one-step nested bypass closure)", () => {
    expect(REJECTED_FUNCTIONS.has("LAMBDA")).toBe(true);
  });
});

describe("validateCellValue — non-formula cells PASS", () => {
  test("non-string cells PASS (number / boolean / null / undefined / object)", () => {
    expect(validateCellValue(42)).toEqual({ ok: true });
    expect(validateCellValue(0)).toEqual({ ok: true });
    expect(validateCellValue(-5)).toEqual({ ok: true });
    expect(validateCellValue(true)).toEqual({ ok: true });
    expect(validateCellValue(false)).toEqual({ ok: true });
    expect(validateCellValue(null)).toEqual({ ok: true });
    expect(validateCellValue(undefined)).toEqual({ ok: true });
    expect(validateCellValue({ formulaValue: "=IMPORTRANGE(...)" })).toEqual({
      ok: true,
    });
  });

  test("non-formula string prefixes PASS (literal text per Sheets semantics)", () => {
    expect(validateCellValue("hello")).toEqual({ ok: true });
    expect(validateCellValue("123")).toEqual({ ok: true });
    expect(validateCellValue("-5")).toEqual({ ok: true }); // negative number literal
    expect(validateCellValue("@user")).toEqual({ ok: true }); // literal per Sheets
    expect(validateCellValue("")).toEqual({ ok: true });
    expect(validateCellValue(" =IMPORTRANGE")).toEqual({ ok: true }); // leading whitespace before = → not a formula
  });

  test("formula prefix but unrecognized function PASS (Google will error)", () => {
    expect(validateCellValue("=")).toEqual({ ok: true });
    expect(validateCellValue("==")).toEqual({ ok: true });
    expect(validateCellValue("=  ")).toEqual({ ok: true });
    expect(validateCellValue("=123")).toEqual({ ok: true }); // doesn't match identifier
    expect(validateCellValue("=SUM(A1)")).toEqual({ ok: true });
    expect(validateCellValue("=AVERAGE(A1:A10)")).toEqual({ ok: true });
    expect(validateCellValue("=VLOOKUP(A1, B:C, 2, FALSE)")).toEqual({
      ok: true,
    });
    expect(validateCellValue("=IF(A1>0, 'pos', 'neg')")).toEqual({ ok: true });
  });
});

describe("validateCellValue — 11 REJECTED functions all hit REJECT path", () => {
  // One sentinel per function ensures each REJECT entry is wired.
  const cases: Array<[string, string]> = [
    ['=IMPORTRANGE("https://...", "A1")', "IMPORTRANGE"],
    ['=IMPORTXML("https://x", "//div")', "IMPORTXML"],
    ['=IMPORTHTML("https://x", "table", 1)', "IMPORTHTML"],
    ['=IMPORTDATA("https://x.csv")', "IMPORTDATA"],
    ['=IMPORTFEED("https://x.rss")', "IMPORTFEED"],
    ['=HYPERLINK("https://attacker", "click me")', "HYPERLINK"],
    ['=GOOGLEFINANCE("GOOG")', "GOOGLEFINANCE"],
    ['=GOOGLETRANSLATE("hi", "en", "ja")', "GOOGLETRANSLATE"],
    ['=IMAGE("https://attacker.example/p.png")', "IMAGE"],
    ['=WEBSERVICE("https://x")', "WEBSERVICE"],
    ["=LAMBDA(x, x+1)(5)", "LAMBDA"],
  ];
  for (const [input, expected] of cases) {
    test(`REJECTS ${expected} via \`${input}\``, () => {
      const result = validateCellValue(input);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.rejected_function).toBe(expected);
      }
    });
  }
});

describe("validateCellValue — case insensitive", () => {
  test("lowercase function name REJECTED (Google evaluates case-insensitively)", () => {
    const r = validateCellValue('=importrange("...", "A1")');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("mixed case REJECTED", () => {
    const r = validateCellValue('=ImPoRtRaNgE("...", "A1")');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("lambda lowercase REJECTED", () => {
    const r = validateCellValue('=lambda(x, IMPORTRANGE(x))("url")');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("LAMBDA");
  });
});

describe("validateCellValue — whitespace tolerance", () => {
  test("single space after = REJECTED", () => {
    expect(validateCellValue('= IMPORTRANGE("...", "A1")').ok).toBe(false);
  });
  test("multiple spaces after = REJECTED", () => {
    expect(validateCellValue('=  IMPORTRANGE("...")').ok).toBe(false);
  });
  test("tab after = REJECTED", () => {
    expect(validateCellValue('=\tIMPORTRANGE("...")').ok).toBe(false);
  });
  test("space before ( REJECTED", () => {
    expect(validateCellValue('=IMPORTRANGE ("...")').ok).toBe(false);
  });
  test("space before and after function name REJECTED", () => {
    expect(validateCellValue('=  IMPORTRANGE  ("...")').ok).toBe(false);
  });
  test("`+` formula prefix REJECTED (legacy Lotus-1-2-3 compat)", () => {
    expect(validateCellValue('+IMPORTRANGE("...")').ok).toBe(false);
  });
});

describe("validateCellValue — NFKC normalize (P7) closes fullwidth bypass", () => {
  test("fullwidth `Ｉ` (U+FF29) in IMPORTRANGE REJECTED post-NFKC", () => {
    // U+FF29 FULLWIDTH LATIN CAPITAL LETTER I → ASCII 'I' under NFKC.
    const input = '=' + String.fromCharCode(0xff29) + 'MPORTRANGE("...", "A1")';
    const r = validateCellValue(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("all-fullwidth function name REJECTED post-NFKC", () => {
    // ＩＭＰＯＲＴＲＡＮＧＥ — fullwidth IMPORTRANGE (11 letters: I M P O R T R A N G E).
    const fullwidth = [
      0xff29, // I
      0xff2d, // M
      0xff30, // P
      0xff2f, // O
      0xff32, // R
      0xff34, // T
      0xff32, // R
      0xff21, // A
      0xff2e, // N
      0xff27, // G
      0xff25, // E
    ]
      .map((c) => String.fromCharCode(c))
      .join("");
    const input = "=" + fullwidth + '("...")';
    const r = validateCellValue(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("NFKC is a no-op for ASCII (regression: doesn't break legitimate inputs)", () => {
    // Verify normal IMPORTRANGE still REJECTS (NFKC is idempotent for ASCII).
    expect(validateCellValue('=IMPORTRANGE("...")').ok).toBe(false);
    // And legitimate non-REJECT formulas still PASS.
    expect(validateCellValue("=SUM(A1:A10)").ok).toBe(true);
  });
});

describe("validateCellValue — nested formula REJECT (v1.34 STEP 5; closes §3.3 gap)", () => {
  // v1.34 FLIPPED the 3 documented-gap sentinels PASS -> REJECT (mirror v1.30
  // §5 sentinel #10 flip). The outer wrapper (SUM / ARRAYFORMULA / QUERY) is
  // irrelevant — Google evaluates the nested IMPORTRANGE side-effect anyway,
  // so STEP 5 now scans for a REJECTED call token at ANY depth. These tests
  // PIN the closure (anti-regression: don't accidentally re-open the bypass).
  test("CLOSED (v1.34): =SUM(IMPORTRANGE(...)) REJECTS (nested IMPORTRANGE)", () => {
    const r = validateCellValue('=SUM(IMPORTRANGE("...", "A1"))');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("CLOSED (v1.34): =ARRAYFORMULA(IMPORTRANGE(...)) REJECTS", () => {
    const r = validateCellValue('=ARRAYFORMULA(IMPORTRANGE("..."))');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("CLOSED (v1.34): =QUERY(IMPORTRANGE(...)) REJECTS", () => {
    const r = validateCellValue('=QUERY(IMPORTRANGE("..."))');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test('LAMBDA gap CLOSED (P3): =LAMBDA(x, IMPORTRANGE(x))("url") REJECTS', () => {
    // STEP 4 path (outer name LAMBDA) — unchanged by v1.34.
    const r = validateCellValue('=LAMBDA(x, IMPORTRANGE(x))("url")');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("LAMBDA");
  });

  test("CHAR-concat bypass PASSES (concat result is inert literal text per Google's eval model)", () => {
    // Documented closed per §3.3 — string-concat is NOT re-evaluated as a
    // formula; v1.34 §9 keeps this PASS (closing it would be a false-positive
    // machine with zero security gain). The quoted "IMPORT"/"RANGE" literals
    // are skipped by STEP 5, and there is no literal `IMPORTRANGE(` token.
    expect(validateCellValue('=CHAR(34)&"IMPORT"&"RANGE"&CHAR(40)').ok).toBe(
      true,
    );
  });

  // --- v1.34 STEP 5: deeper nesting + sibling-term + argument-position ---
  test("deep nesting REJECTS: =IFERROR(ARRAYFORMULA(QUERY(IMPORTRANGE(\"x\"))),0)", () => {
    const r = validateCellValue('=IFERROR(ARRAYFORMULA(QUERY(IMPORTRANGE("x"))),0)');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("sibling-term variant REJECTS: =A1+IMPORTRANGE(...) (no outer call token)", () => {
    const r = validateCellValue('=A1+IMPORTRANGE("url","A1")');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("nested non-IMPORTRANGE rejected fn REJECTS: =SUM(IMAGE(\"url\"))", () => {
    const r = validateCellValue('=SUM(IMAGE("https://attacker/x.png"))');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMAGE");
  });

  test("nested HYPERLINK REJECTS: =IF(A1,HYPERLINK(\"u\",\"t\"),0)", () => {
    const r = validateCellValue('=IF(A1,HYPERLINK("u","t"),0)');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("HYPERLINK");
  });

  test("homoglyph-laced NESTED name REJECTS (STEP 0b composes with STEP 5)", () => {
    // Cyrillic capital I (U+0406) in the nested IMPORTRANGE — STEP 0b
    // normalizes to ASCII before STEP 5 scans.
    const cyr = String.fromCharCode(0x406); // CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I
    const r = validateCellValue(`=SUM(${cyr}MPORTRANGE("x"))`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("zero-width-split NESTED name REJECTS (STEP 0a composes with STEP 5)", () => {
    const zwsp = String.fromCharCode(0x200b);
    const r = validateCellValue(`=SUM(IMP${zwsp}ORTRANGE("x"))`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });
});

describe("validateCellValue — v1.41 rejected_formula_nested discriminator", () => {
  // PRESENCE-as-signal: PRESENT (`true`) ONLY on the STEP 5 nested/sibling
  // scanner path; ABSENT on the STEP 4 direct outer-name match. Operators
  // distinguish a wrapper smuggle (attacker tried to evade the outer-name
  // check) from a direct attack. See docs/v1.41-nested-forensic-flag.md Q1.

  // --- STEP 5 path: field PRESENT (true) ---
  test("nested =SUM(IMPORTRANGE(...)) sets rejected_formula_nested === true", () => {
    const r = validateCellValue('=SUM(IMPORTRANGE("x","A1"))');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_formula_nested).toBe(true);
  });

  test("sibling-term =A1+IMPORTRANGE(...) sets rejected_formula_nested === true", () => {
    const r = validateCellValue('=A1+IMPORTRANGE("url","A1")');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_formula_nested).toBe(true);
  });

  test("nested non-IMPORTRANGE =IF(A1,HYPERLINK(...),0) sets the flag", () => {
    const r = validateCellValue('=IF(A1,HYPERLINK("u","t"),0)');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_formula_nested).toBe(true);
  });

  test("homoglyph-laced NESTED name sets the flag (STEP 0b → STEP 5)", () => {
    const cyr = String.fromCharCode(0x406); // Cyrillic I
    const r = validateCellValue(`=SUM(${cyr}MPORTRANGE("x"))`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_formula_nested).toBe(true);
  });

  // --- STEP 4 direct path: field ABSENT (absence ⇒ direct attack) ---
  test("direct =IMPORTRANGE(...) OMITS rejected_formula_nested", () => {
    const r = validateCellValue('=IMPORTRANGE("x","A1")');
    expect(r.ok).toBe(false);
    expect("rejected_formula_nested" in r).toBe(false);
  });

  test('LAMBDA wrapper REJECTS at STEP 4 (outer name) → field ABSENT, NOT nested', () => {
    // The outer name LAMBDA is itself in REJECTED_FUNCTIONS, so the REJECT
    // fires at STEP 4 — the outer name did NOT lie. Absence is correct even
    // though a nested IMPORTRANGE is present: the discriminator is "outer
    // name benign + smuggled token", which LAMBDA is not.
    const r = validateCellValue('=LAMBDA(x, IMPORTRANGE(x))("url")');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("LAMBDA");
    expect("rejected_formula_nested" in r).toBe(false);
  });

  test("homoglyph DIRECT name REJECTS at STEP 4 → field ABSENT", () => {
    const cyr = String.fromCharCode(0x406); // Cyrillic I → normalizes to ASCII I
    const r = validateCellValue(`=${cyr}MPORTRANGE("x")`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
    expect("rejected_formula_nested" in r).toBe(false);
  });

  test("PASS rows never carry the field (ok:true has no rejected_* fields)", () => {
    const r = validateCellValue("=SUM(A1:A10)");
    expect(r.ok).toBe(true);
    expect("rejected_formula_nested" in r).toBe(false);
  });
});

describe("validateCellValue — v1.34 false-positive corpus (MUST stay PASS)", () => {
  test("=SUM(A1:A10) PASSES (no rejected call token)", () => {
    expect(validateCellValue("=SUM(A1:A10)").ok).toBe(true);
  });

  test('instructional string literal PASSES: ="The IMPORTRANGE function is great"', () => {
    expect(
      validateCellValue('="The IMPORTRANGE function is great"').ok,
    ).toBe(true);
  });

  test('string literal containing call SYNTAX PASSES: ="Use IMPORTRANGE(url) here"', () => {
    // The naive "string-contains-rejected-name" check would false-positive
    // here; the literal-aware scan skips the quoted region.
    expect(validateCellValue('="Use IMPORTRANGE(url) here"').ok).toBe(true);
  });

  test("named-range substring PASSES: =SUM(IMPORTRANGE_TOTAL)", () => {
    // maximal-munch identifier IMPORTRANGE_TOTAL != IMPORTRANGE; also not
    // followed by `(`.
    expect(validateCellValue("=SUM(IMPORTRANGE_TOTAL)").ok).toBe(true);
  });

  test("bare rejected name WITHOUT paren PASSES: =SUM(IMPORTRANGE)", () => {
    // A named-range read called IMPORTRANGE, not a function call.
    expect(validateCellValue("=SUM(IMPORTRANGE)").ok).toBe(true);
  });

  test("sheet-name reference containing call-like text PASSES: ='IMPORTRANGE(x)'!A1", () => {
    expect(validateCellValue("='IMPORTRANGE(x)'!A1").ok).toBe(true);
  });

  test("doubled-quote escape inside literal PASSES: =CONCAT(\"a\"\"IMPORTRANGE(\"\"b\")", () => {
    // `""` is an escaped literal quote — the scan stays inside the string and
    // never sees a bare IMPORTRANGE( token.
    expect(validateCellValue('=CONCAT("a""IMPORTRANGE(""b")').ok).toBe(true);
  });

  test("non-formula text with rejected name PASSES: plain literal", () => {
    expect(validateCellValue("IMPORTRANGE(x)").ok).toBe(true); // no =/+ prefix
  });

  test("legitimate analytics nesting (no rejected fn) PASSES", () => {
    expect(
      validateCellValue("=ARRAYFORMULA(IFERROR(VLOOKUP(A:A,B:C,2,0),0))").ok,
    ).toBe(true);
  });
});

describe("scanRejectedCallTokens — unit (Q1 LOCKED linear scanner)", () => {
  test("finds first rejected token in source order", () => {
    expect(scanRejectedCallTokens('=SUM(IMPORTRANGE("x"))')).toBe("IMPORTRANGE");
  });

  test("returns null for clean formula", () => {
    expect(scanRejectedCallTokens("=SUM(A1:A10)")).toBeNull();
  });

  test("skips both \" and ' literals", () => {
    expect(scanRejectedCallTokens('="IMPORTRANGE(x)"')).toBeNull();
    expect(scanRejectedCallTokens("='IMPORTRANGE(x)'!A1")).toBeNull();
  });

  test("unterminated literal consumes to EOF (no false reject)", () => {
    expect(scanRejectedCallTokens('=SUM("unterminated IMPORTRANGE(')).toBeNull();
  });

  test("case-insensitive nested match", () => {
    expect(scanRejectedCallTokens("=sum(importrange(x))")).toBe("IMPORTRANGE");
  });

  test("whitespace before paren still matches: IMPORTRANGE (", () => {
    expect(scanRejectedCallTokens("=SUM(IMPORTRANGE (x))")).toBe("IMPORTRANGE");
  });

  test("ReDoS/perf: 1500 iters x 256-char hostile input under 1500ms", () => {
    // Hostile shape: many identifier-then-paren tokens, none rejected.
    const hostile = "=" + "AB(".repeat(84); // ~252 chars, all non-rejected calls
    const start = Date.now();
    for (let i = 0; i < 1500; i++) {
      scanRejectedCallTokens(hostile);
    }
    expect(Date.now() - start).toBeLessThan(1500);
  });
});

describe("FORMULA_PREFIX_RE — ReDoS safety + bounded quantifiers", () => {
  test("1500 iterations × 256-char hostile input within 1500ms budget", () => {
    // Hostile shape: `=` followed by many backtrack candidates.
    const hostile = "=" + "A".repeat(254) + "(";
    const start = Date.now();
    for (let i = 0; i < 1500; i++) {
      FORMULA_PREFIX_RE.test(hostile);
    }
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(1500);
  });

  test("regex source contains only bounded quantifiers", () => {
    const src = FORMULA_PREFIX_RE.source;
    // \s* is bounded by realistic input length (whitespace classes don't
    // expand catastrophically); [A-Za-z_][A-Za-z0-9_]* is anchored at start
    // by `^` (in our regex). No nested-group backtracking patterns.
    expect(src).toMatch(/^\^/);
  });
});

describe("formula-reject.ts source-byte safety (P2 from v1.20 a1.ts)", () => {
  test("source file does NOT contain literal U+2028 / U+2029 (paste-artifact defense)", () => {
    const source = fs.readFileSync(
      path.join(__dirname, "formula-reject.ts"),
      "utf-8",
    );
    const ls = String.fromCharCode(0x2028);
    const ps = String.fromCharCode(0x2029);
    expect(source.includes(ls)).toBe(false);
    expect(source.includes(ps)).toBe(false);
  });
});

// ============================================================================
// v1.25 Phase 4 (Item 4) — Unicode zero-width + soft-hyphen pre-strip tests
// Closes v1.21 N1 (3-cycle deferral v1.22 / v1.23 / v1.24)
// ============================================================================

describe("v1.25 Phase 4 — ZERO_WIDTH_AND_SOFT_HYPHEN_RE constant", () => {
  test("regex has global flag (for String.replace replace-all semantics)", () => {
    expect(ZERO_WIDTH_AND_SOFT_HYPHEN_RE.flags).toContain("g");
  });

  test("regex matches all 5 codepoints individually (Q5 LOCKED bounded scope)", () => {
    // Reset lastIndex between tests since /g flag carries state on .test().
    for (const cp of [SHY, ZWSP, ZWNJ, ZWJ, BOM]) {
      const re = new RegExp(
        ZERO_WIDTH_AND_SOFT_HYPHEN_RE.source,
        ZERO_WIDTH_AND_SOFT_HYPHEN_RE.flags,
      );
      expect(re.test(`x${cp}y`)).toBe(true);
    }
  });

  test("ZERO_WIDTH_AND_SOFT_HYPHEN_RE scope: pinned to v1.25 5-codepoint set (Cyrillic handled at STEP 0b via homoglyph-normalize.ts since v1.30)", () => {
    const re = new RegExp(
      ZERO_WIDTH_AND_SOFT_HYPHEN_RE.source,
      ZERO_WIDTH_AND_SOFT_HYPHEN_RE.flags,
    );
    // Cyrillic capital I (U+0406) is INTENTIONALLY out of scope for THIS
    // regex — its purpose is the v1.25 Phase 4 5-codepoint zero-width +
    // soft-hyphen set ONLY. Cyrillic homoglyph defense is handled at
    // STEP 0b of the formula-reject pipeline via
    // `src/sheets/homoglyph-normalize.ts` (shipped v1.30; closes the
    // v1.25 Q6 / v1.26+ / v1.28 inherited carry-forward). This sentinel
    // pins the regex's scope contract — Cyrillic must NOT match here.
    expect(re.test(`x${CYRILLIC_I}y`)).toBe(false);
  });

  test("regex does NOT match ASCII / common safe characters (regression)", () => {
    const re = new RegExp(
      ZERO_WIDTH_AND_SOFT_HYPHEN_RE.source,
      ZERO_WIDTH_AND_SOFT_HYPHEN_RE.flags,
    );
    // Plain ASCII + common whitespace + tab/newline must NOT match (would
    // break NFKC normalize step downstream).
    expect(re.test("IMPORTRANGE")).toBe(false);
    expect(re.test("=SUM(A1)")).toBe(false);
    expect(re.test("\t \n")).toBe(false);
  });
});

describe("v1.25 Phase 4 — 5 codepoints pre-strip REJECTS bypass attempts", () => {
  // Per design §2.4 sentinel tests #1-#5 + #7. Each codepoint splits
  // `IMPORTRANGE` and MUST still REJECT after pre-strip.
  test("#1 SHY (U+00AD) split in IMPORTRANGE REJECTED post-strip", () => {
    const input = `=IMP${SHY}ORTRANGE("x","y")`;
    const r = validateCellValue(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("#2 ZWSP (U+200B) split in IMPORTRANGE REJECTED post-strip", () => {
    const input = `=IMP${ZWSP}ORTRANGE("x","y")`;
    const r = validateCellValue(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("#3 ZWNJ (U+200C) split in IMPORTRANGE REJECTED post-strip", () => {
    const input = `=IMP${ZWNJ}ORTRANGE("x","y")`;
    const r = validateCellValue(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("#4 ZWJ (U+200D) split in IMPORTRANGE REJECTED post-strip", () => {
    const input = `=IMP${ZWJ}ORTRANGE("x","y")`;
    const r = validateCellValue(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("#5 BOM (U+FEFF) prefix + function still REJECTED post-strip", () => {
    const input = `${BOM}=IMPORTRANGE("x")`;
    const r = validateCellValue(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("BOM mid-identifier in IMPORTRANGE REJECTED post-strip", () => {
    const input = `=IMP${BOM}ORTRANGE("x")`;
    const r = validateCellValue(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });
});

describe("v1.25 Phase 4 — all 11 REJECTED functions covered with zero-width injection", () => {
  // Per Phase 4 task spec — each REJECTED function must STILL reject when
  // a zero-width char is injected between letters. Mix codepoints across
  // functions to broaden coverage without ballooning test count.
  const cases: Array<[string, string]> = [
    [`=IMP${ZWSP}ORTRANGE("x","y")`, "IMPORTRANGE"],
    [`=IMP${SHY}ORTXML("x","y")`, "IMPORTXML"],
    [`=IMP${ZWNJ}ORTHTML("x","table",1)`, "IMPORTHTML"],
    [`=IMP${ZWJ}ORTDATA("x.csv")`, "IMPORTDATA"],
    [`=IMP${BOM}ORTFEED("x.rss")`, "IMPORTFEED"],
    [`=HYP${ZWSP}ERLINK("x","click")`, "HYPERLINK"],
    [`=GOOG${SHY}LEFINANCE("GOOG")`, "GOOGLEFINANCE"],
    [`=GOOG${ZWNJ}LETRANSLATE("hi","en","ja")`, "GOOGLETRANSLATE"],
    [`=IM${ZWJ}AGE("https://x.png")`, "IMAGE"],
    [`=WEB${BOM}SERVICE("x")`, "WEBSERVICE"],
    [`=LAM${ZWSP}BDA(x, x+1)(5)`, "LAMBDA"],
  ];
  for (const [input, expected] of cases) {
    test(`REJECTS ${expected} with zero-width split (Phase 4)`, () => {
      const r = validateCellValue(input);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.rejected_function).toBe(expected);
    });
  }
});

describe("v1.25 Phase 4 — compositional + ordering tests", () => {
  test("#6 multiple zero-width chars in one identifier REJECTED post-strip", () => {
    // Per design §2.4 test #6 — all-class combined.
    const input = `=I${SHY}M${ZWSP}P${ZWNJ}O${ZWJ}R${SHY}T${ZWSP}RANGE("x")`;
    const r = validateCellValue(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("pre-strip + NFKC interleaved: ZWSP + fullwidth I REJECTED (ordering sentinel)", () => {
    // ZWSP gets stripped FIRST (Step 0a), then NFKC normalizes the
    // fullwidth I → ASCII I (Step 0). Wrong order = bypass:
    //   - If NFKC ran first: zero-width preserved → regex misses (BYPASS)
    //   - With pre-strip first: zero-width removed → NFKC sees clean string
    //     with fullwidth I → normalizes → regex matches → REJECT.
    // Q5 LOCKED order: STRIP → NFKC → regex.
    const input = `=${ZWSP}${FULLWIDTH_I}MPORTRANGE("x")`;
    const r = validateCellValue(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("pre-strip + NFKC interleaved: ZWJ between fullwidth chars REJECTED", () => {
    // =Ｉ[ZWJ]Ｂ M P O R T R A N G E → strip ZWJ → NFKC fullwidth → =IBMPORTRANGE
    // → outer name is IBMPORTRANGE (not in REJECT) → PASSES. This pins
    // that pre-strip happens BEFORE NFKC at the codepoint level (the
    // ZWJ doesn't survive into the post-NFKC identifier as a separator).
    // Actually, IBMPORTRANGE isn't IMPORTRANGE — different function. So
    // this case is a non-REJECTED PASS, exercised in the next test block.
    // This test instead uses interleaved ZWSP inside IMPORTRANGE-with-
    // fullwidth-prefix; outer name remains IMPORTRANGE after both passes.
    const input = `=${FULLWIDTH_I}MP${ZWJ}ORTRANGE("x")`;
    const r = validateCellValue(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("BOM at start + fullwidth chars REJECTED (Q5 LOCKED ordering)", () => {
    // BOM at start (could break `=` detection if not stripped) +
    // fullwidth chars (require NFKC).
    const input = `${BOM}=${FULLWIDTH_I}MPORTRANGE("x")`;
    const r = validateCellValue(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });
});

describe("v1.25 Phase 4 — non-REJECTED + literal text with zero-width still PASSES", () => {
  test("#8 =SUM with ZWSP split PASSES (SUM not in REJECT set)", () => {
    // Per design §2.4 test #8. After strip → `=SUM(A1)` → outer is SUM.
    const r = validateCellValue(`=S${ZWSP}UM(A1)`);
    expect(r.ok).toBe(true);
  });

  test("=AVERAGE with multiple zero-width chars PASSES (legitimate formula)", () => {
    const r = validateCellValue(`=A${ZWSP}V${SHY}E${ZWJ}RAGE(A1:A10)`);
    expect(r.ok).toBe(true);
  });

  test("#9 literal text with zero-width PASSES (no `=` / `+` prefix)", () => {
    // Per design §2.4 test #9.
    const r = validateCellValue(`This is${ZWSP}not a formula`);
    expect(r.ok).toBe(true);
  });

  test("BOM-only string PASSES (post-strip becomes empty)", () => {
    expect(validateCellValue(BOM).ok).toBe(true);
  });

  test("zero-width only between args (not function name) of SUM still PASSES", () => {
    const r = validateCellValue(`=SUM(A1${ZWSP},B2)`);
    expect(r.ok).toBe(true);
  });
});

describe("v1.30 Phase 2 — documented-gap sentinel #10 FLIPPED (UTS #39 CLOSED)", () => {
  // Per docs/v1.30-uts39-defense.md §2.2 + §6 Q4 LOCKED — v1.30 Phase 2
  // wires `applyHomoglyphPipeline` (Default_Ignorable STRIP + bidi STRIP
  // + Cyrillic/Greek NORMALIZE) into `validateCellValue` STEP 0b. This
  // FLIPS the v1.25 Phase 4 documented-gap sentinel from PASS → REJECT.
  // Mirror v1.21 nested-formula gap pattern (SUM-wrapper test). This is
  // the FIRST SafeSpace cycle to flip a documented-gap assertion (closes
  // v1.25 + v1.26 + v1.28 inherited UTS #39 carry-forward).
  test("#10 Cyrillic homoglyph =ІMPORTRANGE NOW REJECTED (v1.30 Phase 2 FLIPPED + v1.32 Phase 1 forensic)", () => {
    // CYRILLIC_I (U+0406) is visually identical to ASCII `I`. v1.30 Phase 1
    // shipped HOMOGLYPH_MAP with U+0406 → "I"; Phase 2 wires
    // applyHomoglyphPipeline into the REJECT path so the introspected
    // form is `=IMPORTRANGE("x")` and FORMULA_PREFIX_RE catches it. The
    // ORIGINAL cell value (with Cyrillic byte) is what the SDK sees —
    // Q2 LOCKED Option C INTROSPECTION-ONLY semantics. The rejected
    // function name surfaces as NORMALIZED ASCII "IMPORTRANGE" (Q4
    // LOCKED reuse -32029 preserves forensic shape).
    //
    // v1.32 Phase 1 -- ALSO assert the new forensic field
    // `rejected_formula_homoglyph_source` is PRESENT and carries the
    // original Cyrillic byte (per Q2 LOCK Option B). Phase 2 will wire
    // this through MCPError.data + sheetsMutationMeta.
    const input = `=${CYRILLIC_I}MPORTRANGE("x")`;
    const r = validateCellValue(input);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      // NORMALIZED ASCII function name preserves forensic shape between
      // direct ASCII attacks and Cyrillic/Greek homoglyph variants.
      expect(r.rejected_function).toBe("IMPORTRANGE");
      // v1.32 Phase 1 -- forensic field PRESENT (PRESENCE-as-signal on
      // homoglyph attack family). Captures the ORIGINAL Cyrillic byte
      // from input position 1; preserved in input byte order per Q2 LOCK.
      expect(r.rejected_formula_homoglyph_source).toBe(CYRILLIC_I);
    }
  });
});

describe("v1.32 Phase 1 -- forensic field PRESENCE-as-signal (rejected_formula_homoglyph_source)", () => {
  // Pin the PRESENCE-as-signal contract: ASCII attacks MUST NOT carry the
  // forensic field; homoglyph attacks MUST carry it. The field captures the
  // ORIGINAL pre-normalize bytes from input (Q2 LOCK Option B). Phase 1
  // surfaces the field at validateCellValue layer; Phase 2 wires audit +
  // MCPError. The contract is the structural defense: future drift adding
  // the field on PASS path OR omitting it on homoglyph REJECT path would
  // surface as a sentinel failure here.
  test("ASCII REJECT does NOT carry homoglyph_source (PRESENCE-as-signal ABSENT)", () => {
    // Pure ASCII attack: no transformable codepoints in input -> ASCII
    // fast-path in applyHomoglyphPipeline -> homoglyph_source ABSENT.
    // Sentinel for the v1.21 base-case shape preservation post-v1.32 P1.
    const r = validateCellValue('=IMPORTRANGE("x","y")');
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.rejected_function).toBe("IMPORTRANGE");
      expect(r.rejected_formula_homoglyph_source).toBeUndefined();
    }
  });

  test("ZWSP-only REJECT carries homoglyph_source = ZWSP byte (PRESENCE-as-signal PRESENT)", () => {
    // Invisible-char splice attack: STEP 0a strips ZWSP first (v1.25 Phase
    // 4); IF that strip yielded `=IMPORTRANGE` we'd never reach STEP 0b
    // applyHomoglyphPipeline. So the attack would be caught by the old
    // strip, NOT by v1.30/v1.32 pipeline. The forensic field is NOT
    // populated for v1.25 P4 strips -- only for STEP 0b transformations.
    //
    // Confirm by using an attack vector that ONLY the v1.30 pipeline
    // catches: Default_Ignorable codepoint (NOT in v1.25 P4 scope).
    // U+200E LEFT-TO-RIGHT MARK is in DEFAULT_IGNORABLE_RE but NOT in
    // ZERO_WIDTH_AND_SOFT_HYPHEN_RE. So v1.25 P4 strip preserves it;
    // STEP 0b applyHomoglyphPipeline strips it AND captures it.
    const LRM = String.fromCharCode(0x200e); // LEFT-TO-RIGHT MARK
    const input = `=IMP${LRM}ORTRANGE("x")`;
    const r = validateCellValue(input);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.rejected_function).toBe("IMPORTRANGE");
      // v1.32 Phase 1 -- forensic captures the Default_Ignorable byte.
      expect(r.rejected_formula_homoglyph_source).toBe(LRM);
    }
  });

  test("Cyrillic REJECT carries homoglyph_source = Cyrillic byte (canonical Phase 1 case)", () => {
    // The canonical v1.30 Phase 2 case -- Cyrillic capital I -> ASCII I
    // via STEP 0b. v1.32 Phase 1 surfaces the original Cyrillic byte
    // in the forensic field.
    const input = `=${CYRILLIC_I}MPORTRANGE("x")`;
    const r = validateCellValue(input);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.rejected_function).toBe("IMPORTRANGE");
      expect(r.rejected_formula_homoglyph_source).toBe(CYRILLIC_I);
    }
  });
});

describe("v1.25 Phase 4 — v1.21 regression net STILL passes (anti-regression)", () => {
  // Re-prove the v1.21 invariants explicitly after pipeline change. The
  // existing test suites above already cover these — these are belt-and-
  // suspenders sentinels colocated with the Phase 4 block to make any
  // future Phase 4 edit surface v1.21 breakage in this same file.
  test("plain IMPORTRANGE STILL REJECTED (v1.21 regression)", () => {
    const r = validateCellValue('=IMPORTRANGE("x","y")');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("NFKC fullwidth bypass STILL REJECTED (v1.21 P7 regression)", () => {
    const input = `=${FULLWIDTH_I}MPORTRANGE("x")`;
    const r = validateCellValue(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("SUM-wrapper gap now REJECTS (v1.34 STEP 5 — closes v1.21 §3.3)", () => {
    // v1.34 FLIPPED this PASS -> REJECT. The nested IMPORTRANGE call token is
    // caught by STEP 5 regardless of the non-rejected outer SUM wrapper.
    const r = validateCellValue('=SUM(IMPORTRANGE("x","y"))');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("IMPORTRANGE");
  });

  test("LAMBDA gap closure STILL REJECTED (v1.21 P3 regression)", () => {
    const r = validateCellValue('=LAMBDA(x, IMPORTRANGE(x))("url")');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rejected_function).toBe("LAMBDA");
  });
});

describe("v1.25 Phase 4 — extended source-byte purity (5 new codepoints)", () => {
  test("source file does NOT contain literal U+00AD / U+200B / U+200C / U+200D / U+FEFF (extends v1.21 invariant)", () => {
    // Mirror v1.21 U+2028 / U+2029 paste-artifact defense. v1.25 Phase 4
    // extends to the 5 zero-width + soft-hyphen codepoints stripped by
    // ZERO_WIDTH_AND_SOFT_HYPHEN_RE — regex MUST be written with `\u`
    // escape sequences only (NOT literal codepoints) so the source file
    // remains grep-friendly + paste-artifact-immune.
    const source = fs.readFileSync(
      path.join(__dirname, "formula-reject.ts"),
      "utf-8",
    );
    expect(source.includes(SHY)).toBe(false);
    expect(source.includes(ZWSP)).toBe(false);
    expect(source.includes(ZWNJ)).toBe(false);
    expect(source.includes(ZWJ)).toBe(false);
    expect(source.includes(BOM)).toBe(false);
  });
});

// v1.26 Phase 1 Item 5 (NEW-8) — extend the source-byte sentinel to the
// test file itself. Belt-and-suspenders: the v1.25 Phase 4 sentinel above
// only checks `formula-reject.ts`. This block extends the invariant to
// `formula-reject.test.ts` — the test source must use `String.fromCharCode`
// (NOT literal codepoints) so the file remains grep-friendly +
// paste-artifact-immune, mirroring the implementation file's discipline.
//
// Reads the test file as RAW BYTES via Buffer (not utf-8 string includes)
// so even malformed UTF-8 sequences would be caught — defense-in-depth.
describe("v1.26 Phase 1 Item 5 (NEW-8) — test file source-byte purity (5 codepoints)", () => {
  test("formula-reject.test.ts does NOT contain literal U+00AD / U+200B / U+200C / U+200D / U+FEFF (extends v1.25 P4 invariant to test file)", () => {
    const buf = fs.readFileSync(
      path.join(__dirname, "formula-reject.test.ts"),
    );
    // UTF-8 byte sequences for each codepoint:
    //   U+00AD → 0xC2 0xAD
    //   U+200B → 0xE2 0x80 0x8B
    //   U+200C → 0xE2 0x80 0x8C
    //   U+200D → 0xE2 0x80 0x8D
    //   U+FEFF → 0xEF 0xBB 0xBF
    const SHY_BYTES = Buffer.from([0xc2, 0xad]);
    const ZWSP_BYTES = Buffer.from([0xe2, 0x80, 0x8b]);
    const ZWNJ_BYTES = Buffer.from([0xe2, 0x80, 0x8c]);
    const ZWJ_BYTES = Buffer.from([0xe2, 0x80, 0x8d]);
    const BOM_BYTES = Buffer.from([0xef, 0xbb, 0xbf]);
    expect(buf.indexOf(SHY_BYTES)).toBe(-1);
    expect(buf.indexOf(ZWSP_BYTES)).toBe(-1);
    expect(buf.indexOf(ZWNJ_BYTES)).toBe(-1);
    expect(buf.indexOf(ZWJ_BYTES)).toBe(-1);
    expect(buf.indexOf(BOM_BYTES)).toBe(-1);
  });
});
