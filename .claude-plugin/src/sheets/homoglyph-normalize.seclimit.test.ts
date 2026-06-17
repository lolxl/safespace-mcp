// v1.33 Phase 1 sec-L1 -- defensive 256-codepoint cap on the forensic
// homoglyphSource buffer in applyHomoglyphPipeline (docs section 4.1, hook #3).
import { describe, expect, test } from "bun:test";
import { applyHomoglyphPipeline } from "./homoglyph-normalize";
import { SHEETS_HOMOGLYPH_SOURCE_MAX_CHARS } from "./limits";
import { validateCellValue } from "./formula-reject";

const CYR_I_UPPER = String.fromCharCode(0x0406); // Cyrillic I -> "I"
const CYR_A_LOWER = String.fromCharCode(0x0430); // Cyrillic a -> "a"

describe("v1.33 sec-L1 -- homoglyphSource 256-codepoint cap", () => {
  test("cap constant is 256", () => {
    expect(SHEETS_HOMOGLYPH_SOURCE_MAX_CHARS).toBe(256);
  });
  test("normalized UNCAPPED for >256-confuser input (security path intact)", () => {
    expect(applyHomoglyphPipeline(CYR_I_UPPER.repeat(300)).normalized).toBe("I".repeat(300));
  });
  test("homoglyphSource capped at exactly 256 codepoints for >256 input", () => {
    const r = applyHomoglyphPipeline(CYR_I_UPPER.repeat(300));
    expect(r.homoglyphSource).toBeDefined();
    expect([...r.homoglyphSource!].length).toBe(256);
    expect(r.homoglyphSource![0]).toBe(CYR_I_UPPER); // ORIGINAL, not mapped ASCII
  });
  test("exactly-256 input -> field length 256 (boundary)", () => {
    expect([...applyHomoglyphPipeline(CYR_I_UPPER.repeat(256)).homoglyphSource!].length).toBe(256);
  });
  test("255 confusers -> field length 255 (under cap)", () => {
    expect([...applyHomoglyphPipeline(CYR_I_UPPER.repeat(255)).homoglyphSource!].length).toBe(255);
  });
  test("PRESENCE-as-signal: pure ASCII -> homoglyphSource ABSENT", () => {
    expect(applyHomoglyphPipeline("=SUM(A1:A2)").homoglyphSource).toBeUndefined();
  });
  test("validateCellValue REJECT verdict unchanged; propagated field capped 256", () => {
    const cell = "=" + CYR_I_UPPER + "MPORTRANGE(\"" + CYR_A_LOWER.repeat(300) + "\")";
    const r = validateCellValue(cell);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.rejected_function).toBe("IMPORTRANGE");
      expect(r.rejected_formula_homoglyph_source).toBeDefined();
      expect([...r.rejected_formula_homoglyph_source!].length).toBe(256);
    }
  });
});
