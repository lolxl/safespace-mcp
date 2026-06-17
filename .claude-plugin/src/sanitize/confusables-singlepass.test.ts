// Perf hot-path cycle — confusables normalization moved from
// `Array.from(text).map(...).join("")` (allocates a full code-point array for
// every non-ASCII string leaf) to a single-pass `replace(CONFUSABLES_RE, ...)`.
// This must be byte-for-byte behavior-preserving. These tests assert the
// sanitized output equals a per-code-point oracle for the same input.

import { describe, expect, test } from "bun:test";
import { sanitize } from "./index";
import { CONFUSABLES } from "./patterns";

/** Reference implementation — the exact transform the old code performed. */
function oracle(s: string): string {
  return Array.from(s)
    .map((ch) => CONFUSABLES.get(ch) ?? ch)
    .join("");
}

/** Extract the wrapped content between the <warning> preamble and the closing
 *  tag. The test inputs contain no angle brackets, so this is unambiguous. */
function inner(out: unknown): string {
  const m = String(out).match(/<\/warning>([\s\S]*)<\/untrusted-source-/);
  expect(m).not.toBeNull();
  return m![1]!;
}

describe("confusables single-pass replace ≡ per-code-point map", () => {
  test("mixed Cyrillic / Greek / Latin normalizes identically to the oracle", () => {
    // Cyrillic а е о р с х і ѕ + Greek Α Β Ζ mixed with ASCII.
    const s = "Раypаl аdmіn ѕign іn — Αlpha Βeta Ζeta";
    expect(inner(sanitize(s, { toolName: "t" }))).toBe(oracle(s));
  });

  test("every confusable key maps in a single pass", () => {
    const all = Array.from(CONFUSABLES.keys()).join("");
    expect(inner(sanitize(all, { toolName: "t" }))).toBe(oracle(all));
  });

  test("repeated confusables across a long string all normalize", () => {
    const s = "аеор".repeat(500); // 2000 Cyrillic code points
    const out = inner(sanitize(s, { toolName: "t" }));
    expect(out).toBe("aeop".repeat(500));
    expect(out).toBe(oracle(s));
  });

  test("pure-ASCII content is untouched by the confusables step", () => {
    const s = "plain ascii text, no confusables here 12345";
    expect(inner(sanitize(s, { toolName: "t" }))).toBe(s);
  });
});
