import { describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as path from "node:path";
import { A1_MAX_LENGTH, A1_RANGE_RE, parseA1Range } from "./a1";

describe("A1_RANGE_RE — accepted forms (§7 P1 expansion)", () => {
  // Sentinel for the 5 documented accept forms + quoted-sheet variant.
  // Pinned per design §7 "Accepted range-form sentinel test (P1)" so a
  // future PR that re-narrows the regex (e.g., re-requires `!` separator)
  // fails LOUDLY here instead of silently breaking documented usage.
  const ACCEPTED: ReadonlyArray<readonly [string, string]> = [
    ["Sheet1", "bare-sheet (P1 expansion — sheet-only forms target the first cell)"],
    ["Sheet1!A1", "single-cell"],
    ["Sheet1!A1:Z100", "cell-range"],
    ["Sheet1!A:Z", "full-column range"],
    ["Sheet1!1:1", "full-row range (single row)"],
    ["'Sheet with spaces'!A1", "quoted-sheet (embedded space)"],
  ];

  for (const [input, label] of ACCEPTED) {
    test(`accepts ${label}: ${JSON.stringify(input)}`, () => {
      expect(parseA1Range(input).valid).toBe(true);
    });
  }
});

describe("A1_RANGE_RE — hostile inputs (§7 table; all reject pre-SDK)", () => {
  // Per design §7 "Sentinel test enumerates 14+ hostile cases (4 new rows
  // per P1 / P8 / P9)". Matching the post-P9 actual table row count.
  const HOSTILE: ReadonlyArray<readonly [unknown, string]> = [
    ["Sheet1!A1:B10; DROP TABLE", "suffix-injection (trailing garbage)"],
    ["Sheet1!A1:B10,Sheet1!B2", "comma-injection / compound range (P8)"],
    ["Sheet1!A1!INJECT", "double-bang (second ! invalid)"],
    ["Sheet1!A1:B10\n=IMPORTRANGE(...)", "newline-injection (LF)"],
    ["Sheet1!A1:B10\r=INJECT", "newline-injection (CR)"],
    ["Sheet1!", "empty range (trailing ! with nothing after)"],
    ["Sheet1!A0", "row-zero single-cell (P9)"],
    ["Sheet1!A0:B5", "row-zero range start (P9)"],
    ["Sheet1!0:5", "row-zero full-row start (P9)"],
    ["Sheet1!5:0", "row-zero full-row end (P9)"],
    ["Sheet1!ZZZA1", "column overflow (>3 letters)"],
    ["Ｓheet1!Ａ1", "fullwidth-Unicode hijack (rejected on unquoted form)"],
    ["'Sheet'1'!A1:B10", "quote escape (embedded ' rejected)"],
    ["a".repeat(A1_MAX_LENGTH + 1), "length cap exceeded"],
  ];

  for (const [input, label] of HOSTILE) {
    test(`rejects ${label}: ${typeof input === "string" ? JSON.stringify(input).slice(0, 60) : String(input)}`, () => {
      expect(parseA1Range(input).valid).toBe(false);
    });
  }

  test("count check — exactly 14 hostile entries pinned (matches §7 post-P8+P9 count)", () => {
    expect(HOSTILE.length).toBe(14);
  });
});

describe("A1_RANGE_RE — non-string inputs (handler-side typeof guard)", () => {
  const NON_STRING: ReadonlyArray<unknown> = [
    null,
    undefined,
    42,
    true,
    [],
    {},
    Symbol("x"),
  ];

  for (const v of NON_STRING) {
    test(`rejects non-string ${String(v)}`, () => {
      expect(parseA1Range(v).valid).toBe(false);
    });
  }

  test("rejects empty string", () => {
    expect(parseA1Range("").valid).toBe(false);
  });
});

describe("parseA1Range — return shape", () => {
  test("on accept returns {valid:true, normalized: <input verbatim>}", () => {
    const r = parseA1Range("Sheet1!A1");
    expect(r.valid).toBe(true);
    // Phase 1 keeps input verbatim per §5 L4 carry-forward (no whitespace
    // collapsing yet). A future Phase 1b-2 normalization PR may change
    // `normalized` — callers MUST destructure rather than reuse input.
    expect(r.normalized).toBe("Sheet1!A1");
  });

  test("on reject returns {valid:false, normalized: undefined}", () => {
    const r = parseA1Range("Sheet1!A0");
    expect(r.valid).toBe(false);
    expect(r.normalized).toBeUndefined();
  });
});

describe("A1_RANGE_RE — source-byte safety (P2 paste-artifact defense)", () => {
  // Per design §7 "Source-byte safety (P2)". The regex MUST encode the
  // Line Separator / Paragraph Separator codepoints as the LITERAL escape
  // sequences `\u2028` / `\u2029` — NOT the raw codepoints. Rendering
  // tools may show these as ordinary whitespace, masking a copy-paste
  // accident that re-introduces the raw bytes. This sentinel reads the
  // SOURCE file and asserts the byte-level invariant.
  test("source file contains literal \\u2028 escape (not raw U+2028)", () => {
    const filePath = path.resolve(__dirname, "a1.ts");
    const bytes = fs.readFileSync(filePath);
    // Raw U+2028 = 0xE2 0x80 0xA8 (UTF-8). Raw U+2029 = 0xE2 0x80 0xA9.
    const rawU2028 = bytes.indexOf(Buffer.from([0xe2, 0x80, 0xa8]));
    const rawU2029 = bytes.indexOf(Buffer.from([0xe2, 0x80, 0xa9]));
    expect(rawU2028).toBe(-1);
    expect(rawU2029).toBe(-1);
    // Confirm the literal escape sequences DO appear.
    const text = bytes.toString("utf-8");
    expect(text).toContain("\\u2028");
    expect(text).toContain("\\u2029");
  });

  test("regex behaviorally rejects raw U+2028 + U+2029 inside quoted-sheet form (compiled correctly)", () => {
    // Behavior-level sentinel paired with the source-bytes test above.
    // The regex character class `[^'\r\n\u2028\u2029]` must REJECT these
    // raw codepoints when injected into the quoted-sheet portion of a
    // range string. (We assert behavior, not `.source` content — JS regex
    // literals preserve the escape sequences in `.source`, which is why
    // we use a behavioral assertion here.)
    const withLS = "'sheet\u2028name'!A1";
    const withPS = "'sheet\u2029name'!A1";
    expect(A1_RANGE_RE.test(withLS)).toBe(false);
    expect(A1_RANGE_RE.test(withPS)).toBe(false);
    // Sanity: equivalent quoted sheet WITHOUT the LS/PS chars is accepted.
    expect(A1_RANGE_RE.test("'sheet name'!A1")).toBe(true);
  });
});

describe("A1_RANGE_RE — ReDoS safety", () => {
  // The regex uses bounded quantifiers ({1,99} / {0,99} / {0,6} / {1,3});
  // NO unbounded `+` / `*` / nested groups with conflicting matches.
  // Sentinel: 1500 iterations against a hostile 256-char input must
  // complete in < 1ms per iteration on average (very generous budget;
  // typical run < 10us).
  test("1500 iterations against 256-char hostile input < 1500ms total", () => {
    const hostile = "Sheet1!A1:B10" + ",".repeat(A1_MAX_LENGTH - 13);
    const start = performance.now();
    for (let i = 0; i < 1500; i++) {
      parseA1Range(hostile);
    }
    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(1500);
  });

  test("regex source bounded — no unbounded `*` or `+` outside character class", () => {
    // Structural assertion — scan A1_RANGE_RE.source for the patterns
    // that would indicate unbounded quantifiers (which would be a ReDoS
    // smoke gun on a complex alternation regex).
    const src = A1_RANGE_RE.source;
    // Allow `*` / `+` ONLY inside `[...]` character classes (which is
    // fine — not a quantifier). Sentinel: count occurrences OUTSIDE
    // character-class brackets is 0.
    let depth = 0;
    let unboundedOutside = 0;
    for (let i = 0; i < src.length; i++) {
      const c = src[i];
      const prev = i > 0 ? src[i - 1] : "";
      if (c === "[" && prev !== "\\") depth++;
      else if (c === "]" && prev !== "\\") depth = Math.max(0, depth - 1);
      else if ((c === "*" || c === "+") && depth === 0 && prev !== "\\") {
        unboundedOutside++;
      }
    }
    expect(unboundedOutside).toBe(0);
  });
});

describe("A1_MAX_LENGTH constant", () => {
  test("equals 256 (matches v1.19 `due` field precedent)", () => {
    expect(A1_MAX_LENGTH).toBe(256);
  });

  test("256-byte input within cap passes (when grammar matches)", () => {
    // 13 + 240 = 253 bytes; we use sheet-name padding to stay grammar-valid.
    const validShort = "'" + "a".repeat(99) + "'!A1:Z100";
    expect(Buffer.byteLength(validShort, "utf-8")).toBeLessThanOrEqual(A1_MAX_LENGTH);
    expect(parseA1Range(validShort).valid).toBe(true);
  });

  test("UTF-8 byte length (not String.length) is the gate — 100 emoji = 400 bytes rejects", () => {
    // 4-byte UTF-8 emoji × 100 = 400 bytes; would fail byte cap regardless
    // of grammar (which would also reject — emoji not in [A-Za-z0-9_]).
    const utf8Heavy = "😀".repeat(100);
    expect(Buffer.byteLength(utf8Heavy, "utf-8")).toBe(400);
    expect(parseA1Range(utf8Heavy).valid).toBe(false);
  });
});
