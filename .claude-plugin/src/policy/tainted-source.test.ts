// v1.56 F3b — tainted-source provenance tests
// (docs/v1.56-f3-tainted-source-and-lure-flag.md §8 sec-rev hooks). Covers:
// email/URL extraction, case-insensitive normalization, the structured-value
// walk, the recipient membership check, the size cap, and the test-reset.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  __internal,
  __resetTaintedSourceForTests,
  getTaintedCount,
  isTaintedRecipient,
  recordTaintedFromText,
  recordTaintedFromValue,
} from "./tainted-source";

beforeEach(() => __resetTaintedSourceForTests());
afterEach(() => __resetTaintedSourceForTests());

describe("recordTaintedFromText — extraction", () => {
  test("extracts an email and flags it as a tainted recipient", () => {
    recordTaintedFromText("Please contact attacker@evil.ru to confirm.");
    expect(isTaintedRecipient("attacker@evil.ru")).toBe(true);
    expect(getTaintedCount()).toBe(1);
  });

  test("case-insensitive: stored lowercased, matched regardless of recipient case", () => {
    recordTaintedFromText("Mail Attacker@Evil.RU now");
    expect(isTaintedRecipient("attacker@evil.ru")).toBe(true);
    expect(isTaintedRecipient("ATTACKER@EVIL.RU")).toBe(true);
  });

  test("extracts multiple emails + URLs", () => {
    recordTaintedFromText("a@x.com and b@y.org, see https://evil.example/login");
    expect(isTaintedRecipient("a@x.com")).toBe(true);
    expect(isTaintedRecipient("b@y.org")).toBe(true);
    expect(getTaintedCount()).toBe(3); // 2 emails + 1 url
  });

  test("an address NOT in any read is not tainted", () => {
    recordTaintedFromText("nothing actionable here");
    expect(isTaintedRecipient("alice@example.com")).toBe(false);
    expect(getTaintedCount()).toBe(0);
  });

  test("empty / non-string input is a safe no-op", () => {
    recordTaintedFromText("");
    // @ts-expect-error — defensive runtime guard
    recordTaintedFromText(undefined);
    expect(getTaintedCount()).toBe(0);
  });

  test("duplicate tokens are de-duped (set semantics)", () => {
    recordTaintedFromText("a@x.com a@x.com a@x.com");
    expect(getTaintedCount()).toBe(1);
  });
});

describe("recordTaintedFromValue — structured walk (docs response shape)", () => {
  test("walks nested text leaves (textRun.content) and records addresses", () => {
    // Mirrors the Google Docs document resource shape.
    const docResource = {
      documentId: "abc",
      title: "Invoice",
      body: {
        content: [
          { paragraph: { elements: [{ textRun: { content: "Wire to mule@laundering.ru" } }] } },
          { paragraph: { elements: [{ textRun: { content: "Visit https://phish.example/pay" } }] } },
        ],
      },
    };
    recordTaintedFromValue(docResource);
    expect(isTaintedRecipient("mule@laundering.ru")).toBe(true);
    expect(getTaintedCount()).toBe(2);
  });

  test("handles arrays, null, numbers, and cycles without throwing", () => {
    const cyclic: Record<string, unknown> = { note: "ping evil@loop.ru" };
    cyclic.self = cyclic; // cycle
    recordTaintedFromValue([cyclic, null, 42, ["x@y.com"]]);
    expect(isTaintedRecipient("evil@loop.ru")).toBe(true);
    expect(isTaintedRecipient("x@y.com")).toBe(true);
  });

  test("respects the depth bound (does not blow the stack)", () => {
    let deep: unknown = "deepest@x.com";
    for (let i = 0; i < __internal.MAX_WALK_DEPTH + 10; i++) deep = { next: deep };
    expect(() => recordTaintedFromValue(deep)).not.toThrow();
    // Past the bound the leaf is not reached — that's the intended safety cutoff.
    expect(isTaintedRecipient("deepest@x.com")).toBe(false);
  });
});

describe("size cap", () => {
  test("stops recording past MAX_TOKENS but keeps the early (attacker) tokens", () => {
    recordTaintedFromText("first@early.ru"); // recorded early
    const cap = __internal.MAX_TOKENS;
    let blob = "";
    for (let i = 0; i < cap + 50; i++) blob += ` filler${i}@noise.com`;
    recordTaintedFromText(blob);
    expect(getTaintedCount()).toBe(cap); // capped
    expect(isTaintedRecipient("first@early.ru")).toBe(true); // early token NOT evicted
  });
});

describe("isTaintedRecipient — guards", () => {
  test("non-string recipient → false (defensive)", () => {
    recordTaintedFromText("a@x.com");
    // @ts-expect-error — runtime guard
    expect(isTaintedRecipient(undefined)).toBe(false);
    // @ts-expect-error — runtime guard
    expect(isTaintedRecipient(123)).toBe(false);
  });

  test("trims surrounding whitespace before matching", () => {
    recordTaintedFromText("a@x.com");
    expect(isTaintedRecipient("  a@x.com  ")).toBe(true);
  });
});

describe("__resetTaintedSourceForTests", () => {
  test("clears the session set", () => {
    recordTaintedFromText("a@x.com");
    expect(getTaintedCount()).toBe(1);
    __resetTaintedSourceForTests();
    expect(getTaintedCount()).toBe(0);
    expect(isTaintedRecipient("a@x.com")).toBe(false);
  });
});
