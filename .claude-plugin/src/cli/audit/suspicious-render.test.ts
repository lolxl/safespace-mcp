// v1.24 Phase 2 Item 4 — sentinel tests for `suspicious-render.ts` module
// extraction. Validates the NAME-only split exports the 3 expected symbols
// and that the import path from `suspicious.ts` (`./suspicious`) resolves
// cleanly. Behavioral regression is covered by the full
// `suspicious.test.ts` fixture (68 tests pre-extraction, MUST still pass
// post-extraction without a single test edit per design Risk 4).

import { describe, expect, test } from "bun:test";
import { CATEGORY_CHANNEL, renderJson, renderTable } from "./suspicious-render";
import {
  type Category,
  HIGH_CONFIDENCE,
} from "./suspicious";

describe("suspicious-render module exports (v1.24 Phase 2 Item 4 NAME-only split)", () => {
  test("renderJson is exported as a function", () => {
    expect(typeof renderJson).toBe("function");
  });

  test("renderTable is exported as a function", () => {
    expect(typeof renderTable).toBe("function");
  });

  test("CATEGORY_CHANNEL map covers every Category value the classifier can produce", () => {
    // CATEGORY_CHANNEL is keyed by Category (TS-enforced via Record<Category, string>);
    // this asserts at runtime that every HIGH_CONFIDENCE bucket entry has a channel
    // attribution. A missing entry would produce `undefined` in rendered output —
    // we want render to fail-fast at module load if a new HIGH category is added
    // to the registry without a corresponding CATEGORY_CHANNEL entry.
    for (const c of HIGH_CONFIDENCE) {
      expect(CATEGORY_CHANNEL[c]).toBeDefined();
      expect(typeof CATEGORY_CHANNEL[c]).toBe("string");
    }
  });

  test("CATEGORY_CHANNEL has the 10 v1.23/v1.24-known Category keys (sentinel)", () => {
    // Pin the registry-size sentinel — adding a new Category MUST update both
    // suspicious.ts type union AND CATEGORY_CHANNEL map here. v1.23 + v1.24
    // Phase 1 LIVE: 6 channel policy_decision values + 4 MCPError codes = 10.
    const knownKeys: Category[] = [
      "denied_formula_rejected",
      "denied_outbound_sanitize_rejected",
      "denied_no_allowlist",
      "denied_not_in_allowlist",
      "denied_burst_limit",
      "denied_tier",
      "scope_mismatch",
      "recipient_lookup_failed",
      "comment_burst_limit_exceeded",
      "search_burst_limit_exceeded",
    ];
    expect(Object.keys(CATEGORY_CHANNEL).sort()).toEqual([...knownKeys].sort());
  });
});
