// v1.26 Phase 1 Item 2 (NEW-5) — test-exports barrel sentinel.
//
// Asserts barrel re-exports the expected `_*_FOR_TEST` consts and pins
// the count as a drift sentinel. Updating the count forces re-acknowledgment
// when a new `_*_FOR_TEST` is added to handlers.ts AND wired through the
// barrel (per Q3 LOCKED Option A — definitions stay in handlers.ts).

import { describe, expect, test } from "bun:test";
import * as barrel from "./_test-exports";

describe("v1.26 Phase 1 Item 2 (NEW-5) — `_test-exports.ts` barrel", () => {
  test("re-exports all currently-listed `_*_FOR_TEST` symbols", () => {
    // Compile-time guard: TypeScript would fail import if any symbol missing.
    // Runtime sanity: each is a non-empty Set (current shape — all 3 are Sets).
    expect(barrel._SHEETS_BATCH_UPDATE_ALLOWED_TYPES_FOR_TEST).toBeInstanceOf(
      Set,
    );
    expect(barrel._SHEETS_GRID_RANGE_KEYS_FOR_TEST).toBeInstanceOf(Set);
    expect(barrel._SHEETS_GRID_COORDINATE_KEYS_FOR_TEST).toBeInstanceOf(Set);

    expect(barrel._SHEETS_BATCH_UPDATE_ALLOWED_TYPES_FOR_TEST.size).toBe(7);
    expect(barrel._SHEETS_GRID_RANGE_KEYS_FOR_TEST.size).toBe(5);
    expect(barrel._SHEETS_GRID_COORDINATE_KEYS_FOR_TEST.size).toBe(3);
  });

  test("count drift sentinel: barrel exposes EXACTLY 3 `_*_FOR_TEST` symbols (update + re-acknowledge when growing)", () => {
    const exportedForTestKeys = Object.keys(barrel).filter((k) =>
      k.endsWith("_FOR_TEST"),
    );
    expect(exportedForTestKeys.length).toBe(3);
  });
});
