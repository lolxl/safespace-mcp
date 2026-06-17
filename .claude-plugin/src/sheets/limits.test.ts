// v1.22 Phase 2 — sentinel tests for `src/sheets/limits.ts`.
//
// Pins the 4 Sheets cap constants to their canonical values. ANY cap
// change (e.g., per-cell 50KB → 60KB) MUST also edit this test file —
// drift-prevention contract per v1.22 design §2.3 + sec-rev hook #4.
//
// Behavior is UNCHANGED from v1.20 + v1.21 inline implementations; these
// tests lock the extraction so the existing handler test suite (which
// references the same numeric values implicitly via per-cell / per-batch
// reject paths) continues to be authoritative for handler behavior.

import { describe, expect, test } from "bun:test";
import {
  SHEETS_BATCH_MAX_BYTES,
  SHEETS_BATCH_UPDATE_MAX_REQUESTS,
  SHEETS_CELL_MAX_BYTES,
  SHEETS_MAX_CELLS_PER_CALL,
} from "./limits";

describe("v1.22 Phase 2 I-1 — src/sheets/limits.ts canonical cap constants", () => {
  test("SHEETS_CELL_MAX_BYTES = 50000 (per-cell content cap; matches v1.20 + v1.21 inline)", () => {
    expect(SHEETS_CELL_MAX_BYTES).toBe(50000);
  });

  test("SHEETS_BATCH_MAX_BYTES = 100000 (per-batch cumulative byte cap; Q7 LOCKED in v1.21)", () => {
    expect(SHEETS_BATCH_MAX_BYTES).toBe(100000);
  });

  test("SHEETS_MAX_CELLS_PER_CALL = 10000 (per-call cumulative cell-count cap; Q7 LOCKED in v1.21)", () => {
    expect(SHEETS_MAX_CELLS_PER_CALL).toBe(10000);
  });

  test("SHEETS_BATCH_UPDATE_MAX_REQUESTS = 50 (per-batch_update request-count cap; mirror v1.17 docs_modify_structured)", () => {
    expect(SHEETS_BATCH_UPDATE_MAX_REQUESTS).toBe(50);
  });

  test("sentinel — all 4 constants identical to v1.20 + v1.21 inline values (NO drift across extraction)", () => {
    // Drift-prevention contract per v1.22 design §2.3 sec-rev hook #4.
    // Editing any of these literals MUST be accompanied by a documented
    // cap-bump decision (mirror v1.17 docs_modify_structured rationale).
    expect({
      SHEETS_CELL_MAX_BYTES,
      SHEETS_BATCH_MAX_BYTES,
      SHEETS_MAX_CELLS_PER_CALL,
      SHEETS_BATCH_UPDATE_MAX_REQUESTS,
    }).toEqual({
      SHEETS_CELL_MAX_BYTES: 50000,
      SHEETS_BATCH_MAX_BYTES: 100000,
      SHEETS_MAX_CELLS_PER_CALL: 10000,
      SHEETS_BATCH_UPDATE_MAX_REQUESTS: 50,
    });
  });
});
