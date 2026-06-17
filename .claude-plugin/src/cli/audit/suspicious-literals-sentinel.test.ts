/**
 * v1.25 Phase 1 Item 1 — sentinel test asserting `SAFETY_NET_CODES` in
 * `suspicious.ts` matches the corresponding `ERROR_CODES[name].code`
 * entries in `errors.ts`. Structurally prevents the bug class shipped
 * in v1.23 Phase 1 (suspicious.ts hardcoded `-32007` for
 * `scope_mismatch` but real `errors.ts` code was `-32004`); caught
 * in-flight at v1.24 Phase 1 end-to-end MCPError test; fix applied
 * v1.24 Phase 1 in-flight commit; sentinel test added v1.25 Phase 1
 * (this file) to prevent recurrence.
 *
 * If a future PR adds a NEW error code to `ERROR_CODES` AND wants it
 * surfaced via `audit suspicious`, the implementer MUST:
 *   1. Add the entry to `SAFETY_NET_CODES` in `suspicious.ts`
 *   2. Add the row-classification branch in `suspicious.ts` (referencing
 *      `SAFETY_NET_CODES.<name>`, NEVER hardcoded literal)
 *   3. This sentinel test auto-validates the literal matches.
 *
 * If a future PR changes the literal in `ERROR_CODES` for an existing
 * entry referenced in `SAFETY_NET_CODES`, this sentinel fails LOUDLY.
 */

import { describe, expect, test } from "bun:test";
import { ERROR_CODES } from "../../errors";
import { SAFETY_NET_CODES } from "./suspicious";

describe("v1.25 Phase 1 Item 1 — suspicious.ts SAFETY_NET_CODES vs errors.ts ERROR_CODES sentinel", () => {
  // NOTE: receiver order is ERROR_CODES first (typed `number`) so `as const`
  // literal narrowing on SAFETY_NET_CODES values is accepted by Bun's `toBe`
  // overload (literal widens to number on the expected-arg side).
  test("scope_mismatch SAFETY_NET_CODES literal matches ERROR_CODES", () => {
    expect(ERROR_CODES.scope_mismatch.code).toBe(SAFETY_NET_CODES.scope_mismatch);
  });

  test("recipient_lookup_failed SAFETY_NET_CODES literal matches ERROR_CODES", () => {
    expect(ERROR_CODES.recipient_lookup_failed.code).toBe(
      SAFETY_NET_CODES.recipient_lookup_failed,
    );
  });

  test("comment_burst_limit_exceeded SAFETY_NET_CODES literal matches ERROR_CODES", () => {
    expect(ERROR_CODES.comment_burst_limit_exceeded.code).toBe(
      SAFETY_NET_CODES.comment_burst_limit_exceeded,
    );
  });

  test("search_burst_limit_exceeded SAFETY_NET_CODES literal matches ERROR_CODES", () => {
    expect(ERROR_CODES.search_burst_limit_exceeded.code).toBe(
      SAFETY_NET_CODES.search_burst_limit_exceeded,
    );
  });

  test("SAFETY_NET_CODES has exactly 4 entries (drift sentinel — adding 5th requires re-acknowledgment)", () => {
    // If a 5th safety-net code is added to suspicious.ts, this count must
    // bump to 5 + the new entry's row-classification branch must also be
    // wired. Forces the implementer to update this sentinel test, which
    // reads as a deliberate ACK of the new surface.
    expect(Object.keys(SAFETY_NET_CODES).length).toBe(4);
  });
});
