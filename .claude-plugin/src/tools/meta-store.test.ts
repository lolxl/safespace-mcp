// v1.29 Phase 1 — `MetaMapStore` typed wrapper sentinel tests.
//
// Closes v1.27 Phase 2 NEW-3 carry-forward (deferred from v1.28). The
// wrapper class exists post-Phase-1 but is NOT yet wired into
// `with-context.ts` — Phase 2 of this cycle does the bridge surgery +
// removes the 6 `as` casts at the auditEnd bridge. Phase 1 ships the
// type infrastructure + sentinel tests proving the typed contract.
//
// Test coverage:
//   - Runtime contract: typed `.set()` / `.get()` round-trip for each
//     of 6 channels; insertion order preserved (matters for v1.27
//     Phase 2 + v1.28 collision sentinel parity); `.has()` / `.size`
//     / `.keys()` / `.entries()` passthrough.
//   - Compile-time contract: `@ts-expect-error` sentinels pin
//     wrong-type-fails-compile + typo-key-fails-compile at BOTH set
//     and get. These assertions pass at runtime but their value is at
//     `tsc --noEmit` time — removing the `@ts-expect-error` directive
//     would surface the underlying compile error.
//
// ZERO behavior change to production code (wrapper is unused outside
// this test file in Phase 1; bridge replacement is Phase 2).

import { describe, expect, test } from "bun:test";
import type {
  CalendarMutationAuditMeta,
  CommentDeleteAuditMeta,
  CommentPostAuditMeta,
  DocsModifyAuditMeta,
  SheetsMutationAuditMeta,
  TasksMutationAuditMeta,
} from "../audit";
import { MetaMapStore } from "./meta-store";

// --- valid sample meta fixtures (one per channel; MIN field-set) ---

const commentPostSample: CommentPostAuditMeta = {
  target_video_hash: "a".repeat(64),
  comment_length: 42,
  policy_decision: "allowed",
};

const calendarMutationSample: CalendarMutationAuditMeta = {
  target_event_hash: "b".repeat(64),
  policy_decision: "allowed",
};

const docsModifySample: DocsModifyAuditMeta = {
  target_document_id_hash: "c".repeat(64),
  modification_count: 3,
  request_types_csv: "insertText,deleteContentRange",
  policy_decision: "allowed",
};

const commentDeleteSample: CommentDeleteAuditMeta = {
  target_comment_id_hash: "d".repeat(64),
  policy_decision: "deleted",
};

const tasksMutationSample: TasksMutationAuditMeta = {
  target_tasklist_hash: "e".repeat(64),
  operation: "create",
  policy_decision: "allowed",
};

const sheetsMutationSample: SheetsMutationAuditMeta = {
  target_spreadsheet_id_hash: "f".repeat(64),
  operation: "append_values",
  policy_decision: "allowed",
};

// ===== Runtime contract sentinels =====

describe("MetaMapStore — runtime contract", () => {
  test("empty store has size 0", () => {
    const store = new MetaMapStore();
    expect(store.size).toBe(0);
  });

  test("get() on empty store returns undefined", () => {
    const store = new MetaMapStore();
    expect(store.get("commentPostMeta")).toBeUndefined();
    expect(store.get("sheetsMutationMeta")).toBeUndefined();
  });

  test("has() returns false initially, true after set", () => {
    const store = new MetaMapStore();
    expect(store.has("commentPostMeta")).toBe(false);
    store.set("commentPostMeta", commentPostSample);
    expect(store.has("commentPostMeta")).toBe(true);
    expect(store.has("sheetsMutationMeta")).toBe(false);
  });

  test("typed set/get round-trip — commentPostMeta", () => {
    const store = new MetaMapStore();
    store.set("commentPostMeta", commentPostSample);
    const out = store.get("commentPostMeta");
    expect(out).toEqual(commentPostSample);
    // Per-key narrowing: `out` is typed as `CommentPostAuditMeta |
    // undefined` (NOT `unknown`). Accessing a typed field here is the
    // compile-level proof — would fail compile if `.get()` returned
    // `unknown`.
    expect(out?.target_video_hash).toBe(commentPostSample.target_video_hash);
    expect(out?.policy_decision).toBe("allowed");
  });

  test("typed set/get round-trip — sheetsMutationMeta", () => {
    const store = new MetaMapStore();
    store.set("sheetsMutationMeta", sheetsMutationSample);
    const out = store.get("sheetsMutationMeta");
    expect(out).toEqual(sheetsMutationSample);
    expect(out?.operation).toBe("append_values");
    expect(out?.target_spreadsheet_id_hash).toBe(
      sheetsMutationSample.target_spreadsheet_id_hash,
    );
  });

  test("typed set/get round-trip — all 6 channels", () => {
    const store = new MetaMapStore();
    store.set("commentPostMeta", commentPostSample);
    store.set("calendarMutationMeta", calendarMutationSample);
    store.set("docsModifyMeta", docsModifySample);
    store.set("commentDeleteMeta", commentDeleteSample);
    store.set("tasksMutationMeta", tasksMutationSample);
    store.set("sheetsMutationMeta", sheetsMutationSample);
    expect(store.size).toBe(6);
    expect(store.get("commentPostMeta")).toEqual(commentPostSample);
    expect(store.get("calendarMutationMeta")).toEqual(calendarMutationSample);
    expect(store.get("docsModifyMeta")).toEqual(docsModifySample);
    expect(store.get("commentDeleteMeta")).toEqual(commentDeleteSample);
    expect(store.get("tasksMutationMeta")).toEqual(tasksMutationSample);
    expect(store.get("sheetsMutationMeta")).toEqual(sheetsMutationSample);
  });

  test("size increments on first set per key; stable on overwrite", () => {
    const store = new MetaMapStore();
    store.set("commentPostMeta", commentPostSample);
    expect(store.size).toBe(1);
    store.set("commentPostMeta", {
      ...commentPostSample,
      comment_length: 999,
    });
    // Overwrite same key: size stays 1
    expect(store.size).toBe(1);
    expect(store.get("commentPostMeta")?.comment_length).toBe(999);
    store.set("sheetsMutationMeta", sheetsMutationSample);
    expect(store.size).toBe(2);
  });

  test("keys() returns insertion order", () => {
    // Insertion order matters for v1.27 Phase 2 (mutex contract) +
    // v1.28 collision sentinel parity. Wrapper MUST preserve native
    // Map insertion-order semantics.
    const store = new MetaMapStore();
    store.set("sheetsMutationMeta", sheetsMutationSample);
    store.set("commentPostMeta", commentPostSample);
    store.set("docsModifyMeta", docsModifySample);
    expect([...store.keys()]).toEqual([
      "sheetsMutationMeta",
      "commentPostMeta",
      "docsModifyMeta",
    ]);
  });

  test("entries() returns [key, value] pairs in insertion order", () => {
    const store = new MetaMapStore();
    store.set("tasksMutationMeta", tasksMutationSample);
    store.set("commentDeleteMeta", commentDeleteSample);
    const entries = [...store.entries()];
    expect(entries).toHaveLength(2);
    expect(entries[0]?.[0]).toBe("tasksMutationMeta");
    expect(entries[0]?.[1]).toEqual(tasksMutationSample);
    expect(entries[1]?.[0]).toBe("commentDeleteMeta");
    expect(entries[1]?.[1]).toEqual(commentDeleteSample);
  });
});

// ===== Compile-time contract sentinels =====
//
// `@ts-expect-error` directives BELOW are the load-bearing assertions:
// each directive REQUIRES the next statement to fail TypeScript compile.
// If a future refactor relaxed the wrapper typing (e.g., reverted
// `.set<K>(key: K, value: MetaMap[K])` to `.set(key: string, value:
// unknown)`), the underlying call would type-check, the
// `@ts-expect-error` would itself become an error ("Unused
// '@ts-expect-error' directive"), and `bun run typecheck` would fail
// loudly — surfacing the contract regression.
//
// At RUNTIME these tests pass trivially (the wrapper accepts the calls
// because the underlying Map is value-permissive). The proof is at
// `tsc --noEmit` time.

describe("MetaMapStore — compile-time contract (@ts-expect-error sentinels)", () => {
  test("type-level: wrong meta type to channel fails compile (cross-key swap)", () => {
    const store = new MetaMapStore();
    // @ts-expect-error — `sheetsMutationMeta` requires
    // `SheetsMutationAuditMeta` per `MetaMap["sheetsMutationMeta"]`;
    // passing a `CommentPostAuditMeta` shape fails the generic
    // constraint `value: MetaMap[K]`.
    store.set("sheetsMutationMeta", commentPostSample);
    // Runtime: the wrapper accepts because the underlying Map is
    // permissive at runtime. The contract is enforced at compile time
    // only.
    expect(store.has("sheetsMutationMeta")).toBe(true);
  });

  test("type-level: wrong meta type to channel fails compile (second pair)", () => {
    const store = new MetaMapStore();
    // @ts-expect-error — `commentPostMeta` requires
    // `CommentPostAuditMeta`; passing a `CalendarMutationAuditMeta`
    // shape fails the generic constraint.
    store.set("commentPostMeta", calendarMutationSample);
    expect(store.has("commentPostMeta")).toBe(true);
  });

  test("type-level: typo key fails compile on set", () => {
    const store = new MetaMapStore();
    // @ts-expect-error — `"typoChannel"` is not in `keyof MetaMap`
    // (current 6 keys are commentPostMeta / calendarMutationMeta /
    // docsModifyMeta / commentDeleteMeta / tasksMutationMeta /
    // sheetsMutationMeta).
    store.set("typoChannel", commentPostSample);
    expect(store.size).toBe(1);
  });

  test("type-level: typo key fails compile on get", () => {
    const store = new MetaMapStore();
    // @ts-expect-error — `"typoChannel"` is not in `keyof MetaMap`;
    // typed `get<K extends keyof MetaMap>(key: K)` rejects unknown
    // keys at compile time.
    const out = store.get("typoChannel");
    expect(out).toBeUndefined();
  });

  test("type-level: typo key fails compile on has", () => {
    const store = new MetaMapStore();
    // @ts-expect-error — `has<K extends keyof MetaMap>(key: K)`
    // rejects unknown keys at compile time (defense-in-depth — even
    // the boolean-returning passthrough is typed).
    const present = store.has("typoChannel");
    expect(present).toBe(false);
  });

  test("type-level: wrong-shape literal fails compile (missing required field)", () => {
    const store = new MetaMapStore();
    // @ts-expect-error — `commentPostMeta` requires
    // `target_video_hash` + `comment_length` + `policy_decision`;
    // passing a partial object missing required fields fails the
    // generic constraint `value: MetaMap[K]`.
    store.set("commentPostMeta", { policy_decision: "allowed" });
    expect(store.has("commentPostMeta")).toBe(true);
  });
});
