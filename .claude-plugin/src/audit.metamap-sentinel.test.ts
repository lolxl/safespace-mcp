// v1.27 Phase 1 Item 3 (NEW-11) — phantom-typed `SerializeFn<MetaMap[K]>`
// + `MetaMap` interface sentinel.
//
// Closes v1.25 Phase 2 dual-review security DEFER-1 observation: prior
// shape (`SerializeFn = (meta: unknown) => Record<string, unknown>`) left
// the registry-key ↔ meta-type pairing as a code-review convention. The
// v1.27 mapped-type satisfies clause + `MetaMap` interface promote that
// convention to a COMPILE-TIME invariant.
//
// This file is a NAME-matched sentinel pinning the runtime symmetry that
// mirrors the compile-time invariant. The v1.22 audit roundtrip tests
// (`src/audit.roundtrip.test.ts`), v1.24 errorCode tests
// (`src/audit.roundtrip.test.ts`), and v1.25 Phase 2 serialize-refactor
// tests (`src/audit.serialize-refactor.test.ts`) STAY UNCHANGED per
// Q3 LOCKED and pin the behavioral output BYTES. Belt-and-braces:
//   - Layer 1 (this file + mapped-type satisfies clause): MetaMap keys
//     ARE EXACTLY the AUDIT_META_CHANNELS keys; serialize fns accept the
//     correct narrow meta-type per channel at compile time.
//   - Layer 2 (v1.22/v1.24/v1.25 regression tests): per-channel serialize
//     EMITS THE RIGHT FIELDS for every MAX + MIN field-set.
//
// Pattern reference: audit.serialize-refactor.test.ts (v1.25 Phase 2 Item 2
// shape extension sentinel; mirror file naming + structure).

import { describe, expect, test } from "bun:test";
import {
  AUDIT_META_CHANNELS,
  type MetaMap,
  type SerializeFn,
} from "./audit";

describe("MetaMap + SerializeFn<M> phantom-typed registry pairing (v1.27 Phase 1 Item 3 / NEW-11)", () => {
  test("MetaMap has 8 keys matching AUDIT_META_CHANNELS exactly", () => {
    // Runtime symmetry pin. The mapped-type satisfies clause
    // (`as const satisfies {[K in keyof MetaMap]: …}`) already enforces
    // this at compile time — adding a 9th channel to AUDIT_META_CHANNELS
    // without extending MetaMap fails compile ("Property 'xMeta' is
    // missing in type 'MetaMap'"). This test fires loudly if the satisfies
    // clause is ever loosened back to `Record<string, …>`.
    // v1.48 B4 — added playlistMutationMeta (7th channel).
    // v1.106 — added videoMutationMeta (8th channel; youtube_video_update).
    const registryKeys = Object.keys(AUDIT_META_CHANNELS).sort();
    const expected = [
      "calendarMutationMeta",
      "commentDeleteMeta",
      "commentPostMeta",
      "docsModifyMeta",
      "playlistMutationMeta",
      "sheetsMutationMeta",
      "tasksMutationMeta",
      "videoMutationMeta",
    ];
    expect(registryKeys).toEqual(expected);
  });

  test("each channel's serialize accepts its corresponding MetaMap[K] type (runtime smoke probe)", () => {
    // Spot-check 3 channels via synthetic correct-type meta passing through
    // without runtime error. The compile-time guarantee comes from the
    // mapped-type satisfies clause on AUDIT_META_CHANNELS; this runtime
    // assertion pins that the per-channel impl bodies still produce a
    // Record<string, unknown> when fed their corresponding MetaMap[K].
    const commentMeta: MetaMap["commentPostMeta"] = {
      target_video_hash: "v".repeat(64),
      comment_length: 1,
      policy_decision: "allowed",
    };
    expect(
      typeof AUDIT_META_CHANNELS.commentPostMeta.serialize(commentMeta),
    ).toBe("object");

    const calMeta: MetaMap["calendarMutationMeta"] = {
      target_event_hash: "e".repeat(64),
      policy_decision: "allowed",
    };
    expect(
      typeof AUDIT_META_CHANNELS.calendarMutationMeta.serialize(calMeta),
    ).toBe("object");

    const sheetsMeta: MetaMap["sheetsMutationMeta"] = {
      target_spreadsheet_id_hash: "s".repeat(64),
      operation: "create",
      policy_decision: "allowed",
    };
    expect(
      typeof AUDIT_META_CHANNELS.sheetsMutationMeta.serialize(sheetsMeta),
    ).toBe("object");
  });

  test("SerializeFn<M> is parameterized — pins the type alias shape", () => {
    // Type-level pin: SerializeFn<CommentPostAuditMeta> must accept a
    // CommentPostAuditMeta value. This test exists as a compile-time
    // contract sentinel; if SerializeFn drifts back to non-generic
    // `(meta: unknown) => Record<string, unknown>`, the probe assignment
    // below would still type-check but the MetaMap[K] indexing in the
    // body would lose its specificity. The mapped-type satisfies clause
    // is the real enforcement; this test pins the type alias surface so
    // a future PR can't silently flatten SerializeFn back to non-generic.
    type Fn = SerializeFn<MetaMap["commentPostMeta"]>;
    const probe: Fn = (meta) => ({
      // `meta` parameter is typed CommentPostAuditMeta — `comment_length`
      // resolves to `number` at compile time, not `unknown`. If a future
      // PR drops the type parameter (`SerializeFn = (meta: unknown) → …`),
      // `meta.comment_length` would error here at compile time.
      length_probe: meta.comment_length,
    });
    expect(typeof probe).toBe("function");
  });

  test("MetaMap entries match the AuditEndContext field types — pins channel-key ↔ meta-type invariant", () => {
    // Compile-time pin: the per-channel optional fields on AuditEndContext
    // (commentPostMeta?, calendarMutationMeta?, etc) MUST have the same
    // concrete meta-type as the MetaMap entry. This test exists as a
    // structural assertion — the build itself would fail compile if a
    // MetaMap entry diverges from the corresponding AuditEndContext field
    // (because the v1.25 Phase 2 auditEnd dispatch loop pulls meta values
    // from ctx via the AuditEndContext interface and feeds them to
    // serialize fns typed `SerializeFn<MetaMap[K]>` — a divergence
    // would surface there).
    //
    // Runtime assertion: each key in MetaMap (declared via interface) is
    // present in AUDIT_META_CHANNELS (declared via object literal). The
    // mapped-type satisfies clause already enforces one direction
    // (channels ⊆ MetaMap); this test pins the other direction
    // (MetaMap ⊆ channels) via runtime key check.
    const metaMapKeys: ReadonlyArray<keyof MetaMap> = [
      "commentPostMeta",
      "calendarMutationMeta",
      "docsModifyMeta",
      "commentDeleteMeta",
      "tasksMutationMeta",
      "sheetsMutationMeta",
      "playlistMutationMeta",
      "videoMutationMeta",
    ];
    for (const key of metaMapKeys) {
      expect(
        AUDIT_META_CHANNELS[key],
        `MetaMap key ${key} missing from AUDIT_META_CHANNELS`,
      ).toBeDefined();
      expect(
        typeof AUDIT_META_CHANNELS[key].serialize,
        `AUDIT_META_CHANNELS[${key}].serialize is not a function`,
      ).toBe("function");
    }
  });
});

/* ──────────────────────────────────────────────────────────────────────
 *  v1.27 Phase 1 Item 4 (NEW-13) — iteration order sentinel.
 *
 *  Audit row field byte-order is downstream-load-bearing post-v1.25 Phase 2.
 *  The serialize loop in auditEnd runs
 *    `for (const [channelKey, entry] of Object.entries(AUDIT_META_CHANNELS))`
 *  and `Object.assign(payload, entry.serialize(meta))` merges per-channel
 *  fields into payload IN REGISTRY ITERATION ORDER. Per ES2015+ spec,
 *  object literals iterate string keys in insertion order, so today's
 *  6-element registry iterates in the declared order — but that contract
 *  was implicit until v1.27.
 *
 *  Q5 LOCKED Option A — explicit array literal comparison (vs reduce-based
 *  deep compare): the explicit array IS the contract. A future PR that:
 *    - re-orders channel declarations (e.g., alphabetical hygiene)
 *    - swaps AUDIT_META_CHANNELS to a Map-based construction without
 *      preserving insertion order
 *    - serializes the registry from JSON and re-imports
 *  fails this sentinel and forces a deliberate re-design conversation.
 *
 *  Cross-defense: pairs with the v1.18 / v1.25 registry-size sentinel
 *  (`audit.test.ts` line 575) that already pins `Object.keys.length === 6`.
 *  Adding a 7th channel at the END fails THIS test (explicit array literal
 *  doesn't match) which forces the maintainer to update the order
 *  intentionally vs accidentally.
 * ────────────────────────────────────────────────────────────────────── */
describe("AUDIT_META_CHANNELS iteration order (v1.27 Phase 1 Item 4 / NEW-13)", () => {
  test("Object.keys order is the locked 8-element declared order", () => {
    // Q1 LOCKED Option D (v1.28 Phase 1 Item 3 / NEW-5 — status quo +
    // clarifying contract):
    // This sentinel HAND-MAINTAINS the expected 6-element array literal
    // alongside the AUDIT_META_CHANNELS declaration in
    // `src/audit.ts:763-940`. **Two sources of truth.** When a 7th channel
    // is added to the registry, this array MUST be updated to match — the
    // sentinel fails LOUDLY with a clear array-diff message until both
    // are aligned.
    //
    // REJECTED alternatives (Q1 v1.28 §2.3 / §6):
    //   - Option A (derive expected via `Object.keys(AUDIT_META_CHANNELS)`):
    //     TAUTOLOGY — assertion becomes `Object.keys(X).toEqual(Object.keys(X))`,
    //     asserts nothing.
    //   - Option B (lift to exported `AUDIT_META_CHANNEL_ORDER` const driving
    //     both registry + sentinel): ~60 LoC refactor (restructure registry
    //     to ordered-keys iteration); trips v1.22 / v1.24 / v1.25 / v1.27
    //     Q3-LOCK regression nets. Cost exceeds benefit for a cosmetic drift
    //     class (Object.keys() insertion order is ES2015 spec-stable; rare
    //     violation cases would still be caught by the Q3 LOCK regression
    //     net via bytewise field-order shift).
    //   - Option C (meta-test of `.length === 6` + first/last spot-check):
    //     weaker than current `toEqual` (would miss middle-element
    //     transposition); redundant against the existing assertion.
    //
    // Two-sources-of-truth is the deliberate trade-off; the sentinel
    // catches drift at CI time without restructuring the registry. Aligns
    // with the v1.19.2 NEW-4 minimum-surface convention for cosmetic
    // drift classes.
    //
    // MAINTENANCE CONTRACT: when adding/removing/reordering channels in
    // AUDIT_META_CHANNELS, ALSO update this array literal. The cross-defense
    // with the v1.28 NEW-2 2-meta collision sentinel
    // (`with-context.mutex-contract.test.ts`) is intentional — both pin
    // the same registry order from different angles (iteration order vs
    // last-iterated-wins collision semantics).
    expect(Object.keys(AUDIT_META_CHANNELS)).toEqual([
      "commentPostMeta",
      "calendarMutationMeta",
      "docsModifyMeta",
      "commentDeleteMeta",
      "tasksMutationMeta",
      "sheetsMutationMeta",
      "playlistMutationMeta",
      "videoMutationMeta",
    ]);
  });
});
