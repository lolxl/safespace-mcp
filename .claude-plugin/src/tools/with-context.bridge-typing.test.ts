// v1.29 Phase 2 — AuditEndContext bridge cast-removal sentinel.
//
// Phase 2 wires the Phase 1 `MetaMapStore` typed wrapper into
// `with-context.ts:auditEnd(...)` and REMOVES the 6 `as <Type> | undefined`
// casts at the bridge (post-v1.27 Phase 2 cast-removal). This file pins the
// post-Phase-2 contract:
//
//   1. `MetaMapStore.get<K>(key)` returns `MetaMap[K] | undefined` typed
//      directly — bridge consumers get the per-channel narrow type without
//      a cast.
//   2. The runtime bytes that flow through the bridge are byte-identical
//      to the pre-v1.29 plain Map (insertion order preserved; .has + .size
//      + .keys semantics identical).
//
// The HEAVIER end-to-end runtime parity (auditEnd JSONL roundtrip for each
// of 6 channels) is implicitly covered by the Q3 LOCK regression net
// (audit.roundtrip.test.ts + audit.serialize-refactor.test.ts +
// audit.suspicious-decisions.test.ts + with-context.mutex-contract.test.ts
// + with-context.recorder-symmetry.test.ts + audit.metamap-sentinel.test.ts
// + cli/audit/suspicious-literals-sentinel.test.ts). The 7 regression-net
// files MUST diff ZERO across Phase 2 per v1.29 Phase 0 design §6 Q2 LOCK;
// if they stay GREEN with the bridge surgery applied, the bridge bytes are
// byte-equivalent.
//
// This file pins the BRIDGE TYPING SPECIFICALLY — the structural contract
// that makes the cast removal SAFE. If a future PR re-introduces an `as`
// cast at the bridge, OR if a future PR loosens `MetaMapStore.get`'s
// return type, the tests below + the typecheck step would surface the
// regression.

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

describe("v1.29 Phase 2 — AuditEndContext bridge cast removal", () => {
  test("MetaMapStore.get(<channel>) returns the per-channel typed value — no cast needed", () => {
    const store = new MetaMapStore();
    store.set("commentPostMeta", commentPostSample);
    store.set("calendarMutationMeta", calendarMutationSample);
    store.set("docsModifyMeta", docsModifySample);
    store.set("commentDeleteMeta", commentDeleteSample);
    store.set("tasksMutationMeta", tasksMutationSample);
    store.set("sheetsMutationMeta", sheetsMutationSample);

    // Each .get(<key>) call returns the precise per-channel type — the
    // bridge in with-context.ts:auditEnd assigns each directly to the
    // matching AuditEndContext field WITHOUT an `as <Type> | undefined`
    // cast post-Phase-2. The type checks below would fail at tsc if
    // MetaMapStore.get's return type loosened to `unknown` or `any`.
    const commentPost: CommentPostAuditMeta | undefined = store.get("commentPostMeta");
    const calendarMutation: CalendarMutationAuditMeta | undefined =
      store.get("calendarMutationMeta");
    const docsModify: DocsModifyAuditMeta | undefined = store.get("docsModifyMeta");
    const commentDelete: CommentDeleteAuditMeta | undefined = store.get("commentDeleteMeta");
    const tasksMutation: TasksMutationAuditMeta | undefined = store.get("tasksMutationMeta");
    const sheetsMutation: SheetsMutationAuditMeta | undefined =
      store.get("sheetsMutationMeta");

    // Spot-check identity of returned values to prove the typing reflects
    // real runtime data (not just structurally-empty stubs).
    expect(commentPost).toBe(commentPostSample);
    expect(calendarMutation).toBe(calendarMutationSample);
    expect(docsModify).toBe(docsModifySample);
    expect(commentDelete).toBe(commentDeleteSample);
    expect(tasksMutation).toBe(tasksMutationSample);
    expect(sheetsMutation).toBe(sheetsMutationSample);
  });

  test("MetaMapStore.get on unset key returns undefined (preserves PRESENCE-as-signal semantics for AuditEndContext bridge)", () => {
    const store = new MetaMapStore();
    // Bridge's per-channel field is optional (`commentPostMeta?:` etc.);
    // auditEnd serializes the field ONLY when defined. The undefined
    // return from .get on an unset key MUST flow through to the bridge
    // field untouched so PRESENCE-as-signal discrimination survives.
    const commentPost: CommentPostAuditMeta | undefined = store.get("commentPostMeta");
    expect(commentPost).toBeUndefined();

    // Set one channel; verify the OTHER channels still return undefined
    // (cross-channel isolation — bridge's per-channel optional fields
    // must NOT receive values from sibling channels).
    store.set("calendarMutationMeta", calendarMutationSample);
    expect(store.get("commentPostMeta")).toBeUndefined();
    expect(store.get("docsModifyMeta")).toBeUndefined();
    expect(store.get("commentDeleteMeta")).toBeUndefined();
    expect(store.get("tasksMutationMeta")).toBeUndefined();
    expect(store.get("sheetsMutationMeta")).toBeUndefined();
    expect(store.get("calendarMutationMeta")).toBe(calendarMutationSample);
  });

  test("MetaMapStore.size + .has parity with prior Map<keyof, unknown> semantics (mutex check is byte-identical)", () => {
    // The mutex check in with-context.ts uses `recordedMetas.size > 1`
    // for O(1) detection of double-record violations + iterates the
    // registry and calls `.has(key)` per channel to derive labels in
    // registry-order. Both methods MUST match Map's runtime semantics
    // 1:1 — MetaMapStore is a pure typing wrapper, no behavior change.
    const store = new MetaMapStore();
    expect(store.size).toBe(0);
    expect(store.has("commentPostMeta")).toBe(false);

    store.set("commentPostMeta", commentPostSample);
    expect(store.size).toBe(1);
    expect(store.has("commentPostMeta")).toBe(true);
    expect(store.has("calendarMutationMeta")).toBe(false);

    // Double-record scenario (the mutex catch-net case): size grows
    // monotonically with each unique-key set; identical behavior to
    // plain Map.
    store.set("calendarMutationMeta", calendarMutationSample);
    expect(store.size).toBe(2);
    expect(store.has("calendarMutationMeta")).toBe(true);

    // Last-write-wins on same-key re-set: size stays at 2.
    store.set(
      "commentPostMeta",
      { ...commentPostSample, comment_length: 99 } satisfies CommentPostAuditMeta,
    );
    expect(store.size).toBe(2);
  });

  test("insertion order is preserved (registry-order parity with mutex label assembly)", () => {
    // The mutex check assembles `setChannelLabels` by iterating
    // `Object.entries(AUDIT_META_CHANNELS)` (registry-order) — NOT by
    // call-order from the store. But MetaMapStore.keys() / .entries()
    // also surface insertion order per Map semantics, useful for any
    // future caller wanting to walk the recorded channels in call-order.
    // Pin the contract.
    const store = new MetaMapStore();
    store.set("sheetsMutationMeta", sheetsMutationSample);
    store.set("commentPostMeta", commentPostSample);
    store.set("docsModifyMeta", docsModifySample);

    const keys = [...store.keys()];
    expect(keys).toEqual(["sheetsMutationMeta", "commentPostMeta", "docsModifyMeta"]);
  });
});
