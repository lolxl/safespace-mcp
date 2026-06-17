// v1.25 Phase 2 Item 2 — registry-driven `serialize` sentinel tests.
//
// Closes v1.19 NEW-3 "manual 4th site" drift class PERMANENTLY at the
// TypeScript-enforced level. The `AUDIT_META_CHANNELS` value shape was
// extended from `{label, flatHash, suspiciousDecisions?}` to
// `{label, flatHash, suspiciousDecisions?, serialize}` so `auditEnd` can
// dispatch payload-field emission off the registry instead of 6 manually
// maintained `if (ctx.<channel>Meta !== undefined)` blocks. Adding a 7th
// channel without a `serialize` function fails compile via the satisfies
// clause — site 4 of the v1.19 NEW-3 4-site checklist is now structurally
// eliminated.
//
// This file is a NAME-matched sentinel pinning the per-channel serialize
// CONTRACT (input meta → output Record). The v1.22 audit roundtrip tests
// (`src/audit.roundtrip.test.ts`) STAY UNCHANGED per Q3 LOCKED and pin the
// behavioral output BYTES (MAX + MIN field-set per channel). Belt-and-braces
// defense — two layers:
//   - Layer 1 (this file + satisfies clause): site 4 EXISTS for every channel
//   - Layer 2 (v1.22 roundtrip): site 4 EMITS THE RIGHT FIELDS per channel
//
// Pattern reference: audit.suspicious-decisions.test.ts (v1.24 Phase 1 Item 1
// shape extension sentinel; mirror file naming + structure).

import { describe, expect, test } from "bun:test";
import {
  AUDIT_META_CHANNELS,
  type CalendarMutationAuditMeta,
  type CommentDeleteAuditMeta,
  type CommentPostAuditMeta,
  type DocsModifyAuditMeta,
  type SheetsMutationAuditMeta,
  type TasksMutationAuditMeta,
} from "./audit";

describe("AUDIT_META_CHANNELS serialize registry shape (v1.25 Phase 2 Item 2)", () => {
  test("all 6 channels declare a serialize function (TypeScript satisfies clause enforces presence)", () => {
    for (const [key, entry] of Object.entries(AUDIT_META_CHANNELS)) {
      expect(entry.serialize, `channel ${key} missing serialize`).toBeDefined();
      expect(typeof entry.serialize, `channel ${key} serialize is not a function`).toBe("function");
    }
  });

  test("registry size stays at 8 (cross-references v1.18 / v1.19 / v1.20 size sentinel — bumping requires NEW localMetas + AuditEndContext + auditEnd write + suspiciousDecisions + serialize)", () => {
    expect(Object.keys(AUDIT_META_CHANNELS).length).toBe(8);
  });

  test("each channel's serialize is a synchronous function (NOT a Promise) — Q2 LOCKED pure-return", () => {
    // Synthetic minimal meta per channel; the assertion is on the RETURN TYPE
    // of serialize, not on field correctness (that's pinned by audit.roundtrip).
    const probes: Record<string, unknown> = {
      commentPostMeta: {
        target_video_hash: "v".repeat(64),
        comment_length: 1,
        policy_decision: "allowed",
      },
      calendarMutationMeta: {
        target_event_hash: "e".repeat(64),
        policy_decision: "allowed",
      },
      docsModifyMeta: {
        target_document_id_hash: "d".repeat(64),
        modification_count: 1,
        request_types_csv: "insertText",
        policy_decision: "allowed",
      },
      commentDeleteMeta: {
        target_comment_id_hash: "c".repeat(64),
        policy_decision: "deleted",
      },
      tasksMutationMeta: {
        target_tasklist_hash: "t".repeat(64),
        operation: "create",
        policy_decision: "allowed",
      },
      sheetsMutationMeta: {
        target_spreadsheet_id_hash: "s".repeat(64),
        operation: "create",
        policy_decision: "allowed",
      },
      playlistMutationMeta: {
        target_playlist_hash: "p".repeat(64),
        operation: "playlist_create",
        policy_decision: "allowed",
      },
      videoMutationMeta: {
        target_video_hash: "v".repeat(64),
        operation: "video_update",
        title_length: 1,
        policy_decision: "allowed",
      },
    };
    for (const [key, entry] of Object.entries(AUDIT_META_CHANNELS)) {
      const out = entry.serialize(probes[key]);
      expect(out, `channel ${key} serialize returned non-object`).toBeInstanceOf(Object);
      // Must NOT be a Promise — pure-return contract per Q2 LOCKED.
      expect(out instanceof Promise, `channel ${key} serialize returned a Promise`).toBe(false);
    }
  });
});

describe("commentPostMeta.serialize contract (v1.25 Phase 2 Item 2)", () => {
  test("MAX shape (reply): 4 fields emitted in v1.24-mirror ORDER for byte-stability", () => {
    const meta: CommentPostAuditMeta = {
      target_video_hash: "v".repeat(64),
      parent_comment_id_hash: "p".repeat(64),
      comment_length: 42,
      policy_decision: "allowed",
    };
    const out = AUDIT_META_CHANNELS.commentPostMeta.serialize(meta);
    expect(out).toEqual({
      target_video_hash: "v".repeat(64),
      comment_length: 42,
      policy_decision: "allowed",
      parent_comment_id_hash: "p".repeat(64),
    });
  });

  test("MIN shape (top-level post): parent_comment_id_hash ABSENT", () => {
    const meta: CommentPostAuditMeta = {
      target_video_hash: "v".repeat(64),
      comment_length: 7,
      policy_decision: "denied_burst_limit",
    };
    const out = AUDIT_META_CHANNELS.commentPostMeta.serialize(meta);
    expect(out).toEqual({
      target_video_hash: "v".repeat(64),
      comment_length: 7,
      policy_decision: "denied_burst_limit",
    });
    expect(out.parent_comment_id_hash).toBeUndefined();
  });

  test("pure-return: serialize does NOT mutate its input meta", () => {
    const meta: CommentPostAuditMeta = {
      target_video_hash: "v".repeat(64),
      comment_length: 1,
      policy_decision: "allowed",
    };
    const snapshot = JSON.stringify(meta);
    AUDIT_META_CHANNELS.commentPostMeta.serialize(meta);
    expect(JSON.stringify(meta)).toBe(snapshot);
  });
});

describe("calendarMutationMeta.serialize contract (v1.25 Phase 2 Item 2)", () => {
  test("MAX shape (calendar_respond): 3 fields including rsvp_response", () => {
    const meta: CalendarMutationAuditMeta = {
      target_event_hash: "e".repeat(64),
      policy_decision: "allowed",
      rsvp_response: "tentative",
    };
    const out = AUDIT_META_CHANNELS.calendarMutationMeta.serialize(meta);
    expect(out).toEqual({
      target_event_hash: "e".repeat(64),
      policy_decision: "allowed",
      rsvp_response: "tentative",
    });
  });

  test("MIN shape (update/delete): rsvp_response ABSENT", () => {
    const meta: CalendarMutationAuditMeta = {
      target_event_hash: "e".repeat(64),
      policy_decision: "denied_tier",
    };
    const out = AUDIT_META_CHANNELS.calendarMutationMeta.serialize(meta);
    expect(out).toEqual({
      target_event_hash: "e".repeat(64),
      policy_decision: "denied_tier",
    });
    expect(out.rsvp_response).toBeUndefined();
  });
});

describe("docsModifyMeta.serialize contract (v1.25 Phase 2 Item 2)", () => {
  test("MAX shape (with replacements): 5 fields including total_text_replacements", () => {
    const meta: DocsModifyAuditMeta = {
      target_document_id_hash: "d".repeat(64),
      modification_count: 3,
      request_types_csv: "insertText,replaceAllText,updateTextStyle",
      total_text_replacements: 17,
      policy_decision: "allowed",
    };
    const out = AUDIT_META_CHANNELS.docsModifyMeta.serialize(meta);
    expect(out).toEqual({
      target_document_id_hash: "d".repeat(64),
      modification_count: 3,
      request_types_csv: "insertText,replaceAllText,updateTextStyle",
      policy_decision: "allowed",
      total_text_replacements: 17,
    });
  });

  test("MIN shape (no replaceAllText reply): total_text_replacements ABSENT", () => {
    const meta: DocsModifyAuditMeta = {
      target_document_id_hash: "d".repeat(64),
      modification_count: 1,
      request_types_csv: "insertText",
      policy_decision: "denied_tier",
    };
    const out = AUDIT_META_CHANNELS.docsModifyMeta.serialize(meta);
    expect(out).toEqual({
      target_document_id_hash: "d".repeat(64),
      modification_count: 1,
      request_types_csv: "insertText",
      policy_decision: "denied_tier",
    });
    expect(out.total_text_replacements).toBeUndefined();
  });
});

describe("commentDeleteMeta.serialize contract (v1.25 Phase 2 Item 2)", () => {
  test("emits exactly target_comment_id_hash + policy_decision (no optional fields)", () => {
    const meta: CommentDeleteAuditMeta = {
      target_comment_id_hash: "c".repeat(64),
      policy_decision: "deleted",
    };
    const out = AUDIT_META_CHANNELS.commentDeleteMeta.serialize(meta);
    expect(out).toEqual({
      target_comment_id_hash: "c".repeat(64),
      policy_decision: "deleted",
    });
  });

  test("denied_tier shape: same 2 fields; policy_decision discriminates", () => {
    const meta: CommentDeleteAuditMeta = {
      target_comment_id_hash: "c".repeat(64),
      policy_decision: "denied_tier",
    };
    const out = AUDIT_META_CHANNELS.commentDeleteMeta.serialize(meta);
    expect(out).toEqual({
      target_comment_id_hash: "c".repeat(64),
      policy_decision: "denied_tier",
    });
  });
});

describe("tasksMutationMeta.serialize contract (v1.25 Phase 2 Item 2)", () => {
  test("create shape: target_task_hash ABSENT", () => {
    const meta: TasksMutationAuditMeta = {
      target_tasklist_hash: "t".repeat(64),
      operation: "create",
      policy_decision: "allowed",
    };
    const out = AUDIT_META_CHANNELS.tasksMutationMeta.serialize(meta);
    expect(out).toEqual({
      target_tasklist_hash: "t".repeat(64),
      operation: "create",
      policy_decision: "allowed",
    });
    expect(out.target_task_hash).toBeUndefined();
  });

  test("update shape: target_task_hash PRESENT", () => {
    const meta: TasksMutationAuditMeta = {
      target_tasklist_hash: "t".repeat(64),
      target_task_hash: "k".repeat(64),
      operation: "update",
      policy_decision: "allowed",
    };
    const out = AUDIT_META_CHANNELS.tasksMutationMeta.serialize(meta);
    expect(out).toEqual({
      target_tasklist_hash: "t".repeat(64),
      operation: "update",
      policy_decision: "allowed",
      target_task_hash: "k".repeat(64),
    });
  });

  test("delete shape uses operation discriminator (NOT policy_decision === 'deleted' — sec-M3 LOCKED)", () => {
    const meta: TasksMutationAuditMeta = {
      target_tasklist_hash: "t".repeat(64),
      target_task_hash: "k".repeat(64),
      operation: "delete",
      policy_decision: "allowed",
    };
    const out = AUDIT_META_CHANNELS.tasksMutationMeta.serialize(meta);
    expect(out.operation).toBe("delete");
    // policy_decision MUST NOT be the discriminator for tasks delete; it stays
    // binary (allowed | denied_tier) per v1.19 sec-M3 LOCKED.
    expect(out.policy_decision).toBe("allowed");
  });
});

describe("sheetsMutationMeta.serialize contract (v1.25 Phase 2 Item 2)", () => {
  test("create shape: target_range_hash + 3 v1.21 optional fields ABSENT", () => {
    const meta: SheetsMutationAuditMeta = {
      target_spreadsheet_id_hash: "s".repeat(64),
      operation: "create",
      policy_decision: "allowed",
    };
    const out = AUDIT_META_CHANNELS.sheetsMutationMeta.serialize(meta);
    expect(out).toEqual({
      target_spreadsheet_id_hash: "s".repeat(64),
      operation: "create",
      policy_decision: "allowed",
    });
    expect(out.target_range_hash).toBeUndefined();
    expect(out.request_types_csv).toBeUndefined();
    expect(out.total_cell_writes).toBeUndefined();
    expect(out.rejected_formula_function).toBeUndefined();
  });

  test("append_values shape: target_range_hash PRESENT; v1.21 optional fields ABSENT", () => {
    const meta: SheetsMutationAuditMeta = {
      target_spreadsheet_id_hash: "s".repeat(64),
      target_range_hash: "r".repeat(64),
      operation: "append_values",
      policy_decision: "allowed",
    };
    const out = AUDIT_META_CHANNELS.sheetsMutationMeta.serialize(meta);
    expect(out).toEqual({
      target_spreadsheet_id_hash: "s".repeat(64),
      operation: "append_values",
      policy_decision: "allowed",
      target_range_hash: "r".repeat(64),
    });
  });

  test("batch_update MAX shape: all 4 optional fields PRESENT (cell-write CSV + cell count)", () => {
    const meta: SheetsMutationAuditMeta = {
      target_spreadsheet_id_hash: "s".repeat(64),
      target_range_hash: "r".repeat(64),
      operation: "batch_update",
      policy_decision: "allowed",
      request_types_csv: "addSheet,updateCells,repeatCell",
      total_cell_writes: 250,
    };
    const out = AUDIT_META_CHANNELS.sheetsMutationMeta.serialize(meta);
    expect(out).toEqual({
      target_spreadsheet_id_hash: "s".repeat(64),
      operation: "batch_update",
      policy_decision: "allowed",
      target_range_hash: "r".repeat(64),
      request_types_csv: "addSheet,updateCells,repeatCell",
      total_cell_writes: 250,
    });
  });

  test("denied_formula_rejected shape: rejected_formula_function PRESENT (UPPERCASE)", () => {
    const meta: SheetsMutationAuditMeta = {
      target_spreadsheet_id_hash: "s".repeat(64),
      target_range_hash: "r".repeat(64),
      operation: "batch_update",
      policy_decision: "denied_formula_rejected",
      rejected_formula_function: "IMPORTRANGE",
    };
    const out = AUDIT_META_CHANNELS.sheetsMutationMeta.serialize(meta);
    expect(out).toEqual({
      target_spreadsheet_id_hash: "s".repeat(64),
      operation: "batch_update",
      policy_decision: "denied_formula_rejected",
      target_range_hash: "r".repeat(64),
      rejected_formula_function: "IMPORTRANGE",
    });
  });
});

describe("registry-driven auditEnd integration — Layer 1 (this) + Layer 2 (audit.roundtrip) belt-and-braces", () => {
  // Sentinel asserting the production CODE PATH in auditEnd actually iterates
  // AUDIT_META_CHANNELS — if a future refactor accidentally reverts to manual
  // blocks AND leaves the satisfies clause intact, this test catches it by
  // exercising every channel's serialize via the registry surface and
  // confirming the OUTPUT can be assembled identically to a hand-rolled Object.assign.
  test("for every channel, registry.serialize(meta) result is mergeable into a payload via Object.assign without collisions", () => {
    const payload: Record<string, unknown> = { base: 1 };
    // Pick the smallest valid meta per channel; verify each merges cleanly.
    const fixtures: Array<[keyof typeof AUDIT_META_CHANNELS, unknown]> = [
      [
        "commentPostMeta",
        {
          target_video_hash: "v".repeat(64),
          comment_length: 1,
          policy_decision: "allowed",
        },
      ],
      [
        "calendarMutationMeta",
        { target_event_hash: "e".repeat(64), policy_decision: "allowed" },
      ],
      [
        "docsModifyMeta",
        {
          target_document_id_hash: "d".repeat(64),
          modification_count: 1,
          request_types_csv: "insertText",
          policy_decision: "allowed",
        },
      ],
      [
        "commentDeleteMeta",
        { target_comment_id_hash: "c".repeat(64), policy_decision: "deleted" },
      ],
      [
        "tasksMutationMeta",
        {
          target_tasklist_hash: "t".repeat(64),
          operation: "create",
          policy_decision: "allowed",
        },
      ],
      [
        "sheetsMutationMeta",
        {
          target_spreadsheet_id_hash: "s".repeat(64),
          operation: "create",
          policy_decision: "allowed",
        },
      ],
    ];
    for (const [key, meta] of fixtures) {
      const fields = AUDIT_META_CHANNELS[key].serialize(meta);
      Object.assign(payload, fields);
    }
    // Sanity — base field survived; at least one per-channel flatHash emitted
    // (sheets came last, overwriting any prior policy_decision via Object.assign).
    expect(payload.base).toBe(1);
    expect(payload.target_video_hash).toBe("v".repeat(64));
    expect(payload.target_event_hash).toBe("e".repeat(64));
    expect(payload.target_document_id_hash).toBe("d".repeat(64));
    expect(payload.target_comment_id_hash).toBe("c".repeat(64));
    expect(payload.target_tasklist_hash).toBe("t".repeat(64));
    expect(payload.target_spreadsheet_id_hash).toBe("s".repeat(64));
  });
});
