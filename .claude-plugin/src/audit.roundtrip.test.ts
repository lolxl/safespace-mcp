// v1.22 Phase 1 — audit-meta roundtrip sentinel tests (NEW-3 closure).
//
// Closes the multi-cycle drift class first opened in v1.19 NEW-3:
// `auditEnd()` in src/audit.ts has 4 sync sites for adding/extending an
// audit-meta channel. TS enforces sites 1-3 (registry entry + `localMetas`
// keys + AuditEndContext field). The 4th site — the
// `if (ctx.<channel>Meta !== undefined) { payload.X = m.X; ... }` block in
// `auditEnd()` — is plain runtime code with no forcing function.
//
// v1.19 Phase 2b (tasksMutationMeta) + v1.20 Phase 1b-2 (sheetsMutationMeta
// add) + v1.21 Phase 1b (sheetsMutationMeta 3-field extension) all exercised
// the manual 4th site successfully — but ONLY by manual checklist. The class
// was NOT structurally closed.
//
// Per docs/v1.22-structural-fixes.md §2.1 + Q1 LOCKED Option B: this file
// adds roundtrip tests for ALL 6 audit-meta channels (commentPost /
// calendarMutation / docsModify / commentDelete / tasksMutation /
// sheetsMutation). For each channel we synthesize a meta object with the
// MAX field-set possible for that channel + a contrasting MIN field-set,
// invoke `auditEnd()`, and assert the JSONL row contains EXACTLY the fields
// each shape should emit (PRESENCE) and NONE of the optional fields that
// should be omitted (ABSENCE). This pins the 4th-site contract for the
// observed 6 channels.
//
// Sentinel-of-sentinels: deleting any `payload.X = m.X` line in
// `auditEnd()` causes the corresponding roundtrip test below to fail
// loudly. Future v1.23+ channel additions follow the SAME pattern (add a
// channel entry to AUDIT_META_CHANNELS + a roundtrip test alongside the
// channel's interface). Registry-size sentinel in audit.test.ts already
// forces a count-bump check; this file forces the 4th-site contract.
//
// Note: lives in a separate file from `audit.test.ts` so the file PURPOSE
// (roundtrip contract pinning) is visible from the filename alone. New
// channels in v1.23+ extend THIS file, NOT audit.test.ts.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { auditEnd, type AuditEndContext } from "./audit";

let tmpDir: string;
let prevEnv: string | undefined;

beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-audit-roundtrip-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
});

afterEach(async () => {
  if (prevEnv === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevEnv;
  await fs.rm(tmpDir, { recursive: true, force: true });
});

function fakeCtx(overrides: Partial<AuditEndContext> = {}): AuditEndContext {
  return {
    tool: "placeholder_tool",
    email: "alice@example.com",
    argsHash: "sha256:roundtrip",
    status: "ok",
    durationMs: 100,
    ...overrides,
  };
}

async function readLatestRecord(): Promise<Record<string, unknown>> {
  const content = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
  const lines = content.split("\n").filter((l) => l.length > 0);
  return JSON.parse(lines[lines.length - 1]!) as Record<string, unknown>;
}

// 1) commentPostMeta — v1.16 Phase 2b. 3 required + 1 optional.
describe("auditEnd roundtrip — commentPostMeta (channel 1/6)", () => {
  test("MAX shape (reply, all fields): emits target_video_hash + comment_length + policy_decision + parent_comment_id_hash", async () => {
    const VHASH = "v".repeat(64);
    const PHASH = "p".repeat(64);
    await auditEnd(
      fakeCtx({
        tool: "youtube_comment_reply",
        commentPostMeta: {
          target_video_hash: VHASH,
          parent_comment_id_hash: PHASH,
          comment_length: 123,
          policy_decision: "allowed",
        },
      }),
    );
    const r = await readLatestRecord();
    expect(r.target_video_hash).toBe(VHASH);
    expect(r.parent_comment_id_hash).toBe(PHASH);
    expect(r.comment_length).toBe(123);
    expect(r.policy_decision).toBe("allowed");
  });

  test("MIN shape (top-level post, no parent): parent_comment_id_hash ABSENT", async () => {
    const VHASH = "w".repeat(64);
    await auditEnd(
      fakeCtx({
        tool: "youtube_video_comment_post",
        commentPostMeta: {
          target_video_hash: VHASH,
          comment_length: 7,
          policy_decision: "denied_burst_limit",
        },
      }),
    );
    const r = await readLatestRecord();
    expect(r.target_video_hash).toBe(VHASH);
    expect(r.comment_length).toBe(7);
    expect(r.policy_decision).toBe("denied_burst_limit");
    expect(r.parent_comment_id_hash).toBeUndefined();
    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    expect(raw).not.toContain("parent_comment_id_hash");
  });
});

// 2) calendarMutationMeta — v1.17 Phase 1. 2 required + 1 optional.
describe("auditEnd roundtrip — calendarMutationMeta (channel 2/6)", () => {
  test("MAX shape (calendar_respond, all fields): emits target_event_hash + policy_decision + rsvp_response", async () => {
    const EHASH = "e".repeat(64);
    await auditEnd(
      fakeCtx({
        tool: "calendar_respond",
        calendarMutationMeta: {
          target_event_hash: EHASH,
          policy_decision: "allowed",
          rsvp_response: "tentative",
        },
      }),
    );
    const r = await readLatestRecord();
    expect(r.target_event_hash).toBe(EHASH);
    expect(r.policy_decision).toBe("allowed");
    expect(r.rsvp_response).toBe("tentative");
  });

  test("MIN shape (update/delete, no rsvp_response): rsvp_response ABSENT", async () => {
    const EHASH = "f".repeat(64);
    await auditEnd(
      fakeCtx({
        tool: "calendar_delete_event",
        calendarMutationMeta: {
          target_event_hash: EHASH,
          policy_decision: "denied_tier",
        },
      }),
    );
    const r = await readLatestRecord();
    expect(r.target_event_hash).toBe(EHASH);
    expect(r.policy_decision).toBe("denied_tier");
    expect(r.rsvp_response).toBeUndefined();
    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    expect(raw).not.toContain("rsvp_response");
  });
});

// 3) docsModifyMeta — v1.17 Phase 2. 4 required + 1 optional.
describe("auditEnd roundtrip — docsModifyMeta (channel 3/6)", () => {
  test("MAX shape (with replacements): emits all 5 fields including total_text_replacements", async () => {
    const DHASH = "d".repeat(64);
    const CSV = "insertText,replaceAllText,deleteContentRange";
    await auditEnd(
      fakeCtx({
        tool: "docs_modify_structured",
        docsModifyMeta: {
          target_document_id_hash: DHASH,
          modification_count: 3,
          request_types_csv: CSV,
          total_text_replacements: 12,
          policy_decision: "allowed",
        },
      }),
    );
    const r = await readLatestRecord();
    expect(r.target_document_id_hash).toBe(DHASH);
    expect(r.modification_count).toBe(3);
    expect(r.request_types_csv).toBe(CSV);
    expect(r.total_text_replacements).toBe(12);
    expect(r.policy_decision).toBe("allowed");
  });

  test("MIN shape (no replaceAllText reply): total_text_replacements ABSENT; 4 fields emitted", async () => {
    const DHASH = "0".repeat(64);
    await auditEnd(
      fakeCtx({
        tool: "docs_modify_structured",
        docsModifyMeta: {
          target_document_id_hash: DHASH,
          modification_count: 2,
          request_types_csv: "insertText,updateTextStyle",
          policy_decision: "denied_tier",
        },
      }),
    );
    const r = await readLatestRecord();
    expect(r.target_document_id_hash).toBe(DHASH);
    expect(r.modification_count).toBe(2);
    expect(r.request_types_csv).toBe("insertText,updateTextStyle");
    expect(r.policy_decision).toBe("denied_tier");
    expect(r.total_text_replacements).toBeUndefined();
    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    expect(raw).not.toContain("total_text_replacements");
  });
});

// 4) commentDeleteMeta — v1.17 Phase 3. 2 required, NO optional.
describe("auditEnd roundtrip — commentDeleteMeta (channel 4/6)", () => {
  test("emits target_comment_id_hash + policy_decision (deleted path)", async () => {
    const CHASH = "c".repeat(64);
    await auditEnd(
      fakeCtx({
        tool: "youtube_comment_delete",
        commentDeleteMeta: {
          target_comment_id_hash: CHASH,
          policy_decision: "deleted",
        },
      }),
    );
    const r = await readLatestRecord();
    expect(r.target_comment_id_hash).toBe(CHASH);
    expect(r.policy_decision).toBe("deleted");
    // Mutex sentinel — sibling channel hashes MUST NOT appear.
    expect(r.target_video_hash).toBeUndefined();
    expect(r.target_event_hash).toBeUndefined();
    expect(r.target_document_id_hash).toBeUndefined();
    expect(r.target_tasklist_hash).toBeUndefined();
    expect(r.target_spreadsheet_id_hash).toBeUndefined();
  });

  test("denied_tier shape: same 2 fields emitted; policy_decision discriminates", async () => {
    const CHASH = "9".repeat(64);
    await auditEnd(
      fakeCtx({
        tool: "youtube_comment_delete",
        commentDeleteMeta: {
          target_comment_id_hash: CHASH,
          policy_decision: "denied_tier",
        },
      }),
    );
    const r = await readLatestRecord();
    expect(r.target_comment_id_hash).toBe(CHASH);
    expect(r.policy_decision).toBe("denied_tier");
  });
});

// 5) tasksMutationMeta — v1.19 Phase 2b. 3 required + 1 optional.
describe("auditEnd roundtrip — tasksMutationMeta (channel 5/6)", () => {
  test("create shape: target_task_hash ABSENT (no task ID yet at create time)", async () => {
    const TLHASH = "1".repeat(64);
    await auditEnd(
      fakeCtx({
        tool: "tasks_create",
        tasksMutationMeta: {
          target_tasklist_hash: TLHASH,
          operation: "create",
          policy_decision: "allowed",
        },
      }),
    );
    const r = await readLatestRecord();
    expect(r.target_tasklist_hash).toBe(TLHASH);
    expect(r.operation).toBe("create");
    expect(r.policy_decision).toBe("allowed");
    expect(r.target_task_hash).toBeUndefined();
    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    expect(raw).not.toContain("target_task_hash");
  });

  test("update shape: target_task_hash PRESENT; all 4 fields emitted", async () => {
    const TLHASH = "2".repeat(64);
    const THASH = "3".repeat(64);
    await auditEnd(
      fakeCtx({
        tool: "tasks_update",
        tasksMutationMeta: {
          target_tasklist_hash: TLHASH,
          target_task_hash: THASH,
          operation: "update",
          policy_decision: "allowed",
        },
      }),
    );
    const r = await readLatestRecord();
    expect(r.target_tasklist_hash).toBe(TLHASH);
    expect(r.target_task_hash).toBe(THASH);
    expect(r.operation).toBe("update");
    expect(r.policy_decision).toBe("allowed");
  });

  test("delete shape: target_task_hash PRESENT; operation==='delete' (NOT policy_decision==='deleted' per sec-M3)", async () => {
    const TLHASH = "4".repeat(64);
    const THASH = "5".repeat(64);
    await auditEnd(
      fakeCtx({
        tool: "tasks_delete",
        tasksMutationMeta: {
          target_tasklist_hash: TLHASH,
          target_task_hash: THASH,
          operation: "delete",
          policy_decision: "allowed",
        },
      }),
    );
    const r = await readLatestRecord();
    expect(r.target_tasklist_hash).toBe(TLHASH);
    expect(r.target_task_hash).toBe(THASH);
    expect(r.operation).toBe("delete");
    expect(r.policy_decision).toBe("allowed");
  });
});

// 6) sheetsMutationMeta — v1.20 Phase 1b-2 + v1.21 Phase 1b extended.
//    3 required + 4 optional. Multi-op channel — test each operation enum
//    value separately since the field-PRESENCE shape varies per op.
describe("auditEnd roundtrip — sheetsMutationMeta (channel 6/6)", () => {
  test("create shape: target_range_hash ABSENT; only the 3 required fields", async () => {
    const SHASH = "a".repeat(64);
    await auditEnd(
      fakeCtx({
        tool: "sheets_create",
        sheetsMutationMeta: {
          target_spreadsheet_id_hash: SHASH,
          operation: "create",
          policy_decision: "allowed",
        },
      }),
    );
    const r = await readLatestRecord();
    expect(r.target_spreadsheet_id_hash).toBe(SHASH);
    expect(r.operation).toBe("create");
    expect(r.policy_decision).toBe("allowed");
    expect(r.target_range_hash).toBeUndefined();
    expect(r.request_types_csv).toBeUndefined();
    expect(r.total_cell_writes).toBeUndefined();
    expect(r.rejected_formula_function).toBeUndefined();
    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    expect(raw).not.toContain("target_range_hash");
    expect(raw).not.toContain("request_types_csv");
    expect(raw).not.toContain("total_cell_writes");
    expect(raw).not.toContain("rejected_formula_function");
  });

  test("append_values shape: target_range_hash PRESENT; v1.21 optional fields ABSENT", async () => {
    const SHASH = "b".repeat(64);
    const RHASH = "c".repeat(64);
    await auditEnd(
      fakeCtx({
        tool: "sheets_append_values",
        sheetsMutationMeta: {
          target_spreadsheet_id_hash: SHASH,
          target_range_hash: RHASH,
          operation: "append_values",
          policy_decision: "allowed",
        },
      }),
    );
    const r = await readLatestRecord();
    expect(r.target_spreadsheet_id_hash).toBe(SHASH);
    expect(r.target_range_hash).toBe(RHASH);
    expect(r.operation).toBe("append_values");
    expect(r.policy_decision).toBe("allowed");
    expect(r.request_types_csv).toBeUndefined();
    expect(r.total_cell_writes).toBeUndefined();
    expect(r.rejected_formula_function).toBeUndefined();
  });

  test("update_values shape: target_range_hash PRESENT; v1.21 optional fields ABSENT (no batch CSV)", async () => {
    const SHASH = "d".repeat(64);
    const RHASH = "e".repeat(64);
    await auditEnd(
      fakeCtx({
        tool: "sheets_update_values",
        sheetsMutationMeta: {
          target_spreadsheet_id_hash: SHASH,
          target_range_hash: RHASH,
          operation: "update_values",
          policy_decision: "allowed",
        },
      }),
    );
    const r = await readLatestRecord();
    expect(r.target_spreadsheet_id_hash).toBe(SHASH);
    expect(r.target_range_hash).toBe(RHASH);
    expect(r.operation).toBe("update_values");
    expect(r.policy_decision).toBe("allowed");
    expect(r.request_types_csv).toBeUndefined();
    expect(r.total_cell_writes).toBeUndefined();
    expect(r.rejected_formula_function).toBeUndefined();
  });

  test("batch_update MAX shape: request_types_csv + total_cell_writes PRESENT (CSV preserves caller ORDER)", async () => {
    const SHASH = "f".repeat(64);
    const RHASH = "0".repeat(64);
    // ORDER sentinel — preserve caller order; sorting would yield
    // [addSheet, repeatCell, updateCells].
    const CSV_IN_ORDER = "updateCells,addSheet,repeatCell";
    await auditEnd(
      fakeCtx({
        tool: "sheets_batch_update",
        sheetsMutationMeta: {
          target_spreadsheet_id_hash: SHASH,
          target_range_hash: RHASH,
          operation: "batch_update",
          policy_decision: "allowed",
          request_types_csv: CSV_IN_ORDER,
          total_cell_writes: 256,
        },
      }),
    );
    const r = await readLatestRecord();
    expect(r.target_spreadsheet_id_hash).toBe(SHASH);
    expect(r.target_range_hash).toBe(RHASH);
    expect(r.operation).toBe("batch_update");
    expect(r.policy_decision).toBe("allowed");
    expect(r.request_types_csv).toBe(CSV_IN_ORDER);
    expect(r.total_cell_writes).toBe(256);
    expect(r.rejected_formula_function).toBeUndefined();
    // ORDER proof at raw-bytes layer (sorting would re-arrange).
    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    expect(raw).toContain(`"request_types_csv":"${CSV_IN_ORDER}"`);
  });

  test("batch_update MIN shape: pure structural batch (addSheet only) — request_types_csv PRESENT but total_cell_writes ABSENT", async () => {
    const SHASH = "1".repeat(64);
    const RHASH = "2".repeat(64);
    await auditEnd(
      fakeCtx({
        tool: "sheets_batch_update",
        sheetsMutationMeta: {
          target_spreadsheet_id_hash: SHASH,
          target_range_hash: RHASH,
          operation: "batch_update",
          policy_decision: "allowed",
          request_types_csv: "addSheet,deleteSheet",
        },
      }),
    );
    const r = await readLatestRecord();
    expect(r.request_types_csv).toBe("addSheet,deleteSheet");
    expect(r.total_cell_writes).toBeUndefined();
    expect(r.rejected_formula_function).toBeUndefined();
    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    expect(raw).not.toContain("total_cell_writes");
    expect(raw).not.toContain("rejected_formula_function");
  });

  test("denied_formula_rejected shape: rejected_formula_function PRESENT (UPPERCASE function name)", async () => {
    const SHASH = "3".repeat(64);
    const RHASH = "4".repeat(64);
    await auditEnd(
      fakeCtx({
        tool: "sheets_update_values",
        status: "error",
        sheetsMutationMeta: {
          target_spreadsheet_id_hash: SHASH,
          target_range_hash: RHASH,
          operation: "update_values",
          policy_decision: "denied_formula_rejected",
          rejected_formula_function: "IMPORTRANGE",
        },
      }),
    );
    const r = await readLatestRecord();
    expect(r.status).toBe("error");
    expect(r.target_spreadsheet_id_hash).toBe(SHASH);
    expect(r.target_range_hash).toBe(RHASH);
    expect(r.operation).toBe("update_values");
    expect(r.policy_decision).toBe("denied_formula_rejected");
    expect(r.rejected_formula_function).toBe("IMPORTRANGE");
    expect(r.request_types_csv).toBeUndefined();
    expect(r.total_cell_writes).toBeUndefined();
    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    expect(raw).toContain(`"rejected_formula_function":"IMPORTRANGE"`);
  });

  test("denied_tier shape: only the 3 required fields; ALL 4 optional fields ABSENT", async () => {
    const SHASH = "5".repeat(64);
    await auditEnd(
      fakeCtx({
        tool: "sheets_batch_update",
        status: "error",
        sheetsMutationMeta: {
          target_spreadsheet_id_hash: SHASH,
          operation: "batch_update",
          policy_decision: "denied_tier",
        },
      }),
    );
    const r = await readLatestRecord();
    expect(r.target_spreadsheet_id_hash).toBe(SHASH);
    expect(r.operation).toBe("batch_update");
    expect(r.policy_decision).toBe("denied_tier");
    expect(r.target_range_hash).toBeUndefined();
    expect(r.request_types_csv).toBeUndefined();
    expect(r.total_cell_writes).toBeUndefined();
    expect(r.rejected_formula_function).toBeUndefined();
  });
});

// v1.24 Phase 1 Item 2 — error_code field stamping roundtrip (Q3 LOCKED).
//
// auditEnd extends to write `error_code: <number>` when ctx.errorCode is
// defined (PRESENCE-as-signal mirror of v1.15 Phase 3 resolved_recipient_hash
// + v1.16 Phase 2b commentPostMeta patterns). Plain Error throws (or success
// rows) leave errorCode undefined, so the field stays ABSENT from the JSONL
// row — pre-v1.24 downstream consumers continue parsing rows untouched.
//
// The PRESENCE/ABSENCE invariants are pinned BELOW so a regression that
// always-emits (e.g., `payload.error_code = ctx.errorCode ?? null`) fails
// loudly. Mirrors the v1.15 / v1.16 PRESENCE patterns.
describe("auditEnd roundtrip — errorCode field (v1.24 Phase 1 Item 2)", () => {
  test("PRESENT when errorCode is set on an error row (-32025 comment_burst_limit_exceeded)", async () => {
    await auditEnd(
      fakeCtx({
        tool: "youtube_video_comment_post",
        status: "error",
        errorCode: -32025,
      }),
    );
    const r = await readLatestRecord();
    expect(r.status).toBe("error");
    expect(r.error_code).toBe(-32025);
  });

  test("PRESENT when errorCode is set on an error row (-32026 search_burst_limit_exceeded)", async () => {
    await auditEnd(
      fakeCtx({
        tool: "youtube_search",
        status: "error",
        errorCode: -32026,
      }),
    );
    const r = await readLatestRecord();
    expect(r.error_code).toBe(-32026);
  });

  test("PRESENT when errorCode is set on an error row (-32007 scope_mismatch per design §2.2 table)", async () => {
    // NOTE: -32007 is what the design + v1.23 suspicious.ts forward-compat
    // safety net checks for. The actual MCPError `scope_mismatch` code in
    // src/errors.ts is -32004; the v1.23 code reference to -32007 was a
    // documented detection gap. This roundtrip pins the literal value used
    // by suspicious.ts so the safety net activation is a property of the
    // auditEnd contract.
    await auditEnd(
      fakeCtx({
        tool: "tasks_get",
        status: "error",
        errorCode: -32007,
      }),
    );
    const r = await readLatestRecord();
    expect(r.error_code).toBe(-32007);
  });

  test("PRESENT when errorCode is set on an error row (-32022 recipient_lookup_failed)", async () => {
    await auditEnd(
      fakeCtx({
        tool: "gmail_send",
        status: "error",
        errorCode: -32022,
      }),
    );
    const r = await readLatestRecord();
    expect(r.error_code).toBe(-32022);
  });

  test("ABSENT on success rows (status === 'ok')", async () => {
    await auditEnd(
      fakeCtx({
        tool: "gmail_search",
        status: "ok",
        // errorCode intentionally OMITTED — success path leaves it undefined.
      }),
    );
    const r = await readLatestRecord();
    expect(r.status).toBe("ok");
    expect(r.error_code).toBeUndefined();
    const raw = await readLatestRawLine();
    expect(raw).not.toContain("error_code");
  });

  test("ABSENT on error rows where errorCode is undefined (plain Error catch path)", async () => {
    // Simulates with-context.ts catching a plain `Error` rather than an
    // MCPError — errorCode stays undefined; auditEnd skips the field.
    await auditEnd(
      fakeCtx({
        tool: "gmail_search",
        status: "error",
        // errorCode intentionally OMITTED.
      }),
    );
    const r = await readLatestRecord();
    expect(r.status).toBe("error");
    expect(r.error_code).toBeUndefined();
    const raw = await readLatestRawLine();
    expect(raw).not.toContain("error_code");
  });

  test("co-exists with other meta fields (errorCode + commentPostMeta on a denied row)", async () => {
    const VHASH = "z".repeat(64);
    await auditEnd(
      fakeCtx({
        tool: "youtube_video_comment_post",
        status: "error",
        errorCode: -32025,
        commentPostMeta: {
          target_video_hash: VHASH,
          comment_length: 200,
          policy_decision: "denied_burst_limit",
        },
      }),
    );
    const r = await readLatestRecord();
    expect(r.error_code).toBe(-32025);
    expect(r.target_video_hash).toBe(VHASH);
    expect(r.comment_length).toBe(200);
    expect(r.policy_decision).toBe("denied_burst_limit");
  });
});

async function readLatestRawLine(): Promise<string> {
  const content = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
  const lines = content.split("\n").filter((l) => l.length > 0);
  return lines[lines.length - 1]!;
}
