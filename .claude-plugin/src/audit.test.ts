import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  AUDIT_META_CHANNELS,
  auditCrossAccountAggregate,
  auditEnd,
  auditStart,
  __resetChainState,
  type AuditEndContext,
} from "./audit";

let tmpDir: string;
let prevEnv: string | undefined;

beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-audit-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  // v1.89 — the hash-chain `lastMac` is module-global; reset so each test starts a
  // fresh chain matching its fresh tmpDir (else a prior test's tip leaks in).
  __resetChainState();
});

afterEach(async () => {
  if (prevEnv === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevEnv;
  await fs.rm(tmpDir, { recursive: true, force: true });
});

function fakeCtx(overrides: Partial<AuditEndContext> = {}): AuditEndContext {
  return {
    tool: "gmail_search",
    email: "alice@example.com",
    argsHash: "sha256:abc123",
    status: "ok",
    durationMs: 143,
    ...overrides,
  };
}

async function readJsonl(): Promise<Array<Record<string, unknown>>> {
  const content = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
  return content
    .split("\n")
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}

describe("audit — auditStart (no-op stub)", () => {
  test("does not throw and does not create the audit file", async () => {
    auditStart({ tool: "gmail_search", email: "alice@example.com", argsHash: "sha256:x" });
    await expect(fs.stat(path.join(tmpDir, "audit.jsonl"))).rejects.toMatchObject({ code: "ENOENT" });
  });
});

describe("audit — auditEnd JSONL append", () => {
  test("writes one line with the canonical shape", async () => {
    await auditEnd(fakeCtx());
    const records = await readJsonl();
    expect(records).toHaveLength(1);
    const r = records[0]!;
    expect(r.tool).toBe("gmail_search");
    expect(r.account).toBe("alice@example.com");
    expect(r.args_hash).toBe("sha256:abc123");
    expect(r.status).toBe("ok");
    expect(r.duration_ms).toBe(143);
    expect(typeof r.ts).toBe("string");
    // ISO 8601 with Z suffix
    expect(r.ts).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  });

  test("does NOT include token, raw args, or response content", async () => {
    await auditEnd(fakeCtx({ argsHash: "sha256:no_raw_args_here" }));
    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    // Negative assertions — these field names must never appear.
    expect(raw).not.toContain("access_token");
    expect(raw).not.toContain("refresh_token");
    expect(raw).not.toContain("ya29.");
    expect(raw).not.toContain("Bearer ");
    expect(raw).not.toContain("query");
    expect(raw).not.toContain("body");
    expect(raw).not.toContain("content");
  });

  test("multiple calls append (does not truncate)", async () => {
    await auditEnd(fakeCtx({ tool: "gmail_search" }));
    await auditEnd(fakeCtx({ tool: "drive_search" }));
    await auditEnd(fakeCtx({ tool: "gmail_get_message", status: "error" }));
    const records = await readJsonl();
    expect(records).toHaveLength(3);
    expect(records.map((r) => r.tool)).toEqual(["gmail_search", "drive_search", "gmail_get_message"]);
    expect(records[2]!.status).toBe("error");
  });

  test("audit file is mode 0o600", async () => {
    await auditEnd(fakeCtx());
    const stat = await fs.stat(path.join(tmpDir, "audit.jsonl"));
    expect(stat.mode & 0o777).toBe(0o600);
  });

  test("creates the config dir if missing", async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
    // auditEnd should mkdir -p the dir before appending.
    await auditEnd(fakeCtx());
    const records = await readJsonl();
    expect(records).toHaveLength(1);
  });

  test("swallows I/O errors (best-effort) — does not throw", async () => {
    // Portable unwritable-path trick: create a regular file, then point
    // SAFESPACE_CONFIG_DIR at a child UNDER the file. mkdir-recursive
    // hits ENOTDIR on both macOS and Linux (reviewer 5.8 LOW #3).
    const blocker = path.join(tmpDir, "not-a-dir");
    await fs.writeFile(blocker, "");
    process.env.SAFESPACE_CONFIG_DIR = path.join(blocker, "child");
    // Must NOT throw — caller in with-context.ts uses `void auditEnd(...)`
    // in finally; an unhandled rejection would crash the runtime.
    await expect(auditEnd(fakeCtx())).resolves.toBeUndefined();
  });

  test("status=error records the failure shape (Step 6 regression guard)", async () => {
    await auditEnd(fakeCtx({ status: "error", durationMs: 5000 }));
    const records = await readJsonl();
    expect(records).toHaveLength(1);
    expect(records[0]!.status).toBe("error");
    expect(records[0]!.duration_ms).toBe(5000);
  });

  test("concurrent calls produce N lines, no partial / interleaved records", async () => {
    // appendFile is atomic for small writes on POSIX; 10 parallel calls
    // should yield exactly 10 well-formed JSON lines.
    const writes: Array<Promise<void>> = [];
    for (let i = 0; i < 10; i++) {
      writes.push(auditEnd(fakeCtx({ tool: `tool_${i}` })));
    }
    await Promise.all(writes);
    const records = await readJsonl();
    expect(records).toHaveLength(10);
    // Every line parsed successfully → no partial corruption.
    const tools = records.map((r) => r.tool).sort();
    const expected = Array.from({ length: 10 }, (_, i) => `tool_${i}`).sort();
    expect(tools).toEqual(expected);
  });

  test("JSON line is well-formed and terminates with \\n", async () => {
    await auditEnd(fakeCtx());
    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    expect(raw.endsWith("\n")).toBe(true);
    // Removing the trailing \n should give exactly one parseable JSON.
    expect(() => JSON.parse(raw.slice(0, -1))).not.toThrow();
  });

  test("sanitize field defaults to 'applied' when not specified", async () => {
    await auditEnd(fakeCtx());
    const records = await readJsonl();
    expect(records[0]!.sanitize).toBe("applied");
  });

  test("sanitize field records 'bypassed' when caller specifies", async () => {
    await auditEnd(fakeCtx({ sanitize: "bypassed" }));
    const records = await readJsonl();
    expect(records[0]!.sanitize).toBe("bypassed");
  });

  test("sanitize field is grep-able as a JSON token (regression guard)", async () => {
    await auditEnd(fakeCtx({ sanitize: "bypassed" }));
    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    // Exact substring used in docs / runbook for filtering --raw usage.
    expect(raw).toContain('"sanitize":"bypassed"');
  });

  // v1.15 Phase 3 — resolved_recipient_hash audit field. Schema-presence
  // test sentinels the design contract per audit.ts's `resolvedRecipientHash`
  // field comment + docs/v1.15-contacts-api.md §9 step 5.
  test("resolved_recipient_hash absent when handler did not set it (default — no contact-lookup occurred)", async () => {
    await auditEnd(fakeCtx());
    const records = await readJsonl();
    expect(records[0]!.resolved_recipient_hash).toBeUndefined();
    // Defense-in-depth: even the raw bytes do not contain the field name —
    // proves the field is OMITTED, not serialized as null.
    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    expect(raw).not.toContain("resolved_recipient_hash");
  });

  test("resolved_recipient_hash emitted as JSON field when handler set it (Phase 3 contact-lookup occurred)", async () => {
    const HASH = "a".repeat(64); // 64-char hex SHA-256 stand-in
    await auditEnd(fakeCtx({ resolvedRecipientHash: HASH }));
    const records = await readJsonl();
    expect(records[0]!.resolved_recipient_hash).toBe(HASH);
    // Grep-able JSON token for log readers.
    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    expect(raw).toContain(`"resolved_recipient_hash":"${HASH}"`);
  });

  // v1.16 Phase 2b — commentPostMeta conditional field-emission. Schema-presence
  // tests sentinel the design contract per audit.ts's `commentPostMeta` field
  // comment + docs/v1.16-youtube-api.md §7 (Phase 2 audit).
  //
  // Mirrors v1.15 Phase 3 `resolved_recipient_hash` test pattern above: tests
  // 3 shapes — (a) absent → no key serialized, (b) present without
  // parent_comment_id_hash → top-level post shape, (c) present with
  // parent_comment_id_hash → reply shape.
  test("commentPostMeta absent → no target_video_hash / comment_length / policy_decision / parent_comment_id_hash keys in audit row", async () => {
    await auditEnd(fakeCtx());
    const records = await readJsonl();
    expect(records[0]!.target_video_hash).toBeUndefined();
    expect(records[0]!.comment_length).toBeUndefined();
    expect(records[0]!.policy_decision).toBeUndefined();
    expect(records[0]!.parent_comment_id_hash).toBeUndefined();
    // Defense-in-depth: the raw bytes do not contain any of the field names —
    // proves the keys are OMITTED, not serialized as null.
    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    expect(raw).not.toContain("target_video_hash");
    expect(raw).not.toContain("comment_length");
    expect(raw).not.toContain("policy_decision");
    expect(raw).not.toContain("parent_comment_id_hash");
  });

  test("commentPostMeta present without parent_comment_id_hash → 3 keys present, parent_comment_id_hash absent (top-level comment shape)", async () => {
    const VHASH = "a".repeat(64);
    await auditEnd(
      fakeCtx({
        tool: "youtube_video_comment_post",
        commentPostMeta: {
          target_video_hash: VHASH,
          comment_length: 42,
          policy_decision: "allowed",
        },
      }),
    );
    const records = await readJsonl();
    const r = records[0]!;
    expect(r.target_video_hash).toBe(VHASH);
    expect(r.comment_length).toBe(42);
    expect(r.policy_decision).toBe("allowed");
    // Top-level comment-post — parent_comment_id_hash MUST NOT appear.
    expect(r.parent_comment_id_hash).toBeUndefined();
    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    expect(raw).not.toContain("parent_comment_id_hash");
    // Grep-able JSON tokens for log readers.
    expect(raw).toContain(`"target_video_hash":"${VHASH}"`);
    expect(raw).toContain(`"policy_decision":"allowed"`);
  });

  test("commentPostMeta present with parent_comment_id_hash → all 4 keys present (reply shape)", async () => {
    const VHASH = "b".repeat(64);
    const PHASH = "c".repeat(64);
    await auditEnd(
      fakeCtx({
        tool: "youtube_comment_reply",
        commentPostMeta: {
          target_video_hash: VHASH,
          parent_comment_id_hash: PHASH,
          comment_length: 17,
          policy_decision: "denied_outbound_sanitize_rejected",
        },
      }),
    );
    const records = await readJsonl();
    const r = records[0]!;
    expect(r.target_video_hash).toBe(VHASH);
    expect(r.parent_comment_id_hash).toBe(PHASH);
    expect(r.comment_length).toBe(17);
    expect(r.policy_decision).toBe("denied_outbound_sanitize_rejected");
    // Grep-able tokens for log readers.
    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    expect(raw).toContain(`"parent_comment_id_hash":"${PHASH}"`);
    expect(raw).toContain(`"policy_decision":"denied_outbound_sanitize_rejected"`);
  });

  // v1.17 Phase 1 — calendarMutationMeta conditional field-emission. Mirror
  // of the v1.16 Phase 2b commentPostMeta tests above. Tests 3 shapes:
  //   (a) absent          → no target_event_hash / policy_decision keys
  //   (b) present allowed → both keys present with policy_decision="allowed"
  //   (c) present error   → both keys still present on status=error rows
  //                         (hook #7 forensic-survives-SDK-failure)
  test("calendarMutationMeta absent → no target_event_hash / policy_decision keys in audit row", async () => {
    await auditEnd(fakeCtx());
    const records = await readJsonl();
    expect(records[0]!.target_event_hash).toBeUndefined();
    expect(records[0]!.policy_decision).toBeUndefined();
    // Defense-in-depth: raw bytes do not contain the field names.
    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    expect(raw).not.toContain("target_event_hash");
    expect(raw).not.toContain("policy_decision");
  });

  test("calendarMutationMeta present with policy_decision=allowed → both keys present", async () => {
    const EHASH = "1".repeat(64);
    await auditEnd(
      fakeCtx({
        tool: "calendar_update_event",
        calendarMutationMeta: {
          target_event_hash: EHASH,
          policy_decision: "allowed",
        },
      }),
    );
    const records = await readJsonl();
    const r = records[0]!;
    expect(r.target_event_hash).toBe(EHASH);
    expect(r.policy_decision).toBe("allowed");
    // commentPostMeta-only fields MUST NOT appear (the two metas are
    // mutually exclusive per call).
    expect(r.target_video_hash).toBeUndefined();
    expect(r.comment_length).toBeUndefined();
    expect(r.parent_comment_id_hash).toBeUndefined();
    // Grep-able JSON tokens for log readers.
    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    expect(raw).toContain(`"target_event_hash":"${EHASH}"`);
    expect(raw).toContain(`"policy_decision":"allowed"`);
  });

  test("calendarMutationMeta present on status=error row → both keys still present (hook #7 forensic-survives-failure)", async () => {
    // Mirrors v1.15 Phase 3 hook #7 lesson: handler records meta BEFORE the
    // SDK call so a 5xx response still produces an audit row with the
    // target_event_hash + policy_decision. The with-context.ts finally
    // block ensures auditEnd fires even on error.
    const EHASH = "2".repeat(64);
    await auditEnd(
      fakeCtx({
        tool: "calendar_delete_event",
        status: "error",
        calendarMutationMeta: {
          target_event_hash: EHASH,
          policy_decision: "allowed", // SDK call was attempted but failed
        },
      }),
    );
    const records = await readJsonl();
    const r = records[0]!;
    expect(r.status).toBe("error");
    expect(r.target_event_hash).toBe(EHASH);
    expect(r.policy_decision).toBe("allowed");
  });

  // PR #138 sec-M1 — rsvp_response field PRESENCE-as-signal. Emitted ONLY by
  // calendar_respond; absent on update / delete rows. Validates closed-enum
  // emission across all 4 accepted values + absence sentinel on update.
  test("rsvp_response PRESENCE — present when meta sets it (calendar_respond); absent when meta omits it (update/delete)", async () => {
    const EHASH_RESPOND = "a".repeat(64);
    const EHASH_UPDATE = "b".repeat(64);

    // (a) calendar_respond row: rsvp_response is set; field appears in row.
    await auditEnd(
      fakeCtx({
        tool: "calendar_respond",
        calendarMutationMeta: {
          target_event_hash: EHASH_RESPOND,
          policy_decision: "allowed",
          rsvp_response: "accepted",
        },
      }),
    );

    // (b) calendar_update_event row: rsvp_response NOT set; field absent.
    await auditEnd(
      fakeCtx({
        tool: "calendar_update_event",
        calendarMutationMeta: {
          target_event_hash: EHASH_UPDATE,
          policy_decision: "allowed",
        },
      }),
    );

    const records = await readJsonl();
    expect(records).toHaveLength(2);
    expect(records[0]!.tool).toBe("calendar_respond");
    expect(records[0]!.rsvp_response).toBe("accepted");
    expect(records[1]!.tool).toBe("calendar_update_event");
    expect(records[1]!.rsvp_response).toBeUndefined();

    // Defense-in-depth: raw bytes show field present for respond, absent for update.
    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    const lines = raw.split("\n").filter((l) => l.length > 0);
    expect(lines[0]).toContain(`"rsvp_response":"accepted"`);
    expect(lines[1]).not.toContain("rsvp_response");
  });

  test("rsvp_response — all 4 enum values pass through unmodified", async () => {
    const values: Array<"accepted" | "declined" | "tentative" | "needsAction"> = [
      "accepted",
      "declined",
      "tentative",
      "needsAction",
    ];
    for (const v of values) {
      await auditEnd(
        fakeCtx({
          tool: "calendar_respond",
          calendarMutationMeta: {
            target_event_hash: "c".repeat(64),
            policy_decision: "allowed",
            rsvp_response: v,
          },
        }),
      );
    }
    const records = await readJsonl();
    expect(records.map((r) => r.rsvp_response)).toEqual(values);
  });

  // v1.17 Phase 2 — docsModifyMeta conditional field-emission. Mirrors the
  // commentPostMeta / calendarMutationMeta PRESENCE-as-signal pattern. Tests
  // 3 shapes:
  //   (a) absent                      → no target_document_id_hash /
  //                                     modification_count / request_types_csv /
  //                                     policy_decision keys
  //   (b) present w/ replacements     → all 5 fields including
  //                                     total_text_replacements
  //   (c) present w/o replacements    → 4 fields (no total_text_replacements
  //                                     — the ABSENCE itself is forensically
  //                                     meaningful: "no replaceAllText
  //                                     executed" vs "executed and changed N")
  test("docsModifyMeta absent → no target_document_id_hash / modification_count / request_types_csv keys in audit row", async () => {
    await auditEnd(fakeCtx());
    const records = await readJsonl();
    expect(records[0]!.target_document_id_hash).toBeUndefined();
    expect(records[0]!.modification_count).toBeUndefined();
    expect(records[0]!.request_types_csv).toBeUndefined();
    expect(records[0]!.total_text_replacements).toBeUndefined();
    // Defense-in-depth: raw bytes do not contain the field names.
    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    expect(raw).not.toContain("target_document_id_hash");
    expect(raw).not.toContain("modification_count");
    expect(raw).not.toContain("request_types_csv");
    expect(raw).not.toContain("total_text_replacements");
  });

  test("docsModifyMeta present WITH total_text_replacements → all 5 fields emitted; request_types_csv preserves CALLER-SUPPLIED ORDER", async () => {
    const DHASH = "d".repeat(64);
    // ORDER sentinel — CSV preserves [insertText, replaceAllText,
    // deleteContentRange] verbatim; sorting would produce
    // [deleteContentRange, insertText, replaceAllText]. Per design §5 + F15
    // order is forensically relevant ("did replaceAllText run before or
    // after deleteContentRange?").
    const CSV_IN_ORDER = "insertText,replaceAllText,deleteContentRange";
    await auditEnd(
      fakeCtx({
        tool: "docs_modify_structured",
        docsModifyMeta: {
          target_document_id_hash: DHASH,
          modification_count: 3,
          request_types_csv: CSV_IN_ORDER,
          total_text_replacements: 12,
          policy_decision: "allowed",
        },
      }),
    );
    const records = await readJsonl();
    const r = records[0]!;
    expect(r.target_document_id_hash).toBe(DHASH);
    expect(r.modification_count).toBe(3);
    expect(r.request_types_csv).toBe(CSV_IN_ORDER);
    expect(r.total_text_replacements).toBe(12);
    expect(r.policy_decision).toBe("allowed");
    // Mutually exclusive with the other 2 metas — neither must appear.
    expect(r.target_event_hash).toBeUndefined();
    expect(r.target_video_hash).toBeUndefined();
    expect(r.rsvp_response).toBeUndefined();
    expect(r.comment_length).toBeUndefined();
    // Grep-able tokens for log readers; raw bytes prove ORDER preservation.
    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    expect(raw).toContain(`"request_types_csv":"${CSV_IN_ORDER}"`);
    expect(raw).toContain(`"total_text_replacements":12`);
  });

  test("docsModifyMeta present WITHOUT total_text_replacements (e.g., tier-denial / SDK failure pre-reply) → 4 fields emitted; total_text_replacements ABSENT", async () => {
    // Per design §5 + hook #12: ABSENCE of total_text_replacements is
    // forensically meaningful — distinguishes "no replaceAllText executed"
    // from "executed and changed N occurrences". On denied_tier rows the
    // SDK never ran (no reply to sum); on SDK 5xx rows the pre-SDK meta
    // (which set policy_decision: "allowed" but not the count) survives.
    const DHASH = "e".repeat(64);
    await auditEnd(
      fakeCtx({
        tool: "docs_modify_structured",
        status: "error",
        docsModifyMeta: {
          target_document_id_hash: DHASH,
          modification_count: 2,
          request_types_csv: "insertText,updateTextStyle",
          policy_decision: "denied_tier",
        },
      }),
    );
    const records = await readJsonl();
    const r = records[0]!;
    expect(r.status).toBe("error");
    expect(r.target_document_id_hash).toBe(DHASH);
    expect(r.modification_count).toBe(2);
    expect(r.request_types_csv).toBe("insertText,updateTextStyle");
    expect(r.policy_decision).toBe("denied_tier");
    expect(r.total_text_replacements).toBeUndefined();
    // Defense-in-depth: ABSENCE proof at raw-bytes level (the key is the
    // forensic signal per design §5).
    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    expect(raw).not.toContain("total_text_replacements");
  });
});

describe("audit — auditCrossAccountAggregate (v1.14 Phase 1)", () => {
  test("writes one line with the cross_account_aggregate shape", async () => {
    await auditCrossAccountAggregate({
      tool: "gmail_search_all",
      argsHash: "sha256:outer-hash",
      accountCountQueried: 4,
      accountCountSucceeded: 3,
      accountCountFailed: 1,
    });
    const records = await readJsonl();
    expect(records).toHaveLength(1);
    const r = records[0]!;
    expect(r.tool).toBe("gmail_search_all");
    expect(r.event).toBe("cross_account_aggregate");
    expect(r.args_hash).toBe("sha256:outer-hash");
    expect(r.account_count_queried).toBe(4);
    expect(r.account_count_succeeded).toBe(3);
    expect(r.account_count_failed).toBe(1);
    expect(r.ts).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    // NEVER an `account` field on the outer aggregate (identities live on
    // inner rows; outer is integer counts only — anti-enumeration).
    expect(r).not.toHaveProperty("account");
  });

  test("event field is grep-able (forensic correlation)", async () => {
    await auditCrossAccountAggregate({
      tool: "gmail_search_all",
      argsHash: "sha256:x",
      accountCountQueried: 0,
      accountCountSucceeded: 0,
      accountCountFailed: 0,
    });
    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    expect(raw).toContain('"event":"cross_account_aggregate"');
  });

  test("multiple aggregate calls append (does not truncate)", async () => {
    await auditCrossAccountAggregate({
      tool: "gmail_search_all",
      argsHash: "sha256:1",
      accountCountQueried: 2,
      accountCountSucceeded: 2,
      accountCountFailed: 0,
    });
    await auditCrossAccountAggregate({
      tool: "gmail_search_all",
      argsHash: "sha256:2",
      accountCountQueried: 1,
      accountCountSucceeded: 0,
      accountCountFailed: 1,
    });
    const records = await readJsonl();
    expect(records).toHaveLength(2);
    expect(records[0]!.args_hash).toBe("sha256:1");
    expect(records[1]!.args_hash).toBe("sha256:2");
  });
});

/* ──────────────────────────────────────────────────────────────────────
 *  v1.18 Phase 1 — AUDIT_META_CHANNELS registry sentinel
 *  v1.19 Phase 2b — bumped 4 → 5 (`tasksMutationMeta`) + registry value
 *  shape refactored from bare `string` to `{label, flatHash}` (sec-L4
 *  drift class closure — see docs/v1.19-tasks-api.md §6 path (b)).
 *  v1.20 Phase 1b-2 — bumped 5 → 6 (`sheetsMutationMeta`). FIRST production
 *  test of v1.19 path-(b) registry refactor — `cli/audit/policy-decisions.ts`
 *  auto-discovers the new channel via `entry.flatHash` with ZERO code edit.
 *
 *  Bumping this length without adding the corresponding `localMetas` key
 *  + ctx recorder + AuditEndContext field + auditEnd payload write block
 *  would break the 7-channel mutual-exclusion runtime assertion in
 *  `with-context.ts`. The test fails loudly so the maintainer
 *  re-acknowledges all 4 call sites before shipping.
 * ────────────────────────────────────────────────────────────────────── */
describe("AUDIT_META_CHANNELS registry", () => {
  test("has exactly 8 entries (9th channel requires updating localMetas + AuditEndContext + auditEnd payload write)", () => {
    // v1.48 B4 — added playlistMutationMeta (7th channel).
    // v1.106 — added videoMutationMeta (8th channel; youtube_video_update).
    expect(Object.keys(AUDIT_META_CHANNELS).length).toBe(8);
  });

  test("maps the 8 known ctx-side keys to {label, flatHash} (suspiciousDecisions pinned separately in audit.suspicious-decisions.test.ts)", () => {
    // v1.24 Phase 1 Item 1 — registry value shape extended from
    // {label, flatHash} to {label, flatHash, suspiciousDecisions?}. The
    // `label` + `flatHash` invariant stays asserted here; the new
    // `suspiciousDecisions` shape is pinned in the dedicated sentinel
    // test file so the two contracts can evolve independently.
    const labels: Record<string, { label: string; flatHash: string }> = {};
    for (const [key, entry] of Object.entries(AUDIT_META_CHANNELS)) {
      labels[key] = { label: entry.label, flatHash: entry.flatHash };
    }
    expect(labels).toEqual({
      commentPostMeta: { label: "commentPost", flatHash: "target_video_hash" },
      calendarMutationMeta: { label: "calendarMutation", flatHash: "target_event_hash" },
      docsModifyMeta: { label: "docsModify", flatHash: "target_document_id_hash" },
      commentDeleteMeta: { label: "commentDelete", flatHash: "target_comment_id_hash" },
      tasksMutationMeta: { label: "tasksMutation", flatHash: "target_tasklist_hash" },
      sheetsMutationMeta: { label: "sheetsMutation", flatHash: "target_spreadsheet_id_hash" },
      playlistMutationMeta: { label: "playlistMutation", flatHash: "target_playlist_hash" },
      videoMutationMeta: { label: "videoMutation", flatHash: "target_video_hash" },
    });
  });
});
