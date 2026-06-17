// v1.33 Phase 2 (d) -- error_code catch-path forensic GAP-FILL safety net
// (docs section 4.4 + sec-rev hooks #5 #6).
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  auditEnd,
  pickAuditErrorForensics,
  AUDIT_ERROR_FORENSIC_WHITELIST,
  type AuditEndContext,
  type SheetsMutationAuditMeta,
} from "./audit";

let tmpDir: string;
let prevEnv: string | undefined;
beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-audit-eforensics-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
});
afterEach(async () => {
  if (prevEnv === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevEnv;
  await fs.rm(tmpDir, { recursive: true, force: true });
});
function fakeCtx(overrides: Partial<AuditEndContext> = {}): AuditEndContext {
  return { tool: "sheets_update_values", email: "a@example.com", argsHash: "sha256:x", status: "error", durationMs: 5, ...overrides };
}
async function readLatest(): Promise<Record<string, unknown>> {
  const content = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
  const lines = content.split("\n").filter((l) => l.length > 0);
  return JSON.parse(lines[lines.length - 1]!) as Record<string, unknown>;
}

describe("v1.33 (d) -- pickAuditErrorForensics whitelist", () => {
  test("whitelist is exactly the 3 closed-set forensic fields", () => {
    expect([...AUDIT_ERROR_FORENSIC_WHITELIST]).toEqual([
      "rejected_formula_function",
      "rejected_formula_nested",
      "rejected_formula_homoglyph_source",
    ]);
  });
  test("picks ONLY whitelisted fields; drops reason + non-whitelisted PII", () => {
    const out = pickAuditErrorForensics({
      reason: "formula_rejected",
      rejected_formula_function: "IMPORTRANGE",
      rejected_formula_nested: true,
      rejected_formula_homoglyph_source: "x",
      not_whitelisted_pii: "secret@example.com",
    });
    expect(out).toEqual({
      rejected_formula_function: "IMPORTRANGE",
      rejected_formula_nested: true,
      rejected_formula_homoglyph_source: "x",
    });
  });
  test("undefined when no whitelisted field present (PRESENCE-as-signal)", () => {
    expect(pickAuditErrorForensics({ reason: "formula_rejected" })).toBeUndefined();
    expect(pickAuditErrorForensics(undefined)).toBeUndefined();
    expect(pickAuditErrorForensics({})).toBeUndefined();
  });
});

describe("v1.33 (d) -- auditEnd gap-fill", () => {
  test("gap-fills whitelisted forensic fields when NO channel meta recorded", async () => {
    await auditEnd(fakeCtx({
      errorCode: -32029,
      errorForensics: { rejected_formula_function: "IMPORTRANGE", rejected_formula_homoglyph_source: "i" },
    }));
    const row = await readLatest();
    expect(row.error_code).toBe(-32029);
    expect(row.rejected_formula_function).toBe("IMPORTRANGE");
    expect(row.rejected_formula_homoglyph_source).toBe("i");
  });
  test("gap-fill NEVER overwrites a channel-serialize value (collision-safe)", async () => {
    const meta: SheetsMutationAuditMeta = {
      target_spreadsheet_id_hash: "e".repeat(64),
      operation: "update_values",
      policy_decision: "denied_formula_rejected",
      rejected_formula_function: "IMPORTRANGE",
    };
    await auditEnd(fakeCtx({
      sheetsMutationMeta: meta,
      errorCode: -32029,
      errorForensics: { rejected_formula_function: "DIFFERENT" },
    }));
    const row = await readLatest();
    expect(row.rejected_formula_function).toBe("IMPORTRANGE"); // meta wins, NOT "DIFFERENT"
  });
  test("no errorForensics -> row carries no gap-filled fields (byte-stable)", async () => {
    await auditEnd(fakeCtx({ status: "ok", tool: "gmail_search" }));
    const row = await readLatest();
    expect(row.rejected_formula_function).toBeUndefined();
    expect(row.rejected_formula_homoglyph_source).toBeUndefined();
  });
});
