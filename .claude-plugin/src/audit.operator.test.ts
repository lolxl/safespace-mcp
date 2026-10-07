// The audit-row `operator` field: always present and always null since the
// per-operator label (SAFESPACE_OPERATOR_ID) was retired — kept so the row shape
// readers and exports expect does not change.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { auditEnd, type AuditEndContext } from "./audit";

let tmpDir: string;
let prevEnv: string | undefined;

beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-audit-operator-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
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
    durationMs: 12,
    ...overrides,
  };
}

async function readRow(): Promise<Record<string, unknown>> {
  const content = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
  const lines = content.split("\n").filter((l) => l.length > 0);
  return JSON.parse(lines[lines.length - 1]!) as Record<string, unknown>;
}

describe("auditEnd -- operator field", () => {
  test("row.operator is null AND the key is present", async () => {
    await auditEnd(fakeCtx());
    const r = await readRow();
    expect(r.operator).toBeNull();
    expect("operator" in r).toBe(true); // present-as-null, mirrors `account`
    expect(r.account).toBe("alice@example.com");
    expect(r.tool).toBe("gmail_search");
  });
});
