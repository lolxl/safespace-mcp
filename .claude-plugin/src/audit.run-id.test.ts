// v1.58 F5 — audit-row `run_id` field tests.
//
// `run_id` is an ALWAYS-PRESENT base field (like `operator` / `account`): a
// per-PROCESS random id stamped on every row, the session grouping key for
// `safespace audit sessions`. These pin: (a) it is present + matches getRunId(),
// (b) it is STABLE across rows in the same process (same run = same id), (c) it
// is 16 hex chars (the sanitize-nonce shape), carrying no PII.
//
// Own file (NOT audit.test.ts) so the existing audit suite stays byte-stable.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { auditEnd, getRunId, type AuditEndContext } from "./audit";

let tmpDir: string;
let prevEnv: string | undefined;

beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-audit-runid-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
});
afterEach(async () => {
  if (prevEnv === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevEnv;
  await fs.rm(tmpDir, { recursive: true, force: true });
});

function fakeCtx(over: Partial<AuditEndContext> = {}): AuditEndContext {
  return { tool: "gmail_search", email: "a@example.com", argsHash: "sha256:x", status: "ok", durationMs: 1, ...over };
}

async function readRows(): Promise<Array<Record<string, unknown>>> {
  const content = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
  return content.split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l));
}

describe("auditEnd — run_id field (v1.58 F5)", () => {
  test("every row carries run_id === getRunId(), present + 16 hex", async () => {
    await auditEnd(fakeCtx());
    const r = (await readRows())[0]!;
    expect("run_id" in r).toBe(true);
    expect(r.run_id).toBe(getRunId());
    expect(r.run_id).toMatch(/^[0-9a-f]{16}$/);
  });

  test("run_id is STABLE across rows in the same process (same run → same id)", async () => {
    await auditEnd(fakeCtx({ tool: "gmail_send" }));
    await auditEnd(fakeCtx({ tool: "drive_search", status: "error" }));
    const rows = await readRows();
    expect(rows).toHaveLength(2);
    expect(rows[0]!.run_id).toBe(rows[1]!.run_id);
    expect(rows[0]!.run_id).toBe(getRunId());
  });
});
