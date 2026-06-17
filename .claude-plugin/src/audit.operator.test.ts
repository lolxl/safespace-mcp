// v1.36 BLOCKER 2 (audit actor) -- audit-row `operator` field tests.
//
// The `operator` field is an ALWAYS-PRESENT base field (like `account` /
// `sanitize`), NOT a presence-as-signal optional. It is `null` when no operator
// id is configured (single-user default, Q4) and the plaintext id otherwise
// (Q3). These tests pin: (a) set => plaintext on the row, (b) unset/undefined
// => null AND key present, (c) explicit null => null, (d) it sits beside
// `account` without perturbing the other base fields.
//
// Lives in its own file (NOT audit.test.ts) so the existing audit suite stays
// byte-for-byte unchanged as the regression net (design section 12).

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

describe("auditEnd -- operator field (v1.36 BLOCKER 2)", () => {
  test("operator set => row.operator is the plaintext id", async () => {
    await auditEnd(fakeCtx({ operator: "alice.ops-1" }));
    const r = await readRow();
    expect(r.operator).toBe("alice.ops-1");
  });

  test("operator undefined => row.operator is null AND the key is present", async () => {
    await auditEnd(fakeCtx());
    const r = await readRow();
    expect(r.operator).toBeNull();
    expect("operator" in r).toBe(true); // present-as-null, mirrors `account`
  });

  test("operator explicitly null => row.operator is null", async () => {
    await auditEnd(fakeCtx({ operator: null }));
    const r = await readRow();
    expect(r.operator).toBeNull();
  });

  test("operator sits beside account without perturbing base fields", async () => {
    await auditEnd(fakeCtx({ operator: "bob", email: "bob@example.com" }));
    const r = await readRow();
    expect(r.account).toBe("bob@example.com");
    expect(r.operator).toBe("bob");
    expect(r.tool).toBe("gmail_search");
    expect(r.status).toBe("ok");
    expect(r.args_hash).toBe("sha256:abc123");
  });
});
