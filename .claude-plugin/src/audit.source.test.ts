// v1.64 Phase B (B0 relabel) — audit-row `source` field tests.
//
// `source` is an ALWAYS-PRESENT base field (the `run_id` / `operator`
// precedent): the safety-gateway Source connector this call belongs to,
// defaulting to "google-workspace" when the ToolDef carries no `source`. These
// pin: (a) it defaults to "google-workspace" + the key is present, (b) an
// explicit source threads through verbatim, (c) it is NOT presence-as-signal —
// present even on error rows and on every tool. ZERO new audit channel.
//
// Own file (NOT audit.test.ts) so the existing audit suite stays byte-stable —
// mirror of audit.run-id.test.ts / audit.operator.test.ts.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { auditEnd, type AuditEndContext } from "./audit";

let tmpDir: string;
let prevEnv: string | undefined;

beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-audit-source-"));
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

describe("auditEnd — source field (v1.64 Phase B / B0)", () => {
  test("defaults to 'google-workspace' when ctx.source is unset; key present", async () => {
    await auditEnd(fakeCtx());
    const r = (await readRows())[0]!;
    expect("source" in r).toBe(true);
    expect(r.source).toBe("google-workspace");
  });

  test("explicit source threads through verbatim (future-connector ready)", async () => {
    await auditEnd(fakeCtx({ source: "telegram-bot" }));
    const r = (await readRows())[0]!;
    expect(r.source).toBe("telegram-bot");
  });

  test("ALWAYS present (not presence-as-signal) — error rows + every tool carry it", async () => {
    await auditEnd(fakeCtx({ tool: "gmail_send", status: "error", errorCode: -32019 }));
    await auditEnd(fakeCtx({ tool: "drive_search" }));
    const rows = await readRows();
    expect(rows).toHaveLength(2);
    expect(rows[0]!.source).toBe("google-workspace");
    expect(rows[1]!.source).toBe("google-workspace");
  });
});
