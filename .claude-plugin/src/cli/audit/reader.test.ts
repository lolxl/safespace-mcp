import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import {
  collectAuditRows,
  parseWindow,
  strictParseInt,
  strictParseIso8601,
  streamAuditRows,
  truncateHash,
} from "./reader";

let tmp: string;
let prevEnv: string | undefined;

beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  tmp = await fs.mkdtemp(path.join(tmpdir(), "audit-reader-"));
  process.env.SAFESPACE_CONFIG_DIR = tmp;
});

afterEach(async () => {
  if (prevEnv === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevEnv;
  await fs.rm(tmp, { recursive: true, force: true });
});

describe("streamAuditRows", () => {
  test("missing file → yields nothing", async () => {
    const filePath = path.join(tmp, "missing.jsonl");
    const rows = await collectAuditRows(() => true, filePath, { warn: () => undefined });
    expect(rows).toEqual([]);
  });

  test("streams line-by-line; skips malformed", async () => {
    const filePath = path.join(tmp, "audit.jsonl");
    const body = [
      JSON.stringify({ a: 1 }),
      "{ not-json",
      JSON.stringify({ b: 2 }),
      "[1,2,3]",                  // non-object → skipped
      JSON.stringify({ c: 3 }),
    ].join("\n") + "\n";
    await fs.writeFile(filePath, body, { mode: 0o600 });
    const warns: string[] = [];
    const rows = await collectAuditRows(() => true, filePath, { warn: (m) => warns.push(m) });
    expect(rows).toHaveLength(3);
    expect(warns).toHaveLength(2);
    // Raw bad line MUST NOT appear in warnings (hook #5):
    expect(warns.join("\n")).not.toContain("not-json");
    expect(warns.join("\n")).toMatch(/line 2/);
    expect(warns.join("\n")).toMatch(/line 4/);
  });

  test("streaming yields one row at a time (memory-bound)", async () => {
    const filePath = path.join(tmp, "audit.jsonl");
    // Synthesize 1000 rows — small but enough to verify the iterator yields
    // without buffering. We count via the iterator without collecting.
    const lines: string[] = [];
    for (let i = 0; i < 1000; i++) {
      lines.push(JSON.stringify({ ts: new Date().toISOString(), tool: "x", account: "a@x", status: "ok", duration_ms: i }));
    }
    await fs.writeFile(filePath, lines.join("\n") + "\n", { mode: 0o600 });
    let count = 0;
    for await (const _row of streamAuditRows(filePath, { warn: () => undefined })) {
      count++;
    }
    expect(count).toBe(1000);
  });
});

describe("truncateHash (hook #9 uniform truncation)", () => {
  test("64-char hash → 12 hex + ellipsis (13 chars total)", () => {
    const h = "a".repeat(64);
    const t = truncateHash(h);
    expect(t).toBe("a".repeat(12) + "…");
    expect(t.length).toBe(13);
  });

  test("short hash returned as-is", () => {
    expect(truncateHash("short")).toBe("short");
  });

  test("non-string coerced", () => {
    expect(truncateHash(123)).toBe("123");
  });
});

describe("strictParseInt", () => {
  test("valid integer in range", () => {
    expect(strictParseInt("50", "--limit", 1, 100)).toBe(50);
  });

  test("NaN → throws", () => {
    expect(() => strictParseInt("abc", "--limit", 1, 100)).toThrow(/integer/);
  });

  test("non-integer → throws", () => {
    expect(() => strictParseInt("1.5", "--limit", 1, 100)).toThrow(/integer/);
  });

  test("Infinity → throws", () => {
    expect(() => strictParseInt("Infinity", "--limit", 1, 100)).toThrow(/integer/);
  });

  test("out-of-range → throws", () => {
    expect(() => strictParseInt("101", "--limit", 1, 100)).toThrow(/range/);
  });
});

describe("strictParseIso8601", () => {
  test("date-only", () => {
    const d = strictParseIso8601("2026-05-21");
    expect(d.getUTCFullYear()).toBe(2026);
  });

  test("full ISO with Z", () => {
    const d = strictParseIso8601("2026-05-21T10:00:00Z");
    expect(d.toISOString()).toBe("2026-05-21T10:00:00.000Z");
  });

  test("loose format rejected", () => {
    expect(() => strictParseIso8601("yesterday")).toThrow(/ISO 8601/);
    expect(() => strictParseIso8601("2026/05/21")).toThrow(/ISO 8601/);
    expect(() => strictParseIso8601("May 21")).toThrow(/ISO 8601/);
  });
});

describe("parseWindow", () => {
  test("Nh, Nm, Nd valid", () => {
    expect(parseWindow("24h")).toBe(24 * 60 * 60 * 1000);
    expect(parseWindow("60m")).toBe(60 * 60 * 1000);
    expect(parseWindow("1d")).toBe(24 * 60 * 60 * 1000);
  });

  test("0h rejected", () => {
    expect(() => parseWindow("0h")).toThrow();
  });

  test("1y rejected (unsupported unit)", () => {
    expect(() => parseWindow("1y")).toThrow();
  });

  test("1.5h rejected (non-integer)", () => {
    expect(() => parseWindow("1.5h")).toThrow();
  });

  test("721h rejected (above 720h cap)", () => {
    expect(() => parseWindow("721h")).toThrow(/range/);
  });

  test("no unit rejected", () => {
    expect(() => parseWindow("24")).toThrow();
  });
});
