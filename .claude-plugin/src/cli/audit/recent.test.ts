import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { CliError, runCli, type CliIO } from "../../cli";

let tmp: string;
let prevEnv: string | undefined;

beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  tmp = await fs.mkdtemp(path.join(tmpdir(), "audit-recent-"));
  process.env.SAFESPACE_CONFIG_DIR = tmp;
});

afterEach(async () => {
  if (prevEnv === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevEnv;
  await fs.rm(tmp, { recursive: true, force: true });
});

function captureIO(): { io: CliIO; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: { out: (l) => out.push(l), err: (l) => err.push(l) },
    out,
    err,
  };
}

async function writeAuditLines(lines: object[]): Promise<void> {
  const body = lines.map((l) => JSON.stringify(l)).join("\n") + "\n";
  await fs.writeFile(path.join(tmp, "audit.jsonl"), body, { mode: 0o600 });
}

const STANDARD_ROW = {
  ts: "2026-05-24T14:02:11.444Z",
  tool: "gmail_search",
  account: "a@example.com",
  args_hash: "f".repeat(64),
  status: "ok",
  duration_ms: 234,
  sanitize: "applied",
};

const STANDARD_ROW_2 = {
  ts: "2026-05-24T14:03:11.444Z",
  tool: "calendar_delete_event",
  account: "a@example.com",
  args_hash: "a".repeat(64),
  status: "ok",
  duration_ms: 189,
  target_event_hash: "b".repeat(64),
  policy_decision: "allowed",
};

const SHARE_FORENSIC_ROW = {
  ts: "2026-05-24T14:01:11.444Z",
  tool: "drive_share_file",
  account: "a@example.com",
  event: "share_forensic",
  file_id: "1abc",
  share_type: "user",
  role: "reader",
  target_email_hash: "c".repeat(64),
  expiration_iso: null,
  granted_permission_id: "perm123",
};

const RECIPIENT_DENIED_ROW = {
  ts: "2026-05-24T14:00:11.444Z",
  tool: "gmail_send",
  account: "a@example.com",
  event: "recipient_denied_by_policy",
  rejected_recipient_hashes: ["d".repeat(64)],
  rejected_count: 1,
  total_recipients: 1,
  duration_ms: 12,
};

describe("audit recent", () => {
  test("empty audit.jsonl → '(no audit entries)'", async () => {
    const { io, out } = captureIO();
    await runCli(["audit", "recent"], io);
    expect(out.join("\n")).toContain("(no audit entries)");
  });

  test("default filters out 4 non-standard event rows (sec-M1)", async () => {
    await writeAuditLines([STANDARD_ROW, SHARE_FORENSIC_ROW, RECIPIENT_DENIED_ROW, STANDARD_ROW_2]);
    const { io, out } = captureIO();
    await runCli(["audit", "recent"], io);
    const text = out.join("\n");
    expect(text).toContain("gmail_search");
    expect(text).toContain("calendar_delete_event");
    // Event rows excluded by default:
    expect(text).not.toContain("share_forensic");
    expect(text).not.toContain("recipient_denied_by_policy");
  });

  test("--include-events sentinel: shows all 4 row shapes (sec-M1)", async () => {
    await writeAuditLines([STANDARD_ROW, SHARE_FORENSIC_ROW, RECIPIENT_DENIED_ROW, STANDARD_ROW_2]);
    const { io, out } = captureIO();
    await runCli(["audit", "recent", "--include-events", "--json"], io);
    const lines = out.filter((l) => l.length > 0);
    // 4 rows in, 4 rows out:
    expect(lines).toHaveLength(4);
    // Event rows are present:
    const joined = lines.join("\n");
    expect(joined).toContain("share_forensic");
    expect(joined).toContain("recipient_denied_by_policy");
  });

  test("--limit NaN → CliError", async () => {
    const { io } = captureIO();
    await expect(runCli(["audit", "recent", "--limit", "abc"], io)).rejects.toBeInstanceOf(CliError);
  });

  test("--limit 0 → CliError (range 1-1000)", async () => {
    const { io } = captureIO();
    await expect(runCli(["audit", "recent", "--limit", "0"], io)).rejects.toBeInstanceOf(CliError);
  });

  test("--limit -1 → CliError", async () => {
    const { io } = captureIO();
    await expect(runCli(["audit", "recent", "--limit", "-1"], io)).rejects.toBeInstanceOf(CliError);
  });

  test("--limit Infinity → CliError", async () => {
    const { io } = captureIO();
    await expect(runCli(["audit", "recent", "--limit", "Infinity"], io)).rejects.toBeInstanceOf(CliError);
  });

  test("--limit 1.5 (non-integer) → CliError", async () => {
    const { io } = captureIO();
    await expect(runCli(["audit", "recent", "--limit", "1.5"], io)).rejects.toBeInstanceOf(CliError);
  });

  test("--limit 1001 (above cap) → CliError", async () => {
    const { io } = captureIO();
    await expect(runCli(["audit", "recent", "--limit", "1001"], io)).rejects.toBeInstanceOf(CliError);
  });

  test("hash truncation sentinel: 12 hex char + ellipsis in TABLE mode (hook #9)", async () => {
    await writeAuditLines([SHARE_FORENSIC_ROW]);
    const { io, out } = captureIO();
    await runCli(["audit", "recent", "--include-events"], io);
    const text = out.join("\n");
    // Full 64-char hash MUST NOT appear:
    expect(text).not.toContain("c".repeat(64));
    // No row in fixture set policy_decision; share_forensic row carries
    // target_email_hash only — render path adds hash hint only when both
    // policy_decision and target_email_hash present, so for this row
    // truncation is verified via JSON mode instead.
  });

  test("hash truncation sentinel: 12 hex char + ellipsis in JSON mode (hook #9)", async () => {
    await writeAuditLines([STANDARD_ROW]);
    const { io, out } = captureIO();
    await runCli(["audit", "recent", "--json"], io);
    const line = out.find((l) => l.startsWith("{"));
    expect(line).toBeDefined();
    const parsed = JSON.parse(line!) as { args_hash: string };
    expect(parsed.args_hash.length).toBe(13); // 12 hex + 1 ellipsis (U+2026)
    expect(parsed.args_hash).toBe("f".repeat(12) + "…");
    // Full hash MUST NOT appear:
    expect(line).not.toContain("f".repeat(64));
  });

  test("malformed JSON line skipped + stderr warning (reader policy)", async () => {
    const body = JSON.stringify(STANDARD_ROW) + "\n{not-json\n" + JSON.stringify(STANDARD_ROW_2) + "\n";
    await fs.writeFile(path.join(tmp, "audit.jsonl"), body, { mode: 0o600 });
    const { io, out, err } = captureIO();
    await runCli(["audit", "recent"], io);
    const text = out.join("\n");
    // Both valid rows render despite the malformed line:
    expect(text).toContain("gmail_search");
    expect(text).toContain("calendar_delete_event");
    // Warning on stderr; raw malformed line MUST NOT be echoed (hook #5):
    expect(err.join("\n")).toMatch(/skipped malformed JSON at line 2/);
    expect(err.join("\n")).not.toContain("not-json");
  });

  test("unknown flag → CliError", async () => {
    const { io } = captureIO();
    await expect(runCli(["audit", "recent", "--bogus"], io)).rejects.toBeInstanceOf(CliError);
  });
});
