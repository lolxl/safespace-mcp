// v1.99 — `safespace send` CLI: list (shows id / tool / recipient / body preview), approve
// (flips a pending record → approved), deny (removes it), and the arg-validation errors. A tmp
// SAFESPACE_CONFIG_DIR holds the pending-sends.json.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { type CliIO } from "../cli";
import { computeFingerprint, createPending, loadPendingSends, pendingSendsPath } from "../auth/send-approval-store";
import { runSendCmd } from "./send";

let tmp: string;
let prevConfig: string | undefined;

beforeEach(async () => {
  prevConfig = process.env.SAFESPACE_CONFIG_DIR;
  tmp = await fs.mkdtemp(path.join(tmpdir(), "send-cli-"));
  process.env.SAFESPACE_CONFIG_DIR = tmp;
});
afterEach(async () => {
  if (prevConfig === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevConfig;
  await fs.rm(tmp, { recursive: true, force: true });
});

function cap(): { io: CliIO; out: string[] } {
  const out: string[] = [];
  return { io: { out: (l) => out.push(l), err: (l) => out.push(l) }, out };
}

async function seed(body = "hello world"): Promise<string> {
  const fp = computeFingerprint("gmail_send", ["alice@x.com"], body, "");
  return createPending(
    pendingSendsPath(),
    { fingerprint: fp, tool: "gmail_send", recipients: ["alice@x.com"], body, operator: "" },
    Date.now(),
    60_000,
  );
}

describe("runSendCmd", () => {
  test("list (empty) → (no pending sends)", async () => {
    const c = cap();
    await runSendCmd(["list"], c.io);
    expect(c.out.join("\n")).toContain("no pending sends");
  });

  test("list shows id / tool / recipient / body preview", async () => {
    const id = await seed("hello world");
    const c = cap();
    await runSendCmd(["list"], c.io);
    const joined = c.out.join("\n");
    expect(joined).toContain(id);
    expect(joined).toContain("gmail_send");
    expect(joined).toContain("alice@x.com");
    expect(joined).toContain("hello world");
    expect(joined).not.toContain("target:");
  });

  test("list prints a typed public-write target the owner can see", async () => {
    const fp = computeFingerprint("x_post_create", [], "hello world", "", { kind: "x_post", account_id: "12345" });
    const id = await createPending(
      pendingSendsPath(),
      {
        fingerprint: fp,
        tool: "x_post_create",
        recipients: [],
        body: "hello world",
        operator: "",
        target: { kind: "x_post", account_id: "12345" },
      },
      Date.now(),
      60_000,
    );
    const c = cap();
    await runSendCmd(["list"], c.io);
    const joined = c.out.join("\n");
    expect(joined).toContain(id);
    expect(joined).toContain("x_post_create");
    expect(joined).toContain("target: account_id=12345");
  });

  test("approve flips the record to approved", async () => {
    const id = await seed();
    const c = cap();
    await runSendCmd(["approve", id], c.io);
    expect(c.out.join("\n")).toContain("approved");
    const recs = await loadPendingSends(pendingSendsPath(), Date.now());
    expect(recs[0]!.status).toBe("approved");
  });

  test("deny removes the record", async () => {
    const id = await seed();
    const c = cap();
    await runSendCmd(["deny", id], c.io);
    expect(c.out.join("\n")).toContain("denied");
    expect(await loadPendingSends(pendingSendsPath(), Date.now())).toHaveLength(0);
  });

  test("approve a non-existent id → friendly message, no crash", async () => {
    const c = cap();
    await runSendCmd(["approve", "f".repeat(32)], c.io);
    expect(c.out.join("\n")).toContain("no pending send");
  });

  test("unknown subcommand / missing id → CliError", async () => {
    const c = cap();
    await expect(runSendCmd(["bogus"], c.io)).rejects.toThrow(/unknown send subcommand/);
    await expect(runSendCmd(["approve"], c.io)).rejects.toThrow(/requires exactly/);
  });
});
