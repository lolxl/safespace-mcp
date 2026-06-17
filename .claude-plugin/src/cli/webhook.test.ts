// v1.102 (W0) — `safespace webhook` CLI: provider validation, stdin-only secret,
// set/status/clear via injected seams, never echoing the secret.

import { describe, expect, test } from "bun:test";
import type { CliIO } from "../cli";
import { runWebhookCmd, type WebhookCmdDeps } from "./webhook";

function fakeIo(): { io: CliIO; lines: string[] } {
  const lines: string[] = [];
  return { io: { out: (s) => lines.push(s), err: (s) => lines.push(s) }, lines };
}

describe("runWebhookCmd", () => {
  test("set-secret slack saves the stdin secret (never echoed) and confirms by length", async () => {
    const saved: Array<{ p: string; s: string }> = [];
    const deps: WebhookCmdDeps = { readSecret: async () => "  sign-secret-xyz  ", setSecret: async (p, s) => void saved.push({ p, s }) };
    const { io, lines } = fakeIo();
    await runWebhookCmd(["set-secret", "slack"], io, deps);
    expect(saved).toEqual([{ p: "slack", s: "sign-secret-xyz" }]);
    expect(lines.join("\n")).toContain("15 chars");
    expect(lines.join("\n")).not.toContain("sign-secret-xyz");
  });

  test("set-secret with no provider → error", async () => {
    const { io } = fakeIo();
    await expect(runWebhookCmd(["set-secret"], io, { readSecret: async () => "x" })).rejects.toThrow(/provider/);
  });

  test("set-secret with an un-wired provider → error naming the expected set", async () => {
    const { io } = fakeIo();
    // telegram is a WebhookProvider type but NOT wired in the listener (W2) → rejected.
    await expect(runWebhookCmd(["set-secret", "telegram"], io, { readSecret: async () => "x" })).rejects.toThrow(/slack, line/);
  });

  test("set-secret rejects a secret passed on argv (shell-history leak guard)", async () => {
    const { io } = fakeIo();
    await expect(runWebhookCmd(["set-secret", "slack", "the-secret"], io, { readSecret: async () => "x" })).rejects.toThrow(/stdin/);
  });

  test("set-secret with empty stdin → error, nothing saved", async () => {
    const saved: string[] = [];
    const { io } = fakeIo();
    await expect(runWebhookCmd(["set-secret", "slack"], io, { readSecret: async () => "   ", setSecret: async (_p, s) => void saved.push(s) })).rejects.toThrow(/empty/);
    expect(saved).toHaveLength(0);
  });

  test("status slack reports configured + the env-override state, never the secret", async () => {
    const { io, lines } = fakeIo();
    await runWebhookCmd(["status", "slack"], io, { hasSecret: async () => true });
    const out = lines.join("\n");
    expect(out).toContain("slack webhook signing secret: configured");
    expect(out).toContain("SAFESPACE_SLACK_WEBHOOK_SECRET");
  });

  test("status with no provider covers every wired provider (slack + line)", async () => {
    const checked: string[] = [];
    const { io } = fakeIo();
    await runWebhookCmd(["status"], io, { hasSecret: async (p) => (checked.push(p), false) });
    expect(checked).toEqual(["slack", "line"]);
  });

  test("clear-secret slack deletes via the store", async () => {
    const cleared: string[] = [];
    const { io, lines } = fakeIo();
    await runWebhookCmd(["clear-secret", "slack"], io, { deleteSecret: async (p) => void cleared.push(p) });
    expect(cleared).toEqual(["slack"]);
    expect(lines.join("\n")).toContain("removed");
  });

  test("unknown subcommand → error", async () => {
    const { io } = fakeIo();
    await expect(runWebhookCmd(["frobnicate"], io)).rejects.toThrow(/unknown webhook subcommand/);
  });

  test("no subcommand → usage", async () => {
    const { io } = fakeIo();
    await expect(runWebhookCmd([], io)).rejects.toThrow(/usage: safespace webhook/);
  });
});
