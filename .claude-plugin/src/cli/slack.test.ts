// v1.95 — `safespace slack` CLI: set-token reads stdin (NOT argv) and never echoes the
// token; status/clear-token surface state without the value. Mirrors the Discord suite.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { CliError, type CliIO } from "../cli";
import { ENV_SK_ALLOW } from "../policy/slack-recipient-allowlist";
import { runSlackCmd, type SlackCmdDeps } from "./slack";

function captureIO(): { io: CliIO; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return { io: { out: (l) => out.push(l), err: (l) => err.push(l) }, out, err };
}

const saved: Record<string, string | undefined> = {};
const ENV = [ENV_SK_ALLOW, "SAFESPACE_SLACK_BOT_TOKEN", "SAFESPACE_AUTONOMOUS"];
beforeEach(() => {
  for (const k of ENV) saved[k] = process.env[k];
  for (const k of ENV) delete process.env[k];
});
afterEach(() => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
});

describe("safespace slack set-token", () => {
  test("reads the token from stdin, saves it, and NEVER echoes it", async () => {
    let savedTok: string | undefined;
    const TOKEN = "xoxb-1234567890-super-secret-bot-token-ABCdef";
    const deps: SlackCmdDeps = {
      readSecret: async () => TOKEN,
      setToken: async (t) => {
        savedTok = t;
      },
    };
    const cap = captureIO();
    await runSlackCmd(["set-token"], cap.io, deps);
    expect(savedTok).toBe(TOKEN);
    expect([...cap.out, ...cap.err].join("\n")).not.toContain(TOKEN);
    expect(cap.out.join("\n")).toContain(`${TOKEN.length} chars`);
  });

  test("REJECTS a token passed as an argv argument (shell-history leak guard)", async () => {
    let called = false;
    const deps: SlackCmdDeps = { setToken: async () => { called = true; } };
    const cap = captureIO();
    await expect(runSlackCmd(["set-token", "the-token"], cap.io, deps)).rejects.toBeInstanceOf(CliError);
    expect(called).toBe(false);
  });

  test("rejects empty stdin (nothing saved)", async () => {
    let called = false;
    const deps: SlackCmdDeps = {
      readSecret: async () => "   ",
      setToken: async () => { called = true; },
    };
    const cap = captureIO();
    await expect(runSlackCmd(["set-token"], cap.io, deps)).rejects.toBeInstanceOf(CliError);
    expect(called).toBe(false);
  });
});

describe("safespace slack status", () => {
  test("shows configured + allowlist summary, never the token", async () => {
    const deps: SlackCmdDeps = { hasToken: async () => true };
    process.env[ENV_SK_ALLOW] = "C0123456789";
    const cap = captureIO();
    await runSlackCmd(["status"], cap.io, deps);
    const text = cap.out.join("\n");
    expect(text).toContain("configured");
    expect(text).toContain("1 id");
  });

  test("reports not-configured + OFF allowlist", async () => {
    const deps: SlackCmdDeps = { hasToken: async () => false };
    const cap = captureIO();
    await runSlackCmd(["status"], cap.io, deps);
    const text = cap.out.join("\n");
    expect(text).toContain("not configured");
    expect(text).toContain("OFF");
  });
});

describe("safespace slack clear-token / dispatch", () => {
  test("clear-token calls deleteToken", async () => {
    let cleared = false;
    const deps: SlackCmdDeps = { deleteToken: async () => { cleared = true; } };
    const cap = captureIO();
    await runSlackCmd(["clear-token"], cap.io, deps);
    expect(cleared).toBe(true);
  });

  test("no subcommand → CliError (usage)", async () => {
    const cap = captureIO();
    await expect(runSlackCmd([], cap.io, {})).rejects.toBeInstanceOf(CliError);
  });

  test("unknown subcommand → CliError", async () => {
    const cap = captureIO();
    await expect(runSlackCmd(["frobnicate"], cap.io, {})).rejects.toBeInstanceOf(CliError);
  });
});
