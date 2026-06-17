// v1.66 Phase C PR 2 — `safespace line` CLI: set-token reads stdin (NOT argv) and
// never echoes the token; status/clear-token surface state without the value.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { CliError, type CliIO } from "../cli";
import { ENV_LINE_ALLOW } from "../policy/line-recipient-allowlist";
import { runLineCmd, type LineCmdDeps } from "./line";

function captureIO(): { io: CliIO; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return { io: { out: (l) => out.push(l), err: (l) => err.push(l) }, out, err };
}

const saved: Record<string, string | undefined> = {};
const ENV = [ENV_LINE_ALLOW, "SAFESPACE_LINE_CHANNEL_TOKEN", "SAFESPACE_AUTONOMOUS"];
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

describe("safespace line set-token", () => {
  test("reads the token from stdin, saves it, and NEVER echoes it", async () => {
    let savedTok: string | undefined;
    const TOKEN = "super-secret-channel-token-1234567890";
    const deps: LineCmdDeps = {
      readSecret: async () => TOKEN,
      setToken: async (t) => {
        savedTok = t;
      },
    };
    const cap = captureIO();
    await runLineCmd(["set-token"], cap.io, deps);
    expect(savedTok).toBe(TOKEN);
    // The token value must NEVER appear in any output line.
    expect([...cap.out, ...cap.err].join("\n")).not.toContain(TOKEN);
    // It reports a length hint, not the value.
    expect(cap.out.join("\n")).toContain(`${TOKEN.length} chars`);
  });

  test("REJECTS a token passed as an argv argument (shell-history leak guard)", async () => {
    let called = false;
    const deps: LineCmdDeps = { setToken: async () => { called = true; } };
    const cap = captureIO();
    await expect(runLineCmd(["set-token", "the-token"], cap.io, deps)).rejects.toBeInstanceOf(CliError);
    expect(called).toBe(false);
  });

  test("rejects empty stdin (nothing saved)", async () => {
    let called = false;
    const deps: LineCmdDeps = {
      readSecret: async () => "   ",
      setToken: async () => { called = true; },
    };
    const cap = captureIO();
    await expect(runLineCmd(["set-token"], cap.io, deps)).rejects.toBeInstanceOf(CliError);
    expect(called).toBe(false);
  });
});

describe("safespace line status", () => {
  test("shows configured + allowlist summary, never the token", async () => {
    const deps: LineCmdDeps = { hasToken: async () => true };
    process.env[ENV_LINE_ALLOW] = "U" + "0".repeat(32);
    const cap = captureIO();
    await runLineCmd(["status"], cap.io, deps);
    const text = cap.out.join("\n");
    expect(text).toContain("configured");
    expect(text).toContain("1 id");
  });

  test("reports not-configured + OFF allowlist", async () => {
    const deps: LineCmdDeps = { hasToken: async () => false };
    const cap = captureIO();
    await runLineCmd(["status"], cap.io, deps);
    const text = cap.out.join("\n");
    expect(text).toContain("not configured");
    expect(text).toContain("OFF");
  });
});

describe("safespace line clear-token / dispatch", () => {
  test("clear-token calls deleteToken", async () => {
    let cleared = false;
    const deps: LineCmdDeps = { deleteToken: async () => { cleared = true; } };
    const cap = captureIO();
    await runLineCmd(["clear-token"], cap.io, deps);
    expect(cleared).toBe(true);
  });

  test("no subcommand → CliError (usage)", async () => {
    const cap = captureIO();
    await expect(runLineCmd([], cap.io, {})).rejects.toBeInstanceOf(CliError);
  });

  test("unknown subcommand → CliError", async () => {
    const cap = captureIO();
    await expect(runLineCmd(["frobnicate"], cap.io, {})).rejects.toBeInstanceOf(CliError);
  });
});
