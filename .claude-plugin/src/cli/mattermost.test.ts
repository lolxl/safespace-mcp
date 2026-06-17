// v1.107 — `safespace mattermost` CLI: set-token reads stdin (NOT argv) + never echoes the
// token; status surfaces token/server-URL/allowlist state without the token value.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { CliError, type CliIO } from "../cli";
import { ENV_MM_ALLOW } from "../policy/mattermost-recipient-allowlist";
import { ENV_MATTERMOST_SERVER_URL } from "../config";
import { __resetMattermostServerForTests } from "../auth/mattermost/base-url";
import { runMattermostCmd, type MattermostCmdDeps } from "./mattermost";

function captureIO(): { io: CliIO; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return { io: { out: (l) => out.push(l), err: (l) => err.push(l) }, out, err };
}

const saved: Record<string, string | undefined> = {};
const ENV = [ENV_MM_ALLOW, "SAFESPACE_MATTERMOST_BOT_TOKEN", ENV_MATTERMOST_SERVER_URL, "SAFESPACE_AUTONOMOUS"];
beforeEach(() => {
  for (const k of ENV) saved[k] = process.env[k];
  for (const k of ENV) delete process.env[k];
  __resetMattermostServerForTests();
});
afterEach(() => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
  __resetMattermostServerForTests();
});

describe("safespace mattermost set-token", () => {
  test("reads stdin, saves, NEVER echoes the token", async () => {
    let savedTok: string | undefined;
    const TOKEN = "mm-personal-access-token-ABCdef-secret";
    const deps: MattermostCmdDeps = { readSecret: async () => TOKEN, setToken: async (t) => { savedTok = t; } };
    const cap = captureIO();
    await runMattermostCmd(["set-token"], cap.io, deps);
    expect(savedTok).toBe(TOKEN);
    expect([...cap.out, ...cap.err].join("\n")).not.toContain(TOKEN);
  });

  test("REJECTS a token passed as argv (shell-history leak guard)", async () => {
    let called = false;
    const deps: MattermostCmdDeps = { setToken: async () => { called = true; } };
    await expect(runMattermostCmd(["set-token", "tok"], captureIO().io, deps)).rejects.toBeInstanceOf(CliError);
    expect(called).toBe(false);
  });
});

describe("safespace mattermost status", () => {
  test("configured token + valid server URL → shows host, not the token", async () => {
    process.env[ENV_MATTERMOST_SERVER_URL] = "https://mm.example.com";
    __resetMattermostServerForTests();
    const deps: MattermostCmdDeps = { hasToken: async () => true };
    const cap = captureIO();
    await runMattermostCmd(["status"], cap.io, deps);
    const text = cap.out.join("\n");
    expect(text).toContain("configured");
    expect(text).toContain("host: mm.example.com");
  });

  test("unset server URL → reports BLOCKED", async () => {
    const deps: MattermostCmdDeps = { hasToken: async () => false };
    const cap = captureIO();
    await runMattermostCmd(["status"], cap.io, deps);
    const text = cap.out.join("\n");
    expect(text).toContain("not configured");
    expect(text).toContain("BLOCKED");
  });
});

describe("safespace mattermost clear-token / dispatch", () => {
  test("clear-token calls deleteToken", async () => {
    let cleared = false;
    const deps: MattermostCmdDeps = { deleteToken: async () => { cleared = true; } };
    await runMattermostCmd(["clear-token"], captureIO().io, deps);
    expect(cleared).toBe(true);
  });

  test("no / unknown subcommand → CliError", async () => {
    await expect(runMattermostCmd([], captureIO().io, {})).rejects.toBeInstanceOf(CliError);
    await expect(runMattermostCmd(["frob"], captureIO().io, {})).rejects.toBeInstanceOf(CliError);
  });
});
