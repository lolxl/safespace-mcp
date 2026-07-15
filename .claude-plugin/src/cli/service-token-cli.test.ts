// Additive unit tests for makeServiceTokenCommands (pack-aware CLI factory).

import { describe, expect, test } from "bun:test";
import { CliError, type CliIO } from "../cli";
import { LINE_PACK } from "../tools/service-token-pack";
import {
  makeServiceTokenCommands,
  type ServiceTokenCmdDeps,
} from "./service-token-cli";

function captureIO(): { io: CliIO; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return { io: { out: (l) => out.push(l), err: (l) => err.push(l) }, out, err };
}

const commands = makeServiceTokenCommands(LINE_PACK, {
  allowlistSummary: () => ({ kind: "off", id_count: 0 }),
});

describe("makeServiceTokenCommands(LINE_PACK)", () => {
  test("set-token saves via storeKey deps and never echoes the token", async () => {
    let savedTok: string | undefined;
    const TOKEN = "pack-cli-secret-token-xyz";
    const deps: ServiceTokenCmdDeps = {
      readSecret: async () => TOKEN,
      setToken: async (t) => {
        savedTok = t;
      },
    };
    const cap = captureIO();
    await commands.run(["set-token"], cap.io, deps);
    expect(savedTok).toBe(TOKEN);
    expect([...cap.out, ...cap.err].join("\n")).not.toContain(TOKEN);
    expect(cap.out.join("\n")).toContain("LINE channel access token saved");
    expect(cap.out.join("\n")).toContain(`${TOKEN.length} chars`);
  });

  test("status surfaces tokenLabel + OFF allowlist", async () => {
    const deps: ServiceTokenCmdDeps = { hasToken: async () => false };
    const cap = captureIO();
    await commands.run(["status"], cap.io, deps);
    const text = cap.out.join("\n");
    expect(text).toContain("LINE channel access token: not configured");
    expect(text).toContain("OFF");
    expect(text).toContain("all valid ids allowed");
  });

  test("unknown subcommand / no subcommand → CliError with line usage", async () => {
    const cap = captureIO();
    await expect(commands.run([], cap.io, {})).rejects.toBeInstanceOf(CliError);
    await expect(commands.run(["frobnicate"], cap.io, {})).rejects.toBeInstanceOf(CliError);
    try {
      await commands.run(["frobnicate"], cap.io, {});
    } catch (e) {
      expect(String(e)).toContain("unknown line subcommand");
      expect(String(e)).toContain("safespace line");
    }
  });
});
