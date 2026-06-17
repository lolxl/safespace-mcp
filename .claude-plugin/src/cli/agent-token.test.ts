// v1.93 A1 — `safespace agent-token` CLI: mint (plaintext shown once, only the
// hash on disk) / list / revoke round-trip + flag validation + missing-env.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { CliError, type CliIO } from "../cli";
import { runAgentTokenCmd } from "./agent-token";

let tmp: string;
let prevConfig: string | undefined;
let prevTokens: string | undefined;

beforeEach(async () => {
  prevConfig = process.env.SAFESPACE_CONFIG_DIR;
  prevTokens = process.env.SAFESPACE_AGENT_TOKENS_FILE;
  tmp = await fs.mkdtemp(path.join(tmpdir(), "agent-token-cli-"));
  process.env.SAFESPACE_CONFIG_DIR = tmp;
  process.env.SAFESPACE_AGENT_TOKENS_FILE = path.join(tmp, "agent-tokens.json");
});
afterEach(async () => {
  if (prevConfig === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevConfig;
  if (prevTokens === undefined) delete process.env.SAFESPACE_AGENT_TOKENS_FILE;
  else process.env.SAFESPACE_AGENT_TOKENS_FILE = prevTokens;
  await fs.rm(tmp, { recursive: true, force: true });
});

function cap(): { io: CliIO; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return { io: { out: (l) => out.push(l), err: (l) => err.push(l) }, out, err };
}

describe("runAgentTokenCmd", () => {
  test("mint prints the plaintext ONCE + stores only the hash", async () => {
    const c = cap();
    await runAgentTokenCmd(["mint", "alice@example.com"], c.io);
    const joined = c.out.join("\n");
    expect(joined).toContain("alice@example.com");
    expect(joined).toContain("ONLY time");
    const tokenLine = c.out.find((l) => /^ {2}\S{20,}$/.test(l));
    expect(tokenLine).toBeDefined();
    const token = tokenLine!.trim();
    const raw = await fs.readFile(process.env.SAFESPACE_AGENT_TOKENS_FILE!, "utf8");
    expect(raw).not.toContain(token); // plaintext never on disk
  });

  test("mint → list → revoke round-trip", async () => {
    await runAgentTokenCmd(["mint", "alice@example.com"], cap().io);
    const cList = cap();
    await runAgentTokenCmd(["list"], cList.io);
    expect(cList.out.join("\n")).toContain("alice@example.com");
    const cRev = cap();
    await runAgentTokenCmd(["revoke", "alice@example.com"], cRev.io);
    expect(cRev.out.join("\n")).toContain("revoked 1");
    const cList2 = cap();
    await runAgentTokenCmd(["list"], cList2.io);
    expect(cList2.out.join("\n")).toContain("no agent tokens");
  });

  test("mint with --expires records the expiry", async () => {
    const c = cap();
    await runAgentTokenCmd(["mint", "alice@example.com", "--expires", "2099-01-01T00:00:00Z"], c.io);
    expect(c.out.join("\n")).toContain("expires 2099-01-01T00:00:00Z");
  });

  test("usage / flag errors → CliError", async () => {
    await expect(runAgentTokenCmd([], cap().io)).rejects.toBeInstanceOf(CliError);
    await expect(runAgentTokenCmd(["bogus"], cap().io)).rejects.toBeInstanceOf(CliError);
    await expect(runAgentTokenCmd(["mint"], cap().io)).rejects.toBeInstanceOf(CliError); // no login
    await expect(runAgentTokenCmd(["mint", "nope"], cap().io)).rejects.toBeInstanceOf(CliError); // bad login
    await expect(runAgentTokenCmd(["mint", "a@x.com", "--expires"], cap().io)).rejects.toBeInstanceOf(CliError);
    await expect(runAgentTokenCmd(["revoke"], cap().io)).rejects.toBeInstanceOf(CliError);
    await expect(runAgentTokenCmd(["list", "extra"], cap().io)).rejects.toBeInstanceOf(CliError);
  });

  test("missing SAFESPACE_AGENT_TOKENS_FILE → CliError", async () => {
    delete process.env.SAFESPACE_AGENT_TOKENS_FILE;
    await expect(runAgentTokenCmd(["list"], cap().io)).rejects.toBeInstanceOf(CliError);
  });
});
