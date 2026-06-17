// v1.78/v1.79 — `--provider notion` dispatch on the OAuth-account commands. v1.79
// multi-workspace: account-list shows all + the active marker; account-switch/revoke take a
// <id-or-name> positional.
//
// The full consent NETWORK flow is covered by auth/notion/consent.test.ts (injected
// fetch/open); here we test the CLI surface that needs NO network: account-list /
// account-switch / account-revoke against the notion store, --provider parsing, and the
// consent pre-network guard (missing NOTION_CLIENT_ID throws before any network).

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { runCli, type CliIO } from "../cli";
import {
  __resetNotionBackendForTests,
  addNotionAccount,
  readNotionAccounts,
  readNotionActiveWorkspace,
  readNotionToken,
  writeNotionToken,
} from "../auth/notion/oauth";

const WS_A = "11111111-1111-1111-1111-111111111111";
const WS_B = "22222222-2222-2222-2222-222222222222";

let tmpDir: string;
const saved: Record<string, string | undefined> = {};
const ENV = [
  "SAFESPACE_CONFIG_DIR",
  "SAFESPACE_SECRET_BACKEND",
  "SAFESPACE_OPERATOR_ID",
  "SAFESPACE_SECRET_PASSPHRASE",
  "NOTION_CLIENT_ID",
  "NOTION_CLIENT_SECRET",
];

beforeEach(async () => {
  for (const k of ENV) saved[k] = process.env[k];
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-clint-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  process.env.SAFESPACE_SECRET_BACKEND = "file";
  delete process.env.SAFESPACE_OPERATOR_ID;
  delete process.env.SAFESPACE_SECRET_PASSPHRASE;
  delete process.env.NOTION_CLIENT_ID;
  delete process.env.NOTION_CLIENT_SECRET;
  __resetNotionBackendForTests();
});

afterEach(async () => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
  __resetNotionBackendForTests();
  await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
});

function captureIO(): { io: CliIO; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return { io: { out: (l) => out.push(l), err: (l) => err.push(l) }, out, err };
}

async function seed(workspaceId: string, workspaceName: string, token = "ntn_x"): Promise<void> {
  await addNotionAccount({ workspaceId, workspaceName });
  await writeNotionToken(workspaceId, token);
}

describe("--provider parsing (notion)", () => {
  test("--provider bogus → CliError naming the three providers", async () => {
    const { io } = captureIO();
    await expect(runCli(["account-list", "--provider", "bogus"], io)).rejects.toThrow(
      /--provider must be 'google', 'github', or 'notion'/,
    );
  });
});

describe("account-list --provider notion (multi)", () => {
  test("no workspace → friendly hint", async () => {
    const { io, out } = captureIO();
    await runCli(["account-list", "--provider", "notion"], io);
    expect(out.join("\n")).toContain("(no notion workspace;");
  });

  test("lists all workspaces + the [active] marker (never a token)", async () => {
    await seed(WS_A, "Work", "ntn_SECRET_A");
    await seed(WS_B, "Personal", "ntn_SECRET_B"); // last-added is active
    const { io, out } = captureIO();
    await runCli(["account-list", "--provider", "notion"], io);
    const text = out.join("\n");
    expect(text).toContain("Work");
    expect(text).toContain("Personal");
    expect(text).toContain(`(${WS_B}) [active]`);
    expect(text).not.toContain("ntn_SECRET");
  });
});

describe("account-switch --provider notion", () => {
  test("missing positional → CliError", async () => {
    await seed(WS_A, "Work");
    const { io } = captureIO();
    await expect(runCli(["account-switch", "--provider", "notion"], io)).rejects.toThrow(/specify a workspace/);
  });

  test("switch by workspace id sets active", async () => {
    await seed(WS_A, "Work");
    await seed(WS_B, "Personal"); // active = B
    const { io, out } = captureIO();
    await runCli(["account-switch", WS_A, "--provider", "notion"], io);
    expect(out.join("\n")).toContain("active notion workspace: Work");
    expect(await readNotionActiveWorkspace()).toBe(WS_A);
  });

  test("switch by name (case-insensitive) sets active", async () => {
    await seed(WS_A, "Work");
    await seed(WS_B, "Personal");
    const { io } = captureIO();
    await runCli(["account-switch", "work", "--provider", "notion"], io);
    expect(await readNotionActiveWorkspace()).toBe(WS_A);
  });

  test("unknown → CliError; ambiguous name → CliError", async () => {
    await seed(WS_A, "Dup");
    await seed(WS_B, "Dup");
    const { io } = captureIO();
    await expect(runCli(["account-switch", "ghost", "--provider", "notion"], io)).rejects.toThrow(/not found/);
    await expect(runCli(["account-switch", "Dup", "--provider", "notion"], io)).rejects.toThrow(/ambiguous/);
  });
});

describe("account-revoke --provider notion", () => {
  test("revokes ONE workspace + its token; keeps the others", async () => {
    await seed(WS_A, "Work", "tok-A");
    await seed(WS_B, "Personal", "tok-B");
    const { io, out } = captureIO();
    await runCli(["account-revoke", WS_A, "--provider", "notion"], io);
    expect(out.join("\n")).toContain("revoked notion workspace: Work");
    expect((await readNotionAccounts()).map((a) => a.workspaceId)).toEqual([WS_B]);
    expect(await readNotionToken(WS_A)).toBeNull();
    expect(await readNotionToken(WS_B)).toBe("tok-B"); // the other survives
  });

  test("missing positional / unknown → CliError", async () => {
    await seed(WS_A, "Work");
    const { io } = captureIO();
    await expect(runCli(["account-revoke", "--provider", "notion"], io)).rejects.toThrow(/specify a workspace/);
    await expect(runCli(["account-revoke", "ghost", "--provider", "notion"], io)).rejects.toThrow(/not found/);
  });
});

describe("consent --provider notion — pre-network guard", () => {
  test("missing NOTION_CLIENT_ID / SECRET → throws before any network", async () => {
    const { io } = captureIO();
    await expect(runCli(["consent", "--provider", "notion"], io)).rejects.toThrow(
      /NOTION_CLIENT_ID and NOTION_CLIENT_SECRET/,
    );
  });
});
