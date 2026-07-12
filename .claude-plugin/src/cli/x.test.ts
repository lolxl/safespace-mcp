// v1.113 — `--provider x` dispatch on the OAuth-account commands. Multi-account:
// account-list shows all + the active marker; account-switch/revoke take a
// <id-or-username> positional.
//
// The full consent NETWORK flow is covered by auth/x/consent.test.ts (injected
// fetch/open); here we test the CLI surface that needs NO network: account-list /
// account-switch / account-revoke against the x store, --provider parsing, and the
// consent pre-network guard (missing SAFESPACE_X_CLIENT_ID throws before any network).

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { runCli, type CliIO } from "../cli";
import {
  __resetXBackendForTests,
  addXAccount,
  readXAccounts,
  readXActiveAccount,
  readXToken,
  tokenPayloadFromGrant,
  writeXToken,
} from "../auth/x/oauth";

const USER_A = "1111111111111111111";
const USER_B = "2222222222222222222";

let tmpDir: string;
const saved: Record<string, string | undefined> = {};
const ENV = [
  "SAFESPACE_CONFIG_DIR",
  "SAFESPACE_SECRET_BACKEND",
  "SAFESPACE_OPERATOR_ID",
  "SAFESPACE_SECRET_PASSPHRASE",
  "SAFESPACE_X_CLIENT_ID",
  "SAFESPACE_X_CLIENT_SECRET",
];

beforeEach(async () => {
  for (const k of ENV) saved[k] = process.env[k];
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-clix-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  process.env.SAFESPACE_SECRET_BACKEND = "file";
  delete process.env.SAFESPACE_OPERATOR_ID;
  delete process.env.SAFESPACE_SECRET_PASSPHRASE;
  delete process.env.SAFESPACE_X_CLIENT_ID;
  delete process.env.SAFESPACE_X_CLIENT_SECRET;
  __resetXBackendForTests();
});

afterEach(async () => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
  __resetXBackendForTests();
  await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
});

function captureIO(): { io: CliIO; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return { io: { out: (l) => out.push(l), err: (l) => err.push(l) }, out, err };
}

async function seed(id: string, username: string, token = "x_access"): Promise<void> {
  await addXAccount({ id, username });
  await writeXToken(id, tokenPayloadFromGrant({
    access_token: token, refresh_token: `${token}_refresh`, expires_in: 7200,
  }));
}

describe("--provider parsing (x)", () => {
  test("--provider bogus → CliError naming the four providers", async () => {
    const { io } = captureIO();
    await expect(runCli(["account-list", "--provider", "bogus"], io)).rejects.toThrow(
      /--provider must be 'google', 'github', 'notion', or 'x'/,
    );
  });
});

describe("account-list --provider x (multi)", () => {
  test("no account → friendly hint", async () => {
    const { io, out } = captureIO();
    await runCli(["account-list", "--provider", "x"], io);
    expect(out.join("\n")).toContain("(no x account;");
  });

  test("lists all accounts + the [active] marker (never a token)", async () => {
    await seed(USER_A, "alice", "x_SECRET_A");
    await seed(USER_B, "bob", "x_SECRET_B"); // last-added is active
    const { io, out } = captureIO();
    await runCli(["account-list", "--provider", "x"], io);
    const text = out.join("\n");
    expect(text).toContain("@alice");
    expect(text).toContain("@bob");
    expect(text).toContain(`(${USER_B}) [active]`);
    expect(text).not.toContain("x_SECRET");
  });
});

describe("account-switch --provider x", () => {
  test("missing positional → CliError", async () => {
    const { io } = captureIO();
    await expect(runCli(["account-switch", "--provider", "x"], io)).rejects.toThrow(
      /specify an account/,
    );
  });

  test("switches by id", async () => {
    await seed(USER_A, "alice");
    await seed(USER_B, "bob");
    const { io, out } = captureIO();
    await runCli(["account-switch", USER_A, "--provider", "x"], io);
    expect(await readXActiveAccount()).toBe(USER_A);
    expect(out.join("\n")).toContain("@alice");
  });

  test("switches by username (case-insensitive)", async () => {
    await seed(USER_A, "alice");
    await seed(USER_B, "bob");
    const { io } = captureIO();
    await runCli(["account-switch", "ALICE", "--provider", "x"], io);
    expect(await readXActiveAccount()).toBe(USER_A);
  });

  test("unknown / empty → CliError", async () => {
    await seed(USER_A, "alice");
    const { io } = captureIO();
    await expect(runCli(["account-switch", "ghost", "--provider", "x"], io)).rejects.toThrow(
      /not found/,
    );
  });
});

describe("account-revoke --provider x", () => {
  test("removes one account + its token; keeps the other", async () => {
    await seed(USER_A, "alice", "tokA");
    await seed(USER_B, "bob", "tokB");
    const { io, out } = captureIO();
    await runCli(["account-revoke", USER_A, "--provider", "x"], io);
    expect((await readXAccounts()).map((a) => a.id)).toEqual([USER_B]);
    expect(await readXToken(USER_A)).toBeNull();
    expect((await readXToken(USER_B))!.access_token).toBe("tokB");
    expect(out.join("\n")).not.toContain("tokA");
    expect(out.join("\n")).not.toContain("tokB");
  });

  test("missing / unknown → CliError", async () => {
    const { io } = captureIO();
    await expect(runCli(["account-revoke", "--provider", "x"], io)).rejects.toThrow(
      /specify an account/,
    );
    await seed(USER_A, "alice");
    await expect(runCli(["account-revoke", "ghost", "--provider", "x"], io)).rejects.toThrow(
      /not found/,
    );
  });
});

describe("consent --provider x (pre-network)", () => {
  test("missing SAFESPACE_X_CLIENT_ID → throws before any network", async () => {
    const { io } = captureIO();
    await expect(runCli(["consent", "--provider", "x"], io)).rejects.toThrow(
      /SAFESPACE_X_CLIENT_ID/,
    );
  });
});
