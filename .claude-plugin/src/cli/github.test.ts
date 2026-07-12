// v1.70 (G3) — `--provider github` dispatch on the OAuth-account commands.
//
// The full consent NETWORK flow is covered by auth/github/consent.test.ts (with
// injected fetch/open); here we test the CLI surface that needs NO network:
// account-list / account-switch / account-revoke against the github store, plus
// the `--provider` parsing + the consent login VALIDATION (which throws before any
// network is touched).

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { runCli, type CliIO } from "../cli";
import {
  __resetGithubBackendForTests,
  readGithubAccount,
  readGithubToken,
  writeGithubAccount,
  writeGithubToken,
} from "../auth/github/store";

let tmpDir: string;
const saved: Record<string, string | undefined> = {};
const ENV = ["SAFESPACE_CONFIG_DIR", "SAFESPACE_SECRET_BACKEND", "SAFESPACE_OPERATOR_ID", "SAFESPACE_SECRET_PASSPHRASE"];

beforeEach(async () => {
  for (const k of ENV) saved[k] = process.env[k];
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-cligh-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  process.env.SAFESPACE_SECRET_BACKEND = "file";
  delete process.env.SAFESPACE_OPERATOR_ID;
  delete process.env.SAFESPACE_SECRET_PASSPHRASE;
  __resetGithubBackendForTests();
});

afterEach(async () => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
  __resetGithubBackendForTests();
  await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
});

function captureIO(): { io: CliIO; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return { io: { out: (l) => out.push(l), err: (l) => err.push(l) }, out, err };
}

async function seedGithub(login: string, scopes: string[], token = "gho_x"): Promise<void> {
  await writeGithubToken(login, token);
  await writeGithubAccount({ login, scopes });
}

describe("--provider parsing", () => {
  test("--provider bogus → CliError on every account command", async () => {
    const { io } = captureIO();
    await expect(runCli(["account-list", "--provider", "bogus"], io)).rejects.toThrow(
      /--provider must be 'google', 'github', 'notion', or 'x'/,
    );
  });

  test("--provider with no value → CliError", async () => {
    const { io } = captureIO();
    await expect(runCli(["account-list", "--provider"], io)).rejects.toThrow(
      /--provider must be 'google', 'github', 'notion', or 'x'/,
    );
  });

  test("default (no flag) routes to the google account-list, NOT github (back-compat)", async () => {
    const { io, out } = captureIO();
    await runCli(["account-list"], io);
    // The google path prints an EMAIL table / its own empty hint — never the
    // github "(no github account; …)" line. (Asserting the exact google output
    // would couple to shared google account state other suites mutate.)
    expect(out.join("\n")).not.toContain("github account");
  });
});

describe("account-list --provider github", () => {
  test("no github account → friendly hint", async () => {
    const { io, out } = captureIO();
    await runCli(["account-list", "--provider", "github"], io);
    expect(out.join("\n")).toContain("(no github account;");
  });

  test("consented github account → shows login + scopes (never a token)", async () => {
    await seedGithub("octocat", ["read:user", "repo"], "gho_SECRET");
    const { io, out } = captureIO();
    await runCli(["account-list", "--provider", "github"], io);
    const text = out.join("\n");
    expect(text).toContain("github account: octocat");
    expect(text).toContain("read:user, repo");
    expect(text).not.toContain("gho_SECRET");
  });
});

describe("account-switch --provider github", () => {
  test("missing login argv → CliError with github usage", async () => {
    const { io } = captureIO();
    await expect(runCli(["account-switch", "--provider", "github"], io)).rejects.toThrow(
      /usage: safespace account-switch <login> --provider github/,
    );
  });

  test("invalid login format → CliError", async () => {
    const { io } = captureIO();
    await expect(runCli(["account-switch", "bad login!", "--provider", "github"], io)).rejects.toThrow(
      /login must match/,
    );
  });

  test("no github account → CliError", async () => {
    const { io } = captureIO();
    await expect(runCli(["account-switch", "octocat", "--provider", "github"], io)).rejects.toThrow(
      /no github account/,
    );
  });

  test("login mismatch → CliError naming the stored account", async () => {
    await seedGithub("octocat", ["read:user", "repo"]);
    const { io } = captureIO();
    await expect(runCli(["account-switch", "someone-else", "--provider", "github"], io)).rejects.toThrow(
      /github account not found: someone-else/,
    );
  });

  test("matching login (case-insensitive) → confirms it is active", async () => {
    await seedGithub("OctoCat", ["read:user", "repo"]);
    const { io, out } = captureIO();
    await runCli(["account-switch", "octocat", "--provider", "github"], io);
    expect(out.join("\n")).toContain("active github account: OctoCat");
  });
});

describe("account-revoke --provider github", () => {
  test("no github account → CliError, no state change", async () => {
    const { io } = captureIO();
    await expect(runCli(["account-revoke", "octocat", "--provider", "github"], io)).rejects.toThrow(
      /github account not found: octocat/,
    );
  });

  test("login mismatch → CliError, stored account untouched", async () => {
    await seedGithub("octocat", ["read:user"], "gho_keep");
    const { io } = captureIO();
    await expect(runCli(["account-revoke", "ghost", "--provider", "github"], io)).rejects.toThrow(
      /github account not found: ghost/,
    );
    expect(await readGithubAccount()).not.toBeNull();
    expect(await readGithubToken("octocat")).toBe("gho_keep");
  });

  test("matching login → clears the account file AND the stored token", async () => {
    await seedGithub("octocat", ["read:user", "repo"], "gho_SECRET");
    const { io, out } = captureIO();
    await runCli(["account-revoke", "octocat", "--provider", "github"], io);
    expect(out.join("\n")).toContain("revoked github account: octocat");
    expect(await readGithubAccount()).toBeNull();
    expect(await readGithubToken("octocat")).toBeNull();
  });
});

describe("consent --provider github — login validation (pre-network)", () => {
  test("invalid login → CliError before any consent/network", async () => {
    const { io } = captureIO();
    await expect(runCli(["consent", "bad login!", "--provider", "github"], io)).rejects.toThrow(
      /usage: safespace consent <login> --provider github/,
    );
  });

  test("missing login → CliError", async () => {
    const { io } = captureIO();
    await expect(runCli(["consent", "--provider", "github"], io)).rejects.toThrow(
      /usage: safespace consent <login> --provider github/,
    );
  });
});
