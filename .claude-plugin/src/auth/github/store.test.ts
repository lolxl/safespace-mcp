// v1.70 (G2) — github store: account-file round-trip + login validation + the
// SecretBackend token round-trip (per-login isolation). Uses the file backend +
// tmpdir so it runs on any platform (mirrors service-token-store.test.ts).

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  GITHUB_LOGIN_RE,
  __resetGithubBackendForTests,
  clearGithubAccount,
  clearGithubToken,
  readGithubAccount,
  readGithubToken,
  writeGithubAccount,
  writeGithubToken,
} from "./store";

let tmpDir: string;
const saved: Record<string, string | undefined> = {};
const ENV = [
  "SAFESPACE_CONFIG_DIR",
  "SAFESPACE_SECRET_BACKEND",
  "SAFESPACE_OPERATOR_ID",
  "SAFESPACE_SECRET_PASSPHRASE",
];

beforeEach(async () => {
  for (const k of ENV) saved[k] = process.env[k];
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-gh-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  process.env.SAFESPACE_SECRET_BACKEND = "file"; // platform-independent
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

describe("github store — account file", () => {
  test("write → read round-trips the login + scopes", async () => {
    await writeGithubAccount({ login: "octocat", scopes: ["read:user", "repo"] });
    expect(await readGithubAccount()).toEqual({
      login: "octocat",
      scopes: ["read:user", "repo"],
    });
  });

  test("readGithubAccount returns null when no file exists", async () => {
    expect(await readGithubAccount()).toBeNull();
  });

  test("readGithubAccount returns null on a corrupt file", async () => {
    await fs.writeFile(path.join(tmpDir, "github-account.json"), "{ not json");
    expect(await readGithubAccount()).toBeNull();
  });

  test("readGithubAccount returns null when the persisted login is invalid", async () => {
    await fs.writeFile(
      path.join(tmpDir, "github-account.json"),
      JSON.stringify({ login: "bad login!", scopes: [] }),
    );
    expect(await readGithubAccount()).toBeNull();
  });

  test("writeGithubAccount rejects an invalid login before any FS write", async () => {
    await expect(writeGithubAccount({ login: "has space", scopes: [] })).rejects.toThrow(
      /invalid github login/,
    );
    expect(await readGithubAccount()).toBeNull();
  });

  test("clearGithubAccount removes the file (idempotent)", async () => {
    await writeGithubAccount({ login: "octocat", scopes: [] });
    await clearGithubAccount();
    expect(await readGithubAccount()).toBeNull();
    await clearGithubAccount(); // idempotent — no throw on missing
  });

  test("GITHUB_LOGIN_RE accepts valid logins, rejects separators / CRLF / @ / : / overlong", () => {
    expect(GITHUB_LOGIN_RE.test("octocat")).toBe(true);
    expect(GITHUB_LOGIN_RE.test("a-b-1")).toBe(true);
    expect(GITHUB_LOGIN_RE.test("")).toBe(false);
    expect(GITHUB_LOGIN_RE.test("a/b")).toBe(false);
    expect(GITHUB_LOGIN_RE.test("a@b")).toBe(false);
    expect(GITHUB_LOGIN_RE.test("a:b")).toBe(false);
    expect(GITHUB_LOGIN_RE.test("a\nb")).toBe(false);
    expect(GITHUB_LOGIN_RE.test("a".repeat(40))).toBe(false);
  });
});

describe("github store — token (SecretBackend, reserved key github:<login>)", () => {
  test("write → read round-trips the token per login", async () => {
    await writeGithubToken("octocat", "gho_SECRET");
    expect(await readGithubToken("octocat")).toBe("gho_SECRET");
  });

  test("readGithubToken returns null when no token is stored", async () => {
    expect(await readGithubToken("octocat")).toBeNull();
  });

  test("tokens are isolated per login (no cross-login leak)", async () => {
    await writeGithubToken("alice", "tok-a");
    await writeGithubToken("bob", "tok-b");
    expect(await readGithubToken("alice")).toBe("tok-a");
    expect(await readGithubToken("bob")).toBe("tok-b");
  });

  test("clearGithubToken removes the stored token", async () => {
    await writeGithubToken("octocat", "gho_SECRET");
    await clearGithubToken("octocat");
    expect(await readGithubToken("octocat")).toBeNull();
  });

  test("token functions reject an invalid login before touching the backend (G2 sec-review LOW)", async () => {
    await expect(writeGithubToken("bad login", "t")).rejects.toThrow(/invalid github login/);
    await expect(readGithubToken("a:b")).rejects.toThrow(/invalid github login/);
    await expect(clearGithubToken("a/b")).rejects.toThrow(/invalid github login/);
  });
});
