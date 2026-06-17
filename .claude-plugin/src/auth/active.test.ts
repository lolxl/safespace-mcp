import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { clearActive, readActive, writeActive } from "./active";

let tmpDir: string;
let prevEnv: string | undefined;

beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-active-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
});

afterEach(async () => {
  if (prevEnv === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevEnv;
  await fs.rm(tmpDir, { recursive: true, force: true });
});

describe("active-account file IO", () => {
  test("read returns null when file does not exist", async () => {
    expect(await readActive()).toBeNull();
  });

  test("write then read returns the email verbatim", async () => {
    await writeActive("alice@example.com");
    expect(await readActive()).toBe("alice@example.com");
  });

  test("write trims trailing newline on read", async () => {
    await writeActive("alice@example.com");
    const raw = await fs.readFile(path.join(tmpDir, "active-account"), "utf8");
    expect(raw).toBe("alice@example.com\n");
    expect(await readActive()).toBe("alice@example.com");
  });

  test("write overwrites a previous active account", async () => {
    await writeActive("alice@example.com");
    await writeActive("bob@example.com");
    expect(await readActive()).toBe("bob@example.com");
  });

  test("write rejects invalid email format before touching the filesystem", async () => {
    await expect(writeActive("not-an-email")).rejects.toThrow(/invalid email/);
    // Confirm no file was created
    await expect(fs.stat(path.join(tmpDir, "active-account"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("read returns null when content is non-email garbage", async () => {
    await fs.writeFile(path.join(tmpDir, "active-account"), "not an email at all\n");
    expect(await readActive()).toBeNull();
  });

  test("read returns null when file is empty", async () => {
    await fs.writeFile(path.join(tmpDir, "active-account"), "");
    expect(await readActive()).toBeNull();
  });

  test("read returns null when file contains multiple lines (corrupt)", async () => {
    await fs.writeFile(path.join(tmpDir, "active-account"), "alice@example.com\nbob@example.com\n");
    expect(await readActive()).toBeNull();
  });

  test("clearActive removes the file", async () => {
    await writeActive("alice@example.com");
    await clearActive();
    expect(await readActive()).toBeNull();
    await expect(fs.stat(path.join(tmpDir, "active-account"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("clearActive is idempotent (no-op if file missing)", async () => {
    await clearActive();
    await clearActive(); // does not throw
    expect(await readActive()).toBeNull();
  });

  test("active-account file is written with mode 0o600", async () => {
    await writeActive("alice@example.com");
    const stat = await fs.stat(path.join(tmpDir, "active-account"));
    expect(stat.mode & 0o777).toBe(0o600);
  });
});
