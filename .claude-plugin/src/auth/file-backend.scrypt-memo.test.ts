// Perf hot-path cycle — scrypt key memoization in FileBackend.
//
// scrypt(N=2^17) costs ~128 MiB + tens-to-hundreds of ms; it previously ran on
// every token read/write on the passphrase path. The (passphrase, salt) pair is
// stable for an encrypted file's lifetime, so the derived key is memoized.
// These tests pin: derive-once across many reads/writes, and recompute on a
// passphrase change (never serve a stale key).

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  FileBackend,
  __resetFileBackendStateForTests,
  __scryptInvocationsForTests,
} from "./file-backend";

let tmpDir: string;
let prevConfig: string | undefined;
let prevPass: string | undefined;

beforeEach(async () => {
  prevConfig = process.env.SAFESPACE_CONFIG_DIR;
  prevPass = process.env.SAFESPACE_SECRET_PASSPHRASE;
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-scrypt-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  __resetFileBackendStateForTests();
});

afterEach(async () => {
  if (prevConfig === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevConfig;
  if (prevPass === undefined) delete process.env.SAFESPACE_SECRET_PASSPHRASE;
  else process.env.SAFESPACE_SECRET_PASSPHRASE = prevPass;
  await fs.rm(tmpDir, { recursive: true, force: true });
});

describe("FileBackend — scrypt key memoization (perf hot-path)", () => {
  test("key is derived once and reused across reads + writes (same passphrase+salt)", async () => {
    process.env.SAFESPACE_SECRET_PASSPHRASE = "correct horse battery staple";
    const be = new FileBackend();

    // First write mints the salt + derives the key once.
    await be.setToken("a@x.com", JSON.stringify({ at: 1 }));
    expect(__scryptInvocationsForTests()).toBe(1);

    // Subsequent reads + a second write all reuse the salt → memo hits.
    await be.getToken("a@x.com");
    await be.getToken("a@x.com");
    await be.setToken("b@x.com", JSON.stringify({ at: 2 }));
    expect(__scryptInvocationsForTests()).toBe(1);

    // Correctness preserved — values round-trip exactly.
    expect(await be.getToken("a@x.com")).toBe(JSON.stringify({ at: 1 }));
    expect(await be.getToken("b@x.com")).toBe(JSON.stringify({ at: 2 }));
    expect(__scryptInvocationsForTests()).toBe(1);
  });

  test("a passphrase change recomputes the key (memo does NOT serve the stale key)", async () => {
    process.env.SAFESPACE_SECRET_PASSPHRASE = "pass-one";
    const be = new FileBackend();
    await be.setToken("a@x.com", JSON.stringify({ at: 1 }));
    const afterWrite = __scryptInvocationsForTests();
    expect(afterWrite).toBe(1);

    // Reading the same file under a different passphrase must re-derive (and then
    // fail GCM auth → secret_store_corrupt). The point: the memo recomputed
    // rather than returning the pass-one key.
    process.env.SAFESPACE_SECRET_PASSPHRASE = "pass-two";
    await expect(be.getToken("a@x.com")).rejects.toThrow();
    expect(__scryptInvocationsForTests()).toBe(afterWrite + 1);
  });
});
