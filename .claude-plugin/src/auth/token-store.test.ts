// v1.37 BLOCKER 1 -- token-store facade: backend selection caching, operatorId
// threading, and unchanged MCPError passthrough. Uses the file backend + tmpdir
// so it runs on any platform without touching a real Keychain.

import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { __resetBackendForTests, deleteToken, getToken, setToken } from "./token-store";
import { storageKey } from "./secret-backend";
import { MCPError } from "../errors";

let tmpDir: string;
const saved: Record<string, string | undefined> = {};
const ENV = ["SAFESPACE_CONFIG_DIR", "SAFESPACE_SECRET_BACKEND", "SAFESPACE_OPERATOR_ID", "SAFESPACE_SECRET_PASSPHRASE"];
let errSpy: ReturnType<typeof spyOn>;

beforeEach(async () => {
  for (const k of ENV) saved[k] = process.env[k];
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-ts-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  process.env.SAFESPACE_SECRET_BACKEND = "file"; // platform-independent
  delete process.env.SAFESPACE_OPERATOR_ID;
  delete process.env.SAFESPACE_SECRET_PASSPHRASE;
  errSpy = spyOn(console, "error").mockImplementation(() => undefined); // silence key-file warning
  __resetBackendForTests();
});

afterEach(async () => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
  errSpy.mockRestore();
  __resetBackendForTests();
  await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
});

describe("token-store facade", () => {
  test("round-trips getToken/setToken/deleteToken (operatorId unset -> legacy key)", async () => {
    expect(await getToken("a@example.com")).toBeNull();
    await setToken("a@example.com", "T");
    expect(await getToken("a@example.com")).toBe("T");
    await deleteToken("a@example.com");
    expect(await getToken("a@example.com")).toBeNull();
  });

  test("threads the resolved operatorId into the storage key", async () => {
    process.env.SAFESPACE_OPERATOR_ID = "alice";
    await setToken("a@example.com", "T");
    expect(await getToken("a@example.com")).toBe("T");

    // With NO operator, the same email resolves to the legacy key -> the
    // operator's token is NOT found (distinct keys). Lazy re-key only goes
    // legacy -> namespaced, never the reverse.
    delete process.env.SAFESPACE_OPERATOR_ID;
    __resetBackendForTests();
    expect(await getToken("a@example.com")).toBeNull();
    expect(storageKey("alice", "a@example.com")).not.toBe(storageKey(null, "a@example.com"));
  });

  test("caches the backend; __resetBackendForTests re-selects after an env change", async () => {
    await setToken("a@example.com", "T"); // selects + caches file backend
    expect(await getToken("a@example.com")).toBe("T");
    __resetBackendForTests(); // drop cache
    expect(await getToken("a@example.com")).toBe("T"); // re-selects, same store
  });

  test("re-throws backend MCPError unchanged (corrupt store propagates)", async () => {
    await setToken("a@example.com", "T");
    // Corrupt the ciphertext so decryption fails.
    const enc = path.join(tmpDir, "secret.enc");
    const buf = await fs.readFile(enc);
    buf[buf.length - 1] = buf[buf.length - 1]! ^ 0xff;
    await fs.writeFile(enc, buf);
    try {
      await getToken("a@example.com");
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(MCPError);
      expect((e as MCPError).errorName).toBe("secret_store_corrupt");
    }
  });
});
