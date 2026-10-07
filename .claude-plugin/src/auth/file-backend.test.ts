// v1.37 BLOCKER 1 -- FileBackend crypto test matrix (B10: 100% branch target).
//
// All tests run against a tmpdir via SAFESPACE_CONFIG_DIR; FileBackend is
// instantiated directly so no @napi-rs/keyring native dep is needed. Passphrase
// mode (scrypt N=2^17, ~128 MiB) is exercised by a FEW focused tests; the rest
// use the zero-friction key-file default.

import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test";
import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { FileBackend, __resetFileBackendStateForTests } from "./file-backend";
import { MCPError } from "../errors";

// File-format offsets (stable spec, mirrored from file-backend.ts).
const OFF_VERSION = 16;
const OFF_MODE = 17;
const OFF_SALT = 22;
const OFF_NONCE = 38;
const OFF_TAG = 50;
const OFF_CIPHERTEXT = 66;

let tmpDir: string;
let prevConfig: string | undefined;
let prevPass: string | undefined;

beforeEach(async () => {
  prevConfig = process.env.SAFESPACE_CONFIG_DIR;
  prevPass = process.env.SAFESPACE_SECRET_PASSPHRASE;
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-fb-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  delete process.env.SAFESPACE_SECRET_PASSPHRASE; // default = key-file mode
  __resetFileBackendStateForTests();
});

afterEach(async () => {
  if (prevConfig === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevConfig;
  if (prevPass === undefined) delete process.env.SAFESPACE_SECRET_PASSPHRASE;
  else process.env.SAFESPACE_SECRET_PASSPHRASE = prevPass;
  await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
});

const encFile = () => path.join(tmpDir, "secret.enc");
const keyFile = () => path.join(tmpDir, "secret.key");
const TOKEN = JSON.stringify({ refresh_token: "rt", access_token: "ax", expires_at: 1, scopes: [], obtained_at: 0 });

async function expectMCPError(p: Promise<unknown>, name: string): Promise<MCPError> {
  try {
    await p;
    throw new Error(`expected MCPError(${name}) but nothing was thrown`);
  } catch (e) {
    expect(e).toBeInstanceOf(MCPError);
    expect(String((e as MCPError).errorName)).toBe(name);
    return e as MCPError;
  }
}

describe("FileBackend key-file mode (default)", () => {
  test("round-trips set -> get -> delete for a single account (op=null)", async () => {
    const fb = new FileBackend();
    expect(await fb.getToken("a@example.com")).toBeNull();
    await fb.setToken("a@example.com", TOKEN);
    expect(await fb.getToken("a@example.com")).toBe(TOKEN);
    await fb.deleteToken("a@example.com");
    expect(await fb.getToken("a@example.com")).toBeNull();
  });

  test("stores multiple accounts independently", async () => {
    const fb = new FileBackend();
    await fb.setToken("a@example.com", "TA");
    await fb.setToken("b@example.com", "TB");
    expect(await fb.getToken("a@example.com")).toBe("TA");
    expect(await fb.getToken("b@example.com")).toBe("TB");
    await fb.deleteToken("a@example.com");
    expect(await fb.getToken("a@example.com")).toBeNull();
    expect(await fb.getToken("b@example.com")).toBe("TB"); // peer untouched
  });

  test("creates secret.enc + secret.key at 0o600, dir at 0o700", async () => {
    const fb = new FileBackend();
    await fb.setToken("a@example.com", TOKEN);
    expect((await fs.stat(encFile())).mode & 0o777).toBe(0o600);
    expect((await fs.stat(keyFile())).mode & 0o777).toBe(0o600);
    expect((await fs.stat(tmpDir)).mode & 0o777).toBe(0o700);
  });

  test("emits exactly one loud key-file-mode warning per process", async () => {
    const spy = spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const fb = new FileBackend();
      await fb.setToken("a@example.com", TOKEN);
      await fb.setToken("b@example.com", TOKEN); // second write: no new warning
      const warnings = spy.mock.calls.filter((c) => String(c[0]).includes("KEY-FILE mode"));
      expect(warnings.length).toBe(1);
      expect(String(warnings[0]![0])).toContain("SAFESPACE_SECRET_PASSPHRASE");
    } finally {
      spy.mockRestore();
    }
  });

  // v1.110 PR 1c (S7) — on win32 the secret.key 0o600 perm is a no-op (NTFS uses
  // ACLs), so the warning appends a caveat steering to passphrase mode. Only
  // process.platform is faked; the real FS ops run on the host as usual.
  test("on win32 the key-file warning appends the NTFS-ACL no-op caveat", async () => {
    const origPlatform = process.platform;
    Object.defineProperty(process, "platform", { value: "win32", configurable: true });
    const spy = spyOn(console, "error").mockImplementation(() => undefined);
    try {
      await new FileBackend().setToken("a@example.com", TOKEN);
      const warnings = spy.mock.calls.filter((c) => String(c[0]).includes("KEY-FILE mode"));
      expect(warnings.length).toBe(1);
      expect(String(warnings[0]![0])).toContain("NTFS uses ACLs");
      expect(String(warnings[0]![0])).toContain("passphrase mode is effectively required");
    } finally {
      spy.mockRestore();
      Object.defineProperty(process, "platform", { value: origPlatform, configurable: true });
    }
  });

  test("off win32 the key-file warning omits the NTFS caveat (base message only)", async () => {
    const origPlatform = process.platform;
    Object.defineProperty(process, "platform", { value: "linux", configurable: true });
    const spy = spyOn(console, "error").mockImplementation(() => undefined);
    try {
      await new FileBackend().setToken("a@example.com", TOKEN);
      const warnings = spy.mock.calls.filter((c) => String(c[0]).includes("KEY-FILE mode"));
      expect(warnings.length).toBe(1);
      expect(String(warnings[0]![0])).not.toContain("NTFS");
    } finally {
      spy.mockRestore();
      Object.defineProperty(process, "platform", { value: origPlatform, configurable: true });
    }
  });

  test("getToken on a missing store returns null (no file)", async () => {
    expect(await new FileBackend().getToken("ghost@example.com")).toBeNull();
  });

  test("deleteToken on a missing key is an idempotent no-op", async () => {
    const fb = new FileBackend();
    await fb.setToken("a@example.com", TOKEN);
    await fb.deleteToken("ghost@example.com"); // not present
    await fb.deleteToken("ghost@example.com"); // again
    expect(await fb.getToken("a@example.com")).toBe(TOKEN);
  });
});

describe("FileBackend nonce uniqueness (GCM safety)", () => {
  test("every write uses a fresh nonce and produces different ciphertext", async () => {
    const fb = new FileBackend();
    await fb.setToken("a@example.com", TOKEN);
    const buf1 = await fs.readFile(encFile());
    await fb.setToken("b@example.com", TOKEN); // re-encrypt whole file
    const buf2 = await fs.readFile(encFile());
    const nonce1 = buf1.subarray(OFF_NONCE, OFF_TAG);
    const nonce2 = buf2.subarray(OFF_NONCE, OFF_TAG);
    expect(nonce1.equals(nonce2)).toBe(false);
    expect(buf1.subarray(OFF_CIPHERTEXT).equals(buf2.subarray(OFF_CIPHERTEXT))).toBe(false);
  });
});

describe("FileBackend tamper detection (GCM auth + header-as-AAD)", () => {
  async function corruptByte(offset: number): Promise<void> {
    const buf = await fs.readFile(encFile());
    buf[offset] = buf[offset]! ^ 0xff;
    await fs.writeFile(encFile(), buf);
  }

  test("flipping a ciphertext byte -> secret_store_corrupt", async () => {
    const fb = new FileBackend();
    await fb.setToken("a@example.com", TOKEN);
    await corruptByte(OFF_CIPHERTEXT);
    await expectMCPError(fb.getToken("a@example.com"), "secret_store_corrupt");
  });

  test("flipping the version header byte -> secret_store_corrupt (unknown version)", async () => {
    const fb = new FileBackend();
    await fb.setToken("a@example.com", TOKEN);
    await corruptByte(OFF_VERSION);
    await expectMCPError(fb.getToken("a@example.com"), "secret_store_corrupt");
  });

  test("flipping a salt header byte -> secret_store_corrupt (AAD binding trips GCM)", async () => {
    // salt is part of the AAD; in key-file mode salt is unused for the key, so a
    // flipped salt only fails because the header is authenticated.
    const fb = new FileBackend();
    await fb.setToken("a@example.com", TOKEN);
    await corruptByte(OFF_SALT);
    await expectMCPError(fb.getToken("a@example.com"), "secret_store_corrupt");
  });

  test("bad magic -> secret_store_corrupt", async () => {
    const fb = new FileBackend();
    await fb.setToken("a@example.com", TOKEN);
    await corruptByte(0);
    await expectMCPError(fb.getToken("a@example.com"), "secret_store_corrupt");
  });

  test("truncated file (shorter than header) -> secret_store_corrupt", async () => {
    const fb = new FileBackend();
    await fb.setToken("a@example.com", TOKEN);
    await fs.writeFile(encFile(), Buffer.alloc(10));
    await expectMCPError(fb.getToken("a@example.com"), "secret_store_corrupt");
  });

  test("invalid mode byte -> secret_store_corrupt", async () => {
    const fb = new FileBackend();
    await fb.setToken("a@example.com", TOKEN);
    const buf = await fs.readFile(encFile());
    buf[OFF_MODE] = 9; // not 1 or 2 -- but this is part of AAD so GCM also trips
    await fs.writeFile(encFile(), buf);
    await expectMCPError(fb.getToken("a@example.com"), "secret_store_corrupt");
  });

  test("wrong-length key file -> secret_store_corrupt", async () => {
    const fb = new FileBackend();
    await fb.setToken("a@example.com", TOKEN);
    await fs.writeFile(keyFile(), Buffer.alloc(10), { mode: 0o600 }); // truncate key
    await expectMCPError(fb.getToken("a@example.com"), "secret_store_corrupt");
  });

  test("errors carry NO leaked data (empty errorData)", async () => {
    const fb = new FileBackend();
    await fb.setToken("a@example.com", TOKEN);
    await corruptByte(OFF_CIPHERTEXT);
    const err = await expectMCPError(fb.getToken("a@example.com"), "secret_store_corrupt");
    expect(err.errorData).toEqual({});
    // serialized data carries only the static recovery hint -- no path/key/token.
    const data = err.toJsonRpc().data;
    expect(Object.keys(data)).toEqual(["recovery"]);
    expect(JSON.stringify(data)).not.toContain(tmpDir);
    expect(JSON.stringify(data)).not.toContain("rt"); // no token fragment
  });
});

describe("FileBackend passphrase mode", () => {
  test("round-trips with a passphrase and writes NO key file", async () => {
    process.env.SAFESPACE_SECRET_PASSPHRASE = "correct horse battery staple";
    const fb = new FileBackend();
    await fb.setToken("a@example.com", TOKEN);
    expect(await fb.getToken("a@example.com")).toBe(TOKEN);
    await expect(fs.stat(keyFile())).rejects.toMatchObject({ code: "ENOENT" });
    // header records passphrase mode (2).
    const buf = await fs.readFile(encFile());
    expect(buf.readUInt8(OFF_MODE)).toBe(2);
  });

  test("wrong passphrase -> secret_store_corrupt (conflated with tamper, no oracle)", async () => {
    process.env.SAFESPACE_SECRET_PASSPHRASE = "passphrase-A";
    await new FileBackend().setToken("a@example.com", TOKEN);
    process.env.SAFESPACE_SECRET_PASSPHRASE = "passphrase-B";
    await expectMCPError(new FileBackend().getToken("a@example.com"), "secret_store_corrupt");
  });

  test("missing passphrase on a passphrase-mode file -> keychain_locked (retryable)", async () => {
    process.env.SAFESPACE_SECRET_PASSPHRASE = "passphrase-A";
    await new FileBackend().setToken("a@example.com", TOKEN);
    delete process.env.SAFESPACE_SECRET_PASSPHRASE;
    await expectMCPError(new FileBackend().getToken("a@example.com"), "keychain_locked");
  });
});

describe("FileBackend keying", () => {
  test("a token is stored under the plain key and survives a new instance", async () => {
    const fb = new FileBackend();
    await fb.setToken("a@example.com", TOKEN);
    const fb2 = new FileBackend();
    expect(await fb2.getToken("a@example.com")).toBe(TOKEN);
  });

  test("a leftover operator-namespaced entry is never read", async () => {
    const fb = new FileBackend();
    await fb.setToken(`alice${String.fromCharCode(0)}a@example.com`, "OLD");
    expect(await fb.getToken("a@example.com")).toBeNull();
  });
});

describe("FileBackend edge branches (corrupt payload / missing key / salt reuse)", () => {
  /** Re-encrypt an arbitrary plaintext under the existing key-file key, with a
   *  valid header+AAD, so GCM SUCCEEDS but the decrypted payload is whatever we
   *  choose (to exercise the post-decrypt JSON validation). */
  async function writeKeyFilePayload(plaintext: string): Promise<void> {
    const key = await fs.readFile(keyFile()); // 32-byte key-file key
    const aad = Buffer.alloc(OFF_TAG);
    Buffer.from("SAFESPACE-SECRET", "ascii").copy(aad, 0);
    aad.writeUInt8(1, OFF_VERSION); // version 1
    aad.writeUInt8(1, OFF_MODE); // key-file mode
    aad.writeUInt32LE(0, 18); // kdf_n = 0
    // salt (zeros) already from alloc; nonce:
    const nonce = crypto.randomBytes(12);
    nonce.copy(aad, OFF_NONCE);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
    cipher.setAAD(aad);
    const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
    const tag = cipher.getAuthTag();
    await fs.writeFile(encFile(), Buffer.concat([aad, tag, ct]), { mode: 0o600 });
  }

  test("decrypts to non-JSON -> secret_store_corrupt", async () => {
    const fb = new FileBackend();
    await fb.setToken("a@example.com", TOKEN); // creates the key file
    await writeKeyFilePayload("this is not json {{{");
    await expectMCPError(fb.getToken("a@example.com"), "secret_store_corrupt");
  });

  test("decrypts to a JSON array (non-object) -> secret_store_corrupt", async () => {
    const fb = new FileBackend();
    await fb.setToken("a@example.com", TOKEN);
    await writeKeyFilePayload("[1,2,3]");
    await expectMCPError(fb.getToken("a@example.com"), "secret_store_corrupt");
  });

  test("decrypts to an object with a non-string value -> secret_store_corrupt", async () => {
    const fb = new FileBackend();
    await fb.setToken("a@example.com", TOKEN);
    await writeKeyFilePayload(JSON.stringify({ "a@example.com": 42 }));
    await expectMCPError(fb.getToken("a@example.com"), "secret_store_corrupt");
  });

  test("key-file mode with a deleted key file -> keychain_locked (retryable)", async () => {
    const fb = new FileBackend();
    await fb.setToken("a@example.com", TOKEN);
    await fs.rm(keyFile()); // ciphertext remains; key gone
    await expectMCPError(fb.getToken("a@example.com"), "keychain_locked");
  });

  test("passphrase mode reuses the file's salt across writes (stable key)", async () => {
    process.env.SAFESPACE_SECRET_PASSPHRASE = "stable-pass";
    const fb = new FileBackend();
    await fb.setToken("a@example.com", "T1");
    const salt1 = (await fs.readFile(encFile())).subarray(OFF_SALT, OFF_NONCE);
    await fb.setToken("b@example.com", "T2"); // second write reuses the salt
    const salt2 = (await fs.readFile(encFile())).subarray(OFF_SALT, OFF_NONCE);
    expect(salt1.equals(salt2)).toBe(true);
    expect(await fb.getToken("a@example.com")).toBe("T1");
    expect(await fb.getToken("b@example.com")).toBe("T2");
  });
});
