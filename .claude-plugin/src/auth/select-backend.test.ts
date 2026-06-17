// v1.37 BLOCKER 1 -- backend selection matrix (B7).

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  ENV_ALLOW_KEYFILE_AT_REST,
  autonomousKeyfileRefusal,
  enforceAutonomousTokenStorage,
  selectBackend,
  selectBackendKind,
} from "./select-backend";
import { KeychainBackend } from "./keychain-backend";
import { FileBackend } from "./file-backend";
import { ENV_AUTONOMOUS } from "../policy/autonomous-mode";

let prevEnv: string | undefined;
const origPlatform = process.platform;

function setPlatform(p: string): void {
  Object.defineProperty(process, "platform", { value: p, configurable: true });
}

beforeEach(() => {
  prevEnv = process.env.SAFESPACE_SECRET_BACKEND;
});

afterEach(() => {
  if (prevEnv === undefined) delete process.env.SAFESPACE_SECRET_BACKEND;
  else process.env.SAFESPACE_SECRET_BACKEND = prevEnv;
  Object.defineProperty(process, "platform", { value: origPlatform, configurable: true });
});

describe("selectBackendKind (env + platform)", () => {
  test("unset + darwin -> keychain (today's behavior, zero change)", () => {
    delete process.env.SAFESPACE_SECRET_BACKEND;
    setPlatform("darwin");
    expect(selectBackendKind()).toBe("keychain");
  });

  test("unset + linux -> file (the OSS unblock)", () => {
    delete process.env.SAFESPACE_SECRET_BACKEND;
    setPlatform("linux");
    expect(selectBackendKind()).toBe("file");
  });

  test("empty string is treated as unset (platform default)", () => {
    process.env.SAFESPACE_SECRET_BACKEND = "";
    setPlatform("darwin");
    expect(selectBackendKind()).toBe("keychain");
  });

  test('"keychain" forces KeychainBackend even on linux', () => {
    process.env.SAFESPACE_SECRET_BACKEND = "keychain";
    setPlatform("linux");
    expect(selectBackendKind()).toBe("keychain");
  });

  test('"file" forces FileBackend even on darwin', () => {
    process.env.SAFESPACE_SECRET_BACKEND = "file";
    setPlatform("darwin");
    expect(selectBackendKind()).toBe("file");
  });

  test("an invalid non-empty value FAILS CLOSED (throws); message is value-free", () => {
    process.env.SAFESPACE_SECRET_BACKEND = "vault";
    expect(() => selectBackendKind()).toThrow(/expected "keychain" or "file"/);
    // The thrown message must NOT echo the rejected value.
    try {
      selectBackendKind();
    } catch (e) {
      expect(String((e as Error).message)).not.toContain("vault");
    }
  });

  test("strict: uppercase / mixed-case is rejected (no case-folding)", () => {
    process.env.SAFESPACE_SECRET_BACKEND = "Keychain";
    expect(() => selectBackendKind()).toThrow();
  });
});

describe("selectBackend (instantiation)", () => {
  test("returns a KeychainBackend when kind is keychain", () => {
    process.env.SAFESPACE_SECRET_BACKEND = "keychain";
    expect(selectBackend()).toBeInstanceOf(KeychainBackend);
  });

  test("returns a FileBackend when kind is file", () => {
    process.env.SAFESPACE_SECRET_BACKEND = "file";
    expect(selectBackend()).toBeInstanceOf(FileBackend);
  });
});

describe("autonomousKeyfileRefusal — F6 token-at-rest hardening (v1.55)", () => {
  // F6 reads four envs + platform. Save/restore all of them so this block is
  // hermetic (the file-level beforeEach only handles SAFESPACE_SECRET_BACKEND).
  const KEYS = [
    ENV_AUTONOMOUS, // "SAFESPACE_AUTONOMOUS"
    "SAFESPACE_SECRET_BACKEND",
    "SAFESPACE_SECRET_PASSPHRASE",
    ENV_ALLOW_KEYFILE_AT_REST, // "SAFESPACE_ALLOW_KEYFILE_AT_REST"
  ];
  let saved: Record<string, string | undefined>;
  const origPlatform = process.platform;
  const setPlat = (p: string): void => {
    Object.defineProperty(process, "platform", { value: p, configurable: true });
  };

  beforeEach(() => {
    saved = {};
    for (const k of KEYS) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
  });
  afterEach(() => {
    for (const k of KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k]!;
    }
    Object.defineProperty(process, "platform", { value: origPlatform, configurable: true });
  });

  test("ENV constant matches the design contract (rename sentinel)", () => {
    expect(ENV_ALLOW_KEYFILE_AT_REST).toBe("SAFESPACE_ALLOW_KEYFILE_AT_REST");
  });

  test("NOT autonomous + file + key-file → allowed (null); F6 never engages off the flag", () => {
    process.env.SAFESPACE_SECRET_BACKEND = "file";
    expect(autonomousKeyfileRefusal()).toBeNull();
  });

  test("autonomous + Keychain → allowed (Q4 exempt: key is OS-guarded, not beside ciphertext)", () => {
    process.env[ENV_AUTONOMOUS] = "true";
    process.env.SAFESPACE_SECRET_BACKEND = "keychain";
    expect(autonomousKeyfileRefusal()).toBeNull();
  });

  test("autonomous + file + PASSPHRASE set → allowed (the recommended no-key-at-rest state)", () => {
    process.env[ENV_AUTONOMOUS] = "true";
    process.env.SAFESPACE_SECRET_BACKEND = "file";
    process.env.SAFESPACE_SECRET_PASSPHRASE = "correct horse battery staple";
    expect(autonomousKeyfileRefusal()).toBeNull();
  });

  test("autonomous + file + key-file + NO escape hatch → REFUSED (message names both remedies, no path leak)", () => {
    process.env[ENV_AUTONOMOUS] = "true";
    process.env.SAFESPACE_SECRET_BACKEND = "file";
    const msg = autonomousKeyfileRefusal();
    expect(msg).not.toBeNull();
    expect(msg).toContain("SAFESPACE_SECRET_PASSPHRASE");
    expect(msg).toContain("SAFESPACE_ALLOW_KEYFILE_AT_REST");
    // No leaked configDir path / key material — only documented static filenames.
    expect(msg).not.toMatch(/\/(Users|home|var|tmp)\//);
  });

  test("autonomous + file + key-file + escape hatch 'true' → allowed (deliberate opt-in)", () => {
    process.env[ENV_AUTONOMOUS] = "true";
    process.env.SAFESPACE_SECRET_BACKEND = "file";
    process.env[ENV_ALLOW_KEYFILE_AT_REST] = "true";
    expect(autonomousKeyfileRefusal()).toBeNull();
  });

  test("escape hatch is STRICT-truthy: 'True' / '1' do NOT opt in → still REFUSED", () => {
    process.env[ENV_AUTONOMOUS] = "true";
    process.env.SAFESPACE_SECRET_BACKEND = "file";
    for (const v of ["True", "TRUE", "1", "yes", ""]) {
      process.env[ENV_ALLOW_KEYFILE_AT_REST] = v;
      expect(autonomousKeyfileRefusal(), `hatch=${JSON.stringify(v)}`).not.toBeNull();
    }
  });

  test("a TYPO'd autonomous flag ('True') → F6 does NOT engage (allowed) — inherits F2 R3 permissive-on-typo", () => {
    process.env[ENV_AUTONOMOUS] = "True"; // not the literal lowercase "true"
    process.env.SAFESPACE_SECRET_BACKEND = "file";
    expect(autonomousKeyfileRefusal()).toBeNull();
  });

  test("autonomous + UNSET backend on linux (the real OSS deploy) + key-file → REFUSED via platform default", () => {
    process.env[ENV_AUTONOMOUS] = "true";
    delete process.env.SAFESPACE_SECRET_BACKEND; // platform default
    setPlat("linux"); // → FileBackend
    expect(autonomousKeyfileRefusal()).not.toBeNull();
  });

  test("autonomous + UNSET backend on darwin → Keychain default → allowed", () => {
    process.env[ENV_AUTONOMOUS] = "true";
    delete process.env.SAFESPACE_SECRET_BACKEND;
    setPlat("darwin");
    expect(autonomousKeyfileRefusal()).toBeNull();
  });

  // v1.110 PR 1c (S7) — verify F6 still refuses on win32. win32 is non-darwin, so
  // the platform default is FileBackend; and on NTFS the secret.key 0o600 perm is
  // a no-op (ACLs, not POSIX bits), making key-file mode WEAKER there, not safer —
  // F6 must engage, not be bypassed.
  test("autonomous + UNSET backend on win32 (npx-on-Windows deploy) + key-file → REFUSED via platform default", () => {
    process.env[ENV_AUTONOMOUS] = "true";
    delete process.env.SAFESPACE_SECRET_BACKEND; // platform default
    setPlat("win32"); // → FileBackend (non-darwin)
    expect(autonomousKeyfileRefusal()).not.toBeNull();
  });

  test("enforceAutonomousTokenStorage throws iff refused; the throw is what makes the proxy exit", () => {
    process.env[ENV_AUTONOMOUS] = "true";
    process.env.SAFESPACE_SECRET_BACKEND = "file";
    // key-file, no hatch → refused → throws
    expect(() => enforceAutonomousTokenStorage()).toThrow(/key-beside-ciphertext|KEY-FILE/);
    // passphrase set → allowed → no throw
    process.env.SAFESPACE_SECRET_PASSPHRASE = "p";
    expect(() => enforceAutonomousTokenStorage()).not.toThrow();
  });
});
