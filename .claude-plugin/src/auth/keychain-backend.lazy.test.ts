// v1.110 PR 1c (S6) — the native @napi-rs/keyring binding is reached LAZILY: the
// default-factory KeychainBackend constructs no native Entry until a token op
// actually runs, never at import or backend construction. That is the
// portability guarantee that lets a non-mac / `npx safespace-mcp` client run on
// the FileBackend without the native addon being resolved at all (a missing
// platform binary must not crash bootstrap — it stays off the non-Keychain path).
// And a native fault on that lazy path is still masked to keychain_locked with no
// native dlopen path forwarded — the same error-masking discipline as before.
//
// mock.module is process-wide AND eagerly evaluated in bun, so the real module is
// captured up front and re-installed in afterAll for any later file that needs the
// genuine binding.

import { afterAll, beforeAll, expect, mock, test } from "bun:test";
import { MCPError } from "../errors";
import { __resetKeyringMemoForTests } from "./keychain-backend";

let real: unknown;
beforeAll(async () => {
  real = await import("@napi-rs/keyring");
});
afterAll(() => {
  // Restore the real binding AND drop the memo, so a later file's default-factory
  // use re-requires the genuine module (mock.module is process-wide in bun).
  mock.module("@napi-rs/keyring", () => real as Record<string, unknown>);
  __resetKeyringMemoForTests();
});

test("default factory builds no native Entry until a token op runs, and masks a native fault", async () => {
  let entryCtors = 0;
  mock.module("@napi-rs/keyring", () => ({
    Entry: class {
      constructor(_service: string, _account: string) {
        entryCtors++;
      }
      getPassword(): string | null {
        throw new Error("native fault: /opt/secret/keyring.node");
      }
      setPassword(_v: string): void {
        throw new Error("native fault: /opt/secret/keyring.node");
      }
      deletePassword(): void {}
    },
  }));
  // Drop any real module an earlier test file memoized, so loadKeyring re-requires
  // and hits the mock above (the lazy load is what we are exercising here).
  __resetKeyringMemoForTests();

  const { KeychainBackend } = await import("./keychain-backend");
  const kb = new KeychainBackend(); // default factory → the lazy native path

  // Constructing the backend must NOT construct a native Entry (lazy).
  expect(entryCtors).toBe(0);

  // First token op constructs an Entry and (here) hits the native throw → masked
  // keychain_locked, with no native path forwarded.
  try {
    await kb.getToken(null, "a@example.com");
    throw new Error("expected MCPError(keychain_locked)");
  } catch (e) {
    expect(e).toBeInstanceOf(MCPError);
    expect(String((e as MCPError).errorName)).toBe("keychain_locked");
    expect(String((e as Error).message)).not.toContain("/opt/secret");
  }

  // The native Entry WAS built — lazily, on use, not at import/construction.
  expect(entryCtors).toBeGreaterThan(0);
});
