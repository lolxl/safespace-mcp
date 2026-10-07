// v1.37 BLOCKER 1 -- KeychainBackend via an injectable in-memory entry factory,
// so every branch (plain-key routing, error masking) is covered
// without @napi-rs/keyring or a real macOS Keychain.

import { describe, expect, test } from "bun:test";
import { KeychainBackend, type EntryFactory, type KeyringEntry } from "./keychain-backend";
import { MCPError } from "../errors";

const SERVICE = "safespace-mcp";

/** In-memory fake keyring keyed by `${service}::${account}`. */
function fakeStore() {
  const store = new Map<string, string>();
  const factory: EntryFactory = (service, account): KeyringEntry => {
    const k = `${service}::${account}`;
    return {
      getPassword: () => (store.has(k) ? store.get(k)! : null),
      setPassword: (v: string) => void store.set(k, v),
      deletePassword: () => void store.delete(k),
    };
  };
  return { store, factory };
}
const entryKey = (key: string) => `${SERVICE}::${key}`;

async function expectMCPError(p: Promise<unknown>, name: string): Promise<void> {
  try {
    await p;
    throw new Error(`expected MCPError(${name})`);
  } catch (e) {
    expect(e).toBeInstanceOf(MCPError);
    expect(String((e as MCPError).errorName)).toBe(name);
  }
}

describe("KeychainBackend keying", () => {
  test("round-trips under the plain key (the bare email)", async () => {
    const { store, factory } = fakeStore();
    const kb = new KeychainBackend(factory);
    await kb.setToken("a@example.com", "T");
    expect(store.get(entryKey("a@example.com"))).toBe("T");
    expect(await kb.getToken("a@example.com")).toBe("T");
    await kb.deleteToken("a@example.com");
    expect(await kb.getToken("a@example.com")).toBeNull();
  });

  test("a leftover operator-namespaced entry is never read", async () => {
    const { store, factory } = fakeStore();
    store.set(entryKey(`alice${String.fromCharCode(0)}a@example.com`), "OLD");
    expect(await new KeychainBackend(factory).getToken("a@example.com")).toBeNull();
  });

  test("getToken with no entry returns null (not an error)", async () => {
    const { factory } = fakeStore();
    expect(await new KeychainBackend(factory).getToken("ghost@example.com")).toBeNull();
  });
});

describe("KeychainBackend error masking (never forward native message)", () => {
  const throwingFactory: EntryFactory = (): KeyringEntry => ({
    getPassword: () => {
      throw new Error("/Users/secret/path leak");
    },
    setPassword: () => {
      throw new Error("/Users/secret/path leak");
    },
    deletePassword: () => {
      throw new Error("/Users/secret/path leak");
    },
  });

  test("getToken native throw -> keychain_locked", async () => {
    const kb = new KeychainBackend(throwingFactory);
    await expectMCPError(kb.getToken("a@example.com"), "keychain_locked");
  });

  test("setToken native throw -> keychain_locked", async () => {
    const kb = new KeychainBackend(throwingFactory);
    await expectMCPError(kb.setToken("a@example.com", "T"), "keychain_locked");
  });

  test("deleteToken native throw is swallowed (idempotent, no throw)", async () => {
    const kb = new KeychainBackend(throwingFactory);
    await kb.deleteToken("a@example.com"); // must not throw
  });
});
