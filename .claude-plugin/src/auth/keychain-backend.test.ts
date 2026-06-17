// v1.37 BLOCKER 1 -- KeychainBackend via an injectable in-memory entry factory,
// so every branch (storageKey routing, lazy re-key, error masking) is covered
// without @napi-rs/keyring or a real macOS Keychain.

import { describe, expect, test } from "bun:test";
import { KeychainBackend, type EntryFactory, type KeyringEntry } from "./keychain-backend";
import { storageKey } from "./secret-backend";
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
const entryKey = (op: string | null, email: string) => `${SERVICE}::${storageKey(op, email)}`;

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
  test("round-trips with op=null under the bare-email legacy key", async () => {
    const { store, factory } = fakeStore();
    const kb = new KeychainBackend(factory);
    await kb.setToken(null, "a@example.com", "T");
    expect(store.get(entryKey(null, "a@example.com"))).toBe("T");
    expect(await kb.getToken(null, "a@example.com")).toBe("T");
    await kb.deleteToken(null, "a@example.com");
    expect(await kb.getToken(null, "a@example.com")).toBeNull();
  });

  test("namespaces by operatorId; two operators on one account never collide", async () => {
    const { factory } = fakeStore();
    const kb = new KeychainBackend(factory);
    await kb.setToken("alice", "shared@example.com", "ALICE");
    await kb.setToken("bob", "shared@example.com", "BOB");
    expect(await kb.getToken("alice", "shared@example.com")).toBe("ALICE");
    expect(await kb.getToken("bob", "shared@example.com")).toBe("BOB");
  });

  test("getToken with no entry returns null (not an error)", async () => {
    const { factory } = fakeStore();
    expect(await new KeychainBackend(factory).getToken(null, "ghost@example.com")).toBeNull();
  });
});

describe("KeychainBackend lazy re-key on read", () => {
  test("migrates a legacy null-key token to the namespaced key", async () => {
    const { store, factory } = fakeStore();
    store.set(entryKey(null, "a@example.com"), "T"); // pre-existing legacy entry
    const kb = new KeychainBackend(factory);
    expect(await kb.getToken("alice", "a@example.com")).toBe("T");
    // migrated: namespaced key set, legacy key deleted
    expect(store.get(entryKey("alice", "a@example.com"))).toBe("T");
    expect(store.has(entryKey(null, "a@example.com"))).toBe(false);
  });

  test("op=null does NOT fall back (it IS the legacy key)", async () => {
    const { store, factory } = fakeStore();
    store.set(entryKey("alice", "a@example.com"), "NS"); // only a namespaced entry
    const kb = new KeychainBackend(factory);
    expect(await kb.getToken(null, "a@example.com")).toBeNull(); // no reverse fallback
  });

  test("failure-tolerant: returns the legacy token even if the re-key write throws", async () => {
    const store = new Map<string, string>();
    store.set(entryKey(null, "a@example.com"), "T");
    // Factory that THROWS on setPassword (re-key write fails) but reads fine.
    const factory: EntryFactory = (service, account): KeyringEntry => {
      const k = `${service}::${account}`;
      return {
        getPassword: () => (store.has(k) ? store.get(k)! : null),
        setPassword: () => {
          throw new Error("write blocked");
        },
        deletePassword: () => void store.delete(k),
      };
    };
    const kb = new KeychainBackend(factory);
    expect(await kb.getToken("alice", "a@example.com")).toBe("T"); // still returned
    expect(store.get(entryKey(null, "a@example.com"))).toBe("T"); // legacy preserved
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
    await expectMCPError(kb.getToken(null, "a@example.com"), "keychain_locked");
  });

  test("setToken native throw -> keychain_locked", async () => {
    const kb = new KeychainBackend(throwingFactory);
    await expectMCPError(kb.setToken(null, "a@example.com", "T"), "keychain_locked");
  });

  test("deleteToken native throw is swallowed (idempotent, no throw)", async () => {
    const kb = new KeychainBackend(throwingFactory);
    await kb.deleteToken(null, "a@example.com"); // must not throw
  });
});
