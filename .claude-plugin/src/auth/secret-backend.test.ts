// v1.37 BLOCKER 1 -- storageKey() keying rule (the zero-migration linchpin).

import { describe, expect, test } from "bun:test";
import { storageKey } from "./secret-backend";

const NUL = String.fromCharCode(0);

describe("storageKey", () => {
  test("operatorId === null maps to the BARE email (legacy key shape)", () => {
    // This is the zero-migration property: existing Mac entries are keyed by the
    // bare email, and op=null must reproduce that exact key.
    expect(storageKey(null, "alice@example.com")).toBe("alice@example.com");
  });

  test("operatorId set -> operatorId + NUL + email (namespaced)", () => {
    expect(storageKey("alice", "shared@example.com")).toBe(`alice${NUL}shared@example.com`);
    // The delimiter is a real NUL byte at the boundary.
    const k = storageKey("alice", "shared@example.com");
    expect(k.charCodeAt("alice".length)).toBe(0);
  });

  test("different operators on the same account produce distinct, non-colliding keys", () => {
    const a = storageKey("alice", "shared@example.com");
    const b = storageKey("bob", "shared@example.com");
    expect(a).not.toBe(b);
    // Neither namespaced key equals the legacy (null) key for that account.
    const legacy = storageKey(null, "shared@example.com");
    expect(a).not.toBe(legacy);
    expect(b).not.toBe(legacy);
  });
});
