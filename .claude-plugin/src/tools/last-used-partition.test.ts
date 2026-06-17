import { afterEach, expect, test } from "bun:test";
import { _resetLastUsedForTests, getLastUsed, setLastUsed } from "./with-context";

// v1.74 PR-2c — the per-source last-used map is keyed by (operatorId, sourceId) so
// one operator's last-used can NEVER seed another operator's default account (the
// Model-B in-process isolation). Model A (no operator arg) keys under the single
// null namespace → byte-identical to pre-2c.

afterEach(() => _resetLastUsedForTests());

test("last-used is partitioned by operator — A's last-used is invisible to B", () => {
  setLastUsed("alice@example.com", "google-workspace", "alice");
  expect(getLastUsed("google-workspace", "alice")).toBe("alice@example.com");
  // operator B sees NOTHING — A's last-used can't seed B's default account.
  expect(getLastUsed("google-workspace", "bob")).toBeNull();
});

test("Model A default (no operator arg) keys under the single null namespace", () => {
  setLastUsed("alice@example.com"); // sourceId default + operatorId null
  expect(getLastUsed()).toBe("alice@example.com");
  expect(getLastUsed("google-workspace")).toBe("alice@example.com"); // same key
  expect(getLastUsed("google-workspace", null)).toBe("alice@example.com");
});

test("the operator partition is independent of the per-source key", () => {
  setLastUsed("a@x.com", "google-workspace", "alice");
  setLastUsed("g@x.com", "github", "alice");
  expect(getLastUsed("google-workspace", "alice")).toBe("a@x.com");
  expect(getLastUsed("github", "alice")).toBe("g@x.com");
});
