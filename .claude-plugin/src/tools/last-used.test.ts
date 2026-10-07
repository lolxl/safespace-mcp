import { afterEach, expect, test } from "bun:test";
import { _resetLastUsedForTests, getLastUsed, setLastUsed } from "./with-context";

// The last-used map is keyed per source only (the per-operator partition went
// away with Model B): the default sourceId is google-workspace, and each source
// keeps its own last-used account.

afterEach(() => _resetLastUsedForTests());

test("default sourceId is google-workspace — setLastUsed/getLastUsed with no source arg share one key", () => {
  setLastUsed("alice@example.com"); // sourceId default
  expect(getLastUsed()).toBe("alice@example.com");
  expect(getLastUsed("google-workspace")).toBe("alice@example.com"); // same key
});

test("last-used is keyed per source — one source's last-used never seeds another's", () => {
  setLastUsed("a@x.com", "google-workspace");
  setLastUsed("g@x.com", "github");
  expect(getLastUsed("google-workspace")).toBe("a@x.com");
  expect(getLastUsed("github")).toBe("g@x.com");
  expect(getLastUsed("notion")).toBeNull();
});
