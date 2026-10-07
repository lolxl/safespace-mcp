import { describe, expect, test } from "bun:test";
import { googleWorkspace } from "./source";

// googleWorkspace.resolveAccount — an explicit account resolves against the consented
// index (account confinement went away with Model B).

const IDX = async () => ({
  accounts: [
    { email: "alice@example.com", scopes: ["s"] },
    { email: "bob@example.com", scopes: ["s"] },
  ],
});
const noActive = async () => null;

function deps(extra: Record<string, unknown>) {
  return { lastUsed: null, loadIndexImpl: IDX, readActiveImpl: noActive, ...extra } as never;
}

describe("googleWorkspace.resolveAccount — explicit account", () => {
  test("explicit account resolves", async () => {
    const r = await googleWorkspace.resolveAccount(undefined, deps({ explicitAccountId: "bob@example.com" }));
    expect(r.accountId).toBe("bob@example.com");
  });
});
