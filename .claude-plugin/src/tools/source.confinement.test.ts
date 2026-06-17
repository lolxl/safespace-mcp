import { describe, expect, test } from "bun:test";
import { googleWorkspace } from "./source";
import { MCPError } from "../errors";

// v1.74 PR-2c — per-operator account confinement in googleWorkspace.resolveAccount
// (the single-account half of the in-process isolation proof). `allowedAccounts`
// null = unrestricted (Model A, byte-identical); a non-null set confines resolution.

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

async function nameOfThrow(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return "<no throw>";
  } catch (e) {
    return e instanceof MCPError ? e.errorName : "<not MCPError>";
  }
}

describe("googleWorkspace.resolveAccount — Model A (allowedAccounts null)", () => {
  test("explicit account resolves; no confinement", async () => {
    const r = await googleWorkspace.resolveAccount(undefined, deps({ explicitAccountId: "bob@example.com" }));
    expect(r.accountId).toBe("bob@example.com"); // byte-identical to pre-2c
  });
});

describe("googleWorkspace.resolveAccount — confined (allowedAccounts: [alice])", () => {
  const allow = ["alice@example.com"];

  test("an in-set explicit account resolves", async () => {
    const r = await googleWorkspace.resolveAccount(
      undefined,
      deps({ explicitAccountId: "alice@example.com", allowedAccounts: allow }),
    );
    expect(r.accountId).toBe("alice@example.com");
  });

  test("an OUT-of-set explicit account → account_not_found (no oracle — same as nonexistent)", async () => {
    expect(
      await nameOfThrow(
        googleWorkspace.resolveAccount(
          undefined,
          deps({ explicitAccountId: "bob@example.com", allowedAccounts: allow }),
        ),
      ),
    ).toBe("account_not_found"); // operator A can NEVER resolve B's account
  });

  test("an out-of-set ACTIVE-FILE default is skipped (not an error) → falls through", async () => {
    // active file points to bob (not in alice's set); no explicit, no last-used →
    // the fallback is ignored and resolution reaches no_active_account.
    expect(
      await nameOfThrow(
        googleWorkspace.resolveAccount(
          undefined,
          deps({ allowedAccounts: allow, readActiveImpl: async () => "bob@example.com" }),
        ),
      ),
    ).toBe("account_not_found");
  });

  test("an out-of-set active-file is skipped BUT an in-set last-used still resolves", async () => {
    const r = await googleWorkspace.resolveAccount(
      undefined,
      deps({
        allowedAccounts: allow,
        readActiveImpl: async () => "bob@example.com", // out-of-set → skipped
        lastUsed: "alice@example.com", // in-set → used
      }),
    );
    expect(r.accountId).toBe("alice@example.com");
  });

  test("allowedAccounts [] (zero accounts) → nothing resolves", async () => {
    expect(
      await nameOfThrow(
        googleWorkspace.resolveAccount(
          undefined,
          deps({ explicitAccountId: "alice@example.com", allowedAccounts: [] }),
        ),
      ),
    ).toBe("account_not_found"); // [] is NOT "unrestricted" (that is null)
  });
});
