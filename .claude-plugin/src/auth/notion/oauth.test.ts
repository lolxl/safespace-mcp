// v1.79 — the Notion multi-workspace store: the combined-file store round-trip, the v1.78
// single-object back-compat read, add/upsert/remove/active, findNotionWorkspace
// (id/name/ambiguous), token isolation, UUID validation — PLUS the notion Source's
// resolveAccount resolution (explicit id/name → active → last-used)
// + the no-oracle account_not_found, exercised over the real store. File backend + temp dir.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { notion } from "../../tools/source";
import {
  __resetNotionBackendForTests,
  addNotionAccount,
  clearNotionToken,
  findNotionWorkspace,
  NOTION_WORKSPACE_ID_RE,
  readNotionAccounts,
  readNotionActiveWorkspace,
  readNotionStore,
  readNotionToken,
  removeNotionAccount,
  setNotionActiveWorkspace,
  writeNotionToken,
} from "./oauth";

const WS_A = "11111111-1111-1111-1111-111111111111";
const WS_B = "22222222-2222-2222-2222-222222222222";

let tmpDir: string;
const saved: Record<string, string | undefined> = {};
const ENV = ["SAFESPACE_CONFIG_DIR", "SAFESPACE_SECRET_BACKEND", "SAFESPACE_OPERATOR_ID", "SAFESPACE_SECRET_PASSPHRASE"];

beforeEach(async () => {
  for (const k of ENV) saved[k] = process.env[k];
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-ntn-store-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  process.env.SAFESPACE_SECRET_BACKEND = "file";
  delete process.env.SAFESPACE_OPERATOR_ID;
  delete process.env.SAFESPACE_SECRET_PASSPHRASE;
  __resetNotionBackendForTests();
});

afterEach(async () => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
  __resetNotionBackendForTests();
  await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
});

describe("notion multi-workspace store", () => {
  test("addNotionAccount adds + activates; a 2nd add keeps the 1st (multi)", async () => {
    expect(await readNotionAccounts()).toEqual([]);
    expect((await addNotionAccount({ workspaceId: WS_A, workspaceName: "Alpha" })).wasNew).toBe(true);
    expect((await addNotionAccount({ workspaceId: WS_B, workspaceName: "Beta" })).wasNew).toBe(true);
    const accounts = await readNotionAccounts();
    expect(accounts.map((a) => a.workspaceId).sort()).toEqual([WS_A, WS_B].sort());
    expect(await readNotionActiveWorkspace()).toBe(WS_B); // the last-added is active
  });

  test("re-adding an existing workspace upserts the name (wasNew false) + reactivates", async () => {
    await addNotionAccount({ workspaceId: WS_A, workspaceName: "Alpha" });
    await addNotionAccount({ workspaceId: WS_B, workspaceName: "Beta" }); // active = B
    const r = await addNotionAccount({ workspaceId: WS_A, workspaceName: "Alpha Renamed" });
    expect(r.wasNew).toBe(false);
    const accounts = await readNotionAccounts();
    expect(accounts).toHaveLength(2);
    expect(accounts.find((a) => a.workspaceId === WS_A)?.workspaceName).toBe("Alpha Renamed");
    expect(await readNotionActiveWorkspace()).toBe(WS_A); // re-add reactivates
  });

  test("removeNotionAccount removes one + clears active if it pointed there", async () => {
    await addNotionAccount({ workspaceId: WS_A, workspaceName: "Alpha" });
    await addNotionAccount({ workspaceId: WS_B, workspaceName: "Beta" }); // active = B
    await removeNotionAccount(WS_B);
    expect((await readNotionAccounts()).map((a) => a.workspaceId)).toEqual([WS_A]);
    expect(await readNotionActiveWorkspace()).toBeNull(); // active B was removed
    await removeNotionAccount(WS_A);
    expect(await readNotionAccounts()).toEqual([]); // file removed when empty
  });

  test("setNotionActiveWorkspace switches; rejects an unknown workspace", async () => {
    await addNotionAccount({ workspaceId: WS_A, workspaceName: "Alpha" });
    await addNotionAccount({ workspaceId: WS_B, workspaceName: "Beta" });
    await setNotionActiveWorkspace(WS_A);
    expect(await readNotionActiveWorkspace()).toBe(WS_A);
    await expect(setNotionActiveWorkspace("33333333-3333-3333-3333-333333333333")).rejects.toThrow(/not a stored/);
  });

  test("readNotionStore reads the v1.78 single-object shape as a one-element active index (back-compat)", async () => {
    await fs.mkdir(tmpDir, { recursive: true });
    await fs.writeFile(
      path.join(tmpDir, "notion-account.json"),
      JSON.stringify({ workspaceId: WS_A, workspaceName: "Legacy" }),
    );
    const store = await readNotionStore();
    expect(store.workspaces).toEqual([{ workspaceId: WS_A, workspaceName: "Legacy" }]);
    expect(store.active).toBe(WS_A);
  });

  test("a corrupt file → empty store; active naming a missing workspace → null", async () => {
    await fs.mkdir(tmpDir, { recursive: true });
    await fs.writeFile(path.join(tmpDir, "notion-account.json"), "{ not json");
    expect(await readNotionStore()).toEqual({ workspaces: [], active: null });
    await fs.writeFile(
      path.join(tmpDir, "notion-account.json"),
      JSON.stringify({ workspaces: [{ workspaceId: WS_A, workspaceName: "Alpha" }], active: WS_B }),
    );
    expect(await readNotionActiveWorkspace()).toBeNull(); // active WS_B not in workspaces
  });

  test("token isolation: each workspace's token is independent", async () => {
    await writeNotionToken(WS_A, "tok-A");
    await writeNotionToken(WS_B, "tok-B");
    expect(await readNotionToken(WS_A)).toBe("tok-A");
    expect(await readNotionToken(WS_B)).toBe("tok-B");
    await clearNotionToken(WS_A);
    expect(await readNotionToken(WS_A)).toBeNull();
    expect(await readNotionToken(WS_B)).toBe("tok-B");
  });

  test("token helpers reject a non-UUID workspace id (key-injection guard)", async () => {
    await expect(readNotionToken("a:b")).rejects.toThrow(/workspace id/);
    await expect(writeNotionToken("a:b", "x")).rejects.toThrow(/workspace id/);
    await expect(clearNotionToken("../etc")).rejects.toThrow(/workspace id/);
  });
});

describe("findNotionWorkspace (pure)", () => {
  const accounts = [
    { workspaceId: WS_A, workspaceName: "Work" },
    { workspaceId: WS_B, workspaceName: "Personal" },
  ];
  test("matches an exact id (case-insensitive)", () => {
    expect(findNotionWorkspace(WS_A.toUpperCase(), accounts)).toEqual(accounts[0]!);
  });
  test("matches a unique name (case-insensitive)", () => {
    expect(findNotionWorkspace("personal", accounts)).toEqual(accounts[1]!);
  });
  test("returns 'ambiguous' for a duplicated name", () => {
    const dup = [...accounts, { workspaceId: "33333333-3333-3333-3333-333333333333", workspaceName: "Work" }];
    expect(findNotionWorkspace("Work", dup)).toBe("ambiguous");
  });
  test("returns null for an unknown id/name", () => {
    expect(findNotionWorkspace("nope", accounts)).toBeNull();
  });
  test("NOTION_WORKSPACE_ID_RE accepts a dashed UUID, rejects undashed/junk", () => {
    expect(NOTION_WORKSPACE_ID_RE.test(WS_A)).toBe(true);
    expect(NOTION_WORKSPACE_ID_RE.test("11111111111111111111111111111111")).toBe(false);
    expect(NOTION_WORKSPACE_ID_RE.test("a:b")).toBe(false);
  });
});

describe("notion.resolveAccount — resolution (over the real store)", () => {
  async function seed(): Promise<void> {
    await addNotionAccount({ workspaceId: WS_A, workspaceName: "Work" });
    await addNotionAccount({ workspaceId: WS_B, workspaceName: "Personal" }); // active = B
  }
  const resolve = (deps: Record<string, unknown>) =>
    (notion as { resolveAccount: (t: undefined, d: unknown) => Promise<{ accountId: string }> }).resolveAccount(
      undefined,
      deps,
    );

  test("explicit account_id by workspace id resolves it", async () => {
    await seed();
    expect((await resolve({ explicitAccountId: WS_A })).accountId).toBe(WS_A);
  });

  test("explicit account_id by NAME resolves to the workspace id", async () => {
    await seed();
    expect((await resolve({ explicitAccountId: "Work" })).accountId).toBe(WS_A);
  });

  test("no explicit → the active workspace", async () => {
    await seed();
    expect((await resolve({})).accountId).toBe(WS_B);
  });

  test("no explicit, no active → the per-source last-used", async () => {
    await addNotionAccount({ workspaceId: WS_A, workspaceName: "Work" }); // active = A
    await addNotionAccount({ workspaceId: WS_B, workspaceName: "Personal" }); // active = B
    await removeNotionAccount(WS_B); // clears active (was B); WS_A remains, active = null
    expect(await readNotionActiveWorkspace()).toBeNull();
    expect((await resolve({ lastUsed: WS_A })).accountId).toBe(WS_A);
  });

  test("nothing resolvable → account_not_found{no_active_account}", async () => {
    await expect(resolve({})).rejects.toMatchObject({
      errorName: "account_not_found",
      errorData: { reason: "no_active_account" },
    });
  });

  test("an unknown explicit name → account_not_found echoing the INPUT (no oracle)", async () => {
    await seed();
    await expect(resolve({ explicitAccountId: "ghost" })).rejects.toMatchObject({
      errorName: "account_not_found",
      errorData: { email: "ghost" },
    });
  });
});
