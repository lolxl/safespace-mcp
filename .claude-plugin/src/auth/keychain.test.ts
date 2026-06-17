import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  configDir,
  loadIndex,
  removeAccount,
  saveIndex,
  upsertAccount,
  type AccountEntry,
  type AccountsIndex,
} from "./keychain";

let tmpDir: string;
let prevEnv: string | undefined;

beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-test-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
});

afterEach(async () => {
  if (prevEnv === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevEnv;
  await fs.rm(tmpDir, { recursive: true, force: true });
});

const ENTRY: AccountEntry = {
  email: "alice@example.com",
  scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
  added_at: "2026-05-06T07:30:00.000Z",
  last_used_at: null,
};

const SAMPLE: AccountsIndex = { version: 1, accounts: [ENTRY] };

describe("loadIndex", () => {
  test("returns empty index when no files exist", async () => {
    const idx = await loadIndex();
    expect(idx).toEqual({ version: 2, accounts: [] });
  });

  test("reads a valid primary index", async () => {
    await saveIndex(SAMPLE);
    const idx = await loadIndex();
    expect(idx).toEqual(SAMPLE);
  });

  test("falls back to .bak when primary is corrupt", async () => {
    await saveIndex(SAMPLE); // creates accounts.json
    await saveIndex(SAMPLE); // creates accounts.json.bak (copy of prior)
    await fs.writeFile(path.join(configDir(), "accounts.json"), "{not json", { mode: 0o600 });
    const idx = await loadIndex();
    expect(idx).toEqual(SAMPLE);
  });

  test("returns empty when primary missing AND backup also corrupt", async () => {
    await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
    await fs.writeFile(path.join(configDir(), "accounts.json.bak"), "garbage", { mode: 0o600 });
    const idx = await loadIndex();
    expect(idx).toEqual({ version: 2, accounts: [] });
  });

  test("rejects wrong version (treats as corrupt)", async () => {
    await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
    await fs.writeFile(
      path.join(configDir(), "accounts.json"),
      JSON.stringify({ version: 99, accounts: [] }),
      { mode: 0o600 },
    );
    const idx = await loadIndex();
    expect(idx).toEqual({ version: 2, accounts: [] });
  });

  test("v2.0 PR-2b: reads v1 on-disk format (migrate-v2 compat)", async () => {
    // The reader must accept v1 so the upcoming `safespace migrate-v2` CLI
    // can load legacy `safespace-read/` and `safespace-send/` indexes
    // without flagging them as corrupt.
    await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
    const v1Index: AccountsIndex = { version: 1, accounts: [ENTRY] };
    await fs.writeFile(
      path.join(configDir(), "accounts.json"),
      JSON.stringify(v1Index),
      { mode: 0o600 },
    );
    const idx = await loadIndex();
    expect(idx).toEqual(v1Index);
  });

  test("v2.0 PR-2b: mutation upgrades on-disk format v1 → v2", async () => {
    // upsertAccount loads any-version index, but must persist as v2 — so a
    // partially-migrated config dir (v1 file on disk) self-heals on the
    // first write.
    await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
    await fs.writeFile(
      path.join(configDir(), "accounts.json"),
      JSON.stringify({ version: 1, accounts: [] }),
      { mode: 0o600 },
    );
    await upsertAccount(ENTRY);
    const raw = await fs.readFile(path.join(configDir(), "accounts.json"), "utf8");
    const parsed = JSON.parse(raw);
    expect(parsed.version).toBe(2);
    expect(parsed.accounts).toEqual([ENTRY]);
  });
});

describe("saveIndex", () => {
  test("creates config dir at 0o700", async () => {
    await saveIndex(SAMPLE);
    const stat = await fs.stat(configDir());
    expect(stat.mode & 0o777).toBe(0o700);
  });

  test("writes accounts.json at 0o600", async () => {
    await saveIndex(SAMPLE);
    const stat = await fs.stat(path.join(configDir(), "accounts.json"));
    expect(stat.mode & 0o777).toBe(0o600);
  });

  test("creates .bak (copy of previous) before overwriting", async () => {
    const v1: AccountsIndex = { version: 1, accounts: [{ ...ENTRY, email: "v1@example.com" }] };
    const v2: AccountsIndex = { version: 1, accounts: [{ ...ENTRY, email: "v2@example.com" }] };
    await saveIndex(v1);
    await saveIndex(v2);
    const bakRaw = await fs.readFile(path.join(configDir(), "accounts.json.bak"), "utf8");
    expect(JSON.parse(bakRaw)).toEqual(v1);
    const liveRaw = await fs.readFile(path.join(configDir(), "accounts.json"), "utf8");
    expect(JSON.parse(liveRaw)).toEqual(v2);
  });

  test("does not leave stray .tmp files on success", async () => {
    await saveIndex(SAMPLE);
    const files = await fs.readdir(configDir());
    expect(files.some((f) => f.includes(".tmp."))).toBe(false);
  });
});

describe("upsertAccount / removeAccount", () => {
  test("upsert adds a new entry", async () => {
    await upsertAccount(ENTRY);
    const idx = await loadIndex();
    expect(idx.accounts).toEqual([ENTRY]);
  });

  test("upsert replaces an existing entry by email", async () => {
    await upsertAccount(ENTRY);
    const updated: AccountEntry = { ...ENTRY, last_used_at: "2026-05-06T08:00:00.000Z" };
    await upsertAccount(updated);
    const idx = await loadIndex();
    expect(idx.accounts).toHaveLength(1);
    expect(idx.accounts[0]).toEqual(updated);
  });

  test("remove drops the entry by email; idempotent if missing", async () => {
    await upsertAccount(ENTRY);
    await removeAccount(ENTRY.email);
    const idx1 = await loadIndex();
    expect(idx1.accounts).toEqual([]);
    await removeAccount(ENTRY.email);
    const idx2 = await loadIndex();
    expect(idx2.accounts).toEqual([]);
  });
});
