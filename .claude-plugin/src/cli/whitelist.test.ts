import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { configDir } from "../auth/keychain";
import { CliError, runCli, type CliIO } from "../cli";
import { loadWhitelist, WHITELIST_FILENAME } from "../policy/drive-whitelist";

const FOLDER_A = "1aBcDeFgHiJkLmNoPqRs00";
const FOLDER_B = "2bCdEfGhIjKlMnOpQrSt00";
const FILE_A = "3cDeFgHiJkLmNoPqRsTu00";

let tmp: string;
let prevEnv: string | undefined;

beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  tmp = await fs.mkdtemp(path.join(tmpdir(), "wl-cli-"));
  process.env.SAFESPACE_CONFIG_DIR = tmp;
});

afterEach(async () => {
  if (prevEnv === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevEnv;
  await fs.rm(tmp, { recursive: true, force: true });
});

function captureIO(): { io: CliIO; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: { out: (l) => out.push(l), err: (l) => err.push(l) },
    out,
    err,
  };
}

function whitelistPath(): string {
  return path.join(tmp, WHITELIST_FILENAME);
}

describe("whitelist list", () => {
  test("no file → policy-off message", async () => {
    const { io, out } = captureIO();
    await runCli(["whitelist", "list"], io);
    expect(out.join("\n")).toContain("policy is OFF");
  });

  test("malformed JSON → throws CliError + stderr context", async () => {
    await fs.writeFile(whitelistPath(), "not json");
    const { io, err } = captureIO();
    await expect(runCli(["whitelist", "list"], io)).rejects.toBeInstanceOf(CliError);
    expect(err.join("\n")).toMatch(/malformed/);
  });

  test("empty entries → default-deny message", async () => {
    await runCli(["whitelist", "add", FOLDER_A, "--type", "folder"], captureIO().io);
    await runCli(["whitelist", "remove", FOLDER_A], captureIO().io);
    const { io, out } = captureIO();
    await runCli(["whitelist", "list"], io);
    expect(out.join("\n")).toContain("default-deny");
  });

  test("populated → header + rows", async () => {
    await runCli(
      ["whitelist", "add", FOLDER_A, "--type", "folder", "--label", "Work shared drive"],
      captureIO().io,
    );
    const { io, out } = captureIO();
    await runCli(["whitelist", "list"], io);
    const text = out.join("\n");
    expect(text).toContain("TYPE");
    expect(text).toContain("ID");
    expect(text).toContain("LABEL");
    expect(text).toContain(FOLDER_A);
    expect(text).toContain("Work shared drive");
    expect(text).toContain("1 entry");
  });

  test("rejects extra args", async () => {
    const { io } = captureIO();
    await expect(runCli(["whitelist", "list", "extra"], io)).rejects.toThrow(/unexpected argument/);
  });
});

describe("whitelist add", () => {
  test("creates file at mode 0o600 on first add", async () => {
    const { io, out } = captureIO();
    await runCli(["whitelist", "add", FOLDER_A, "--type", "folder"], io);
    const stat = await fs.stat(whitelistPath());
    expect(stat.mode & 0o777).toBe(0o600);
    expect(out.join("\n")).toContain("added");
    expect(out.join("\n")).toContain("restart Claude Code");
  });

  test("requires --type", async () => {
    const { io } = captureIO();
    await expect(runCli(["whitelist", "add", FOLDER_A], io)).rejects.toThrow(/--type/);
  });

  test("rejects invalid drive id", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["whitelist", "add", "tooshort", "--type", "folder"], io),
    ).rejects.toThrow(/invalid Drive ID/);
  });

  test("rejects unknown --type value", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["whitelist", "add", FOLDER_A, "--type", "weird"], io),
    ).rejects.toThrow(/--type must be 'folder' or 'file'/);
  });

  test("rejects label with newline", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["whitelist", "add", FOLDER_A, "--type", "folder", "--label", "a\nb"], io),
    ).rejects.toThrow(/newlines/);
  });

  test("rejects label over 100 chars", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["whitelist", "add", FOLDER_A, "--type", "folder", "--label", "x".repeat(101)], io),
    ).rejects.toThrow(/100-character cap/);
  });

  test("dedup: re-adding same id is a no-op with stderr warn", async () => {
    await runCli(["whitelist", "add", FOLDER_A, "--type", "folder"], captureIO().io);

    const { io, err } = captureIO();
    await runCli(["whitelist", "add", FOLDER_A, "--type", "file"], io);
    expect(err.join("\n")).toMatch(/already in whitelist/);

    const data = JSON.parse(await fs.readFile(whitelistPath(), "utf8"));
    expect(data.entries).toHaveLength(1);
    expect(data.entries[0].type).toBe("folder");
  });

  test("appends multiple entries", async () => {
    await runCli(["whitelist", "add", FOLDER_A, "--type", "folder"], captureIO().io);
    await runCli(["whitelist", "add", FOLDER_B, "--type", "folder"], captureIO().io);
    await runCli(["whitelist", "add", FILE_A, "--type", "file"], captureIO().io);

    const data = JSON.parse(await fs.readFile(whitelistPath(), "utf8"));
    expect(data.entries).toHaveLength(3);
    expect(data.entries.map((e: { id: string }) => e.id)).toEqual([
      FOLDER_A,
      FOLDER_B,
      FILE_A,
    ]);
  });

  test("refuses to mutate when file is malformed", async () => {
    await fs.writeFile(whitelistPath(), "not json");
    const { io } = captureIO();
    await expect(
      runCli(["whitelist", "add", FOLDER_A, "--type", "folder"], io),
    ).rejects.toThrow(/malformed/);
  });
});

describe("whitelist remove", () => {
  test("removes existing entry", async () => {
    await runCli(["whitelist", "add", FOLDER_A, "--type", "folder"], captureIO().io);
    await runCli(["whitelist", "add", FOLDER_B, "--type", "folder"], captureIO().io);

    const { io, out } = captureIO();
    await runCli(["whitelist", "remove", FOLDER_A], io);

    const data = JSON.parse(await fs.readFile(whitelistPath(), "utf8"));
    expect(data.entries).toHaveLength(1);
    expect(data.entries[0].id).toBe(FOLDER_B);
    expect(out.join("\n")).toContain("removed");
  });

  test("not-found → CliError", async () => {
    await runCli(["whitelist", "add", FOLDER_A, "--type", "folder"], captureIO().io);
    const { io } = captureIO();
    await expect(runCli(["whitelist", "remove", FOLDER_B], io)).rejects.toThrow(/id not found/);
  });

  test("rejects invalid drive id", async () => {
    const { io } = captureIO();
    await expect(runCli(["whitelist", "remove", "bad-id"], io)).rejects.toThrow(/invalid Drive ID/);
  });

  test("file absent → CliError", async () => {
    const { io } = captureIO();
    await expect(runCli(["whitelist", "remove", FOLDER_A], io)).rejects.toThrow(
      /no drive-whitelist\.json/,
    );
  });
});

describe("whitelist usage", () => {
  test("no subcommand → CliError with usage", async () => {
    const { io } = captureIO();
    await expect(runCli(["whitelist"], io)).rejects.toThrow(/usage: safespace whitelist/);
  });

  test("unknown subcommand", async () => {
    const { io } = captureIO();
    await expect(runCli(["whitelist", "purge"], io)).rejects.toThrow(/unknown whitelist subcommand/);
  });
});

// v1.9 #4 — CLI ↔ policy round-trip integration. Locks the schema contract
// between the CLI's WhitelistFile output and the policy module's loadWhitelist
// parser. A future refactor that diverges (e.g., entry shape change in
// drive-whitelist.ts not reflected in cli/whitelist.ts) would break here.
describe("whitelist CLI ↔ policy round-trip", () => {
  test("CLI add → loadWhitelist returns equivalent entries", async () => {
    await runCli(
      ["whitelist", "add", FOLDER_A, "--type", "folder", "--label", "Work shared drive"],
      captureIO().io,
    );
    await runCli(
      ["whitelist", "add", FILE_A, "--type", "file", "--label", "Q2 report"],
      captureIO().io,
    );

    const state = await loadWhitelist(configDir());
    expect(state.kind).toBe("loaded");
    if (state.kind !== "loaded") return;

    expect(state.file.schema_version).toBe(1);
    expect(state.file.entries).toHaveLength(2);
    expect(state.file.entries[0]).toMatchObject({
      type: "folder",
      id: FOLDER_A,
      label: "Work shared drive",
    });
    expect(state.file.entries[1]).toMatchObject({
      type: "file",
      id: FILE_A,
      label: "Q2 report",
    });
    // added_at is ISO 8601 UTC — sanity check the format.
    expect(state.file.entries[0]!.added_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  test("CLI remove → loadWhitelist sees the deletion", async () => {
    await runCli(["whitelist", "add", FOLDER_A, "--type", "folder"], captureIO().io);
    await runCli(["whitelist", "add", FOLDER_B, "--type", "folder"], captureIO().io);
    await runCli(["whitelist", "remove", FOLDER_A], captureIO().io);

    const state = await loadWhitelist(configDir());
    expect(state.kind).toBe("loaded");
    if (state.kind !== "loaded") return;
    expect(state.file.entries).toHaveLength(1);
    expect(state.file.entries[0]!.id).toBe(FOLDER_B);
  });

  test("empty entries after remove-all → kind=loaded with empty array (active default-deny)", async () => {
    await runCli(["whitelist", "add", FOLDER_A, "--type", "folder"], captureIO().io);
    await runCli(["whitelist", "remove", FOLDER_A], captureIO().io);

    const state = await loadWhitelist(configDir());
    expect(state.kind).toBe("loaded");
    if (state.kind !== "loaded") return;
    // policy/drive-whitelist treats empty entries as default-deny (not absent).
    expect(state.file.entries).toEqual([]);
  });
});

