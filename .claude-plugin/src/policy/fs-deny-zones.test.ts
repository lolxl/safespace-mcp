// fs_read deny zones (CARRY-FORWARD item 12): SafeSpace's own stores, AI-client config,
// /proc and /dev are never readable through fs_read, whatever the roots allow, and a
// denial answers exactly like the gate's ordinary outcome for the same position. Real
// temp dirs, symlinks, hard links and a FIFO — not mocks.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { MCPError } from "../errors";
import { EMPTY_DENY_INDEX, buildDenyIndex, inDenyZone, zoneSpec } from "./fs-deny-zones";
import { type FsRootsState, __internal as gateInternal, readThroughGate } from "./fs-gate";

async function outcome(p: Promise<unknown>): Promise<{ name: string; reason: unknown } | "read"> {
  try {
    await p;
    return "read";
  } catch (e) {
    if (e instanceof MCPError) return { name: e.errorName, reason: e.errorData?.reason };
    throw e;
  }
}

const NOT_FOUND = { name: "fs_read_failed", reason: "not_found" };
const OUTSIDE = { name: "path_blocked_by_policy", reason: "not_in_allowlist" };

const realFs = {
  realpath: (p: string) => fs.realpath(p),
  lstat: (p: string) => fs.lstat(p, { bigint: true }),
  stat: (p: string) => fs.stat(p, { bigint: true }),
  readdir: (p: string) => fs.readdir(p),
};

let T = "";
const saved: Record<string, string | undefined> = {};
const ENV = ["SAFESPACE_CONFIG_DIR", "CLAUDE_PLUGIN_DATA"] as const;
const rootsAt = (...roots: string[]): FsRootsState => ({
  kind: "active",
  roots,
  platform: process.platform,
});

beforeEach(async () => {
  for (const k of ENV) saved[k] = process.env[k];
  // Canonical temp dir (macOS /var → /private/var) so expectations compare cleanly.
  T = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "fsdeny-")));
  process.env.SAFESPACE_CONFIG_DIR = path.join(T, "cfg");
  delete process.env.CLAUDE_PLUGIN_DATA;
  await fs.mkdir(path.join(T, "cfg"));
  await fs.writeFile(path.join(T, "cfg", "secret.key"), "TOP-SECRET-KEY");
  await fs.writeFile(path.join(T, "cfg", ".env"), "SAFESPACE_SECRET_PASSPHRASE=hunter2");
  await fs.mkdir(path.join(T, "data"));
  await fs.writeFile(path.join(T, "data", "notes.txt"), "ordinary");
});

afterEach(async () => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  await fs.rm(T, { recursive: true, force: true });
});

describe("the config dir is never readable", () => {
  test("a broad root covering the config dir: a secret answers like a missing file", async () => {
    const state = rootsAt(T);
    expect(await outcome(readThroughGate(path.join(T, "cfg", "secret.key"), { state }))).toEqual(NOT_FOUND);
    expect(await outcome(readThroughGate(path.join(T, "cfg", "absent"), { state }))).toEqual(NOT_FOUND);
    expect(await outcome(readThroughGate(path.join(T, "data", "absent"), { state }))).toEqual(NOT_FOUND);
    expect(await outcome(readThroughGate(path.join(T, "data", "notes.txt"), { state }))).toBe("read");
  });

  test("a root set exactly to the config dir reads nothing", async () => {
    const state = rootsAt(path.join(T, "cfg"));
    expect(await outcome(readThroughGate(path.join(T, "cfg", ".env"), { state }))).toEqual(NOT_FOUND);
  });

  test("a config dir outside the roots answers like any other out-of-root path", async () => {
    const state = rootsAt(path.join(T, "data"));
    expect(await outcome(readThroughGate(path.join(T, "cfg", "secret.key"), { state }))).toEqual(OUTSIDE);
    expect(await outcome(readThroughGate(path.join(T, "elsewhere", "x"), { state }))).toEqual(OUTSIDE);
  });

  test("zone and non-zone paths through the same outward symlink answer identically", async () => {
    await fs.mkdir(path.join(T, "other"));
    await fs.writeFile(path.join(T, "other", "f"), "x");
    await fs.symlink(path.join(T, "cfg"), path.join(T, "data", "to-cfg"));
    await fs.symlink(path.join(T, "other"), path.join(T, "data", "to-other"));
    const state = rootsAt(path.join(T, "data"));
    const zone = await outcome(readThroughGate(path.join(T, "data", "to-cfg", "secret.key"), { state }));
    const plain = await outcome(readThroughGate(path.join(T, "data", "to-other", "f"), { state }));
    expect(zone).toEqual(OUTSIDE);
    expect(plain).toEqual(OUTSIDE);
  });

  test("an in-root symlink into the config dir does not read it", async () => {
    await fs.symlink(path.join(T, "cfg", "secret.key"), path.join(T, "data", "link"));
    const state = rootsAt(T);
    expect(await outcome(readThroughGate(path.join(T, "data", "link"), { state }))).toEqual(NOT_FOUND);
  });

  test("a hard link to a config file inside a root is refused by identity", async () => {
    await fs.link(path.join(T, "cfg", "secret.key"), path.join(T, "data", "hl"));
    const state = rootsAt(path.join(T, "data"));
    expect(await outcome(readThroughGate(path.join(T, "data", "hl"), { state }))).toEqual(NOT_FOUND);
  });

  test("the compiled-in default config dir stays denied when overridden", async () => {
    const index = await buildDenyIndex(process.platform, realFs);
    const def = path.join(os.homedir(), ".config", "safespace", "secret.key");
    expect(inDenyZone(def, index, process.platform)).toBe(process.platform !== "win32");
  });
});

describe("plugin-data, legacy and migration dirs", () => {
  test("every store dir under CLAUDE_PLUGIN_DATA is denied; a look-alike sibling is not", async () => {
    process.env.CLAUDE_PLUGIN_DATA = path.join(T, "pd");
    const state = rootsAt(T);
    for (const d of [
      "safespace",
      "safespace-read",
      "safespace-send",
      "safespace.tmp",
      "safespace-read.migrated",
      "safespace-send.migrated",
    ]) {
      await fs.mkdir(path.join(T, "pd", d), { recursive: true });
      await fs.writeFile(path.join(T, "pd", d, ".env"), "GOOGLE_CLIENT_SECRET=x");
      expect(await outcome(readThroughGate(path.join(T, "pd", d, ".env"), { state }))).toEqual(NOT_FOUND);
    }
    await fs.mkdir(path.join(T, "pd", "safespace-other"));
    await fs.writeFile(path.join(T, "pd", "safespace-other", "ok.txt"), "fine");
    expect(await outcome(readThroughGate(path.join(T, "pd", "safespace-other", "ok.txt"), { state }))).toBe("read");
  });
});

describe("AI-client config", () => {
  test("client dirs and ~/.claude.json* are denied; other home files read", async () => {
    const home = path.join(T, "home");
    for (const d of [".claude", ".cursor", ".codex", ".gemini", ".codeium"]) {
      await fs.mkdir(path.join(home, d), { recursive: true });
      await fs.writeFile(path.join(home, d, "mcp.json"), "{\"env\":{\"GOOGLE_CLIENT_SECRET\":\"x\"}}");
    }
    await fs.writeFile(path.join(home, ".claude.json"), "{}");
    await fs.writeFile(path.join(home, ".claude.json.backup"), "{}");
    await fs.writeFile(path.join(home, "notes.txt"), "fine");
    const denyIndex = await buildDenyIndex(process.platform, realFs, process.env, home);
    const state = rootsAt(home);
    for (const p of [
      path.join(home, ".claude", "mcp.json"),
      path.join(home, ".cursor", "mcp.json"),
      path.join(home, ".codex", "mcp.json"),
      path.join(home, ".gemini", "mcp.json"),
      path.join(home, ".codeium", "mcp.json"),
      path.join(home, ".claude.json"),
      path.join(home, ".claude.json.backup"),
    ]) {
      expect(await outcome(readThroughGate(p, { state, denyIndex }))).toEqual(NOT_FOUND);
    }
    expect(await outcome(readThroughGate(path.join(home, "notes.txt"), { state, denyIndex }))).toBe("read");
  });

  test("a hard link to ~/.claude.json elsewhere is refused by identity", async () => {
    const home = path.join(T, "home");
    await fs.mkdir(home);
    await fs.writeFile(path.join(home, ".claude.json"), "{}");
    await fs.link(path.join(home, ".claude.json"), path.join(T, "data", "copy.json"));
    const denyIndex = await buildDenyIndex(process.platform, realFs, process.env, home);
    const state = rootsAt(path.join(T, "data"));
    expect(await outcome(readThroughGate(path.join(T, "data", "copy.json"), { state, denyIndex }))).toEqual(NOT_FOUND);
  });
});

describe("pseudo filesystems and special files", () => {
  test.skipIf(process.platform === "win32")("/dev and /proc are denied under a root of /", async () => {
    const state = rootsAt("/");
    expect(await outcome(readThroughGate("/dev/null", { state }))).toEqual(NOT_FOUND);
    expect(await outcome(readThroughGate("/proc/self/status", { state }))).toEqual(NOT_FOUND);
  });

  test.skipIf(process.platform === "win32")("a FIFO under a root returns promptly instead of hanging", async () => {
    const fifo = path.join(T, "data", "pipe");
    expect(spawnSync("mkfifo", [fifo]).status).toBe(0);
    const state = rootsAt(path.join(T, "data"));
    const started = Date.now();
    const result = await outcome(readThroughGate(fifo, { state }));
    expect(Date.now() - started).toBeLessThan(2000);
    expect(result).toEqual({ name: "fs_read_failed", reason: "not_a_file" });
  });
});

describe("robustness", () => {
  test("absent zone dirs (fresh install) do not block ordinary reads", async () => {
    await fs.rm(path.join(T, "cfg"), { recursive: true });
    const state = rootsAt(T);
    expect(await outcome(readThroughGate(path.join(T, "data", "notes.txt"), { state }))).toBe("read");
  });

  test("a dangling symlink inside the config dir does not block ordinary reads", async () => {
    await fs.symlink(path.join(T, "nowhere"), path.join(T, "cfg", "dangling"));
    const state = rootsAt(T);
    expect(await outcome(readThroughGate(path.join(T, "data", "notes.txt"), { state }))).toBe("read");
  });

  test("an index that could not be built fails every read closed", async () => {
    const state = rootsAt(T);
    const denyIndex = { ...EMPTY_DENY_INDEX, failed: true };
    expect(await outcome(readThroughGate(path.join(T, "data", "notes.txt"), { state, denyIndex }))).toEqual(NOT_FOUND);
    const outside = rootsAt(path.join(T, "data"));
    expect(await outcome(readThroughGate(path.join(T, "x", "y"), { state: outside, denyIndex }))).toEqual(OUTSIDE);
  });

  test("a file whose identity cannot be established is not read", async () => {
    const state = rootsAt(T);
    const openImpl = async () => ({
      stat: async () => ({ isFile: () => true, size: 3n, dev: 1n, ino: 0n }),
      read: async () => Buffer.from("abc"),
      close: async () => {},
    });
    expect(
      await outcome(readThroughGate(path.join(T, "data", "notes.txt"), { state, openImpl, denyIndex: EMPTY_DENY_INDEX })),
    ).toEqual(NOT_FOUND);
  });

  test("darwin deny comparison is case-insensitive; linux is not", async () => {
    const index = { ...EMPTY_DENY_INDEX, zonePaths: ["/Users/x/.config/safespace"] };
    expect(inDenyZone("/users/X/.Config/SafeSpace/secret.key", index, "darwin")).toBe(true);
    expect(inDenyZone("/users/X/.Config/SafeSpace/secret.key", index, "linux")).toBe(false);
    expect(inDenyZone("/Users/x/.config/safespace-other/f", index, "darwin")).toBe(false);
  });
});

// Each defence layer on its own (a test per layer, so removing any one goes red).
describe("each layer independently", () => {
  const state = (): FsRootsState => rootsAt(path.join(T, "data"));
  const fileOpen = (dev: bigint, ino: bigint, isFile = true) => async () => ({
    stat: async () => ({ isFile: () => isFile, size: 3n, dev, ino }),
    read: async () => Buffer.from("abc"),
    close: async () => {},
  });
  const fresh = async () => ({ dev: 7n, ino: BigInt(Math.floor(Math.random() * 1e9) + 10) });

  test("ancestor identity alone: an ancestor that is a zone directory refuses the read", async () => {
    const denyIndex = { ...EMPTY_DENY_INDEX, dirIds: new Set(["9:99"]) };
    const ancestorStatImpl = async (p: string) =>
      p === path.join(T, "data") ? { dev: 9n, ino: 99n } : fresh();
    expect(
      await outcome(
        readThroughGate(path.join(T, "data", "notes.txt"), {
          state: state(),
          denyIndex,
          openImpl: fileOpen(1n, 5n),
          ancestorStatImpl,
        }),
      ),
    ).toEqual(NOT_FOUND);
  });

  test("opened-object identity alone: opening a zone directory's alias refuses (not not_a_file)", async () => {
    const denyIndex = { ...EMPTY_DENY_INDEX, dirIds: new Set(["3:33"]) };
    expect(
      await outcome(
        readThroughGate(path.join(T, "data", "notes.txt"), {
          state: state(),
          denyIndex,
          openImpl: fileOpen(3n, 33n, false),
          ancestorStatImpl: fresh,
        }),
      ),
    ).toEqual(NOT_FOUND);
  });

  test("O_NOFOLLOW: a final component swapped for a symlink (ELOOP) is not read", async () => {
    const openImpl = async () => {
      throw Object.assign(new Error("loop"), { code: "ELOOP" });
    };
    expect(
      await outcome(
        readThroughGate(path.join(T, "data", "notes.txt"), { state: state(), denyIndex: EMPTY_DENY_INDEX, openImpl }),
      ),
    ).toEqual(NOT_FOUND);
  });

  test("inventory cap: a store with more than 2000 entries fails the index closed", async () => {
    const big = { ...realFs, readdir: async () => Array.from({ length: 2001 }, (_, i) => `f${i}`) };
    const index = await buildDenyIndex(process.platform, big, process.env, path.join(T, "home"));
    expect(index.failed).toBe(true);
  });

  test.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "an unreadable store directory fails the index closed",
    async () => {
      await fs.chmod(path.join(T, "cfg"), 0o000);
      try {
        const index = await buildDenyIndex(process.platform, realFs, process.env, path.join(T, "home"));
        expect(index.failed).toBe(true);
      } finally {
        await fs.chmod(path.join(T, "cfg"), 0o700);
      }
    },
  );

  test("an unresolvable zone path (EACCES) fails the index closed instead of throwing", async () => {
    const throwingEnv = { ...process.env };
    const index = await buildDenyIndex(
      process.platform,
      { ...realFs, realpath: async () => { throw Object.assign(new Error("x"), { code: "EACCES" }); } },
      throwingEnv,
      path.join(T, "home"),
    );
    expect(index.failed).toBe(true);
  });
});

describe("review fixes", () => {
  test("a symlinked ~/.claude.json is protected by its target's identity", async () => {
    const home = path.join(T, "home");
    await fs.mkdir(home);
    await fs.mkdir(path.join(T, "dotfiles"));
    await fs.writeFile(path.join(T, "dotfiles", "claude.json"), "SECRET");
    await fs.symlink(path.join(T, "dotfiles", "claude.json"), path.join(home, ".claude.json"));
    await fs.link(path.join(T, "dotfiles", "claude.json"), path.join(T, "data", "alias.json"));
    const denyIndex = await buildDenyIndex(process.platform, realFs, process.env, home);
    expect(
      await outcome(readThroughGate(path.join(T, "data", "alias.json"), { state: rootsAt(path.join(T, "data")), denyIndex })),
    ).toEqual(NOT_FOUND);
  });

  test("the same store directory under two names is walked once", async () => {
    let cfgReads = 0;
    const counting = {
      ...realFs,
      readdir: async (p: string) => {
        if (p === path.join(T, "cfg")) cfgReads++;
        return fs.readdir(p);
      },
    };
    // Config dir T/cfg, and CLAUDE_PLUGIN_DATA/safespace is a symlink to it: two store
    // names, one directory.
    await fs.mkdir(path.join(T, "pd"));
    await fs.symlink(path.join(T, "cfg"), path.join(T, "pd", "safespace"));
    process.env.CLAUDE_PLUGIN_DATA = path.join(T, "pd");
    const home = path.join(T, "home");
    await fs.mkdir(home);
    const index = await buildDenyIndex(process.platform, counting, process.env, home);
    expect(index.failed).toBe(false);
    // The alias resolves to the same directory: it is walked exactly once.
    expect(cfgReads).toBe(1);
  });

  test("an unopenable regular file keeps read_error (reachable when open fails after realpath succeeded; Bun's realpath already fails on mode 000)", async () => {
    const openImpl = async () => {
      throw Object.assign(new Error("denied"), { code: "EACCES" });
    };
    expect(
      await outcome(
        readThroughGate(path.join(T, "data", "notes.txt"), { state: rootsAt(path.join(T, "data")), denyIndex: EMPTY_DENY_INDEX, openImpl }),
      ),
    ).toEqual({ name: "fs_read_failed", reason: "read_error" });
  });

  test("a non-file that cannot be opened keeps not_a_file", async () => {
    const openImpl = async () => {
      throw Object.assign(new Error("dir"), { code: "EISDIR" });
    };
    expect(
      await outcome(
        readThroughGate(path.join(T, "data"), { state: rootsAt(T), denyIndex: EMPTY_DENY_INDEX, openImpl }),
      ),
    ).toEqual({ name: "fs_read_failed", reason: "not_a_file" });
  });

  test("linux inventory: ~/.CLAUDE.JSON is not inventoried as a protected file", async () => {
    const home = path.join(T, "home");
    await fs.mkdir(home);
    await fs.writeFile(path.join(home, ".CLAUDE.JSON"), "{}");
    const st = await fs.stat(path.join(home, ".CLAUDE.JSON"), { bigint: true });
    const index = await buildDenyIndex("linux", realFs, process.env, home);
    expect(index.fileIds.has(`${st.dev}:${st.ino}`)).toBe(false);
    const darwin = await buildDenyIndex("darwin", realFs, process.env, home);
    expect(darwin.fileIds.has(`${st.dev}:${st.ino}`)).toBe(true);
  });

  test("linux: ~/.CLAUDE.JSON is an ordinary file (case-sensitive), darwin denies it", async () => {
    const home = "/home/u";
    const index = { ...EMPTY_DENY_INDEX, homeForms: [home] };
    expect(inDenyZone("/home/u/.CLAUDE.JSON", index, "linux")).toBe(false);
    expect(inDenyZone("/home/u/.claude.json.backup", index, "linux")).toBe(true);
    expect(inDenyZone("/home/u/.CLAUDE.JSON", index, "darwin")).toBe(true);
  });

  test("win32 zone table: Desktop dir under APPDATA, ~/.claude.json*, case-folded", () => {
    const spec = zoneSpec("win32", { APPDATA: "C:\\Users\\x\\AppData\\Roaming" }, "C:\\Users\\x");
    expect(spec.clientDirs).toContain("C:\\Users\\x\\AppData\\Roaming\\Claude");
    expect(spec.pseudo).toEqual([]);
    const index = {
      ...EMPTY_DENY_INDEX,
      zonePaths: [...spec.clientDirs, ...spec.stores],
      homeForms: ["C:\\Users\\x"],
    };
    expect(inDenyZone("c:\\users\\X\\.claude.json.backup", index, "win32")).toBe(true);
    expect(inDenyZone("C:\\Users\\x\\AppData\\Roaming\\claude\\claude_desktop_config.json", index, "win32")).toBe(true);
    expect(inDenyZone("C:\\Users\\x\\AppData\\Roaming\\safespace-other\\f", index, "win32")).toBe(false);
  });
});

test.skipIf(process.platform === "win32")("the open flags include O_NOFOLLOW and O_NONBLOCK", async () => {
  const { constants } = await import("node:fs");
  expect(gateInternal.OPEN_FLAGS & constants.O_NOFOLLOW).toBe(constants.O_NOFOLLOW);
  expect(gateInternal.OPEN_FLAGS & constants.O_NONBLOCK).toBe(constants.O_NONBLOCK);
});

describe("open-failure path under a protected directory alias", () => {
  test("EACCES / socket under a zone-dir alias answer not_found, not read_error / not_a_file", async () => {
    const denyIndex = { ...EMPTY_DENY_INDEX, dirIds: new Set(["9:99"]) };
    const ancestorStatImpl = async (p: string) =>
      p === path.join(T, "data") ? { dev: 9n, ino: 99n } : { dev: 7n, ino: BigInt(p.length) + 100n };
    for (const code of ["EACCES", "EOPNOTSUPP"]) {
      const openImpl = async () => {
        throw Object.assign(new Error(code), { code });
      };
      expect(
        await outcome(
          readThroughGate(path.join(T, "data", "notes.txt"), {
            state: rootsAt(path.join(T, "data")),
            denyIndex,
            openImpl,
            ancestorStatImpl,
          }),
        ),
      ).toEqual(NOT_FOUND);
    }
  });
});

test("a deeply nested store file hard-linked into a root is refused", async () => {
  await fs.mkdir(path.join(T, "cfg", "a", "b", "c"), { recursive: true });
  await fs.writeFile(path.join(T, "cfg", "a", "b", "c", "deep.key"), "DEEP");
  await fs.link(path.join(T, "cfg", "a", "b", "c", "deep.key"), path.join(T, "data", "deep-alias"));
  expect(
    await outcome(readThroughGate(path.join(T, "data", "deep-alias"), { state: rootsAt(path.join(T, "data")) })),
  ).toEqual(NOT_FOUND);
});
