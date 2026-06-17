import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { MCPError } from "../errors";
import {
  __internal,
  buildFsRootsState,
  fsRootsSummary,
  type FsRootsState,
  parseFsRoots,
  readThroughGate,
} from "./fs-gate";

// v1.75 — the fs_read path gate: default-deny roots + lexical-containment + realpath
// symlink re-check + size/UTF-8/regular-file caps. These tests use REAL temp dirs +
// a REAL symlink so the realpath escape check is exercised end-to-end (not mocked).

async function nameOfThrow(p: Promise<unknown>): Promise<{ name: string; reason: unknown }> {
  try {
    await p;
    return { name: "<no throw>", reason: undefined };
  } catch (e) {
    return e instanceof MCPError
      ? { name: e.errorName, reason: e.errorData.reason }
      : { name: "<not MCPError>", reason: undefined };
  }
}

describe("parseFsRoots + buildFsRootsState", () => {
  test("rejects non-absolute entries; keeps absolute (normalized, deduped)", () => {
    const r = parseFsRoots("/srv/a, relative/b, /srv/a/../a, /srv/c");
    expect(r.ok).toEqual(["/srv/a", "/srv/c"]); // /srv/a/../a normalizes to /srv/a (dup)
    expect(r.rejected).toEqual(["relative/b"]);
  });

  test("unset (both undefined) → off (default-deny)", () => {
    expect(buildFsRootsState(undefined, undefined)).toEqual({ kind: "off" });
  });

  test("base + extra merge (deduped)", () => {
    const s = buildFsRootsState("/srv/a", "/srv/b,/srv/a") as { kind: "active"; roots: string[] };
    expect(s.kind).toBe("active");
    expect(s.roots.sort()).toEqual(["/srv/a", "/srv/b"]);
  });
});

describe("fsRootsSummary (doctor --posture — counts only)", () => {
  afterEach(() => {
    delete process.env.SAFESPACE_FS_READ_ROOTS;
    __internal.resetSingletons();
  });

  test("unset → off / 0", () => {
    delete process.env.SAFESPACE_FS_READ_ROOTS;
    __internal.resetSingletons();
    expect(fsRootsSummary()).toEqual({ kind: "off", count: 0 });
  });

  test("active → count, and NEVER the root paths (no-PII-echo)", () => {
    process.env.SAFESPACE_FS_READ_ROOTS = "/srv/secret-data,/home/alice/private";
    __internal.resetSingletons();
    const s = fsRootsSummary();
    expect(s).toEqual({ kind: "active", count: 2 });
    expect(JSON.stringify(s)).not.toContain("secret-data");
    expect(JSON.stringify(s)).not.toContain("alice");
  });
});

describe("withinRoots boundary-safety", () => {
  test("a sibling sharing a name prefix is NOT contained (the classic escape)", () => {
    expect(__internal.withinRoots("/srv/data-secret/x", ["/srv/data"])).toBe(false);
    expect(__internal.withinRoots("/srv/data/x", ["/srv/data"])).toBe(true);
    expect(__internal.withinRoots("/srv/data", ["/srv/data"])).toBe(true); // root itself
  });
});

describe("readThroughGate — real filesystem", () => {
  let root: string;
  let outside: string;
  let state: FsRootsState;

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), "fsgate-root-"));
    outside = await fs.mkdtemp(path.join(os.tmpdir(), "fsgate-out-"));
    state = { kind: "active", roots: [await fs.realpath(root)] }; // realpath: macOS /tmp→/private/tmp
  });
  afterEach(async () => {
    await fs.rm(root, { recursive: true, force: true });
    await fs.rm(outside, { recursive: true, force: true });
  });

  test("off state → no_allowlist (default-deny)", async () => {
    const t = await nameOfThrow(readThroughGate(path.join(root, "f.txt"), { state: { kind: "off" } }));
    expect(t).toEqual({ name: "path_blocked_by_policy", reason: "no_allowlist" });
  });

  test("a text file under an allowed root → reads its content", async () => {
    await fs.writeFile(path.join(root, "notes.md"), "hello world");
    const res = await readThroughGate(path.join(root, "notes.md"), { state });
    expect(res.content).toBe("hello world");
    expect(res.bytes).toBe(11);
  });

  test("a path OUTSIDE the roots → not_in_allowlist (no fs touch, no oracle)", async () => {
    await fs.writeFile(path.join(outside, "secret.txt"), "nope");
    const t = await nameOfThrow(readThroughGate(path.join(outside, "secret.txt"), { state }));
    expect(t).toEqual({ name: "path_blocked_by_policy", reason: "not_in_allowlist" });
  });

  test("`..` traversal out of the root → not_in_allowlist", async () => {
    const t = await nameOfThrow(
      readThroughGate(path.join(root, "..", "..", "etc", "passwd"), { state }),
    );
    expect(t.name).toBe("path_blocked_by_policy");
    expect(t.reason).toBe("not_in_allowlist");
  });

  test("SYMLINK inside the root pointing OUTSIDE → blocked by the realpath re-check", async () => {
    await fs.writeFile(path.join(outside, "target.txt"), "exfiltrated");
    // a symlink that is LEXICALLY inside the root but resolves outside it.
    await fs.symlink(path.join(outside, "target.txt"), path.join(root, "link.txt"));
    const t = await nameOfThrow(readThroughGate(path.join(root, "link.txt"), { state }));
    expect(t).toEqual({ name: "path_blocked_by_policy", reason: "not_in_allowlist" });
  });

  test("a directory → not_a_file", async () => {
    await fs.mkdir(path.join(root, "sub"));
    const t = await nameOfThrow(readThroughGate(path.join(root, "sub"), { state }));
    expect(t).toEqual({ name: "fs_read_failed", reason: "not_a_file" });
  });

  test("a nonexistent path UNDER the root → not_found", async () => {
    const t = await nameOfThrow(readThroughGate(path.join(root, "ghost.txt"), { state }));
    expect(t).toEqual({ name: "fs_read_failed", reason: "not_found" });
  });

  test("a binary file (NUL byte) → not_text", async () => {
    await fs.writeFile(path.join(root, "bin"), Buffer.from([0x68, 0x00, 0x69]));
    const t = await nameOfThrow(readThroughGate(path.join(root, "bin"), { state }));
    expect(t).toEqual({ name: "fs_read_failed", reason: "not_text" });
  });

  test("invalid UTF-8 → not_text", async () => {
    await fs.writeFile(path.join(root, "bad"), Buffer.from([0xff, 0xfe, 0xfd]));
    const t = await nameOfThrow(readThroughGate(path.join(root, "bad"), { state }));
    expect(t).toEqual({ name: "fs_read_failed", reason: "not_text" });
  });

  test("over the 5 MB cap → too_large (statImpl injected to avoid a huge write)", async () => {
    await fs.writeFile(path.join(root, "big.txt"), "x");
    const fakeStat = (async () => ({ isFile: () => true, size: __internal.MAX_BYTES + 1 })) as never;
    const t = await nameOfThrow(
      readThroughGate(path.join(root, "big.txt"), { state, statImpl: fakeStat }),
    );
    expect(t).toEqual({ name: "fs_read_failed", reason: "too_large" });
  });

  test("a RELATIVE path is rejected before resolving (sec-rev NIT-1, never cwd-relative)", async () => {
    const t = await nameOfThrow(readThroughGate("notes.md", { state }));
    expect(t).toEqual({ name: "path_blocked_by_policy", reason: "not_in_allowlist" });
  });

  test("a SYMLINKED root config still reads a file under it (root realpath'd per call)", async () => {
    await fs.writeFile(path.join(root, "real.txt"), "via symlinked root");
    // Configure the root as a SYMLINK to the real dir (not its realpath).
    const linkRoot = path.join(outside, "rootlink");
    await fs.symlink(root, linkRoot);
    const symState: FsRootsState = { kind: "active", roots: [linkRoot] };
    const res = await readThroughGate(path.join(linkRoot, "real.txt"), { state: symState });
    expect(res.content).toBe("via symlinked root"); // root + request both realpath'd → match
  });
});

// v1.108 PR 1b — win32 hardening. These run on the POSIX CI runner by injecting
// platform:"win32" (gate selects path.win32) + mocked fs, so the Windows path forms
// are exercised without a Windows host. POSIX behaviour above is unchanged.

describe("isForbiddenWin32Form (S8/S10/S11 classification)", () => {
  const W = (p: string): boolean => __internal.isForbiddenWin32Form(p, "win32");
  test("S8 — device-namespace / extended-length prefixes rejected", () => {
    expect(W("\\\\?\\C:\\data\\x")).toBe(true); // \\?\ extended-length
    expect(W("\\\\.\\C:")).toBe(true); // \\.\ device namespace
    expect(W("//?/C:/x")).toBe(true); // forward-slash variant
    expect(W("//./PhysicalDrive0")).toBe(true); // forward-slash device prefix (sec-rev L-4)
  });
  test("S10 — Alternate Data Stream colon rejected", () => {
    expect(W("C:\\data\\public.txt:secret")).toBe(true);
    expect(W("C:\\data\\public.txt::$DATA")).toBe(true);
  });
  test("S11 — drive-relative-rooted `\\foo` rejected (current-drive ambiguous)", () => {
    expect(W("\\foo\\bar")).toBe(true);
    // A `\\?server\share` (server name starting with `?`) matches NEITHER the device
    // regex (no separator after `?`) NOR the UNC regex (`?` is excluded) → falls to the
    // not-drive-not-UNC reject. Safe over-reject of an ambiguous form (sec-rev L-2).
    expect(W("\\\\?server\\share")).toBe(true);
  });
  test("a fully-qualified drive / UNC path is permitted", () => {
    expect(W("C:\\data\\notes.txt")).toBe(false);
    expect(W("C:/data/notes.txt")).toBe(false);
    expect(W("\\\\server\\share\\f.txt")).toBe(false);
  });
  test("OFF win32 → always false (the POSIX gate is untouched)", () => {
    expect(__internal.isForbiddenWin32Form("\\\\?\\C:\\x", "darwin")).toBe(false);
    expect(__internal.isForbiddenWin32Form("C:\\a:b", "linux")).toBe(false);
  });
});

describe("parseFsRoots — win32 platform", () => {
  test("keeps drive-absolute roots (normalized); rejects relative + forbidden forms", () => {
    const r = parseFsRoots(
      "C:\\Data, C:/More, relative, C:foo, \\foo, \\\\?\\C:\\x, C:\\a\\b.txt:ads",
      "win32",
    );
    expect(r.ok).toEqual(["C:\\Data", "C:\\More"]); // C:/More → backslash-normalized
    expect(r.rejected).toEqual(["relative", "C:foo", "\\foo", "\\\\?\\C:\\x", "C:\\a\\b.txt:ads"]);
  });
  test("S12 — a UNC root is KEPT but flagged for a network-share warning", () => {
    const r = parseFsRoots("\\\\server\\share", "win32");
    expect(r.ok).toEqual(["\\\\server\\share\\"]); // win32.resolve appends a trailing sep
    expect(r.unc).toEqual(["\\\\server\\share"]); // the raw form the operator typed
  });
});

describe("readThroughGate — win32 semantics (mocked fs on the POSIX runner)", () => {
  const winState = (roots: string[]): FsRootsState => ({ kind: "active", roots, platform: "win32" });
  const idRealpath = async (p: string): Promise<string> => p; // identity (preserves case)
  const fileStat = (async () => ({ isFile: () => true, size: 5 })) as never;
  const readHello = (async () => Buffer.from("hello")) as never;

  test("a file under a drive-absolute root reads", async () => {
    const res = await readThroughGate("C:\\Data\\notes.txt", {
      state: winState(["C:\\Data"]),
      realpathImpl: idRealpath,
      statImpl: fileStat,
      readFileImpl: readHello,
    });
    expect(res.content).toBe("hello");
    expect(res.path).toBe("C:\\Data\\notes.txt");
  });

  test("S12 — a file under a UNC root (trailing-sep, as win32.resolve emits) reads (sec-rev L-3)", async () => {
    const res = await readThroughGate("\\\\server\\share\\notes.txt", {
      state: winState(["\\\\server\\share\\"]), // win32.resolve appends the trailing sep
      realpathImpl: idRealpath,
      statImpl: fileStat,
      readFileImpl: readHello,
    });
    expect(res.content).toBe("hello"); // the r.endsWith(sep) boundary guard handles the trailing sep
  });

  test("S9 — case-INSENSITIVE containment: lowercase request under a mixed-case root reads", async () => {
    const res = await readThroughGate("c:\\data\\notes.txt", {
      state: winState(["C:\\Data"]), // realpath identity → the case genuinely differs
      realpathImpl: idRealpath,
      statImpl: fileStat,
      readFileImpl: readHello,
    });
    expect(res.content).toBe("hello"); // only matches because withinRoots folds en-US
  });

  test("`..` traversal OUT of the root is blocked (win32 resolve collapses ..)", async () => {
    const t = await nameOfThrow(
      readThroughGate("C:\\Data\\..\\..\\Windows\\sys.txt", {
        state: winState(["C:\\Data"]),
        realpathImpl: idRealpath,
      }),
    );
    expect(t).toEqual({ name: "path_blocked_by_policy", reason: "not_in_allowlist" });
  });

  test("S10 — an ADS request is blocked before any fs touch", async () => {
    const t = await nameOfThrow(
      readThroughGate("C:\\Data\\notes.txt:secret", { state: winState(["C:\\Data"]) }),
    );
    expect(t).toEqual({ name: "path_blocked_by_policy", reason: "not_in_allowlist" });
  });

  test("S8 — a `\\\\?\\` device-prefix request is blocked", async () => {
    const t = await nameOfThrow(
      readThroughGate("\\\\?\\C:\\Data\\notes.txt", { state: winState(["C:\\Data"]) }),
    );
    expect(t).toEqual({ name: "path_blocked_by_policy", reason: "not_in_allowlist" });
  });

  test("S11 — a drive-relative `\\foo` request is blocked", async () => {
    const t = await nameOfThrow(
      readThroughGate("\\foo\\notes.txt", { state: winState(["C:\\Data"]) }),
    );
    expect(t).toEqual({ name: "path_blocked_by_policy", reason: "not_in_allowlist" });
  });

  // HIGH#1 (security-review): forces the canonicalize() ancestor-walk branch under
  // win32. The root realpaths to a DIFFERENT canonical (C:\Real, a junction), so the
  // missing-tail rejoin must use win32 dirname/join to stay contained. A POSIX dirname
  // would mis-parse `C:\Data\ghost.txt` (dirname → ".") and wrongly report
  // path_blocked instead of not_found — proving the flavor is threaded through.
  test("a missing file under a junction-resolved root → not_found (win32 ancestor walk)", async () => {
    const realpathImpl = async (p: string): Promise<string> => {
      if (p === "C:\\Data\\ghost.txt" || p === "C:\\Data\\sub") throw new Error("ENOENT");
      if (p === "C:\\Data") return "C:\\Real"; // root → different canonical (junction)
      return p;
    };
    const t = await nameOfThrow(
      readThroughGate("C:\\Data\\ghost.txt", { state: winState(["C:\\Data"]), realpathImpl }),
    );
    expect(t).toEqual({ name: "fs_read_failed", reason: "not_found" });
  });
});
