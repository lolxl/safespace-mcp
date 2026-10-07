// Deny zones for fs_read: places an agent must never read through SafeSpace, whatever
// SAFESPACE_FS_READ_ROOTS allows (CARRY-FORWARD item 12).
//
// Threat model: an agent that reaches the filesystem only through SafeSpace's tools,
// with roots set broader than intended (`/`, `$HOME`). It cannot create files, links or
// mounts. Hard links, bind mounts and macOS firmlink aliases are covered by an identity
// (dev, ino) check as defence in depth. Secret files at operator-chosen paths outside
// every zone are a documented residual (CARRY-FORWARD item 11).
//
// Two kinds of zone:
// - SafeSpace stores (the config dir, its compiled-in default, and the plugin-data /
//   legacy / migration dirs): matched by path AND every file inside is inventoried by
//   identity, so a hard link to one elsewhere is still refused.
// - Path-only zones (AI-client config dirs, ~/.claude.json*, /proc, /dev): matched by
//   path; for the client dirs and ~/.claude.json the directory/file identity is recorded
//   too (catches firmlink / bind-mount aliases) but their contents are not walked.
//
// Everything is rebuilt on every call (env is read per call, never at module eval). A
// zone that does not exist is an empty set; any other resolution or walk error marks the
// index `failed`, and the gate then refuses every read (fail closed).

import type { BigIntStats } from "node:fs";
import * as nodePath from "node:path";
import { homedir } from "node:os";
import { configDir, defaultConfigDir } from "../auth/keychain";

type PathFlavor = typeof nodePath.win32;

/** Directory names SafeSpace (or its migration) writes under a store parent. */
const STORE_DIR_NAMES = [
  "safespace",
  "safespace-read",
  "safespace-send",
  "safespace.tmp",
  "safespace-read.migrated",
  "safespace-send.migrated",
] as const;

/** Above this many inventoried entries the gate stops trusting the inventory. */
const MAX_INVENTORY_ENTRIES = 2000;

export interface DenyFs {
  realpath: (p: string) => Promise<string>;
  lstat: (p: string) => Promise<BigIntStats>;
  /** Follows symlinks: a symlinked ~/.claude.json is protected by its target's identity. */
  stat: (p: string) => Promise<BigIntStats>;
  readdir: (p: string) => Promise<string[]>;
}

export interface DenyIndex {
  /** Lexical-resolved and canonical forms of every directory/file zone. */
  zonePaths: string[];
  /** Home-dir forms, for the `~/.claude.json*` basename rule. */
  homeForms: string[];
  /** `dev:ino` of every inventoried SafeSpace store file and the recorded zone files. */
  fileIds: Set<string>;
  /** `dev:ino` of every existing zone directory (SafeSpace stores and client dirs). */
  dirIds: Set<string>;
  /** True when protection could not be established: the gate must refuse every read. */
  failed: boolean;
}

export const EMPTY_DENY_INDEX: DenyIndex = {
  zonePaths: [],
  homeForms: [],
  fileIds: new Set(),
  dirIds: new Set(),
  failed: false,
};

export function idOf(st: { dev: bigint; ino: bigint }): string | null {
  return st.ino === 0n ? null : `${st.dev}:${st.ino}`;
}

function isMissing(e: unknown): boolean {
  const code = (e as NodeJS.ErrnoException | undefined)?.code;
  return code === "ENOENT" || code === "ENOTDIR";
}

/** Deny-side case fold: darwin (APFS is case-insensitive by default) and win32 fold;
 *  folding only ever widens a DENY, so it is safe on a case-sensitive volume too. */
export function denyFoldFor(platform: NodeJS.Platform): (s: string) => string {
  return platform === "win32" || platform === "darwin"
    ? (s) => s.toLocaleLowerCase("en-US")
    : (s) => s;
}

/** The zone paths for this platform and environment (not yet canonicalized). */
export function zoneSpec(
  platform: NodeJS.Platform,
  env: NodeJS.ProcessEnv = process.env,
  home: string = homedir(),
): { stores: string[]; clientDirs: string[]; clientFiles: string[]; pseudo: string[] } {
  const pp: PathFlavor = platform === "win32" ? nodePath.win32 : nodePath.posix;
  const active = pp.resolve(configDir());
  const fallback = pp.resolve(defaultConfigDir());
  const parents = new Set<string>([pp.dirname(active), pp.dirname(fallback)]);
  const pluginData = env.CLAUDE_PLUGIN_DATA;
  if (pluginData) parents.add(pp.resolve(pluginData));
  const stores = new Set<string>([active, fallback, pp.join(home, ".safespace")]);
  for (const p of parents) for (const name of STORE_DIR_NAMES) stores.add(pp.join(p, name));

  const clientDirs = [".claude", ".cursor", ".codex", ".gemini", ".codeium"].map((d) =>
    pp.join(home, d),
  );
  if (platform === "darwin") {
    clientDirs.push(pp.join(home, "Library", "Application Support", "Claude"));
  } else if (platform === "win32") {
    clientDirs.push(pp.join(env.APPDATA ?? pp.join(home, "AppData", "Roaming"), "Claude"));
  } else {
    clientDirs.push(pp.join(home, ".config", "Claude"));
  }
  return {
    stores: [...stores],
    clientDirs,
    clientFiles: [pp.join(home, ".claude.json")],
    pseudo: platform === "win32" ? [] : ["/proc", "/dev"],
  };
}

/** Canonical form of a zone path. Missing components resolve through the nearest
 *  existing ancestor; any error other than "missing" is thrown (the caller fails
 *  closed). */
async function canonicalZone(lexical: string, fs: DenyFs, pp: PathFlavor): Promise<string> {
  try {
    return await fs.realpath(lexical);
  } catch (e) {
    if (!isMissing(e)) throw e;
  }
  const tail: string[] = [];
  let cur = lexical;
  for (;;) {
    const parent = pp.dirname(cur);
    tail.unshift(pp.basename(cur));
    if (parent === cur) return lexical;
    try {
      return pp.join(await fs.realpath(parent), ...tail);
    } catch (e) {
      if (!isMissing(e)) throw e;
      cur = parent;
    }
  }
}

/** Build the deny index. Never throws: any failure to establish protection is reported
 *  as `failed: true`. */
export async function buildDenyIndex(
  platform: NodeJS.Platform,
  fs: DenyFs,
  env: NodeJS.ProcessEnv = process.env,
  homeOverride?: string,
): Promise<DenyIndex> {
  const pp: PathFlavor = platform === "win32" ? nodePath.win32 : nodePath.posix;
  const fold = denyFoldFor(platform);
  const index: DenyIndex = {
    zonePaths: [],
    homeForms: [],
    fileIds: new Set(),
    dirIds: new Set(),
    failed: false,
  };
  try {
    // Inside the try: homedir() can throw (no HOME, no passwd entry) → fail closed.
    const home = homeOverride ?? homedir();
    const spec = zoneSpec(platform, env, home);
    const canonCache = new Map<string, Promise<string>>();
    const canon = (lex: string): Promise<string> => {
      let c = canonCache.get(lex);
      if (c === undefined) {
        c = canonicalZone(lex, fs, pp);
        canonCache.set(lex, c);
      }
      return c;
    };
    const forms = async (p: string): Promise<string[]> => {
      const lex = pp.resolve(p);
      return [lex, await canon(lex)];
    };
    for (const p of [...spec.stores, ...spec.clientDirs, ...spec.clientFiles, ...spec.pseudo]) {
      index.zonePaths.push(...(await forms(p)));
    }
    index.homeForms.push(...(await forms(home)));

    let entries = 0;
    const recordDir = async (dir: string): Promise<boolean> => {
      try {
        const st = await fs.lstat(dir);
        if (!st.isDirectory()) return false;
        const id = idOf(st);
        if (id === null) throw new Error("no identity");
        index.dirIds.add(id);
        return true;
      } catch (e) {
        if (isMissing(e)) return false;
        throw e;
      }
    };
    // Walks the whole store tree; MAX_INVENTORY_ENTRIES bounds the work.
    const walk = async (dir: string): Promise<void> => {
      for (const name of await fs.readdir(dir)) {
        if (++entries > MAX_INVENTORY_ENTRIES) throw new Error("inventory too large");
        const child = pp.join(dir, name);
        let st: BigIntStats;
        try {
          st = await fs.lstat(child);
        } catch (e) {
          if (isMissing(e)) continue; // removed mid-walk
          throw e;
        }
        if (st.isSymbolicLink()) continue; // a link is not the protected file itself
        const id = idOf(st);
        if (st.isFile()) {
          if (id === null) throw new Error("no identity");
          index.fileIds.add(id);
        } else if (st.isDirectory()) {
          if (id === null) throw new Error("no identity");
          index.dirIds.add(id);
          await walk(child);
        }
      }
    };
    // Walk each distinct store directory once (the active and default config dirs, or
    // a plugin-data parent, can be the same directory under different names).
    const walkedDirs = new Set<string>();
    for (const store of spec.stores) {
      const dir = await canon(pp.resolve(store));
      let st: BigIntStats;
      try {
        st = await fs.lstat(dir);
      } catch (e) {
        if (isMissing(e)) continue;
        throw e;
      }
      if (!st.isDirectory()) continue;
      const id = idOf(st);
      if (id === null) throw new Error("no identity");
      if (walkedDirs.has(id)) continue;
      walkedDirs.add(id);
      index.dirIds.add(id);
      await walk(dir);
    }
    for (const dir of spec.clientDirs) {
      await recordDir(await canon(pp.resolve(dir)));
    }
    // ~/.claude.json and its siblings (`.claude.json.backup`, …): identity of each file,
    // following a symlink to its target (dotfile managers link it); a dangling link is
    // skipped. Counted against the same inventory cap.
    const homeCanon = await canon(pp.resolve(home));
    let homeEntries: string[] = [];
    try {
      homeEntries = await fs.readdir(homeCanon);
    } catch (e) {
      if (!isMissing(e)) throw e;
    }
    for (const name of homeEntries) {
      if (!fold(name).startsWith(".claude.json")) continue;
      if (++entries > MAX_INVENTORY_ENTRIES) throw new Error("inventory too large");
      try {
        const st = await fs.stat(pp.join(homeCanon, name));
        if (!st.isFile()) continue;
        const id = idOf(st);
        if (id === null) throw new Error("no identity");
        index.fileIds.add(id);
      } catch (e) {
        if (!isMissing(e)) throw e;
      }
    }
  } catch {
    index.failed = true;
  }
  return index;
}

/** True when `p` (a lexical-resolved or canonical request path) falls in a zone. */
export function inDenyZone(
  p: string,
  index: DenyIndex,
  platform: NodeJS.Platform,
): boolean {
  const pp: PathFlavor = platform === "win32" ? nodePath.win32 : nodePath.posix;
  const fold = denyFoldFor(platform);
  const c = fold(p);
  for (const z of index.zonePaths) {
    const f = fold(z);
    if (c === f || c.startsWith(f.endsWith(pp.sep) ? f : f + pp.sep)) return true;
  }
  // ~/.claude.json, ~/.claude.json.backup, … — a basename prefix in the home dir.
  const dir = fold(pp.dirname(p));
  if (
    index.homeForms.some((h) => fold(h) === dir) &&
    fold(pp.basename(p)).startsWith(".claude.json")
  ) {
    return true;
  }
  return false;
}
