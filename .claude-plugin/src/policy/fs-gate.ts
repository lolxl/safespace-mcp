// v1.75 — the filesystem-read gate (class-C KEYLESS connector `fs_read`).
//
// The filesystem analogue of policy/url-gate.ts: fs_read reads a host file, so the
// new security surface SafeSpace OWNS is "which paths may be read". The gate is
// DEFAULT-DENY (mirrors github-write-targets / youtube-comment-targets, NOT the
// off→allow recipient allowlist): with no roots configured, fs_read reads NOTHING.
//
// The path defence has TWO layers (the filesystem analogue of url-gate's "validate
// the host THEN pin the resolved IP at connect" anti-DNS-rebinding):
//   1. LEXICAL containment FIRST — `path.resolve()` collapses `..` with no fs touch;
//      a path not lexically within an allowed root is rejected BEFORE any stat/read,
//      so a probe outside the allowlist learns nothing (no existence oracle).
//   2. REALPATH re-check — the lexically-OK path is realpath()'d (symlinks followed)
//      and re-checked against the roots, so a symlink *inside* a root pointing
//      *outside* it cannot escape. This is the load-bearing anti-symlink gate.
// Then: must be a regular file, ≤ MAX_BYTES, valid UTF-8 (binary/NUL → rejected, so
// no garbage reaches the model's context).
//
// CROSS-PLATFORM (v1.108 PR 1b): the gate is platform-aware. On POSIX (macOS/Linux)
// the path flavor is `path.posix` and behaviour is BYTE-IDENTICAL to v1.75. On win32
// the flavor is `path.win32` and three extra hardening layers apply (all no-ops off
// win32): (S8) reject `\\?\`/`\\.\` device-namespace + extended-length prefixes —
// these bypass Win32 path canonicalization, and `fs.realpath` has NO stable
// `\\?\`-stripping contract across Node versions, so this reject is LOAD-BEARING, not
// redundant; (S10) reject Alternate Data Streams (any `:` past the drive-letter colon
// — `file.txt:hidden` is a covert read of an allowed file); (S11) reject
// drive-relative-rooted `\foo` (ambiguous current-drive). win32 containment is
// case-FOLDED (NTFS is case-insensitive). UNC roots (S12) are allowed (operator
// config, not agent input) but warned. The `platform` is injectable for tests so the
// win32 paths are exercised on a POSIX CI runner.
//
// NO-LEAK: a blocked path → `path_blocked_by_policy` with a closed-set reason and
// NO echo of the requested path (anti-PII / anti-oracle). The roots themselves are
// operator config (process env), not attacker input.

import { constants as FS_CONSTANTS } from "node:fs";
import { lstat, open, readdir, realpath, stat } from "node:fs/promises";
import * as nodePath from "node:path";
import { ENV_FS_READ_ROOTS as ENV_ROOTS, ENV_FS_READ_ROOTS_EXTRA as ENV_ROOTS_EXTRA } from "../config";
import { MCPError } from "../errors";
import { buildDenyIndex, type DenyIndex, idOf, inDenyZone } from "./fs-deny-zones";

export { ENV_ROOTS, ENV_ROOTS_EXTRA };

/** 5 MB read cap — same bound as Drive/Gmail-attachment/web-fetch. A read above
 *  this protects the model's context (the file content is returned to the LLM). */
const MAX_BYTES = 5 * 1024 * 1024;

// ----- platform path flavor (injectable; default = the host platform) -----

type PathFlavor = typeof nodePath.win32;

/** The platform-specific `node:path` variant. On non-win32 hosts this is the POSIX
 *  flavor → the v1.75 code path, byte-identical. Injecting `"win32"` selects the
 *  win32 flavor so its hardening is exercised on a POSIX test runner. */
function flavorFor(platform: NodeJS.Platform): PathFlavor {
  return platform === "win32" ? nodePath.win32 : nodePath.posix;
}

/** The containment case-fold. Identity off win32; on win32 (NTFS case-insensitive)
 *  fold to lower with the en-US locale — NEVER the default locale, whose Turkish
 *  mapping turns `"I"` into `"ı"` (dotless) and would mis-compare a path. */
function folderFor(platform: NodeJS.Platform): (s: string) => string {
  return platform === "win32" ? (s) => s.toLocaleLowerCase("en-US") : (s) => s;
}

// win32 forbidden-form matchers (all no-ops off win32 — see isForbiddenWin32Form).
const WIN32_DEVICE_PREFIX_RE = /^[\\/]{2}[.?][\\/]/; // \\?\  \\.\  (+ forward-slash variants)
const WIN32_DRIVE_ABS_RE = /^[A-Za-z]:[\\/]/; // C:\  C:/  (drive-letter + separator)
const WIN32_UNC_RE = /^[\\/]{2}[^.?\\/]/; // \\server\share  (NOT a device prefix)

/** True iff `p` is a win32 path form that must be rejected BEFORE resolve/realpath.
 *  Off win32 → always false (the POSIX gate is unchanged). On win32:
 *    S8  `\\?\` / `\\.\` device-namespace / extended-length prefix — bypasses Win32
 *        canonicalization; realpath has no stable strip contract → reject outright.
 *    S10 Alternate Data Stream — the ONLY legal colon is the drive-letter colon; any
 *        further `:` (`file.txt:secret`, `::$DATA`) names a covert stream.
 *    S11 drive-relative-rooted `\foo` — `isAbsolute` says true but it is rooted on
 *        the CURRENT drive (ambiguous); require a fully-qualified drive or UNC form. */
function isForbiddenWin32Form(p: string, platform: NodeJS.Platform): boolean {
  if (platform !== "win32") return false;
  if (WIN32_DEVICE_PREFIX_RE.test(p)) return true; // S8
  const afterDrive = /^[A-Za-z]:/.test(p) ? p.slice(2) : p;
  if (afterDrive.includes(":")) return true; // S10 ADS
  if (!WIN32_DRIVE_ABS_RE.test(p) && !WIN32_UNC_RE.test(p)) return true; // S11
  return false;
}

/** True iff `p` is a win32 UNC root (`\\server\share`). UNC roots are operator config
 *  (not agent input) so they are ALLOWED — but they reach a network share, so the
 *  caller warns once. Off win32 → false. */
function isWin32Unc(p: string, platform: NodeJS.Platform): boolean {
  return platform === "win32" && WIN32_UNC_RE.test(p);
}

// ----- roots allowlist (default-deny, two-layer) -----

export type FsRootsState =
  | { kind: "off" }
  // `platform` is OPTIONAL: buildFsRootsState always stamps it, but a hand-built test
  // state may omit it → readThroughGate falls back to process.platform (POSIX on CI).
  | { kind: "active"; roots: string[]; platform?: NodeJS.Platform }; // absolute, lexically-normalized

/** Parse a comma-separated list of ABSOLUTE root paths. Each is lexically normalized
 *  (`path.resolve`, no fs touch — symlinked roots are re-resolved per read in the
 *  realpath layer). A relative/empty entry, or a forbidden win32 form (device prefix /
 *  ADS / drive-relative), is rejected (loud config error). Deduped. `unc` lists win32
 *  UNC roots that were KEPT but warrant a network-share warning. */
export function parseFsRoots(
  input: string | undefined,
  platform: NodeJS.Platform = process.platform,
): { ok: string[]; rejected: string[]; unc: string[] } {
  const result: { ok: string[]; rejected: string[]; unc: string[] } = { ok: [], rejected: [], unc: [] };
  if (input === undefined) return result;
  const pp = flavorFor(platform);
  const seen = new Set<string>();
  for (const raw of input.split(",").map((t) => t.trim()).filter((t) => t.length > 0)) {
    if (!pp.isAbsolute(raw) || isForbiddenWin32Form(raw, platform)) {
      result.rejected.push(raw); // must be absolute + a permitted form
      continue;
    }
    if (isWin32Unc(raw, platform)) result.unc.push(raw);
    const norm = pp.resolve(raw); // collapse any `.`/`..`/trailing slash, normalize separators
    if (seen.has(norm)) continue;
    seen.add(norm);
    result.ok.push(norm);
  }
  return result;
}

export function buildFsRootsState(
  rootsEnv: string | undefined,
  extraEnv: string | undefined,
  platform: NodeJS.Platform = process.platform,
): FsRootsState {
  if (rootsEnv === undefined && extraEnv === undefined) return { kind: "off" };
  const merged: string[] = [];
  const seen = new Set<string>();
  for (const r of [...parseFsRoots(rootsEnv, platform).ok, ...parseFsRoots(extraEnv, platform).ok]) {
    if (seen.has(r)) continue;
    seen.add(r);
    merged.push(r);
  }
  return { kind: "active", roots: merged, platform };
}

/** True iff `candidate` (an absolute, normalized path) is at or under some root.
 *  Boundary-safe: `/srv/data` does NOT contain `/srv/data-secret` (the `sep` guard
 *  prevents the classic prefix-match escape). A path EQUAL to a root is allowed.
 *  `pp`/`fold` default to POSIX-identity so the v1.75 2-arg call site + tests are
 *  unchanged; win32 passes the win32 flavor + the en-US case-fold. */
function withinRoots(
  candidate: string,
  roots: readonly string[],
  pp: PathFlavor = nodePath.posix,
  fold: (s: string) => string = (s) => s,
): boolean {
  const c = fold(candidate);
  for (const root of roots) {
    const r = fold(root);
    if (c === r || c.startsWith(r.endsWith(pp.sep) ? r : r + pp.sep)) {
      return true;
    }
  }
  return false;
}

/** Resolve `lexical` (an absolute path) to its CANONICAL form (symlinks followed).
 *  If the full path exists → `realpath` it (`existed:true`). If it (or a component)
 *  does NOT exist → resolve via the nearest existing ANCESTOR + rejoin the missing
 *  tail (`existed:false`). This gives a missing path a canonical form too, so the
 *  containment check can run on it — a path OUTSIDE the roots returns the SAME block
 *  whether it exists or not (no existence oracle), while a missing path INSIDE a root
 *  is reported as not_found. `pp` is the platform flavor: the ancestor walk MUST use
 *  the win32 dirname/basename/join on win32 (a POSIX dirname mis-parses `C:\a\b`). */
async function canonicalize(
  lexical: string,
  realpathFn: (p: string) => Promise<string>,
  pp: PathFlavor,
): Promise<{ real: string; existed: boolean }> {
  try {
    return { real: await realpathFn(lexical), existed: true };
  } catch {
    /* fall through to the ancestor walk */
  }
  const segments: string[] = [];
  let cur = lexical;
  for (;;) {
    const parent = pp.dirname(cur);
    segments.unshift(pp.basename(cur));
    if (parent === cur) return { real: lexical, existed: false }; // hit the root, nothing resolved
    try {
      const realParent = await realpathFn(parent);
      return { real: pp.join(realParent, ...segments), existed: false };
    } catch {
      cur = parent; // parent missing too — keep walking up
    }
  }
}

// ----- per-process singleton (load-once, MCP-restart-clears) -----

let cachedState: FsRootsState | undefined;
let warnEmitted = false;

/** Posture summary — COUNTS ONLY (never the root PATHS; mirrors the no-PII-echo
 *  invariant the other connectors' summaries hold). For `doctor --posture`. */
export function fsRootsSummary(): { kind: "off" | "active"; count: number } {
  const state = getFsRootsState();
  return state.kind === "off"
    ? { kind: "off", count: 0 }
    : { kind: "active", count: state.roots.length };
}

export function getFsRootsState(): FsRootsState {
  if (cachedState !== undefined) return cachedState;
  const rootsEnv = process.env[ENV_ROOTS];
  const extraEnv = process.env[ENV_ROOTS_EXTRA];

  if (!warnEmitted && rootsEnv === undefined && typeof extraEnv === "string" && extraEnv.length > 0) {
    console.error(
      "[safespace] WARNING: SAFESPACE_FS_READ_ROOTS_EXTRA is set but SAFESPACE_FS_READ_ROOTS " +
        "is not. fs_read is in default-deny mode with EXTRA only.",
    );
    warnEmitted = true;
  }
  const parsedRoots = parseFsRoots(rootsEnv);
  const parsedExtra = parseFsRoots(extraEnv);
  for (const rej of [...parsedRoots.rejected, ...parsedExtra.rejected]) {
    console.error(`[safespace] WARNING: SAFESPACE_FS_READ_ROOTS rejected non-absolute/forbidden entry: ${rej}`);
  }
  for (const unc of [...parsedRoots.unc, ...parsedExtra.unc]) {
    console.error(
      `[safespace] WARNING: SAFESPACE_FS_READ_ROOTS allows a UNC (network-share) root: ${unc} — ` +
        "fs_read can pull from that SMB share.",
    );
  }
  cachedState = buildFsRootsState(rootsEnv, extraEnv);
  if (cachedState.kind === "active" && cachedState.roots.length === 0) {
    console.error(
      "[safespace] WARNING: SAFESPACE_FS_READ_ROOTS is set but yielded 0 valid roots — " +
        "fs_read will deny everything. Use comma-separated ABSOLUTE paths (e.g. /srv/shared).",
    );
  }
  return cachedState;
}

// ----- the read gate -----

export interface FsReadResult {
  /** The realpath actually read (within an allowed root). */
  path: string;
  bytes: number;
  content: string;
}

/** The slice of an open file the gate uses (injectable for the mocked-fs tests). */
export interface FsFileHandle {
  stat(): Promise<{ isFile(): boolean; size: bigint; dev: bigint; ino: bigint }>;
  read(): Promise<Buffer>;
  close(): Promise<void>;
}

/** O_NOFOLLOW: a final component swapped for a symlink after the check is not followed.
 *  O_NONBLOCK: a FIFO under a root returns at once instead of hanging the call. Both are
 *  absent on win32 (the constants are undefined there). */
const OPEN_FLAGS =
  FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0) | (FS_CONSTANTS.O_NONBLOCK ?? 0);

async function openForRead(p: string): Promise<FsFileHandle> {
  const fh = await open(p, OPEN_FLAGS);
  return {
    stat: () => fh.stat({ bigint: true }),
    read: () => fh.readFile(),
    close: () => fh.close(),
  };
}

export interface FsGateDeps {
  realpathImpl?: (p: string) => Promise<string>;
  /** Open the canonical path for reading (identity + content come from this handle). */
  openImpl?: (p: string) => Promise<FsFileHandle>;
  /** Identity of an ancestor directory (bind-mount / firmlink alias check). */
  ancestorStatImpl?: (p: string) => Promise<{ dev: bigint; ino: bigint }>;
  /** A prebuilt deny index (tests); default = built from the real filesystem per call. */
  denyIndex?: DenyIndex;
  /** lstat used to classify an open failure (tests). */
  lstatImpl?: (p: string) => Promise<{ dev: bigint; ino: bigint; isFile(): boolean; isSymbolicLink(): boolean }>;
  state?: FsRootsState;
  /** Override the path platform (tests exercise win32 on a POSIX runner). Defaults to
   *  the active state's platform, else the host. */
  platform?: NodeJS.Platform;
}

let denyFailureReported = false;

/** True when any ancestor directory of `real` has the identity of a zone directory (a
 *  bind-mount or firmlink alias of a protected dir). An ancestor that cannot be stat'd
 *  also answers true (fail closed). */
async function ancestorIsZone(
  real: string,
  pp: PathFlavor,
  deny: DenyIndex,
  ancestorStat: (p: string) => Promise<{ dev: bigint; ino: bigint }>,
): Promise<boolean> {
  for (let dir = pp.dirname(real); ; dir = pp.dirname(dir)) {
    let ast: { dev: bigint; ino: bigint };
    try {
      ast = await ancestorStat(dir);
    } catch {
      return true;
    }
    const aid = idOf(ast);
    if (aid !== null && deny.dirIds.has(aid)) return true;
    if (pp.dirname(dir) === dir) return false;
  }
}

/** Map a failed open of an in-root, existing, non-zone path to the error the pre-descriptor
 *  gate gave: a protected identity → refuse(); vanished / swapped-in symlink (ELOOP) →
 *  not_found; a non-file (directory on win32, socket, …) → not_a_file; a regular file
 *  that cannot be opened (EACCES, locked) → read_error. */
async function classifyOpenFailure(
  real: string,
  openErr: unknown,
  deny: DenyIndex,
  refuse: () => MCPError,
  isZoneAncestor: () => Promise<boolean>,
  lstatImpl?: FsGateDeps["lstatImpl"],
): Promise<MCPError> {
  // Under a protected directory's alias, every failure answers like a zone hit, so the
  // differentiated errors below cannot reveal what lies there.
  if (await isZoneAncestor()) return refuse();
  const code = (openErr as NodeJS.ErrnoException | undefined)?.code;
  if (code === "ENOENT" || code === "ENOTDIR" || code === "ELOOP") {
    return new MCPError("fs_read_failed", { reason: "not_found" });
  }
  let st: Awaited<ReturnType<NonNullable<FsGateDeps["lstatImpl"]>>>;
  try {
    st = await (lstatImpl ?? ((p: string) => lstat(p, { bigint: true })))(real);
  } catch {
    return new MCPError("fs_read_failed", { reason: "not_found" });
  }
  const id = idOf(st);
  if (id !== null && (deny.fileIds.has(id) || deny.dirIds.has(id))) return refuse();
  if (st.isSymbolicLink()) return new MCPError("fs_read_failed", { reason: "not_found" });
  if (!st.isFile()) return new MCPError("fs_read_failed", { reason: "not_a_file" });
  return new MCPError("fs_read_failed", { reason: "read_error" });
}

/** Read `requestedPath` through the gate. Throws path_blocked_by_policy (gate) or
 *  fs_read_failed (operational) — both closed-set reason, never echoing the path. */
export async function readThroughGate(
  requestedPath: string,
  deps: FsGateDeps = {},
): Promise<FsReadResult> {
  const state = deps.state ?? getFsRootsState();
  if (state.kind === "off") {
    throw new MCPError("path_blocked_by_policy", { reason: "no_allowlist" });
  }
  const platform = deps.platform ?? state.platform ?? process.platform;
  const pp = flavorFor(platform);
  const fold = folderFor(platform);
  // Require an ABSOLUTE, permitted-form path BEFORE resolving (sec-rev NIT-1). A
  // relative path would otherwise resolve against process.cwd() — and if cwd happened
  // to sit inside an allowed root, a bare "notes.md" could silently read. On win32
  // also reject the forbidden forms (device prefix / ADS / drive-relative) here, where
  // they would otherwise survive resolve/realpath. Same generic gate error (no oracle).
  if (!pp.isAbsolute(requestedPath) || isForbiddenWin32Form(requestedPath, platform)) {
    throw new MCPError("path_blocked_by_policy", { reason: "not_in_allowlist" });
  }
  // Resolve to the CANONICAL (symlink-followed) form on BOTH sides so containment is
  // symlink-safe AND independent of symlink-form (a symlinked root vs a symlinked
  // request — e.g. macOS /tmp → /private/tmp — must still match). A configured root
  // that does not exist can contain nothing → dropped. This per-root realpath loop is
  // LOAD-BEARING on win32 too: it expands an 8.3 short-name root to its long form so a
  // long-name request still matches — do NOT skip it as a "stable roots" optimization.
  const realpathFn = deps.realpathImpl ?? realpath;
  const canonRoots: string[] = [];
  for (const r of state.roots) {
    try {
      canonRoots.push(await realpathFn(r));
    } catch {
      /* a configured root that doesn't exist contains nothing; skip */
    }
  }
  const lexical = pp.resolve(requestedPath);
  const { real, existed } = await canonicalize(lexical, realpathFn, pp);
  const inRoots = withinRoots(real, canonRoots, pp, fold);
  // Deny zones (SafeSpace's own stores, AI-client config, /proc, /dev — see
  // fs-deny-zones.ts) win over any root. A denial answers exactly like the gate's
  // existing outcome for the same position: inside the roots → the not_found a missing
  // file gets; outside → the ordinary not_in_allowlist. It never says "deny zone".
  const refuse = (): MCPError =>
    inRoots
      ? new MCPError("fs_read_failed", { reason: "not_found" })
      : new MCPError("path_blocked_by_policy", { reason: "not_in_allowlist" });
  const deny =
    deps.denyIndex ??
    (await buildDenyIndex(platform, {
      realpath,
      lstat: (p) => lstat(p, { bigint: true }),
      stat: (p) => stat(p, { bigint: true }),
      readdir: (p) => readdir(p),
    }));
  if (deny.failed && !denyFailureReported) {
    // Once per process, no path: otherwise an operator only ever sees not_found.
    denyFailureReported = true;
    console.error(
      "[safespace] fs_read: the protected-path index could not be built (unreadable home " +
        "or SafeSpace dir, or too many entries) — refusing all fs_read calls.",
    );
  }
  if (deny.failed || inDenyZone(lexical, deny, platform) || inDenyZone(real, deny, platform)) {
    throw refuse();
  }
  // Authoritative containment on the canonical path: a symlink inside a root pointing
  // OUTSIDE resolves out and is blocked; a path outside the roots (present OR missing)
  // → the SAME generic block (no existence oracle for outside paths).
  if (!inRoots) {
    throw new MCPError("path_blocked_by_policy", { reason: "not_in_allowlist" });
  }
  if (!existed) {
    throw new MCPError("fs_read_failed", { reason: "not_found" });
  }
  // Open once and take identity, type, size and content from the same descriptor, so the
  // checked file is the file that is read.
  const ancestorStat = deps.ancestorStatImpl ?? ((p: string) => stat(p, { bigint: true }));
  const isZoneAncestor = () => ancestorIsZone(real, pp, deny, ancestorStat);
  let fh: FsFileHandle;
  try {
    fh = await (deps.openImpl ?? openForRead)(real);
  } catch (openErr) {
    throw await classifyOpenFailure(real, openErr, deny, refuse, isZoneAncestor, deps.lstatImpl);
  }
  try {
    let st: Awaited<ReturnType<FsFileHandle["stat"]>>;
    try {
      st = await fh.stat();
    } catch {
      throw new MCPError("fs_read_failed", { reason: "not_found" });
    }
    // Identity before type/size, so an alias of a protected file or directory (hard
    // link, bind mount, firmlink) answers not_found rather than not_a_file / too_large.
    const id = idOf(st);
    if (id === null || deny.fileIds.has(id) || deny.dirIds.has(id)) throw refuse();
    if (await isZoneAncestor()) throw refuse();
    if (!st.isFile()) {
      throw new MCPError("fs_read_failed", { reason: "not_a_file" });
    }
    if (st.size > BigInt(MAX_BYTES)) {
      throw new MCPError("fs_read_failed", { reason: "too_large" });
    }
    let buf: Buffer;
    try {
      buf = await fh.read();
    } catch {
      throw new MCPError("fs_read_failed", { reason: "read_error" });
    }
    if (buf.byteLength > MAX_BYTES) {
      // Defensive: the file grew between fstat and read.
      throw new MCPError("fs_read_failed", { reason: "too_large" });
    }
    if (buf.includes(0)) {
      // A NUL byte → binary; reject rather than feed garbage to the model.
      throw new MCPError("fs_read_failed", { reason: "not_text" });
    }
    const content = buf.toString("utf8");
    // toString("utf8") replaces invalid sequences with U+FFFD; reject if that lost
    // information (round-trip mismatch ⇒ the file was not valid UTF-8).
    if (Buffer.byteLength(content, "utf8") !== buf.byteLength) {
      throw new MCPError("fs_read_failed", { reason: "not_text" });
    }
    return { path: real, bytes: buf.byteLength, content };
  } finally {
    await fh.close().catch(() => {});
  }
}

/** Per-source error mapper — MCPError passthrough (the gate throws the closed-set
 *  path_blocked_by_policy / fs_read_failed); any other thrown value → generic
 *  fs_read_failed. Mirrors mapWebFetchError. NEVER echoes the requested path.
 *  B6.1-B — a DELIBERATE handler-level exception to the client-layer error-mapping
 *  contract (src/auth/http/connector-error-contract.ts): fs-read has no network and
 *  no client layer — this maps local fs errors. */
export function mapFsReadError(err: unknown): Error {
  if (err instanceof MCPError) return err;
  return new MCPError("fs_read_failed", { reason: "read_error" });
}

/** Test-only. */
export const __internal = {
  MAX_BYTES,
  OPEN_FLAGS,
  withinRoots,
  isForbiddenWin32Form,
  resetSingletons: (): void => {
    cachedState = undefined;
    warnEmitted = false;
    denyFailureReported = false;
  },
};
