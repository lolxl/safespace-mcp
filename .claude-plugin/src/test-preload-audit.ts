// Test preload (bunfig.toml): before EVERY test in every file, let in-flight audit
// writes finish and reset the audit chain state and the process role. Bun shares
// module state across the test files of one run, so a test that calls `runCli` (which
// switches the process to the CLI chain) would otherwise send later suites' audit rows
// to audit-cli.jsonl. Applies when `bun test` runs from .claude-plugin (as CI does).
//
// It also keeps the run out of the real config dir under the home directory: a run with
// no SAFESPACE_CONFIG_DIR gets a temp one (removed at the end), and a tripwire fails the
// run if the real dir changed anyway (a test that deletes the variable, or a child started
// without it that wrote before the check). The repo-root bunfig.toml loads this preload
// too, so a run from the repo root is covered.
//
// Known limits: a child a test did not wait for, writing after the check, is not seen. The
// tripwire forgives only audit-log rows from a run_id already in that log (a server that
// was writing it), so another SafeSpace process on this machine can still trip it: a CLI
// run (new run_id), a server's forensic event rows (they carry no run_id), or a token
// refresh rewriting the secret store. Rerun when nothing else is using the real dir.
import { afterAll, beforeEach } from "bun:test";
import { createHash } from "node:crypto";
import { lstatSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, realpathSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { __drainAuditWrites, __resetChainState } from "./audit";
import { defaultConfigDir } from "./auth/keychain";

let createdConfigDir: string | null = null;
if (!process.env.SAFESPACE_CONFIG_DIR) {
  createdConfigDir = mkdtempSync(join(tmpdir(), "safespace-test-config-"));
  process.env.SAFESPACE_CONFIG_DIR = createdConfigDir;
}

type FileEntry = { kind: "file"; hash: string; size: number; runIds: string[] };
type Entry =
  | FileEntry
  | { kind: "dir" }
  | { kind: "link"; target: string; file?: FileEntry }
  | { kind: "gone" };
const sha = (buf: Buffer): string => createHash("sha256").update(buf).digest("hex");

/** The run_ids of the rows in a JSONL buffer. */
function runIdsOf(buf: Buffer): string[] {
  const ids = new Set<string>();
  for (const l of buf.toString("utf8").split("\n")) {
    try {
      const id = (JSON.parse(l) as { run_id?: unknown }).run_id;
      if (typeof id === "string") ids.add(id);
    } catch {
      // not a row
    }
  }
  return [...ids];
}

/** Every entry under the real default config dir, recursively: regular files by content
 *  hash, symlinks by target (not followed), directories by name. null when the root
 *  itself does not exist. */
function snapshotRealConfigDir(): Map<string, Entry> | null {
  const root = defaultConfigDir();
  let rootStat;
  try {
    rootStat = lstatSync(root);
  } catch {
    return null;
  }
  const out = new Map<string, Entry>();
  // The root itself: a symlinked config dir is recorded by its target (a retarget counts as
  // a change) and its contents are walked through it.
  out.set(".", rootStat.isSymbolicLink() ? { kind: "link", target: readlinkSync(root) } : { kind: "dir" });
  const fileEntry = (p: string, jsonl: boolean): FileEntry => {
    const buf = readFileSync(p);
    return { kind: "file", hash: sha(buf), size: buf.length, runIds: jsonl ? runIdsOf(buf) : [] };
  };
  // Symlinks inside are recorded by target AND by what they point at (a file's content, a
  // directory's entries), so writes through a link are seen; each real directory is walked
  // once (no cycles).
  const visited = new Set<string>();
  const walk = (dir: string, rel: string): void => {
    let real: string;
    try {
      real = realpathSync(dir);
    } catch {
      return;
    }
    if (visited.has(real)) return;
    visited.add(real);
    for (const name of readdirSync(dir).sort()) {
      const p = join(dir, name);
      const r = rel ? `${rel}/${name}` : name;
      try {
        const st = lstatSync(p);
        if (st.isSymbolicLink()) {
          const entry: Entry = { kind: "link", target: readlinkSync(p) };
          try {
            const to = statSync(p);
            if (to.isFile()) entry.file = fileEntry(p, r.endsWith(".jsonl") || entry.target.endsWith(".jsonl"));
            else if (to.isDirectory()) walk(p, r);
          } catch {
            // dangling: the target string is the record
          }
          out.set(r, entry);
        } else if (st.isDirectory()) {
          out.set(r, { kind: "dir" });
          walk(p, r);
        } else {
          out.set(r, fileEntry(p, r.endsWith(".jsonl")));
        }
      } catch {
        out.set(r, { kind: "gone" }); // vanished or unreadable mid-walk
      }
    }
  };
  walk(root, "");
  return out;
}

/** True when `rel` only grew by rows of a SafeSpace process that was already writing it
 *  before the run (a server on this machine): the old content is an unchanged prefix and
 *  every appended row carries a run_id already present in it. A test, or a child it
 *  started, has a run_id the file has never seen, so its rows still trip. */
function grewOnlyFromOtherProcesses(rel: string, before: Entry | undefined, after: Entry | undefined): boolean {
  if (before === undefined || after === undefined || before.kind !== after.kind) return false;
  // An audit log by its own name, or a link to one under another name.
  const isJsonl = rel.endsWith(".jsonl") || (before.kind === "link" && before.target.endsWith(".jsonl"));
  if (!isJsonl) return false;
  if (before.kind === "link" && after.kind === "link" && before.target !== after.target) return false;
  const b = before.kind === "link" ? before.file : before.kind === "file" ? before : undefined;
  const a = after.kind === "link" ? after.file : after.kind === "file" ? after : undefined;
  if (!b || !a || a.size <= b.size) return false;
  const buf = readFileSync(join(defaultConfigDir(), rel));
  if (sha(buf.subarray(0, b.size)) !== b.hash) return false;
  const known = new Set(b.runIds);
  return buf
    .subarray(b.size)
    .toString("utf8")
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .every((l) => {
      try {
        const id = (JSON.parse(l) as { run_id?: unknown }).run_id;
        return typeof id === "string" && known.has(id);
      } catch {
        return false;
      }
    });
}

const realConfigBefore = snapshotRealConfigDir();

afterAll(async () => {
  // The last test's writes land before the comparison: queued audit writes, then a short
  // grace for any other write a test started without awaiting it.
  await __drainAuditWrites();
  await new Promise((r) => setTimeout(r, 200));
  if (createdConfigDir !== null) rmSync(createdConfigDir, { recursive: true, force: true });
  const after = snapshotRealConfigDir();
  const keys = new Set([...(realConfigBefore?.keys() ?? []), ...(after?.keys() ?? [])]);
  const changed = [...keys].filter((k) => {
    const x = realConfigBefore?.get(k);
    const y = after?.get(k);
    if (JSON.stringify(x) === JSON.stringify(y)) return false;
    return !grewOnlyFromOtherProcesses(k, x, y);
  });
  if ((realConfigBefore === null) !== (after === null) || changed.length > 0) {
    throw new Error(
      `the real config dir changed during the test run (${defaultConfigDir()}): ${changed.join(", ") || "created"}. ` +
        "A test wrote it — or another SafeSpace process on this machine did (see the preload's notes).",
    );
  }
});

beforeEach(async () => {
  await __drainAuditWrites();
  __resetChainState();
});
