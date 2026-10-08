// Shared helpers, types, and constants for the `safespace status` / `doctor` /
// `doctor --posture` commands (split out of status.ts, v1.112.5 — behavior-preserving).
// Pure leaf: the three command entry points (status.ts runStatus, status/doctor.ts
// runDoctor, status/posture.ts runPosture) all import from here. The module SECURITY
// ASSUMPTIONS these helpers implement are documented in status.ts.
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { execFile } from "node:child_process";
import { countRows } from "../audit/cli-chain";
import { configDir } from "../auth/keychain";
import { ENV_TIER } from "../config";

export const ACCOUNTS_FILE = "accounts.json";
export const ENV_FILE = ".env";
export const AUDIT_FILE = "audit.jsonl";
export const AUDIT_CLI_FILE = "audit-cli.jsonl";
export const SALT_FILE = "audit-salt";
export const SALT_SIZE_BYTES = 32;
const AUDIT_TAIL_BYTES = 512; // M-2: tail-read window; covers ~3 typical audit lines

const EMAIL_RE = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

// ----- public types -----

export type CheckStatus = "pass" | "warn" | "fail";

export interface CheckResult {
  name: string;
  status: CheckStatus;
  /** Fixed sentinel string — NEVER attacker-controlled content. */
  value?: string;
}

export interface DoctorReport {
  status: "ok" | "warn" | "fail";
  checks: CheckResult[];
}

export interface StatusReport {
  configDir: string;
  tier: "read" | "write" | "share" | "unset";
  accountCount: number;
  activeAccount: string | null;
  lastAuditEntry: { ts: string; tool: string } | null;
  auditLineCount: number;
  /** Lines in audit-cli.jsonl; present only when that file exists. */
  auditCliLineCount?: number;
}

export interface CliIO {
  out: (line: string) => void;
  err: (line: string) => void;
}

export interface DoctorOptions {
  deep?: boolean;
  json?: boolean;
  /** Test seam — Bun.spawn-based version probes are awkward in unit tests. */
  versionProbe?: (cmd: string) => Promise<string | null>;
  /** Test seam (v1.110 PR 1c, S5) — defaults to process.platform. On "win32"
   *  the POSIX file-mode checks report "n/a (NTFS ACL)" instead of failing. */
  platform?: NodeJS.Platform;
}

export interface StatusOptions {
  json?: boolean;
}

export interface PostureOptions {
  json?: boolean;
}

// ----- tilde-path helper (H-2) -----

/** Replace `$HOME` prefix with `~/` so JSON output doesn't leak the OS
 *  username. Used ONLY in --json output. Human-readable text output keeps
 *  the full path (it's not meant for forwarding). */
export function tildePath(p: string): string {
  const home = os.homedir();
  if (p === home) return "~";
  if (p.startsWith(home + path.sep)) return "~" + p.slice(home.length);
  return p;
}

// ----- safe stat (mode-only; never reads content) -----

interface FileStat {
  exists: boolean;
  mode: number;
  size: number;
}

export async function safeStat(p: string): Promise<FileStat> {
  try {
    const s = await fs.stat(p);
    return { exists: true, mode: s.mode & 0o777, size: s.size };
  } catch {
    return { exists: false, mode: 0, size: 0 };
  }
}

// v1.110 PR 1c (S5) — POSIX file-mode posture is meaningless on Windows: NTFS
// uses ACLs, not 0o600/0o700 permission bits, and node's fs.stat() reports a
// synthetic mode whose low 9 bits never equal 0o600/0o700. So on win32 every
// mode check in runDoctor would spuriously FAIL. modeVerdict collapses that: on
// win32 it reports "n/a (NTFS ACL)" and passes; on POSIX it does the real
// comparison, byte-identical to the pre-1.110 inline `=== expected` checks.
// Existence / schema / size checks are platform-independent and stay authoritative.
export function modeVerdict(
  actual: number,
  expected: number,
  platform: NodeJS.Platform,
): { ok: boolean; value: string } {
  if (platform === "win32") return { ok: true, value: "n/a (NTFS ACL)" };
  return actual === expected
    ? { ok: true, value: `0o${expected.toString(8)}` }
    : { ok: false, value: `wrong mode (expected 0o${expected.toString(8)})` };
}

// ----- accounts.json reader (mirrors keychain.ts:readJsonIndex; sec-rev C-1) -----

interface AccountsSummary {
  ok: boolean;
  version?: 1 | 2;
  count?: number;
  emails?: string[];
}

export async function readAccountsSummary(): Promise<AccountsSummary> {
  const p = path.join(configDir(), ACCOUNTS_FILE);
  try {
    const raw = await fs.readFile(p, "utf8");
    const parsed = JSON.parse(raw) as unknown;
    const v = (parsed as { version?: unknown } | null)?.version;
    if (
      parsed &&
      typeof parsed === "object" &&
      (v === 1 || v === 2) &&
      Array.isArray((parsed as { accounts?: unknown }).accounts)
    ) {
      const accounts = (parsed as { accounts: Array<{ email?: unknown }> }).accounts;
      const emails: string[] = [];
      for (const a of accounts) {
        if (a && typeof a.email === "string" && EMAIL_RE.test(a.email)) {
          emails.push(a.email);
        }
        // Silently skip malformed entries — never echo the bad value (C-1).
      }
      return { ok: true, version: v as 1 | 2, count: emails.length, emails };
    }
    return { ok: false };
  } catch {
    // C-1: discard native error message entirely. JSON parse errors can
    // include a fragment of the file content (e.g. `Unexpected token 'B',
    // "BEARER tok"... is not valid JSON`).
    return { ok: false };
  }
}

// ----- audit.jsonl tail-read (M-2, L-3) -----

export async function tailReadLastAuditEntry(
  /** Defaults reproduce the original single-file read (audit.jsonl, 512-byte tail,
   *  last line only). `scanBack` keeps the LAST tail line that has a string `ts` and
   *  `tool` (skipping e.g. an anchor or event row) — used when two files are compared. */
  opts: { file?: string; tailBytes?: number; scanBack?: boolean } = {},
): Promise<{
  lineCount: number;
  lastEntry: { ts: string; tool: string } | null;
}> {
  const p = path.join(configDir(), opts.file ?? AUDIT_FILE);
  const tailBytes = opts.tailBytes ?? AUDIT_TAIL_BYTES;
  const stat = await safeStat(p);
  if (!stat.exists || stat.size === 0) return { lineCount: 0, lastEntry: null };

  let fh: fs.FileHandle | null = null;
  try {
    fh = await fs.open(p, "r");
    // M-2: read only the last AUDIT_TAIL_BYTES, not the full file.
    const start = Math.max(0, stat.size - tailBytes);
    const len = stat.size - start;
    const buf = Buffer.alloc(len);
    await fh.read(buf, 0, len, start);
    const text = buf.toString("utf8");
    // Lines end where the audit readers end them ("\r\n", "\n" or a lone "\r").
    const lines = text.split(/\r\n|\n|\r/).filter((l) => l.length > 0);
    // Only the original read takes the raw last line; scanBack walks back through the tail
    // and skips an unterminated final segment (a write in progress).
    const complete = opts.scanBack && !/[\r\n]$/.test(text) ? lines.slice(0, -1) : lines;
    const candidates = opts.scanBack ? [...complete].reverse() : lines.slice(-1);
    let lastEntry: { ts: string; tool: string } | null = null;
    for (const lastLine of candidates) {
      if (lastEntry !== null) break;
      try {
        const obj = JSON.parse(lastLine) as unknown;
        // L-3: extract ONLY ts + tool. Ignore account / argsHash / args.
        if (
          obj &&
          typeof obj === "object" &&
          typeof (obj as { ts?: unknown }).ts === "string" &&
          typeof (obj as { tool?: unknown }).tool === "string"
        ) {
          lastEntry = {
            ts: (obj as { ts: string }).ts,
            tool: (obj as { tool: string }).tool,
          };
        }
      } catch {
        // C-1: parse failure → no entry, no error echo.
        lastEntry = null;
      }
    }

    // Row count as the audit readers see the file (non-empty lines, streamed).
    const lineCount = await countRows(p);

    return { lineCount, lastEntry };
  } catch {
    return { lineCount: 0, lastEntry: null };
  } finally {
    if (fh) await fh.close().catch(() => undefined);
  }
}

// ----- tier read (M-3: never echo env value) -----

export function readTier(): "read" | "write" | "share" | "unset" {
  const raw = process.env[ENV_TIER];
  if (raw === undefined || raw === "") return "unset";
  if (raw === "read" || raw === "write" || raw === "share") return raw;
  return "unset"; // sentinel — actual invalid case detected by tierIsValidInEnv
}

export function tierIsValidInEnv(): boolean {
  const raw = process.env[ENV_TIER];
  if (raw === undefined || raw === "") return true; // unset is valid (defaults to read)
  return raw === "read" || raw === "write" || raw === "share";
}

// ----- dependency version probe -----

const PROBE_TIMEOUT_MS = 5000; // L3 (#61 review): cap a misbehaving binary's hang

export async function defaultVersionProbe(cmd: string): Promise<string | null> {
  // execFile (NOT a shell) runs `<cmd> --version` with a hard timeout that kills a
  // misbehaving binary — interactive REPL, network-fetching shim — so `doctor` can't hang
  // forever (L3 #61). `cmd` is drawn from a fixed internal tool list, never user input, so
  // there is no argument-injection surface even without a shell.
  return new Promise<string | null>((resolve) => {
    execFile(cmd, ["--version"], { timeout: PROBE_TIMEOUT_MS }, (err, stdout, stderr) => {
      // err is set on ENOENT (not installed), non-zero exit, OR timeout → no version.
      if (err) { resolve(null); return; }
      // L1 (#61): merge stdout + stderr — some tools print --version to stderr
      // (older Unix utilities, certain Go binaries). Take the first non-empty line.
      const combined = (stdout + "\n" + stderr)
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean);
      resolve(combined[0] ?? null);
    });
  });
}

// ----- doctor/posture roll-up -----

export function summarize(checks: CheckResult[]): "ok" | "warn" | "fail" {
  if (checks.some((c) => c.status === "fail")) return "fail";
  if (checks.some((c) => c.status === "warn")) return "warn";
  return "ok";
}
