// Atomic accounts.json index + config-dir resolution.
// See docs/DESIGN.md §Concurrency & Crash Safety (Issue 1A).
// Security-review fixes (2026-04-30):
//   - dir mode 0o700, file mode 0o600 (prevent local enumeration of registered Google accounts)
//   - .bak fallback on corrupt index (rebuild-from-Keychain enumeration is not supported by the library)
//
// v1.37 BLOCKER 1: the TOKEN half (setToken/getToken/deleteToken via
// @napi-rs/keyring) moved OUT of here, behind the SecretBackend seam
// (auth/keychain-backend.ts is the macOS impl; auth/token-store.ts is the
// email-only facade every caller now uses). This file keeps ONLY the
// accounts.json index + configDir(), which are storage-backend-agnostic.
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";
import { ENV_CONFIG_DIR } from "../config";

/** The compiled-in config dir, ignoring SAFESPACE_CONFIG_DIR. Per-OS default:
 *  %APPDATA%\safespace on Windows (the roaming-profile convention), ~/.config/safespace
 *  on macOS/Linux. Guard the unusual case (e.g. a Windows container) where APPDATA is
 *  unset. */
export function defaultConfigDir(): string {
  return process.platform === "win32"
    ? path.join(process.env.APPDATA ?? os.homedir(), "safespace")
    : path.join(os.homedir(), ".config", "safespace");
}

export function configDir(): string {
  // The SAFESPACE_CONFIG_DIR override wins when set.
  return process.env[ENV_CONFIG_DIR] ?? defaultConfigDir();
}
function indexPath(): string { return path.join(configDir(), "accounts.json"); }
function backupPath(): string { return path.join(configDir(), "accounts.json.bak"); }

export interface AccountEntry {
  email: string;
  scopes: string[];
  added_at: string;          // ISO 8601
  last_used_at: string | null;
}

// v2.0 PR-2b: schema bumped from 1 → 2 alongside the two-profile → single-profile
// collapse. The on-disk SHAPE is identical between v1 and v2 (same fields per
// AccountEntry); the bump is a marker so the upcoming `safespace migrate-v2`
// CLI (PR-2b-2) can tell whether a config dir has already been merged. New
// writes always emit v2; the reader still tolerates v1 so migrate-v2 can read
// legacy dirs (`safespace-read/`, `safespace-send/`) without choking.
export interface AccountsIndex {
  version: 1 | 2;
  accounts: AccountEntry[];
}

const EMPTY_INDEX: AccountsIndex = { version: 2, accounts: [] };

/* ───────── Index file (atomic write + .bak fallback) ───────── */

async function ensureConfigDir(): Promise<void> {
  await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
}

async function readJsonIndex(p: string): Promise<AccountsIndex | null> {
  try {
    const raw = await fs.readFile(p, "utf8");
    const parsed = JSON.parse(raw) as unknown;
    if (
      parsed && typeof parsed === "object" &&
      (parsed as { version?: unknown }).version !== undefined &&
      (parsed as { version: unknown }).version !== null &&
      ((parsed as { version: unknown }).version === 1 || (parsed as { version: unknown }).version === 2) &&
      Array.isArray((parsed as { accounts?: unknown }).accounts)
    ) {
      return parsed as AccountsIndex;
    }
    return null;
  } catch {
    return null;
  }
}

export async function loadIndex(): Promise<AccountsIndex> {
  await ensureConfigDir();
  const primary = await readJsonIndex(indexPath());
  if (primary) return primary;

  const backup = await readJsonIndex(backupPath());
  if (backup) {
    console.error(`[safespace] accounts.json corrupt or missing — restored from .bak`);
    return backup;
  }

  return { ...EMPTY_INDEX };
}

export async function saveIndex(index: AccountsIndex): Promise<void> {
  await ensureConfigDir();

  // Backup current valid index before overwrite (security-review #6b).
  try {
    await fs.copyFile(indexPath(), backupPath());
    await fs.chmod(backupPath(), 0o600); // copyFile mode preservation isn't guaranteed cross-platform
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
  }

  const tmpPath = `${indexPath()}.tmp.${process.pid}.${Date.now()}`;
  const json = JSON.stringify(index, null, 2);
  await fs.writeFile(tmpPath, json, { mode: 0o600 });
  await fs.rename(tmpPath, indexPath());
}

export async function upsertAccount(entry: AccountEntry): Promise<void> {
  const idx = await loadIndex();
  const i = idx.accounts.findIndex((a) => a.email === entry.email);
  if (i >= 0) idx.accounts[i] = entry;
  else idx.accounts.push(entry);
  idx.version = 2; // v2.0: any mutation writes the current schema marker
  await saveIndex(idx);
}

export async function removeAccount(email: string): Promise<void> {
  const idx = await loadIndex();
  idx.accounts = idx.accounts.filter((a) => a.email !== email);
  idx.version = 2; // v2.0: any mutation writes the current schema marker
  await saveIndex(idx);
}
