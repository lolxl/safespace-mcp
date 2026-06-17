// Persisted active-account file at `~/.config/safespace/active-account`.
// Set by `safespace account-switch <email>` (Step 5.6).
// Read by withToolContext as a fallback BETWEEN args.account_id and the
// in-memory lastUsedAccount.
//
// Plan agent D8: `account-switch` is an explicit user CLI action — it should
// persist across process restarts. This overrides DESIGN.md's original
// "lastUsedAccount in-memory only" rule for the deliberate-switch path.
// The in-memory `lastUsedAccount` (touched by every successful tool call)
// stays ephemeral — only this file persists.

import * as fs from "node:fs/promises";
import * as path from "node:path";
import { configDir } from "./keychain";

const ACTIVE_FILE = "active-account";

// Same shape as cli.ts EMAIL_RE; intentionally duplicated rather than imported
// to keep auth/ standalone (cli.ts imports auth/, not vice versa).
const EMAIL_RE = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

function activePath(): string {
  return path.join(configDir(), ACTIVE_FILE);
}

/** Return the persisted active account, or null if missing/corrupt.
 *
 * Corrupt files (non-email content, multi-line, etc.) return null rather
 * than throwing — defensive against user-edited files or a partial write
 * from a crashed CLI. Caller falls back to the next resolution tier. */
export async function readActive(): Promise<string | null> {
  try {
    const content = await fs.readFile(activePath(), "utf8");
    const trimmed = content.trim();
    if (!EMAIL_RE.test(trimmed)) return null;
    return trimmed;
  } catch {
    // ENOENT, EACCES, or any other I/O error → treat as no active account.
    // Intentionally swallowed: from the caller's perspective "no active
    // account" is the same regardless of why (defensive against partial
    // writes, hand-edited files, post-sudo root-owned files, etc).
    // The caller falls back to the next resolution tier with no surprise.
    return null;
  }
}

/** Write `email\n` to the active-account file (mode 0o600). Rejects bad
 *  emails before any filesystem work to avoid creating corrupt files. */
export async function writeActive(email: string): Promise<void> {
  if (!EMAIL_RE.test(email)) {
    throw new Error("writeActive: invalid email format");
  }
  await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
  await fs.writeFile(activePath(), `${email}\n`, { mode: 0o600 });
}

/** Remove the active-account file. Idempotent (no-op if missing).
 *  Used by `account-revoke` (Step 5.7) when the revoked account was active. */
export async function clearActive(): Promise<void> {
  await fs.unlink(activePath()).catch(() => undefined);
}
