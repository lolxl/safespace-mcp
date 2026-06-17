// v1.8.2 #7 — Proxy startup marker.
//
// The proxy reads policy state ONCE at startup:
//   - `.env` via `bun --env-file=` (env vars frozen at process start)
//   - `drive-whitelist.json` via getWhitelistState() at first share call
//     (cached for proxy lifetime)
//
// So any change to those files AFTER the proxy started will not take effect
// until Claude Code is restarted. The CLI surfaces this with a printed
// `(restart Claude Code to pick up …)` line after each mutation, but users
// forget. `safespace doctor` should be able to detect "config newer than
// proxy startup" and surface it as a warn.
//
// The mechanism: proxy writes an ISO 8601 timestamp to a marker file at
// startup; doctor reads it + compares to mtime of `drive-whitelist.json` +
// `.env`. If any policy file mtime > marker → pending restart.
//
// Edge cases (documented):
//   - Multiple Claude Code instances overwrite the marker: last writer wins.
//     Doctor sees the latest startup, not "is there a stale proxy somewhere".
//   - Proxy crashes without re-writing marker: doctor still sees old marker.
//     False negative. Acceptable — user can manually verify Claude Code is
//     actually running.
//   - First-time install with no marker: doctor reports "absent" as info,
//     not as a failure (proxy hasn't run yet, expected on fresh setup).

import { promises as fs } from "node:fs";
import * as path from "node:path";

export const STARTUP_MARKER_FILE = ".proxy-startup-marker";

function markerPath(configDir: string): string {
  return path.join(configDir, STARTUP_MARKER_FILE);
}

/** Write the current ISO 8601 timestamp to the marker file at 0o600.
 *  Best-effort: any error is logged to stderr and swallowed — proxy startup
 *  must NEVER fail because of a marker write error. */
export async function writeStartupMarker(configDir: string): Promise<void> {
  try {
    await fs.mkdir(configDir, { recursive: true, mode: 0o700 });
    const ts = new Date().toISOString() + "\n";
    // writeFile 'w' truncates; last-writer-wins semantics. Mode option honored
    // by both Bun and Node fs.promises.
    await fs.writeFile(markerPath(configDir), ts, { mode: 0o600 });
  } catch (e) {
    console.error(
      `[safespace] startup marker write failed: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
}

/** Read the marker file and return the parsed timestamp.
 *  Returns null on:
 *    - file absent (ENOENT) — first-time install or wiped marker
 *    - unreadable / parse failure — treat as "no useful info"
 *  Does NOT throw. */
export async function readStartupMarker(configDir: string): Promise<Date | null> {
  let raw: string;
  try {
    raw = await fs.readFile(markerPath(configDir), "utf8");
  } catch {
    return null;
  }
  const trimmed = raw.trim();
  if (trimmed.length === 0) return null;
  const parsed = new Date(trimmed);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed;
}
