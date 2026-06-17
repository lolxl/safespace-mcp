#!/usr/bin/env bun
/**
 * Probe: calendar_get_event sanitize coverage on a real Calendar event.
 *
 * v1.13 Phase 1b — manual one-time validation per docs/v1.13-calendar-api.md
 * §5 + §8. Run this once per consented account against a real event that
 * exercises the SKIP_FIELDS list (ideally an event with ≥2 attendees, a
 * Meet link, and recurrence) to confirm:
 *
 *   1. User-visible text (summary, description, location, attendees[*].displayName,
 *      attendees[*].email) IS wrapped in <untrusted-source-NONCE/> per the
 *      sanitize pipeline.
 *   2. Google opaque keys (iCalUID / htmlLink / hangoutLink / recurringEventId)
 *      AND closed enums (status / transparency / visibility / eventType) pass
 *      through UNWRAPPED — they're addressed in SKIP_FIELDS so Claude can
 *      keep using them as opaque references.
 *   3. The walk completes without throwing `sanitize_failed` — confirming the
 *      MAX_DEPTH=64 ceiling (carried from v1.12) accommodates real Calendar
 *      events including conferenceData entryPoints + nested extendedProperties.
 *
 * Usage:
 *   bun scripts/probe-calendar-sanitize.ts \
 *     --account=alice@example.com \
 *     --event-id=<eventId> \
 *     [--calendar-id=primary] \
 *     [--config-dir=<path>]
 *
 * SAFETY:
 *   - Read-only — calls `events.get` once and walks the response. No writes,
 *     no shares, no invites.
 *   - Bypasses the production `withToolContext` middleware (this calls
 *     `calendarClientFromToken` + `sanitize` directly so the assertions are
 *     observable). The handler-level validation is exercised in the unit
 *     tests; this probe specifically validates real-API shape compatibility.
 *
 * Reproducibility: kept in repo so the sanitize compatibility analysis can
 * be re-validated if Google adds new opaque keys or schema-level fields in
 * future Calendar API revisions.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

// ──────────────── arg parsing ────────────────
const args = process.argv.slice(2).reduce<Record<string, string>>((acc, arg) => {
  const m = arg.match(/^--([\w-]+)=(.+)$/);
  if (m && m[1] && m[2]) acc[m[1]] = m[2];
  return acc;
}, {});

const account = args.account;
const eventId = args["event-id"];
const calendarId = args["calendar-id"] ?? "primary";
const configDir =
  args["config-dir"] ??
  process.env.SAFESPACE_CONFIG_DIR ??
  path.join(os.homedir(), ".claude", "plugins", "data", "safespace-mcp-safespace", "safespace");

if (!account || !eventId) {
  console.error(
    "Usage: bun scripts/probe-calendar-sanitize.ts " +
      "--account=<email> --event-id=<eventId> [--calendar-id=primary] [--config-dir=<path>]",
  );
  process.exit(1);
}

// ──────────────── env bootstrap ────────────────
const envFile = path.join(configDir, ".env");
if (!fs.existsSync(envFile)) {
  console.error(`ERROR: .env not found at ${envFile}`);
  console.error(`       (override with --config-dir=<path/to/safespace>)`);
  process.exit(1);
}
const envContent = fs.readFileSync(envFile, "utf-8");
for (const line of envContent.split("\n")) {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#")) continue;
  const eq = trimmed.indexOf("=");
  if (eq < 0) continue;
  const key = trimmed.slice(0, eq).trim();
  let val = trimmed.slice(eq + 1).trim();
  if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
    val = val.slice(1, -1);
  }
  if (key && !(key in process.env)) {
    process.env[key] = val;
  }
}
process.env.SAFESPACE_CONFIG_DIR = configDir;

const { refreshAccessToken } = await import("../.claude-plugin/src/auth/refresh");
const { calendarClientFromToken } = await import("../.claude-plugin/src/google-api/client");
const { sanitize } = await import("../.claude-plugin/src/sanitize");

console.log(`# Probe config`);
console.log(`  account:     ${account}`);
console.log(`  calendar_id: ${calendarId}`);
console.log(`  event_id:    ${eventId}`);
console.log("");

console.log("# Refreshing access token...");
const tokens = await refreshAccessToken(account, { force: true });
console.log(`  ✓ Got fresh token`);
console.log("");

console.log("# Calling events.get...");
const calendar = calendarClientFromToken(tokens.access_token);
const res = await calendar.events.get({ calendarId, eventId });
const raw = res.data;
console.log(`  ✓ Got response (id="${raw.id}", summary="${raw.summary}")`);
console.log("");

// ──────────────── walk helpers ────────────────
type WalkVisitor = (key: string, value: unknown, path: string) => void;
function walkResponse(obj: unknown, visit: WalkVisitor, p = "$"): void {
  if (obj === null || typeof obj !== "object") return;
  if (Array.isArray(obj)) {
    obj.forEach((el, i) => walkResponse(el, visit, `${p}[${i}]`));
    return;
  }
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    visit(k, v, `${p}.${k}`);
    walkResponse(v, visit, `${p}.${k}`);
  }
}

const WRAP_PREFIX_RE = /^<untrusted-source-[0-9a-f]{16}/;

// ──────────────── sanitize + assert ────────────────
console.log("# Running sanitize() over response...");
let sanitized: unknown;
try {
  sanitized = sanitize(raw, { toolName: "calendar_get_event" });
} catch (err) {
  console.error(`  ✗ sanitize threw: ${(err as Error).message}`);
  console.error("    This means MAX_DEPTH=64 is still too low OR a SKIP_FIELDS");
  console.error("    edge-case fired. Fix sanitize/ before shipping.");
  process.exit(2);
}
console.log("  ✓ sanitize() completed (no depth overflow / circular ref)");
console.log("");

// Pass criterion 1: user-visible text fields ARE wrapped.
console.log("# Pass criterion 1: summary / description / location / attendees[].* values ARE wrapped");
const USER_VISIBLE_KEYS = new Set([
  "summary",
  "description",
  "location",
  "displayName",
  "email",
]);
let wrappedUserVisible = 0;
let unwrappedUserVisible = 0;
walkResponse(sanitized, (k, v, p) => {
  if (USER_VISIBLE_KEYS.has(k) && typeof v === "string" && v.length > 0) {
    if (WRAP_PREFIX_RE.test(v)) {
      wrappedUserVisible++;
    } else {
      unwrappedUserVisible++;
      console.error(`    ✗ UNWRAPPED user-visible at ${p}: ${v.slice(0, 60)}...`);
    }
  }
});
console.log(`  → ${wrappedUserVisible} user-visible fields wrapped`);
if (unwrappedUserVisible > 0) {
  console.error(`  ✗ FAIL: ${unwrappedUserVisible} user-visible values escaped wrapping`);
  process.exit(3);
}
if (wrappedUserVisible === 0) {
  console.warn("  ⚠ WARNING: no user-visible text wrapped — is the event empty?");
}
console.log("");

// Pass criterion 2: SKIP_FIELDS keys NEVER wrapped.
console.log("# Pass criterion 2: SKIP_FIELDS Calendar keys NOT wrapped");
const opaqueKeys = [
  "iCalUID",
  "htmlLink",
  "hangoutLink",
  "etag",
  "recurringEventId",
  "status",
  "transparency",
  "visibility",
  "eventType",
];
const leaks: Array<{ path: string; key: string; value: string }> = [];
walkResponse(sanitized, (k, v, p) => {
  if (opaqueKeys.includes(k) && typeof v === "string" && WRAP_PREFIX_RE.test(v)) {
    leaks.push({ path: p, key: k, value: v.slice(0, 80) });
  }
});
if (leaks.length > 0) {
  console.error("  ✗ FAIL: opaque keys leaked into sanitize wrap:");
  for (const l of leaks) {
    console.error(`    - ${l.path} (${l.key}): ${l.value}...`);
  }
  process.exit(4);
}
console.log(`  ✓ all ${opaqueKeys.length} opaque key families pass through unwrapped`);
console.log("");

// Pass criterion 3: implicit — we got here without sanitize_failed.
console.log("# Pass criterion 3: walk completed without sanitize_failed");
console.log("  ✓ implicit pass (sanitize() returned)");
console.log("");

console.log("# All probe criteria PASSED. v1.13 Phase 1b sanitize coverage is valid for this account/event.");
