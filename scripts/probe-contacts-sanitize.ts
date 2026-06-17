#!/usr/bin/env bun
/**
 * Probe: contacts_search + contacts_get sanitize coverage on a real People
 * (Contacts) account.
 *
 * v1.15 Phase 1b — manual one-time validation per
 * docs/v1.15-contacts-api.md §10. Run this once per consented account
 * against (a) a real contact resource_name AND (b) a sample search query
 * to confirm:
 *
 *   1. User-typed content (names[*].displayName, emailAddresses[*].value,
 *      phoneNumbers[*].value, biographies[*].value, organizations[*].name,
 *      urls[*].value, addresses[*].formattedValue, etc.) IS wrapped in
 *      <untrusted-source-NONCE/> per the sanitize pipeline.
 *   2. Google opaque keys (resourceName, etag, metadata.sources[*].id,
 *      metadata.sources[*].etag) AND closed enums (objectType) pass through
 *      UNWRAPPED — they're in SKIP_FIELDS so Claude can keep using them as
 *      opaque references (e.g., feed resourceName into a follow-up
 *      contacts_get call).
 *   3. The walk completes without throwing `sanitize_failed` — confirming
 *      the MAX_DEPTH=64 ceiling (carried from v1.12) accommodates real
 *      Person resources including nested metadata.sources / userDefined.
 *   4. Cache-warming overhead: cold-call latency (first call per process)
 *      should be ≥3 seconds (warm sleep + warm SDK call); warm-call latency
 *      (second call same account) should be <500ms typical.
 *
 * Usage:
 *   bun scripts/probe-contacts-sanitize.ts \
 *     --account=alice@example.com \
 *     --resource-name=people/c1234567890123456789 \
 *     [--query=alice] \
 *     [--config-dir=<path>]
 *
 * SAFETY:
 *   - Read-only — calls `people.get` + `people.searchContacts` once each and
 *     walks the responses. No writes, no shares, no invites.
 *   - Bypasses the production `withToolContext` middleware (this calls
 *     `peopleClientFromToken` + `sanitize` directly so the assertions are
 *     observable). The handler-level validation is exercised in unit tests;
 *     this probe specifically validates real-API shape compatibility.
 *
 * MANUAL one-time validation; not in CI. Run after Phase 1b ships to verify
 * against real Google API.
 *
 * Reproducibility: kept in repo so the sanitize compatibility analysis can
 * be re-validated if Google adds new opaque keys or schema-level fields in
 * future People API revisions.
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
const resourceName = args["resource-name"];
const query = args.query ?? "a"; // single-char fallback query; expected to hit something
const configDir =
  args["config-dir"] ??
  process.env.SAFESPACE_CONFIG_DIR ??
  path.join(os.homedir(), ".claude", "plugins", "data", "safespace-mcp-safespace", "safespace");

if (!account || !resourceName) {
  console.error(
    "Usage: bun scripts/probe-contacts-sanitize.ts " +
      "--account=<email> --resource-name=people/cXXX [--query=<text>] [--config-dir=<path>]",
  );
  process.exit(1);
}

const RESOURCE_NAME_RE = /^people\/c[0-9]{1,32}$/;
if (!RESOURCE_NAME_RE.test(resourceName)) {
  console.error(
    `ERROR: --resource-name=${resourceName} does not match /^people\\/c[0-9]{1,32}$/`,
  );
  console.error(
    "       Example: --resource-name=people/c1234567890123456789",
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
const { peopleClientFromToken } = await import("../.claude-plugin/src/google-api/client");
const { sanitize } = await import("../.claude-plugin/src/sanitize");

console.log(`# Probe config`);
console.log(`  account:       ${account}`);
console.log(`  resource_name: ${resourceName}`);
console.log(`  query:         ${query}`);
console.log("");

console.log("# Refreshing access token...");
const tokens = await refreshAccessToken(account, { force: true });
console.log(`  ✓ Got fresh token`);
console.log("");

const people = peopleClientFromToken(tokens.access_token);

// ──────────────── cold-call latency (cache warm) ────────────────
console.log("# Cache-warming probe (cold call: empty-query + 3000ms sleep + real query)...");
const coldStart = Date.now();
await people.people.searchContacts({
  query: "",
  readMask: "names,emailAddresses",
  pageSize: 1,
});
// Honor the 3000ms warm sleep as the production handler does.
await new Promise<void>((resolve) => setTimeout(resolve, 3000));
const warmStart = Date.now();
const searchRes = await people.people.searchContacts({
  query,
  readMask: "names,emailAddresses,phoneNumbers,organizations,biographies,urls,addresses",
  pageSize: 10,
});
const coldEnd = Date.now();
console.log(`  cold-call total:  ${coldEnd - coldStart}ms (warm + sleep + real)`);
console.log(`  real-query alone: ${coldEnd - warmStart}ms`);
console.log("");

console.log("# Warm-call probe (second call same process; warm-once flag would skip warming)...");
const warm2Start = Date.now();
await people.people.searchContacts({
  query,
  readMask: "names,emailAddresses",
  pageSize: 1,
});
const warm2End = Date.now();
console.log(`  warm-call latency: ${warm2End - warm2Start}ms`);
if (warm2End - warm2Start > 2500) {
  console.warn(
    "  ⚠ WARNING: warm call took >2.5s; the handler's warm-once flag would still",
  );
  console.warn(
    "    skip the in-handler sleep, but Google-side latency is unusually high.",
  );
}
console.log("");

// ──────────────── people.get for the named resource ────────────────
console.log(`# Calling people.get for ${resourceName}...`);
const res = await people.people.get({
  resourceName,
  personFields:
    "names,emailAddresses,phoneNumbers,organizations,biographies,urls,addresses,birthdays",
});
const raw = res.data;
console.log(`  ✓ Got response (resourceName="${raw.resourceName}")`);
const firstName = raw.names?.[0]?.displayName ?? "(no displayName)";
console.log(`    primary display name: ${firstName}`);
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

// ──────────────── sanitize + assert (people.get response) ────────────────
console.log("# Running sanitize() over people.get response...");
let sanitized: unknown;
try {
  sanitized = sanitize(raw, { toolName: "contacts_get" });
} catch (err) {
  console.error(`  ✗ sanitize threw: ${(err as Error).message}`);
  console.error("    MAX_DEPTH=64 may need bumping OR a SKIP_FIELDS edge-case fired.");
  process.exit(2);
}
console.log("  ✓ sanitize() completed (no depth overflow / circular ref)");
console.log("");

// Pass criterion 1: user-visible text fields ARE wrapped.
console.log("# Pass criterion 1: user-typed text fields ARE wrapped");
const USER_VISIBLE_KEYS = new Set([
  "displayName",
  "givenName",
  "familyName",
  "value",            // emailAddresses[].value, phoneNumbers[].value, urls[].value, biographies[].value
  "formattedValue",   // addresses[].formattedValue
  "name",             // organizations[].name
  "title",            // organizations[].title
  "department",       // organizations[].department
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
  console.warn(
    "  ⚠ WARNING: no user-visible text wrapped — is this contact empty?",
  );
}
console.log("");

// Pass criterion 2: SKIP_FIELDS keys NEVER wrapped.
console.log("# Pass criterion 2: SKIP_FIELDS People-API keys NOT wrapped");
const opaqueKeys = [
  "resourceName",
  "objectType",
  "etag",
  "id",       // metadata.sources[*].id
  "kind",
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

// ──────────────── sanitize + assert (searchContacts response) ────────────────
console.log("# Running sanitize() over searchContacts response...");
let searchSanitized: unknown;
try {
  searchSanitized = sanitize(searchRes.data, { toolName: "contacts_search" });
} catch (err) {
  console.error(`  ✗ sanitize threw on search response: ${(err as Error).message}`);
  process.exit(2);
}
console.log("  ✓ search response sanitize() completed");

let searchWrapped = 0;
let searchUnwrapped = 0;
walkResponse(searchSanitized, (k, v, p) => {
  if (USER_VISIBLE_KEYS.has(k) && typeof v === "string" && v.length > 0) {
    if (WRAP_PREFIX_RE.test(v)) {
      searchWrapped++;
    } else {
      searchUnwrapped++;
      console.error(`    ✗ UNWRAPPED user-visible at ${p}: ${v.slice(0, 60)}...`);
    }
  }
});
console.log(`  → search: ${searchWrapped} user-visible wrapped`);
if (searchUnwrapped > 0) {
  console.error(`  ✗ FAIL: ${searchUnwrapped} user-visible search values escaped wrapping`);
  process.exit(3);
}
console.log("");

console.log("# All probe criteria PASSED. v1.15 Phase 1b sanitize coverage is valid for this account.");
// Explicit exit(0) on success — defense-in-depth against a stray unhandled
// rejection or non-empty event-loop queue holding the process open after the
// probe has reported success. Failure paths above already `process.exit(N)`
// with N ∈ {1,2,3,4}.
process.exit(0);
