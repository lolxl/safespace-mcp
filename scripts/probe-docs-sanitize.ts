#!/usr/bin/env bun
/**
 * Probe: docs_get_content sanitize coverage on a real Google Docs response.
 *
 * v1.12 Phase 1b — manual one-time validation per docs/v1.12-docs-api.md §8
 * test #12. Run this once per consented account against a real doc that
 * exercises the SKIP_FIELDS list (ideally a doc with ≥2-deep nested table
 * plus a comment) to confirm:
 *
 *   1. User-visible text (textRun.content, title, etc.) IS wrapped in
 *      <untrusted-source-NONCE/> per the sanitize pipeline.
 *   2. Google opaque keys (objectId / revisionId / inheritedNamedStyleType)
 *      pass through UNWRAPPED — they're addressed in SKIP_FIELDS so Claude
 *      can keep using them as opaque references.
 *   3. The walk completes without throwing `sanitize_failed` — confirming the
 *      v1.12 MAX_DEPTH bump (32 → 64) accommodates real Docs nesting.
 *
 * Usage:
 *   bun scripts/probe-docs-sanitize.ts \
 *     --account=alice@example.com \
 *     --document-id=<docId> \
 *     [--config-dir=<path>]   # optional; defaults to plugin runtime location
 *
 * SAFETY:
 *   - Read-only — calls `documents.get` once and walks the response. No
 *     writes, no shares.
 *   - Bypasses the production `withToolContext` middleware (this calls
 *     `docsClientFromToken` + `sanitize` directly so the assertions are
 *     observable). The handler-level validation is exercised in the unit
 *     tests; this probe specifically validates real-API shape compatibility.
 *
 * Reproducibility: kept in repo so the sanitize compatibility analysis can
 * be re-validated if Google adds new opaque keys or schema-level fields in
 * future Docs API revisions.
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
const documentId = args["document-id"];
const configDir =
  args["config-dir"] ??
  process.env.SAFESPACE_CONFIG_DIR ??
  path.join(os.homedir(), ".claude", "plugins", "data", "safespace-mcp-safespace", "safespace");

if (!account || !documentId) {
  console.error(
    "Usage: bun scripts/probe-docs-sanitize.ts " +
      "--account=<email> --document-id=<docId> [--config-dir=<path>]",
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
const { docsClientFromToken } = await import("../.claude-plugin/src/google-api/client");
const { sanitize } = await import("../.claude-plugin/src/sanitize");

console.log(`# Probe config`);
console.log(`  account:     ${account}`);
console.log(`  document_id: ${documentId}`);
console.log("");

console.log("# Refreshing access token...");
const tokens = await refreshAccessToken(account, { force: true });
console.log(`  ✓ Got fresh token`);
console.log("");

console.log("# Calling documents.get...");
const docs = docsClientFromToken(tokens.access_token);
const res = await docs.documents.get({ documentId });
const raw = res.data;
console.log(`  ✓ Got response (title="${raw.title}", revisionId="${raw.revisionId}")`);
console.log("");

// ──────────────── walk helpers ────────────────
type WalkVisitor = (key: string, value: unknown, path: string) => void;
function walkResponse(obj: unknown, visit: WalkVisitor, path = "$"): void {
  if (obj === null || typeof obj !== "object") return;
  if (Array.isArray(obj)) {
    obj.forEach((el, i) => walkResponse(el, visit, `${path}[${i}]`));
    return;
  }
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    visit(k, v, `${path}.${k}`);
    walkResponse(v, visit, `${path}.${k}`);
  }
}

const WRAP_PREFIX_RE = /^<untrusted-source-[0-9a-f]{16}/;

// ──────────────── sanitize + assert ────────────────
console.log("# Running sanitize() over response...");
let sanitized: unknown;
try {
  sanitized = sanitize(raw, { toolName: "docs_get_content" });
} catch (err) {
  console.error(`  ✗ sanitize threw: ${(err as Error).message}`);
  console.error("    This means MAX_DEPTH=64 is still too low OR a SKIP_FIELDS");
  console.error("    edge-case fired. Fix sanitize/ before shipping.");
  process.exit(2);
}
console.log("  ✓ sanitize() completed (no depth overflow / circular ref)");
console.log("");

// Pass criterion 1: at least one user-visible text leaf IS wrapped.
console.log("# Pass criterion 1: textRun.content values ARE wrapped");
let wrappedCount = 0;
let unwrappedTextRunCount = 0;
walkResponse(sanitized, (k, v) => {
  if (k === "content" && typeof v === "string" && WRAP_PREFIX_RE.test(v)) {
    wrappedCount++;
  }
  // A textRun.content that does NOT start with the wrap prefix is a leak.
  // We don't have parent context here; approximate by checking content
  // strings that look like real text (length > 0, not the wrap shape).
});
walkResponse(sanitized, (k, v, p) => {
  if (
    p.includes(".textRun.content") &&
    typeof v === "string" &&
    v.length > 0 &&
    !WRAP_PREFIX_RE.test(v)
  ) {
    unwrappedTextRunCount++;
    console.error(`    ✗ UNWRAPPED textRun.content at ${p}: ${v.slice(0, 60)}...`);
  }
});
console.log(`  → ${wrappedCount} wrapped content fields found`);
if (unwrappedTextRunCount > 0) {
  console.error(`  ✗ FAIL: ${unwrappedTextRunCount} textRun.content values escaped wrapping`);
  process.exit(3);
}
if (wrappedCount === 0) {
  console.warn("  ⚠ WARNING: no wrapped text found — is this an empty doc?");
}
console.log("");

// Pass criterion 2: SKIP_FIELDS keys NEVER wrapped.
console.log("# Pass criterion 2: objectId / revisionId / inheritedNamedStyleType NOT wrapped");
const opaqueKeys = ["objectId", "revisionId", "inheritedNamedStyleType"];
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

console.log("# All probe criteria PASSED. v1.12 sanitize coverage is valid for this account/doc.");
