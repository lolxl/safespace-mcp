#!/usr/bin/env bun
/**
 * Bench: Drive permission-create latency, 3 approaches.
 *
 * Issue #101 post-v1.11 re-evaluation: validates the analytical claim that
 * post-v1.11, **parallel SDK calls** outperform **HTTP /batch/drive/v3** for
 * Drive permission creation. The original v1.10 deferred decision (DESIGN.md
 * §1322-1385) was made under gws-subprocess constraint; this measures the
 * actual numbers under the direct-googleapis stack.
 *
 * Approaches:
 *   A. Sequential — `for (id) await drive.permissions.create(...)` (baseline)
 *   B. Parallel   — `Promise.all(ids.map(id => drive.permissions.create(...)))`
 *   C. HTTP batch — single POST to /batch/drive/v3 with N multipart sub-requests
 *
 * Hypothesis: B > C because Drive's batch endpoint processes sub-requests
 * server-side sequentially (Google's batch docs: "not necessarily processed
 * in parallel"), while parallel SDK calls saturate the TCP connection pool
 * and Google handles each as an independent transaction.
 *
 * Usage:
 *   bun scripts/bench-drive-batch.ts \
 *     --account=alice@example.com \
 *     --recipient=alice+bench@example.com \
 *     --n=10
 *
 * SAFETY:
 *   - Creates N throwaway empty Google Docs per approach (3N total)
 *   - Shares each with --recipient using `sendNotificationEmail: false`
 *     (no email notifications sent to the recipient)
 *   - Deletes all created files in a `finally` block (cleanup is guaranteed)
 *   - File IDs are pushed into the shared cleanup accumulator AS THEY ARE
 *     CREATED — not after the per-approach loop returns — so a mid-loop
 *     throw (401, 429, network hiccup) still leaves cleanup-reachable IDs
 *   - Reports cleanup success/failure counts so any stragglers are visible
 *
 * SCOPE / WHAT THIS BENCH IS NOT:
 *   - **Bypasses the production recipient-allowlist gate.** The script calls
 *     `drive.permissions.create` directly via `driveClientFromToken`, NOT via
 *     the `drive_share_file` MCP handler. The v2.2 recipient-allowlist
 *     (`SAFESPACE_RECIPIENT_ALLOW`) is NOT enforced here. Only run with a
 *     `--recipient` you fully control (your own plus-address is ideal).
 *   - **Does not pass `supportsAllDrives: true`.** The production handler
 *     sets it (`handlers.ts driveShareFile`); the bench omits it because
 *     the test files live in the user's personal Drive root, not in a
 *     shared drive. Apples-to-apples for the bench comparison; the absolute
 *     numbers may shift slightly vs production if the user has shared drives.
 *
 * Reproducibility: kept in repo so the deferred-decision analysis can be
 * re-validated when API behavior changes or v2.x architectural decisions
 * reopen the question.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { google } from "googleapis";

// ──────────────── arg parsing ────────────────
const args = process.argv.slice(2).reduce<Record<string, string>>((acc, arg) => {
  const m = arg.match(/^--([\w-]+)=(.+)$/);
  if (m && m[1] && m[2]) acc[m[1]] = m[2];
  return acc;
}, {});

const account = args.account;
const recipient = args.recipient;
const n = parseInt(args.n ?? "10", 10);
// Default to the plugin-runtime config dir (where Claude Code stores the .env
// with OAuth client creds + accounts.json). Override via --config-dir if your
// install uses a non-standard layout.
const configDir =
  args["config-dir"] ??
  process.env.SAFESPACE_CONFIG_DIR ??
  path.join(os.homedir(), ".claude", "plugins", "data", "safespace-mcp-safespace", "safespace");

if (!account || !recipient || !Number.isFinite(n) || n < 1) {
  console.error(
    "Usage: bun scripts/bench-drive-batch.ts " +
      "--account=<email> --recipient=<email> --n=<count> [--config-dir=<path>]",
  );
  process.exit(1);
}

// ──────────────── env bootstrap ────────────────
// SafeSpace's getAuthClient reads GOOGLE_CLIENT_ID/SECRET from process.env
// (set via `bun --env-file=...` in production). For this standalone script,
// parse the .env manually so the script is one-command runnable.
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
  // Strip surrounding quotes if present
  if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
    val = val.slice(1, -1);
  }
  if (key && !(key in process.env)) {
    process.env[key] = val;
  }
}
// configDir() in keychain.ts reads SAFESPACE_CONFIG_DIR; set it so the
// auth flow finds accounts.json + keychain entries in the right place.
process.env.SAFESPACE_CONFIG_DIR = configDir;

// Use production handler's exact pattern: refresh once, then driveClientFromToken
// with the raw access_token (minimal OAuth2Client — only access_token + Bearer).
// This mirrors what `drive_search` / `drive_share_file` do post-v1.11.
const { refreshAccessToken } = await import("../.claude-plugin/src/auth/refresh");
const { driveClientFromToken, oauth2ClientFromToken } = await import(
  "../.claude-plugin/src/google-api/client"
);

console.log(`# Bench config`);
console.log(`  account:   ${account}`);
console.log(`  recipient: ${recipient}`);
console.log(`  n:         ${n} (× 3 approaches = ${n * 3} test files created total)`);
console.log("");

// ──────────────── auth + clients ────────────────
// Force-refresh upfront. Bench runs in seconds; one fresh token guarantees
// no mid-bench 401s skewing the latency numbers.
console.log("# Refreshing access token...");
const tokens = await refreshAccessToken(account, { force: true });
console.log(`  ✓ Got fresh token (expires in ${Math.round((tokens.expires_at - Date.now()) / 1000)}s)`);
console.log("");

const drive = driveClientFromToken(tokens.access_token);
const oauth = oauth2ClientFromToken(tokens.access_token);

// ──────────────── helpers ────────────────
async function createTestFiles(
  count: number,
  tag: string,
  cleanupAccumulator: string[],
): Promise<string[]> {
  console.log(`  Creating ${count} test files (tag=${tag})...`);
  // Push each ID into the SHARED cleanup accumulator AS SOON AS it's
  // created. If this loop throws on iteration K, IDs 0..K-1 are already
  // visible to the outer finally-cleanup. Without this, a mid-loop throw
  // would orphan the partial set on the user's Drive (sec-rev PR #103 D1).
  const startIdx = cleanupAccumulator.length;
  for (let i = 0; i < count; i++) {
    const res = await drive.files.create({
      requestBody: {
        name: `bench-drive-batch-${tag}-${Date.now()}-${i}`,
        mimeType: "application/vnd.google-apps.document",
      },
      fields: "id",
    });
    if (!res.data.id) throw new Error(`Create failed at i=${i}`);
    cleanupAccumulator.push(res.data.id);
  }
  return cleanupAccumulator.slice(startIdx);
}

async function deleteFiles(ids: string[]): Promise<{ ok: number; fail: number }> {
  let ok = 0,
    fail = 0;
  for (const id of ids) {
    try {
      await drive.files.delete({ fileId: id });
      ok++;
    } catch (err) {
      fail++;
      console.error(`  ! delete failed for ${id}: ${(err as Error).message}`);
    }
  }
  return { ok, fail };
}

// ──────────────── benches ────────────────
async function benchSequential(fileIds: string[]): Promise<number> {
  const t0 = Date.now();
  for (const fileId of fileIds) {
    await drive.permissions.create({
      fileId,
      requestBody: { role: "reader", type: "user", emailAddress: recipient },
      sendNotificationEmail: false,
    });
  }
  return Date.now() - t0;
}

async function benchParallel(fileIds: string[]): Promise<number> {
  const t0 = Date.now();
  await Promise.all(
    fileIds.map((fileId) =>
      drive.permissions.create({
        fileId,
        requestBody: { role: "reader", type: "user", emailAddress: recipient },
        sendNotificationEmail: false,
      }),
    ),
  );
  return Date.now() - t0;
}

async function benchHttpBatch(fileIds: string[]): Promise<number> {
  // Construct a multipart/mixed body with one sub-request per file. Boundary
  // is random hex; collision with sub-body JSON is astronomically unlikely.
  const boundary = `batch_${Date.now()}_${Math.random().toString(36).slice(2, 14)}`;
  const bodyJson = JSON.stringify({
    role: "reader",
    type: "user",
    emailAddress: recipient,
  });
  const CRLF = "\r\n";
  const parts: string[] = [];
  for (const fileId of fileIds) {
    parts.push(
      `--${boundary}${CRLF}` +
        `Content-Type: application/http${CRLF}` +
        `Content-Transfer-Encoding: binary${CRLF}` +
        `${CRLF}` +
        `POST /drive/v3/files/${fileId}/permissions?sendNotificationEmail=false${CRLF}` +
        `Content-Type: application/json${CRLF}` +
        `Content-Length: ${Buffer.byteLength(bodyJson, "utf8")}${CRLF}` +
        `${CRLF}` +
        bodyJson +
        `${CRLF}`,
    );
  }
  const body = parts.join("") + `--${boundary}--${CRLF}`;

  const t0 = Date.now();
  await oauth.request({
    url: "https://www.googleapis.com/batch/drive/v3",
    method: "POST",
    headers: { "Content-Type": `multipart/mixed; boundary=${boundary}` },
    body,
    responseType: "text",
  });
  return Date.now() - t0;
}

// ──────────────── main ────────────────
const allCreated: string[] = [];
const results: Array<{ approach: string; ms: number }> = [];

try {
  console.log("## A. Sequential");
  const idsA = await createTestFiles(n, "seq", allCreated);
  const tA = await benchSequential(idsA);
  results.push({ approach: "Sequential", ms: tA });
  console.log(`  → ${tA} ms`);
  console.log("");

  console.log("## B. Parallel SDK");
  const idsB = await createTestFiles(n, "par", allCreated);
  const tB = await benchParallel(idsB);
  results.push({ approach: "Parallel SDK", ms: tB });
  console.log(`  → ${tB} ms`);
  console.log("");

  console.log("## C. HTTP batch (/batch/drive/v3)");
  const idsC = await createTestFiles(n, "batch", allCreated);
  const tC = await benchHttpBatch(idsC);
  results.push({ approach: "HTTP batch", ms: tC });
  console.log(`  → ${tC} ms`);
  console.log("");

  console.log("# Summary");
  const tSeq = results[0]?.ms ?? 0;
  for (const r of results) {
    const ratio = tSeq > 0 ? `${(tSeq / r.ms).toFixed(2)}x vs seq` : "—";
    console.log(`  ${r.approach.padEnd(14)} ${String(r.ms).padStart(6)} ms  (${ratio})`);
  }
} finally {
  console.log("");
  console.log("# Cleanup");
  console.log(`  Deleting ${allCreated.length} created files...`);
  const result = await deleteFiles(allCreated);
  console.log(`  Deleted: ${result.ok}, Failed: ${result.fail}`);
  if (result.fail > 0) {
    console.error(`  !! WARNING: ${result.fail} files failed to delete — check Drive UI manually`);
    process.exit(2);
  }
  console.log("  ✓ All test files removed.");
}
