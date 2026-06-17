// v1.110 PR 1d — cross-platform delivery smoke test.
//
// Proves the multi-client path (Antigravity / Gemini / Codex / any MCP client)
// that PR 1c built: the prebuilt dist/ bundle launches on PLAIN NODE (no Bun)
// and speaks MCP. Run AFTER `bun run build`, on each target OS in CI:
//
//   node scripts/smoke-mcp.mjs
//
// It is deliberately a .mjs Node script (not bash / PowerShell) so the SAME
// file runs identically on Windows, macOS, and Linux. It spawns the server with
// `process.execPath` (the node running this script — NOT bun), so a green run
// means the consumer-facing Node path genuinely works.
//
// Checks:
//   1. dist/proxy.js (the `safespace-mcp` server bin) boots on node, completes
//      the MCP `initialize` handshake (serverInfo.name === "safespace-mcp") and
//      answers tools/list with a non-empty tool array. On Windows this also
//      proves S6 — bootstrap reaches the FileBackend default WITHOUT loading the
//      native @napi-rs/keyring addon.
//   2. dist/cli.js (the `safespace` CLI bin) loads on node and prints usage.
//
// Exit 0 on success, 1 on any failure (so CI gates on it).

import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PKG_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PROXY = join(PKG_ROOT, "dist", "proxy.js");
const CLI = join(PKG_ROOT, "dist", "cli.js");
const TIMEOUT_MS = 30_000;

function fail(msg) {
  console.error(`smoke FAIL: ${msg}`);
  process.exit(1);
}

/** Spawn a built bin on plain node (with optional argv), feed it `stdinLines`,
 *  resolve with the collected { stdout, stderr, code } once it exits (or reject
 *  on timeout). */
function runBin(binPath, stdinLines, configDir, args = []) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [binPath, ...args], {
      env: { ...process.env, SAFESPACE_CONFIG_DIR: configDir },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill(); // SIGTERM → TerminateProcess on Windows; no signal arg = portable
      reject(new Error(`timed out after ${TIMEOUT_MS}ms`));
    }, TIMEOUT_MS);
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ stdout, stderr, code });
    });
    for (const line of stdinLines) child.stdin.write(line + "\n");
    child.stdin.end(); // EOF → the stdio MCP transport closes → server exits
  });
}

/** Parse newline-delimited JSON-RPC, return the first message with `id`. */
function findResponse(stdout, id) {
  for (const line of stdout.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    let msg;
    try {
      msg = JSON.parse(t);
    } catch {
      continue;
    }
    if (msg && msg.id === id) return msg;
  }
  return null;
}

async function main() {
  if (!existsSync(PROXY) || !existsSync(CLI)) {
    fail(`dist not built — expected ${PROXY} and ${CLI}. Run \`bun run build\` first.`);
  }
  const configDir = mkdtempSync(join(tmpdir(), "ss-smoke-"));
  try {
    // 1. Server: MCP initialize + tools/list over stdio on plain node.
    const init = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "smoke", version: "0" },
      },
    });
    const list = JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
    const server = await runBin(PROXY, [init, list], configDir);

    const initResp = findResponse(server.stdout, 1);
    if (!initResp) fail(`no initialize response. stderr:\n${server.stderr}`);
    const name = initResp.result?.serverInfo?.name;
    if (name !== "safespace-mcp") fail(`unexpected serverInfo.name: ${JSON.stringify(name)}`);

    const listResp = findResponse(server.stdout, 2);
    const tools = listResp?.result?.tools;
    if (!Array.isArray(tools) || tools.length === 0) {
      fail(`tools/list returned no tools. stderr:\n${server.stderr}`);
    }
    console.log(`smoke ok: server booted on node ${process.version}, ${tools.length} tools advertised`);

    // 2. CLI bin loads + a real subcommand runs to completion (exit 0). `status`
    //    is a read-only report that also exercises config-dir resolution
    //    (relevant on Windows %APPDATA%). A no-arg invocation is itself an
    //    exit-1 usage error, so we run a genuine zero-exit subcommand instead.
    const cli = await runBin(CLI, [], configDir, ["status"]);
    if (cli.code !== 0) fail(`cli \`status\` exited ${cli.code}. stderr:\n${cli.stderr}`);
    if (!/config dir:/.test(cli.stdout)) {
      fail(`cli \`status\` printed no report. stdout:\n${cli.stdout}\nstderr:\n${cli.stderr}`);
    }
    console.log("smoke ok: cli bin loaded and ran `status`");

    console.log("smoke PASS");
  } finally {
    rmSync(configDir, { recursive: true, force: true });
  }
}

// Print the stack (not just the message) so an unexpected CI failure — notably
// on the Windows leg we can't run locally — is diagnosable from the log.
main().catch((e) => fail(e?.stack ?? e?.message ?? String(e)));
