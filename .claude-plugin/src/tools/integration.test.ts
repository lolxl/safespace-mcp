// Integration tests closing the 3 gaps documented in docs/TEST_PLAN.md
// §Known gaps (deferred to future PRs). See GitHub issue #25.
//
// All three tests run through the real withToolContext stack with surgical
// DI substitutions — no source code changes were required because the
// existing RefreshDeps interface (src/auth/refresh.ts) and the gaxios
// handler seam (src/google-api/test-utils.ts) already expose the needed
// hooks.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { MCPError } from "../errors";
import {
  loadIndex,
  saveIndex,
  type AccountEntry,
  type AccountsIndex,
} from "../auth/keychain";
import type { TokenSet } from "../auth/refresh";
import { gmailSearch } from "./handlers";
import {
  _resetLastUsedForTests,
  withToolContext,
  type WithContextDeps,
} from "./with-context";

const ENV_BACKUP = {
  id: process.env.GOOGLE_CLIENT_ID,
  secret: process.env.GOOGLE_CLIENT_SECRET,
  configDir: process.env.SAFESPACE_CONFIG_DIR,
};

let tmpDir: string;

beforeEach(async () => {
  process.env.GOOGLE_CLIENT_ID = "fake";
  process.env.GOOGLE_CLIENT_SECRET = "fake";
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-integration-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  _resetLastUsedForTests();
});

afterEach(async () => {
  process.env.GOOGLE_CLIENT_ID = ENV_BACKUP.id;
  process.env.GOOGLE_CLIENT_SECRET = ENV_BACKUP.secret;
  if (ENV_BACKUP.configDir === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = ENV_BACKUP.configDir;
  await fs.rm(tmpDir, { recursive: true, force: true });
  _resetLastUsedForTests();
});

function freshTokenSet(overrides: Partial<TokenSet> = {}): TokenSet {
  return {
    refresh_token: "rt",
    access_token: "access",
    expires_at: Date.now() + 30 * 60_000,
    scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
    obtained_at: Date.now(),
    ...overrides,
  };
}

function entry(email: string): AccountEntry {
  return {
    email,
    scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
    added_at: "2026-05-15T00:00:00.000Z",
    last_used_at: null,
  };
}

/* ─────────────── Gap 1: Concurrent saveIndex (cross-process) ─────────────── */
//
// Original plan Integration #4 — two Claude Code instances (= two MCP server
// PROCESSES) writing accounts.json simultaneously. v1's safety property: the
// `accounts.json.tmp.<pid>.<ms>` + rename pattern in keychain.ts saveIndex
// gives each PROCESS a unique tmp path (different PIDs), and fs.rename is
// kernel-atomic on POSIX. Two processes can race the rename but cannot
// corrupt the final JSON — last-writer-wins per DESIGN.md.
//
// Within-process Promise.all of saveIndex is NOT the right model: two
// coroutines in the same Bun process share PID and can collide on the
// millisecond timestamp, producing an ENOENT on rename. Real concurrent
// CLI invocations always have distinct PIDs, so we spawn subprocesses.

describe("integration: concurrent cross-process saveIndex (Gap 1, plan Integration #4)", () => {
  test("two subprocesses writing accounts.json leave a valid, parseable index", async () => {
    // Each subprocess runs a tiny `bun -e` script that imports saveIndex from
    // the same source tree and writes a distinct one-account index.
    const repoRoot = path.resolve(import.meta.dir, "..", "..");
    const keychainPath = path.join(repoRoot, "src", "auth", "keychain.ts");

    function runWriter(email: string): Promise<{ exitCode: number; stderr: string }> {
      const code = `
        import { saveIndex } from ${JSON.stringify(keychainPath)};
        await saveIndex({
          version: 1,
          accounts: [{
            email: ${JSON.stringify(email)},
            scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
            added_at: "2026-05-15T00:00:00.000Z",
            last_used_at: null,
          }],
        });
      `;
      return (async () => {
        const proc = Bun.spawn(["bun", "-e", code], {
          env: { ...process.env, SAFESPACE_CONFIG_DIR: tmpDir },
          stdout: "pipe",
          stderr: "pipe",
        });
        const [stderr, exitCode] = await Promise.all([
          new Response(proc.stderr).text(),
          proc.exited,
        ]);
        return { exitCode, stderr };
      })();
    }

    const [a, b] = await Promise.all([
      runWriter("alice@example.com"),
      runWriter("bob@example.com"),
    ]);
    expect(a.exitCode, `subprocess A stderr: ${a.stderr}`).toBe(0);
    expect(b.exitCode, `subprocess B stderr: ${b.stderr}`).toBe(0);

    const final = await loadIndex();
    expect(final.version).toBe(1);
    expect(final.accounts).toHaveLength(1);
    const email = final.accounts[0]!.email;
    // Last-writer-wins: whichever subprocess renamed second is the winner.
    expect(["alice@example.com", "bob@example.com"]).toContain(email);
  }, 15_000);

  test("interleaved save + load does not produce a partial-write read", async () => {
    // Within-process is OK here because we test the LOAD path's robustness
    // against a save in flight, not concurrent saves against each other.
    await saveIndex({ version: 1, accounts: [entry("alice@example.com")] });

    const newIdx: AccountsIndex = {
      version: 1,
      accounts: [entry("alice@example.com"), entry("bob@example.com")],
    };
    const ops: Array<Promise<unknown>> = [saveIndex(newIdx)];
    for (let i = 0; i < 5; i++) ops.push(loadIndex());

    const results = await Promise.all(ops);
    const loads = results.slice(1) as AccountsIndex[];
    for (const idx of loads) {
      expect(idx.version).toBe(1);
      // Either the seed (1 account) or the new state (2 accounts) — never a
      // corrupted JSON, never the empty fallback (which would mean both files
      // were unreadable, i.e. a torn write).
      expect([1, 2]).toContain(idx.accounts.length);
    }
  });
});

/* ─────────────── Gap 2: 403 → scope_mismatch ─────────────── */
//
// Original plan Integration #5 — user revokes a scope from Google's security
// dashboard between consent and runtime; the next tool call hits 403 which
// must surface to Claude as MCPError("scope_mismatch") so the recovery hint
// (run `safespace consent --re-auth`) reaches the user.
//
// The mapping itself is unit-tested in with-context.test.ts (mapHttpError
// table). This integration test proves the FULL stack: gaxios returns a
// 403 → handlers.ts mapGoogleError → MCPError("scope_mismatch") →
// withToolContext lets MCPError pass through → caller sees it via
// toJsonRpc with code -32004 + recovery hint.

describe("integration: 403 from googleapis → scope_mismatch (Gap 2, plan Integration #5)", () => {
  test("gmail_search with a 403 gaxios response surfaces MCPError(scope_mismatch)", async () => {
    const { setGaxiosHandler, makeGaxiosError, resetGaxiosHandler } = await import(
      "../google-api/test-utils"
    );
    resetGaxiosHandler();
    setGaxiosHandler(async () => {
      throw makeGaxiosError({
        status: 403,
        errorStatus: "PERMISSION_DENIED",
        errors: [{ reason: "insufficientScopes" }],
        errorMessage: "insufficient_scope",
      });
    });

    const deps: WithContextDeps = {
      getToken: async () => JSON.stringify(freshTokenSet()),
      setToken: async () => undefined,
      deleteToken: async () => undefined,
      removeAccount: async () => undefined,
      fetchImpl: (async () => new Response("{}", { status: 200 })) as unknown as typeof fetch,
      loadIndexImpl: async () => ({ accounts: [{ email: "alice@example.com" }] }),
    };

    let caught: unknown;
    try {
      await withToolContext(
        "gmail_search",
        { query: "anything", account_id: "alice@example.com" },
        gmailSearch,
        deps,
      );
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeInstanceOf(MCPError);
    const err = caught as MCPError;
    expect(err.errorName).toBe("scope_mismatch");
    // Wireup through toJsonRpc — assert code (stable) + recovery presence,
    // not prose content (locale-coupled: errors.ts uses zh-TW strings).
    const json = err.toJsonRpc();
    expect(json.code).toBe(-32004);
    expect(typeof json.data.recovery).toBe("string");

    resetGaxiosHandler();
  });
});

/* ─────────────── Gap 3: keychain_locked propagation ─────────────── */
//
// Original plan Error UX #6 — Keychain is locked at fresh boot (user hasn't
// entered their macOS login password yet, or has manually locked the
// Keychain). The keyring native call throws; keychain.ts wraps it as
// MCPError("keychain_locked"). The end-to-end question is whether that
// MCPError survives the withToolContext stack and reaches the caller with
// the correct error code + recovery hint.
//
// "Actually locking the Keychain" is impractical in CI (platform-specific +
// requires user interaction). We inject via the existing RefreshDeps.getToken
// seam, which is the same seam refresh.ts uses internally. The propagation
// path is what we care about — the OS-level locking behaviour is already
// exercised in keychain.test.ts via real @napi-rs/keyring round-trips.

describe("integration: keychain_locked propagates through withToolContext (Gap 3, plan Error UX #6)", () => {
  test("getToken throwing keychain_locked surfaces as MCPError(keychain_locked) to caller", async () => {
    let getTokenCalls = 0;
    const deps: WithContextDeps = {
      getToken: async () => {
        getTokenCalls += 1;
        throw new MCPError("keychain_locked");
      },
      setToken: async () => undefined,
      deleteToken: async () => undefined,
      removeAccount: async () => undefined,
      fetchImpl: (async () => new Response("{}", { status: 200 })) as unknown as typeof fetch,
      loadIndexImpl: async () => ({ accounts: [{ email: "alice@example.com" }] }),
    };

    let caught: unknown;
    try {
      await withToolContext(
        "gmail_search",
        { query: "anything", account_id: "alice@example.com" },
        gmailSearch,
        deps,
      );
    } catch (e) {
      caught = e;
    }

    expect(getTokenCalls).toBeGreaterThan(0);
    expect(caught).toBeInstanceOf(MCPError);
    const err = caught as MCPError;
    expect(err.errorName).toBe("keychain_locked");
    // No accidental errorData leakage from the native layer — keychain.ts
    // catches `e` and constructs MCPError("keychain_locked") with empty
    // data. The test mock here follows the same contract.
    expect(err.errorData).toEqual({});
    // Wireup through toJsonRpc — assert code (stable) + recovery presence,
    // not prose content (locale-coupled: errors.ts uses zh-TW strings).
    const json = err.toJsonRpc();
    expect(json.code).toBe(-32002);
    expect(typeof json.data.recovery).toBe("string");
  });
});
