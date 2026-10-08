import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { saveIndex } from "./auth/keychain";
// v1.37 BLOCKER 1: token fixtures go through the SecretBackend facade (same
// platform default as production: KeychainBackend on macOS, FileBackend else).
import { deleteToken, setToken } from "./auth/token-store";
import { CliError, runCli, type CliIO } from "./cli";
import { __resetChainState, __drainAuditWrites } from "./audit";
import { MCPError } from "./errors";
import { __resetServiceTokenBackendForTests } from "./auth/service-token-store";

let tmpDir: string;
let prevEnv: string | undefined;

beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-cli-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
});

afterEach(async () => {
  if (prevEnv === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevEnv;
  await fs.rm(tmpDir, { recursive: true, force: true });
});

function captureIO(): { io: CliIO; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: { out: (l) => out.push(l), err: (l) => err.push(l) },
    out,
    err,
  };
}

async function planIndex(emails: Array<{ email: string; scopes?: string[]; lastUsedAt?: string | null }>): Promise<void> {
  await saveIndex({
    version: 1,
    accounts: emails.map((e) => ({
      email: e.email,
      scopes: e.scopes ?? ["https://www.googleapis.com/auth/gmail.readonly"],
      added_at: "2026-05-01T00:00:00.000Z",
      last_used_at: e.lastUsedAt ?? null,
    })),
  });
}

describe("runCli — SAFESPACE_OPERATOR_ID retired", () => {
  let prevOp: string | undefined;
  let prevLine: string | undefined;
  beforeEach(() => {
    prevOp = process.env.SAFESPACE_OPERATOR_ID;
    prevLine = process.env.SAFESPACE_LINE_CHANNEL_TOKEN;
  });
  afterEach(() => {
    if (prevOp === undefined) delete process.env.SAFESPACE_OPERATOR_ID;
    else process.env.SAFESPACE_OPERATOR_ID = prevOp;
    if (prevLine === undefined) delete process.env.SAFESPACE_LINE_CHANNEL_TOKEN;
    else process.env.SAFESPACE_LINE_CHANNEL_TOKEN = prevLine;
  });

  test("every subcommand, doctor included, refuses before doing anything", async () => {
    process.env.SAFESPACE_OPERATOR_ID = "alice-x9";
    // An env service token would make `line status` answer without the backend.
    process.env.SAFESPACE_LINE_CHANNEL_TOKEN = "env-line-token";
    await planIndex([{ email: "a@example.com" }]);
    for (const argv of [
      ["doctor"],
      ["doctor", "--deep"],
      ["line", "status"],
      ["account-list"],
      ["consent", "a@example.com"],
      ["exec", "gmail_list_labels", "--params", "{}"],
    ]) {
      const { io, out, err } = captureIO();
      const p = runCli(argv, io);
      await expect(p).rejects.toBeInstanceOf(CliError);
      await expect(p).rejects.toThrow(/SAFESPACE_OPERATOR_ID/);
      await p.catch((e: Error) => expect(e.message).not.toContain("alice-x9"));
      expect(out).toEqual([]);
      expect(err).toEqual([]);
    }
  });

  test("an empty value is unset: the CLI runs", async () => {
    process.env.SAFESPACE_OPERATOR_ID = "";
    const { io, out } = captureIO();
    await runCli(["account-list"], io);
    expect(out.length).toBeGreaterThan(0);
  });
});

describe("runCli — dispatch + usage", () => {
  test("no subcommand → CliError with usage", async () => {
    const { io } = captureIO();
    await expect(runCli([], io)).rejects.toBeInstanceOf(CliError);
    await expect(runCli([], io)).rejects.toThrow(/usage: safespace/);
  });

  test("unknown subcommand → CliError naming it", async () => {
    const { io } = captureIO();
    await expect(runCli(["bogus"], io)).rejects.toThrow(/unknown subcommand: bogus/);
  });

  test("audit with no sub-subcommand surfaces USAGE (v1.18 Phase 2 wired)", async () => {
    const { io } = captureIO();
    await expect(runCli(["audit"], io)).rejects.toThrow(/recent\|stats\|deletes\|policy-decisions/);
  });
});

describe("runCli account-list", () => {
  test("empty index → friendly hint, no exception", async () => {
    const { io, out } = captureIO();
    await runCli(["account-list"], io);
    expect(out.join("\n")).toContain("(no accounts;");
  });

  test("populated index → table with header + rows, no active marker if no file", async () => {
    await planIndex([
      { email: "alice@example.com", lastUsedAt: "2026-05-12T10:00:00.000Z" },
      { email: "bob@example.com" },
    ]);
    const { io, out } = captureIO();
    await runCli(["account-list"], io);
    const text = out.join("\n");
    expect(text).toContain("EMAIL");
    expect(text).toContain("SCOPES");
    expect(text).toContain("alice@example.com");
    expect(text).toContain("bob@example.com");
    // No active marker since active-account file doesn't exist
    expect(text).not.toContain("*");
  });

  test("5.6 code-rev HIGH regression: column header aligns with data rows", async () => {
    await planIndex([
      { email: "alice@example.com", lastUsedAt: "2026-05-12T10:00:00.000Z" },
    ]);
    const { io, out } = captureIO();
    await runCli(["account-list"], io);
    // Header line should be the first output. Data rows follow.
    const header = out[0]!;
    const dataRow = out.find((l) => l.includes("alice@example.com"))!;
    // EMAIL header starts at offset 2 (after the 2-char marker column).
    expect(header.indexOf("EMAIL")).toBe(2);
    // SCOPES, ADDED, LAST USED columns must align with the row's content
    // (data row uses padEnd, so digit-1 scope sits at the column start).
    expect(header.indexOf("SCOPES")).toBe(dataRow.indexOf("1"));
    expect(header.indexOf("ADDED")).toBe(dataRow.indexOf("2026-05-01"));
    expect(header.indexOf("LAST USED")).toBe(dataRow.indexOf("2026-05-12"));
  });

  test("populated index + active file → marks the active row with `* `", async () => {
    await planIndex([
      { email: "alice@example.com" },
      { email: "bob@example.com" },
    ]);
    await fs.writeFile(path.join(tmpDir, "active-account"), "bob@example.com\n", { mode: 0o600 });
    const { io, out } = captureIO();
    await runCli(["account-list"], io);
    const text = out.join("\n");
    const bobRow = out.find((l) => l.includes("bob@example.com"));
    expect(bobRow).toBeDefined();
    expect(bobRow!.startsWith("* ")).toBe(true);
    const aliceRow = out.find((l) => l.includes("alice@example.com"));
    expect(aliceRow!.startsWith("  ")).toBe(true);
    expect(text).toContain("* = active account");
  });

  test("active marker footer shows the RESOLVED active-account path (regression: no hardcoded ~/.config)", async () => {
    // Older builds always printed "(from ~/.config/safespace/active-account)"
    // regardless of SAFESPACE_CONFIG_DIR. The footer must reflect the actual
    // path the CLI reads from — critical when the plugin install puts the
    // file under ${CLAUDE_PLUGIN_DATA}/safespace/, not under ~/.config.
    await planIndex([{ email: "alice@example.com" }]);
    await fs.writeFile(path.join(tmpDir, "active-account"), "alice@example.com\n", { mode: 0o600 });
    const { io, out } = captureIO();
    await runCli(["account-list"], io);
    const footer = out.find((l) => l.includes("active account"));
    expect(footer).toBeDefined();
    // The actual config dir (tmpDir) is NOT inside $HOME, so tildePath
    // returns it verbatim. The footer must contain the absolute tmpDir
    // path, never the hardcoded "~/.config/safespace" string.
    expect(footer!).toContain(path.join(tmpDir, "active-account"));
    expect(footer!).not.toContain("~/.config/safespace/active-account");
  });
});

describe("runCli account-switch", () => {
  test("missing email argv → CliError with usage", async () => {
    const { io } = captureIO();
    await expect(runCli(["account-switch"], io)).rejects.toThrow(/usage: safespace account-switch/);
  });

  test("invalid email format → CliError", async () => {
    const { io } = captureIO();
    await expect(runCli(["account-switch", "not-an-email"], io)).rejects.toThrow(/must be a valid address/);
  });

  test("email not in accounts.json → CliError, no file written", async () => {
    await planIndex([{ email: "alice@example.com" }]);
    const { io } = captureIO();
    await expect(runCli(["account-switch", "ghost@example.com"], io)).rejects.toThrow(/account not found: ghost@example.com/);
    await expect(fs.stat(path.join(tmpDir, "active-account"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("valid switch → writes active-account file + prints confirmation", async () => {
    await planIndex([
      { email: "alice@example.com" },
      { email: "bob@example.com" },
    ]);
    const { io, out } = captureIO();
    await runCli(["account-switch", "bob@example.com"], io);
    expect(out.join("\n")).toContain("active account set to bob@example.com");
    const content = await fs.readFile(path.join(tmpDir, "active-account"), "utf8");
    expect(content.trim()).toBe("bob@example.com");
  });

  test("subsequent switch overwrites the previous active account", async () => {
    await planIndex([
      { email: "alice@example.com" },
      { email: "bob@example.com" },
    ]);
    const { io } = captureIO();
    await runCli(["account-switch", "alice@example.com"], io);
    await runCli(["account-switch", "bob@example.com"], io);
    const content = await fs.readFile(path.join(tmpDir, "active-account"), "utf8");
    expect(content.trim()).toBe("bob@example.com");
  });
});

// Tests use synthetic emails with NO Keychain entry on purpose: the
// `getToken` call returns null, runAccountRevoke skips the remote revoke
// (warn-only), and we verify the rest of the cleanup chain. The actual
// revoke endpoint behavior is covered in revoke.test.ts via fetchImpl
// injection — we don't want cli.test.ts touching the real macOS Keychain.
describe("runCli account-revoke", () => {
  test("missing email argv → CliError with usage", async () => {
    const { io } = captureIO();
    await expect(runCli(["account-revoke"], io)).rejects.toThrow(/usage: safespace account-revoke/);
  });

  test("invalid email format → CliError", async () => {
    const { io } = captureIO();
    await expect(runCli(["account-revoke", "not-an-email"], io)).rejects.toThrow(/must be a valid address/);
  });

  test("email not in accounts.json → CliError, no state change", async () => {
    await planIndex([{ email: "alice@example.com" }]);
    await fs.writeFile(path.join(tmpDir, "active-account"), "alice@example.com\n", { mode: 0o600 });
    const { io } = captureIO();
    await expect(runCli(["account-revoke", "ghost@example.com"], io)).rejects.toThrow(/account not found: ghost@example.com/);
    // accounts.json + active-account untouched
    const idxRaw = await fs.readFile(path.join(tmpDir, "accounts.json"), "utf8");
    expect(idxRaw).toContain("alice@example.com");
    const active = await fs.readFile(path.join(tmpDir, "active-account"), "utf8");
    expect(active.trim()).toBe("alice@example.com");
  });

  test("no Keychain entry → warn + still clean accounts.json", async () => {
    // Use unique synthetic email per run so a leftover Keychain entry from
    // a previous flaky run cannot mask this test.
    const email = `revoke-test-no-kc-${Date.now()}@example.invalid`;
    await planIndex([
      { email: "alice@example.com" },
      { email },
    ]);
    const { io, out, err } = captureIO();
    await runCli(["account-revoke", email], io);
    expect(err.some((l) => l.includes("no Keychain entry"))).toBe(true);
    expect(out.join("\n")).toContain(`revoked: ${email}`);
    const idxRaw = await fs.readFile(path.join(tmpDir, "accounts.json"), "utf8");
    expect(idxRaw).not.toContain(email);
    expect(idxRaw).toContain("alice@example.com"); // untouched peer
  });

  test("active account revoked → active-account file cleared and message notes it", async () => {
    const email = `revoke-test-active-${Date.now()}@example.invalid`;
    await planIndex([{ email }]);
    await fs.writeFile(path.join(tmpDir, "active-account"), `${email}\n`, { mode: 0o600 });
    const { io, out } = captureIO();
    await runCli(["account-revoke", email], io);
    expect(out.join("\n")).toContain("was active; active account cleared");
    await expect(fs.stat(path.join(tmpDir, "active-account"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("Keychain has valid JSON but no refresh_token field → warn + still clean", async () => {
    // This test DOES touch the real macOS Keychain (synthetic email +
    // try/finally cleanup) because runAccountRevoke reads via keychain.ts's
    // top-level `getToken`, which has no DI surface. Synthetic email avoids
    // collision with any real registered account.
    const email = `revoke-test-no-rt-${Date.now()}@example.invalid`;
    await planIndex([{ email }]);
    await setToken(email, JSON.stringify({ access_token: "ax", expires_at: 0 })); // missing refresh_token
    try {
      const { io, out, err } = captureIO();
      await runCli(["account-revoke", email], io);
      expect(err.some((l) => l.includes("no refresh_token in Keychain"))).toBe(true);
      expect(out.join("\n")).toContain(`revoked: ${email}`);
      const idxRaw = await fs.readFile(path.join(tmpDir, "accounts.json"), "utf8");
      expect(idxRaw).not.toContain(email);
    } finally {
      await deleteToken(email).catch(() => undefined);
    }
  });

  test("Keychain has unparseable string → warn + still clean", async () => {
    const email = `revoke-test-bad-json-${Date.now()}@example.invalid`;
    await planIndex([{ email }]);
    await setToken(email, "this is not json {{{ ");
    try {
      const { io, out, err } = captureIO();
      await runCli(["account-revoke", email], io);
      // Single warning, NOT two (5.7 sec-rev HIGH regression guard).
      const warnings = err.filter((l) => l.includes("warning:"));
      expect(warnings.length).toBe(1);
      expect(warnings[0]).toContain("could not be parsed");
      expect(out.join("\n")).toContain(`revoked: ${email}`);
    } finally {
      await deleteToken(email).catch(() => undefined);
    }
  });

  test("non-active account revoked → active-account untouched", async () => {
    const email = `revoke-test-other-${Date.now()}@example.invalid`;
    await planIndex([
      { email: "alice@example.com" },
      { email },
    ]);
    await fs.writeFile(path.join(tmpDir, "active-account"), "alice@example.com\n", { mode: 0o600 });
    const { io, out } = captureIO();
    await runCli(["account-revoke", email], io);
    expect(out.join("\n")).toContain(`revoked: ${email}`);
    expect(out.join("\n")).not.toContain("active account cleared");
    const active = await fs.readFile(path.join(tmpDir, "active-account"), "utf8");
    expect(active.trim()).toBe("alice@example.com");
  });
});


describe("runCli exec", () => {
  /** Stub RunTool that records calls + returns a fixed payload. */
  function makeStubRunTool(payload: unknown = { ok: true }) {
    const calls: Array<{
      toolName: string;
      args: Record<string, unknown>;
      opts?: { raw?: boolean };
    }> = [];
    const fn = async (
      toolName: string,
      args: Record<string, unknown>,
      opts?: { raw?: boolean },
    ) => {
      calls.push({ toolName, args, opts });
      return payload;
    };
    return { runTool: fn, calls };
  }

  test("no tool name → usage + lists implemented tools", async () => {
    const { io } = captureIO();
    const { runTool } = makeStubRunTool();
    await expect(runCli(["exec"], io, { runTool })).rejects.toThrow(
      /usage: safespace exec/,
    );
    await expect(runCli(["exec"], io, { runTool })).rejects.toThrow(
      /gmail_search/,
    );
  });

  test("unknown tool → CliError naming it + listing valid tools", async () => {
    const { io } = captureIO();
    const { runTool } = makeStubRunTool();
    await expect(
      runCli(["exec", "bogus_tool"], io, { runTool }),
    ).rejects.toThrow(/unknown tool: bogus_tool/);
    await expect(
      runCli(["exec", "bogus_tool"], io, { runTool }),
    ).rejects.toThrow(/gmail_search/);
  });

  test("missing --params → CliError", async () => {
    const { io } = captureIO();
    const { runTool } = makeStubRunTool();
    await expect(
      runCli(["exec", "gmail_search"], io, { runTool }),
    ).rejects.toThrow(/--params <json> is required/);
  });

  test("--params malformed JSON → CliError mentioning parse error", async () => {
    const { io } = captureIO();
    const { runTool } = makeStubRunTool();
    await expect(
      runCli(
        ["exec", "gmail_search", "--params", "not{json"],
        io,
        { runTool },
      ),
    ).rejects.toThrow(/parse error/);
  });

  test("--params is not an object (array) → CliError", async () => {
    const { io } = captureIO();
    const { runTool } = makeStubRunTool();
    await expect(
      runCli(
        ["exec", "gmail_search", "--params", "[1,2,3]"],
        io,
        { runTool },
      ),
    ).rejects.toThrow(/must be a JSON object/);
  });

  test("--params is null → CliError", async () => {
    const { io } = captureIO();
    const { runTool } = makeStubRunTool();
    await expect(
      runCli(
        ["exec", "gmail_search", "--params", "null"],
        io,
        { runTool },
      ),
    ).rejects.toThrow(/must be a JSON object/);
  });

  test("--account invalid email → CliError", async () => {
    const { io } = captureIO();
    const { runTool } = makeStubRunTool();
    await expect(
      runCli(
        [
          "exec", "gmail_search",
          "--account", "not-an-email",
          "--params", '{"query":"newer_than:1d"}',
        ],
        io,
        { runTool },
      ),
    ).rejects.toThrow(/--account must be a valid email/);
  });

  test("account_id inside --params → CliError telling user to use --account", async () => {
    const { io } = captureIO();
    const { runTool } = makeStubRunTool();
    await expect(
      runCli(
        [
          "exec", "gmail_search",
          "--params", '{"query":"x","account_id":"a@b.com"}',
        ],
        io,
        { runTool },
      ),
    ).rejects.toThrow(/use the --account flag/);
  });

  test("unknown flag → CliError naming it", async () => {
    const { io } = captureIO();
    const { runTool } = makeStubRunTool();
    await expect(
      runCli(
        ["exec", "gmail_search", "--bogus", "x", "--params", "{}"],
        io,
        { runTool },
      ),
    ).rejects.toThrow(/unknown flag: --bogus/);
  });

  test("happy path: forwards params to runTool, prints JSON to stdout", async () => {
    const payload = {
      messages: [{ id: "m1", threadId: "t1" }],
      resultSizeEstimate: 1,
    };
    const { io, out } = captureIO();
    const { runTool, calls } = makeStubRunTool(payload);
    await runCli(
      [
        "exec", "gmail_search",
        "--params", '{"query":"newer_than:1d","max_results":50}',
      ],
      io,
      { runTool },
    );
    expect(calls).toHaveLength(1);
    expect(calls[0]!.toolName).toBe("gmail_search");
    expect(calls[0]!.args).toEqual({
      query: "newer_than:1d",
      max_results: 50,
    });
    expect(out).toHaveLength(1);
    expect(JSON.parse(out[0]!)).toEqual(payload);
  });

  test("--account flag is forwarded as account_id in args", async () => {
    const { io } = captureIO();
    const { runTool, calls } = makeStubRunTool({ ok: true });
    await runCli(
      [
        "exec", "gmail_search",
        "--account", "alice@example.com",
        "--params", '{"query":"x"}',
      ],
      io,
      { runTool },
    );
    expect(calls[0]!.args).toEqual({
      query: "x",
      account_id: "alice@example.com",
    });
  });

  test("no --account → args contain no account_id (handler middleware resolves)", async () => {
    const { io } = captureIO();
    const { runTool, calls } = makeStubRunTool({ ok: true });
    await runCli(
      ["exec", "gmail_search", "--params", '{"query":"x"}'],
      io,
      { runTool },
    );
    expect(calls[0]!.args).toEqual({ query: "x" });
    expect(calls[0]!.args.account_id).toBeUndefined();
  });

  test("handler throws → bubbles up (not swallowed)", async () => {
    const { io } = captureIO();
    const runTool = async () => {
      throw new Error("upstream 500");
    };
    await expect(
      runCli(
        ["exec", "gmail_search", "--params", '{"query":"x"}'],
        io,
        { runTool },
      ),
    ).rejects.toThrow(/upstream 500/);
  });

  test("flag order independent: --params before --account", async () => {
    const { io } = captureIO();
    const { runTool, calls } = makeStubRunTool({ ok: true });
    await runCli(
      [
        "exec", "gmail_search",
        "--params", '{"query":"x"}',
        "--account", "alice@example.com",
      ],
      io,
      { runTool },
    );
    expect(calls[0]!.args).toEqual({
      query: "x",
      account_id: "alice@example.com",
    });
  });

  test("--params empty string → same 'is required' message (not parse error)", async () => {
    const { io } = captureIO();
    const { runTool } = makeStubRunTool();
    await expect(
      runCli(["exec", "gmail_search", "--params", ""], io, { runTool }),
    ).rejects.toThrow(/--params <json> is required/);
  });

  test("result with BigInt → CliError 'result serialization failed' (not raw TypeError)", async () => {
    const { io } = captureIO();
    const runTool = async () => ({ count: 12345n });
    await expect(
      runCli(
        ["exec", "gmail_search", "--params", '{"query":"x"}'],
        io,
        { runTool },
      ),
    ).rejects.toThrow(/result serialization failed/);
  });

  test("result with circular reference → CliError 'result serialization failed'", async () => {
    const { io } = captureIO();
    const runTool = async () => {
      const cyc: Record<string, unknown> = { a: 1 };
      cyc.self = cyc;
      return cyc;
    };
    await expect(
      runCli(
        ["exec", "gmail_search", "--params", '{"query":"x"}'],
        io,
        { runTool },
      ),
    ).rejects.toThrow(/result serialization failed/);
  });

  // ── --raw flag ───────────────────────────────────────────────────────

  test("default (no --raw) → opts.raw is false (sanitize applied)", async () => {
    const { io } = captureIO();
    const { runTool, calls } = makeStubRunTool({ ok: true });
    await runCli(
      ["exec", "gmail_search", "--params", '{"query":"x"}'],
      io,
      { runTool },
    );
    expect(calls[0]!.opts?.raw).toBe(false);
  });

  test("--raw flag → opts.raw is true (sanitize bypassed)", async () => {
    const { io } = captureIO();
    const { runTool, calls } = makeStubRunTool({ ok: true });
    await runCli(
      ["exec", "gmail_search", "--raw", "--params", '{"query":"x"}'],
      io,
      { runTool },
    );
    expect(calls[0]!.opts?.raw).toBe(true);
  });

  test("--raw emits a loud stderr warning before the tool call", async () => {
    const { io, err } = captureIO();
    const { runTool } = makeStubRunTool({ ok: true });
    await runCli(
      ["exec", "gmail_search", "--raw", "--params", '{"query":"x"}'],
      io,
      { runTool },
    );
    const warning = err.find((l) => l.includes("--raw bypasses"));
    expect(warning).toBeDefined();
    expect(warning).toMatch(/Only safe when the caller is NOT an LLM/);
    expect(warning).toMatch(/sanitize=bypassed/);
  });

  test("no --raw → no stderr warning", async () => {
    const { io, err } = captureIO();
    const { runTool } = makeStubRunTool({ ok: true });
    await runCli(
      ["exec", "gmail_search", "--params", '{"query":"x"}'],
      io,
      { runTool },
    );
    expect(err.filter((l) => l.includes("--raw"))).toHaveLength(0);
  });

  test("--raw works alongside --account", async () => {
    const { io } = captureIO();
    const { runTool, calls } = makeStubRunTool({ ok: true });
    await runCli(
      [
        "exec", "gmail_search",
        "--raw",
        "--account", "alice@example.com",
        "--params", '{"query":"x"}',
      ],
      io,
      { runTool },
    );
    expect(calls[0]!.opts?.raw).toBe(true);
    expect(calls[0]!.args).toEqual({
      query: "x",
      account_id: "alice@example.com",
    });
  });

  test("--raw flag-order independent (after --params)", async () => {
    const { io } = captureIO();
    const { runTool, calls } = makeStubRunTool({ ok: true });
    await runCli(
      ["exec", "gmail_search", "--params", '{"query":"x"}', "--raw"],
      io,
      { runTool },
    );
    expect(calls[0]!.opts?.raw).toBe(true);
  });
});

describe("runCli exec — routes like the server (non-OAuth, cross-account)", () => {
  // Pinned so a developer shell cannot change which gate answers; the file backend
  // keeps the service-token case off the real Keychain.
  const PINNED = [
    "SAFESPACE_FS_READ_ROOTS",
    "SAFESPACE_FS_READ_ROOTS_EXTRA",
    "SAFESPACE_AUTONOMOUS",
    "SAFESPACE_WEBFETCH_ALLOW",
    "SAFESPACE_WEBFETCH_ALLOW_EXTRA",
    "SAFESPACE_TELEGRAM_BOT_TOKEN",
    "SAFESPACE_SECRET_BACKEND",
    "SAFESPACE_SECRET_PASSPHRASE",
  ];
  const saved: Record<string, string | undefined> = {};
  beforeEach(() => {
    for (const k of PINNED) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
    process.env.SAFESPACE_SECRET_BACKEND = "file";
    __resetChainState(); // this test's config dir starts its own chain
    __resetServiceTokenBackendForTests();
  });
  afterEach(() => {
    for (const k of PINNED) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    __resetChainState();
    __resetServiceTokenBackendForTests();
  });

  /** The non-OAuth choke point writes its row without awaiting it: wait for the queued
   *  write (it is queued before the refusal propagates), then read the CLI chain file. */
  async function auditRows(): Promise<Array<Record<string, unknown>>> {
    await __drainAuditWrites();
    try {
      const text = await fs.readFile(path.join(tmpDir, "audit-cli.jsonl"), "utf8");
      return text.split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l));
    } catch {
      return [];
    }
  }

  test("web_fetch reaches the non-OAuth choke point: its own refusal + an audit row", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["exec", "web_fetch", "--params", JSON.stringify({ url: "http://127.0.0.1/" })], io),
    ).rejects.toThrow(/url_blocked_by_policy/);
    const rows = await auditRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ tool: "web_fetch", source: "web-fetch", status: "error" });
  });

  test("fs_read reaches the non-OAuth choke point: its own refusal + an audit row", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["exec", "fs_read", "--params", JSON.stringify({ path: "/etc/hosts" })], io),
    ).rejects.toThrow(/path_blocked_by_policy/);
    const rows = await auditRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ tool: "fs_read", source: "fs-read", status: "error" });
  });

  test("a cross-account tool fans out via withAllAccounts and writes its aggregate row", async () => {
    const { io, out } = captureIO();
    await runCli(["exec", "gmail_search_all", "--params", JSON.stringify({ query: "x" })], io);
    expect(JSON.parse(out.join("\n"))).toEqual({ successes: [], failures: [] });
    const rows = await auditRows();
    expect(rows.some((r) => r.tool === "gmail_search_all" && r.event === "cross_account_aggregate")).toBe(true);
  });

  test("a service-token tool reaches its choke point: no_token + an audit row", async () => {
    const { io } = captureIO();
    const err = await runCli(
      ["exec", "telegram_send_message", "--params", JSON.stringify({ chat_id: "1", text: "x" })],
      io,
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(MCPError);
    expect((err as MCPError).errorName).toBe("telegram_api_failed");
    expect((err as MCPError).errorData).toMatchObject({ reason: "no_token" });
    const rows = await auditRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ tool: "telegram_send_message", source: "telegram", status: "error" });
  });

  test("--raw and --account are refused outside single-account OAuth tools", async () => {
    const { io, err } = captureIO();
    await expect(
      runCli(["exec", "web_fetch", "--raw", "--params", JSON.stringify({ url: "https://example.com/" })], io),
    ).rejects.toThrow(/--raw applies only to single-account OAuth tools/);
    await expect(
      runCli(["exec", "gmail_search_all", "--account", "a@example.com", "--params", "{}"], io),
    ).rejects.toThrow(/--account applies only to single-account OAuth tools; gmail_search_all is a cross-account tool/);
    expect(err).toEqual([]); // refused before the --raw warning
  });

  test("a failing exec still lands its audit row before the process exits", async () => {
    const proc = Bun.spawn(
      [process.execPath, path.join(import.meta.dir, "cli.ts"), "exec", "web_fetch", "--params", JSON.stringify({ url: "http://127.0.0.1/" })],
      { env: { ...process.env, SAFESPACE_CONFIG_DIR: tmpDir }, stdout: "pipe", stderr: "pipe" },
    );
    expect(await proc.exited).toBe(1);
    const text = await fs.readFile(path.join(tmpDir, "audit-cli.jsonl"), "utf8");
    expect(text).toContain('"tool":"web_fetch"');
  });
});

describe("runCli doctor --posture (hardening posture)", () => {
  const POSTURE_VARS = ["SAFESPACE_AUTONOMOUS", "SAFESPACE_SECRET_BACKEND", "SAFESPACE_REQUIRE_SEND_APPROVAL"];
  let prevExitCode: number;
  beforeEach(() => {
    // Bun ignores `process.exitCode = undefined`, so restoring an unset code must
    // write 0 — otherwise the failing-gate test below leaks exit 1 into the run.
    prevExitCode = (process.exitCode as number | undefined) ?? 0;
  });
  afterEach(async () => {
    for (const v of POSTURE_VARS) delete process.env[v];
    process.exitCode = prevExitCode;
    // --posture's egress section loads (with the autonomous flag baked in) the
    // cached allowlist singletons — reset so a stale cache can't leak into another
    // test file (e.g. a tasks-delete state built under autonomous=true).
    for (const m of ["recipient-allowlist", "tasks-delete-targets", "youtube-comment-targets", "github-write-targets", "github-merge-targets", "fs-gate"]) {
      (await import(`./policy/${m}`)).__internal.resetSingletons();
    }
  });

  test("routes to the posture report (the three hardening settings)", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    process.env.SAFESPACE_SECRET_BACKEND = "keychain";
    const { io, out } = captureIO();
    await runCli(["doctor", "--posture"], io);
    const joined = out.join("\n");
    expect(joined).not.toContain("enforced_mode");
    expect(joined).toContain("autonomous_mode");
    expect(joined).toContain("send_approval");
    expect(joined).toContain("token_at_rest");
    expect(joined).toContain("SOLE-EGRESS.md"); // the external-layers note
  });

  test("--posture --json emits one JSON line with external_layers", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    process.env.SAFESPACE_SECRET_BACKEND = "keychain";
    process.env.SAFESPACE_REQUIRE_SEND_APPROVAL = "true";
    const { io, out } = captureIO();
    await runCli(["doctor", "--posture", "--json"], io);
    expect(out.length).toBe(1);
    const parsed = JSON.parse(out[0]!);
    expect(parsed.status).toBe("ok");
    expect(parsed.external_layers).toContain("SOLE-EGRESS.md");
  });

  test("a setting that is off under --posture sets a non-zero exit code", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    process.env.SAFESPACE_SECRET_BACKEND = "file"; // KEY-FILE mode → token_at_rest fail
    process.env.SAFESPACE_REQUIRE_SEND_APPROVAL = "true";
    const { io, out } = captureIO();
    await runCli(["doctor", "--posture"], io);
    expect(out.join("\n")).toContain("[FAIL] token_at_rest");
    expect(process.exitCode).toBe(1);
  });

  test("a fully hardened posture leaves the exit code at 0", async () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    process.env.SAFESPACE_SECRET_BACKEND = "keychain";
    process.env.SAFESPACE_REQUIRE_SEND_APPROVAL = "true";
    process.exitCode = 0;
    const { io } = captureIO();
    await runCli(["doctor", "--posture"], io);
    expect(process.exitCode).toBe(0);
  });

  test("an unknown doctor flag still errors (usage lists --posture)", async () => {
    const { io } = captureIO();
    await expect(runCli(["doctor", "--bogus"], io)).rejects.toThrow(/--posture/);
  });
});
