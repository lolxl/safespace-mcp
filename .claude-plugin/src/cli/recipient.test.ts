import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { saveIndex } from "../auth/keychain";
import { runCli, type CliIO } from "../cli";
import {
  ENV_ALLOW,
  ENV_ALLOW_EXTRA,
  buildAllowlistState,
  isRecipientAllowed,
  parseAllowlistTokens,
} from "../policy/recipient-allowlist";
import { readEnvKey } from "./atomic-env";

let tmp: string;
let prevConfigDir: string | undefined;
let prevAllow: string | undefined;
let prevExtra: string | undefined;

beforeEach(async () => {
  prevConfigDir = process.env.SAFESPACE_CONFIG_DIR;
  prevAllow = process.env[ENV_ALLOW];
  prevExtra = process.env[ENV_ALLOW_EXTRA];
  tmp = await fs.mkdtemp(path.join(tmpdir(), "rcp-cli-"));
  process.env.SAFESPACE_CONFIG_DIR = tmp;
  delete process.env[ENV_ALLOW];
  delete process.env[ENV_ALLOW_EXTRA];
});

afterEach(async () => {
  if (prevConfigDir === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevConfigDir;
  if (prevAllow === undefined) delete process.env[ENV_ALLOW];
  else process.env[ENV_ALLOW] = prevAllow;
  if (prevExtra === undefined) delete process.env[ENV_ALLOW_EXTRA];
  else process.env[ENV_ALLOW_EXTRA] = prevExtra;
  await fs.rm(tmp, { recursive: true, force: true });
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

function envPath(): string {
  return path.join(tmp, ".env");
}

async function planAccounts(emails: string[]): Promise<void> {
  await saveIndex({
    version: 1,
    accounts: emails.map((email) => ({
      email,
      scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
      added_at: "2026-05-01T00:00:00.000Z",
      last_used_at: null,
    })),
  });
}

describe("recipient list", () => {
  test("no .env → policy-off message", async () => {
    const { io, out } = captureIO();
    await runCli(["recipient", "list"], io);
    expect(out.join("\n")).toContain("policy OFF");
  });

  test("empty value → default-deny baseline", async () => {
    await fs.writeFile(envPath(), `${ENV_ALLOW}=\n`);
    const { io, out } = captureIO();
    await runCli(["recipient", "list"], io);
    expect(out.join("\n")).toContain("default-deny");
  });

  test("populated → lists entries", async () => {
    await fs.writeFile(envPath(), `${ENV_ALLOW}=alice@example.com,@partner.com\n`);
    const { io, out } = captureIO();
    await runCli(["recipient", "list"], io);
    const text = out.join("\n");
    expect(text).toContain("2 entries");
    expect(text).toContain("alice@example.com");
    expect(text).toContain("@partner.com");
  });

  test("self-implicit shown from accounts.json", async () => {
    await planAccounts(["me@gmail.com", "work@example.com"]);
    const { io, out } = captureIO();
    await runCli(["recipient", "list"], io);
    const text = out.join("\n");
    expect(text).toContain("self-send implicit: 2 account emails");
    expect(text).toContain("me@gmail.com");
    expect(text).toContain("work@example.com");
  });

  test("EXTRA from process.env shows as 'current shell only'", async () => {
    process.env[ENV_ALLOW_EXTRA] = "session@x.com";
    const { io, out } = captureIO();
    await runCli(["recipient", "list"], io);
    expect(out.join("\n")).toContain("current shell only");
    expect(out.join("\n")).toContain("session@x.com");
  });

  test("warns about unparseable .env tokens (no plaintext echo)", async () => {
    await fs.writeFile(envPath(), `${ENV_ALLOW}=alice@example.com,bare-domain.com\n`);
    const { io, err, out } = captureIO();
    await runCli(["recipient", "list"], io);
    expect(err.join("\n")).toMatch(/1 unparseable token/);
    expect(err.join("\n")).not.toContain("bare-domain.com");
    expect(out.join("\n")).not.toContain("bare-domain.com");
  });

  test("rejects extra args", async () => {
    const { io } = captureIO();
    await expect(runCli(["recipient", "list", "extra"], io)).rejects.toThrow(/unexpected argument/);
  });
});

describe("recipient add", () => {
  test("creates .env with mode 0o600 when absent", async () => {
    const { io, out } = captureIO();
    await runCli(["recipient", "add", "alice@example.com"], io);
    const stat = await fs.stat(envPath());
    expect(stat.mode & 0o777).toBe(0o600);
    const content = await fs.readFile(envPath(), "utf8");
    expect(content).toBe(`${ENV_ALLOW}=alice@example.com\n`);
    expect(out.join("\n")).toContain("added 1 entry");
  });

  test("appends to existing list (preserves other keys)", async () => {
    await fs.writeFile(
      envPath(),
      `SAFESPACE_TIER=share\n${ENV_ALLOW}=alice@example.com\n# comment\n`,
    );
    await runCli(["recipient", "add", "bob@example.com", "@partner.com"], captureIO().io);
    const content = await fs.readFile(envPath(), "utf8");
    expect(content).toBe(
      `SAFESPACE_TIER=share\n${ENV_ALLOW}=alice@example.com,bob@example.com,@partner.com\n# comment\n`,
    );
  });

  test("dedup: all tokens already present → no-op + stderr warn", async () => {
    await fs.writeFile(envPath(), `${ENV_ALLOW}=alice@example.com,@partner.com\n`);
    const { io, err } = captureIO();
    await runCli(["recipient", "add", "alice@example.com", "@partner.com"], io);
    expect(err.join("\n")).toMatch(/already in /);
    const content = await fs.readFile(envPath(), "utf8");
    expect(content).toBe(`${ENV_ALLOW}=alice@example.com,@partner.com\n`);
  });

  test("dedup: partial overlap → adds new, skips existing", async () => {
    await fs.writeFile(envPath(), `${ENV_ALLOW}=alice@example.com\n`);
    const { io, out } = captureIO();
    await runCli(["recipient", "add", "alice@example.com", "bob@example.com"], io);
    expect(out.join("\n")).toContain("1 already-present skipped");
    const content = await fs.readFile(envPath(), "utf8");
    expect(content).toBe(`${ENV_ALLOW}=alice@example.com,bob@example.com\n`);
  });

  test("rejects bare-domain token (must use @domain.tld)", async () => {
    const { io } = captureIO();
    await expect(runCli(["recipient", "add", "bare-domain.com"], io)).rejects.toThrow(
      /invalid recipient token/,
    );
  });

  test("rejects mixed valid/invalid tokens atomically", async () => {
    const { io } = captureIO();
    await expect(
      runCli(["recipient", "add", "alice@example.com", "bare-domain.com"], io),
    ).rejects.toThrow(/invalid recipient token/);
    try {
      await fs.stat(envPath());
      throw new Error("file should not exist");
    } catch (e) {
      expect((e as NodeJS.ErrnoException).code).toBe("ENOENT");
    }
  });

  test("requires at least one arg", async () => {
    const { io } = captureIO();
    await expect(runCli(["recipient", "add"], io)).rejects.toThrow(/usage:/);
  });

  test("domain comparison is case-insensitive for dedup", async () => {
    await fs.writeFile(envPath(), `${ENV_ALLOW}=@partner.com\n`);
    const { io, err } = captureIO();
    await runCli(["recipient", "add", "@PARTNER.COM"], io);
    expect(err.join("\n")).toMatch(/already in /);
  });
});

describe("recipient remove", () => {
  test("removes existing entry", async () => {
    await fs.writeFile(envPath(), `${ENV_ALLOW}=alice@example.com,bob@example.com\n`);
    const { io, out } = captureIO();
    await runCli(["recipient", "remove", "alice@example.com"], io);
    const content = await fs.readFile(envPath(), "utf8");
    expect(content).toBe(`${ENV_ALLOW}=bob@example.com\n`);
    expect(out.join("\n")).toContain("removed 1 entry");
  });

  test("not-found → CliError", async () => {
    await fs.writeFile(envPath(), `${ENV_ALLOW}=alice@example.com\n`);
    const { io } = captureIO();
    await expect(runCli(["recipient", "remove", "bob@example.com"], io)).rejects.toThrow(
      /no matching entries/,
    );
  });

  test("ENV_ALLOW unset → CliError", async () => {
    const { io } = captureIO();
    await expect(runCli(["recipient", "remove", "alice@example.com"], io)).rejects.toThrow(
      /is not set in \.env/,
    );
  });

  test("removing last entry leaves empty default-deny baseline", async () => {
    await fs.writeFile(envPath(), `${ENV_ALLOW}=alice@example.com\n`);
    const { io, out } = captureIO();
    await runCli(["recipient", "remove", "alice@example.com"], io);
    const content = await fs.readFile(envPath(), "utf8");
    expect(content).toBe(`${ENV_ALLOW}=\n`);
    expect(out.join("\n")).toContain("default-deny");
  });

  test("rejects invalid token", async () => {
    await fs.writeFile(envPath(), `${ENV_ALLOW}=alice@example.com\n`);
    const { io } = captureIO();
    await expect(runCli(["recipient", "remove", "bare-domain.com"], io)).rejects.toThrow(
      /invalid recipient token/,
    );
  });

  test("partial match: warns about not-present tokens but proceeds", async () => {
    await fs.writeFile(envPath(), `${ENV_ALLOW}=alice@example.com,bob@example.com\n`);
    const { io, err } = captureIO();
    await runCli(["recipient", "remove", "alice@example.com", "ghost@example.com"], io);
    expect(err.join("\n")).toMatch(/not present/);
    const content = await fs.readFile(envPath(), "utf8");
    expect(content).toBe(`${ENV_ALLOW}=bob@example.com\n`);
  });
});

describe("recipient usage", () => {
  test("no subcommand → CliError with usage", async () => {
    const { io } = captureIO();
    await expect(runCli(["recipient"], io)).rejects.toThrow(/usage: safespace recipient/);
  });

  test("unknown subcommand", async () => {
    const { io } = captureIO();
    await expect(runCli(["recipient", "purge"], io)).rejects.toThrow(/unknown recipient subcommand/);
  });

  test("duplicate ALLOW lines in .env → write refuses", async () => {
    await fs.writeFile(envPath(), `${ENV_ALLOW}=a@x.com\n${ENV_ALLOW}=b@x.com\n`);
    const { io } = captureIO();
    await expect(runCli(["recipient", "add", "c@x.com"], io)).rejects.toThrow(/duplicate_key/);
  });
});

// v1.9 #4 — CLI ↔ policy round-trip integration. Locks the shape contract
// between the CLI's serialized .env value and the policy module's parser
// (parseAllowlistTokens + buildAllowlistState + isRecipientAllowed).
//
// A future refactor that diverges (e.g., CLI starts URL-encoding values,
// or parser stops accepting bare-@domain form) would break here.
describe("recipient CLI ↔ policy round-trip", () => {
  test("CLI add → readEnvKey + parseAllowlistTokens reproduces structured entries", async () => {
    await runCli(
      ["recipient", "add", "alice@example.com", "@partner.com", "bob@example.com"],
      captureIO().io,
    );

    const raw = await readEnvKey(envPath(), ENV_ALLOW);
    expect(raw).toBe("alice@example.com,@partner.com,bob@example.com");

    const parsed = parseAllowlistTokens(raw);
    expect(parsed.rejected).toEqual([]);
    expect(parsed.ok).toHaveLength(3);
    expect(parsed.ok[0]).toEqual({
      kind: "email",
      localpart: "alice",
      domain: "example.com",
    });
    expect(parsed.ok[1]).toEqual({ kind: "domain", domain: "partner.com" });
    expect(parsed.ok[2]).toEqual({
      kind: "email",
      localpart: "bob",
      domain: "example.com",
    });
  });

  test("CLI add → buildAllowlistState + isRecipientAllowed enforces correctly", async () => {
    await runCli(
      ["recipient", "add", "alice@example.com", "@partner.com"],
      captureIO().io,
    );

    const raw = await readEnvKey(envPath(), ENV_ALLOW);
    expect(raw).toBeDefined();

    // Simulate what the proxy does at startup: build state from the .env
    // value (no shell EXTRA, no self emails).
    const state = buildAllowlistState(raw, undefined, new Set());
    expect(state.kind).toBe("active");

    // The exact email matches.
    expect(isRecipientAllowed("alice@example.com", state)).toBe(true);
    // Domain-pattern matches any localpart.
    expect(isRecipientAllowed("anyone@partner.com", state)).toBe(true);
    expect(isRecipientAllowed("BOB@partner.com", state)).toBe(true);
    // Not in allowlist — rejected.
    expect(isRecipientAllowed("eve@evil.com", state)).toBe(false);
    // Localpart-sensitive: bob@example.com is NOT in (only alice@example.com).
    expect(isRecipientAllowed("bob@example.com", state)).toBe(false);
  });

  test("CLI remove last entry → empty baseline preserves active default-deny state", async () => {
    await runCli(["recipient", "add", "alice@example.com"], captureIO().io);
    await runCli(["recipient", "remove", "alice@example.com"], captureIO().io);

    const raw = await readEnvKey(envPath(), ENV_ALLOW);
    expect(raw).toBe(""); // empty string baseline, not undefined

    // empty string → buildAllowlistState returns kind=active with no entries.
    // This is the v2.2 spec: empty != unset; unset = off, empty = default-deny.
    const state = buildAllowlistState(raw, undefined, new Set());
    expect(state.kind).toBe("active");
    if (state.kind !== "active") return;
    expect(state.allow).toEqual([]);
    expect(isRecipientAllowed("eve@evil.com", state)).toBe(false);
  });

  test("CLI add does not produce values the parser rejects (canary)", async () => {
    // Throw a mix of valid token shapes at the CLI; the resulting .env
    // value must round-trip with zero rejections from parseAllowlistTokens.
    await runCli(
      [
        "recipient",
        "add",
        "alice@example.com",
        "@a-domain-with-hyphens.com",
        "first.last+filter@subdomain.example.co.uk",
      ],
      captureIO().io,
    );

    const raw = await readEnvKey(envPath(), ENV_ALLOW);
    const parsed = parseAllowlistTokens(raw);
    expect(parsed.rejected).toEqual([]);
    expect(parsed.ok).toHaveLength(3);
  });

  test("self-implicit emails are honored when buildAllowlistState gets the state from .env+accounts", async () => {
    await planAccounts(["me@gmail.com"]);
    await runCli(["recipient", "add", "alice@example.com"], captureIO().io);

    const raw = await readEnvKey(envPath(), ENV_ALLOW);
    const state = buildAllowlistState(raw, undefined, new Set(["me@gmail.com"]));

    expect(isRecipientAllowed("me@gmail.com", state)).toBe(true); // self-implicit
    expect(isRecipientAllowed("alice@example.com", state)).toBe(true); // ALLOW
    expect(isRecipientAllowed("other@example.com", state)).toBe(false); // not in ALLOW or self
  });
});

