import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { migrateV2, MigrationError } from "./migrate";

// Each test gets its own tmp parent dir representing ${CLAUDE_PLUGIN_DATA}.
let parent: string;

beforeEach(async () => {
  parent = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-migrate-"));
});

afterEach(async () => {
  await fs.rm(parent, { recursive: true, force: true });
});

// ----- fixtures -----

const ENTRY_ALICE = {
  email: "alice@example.com",
  scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
  added_at: "2026-05-01T00:00:00.000Z",
  last_used_at: null as string | null,
};

const ENTRY_ALICE_SEND = {
  email: "alice@example.com",
  scopes: [
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/drive",
  ],
  added_at: "2026-05-02T00:00:00.000Z",
  last_used_at: "2026-05-10T12:00:00.000Z",
};

const ENTRY_BOB = {
  email: "bob@example.com",
  scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
  added_at: "2026-05-03T00:00:00.000Z",
  last_used_at: null,
};

async function setupProfile(
  name: "safespace-read" | "safespace-send",
  opts: {
    accounts?: object;
    auditLines?: string[];
    salt?: Buffer;
    env?: string;
    auditMtimeMs?: number;
  },
): Promise<void> {
  const dir = path.join(parent, name);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  if (opts.accounts) {
    await fs.writeFile(path.join(dir, "accounts.json"), JSON.stringify(opts.accounts), {
      mode: 0o600,
    });
  }
  if (opts.auditLines) {
    await fs.writeFile(path.join(dir, "audit.jsonl"), opts.auditLines.join("\n") + "\n", {
      mode: 0o600,
    });
    if (opts.auditMtimeMs !== undefined) {
      const secs = opts.auditMtimeMs / 1000;
      await fs.utimes(path.join(dir, "audit.jsonl"), secs, secs);
    } else {
      // Default: aged past the 60s threshold so tests don't trip H2.
      const old = (Date.now() - 5 * 60 * 1000) / 1000;
      await fs.utimes(path.join(dir, "audit.jsonl"), old, old);
    }
  }
  if (opts.salt) {
    await fs.writeFile(path.join(dir, "audit-salt"), opts.salt, { mode: 0o600 });
  }
  if (opts.env) {
    await fs.writeFile(path.join(dir, ".env"), opts.env, { mode: 0o600 });
  }
}

// ----- tests -----

describe("migrateV2 — happy paths", () => {
  test("two sources, distinct accounts → merged into v2", async () => {
    await setupProfile("safespace-read", {
      accounts: { version: 1, accounts: [ENTRY_ALICE] },
      auditLines: ['{"ts":"2026-05-01T00:00:00.000Z","tool":"gmail_search","account":"alice@example.com"}'],
    });
    await setupProfile("safespace-send", {
      accounts: { version: 1, accounts: [ENTRY_BOB] },
      auditLines: ['{"ts":"2026-05-03T00:00:00.000Z","tool":"gmail_send","account":"bob@example.com"}'],
    });

    const report = await migrateV2({ parentDir: parent });

    expect(report.applied).toBe(true);
    expect(report.accountsMerged).toBe(2);
    expect(report.auditLinesMerged).toBe(2);
    expect(report.saltMismatch).toBe(false);
    expect(report.warnings).toEqual([]);

    const merged = JSON.parse(await fs.readFile(path.join(parent, "safespace", "accounts.json"), "utf8"));
    expect(merged.version).toBe(2);
    expect(merged.accounts).toHaveLength(2);
    const emails = merged.accounts.map((a: { email: string }) => a.email).sort();
    expect(emails).toEqual(["alice@example.com", "bob@example.com"]);
  });

  test("two sources, same email → deduped with union of scopes + earliest added + latest used", async () => {
    await setupProfile("safespace-read", {
      accounts: { version: 1, accounts: [ENTRY_ALICE] },
    });
    await setupProfile("safespace-send", {
      accounts: { version: 1, accounts: [ENTRY_ALICE_SEND] },
    });

    const report = await migrateV2({ parentDir: parent });
    expect(report.applied).toBe(true);
    expect(report.accountsMerged).toBe(1);

    const merged = JSON.parse(await fs.readFile(path.join(parent, "safespace", "accounts.json"), "utf8"));
    const alice = merged.accounts[0];
    expect(alice.email).toBe("alice@example.com");
    expect(alice.scopes).toEqual([
      "https://www.googleapis.com/auth/drive",
      "https://www.googleapis.com/auth/gmail.readonly",
      "https://www.googleapis.com/auth/gmail.send",
    ]);
    expect(alice.added_at).toBe("2026-05-01T00:00:00.000Z"); // earliest
    expect(alice.last_used_at).toBe("2026-05-10T12:00:00.000Z"); // latest (read's null bows to send's value)
  });

  test("single source (only read/) → migrated", async () => {
    await setupProfile("safespace-read", {
      accounts: { version: 1, accounts: [ENTRY_ALICE] },
    });

    const report = await migrateV2({ parentDir: parent });
    expect(report.applied).toBe(true);
    expect(report.sources).toEqual({ read: true, send: false });
    expect(report.accountsMerged).toBe(1);
  });
});

describe("migrateV2 — audit merge (H1: no sort, boundary line)", () => {
  test("preserves per-source append order + emits migration_boundary records", async () => {
    await setupProfile("safespace-read", {
      auditLines: [
        '{"ts":"2026-05-10T00:00:00.000Z","tool":"gmail_search","account":"alice@example.com"}',
        '{"ts":"2026-05-01T00:00:00.000Z","tool":"gmail_search","account":"alice@example.com"}', // out of order on purpose
      ],
    });
    await setupProfile("safespace-send", {
      auditLines: [
        '{"ts":"2026-05-05T00:00:00.000Z","tool":"gmail_send","account":"bob@example.com"}',
      ],
    });

    await migrateV2({ parentDir: parent });

    const merged = await fs.readFile(path.join(parent, "safespace", "audit.jsonl"), "utf8");
    const lines = merged.split("\n").filter((l) => l.length > 0);

    // Expected structure: boundary(read), read line 1, read line 2, boundary(send), send line 1
    expect(lines).toHaveLength(5);
    const boundary0 = JSON.parse(lines[0]!);
    expect(boundary0.event).toBe("migration_boundary");
    expect(boundary0.source).toBe("safespace-read");
    const read1 = JSON.parse(lines[1]!);
    expect(read1.ts).toBe("2026-05-10T00:00:00.000Z"); // first source line, NOT sorted
    const read2 = JSON.parse(lines[2]!);
    expect(read2.ts).toBe("2026-05-01T00:00:00.000Z"); // append order preserved (older AFTER newer)
    const boundary3 = JSON.parse(lines[3]!);
    expect(boundary3.event).toBe("migration_boundary");
    expect(boundary3.source).toBe("safespace-send");
    const send1 = JSON.parse(lines[4]!);
    expect(send1.ts).toBe("2026-05-05T00:00:00.000Z");
  });
});

describe("migrateV2 — refusals", () => {
  test("no source dirs → MigrationError", async () => {
    await expect(migrateV2({ parentDir: parent })).rejects.toThrow(/nothing to migrate/);
  });

  test("target already populated → MigrationError", async () => {
    await setupProfile("safespace-read", {
      accounts: { version: 1, accounts: [ENTRY_ALICE] },
    });
    await fs.mkdir(path.join(parent, "safespace"), { recursive: true, mode: 0o700 });
    await fs.writeFile(
      path.join(parent, "safespace", "accounts.json"),
      JSON.stringify({ version: 2, accounts: [ENTRY_ALICE] }),
      { mode: 0o600 },
    );

    await expect(migrateV2({ parentDir: parent })).rejects.toThrow(/already contains migrated data/);
  });

  test("recent audit.jsonl mtime (proxy live, H2) → MigrationError", async () => {
    await setupProfile("safespace-read", {
      accounts: { version: 1, accounts: [ENTRY_ALICE] },
      auditLines: ['{"ts":"2026-05-01T00:00:00.000Z","tool":"gmail_search","account":"alice@example.com"}'],
      auditMtimeMs: Date.now() - 10_000, // 10s ago, within 60s threshold
    });
    await expect(migrateV2({ parentDir: parent })).rejects.toThrow(/stop the safespace MCP server/);
  });

  test("salt mismatch without --force-salt-mismatch → MigrationError (H4)", async () => {
    await setupProfile("safespace-read", {
      accounts: { version: 1, accounts: [ENTRY_ALICE] },
      salt: crypto.randomBytes(32),
    });
    await setupProfile("safespace-send", {
      accounts: { version: 1, accounts: [ENTRY_BOB] },
      salt: crypto.randomBytes(32),
    });
    await expect(migrateV2({ parentDir: parent })).rejects.toThrow(/salts differ/);
  });
});

describe("migrateV2 — salt mismatch with --force-salt-mismatch", () => {
  test("proceeds + writes salt-mismatch.warning marker", async () => {
    await setupProfile("safespace-read", {
      accounts: { version: 1, accounts: [ENTRY_ALICE] },
      salt: crypto.randomBytes(32),
    });
    await setupProfile("safespace-send", {
      accounts: { version: 1, accounts: [ENTRY_BOB] },
      salt: crypto.randomBytes(32),
    });

    const report = await migrateV2({ parentDir: parent, forceSaltMismatch: true });

    expect(report.applied).toBe(true);
    expect(report.saltMismatch).toBe(true);
    expect(report.warnings.some((w) => w.includes("salt-mismatch"))).toBe(true);

    const marker = await fs.readFile(
      path.join(parent, "safespace", "salt-mismatch.warning"),
      "utf8",
    );
    expect(marker).toContain("audit salt mismatch");
    expect(marker).toContain("not comparable");
  });
});

describe("migrateV2 — dry-run", () => {
  test("dry-run returns plan without writing safespace/", async () => {
    await setupProfile("safespace-read", {
      accounts: { version: 1, accounts: [ENTRY_ALICE] },
      auditLines: ['{"ts":"2026-05-01T00:00:00.000Z","tool":"gmail_search","account":"alice@example.com"}'],
    });
    await setupProfile("safespace-send", {
      accounts: { version: 1, accounts: [ENTRY_BOB] },
      auditLines: ['{"ts":"2026-05-03T00:00:00.000Z","tool":"gmail_send","account":"bob@example.com"}'],
    });

    const report = await migrateV2({ parentDir: parent, dryRun: true });

    expect(report.dryRun).toBe(true);
    expect(report.applied).toBe(false);
    expect(report.accountsMerged).toBe(2);
    expect(report.auditLinesMerged).toBe(2);

    // safespace/ must NOT exist after dry-run.
    await expect(fs.access(path.join(parent, "safespace"))).rejects.toThrow();
    // Sources must NOT be renamed to .migrated/.
    await expect(fs.access(path.join(parent, "safespace-read.migrated"))).rejects.toThrow();
  });
});

describe("migrateV2 — stranded staging cleanup (H3)", () => {
  test("stranded safespace.tmp/ with plaintext .env is removed unconditionally before migration", async () => {
    // Plant a stranded staging dir as if a prior run was killed mid-write.
    const stranded = path.join(parent, "safespace.tmp");
    await fs.mkdir(stranded, { recursive: true, mode: 0o700 });
    await fs.writeFile(
      path.join(stranded, ".env"),
      "GOOGLE_CLIENT_SECRET=leaked-from-prior-run\n",
      { mode: 0o600 },
    );

    await setupProfile("safespace-read", {
      accounts: { version: 1, accounts: [ENTRY_ALICE] },
    });

    await migrateV2({ parentDir: parent });

    // After successful run, staging dir must be gone (renamed to safespace/).
    await expect(fs.access(stranded)).rejects.toThrow();
  });
});

describe("migrateV2 — lock", () => {
  test("active lock with live PID refuses second migration", async () => {
    await setupProfile("safespace-read", {
      accounts: { version: 1, accounts: [ENTRY_ALICE] },
    });
    // Plant a fresh lock with the current process's PID.
    await fs.writeFile(path.join(parent, ".migrate-v2.lock"), `${process.pid}\n`, {
      mode: 0o600,
    });
    await expect(migrateV2({ parentDir: parent })).rejects.toThrow(/migration already in progress/);
  });
});

describe("migrateV2 — source rename to .migrated/", () => {
  test("successful migration renames sources to .migrated/ (Q2 = no --rollback ships)", async () => {
    await setupProfile("safespace-read", {
      accounts: { version: 1, accounts: [ENTRY_ALICE] },
    });
    await setupProfile("safespace-send", {
      accounts: { version: 1, accounts: [ENTRY_BOB] },
    });

    await migrateV2({ parentDir: parent });

    // .migrated/ dirs exist (fs.access throws if missing).
    await fs.access(path.join(parent, "safespace-read.migrated"));
    await fs.access(path.join(parent, "safespace-send.migrated"));
    // Originals are gone.
    await expect(fs.access(path.join(parent, "safespace-read"))).rejects.toThrow();
    await expect(fs.access(path.join(parent, "safespace-send"))).rejects.toThrow();
  });
});

describe("migrateV2 — file permissions (C2)", () => {
  test("target dir is 0o700; all files (accounts/audit/env/salt) are 0o600", async () => {
    await setupProfile("safespace-send", {
      accounts: { version: 1, accounts: [ENTRY_ALICE] },
      auditLines: ['{"ts":"2026-05-01T00:00:00.000Z","tool":"gmail_send","account":"alice@example.com"}'],
      env: "GOOGLE_CLIENT_ID=test\nGOOGLE_CLIENT_SECRET=synthetic-secret\n",
      salt: crypto.randomBytes(32),
    });

    await migrateV2({ parentDir: parent });

    const safespace = path.join(parent, "safespace");
    expect((await fs.stat(safespace)).mode & 0o777).toBe(0o700);
    expect((await fs.stat(path.join(safespace, "accounts.json"))).mode & 0o777).toBe(0o600);
    expect((await fs.stat(path.join(safespace, "audit.jsonl"))).mode & 0o777).toBe(0o600);
    expect((await fs.stat(path.join(safespace, ".env"))).mode & 0o777).toBe(0o600);
    expect((await fs.stat(path.join(safespace, "audit-salt"))).mode & 0o777).toBe(0o600);
  });
});

describe("migrateV2 — active-account preservation (H-NEW-2 from self-review)", () => {
  test("copies active-account file from preferred source (send) into target", async () => {
    await setupProfile("safespace-send", {
      accounts: { version: 1, accounts: [ENTRY_ALICE] },
    });
    // Plant active-account file in send/ (prefer-send is the same policy as .env).
    await fs.writeFile(
      path.join(parent, "safespace-send", "active-account"),
      "alice@example.com\n",
      { mode: 0o600 },
    );

    await migrateV2({ parentDir: parent });

    const copied = await fs.readFile(path.join(parent, "safespace", "active-account"), "utf8");
    expect(copied).toBe("alice@example.com\n");
    expect((await fs.stat(path.join(parent, "safespace", "active-account"))).mode & 0o777).toBe(0o600);
  });

  test("falls back to read/active-account when send has none", async () => {
    await setupProfile("safespace-read", {
      accounts: { version: 1, accounts: [ENTRY_ALICE] },
    });
    await setupProfile("safespace-send", {
      accounts: { version: 1, accounts: [ENTRY_BOB] },
    });
    await fs.writeFile(
      path.join(parent, "safespace-read", "active-account"),
      "alice@example.com\n",
      { mode: 0o600 },
    );

    await migrateV2({ parentDir: parent });

    const copied = await fs.readFile(path.join(parent, "safespace", "active-account"), "utf8");
    expect(copied).toBe("alice@example.com\n");
  });

  test("missing active-account on both sources → no file in target (no error)", async () => {
    await setupProfile("safespace-read", {
      accounts: { version: 1, accounts: [ENTRY_ALICE] },
    });
    await migrateV2({ parentDir: parent });

    await expect(fs.access(path.join(parent, "safespace", "active-account"))).rejects.toThrow();
  });
});

describe("migrateV2 — secret leak guard (C1)", () => {
  test(".env content NEVER appears in MigrationError messages (canary)", async () => {
    // Setup a salt mismatch + .env with a unique canary secret. The salt
    // mismatch path is the most likely place a careless error message would
    // leak adjacent file content — assert the canary string never appears.
    await setupProfile("safespace-read", {
      accounts: { version: 1, accounts: [ENTRY_ALICE] },
      salt: crypto.randomBytes(32),
      env: "GOOGLE_CLIENT_ID=client-id-test-CANARY-A\nGOOGLE_CLIENT_SECRET=SECRET-CANARY-DO-NOT-LEAK\n",
    });
    await setupProfile("safespace-send", {
      accounts: { version: 1, accounts: [ENTRY_BOB] },
      salt: crypto.randomBytes(32),
      env: "GOOGLE_CLIENT_ID=client-id-test-CANARY-B\nGOOGLE_CLIENT_SECRET=SECRET-CANARY-DO-NOT-LEAK\n",
    });

    let caught: Error | null = null;
    try {
      await migrateV2({ parentDir: parent });
    } catch (e) {
      caught = e as Error;
    }
    expect(caught).toBeInstanceOf(MigrationError);
    expect(caught!.message).not.toContain("SECRET-CANARY-DO-NOT-LEAK");
    expect(caught!.message).not.toContain("CANARY-A");
    expect(caught!.message).not.toContain("CANARY-B");
  });
});

describe("migrateV2 — SAFESPACE_TIER auto-derivation from v1.x legacy .env flags", () => {
  // The proxy hard-fails on a v1.x .env carried through verbatim (legacy
  // flags without SAFESPACE_TIER). migrate-v2 derives the tier from those
  // flags + rewrites the .env so the user doesn't have to edit by hand.
  // Precedence in the helper (deriveTierFromLegacyEnv) is unit-tested in
  // tier.test.ts; these tests verify the wiring + .env-on-disk behavior.

  test("send .env with ENABLE_SEND=1 → writes SAFESPACE_TIER=write, comments flag", async () => {
    await setupProfile("safespace-read", {
      accounts: { version: 1, accounts: [ENTRY_ALICE] },
    });
    await setupProfile("safespace-send", {
      accounts: { version: 1, accounts: [ENTRY_BOB] },
      env: "GOOGLE_CLIENT_ID=cid-A\nGOOGLE_CLIENT_SECRET=sec-A\nSAFESPACE_ENABLE_SEND=1\n",
    });

    const report = await migrateV2({ parentDir: parent });

    expect(report.applied).toBe(true);
    expect(report.tierDerived).toEqual({
      derivedTier: "write",
      legacyFlagsFound: ["SAFESPACE_ENABLE_SEND"],
    });
    // Warning surfaces to user so they know what changed.
    expect(report.warnings.some((w) => /auto-derived SAFESPACE_TIER=write/.test(w))).toBe(true);

    const env = await fs.readFile(path.join(parent, "safespace", ".env"), "utf8");
    expect(env).toContain("GOOGLE_CLIENT_ID=cid-A");
    expect(env).toContain("GOOGLE_CLIENT_SECRET=sec-A");
    expect(env).toMatch(/^# .*SAFESPACE_ENABLE_SEND=1$/m);
    expect(env).not.toMatch(/^SAFESPACE_ENABLE_SEND=1$/m);
    expect(env).toMatch(/^SAFESPACE_TIER=write$/m);
  });

  test("ENABLE_DRIVE_SHARE=1 → SAFESPACE_TIER=share (highest precedence)", async () => {
    await setupProfile("safespace-send", {
      accounts: { version: 1, accounts: [ENTRY_BOB] },
      env: "GOOGLE_CLIENT_ID=cid\nSAFESPACE_ENABLE_SEND=1\nSAFESPACE_ENABLE_DRIVE_SHARE=1\n",
    });

    const report = await migrateV2({ parentDir: parent });

    expect(report.tierDerived?.derivedTier).toBe("share");
    const env = await fs.readFile(path.join(parent, "safespace", ".env"), "utf8");
    expect(env).toMatch(/^SAFESPACE_TIER=share$/m);
    expect(env).not.toMatch(/^SAFESPACE_ENABLE_DRIVE_SHARE=1$/m);
    expect(env).not.toMatch(/^SAFESPACE_ENABLE_SEND=1$/m);
  });

  test("explicit SAFESPACE_TIER already in .env → no derivation, content preserved", async () => {
    // User had a v2.0-style tier set manually + a leftover legacy flag.
    // Derivation must not override the explicit choice. Flag stays as-is
    // (user can clean it up manually; migrate-v2 doesn't second-guess).
    await setupProfile("safespace-send", {
      accounts: { version: 1, accounts: [ENTRY_BOB] },
      env: "SAFESPACE_TIER=read\nSAFESPACE_ENABLE_SEND=1\n",
    });

    const report = await migrateV2({ parentDir: parent });

    expect(report.tierDerived).toBeNull();
    expect(report.warnings.some((w) => /auto-derived SAFESPACE_TIER/.test(w))).toBe(false);

    const env = await fs.readFile(path.join(parent, "safespace", ".env"), "utf8");
    expect(env).toBe("SAFESPACE_TIER=read\nSAFESPACE_ENABLE_SEND=1\n");
  });

  test(".env with no legacy flags and no TIER → no derivation, content verbatim", async () => {
    await setupProfile("safespace-send", {
      accounts: { version: 1, accounts: [ENTRY_BOB] },
      env: "GOOGLE_CLIENT_ID=cid\nGOOGLE_CLIENT_SECRET=sec\n",
    });

    const report = await migrateV2({ parentDir: parent });

    expect(report.tierDerived).toBeNull();
    const env = await fs.readFile(path.join(parent, "safespace", ".env"), "utf8");
    expect(env).toBe("GOOGLE_CLIENT_ID=cid\nGOOGLE_CLIENT_SECRET=sec\n");
  });

  test("no .env in either source → no derivation, no error", async () => {
    await setupProfile("safespace-read", {
      accounts: { version: 1, accounts: [ENTRY_ALICE] },
    });
    // intentionally no env on either side

    const report = await migrateV2({ parentDir: parent });
    expect(report.applied).toBe(true);
    expect(report.tierDerived).toBeNull();
  });

  test("dry-run reports derivation without writing the .env file", async () => {
    // Dry-run is the user's "what will happen" preview. The tier derivation
    // must surface there too, otherwise the user only sees it after the
    // destructive operation.
    await setupProfile("safespace-send", {
      accounts: { version: 1, accounts: [ENTRY_BOB] },
      env: "GOOGLE_CLIENT_ID=cid\nSAFESPACE_ENABLE_MODIFY=1\n",
    });

    const report = await migrateV2({ parentDir: parent, dryRun: true });

    expect(report.applied).toBe(false);
    expect(report.tierDerived).toEqual({
      derivedTier: "write",
      legacyFlagsFound: ["SAFESPACE_ENABLE_MODIFY"],
    });
    // No on-disk writes happened.
    await expect(fs.access(path.join(parent, "safespace"))).rejects.toThrow();
  });

  test("derivation preserves file mode 0600 on rewritten .env", async () => {
    await setupProfile("safespace-send", {
      accounts: { version: 1, accounts: [ENTRY_BOB] },
      env: "GOOGLE_CLIENT_ID=cid\nSAFESPACE_ENABLE_SEND=1\n",
    });

    await migrateV2({ parentDir: parent });
    const stat = await fs.stat(path.join(parent, "safespace", ".env"));
    expect(stat.mode & 0o777).toBe(0o600);
  });

  test("derivation warning does NOT include any .env content (secret-leak guard)", async () => {
    // The warning surfaces flag NAMES but never values. Reuse the canary
    // pattern from the C1 test to verify the warning string is clean.
    await setupProfile("safespace-send", {
      accounts: { version: 1, accounts: [ENTRY_BOB] },
      env:
        "GOOGLE_CLIENT_ID=client-CANARY-WARN-A\n" +
        "GOOGLE_CLIENT_SECRET=SECRET-CANARY-WARN-B\n" +
        "SAFESPACE_ENABLE_SEND=1\n",
    });

    const report = await migrateV2({ parentDir: parent });
    const allWarnings = report.warnings.join("\n");
    expect(allWarnings).not.toContain("CANARY-WARN-A");
    expect(allWarnings).not.toContain("SECRET-CANARY-WARN-B");
  });

  test("send .env preferred when both sources have .env (consistent with verbatim copy)", async () => {
    // copyEnvSafely already prefers send over read. The derivation must
    // run on the SAME source so the warning + on-disk content match.
    await setupProfile("safespace-read", {
      accounts: { version: 1, accounts: [ENTRY_ALICE] },
      env: "GOOGLE_CLIENT_ID=read-cid\n", // no legacy flag
    });
    await setupProfile("safespace-send", {
      accounts: { version: 1, accounts: [ENTRY_BOB] },
      env: "GOOGLE_CLIENT_ID=send-cid\nSAFESPACE_ENABLE_SEND=1\n",
    });

    const report = await migrateV2({ parentDir: parent });
    expect(report.tierDerived?.derivedTier).toBe("write");
    const env = await fs.readFile(path.join(parent, "safespace", ".env"), "utf8");
    expect(env).toContain("GOOGLE_CLIENT_ID=send-cid"); // send won
    expect(env).not.toContain("GOOGLE_CLIENT_ID=read-cid");
  });
});
