// v1.93 A1 — agent-token store tests: hashing, fail-loud parse, lookup + expiry,
// bearer parsing, and the mint/revoke/list round-trip (the plaintext is never
// persisted — only its HMAC hash).

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import {
  extractBearerToken,
  generateAgentToken,
  getOrCreateAgentTokenSalt,
  hashAgentToken,
  listAgentTokens,
  loadAgentTokens,
  lookupTokenLogin,
  mintAgentToken,
  parseAgentTokens,
  revokeAgentTokensForLogin,
} from "./agent-token-store";

let tmp: string;
let prevEnv: string | undefined;
beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  tmp = await fs.mkdtemp(path.join(tmpdir(), "agent-token-"));
  process.env.SAFESPACE_CONFIG_DIR = tmp;
});
afterEach(async () => {
  if (prevEnv === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevEnv;
  await fs.rm(tmp, { recursive: true, force: true });
});
const tokensFile = () => path.join(tmp, "agent-tokens.json");

describe("hash + token generation", () => {
  test("generateAgentToken is unique + high-entropy", () => {
    const a = generateAgentToken();
    expect(a).not.toBe(generateAgentToken());
    expect(a.length).toBeGreaterThanOrEqual(40); // 32 bytes base64url ≈ 43 chars
  });
  test("hashAgentToken is deterministic per salt, 64 hex, input-sensitive", () => {
    const salt = Buffer.from("00".repeat(32), "hex");
    const h = hashAgentToken("tok", salt);
    expect(h).toMatch(/^[0-9a-f]{64}$/);
    expect(hashAgentToken("tok", salt)).toBe(h);
    expect(hashAgentToken("tok2", salt)).not.toBe(h);
    // a different salt → a different hash (per-install isolation)
    expect(hashAgentToken("tok", Buffer.from("ff".repeat(32), "hex"))).not.toBe(h);
  });
  test("getOrCreateAgentTokenSalt persists (32 bytes, stable across calls)", async () => {
    const s1 = await getOrCreateAgentTokenSalt();
    const s2 = await getOrCreateAgentTokenSalt();
    expect(s1.length).toBe(32);
    expect(s1.equals(s2)).toBe(true);
  });
});

describe("extractBearerToken", () => {
  test("parses a Bearer header (scheme case-insensitive)", () => {
    expect(extractBearerToken("Bearer abc.def")).toBe("abc.def");
    expect(extractBearerToken("bearer xyz")).toBe("xyz");
    expect(extractBearerToken("  Bearer   padded  ")).toBe("padded");
  });
  test("rejects absent / non-Bearer / empty", () => {
    expect(extractBearerToken(undefined)).toBeNull();
    expect(extractBearerToken("")).toBeNull();
    expect(extractBearerToken("Basic abc")).toBeNull();
    expect(extractBearerToken("Bearer")).toBeNull();
    expect(extractBearerToken("Bearer ")).toBeNull();
  });
});

describe("parseAgentTokens — fail-loud", () => {
  const HASH = "a".repeat(64);
  const cases: Array<[string, string]> = [
    ["not JSON", "{nope"],
    ["top-level array", JSON.stringify([])],
    ["tokens not an array", JSON.stringify({ tokens: {} })],
    ["entry not an object", JSON.stringify({ tokens: ["x"] })],
    ["tokenHash too short", JSON.stringify({ tokens: [{ tokenHash: "ab", login: "a@x.com" }] })],
    ["tokenHash non-hex", JSON.stringify({ tokens: [{ tokenHash: "Z".repeat(64), login: "a@x.com" }] })],
    ["login not name@provider", JSON.stringify({ tokens: [{ tokenHash: HASH, login: "nope" }] })],
    ["expiresAt not ISO", JSON.stringify({ tokens: [{ tokenHash: HASH, login: "a@x.com", expiresAt: "soon" }] })],
    [
      "duplicate tokenHash",
      JSON.stringify({ tokens: [{ tokenHash: HASH, login: "a@x.com" }, { tokenHash: HASH, login: "b@x.com" }] }),
    ],
  ];
  for (const [name, raw] of cases) {
    test(`throws on: ${name}`, () => expect(() => parseAgentTokens(raw)).toThrow());
  }
  test("valid → hash→record map", () => {
    const m = parseAgentTokens(
      JSON.stringify({ tokens: [{ tokenHash: HASH, login: "alice@example.com", expiresAt: "2099-01-01T00:00:00Z" }] }),
    );
    expect(m.size).toBe(1);
    expect(m.get(HASH)).toEqual({ login: "alice@example.com", expiresAt: "2099-01-01T00:00:00Z" });
  });
});

describe("lookupTokenLogin", () => {
  const salt = Buffer.from("ab".repeat(32), "hex");
  test("valid token → login; unknown → null", () => {
    const tok = "secret-token";
    const store = new Map([[hashAgentToken(tok, salt), { login: "alice@example.com" }]]);
    expect(lookupTokenLogin(tok, store, salt, 1000)).toBe("alice@example.com");
    expect(lookupTokenLogin("wrong", store, salt, 1000)).toBeNull();
  });
  test("expired → null; future expiry → login", () => {
    const tok = "t";
    const now = Date.parse("2026-01-01T00:00:00Z");
    const expired = new Map([[hashAgentToken(tok, salt), { login: "a@x.com", expiresAt: "2000-01-01T00:00:00Z" }]]);
    expect(lookupTokenLogin(tok, expired, salt, now)).toBeNull();
    const live = new Map([[hashAgentToken(tok, salt), { login: "a@x.com", expiresAt: "2099-01-01T00:00:00Z" }]]);
    expect(lookupTokenLogin(tok, live, salt, now)).toBe("a@x.com");
  });
});

describe("mint / revoke / list round-trip", () => {
  test("mint persists only the HASH; the plaintext resolves back to the login", async () => {
    const salt = await getOrCreateAgentTokenSalt();
    const token = await mintAgentToken(tokensFile(), "alice@example.com", salt);
    const raw = await fs.readFile(tokensFile(), "utf8");
    expect(raw).not.toContain(token); // plaintext NEVER on disk
    expect(raw).toContain(hashAgentToken(token, salt)); // only the hash
    const store = await loadAgentTokens(tokensFile());
    expect(lookupTokenLogin(token, store, salt, Date.now())).toBe("alice@example.com");
  });
  test("mint rejects a malformed login / expiry", async () => {
    const salt = await getOrCreateAgentTokenSalt();
    await expect(mintAgentToken(tokensFile(), "nope", salt)).rejects.toThrow();
    await expect(mintAgentToken(tokensFile(), "a@x.com", salt, "notadate")).rejects.toThrow();
  });
  test("revoke removes a login's tokens → next lookup misses", async () => {
    const salt = await getOrCreateAgentTokenSalt();
    const token = await mintAgentToken(tokensFile(), "alice@example.com", salt);
    expect(await revokeAgentTokensForLogin(tokensFile(), "alice@example.com")).toBe(1);
    const store = await loadAgentTokens(tokensFile());
    expect(lookupTokenLogin(token, store, salt, Date.now())).toBeNull();
    expect(await revokeAgentTokensForLogin(tokensFile(), "alice@example.com")).toBe(0); // idempotent
  });
  test("two mints for the same login coexist; revoke removes both", async () => {
    const salt = await getOrCreateAgentTokenSalt();
    await mintAgentToken(tokensFile(), "alice@example.com", salt);
    await mintAgentToken(tokensFile(), "alice@example.com", salt);
    expect((await listAgentTokens(tokensFile())).length).toBe(2);
    expect(await revokeAgentTokensForLogin(tokensFile(), "alice@example.com")).toBe(2);
  });
  test("list shows login + 12-char hash prefix + expiry; missing file → empty", async () => {
    expect(await listAgentTokens(tokensFile())).toEqual([]);
    const salt = await getOrCreateAgentTokenSalt();
    await mintAgentToken(tokensFile(), "alice@example.com", salt, "2099-01-01T00:00:00Z");
    const rows = await listAgentTokens(tokensFile());
    expect(rows).toHaveLength(1);
    expect(rows[0]!.login).toBe("alice@example.com");
    expect(rows[0]!.hashPrefix).toHaveLength(12);
    expect(rows[0]!.expiresAt).toBe("2099-01-01T00:00:00Z");
  });
  test("loadAgentTokens on a missing file → empty store", async () => {
    expect((await loadAgentTokens(tokensFile())).size).toBe(0);
  });
});
