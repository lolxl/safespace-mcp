// v1.93 A1 — agent→gateway bearer-token auth store (Model B, OFF-tailnet).
//
// The COMPLEMENT to Tailscale WhoIs: when SAFESPACE_AUTH=token, each HTTP request
// authenticates by an `Authorization: Bearer <token>` instead of by peer IP. The
// token resolves (via its HMAC hash) to a `name@provider` login, which then feeds
// the SAME default-deny operators.json registry lookup — so a token authenticates
// WHO, and the registry still authorizes (tier / allowedAccounts). A token whose
// login is not a registered operator is refused, exactly like an unregistered
// tailnet login.
//
// AT REST: agent-tokens.json stores only each token's HMAC-SHA256 HASH (keyed by a
// per-install salt outside the file), never the plaintext — leaking the file
// reveals no usable token (the same posture as the recipient-allowlist + audit
// HMAC hashes). The plaintext is shown ONCE at `safespace agent-token mint` and
// lives only on the operator/agent side.
//
// LOOPBACK-ONLY for this cycle (A1): the enforced-mode bind gate is unchanged, so
// this never widens network exposure — it is a pure additive identity source. The
// public-bind relaxation + the TLS guarantee are A2 (their own security review).
//
// REVOCATION (A1-minimal): the store is re-read at every session INIT, so a
// revoked/expired token cannot START a new session; registry-side revocation still
// bites existing sessions per request (reresolveOrRevoke, unchanged). An already
// OPEN session survives its token's removal until it closes — documented; the
// per-request token re-check rides into A2 where exposure makes the gap matter.

import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { configDir } from "./keychain";
import { AGENT_TOKEN_HMAC_ALG } from "../crypto-algorithms";

const SALT_FILE = "agent-token-salt";
const TOKEN_BYTES = 32; // 256 bits of entropy → the hash is not brute-forceable.
const TOKEN_HASH_RE = /^[0-9a-f]{64}$/; // HMAC-SHA256 hex.
// A login is `name@provider` (alice@example.com, alice@github). Built from a
// STRING so the source carries no literal control byte; control chars / whitespace
// are excluded. The operators registry is the real authority — this just rejects
// obviously-malformed store entries.
const LOGIN_RE = new RegExp("^[^\\s\\u0000-\\u001f@]{1,128}@[^\\s\\u0000-\\u001f@]{1,128}$");

/** One resolved store entry (the plaintext token is NEVER stored). */
export interface AgentTokenRecord {
  readonly login: string;
  /** Optional ISO 8601 expiry; absent = no expiry. */
  readonly expiresAt?: string;
}

function fail(msg: string): never {
  throw new Error(`[safespace] agent-tokens store invalid: ${msg}`);
}

function saltPath(): string {
  return path.join(configDir(), SALT_FILE);
}

/** Read the per-install agent-token HMAC salt, creating it (32 random bytes,
 *  0o600) on first use. Dedicated (NOT the audit salt) so token auth and audit
 *  hashing stay decoupled. Concurrent-safe via O_EXCL: a create race falls back
 *  to reading the winner's file. */
export async function getOrCreateAgentTokenSalt(): Promise<Buffer> {
  const p = saltPath();
  try {
    return await fs.readFile(p);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
  }
  await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
  const salt = crypto.randomBytes(32);
  try {
    const fh = await fs.open(p, "wx", 0o600);
    try {
      await fh.write(salt);
    } finally {
      await fh.close();
    }
    return salt;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") return await fs.readFile(p);
    throw e;
  }
}

/** A fresh random bearer token (URL-safe base64, no padding) — shown once at mint. */
export function generateAgentToken(): string {
  return crypto.randomBytes(TOKEN_BYTES).toString("base64url");
}

/** HMAC-SHA256(salt, token) as hex — the value stored at rest + the lookup key. */
export function hashAgentToken(plaintext: string, salt: Buffer): string {
  return crypto.createHmac(AGENT_TOKEN_HMAC_ALG, salt).update(plaintext).digest("hex");
}

function isPlausibleLogin(s: unknown): s is string {
  return typeof s === "string" && LOGIN_RE.test(s);
}

/** Parse + validate raw agent-tokens.json into a hash→record map. Pure (no I/O).
 *  Throws on the FIRST violation — fail-loud, so a misconfigured store never
 *  silently serves. Errors reference the entry INDEX + field, never the raw value. */
export function parseAgentTokens(raw: string): Map<string, AgentTokenRecord> {
  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch {
    fail("not valid JSON");
  }
  if (doc == null || typeof doc !== "object" || Array.isArray(doc)) {
    fail("top-level must be an object with a `tokens` array");
  }
  const tokens = (doc as { tokens?: unknown }).tokens;
  if (!Array.isArray(tokens)) fail("`tokens` must be an array");

  const byHash = new Map<string, AgentTokenRecord>();
  tokens.forEach((rawEntry, i) => {
    if (rawEntry == null || typeof rawEntry !== "object" || Array.isArray(rawEntry)) {
      fail(`entry #${i} must be an object`);
    }
    const e = rawEntry as Record<string, unknown>;
    if (typeof e.tokenHash !== "string" || !TOKEN_HASH_RE.test(e.tokenHash)) {
      fail(`entry #${i}: \`tokenHash\` must be 64 lowercase hex chars`);
    }
    if (!isPlausibleLogin(e.login)) {
      fail(`entry #${i}: \`login\` must be a name@provider identity`);
    }
    if (e.expiresAt !== undefined) {
      if (typeof e.expiresAt !== "string" || Number.isNaN(Date.parse(e.expiresAt))) {
        fail(`entry #${i}: \`expiresAt\`, when set, must be an ISO 8601 timestamp`);
      }
    }
    if (byHash.has(e.tokenHash)) fail(`entry #${i}: duplicate tokenHash`);
    byHash.set(e.tokenHash, {
      login: e.login,
      ...(e.expiresAt !== undefined ? { expiresAt: e.expiresAt as string } : {}),
    });
  });
  return byHash;
}

/** Read + parse the store file. Throws (fail-loud) on unreadable/invalid content;
 *  a MISSING file yields an EMPTY store (no tokens → every token auth is refused),
 *  so `mint` can create the first token without the file pre-existing. */
export async function loadAgentTokens(filePath: string): Promise<Map<string, AgentTokenRecord>> {
  let raw: string;
  try {
    raw = await fs.readFile(filePath, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return new Map();
    fail("cannot read the agent-tokens file at the configured path");
  }
  return parseAgentTokens(raw);
}

/** Resolve a presented plaintext token → its login, or null (no match / expired).
 *  Map.get on the full HMAC hash is the comparison — NOT a per-byte compare of the
 *  secret, so there is no token-value timing oracle (an attacker cannot time their
 *  way to a 256-bit-preimage token; a hash they don't possess simply misses). */
export function lookupTokenLogin(
  plaintext: string,
  store: Map<string, AgentTokenRecord>,
  salt: Buffer,
  now: number,
): string | null {
  const rec = store.get(hashAgentToken(plaintext, salt));
  if (rec === undefined) return null;
  if (rec.expiresAt !== undefined && Date.parse(rec.expiresAt) <= now) return null;
  return rec.login;
}

// A real token is ~43 base64url chars; cap well above that and reject anything
// longer BEFORE hashing it (defence-in-depth — Node's 16 KB header limit already
// bounds the input, but an explicit guard avoids hashing a pathological payload).
const MAX_BEARER_LEN = 512;

/** Extract the bearer token from an `Authorization` header value (scheme is
 *  case-insensitive). Returns null when absent / not a non-empty Bearer / longer
 *  than MAX_BEARER_LEN. */
export function extractBearerToken(authHeader: string | undefined): string | null {
  if (typeof authHeader !== "string") return null;
  const m = /^Bearer[ \t]+(\S+)$/i.exec(authHeader.trim());
  if (m === null || m[1]!.length > MAX_BEARER_LEN) return null;
  return m[1]!;
}

// ── store mutation (the `safespace agent-token` CLI) ───────────────────────────

function serialize(store: Map<string, AgentTokenRecord>): string {
  const tokens = Array.from(store.entries()).map(([tokenHash, rec]) => ({
    tokenHash,
    login: rec.login,
    ...(rec.expiresAt !== undefined ? { expiresAt: rec.expiresAt } : {}),
  }));
  return JSON.stringify({ tokens }, null, 2) + "\n";
}

async function writeStore(filePath: string, store: Map<string, AgentTokenRecord>): Promise<void> {
  await fs.writeFile(filePath, serialize(store), { mode: 0o600 });
}

/** Mint a fresh token for `login`, append its HASH to the store, and return the
 *  PLAINTEXT (the caller prints it once). Validates the login shape + expiry. */
export async function mintAgentToken(
  filePath: string,
  login: string,
  salt: Buffer,
  expiresAt?: string,
): Promise<string> {
  if (!isPlausibleLogin(login)) {
    throw new Error("login must be a name@provider identity (matching the operators registry)");
  }
  if (expiresAt !== undefined && Number.isNaN(Date.parse(expiresAt))) {
    throw new Error("--expires must be an ISO 8601 timestamp");
  }
  const store = await loadAgentTokens(filePath);
  const token = generateAgentToken();
  store.set(hashAgentToken(token, salt), {
    login,
    ...(expiresAt !== undefined ? { expiresAt } : {}),
  });
  await writeStore(filePath, store);
  return token;
}

/** Revoke every token for `login`. Returns the number removed. */
export async function revokeAgentTokensForLogin(filePath: string, login: string): Promise<number> {
  const store = await loadAgentTokens(filePath);
  // Collect the matching hashes first (materialized), THEN delete — never mutate
  // the Map mid-iteration.
  const toRemove = [...store].filter(([, rec]) => rec.login === login).map(([hash]) => hash);
  for (const hash of toRemove) store.delete(hash);
  if (toRemove.length > 0) await writeStore(filePath, store);
  return toRemove.length;
}

/** List the stored tokens for display — login + a truncated hash + expiry, NEVER
 *  a plaintext (there is none stored). */
export async function listAgentTokens(
  filePath: string,
): Promise<Array<{ login: string; hashPrefix: string; expiresAt: string | null }>> {
  const store = await loadAgentTokens(filePath);
  return Array.from(store.entries()).map(([hash, rec]) => ({
    login: rec.login,
    hashPrefix: hash.slice(0, 12),
    expiresAt: rec.expiresAt ?? null,
  }));
}
