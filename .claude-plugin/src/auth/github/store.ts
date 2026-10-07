// v1.70 (G2) — the GitHub account + token store. GitHub is SafeSpace's 2nd OAuth
// source; unlike Google's multi-account accounts.json, the v1 read connector is
// single-account (one consented github login). The login + the scopes consent
// granted live in a small `github-account.json`; the TOKEN lives in the SAME
// swappable SecretBackend the Google OAuth tokens + the class-B service tokens use,
// under a RESERVED key `github:<login>` — it contains ":" and no "@", so it can
// never collide with a Google email key (the same keying discipline as
// auth/service-token-store.ts).
//
// G2 ships the READ side (consumed by the github Source's resolveAccount /
// resolveCredential in tools/source.ts) AND the WRITE side (consumed by the G3
// consent flow + the `safespace consent --provider github` / account-revoke CLI).
// The token is NEVER logged, echoed, or stored as a field — handlers read it via
// the `oauth` Credential's getter, inline when building the Authorization header.

import * as fs from "node:fs/promises";
import * as path from "node:path";
import { configDir } from "../keychain";
import type { SecretBackend } from "../secret-backend";
import { selectBackend } from "../select-backend";

/** GitHub login: 1–39 chars of `[A-Za-z0-9-]` (GitHub's own username rule). The
 *  anchored class also rejects path separators / CRLF / "@" / ":" — so a login is
 *  safe both as a SecretBackend key segment and (G4) as a URL path segment. */
export const GITHUB_LOGIN_RE = /^[A-Za-z0-9-]{1,39}$/;

const ACCOUNT_FILE = "github-account.json";

/** The persisted GitHub account: the login + the scopes consent granted. */
export interface GithubAccount {
  readonly login: string;
  readonly scopes: readonly string[];
}

function accountPath(): string {
  return path.join(configDir(), ACCOUNT_FILE);
}

/** Read the persisted GitHub account, or null if missing/corrupt (defensive
 *  against a hand-edited / partially-written file — the caller treats it as "no
 *  github account", the same posture as auth/active.ts `readActive`). */
export async function readGithubAccount(): Promise<GithubAccount | null> {
  try {
    const parsed = JSON.parse(await fs.readFile(accountPath(), "utf8")) as unknown;
    if (
      parsed &&
      typeof parsed === "object" &&
      typeof (parsed as { login?: unknown }).login === "string" &&
      GITHUB_LOGIN_RE.test((parsed as { login: string }).login) &&
      Array.isArray((parsed as { scopes?: unknown }).scopes) &&
      (parsed as { scopes: unknown[] }).scopes.every((s) => typeof s === "string")
    ) {
      const p = parsed as { login: string; scopes: string[] };
      return { login: p.login, scopes: p.scopes };
    }
    return null;
  } catch {
    return null;
  }
}

/** Persist the GitHub account (the G3 consent writer). Rejects a bad login before
 *  any filesystem work. file mode 0o600, dir 0o700 (mirror auth/active.ts). */
export async function writeGithubAccount(account: GithubAccount): Promise<void> {
  if (!GITHUB_LOGIN_RE.test(account.login)) {
    throw new Error("writeGithubAccount: invalid github login");
  }
  await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
  await fs.writeFile(
    accountPath(),
    `${JSON.stringify({ login: account.login, scopes: account.scopes }, null, 2)}\n`,
    { mode: 0o600 },
  );
}

/** Remove the persisted GitHub account file (account-revoke; idempotent). */
export async function clearGithubAccount(): Promise<void> {
  await fs.unlink(accountPath()).catch(() => undefined);
}

/* ── token (SecretBackend, reserved key `github:<login>`) ─────────────────── */

let cachedBackend: SecretBackend | null = null;
function backend(): SecretBackend {
  if (cachedBackend === null) cachedBackend = selectBackend();
  return cachedBackend;
}

/** Test-only: drop the cached backend so a test can flip the backend selection
 *  (mirror service-token-store.__resetServiceTokenBackendForTests). */
export function __resetGithubBackendForTests(): void {
  cachedBackend = null;
}

function reservedKey(login: string): string {
  // Defense-in-depth (G2 security-review LOW): validate BEFORE constructing the
  // SecretBackend key. The G3 consent flow calls writeGithubToken with a login from
  // the OAuth callback; an unvalidated login (a `:` / path separator) could shape an
  // unexpected key. writeGithubAccount validates the file path too — this covers the
  // token read / write / clear path in ONE place.
  if (!GITHUB_LOGIN_RE.test(login)) {
    throw new Error("github store: invalid github login");
  }
  return `github:${login}`;
}

/** Read the stored GitHub token for `login`, or null if none. Reads ONLY the
 *  SecretBackend (no shell env override this PR; G3 may add one alongside the
 *  GitHub client-id/secret env vars). */
export async function readGithubToken(login: string): Promise<string | null> {
  return backend().getToken(reservedKey(login));
}

/** Persist the GitHub token (the G3 consent writer). Opaque to the backend. */
export async function writeGithubToken(login: string, token: string): Promise<void> {
  await backend().setToken(reservedKey(login), token);
}

/** Remove the stored GitHub token (account-revoke; idempotent at the backend). */
export async function clearGithubToken(login: string): Promise<void> {
  await backend().deleteToken(reservedKey(login));
}
