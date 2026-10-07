// v1.37 BLOCKER 1 -- KeychainBackend: the macOS (@napi-rs/keyring) SecretBackend.
//
// This is today's token-storage behavior, lifted out of keychain.ts (which now
// keeps ONLY the accounts.json index half) and put behind the SecretBackend
// seam. The native error-masking discipline is preserved VERBATIM from the old
// keychain.ts get/setToken (see the catch blocks): NEVER forward String(e) --
// @napi-rs/keyring native errors may carry the Keychain service/account or a
// filesystem path, which would leak into MCPError.data and reach Claude.
//
// Keying: the plain store key (a Google email is the exact
// `new Entry("safespace-mcp", email)` key existing Mac users already have).

import { createRequire } from "node:module";
import { MCPError } from "../errors";
import type { SecretBackend } from "./secret-backend";

const SERVICE = "safespace-mcp";

/** The slice of @napi-rs/keyring's `Entry` this backend uses. Declared as an
 *  interface + injectable factory so unit tests can supply an in-memory fake and
 *  exercise every branch (error masking) without the native lib or
 *  a real Keychain. */
export interface KeyringEntry {
  getPassword(): string | null;
  setPassword(password: string): void;
  deletePassword(): void;
}
export type EntryFactory = (service: string, account: string) => KeyringEntry;

// v1.110 PR 1c (S6) — lazy-load the native @napi-rs/keyring binding.
//
// @napi-rs/keyring is a native addon (a per-platform .node binary). A static
// top-level `import { Entry }` loaded that binary the instant ANYTHING imported
// this module -- even on deployments that never reach the Keychain: Linux/Windows
// running on the FileBackend, or the `npx safespace-mcp` multi-client path on a
// host whose platform binary isn't installed. A missing/incompatible binary then
// crashed the whole process at IMPORT, before select-backend could route to the
// FileBackend -- a portability footgun for the very non-mac clients this cycle adds.
//
// Loading it lazily -- only when defaultEntryFactory actually constructs an Entry,
// i.e. KeychainBackend is the SELECTED backend AND a token op runs -- keeps the
// native dependency wholly off the path of every non-Keychain deployment. The
// require() is memoized so repeated entries pay the resolve once. A load failure
// throws HERE, inside the factory, which each call site (read / setToken /
// deleteToken) already wraps in try/catch -> it surfaces as the same masked
// `keychain_locked`, NEVER forwarding the native dlopen path. Masking discipline
// preserved (see the catch blocks below).
const nodeRequire = createRequire(import.meta.url);
type KeyringModule = { Entry: new (service: string, account: string) => KeyringEntry };
let keyringModule: KeyringModule | null = null;
function loadKeyring(): KeyringModule {
  return (keyringModule ??= nodeRequire("@napi-rs/keyring") as KeyringModule);
}

/** Test-only: drop the memoized native-keyring module so a test can re-exercise
 *  the lazy load deterministically, regardless of whether an earlier test file
 *  already populated the memo with the real binding. */
export function __resetKeyringMemoForTests(): void {
  keyringModule = null;
}

const defaultEntryFactory: EntryFactory = (service, account) =>
  new (loadKeyring().Entry)(service, account);

export class KeychainBackend implements SecretBackend {
  constructor(private readonly makeEntry: EntryFactory = defaultEntryFactory) {}

  async getToken(key: string): Promise<string | null> {
    return this.read(key);
  }

  async setToken(key: string, tokenJson: string): Promise<void> {
    try {
      this.makeEntry(SERVICE, key).setPassword(tokenJson);
    } catch {
      // Do NOT forward String(e) -- native error may leak service/account/path.
      throw new MCPError("keychain_locked");
    }
  }

  async deleteToken(key: string): Promise<void> {
    try {
      this.makeEntry(SERVICE, key).deletePassword();
    } catch {
      // Best-effort / idempotent: the entry may already be gone or the store may
      // be locked. Mirrors the old keychain.deleteToken (recovery > policy).
    }
  }

  /** Read one storage key. Missing entry -> null (mirrors the old
   *  `getPassword() ?? null`); any thrown native error -> keychain_locked with
   *  NO native message forwarded. */
  private read(key: string): string | null {
    try {
      return this.makeEntry(SERVICE, key).getPassword() ?? null;
    } catch {
      throw new MCPError("keychain_locked");
    }
  }
}
