// v1.37 BLOCKER 1 -- SecretBackend seam (now BEHAVIORAL; was a Q7 type-only stub).
//
// OAuth tokens used to live in the macOS Keychain only (auth/keychain.ts,
// @napi-rs/keyring), keyed by Google email -- so the server did not run on a
// headless Linux box or for a second OS user (the #1 adoption blocker for
// open-source / multi-user). Token storage now sits behind this interface so
// KeychainBackend (macOS; today's behavior) and FileBackend (encrypted-at-rest;
// the Linux/OSS unblock) are swappable; a future VaultBackend stays a non-goal
// (roadmap N2). Selection: auth/select-backend.ts. Facade: auth/token-store.ts.
//
// Keys are the plain store key (a Google email, `github:<login>`, a service's
// reserved key, ...) — the same shape KeychainBackend used before v1.37. The former
// per-operator namespace was removed with SAFESPACE_OPERATOR_ID
// (policy/retired-settings.ts).

/** Swappable token-storage backend. Methods move the raw token JSON string;
 *  getToken returns null when nothing is stored under that key. */
export interface SecretBackend {
  getToken(key: string): Promise<string | null>;
  setToken(key: string, tokenJson: string): Promise<void>;
  deleteToken(key: string): Promise<void>;
}
