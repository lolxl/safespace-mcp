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
// Tokens key on BOTH operatorId AND googleAccount (design section 4.2) so two
// operators authing the same Google account never collide. See storageKey():
// operatorId === null (today's single-user default) maps to the LEGACY
// email-only key, so existing Mac users migrate with ZERO action.

/** Swappable token-storage backend. Methods move the same raw token JSON string
 *  that auth/keychain.ts get/setToken handled before this cycle; getToken
 *  returns null when no token is stored for that (operatorId, googleAccount)
 *  pair.
 *
 *  operatorId is `string | null` (B4 LOCKED): resolveOperatorId() already
 *  returns string|null, and making null first-class here keeps the
 *  legacy-key-compat rule in ONE auditable place (storageKey) rather than a
 *  "magic empty string" sentinel smeared across call sites. */
export interface SecretBackend {
  getToken(operatorId: string | null, googleAccount: string): Promise<string | null>;
  setToken(operatorId: string | null, googleAccount: string, tokenJson: string): Promise<void>;
  deleteToken(operatorId: string | null, googleAccount: string): Promise<void>;
}

/** NUL (U+0000) namespace delimiter. Built via String.fromCharCode(0) so NO
 *  literal control byte ever appears in this source file. Unspoofable: the
 *  operator-id regex (`^[A-Za-z0-9_.-]{1,64}$`, identity/operator-id.ts)
 *  excludes NUL and email addresses cannot contain NUL, so the joined key
 *  `operatorId + NUL + googleAccount` is unambiguous and cannot be forged by a
 *  crafted operatorId or email. */
const NS_DELIM = String.fromCharCode(0);

/** Map (operatorId, googleAccount) to a single storage key, shared by every
 *  backend so the keying rule lives in one place.
 *
 *  operatorId === null  -> the BARE googleAccount = the LEGACY key shape that
 *  KeychainBackend used before v1.37 (`new Entry("safespace-mcp", email)`), so
 *  existing single-user Mac entries are found with NO migration (design 4.3.1,
 *  G2). operatorId set -> `operatorId + NUL + googleAccount`, a distinct
 *  namespaced key, so two operators sharing one config dir / Google account
 *  never collide. */
export function storageKey(operatorId: string | null, googleAccount: string): string {
  return operatorId === null ? googleAccount : `${operatorId}${NS_DELIM}${googleAccount}`;
}
