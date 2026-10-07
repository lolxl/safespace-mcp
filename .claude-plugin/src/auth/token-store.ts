// v1.37 BLOCKER 1 -- token-store facade (design 4.4).
//
// The smallest-blast-radius seam: exposes the SAME email-only API the old
// keychain.ts get/setToken had, so the 5 call sites (refresh.ts, consent.ts,
// cli.ts, status.ts, with-context.ts) change only their import. The backend is
// resolved once and cached; the Google email is the store key.
//
// MCPErrors thrown by the backend (keychain_locked / secret_store_corrupt) are
// re-thrown UNCHANGED so the cli.ts account-revoke unlock-and-retry UX survives
// identically across backends.

import { type SecretBackend } from "./secret-backend";
import { selectBackend } from "./select-backend";

let cached: SecretBackend | null = null;
function backend(): SecretBackend {
  if (cached === null) cached = selectBackend();
  return cached;
}

export async function getToken(email: string): Promise<string | null> {
  return backend().getToken(email);
}

export async function setToken(email: string, tokenJson: string): Promise<void> {
  return backend().setToken(email, tokenJson);
}

export async function deleteToken(email: string): Promise<void> {
  return backend().deleteToken(email);
}

/** Test-only: drop the cached backend so a test can flip
 *  $SAFESPACE_SECRET_BACKEND / process.platform and re-select. */
export function __resetBackendForTests(): void {
  cached = null;
}
