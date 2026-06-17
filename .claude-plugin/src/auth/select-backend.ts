// v1.37 BLOCKER 1 -- backend selection (B7 LOCKED).
//
// $SAFESPACE_SECRET_BACKEND is a STRICT lowercase exact-match {keychain,file}
// (mirrors the strict-truthy env convention elsewhere; no trimming/case-folding).
//   unset      -> keychain on darwin (today's behavior, zero change), file
//                 elsewhere (the Linux/OSS unblock).
//   "keychain" -> KeychainBackend (a Linux DESKTOP with Secret Service opts in).
//   "file"     -> FileBackend (a Mac user who wants portable/headless opts in).
//   anything else -> FAIL-CLOSED startup error (reject typos loudly; never
//                 silently fall back to a different store).
//
// No auto-probe of Secret Service on Linux: it can succeed at construction yet
// fail opaquely at runtime (no daemon). Default-by-platform + explicit override
// is predictable and documented.

import { type SecretBackend } from "./secret-backend";
import { KeychainBackend } from "./keychain-backend";
import { FileBackend, isPassphraseMode } from "./file-backend";
import { isAutonomousMode } from "../policy/autonomous-mode";
import { ENV_SECRET_BACKEND, ENV_ALLOW_KEYFILE_AT_REST, readStrictTruthy } from "../config";

export type BackendKind = "keychain" | "file";

/** Resolve which backend to use. Pure (reads env + platform only) so the
 *  selection matrix is unit-testable without instantiating a backend. Throws on
 *  an invalid non-empty value (fail-closed); the message is value-free. */
export function selectBackendKind(): BackendKind {
  const env = process.env[ENV_SECRET_BACKEND];
  if (env === undefined || env === "") {
    return process.platform === "darwin" ? "keychain" : "file";
  }
  if (env === "keychain" || env === "file") return env;
  throw new Error('Invalid SAFESPACE_SECRET_BACKEND (expected "keychain" or "file")');
}

export function selectBackend(): SecretBackend {
  return selectBackendKind() === "keychain" ? new KeychainBackend() : new FileBackend();
}

// ── v1.55 F6 — autonomous token-at-rest hardening ──────────────────────────
//
// docs/v1.55-f6-autonomous-token-hardening.md. Finishes the autonomous-deploy
// story (F2 deny-external → F4 deny-permanent-delete → F6 harden token at rest).
// FileBackend defaults to KEY-FILE mode: the AES key sits in secret.key BESIDE
// the ciphertext secret.enc, so a single backup / disk image / directory
// snapshot of an UNATTENDED box yields both halves = full offline token
// compromise, no agent interaction. F6 refuses to run an autonomous deployment
// on key-beside-ciphertext storage unless the operator either sets a passphrase
// (no key at rest) or explicitly opts back in.
//
// HONEST BOUNDARY (do not oversell): F6 raises the bar only against OFFLINE
// capture. A same-host agent that can run shell with the passphrase in its env
// can still read the live token (axis-3) — that stays an OpenClaw-side sandbox
// responsibility (SECURITY.md isolation note), NOT something F6 closes.
//
// Q-LOCKED (all-as-recommended): Q2 = refuse-to-start (fail loud + early) with an escape
// hatch; Q3 = single strict-truthy SAFESPACE_ALLOW_KEYFILE_AT_REST; Q4 =
// Keychain exempt (key is OS-guarded, not beside ciphertext); Q5 = startup
// failure → NO new error code; Q6 = once autonomous is CONFIRMED, fail toward
// REFUSE (the SAFESPACE_AUTONOMOUS flag itself still fails permissive on a typo
// per F2 R3 — the strictness only engages on a deliberately-set flag).

/** The escape hatch: deliberately accept FileBackend key-file mode under
 *  autonomous mode. Strict-truthy (literal lowercase "true"), mirroring
 *  SAFESPACE_AUTONOMOUS / isContactLookupEnabled. */
export { ENV_ALLOW_KEYFILE_AT_REST };

function isKeyfileAtRestAllowed(): boolean {
  return readStrictTruthy(ENV_ALLOW_KEYFILE_AT_REST);
}

/** Pure (env + platform only). Returns a refusal MESSAGE when an autonomous
 *  deployment is about to run on FileBackend KEY-FILE mode without the escape
 *  hatch; null when allowed. Allowed when: not autonomous (F2 R3 — a typo'd flag
 *  must not brick startup); the backend is Keychain (Q4 exempt); passphrase mode
 *  (the recommended state); or the escape hatch is explicitly "true". The
 *  message names BOTH remedies and echoes no path / key material (only the
 *  documented static filenames). */
export function autonomousKeyfileRefusal(): string | null {
  if (!isAutonomousMode()) return null;
  if (selectBackendKind() !== "file") return null;
  if (isPassphraseMode()) return null;
  if (isKeyfileAtRestAllowed()) return null;
  return (
    "SAFESPACE_AUTONOMOUS=true but the OAuth token store is FileBackend in " +
    "KEY-FILE mode — the AES key sits in secret.key beside the ciphertext " +
    "secret.enc, which is vulnerable to offline backup / disk-image / directory " +
    "capture. Refusing to start an unattended deployment on key-beside-ciphertext " +
    "storage. Fix EITHER by setting SAFESPACE_SECRET_PASSPHRASE for no-key-at-rest " +
    "encryption (recommended), OR by setting SAFESPACE_ALLOW_KEYFILE_AT_REST=true " +
    "to deliberately accept key-file mode for this deployment. See SECURITY.md."
  );
}

/** Startup enforcement (Q2 = refuse-to-start). Throws when
 *  `autonomousKeyfileRefusal()` returns a message; the proxy bootstrap catches
 *  the throw, prints it to stderr, and exits non-zero BEFORE serving any tool. */
export function enforceAutonomousTokenStorage(): void {
  const reason = autonomousKeyfileRefusal();
  if (reason !== null) throw new Error(reason);
}
