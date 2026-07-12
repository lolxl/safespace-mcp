/**
 * Cold-path #1 — lazy, memoized accessor for the googleapis `google` namespace.
 *
 * `googleapis` is ~114 MB on disk. A top-level `import { google }` parsed and
 * evaluated the ENTIRE SDK the instant any handler module was pulled onto the
 * graph — which happens at `createMcpServer()` for EVERY transport, including
 * the `npx safespace-mcp` multi-client path on a host that only ever calls
 * web_fetch / fs_read / GitHub / Notion and NEVER touches a Google tool. That
 * SDK parse is the single largest cold-start cost in the process.
 *
 * Deferring the resolve to first Google-tool use — the synchronous *FromToken
 * factories call `getGoogle()` at call time — keeps the SDK wholly off the
 * bootstrap path; non-Google sessions never resolve it. Mirrors the v1.110 S6
 * keychain-backend precedent (`createRequire` + a memoized `require()` so the
 * resolve is paid once). The require form — NOT `await import` — keeps the
 * factory signatures synchronous: no async ripple through the 10 Google
 * handlers. The same require/import.meta.url shape already ships in this dist
 * build pipeline via keychain-backend.ts.
 *
 * Type-only imports of the SDK namespaces (calendar_v3, gmail_v1, …) stay as
 * `import type` at each call site: those are erased at compile time and carry
 * NO runtime SDK load — only this `google` VALUE accessor defers anything.
 */

import { createRequire } from "node:module";

const nodeRequire = createRequire(import.meta.url);
type GoogleApis = typeof import("googleapis");
let mod: GoogleApis | null = null;

/** The googleapis `google` namespace, resolved + memoized on first call. */
export function getGoogle(): GoogleApis["google"] {
  return (mod ??= nodeRequire("googleapis") as GoogleApis).google;
}

/** Test-only: drop the memoized SDK module so a test can re-exercise the lazy
 *  resolve deterministically. Mirrors `__resetKeyringMemoForTests`. */
export function __resetGoogleMemoForTests(): void {
  mod = null;
}
