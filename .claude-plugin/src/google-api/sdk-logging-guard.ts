// SDK debug-logging kill switch. Imported by every module that loads a Google
// library (proxy.ts, cli.ts, auth/consent.ts, google-api/lazy-google.ts).
//
// Why: google-auth-library >= 10 installs default transporter interceptors
// (authclient.js DEFAULT_REQUEST/RESPONSE_INTERCEPTOR) that write
// `AuthClient.log.debug('... response %j', response.data)` — the raw token
// endpoint body (access/refresh/id tokens) and every API call's request headers
// (Authorization: Bearer ...) and response data. They are inert unless
// GOOGLE_SDK_NODE_LOGGING is set; with `auth` / `*` / `all` / `true` they print all of
// it to stderr, which an MCP host captures into its logs. SafeSpace is a safety
// envelope: it must never emit credential-bearing or user-data SDK traffic,
// whatever the environment says. (gaxios 8 / googleapis-common 9 add no logging of
// their own; google-auth-library's AuthClient is the only caller of the logger.)
//
// The switch is in google-logging-utils/build/src/logging-utils.js:
//   - `log(namespace)` (line ~358) is evaluated ONCE when authclient.js loads
//     (`static log = log('auth')`, authclient.js:174): env unset at that instant →
//     an inert placeholder forever; env set → a Node backend (which re-reads the
//     variable in its constructor, line ~141, and caches it).
//   - `setBackend(null)` (line ~344) is the explicit global off switch: every
//     logger — already created or created later — checks `cachedBackend` on each
//     call and returns without output when it is null.
//
// Two layers, because import ORDER cannot be relied on: Bun evaluates a bare package
// import (`google-auth-library`) BEFORE a sibling side-effect import, so a "delete
// the env var first" guard alone is a no-op in consent.ts (observed: logs still
// printed). So:
//   1. setBackend(null) on the exact google-logging-utils copy google-auth-library
//      resolves (works whether the library loaded before or after this module, and
//      for the lazy `require("googleapis")` in lazy-google.ts, which shares that
//      singleton). It is the load-bearing layer.
//   2. delete GOOGLE_SDK_NODE_LOGGING — for libraries that load after this module
//      this keeps `log()` on its inert-placeholder path even if (1) failed to resolve.
//
// FAIL CLOSED, but only in the risky case. If GOOGLE_SDK_NODE_LOGGING was set when
// this module evaluated AND layer 1 did not succeed, the env deletion alone cannot
// be trusted (google-auth-library may already have built its logger with the
// variable set — Bun consent import order, Node CLI bundle static import), so
// `assertSdkLoggingDisabled()` throws a FIXED message (the variable's value is never
// echoed). If the variable was absent nothing was ever enabled, so a layer-1 failure
// is harmless and startup is never broken.
//
// Why a function and not a throw at module evaluation: proxy.ts documents that a throw
// during `import` reaches the MCP client as a bare "server disconnected" with no
// message, and it would make every importer (tests, tooling) unimportable. Instead the
// entrypoints call the assert in their guarded startup path (proxy.ts: the try block
// that prints `[safespace] <msg>` and exits 1; cli.ts: the top-level shim that prints
// `error: <msg>` and sets exitCode 1) and the two loaders re-assert at point of use
// (consent(), getGoogle()) so a process that bypasses an entrypoint still refuses before
// any credential-bearing call.
import { createRequire } from "node:module";

const ENV = "GOOGLE_SDK_NODE_LOGGING";
const loggingWasRequested = (process.env[ENV] ?? "") !== "";
delete process.env[ENV];

let backendDisabled = false;
try {
  const req = createRequire(import.meta.url);
  const fromAuthLib = createRequire(req.resolve("google-auth-library"));
  const utils = fromAuthLib("google-logging-utils") as { setBackend?: unknown };
  if (typeof utils.setBackend !== "function") throw new Error("setBackend unavailable");
  (utils.setBackend as (b: null) => void)(null);
  backendDisabled = true;
} catch {
  // Layer 1 failed. Harmless when logging was never requested (see assert below).
}

/** Throws a fixed, value-free error when SDK logging was requested but could not be disabled. */
export function assertSdkLoggingDisabled(): void {
  if (loggingWasRequested && !backendDisabled) {
    throw new Error(
      "GOOGLE_SDK_NODE_LOGGING is set but Google SDK logging could not be disabled; unset it and restart.",
    );
  }
}
