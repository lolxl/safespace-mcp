// Entry point: the MCP server bootstrap. Runs the startup guards, then connects the
// server over stdio. The server DEFINITION lives in ./server.ts (`createMcpServer`) so
// tests can import it without triggering this file's startup side effects.
import { assertSdkLoggingDisabled } from "./google-api/sdk-logging-guard"; // MUST stay first: strips GOOGLE_SDK_NODE_LOGGING before any Google lib loads
import { createStdioTransport } from "./stdio-transport";
import { configDir } from "./auth/keychain";
import { enforceAutonomousTokenStorage } from "./auth/select-backend";
import { validateConnectors } from "./policy/connector-toggle";
import { enforceNoRetiredSettings } from "./policy/retired-settings";
import { createMcpServer } from "./server";
import { writeStartupMarker } from "./startup-marker";

// Startup hardening guards — fail loud + EARLY, before the MCP handshake, so a
// misconfigured deployment never serves a single tool. The catch prints the
// refusal to stderr and exits non-zero.
//
// v1.55 F6 — refuse to start an autonomous deployment on key-beside-ciphertext
// token storage (FileBackend KEY-FILE mode) unless the operator set a passphrase
// or the SAFESPACE_ALLOW_KEYFILE_AT_REST escape hatch. No-op when not autonomous,
// in passphrase mode, on Keychain, or with the escape hatch set.
//
// v1.127 — `validateConnectors()` refuses to start on an unrecognized
// SAFESPACE_CONNECTORS token (or a set that selects nothing), naming the offenders
// and printing every valid token. It lives HERE, in the guarded startup sequence,
// and deliberately NOT at module evaluation of policy/connector-toggle.ts: a throw
// during `import` would reach the MCP client as a bare "server disconnected" with
// no message at all, and would make server.ts unimportable by tests that have not
// pre-set the env. Fail-loud (not the fs-gate's warn-and-drop) because a dropped
// connector token is silent capability loss, the failure direction tier.ts names as
// the dangerous one. No-op when the variable is unset (Model A, byte-identical).
//
// Retired settings (policy/retired-settings.ts) are checked first: a deployment that
// still sets one expects a removed feature, e.g. a bound inbound webhook socket or the
// former SAFESPACE_ENFORCED refuse-to-start checklist.
try {
  // Fail closed if GOOGLE_SDK_NODE_LOGGING is set and the SDK logger could not be
  // switched off (it would print tokens / API data to stderr). No-op otherwise.
  assertSdkLoggingDisabled();
  enforceNoRetiredSettings();
  validateConnectors();
  enforceAutonomousTokenStorage();
} catch (e) {
  console.error(`[safespace] ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
}

// MCP over stdio — the only transport.
await createMcpServer().connect(createStdioTransport());

// v1.8.2 #7 / cold-path: write the startup marker AFTER the transport is
// connected, not before the handshake.
// `safespace doctor` reads it to detect "policy file modified after proxy
// started"; marking "serving began" a few ms later is equally valid and keeps
// the 2 best-effort disk syscalls (mkdir + write) off the time-to-first-tool
// path. Best-effort — write failure is logged to stderr and swallowed; never
// blocks proxy startup.
await writeStartupMarker(configDir());
