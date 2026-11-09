// TEST-ONLY `bun --preload` file (never imported by production code): makes layer 1
// of sdk-logging-guard.ts fail, to prove the guard fails closed when
// GOOGLE_SDK_NODE_LOGGING is set and stays out of the way when it is not.
// Mode comes from SDK_LOGGING_TEST_FAIL_MODE: "throw" (setBackend throws) |
// "missing" (setBackend is not a function).
import { createRequire } from "node:module";

const req = createRequire(import.meta.url);
// index.js re-exports through read-only getters; patch the implementation module
// they read from (live binding), which is a plain writable exports object.
const fromAuthLib = createRequire(req.resolve("google-auth-library"));
const utils = fromAuthLib(
  fromAuthLib.resolve("google-logging-utils").replace(/index\.js$/, "logging-utils.js"),
) as { setBackend?: unknown };
if (process.env["SDK_LOGGING_TEST_FAIL_MODE"] === "missing") {
  utils.setBackend = undefined;
} else {
  utils.setBackend = () => {
    throw new Error("injected setBackend failure");
  };
}
