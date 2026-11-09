// SDK debug logging must never emit credentials or user data.
//
// google-auth-library >= 10 logs token-endpoint bodies and API response data
// through default transporter interceptors when GOOGLE_SDK_NODE_LOGGING is set.
// This runs the REAL libraries in a subprocess (the bun test preload mocks gaxios
// in-process) with GOOGLE_SDK_NODE_LOGGING=* and asserts no sentinel secret is
// written to stdout/stderr. See sdk-logging-guard.ts for the switch analysis.

import { describe, expect, test } from "bun:test";
import { join } from "node:path";

const FIXTURE = join(import.meta.dir, "sdk-logging-fixture.ts");
const SENTINELS = [
  "SENTINEL-ACCESS-TOKEN-7f3a",
  "SENTINEL-REFRESH-TOKEN-9c1d",
  "SENTINEL-ID-TOKEN-2b8e",
  "SENTINEL-USER-DATA-4e6f",
];

const FAIL_PRELOAD = join(import.meta.dir, "sdk-logging-fail-preload.ts");
const SRC = join(import.meta.dir, "..");
const FIXED_MSG =
  "GOOGLE_SDK_NODE_LOGGING is set but Google SDK logging could not be disabled; unset it and restart.";

interface RunResult {
  out: string;
  err: string;
  code: number;
}

/** Spawn `bun [--preload fail] <script> <args>`; `loggingValue` undefined = variable ABSENT. */
async function spawnBun(
  script: string,
  args: string[],
  loggingValue: string | undefined,
  failMode?: "throw" | "missing",
): Promise<RunResult> {
  const env: Record<string, string | undefined> = { ...process.env };
  delete env["GOOGLE_SDK_NODE_LOGGING"];
  if (loggingValue !== undefined) env["GOOGLE_SDK_NODE_LOGGING"] = loggingValue;
  if (failMode) env["SDK_LOGGING_TEST_FAIL_MODE"] = failMode;
  const argv = [process.execPath, ...(failMode ? ["--preload", FAIL_PRELOAD] : []), script, ...args];
  const proc = Bun.spawn(argv, { stdout: "pipe", stderr: "pipe", stdin: "ignore", env });
  const killer = setTimeout(() => proc.kill(), 25_000);
  const [out, err] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
  const code = await proc.exited;
  clearTimeout(killer);
  return { out, err, code };
}

const run = (scenario: string, loggingValue: string): Promise<RunResult> =>
  spawnBun(FIXTURE, [scenario], loggingValue);

describe("GOOGLE_SDK_NODE_LOGGING cannot leak credentials / user data", () => {
  for (const value of ["*", "auth", "all", "true"]) {
    for (const scenario of ["token_exchange", "api_call"]) {
      test(`${scenario} with GOOGLE_SDK_NODE_LOGGING=${value}: no sentinel on stdout/stderr`, async () => {
        const { out, err } = await run(scenario, value);
        // The flow really ran (sentinels really crossed the interceptors)...
        expect(out).toContain('"ok":true');
        // ...and none of it was logged.
        for (const s of SENTINELS) {
          expect(out).not.toContain(s);
          expect(err).not.toContain(s);
        }
      }, 30_000);
    }
  }
});

// Layer 1 (setBackend(null)) forced to fail via a TEST-ONLY --preload (no production
// switch exists). Fail closed only when the variable was actually set.
describe("sdk-logging guard fails closed only when logging was requested", () => {
  for (const mode of ["throw", "missing"] as const) {
    test(`[${mode}] GOOGLE_SDK_NODE_LOGGING=* + layer 1 failed: api_call refuses, nothing logged`, async () => {
      const r = await spawnBun(FIXTURE, ["api_call"], "*", mode);
      expect(r.code).not.toBe(0);
      expect(r.out).toContain('"ok":false');
      expect(r.out).toContain(FIXED_MSG);
      for (const s of SENTINELS) {
        expect(r.out).not.toContain(s);
        expect(r.err).not.toContain(s);
      }
    }, 30_000);

    test(`[${mode}] GOOGLE_SDK_NODE_LOGGING=* + layer 1 failed: consent() refuses before any network step`, async () => {
      const r = await spawnBun(FIXTURE, ["consent"], "*", mode);
      expect(r.code).not.toBe(0);
      expect(r.out).toContain(FIXED_MSG);
      for (const s of SENTINELS) expect(r.out + r.err).not.toContain(s);
    }, 30_000);

    test(`[${mode}] variable ABSENT + layer 1 failed: flows still run`, async () => {
      for (const scenario of ["token_exchange", "api_call"]) {
        const r = await spawnBun(FIXTURE, [scenario], undefined, mode);
        expect(r.code).toBe(0);
        expect(r.out).toContain('"ok":true');
        expect(r.out + r.err).not.toContain(FIXED_MSG);
      }
    }, 30_000);

    test(`[${mode}] variable set but EMPTY + layer 1 failed: treated as absent`, async () => {
      const r = await spawnBun(FIXTURE, ["api_call"], "", mode);
      expect(r.code).toBe(0);
      expect(r.out).toContain('"ok":true');
    }, 30_000);

    test(`[${mode}] CLI entrypoint refuses (error: <fixed msg>, exit 1) when set; runs when absent`, async () => {
      const bad = await spawnBun(join(SRC, "cli.ts"), ["status"], "*", mode);
      expect(bad.code).toBe(1);
      expect(bad.err).toContain(`error: ${FIXED_MSG}`);
      const ok = await spawnBun(join(SRC, "cli.ts"), ["status"], undefined, mode);
      expect(ok.code).toBe(0);
      expect(ok.err).not.toContain(FIXED_MSG);
    }, 30_000);

    test(`[${mode}] proxy entrypoint refuses with [safespace] <fixed msg>, exit 1, before serving`, async () => {
      const bad = await spawnBun(join(SRC, "proxy.ts"), [], "*", mode);
      expect(bad.code).toBe(1);
      expect(bad.err).toContain(`[safespace] ${FIXED_MSG}`);
      expect(bad.out).toBe("");
    }, 30_000);
  }

  test("the fixed message never echoes the variable's value", async () => {
    const r = await spawnBun(FIXTURE, ["api_call"], "super-secret-looking-value", "throw");
    expect(r.out + r.err).not.toContain("super-secret-looking-value");
    expect(r.out).toContain(FIXED_MSG);
  }, 30_000);
});
