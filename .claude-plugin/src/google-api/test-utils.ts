/**
 * v1.11 Phase 1b — gaxios mock infrastructure for googleapis tests.
 *
 * Architectural note: the v1.11 ADR specified MSW / undici interceptors
 * (transport-level mocks) as the preferred test infrastructure. Phase 1a
 * spike validated that MSW does NOT intercept under Bun for googleapis
 * (Bun's `node:http` polyfill doesn't take the monkeypatch). Fallback:
 * mock at `gaxios` (googleapis' HTTP-client layer) via Bun's `mock.module`.
 *
 * Trade-off vs MSW: SDK-level instead of transport-level. We lose
 * adversarial parity for raw HTTP/2 / TLS quirks, but those concerns
 * are bounded by `gaxios`'s own error surface (`GaxiosError` with
 * `response.status`, `code`, etc.) which our tests CAN simulate by
 * throwing the right shapes from the mocked handler. Acceptable for our
 * threat model (LLM prompt-injection of tool args, NOT transport attacks).
 *
 * Usage — IMPORTANT: use `await import(...)` inside each test, NOT static
 * imports, for any module that transitively imports `googleapis`. Static
 * imports are subject to ESM hoist ordering, and any test file that loads
 * before this one and transitively imports googleapis will cache `gaxios`
 * BEFORE `mock.module("gaxios", ...)` fires — defeating the mock silently.
 *
 * `bunfig.toml` `preload` mitigates this when running the full `bun test`
 * suite (test-utils loads first, mock installs first), but order is fragile
 * and standalone test runs can still mis-order. Dynamic import inside the
 * test body is the bulletproof pattern.
 *
 *   import { setGaxiosHandler, makeGaxiosError, resetGaxiosHandler } from "./test-utils";
 *   import type { AuthDeps } from "./auth";  // type-only — does NOT load gaxios
 *
 *   beforeEach(() => resetGaxiosHandler());
 *
 *   test("rate-limit maps to MCPError", async () => {
 *     setGaxiosHandler(() => {
 *       throw makeGaxiosError({ status: 429, errorStatus: "RESOURCE_EXHAUSTED" });
 *     });
 *     // Dynamic import — guarantees gaxios mock is in place first.
 *     const { getGmailClient } = await import("./client");
 *     // ... use getGmailClient + assert MCPError("rate_limited") thrown ...
 *   });
 */

import { dirname, join } from "node:path";
import { beforeEach, mock } from "bun:test";
// refresh.ts holds a process-level in-memory TokenSet cache (per-call hot-path
// optimization). Reset it before EVERY test so a token cached by one test cannot
// satisfy a later test that expects a cache miss (account_not_found / forced
// refresh / mutex assertions). Imported here (the global preload) so the reset
// is universal — refresh.ts pulls in no `gaxios`, so the mock.module ordering
// below is unaffected.
import { _resetTokenCacheForTests } from "../auth/refresh";

beforeEach(() => {
  _resetTokenCacheForTests();
});

export interface GaxiosMockResponse<T = unknown> {
  data: T;
  status: number;
  headers?: Record<string, string>;
  statusText?: string;
}

export interface GaxiosRequestOptions {
  url?: string;
  method?: string;
  /** JSON payload (gaxios auto-serializes). */
  data?: unknown;
  /** Raw request body (used for pre-formatted bodies like multipart/mixed). */
  body?: unknown;
  params?: Record<string, unknown>;
  headers?: Record<string, string>;
  responseType?: string;
}

export type GaxiosHandler = (
  opts: GaxiosRequestOptions,
) => Promise<GaxiosMockResponse> | GaxiosMockResponse;

// Module-level handler — tests reassign via setGaxiosHandler.
let currentHandler: GaxiosHandler = () => {
  throw new Error(
    "test-utils: gaxios handler not set — call setGaxiosHandler() in your test or beforeEach()",
  );
};

// Install the mock AT IMPORT TIME so test files importing this module before
// any googleapis-touching code get the mock applied first. Bun's mock.module
// patches the resolved module registry; later imports of 'gaxios' get the
// mocked version.
const fakeGaxiosModule = {
  Gaxios: class FakeGaxios {
    // googleapis-common >= gaxios 7 calls the static `Gaxios.mergeHeaders`
    // and then `.set()`s on the result — it must be a WHATWG `Headers`.
    static mergeHeaders(base?: ConstructorParameters<typeof Headers>[0], ...more: ConstructorParameters<typeof Headers>[0][]): Headers {
      const merged = new Headers(base ?? {});
      for (const extra of more) {
        new Headers(extra ?? {}).forEach((v, k) => merged.set(k, v));
      }
      return merged;
    }
    // AuthClient registers a request interceptor on its transporter at
    // construction; the fake never runs interceptors, it only needs `.add`.
    interceptors = { request: new Set<unknown>(), response: new Set<unknown>() };
    async request(rawOpts: GaxiosRequestOptions) {
      // Handlers see headers as a plain object (the contract the tests were
      // written against), whatever shape gaxios hands in. `Headers` lower-cases
      // names, so lookups go through a case-insensitive proxy to keep
      // `headers["Content-Type"]`-style reads working.
      const opts: GaxiosRequestOptions =
        rawOpts.headers &&
        typeof (rawOpts.headers as unknown as Headers).forEach === "function"
          ? {
              ...rawOpts,
              headers: new Proxy(
                Object.fromEntries(
                  (rawOpts.headers as unknown as Headers).entries(),
                ),
                {
                  get: (t, k) =>
                    typeof k === "string" ? t[k.toLowerCase()] : undefined,
                },
              ),
            }
          : rawOpts;
      // Real gaxios hands back the body in the REQUESTED shape: a raw STRING for
      // `responseType: "text"` (gmail batch), and for a non-2xx `"stream"` it
      // buffers the stream into a string before building the GaxiosError. The
      // handlers' fixtures speak objects, so serialise here to keep the mock
      // faithful (errors.ts must parse the string; an object would hide that).
      const asRequestedShape = (v: unknown): unknown =>
        (rawOpts.responseType === "text" || rawOpts.responseType === "stream") &&
        v !== null &&
        typeof v === "object" &&
        !(v instanceof Uint8Array) &&
        typeof (v as { pipe?: unknown }).pipe !== "function"
          ? JSON.stringify(v)
          : v;
      let response: GaxiosMockResponse;
      try {
        response = await currentHandler(opts);
      } catch (e) {
        const r = (e as { response?: { data?: unknown } } | null)?.response;
        if (r && typeof r === "object" && "data" in r) {
          r.data = asRequestedShape(r.data);
        }
        throw e;
      }
      return {
        ...response,
        config: opts,
        headers: response.headers ?? {},
        statusText: response.statusText ?? "OK",
      };
    }
  },
  // Re-export the error class shape googleapis catches against.
  GaxiosError: class GaxiosError extends Error {
    response?: unknown;
    code?: string;
    constructor(
      message: string,
      opts?: { response?: unknown; code?: string },
    ) {
      super(message);
      this.name = "GaxiosError";
      this.response = opts?.response;
      this.code = opts?.code;
    }
  },
};

// gaxios >= 7 ships separate CJS and ESM builds behind `exports`; googleapis'
// CJS code `require()`s the CJS build while ESM importers get the ESM build,
// and Bun's mock.module keys on the RESOLVED path. Mock the bare specifier and
// both builds so every importer gets the same fake.
const gaxiosDir = dirname(require.resolve("gaxios"));
for (const spec of [
  "gaxios",
  join(gaxiosDir, "index.js"),
  join(gaxiosDir, "../../esm/src/index.js"),
]) {
  mock.module(spec, () => fakeGaxiosModule);
}

/** Set the per-test gaxios mock handler. */
export function setGaxiosHandler(handler: GaxiosHandler): void {
  currentHandler = handler;
}

/** Reset to the default "no handler installed" throwing behavior. Call in beforeEach. */
export function resetGaxiosHandler(): void {
  currentHandler = () => {
    throw new Error(
      "test-utils: gaxios handler not set — call setGaxiosHandler()",
    );
  };
}

export interface MakeGaxiosErrorOpts {
  /** HTTP status code (omit for network errors). */
  status?: number;
  /** Google's API-level error status string (e.g., "PERMISSION_DENIED"). */
  errorStatus?: string;
  /** Top-level error message from Google. */
  errorMessage?: string;
  /** Per-error detail entries (reason fields). */
  errors?: Array<{ reason?: string; message?: string; domain?: string }>;
  /** Network error code (e.g., "ECONNRESET") — only used when status is undefined. */
  code?: string;
}

/**
 * Build a GaxiosError-shaped object that `mapGoogleError` will recognize.
 * Used by tests to throw from inside the handler:
 *
 *   setGaxiosHandler(() => { throw makeGaxiosError({ status: 429 }); });
 */
export function makeGaxiosError(opts: MakeGaxiosErrorOpts): Error {
  const err = new Error(
    opts.errorMessage ?? (opts.status ? `HTTP ${opts.status}` : "Network error"),
  ) as Error & {
    response?: unknown;
    code?: string;
    config?: unknown;
  };
  err.name = "GaxiosError";
  // googleapis' internal error handler accesses `.config.data` on the error
  // (separately from `.response.data`) — without it, the SDK crashes with
  // "undefined is not an object (evaluating 'res.config.data')" before our
  // catch block sees the error. Empty object is sufficient.
  err.config = { data: undefined };
  if (opts.code !== undefined) {
    err.code = opts.code;
  }
  if (opts.status !== undefined) {
    err.response = {
      status: opts.status,
      data: {
        error: {
          code: opts.status,
          message: opts.errorMessage ?? `HTTP ${opts.status}`,
          status: opts.errorStatus,
          errors: opts.errors,
        },
      },
      config: { data: undefined },
    };
  }
  return err;
}
