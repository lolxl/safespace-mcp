// v1.74 — Model B PR-2b: the operator registry.
//
// A config file (`SAFESPACE_OPERATORS_FILE` → operators.json) maps a VERIFIED
// tailnet login → operator policy (operatorId / tier / allowedAccounts). It is the
// per-operator analogue of the single-operator `$SAFESPACE_OPERATOR_ID` +
// `$SAFESPACE_TIER` + active-account file (docs/v1.74-model-b-operator-auth.md §5).
//
// DEFAULT-DENY: a login absent from the registry is refused at the transport (§4.2)
// — there is NO anonymous / fallback operator on the HTTP path.
//
// FAIL-LOUD: `loadOperatorRegistry` throws on ANY shape violation (bad tier,
// malformed operatorId, duplicate/blank login, non-array allowedAccounts) so a
// misconfigured registry can NEVER silently widen access — the http transport
// refuses to start. (The "allowedAccounts ⊆ accounts.json" cross-check rides with
// PR-2c, where `allowedAccounts` is actually CONSUMED for account confinement; in
// 2b it is carried but unused, so cross-checking it against the live account index
// here would couple this module to the account store before there is a consumer.)
//
// Errors reference the offending ENTRY INDEX + field name, never the raw value —
// a malformed login/operatorId could carry control bytes the audit/operator-id
// gates exist to keep off stderr.

import { readFileSync, statSync } from "node:fs";
import { ENV_OPERATORS_FILE } from "../config";
import { isValidOperatorId } from "./operator-id";
import type { Tier } from "../tier";
import { BURST_MIN, BURST_MAX } from "../policy/write-burst";

const VALID_TIERS: ReadonlySet<string> = new Set<Tier>(["read", "write", "share"]);

// A tailnet login (Tailscale `UserProfile.LoginName`) is an `name@provider`
// identity (`alice@example.com`, `alice@github`). Require a single `@`, non-empty
// halves, no whitespace / control chars, bounded length. Exact-match lookup is
// what enforces identity; this just rejects obviously-malformed registry entries.
const TAILNET_LOGIN_RE = /^[^\s\x00-\x1f@]{1,128}@[^\s\x00-\x1f@]{1,128}$/;

export interface OperatorEntry {
  /** Normalized (lowercased) tailnet login — the WhoIs lookup key. */
  readonly tailnetLogin: string;
  readonly operatorId: string;
  readonly tier: Tier;
  /** The accounts this operator may resolve (PR-2c confinement consumes this; 2b
   *  carries it). An empty array is legal (the operator has no OAuth accounts —
   *  e.g. a read-only viewer of shared service-token channels). */
  readonly allowedAccounts: readonly string[];
  /** v1.92 — optional per-operator F1 burst caps. Absent → this operator uses the
   *  global env default. When present, validated to an integer in
   *  [BURST_MIN, BURST_MAX] at parse (fail-loud, never silently clamped). */
  readonly writeBurstLimit?: number;
  readonly deleteBurstLimit?: number;
}

export interface OperatorRegistry {
  /** Resolve a verified tailnet login → its operator policy, or null when the
   *  login is not registered (default-deny). Case-insensitive (logins are emails). */
  lookupByTailnetLogin(login: string): OperatorEntry | null;
  readonly size: number;
}

export interface LoadRegistryDeps {
  /** Test seam: defaults to `readFileSync(path, "utf8")`. */
  readFileImpl?: (path: string) => string;
  /** Override the env-configured path (tests / programmatic use). */
  operatorsFilePath?: string;
  /** v1.74 PR-2c — the consented-account email set (from accounts.json). When
   *  provided, EVERY `allowedAccounts` entry must be in it or the registry is
   *  rejected (fail-loud — a typo'd account can never silently deny at runtime).
   *  proxy.ts supplies it; omitting it (tests) skips the cross-check. */
  knownAccounts?: ReadonlySet<string>;
}

function fail(msg: string): never {
  throw new Error(`[safespace] operators registry invalid: ${msg}`);
}

/** Parse + validate raw operators.json content into an OperatorRegistry. Pure
 *  (no I/O, no env). Throws on the FIRST violation — fail-loud.
 *
 *  v1.74 PR-2c — when `knownAccounts` (the consented-account email set) is supplied,
 *  every `allowedAccounts` entry MUST be in it or the registry is rejected — a
 *  typo'd account can never silently deny at runtime. Omitted → cross-check skipped. */
export function parseOperatorRegistry(
  raw: string,
  knownAccounts?: ReadonlySet<string>,
): OperatorRegistry {
  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch {
    fail("not valid JSON");
  }
  if (doc == null || typeof doc !== "object" || Array.isArray(doc)) {
    fail("top-level must be an object with an `operators` array");
  }
  const operators = (doc as { operators?: unknown }).operators;
  if (!Array.isArray(operators)) {
    fail("`operators` must be an array");
  }

  const byLogin = new Map<string, OperatorEntry>();
  operators.forEach((rawEntry, i) => {
    if (rawEntry == null || typeof rawEntry !== "object" || Array.isArray(rawEntry)) {
      fail(`entry #${i} must be an object`);
    }
    const e = rawEntry as Record<string, unknown>;

    if (typeof e.tailnetLogin !== "string" || !TAILNET_LOGIN_RE.test(e.tailnetLogin)) {
      fail(`entry #${i}: \`tailnetLogin\` must be a name@provider identity`);
    }
    if (typeof e.operatorId !== "string" || !isValidOperatorId(e.operatorId)) {
      fail(`entry #${i}: \`operatorId\` must match ^[A-Za-z0-9_.-]{1,64}$`);
    }
    if (typeof e.tier !== "string" || !VALID_TIERS.has(e.tier)) {
      fail(`entry #${i}: \`tier\` must be one of read|write|share`);
    }
    if (
      !Array.isArray(e.allowedAccounts) ||
      e.allowedAccounts.some((a) => typeof a !== "string" || a.length === 0)
    ) {
      fail(`entry #${i}: \`allowedAccounts\` must be an array of non-empty strings`);
    }
    // v1.74 PR-2c — cross-check against the consented-account index (when supplied).
    // Reference the index, never echo the raw account value (a malformed file could
    // smuggle control bytes onto stderr).
    if (knownAccounts) {
      for (const a of e.allowedAccounts as string[]) {
        if (!knownAccounts.has(a)) {
          fail(`entry #${i}: an \`allowedAccounts\` entry is not a consented account`);
        }
      }
    }

    // v1.92 — optional per-operator F1 burst overrides. When present each must be
    // an integer in [BURST_MIN, BURST_MAX] (the same bounds the env readers clamp
    // to); absent → the operator uses the global env default. REJECT out-of-range
    // (fail-loud), never silently clamp — a typo'd cap must not widen the ceiling.
    const burst = (field: "writeBurstLimit" | "deleteBurstLimit"): number | undefined => {
      const v = e[field];
      if (v === undefined) return undefined;
      if (typeof v !== "number" || !Number.isInteger(v) || v < BURST_MIN || v > BURST_MAX) {
        fail(`entry #${i}: \`${field}\`, when set, must be an integer in [${BURST_MIN}, ${BURST_MAX}]`);
      }
      return v;
    };
    const writeBurstLimit = burst("writeBurstLimit");
    const deleteBurstLimit = burst("deleteBurstLimit");

    const loginKey = e.tailnetLogin.toLowerCase();
    if (byLogin.has(loginKey)) {
      fail(`entry #${i}: duplicate tailnetLogin (case-insensitive)`);
    }
    byLogin.set(loginKey, {
      tailnetLogin: loginKey,
      operatorId: e.operatorId,
      tier: e.tier as Tier,
      allowedAccounts: [...(e.allowedAccounts as string[])],
      ...(writeBurstLimit !== undefined ? { writeBurstLimit } : {}),
      ...(deleteBurstLimit !== undefined ? { deleteBurstLimit } : {}),
    });
  });

  return {
    size: byLogin.size,
    lookupByTailnetLogin(login: string): OperatorEntry | null {
      if (typeof login !== "string" || login.length === 0) return null;
      return byLogin.get(login.toLowerCase()) ?? null;
    },
  };
}

/** Load + validate the operators registry from `SAFESPACE_OPERATORS_FILE` (or the
 *  injected path). REQUIRED when `SAFESPACE_TRANSPORT=http`: throws fail-loud if the
 *  env is unset, the file is unreadable, or the content fails validation.
 *
 *  v1.80 PR-3 note: `proxy.ts` now constructs the hot-reloading
 *  `createRegistryProvider` (whose INITIAL load applies these exact semantics)
 *  instead of calling this directly; this one-shot form remains the validation
 *  reference + the test entry point. */
export function loadOperatorRegistry(deps: LoadRegistryDeps = {}): OperatorRegistry {
  const path = deps.operatorsFilePath ?? process.env[ENV_OPERATORS_FILE];
  if (path == null || path === "") {
    fail(`${ENV_OPERATORS_FILE} must be set when SAFESPACE_TRANSPORT=http`);
  }
  let raw: string;
  try {
    raw = (deps.readFileImpl ?? ((p: string) => readFileSync(p, "utf8")))(path);
  } catch {
    // Don't echo the path's content; the path itself is operator-supplied config.
    fail(`cannot read the operators file at the configured path`);
  }
  return parseOperatorRegistry(raw, deps.knownAccounts);
}

// ----- v1.80 PR-3 — hot-reload provider -----

/** The hot-reloading registry handle the http transport consumes (v1.80 PR-3 —
 *  the `v1.74 §12` "runtime registry reload" deferral). `current()` re-validates
 *  the file when its mtime changed; otherwise it returns the cached last-good
 *  instance, so a registry edit applies WITHOUT a restart (revocation bites on
 *  the operator's next request — transport/http.ts re-resolves per request). */
export interface OperatorRegistryProvider {
  current(): Promise<OperatorRegistry>;
}

export interface RegistryProviderDeps {
  /** Override the env-configured path (tests / programmatic use). */
  operatorsFilePath?: string;
  /** Test seam: defaults to `readFileSync(path, "utf8")`. */
  readFileImpl?: (path: string) => string;
  /** Test seam: the file's mtime in ms. Defaults to `statSync(path).mtimeMs`. */
  statMtimeImpl?: (path: string) => number;
  /** Re-read the consented-account email set for the reload-time
   *  `allowedAccounts ⊆ accounts.json` cross-check (consent may have added
   *  accounts since startup). Called once per (re)load. proxy.ts supplies the
   *  accounts.json read; omitting it (tests) skips the cross-check. A throw
   *  during a RELOAD is treated as an invalid replacement (keep last-good);
   *  a throw during the INITIAL load propagates (fail-loud startup). */
  loadKnownAccounts?: () => Promise<ReadonlySet<string> | undefined>;
}

/** Create the hot-reloading provider. The INITIAL load keeps the v1.74 startup
 *  posture byte-identical: any violation (missing env/file, bad JSON/shape,
 *  cross-check miss) THROWS, so `proxy.ts` still refuses to serve HTTP on a bad
 *  registry. RUNTIME replacement is fail-SAFE-keep-last-good: a bad edit (bad
 *  JSON / shape violation / cross-check miss / half-written file / deleted
 *  file) leaves the PREVIOUS registry enforced — the running server never
 *  crashes on an edit and never falls open (default-deny for unknown logins
 *  persists) — and warns ONCE per failed content on stderr (never echoing file
 *  content / account values / logins). The new mtime is recorded ONLY after a
 *  successful parse, so a half-written file is retried automatically on the
 *  next request. A per-request `stat` is microseconds at tool-call rate — no
 *  throttle. */
export async function createRegistryProvider(
  deps: RegistryProviderDeps = {},
): Promise<OperatorRegistryProvider> {
  const path = deps.operatorsFilePath ?? process.env[ENV_OPERATORS_FILE];
  if (path == null || path === "") {
    fail(`${ENV_OPERATORS_FILE} must be set when SAFESPACE_TRANSPORT=http`);
  }
  const readFile = deps.readFileImpl ?? ((p: string) => readFileSync(p, "utf8"));
  const statMtime = deps.statMtimeImpl ?? ((p: string) => statSync(p).mtimeMs);
  const loadKnownAccounts = deps.loadKnownAccounts ?? (async () => undefined);

  // Initial load — FAIL-LOUD (the v1.74 startup posture, unchanged). stat BEFORE
  // read: if the file is replaced between the two, the recorded mtime is older
  // than the content read, so the next current() re-reads (at worst one
  // redundant reload — never a missed one).
  let lastMtimeMs: number;
  let raw: string;
  try {
    lastMtimeMs = statMtime(path);
    raw = readFile(path);
  } catch {
    // Don't echo the path's content; the path itself is operator-supplied config.
    fail(`cannot read the operators file at the configured path`);
  }
  let lastGood = parseOperatorRegistry(raw, await loadKnownAccounts());
  // Warn-once bookkeeping — one warning per failed CONTENT, not one per request.
  // THREE states: `null` = nothing warned / the last (re)load succeeded;
  // `mtimeMs` = THAT content's parse/validation failure was already warned
  // (a fix writes a new mtime → eligible to warn again); `-1` = the
  // file-unreadable (stat-failure) warning fired (mtimeMs is never negative,
  // so -1 cannot collide with a real mtime).
  let warnedMtimeMs: number | null = null;

  return {
    async current(): Promise<OperatorRegistry> {
      let mtimeMs: number;
      try {
        mtimeMs = statMtime(path);
      } catch {
        // File deleted / unreadable at runtime → keep last-good, warn once.
        if (warnedMtimeMs !== -1) {
          warnedMtimeMs = -1;
          console.error(
            "[safespace] WARNING: operators file unreadable at runtime — keeping the last-good registry. Restore the file; it is re-checked on every request.",
          );
        }
        return lastGood;
      }
      if (mtimeMs === lastMtimeMs) return lastGood;
      try {
        const fresh = parseOperatorRegistry(readFile(path), await loadKnownAccounts());
        lastGood = fresh;
        lastMtimeMs = mtimeMs;
        warnedMtimeMs = null;
        // stderr, like the listen banner — counts only, no logins/accounts.
        console.error(
          `[safespace] operators registry reloaded (${fresh.size} operator(s))`,
        );
      } catch {
        if (warnedMtimeMs !== mtimeMs) {
          warnedMtimeMs = mtimeMs;
          console.error(
            "[safespace] WARNING: operators registry replacement is INVALID — keeping the last-good registry. Fix the file; it is re-validated on the next request.",
          );
        }
        // lastMtimeMs deliberately NOT updated → the next request retries.
      }
      return lastGood;
    },
  };
}
