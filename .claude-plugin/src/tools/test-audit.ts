// v1.64 Phase B (B1 — audit facade) test helper.
//
// Before B1, tests captured forensic metadata by hanging an inline `record*`
// closure on a ToolContext literal (e.g. `recordTasksMutationMeta: (m) => {
// captured = m; }`) and asserting the captured variable. B1 replaced the 10
// `record*` closures with ONE `ctx.audit.record(channel, meta)` sink, so tests
// capture through this helper instead:
//
//   const rec = capturingAudit();
//   const ctx: ToolContext = { ...BASE, audit: rec.sink };
//   await handler(ctx, args);
//   expect(rec.last("tasksMutationMeta")).toEqual({ ... });
//   expect(rec.has("taintedSource")).toBe(true);   // flag channel
//
// Read-tool tests that record nothing use the shared NOOP_AUDIT.

import type {
  AuditChannel,
  AuditSink,
  AuditSinkChannels,
  Credential,
} from "./types";

/** v1.64 Phase B (B2 — Credential union) test helper. Before B2, tests built a
 *  ToolContext with sibling `email` + `getAccessToken` fields; B2 nests those in
 *  the `oauth` Credential variant. This collapses the pair into one property:
 *
 *    const ctx: ToolContext = {
 *      credential: oauthCred("alice@example.com", () => FAKE_TOKEN),
 *      tier, audit: NOOP_AUDIT,
 *    };
 *
 *  Both args default so a test that doesn't care about identity/token can write
 *  `oauthCred()`. Handlers reach `.accountId` / `.getAccessToken()` via
 *  `requireOAuth(ctx)`. */
export function oauthCred(
  accountId = "alice@example.com",
  getAccessToken: () => string = () => "<test-token>",
): Credential {
  return { kind: "oauth", provider: "google", accountId, getAccessToken };
}

/** v1.66 Phase C PR 2 (Credential union) test helper — the service-token analogue
 *  of {@link oauthCred}. Builds the `service-token` Credential variant a class-B
 *  connector handler (LINE) narrows via `requireServiceToken(ctx)`:
 *
 *    const ctx: ToolContext = {
 *      credential: serviceTokenCred(() => "channel-tok"),
 *      tier, audit: NOOP_AUDIT,
 *    };
 *
 *  The arg defaults so a test that doesn't care about the value can write
 *  `serviceTokenCred()`. */
export function serviceTokenCred(
  token: () => string = () => "<test-service-token>",
): Credential {
  return { kind: "service-token", token };
}

export interface CapturingAudit {
  /** Hand this to `ctx.audit`. */
  readonly sink: AuditSink;
  /** Every record() call in order (the audit-facade equivalent of the old
   *  per-channel capture closures). */
  readonly calls: ReadonlyArray<{ channel: AuditChannel; meta: unknown }>;
  /** Most-recent meta recorded for `channel` (last-write-wins — matches the
   *  production MetaMapStore/scalar semantics); undefined if never recorded. */
  last<C extends AuditChannel>(channel: C): AuditSinkChannels[C] | undefined;
  /** Whether `channel` was recorded at all (presence-as-signal — the natural
   *  assertion for flag channels like "taintedSource"). */
  has(channel: AuditChannel): boolean;
  /** How many times `channel` was recorded (e.g. the sheets/playlist 2-step). */
  count(channel: AuditChannel): number;
}

/** A capturing AuditSink for tests. The `as AuditSink` cast mirrors the
 *  with-context.ts production impl: the broad-param impl satisfies the generic-
 *  variadic public signature, and call sites keep full type safety. */
export function capturingAudit(): CapturingAudit {
  const calls: Array<{ channel: AuditChannel; meta: unknown }> = [];
  const sink: AuditSink = {
    record(channel: AuditChannel, meta?: unknown): void {
      calls.push({ channel, meta });
    },
  } as AuditSink;
  return {
    sink,
    calls,
    last<C extends AuditChannel>(channel: C): AuditSinkChannels[C] | undefined {
      for (let i = calls.length - 1; i >= 0; i--) {
        if (calls[i]!.channel === channel) return calls[i]!.meta as AuditSinkChannels[C];
      }
      return undefined;
    },
    has(channel: AuditChannel): boolean {
      return calls.some((c) => c.channel === channel);
    },
    count(channel: AuditChannel): number {
      return calls.filter((c) => c.channel === channel).length;
    },
  };
}

/** Shared no-op sink for read-tool tests that never record forensic meta. */
export const NOOP_AUDIT: AuditSink = { record() {} } as AuditSink;

/** An AuditSink that dispatches each recorded channel to a per-channel capture
 *  callback — the drop-in replacement for the pre-B1 inline `record*` closures.
 *  A test that used `recordTasksMutationMeta: (m) => { captured = m; }` becomes
 *  `audit: recorderSink({ tasksMutationMeta: (m) => { captured = m; } })`, with
 *  the closure body + the asserted capture variable UNCHANGED. The callback's
 *  parameter is typed per channel via `AuditSinkChannels[C]`, so a meta-channel
 *  body keeps its concrete `*AuditMeta` typing and a scalar body keeps `string`.
 *  Handles single- and multi-channel capture uniformly (the v1.17 Phase 3
 *  mutual-exclusion test records into several channels through one ctx). */
export function recorderSink(
  captures: Partial<{ [C in AuditChannel]: (meta: AuditSinkChannels[C]) => void }>,
): AuditSink {
  const map = captures as Record<string, (meta: unknown) => void>;
  return {
    record(channel: AuditChannel, meta?: unknown): void {
      const fn = map[channel];
      if (fn) fn(meta);
    },
  } as AuditSink;
}
