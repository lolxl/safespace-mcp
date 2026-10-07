// The per-call context the choke points read: the privilege tier. Resolved from
// process env on every call (never snapshotted), so tests
// and a long-lived stdio process both honor env changes. `OperatorResolver` stays as
// the seam `createMcpServer` takes, which lets tests inject a fixed context.

import { currentTier, type Tier } from "../tier";

/** The resolved identity for one tool call. Assembled ONCE per call from env and
 *  read by the choke points in place of the process-global env. */
export interface OperatorContext {
  readonly tier: Tier;
}

/** Strategy: produce the OperatorContext for an inbound call. */
export interface OperatorResolver {
  resolve(): OperatorContext;
}

/** The tier comes from process env, re-read on every call. */
export class EnvOperatorResolver implements OperatorResolver {
  resolve(): OperatorContext {
    return {
      tier: currentTier(),
    };
  }
}

/** The per-call env-backed context (Model A). Used as the choke-point `op`
 *  parameter DEFAULT so existing callers (cli exec, tests) stay byte-identical.
 *
 *  ⚠️ Resolved PER CALL — NEVER snapshot at module/server construction. The
 *  project relies on env readers being functions, not snapshots (config.ts drift
 *  sentinels; tests mutate `process.env` between constructing a server and issuing
 *  a call). A frozen context would silently break that contract; this re-reads env
 *  on every call, so Model A stays byte-identical AND the env-mutation test
 *  contract survives. */
export function envOperatorContext(): OperatorContext {
  return new EnvOperatorResolver().resolve();
}
