// v1.74 — Model B PR-2a: the OperatorContext seam (made REAL).
//
// Lineage: v1.36 (BLOCKER 2) landed this file as a type-only forward-declaration
// — `OperatorContext` with `operatorId`/`tier`/`policyScope`, "nothing constructs
// one yet". PR-2a is the cycle that makes it real: the choke points now read a
// resolved `OperatorContext` in place of the process-global env. The v1.36
// `policyScope` placeholder is SUPERSEDED by `allowedAccounts` per the merged
// design (docs/v1.74-model-b-operator-auth.md §2 + Q8): per-operator allowlists
// stay GLOBAL for this arc, so the per-operator scoping the envelope actually
// needs is OAuth-account confinement, not an allowlist partition.
//
// The NORTHBOUND mirror of the southbound Source / Credential strategy. One
// RESOLVED identity per call, two resolvers, and — the load-bearing invariant —
// NO `if (modelB)` branch anywhere: the choke points consume an `OperatorContext`
// and never know which resolver produced it. Model A is the DEGENERATE case (the
// resolver that reads env); Model B (PR-2b) is the resolver that reads a verified
// connection.
//
// PR-2a ships the RAIL ONLY:
//   - the OperatorContext type + the OperatorResolver interface,
//   - the Model-A `EnvOperatorResolver` (reproduces today's process-global env
//     reads: `resolveOperatorId()` + `currentTier()`, `allowedAccounts: null`),
//   - and the choke points read this context INSTEAD of calling currentTier() /
//     resolveOperatorId() directly.
// In production nothing yet passes a non-default resolver, so behavior is
// byte-identical (the suite is the net). The Model-B `ConnectionOperatorResolver`
// (Tailscale WhoIs → operators.json registry) lands in PR-2b; the
// `allowedAccounts` per-operator account confinement lands in PR-2c.

import { resolveOperatorId } from "./operator-id";
import { currentTier, type Tier } from "../tier";

/** The resolved northbound identity for one tool call. Assembled ONCE per call
 *  (Model A: from env; Model B: from the session's verified connection) and read
 *  by the choke points in place of the process-global env. */
export interface OperatorContext {
  /** The human operator id stamped on the audit row — NOT a Google account email
   *  (see identity/operator-id.ts). Model A: `$SAFESPACE_OPERATOR_ID`, which is
   *  `null` when unset/malformed (the v1.36 stub typed this `string`; the honest
   *  type is `string | null` — `resolveOperatorId()` has always returned null for
   *  the single-user default). Model B (PR-2b): the connection-derived id — never
   *  null, because an unidentified connection is refused before any context
   *  exists. */
  readonly operatorId: string | null;
  /** This operator's privilege tier. Model A: `currentTier()` (`$SAFESPACE_TIER`).
   *  Model B (PR-2b): the operator-registry tier for this operator. */
  readonly tier: Tier;
  /** The accountIds this operator may resolve a credential against. `null` = "no
   *  restriction" (Model A: the single global active-account set = today's
   *  behavior). Model B (PR-2c): the registry's allow-set; account resolution is
   *  confined to it (cross-operator account isolation). PR-2a always produces
   *  null — the confinement consumer lands in PR-2c. */
  readonly allowedAccounts: readonly string[] | null;
  /** v1.92 — this operator's per-operator F1 write/delete burst caps (registry
   *  override). Absent / null = use the global env default (`getWriteBurstLimit()`
   *  / `getDeleteBurstLimit()`). Model A leaves them absent → byte-identical to the
   *  pre-v1.92 process-wide caps. Already validated to [BURST_MIN, BURST_MAX] at
   *  registry parse; the F1 gate keys on `operatorId` and reads these as the cap. */
  readonly writeBurstLimit?: number | null;
  readonly deleteBurstLimit?: number | null;
}

/** Strategy: produce the OperatorContext for an inbound call. Model A's
 *  `EnvOperatorResolver` ignores any connection; Model B's
 *  `ConnectionOperatorResolver` (PR-2b) is constructed bound to one session's
 *  verified connection and returns that operator's context. */
export interface OperatorResolver {
  resolve(): OperatorContext;
}

/** Model A (the degenerate case): the operator/tier come from process env, exactly
 *  as every choke point read them before v1.74. `allowedAccounts` is null (no
 *  per-operator confinement under single-operator Model A). */
export class EnvOperatorResolver implements OperatorResolver {
  resolve(): OperatorContext {
    return {
      operatorId: resolveOperatorId(),
      tier: currentTier(),
      allowedAccounts: null,
    };
  }
}

/** Model B (PR-2b, supplier-based since v1.80 PR-3): the resolver for ONE
 *  authenticated connection. The transport resolves the connection's verified
 *  tailnet identity (WhoIs) → operator-registry entry → `OperatorContext` at
 *  session init, then constructs this resolver bound to a SUPPLIER of that
 *  session's CURRENT context. v1.80 made the registry hot-reloadable and the
 *  transport re-resolves the session's login per request — `resolve()` reads
 *  the supplier so a registry tier / `allowedAccounts` change applies on the
 *  operator's NEXT call (the v1.74 form froze the context for the session's
 *  lifetime). The IDENTITY (who) still never changes mid-session — only the
 *  registry-side POLICY (tier/accounts) can.
 *
 *  An unidentified / unregistered connection is refused BEFORE this is ever
 *  constructed (default-deny), and a mid-session REMOVAL is refused by the
 *  transport (403 + teardown) BEFORE dispatch — so the supplier always
 *  observes a real, registered operator. */
export class ConnectionOperatorResolver implements OperatorResolver {
  constructor(private readonly supplier: () => OperatorContext) {}
  resolve(): OperatorContext {
    return this.supplier();
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
