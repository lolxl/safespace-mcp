import type { MetaMap } from "../audit";

/** v1.29 Phase 1 (closes v1.27 NEW-3 carry-forward) — typed wrapper
 *  around the v1.27 Phase 2 `Map<keyof typeof AUDIT_META_CHANNELS,
 *  unknown>` aggregator. Replaces unknown-typed storage + 6 `as` casts
 *  at the AuditEndContext bridge (`with-context.ts:472-494`) with a
 *  per-key TYPED set/get contract enforced at BOTH sites via TypeScript
 *  generic methods.
 *
 *  Internal storage stays `Map<keyof MetaMap, MetaMap[keyof MetaMap]>`
 *  — the public API methods are GENERIC and provide the per-key
 *  narrowing. Runtime behavior is byte-identical to a plain Map (this
 *  is a TypeScript-only construct).
 *
 *  Drift defense via TypeScript:
 *    - `.set(key, value)`: value type must match `MetaMap[key]`;
 *      mismatched types fail compile (`TS2345 not assignable`).
 *    - `.get(key)`: return type is `MetaMap[key] | undefined` (no
 *      `as` cast needed at consumption sites).
 *
 *  Q3 LOCK preserved: wrapper does NOT change AuditEndContext interface;
 *  v1.22 + v1.24 + v1.25 + v1.27 audit roundtrip / errorCode /
 *  serialize-refactor / suspicious-decisions / mutex-contract /
 *  recorder-symmetry tests pass UNCHANGED. v1.27 Q4 LOCKED Option A
 *  insertion-order semantics + O(1) `Map.size` mutex check + Q3 LOCK
 *  byte-stability are all preserved because the wrapper is a pure
 *  typing layer over `Map`.
 *
 *  Wrapper sits between the recorder fns (set side) and the auditEnd
 *  bridge (get side). The 6 `as` casts at the bridge in
 *  `with-context.ts` are eliminated in Phase 2 of this cycle. Phase 1
 *  ships the class only; Phase 2 wires it into `with-context.ts` and
 *  removes the casts. Companion sentinel tests:
 *    - `meta-store.test.ts` (this Phase) — typed set/get round-trip +
 *      `@ts-expect-error` compile-fail pins for cross-key wrong-type
 *      and typo-key
 *    - `with-context.bridge-typing.test.ts` (Phase 2) — runtime parity
 *      after bridge surgery
 *
 *  Why Option A wrapper (vs Option B per-key typed getter helper / D
 *  branded recorders + runtime check / E heterogeneous native Map): see
 *  design `docs/v1.29-audit-bridge-tightening.md` §6 Q1 LOCKED. Option
 *  B types only the read side (`.set()` stays `unknown` — future direct
 *  set bypass corrupts invariant). Option D adds hot-path runtime
 *  brand checks for marginal value. Option E is impossible — TS
 *  `Map<K, V>` requires single V; heterogeneous per-key typing is NOT
 *  supported natively.
 *
 *  Sec-rev hook references (design §8): #1 (compile-time guarantees at
 *  bridge — wrapper enforces per-key value-type invariant), #10
 *  (wrapper scales to 7th channel via MetaMap[K] mapped-type — adding a
 *  channel automatically extends the typed surface without code edits
 *  to the wrapper itself). */
export class MetaMapStore {
  // The internal Map uses a UNION value type (TS Map limitation: single
  // value type required). The public API methods are GENERIC and
  // provide per-key narrowing; the lone `as` cast inside `.get()` is
  // local + bounded — the wrapper trusts its own `.set()` invariant.
  private readonly map = new Map<keyof MetaMap, MetaMap[keyof MetaMap]>();

  set<K extends keyof MetaMap>(key: K, value: MetaMap[K]): void {
    this.map.set(key, value);
  }

  get<K extends keyof MetaMap>(key: K): MetaMap[K] | undefined {
    // The lone cast: storage is union-typed; typed `set` enforces the
    // per-key invariant on entry, so re-narrowing on exit is safe. The
    // cast cannot be removed without changing the storage shape (which
    // would require eliminating `keyof MetaMap` heterogeneity — see
    // Option E rejection in design §6 Q1).
    return this.map.get(key) as MetaMap[K] | undefined;
  }

  has<K extends keyof MetaMap>(key: K): boolean {
    return this.map.has(key);
  }

  get size(): number {
    return this.map.size;
  }

  keys(): IterableIterator<keyof MetaMap> {
    return this.map.keys();
  }

  entries(): IterableIterator<[keyof MetaMap, MetaMap[keyof MetaMap]]> {
    return this.map.entries();
  }
}
