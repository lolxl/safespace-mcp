// v1.66.1 (B6.1a) — the shared per-call audit accumulator.
//
// WHY THIS EXISTS (architecture review post-Phase-C, P0-1 / thesis D6): before
// v1.66.1 the per-call audit "observability envelope" was BYTE-DUPLICATED across
// the two choke points — the `AuditSink.record()` switch and the ~10-field
// forensic block threaded into `auditEnd(...)` appeared verbatim in BOTH
// `with-context.ts` (OAuth) and `with-nonoauth-context.ts` (keyless / service-token).
// The credential path is already polymorphic + clean; the DUPLICATION was the
// observability layer — exactly the part that silently rots. Concrete drift risk:
// a future 8th meta channel (the next mutation connector) had to be hand-added to
// the `auditEnd` field-list in BOTH files; missing the non-OAuth one would record a
// service-token-outbound mutation to the sink but NEVER onto the audit row — a
// silent forensic hole on the path where forensics matter most.
//
// This module is the SINGLE SOURCE for both:
//   - `sink`           — the AuditSink handlers call via `ctx.audit.record(...)`.
//   - `forensicFields()` — the object spread into `auditEnd(...)` (the 3 scalar
//     channels + the 8 AUDIT_META_CHANNELS, read back from the aggregator).
//   - `metas`          — the MetaMapStore aggregator, exposed for the with-context
//     mutual-exclusion mutex check (the `_all` choke point does not run it).
//
// Behavior is byte-identical to the pre-v1.66.1 inline sinks: the `record()` switch
// and the forensic field set are the same; this only de-duplicates them.
//
// DRIFT DEFENSE (replaces the old per-file 4-layer doc): a new meta channel added
// to `MetaMap` is AUTOMATICALLY a valid `record()` target (the sink's `default`
// case is generic; `AuditSinkChannels extends MetaMap` in types.ts makes it
// compile-time). The ONE remaining hand-list is `forensicFields()`'s named meta
// keys — pinned by `audit-accumulator.test.ts` (asserts forensicFields covers every
// AUDIT_META_CHANNELS key), so a new channel without a forensicFields entry fails CI.

import { type MetaMap } from "../audit";
import { MetaMapStore } from "./meta-store";
import type { AuditChannel, AuditSink } from "./types";

/** The forensic fields spread into `auditEnd(...)` — the 3 scalar channels plus the
 *  per-channel meta from the aggregator. Keys/types mirror AuditEndContext's
 *  optional forensic fields exactly, so `...forensicFields()` type-checks at both
 *  choke points. */
export interface ForensicFields {
  resolvedRecipientHash: string | undefined;
  taintedSource: boolean | undefined;
  outboundSecretShape: string | undefined;
  commentPostMeta: MetaMap["commentPostMeta"] | undefined;
  calendarMutationMeta: MetaMap["calendarMutationMeta"] | undefined;
  docsModifyMeta: MetaMap["docsModifyMeta"] | undefined;
  commentDeleteMeta: MetaMap["commentDeleteMeta"] | undefined;
  tasksMutationMeta: MetaMap["tasksMutationMeta"] | undefined;
  sheetsMutationMeta: MetaMap["sheetsMutationMeta"] | undefined;
  playlistMutationMeta: MetaMap["playlistMutationMeta"] | undefined;
  videoMutationMeta: MetaMap["videoMutationMeta"] | undefined;
}

export interface AuditAccumulator {
  /** Hand to `ctx.audit`. Handlers record forensic metadata through it. */
  readonly sink: AuditSink;
  /** The meta-channel aggregator — exposed for the with-context.ts mutex check
   *  (iterate AUDIT_META_CHANNELS, warn if >1 meta set per call). */
  readonly metas: MetaMapStore;
  /** The forensic block to spread into `auditEnd(...)`. Reads the 3 scalars + each
   *  meta channel back from the aggregator (last-write-wins). */
  forensicFields(): ForensicFields;
}

/** Create a per-call audit accumulator. One per choke-point invocation. */
export function createAuditAccumulator(): AuditAccumulator {
  // The 3 SCALAR row channels (set once per call by the egress / contact-lookup
  // gates). Owned here as closure state so both choke points share one impl.
  let resolvedRecipientHash: string | undefined;
  let taintedSource: boolean | undefined;
  let outboundSecretShape: string | undefined;
  // The 8 AUDIT_META_CHANNELS aggregator (last-write-wins by Map semantics — 1:1
  // with the pre-v1.64 per-channel closures).
  const recordedMetas = new MetaMapStore();

  // Impl typed broad + `as AuditSink`: the generic-variadic public signature
  // (types.ts) gives call sites full type safety while the impl narrows internally
  // — the same bounded-cast the MetaMapStore bridge uses. NEVER records plaintext —
  // only hashes / flags / closed-set classes (see each *AuditMeta in audit.ts).
  const sink: AuditSink = {
    record(channel: AuditChannel, meta?: unknown): void {
      switch (channel) {
        case "resolvedRecipientHash":
          // v1.15 Phase 3 — last-write-wins; handlers call once after all
          // recipients resolved.
          resolvedRecipientHash = meta as string;
          return;
        case "taintedSource":
          // v1.56 F3b — idempotent set-true flag; never affects control flow.
          taintedSource = true;
          return;
        case "outboundSecretShape":
          // v1.57 F3a — last-write-wins; the closed-set shape class, never bytes.
          outboundSecretShape = meta as string;
          return;
        default:
          // ⚠️ A NEW SCALAR channel added to `AuditSinkChannels` MUST get its own
          // `case` above, or it falls through HERE, is stored under a non-`MetaMap`
          // key, and is SILENTLY DROPPED (auditEnd's serialize loop only iterates
          // AUDIT_META_CHANNELS). The scalar-channel coverage is pinned by
          // audit-accumulator.test.ts. One of the 8 AUDIT_META_CHANNELS otherwise:
          // Map.set replaces the prior value at the same key (last-write-wins) — the
          // docs_modify / sheets_create / playlist_create 2-step BEFORE/AFTER-SDK
          // recorders rely on this.
          recordedMetas.set(
            channel as keyof MetaMap,
            meta as MetaMap[keyof MetaMap],
          );
          return;
      }
    },
  } as AuditSink;

  return {
    sink,
    metas: recordedMetas,
    forensicFields(): ForensicFields {
      return {
        resolvedRecipientHash,
        taintedSource,
        outboundSecretShape,
        commentPostMeta: recordedMetas.get("commentPostMeta"),
        calendarMutationMeta: recordedMetas.get("calendarMutationMeta"),
        docsModifyMeta: recordedMetas.get("docsModifyMeta"),
        commentDeleteMeta: recordedMetas.get("commentDeleteMeta"),
        tasksMutationMeta: recordedMetas.get("tasksMutationMeta"),
        sheetsMutationMeta: recordedMetas.get("sheetsMutationMeta"),
        playlistMutationMeta: recordedMetas.get("playlistMutationMeta"),
        videoMutationMeta: recordedMetas.get("videoMutationMeta"),
      };
    },
  };
}
