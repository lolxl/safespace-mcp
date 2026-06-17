// v1.66.1 (B6.1a) — the shared audit accumulator: sink routing + the single-source
// forensicFields(), incl. the DRIFT-DEFENSE sentinel that forensicFields() covers
// every AUDIT_META_CHANNELS channel (so a new channel without a forensicFields entry
// fails CI — the whole point of de-duplicating the two choke points' audit envelope).

import { describe, expect, test } from "bun:test";
import { AUDIT_META_CHANNELS } from "../audit";
import { createAuditAccumulator } from "./audit-accumulator";

describe("createAuditAccumulator", () => {
  test("the 3 scalar channels route onto forensicFields()", () => {
    const acc = createAuditAccumulator();
    acc.sink.record("resolvedRecipientHash", "deadbeef");
    acc.sink.record("taintedSource");
    acc.sink.record("outboundSecretShape", "private_key");
    const f = acc.forensicFields();
    expect(f.resolvedRecipientHash).toBe("deadbeef");
    expect(f.taintedSource).toBe(true);
    expect(f.outboundSecretShape).toBe("private_key");
  });

  test("unrecorded channels are undefined (presence-as-signal → auditEnd omits them)", () => {
    const acc = createAuditAccumulator();
    const f = acc.forensicFields();
    expect(f.resolvedRecipientHash).toBeUndefined();
    expect(f.taintedSource).toBeUndefined();
    expect(f.outboundSecretShape).toBeUndefined();
    expect(f.tasksMutationMeta).toBeUndefined();
  });

  test("a meta channel routes through the aggregator onto forensicFields() + metas", () => {
    const acc = createAuditAccumulator();
    const meta = { operation: "create", list_id_hash: "h", task_id_hash: "t" };
    // Record through a loosely-typed view — this test pins ROUTING (sink → aggregator
    // → forensicFields), not the per-channel meta SHAPE (each *AuditMeta is pinned by
    // its own handler test).
    (acc.sink.record as (c: string, m?: unknown) => void)("tasksMutationMeta", meta);
    const got = acc.forensicFields() as unknown as Record<string, unknown>;
    expect(got.tasksMutationMeta).toEqual(meta);
    expect(acc.metas.has("tasksMutationMeta")).toBe(true);
    expect(acc.metas.size).toBe(1);
  });

  test("last-write-wins for a scalar + a meta channel", () => {
    const acc = createAuditAccumulator();
    acc.sink.record("resolvedRecipientHash", "first");
    acc.sink.record("resolvedRecipientHash", "second");
    expect(acc.forensicFields().resolvedRecipientHash).toBe("second");
  });

  // THE DRIFT-DEFENSE SENTINEL (architecture review P0-1): the single remaining
  // hand-list is forensicFields()'s named meta keys. If a future meta channel is
  // added to AUDIT_META_CHANNELS without a forensicFields() entry, it would record
  // to the sink but never reach the audit row (a silent forensic hole). This pins
  // that forensicFields() exposes a key for EVERY registry meta channel.
  test("forensicFields() exposes a key for EVERY AUDIT_META_CHANNELS channel", () => {
    const fieldKeys = new Set(Object.keys(createAuditAccumulator().forensicFields()));
    for (const channel of Object.keys(AUDIT_META_CHANNELS)) {
      expect(fieldKeys.has(channel), `forensicFields() must expose '${channel}'`).toBe(true);
    }
  });
});
