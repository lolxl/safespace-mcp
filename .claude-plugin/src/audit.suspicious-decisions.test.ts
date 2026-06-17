// v1.24 Phase 1 Item 1 — AUDIT_META_CHANNELS suspiciousDecisions sentinel.
//
// Closes the 4th hardcoded-enum drift site (v1.23 Q5). The registry value
// shape was extended from {label, flatHash} → {label, flatHash,
// suspiciousDecisions?} so `cli/audit/suspicious.ts` derives its
// per-bucket category arrays via `collectByBucket()` (registry-driven)
// instead of 4 hardcoded const arrays.
//
// This file is a NAME-matched sentinel: when a future cycle adds a new
// audit-meta channel OR a new `policy_decision` value to an existing
// channel, the maintainer updates the channel's `suspiciousDecisions` in
// audit.ts AND the canonical-expected map below. The classifier in
// `cli/audit/suspicious.ts` picks up the new value automatically — no
// 3-4 site sync drift. Cross-test invariant: ALL 6 channels carry
// `suspiciousDecisions` (none omitted at v1.24); future channels MAY
// omit if they have no suspicious-track decisions.
//
// Pattern reference: audit.roundtrip.test.ts (v1.22 Phase 1 NEW-3
// closure) pins auditEnd's payload-write block contract; this file pins
// AUDIT_META_CHANNELS's suspiciousDecisions contract. Two distinct
// sentinel files for two distinct contracts.

import { describe, expect, test } from "bun:test";
import { AUDIT_META_CHANNELS, type SuspiciousClassification } from "./audit";

describe("AUDIT_META_CHANNELS suspiciousDecisions registry shape (v1.24 Phase 1 Item 1)", () => {
  test("all 6 channels carry a suspiciousDecisions object (v1.24 — none omitted)", () => {
    for (const [key, entry] of Object.entries(AUDIT_META_CHANNELS)) {
      expect(entry.suspiciousDecisions, `channel ${key} missing suspiciousDecisions`).toBeDefined();
    }
  });

  test("commentPostMeta high carries denied_outbound_sanitize_rejected (YouTube v1.16 Phase 2b canary)", () => {
    expect(AUDIT_META_CHANNELS.commentPostMeta.suspiciousDecisions.high).toContain(
      "denied_outbound_sanitize_rejected",
    );
  });

  test("sheetsMutationMeta high carries denied_formula_rejected (Sheets v1.21 canary)", () => {
    expect(AUDIT_META_CHANNELS.sheetsMutationMeta.suspiciousDecisions.high).toContain(
      "denied_formula_rejected",
    );
  });

  test("commentPostMeta medium_allowlist enumerates the 2 commentPost-only allowlist denials", () => {
    expect(AUDIT_META_CHANNELS.commentPostMeta.suspiciousDecisions.medium_allowlist).toEqual([
      "denied_no_allowlist",
      "denied_not_in_allowlist",
    ]);
  });

  test("commentPostMeta medium_burst carries denied_burst_limit (commentPost-only channel decision)", () => {
    expect(AUDIT_META_CHANNELS.commentPostMeta.suspiciousDecisions.medium_burst).toEqual([
      "denied_burst_limit",
    ]);
  });

  test("ALL 6 channels declare low_tier with denied_tier (cross-channel — tier denial applies anywhere)", () => {
    for (const [key, entry] of Object.entries(AUDIT_META_CHANNELS)) {
      expect(
        entry.suspiciousDecisions.low_tier,
        `channel ${key} missing low_tier denied_tier`,
      ).toContain("denied_tier");
    }
  });

  test("ONLY 2 channels declare HIGH-confidence canaries (commentPost + sheetsMutation)", () => {
    const highChannels: string[] = [];
    for (const [key, entry] of Object.entries(AUDIT_META_CHANNELS)) {
      if ((entry.suspiciousDecisions as SuspiciousClassification).high) highChannels.push(key);
    }
    expect(highChannels.sort()).toEqual(["commentPostMeta", "sheetsMutationMeta"]);
  });

  test("ONLY commentPostMeta declares medium_allowlist (allowlist denials are YouTube-only at v1.24)", () => {
    const allowlistChannels: string[] = [];
    for (const [key, entry] of Object.entries(AUDIT_META_CHANNELS)) {
      if ((entry.suspiciousDecisions as SuspiciousClassification).medium_allowlist) {
        allowlistChannels.push(key);
      }
    }
    expect(allowlistChannels).toEqual(["commentPostMeta"]);
  });

  test("ONLY commentPostMeta declares medium_burst (channel-level burst denial is YouTube-only at v1.24)", () => {
    const burstChannels: string[] = [];
    for (const [key, entry] of Object.entries(AUDIT_META_CHANNELS)) {
      if ((entry.suspiciousDecisions as SuspiciousClassification).medium_burst) {
        burstChannels.push(key);
      }
    }
    expect(burstChannels).toEqual(["commentPostMeta"]);
  });

  test("collected high union matches the v1.23 hardcoded HIGH_CONFIDENCE array (regression sentinel)", () => {
    // Forward-compat — bit-identical pre-/post-refactor: classifier's
    // HIGH_CONFIDENCE used to be a hardcoded literal array; now it is
    // registry-derived via collectByBucket("high"). This test sentinel
    // asserts the registry produces the same canonical 2-element union
    // (order-tolerant). A v1.25+ Slides channel adding a new HIGH
    // canary would bump this list — the maintainer updates the
    // expected array AND the new channel's `suspiciousDecisions.high`
    // simultaneously.
    const collected: string[] = [];
    for (const entry of Object.values(AUDIT_META_CHANNELS)) {
      const high = (entry.suspiciousDecisions as SuspiciousClassification).high;
      if (high) collected.push(...high);
    }
    expect(collected.sort()).toEqual(
      ["denied_formula_rejected", "denied_outbound_sanitize_rejected"].sort(),
    );
  });

  test("collected medium_allowlist union matches the v1.23 hardcoded ALLOWLIST_CATEGORIES array", () => {
    const collected: string[] = [];
    for (const entry of Object.values(AUDIT_META_CHANNELS)) {
      const ma = (entry.suspiciousDecisions as SuspiciousClassification).medium_allowlist;
      if (ma) collected.push(...ma);
    }
    expect(collected.sort()).toEqual(["denied_no_allowlist", "denied_not_in_allowlist"].sort());
  });

  test("collected low_tier union has denied_tier present 8 times (one per channel — de-dup happens in suspicious.ts)", () => {
    const collected: string[] = [];
    for (const entry of Object.values(AUDIT_META_CHANNELS)) {
      const lt = (entry.suspiciousDecisions as SuspiciousClassification).low_tier;
      if (lt) collected.push(...lt);
    }
    // 8 channels each contribute ["denied_tier"] — 8 raw entries pre-dedup
    // (v1.48 B4 added playlistMutationMeta; v1.106 added videoMutationMeta).
    // suspicious.ts dedupes via Set; this sentinel checks the registry contract pre-dedup.
    expect(collected).toEqual(["denied_tier", "denied_tier", "denied_tier", "denied_tier", "denied_tier", "denied_tier", "denied_tier", "denied_tier"]);
  });

  test("registry size stays at 8 (cross-references v1.18 / v1.19 / v1.20 size sentinel — bumping requires NEW localMetas + AuditEndContext + auditEnd write + suspiciousDecisions)", () => {
    expect(Object.keys(AUDIT_META_CHANNELS).length).toBe(8);
  });

  test("no channel declares NULL or empty-array suspiciousDecisions (use omit-the-field-entirely instead — keeps the satisfies clause loose)", () => {
    for (const [key, entry] of Object.entries(AUDIT_META_CHANNELS)) {
      expect(entry.suspiciousDecisions).not.toBeNull();
      const sd = entry.suspiciousDecisions as SuspiciousClassification;
      // Each declared bucket MUST be non-empty (declaring `high: []` would
      // mean "the channel has no HIGH canaries"; omit the field instead).
      for (const bucket of ["high", "medium_allowlist", "medium_burst", "low_tier"] as const) {
        const values = sd[bucket];
        if (values !== undefined) {
          expect(values.length, `channel ${key} bucket ${bucket} is empty`).toBeGreaterThan(0);
        }
      }
    }
  });
});
