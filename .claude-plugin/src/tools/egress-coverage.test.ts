// Egress-coverage sentinel — the machine-checked "external-reaching write ⇒
// gated" invariant (the R7 forcing function).
//
// WHY THIS EXISTS (thesis §6.1 / R7): the envelope's egress protection is the
// one part that is NOT fully applied by a single central choke point. tier +
// sanitize + audit + burst run universally inside the 3 choke points
// (with-context / with-nonoauth-context / with-all-accounts), but the recipient /
// public-surface gates live per-tool — the CENTRALIZED_EGRESS tools call the
// `tools/egress.ts` gate from their handlers (B3), the PIPELINE_EGRESS tools
// (B6.1 wave A1) have it fired BY the non-OAuth choke point via an egress
// descriptor, while drive_share_file + the YouTube comment/video writes carry
// their own bespoke handler gates. So a future connector tool that reaches an
// external party (a new "send" / "post" / "share") can be added at min_tier:write
// and ship with ZERO egress protection while *looking* protected — the exact R7
// trap.
//
// This sentinel removes the "looks protected" ambiguity by forcing EVERY
// write/share tool to be classified into exactly one bucket. A newly-added
// write/share tool that nobody classified is an orphan → this test FAILS → it
// cannot merge until its author answers "does this reach an external party, and
// if so where is its gate?". The maintenance cost of adding a name below IS the
// forcing function.
//
// This is a test-only invariant (no runtime behavior). It composes with the two
// adjacent registry sentinels: the v1.64-B0 `direction:"outbound-write"` set
// (registry.test.ts) and the v1.52-F1 `cross_account ⇒ min_tier:read` set.

import { describe, expect, test } from "bun:test";
import {
  CENTRALIZED_EGRESS,
  HANDLER_GATED_EXTERNAL,
  OWN_DATA_WRITE,
  PIPELINE_EGRESS,
} from "./egress-coverage.sets";
import { TOOL_REGISTRY } from "./registry";

/** Every write/share tool in the registry — the universe the partition covers.
 *  read-tier tools (no mutation) and cross_account `_all` tools (pinned
 *  min_tier:read by the F1 sentinel) are out of scope by construction. */
const allWriteShare = Object.entries(TOOL_REGISTRY)
  .filter(([, def]) => def.min_tier === "write" || def.min_tier === "share")
  .map(([name]) => name);

describe("egress-coverage sentinel — every write/share tool is classified", () => {
  test("the 4 buckets are pairwise disjoint (no tool double-classified)", () => {
    const overlap = (a: ReadonlySet<string>, b: ReadonlySet<string>) =>
      [...a].filter((x) => b.has(x));
    expect(overlap(CENTRALIZED_EGRESS, HANDLER_GATED_EXTERNAL)).toEqual([]);
    expect(overlap(CENTRALIZED_EGRESS, OWN_DATA_WRITE)).toEqual([]);
    expect(overlap(HANDLER_GATED_EXTERNAL, OWN_DATA_WRITE)).toEqual([]);
    // B6.1 wave A1 — a tool is EITHER handler-called-centralized OR pipeline-fired,
    // never both (a double classification would hide a double-fire).
    expect(overlap(CENTRALIZED_EGRESS, PIPELINE_EGRESS)).toEqual([]);
    expect(overlap(PIPELINE_EGRESS, HANDLER_GATED_EXTERNAL)).toEqual([]);
    expect(overlap(PIPELINE_EGRESS, OWN_DATA_WRITE)).toEqual([]);
  });

  test("EVERY write/share tool is classified — a new tool is an orphan until gated", () => {
    const classified = new Set([
      ...CENTRALIZED_EGRESS,
      ...PIPELINE_EGRESS,
      ...HANDLER_GATED_EXTERNAL,
      ...OWN_DATA_WRITE,
    ]);
    // Orphan: a write/share tool nobody put in a bucket. If this fires for a new
    // tool, decide whether it reaches an external party — if so, gate it and add
    // it to PIPELINE_EGRESS (preferred for a non-OAuth send: descriptor-carried,
    // choke-point-fired) or CENTRALIZED_EGRESS / HANDLER_GATED_EXTERNAL; if it
    // only writes the caller's own data, add it to OWN_DATA_WRITE.
    const unclassified = allWriteShare.filter((t) => !classified.has(t));
    expect(unclassified).toEqual([]);
    // Stale: a name in a bucket that is no longer a write/share tool (renamed or
    // removed) — keep the buckets honest.
    const stale = [...classified].filter((t) => !allWriteShare.includes(t));
    expect(stale).toEqual([]);
  });

  test("CENTRALIZED_EGRESS ∪ PIPELINE_EGRESS is EXACTLY the direction:'outbound-write' label set", () => {
    // The label and the gated sets must never drift: a tool labeled outbound-write
    // that is neither handler-called-centralized nor pipeline-fired (or vice-versa)
    // is the R7 hole this prevents. Disjointness is pinned above, so the union is
    // a real partition of the label set.
    const labelled = Object.entries(TOOL_REGISTRY)
      .filter(([, def]) => def.direction === "outbound-write")
      .map(([name]) => name)
      .sort();
    expect(labelled).toEqual([...CENTRALIZED_EGRESS, ...PIPELINE_EGRESS].sort());
  });

  test("no cross_account tool carries the outbound-write label (the withAllAccounts choke point has NO egress tripwire)", () => {
    // v1.116 — the runtime egress tripwire (internal_routing_error{egress_gate_not_fired})
    // lives ONLY in with-context.ts + with-nonoauth-context.ts. cross_account `_all` tools
    // are dispatched through withAllAccounts (a THIRD choke point) which has no such tripwire.
    // That omission is SAFE precisely because this pin holds: a cross_account tool is never
    // labeled outbound-write, so no outbound-write tool can slip past a tripwire-less path.
    // (It is also implied by the F1 sentinel `cross_account ⇒ min_tier:read` — a read tool is
    // never outbound-write — but pinning the intersection directly keeps the tripwire's
    // safety argument legible in this file.)
    const crossAccountOutbound = Object.entries(TOOL_REGISTRY)
      .filter(([, def]) => def.cross_account === true && def.direction === "outbound-write")
      .map(([name]) => name);
    expect(crossAccountOutbound).toEqual([]);
  });

  test("no HANDLER_GATED_EXTERNAL tool carries the outbound-write label", () => {
    // These are gated in-handler, NOT via egress.ts. Labeling one outbound-write
    // would falsely claim centralized coverage (and, post-B6.1, route it through
    // a pipeline-fired gate whose shape it doesn't match).
    for (const t of HANDLER_GATED_EXTERNAL) {
      expect(TOOL_REGISTRY[t]?.direction).toBeUndefined();
    }
  });
});
