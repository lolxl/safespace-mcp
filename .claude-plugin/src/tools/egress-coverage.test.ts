// Egress-coverage sentinel — the machine-checked "external-reaching write ⇒
// gated" invariant (the R7 forcing function).
//
// WHY THIS EXISTS (thesis §6.1 / R7): the envelope's egress protection is the
// one part that is NOT applied by a single central choke point. tier + sanitize
// + audit + burst run universally inside the 3 choke points (with-context /
// with-nonoauth-context / with-all-accounts), but the recipient / public-surface
// gates live per-tool — 8 tools go through the centralized `tools/egress.ts`
// gate, while drive_share_file + the two YouTube comment-write tools carry their
// own bespoke handler gates. So a future connector tool that reaches an external
// party (a new "send" / "post" / "share") can be added at min_tier:write and ship
// with ZERO egress protection while *looking* protected — the exact R7 trap.
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
} from "./egress-coverage.sets";
import { TOOL_REGISTRY } from "./registry";

/** Every write/share tool in the registry — the universe the partition covers.
 *  read-tier tools (no mutation) and cross_account `_all` tools (pinned
 *  min_tier:read by the F1 sentinel) are out of scope by construction. */
const allWriteShare = Object.entries(TOOL_REGISTRY)
  .filter(([, def]) => def.min_tier === "write" || def.min_tier === "share")
  .map(([name]) => name);

describe("egress-coverage sentinel — every write/share tool is classified", () => {
  test("the 3 buckets are pairwise disjoint (no tool double-classified)", () => {
    const overlap = (a: ReadonlySet<string>, b: ReadonlySet<string>) =>
      [...a].filter((x) => b.has(x));
    expect(overlap(CENTRALIZED_EGRESS, HANDLER_GATED_EXTERNAL)).toEqual([]);
    expect(overlap(CENTRALIZED_EGRESS, OWN_DATA_WRITE)).toEqual([]);
    expect(overlap(HANDLER_GATED_EXTERNAL, OWN_DATA_WRITE)).toEqual([]);
  });

  test("EVERY write/share tool is classified — a new tool is an orphan until gated", () => {
    const classified = new Set([
      ...CENTRALIZED_EGRESS,
      ...HANDLER_GATED_EXTERNAL,
      ...OWN_DATA_WRITE,
    ]);
    // Orphan: a write/share tool nobody put in a bucket. If this fires for a new
    // tool, decide whether it reaches an external party — if so, gate it and add
    // it to CENTRALIZED_EGRESS (preferred) or HANDLER_GATED_EXTERNAL; if it only
    // writes the caller's own data, add it to OWN_DATA_WRITE.
    const unclassified = allWriteShare.filter((t) => !classified.has(t));
    expect(unclassified).toEqual([]);
    // Stale: a name in a bucket that is no longer a write/share tool (renamed or
    // removed) — keep the buckets honest.
    const stale = [...classified].filter((t) => !allWriteShare.includes(t));
    expect(stale).toEqual([]);
  });

  test("CENTRALIZED_EGRESS is EXACTLY the direction:'outbound-write' label set", () => {
    // The label and the gated set must never drift: a tool labeled outbound-write
    // that is not centrally gated (or vice-versa) is the R7 hole this prevents.
    const labelled = Object.entries(TOOL_REGISTRY)
      .filter(([, def]) => def.direction === "outbound-write")
      .map(([name]) => name)
      .sort();
    expect(labelled).toEqual([...CENTRALIZED_EGRESS].sort());
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
