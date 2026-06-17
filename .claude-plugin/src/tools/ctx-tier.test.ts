// v1.38 BLOCKER 3 — proves `ctx.tier` is the per-call SOURCE OF TRUTH for handler
// tier gates, replacing the process-global `currentTier()`. The full suite is the
// regression gate that every existing tier denial still fires; THESE tests prove the
// NEW property: a handler honors `ctx.tier` even when the process global
// `$SAFESPACE_TIER` disagrees — the exact guarantee Model B's per-session tier will
// rely on. `drive_share_file`'s anyone-gate (handlers.ts ~1295) is the cleanest probe:
// it reads ONLY `ctx.tier` and throws BEFORE any account/SDK work, so no mocks needed.
//
// NOT re-tested here (covered elsewhere, by design):
//   - Cross-account SENTINEL_CTX.tier (proxy.ts) is COMPILE-TIME-verified:
//     ToolContext.tier is required, so `bun run typecheck` fails if the sentinel omits
//     it. proxy.ts cannot be imported in a unit test — it boots the stdio server at
//     module load.
//   - The withToolContext invariant (`ctx.tier === currentTier()` under a fixed env)
//     is covered transitively by the full suite: every tier-gated handler test drives
//     withToolContext and now denies/allows on ctx.tier; the regression mocks carry a
//     LIVE `get tier() { return currentTier(); }` so they reproduce the pre-v1.38
//     "resolved live" behavior 1:1.

import { describe, expect, test } from "bun:test";
import { oauthCred, NOOP_AUDIT } from "./test-audit";
import type { Tier } from "../tier";
import { driveShareFile } from "./handlers";
import type { ToolContext } from "./types";

/** A minimal mock whose `tier` is STATIC — unlike the live getter the regression
 *  mocks use. That is the whole point: it must be able to CONTRADICT the env. */
function ctxWithTier(tier: Tier): ToolContext {
  return { allowedAccounts: null, credential: oauthCred("alice@example.com", () => "<unused>"), tier, audit: NOOP_AUDIT };
}

/** Run `fn` with `$SAFESPACE_TIER` forced to `value`, restoring the prior value. */
async function withEnvTier(value: string, fn: () => Promise<void>): Promise<void> {
  const prev = process.env.SAFESPACE_TIER;
  process.env.SAFESPACE_TIER = value;
  try {
    await fn();
  } finally {
    if (prev === undefined) delete process.env.SAFESPACE_TIER;
    else process.env.SAFESPACE_TIER = prev;
  }
}

describe("BLOCKER 3 — ctx.tier is the per-call source of truth (overrides the process global)", () => {
  test("DENY: ctx.tier=write blocks anyone-share even when $SAFESPACE_TIER=share", async () => {
    await withEnvTier("share", async () => {
      // The process global says SHARE, but THIS call's tier is write.
      const ctx = ctxWithTier("write");
      await expect(
        driveShareFile(ctx, { file_id: "test_file_id_000000000000", share_type: "anyone", role: "reader" }),
      ).rejects.toMatchObject({
        errorName: "share_target_forbidden",
        // `current_tier: "write"` proves the error payload (handlers.ts:1299) reads
        // ctx.tier — NOT the global, which is "share" here.
        errorData: expect.objectContaining({
          reason: "anyone_requires_share_tier",
          current_tier: "write",
        }),
      });
    });
  });

  test("ALLOW: ctx.tier=share clears the anyone-gate even when $SAFESPACE_TIER=read", async () => {
    await withEnvTier("read", async () => {
      // The process global says READ, but THIS call's tier is share.
      const ctx = ctxWithTier("share");
      // An INVALID role proves we got PAST the tier gate to the NEXT gate
      // (share_role_forbidden) — i.e. ctx.tier=share admitted the anyone path that
      // the global "read" would have refused at the tier gate.
      await expect(
        driveShareFile(ctx, { file_id: "test_file_id_000000000000", share_type: "anyone", role: "owner" }),
      ).rejects.toMatchObject({ errorName: "share_role_forbidden" });
    });
  });
});
