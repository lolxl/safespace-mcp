// Sentinel for the pinned keyed-MAC algorithm invariant (crypto-algorithms.ts).
//
// Two guards:
//   1. Each MAC contract is HMAC-SHA256 — a downgrade (e.g. to "md5"/"sha1") fails here,
//      forcing it to be a conscious, reviewed edit of a named wire/at-rest contract.
//   2. NO createHmac() anywhere in src passes an inline string-literal algorithm — every
//      HMAC routes its algorithm through crypto-algorithms.ts. A future regression (a new
//      connector inlining `createHmac("sha1", …)`, or re-hardcoding "sha256" outside the
//      module) re-introduces the literal and trips this test. Because SafeSpace has NO
//      JWT `alg`-header decode path, these compile-time createHmac calls are the ONLY
//      algorithm surface — pinning them pins the whole surface.

import { describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  AGENT_TOKEN_HMAC_ALG,
  AUDIT_HMAC_ALG,
  WEBHOOK_SIGNATURE_HMAC_ALG,
} from "./crypto-algorithms";

const SRC_DIR = import.meta.dir;

describe("crypto-algorithms — pinned keyed-MAC invariant", () => {
  it("pins every keyed-MAC / signature contract to HMAC-SHA256", () => {
    expect(AGENT_TOKEN_HMAC_ALG).toBe("sha256");
    expect(WEBHOOK_SIGNATURE_HMAC_ALG).toBe("sha256");
    expect(AUDIT_HMAC_ALG).toBe("sha256");
  });

  it("no createHmac() in src uses an inline algorithm literal", () => {
    // `createHmac(` immediately followed (modulo whitespace) by a quote = an inline
    // literal algorithm. After this cycle every call passes a named constant instead.
    const inlineLiteral = /createHmac\s*\(\s*["'`]/;
    const offenders: string[] = [];
    for (const rel of fs.readdirSync(SRC_DIR, { recursive: true }) as string[]) {
      if (!rel.endsWith(".ts") || rel.endsWith(".test.ts")) continue;
      const src = fs.readFileSync(path.join(SRC_DIR, rel), "utf8");
      if (inlineLiteral.test(src)) offenders.push(rel);
    }
    expect(offenders).toEqual([]);
  });
});
