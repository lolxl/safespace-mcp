// v1.113 — PKCE helpers for the X OAuth flow.

import { describe, expect, test } from "bun:test";
import * as crypto from "node:crypto";
import {
  base64url,
  codeChallengeS256,
  generateCodeVerifier,
  generateState,
} from "./pkce";

describe("pkce helpers", () => {
  test("base64url is unpadded URL-safe base64", () => {
    const raw = Buffer.from([0xff, 0xee, 0xdd, 0x00, 0x01]);
    const out = base64url(raw);
    expect(out).not.toMatch(/[+/=]/);
    expect(Buffer.from(out, "base64url").equals(raw)).toBe(true);
  });

  test("generateCodeVerifier is 43 base64url chars (32 random bytes)", () => {
    const v = generateCodeVerifier();
    expect(v).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // Two calls differ (entropy).
    expect(generateCodeVerifier()).not.toBe(v);
  });

  test("codeChallengeS256 is base64url(sha256(ascii(verifier)))", () => {
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    // RFC 7636 Appendix B test vector.
    expect(codeChallengeS256(verifier)).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });

  test("generateState is 43 base64url chars", () => {
    const s = generateState();
    expect(s).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(generateState()).not.toBe(s);
  });

  test("codeChallenge never contains the verifier bytes as plaintext", () => {
    const verifier = generateCodeVerifier();
    const challenge = codeChallengeS256(verifier);
    expect(challenge).not.toBe(verifier);
    // The challenge is a hash, not a substring of the verifier.
    expect(verifier.includes(challenge)).toBe(false);
    // Sanity: recompute independently.
    const again = crypto.createHash("sha256").update(verifier, "ascii").digest("base64url");
    expect(challenge).toBe(again);
  });
});
