// v1.113 — PKCE (RFC 7636 S256) helpers for the X (Twitter) OAuth 2.0 consent flow.
// Isolated so consent.ts stays focused on the loopback dance + token exchange, and
// so unit tests can pin the base64url / SHA-256 shapes without a live consent run.
//
// SECURITY: the code_verifier is a high-entropy secret equivalent to a short-lived
// password — NEVER log, echo, or put it in a thrown Error message.

import * as crypto from "node:crypto";

/** base64url (no padding) of `bytes` — the OAuth 2.0 / PKCE wire form. */
export function base64url(bytes: Buffer | Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/** A fresh PKCE code_verifier: base64url(randomBytes(32)) → 43 chars. */
export function generateCodeVerifier(): string {
  return base64url(crypto.randomBytes(32));
}

/** S256 code_challenge = base64url(SHA-256(ascii(code_verifier))). */
export function codeChallengeS256(verifier: string): string {
  return base64url(crypto.createHash("sha256").update(verifier, "ascii").digest());
}

/** A fresh CSRF `state` token (base64url of 32 random bytes). */
export function generateState(): string {
  return base64url(crypto.randomBytes(32));
}
