// v1.57 F3a — outbound secret-shape scanner tests
// (docs/v1.57-f3a-outbound-secret-and-f3b-gate.md §7). Covers: each DEFAULT shape
// matches, clean bodies → null, the EXTRA rules gated OFF by default + ON via the
// opt-in env, and the no-byte-return contract.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  ENV_OUTBOUND_SECRET_EXTRA,
  scanOutboundSecret,
} from "./outbound-secret";

let prevExtra: string | undefined;
beforeEach(() => {
  prevExtra = process.env[ENV_OUTBOUND_SECRET_EXTRA];
  delete process.env[ENV_OUTBOUND_SECRET_EXTRA];
});
afterEach(() => {
  if (prevExtra === undefined) delete process.env[ENV_OUTBOUND_SECRET_EXTRA];
  else process.env[ENV_OUTBOUND_SECRET_EXTRA] = prevExtra;
});

describe("scanOutboundSecret — default shapes", () => {
  test("private-key block (RSA / EC / OPENSSH / bare)", () => {
    expect(scanOutboundSecret("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")).toBe("private_key");
    expect(scanOutboundSecret("-----BEGIN EC PRIVATE KEY-----")).toBe("private_key");
    expect(scanOutboundSecret("-----BEGIN OPENSSH PRIVATE KEY-----")).toBe("private_key");
    expect(scanOutboundSecret("-----BEGIN PRIVATE KEY-----")).toBe("private_key");
  });

  test("AWS access key id", () => {
    expect(scanOutboundSecret("creds: AKIAIOSFODNN7EXAMPLE rest")).toBe("aws_key");
  });

  test("Google API key", () => {
    expect(scanOutboundSecret("key=AIzaSyA1234567890abcdefghijklmnopqrstuv done")).toBe(
      "google_api_key",
    );
  });

  test("GitHub token (ghp_ and github_pat_)", () => {
    expect(scanOutboundSecret("token ghp_0123456789abcdefghijklmnopqrstuvwxyz here")).toBe(
      "github_token",
    );
    expect(scanOutboundSecret("github_pat_0123456789abcdefghijABCD more")).toBe("github_token");
  });

  test("Slack / Stripe / OpenAI tokens", () => {
    expect(scanOutboundSecret("xoxb-1234567890-abcdefghij")).toBe("slack_token");
    expect(scanOutboundSecret("sk_live_0123456789abcdefghijklmn")).toBe("stripe_key");
    expect(scanOutboundSecret("sk-0123456789abcdefghijklmnopqrstuvwxyz")).toBe("openai_key");
  });

  test("a benign body → null", () => {
    expect(scanOutboundSecret("Hi Bob, lunch at noon? See the attached agenda.")).toBeNull();
    expect(scanOutboundSecret("Here is the report for Q3, totals look good.")).toBeNull();
  });

  test("empty / non-string → null", () => {
    expect(scanOutboundSecret("")).toBeNull();
    // @ts-expect-error runtime guard
    expect(scanOutboundSecret(undefined)).toBeNull();
  });

  test("returns the shape CLASS, never the matched secret bytes", () => {
    const result = scanOutboundSecret("my key is AKIAIOSFODNN7EXAMPLE ok");
    expect(result).toBe("aws_key");
    // The return is a fixed class string — it does not contain the secret.
    expect(result).not.toContain("AKIA");
  });
});

describe("scanOutboundSecret — EXTRA rules (Q6, default OFF)", () => {
  const longBase64 = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A=";

  test("high-entropy base64 is NOT flagged by default (opt-in OFF)", () => {
    expect(scanOutboundSecret(`token: ${longBase64}`)).toBeNull();
  });

  test("verification-code shape is NOT flagged by default", () => {
    expect(scanOutboundSecret("Your verification code is 482915")).toBeNull();
  });

  test("with the opt-in env set, high-entropy base64 IS flagged", () => {
    process.env[ENV_OUTBOUND_SECRET_EXTRA] = "true";
    expect(scanOutboundSecret(`token: ${longBase64}`)).toBe("high_entropy_base64");
  });

  test("with the opt-in env set, verification-code shape IS flagged", () => {
    process.env[ENV_OUTBOUND_SECRET_EXTRA] = "true";
    expect(scanOutboundSecret("Your verification code is 482915")).toBe("verification_code");
    expect(scanOutboundSecret("482915 is your one-time passcode")).toBe("verification_code");
  });

  test("opt-in env is strict-truthy ('True' / '1' do NOT enable)", () => {
    process.env[ENV_OUTBOUND_SECRET_EXTRA] = "True";
    expect(scanOutboundSecret("Your verification code is 482915")).toBeNull();
    process.env[ENV_OUTBOUND_SECRET_EXTRA] = "1";
    expect(scanOutboundSecret("Your verification code is 482915")).toBeNull();
  });

  test("default shapes still fire even with EXTRA off", () => {
    expect(scanOutboundSecret("-----BEGIN PRIVATE KEY-----")).toBe("private_key");
  });

  test("ENV constant matches the design contract (rename sentinel)", () => {
    expect(ENV_OUTBOUND_SECRET_EXTRA).toBe("SAFESPACE_OUTBOUND_SECRET_EXTRA");
  });
});
