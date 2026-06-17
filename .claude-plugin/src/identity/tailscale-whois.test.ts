import { describe, expect, test } from "bun:test";
import { loginFromWhoisResponse, tailscaleWhois } from "./tailscale-whois";

// v1.74 PR-2b — Tailscale WhoIs. The login comes from the LOCAL daemon keyed on the
// verified peer IP; any failure is fail-CLOSED (null = no identity → default-deny).

describe("loginFromWhoisResponse (pure extractor)", () => {
  test("extracts UserProfile.LoginName for a real user", () => {
    expect(
      loginFromWhoisResponse({ UserProfile: { LoginName: "alice@example.com" }, Node: {} }),
    ).toBe("alice@example.com");
  });

  test("a tagged/shared node (tagged-devices) has no human operator → null", () => {
    expect(loginFromWhoisResponse({ UserProfile: { LoginName: "tagged-devices" } })).toBeNull();
  });

  test("null on a malformed / identity-less response", () => {
    expect(loginFromWhoisResponse(null)).toBeNull();
    expect(loginFromWhoisResponse("nope")).toBeNull();
    expect(loginFromWhoisResponse({})).toBeNull(); // no UserProfile
    expect(loginFromWhoisResponse({ UserProfile: null })).toBeNull();
    expect(loginFromWhoisResponse({ UserProfile: {} })).toBeNull(); // no LoginName
    expect(loginFromWhoisResponse({ UserProfile: { LoginName: "" } })).toBeNull(); // empty
    expect(loginFromWhoisResponse({ UserProfile: { LoginName: 42 } })).toBeNull(); // wrong type
  });
});

describe("tailscaleWhois (injected daemon)", () => {
  test("returns the verified login on a well-formed response", async () => {
    const login = await tailscaleWhois("100.64.0.1:5000", {
      rawWhoisImpl: async () => ({ UserProfile: { LoginName: "alice@example.com" } }),
    });
    expect(login).toBe("alice@example.com");
  });

  test("fail-closed: a thrown daemon call → null (default-deny)", async () => {
    const login = await tailscaleWhois("100.64.0.1:5000", {
      rawWhoisImpl: async () => {
        throw new Error("socket missing");
      },
    });
    expect(login).toBeNull();
  });

  test("fail-closed: an unparseable / identity-less daemon response → null", async () => {
    expect(
      await tailscaleWhois("x", { rawWhoisImpl: async () => null }),
    ).toBeNull();
    expect(
      await tailscaleWhois("x", { rawWhoisImpl: async () => ({ UserProfile: {} }) }),
    ).toBeNull();
  });
});
