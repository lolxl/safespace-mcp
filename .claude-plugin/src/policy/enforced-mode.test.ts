// v1.86 — enforced-mode hardening guard tests.

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import {
  isEnforcedMode,
  evaluateEnforcedGates,
  enforcedModeRefusal,
  enforceEnforcedMode,
  type EnforcedGate,
} from "./enforced-mode";

// The env vars the gates read. Snapshot + restore so a test can't leak into the
// next (and into the rest of the suite, which mutates process.env freely).
const VARS = [
  "SAFESPACE_ENFORCED",
  "SAFESPACE_AUTONOMOUS",
  "SAFESPACE_SECRET_BACKEND",
  "SAFESPACE_SECRET_PASSPHRASE",
  "SAFESPACE_ALLOW_KEYFILE_AT_REST",
  "SAFESPACE_TRANSPORT",
  "SAFESPACE_HTTP_BIND",
  "SAFESPACE_TLS_TERMINATED",
] as const;

const saved: Record<string, string | undefined> = {};
beforeEach(() => {
  for (const v of VARS) {
    saved[v] = process.env[v];
    delete process.env[v];
  }
});
afterEach(() => {
  for (const v of VARS) {
    if (saved[v] === undefined) delete process.env[v];
    else process.env[v] = saved[v];
  }
});

const gate = (gates: EnforcedGate[], name: EnforcedGate["name"]): EnforcedGate =>
  gates.find((g) => g.name === name)!;

/** The minimal all-pass config: enforced + autonomous + keychain backend + stdio
 *  (http_bind n/a). Individual tests then perturb one var. */
function hardenedStdio(): void {
  process.env.SAFESPACE_ENFORCED = "true";
  process.env.SAFESPACE_AUTONOMOUS = "true";
  process.env.SAFESPACE_SECRET_BACKEND = "keychain";
  // SAFESPACE_TRANSPORT unset → stdio.
}

describe("isEnforcedMode (strict-truthy)", () => {
  test('true ONLY for the literal lowercase "true"', () => {
    process.env.SAFESPACE_ENFORCED = "true";
    expect(isEnforcedMode()).toBe(true);
  });
  for (const v of ["True", "TRUE", "1", "yes", "on", "false", "", " true "]) {
    test(`false for ${JSON.stringify(v)} (typo → non-enforced, the safe direction)`, () => {
      process.env.SAFESPACE_ENFORCED = v;
      expect(isEnforcedMode()).toBe(false);
    });
  }
  test("false when unset", () => {
    expect(isEnforcedMode()).toBe(false);
  });
});

describe("evaluateEnforcedGates — autonomous_mode", () => {
  test("pass when SAFESPACE_AUTONOMOUS=true", () => {
    process.env.SAFESPACE_AUTONOMOUS = "true";
    expect(gate(evaluateEnforcedGates(), "autonomous_mode").status).toBe("pass");
  });
  test("fail when autonomous off (even a typo'd 'True')", () => {
    process.env.SAFESPACE_AUTONOMOUS = "True";
    const g = gate(evaluateEnforcedGates(), "autonomous_mode");
    expect(g.status).toBe("fail");
    expect(g.detail).toContain("SAFESPACE_AUTONOMOUS");
  });
});

describe("evaluateEnforcedGates — token_at_rest", () => {
  test("pass on keychain backend", () => {
    process.env.SAFESPACE_SECRET_BACKEND = "keychain";
    expect(gate(evaluateEnforcedGates(), "token_at_rest").status).toBe("pass");
  });
  test("pass on file backend + passphrase (no key at rest)", () => {
    process.env.SAFESPACE_SECRET_BACKEND = "file";
    process.env.SAFESPACE_SECRET_PASSPHRASE = "a-real-passphrase";
    expect(gate(evaluateEnforcedGates(), "token_at_rest").status).toBe("pass");
  });
  test("fail on file backend KEY-FILE mode (no passphrase)", () => {
    process.env.SAFESPACE_SECRET_BACKEND = "file";
    const g = gate(evaluateEnforcedGates(), "token_at_rest");
    expect(g.status).toBe("fail");
    expect(g.detail).toContain("KEY-FILE");
  });
  test("STRICTER THAN F6: SAFESPACE_ALLOW_KEYFILE_AT_REST does NOT rescue it", () => {
    process.env.SAFESPACE_SECRET_BACKEND = "file";
    process.env.SAFESPACE_ALLOW_KEYFILE_AT_REST = "true"; // F6 hatch — ignored here
    const g = gate(evaluateEnforcedGates(), "token_at_rest");
    expect(g.status).toBe("fail");
    expect(g.detail).toContain("does NOT honor SAFESPACE_ALLOW_KEYFILE_AT_REST");
  });
});

describe("evaluateEnforcedGates — http_bind", () => {
  test("n/a under stdio (no listener)", () => {
    // SAFESPACE_TRANSPORT unset → stdio.
    expect(gate(evaluateEnforcedGates(), "http_bind").status).toBe("n/a");
  });
  test("fail under http binding all interfaces (0.0.0.0)", () => {
    process.env.SAFESPACE_TRANSPORT = "http";
    process.env.SAFESPACE_HTTP_BIND = "0.0.0.0";
    const g = gate(evaluateEnforcedGates(), "http_bind");
    expect(g.status).toBe("fail");
    expect(g.detail).toContain("0.0.0.0");
  });
  test("fail under http binding all interfaces (::)", () => {
    process.env.SAFESPACE_TRANSPORT = "http";
    process.env.SAFESPACE_HTTP_BIND = "::";
    expect(gate(evaluateEnforcedGates(), "http_bind").status).toBe("fail");
  });
  test("pass under http on explicit loopback", () => {
    process.env.SAFESPACE_TRANSPORT = "http";
    process.env.SAFESPACE_HTTP_BIND = "127.0.0.1";
    expect(gate(evaluateEnforcedGates(), "http_bind").status).toBe("pass");
  });
  test("pass under http with bind unset (falls back to loopback, NEVER 0.0.0.0)", () => {
    process.env.SAFESPACE_TRANSPORT = "http";
    expect(gate(evaluateEnforcedGates(), "http_bind").status).toBe("pass");
  });
  test("pass under http on an explicit tailnet interface", () => {
    process.env.SAFESPACE_TRANSPORT = "http";
    process.env.SAFESPACE_HTTP_BIND = "100.64.1.2";
    expect(gate(evaluateEnforcedGates(), "http_bind").status).toBe("pass");
  });

  // v1.94 A2 — the SAFESPACE_TLS_TERMINATED attestation relaxes the all-interfaces
  // bind gate (the operator attests an external TLS-terminating proxy fronts the
  // plaintext listener). The hatch is strict-truthy → a typo stays a hard fail.
  describe("SAFESPACE_TLS_TERMINATED attestation (A2 bind relaxation)", () => {
    test("0.0.0.0 + TLS_TERMINATED=true → pass, with the attestation explicit", () => {
      process.env.SAFESPACE_TRANSPORT = "http";
      process.env.SAFESPACE_HTTP_BIND = "0.0.0.0";
      process.env.SAFESPACE_TLS_TERMINATED = "true";
      const g = gate(evaluateEnforcedGates(), "http_bind");
      expect(g.status).toBe("pass");
      expect(g.detail).toContain("SAFESPACE_TLS_TERMINATED");
      expect(g.detail).toContain("0.0.0.0");
      // honest boundary — SafeSpace does NOT verify the upstream TLS.
      expect(g.detail).toContain("cannot verify");
    });
    test(":: + TLS_TERMINATED=true → pass", () => {
      process.env.SAFESPACE_TRANSPORT = "http";
      process.env.SAFESPACE_HTTP_BIND = "::";
      process.env.SAFESPACE_TLS_TERMINATED = "true";
      expect(gate(evaluateEnforcedGates(), "http_bind").status).toBe("pass");
    });
    for (const v of ["True", "TRUE", "1", "yes", ""]) {
      test(`0.0.0.0 + TLS_TERMINATED=${JSON.stringify(v)} (typo) → still fail (strict-truthy)`, () => {
        process.env.SAFESPACE_TRANSPORT = "http";
        process.env.SAFESPACE_HTTP_BIND = "0.0.0.0";
        process.env.SAFESPACE_TLS_TERMINATED = v;
        const g = gate(evaluateEnforcedGates(), "http_bind");
        expect(g.status).toBe("fail");
        // the failure points at the attestation as the remedy.
        expect(g.detail).toContain("SAFESPACE_TLS_TERMINATED");
      });
    }
    test("loopback + TLS_TERMINATED=true → the normal loopback pass (no attestation text)", () => {
      process.env.SAFESPACE_TRANSPORT = "http";
      process.env.SAFESPACE_HTTP_BIND = "127.0.0.1";
      process.env.SAFESPACE_TLS_TERMINATED = "true";
      const g = gate(evaluateEnforcedGates(), "http_bind");
      expect(g.status).toBe("pass");
      // the attestation only applies to an all-interfaces bind; a loopback bind
      // passes on its own merits and must NOT borrow the attestation copy.
      expect(g.detail).not.toContain("SAFESPACE_TLS_TERMINATED");
    });
  });
});

describe("gates are INDEPENDENT of the enforced flag (so --posture can preview)", () => {
  test("a gate still reports fail when SAFESPACE_ENFORCED is unset", () => {
    process.env.SAFESPACE_AUTONOMOUS = "false"; // off
    // ENFORCED unset.
    expect(gate(evaluateEnforcedGates(), "autonomous_mode").status).toBe("fail");
  });
});

describe("enforcedModeRefusal", () => {
  test("null when NOT enforced, even if gates would fail", () => {
    // Nothing set → autonomous off, file/keychain by platform — but ENFORCED unset.
    expect(enforcedModeRefusal()).toBeNull();
  });
  test("null when enforced AND all gates pass", () => {
    hardenedStdio();
    expect(enforcedModeRefusal()).toBeNull();
  });
  test("names the autonomous failure when enforced + autonomous off", () => {
    process.env.SAFESPACE_ENFORCED = "true";
    process.env.SAFESPACE_SECRET_BACKEND = "keychain";
    // autonomous unset → off.
    const msg = enforcedModeRefusal();
    expect(msg).not.toBeNull();
    expect(msg).toContain("SAFESPACE_AUTONOMOUS");
    expect(msg).toContain("refusing to");
    expect(msg).toContain("SOLE-EGRESS.md"); // the honest external-layers footer
  });
  test("lists EVERY failing precondition at once (no whack-a-mole)", () => {
    process.env.SAFESPACE_ENFORCED = "true";
    process.env.SAFESPACE_SECRET_BACKEND = "file"; // token_at_rest fail
    process.env.SAFESPACE_TRANSPORT = "http";
    process.env.SAFESPACE_HTTP_BIND = "0.0.0.0"; // http_bind fail
    // autonomous unset → autonomous_mode fail too.
    const msg = enforcedModeRefusal()!;
    expect(msg).toContain("SAFESPACE_AUTONOMOUS");
    expect(msg).toContain("KEY-FILE");
    expect(msg).toContain("0.0.0.0");
    expect(msg.split("\n  - ").length).toBe(4); // 1 header + 3 bullets
  });
  test("v1.94 A2: null when enforced + hardened + all-interfaces bind ATTESTED", () => {
    // The exposure-widening shape A2 enables: a no-tailnet token deployment behind a
    // reverse proxy, fully hardened except it binds all interfaces inside its netns.
    process.env.SAFESPACE_ENFORCED = "true";
    process.env.SAFESPACE_AUTONOMOUS = "true";
    process.env.SAFESPACE_SECRET_BACKEND = "keychain";
    process.env.SAFESPACE_TRANSPORT = "http";
    process.env.SAFESPACE_HTTP_BIND = "0.0.0.0";
    process.env.SAFESPACE_TLS_TERMINATED = "true"; // operator attests upstream TLS
    expect(enforcedModeRefusal()).toBeNull();
  });
});

describe("enforceEnforcedMode (startup guard)", () => {
  test("throws when a precondition fails", () => {
    process.env.SAFESPACE_ENFORCED = "true";
    process.env.SAFESPACE_SECRET_BACKEND = "file"; // no passphrase → fail
    expect(() => enforceEnforcedMode()).toThrow(/refusing to start/);
  });
  test("no-op when not enforced (Model A / today's posture)", () => {
    // ENFORCED unset → never throws, whatever the gates say.
    expect(() => enforceEnforcedMode()).not.toThrow();
  });
  test("no-op when enforced + fully hardened", () => {
    hardenedStdio();
    expect(() => enforceEnforcedMode()).not.toThrow();
  });
});
