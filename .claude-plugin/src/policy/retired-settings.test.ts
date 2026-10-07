import { describe, expect, test } from "bun:test";
import {
  enforceNoRetiredSettings,
  retiredCliRefusal,
  retiredSettingsRefusal,
  retiredSettingsSet,
} from "./retired-settings";

describe("retired settings refuse startup", () => {
  test("none set → no refusal", () => {
    expect(retiredSettingsRefusal({})).toBeNull();
  });

  test("an empty value counts as unset", () => {
    expect(retiredSettingsRefusal({ SAFESPACE_WEBHOOK_PORT: "" })).toBeNull();
  });

  test("each retired webhook variable is named; its value is never echoed", () => {
    const msg = retiredSettingsRefusal({
      SAFESPACE_WEBHOOK_PORT: "8787",
      SAFESPACE_WEBHOOK_BIND: "10.1.2.3",
    });
    expect(msg).toContain("SAFESPACE_WEBHOOK_PORT");
    expect(msg).toContain("SAFESPACE_WEBHOOK_BIND");
    expect(msg).not.toContain("8787");
    expect(msg).not.toContain("10.1.2.3");
  });

  test("enforceNoRetiredSettings throws when one is set", () => {
    const prev = process.env.SAFESPACE_WEBHOOK_LISTEN_WITHOUT_AGENT;
    process.env.SAFESPACE_WEBHOOK_LISTEN_WITHOUT_AGENT = "true";
    try {
      expect(() => enforceNoRetiredSettings()).toThrow(/SAFESPACE_WEBHOOK_LISTEN_WITHOUT_AGENT/);
    } finally {
      if (prev === undefined) delete process.env.SAFESPACE_WEBHOOK_LISTEN_WITHOUT_AGENT;
      else process.env.SAFESPACE_WEBHOOK_LISTEN_WITHOUT_AGENT = prev;
    }
  });

  test("SAFESPACE_TRANSPORT refuses only for the value that selected HTTP", () => {
    expect(retiredSettingsRefusal({ SAFESPACE_TRANSPORT: "stdio" })).toBeNull();
    expect(retiredSettingsRefusal({ SAFESPACE_TRANSPORT: "HTTP" })).toBeNull();
    expect(retiredSettingsRefusal({ SAFESPACE_TRANSPORT: "http" })).toContain("SAFESPACE_TRANSPORT");
  });

  test("the HTTP-stack variables refuse when set, naming the variable only", () => {
    const msg = retiredSettingsRefusal({
      SAFESPACE_AUTH: "token",
      SAFESPACE_AGENT_TOKENS_FILE: "/srv/tokens.json",
      SAFESPACE_OPERATORS_FILE: "/srv/operators.json",
    });
    expect(msg).toContain("SAFESPACE_AUTH");
    expect(msg).toContain("SAFESPACE_AGENT_TOKENS_FILE");
    expect(msg).toContain("SAFESPACE_OPERATORS_FILE");
    expect(msg).not.toContain("/srv/");
  });

  test("retiredSettingsSet lists names only, honoring the same rules", () => {
    expect(retiredSettingsSet({})).toEqual([]);
    expect(retiredSettingsSet({ SAFESPACE_TRANSPORT: "stdio", SAFESPACE_HTTP_PORT: "" })).toEqual([]);
    expect(retiredSettingsSet({ SAFESPACE_TRANSPORT: "http", SAFESPACE_AUTH: "token" })).toEqual([
      "SAFESPACE_TRANSPORT",
      "SAFESPACE_AUTH",
    ]);
  });
});

describe("SAFESPACE_OPERATOR_ID is retired for the server and the CLI", () => {
  test("refuses startup and the CLI for any non-empty value, never echoing it", () => {
    for (const value of ["alice-x9", "not a valid id!"]) {
      const env = { SAFESPACE_OPERATOR_ID: value };
      const start = retiredSettingsRefusal(env);
      const cli = retiredCliRefusal(env);
      expect(start).toContain("SAFESPACE_OPERATOR_ID");
      expect(cli).toContain("SAFESPACE_OPERATOR_ID");
      expect(cli).toContain("--re-auth");
      expect(start).not.toContain(value);
      expect(cli).not.toContain(value);
    }
  });

  test("an empty value (the shipped .env.example line) counts as unset", () => {
    expect(retiredCliRefusal({ SAFESPACE_OPERATOR_ID: "" })).toBeNull();
    expect(retiredSettingsRefusal({ SAFESPACE_OPERATOR_ID: "" })).toBeNull();
  });

  test("only cli-marked settings stop the CLI", () => {
    expect(retiredCliRefusal({ SAFESPACE_WEBHOOK_PORT: "8787", SAFESPACE_TRANSPORT: "http" })).toBeNull();
  });
});

describe("SAFESPACE_ENFORCED is retired", () => {
  test("only the literal \"true\" (the value that turned it on) refuses startup", () => {
    const msg = retiredSettingsRefusal({ SAFESPACE_ENFORCED: "true" });
    expect(msg).toContain("SAFESPACE_ENFORCED");
    expect(msg).toContain("SAFESPACE_AUTONOMOUS=true");
    expect(msg).toContain("passphrase");
    for (const v of ["True", "1", "false", ""]) {
      expect(retiredSettingsRefusal({ SAFESPACE_ENFORCED: v })).toBeNull();
    }
  });

  test("it does not stop the CLI", () => {
    expect(retiredCliRefusal({ SAFESPACE_ENFORCED: "true" })).toBeNull();
  });
});
