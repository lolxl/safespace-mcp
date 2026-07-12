// v1.88 — egress-destination registry + assertEgressHost tests.

import { describe, test, expect } from "bun:test";
import { MCPError } from "../errors";
import {
  EGRESS_DESTINATIONS,
  assertEgressHost,
  type EgressDestination,
} from "./egress-destinations";

const byConnector = (c: string): EgressDestination => EGRESS_DESTINATIONS.find((d) => d.connector === c)!;

/** Capture the MCPError thrown by assertEgressHost (it is synchronous). */
function thrownBy(fn: () => void): MCPError | null {
  try {
    fn();
    return null;
  } catch (e) {
    return e instanceof MCPError ? e : null;
  }
}

describe("EGRESS_DESTINATIONS registry", () => {
  test("every entry is well-formed", () => {
    for (const d of EGRESS_DESTINATIONS) {
      expect(d.connector.length, d.connector).toBeGreaterThan(0);
      expect(d.hosts.length, d.connector).toBeGreaterThan(0);
      expect(["enforced", "declared", "configured"]).toContain(d.enforcement);
    }
  });

  test("declared entries carry a note explaining WHY they can't be enforced", () => {
    for (const d of EGRESS_DESTINATIONS.filter((d) => d.enforcement === "declared")) {
      expect(d.note, d.connector).toBeDefined();
    }
  });

  test("the socket-owned connectors are enforced; google + web-fetch are declared", () => {
    for (const c of ["github", "notion", "x", "line", "telegram", "discord", "slack"]) {
      expect(byConnector(c).enforcement, c).toBe("enforced");
    }
    expect(byConnector("google-workspace").enforcement).toBe("declared");
    expect(byConnector("web-fetch").enforcement).toBe("declared");
  });

  test("v1.113 — x is enforced against api.x.com", () => {
    expect(byConnector("x").hosts).toEqual(["api.x.com"]);
    expect(byConnector("x").enforcement).toBe("enforced");
  });

  test("v1.107 — mattermost is 'configured' (self-hosted; host pinned at runtime, not a fixed constant)", () => {
    expect(byConnector("mattermost").enforcement).toBe("configured");
  });

  test("no two connectors share a name", () => {
    const names = EGRESS_DESTINATIONS.map((d) => d.connector);
    expect(new Set(names).size).toBe(names.length);
  });
});

describe("assertEgressHost", () => {
  test("the registered host for a connector passes (no throw)", () => {
    expect(() => assertEgressHost("api.github.com", "github")).not.toThrow();
    expect(() => assertEgressHost("api.notion.com", "notion")).not.toThrow();
    expect(() => assertEgressHost("api.x.com", "x")).not.toThrow();
    expect(() => assertEgressHost("api.line.me", "line")).not.toThrow();
    expect(() => assertEgressHost("api.telegram.org", "telegram")).not.toThrow();
    expect(() => assertEgressHost("discord.com", "discord")).not.toThrow();
  });

  test("case-insensitive on the host", () => {
    expect(() => assertEgressHost("API.GitHub.com", "github")).not.toThrow();
  });

  test("an unregistered host throws -32047 echoing ONLY the host", () => {
    const e = thrownBy(() => assertEgressHost("evil.com", "github"));
    expect(e).not.toBeNull();
    expect(e!.errorName).toBe("egress_destination_blocked");
    expect(e!.errorData.host).toBe("evil.com");
  });

  test("a host-injection escape (…@evil.com) is what this catches", () => {
    // new URL("https://api.github.com@evil.com/x").hostname === "evil.com"
    const host = new URL("https://api.github.com@evil.com/repos").hostname;
    expect(host).toBe("evil.com");
    expect(thrownBy(() => assertEgressHost(host, "github"))!.errorName).toBe("egress_destination_blocked");
  });

  test("cross-connector is rejected (line's host is not telegram's)", () => {
    expect(thrownBy(() => assertEgressHost("api.line.me", "telegram"))).not.toBeNull();
  });

  test("a DECLARED connector is never assertable (fail-closed — declared = not enforced)", () => {
    // google-workspace / web-fetch are declared, so they are absent from the enforced
    // map → asserting them always throws (they must NOT be wired to assertEgressHost).
    expect(thrownBy(() => assertEgressHost("oauth2.googleapis.com", "google-workspace"))).not.toBeNull();
  });

  test("the token in a Telegram-style URL never reaches the error (host is pre-stripped)", () => {
    // The handler passes new URL(url).hostname — the bot token in the path is gone.
    const host = new URL("https://api.telegram.org/botSECRET123/sendMessage").hostname;
    expect(host).toBe("api.telegram.org");
    expect(() => assertEgressHost(host, "telegram")).not.toThrow(); // registered → passes
    // And even a blocked case only ever holds the hostname, never a token.
    const e = thrownBy(() => assertEgressHost("evil.com", "telegram"));
    expect(JSON.stringify(e!.errorData)).not.toContain("SECRET");
  });
});
