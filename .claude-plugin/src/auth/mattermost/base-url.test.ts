// v1.107 — Mattermost self-hosted base-URL resolver + the configured-host egress pin.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  __resetMattermostServerForTests,
  getMattermostServer,
  mattermostConfiguredHost,
  requireMattermostBaseUrl,
} from "./base-url";
import { ENV_MATTERMOST_SERVER_URL } from "../../config";
import { assertEgressHost } from "../../policy/egress-destinations";
import { MCPError } from "../../errors";

let saved: string | undefined;
let prevErr: typeof console.error;

beforeEach(() => {
  saved = process.env[ENV_MATTERMOST_SERVER_URL];
  delete process.env[ENV_MATTERMOST_SERVER_URL];
  __resetMattermostServerForTests();
  prevErr = console.error;
  console.error = (): void => undefined; // silence the warn-once
});

afterEach(() => {
  if (saved === undefined) delete process.env[ENV_MATTERMOST_SERVER_URL];
  else process.env[ENV_MATTERMOST_SERVER_URL] = saved;
  __resetMattermostServerForTests();
  console.error = prevErr;
});

function set(url: string): void {
  process.env[ENV_MATTERMOST_SERVER_URL] = url;
  __resetMattermostServerForTests();
}

describe("getMattermostServer (fail-closed validation)", () => {
  test("unset → null", () => {
    expect(getMattermostServer()).toBeNull();
    expect(mattermostConfiguredHost()).toBeNull();
  });

  test("non-https (http) → null (protects the bearer token)", () => {
    set("http://mm.example.com");
    expect(getMattermostServer()).toBeNull();
  });

  test("unparseable → null", () => {
    set("not a url");
    expect(getMattermostServer()).toBeNull();
  });

  test("valid https → {baseUrl, host} with the lowercased host", () => {
    set("https://MM.Example.COM");
    const s = getMattermostServer();
    expect(s).not.toBeNull();
    expect(s!.host).toBe("mm.example.com");
    expect(s!.baseUrl).toBe("https://mm.example.com");
  });

  test("subpath deployment is preserved; trailing slash + query/fragment stripped", () => {
    set("https://example.com/mattermost/?x=1#f");
    const s = getMattermostServer();
    expect(s!.baseUrl).toBe("https://example.com/mattermost");
    expect(s!.host).toBe("example.com");
  });

  test("private/internal host is ALLOWED (owner-configured, not agent-supplied)", () => {
    set("https://mattermost.internal.lan:8065");
    const s = getMattermostServer();
    expect(s!.host).toBe("mattermost.internal.lan");
    expect(s!.baseUrl).toBe("https://mattermost.internal.lan:8065");
  });

  test("result is cached until reset", () => {
    set("https://a.example.com");
    expect(getMattermostServer()!.host).toBe("a.example.com");
    process.env[ENV_MATTERMOST_SERVER_URL] = "https://b.example.com"; // no reset
    expect(getMattermostServer()!.host).toBe("a.example.com"); // cached
  });
});

describe("requireMattermostBaseUrl", () => {
  test("unset → throws mattermost_api_failed{no_server_url}", () => {
    try {
      requireMattermostBaseUrl();
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(MCPError);
      expect((e as MCPError).errorName).toBe("mattermost_api_failed");
      expect((e as MCPError).errorData).toMatchObject({ reason: "no_server_url" });
    }
  });

  test("set → returns the normalized base URL", () => {
    set("https://mm.example.com/");
    expect(requireMattermostBaseUrl()).toBe("https://mm.example.com");
  });
});

describe("assertEgressHost('mattermost') — configured-host pin", () => {
  test("unset → ANY host blocked (fail-closed, -32047)", () => {
    expect(() => assertEgressHost("mm.example.com", "mattermost")).toThrow();
  });

  test("configured host passes; any other host is blocked (path-injection backstop)", () => {
    set("https://mm.example.com");
    expect(() => assertEgressHost("mm.example.com", "mattermost")).not.toThrow();
    expect(() => assertEgressHost("MM.EXAMPLE.COM", "mattermost")).not.toThrow(); // case-insensitive
    let caught: unknown;
    try {
      assertEgressHost("evil.com", "mattermost");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(MCPError);
    expect((caught as MCPError).errorName).toBe("egress_destination_blocked");
    expect((caught as MCPError).errorData).toMatchObject({ host: "evil.com" });
  });
});
