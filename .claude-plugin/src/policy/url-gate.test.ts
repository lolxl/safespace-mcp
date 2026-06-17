// v1.65 Phase C — SSRF URL gate tests. This is the connector's security core, so
// the bar is the sanitize bar: every gate branch + every IP range (v4/v6/mapped) +
// the redirect re-gate + the allowlist × autonomous matrix + size/content-type.
import { describe, expect, test } from "bun:test";
import { MCPError } from "../errors";
import {
  assertUrlAllowed,
  expandIpv6ToBytes,
  fetchThroughGate,
  hostAllowed,
  isAllowedContentType,
  isBlockedAddress,
  isBlockedIpv4,
  isBlockedIpv6,
  mapWebFetchError,
  webfetchAllowlistSummary,
  type HttpGetOnceFn,
  type LookupFn,
  type RawResponse,
} from "./url-gate";

const EMPTY_ENV = {} as NodeJS.ProcessEnv;

async function* bytesOf(...chunks: string[]): AsyncGenerator<Uint8Array> {
  for (const c of chunks) yield new TextEncoder().encode(c);
}
function rawResponse(p: Partial<RawResponse> = {}): RawResponse {
  return {
    status: p.status ?? 200,
    headers: p.headers ?? { "content-type": "text/html; charset=utf-8" },
    location: p.location,
    body: p.body ?? bytesOf("<html>hello</html>"),
  };
}
const PUBLIC_LOOKUP: LookupFn = async () => [{ address: "93.184.216.34", family: 4 }];
const PRIVATE_LOOKUP: LookupFn = async () => [{ address: "10.0.0.1", family: 4 }];

async function expectBlocked(p: Promise<unknown>, reason: string): Promise<void> {
  try {
    await p;
    throw new Error("expected throw");
  } catch (e) {
    expect(e).toBeInstanceOf(MCPError);
    expect((e as MCPError).errorName).toBe("url_blocked_by_policy");
    expect((e as MCPError).errorData.reason).toBe(reason);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
describe("isBlockedIpv4 — private/reserved ranges", () => {
  test.each([
    ["0.0.0.0", true],
    ["10.0.0.1", true],
    ["10.255.255.255", true],
    ["100.64.0.1", true], // CGNAT
    ["100.127.255.255", true],
    ["100.63.255.255", false], // just below CGNAT
    ["100.128.0.1", false], // just above CGNAT
    ["127.0.0.1", true],
    ["169.254.0.1", true],
    ["169.254.169.254", true], // cloud metadata — the headline target
    ["172.15.255.255", false], // just below 172.16/12
    ["172.16.0.1", true],
    ["172.31.255.255", true],
    ["172.32.0.1", false], // just above 172.16/12
    ["192.0.0.1", true],
    ["192.0.2.5", true], // TEST-NET-1
    ["192.0.1.1", false],
    ["192.168.1.1", true],
    ["198.18.0.1", true],
    ["198.19.255.255", true],
    ["198.20.0.1", false],
    ["198.51.100.1", true], // TEST-NET-2
    ["203.0.113.1", true], // TEST-NET-3
    ["224.0.0.1", true], // multicast
    ["239.255.255.255", true],
    ["240.0.0.1", true], // reserved
    ["255.255.255.255", true], // broadcast
    ["8.8.8.8", false], // public
    ["1.1.1.1", false],
    ["93.184.216.34", false], // example.com
    ["not.an.ip", true], // unparseable → fail closed
    ["1.2.3", true], // wrong shape → fail closed
    ["1.2.3.999", true], // out of range → fail closed
  ])("%s → blocked=%p", (addr, blocked) => {
    expect(isBlockedIpv4(addr as string)).toBe(blocked as boolean);
  });
});

describe("isBlockedIpv6 — reserved ranges + IPv4-mapped", () => {
  test.each([
    ["::1", true], // loopback
    ["::", true], // unspecified
    ["fc00::1", true], // ULA
    ["fd12:3456::1", true], // ULA
    ["fe80::1", true], // link-local
    ["ff02::1", true], // multicast
    ["2001:db8::1", true], // documentation
    ["100::1", true], // discard
    ["64:ff9b::1", true], // NAT64
    ["::ffff:127.0.0.1", true], // mapped loopback → recheck v4
    ["::ffff:10.0.0.1", true], // mapped private
    ["::ffff:8.8.8.8", false], // mapped PUBLIC → allowed
    ["2606:4700:4700::1111", false], // public (cloudflare DNS)
    ["2001:4860:4860::8888", false], // public (google DNS)
    ["not::valid::addr", true], // double "::" → fail closed
    ["gggg::1", true], // bad hex → fail closed
  ])("%s → blocked=%p", (addr, blocked) => {
    expect(isBlockedIpv6(addr as string)).toBe(blocked as boolean);
  });
});

describe("isBlockedAddress — dispatch", () => {
  test("routes v4 / v6 / rejects non-IP", () => {
    expect(isBlockedAddress("10.0.0.1")).toBe(true);
    expect(isBlockedAddress("8.8.8.8")).toBe(false);
    expect(isBlockedAddress("::1")).toBe(true);
    expect(isBlockedAddress("2606:4700:4700::1111")).toBe(false);
    expect(isBlockedAddress("example.com")).toBe(true); // not an IP → fail closed
    expect(isBlockedAddress("")).toBe(true);
  });
});

describe("expandIpv6ToBytes", () => {
  test("expands compressed + mapped forms; rejects malformed", () => {
    expect(expandIpv6ToBytes("::1")?.[15]).toBe(1);
    expect(expandIpv6ToBytes("::")?.every((b) => b === 0)).toBe(true);
    const mapped = expandIpv6ToBytes("::ffff:1.2.3.4")!;
    expect([mapped[12], mapped[13], mapped[14], mapped[15]]).toEqual([1, 2, 3, 4]);
    expect(expandIpv6ToBytes("a::b::c")).toBeNull();
    expect(expandIpv6ToBytes("")).toBeNull();
    expect(expandIpv6ToBytes("1:2:3:4:5:6:7:8:9")).toBeNull(); // too many groups
  });
});

// ─────────────────────────────────────────────────────────────────────────────
describe("webfetchAllowlistSummary — counts only, never host values", () => {
  test("empty env → off / 0", () => {
    expect(webfetchAllowlistSummary(EMPTY_ENV)).toEqual({ kind: "off", count: 0 });
  });
  test("base + extra → active with the merged count", () => {
    const env = {
      SAFESPACE_WEBFETCH_ALLOW: "a.example, b.example",
      SAFESPACE_WEBFETCH_ALLOW_EXTRA: "c.example",
    } as never;
    expect(webfetchAllowlistSummary(env)).toEqual({ kind: "active", count: 3 });
  });
  test("never echoes the host values (no-PII-echo)", () => {
    const s = webfetchAllowlistSummary({ SAFESPACE_WEBFETCH_ALLOW: "internal.corp.example" } as never);
    expect(JSON.stringify(s)).not.toContain("internal.corp");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
describe("hostAllowed — Q4 allowlist × autonomous matrix", () => {
  test("empty allowlist: allow when interactive, DENY when autonomous", () => {
    expect(hostAllowed("example.com", EMPTY_ENV)).toBe(true);
    expect(hostAllowed("example.com", { SAFESPACE_AUTONOMOUS: "true" } as never)).toBe(false);
  });
  test("set allowlist matches exact host + subdomains; rejects others", () => {
    const env = { SAFESPACE_WEBFETCH_ALLOW: "example.com, @docs.internal" } as never;
    expect(hostAllowed("example.com", env)).toBe(true);
    expect(hostAllowed("api.example.com", env)).toBe(true); // subdomain
    expect(hostAllowed("docs.internal", env)).toBe(true); // @-prefixed entry accepted
    expect(hostAllowed("evil.com", env)).toBe(false);
    expect(hostAllowed("notexample.com", env)).toBe(false); // not a subdomain
  });
  test("EXTRA merges; even under autonomous a listed host passes", () => {
    const env = {
      SAFESPACE_AUTONOMOUS: "true",
      SAFESPACE_WEBFETCH_ALLOW_EXTRA: "trusted.org",
    } as never;
    expect(hostAllowed("trusted.org", env)).toBe(true);
    expect(hostAllowed("other.org", env)).toBe(false);
  });
});

describe("isAllowedContentType", () => {
  test.each([
    ["text/html; charset=utf-8", true],
    ["text/plain", true],
    ["application/json", true],
    ["application/xml", true],
    ["application/xhtml+xml", true],
    ["application/ld+json", true],
    ["application/vnd.api+json", true],
    ["application/atom+xml", true],
    ["image/png", false],
    ["application/pdf", false],
    ["application/octet-stream", false],
    ["", false],
    [undefined, false],
  ])("%s → allowed=%p", (ct, allowed) => {
    expect(isAllowedContentType(ct as string | undefined)).toBe(allowed as boolean);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
describe("assertUrlAllowed", () => {
  test("rejects non-http(s) scheme", async () => {
    await expectBlocked(
      assertUrlAllowed(new URL("ftp://example.com/x"), PUBLIC_LOOKUP, EMPTY_ENV),
      "scheme_not_allowed",
    );
    await expectBlocked(
      assertUrlAllowed(new URL("file:///etc/passwd"), PUBLIC_LOOKUP, EMPTY_ENV),
      "scheme_not_allowed",
    );
  });
  test("rejects host not in a set allowlist", async () => {
    await expectBlocked(
      assertUrlAllowed(new URL("https://evil.com/"), PUBLIC_LOOKUP, {
        SAFESPACE_WEBFETCH_ALLOW: "example.com",
      } as never),
      "host_not_in_allowlist",
    );
  });
  test("allows a public-resolving host and returns the pinned addr", async () => {
    const addr = await assertUrlAllowed(new URL("https://example.com/"), PUBLIC_LOOKUP, EMPTY_ENV);
    expect(addr.address).toBe("93.184.216.34");
  });

  test("rejects a non-default port (SSRF to internal services on a public IP)", async () => {
    await expectBlocked(
      assertUrlAllowed(new URL("https://example.com:6379/"), PUBLIC_LOOKUP, EMPTY_ENV),
      "port_not_allowed",
    );
    await expectBlocked(
      assertUrlAllowed(new URL("https://example.com:8080/"), PUBLIC_LOOKUP, EMPTY_ENV),
      "port_not_allowed",
    );
  });

  test("allows the default web ports (normalized + explicit 80/443)", async () => {
    for (const u of ["https://example.com/", "http://example.com:80/", "https://example.com:443/"]) {
      const addr = await assertUrlAllowed(new URL(u), PUBLIC_LOOKUP, EMPTY_ENV);
      expect(addr.address).toBe("93.184.216.34");
    }
  });
  test("rejects a host that resolves to a private IP", async () => {
    await expectBlocked(
      assertUrlAllowed(new URL("https://intranet.example/"), PRIVATE_LOOKUP, EMPTY_ENV),
      "private_or_reserved_ip",
    );
  });
  test("rejects a literal private IP host (no DNS)", async () => {
    await expectBlocked(
      assertUrlAllowed(new URL("http://169.254.169.254/latest/meta-data/"), PUBLIC_LOOKUP, EMPTY_ENV),
      "private_or_reserved_ip",
    );
  });
  test("rejects when ANY resolved addr is private (mixed result)", async () => {
    const mixed: LookupFn = async () => [
      { address: "93.184.216.34", family: 4 },
      { address: "127.0.0.1", family: 4 },
    ];
    await expectBlocked(
      assertUrlAllowed(new URL("https://rebind.example/"), mixed, EMPTY_ENV),
      "private_or_reserved_ip",
    );
  });
  test("rejects an empty DNS result (fail closed)", async () => {
    await expectBlocked(
      assertUrlAllowed(new URL("https://void.example/"), async () => [], EMPTY_ENV),
      "private_or_reserved_ip",
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
describe("fetchThroughGate — orchestration", () => {
  const okGet: HttpGetOnceFn = async () => rawResponse();

  test("happy path returns the sanitizable shape", async () => {
    const out = await fetchThroughGate("https://example.com/page", {
      lookup: PUBLIC_LOOKUP,
      httpGetOnce: okGet,
      env: EMPTY_ENV,
    });
    expect(out.url).toBe("https://example.com/page");
    expect(out.final_url).toBe("https://example.com/page");
    expect(out.status).toBe(200);
    expect(out.content_type).toBe("text/html; charset=utf-8");
    expect(out.content).toBe("<html>hello</html>");
  });

  test("malformed URL → malformed_url", async () => {
    await expectBlocked(fetchThroughGate("not a url", { env: EMPTY_ENV }), "malformed_url");
  });

  test("over-long URL → url_too_long", async () => {
    const long = "https://example.com/" + "a".repeat(3000);
    await expectBlocked(fetchThroughGate(long, { env: EMPTY_ENV }), "url_too_long");
  });

  test("follows a redirect to a public host + re-gates", async () => {
    let call = 0;
    const get: HttpGetOnceFn = async (url) => {
      call += 1;
      if (call === 1) return rawResponse({ status: 302, location: "https://example.com/final" });
      expect(url.pathname).toBe("/final");
      return rawResponse({ body: bytesOf("final body") });
    };
    const out = await fetchThroughGate("https://example.com/start", {
      lookup: PUBLIC_LOOKUP,
      httpGetOnce: get,
      env: EMPTY_ENV,
    });
    expect(out.final_url).toBe("https://example.com/final");
    expect(out.content).toBe("final body");
  });

  test("BLOCKS a redirect to a private IP (the headline SSRF bypass)", async () => {
    const get: HttpGetOnceFn = async () =>
      rawResponse({ status: 302, location: "http://169.254.169.254/latest/" });
    await expectBlocked(
      fetchThroughGate("https://public.example/page", {
        lookup: PUBLIC_LOOKUP,
        httpGetOnce: get,
        env: EMPTY_ENV,
      }),
      "private_or_reserved_ip",
    );
  });

  test("rejects a redirect Location that is unparseable", async () => {
    const get: HttpGetOnceFn = async () => rawResponse({ status: 301, location: "http://[" });
    await expectBlocked(
      fetchThroughGate("https://example.com/", {
        lookup: PUBLIC_LOOKUP,
        httpGetOnce: get,
        env: EMPTY_ENV,
      }),
      "redirect_blocked",
    );
  });

  test("BLOCKS a redirect to a non-http(s) scheme via the re-gate", async () => {
    const get: HttpGetOnceFn = async () =>
      rawResponse({ status: 302, location: "file:///etc/passwd" });
    await expectBlocked(
      fetchThroughGate("https://example.com/", {
        lookup: PUBLIC_LOOKUP,
        httpGetOnce: get,
        env: EMPTY_ENV,
      }),
      "scheme_not_allowed",
    );
  });

  test("BLOCKS a redirect to a non-default port via the re-gate (sec-rev H1)", async () => {
    const get: HttpGetOnceFn = async () =>
      rawResponse({ status: 302, location: "http://example.com:22/" });
    await expectBlocked(
      fetchThroughGate("https://example.com/", { lookup: PUBLIC_LOOKUP, httpGetOnce: get, env: EMPTY_ENV }),
      "port_not_allowed",
    );
  });

  test("rejects a redirect status with NO Location header (sec-rev M2)", async () => {
    const get: HttpGetOnceFn = async () => rawResponse({ status: 307, location: undefined });
    await expectBlocked(
      fetchThroughGate("https://example.com/", { lookup: PUBLIC_LOOKUP, httpGetOnce: get, env: EMPTY_ENV }),
      "redirect_blocked",
    );
  });

  test("a slow body trips the read deadline → web_fetch_failed timeout (sec-rev M1)", async () => {
    let destroyed = false;
    const slowBody: AsyncIterable<Uint8Array> = {
      async *[Symbol.asyncIterator]() {
        yield new TextEncoder().encode("partial");
        // Hang until readCapped's deadline destroys us.
        await new Promise<void>((_resolve, reject) => {
          const t = setInterval(() => {
            if (destroyed) {
              clearInterval(t);
              reject(new Error("socket destroyed"));
            }
          }, 5);
        });
      },
    };
    const get: HttpGetOnceFn = async () => ({
      status: 200,
      headers: { "content-type": "text/plain" },
      body: slowBody,
      destroy: () => {
        destroyed = true;
      },
    });
    try {
      await fetchThroughGate("https://example.com/slow", {
        lookup: PUBLIC_LOOKUP,
        httpGetOnce: get,
        env: EMPTY_ENV,
        timeoutMs: 60,
      });
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(MCPError);
      expect((e as MCPError).errorName).toBe("web_fetch_failed");
      expect((e as MCPError).errorData.reason).toBe("timeout");
    }
  });

  test("caps redirects → too_many_redirects", async () => {
    let n = 0;
    const get: HttpGetOnceFn = async () =>
      rawResponse({ status: 302, location: `https://example.com/hop${n++}` });
    await expectBlocked(
      fetchThroughGate("https://example.com/start", {
        lookup: PUBLIC_LOOKUP,
        httpGetOnce: get,
        env: EMPTY_ENV,
      }),
      "too_many_redirects",
    );
  });

  test("rejects a non-text content type", async () => {
    const get: HttpGetOnceFn = async () =>
      rawResponse({ headers: { "content-type": "image/png" }, body: bytesOf("\x89PNG") });
    await expectBlocked(
      fetchThroughGate("https://example.com/img", {
        lookup: PUBLIC_LOOKUP,
        httpGetOnce: get,
        env: EMPTY_ENV,
      }),
      "content_type_not_allowed",
    );
  });

  test("enforces the size cap → file_too_large", async () => {
    const get: HttpGetOnceFn = async () =>
      rawResponse({ body: bytesOf("aaaa", "bbbb", "cccc") }); // 12 bytes
    try {
      await fetchThroughGate("https://example.com/big", {
        lookup: PUBLIC_LOOKUP,
        httpGetOnce: get,
        env: EMPTY_ENV,
        maxBytes: 8,
      });
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(MCPError);
      expect((e as MCPError).errorName).toBe("file_too_large");
    }
  });

  test("blocks the entry scheme before any fetch", async () => {
    await expectBlocked(
      fetchThroughGate("file:///etc/passwd", { env: EMPTY_ENV }),
      "scheme_not_allowed",
    );
  });
});

describe("real-transport defense (no mock) — literal + DNS private hosts blocked", () => {
  test("a literal loopback IP is blocked end-to-end", async () => {
    await expectBlocked(fetchThroughGate("http://127.0.0.1/"), "private_or_reserved_ip");
  });
  test("`localhost` resolves (real DNS) and is blocked before connect", async () => {
    await expectBlocked(fetchThroughGate("http://localhost/"), "private_or_reserved_ip");
  });
});

describe("mapWebFetchError", () => {
  test("passes an MCPError through unchanged", () => {
    const e = new MCPError("url_blocked_by_policy", { reason: "scheme_not_allowed" });
    expect(mapWebFetchError(e)).toBe(e);
  });
  test("wraps a non-MCPError as web_fetch_failed (no raw-string leak)", () => {
    const mapped = mapWebFetchError(new Error("ECONNREFUSED 10.0.0.1:443"));
    expect(mapped).toBeInstanceOf(MCPError);
    expect((mapped as MCPError).errorName).toBe("web_fetch_failed");
    expect((mapped as MCPError).errorData.reason).toBe("connection_failed");
    expect(mapped.message).not.toContain("10.0.0.1");
  });
});
