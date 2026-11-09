// Test helper — a per-request ROUTER fetch stub for the Notion handlers (replaces the
// single-response `fetchStub` where a tool makes several calls, e.g. the database → data
// source resolver). Each route is consumed IN ORDER and must match the call's METHOD + PATH
// (pathname + query); a call that does not match the next route is recorded in `unexpected`
// and answered 599 (so a wrong-method / wrong-path / extra request fails loudly), and a
// request after the routes are exhausted is `unexpected` too.
//
//   const r = notionRouter([
//     { method: "GET", path: `/v1/databases/${DB}`, body: { data_sources: [...] } },
//     { method: "POST", path: `/v1/data_sources/${DS}/query`, body: {...} },
//   ]);
//   await handler(ctx, args, { fetchImpl: r.impl });
//   expect(r.trace()).toEqual([`GET /v1/databases/${DB}`, ...]);   // method+path order
//   expect(r.unexpected).toEqual([]);

/** The agent-facing opaque cursor SafeSpace emits for an upstream cursor (`ssc1.` + base64url). */
export const encCursor = (upstream: string): string => "ssc1." + Buffer.from(upstream, "utf8").toString("base64url");

export interface NotionRoute {
  readonly method: "GET" | "POST" | "PATCH";
  /** pathname (+ `?query` when the call has one), e.g. `/v1/data_sources/<id>/query`. */
  readonly path: string;
  readonly status?: number;
  /** JSON body (serialized), or a raw string (sent verbatim — for malformed-body cases). */
  readonly body?: unknown;
}

export interface RecordedCall {
  readonly method: string;
  readonly path: string;
  readonly headers: Record<string, string>;
  readonly body: unknown;
}

export function notionRouter(routes: readonly NotionRoute[]) {
  const calls: RecordedCall[] = [];
  const unexpected: string[] = [];
  let i = 0;
  const impl = (async (url: unknown, init?: unknown) => {
    const u = new URL(String(url));
    const i0 = (init ?? {}) as RequestInit;
    const method = (i0.method ?? "GET").toUpperCase();
    const path = u.pathname + u.search;
    const rawBody = typeof i0.body === "string" ? i0.body : undefined;
    calls.push({
      method,
      path,
      headers: (i0.headers ?? {}) as Record<string, string>,
      body: rawBody === undefined ? undefined : JSON.parse(rawBody),
    });
    const route = routes[i];
    if (route === undefined || route.method !== method || route.path !== path) {
      unexpected.push(`${method} ${path}`);
      return new Response("{}", { status: 599 });
    }
    i++;
    const text = typeof route.body === "string" ? route.body : JSON.stringify(route.body ?? {});
    return new Response(text, { status: route.status ?? 200 });
  }) as unknown as typeof fetch;
  return {
    impl,
    calls,
    unexpected,
    /** `METHOD /path` per call, in order. */
    trace: () => calls.map((c) => `${c.method} ${c.path}`),
    /** the number of non-GET calls (writes) made. */
    writes: () => calls.filter((c) => c.method !== "GET").length,
  };
}
