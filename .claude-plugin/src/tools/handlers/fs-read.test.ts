import { describe, expect, test } from "bun:test";
import { MCPError } from "../../errors";
import { fsReadHandler } from "./fs-read";

// v1.75 — the fs_read handler: thin arg-validation + gate call + error mapping
// (mirrors web-fetch.test.ts). The gate itself is tested in policy/fs-gate.test.ts.

const CTX = {} as never; // keyless handler ignores ctx

describe("fsReadHandler", () => {
  test("rejects a missing / empty / non-string path (plain Error, not MCPError)", async () => {
    await expect(fsReadHandler(CTX, {})).rejects.toThrow("fs_read");
    await expect(fsReadHandler(CTX, { path: "" })).rejects.toThrow();
    await expect(fsReadHandler(CTX, { path: "   " })).rejects.toThrow();
    await expect(fsReadHandler(CTX, { path: 123 })).rejects.toThrow();
  });

  test("trims + forwards the path to the gate, returns its result", async () => {
    let seen: string | undefined;
    const out = await fsReadHandler(
      CTX,
      { path: "  /srv/x/f.txt  " },
      {
        read: async (p) => {
          seen = p;
          return { path: p, bytes: 3, content: "abc" };
        },
      },
    );
    expect(seen).toBe("/srv/x/f.txt"); // trimmed
    expect(out).toEqual({ path: "/srv/x/f.txt", bytes: 3, content: "abc" });
  });

  test("passes a gate MCPError through unchanged", async () => {
    const e = new MCPError("path_blocked_by_policy", { reason: "not_in_allowlist" });
    await expect(
      fsReadHandler(CTX, { path: "/srv/x" }, {
        read: async () => {
          throw e;
        },
      }),
    ).rejects.toBe(e);
  });

  test("wraps an unexpected non-MCPError as fs_read_failed (never leaks the raw error)", async () => {
    const caught = await fsReadHandler(CTX, { path: "/srv/x" }, {
      read: async () => {
        throw new Error("boom internal path /etc/shadow");
      },
    }).catch((x) => x);
    expect(caught).toBeInstanceOf(MCPError);
    expect((caught as MCPError).errorName).toBe("fs_read_failed");
    expect((caught as MCPError).message).not.toContain("/etc/shadow");
  });
});
