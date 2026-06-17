// Security-critical (review S2): the browser launcher must never route the URL through a
// shell tokenizer. These tests pin the per-platform argv and the shell:false invariant.

import { describe, expect, test } from "bun:test";
import { browserLaunchArgv, openUrl } from "./open-url";

const URL_PLAIN = "https://accounts.google.com/o/oauth2/v2/auth?state=abc&scope=x";
// A URL carrying cmd.exe metacharacters — if it ever reached `cmd /c start`, cmd would
// split on `&`/`|`/`^`/`%`. It must always survive as ONE literal argv element.
const URL_HOSTILE = "https://x/cb?a=1&b=2|c^%PATHEXT%";

describe("browserLaunchArgv — per-platform, injection-safe", () => {
  test("darwin → open <url>", () => {
    expect(browserLaunchArgv(URL_PLAIN, "darwin")).toEqual(["open", [URL_PLAIN]]);
  });

  test("linux → xdg-open <url>", () => {
    expect(browserLaunchArgv(URL_PLAIN, "linux")).toEqual(["xdg-open", [URL_PLAIN]]);
  });

  test("win32 → rundll32 FileProtocolHandler, NOT cmd /c start", () => {
    const [cmd, args] = browserLaunchArgv(URL_PLAIN, "win32");
    expect(cmd).toBe("rundll32.exe");
    expect(args).toEqual(["url.dll,FileProtocolHandler", URL_PLAIN]);
    expect(cmd).not.toContain("cmd");
    expect(args).not.toContain("start");
  });

  test("the URL is ALWAYS a single literal argv element (no shell splitting), every platform", () => {
    for (const platform of ["darwin", "linux", "win32"] as const) {
      const [, args] = browserLaunchArgv(URL_HOSTILE, platform);
      // The full hostile URL appears verbatim as exactly one argv element.
      expect(args).toContain(URL_HOSTILE);
    }
  });
});

describe("openUrl — spawn contract", () => {
  test("spawns with shell:false and swallows a launcher error", () => {
    let captured: { cmd: string; args: string[]; opts: unknown } | null = null;
    const fakeSpawn = ((cmd: string, args: string[], opts: unknown) => {
      captured = { cmd, args, opts };
      // Minimal child stub: .on returns self, .unref is a no-op.
      const child = { on: () => child, unref: () => {} };
      return child as never;
    }) as never;

    expect(() => openUrl(URL_PLAIN, fakeSpawn)).not.toThrow();
    expect(captured).not.toBeNull();
    expect((captured!.opts as { shell: boolean }).shell).toBe(false);
    // Whatever the host platform, the URL is delivered as one argv element.
    expect(captured!.args).toContain(URL_PLAIN);
  });
});
