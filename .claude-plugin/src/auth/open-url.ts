// Cross-platform "open this URL in the default browser" for the OAuth consent flow.
// Replaces the Bun-only `Bun.spawn(["open", url])` so the CLI runs on Node, on macOS,
// Linux, and Windows alike.
//
// SECURITY (review S2, CRITICAL): the URL is passed as a single argv element with
// `shell: false`, so no shell tokenizer ever sees it. On Windows we use
//   rundll32.exe url.dll,FileProtocolHandler <url>
// and deliberately NOT `cmd /c start <url>` — cmd.exe re-parses its argument for
// metacharacters (`& | ^ %`) on its OWN tokenizer regardless of `shell: false`, which
// would be a command-injection sink. `rundll32` takes the URL as a literal argument and
// never routes it through a shell. `open` (macOS) and `xdg-open` (Linux) likewise receive
// the URL as a literal argv[1] and do not re-parse it.

import { spawn } from "node:child_process";

/** Resolve the (command, args) pair that opens `url` for the given platform. Exported for
 *  testing: it lets a test assert the win32 path uses `rundll32` (NOT `cmd /c start`) and
 *  that the URL is always a single literal argv element. */
export function browserLaunchArgv(url: string, platform: NodeJS.Platform): [string, string[]] {
  if (platform === "darwin") return ["open", [url]];
  if (platform === "win32") return ["rundll32.exe", ["url.dll,FileProtocolHandler", url]];
  return ["xdg-open", [url]];
}

/** Open `url` in the OS default browser. Fire-and-forget: detached + errors swallowed,
 *  because the consent flow does not depend on the launch succeeding — the caller has
 *  already printed the URL to stderr for the user to open manually. `spawnImpl` is an
 *  injection seam for tests. */
export function openUrl(url: string, spawnImpl: typeof spawn = spawn): void {
  const [cmd, args] = browserLaunchArgv(url, process.platform);
  try {
    const child = spawnImpl(cmd, args, { stdio: "ignore", shell: false });
    child.on("error", () => {}); // a missing launcher binary must not crash consent
    child.unref();
  } catch {
    // ignore — the URL was already printed to stderr by the caller
  }
}
