#!/usr/bin/env bash
# v1.110 PR 1c — build the Node-runnable dist/ bundle shipped to npm.
#
# Why this exists: the Claude Code plugin path launches the server straight
# from TypeScript via Bun (.mcp.json → `bun run src/proxy.ts`), but the
# multi-client delivery (Antigravity / Gemini / Codex / generic MCP clients)
# runs `npx safespace-mcp`, and those consumers do NOT have Bun. So we ship a
# prebuilt bundle that runs on plain Node.
#
# Asymmetry to remember: only CONSUMERS are Bun-free — they install the prebuilt
# dist/ from the npm tarball and run it on Node. This script (and package.json's
# `prepublishOnly`, which invokes it) is a MAINTAINER/publish-time step that
# shells out to `bun build`, so the PUBLISHER's machine MUST have Bun installed.
#
# What it builds:
#   - dist/proxy.js → the MCP server entry, the `safespace-mcp` bin
#   - dist/cli.js   → the `safespace` CLI (consent / doctor / audit / …)
#
# --packages=external keeps EVERY node_modules dependency out of the bundle
# (only ./src is bundled). The three runtime deps (@modelcontextprotocol/sdk,
# googleapis, @napi-rs/keyring) are declared in package.json and resolved from
# the consumer's installed node_modules at runtime. @napi-rs/keyring is a
# native module that CANNOT be bundled, so external is load-bearing, not an
# optimization.
#
# Shebang normalization: bun build preserves an entry file's own shebang
# (src/cli.ts carries `#!/usr/bin/env bun` for dev), which would make the
# published cli.js demand Bun. We therefore strip any leading shebang from
# each output and prepend `#!/usr/bin/env node` so the npm bins run on Node.
# `prepublishOnly` runs this, so a publish can never ship a stale/bun bundle.

set -euo pipefail

cd "$(dirname "$0")/.."  # → .claude-plugin (the npm package root)

rm -rf dist

bun build ./src/proxy.ts ./src/cli.ts \
  --outdir ./dist \
  --target node \
  --packages=external

# Force a Node shebang on both bins regardless of the source file's own.
for f in dist/proxy.js dist/cli.js; do
  { printf '#!/usr/bin/env node\n'; sed '1{/^#!/d;}' "$f"; } > "$f.tmp"
  mv "$f.tmp" "$f"
  chmod +x "$f"
done

echo "build-dist: wrote $(cd dist && ls | tr '\n' ' ')"
