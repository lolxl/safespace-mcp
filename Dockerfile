# syntax=docker/dockerfile:1
#
# SafeSpace MCP — Model B (multi-operator) container image.
#
# ⚠️ Model A (single-user, stdio) is NOT containerized — see
#    docs/model-b-deployment.md §1. This image exists ONLY for the shared,
#    multi-operator Model B deployment: it runs the MCP Streamable HTTP transport
#    bound to the tailscale interface, with per-connection operator authentication
#    (Tailscale WhoIs → operators.json) and FileBackend token storage.
#
# Secrets (the FileBackend passphrase, GOOGLE_CLIENT_SECRET) are NEVER baked into
# the image — they arrive at runtime as Docker Compose secrets and are bridged to
# the env by entrypoint.sh. See docs/DEPLOY.md.

# ── deps: install with the committed lockfile for a reproducible image ──
# `oven/bun:1.3` floats within the 1.3.x patch series (auto picks up patch-level
# security fixes). For a fully reproducible build, pin to a specific patch or
# digest (e.g. `oven/bun:1.3.0` / `oven/bun@sha256:…`).
FROM oven/bun:1.3 AS deps
WORKDIR /app/.claude-plugin
COPY .claude-plugin/package.json .claude-plugin/bun.lock ./
RUN bun install --frozen-lockfile --production

# ── runtime: slim base, non-root ──
FROM oven/bun:1.3-slim AS runtime
WORKDIR /app/.claude-plugin

# The persistent state dir (audit.jsonl / accounts + index / encrypted token store
# / drive-whitelist.json) lives on a mounted volume; create + own the default
# mountpoint so a fresh named volume inherits non-root ownership.
RUN mkdir -p /data && chown bun:bun /data

# App source (node_modules excluded via .dockerignore) + the installed deps.
COPY --chown=bun:bun .claude-plugin/ ./
COPY --from=deps --chown=bun:bun /app/.claude-plugin/node_modules ./node_modules
COPY --chown=bun:bun deploy/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

USER bun
ENV SAFESPACE_CONFIG_DIR=/data
# Transport / bind / port / operators-file / secrets all come from the environment
# (docker-compose.yml + entrypoint.sh). entrypoint.sh bridges the mounted secret
# files → env, then execs the MCP server. NEVER put a secret here.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bun", "run", "src/proxy.ts"]
