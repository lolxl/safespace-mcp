#!/bin/sh
# SafeSpace MCP — Model B container entrypoint.
#
# Bridges Docker Compose SECRETS (mounted as files under /run/secrets, tmpfs,
# mode 0400) → the environment variables the app reads via process.env. This is
# the standard secret-file→env pattern: the secret never lands at rest beside the
# encrypted token store, and never appears in docker-compose.yml or the image.
#
# - SAFESPACE_SECRET_PASSPHRASE — unlocks the FileBackend token store (v1.37/F6).
# - GOOGLE_CLIENT_SECRET / GITHUB_CLIENT_SECRET — the OAuth-app secrets the shared
#   server uses to refresh operators' tokens.
#
# Each is optional: an absent secret file leaves the var unset (e.g. a deployment
# with no GitHub source omits the GitHub secret). The plaintext is exported into
# THIS process's environment only; `exec` replaces the shell so nothing lingers.
set -eu

# load_secret NAME FILE — export NAME=<contents of FILE> when FILE exists.
# `export "NAME=value"` is POSIX (the whole assignment is one quoted word, so a
# passphrase with spaces/special chars is preserved verbatim — no word-splitting,
# no glob, no eval). `$(cat …)` strips any TRAILING newline (command-substitution
# semantics), so a secret file written with either `printf '%s'` OR a plain `echo`
# (the common muscle-memory) yields the same newline-free value — the deploy can't
# silently break on a stray `\n`.
load_secret() {
  if [ -f "$2" ]; then
    export "$1=$(cat "$2")"
  fi
}

load_secret SAFESPACE_SECRET_PASSPHRASE /run/secrets/safespace_passphrase
load_secret GOOGLE_CLIENT_SECRET        /run/secrets/google_client_secret
load_secret GITHUB_CLIENT_SECRET        /run/secrets/github_client_secret

# Hand off to the MCP server (CMD). exec → the proxy replaces this shell, so
# SIGTERM from `docker stop` reaches it directly for a clean shutdown.
exec "$@"
