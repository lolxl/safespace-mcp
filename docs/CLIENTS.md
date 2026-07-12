# Running SafeSpace MCP from any MCP client

SafeSpace is a standard [Model Context Protocol](https://modelcontextprotocol.io)
stdio server. It runs the same safety envelope no matter which agent launches it.
There are two ways to start it:

| Path | Runtime | Best for |
| --- | --- | --- |
| **Claude Code plugin** | Bun (bundled with the plugin) | Claude Code — zero config, see the [README](../README.md) |
| **`npx` / npm** | **plain Node ≥ 20** | Google Antigravity / Gemini, OpenAI Codex, Cursor, Claude Desktop, any other MCP client |

The npm package ships a prebuilt bundle (`dist/`), so **the npx path needs only
Node — Bun is not required** on the consumer machine.

---

## 1. Prerequisites (npx path)

- **Node ≥ 20.**
- A **Google Cloud OAuth client** of type *Desktop app* →
  `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET`. (Only for the Google connectors;
  GitHub / Notion / service-token connectors are optional and configured the
  same way.) See [`.env.example`](../.env.example) for the full variable list.
  - ⚠️ **Publish the OAuth consent screen to "In production"** (Cloud Console →
    *APIs & Services → OAuth consent screen* → **Publish app**). The default
    **"Testing"** status expires refresh tokens after **7 days**, forcing a weekly
    re-`consent`. The "unverified app" prompt is expected for a self-hosted client
    you authored (click *Advanced → Go to app*); **no Google verification is
    needed**. **Workspace** users can use **user type "Internal"** instead (no
    expiry, no warning; org-confined). Re-run `consent … --re-auth` after changing.
- A stable **config directory** (`SAFESPACE_CONFIG_DIR`) where OAuth tokens and
  state persist between runs. Pick any path you control, e.g. `~/.safespace`.

> The npx path does **not** auto-load a `.env` file (that is a Bun-only
> convenience used by the Claude Code plugin). Every variable the server needs —
> the OAuth client id/secret (used for token **refresh**, not just consent), the
> config dir, the tier — must be passed in the client's `env` block, or exported
> in the shell you run the CLI from.

---

## 2. One-time setup (consent)

Run the bundled CLI with the **same** environment you will hand the server. The
CLI lives behind the same package; invoke it with `-p safespace-mcp`:

```sh
export SAFESPACE_CONFIG_DIR="$HOME/.safespace"
export GOOGLE_CLIENT_ID="<your-id>.apps.googleusercontent.com"
export GOOGLE_CLIENT_SECRET="GOCSPX-<your-secret>"

# Opens a browser for Google consent; tokens are stored under
# SAFESPACE_CONFIG_DIR behind the SecretBackend (Keychain on macOS, an encrypted
# file elsewhere — see docs/DEPLOY.md).
npx -y -p safespace-mcp safespace consent you@example.com

# Verify the install + posture (config dir perms, tier, accounts, audit chain).
npx -y -p safespace-mcp safespace doctor
```

`SAFESPACE_CONFIG_DIR` is the link between setup and serving: the tokens consent
writes there are exactly what the server reads. Use the **same value** in both.

---

## 3. Client configuration

Every MCP client takes the same three things — a command, its args, and an env
block. The generic server entry:

```json
{
  "command": "npx",
  "args": ["-y", "safespace-mcp"],
  "env": {
    "SAFESPACE_CONFIG_DIR": "/Users/you/.safespace",
    "SAFESPACE_TIER": "read",
    "GOOGLE_CLIENT_ID": "<your-id>.apps.googleusercontent.com",
    "GOOGLE_CLIENT_SECRET": "GOCSPX-<your-secret>"
  }
}
```

`npx -y safespace-mcp` runs the **server** bin. (`-y` skips the install prompt;
the first launch downloads the package, later launches are cached.)

### Google Antigravity / Gemini

Antigravity and the Gemini MCP integrations read a JSON config with an
`mcpServers` object. Add SafeSpace as one entry:

```json
{
  "mcpServers": {
    "safespace": {
      "command": "npx",
      "args": ["-y", "safespace-mcp"],
      "env": {
        "SAFESPACE_CONFIG_DIR": "/Users/you/.safespace",
        "SAFESPACE_TIER": "read",
        "GOOGLE_CLIENT_ID": "<your-id>.apps.googleusercontent.com",
        "GOOGLE_CLIENT_SECRET": "GOCSPX-<your-secret>"
      }
    }
  }
}
```

The exact file location varies by client version — consult the client's "add an
MCP server" docs for where its `mcpServers` config lives.

### OpenAI Codex

Codex configures MCP servers in `~/.codex/config.toml` under an `mcp_servers`
table:

```toml
[mcp_servers.safespace]
command = "npx"
args = ["-y", "safespace-mcp"]
env = { SAFESPACE_CONFIG_DIR = "/Users/you/.safespace", SAFESPACE_TIER = "read", GOOGLE_CLIENT_ID = "<your-id>.apps.googleusercontent.com", GOOGLE_CLIENT_SECRET = "GOCSPX-<your-secret>" }
```

### Cursor / Windsurf / Claude Desktop / others

These read a JSON config with the same `mcpServers` shape shown for Antigravity
above (e.g. Claude Desktop's `claude_desktop_config.json`). Drop the same
`safespace` entry in.

---

## 4. Notes & gotchas

- **Tier.** `SAFESPACE_TIER` is `read` (default) / `write` / `share`. It is
  enforced at the `tools/list` boundary, so disallowed tools are invisible to the
  agent. Start at `read`; raise it only for the surface you want the agent to
  write to.
- **One host owns the tokens.** Tokens live on the machine that runs the server,
  under `SAFESPACE_CONFIG_DIR`. Run consent on that same machine (or copy the
  config dir there) so the server can read and refresh them.
- **Windows.** SafeSpace runs on Node on Windows. Token storage defaults to the
  encrypted FileBackend; because NTFS uses ACLs rather than POSIX permission
  bits, the key-file mode's `0o600` is a no-op there — set
  `SAFESPACE_SECRET_PASSPHRASE` for no-key-at-rest encryption. `safespace doctor`
  reports the POSIX mode checks as `n/a (NTFS ACL)` on Windows rather than
  failing them.
- **The CLI.** Every subcommand (`consent`, `doctor`, `audit`, `account-list`,
  `whitelist`, `recipient`, …) runs as `npx -y -p safespace-mcp safespace <cmd>`.
- **Full configuration reference.** Every environment variable — egress
  allowlists, autonomy hardening, burst caps, transport — is documented in
  [`.env.example`](../.env.example). For multi-operator / shared-server
  deployments see [`docs/DEPLOY.md`](DEPLOY.md).
