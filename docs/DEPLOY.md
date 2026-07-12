# Deploying SafeSpace — Model B (shared, multi-operator)

This guide ships the **Model B** deployment: ONE long-running SafeSpace server that
several **mutually-trusting** operators connect to over a Tailscale tailnet to
co-manage shared accounts (the canonical case: a few people co-managing one YouTube
channel). It is the concrete realization of `docs/model-b-deployment.md` §5–6, now
that the multi-operator engine (v1.73 transport + the v1.74 operator-auth arc) is
built.

> ### ⚠️ This is NOT for single users
> If you're one person on one machine, **do not use this** — run the plugin in the
> normal stdio mode (Model A). Model A is a child process of your own Claude, needs
> no container, and keeps the macOS Keychain. See `docs/model-b-deployment.md` §1.
>
> ### ⚠️ All-local OR all-shared — never mixed
> The A→B move is a **CUTOVER** (`model-b-deployment.md` §3.5): once you run the
> shared server, every operator connects to it; running local instances *alongside*
> it against the same upstream accounts is **not supported** (it dilutes the F1
> burst caps, scatters audit, and forks allowlist config).

The artifacts: `Dockerfile`, `docker-compose.yml`, `deploy/entrypoint.sh`,
`deploy/operators.example.json`.

---

## What you need

- A **Linux host** that's always on (a mini-PC / Pi-class box / always-on Mac mini)
  with **Docker + Compose** and **Tailscale installed and joined** to your tailnet.
  (Tailscale's free Personal plan — 3 users / 100 devices — covers the scenario.)
- A **Google OAuth app** (Client ID + Secret) — and a **GitHub OAuth app** if you
  enable the GitHub source.
- The shared upstream accounts you want to co-manage (Google accounts; the channel).

---

## Step 1 — host Tailscale

Install + join Tailscale on the host, then note the host's tailnet IP:

```sh
tailscale ip -4          # → e.g. 100.101.102.103
```

In the Tailscale admin console, an **ACL** restricts which tailnet users may reach
the host's MCP port. A member who leaves = remove their device → access ends
immediately, no shared secret to rotate.

## Step 2 — secrets (mode 600, never committed)

`docker-compose.yml` reads these as Compose **secrets** (mounted at `/run/secrets`,
bridged to env by `entrypoint.sh`). They are gitignored.

```sh
mkdir -p secrets
printf '%s' 'your-strong-filebackend-passphrase'  > secrets/safespace_passphrase
printf '%s' 'your-google-oauth-client-secret'      > secrets/google_client_secret
# printf '%s' 'your-github-oauth-client-secret'    > secrets/github_client_secret
chmod 600 secrets/*
```

The passphrase unlocks the **encrypted FileBackend token store** (there is no
Keychain in a container; F6/v1.55 *requires* a passphrase, so the server refuses to
start without one). The passphrase **never** travels with a backup and is never at
rest beside the store.

## Step 3 — host config (`.env`, gitignored)

```sh
cat > .env <<EOF
SAFESPACE_HTTP_BIND=100.101.102.103      # the host tailscale IP from Step 1 — NEVER 0.0.0.0
SAFESPACE_HTTP_PORT=8765
GOOGLE_CLIENT_ID=xxxxx.apps.googleusercontent.com
# GITHUB_CLIENT_ID=Iv1.xxxx                # only if you enable the GitHub source
EOF
```

## Step 4 — consent the shared accounts into the token store

The server refreshes operators' tokens, so each shared account must be **consented
once** into the data volume's encrypted store. Run the consent flow in a throwaway
container that shares the data volume + the passphrase (both inherited from the
service definition — the entrypoint bridges the passphrase secret, so the encrypted
store can be written):

```sh
docker compose run --rm safespace bun run src/cli.ts consent shared-channel@gmail.com
# repeat for each shared Google account (and `--provider github <login>` for GitHub).
```

The consent CLI prints an authorization URL and starts a one-shot OAuth callback on
a **loopback** port (chosen per run). Because the service is `network_mode: host`,
that callback binds the **host's** `127.0.0.1:<port>` directly — so do NOT add a
`-p` port mapping (Docker discards published ports under host networking; it would
be a no-op). Complete the flow from a browser that can reach the host's loopback:

- **Host with a desktop browser** — just open the printed URL there.
- **Headless host (SSH)** — SSH-forward the printed callback port to your laptop,
  e.g. `ssh -L <port>:127.0.0.1:<port> <host>`, then open the URL on your laptop.

Every account you consent here must also appear in some operator's `allowedAccounts`
(Step 5) — and conversely, every `allowedAccounts` entry must be a consented account,
or the server refuses to start (the registry cross-check).

## Step 5 — the operator registry

Map each **verified Tailscale login** → operator policy. Copy the template into the
data volume as `operators.json`:

```sh
cp deploy/operators.example.json /tmp/operators.json
$EDITOR /tmp/operators.json     # set real tailnetLogin / operatorId / tier / allowedAccounts
docker compose run --rm -v /tmp/operators.json:/tmp/operators.json:ro \
  safespace cp /tmp/operators.json /data/operators.json
```

(Or write it directly to the named volume by any means you prefer; it must land at
`/data/operators.json`.) **Default-deny:** a tailnet login not listed is refused.
This must be in place **before Step 6** — the server fail-louds at startup if
`SAFESPACE_OPERATORS_FILE` is missing/invalid, and the registry cross-check also
requires every `allowedAccounts` entry to be a consented account (Step 4).

## Step 6 — launch

```sh
docker compose up -d
docker compose logs -f safespace
# expect: "...Streamable HTTP transport on http://100.x.y.z:8765/mcp (operator auth: ...)"
```

## Step 7 — operators connect

Each operator points their Claude MCP server config at the host's MagicDNS name:

```
http://<host>.<your-tailnet>.ts.net:8765/mcp
```

On connect, the server reads their **verified tailnet identity** (Tailscale WhoIs),
looks it up in `operators.json`, and applies *that* operator's tier + account set.
An unregistered / unidentified connection gets a flat `403`.

---

## Member join / leave

> **v1.80 — `operators.json` is HOT-RELOADED.** The server re-validates the file
> whenever its mtime changes; NO restart is needed for registry edits. An
> INVALID edit (bad JSON, unknown account, half-written file) keeps the
> last-good registry enforced and warns on stderr — the server never crashes on
> an edit and never falls open. (Startup still refuses to serve on an invalid
> file.)

- **Join:** the person installs Tailscale + you approve their device + add an ACL
  line + add an `operators.json` entry → they can connect on their next attempt
  (no restart).
- **Leave:** remove their Tailscale device (network access ends immediately) and
  delete their `operators.json` entry — their authorization ends on their **next
  request**, even for an already-open session (the transport re-resolves every
  request against the current registry and tears the session down with a 403).
- **Tier / account change:** edit the entry — it applies on that operator's next
  call (an open session observes the new tier/`allowedAccounts` without
  reconnecting).

## No Tailscale on the host? (sidecar alternative)

If the host doesn't run Tailscale, add a `tailscale/tailscale` **sidecar** container,
join it with an auth key, share its network namespace
(`network_mode: "service:tailscale"` on the `safespace` service instead of
`network_mode: host`), and mount the sidecar's `tailscaled.sock` into `safespace`
(point `SAFESPACE_TAILSCALE_SOCKET` at it). Everything else is identical. This is
more self-contained but heavier (an auth key + a tailscale state volume).

## No tailnet at all? (bearer-token auth — v1.93 A1)

If you can't use Tailscale, authenticate operators with **bearer tokens** instead of
WhoIs. Set `SAFESPACE_AUTH=token` and point `SAFESPACE_AGENT_TOKENS_FILE` at a store
on your data volume. The token authenticates **who**; the operator must STILL be in
`operators.json` (the registry authorizes tier / accounts), so set up Step 5 exactly
as before — the token just replaces the tailnet-identity step.

```sh
# mint one token per operator (the login MUST match an operators.json entry).
# The plaintext is printed ONCE — copy it, then hand it to that operator.
docker compose exec safespace safespace agent-token mint alice@example.com --expires 2026-12-31T00:00:00Z
docker compose exec safespace safespace agent-token list      # logins + hash prefixes, never plaintext
docker compose exec safespace safespace agent-token revoke alice@example.com
```

Operators send the token as `Authorization: Bearer <token>` on every request. Only
each token's HMAC hash is stored; a leaked `agent-tokens.json` reveals no usable
token. Because the token is re-presented on every request, a `revoke` (or an expiry
lapse) now bites an operator's **open session on its next request** — not only its
next connection (v1.94 A2); a `mint` takes effect on the operator's next connection.

### Exposing the listener off-loopback (v1.94 A2)

SafeSpace's listener is **plaintext `node:http`** — SafeSpace does **not** terminate
TLS in-process (that is what your reverse proxy / cloud load-balancer does, better,
without SafeSpace owning cert rotation). So to reach a token-auth deployment from
another host you **front it with your own TLS-terminating proxy** and let SafeSpace
bind only what the proxy reaches:

- **Preferred:** keep SafeSpace on **loopback** (or its container's internal
  interface) and point the proxy's upstream at it. No bind-gate change needed.
- **Container bridge-network / all-interfaces bind:** if the listener must bind
  `0.0.0.0`/`::` inside its netns (so the proxy/sidecar can reach the published
  port), enforced mode would normally **refuse to start** (a plaintext all-interfaces
  bind looks like a naked public bind). Set **`SAFESPACE_TLS_TERMINATED=true`** to
  **attest** that an external TLS-terminating proxy fronts the listener and restricts
  who can reach it. SafeSpace **cannot verify** this — the attestation makes your
  responsibility explicit, exactly like the egress lockdown (`SOLE-EGRESS.md`).

> ⚠️ A bearer token over **plaintext on a reachable interface** is an exposed
> credential. `SAFESPACE_TLS_TERMINATED` relaxes only the *bind gate* — it asserts
> nothing about the wire. TLS termination and network access control remain **your**
> responsibility, the same deployment-external boundary as the rest of `SOLE-EGRESS.md`.
> The flag is strict-truthy (`=true`); any typo leaves the gate a hard fail.

## North-side authentication — front SafeSpace with your gateway / IdP

SafeSpace's **inbound** auth (Tailscale WhoIs, or the v1.93 bearer token) is
**deliberately thin**: it authenticates **who** the caller is and feeds that login to
the default-deny `operators.json` registry, which authorizes (tier / accounts). It does
**not** implement the public MCP-OAuth ceremony — no RFC 9728 protected-resource
discovery, no Authorization-Code + PKCE, no JWKS verification, no RFC 8707 audience
binding. **That is by design.** SafeSpace is the **south-side** envelope (egress
governance + content sanitization + audit hash-chain); the standardized **north-side**
agent→server OAuth belongs at the edge, in the gateway / IdP your organization already
runs. **Don't rebuild a half-OAuth inside SafeSpace — put a real one in front of it.**

For a **company deployment**, front SafeSpace with a TLS-terminating auth proxy. Three
shapes, cheapest first:

- **Tailscale ACL (the default in this guide).** The tailnet *is* your access boundary;
  with Tailscale SSO, tailnet identity is your IdP identity. SafeSpace resolves it by
  peer IP (`WhoIs`) — no extra component. Best for a small mutually-trusting team.
- **An MCP-OAuth gateway** (e.g. **Kong API Gateway** + the `mcp-oauth2` plugin /
  AuthGate). It implements the MCP 2025-06 authorization spec at the edge — RFC 9728
  discovery (`401 + WWW-Authenticate: resource_metadata=…`), Auth-Code + PKCE, RS256
  access tokens validated offline via JWKS, RFC 8707 `aud` binding — and forwards a
  verified subject. It owns exactly the four things SafeSpace deliberately does **not**.
- **An OIDC reverse proxy** — Okta / Microsoft Entra ID / Auth0 / Cloudflare Access /
  `oauth2-proxy`. Same shape: the proxy authenticates the human and terminates TLS.

In **all** shapes the wiring is the same: keep SafeSpace on **loopback / its internal
interface**, point the proxy's upstream at it, terminate TLS + run the OAuth at the
proxy, and gate who may reach SafeSpace at the network layer. Set
**`SAFESPACE_TLS_TERMINATED=true`** to attest the fronting proxy (above), and
**`SAFESPACE_ENFORCED=true`** to make a non-loopback plaintext bind a hard
refuse-to-start precondition. SafeSpace **cannot verify** the proxy is present — the
attestation makes that boundary your responsibility, identical to `SOLE-EGRESS.md`.

> **Known gap (not this cycle).** SafeSpace does not yet consume a *trusted
> forwarded-identity header* (e.g. the gateway's `X-MCP-Subject`) as an auth source, so
> the gateway→SafeSpace hop still authenticates via **Tailscale or a per-operator bearer
> token**, not via the gateway's per-end-user identity. If you need each end user mapped
> to a distinct SafeSpace operator off-tailnet **today**, mint **one bearer token per
> operator** (above) and let the gateway authenticate the human while SafeSpace
> authenticates the token. Per-user identity passthrough from the gateway is a possible
> future "trusted-header" auth mode, intentionally deferred — see
> `docs/safety-gateway-thesis.md` (the north/south split).

## Backups & updates

- **Backup:** snapshot the `safespace-data` volume periodically. The token store is
  already ciphertext, so no extra encryption is needed — but the passphrase must
  **not** travel with the snapshot.
- **Update:** `docker compose pull && docker compose up -d` (or rebuild). A restart
  loses only per-session in-process state (the tainted-source set + burst windows) —
  per-session by design, acceptable.

## Optional hardening

- **Autonomous posture** — for an unattended shared server, set
  `SAFESPACE_AUTONOMOUS=true` (deny-by-default recipient/drive/tasks-delete
  allowlists + permanent-delete deny, F2/F4). If you do, configure those allowlists
  or the gated tools deny by default.
- **Read-only root FS** — add `read_only: true` + `tmpfs: ["/tmp"]` to the service.
  Test first: Bun's runtime cache may need a writable path on some setups.
- **Egress firewall** — for a single trusted operator, optional (SafeSpace already
  gates egress at the app layer: recipient allowlists, F3a secret-shape, the web-fetch
  SSRF gate). **For a company deployment it is mandatory, not optional** — SafeSpace is a
  *cooperative* gateway and cannot enforce itself as the sole exit. To make it an
  enforced chokepoint (lock credentials + network + runtime so the agent has no other
  way out), follow [`SOLE-EGRESS.md`](SOLE-EGRESS.md).

---

See `docs/model-b-deployment.md` for the full design + the rationale behind each
choice (why single-container/in-process over container-per-operator, why Tailscale
over a public VPS, why not Cloud Run / Kubernetes).
