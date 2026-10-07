# Making SafeSpace the sole egress (company deployment hardening)

SafeSpace gates everything that flows **through** it. But it is an MCP server — a
**cooperative** gateway: the agent *chooses* to call its tools. SafeSpace cannot, by
itself, stop an agent from reaching an external API some other way.

> **"SafeSpace is the only exit" is a property of the deployment, not a feature of
> SafeSpace.** SafeSpace provides the *safe lane* (gated tools + credential custody +
> audit). The deployment must remove every *other* lane.

For a single trusted operator on their own machine this doesn't matter —
you trust the human. For a **company deployment**, where an agent acts semi-autonomously
and a compromised or buggy agent is in the threat model, you make SafeSpace an *enforced*
chokepoint by locking the three ways an agent could go around it.

## The three bypass paths — lock all three

An agent can only reach an external API directly if it has **(1) a credential**, **(2) a
network route**, and **(3) a way to make the call**. Remove any one and the bypass fails;
remove all three for defense in depth.

### Layer 1 — Credential custody: the agent holds ZERO secrets

The only reason an agent could call Gmail / GitHub directly is that it holds the token.
SafeSpace already keeps **all** credentials in its `SecretBackend` (macOS Keychain /
encrypted file / a vault in a hosted deployment); the agent never sees them. Enforce it:

- Run SafeSpace as a **separate process / user / container** from the agent. The agent's
  environment must not be able to read SafeSpace's keychain / encrypted token file /
  vault (no shared filesystem, no shared user).
- **No API keys, OAuth tokens, or bot tokens in the agent's environment** (env vars,
  config, mounted files). The agent's *only* way to a provider is the stdio connection
  its MCP client opens to SafeSpace.

- **SafeSpace's own reads must not reach its secrets.** `fs_read` and `web_fetch` run
  inside SafeSpace's trust zone on the agent's behalf. `fs_read` refuses SafeSpace's
  config/store dirs, AI-client config dirs, `/proc` and `/dev` whatever the roots say
  (`policy/fs-deny-zones.ts`); still keep the roots narrow, and never let an entry in
  `SAFESPACE_FS_READ_ROOTS` **or** `SAFESPACE_FS_READ_ROOTS_EXTRA` (both are merged)
  cover SafeSpace's config dir (default `~/.config/safespace`: token store, key file,
  `.env`, audit salt), `/proc`, or a mount shared with the agent. Keep `web_fetch`
  deny-all in this posture: set `SAFESPACE_CONNECTORS` to an explicit list that does
  not include `web-fetch` (unset means every connector is on), or leave **both**
  `SAFESPACE_WEBFETCH_ALLOW` and `SAFESPACE_WEBFETCH_ALLOW_EXTRA` empty under
  autonomous mode. Its allowlist also matches every subdomain, so an entry like
  `googleapis.com` admits user-content hosts such as `storage.googleapis.com` — an
  exfiltration route.

→ For every credentialed source, the agent now simply **cannot authenticate** on its own.

### Layer 2 — Network egress: the agent's runtime can't reach the outside

This is the enforcement teeth. SafeSpace speaks MCP over **stdio**: the agent's MCP
client launches it and talks to it over a pipe, so the agent never needs a network route
*to* SafeSpace. Isolation is therefore **per process identity**, not per address: the
agent's identity gets **deny-all egress**, and only SafeSpace's identity may reach the
provider endpoints (`googleapis.com`, `api.github.com`, `api.line.me`, …). The stdio pipe
crosses that boundary; packets from the agent do not.

Mechanisms (pick what fits the platform):

- **Separate VM or container, started by a trusted supervisor (recommended)** — the
  agent's VM / container gets **only a loopback interface**: no other NIC, no IPv6
  router advertisements (`accept_ra=0`), and no route to link-local
  `169.254.0.0/16` (cloud metadata at `169.254.169.254` hands out instance
  credentials). A namespace-based sandbox also needs its own PID and mount namespaces
  with a **fresh procfs mounted inside them** (new namespaces do not remount `/proc`;
  e.g. `unshare --mount-proc`), and no `CAP_SYS_ADMIN` / `CAP_NET_ADMIN` /
  `CAP_SYS_PTRACE` — otherwise the agent can `setns` into the host's network or read
  SafeSpace's environment (the token passphrase) from `/proc/<pid>/environ`. SafeSpace runs in a separate VM or container that may reach only the
  provider hosts, started by a supervisor the agent does not control, with its
  stdin/stdout attached to the agent's MCP client as plain pipes (no TTY). If the pipe
  is bridged through a Unix socket, the shared mount holds only that socket, gives the
  agent connect-only access (it must not be able to replace the socket), and is never
  SafeSpace's working or config directory. Never give the agent the Docker
  socket or namespace privileges to start SafeSpace — that hands it root on the host
  and a full network route.
- **Same host, separate OS user (advanced — not documented here)** — a firewall keyed
  on the user can separate the agent's egress from SafeSpace's on Linux (nftables
  `meta skuid` / iptables `owner`, IPv4 **and** IPv6). macOS `pf` cannot do this
  completely: it applies `user` to TCP and UDP only, so the agent can still send ICMP
  (and raw IP, if it ever gains root), and any host-wide ICMP allowance applies to the
  agent too. The agent's
  client must also start SafeSpace under the other user through a privileged
  launcher, and that launcher **is the security boundary**: everything the agent's
  user can influence — environment, `PATH`, arguments, working directory (Bun runs a
  `bunfig.toml` preload from it), the binaries and code it executes, the config it
  loads — must be out of the agent's reach. SafeSpace does not ship or document such a
  launcher; build it only with a dedicated security review, or use the VM/container
  boundary above.
- **Forced egress proxy** — only SafeSpace's identity is permitted to use the outbound
  proxy; the agent's identity has no route at all.

→ This is what turns "cooperative" into "enforced": even if the agent *wanted* to call
Gmail directly, the packet does not route.

### Layer 3 — Runtime / tool surface: the agent can't build its own exit

The agent must not have an **unrestricted shell, code-exec, or arbitrary-fetch** that can
open its own sockets. If the agent runtime (Claude Code, a custom harness) exposes
bash/exec, that runtime must live in the **same network-denied sandbox** so Layer 2 backs
it up. Give the agent **only** the MCP tools you intend (SafeSpace's) — not a raw
`curl` / `web_fetch`.

→ This is the thesis's *axis-3 = agent-runtime sandbox*. Layer 2 is the backstop: even
arbitrary code can't leave a netns with no route out.

### Layer 4 — Provider-side pinning (defense in depth)

Where the provider supports it, restrict the credential so it is **only usable from
SafeSpace's egress IP**. Support varies by provider, so check what *your* credential type
allows: a **GitHub organization IP allowlist** applies to OAuth tokens; for keyless /
API-key connectors, issue an **IP-restricted API key**. (Note: a standard Google OAuth
*access token* can't be IP-pinned — this layer isn't available everywhere, which is why
it is defense-in-depth, not a primary control.) Where it does apply, a stolen token is
useless from anywhere but SafeSpace's egress, so a bypass fails **at the provider** even
if Layers 1–3 had a hole. This only helps when SafeSpace's egress IP differs from the
agent's: with the same-host, per-user isolation above both leave from one address, and
pinning no longer tells them apart — use a separate egress (the proxy, or a
container/VM with its own IP) if you rely on this layer.

### Layer 5 — Detection: catch what leaks

SafeSpace's `run_id` audit trail is the record of everything that went **through** the
gate. To detect a **bypass**, monitor egress **per identity**: any outbound connection by
the agent's user / cgroup / container (e.g. an nftables `meta skuid` log rule, or the
egress proxy's per-identity log) is a misconfiguration or an attack → **alert**. On a
shared host a per-subnet monitor cannot tell the agent from SafeSpace.

→ SafeSpace audit + an egress monitor = *everything that left, and an alarm if something
left another way.*

## Two postures

| | **Local** — single trusted operator | **Company** — enforced sole egress |
|---|---|---|
| SafeSpace role | cooperative gateway; gates + audits what flows through it | a true chokepoint |
| You add | nothing (your own machine, your own trust) | ① credential isolation · ② network egress lockdown (the load-bearing one) · ③ runtime sandbox · ④ provider IP pinning · ⑤ egress monitoring |

## What SafeSpace gives vs. what the deployment must add

| SafeSpace provides | The deployment must add |
|---|---|
| The gated tool surface (tier / scope / recipient / target / SSRF gates) | The network walls that delete every other route (Layer 2) |
| Credential custody (`SecretBackend`, F6 token-at-rest hardening) | Isolation so the agent can't read that store (Layer 1) |
| The `run_id` audit trail | An egress monitor to detect bypass + a SIEM sink (Layer 5) |

**Bottom line:** SafeSpace is *necessary but not sufficient* for "sole exit." It is the
safe lane, the credential custody, and the audit; the company deployment builds the walls
— above all the **network egress lockdown (Layer 2)** — that remove every other lane.

## The SafeSpace-side knobs

SafeSpace can't verify the *external* walls (Layers 2–4 are the deployment's job). Its
**own** hardening knobs for a company deployment are three separate settings:

- **autonomous mode** (`SAFESPACE_AUTONOMOUS=true`) — the egress allowlists become
  deny-by-default and permanent-deletes are hard-denied (F2/F4); with key-file token
  storage it also refuses to start unless you set a passphrase or the
  `SAFESPACE_ALLOW_KEYFILE_AT_REST` escape hatch (F6) — the hatch keeps the key beside the
  ciphertext, so `doctor --posture` still reports it as a failure;
- **a token store that is not offline-capturable** — the OS keychain, or an encrypted
  FileBackend in passphrase mode (`SAFESPACE_SECRET_PASSPHRASE`);
- **supervised send-approval** (`SAFESPACE_REQUIRE_SEND_APPROVAL=true`) — owner approval
  for human-sends and irretractable public writes (`youtube_video_comment_post`,
  `youtube_comment_reply`, `x_post_create`, `drive_share_file` when `share_type=anyone`).
  An unattended deploy with it on needs someone to run `safespace send approve`.

(The former `SAFESPACE_ENFORCED=true` refuse-to-start checklist over these three was
removed; a leftover `SAFESPACE_ENFORCED=true` now refuses startup and names them.)

`safespace doctor --posture` reports these three settings **without** starting the server;
any one of them off is a `FAIL` and the command exits 1, so `safespace doctor --posture &&
deploy` works as a pre-deploy hardening check. It never stops the server itself. It
also enumerates every connector's egress/access allowlist — `restricted (N)` / `deny-all` /
`OPEN` — so you can see exactly what can reach or leave through the deployment (counts only,
never the allowlist contents), plus the **egress-destination registry** — the external hosts
SafeSpace's own process connects to, each `enforced` (runtime-gated at the fetch chokepoint
against a host-injection escape) or `declared` (listed but ungatable — the googleapis SDK
owns its socket, web-fetch is the dynamic SSRF-gated path). And it always prints the honest reminder that the network
egress lockdown, the agent sandbox, and provider IP-pinning are **deployment-external**: an
`OK` summary means all three settings are on and no egress row is `OPEN` — SafeSpace's own
knobs, never that SafeSpace is the *sole* exit. Build the walls above; the posture only shows
you didn't leave SafeSpace's own door open.

## See also

- [`SECURITY.md`](../SECURITY.md) — the trust boundary and threat model.
