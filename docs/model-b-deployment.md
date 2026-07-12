# Model B deployment — design + shipped artifacts

> **Status update (2026-06-10):** the Model B **engine is now built** — the PR-2
> arc shipped the two real blockers this doc named in §2/§7 (transport: v1.73;
> operator auth + per-connection identity + `OperatorContext` + per-operator
> account confinement: the v1.74.0→v1.74.2 arc). The **deployment artifacts**
> (`Dockerfile`, `docker-compose.yml`, `deploy/entrypoint.sh`,
> `deploy/operators.example.json`) + the operator runbook (**`docs/DEPLOY.md`**)
> now realize §5–6 of this design. The §3–8 analysis below is the rationale; the
> §3.5 coexistence posture + §9 decisions remain authoritative.
>
> **Original status (kept for provenance):** DRAFT / forward-looking analysis
> (2026-06-10). This document captured the deployment analysis ahead of time so
> that when Model B is scheduled, the deployment shape is already settled and the
> app-layer work can be scoped against it.
> Open decisions are listed as Q1–Q3 in §9 and are NOT yet owner-locked.
> **One posture IS owner-DECIDED (2026-06-10, §3.5): the DEFAULT scenario is
> single-user Model A, and single-user / multi-user must NOT be mixed — a
> deployment is either all-local or all-shared; the A→B move is a CUTOVER,
> not a blend.**
> Companion to `docs/safety-gateway-thesis.md` (north star) and
> `docs/ARCHITECTURE.md` (as-built structure). Written against `51ae726`
> (post-v1.70.4).

---

## 0. Scope — what this document is and is not

**Is:** the analysis of *how a Model B deployment should be shipped and
operated* — container strategy, network exposure, secret injection, persistence,
and the evaluation that eliminated the alternatives.

**Is not:** the Model B *application-layer* design (operator authentication,
`OperatorContext` assembly, per-operator tier/allowlist resolution, the HTTP
transport). Those are the real blockers (§2) and get their own design doc when
Model B is scheduled. Deployment is the *easiest 20%* of Model B; this doc
exists so it is a solved problem by then, not so it pulls Model B forward.

**Definitions used throughout:**

- **Model A** (today): one operator = one machine = one stdio child process of
  the operator's own Claude. No network surface, no shared state.
- **Model B** (paused): ONE long-running shared SafeSpace process; several
  trusted operators connect to it remotely and co-manage shared surface (the
  canonical use case: a few people co-managing one YouTube channel).

---

## 1. Why Model A must NOT be containerized

"Dockerize what we have" is a non-goal, and would actively break things:

1. **stdio transport** — the MCP server is spawned as a child process by the
   operator's Claude over stdin/stdout. There is no network listener to put
   behind a container boundary; a container adds a layer and removes nothing.
2. **Keychain** — the preferred `SecretBackend` on macOS does not exist inside
   a Linux container. Containerizing Model A would force every user down to
   FileBackend for zero benefit.
3. **No shared server → no problem for a container to solve.** Containers earn
   their keep when there is one persistent deployment serving several clients.
   That is Model B's definition, not Model A's.

**Docker enters exactly at the Model A → Model B topology switch, not before.**

---

## 2. Upstream of Docker: the two real blockers (neither is deployment)

Before the first line of any Dockerfile matters, Model B needs two app-layer
prerequisites. These carry the engineering weight; Docker is downstream of both:

| Prerequisite | Today | What it is |
|---|---|---|
| **(A) Network transport** | stdio only | Remote Claude clients connecting to one server require the MCP **Streamable HTTP** transport. Without it the containerized server has no face to the network. |
| **(B) Operator authentication + `OperatorContext`** | no-op seam, deferred | When operator A's Claude connects, the server must know "this is A, not B" — to stamp the right audit `operator`, apply A's tier, apply A's allowlists, and route to A's OAuth accounts. This is the deliberately-paused Model-B-prep seam (per-call `ctx.tier` v1.38 + per-row `operator` v1.36 are the already-landed halves). |

Docker solves neither. It answers "once those exist, how does the artifact run
persistently" — packaging and operations, not multi-tenancy logic.

---

## 3. Isolation model: single container in-process vs container-per-operator

The one genuine *design* decision at the deployment layer.

### Option A — single container, in-process multi-operator (RECOMMENDED)

One SafeSpace process serves all operators; the connection layer identifies the
operator (§5) and the process assembles `OperatorContext` per call.

- **Pros:** cheapest to run; **this is the shape the existing seams were built
  for** — per-call `ctx.tier`, per-row `operator` audit actor, and the
  `accountId`+`provider`-keyed credential resolution (v1.70 G0–G4) all assume
  one process distinguishing operators internally.
- **Cons:** all operators' tokens live in one `SecretBackend`, one blast
  radius. But **the envelope product's thesis is precisely that one process can
  keep operators safe from each other** — for a small mutually-trusting group
  co-managing shared surface, this is the natural shape, and it actually
  exercises the model the product claims.

### Option B — one container per operator

Each operator gets a SafeSpace container with its own `SecretBackend` volume
and tokens; a reverse proxy routes operator → container.

- **Pros:** OS-level hard isolation; one compromised operator's tokens cannot
  reach another's.
- **Cons:** heavy (N containers), duplicated token storage, per-container OAuth
  consent; and it is really "Model A × N behind a proxy" — it never validates
  the in-process multi-operator model the thesis cares about. Right posture for
  *adversarial* multi-tenant SaaS; wrong fit for the stated goal.

> **Recommendation: Option A.** Option B stays on the shelf as the fallback if
> the isolation guarantees are ever distrusted, or if SafeSpace someday becomes
> an externally-offered service.

---

## 3.5 Single-user / multi-user coexistence posture — **owner-DECIDED 2026-06-10**

**The decision: the DEFAULT usage scenario is single-user Model A. Single-user
and multi-user must NOT be mixed.** Unpacked across the three senses in which
"coexistence" could be meant:

### (1) One codebase, two modes — YES; design principle: Model A is the degenerate case

Transport is an entry-point concern; everything from the proxy down (the entire
envelope) never knows who is listening above it. The same codebase serves both
modes behind a launch flag (`--stdio` today's default vs a future `--http`),
and **Model A is designed as the single-operator DEGENERATE CASE of Model B,
never a parallel code path**:

- The already-landed seams were built for exactly this: per-call `ctx.tier`
  (v1.38) resolves to the process-global `SAFESPACE_TIER` under Model A and to
  a per-operator tier under Model B — same field, different resolver. Same for
  the always-present audit `operator` (v1.36, env-fed today) and the
  `provider`+`accountId`-keyed credential store (v1.70, gains an
  operator→accounts binding under Model B).
- The shape mirrors the southbound `Source`/`CredentialResolver` strategy
  pattern: a northbound **`OperatorResolver` strategy** with two
  implementations — `EnvOperatorResolver` (Model A: reads env, always returns
  the one operator) and `ConnectionOperatorResolver` (Model B: maps connection
  identity, §5.1). Choke points consume `OperatorContext` only; **no
  `if (modelB)` branches anywhere** — that is what would rot the single-user
  path.
- **stdio mode is NEVER retired.** It is the zero-network-surface,
  zero-auth-gateway minimal-attack-surface form and remains the default and the
  right answer for single users permanently. Model B is additive, not a
  replacement.

### (2) One running process listening on stdio AND HTTP simultaneously — NO

Technically possible, semantically wrong: stdio's lifecycle is "child of one
Claude session — it dies, I die"; a shared server's is "persistent, owned by
no one". Binding both ties the whole group's server to one owner window. On a
shared host the owner's Claude connects over HTTP/tailnet like everyone else.

### (3) Mixed topology — some operators on local Model A instances AND a shared Model B server against the same upstream accounts — **NOT SUPPORTED (the owner decision)**

Upstream providers would allow it (independent consents, independent refresh
tokens), but **the envelope's guarantees are per-gateway-instance, not global
per upstream account**: two gateways against the same account means F1 burst
caps dilute N-fold, audit forensics scatter across machines (`run_id` spaces
never meet), and allowlist config forks silently. These are not bugs — they are
the instance-boundary made visible — which is exactly why the topology is
rejected rather than papered over: **a deployment is either all-local
(Model A ×N, §8 step 1) or all-shared (one Model B server, §8 step 2). The
A→B migration is a CUTOVER, not a blend.**

---

## 4. Deployment option comparison and elimination

### 4.1 Evaluation criteria (derived from SafeSpace's actual shape)

1. **File-shaped state** — `audit.jsonl` (append-only forensics), index +
   account files, the encrypted token store, `drive-whitelist.json` are all
   local files. A deployment MUST provide a persistent volume, or the storage
   layer has to be rewritten first.
2. **Secret model** — no Keychain in a container → FileBackend + passphrase is
   the only path, and **F6 (v1.55) already refuses to start keyfile-at-rest
   under `SAFESPACE_AUTONOMOUS` without `SAFESPACE_SECRET_PASSPHRASE`** — the
   "passphrase must be injected at runtime" rail is already built.
3. **User scale** — a few *mutually trusting* people, not external SaaS. This
   directly sizes the acceptable attack surface.
4. **Single-process assumption** — audit append, the F1 burst sliding windows,
   the tainted-source session Set, and the ancestor LRU cache are all
   *in-process* state. The deployment must be ONE persistent process; N
   horizontally-scaled replicas would each run their own burst window and
   dilute the cap N-fold. This criterion alone kills serverless and
   multi-replica orchestration.
5. **MCP transport** — any remote option presupposes §2(A) is done.

### 4.2 The comparison

| Option | Persistent files | Single process | Attack surface | Ops cost | Verdict |
|---|---|---|---|---|---|
| **A. Model A local ×N (status quo)** | ✅ native | ✅ one each | zero network | zero | ✅ **best for NOW** |
| **B. Home host + Compose + Tailscale** | ✅ volume | ✅ | zero public exposure | low | ✅ **first choice for Model B** |
| **C. Public VPS + Compose + Caddy** | ✅ volume | ✅ | public 443 | medium | ⚠️ fallback |
| **D. GCP Cloud Run (serverless)** | ❌ ephemeral FS | ❌ scale-to-zero / multi-replica | low | low | ❌ eliminated |
| **E. Kubernetes** | ✅ | ⚠️ must pin 1 replica | depends | high | ❌ eliminated |

### 4.3 Elimination rationale

- **D. Cloud Run** — superficially attractive (Google ecosystem, Secret Manager
  integration) but fails criteria 1 and 4: the filesystem is ephemeral, so
  `audit.jsonl` evaporates on restart — for a security gateway whose *selling
  point is audit forensics*, that is a product-level contradiction. Rescuing it
  means rewriting audit/account/token storage onto Firestore/GCS — a refactor
  larger than Model B itself, to save one host. Multi-replica scaling would
  additionally dilute the burst gates. Re-evaluate only if SafeSpace ever
  becomes an external SaaS.
- **E. Kubernetes** — for "a few trusted people + one process", the ops cost is
  pure waste, and its core value (horizontal scaling, self-healing rescheduling)
  directly conflicts with criterion 4.

---

## 5. First choice: home host + Docker Compose + Tailscale private network

### 5.1 Why Tailscale over a public VPS — the highest-leverage call in this doc

1. **It shrinks Model B's hardest block.** On a public VPS you must build a
   full auth gateway (API-key issuance/rotation, or oauth2-proxy, or mTLS cert
   management). On a tailnet:
   - the server is **never exposed to the public internet** — no port scans, no
     brute force, no TLS certificate management;
   - joining the tailnet is itself a device-level identity verification (SSO
     login + admin device approval);
   - **every inbound connection carries "who this is"** — each tailnet IP maps
     to one verified user+device, queryable via the local Tailscale `WhoIs` API
     or Tailscale Serve identity headers. The operator-auth gateway shrinks
     from "build an account system" to "read a connection-identity → operator-id
     mapping".
2. **Zero migration of file-shaped state** — named volumes mount the existing
   audit/accounts/token-store files as-is; the F6 passphrase rail applies
   unchanged.
3. **Hardware bar is trivially low** — a mini PC, a Raspberry-Pi-class box, or
   an always-on Mac mini serves a handful of operators with a single Bun
   process. No suitable home host → fall back to Option C (smallest VPS,
   ~US$5/month, Caddy auto-HTTPS in front, self-built auth gateway) — same
   architecture, swapping "private-network identity" for "public TLS +
   self-managed keys".

### 5.2 What Tailscale actually is (recorded here so the doc is self-contained)

A WireGuard-based **overlay network**: devices behind arbitrary NATs join one
virtual private network (a **tailnet**) and talk directly, with no inbound
ports opened anywhere.

- **Control plane** (Tailscale's coordination server): manages membership and
  distributes WireGuard public keys + stable `100.x.y.z` addresses and MagicDNS
  names. It introduces peers; **it cannot read traffic**.
- **Data plane**: direct point-to-point WireGuard tunnels (NAT-traversed);
  worst-case fallback relays (DERP) carry only ciphertext.
- **Identity**: joining = SSO login (Google/GitHub/MS) + admin approval of the
  device. Tailnet **ACLs** declare which users may reach the SafeSpace host's
  MCP port — a connection-layer allowlist in front of the app-layer gates.

**Honest limits:**

1. **Trust in Tailscale's control plane** — it cannot read traffic but it
   governs membership; a compromised coordination server could admit a hostile
   device. Self-hosted **Headscale** exists if this ever matters; for a small
   trusted group the hosted service is the right trade.
2. **Every operator installs an agent** — a one-time cost for a fixed small
   group; also exactly why this is wrong for external SaaS.
3. **Free tier** — the Personal plan (3 users / 100 devices) covers the stated
   scenario.
4. **It authenticates the *device*, not each request** — a stolen unlocked
   device impersonates its operator. The app-layer envelope (audit `operator`,
   tier, allowlists, burst) remains mandatory; Tailscale is the outer door,
   not a substitute for the envelope.

### 5.3 Target architecture

```
[operator A's Claude] ─┐
[operator B's Claude] ─┼─ Tailscale tailnet ─→ [home host]
[operator C's Claude] ─┘                         └─ Docker Compose
                                                   ├─ safespace (oven/bun, non-root,
                                                   │             ONE container, ONE process)
                                                   │   ├─ MCP Streamable HTTP — bound to the
                                                   │   │   tailscale interface ONLY
                                                   │   └─ volume: audit.jsonl / accounts +
                                                   │       index files / encrypted token
                                                   │       store / drive-whitelist.json
                                                   └─ secret: SAFESPACE_SECRET_PASSPHRASE
                                                      (Compose secrets file-mount, or pulled
                                                       from GCP Secret Manager at start;
                                                       never at rest beside the store)
```

Operators configure their Claude's MCP server URL as
`http://<host>.<tailnet>.ts.net:<port>` — to the client it looks like a LAN
machine. Member joins = install Tailscale + admin approves device + one ACL
line. Member leaves = remove the device; connection-layer access ends
immediately, **no shared secret to rotate**.

---

## 6. Supporting stack details

1. **Packaging** — `Dockerfile` on an `oven/bun` base, multi-stage build,
   **non-root** user.
2. **Orchestration** — Docker Compose, single host. Kubernetes is explicitly
   rejected (§4.3).
3. **Binding** — the HTTP listener binds the tailscale interface (`100.x.y.z`),
   NOT `0.0.0.0`; the physical NIC exposes nothing. (Under fallback Option C:
   bind loopback, Caddy terminates TLS in front.)
4. **🔑 Secret injection (the biggest landmine):**
   - No Keychain in-container → FileBackend (AES-256-GCM/scrypt, v1.37) is the
     path; **F6 already forces the passphrase to be supplied**.
   - Passphrase source: at this scale **Docker Compose secrets (file mount,
     mode 600) is sufficient**; upgrade to **GCP Secret Manager** (natural fit,
     Google ecosystem) if read-audit of the secret itself is ever wanted.
   - NEVER baked into the image; NEVER plaintext in `docker-compose.yml`; the
     encrypted store and its passphrase are never at rest together.
5. **Persistence** — named volume (or bind mount) for `audit.jsonl`
   (cross-restart `run_id` session forensics depend on it), account/index
   files, the encrypted token store, `drive-whitelist.json`.
6. **Backup** — periodic snapshot of the volume elsewhere. The token store is
   already ciphertext, so backups need no extra encryption layer — but the
   passphrase never travels with the backup.
7. **Updates** — release → `docker compose pull && up -d`. A restart loses only
   per-session in-process state (tainted-source Set, burst windows) — these are
   per-session semantics by design; acceptable.
8. **Egress** — the container needs outbound HTTPS to Google / GitHub / LINE /
   Telegram / Discord APIs. An egress firewall is optional; SafeSpace already
   gates egress at the app layer (recipient allowlists, F3a, url-gate).

---

## 7. Readiness inventory — what is already built vs what is missing

**Already-landed foundations (each shipped for its own reason, all reusable
here):**

- ✅ `SecretBackend` abstraction + encrypted FileBackend (v1.37) → container-viable secret storage
- ✅ F6 token-at-rest enforcement (v1.55) → passphrase injection is forced, not optional
- ✅ per-row `operator` audit actor (v1.36) + `run_id` session forensics (v1.58)
- ✅ per-call `ctx.tier` seam (v1.38) → per-operator tier has a wiring point
- ✅ `accountId` + `provider`-keyed credential resolution (v1.70 G0–G4) → multi-account/multi-provider cleanly keyed in one store

**Formerly-missing blockers — ALL now shipped (the v1.73 + v1.74 PR-2 arc):**

- ✅ MCP Streamable HTTP transport (v1.73 — opt-in, loopback→tailnet-bound, DNS-rebind)
- ✅ operator authentication + per-connection identity + `OperatorContext` (v1.74.0 seam → v1.74.1 Tailscale WhoIs + `operators.json` registry, default-deny)
- ✅ per-operator tier resolution (v1.74.1 — the registry tier drives the envelope per connection). Per-operator *allowlists* (the `policyScope` seam) intentionally stay GLOBAL for the trusted-group model (§7/Q8 of the operator-auth design)
- ✅ in-process multi-operator account confinement (v1.74.2 — operator A can never resolve/fan-out to B's accounts; the isolation proof)
- ✅ **deployment artifacts (this PR):** `Dockerfile` / `docker-compose.yml` / `deploy/entrypoint.sh` / `deploy/operators.example.json` + the runbook `docs/DEPLOY.md`

---

## 8. The evolution path

**A → B → C, each step taken only when the previous step's pain is real:**

1. **NOW — Model A local ×N (zero cost).** Multi-person collaboration does NOT
   wait for Model B: each operator runs their own local instance (Keychain on
   Mac, FileBackend elsewhere), consents the shared accounts, and sets
   `SAFESPACE_OPERATOR_ID` so audit rows distinguish actors (v1.36). Costs:
   audit is scattered across N machines and allowlists are per-machine config —
   exactly the original BLOCKER 3/4, which Model B exists to converge, but not
   a blocker to *starting* collaboration.
2. **Model B scheduled — home host + Compose + Tailscale (§5).** The A→B move
   is a **CUTOVER** (§3.5): all operators converge on the shared server at
   once; running local instances alongside it against the same accounts is NOT
   supported.
3. **Only if membership ever grows past the trust boundary, or SafeSpace is
   offered externally** — public exposure (Option C posture or beyond) and a
   real auth gateway; re-open the Cloud Run / managed-platform question there,
   together with the storage-layer rewrite it requires.

---

## 9. Open decisions (NOT locked — for the owner when Model B is scheduled)

- **Q1 — Isolation model:** Option A single-container in-process (recommended,
  §3) vs Option B container-per-operator. Decides how transport + the auth
  gateway are designed; must be settled before Model B app-layer work starts.
- **Q2 — Network posture:** Tailscale private tailnet (recommended, §5.1) vs
  public VPS + Caddy + self-built auth gateway. Directly sizes the operator-auth
  work: connection-identity mapping vs a full account system.
- **Q3 — Passphrase source:** Docker Compose secrets (recommended at current
  scale) vs GCP Secret Manager.
