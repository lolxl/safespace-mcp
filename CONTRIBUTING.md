# Contributing to SafeSpace MCP

Thanks for your interest in SafeSpace MCP — the security-first safety gateway
between an AI agent and the external sources it touches (Google Workspace,
GitHub, Notion, web-fetch, the filesystem, LINE / Telegram / Discord). This
guide covers how to report issues, propose changes, and get a pull request
merged.

> **Adding a connector?** See [`docs/ADDING-A-CONNECTOR.md`](docs/ADDING-A-CONNECTOR.md)
> — the three connector classes, the edit-site checklist, and the egress gate
> that CI *requires* for any tool that sends data out.

## Reporting a security vulnerability

**Do not open a public issue, PR, or discussion for a security vulnerability.**
SafeSpace is a security tool; a public report can expose users before a fix
ships. Use the private channel described in [`SECURITY.md`](SECURITY.md)
(GitHub ▸ Security ▸ Advisories ▸ *Report a vulnerability*). Everything else —
bugs, features, questions — is welcome in the open.

## Before you start

- For anything larger than a small fix, **open an issue first** so we can agree
  on the approach before you write code. SafeSpace makes deliberate, documented
  security trade-offs; a quick discussion saves a round-trip on the PR.
- Read the [`README.md`](README.md) for the architecture and the three security
  pillars, and [`SECURITY.md`](SECURITY.md) for the trust boundary (**Model A**:
  one human operator per local process). Changes that weaken a documented control
  need to say so explicitly and justify it.

## Development setup

The plugin and all its source live under `.claude-plugin/`. Run every dev command
from there.

```bash
git clone https://github.com/lolxl/safespace-mcp.git
cd safespace-mcp/.claude-plugin
bun install
```

> **Note:** the repository root has no `bunfig.toml`, so `bun test` from the root
> finds zero test files and exits silently. Always `cd .claude-plugin` first.

## Tests and type checking

```bash
cd .claude-plugin
bun test          # full suite (2000+ tests)
bun run typecheck # tsc --noEmit, must be clean
```

Both must pass before a PR can merge — CI enforces them.

- **`src/sanitize/` requires 100% branch coverage** (CI job `sanitize-coverage`).
  Any change under `src/sanitize/` must keep that gate green.
- New behavior needs tests. We lean heavily on **sentinel tests** that pin a
  security invariant and fail loudly if a future change regresses it — match that
  style when you touch a security path.

## Coding conventions

- **TypeScript**, run on [Bun](https://bun.sh). Keep the existing module
  boundaries (`src/auth`, `src/sanitize`, `src/sheets`, `src/policy`,
  `src/tools/handlers`, `src/tools/registry`, …) — put new code where its
  neighbors live rather than growing a catch-all file.
- Match the surrounding code's naming, comment density, and idioms.
- Touching `auth`, `sanitize`, OAuth scopes, or anything that reads untrusted
  external content is the highest-scrutiny path — expect a thorough security
  review and explain the threat model in your PR description.

## Pull request process

1. Branch from `main` (e.g. `feat/...`, `fix/...`, `docs/...`, `refactor/...`,
   `chore/...`).
2. Keep each PR to one logical change. Update tests and any affected docs in the
   same PR.
3. Use clear commit messages — a [Conventional Commits](https://www.conventionalcommits.org/)
   prefix (`feat:`, `fix:`, `docs:`, `refactor:`, `chore:`) matching the change.
4. If you bump the version, all three manifests (`package.json`,
   `marketplace.json`, `plugin.json`) must stay in sync — `scripts/check-manifest-versions.sh`
   and a CI sentinel enforce this.
5. Open the PR against `main`, fill in the template, and make sure CI is green.
   PRs are **squash-merged**.

## License

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
