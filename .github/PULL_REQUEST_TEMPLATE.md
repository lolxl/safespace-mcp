## Summary

<!-- What does this PR change, and why? Link any related issue. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / cleanup (no behavior change)
- [ ] Docs
- [ ] Security hardening

## Security impact

<!-- Does this touch auth, sanitize, OAuth scopes, allowlists, or any path that
reads untrusted external content? If yes, describe the threat model and how the
change preserves (or deliberately changes) a control documented in SECURITY.md.
If no, write "none". -->

## Testing

- [ ] `cd .claude-plugin && bun test` passes
- [ ] `cd .claude-plugin && bun run typecheck` is clean
- [ ] Added or updated tests for the change
- [ ] If `src/sanitize/` changed, branch coverage stays at 100%

## Checklist

- [ ] One logical change; commits use a Conventional Commits prefix
- [ ] If the version was bumped, all three manifests are in sync
- [ ] Updated any affected docs
