
# Contributing to PGW

This page is the entry point for contributors. The normative engineering rules
are split into focused documents:

- [Coding Standards](CODING_STANDARDS.md) — code, tests, security, data-plane
  safety, and documentation conventions.
- [Git Workflow](GIT_WORKFLOW.md) — branches, commits, pull requests, reviews,
  merge, releases, hotfixes, and reverts.
- [Continuous Integration](CI.md) — required checks, local equivalents, CI
  permissions, and future privileged network tests.

If these documents conflict with a security or fail-close requirement, the
stricter requirement wins. Network behavior must remain backward compatible
unless an approved change explicitly documents the impact and rollback.

## Development baseline

- Go version and toolchain are defined by [`go.mod`](../go.mod); do not copy a
  different version into automation.
- The Forwarder contains Linux-specific socket handling. Run the authoritative
  full build and test suite on Linux, matching GitHub Actions.
- Use `make build` for the five deployed services. Webhook-driven deployment is
  unsupported and must not be added to release automation.
- Never commit real proxy credentials, JWTs, private keys, production state,
  generated binaries, or traffic captures containing sensitive data.

## Before opening a pull request

Format the Go files changed by the branch, then run the blocking checks on
Linux:

```bash
git diff --name-only --diff-filter=ACMR origin/main -- '*.go' \
  | xargs -r gofmt -w
go vet ./...
go test ./...
go build ./...
```

Also run the relevant focused tests and inspect the resulting diff:

```bash
git diff --check
git status --short
```

Shell changes must pass ShellCheck. UI changes require browser evidence for the
affected states. Firewall, forwarding, mapping, proxy, or routing changes must
include fail-close evidence and a rollback procedure as described in the Git
workflow.

## Change submission

When using a pull request, include:

1. Link an issue or explain why no issue is needed.
2. State behavior before and after the change.
3. Identify compatibility, security, migration, and operational impact.
4. Include tests and evidence proportional to risk.
5. Keep secrets and sensitive traffic data out of logs and attachments.
6. Pass all required CI checks before merge. External review is optional for a
   self-managed project and may be used when collaborators are available.

Use the repository pull request template when it is helpful; a maintainer may
merge a direct change after recording the same scope, tests, and rollback facts.
