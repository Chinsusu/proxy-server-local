# Continuous Integration

CI validates source quality; it is not a deployment approval hierarchy.

The standard checks are format, vet, unit/integration tests, dependency
verification, secret scanning, release-candidate validation, and non-root
deployment contracts. They run with minimal permissions and must never receive
gateway root credentials, runtime keys, or proxy credentials.

The protected system check retains Ubuntu 22.04 / systemd 249 unit compatibility
coverage; this is a runtime compatibility test, not an approval workflow.

The project owner may merge and deploy their own passing change. Pull requests,
CODEOWNERS, branch protection, and GitHub Actions are useful when collaborators
exist, but none is required for a self-managed gateway.

Before deployment, run the applicable local checks and record the commit,
candidate SHA-256, manifest SHA-256, and test results. CI artifacts are useful
diagnostics only; the gateway deployment still requires a backup, launcher
dry-run, one-client canary, and rollback point.

```bash
go vet ./...
go test -count=1 ./...
go mod verify
bash deploy/tests/hardening_test.sh
```

The protected-push candidate job publishes a closed self-managed candidate tar.
The gateway owner verifies its recorded digest, extracts it below a root-owned
inbox, then uses `pgw-release-launcher --adopt` for dry-run and apply. CI itself
never receives gateway root credentials and never deploys.
