# PGW v2.0 kickoff and evidence checklist

> This checklist establishes delivery readiness and evidence collection. It
> does **not** authorize installation, deployment, or production promotion.

## Current baseline

- P0-02 through P0-08 are implemented and repository-tested; host/canary
  acceptance evidence is still required.
- P0-01 is incomplete: `main` protection and independent reviewer availability
  have not been evidenced.
- P0-09 is `BLOCKED_UNPROVISIONED`: no independent external
  attestor/orchestrator is provisioned, so production promotion is unavailable.
- P1 is deferred until all P0 gates close.

## A. Governance and access — P0-01

- [ ] Name accountable Product, Technical, Agent/Platform, Security, QA, and
  Release owners.
- [ ] Configure and independently verify `main` protection, required checks,
  CODEOWNERS, and non-author review requirements in GitHub administration.
- [ ] Confirm CI runners can execute unprivileged repository validation only;
  they receive no deploy credential, release trust root, or signing authority.
- [ ] Record the change, incident, and evidence-retention process in the team
  delivery system.

## B. v2 architecture and scope

- [ ] Review [00_OVERVIEW_COMBINED.md](00_OVERVIEW_COMBINED.md),
  [architecture.md](architecture.md), and [CONFIG_REFERENCE.md](CONFIG_REFERENCE.md).
- [ ] Review [API_SPEC.yaml](API_SPEC.yaml) before integrating with `/v2`.
  New integrations use `/v2`; `/v1` is a limited compatibility layer.
- [ ] Confirm the separation of duties: UI/API do not manage nftables or
  Forwarders; Agent uses the protected UDS and is the sole runtime owner.
- [ ] Confirm P0 scope: IPv4 host identity and `web_only`; UDP and IPv6 remain
  denied, `all_tcp` remains off, and no direct-WAN fallback exists.
- [ ] Record P1 as deferred: capability-state refinement, HTTPS/SOCKS
  extensions, MAC/VLAN/DNS policy, and UI egress proof begin only after P0.

## C. Repository validation — P0-02 through P0-08

- [ ] Run and retain results for `go vet ./...`, `go test -count=1 ./...`,
  `go mod verify`, and `bash deploy/tests/hardening_test.sh` from a clean
  checkout.
- [ ] Review [TEST_PLAN.md](TEST_PLAN.md) and assign an evidence owner for each
  host/canary scenario HST-01 through HST-08.
- [ ] Review [SOP_BACKUP_RESTORE.md](SOP_BACKUP_RESTORE.md),
  [OBSERVABILITY.md](OBSERVABILITY.md), and [SECURITY_MODEL.md](SECURITY_MODEL.md).

## D. Canary-host readiness

- [ ] Preserve console or other out-of-band access before any canary mutation.
- [ ] Validate intended LAN/WAN interfaces, concrete LAN IPv4, nftables,
  systemd compatibility, disk capacity, and root-owned credential inbox paths.
- [ ] Prepare a representative SQLite backup and a controlled test client.
- [ ] Collect client-side results, WAN packet captures, full nftables rulesets,
  service state, reconcile state, and redacted logs for success and failure
  cases.
- [ ] Obtain independent review of the completed canary evidence.

## E. Release trust — P0-09

- [ ] Record that CI candidates and local rehearsals are non-promotable.
- [ ] Do not provision release authority in this repository or candidate CI.
- [ ] Provision the independent external attestor/orchestrator, pinned tools,
  custom trusted root, policy, and host entrypoint described in [deploy.md](deploy.md)
  and [RELEASE_TRUST.md](RELEASE_TRUST.md).
- [ ] Verify offline promotion only after independent provisioning. Until then,
  keep status `BLOCKED_UNPROVISIONED` and do not claim production promotion.

## Historical v1.1 kickoff — retained for context only

Generated: 2025-08-29 03:50. This former checklist is retained for archaeology;
it is not the v2 kickoff or release authorization.

- Assign PM, Tech Lead, Backend, Agent, UI, QA, and DevOps roles.
- Prepare Ubuntu 22.04 with `eth0` WAN and `ens19` LAN (`192.168.2.1/24`).
- Read `SCOPE_LOCK_v1.1.md`, the former v1.1 Definition of Done, the legacy API
  specification, database schema, and v1.1 test plan.
- Prepare CI runners, environment files, Docker/systemd assets, a client VM,
  and a basic nftables smoke test.
