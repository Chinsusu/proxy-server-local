# PGW v2.0 roadmap and release state

> **Status as of 2026-08-26:** P0-02 through P0-08 are implemented and
> covered by repository tests. They still require host and canary acceptance
> evidence. P0-01 is incomplete, and P0-09 is fail-closed
> `BLOCKED_UNPROVISIONED`. This document does **not** authorize deployment or
> production promotion.

PGW v2 delivers a fail-closed, TCP web-egress control plane. The authoritative
architecture is in [00_OVERVIEW_COMBINED.md](00_OVERVIEW_COMBINED.md) and
[architecture.md](architecture.md). API and UI never own nftables or Forwarder
lifecycle; the Agent does.

## P0 — required before P1

| ID | Outcome | Current repository state | Release gate |
|---|---|---|---|
| P0-01 | Governance, baseline, and CI | **Incomplete.** CI and contribution controls exist in the repository, but `main` protection is not yet evidenced. | Configure and verify branch protection and required checks in GitHub administration; retain the evidence. |
| P0-02 | Enforcement and honest status | **Implemented and repository-tested.** Agent-owned redirects, Forwarders, data-plane state, and UI/API status are present. | Run host/canary traffic tests and record the observed status. |
| P0-03 | Immutable base kill-switch | **Implemented and repository-tested.** Static base policy is separate from Agent dynamic state and remains fail-close. | Verify on the target host that service loss never opens LAN-to-WAN forwarding. |
| P0-04 | Generation, reconcile, and LKG | **Implemented and repository-tested.** Immutable snapshots, hash/generation checks, ACKs, LKG, and recovery journal are present. | Exercise apply, failure, restart, and recovery on a canary host. |
| P0-05 | SQLite, migrations, import, and backup | **Implemented and repository-tested.** SQLite is authoritative; migrations and guarded import/backup paths are present. | Run migration, backup, restore, and integrity checks using host data. |
| P0-06 | AES-256-GCM secret handling | **Implemented and repository-tested.** Proxy credentials are encrypted at rest and redacted from public API, logs, and audit data. | Verify credential delivery and redaction on the canary host. |
| P0-07 | Observability | **Implemented and repository-tested.** Structured request-scoped logs, metrics, and reconcile state are present. | Capture host/canary dashboards, logs, and failure-path evidence. |
| P0-08 | Hardening | **Implemented and repository-tested.** Privilege separation, UDS-only Agent control, strict configuration, and lifecycle hardening are present. | Complete target-host hardening and negative-path acceptance checks. |
| P0-09 | Signed release, rehearsal, and promotion | **Blocked — `BLOCKED_UNPROVISIONED`.** Repository CI can create only a diagnostic candidate and non-root rehearsal evidence. | Provision the independent, pinned external attestor/orchestrator described in [deploy.md](deploy.md) and [RELEASE_TRUST.md](RELEASE_TRUST.md). Until then, production promotion is unavailable. |

### P0 completion criteria

P0 is complete only when all of the following are true:

- P0-01 governance controls are verified and the evidence retained.
- P0-02 through P0-08 have current host/canary acceptance evidence, including
  fail-close and no-direct-WAN tests.
- P0-09 is no longer `BLOCKED_UNPROVISIONED` and the external attestor (a
  separate trust domain the maintainer provisions, independent of this
  repository and its CI - not a second person) has
  verified a promotion. A local candidate, CI artifact, rehearsal, or a
  documentation change is not a promotion.

## P1 — deferred until P0 completes

P1 work must not broaden the data-plane while any P0 gate remains open. The
following items are approved as the next sequence, not as production claims.

| ID | Capability | Current state |
|---|---|---|
| P1-01 | `web_only` policy and TCP allowlist, with `all_tcp` off | The v2 default is `web_only` (TCP 80/443); no `all_tcp` policy is enabled. Further policy expansion is deferred. |
| P1-02 | Capability/probe state distinguishes `INCOMPATIBLE` from `DEGRADED` | Deferred; do not infer capability from a proxy protocol label or a health result. |
| P1-03 | HTTPS adapter with CA, SNI, and custom-CA handling | Deferred pending P0 closure and a capability-safe contract. |
| P1-04 | SOCKS5 adapter with authentication, remote DNS, and UDP explicitly false | SOCKS5 CONNECT/auth forwarding exists and is repository-tested. Remote-DNS capability semantics and host/canary/production validation remain P1; UDP remains denied. |
| P1-05 | MAC/VLAN client identity and DNS policy | Deferred; v2 P0 identity is IPv4 host CIDR only and IPv6 is deny-only. |
| P1-06 | UI validation and egress proof | Deferred; P0 UI/status paths must not be represented as proof of client egress. |

## Delivery evidence

- [API_SPEC.yaml](API_SPEC.yaml) is the current `/v2` control-plane contract.
- [TEST_PLAN.md](TEST_PLAN.md) distinguishes repository coverage from required
  host/canary acceptance evidence.
- [REQ_TRACE_v1.1.md](REQ_TRACE_v1.1.md) retains the legacy trace and maps the
  v2 P0/P1 outcomes to implementation and acceptance evidence.
- [CI.md](CI.md), [deploy.md](deploy.md), and [RELEASE_TRUST.md](RELEASE_TRUST.md)
  define the non-promotable candidate boundary and P0-09 block.

## Historical v1.1 roadmap — retained for context only

The following material described the former v1.1 MVP. It is not an executable
plan, acceptance contract, or release authorization for PGW v2.

| Historical phase | Historical scope |
|---|---|
| v1.1 | TCP redirect MVP, 30-second health checks, UI tabs, block-on-fail, Docker Compose, and systemd examples. |
| v1.2 | TPROXY (UDP and TCP), `tc` quotas, mapping CSV import/export, and audit UI/search. |
| v1.3 | HA/VRRP, OIDC SSO, and multi-tenant organizations/projects. |

Historical v1.1 targets such as immediate health-gated mapping creation,
SSE/WebSocket updates, Docker Compose deployment, TPROXY/UDP planning, and the
former performance numbers do not override the v2 architecture or P0/P1 gates.
