# Requirement traceability — v2.0 current map

> This file keeps its legacy `v1.1` filename so existing links continue to
> work. The first section is the current PGW v2.0 trace. The original v1.1
> trace is retained below as historical context only.

| Req ID | Requirement | Implementation / design evidence | Verification evidence | Current state |
|---|---|---|---|---|
| P0-01 | Govern changes with a reliable baseline and CI | [GIT_WORKFLOW.md](GIT_WORKFLOW.md), [CI.md](CI.md), `.github/` controls | `main` protection and required checks must be verified in GitHub administration. | Incomplete |
| P0-02 | Enforce mapped TCP egress and report truthful state | [00_OVERVIEW_COMBINED.md](00_OVERVIEW_COMBINED.md), [architecture.md](architecture.md), `internal/agent`, `internal/api` | Repository tests; target-host redirect/status and client-egress canary tests. | Implemented/tested in code; host/canary pending |
| P0-03 | Preserve an immutable fail-close base kill-switch | [architecture.md](architecture.md), `pkg/nft`, `internal/agent` | Repository rules tests; target-host service-loss/no-WAN-leak capture. | Implemented/tested in code; host/canary pending |
| P0-04 | Reconcile immutable generations and retain verified LKG | [architecture.md](architecture.md), `internal/domain`, `internal/agent`, `internal/persistence/sqlite` | Repository generation/ACK/recovery tests; canary apply/fail/restart recovery. | Implemented/tested in code; host/canary pending |
| P0-05 | Use SQLite with migrations, guarded import, backup, and restore | [DB_SCHEMA.sql](DB_SCHEMA.sql), `internal/persistence/sqlite`, [SOP_BACKUP_RESTORE.md](SOP_BACKUP_RESTORE.md) | Repository migration/import/backup tests; target-host migration and restore evidence. | Implemented/tested in code; host/canary pending |
| P0-06 | Encrypt proxy secrets with AES-256-GCM and keep them out of public responses | [CONFIG_REFERENCE.md](CONFIG_REFERENCE.md), `internal/secret`, `internal/persistence/sqlite`, [API_SPEC.yaml](API_SPEC.yaml) | Repository redaction/secret tests; canary credential-delivery and log/audit review. | Implemented/tested in code; host/canary pending |
| P0-07 | Provide request-scoped logs, metrics, and reconcile visibility | [OBSERVABILITY.md](OBSERVABILITY.md), `pkg/observability`, `internal/api` | Repository observability tests; canary success and failure telemetry capture. | Implemented/tested in code; host/canary pending |
| P0-08 | Maintain privilege, transport, configuration, and lifecycle hardening | [SECURITY_MODEL.md](SECURITY_MODEL.md), [CONFIG_REFERENCE.md](CONFIG_REFERENCE.md), [deploy.md](deploy.md) | Repository hardening tests; host negative-path and configuration validation. | Implemented/tested in code; host/canary pending |
| P0-09 | Promote only externally attested releases | [CI.md](CI.md), [deploy.md](deploy.md), [RELEASE_TRUST.md](RELEASE_TRUST.md), `deploy/trust/external-attestor-handoff.json` | Independent orchestrator provisioning and offline promotion verification. | Blocked — `BLOCKED_UNPROVISIONED` |

## P1 trace — planned only after P0

| Req ID | Requirement | Acceptance condition | Current state |
|---|---|---|---|
| P1-01 | Retain `web_only` TCP allowlist and keep `all_tcp` off | Only approved TCP ports are redirected; UDP and IPv6 remain denied. | Deferred; current default is `web_only`. |
| P1-02 | Represent probe/capability `INCOMPATIBLE` separately from `DEGRADED` | A policy-capability mismatch cannot appear as transient health degradation. | Deferred. |
| P1-03 | Add an HTTPS adapter with CA/SNI/custom-CA controls | Positive and negative TLS/CA/SNI cases pass without fallback. | Deferred. |
| P1-04 | Complete SOCKS5 remote-DNS capability and production validation while UDP remains false | CONNECT/auth forwarding exists in code. Complete capability semantics and host/canary/production validation for remote DNS; UDP remains explicitly denied. | Partially implemented; P1 validation deferred. |
| P1-05 | Add MAC/VLAN identity and DNS policy | Identity changes and DNS failures remain fail-close and auditable. | Deferred. |
| P1-06 | Add UI validation and client egress proof | UI validates policy inputs and presents independently captured egress proof. | Deferred. |

## Historical v1.1 trace — retained for context only

This was the original v1.1 planning trace. Its design references and tests do
not override v2 ownership, UDS, SQLite, fail-close, or release-trust contracts.

| Req ID | Requirement | Source | Historical design/spec | Historical test(s) |
|---|---|---|---|---|
| R-001 | Each client egress only via mapped proxy | User brief | TECHNICAL_DESIGN_v1.1 §1/4/5 | ENF-001/002, FAIL-001 |
| R-002 | Health check every 30s; record exit IP and latency | User brief | TECHNICAL_DESIGN_v1.1 §3 | HLTH-001 |
| R-003 | Auto-apply rules only after health OK | User brief | v1 API spec and Agent | UI-001, HLTH-001 |
| R-004 | Block and no WAN leak when proxy is down | User brief | v1 no-leak design and nft | FAIL-001, ENF-002, no-leak capture |
| R-005 | UI tabs: Dashboard, Proxy Mappings, Configuration, Authentication | User brief | UI_SPEC | UI-001 |
| R-006 | JWT authentication and roles | User brief | SECURITY_MODEL, v1 API spec | AUTH-001 |
| R-007 | Deployment guides and artifacts | User brief | DEPLOYMENT_GUIDE | OPS-001 |
