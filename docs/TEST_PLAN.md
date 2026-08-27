# PGW v2.0 test and acceptance plan

> **Evidence boundary:** P0-02 through P0-08 are implemented and covered by
> repository tests. That is not evidence that a target host has been installed,
> exercised with client traffic, or promoted. P0-01 remains incomplete and
> P0-09 remains `BLOCKED_UNPROVISIONED`.

This plan separates repeatable repository validation from the host/canary
acceptance that must precede any rollout. It does not authorize deployment or
production promotion.

## 1. Repository validation — P0-02 through P0-08

Run these checks from a clean, unprivileged checkout. Capture the commit SHA,
tool versions, command output, and any test artifacts with the result.

```bash
go vet ./...
go test -count=1 ./...
go mod verify
bash deploy/tests/hardening_test.sh
```

Repository coverage must include, at minimum:

| ID | P0 outcome | Required repository evidence |
|---|---|---|
| T-P0-02 | Enforcement and status | Agent/API/Forwarder tests cover desired state, data-plane state, redacted responses, and no direct control from UI/API to nftables. |
| T-P0-03 | Immutable base kill-switch | Rules rendering and negative-path tests show the static base policy is separate from dynamic Agent state and UDP/IPv6 remain denied. |
| T-P0-04 | Generation, reconcile, and LKG | Snapshot hash/generation, ACK, stale-generation, LKG, and recovery tests pass. |
| T-P0-05 | SQLite and recovery data | Migration, transaction, idempotency, import, backup, restore, and integrity tests pass. |
| T-P0-06 | Secret handling | AES-256-GCM, credential redaction, and no-secret public response/log/audit tests pass. |
| T-P0-07 | Observability | Request-ID, route redaction, metrics, and reconcile telemetry tests pass. |
| T-P0-08 | Hardening | UDS-only Agent access, configuration rejection, privilege/lifecycle contracts, and deployment hardening tests pass. |

## 2. Host and canary acceptance — still required

Run these scenarios only on a provisioned canary with preserved out-of-band
access. Do not treat a developer machine, CI runner, or non-root rehearsal as
equivalent evidence. Save commands, timestamps, packet captures, rulesets,
service state, and relevant redacted logs.

| ID | Scenario | Pass condition | P0 link |
|---|---|---|---|
| HST-01 | Install/configuration preflight | The target has the intended LAN/WAN interfaces and validated concrete LAN IPv4; invalid or wildcard management binds are rejected. | P0-08 |
| HST-02 | Mapped client egress | A client mapped to an active `web_only` proxy reaches only TCP/80 and TCP/443 through the configured upstream. The observed result matches API/Agent status. | P0-02 |
| HST-03 | No direct WAN path | With a proxy, Forwarder, API, or Agent failure, capture shows zero direct client packets on the WAN interface. The base policy remains intact. | P0-03 |
| HST-04 | Generation/reconcile recovery | Activate, suspend, rotate, and delete mappings; inject a failed apply and restart. Agent verifies or quarantines rather than reporting an unverified state as applied. | P0-04 |
| HST-05 | Database and recovery data | Perform migration, guarded import, backup, restore, and `PRAGMA integrity_check` against representative canary data. | P0-05 |
| HST-06 | Credential and redaction review | Confirm systemd credential delivery and inspect API responses, audit records, and logs for absent plaintext proxy passwords. | P0-06 |
| HST-07 | Observability failure paths | Trigger controlled proxy/reconcile failures and confirm request IDs, bounded error information, metrics, and status transitions. | P0-07 |
| HST-08 | Privilege and transport negatives | Verify the UI cannot call Agent endpoints, Agent internal API rejects TCP, and unauthorized/invalid configuration requests fail closed. | P0-08 |

### Canary evidence checklist

- [ ] Target identity, interface names, and exact test configuration are recorded.
- [ ] Client-side egress results are captured separately from control-plane status.
- [ ] WAN packet capture covers normal, proxy-down, Forwarder-down, API-down,
  and Agent-down cases.
- [ ] Full `nft list ruleset`, service state, reconcile state, and redacted
  logs are attached for each failure scenario.
- [ ] Database backup/restore evidence includes integrity results and rollback
  outcome.
- [ ] The maintainer re-checks the evidence in a separate verification pass
  from execution, and retains it.

## 3. P0-01 and P0-09 gates

P0-01 and P0-09 are not satisfied by test execution alone.

| Gate | Required evidence | Current state |
|---|---|---|
| P0-01 governance | `main` protection and required status checks are verified in GitHub administration and the evidence retained. | Incomplete |
| P0-09 promotion | Independent external attestor/orchestrator is provisioned; its pinned policy verifies a closed candidate and produces an offline promotion receipt. | `BLOCKED_UNPROVISIONED` |

Repository CI and `deploy/rehearse-release.sh` can create diagnostic candidate
and non-root rehearsal evidence only. They cannot be cited as a production
promotion result.

## 4. P1 test design — deferred until P0 is complete

| ID | Future capability | Minimum acceptance tests |
|---|---|---|
| P1-01 | `web_only` / TCP allowlist, `all_tcp` off | Positive TCP/80 and TCP/443 tests plus negative non-web TCP, UDP, and IPv6 tests. |
| P1-02 | `INCOMPATIBLE` vs `DEGRADED` | A policy-capability mismatch is reported as incompatible, never as transient degraded health. |
| P1-03 | HTTPS adapter and CA/SNI/custom CA | Valid and invalid certificate chains, SNI, custom CA, and no-fallback tests. |
| P1-04 | SOCKS5 remote-DNS capability and production validation, UDP false | CONNECT/auth forwarding is repository-tested. Add capability-state and host/canary remote-DNS validation; UDP remains positively denied. |
| P1-05 | MAC/VLAN identity and DNS policy | Identity movement/spoofing and DNS allow/deny tests remain fail-close. |
| P1-06 | UI validation and egress proof | Invalid policy input is blocked; displayed proof links to independently captured client/packet evidence. |

## 5. Historical v1.1 plan — retained for context only

The following was the old v1.1 test plan. It is not the v2 acceptance contract.

| Area | Historical test ID | Historical description |
|---|---|---|
| Enforcement | ENF-001 | PREROUTING redirect per client |
| Enforcement | ENF-002 | FORWARD drop LAN-to-WAN |
| Failover | FAIL-001 | Proxy down causes drop within one second |
| Health | HLTH-001 | Latency and exit IP captured |
| UI | UI-001 | Add/edit/delete mapping flows |
| Auth | AUTH-001 | Admin/viewer RBAC |
| Performance | PERF-001 | 256-mapping overhead |
| Operations | OPS-001 | Reboot re-apply |

The former v1.1 health-gate timing, SSE/WebSocket expectation, Dockerized E2E
harness, reboot target, and 256-mapping target require re-validation and v2-safe
test design before they can become current acceptance criteria.
