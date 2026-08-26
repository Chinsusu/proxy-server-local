# PGW v2.0 risk register

This register tracks current delivery risks. A repository implementation or
test is not host/canary evidence, deployment evidence, or production
promotion.

| ID | Risk | Likelihood | Impact | Mitigation / decision | Owner | Status |
|---|---|---|---|---|---|---|
| V2-R1 | `main` lacks verified protection or independent review | M | H | Complete P0-01 outside the repository: protect `main`, require checks and independent CODEOWNER review, then retain evidence. | Maintainer | Open |
| V2-R2 | A host-specific nftables, interface, or systemd condition defeats fail-close assumptions | M | Critical | Complete P0-02/03/08 canary tests, including service-loss and no-direct-WAN packet capture, before any rollout. | Agent/Platform | Open — host acceptance pending |
| V2-R3 | Generation, LKG, or recovery behavior is not validated across an actual restart/failure | M | Critical | Run P0-04 canary apply/fail/restart/recovery scenarios and save verified evidence. | Agent/Platform | Open — host acceptance pending |
| V2-R4 | Migration, import, backup, or restore is unsafe for target data | M | H | Use a representative canary database; run integrity, backup, restore, and rollback verification under P0-05. | Data/Platform | Open — host acceptance pending |
| V2-R5 | Credentials leak through an untested host integration | L | Critical | Use systemd credentials; review API/log/audit output during P0-06 canary validation. Never use plaintext environment variables. | Security | Open — host acceptance pending |
| V2-R6 | Metrics/status can be mistaken for proof of client egress | M | H | Treat UI/API state as observability only. Obtain separate client-side and packet-capture evidence; P1-06 formalizes egress proof. | QA/Platform | Open |
| V2-R7 | A repository CI candidate is mistaken for an approved production release | M | Critical | Keep promotion fail-closed. P0-09 remains `BLOCKED_UNPROVISIONED` until an independent external attestor/orchestrator is provisioned. | Release/Security | Open — blocked |
| V2-R8 | P1 protocol, DNS, or identity features broaden egress before P0 is closed | M | Critical | Do not enable `all_tcp`, UDP, IPv6, HTTPS extensions, or MAC/VLAN/DNS policy work as a release shortcut. SOCKS5 CONNECT/auth forwarding exists, but remote-DNS capability and host/canary/production validation still require P1 evidence. | Product/Security | Open — deferred |

## Historical v1.1 register — retained for context only

The former v1.1 risks below remain useful background, but their mitigations do
not replace the v2 controls above.

| ID | Historical risk | Likelihood | Impact | Historical mitigation | Owner |
|---|---|---|---|---|---|
| R1 | nftables conflicts with existing rules | M | H | Dedicated table, namespaced chains, preflight check | Agent Lead |
| R2 | WAN leak due to misapplied rules | L | H | Default FORWARD drop, acceptance test, manual reconcile | Agent Lead |
| R3 | Upstream proxy rate-limits health checks | M | M | Backoff/jitter and multiple exit-IP providers | Backend |
| R4 | Secret sprawl (proxy credentials) | M | H | Server-side storage, restricted UI display, audit log | PM/Security |
| R5 | Performance with 256+ mappings | M | M | Listener pool, reuse, microbenchmarks | Tech Lead |
| R6 | Single host failure | M | M | Backups, documented restore, future HA | DevOps |
