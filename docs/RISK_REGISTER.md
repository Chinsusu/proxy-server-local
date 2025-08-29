
# Risk Register (v1.1)

| ID | Risk | Likelihood | Impact | Mitigation | Owner |
|---|---|---|---|---|---|
| R1 | nftables conflicts with existing rules | M | H | Use dedicated table `inet pgw`; namespace chains; preflight check | Agent Lead |
| R2 | WAN leak due to misapplied rules | L | H | Default FORWARD drop; acceptance test ENF-002; manual reconcile command | Agent Lead |
| R3 | Upstream proxy rate-limits health checks | M | M | Backoff & jitter; multiple exit-IP providers | Backend |
| R4 | Secret sprawl (proxy creds) | M | H | Store server-side; restrict UI display; audit log | PM/Sec |
| R5 | Performance with 256+ mappings | M | M | Listener pool, reuse, microbenchmarks | Tech Lead |
| R6 | Single point of failure (host) | M | M | Backups, documented restore, HA in v1.3 | DevOps |
