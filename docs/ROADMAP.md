
# Roadmap

v1.1 (this docs):
- MVP enforcement (tcp redirect), health 30s, UI tabs, block-on-fail
- Docker Compose and systemd examples

v1.2:
- TPROXY mode (UDP+TCP)
- Per-client quotas via tc
- CSV import/export for mappings
- Audit UI and event search

v1.3:
- HA pair with VRRP
- OIDC SSO
- Multi-tenant orgs/projects


## Definition of Done — v1.1 (MVP, Scope Locked)

**Functional**
- Per-client enforcement via nftables:
  - NAT PREROUTING redirect (TCP) from `192.168.2.0/24` clients to `127.0.0.1:<port>` per mapping.
  - FORWARD chain **drops** all `ens19 -> eth0` traffic (no WAN leak path).
  - DNS minimal mode: **DROP UDP/53** from clients. (Enhanced DoH stub is optional and may be off by default.)
- Health service runs every **30s**; records `status`, `latency_ms`, `exit_ip`.
- Add/Edit Mapping: **health-gated**; on success, Agent auto-applies rules; on failure, mapping rejected.
- Proxy **DOWN** -> client **blocked** within **<1s** via event path; **<5s** via polling fallback.
- UI (4 tabs): Dashboard, Proxy Mappings, Configuration, Authentication; live badges via SSE/WebSocket.
- AuthN/AuthZ: JWT (HS256), roles `admin`/`viewer`; passwords **Argon2id**.
- API conforms to `API_SPEC.yaml` (subset required by UI end-to-end).

**Security & Compliance**
- No-WAN-leak guarantee proven by test: with proxy DOWN, **0 packets** from client IP traverse `eth0` (tcpdump).
- CSRF for form posts; HTTPS termination supported; secrets from env files; audit log for CRUD.
- Optional strict OUTPUT mode documented and test-covered (allow only `uid pgw` -> upstream proxies).

**Observability**
- Prometheus metrics: proxy status/latency, client blocked, forwarder active.
- Structured logs (request IDs).

**Performance (bench, single host)**
- Support **≥256** active mappings.
- Forwarder overhead: added TCP connect latency **≤30ms P95** on local lab net.
- Agent reconcile loop CPU **<5%** idle; memory **<128MB** per service typical.

**Operability**
- Docker Compose + systemd samples; environment template; DB migrations.
- Host reboot: rules re-applied and all mappings effective within **≤5s** after services up.

**Documentation**
- Docs Pack v1.1 present (this folder) incl. SCOPE_LOCK, API spec, DB schema, Deployment, Security, Test Plan.

**Out of Scope (v1.1)**
- UDP application traffic (beyond DNS handling); TPROXY; bandwidth quotas; HA/VRRP; OIDC SSO; multi-tenant orgs.

