
# Proxy Gateway Manager — Technical Design v1.1

Target OS: Ubuntu 22.04
Interfaces: eth0 = WAN, ens19 = LAN (192.168.2.1/24)
Goal: Each LAN client egresses ONLY via its mapped upstream proxy. If that proxy is DOWN, the client is immediately blocked (no WAN fallback). Health is polled every 30s; exit IP and latency are recorded.


## 1. Architecture (microservices)

- pgw-api (Go): REST/gRPC control-plane, JWT auth, emits events.
- pgw-ui (Go + HTMX/Tailwind): dashboard and CRUD for proxies/clients/mappings.
- pgw-health (Go): periodic health checks -> updates DB -> publishes events.
- pgw-agent (Go): nftables reconciler + rule generator; owns enforcement.
- pgw-fwd (Go): local TCP forwarders per mapping that dial the specific upstream proxy.

Infra:
- DB: SQLite (dev) or Postgres 14+ (prod).
- Events: NATS (preferred) or Redis streams.
- Firewall: nftables via go-nftables.

Forward path:
LAN client -> ens19 -> PREROUTING nat REDIRECT to 127.0.0.1:<port> -> pgw-fwd -> upstream proxy -> Internet.

WAN leak prevention:
- FORWARD chain drops any LAN->WAN traffic by default.
- Agent never inserts ACCEPT to WAN; only REDIRECT to local listeners.
- On proxy DOWN, Agent rewrites the client's PREROUTING rule to DROP (RST) and keeps FORWARD drop.


## 2. Data model

Proxy(id, label, type=http|socks5, host, port, username, password, enabled, status, latency_ms, exit_ip, last_checked_at)
Client(id, ip_cidr, note, enabled)
Mapping(id, client_id, proxy_id, protocol=http|socks5, local_redirect_port, state=APPLIED|PENDING|FAILED, last_applied_at)
User(id, email, password_hash, role)

Telemetry is stored on the Proxy record and joined into listing responses.


## 3. Health algorithm (every 30s)

for each enabled proxy:
  1) tcp connect (deadline 2s)
  2) if http: GET https://api.ipify.org?format=text via Proxy (timeout 5s)
     if socks5: socks5 dial api.ipify.org:443 then TLS + GET / (timeout 5s)
  3) latency_ms = connect + handshake + first-byte
  4) if success: status=OK if latency < threshold (default 800ms), else DEGRADED
     if failure: status=DOWN
  5) persist telemetry; if changed, publish proxy.status_changed

API/UI uses the last telemetry; Agent listens to status changes to toggle per-client rules.


## 4. Reconciliation (pgw-agent)

Input: desired state from DB (mappings and proxy statuses)
Loop:
- enumerate active mappings
- for each mapping:
    - if proxy status in {OK, DEGRADED}: ensure PREROUTING rules redirect ip saddr to local port; ensure per-client DNS handling; ensure FORWARD drop LAN->WAN exists
    - if proxy status == DOWN: ensure PREROUTING rule drops this client; FORWARD drop remains
- ensure OUTPUT chain (optional strict mode) only allows user 'pgw' to reach upstream proxy IPs/ports in use
- garbage collect rules for deleted mappings

Agent is idempotent; it recalculates full desired ruleset on every tick and applies diffs.


## 5. nftables layout (inet table "pgw")

Chains:
- pgw_prerouting (nat, prerouting, prio -100)
- pgw_forward (filter, forward, prio 0)
- pgw_output (filter, output, prio 0)  [optional strict mode]

Rules (conceptual):
- pgw_forward: iifname "ens19" oifname "eth0" drop
- pgw_prerouting: ip saddr 192.168.2.3 tcp redirect to :15001
- pgw_prerouting: ip saddr 192.168.2.3 udp dport 53 redirect to :5353 (optional DNS capture)
- when proxy DOWN: ip saddr 192.168.2.3 drop
- pgw_output (strict mode): meta skuid "pgw" tcp daddr @proxy_targets accept; counter drop

The agent computes concrete rules from the mapping table.


## 6. DNS strategy (choose one)

Minimal mode (default):
- Do not intercept DNS; clients should use DoH/DoT over their proxy.
- Agent DROPs UDP/53 from clients to avoid cleartext leaks.

Enhanced mode:
- Run lightweight stub `pgw-dns` on 127.0.0.1:5353.
- Redirect client UDP/53 to stub; stub relays queries over the client's own forwarder socket (through the proxy).


## 7. API surfaces (overview)

See API_SPEC.yaml for full OpenAPI.
Key endpoints:
- POST /v1/auth/login  -> JWT
- GET/POST/PUT/DELETE /v1/proxies
- POST /v1/proxies/check
- GET/POST /v1/clients
- GET/POST/PUT/DELETE /v1/mappings
- POST /v1/apply
- GET /v1/events (SSE) for UI live updates


## 8. Security model (summary)

- Argon2id password hashing with per-user salt; JWT HS256 (short TTL) + refresh token.
- RBAC: admin (full) and viewer (read-only).
- HTTPS termination on UI/API; HSTS.
- Secrets via /etc/pgw/pgw.env or systemd drop-ins; do not commit secrets.
- Optional host OUTPUT strict mode: only uid 'pgw' -> upstream proxies allowed.
- Audit log for CRUD actions (append-only table).


## 9. Deployment notes

- sysctl: net.ipv4.ip_forward=1, rp_filter=0
- Services as systemd units; pgw-agent requires CAP_NET_ADMIN and usually runs with --network host if containerized.
- Postgres: enable WAL and daily dumps; or SQLite WAL with fsync on (for lab only).
- Docker alternative: see DEPLOYMENT_GUIDE.md


## 10. SLOs and health

- Health check interval: 30s (configurable).
- Time to block on proxy DOWN: < 1s on event path; < 5s on polling fallback.
- UI shows latency buckets: <200ms green, 200-800ms amber, >800ms red.

## 11. Failure cases

- NATS down: agent polls DB every 5s; UI falls back to polling.
- DB down: control-plane becomes read-only; existing nft rules keep working.
- Host reboot: systemd After=nftables.service; agent reconstructs rules from DB.


## 12. Roadmap heads-up

- TPROXY mode for UDP/TCP transparency
- Per-client bandwidth caps (TC)
- HA pair (VRRP) and state sync
- OAuth2 (OIDC) SSO

