# Proxy Gateway Manager — Overview (Combined README + Technical Design) v1.1

*Generated:* 2025-08-29T03:43:48

This document merges the original **README.md** (quick start, usage) and **TECHNICAL_DESIGN.md** (architecture & enforcement)
into a single entry point. It is the canonical landing page for all documentation in `docs_v1_1/`.

---

## Part A — README (Quick Start & Usage)

# Proxy Gateway Manager (Go, microservices)

Force each LAN client to exit the Internet via its **assigned upstream proxy**. If the proxy is unhealthy, **block** the client to avoid WAN IP leakage. Built for **Ubuntu 22.04** with **nftables** enforcement.

## Quick Start (Lab, single host)

### 0) Network
- **WAN:** `eth0`
- **LAN:** `ens19` with `192.168.2.1/24`

Make sure clients use `192.168.2.1` as **default gateway**.

### 1) Install prerequisites
```bash
sudo apt update
sudo apt install -y nftables ca-certificates
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-pgw.conf
sudo sysctl --system
```

### 2) Build binaries
```bash
git clone https://github.com/your-org/proxy-gw-manager.git
cd proxy-gw-manager
make build
```

Binaries produced:
- `pgw-api`, `pgw-ui`, `pgw-agent`, `pgw-health`, `pgw-fwd`

### 3) First run (SQLite + NATS in Docker)
```bash
cd deploy
sudo docker compose up -d
```

### 4) Create admin user
```bash
./pgw-api users create --email admin@example.com
```

### 5) Add a proxy
In UI -> **Configuration / Proxies** -> Add:  
- Type: `HTTP` or `SOCKS5`  
- Host/Port, Username/Password (if any)

The system will **health check** immediately and show **Exit IP** and **Latency**.

### 6) Map a client
In UI -> **Proxy Mappings -> Add**:  
- Client IP: e.g., `192.168.2.3`  
- Select the proxy you added

Upon **Save**, the API runs a health check. If `OK/DEGRADED`, Agent **applies rules**:
- TCP from `192.168.2.3` -> `127.0.0.1:<port>` (local forwarder)  
- UDP/53 redirected to local DNS (optional)  
- FORWARD LAN->WAN is **DROP**

If the proxy becomes **DOWN**, the client is **blocked** automatically.

---

## CLI/Env

Common env in `/etc/pgw/pgw.env`:
```
PGW_DB_DSN=sqlite3:///var/lib/pgw/pgw.db
PGW_NATS_URL=nats://127.0.0.1:4222
PGW_HEALTH_INTERVAL=30s
PGW_UI_ADDR=:8443
PGW_API_ADDR=:8080
PGW_AGENT_ADDR=127.0.0.1:9090
PGW_FORWARDER_BASE_PORT=15000
PGW_WAN_IFACE=eth0
PGW_LAN_IFACE=ens19
PGW_STRICT_OUTPUT=true
PGW_JWT_SECRET=change-me
```

---

## Health Check Logic

1. Dial upstream proxy.  
2. Request `https://api.ipify.org?format=text`.  
3. Save `exit_ip` and `latency_ms`.  
4. Publish event if status changed.

You can run an on-demand check:
```bash
curl -H "Authorization: Bearer <token>" -XPOST http://127.0.0.1:8080/v1/proxies/check \
  -d '{"proxy_id":"..."}'
```

---

## nftables Primer

- We create table `inet pgw` with chains:
  - `pgw_prerouting` (nat) – redirect per-client traffic to local forwarder
  - `pgw_forward` (filter) – drop LAN->WAN (no leaks)

Check rules:
```bash
sudo nft list ruleset | sed -n '/table inet pgw/,$p'
```

Reset (dangerous, removes table):
```bash
sudo nft delete table inet pgw || true
```

---

## Security

- UI/API protected by JWT; passwords hashed with Argon2id.  
- Role `admin` vs `viewer`.  
- Optional strict host OUTPUT filter so only the `pgw` process can reach the Internet (whitelisting upstream proxy IPs).

---

## Limitations (v1.0)

- TCP-only interception. For UDP apps besides DNS, traffic is dropped (no leak).  
- DNS: either redirect to local DNS over HTTPS or require clients to use DoH/DoT through the proxy themselves.

---

## Contributing

- Open issues/PRs on GitHub.  
- Run `make lint test`.  
- CI with GitHub Actions + Go 1.22.

---

## License

AGPL-3.0 (server-side changes must be shared).

---

## Part B — Technical Design

# Proxy Gateway Manager — Technical Design (v1.0)

> Target OS: **Ubuntu 22.04**  
> NICs: **eth0 = WAN**, **ens19 = LAN (192.168.2.1/24)**  
> Goal: Every LAN client’s traffic **must** egress via its assigned upstream proxy. If the proxy is unhealthy, **block the client completely** to avoid WAN IP leaks. Health is checked every **30s** and the **exit IP** + **latency** are updated in near‑real time.  
> Stack: **Golang + microservices**, control-plane UI, **nftables** for enforcement, **SQLite (or Postgres)** for state, **NATS** (or Redis streams) for events.

---

## 1) High‑level Architecture

```
+-----------------------+           +----------------------+
|        UI (Go)        |  HTTPS    |      API (Go)        |
| Dashboard / Mappings  +---------->+ REST/gRPC + Auth     |
| Config / Auth         |           | Emits events         |
+-----------+-----------+           +----------+-----------+
            ^                                  |
            |                                  v events (NATS)
            |                         +--------+--------+
            |                         |   HealthSvc     |
            |                         |  (check 30s)    |
            |                         +--------+--------+
            |                                  |
            |               +------------------+------------------+
            |               |                                     |
            v               v                                     v
+-----------+---------------+-------------+      +-----------------+----------+
|    Policy/Agent (Go) - nftables         |      |  Forwarder(s) (Go)         |
| - Programs nft rules/ipsets per client  |      | - Local listeners (per map)|
| - Enforces block-on-fail & no-leak      |      | - Dial upstream HTTP/SOCKS |
| - Redirects TCP to local forwarder port |      | - Optional DoH DNS tunnel  |
+----------------------+------------------+      +-----------------+----------+
                       |                                   |
                       |                                   |
           +-----------v-----------+            +----------v----------+
           |  LAN (ens19)          |            |   WAN (eth0)        |
           |  192.168.2.0/24       |            |  Internet           |
           +-----------------------+            +---------------------+
```

**Why this shape?**  
- The **Agent** owns nftables and never trusts client settings.  
- All TCP flows from a mapped client are **REDIRECT**ed to a **local Forwarder** port. The forwarder connects **only** to the mapped upstream proxy.  
- The **FORWARD** path from LAN→WAN is **DROP** by default to avoid accidental leaks.  
- If a proxy is **Unhealthy**, the Agent switches the client to **DROP** immediately (no fallback to WAN).  
- The **HealthSvc** verifies liveness + exit IP + latency, publishing results for UI and Agent.

---

## 2) Data Model

### 2.1 Entities
- **Proxy**  
  - `id` (uuid), `label`, `type` (`http|socks5`), `host`, `port`, `username`, `password`, `enabled`  
  - Derived/telemetry: `status` (`OK|DEGRADED|DOWN`), `latency_ms`, `exit_ip`, `last_checked_at`

- **Client**  
  - `id` (uuid), `ip_cidr` (e.g., `192.168.2.3/32`), `note`, `enabled`

- **Mapping** (1:1 required)  
  - `id` (uuid), `client_id`, `proxy_id`, `state` (`APPLIED|PENDING|FAILED`)  
  - Runtime: `local_redirect_port` (e.g., `15001`), `last_applied_at`

- **User** (for UI)  
  - `id`, `email`, `password_hash`, `role` (`admin|viewer`), `created_at`

### 2.2 Storage
- Development: **SQLite** (single file, WAL ON)  
- Production: **Postgres** 14+ (preferred).  
- **Migrations** via `golang-migrate`.

---

## 3) Services

### 3.1 API Service (`pgw-api`)
- **REST** (OpenAPI) + optional **gRPC**.
- Endpoints
  - `GET /health` – liveness
  - `POST /proxies` / `PUT /proxies/{id}` / `DELETE /proxies/{id}`
  - `GET /proxies` (with `status` filter)
  - `POST /clients`, `GET /clients`
  - `POST /mappings`, `PUT /mappings/{id}`
  - `POST /apply` – ask Agent to reconcile
  - `POST /auth/login` → JWT (HS256)  
- Emits events on **NATS** (`proxy.updated`, `mapping.updated`, `apply.request`).

### 3.2 UI Service (`pgw-ui`)
- Go + HTMX/Tailwind (no Node dependency) for simplicity.  
- Tabs: **Dashboard**, **Proxy Mappings**, **Configuration**, **Authentication**.  
- Live telemetry via Server‑Sent Events or WebSocket from API.

### 3.3 Health Service (`pgw-health`)
- Every **30s** (configurable):
  1. For each **enabled** proxy, perform a dial through the proxy:
     - Measure **TCP connect** time + **TLS handshake** time (when applicable).
     - Do an HTTP `GET https://api.ipify.org?format=text` (fallbacks: `https://ifconfig.me`, `https://ipinfo.io/ip`).  
       - Time budget: 5s.  
  2. Update `status`, `latency_ms`, `exit_ip`, `last_checked_at` in DB.  
  3. Publish `proxy.status_changed` if any field changed.  
- **Status derivation**:  
  - `OK` = request success & latency < threshold (default 800ms)  
  - `DEGRADED` = success but > threshold  
  - `DOWN` = failure or auth error

### 3.4 Policy/Agent (`pgw-agent`)
- Listens to events and **reconciles nftables** to match DB state.  
- For each `Mapping(client→proxy)`:
  - Allocate or reuse a **local redirect port** (e.g., `15000+index`).  
  - Program nftables:
    - **PREROUTING** (nat): Redirect all **TCP** from `client.ip/32` to `127.0.0.1:<redirect_port>`.
    - **PREROUTING** (nat): Redirect **UDP/53** from `client.ip/32` to local DNS proxy (prevents direct DNS).  
    - **FORWARD**: **DROP** any packets from `client.ip/32` to **eth0** (WAN).  
    - **INPUT**: Allow the client to reach **192.168.2.1** (the gateway) only.  
  - When proxy status becomes **DOWN** → replace redirect with **DROP** in PREROUTING for that client (and keep FORWARD DROP).  
- Exposes `POST /agent/reconcile` (local) for manual force‑apply.

### 3.5 Forwarder (`pgw-fwd`)
- A pool of lightweight **Go forwarders**, one **listener per mapping** bound to `127.0.0.1:<redirect_port>`.  
- For each inbound TCP connection:
  - **Dials the upstream proxy** (HTTP or SOCKS5) using mapping credentials.  
  - For **HTTP**, supports **CONNECT** tunnels and plain HTTP proxying.  
  - For **SOCKS5**, performs RFC1928 handshake then streams bytes.  
  - Enforces **hard egress**: connections are only made to the **configured upstream proxy**.  
- Optionally tags its process with Linux cgroup/uid so OUTPUT firewall can allow only this process to reach the Internet.

---

## 4) No‑Leak Design

1. **Default DROP** for all FORWARD traffic LAN→WAN on **eth0**.  
2. Only **PREROUTING REDIRECT** to local `pgw-fwd` is allowed; everything else from clients is dropped.  
3. The **host’s own OUTPUT** is allowed only to:
   - upstream proxy IPs/ports in use, and
   - DNS over HTTPS targets (if enabled), and
   - package mirrors/apt (admin switch).  
4. When a proxy is `DOWN`, the client’s PREROUTING rule switches to **DROP** (RST for TCP) to avoid hang/leak.

---

## 5) nftables layout

Family `inet`, table `pgw`:

- **Sets**
  - `clients_v4` – list of /32 client IPs
  - `proxy_targets` – list of `<ip,port>` of upstream proxies
- **Chains**
  - `pgw_prerouting` (type `nat`, hook `prerouting`, prio -100)
    - Per‑client rules (generated):  
      - `ip saddr 192.168.2.3 tcp redirect to :15001`  
      - `ip saddr 192.168.2.3 udp dport 53 redirect to :5353`  
      - `meta mark 0xDEAD drop` (when proxy DOWN)
  - `pgw_forward` (hook `forward`, prio 0)
    - `iifname "ens19" oifname "eth0" drop` (catch‑all)  
  - `pgw_output` (hook `output`, prio 0)
    - Allow `uid pgw` to `@proxy_targets`  
    - Drop otherwise (optional strict mode)

> Implementation uses **go‑nftables** to avoid shelling out to `nft`.

---

## 6) DNS Strategy

- Redirect all LAN port **53** to a local stub (`pgw-dns`), which resolves via **DoH** through the same client’s proxy by sending queries over the **listener port** (ensures per‑client isolation).  
- Minimal version: force **DROP** of UDP/53 and require clients to use DoH/DoT themselves through the proxy (simpler).

---

## 7) Health Check Details

- **TCP connect latency** measured with `net.Dialer` deadlines.  
- **HTTP proxy**:  
  - Build `http.Client{Transport: &http.Transport{Proxy: ...}}`  
  - Request `https://api.ipify.org?format=text`  
- **SOCKS5 proxy**:  
  - Use `golang.org/x/net/proxy` to dial `tcp` `api.ipify.org:443` and perform a short TLS GET.  
- Store latency (ms) and parse exit IP from body.  
- Retries: `3`, backoff `200ms * 2^n`.  
- Status transitions publish events for UI + Agent.

---

## 8) API (OpenAPI sketch)

- `GET /v1/mappings` → list with joined telemetry (`exit_ip`, `latency_ms`, `status`)  
- `POST /v1/mappings` body:
```json
{ "client_ip": "192.168.2.3", "proxy_id": "uuid", "protocol": "socks5|http" }
```
- `PUT /v1/mappings/{id}` → edit mapping; server will **health‑check first** then emit `apply.request` if OK.  
- `POST /v1/proxies/check` → ad‑hoc check; returns telemetry.  
- `POST /v1/apply` → reconcile all.

Authentication: `POST /v1/auth/login` → JWT; roles check via middleware.

---

## 9) UI/UX Notes

- **Proxy Mappings** table columns: *Client IP*, *Proxy Server*, *Username*, *Status* (badge + RTT), *Exit IP*, *Actions* (Edit/Delete).  
- **Add New Mapping** form: client IP (or pick from ARP), proxy select, port (default 1080), user/pass.  
- After **Add/Edit**: back‑end performs health check; if `OK|DEGRADED` → Agent apply; else show error.  
- **Dashboard**: cards—Total clients, Healthy/Down proxies, blocked clients, recent events.  
- **Configuration**: check interval, latency thresholds, DNS mode, strict output firewall ON/OFF.  
- **Authentication**: manage users, rotate JWT secret.

---

## 10) Deployment

### 10.1 System requirements
- Ubuntu 22.04, root or `cap_net_admin` for Agent
- `nftables` (default), `ip_forward=1`

### 10.2 Base sysctl
```
sudo tee /etc/sysctl.d/99-pgw.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF
sudo sysctl --system
```

### 10.3 Example bootstrap (minimal, single node)
1. Install Postgres or use SQLite.  
2. Install NATS (`apt` or docker).  
3. Build services:
```
make build
sudo systemctl enable --now pgw-agent pgw-api pgw-health pgw-ui
```
4. Confirm nftables:
```
sudo nft list ruleset | sed -n '/table inet pgw/,$p'
```

### 10.4 Docker Compose (alternative)
- One compose file with services (`api`, `ui`, `agent`, `health`, `nats`, `postgres`).  
- `agent` must run in `--cap-add NET_ADMIN --network host` to manage nftables and listen on 127.0.0.1.

---

## 11) Failure Modes & Handling

- **Proxy DOWN** → Agent sets client to **DROP** within one reconcile cycle (<1s after event).  
- **NATS down** → Agent runs local reconciliation loop (polls DB every 5s).  
- **API down** → Existing rules continue to enforce isolation.  
- **Host reboot** → systemd units re‑apply; Agent reconstructs nftables from DB.

---

## 12) Observability

- Structured logs (Zap) with request IDs.  
- Prometheus metrics:
  - `pgw_proxy_status{proxy_id}` (0/1)
  - `pgw_proxy_latency_ms{proxy_id}`
  - `pgw_client_blocked{client_ip}`
  - `pgw_forwarder_active{mapping_id}`
- Tracing with OpenTelemetry (optional).

---

## 13) Security

- Argon2id password hashing.  
- JWT, short TTL, refresh tokens.  
- RBAC: admin/viewer.  
- Secrets via `/etc/pgw/pgw.env` or Vault.  
- Optional: pin upstream proxy IPs in `pgw_output` chain; run forwarders under dedicated `pgw` user/cgroup.  
- CSRF protection for UI forms, HTTPS on UI/API.

---

## 14) Repository Layout

```
proxy-gw-manager/
  cmd/
    api/
    ui/
    agent/
    health/
    fwd/
  pkg/
    models/     # DB models + migrations
    nft/        # go-nftables helpers
    check/      # health checkers
    proxy/      # http/socks clients
    events/     # NATS wrappers
    auth/       # JWT, hashing
  web/          # static UI assets (htmx, tailwind, templates)
  deploy/
    systemd/
    docker-compose.yml
  Makefile
  README.md
  TECHNICAL_DESIGN.md
```

---

## 15) Minimal nftables Example

```bash
# Create table/chains
nft add table inet pgw
nft 'add chain inet pgw pgw_prerouting { type nat hook prerouting priority -100; }'
nft 'add chain inet pgw pgw_forward { type filter hook forward priority 0; }'

# Drop any forward LAN->WAN (ens19->eth0)
nft add rule inet pgw pgw_forward iifname "ens19" oifname "eth0" drop

# Example: client 192.168.2.3 mapped to local forwarder :15001
nft add rule inet pgw pgw_prerouting ip saddr 192.168.2.3 tcp redirect to :15001
# DNS capture (optional)
nft add rule inet pgw pgw_prerouting ip saddr 192.168.2.3 udp dport 53 redirect to :5353
```

The **Agent** will generate/remove the exact rules above per mapping.

---

## 16) Roadmap → v1.1
- UDP/TCP full TPROXY mode for better transparency
- Per‑client bandwidth caps/quotas
- HA (active‑standby) with VRRP
- OAuth2 (OIDC) login
- Audit log UI
- Import/export mappings via CSV
