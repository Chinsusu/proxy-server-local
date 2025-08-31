# PGW Quick Operations Checklist (Ubuntu 22.04)

1) System prep
- Ensure packages: nftables, dnsmasq
- Sysctl: /etc/sysctl.d/99-pgw.conf
  - net.ipv4.ip_forward=1
  - net.ipv4.conf.all.rp_filter=0
  - net.ipv4.conf.default.rp_filter=0
  - (Optional) disable IPv6 host-wide for simplicity
- Apply: sysctl --system

2) Env file (/etc/pgw/pgw.env)
- PGW_JWT_SECRET=...
- PGW_API_ADDR=:8080
- PGW_AGENT_ADDR=:9090
- PGW_UI_ADDR=:8081
- PGW_WAN_IFACE=eth0
- PGW_LAN_IFACE=ens19
- PGW_FORWARDER_BASE_PORT=15001
- PGW_FWD_MAX_PORT=15100
- (Important) PGW_AGENT_TOKEN=... (random)

3) Build & install
- make build or:
  - go build -o bin/pgw-api   ./cmd/api
  - go build -o bin/pgw-agent ./cmd/agent
  - go build -o bin/pgw-ui    ./cmd/ui
  - go build -o bin/pgw-fwd   ./cmd/fwd
- install -m 0755 bin/pgw-* /usr/local/bin/

4) Services (systemd)
- Enable/Start: pgw-api, pgw-agent, pgw-ui
- pgw-agent must have CAP_NET_ADMIN (AmbientCapabilities)
- (Optional) pgw-health

5) DNS for LAN clients
- dnsmasq on gateway 192.168.2.1:53 (ens19)
- Consider filter-AAAA to avoid IPv6 timeouts

6) Create resources
- Create Proxy (type=http, host:port, username/password, enabled=true)
- Health check Proxy → expect OK/DEGRADED
- Create Client (IPv4 only, /32)
- Create Mapping (client ↔ proxy)

7) Verify apply
- Forwarder: systemctl status pgw-fwd@<port> (active)
- nftables:
  - nft list table ip pgw | grep "ip saddr <client> ... redirect to :<port>"
  - nft list table inet pgw_filter (DROP LAN→WAN, allow DNS 53 and port)
- Traffic from client (192.168.2.X):
  - DNS: nslookup icanhazip.com 192.168.2.1
  - HTTP/S: curl https://icanhazip.com → exit IP = proxy IP

8) Cleanup
- Delete mapping → agent reconcile → rules removed
- If port unused → system stops pgw-fwd@<port>

9) Troubleshooting
- Logs: journalctl -u pgw-api|pgw-agent|pgw-fwd@<port> -n 200 --no-pager
- Verify env: /etc/pgw/pgw.env
- Confirm interfaces match real NICs (eth0/ens19)

