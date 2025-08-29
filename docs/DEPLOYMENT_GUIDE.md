
# Deployment Guide (Ubuntu 22.04)

## 0) Network
- WAN: eth0
- LAN: ens19, address 192.168.2.1/24

## 1) System prep
```bash
sudo apt update
sudo apt install -y nftables ca-certificates curl jq
cat <<EOF | sudo tee /etc/sysctl.d/99-pgw.conf
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF
sudo sysctl --system
```

## 2) Postgres + NATS (docker)
```bash
sudo apt install -y docker.io docker-compose-plugin
mkdir -p /opt/pgw
cat >/opt/pgw/docker-compose.yml <<'YML'
services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: pgw
      POSTGRES_USER: pgw
      POSTGRES_DB: pgw
    volumes: [ "pgdata:/var/lib/postgresql/data" ]
  nats:
    image: nats:2
    command: -js
  pgw-api:
    image: ghcr.io/your-org/pgw-api:latest
    env_file: [ /opt/pgw/pgw.env ]
    depends_on: [ postgres, nats ]
    ports: [ "8080:8080" ]
  pgw-ui:
    image: ghcr.io/your-org/pgw-ui:latest
    env_file: [ /opt/pgw/pgw.env ]
    depends_on: [ pgw-api ]
    ports: [ "8443:8443" ]
  pgw-agent:
    image: ghcr.io/your-org/pgw-agent:latest
    env_file: [ /opt/pgw/pgw.env ]
    network_mode: host
    cap_add: [ "NET_ADMIN" ]
    depends_on: [ pgw-api ]
  pgw-health:
    image: ghcr.io/your-org/pgw-health:latest
    env_file: [ /opt/pgw/pgw.env ]
    depends_on: [ pgw-api ]
volumes:
  pgdata: {}
YML
```

Create env file:
```bash
cat >/opt/pgw/pgw.env <<'ENV'
PGW_DB_DSN=postgres://pgw:pgw@postgres:5432/pgw?sslmode=disable
PGW_NATS_URL=nats://nats:4222
PGW_HEALTH_INTERVAL=30s
PGW_UI_ADDR=:8443
PGW_API_ADDR=:8080
PGW_AGENT_ADDR=127.0.0.1:9090
PGW_FORWARDER_BASE_PORT=15000
PGW_WAN_IFACE=eth0
PGW_LAN_IFACE=ens19
PGW_STRICT_OUTPUT=true
PGW_JWT_SECRET=change-me
ENV
```

Start:
```bash
sudo docker compose -f /opt/pgw/docker-compose.yml up -d
```

## 3) Bare-metal systemd (optional)

Unit example for pgw-agent:
```
[Unit]
Description=PGW Agent
After=network-online.target nftables.service
Wants=network-online.target

[Service]
User=pgw
Group=pgw
AmbientCapabilities=CAP_NET_ADMIN
EnvironmentFile=/etc/pgw/pgw.env
ExecStart=/usr/local/bin/pgw-agent
Restart=always
RestartSec=2s

[Install]
WantedBy=multi-user.target
```

Repeat similarly for api/ui/health with appropriate ExecStart.


## 4) Verification
- `sudo nft list ruleset | sed -n '/table inet pgw/,$p'`
- Add a test proxy and mapping in UI and confirm:
  - Status becomes OK
  - Exit IP and latency appear
  - Client traffic succeeds only when proxy is OK; after stopping proxy, traffic is blocked.

