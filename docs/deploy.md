# Hướng dẫn triển khai

## Build & cài đặt

```bash
go build -o bin/pgw-api   ./cmd/api
go build -o bin/pgw-agent ./cmd/agent
go build -o bin/pgw-fwd   ./cmd/fwd
go build -o bin/pgw-ui    ./cmd/ui
sudo install -m 0755 bin/pgw-* /usr/local/bin/
```

## systemd units (ví dụ)

`/etc/systemd/system/pgw-api.service`

```ini
[Unit]
Description=PGW API
After=network.target

[Service]
Environment=PGW_API_ADDR=:8080
Environment=PGW_STORE=memory
# Environment=PGW_STORE=file
# Environment=PGW_STORE_PATH=/var/lib/pgw/state.json
Environment=PGW_HEALTH_INTERVAL=30s
ExecStart=/usr/local/bin/pgw-api
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/pgw-agent.service`

```ini
[Unit]
Description=PGW Agent
After=network.target pgw-api.service

[Service]
Environment=PGW_AGENT_ADDR=:9090
Environment=PGW_API_BASE=http://127.0.0.1:8080
Environment=PGW_WAN_IFACE=eth0
Environment=PGW_LAN_IFACE=ens19
ExecStart=/usr/local/bin/pgw-agent
# Nếu cần quyền nft:
# CapabilityBoundingSet=CAP_NET_ADMIN
# hoặc cấu hình sudoers cho "nft -f -" an toàn
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/pgw-fwd.service`

```ini
[Unit]
Description=PGW Forwarder
After=network.target

[Service]
Environment=PGW_FWD_ADDR=:15001
ExecStart=/usr/local/bin/pgw-fwd
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/pgw-ui.service`

```ini
[Unit]
Description=PGW UI
After=network.target pgw-api.service pgw-agent.service

[Service]
Environment=PGW_UI_ADDR=:8081
Environment=PGW_UI_API=http://127.0.0.1:8080
Environment=PGW_UI_AGENT=http://127.0.0.1:9090/agent
ExecStart=/usr/local/bin/pgw-ui
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Kích hoạt:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pgw-api pgw-agent pgw-fwd pgw-ui
```

## Kiểm tra nhanh

```bash
# UI reverse proxy tới agent
curl -sI http://127.0.0.1:8081/agent/reconcile | head -n1   # 200 OK

# Kiểm tra rule
sudo nft list table ip pgw
sudo nft list table inet pgw_filter

# Kiểm tra forwarder
ss -lntp | grep :15001
journalctl -u pgw-fwd -f
```
