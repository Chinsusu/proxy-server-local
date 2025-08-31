#!/usr/bin/env bash
set -euo pipefail

REPO_HTTPS="https://github.com/Chinsusu/proxy-server-local.git"
REPO_DIR="/opt/proxy-server-local"
LAN_IFACE_DEFAULT="ens19"
WAN_IFACE_DEFAULT="eth0"
FWD_BASE=15001
FWD_MAX=15050

need_root() { if [[ $EUID -ne 0 ]]; then echo "Run as root" >&2; exit 1; fi; }
have_cmd(){ command -v "$1" >/dev/null 2>&1; }

ensure_packages(){ export DEBIAN_FRONTEND=noninteractive; apt-get update -y; apt-get install -y curl ca-certificates git jq nftables dnsmasq build-essential; }
ensure_sysctl(){ install -d -m 0755 /etc/sysctl.d; cat >/etc/sysctl.d/99-pgw.conf <<CONF
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
CONF
sysctl --system || true; }

install_go(){
  local URL=https://go.dev/dl/go1.23.2.linux-amd64.tar.gz
  curl -fsSL "$URL" -o /tmp/go.tar.gz
  rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz && rm -f /tmp/go.tar.gz
  cat >/etc/profile.d/go.sh <<P
export PATH=/usr/local/go/bin:$PATH
P
}

clone_repo(){ install -d -m 0755 "$REPO_DIR"; if [[ ! -d "$REPO_DIR/.git" ]]; then git clone -b main "$REPO_HTTPS" "$REPO_DIR"; else git -C "$REPO_DIR" pull --ff-only origin main; fi; }

build_install(){ local G=/usr/local/go/bin/go; (cd "$REPO_DIR"; mkdir -p bin; "$G" build -o bin/pgw-api   ./cmd/api; "$G" build -o bin/pgw-agent ./cmd/agent; "$G" build -o bin/pgw-ui ./cmd/ui; "$G" build -o bin/pgw-fwd ./cmd/fwd); install -m 0755 "$REPO_DIR"/bin/pgw-* /usr/local/bin/; }

install_web(){ install -d -m 0755 /usr/local/share/pgw/web/static; cp -f "$REPO_DIR"/web/*.html /usr/local/share/pgw/web/; cp -f "$REPO_DIR"/web/static/* /usr/local/share/pgw/web/static/; }

ensure_user(){ id pgw >/dev/null 2>&1 || useradd --system --no-create-home --home /nonexistent --shell /usr/sbin/nologin pgw; install -d -m 0750 /etc/pgw; install -d -m 0755 /var/lib/pgw/ports; chown -R pgw:pgw /var/lib/pgw; }

secr(){ head -c 24 /dev/urandom | base64 | tr -dc A-Za-z0-9 | head -c 48; }

write_env(){ local JWT=$(secr); local AT=$(secr); cat >/etc/pgw/pgw.env <<ENV
PGW_JWT_SECRET=$JWT
PGW_API_ADDR=:8080
PGW_AGENT_ADDR=:9090
PGW_UI_ADDR=:8081
PGW_WAN_IFACE=${PGW_WAN_IFACE:-$WAN_IFACE_DEFAULT}
PGW_LAN_IFACE=${PGW_LAN_IFACE:-$LAN_IFACE_DEFAULT}
PGW_FORWARDER_BASE_PORT=$FWD_BASE
PGW_FWD_MAX_PORT=$FWD_MAX
PGW_AGENT_TOKEN=$AT
PGW_STORE=file
PGW_STORE_PATH=/var/lib/pgw/state.json
PGW_ADMIN_USER=admin
PGW_ADMIN_PASS=ChangeMe$(head -c4 /dev/urandom | base64 | tr -dc A-Za-z0-9 | head -c6)
ENV
chmod 0640 /etc/pgw/pgw.env; }

conf_dns(){ install -d -m 0755 /etc/dnsmasq.d; cat >/etc/dnsmasq.d/pgw.conf <<CONF
interface=$LAN_IFACE_DEFAULT
listen-address=192.168.2.1
bind-interfaces
no-resolv
server=1.1.1.1
server=8.8.8.8
cache-size=500
filter-AAAA
CONF
systemctl enable --now dnsmasq || true; }

units(){ cat >/etc/systemd/system/pgw-api.service <<U
[Unit]
Description=PGW API
After=network-online.target
Wants=network-online.target
[Service]
User=pgw
Group=pgw
EnvironmentFile=/etc/pgw/pgw.env
ExecStart=/usr/local/bin/pgw-api
Restart=always
RestartSec=2s
[Install]
WantedBy=multi-user.target
U
cat >/etc/systemd/system/pgw-agent.service <<U
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
U
cat >/etc/systemd/system/pgw-ui.service <<U
[Unit]
Description=PGW UI
After=network-online.target
Wants=network-online.target
[Service]
User=pgw
Group=pgw
EnvironmentFile=/etc/pgw/pgw.env
ExecStart=/usr/local/bin/pgw-ui
Restart=always
RestartSec=2s
[Install]
WantedBy=multi-user.target
U
cat >/etc/systemd/system/pgw-health.service <<U
[Unit]
Description=PGW Health
After=network-online.target
Wants=network-online.target
[Service]
User=pgw
Group=pgw
EnvironmentFile=/etc/pgw/pgw.env
ExecStart=/usr/local/bin/pgw-health
Restart=always
RestartSec=2s
[Install]
WantedBy=multi-user.target
U
cat >/etc/systemd/system/pgw-fwd@.service <<U
[Unit]
Description=PGW Forwarder instance on port %i
After=network-online.target pgw-api.service
Wants=network-online.target
[Service]
User=pgw
Group=pgw
EnvironmentFile=/etc/pgw/pgw.env
Environment=PGW_FWD_ADDR=:%i
Environment=PGW_API_BASE=http://127.0.0.1:8080
ExecStart=/usr/local/bin/pgw-fwd
Restart=always
RestartSec=2s
[Install]
WantedBy=multi-user.target
U
systemctl daemon-reload; systemctl enable --now pgw-api pgw-agent pgw-ui pgw-health; }

start_fwds(){ for p in $(seq $FWD_BASE $FWD_MAX); do systemctl start pgw-fwd@"$p" || true; done; }

notes(){ install -d -m 0755 /etc/pgw; date -Is > /etc/pgw/INSTALL_NOTES.txt; echo "See /etc/pgw/pgw.env for credentials" >> /etc/pgw/INSTALL_NOTES.txt; }

main(){ need_root; ensure_packages; ensure_sysctl; install_go; clone_repo; build_install; install_web; ensure_user; write_env; conf_dns; units; start_fwds; notes; echo "OK: install done."; }

main "$@"
chmod +x deploy/install-pgw.sh
sed -n 1,200p deploy/install-pgw.sh
