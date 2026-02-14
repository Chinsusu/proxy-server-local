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

ensure_packages(){ export DEBIAN_FRONTEND=noninteractive; apt-get update -y; apt-get install -y curl ca-certificates git jq nftables dnsmasq build-essential sudo; }
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

install_web(){ 
  install -d -m 0755 /usr/local/share/pgw/web/static
  # Copy HTML files if they exist (optional - we use embedded templates now)
  if ls "$REPO_DIR"/web/*.html &gt;/dev/null 2&gt;&1; then
    cp -f "$REPO_DIR"/web/*.html /usr/local/share/pgw/web/
  fi
  # Always copy static assets (CSS, JS)
  cp -f "$REPO_DIR"/web/static/* /usr/local/share/pgw/web/static/
}

ensure_user(){ id pgw >/dev/null 2>&1 || useradd --system --no-create-home --home /nonexistent --shell /usr/sbin/nologin pgw; install -d -m 0750 /etc/pgw; install -d -m 0755 /var/lib/pgw/ports; chown -R pgw:pgw /var/lib/pgw; }

setup_sudoers(){
  # Allow pgw user to manage pgw-fwd services for auto-start functionality  
  cat > /etc/sudoers.d/pgw << 'SUDO'
# Allow pgw user to manage pgw-fwd services without password
# Both with and without .service extension for compatibility
pgw ALL=(root) NOPASSWD: /usr/bin/systemctl start pgw-fwd@*.service
pgw ALL=(root) NOPASSWD: /usr/bin/systemctl stop pgw-fwd@*.service  
pgw ALL=(root) NOPASSWD: /usr/bin/systemctl restart pgw-fwd@*.service
pgw ALL=(root) NOPASSWD: /usr/bin/systemctl is-active pgw-fwd@*.service
pgw ALL=(root) NOPASSWD: /usr/bin/systemctl status pgw-fwd@*.service
pgw ALL=(root) NOPASSWD: /usr/bin/systemctl start pgw-fwd@*
pgw ALL=(root) NOPASSWD: /usr/bin/systemctl stop pgw-fwd@*
pgw ALL=(root) NOPASSWD: /usr/bin/systemctl restart pgw-fwd@*
pgw ALL=(root) NOPASSWD: /usr/bin/systemctl is-active pgw-fwd@*
pgw ALL=(root) NOPASSWD: /usr/bin/systemctl status pgw-fwd@*
pgw ALL=(root) NOPASSWD: /bin/systemctl start pgw-fwd@*.service
pgw ALL=(root) NOPASSWD: /bin/systemctl stop pgw-fwd@*.service  
pgw ALL=(root) NOPASSWD: /bin/systemctl restart pgw-fwd@*.service
pgw ALL=(root) NOPASSWD: /bin/systemctl is-active pgw-fwd@*.service
pgw ALL=(root) NOPASSWD: /bin/systemctl status pgw-fwd@*.service
pgw ALL=(root) NOPASSWD: /bin/systemctl start pgw-fwd@*
pgw ALL=(root) NOPASSWD: /bin/systemctl stop pgw-fwd@*
pgw ALL=(root) NOPASSWD: /bin/systemctl restart pgw-fwd@*
pgw ALL=(root) NOPASSWD: /bin/systemctl is-active pgw-fwd@*
pgw ALL=(root) NOPASSWD: /bin/systemctl status pgw-fwd@*
SUDO
  # Validate sudoers file
  visudo -cf /etc/sudoers.d/pgw
}

secr(){ head -c 64 /dev/urandom | base64 | tr -dc A-Za-z0-9 | head -c 48; }

write_env(){ local JWT=$(secr); local AT=$(secr); local AP=$(secr | head -c 16); cat >/etc/pgw/pgw.env <<ENV
# PGW environment configuration
# Generated at $(date -Is)

# Common / security
PGW_JWT_SECRET=$JWT

# API service
PGW_API_ADDR=:8080
PGW_STORE=file
PGW_STORE_PATH=/var/lib/pgw/state.json
PGW_HEALTH_INTERVAL=30s

# Agent service
PGW_AGENT_ADDR=:9090
PGW_API_BASE=http://127.0.0.1:8080
PGW_WAN_IFACE=eth0
PGW_LAN_IFACE=ens19
PGW_AGENT_TOKEN=$AT

# UI service
PGW_UI_ADDR=:8081
PGW_UI_API=http://127.0.0.1:8080
PGW_UI_AGENT=http://127.0.0.1:9090/agent

# Forwarder settings
PGW_FWD_BASE_PORT=15001
PGW_FWD_MAX_PORT=15050
PGW_FWD_LOG_SAMPLE=100
PGW_FWD_MAX_CONNS=8192
PGW_FWD_IDLE_TIMEOUT=30m

# Admin bootstrap (API login)
PGW_ADMIN_USER=admin
PGW_ADMIN_PASS=$AP

ENV
chmod 0640 /etc/pgw/pgw.env
echo ""; echo "========================================"; echo "  Admin credentials:"; echo "  Username: admin"; echo "  Password: $AP"; echo "========================================"; echo ""; }

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

setup_journald(){
  install -d -m 0755 /etc/systemd/journald.conf.d
  cp -f "$REPO_DIR/deploy/journald-pgw.conf" /etc/systemd/journald.conf.d/pgw.conf
  systemctl restart systemd-journald || true
}

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
KillSignal=SIGTERM
TimeoutStopSec=15s
LimitNOFILE=131072
MemoryMax=1G
TasksMax=8192
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
KillSignal=SIGTERM
TimeoutStopSec=15s
LimitNOFILE=65536
MemoryMax=256M
TasksMax=1024
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
KillSignal=SIGTERM
TimeoutStopSec=15s
LimitNOFILE=32768
MemoryMax=128M
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
KillSignal=SIGTERM
TimeoutStopSec=35s
LimitNOFILE=131072
MemoryMax=1G
TasksMax=65536
[Install]
WantedBy=multi-user.target
U
systemctl daemon-reload; systemctl enable --now pgw-api pgw-agent pgw-ui pgw-health; }

start_fwds(){ for p in $(seq $FWD_BASE $FWD_MAX); do systemctl start pgw-fwd@"$p" || true; done; }

notes(){ install -d -m 0755 /etc/pgw; date -Is > /etc/pgw/INSTALL_NOTES.txt; echo "See /etc/pgw/pgw.env for credentials" >> /etc/pgw/INSTALL_NOTES.txt; }

main(){ need_root; ensure_packages; ensure_sysctl; install_go; clone_repo; build_install; install_web; ensure_user; setup_sudoers; write_env; conf_dns; setup_journald; units; start_fwds; notes; echo "OK: install done."; }

main "$@"
