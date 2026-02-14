#!/bin/bash
set -e

echo "=== PGW Update Script ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
   echo "Please run as root (sudo)"
   exit 1
fi

cd /opt/proxy-server-local

echo "[1/5] Pulling latest code..."
git pull origin main

echo ""
echo "[2/5] Building binaries..."
export PATH=/usr/local/go/bin:$PATH
go build -o pgw-api ./cmd/api
go build -o pgw-agent ./cmd/agent
go build -o pgw-ui ./cmd/ui
go build -o pgw-fwd ./cmd/fwd
go build -o pgw-health ./cmd/health

echo ""
echo "[3/5] Installing binaries..."
install -m 0755 pgw-api /usr/local/bin/
install -m 0755 pgw-agent /usr/local/bin/
install -m 0755 pgw-ui /usr/local/bin/
install -m 0755 pgw-fwd /usr/local/bin/
install -m 0755 pgw-health /usr/local/bin/

echo ""
echo "[4/5] Restarting services..."
systemctl restart pgw-api pgw-agent pgw-ui pgw-health

# Restart all forwarder instances
for p in $(seq 15001 15050); do
    if systemctl is-active --quiet pgw-fwd@$p; then
        systemctl restart pgw-fwd@$p
    fi
done

echo ""
echo "[5/5] Checking service status..."
sleep 2
systemctl status pgw-api --no-pager -l | head -5
systemctl status pgw-agent --no-pager -l | head -5
systemctl status pgw-ui --no-pager -l | head -5

echo ""
echo "=== Update complete! ==="
echo ""
echo "Verify agent health endpoint:"
echo "  curl -I http://127.0.0.1:9090/agent/health"
echo ""
