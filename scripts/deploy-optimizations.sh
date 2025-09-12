#!/bin/bash

set -e

echo "=== PGW Optimization Deployment Script ==="
echo "Deploying system optimizations for PGW..."

# Kiểm tra quyền root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root (sudo)"
    exit 1
fi

REPO_ROOT="/opt/proxy-server-local"

echo "1. Applying file descriptor limits..."
cat $REPO_ROOT/deploy/limits-pgw.conf >> /etc/security/limits.conf

echo "2. Creating systemd limits configuration..."
mkdir -p /etc/systemd/system.conf.d
cat > /etc/systemd/system.conf.d/limits.conf << 'SYSTEMD_LIMITS'
[Manager]
DefaultLimitNOFILE=65536
DefaultTasksMax=8192
SYSTEMD_LIMITS

echo "3. Applying network optimizations..."
cp $REPO_ROOT/deploy/sysctl-pgw.conf /etc/sysctl.d/99-pgw.conf
sysctl -p /etc/sysctl.d/99-pgw.conf

echo "4. Updating systemd service files..."
cp $REPO_ROOT/deploy/systemd/pgw-*.service /etc/systemd/system/
systemctl daemon-reload

echo "5. Restarting PGW services..."
systemctl restart pgw-api pgw-agent pgw-ui pgw-health

echo "6. Restarting forwarder services..."
for port in {15001..15025}; do
    if systemctl is-active --quiet pgw-fwd@$port; then
        systemctl restart pgw-fwd@$port
    fi
done

echo "=== Deployment completed! ==="
echo "Running system monitor to verify changes..."
$REPO_ROOT/scripts/monitor-pgw.sh
