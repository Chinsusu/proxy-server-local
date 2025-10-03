#!/bin/bash
# update-pgw.sh - Quick update script for pgw services
# Usage: curl -fsSL https://raw.githubusercontent.com/Chinsusu/proxy-server-local/main/update-pgw.sh | sudo bash
# Or:    sudo bash update-pgw.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PGW_DIR="/opt/proxy-server-local"
SERVICES=("pgw-agent" "pgw-api" "pgw-ui" "pgw-health")

echo -e "${GREEN}==> PGW Update Script${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    exit 1
fi

# Check if directory exists
if [ ! -d "$PGW_DIR" ]; then
    echo -e "${RED}Error: $PGW_DIR not found${NC}"
    echo "Please ensure proxy-server-local is installed in $PGW_DIR"
    exit 1
fi

# Navigate to directory
cd "$PGW_DIR"

# Check for uncommitted changes
if ! git diff-index --quiet HEAD -- 2>/dev/null; then
    echo -e "${YELLOW}Warning: You have uncommitted changes in $PGW_DIR${NC}"
    echo -e "${YELLOW}These will be preserved (stashed) before update${NC}"
    git stash push -m "Auto-stash before update $(date +%Y-%m-%d_%H:%M:%S)"
fi

echo -e "${GREEN}==> Pulling latest code from GitHub...${NC}"
git pull origin main

echo ""
echo -e "${GREEN}==> Building binaries...${NC}"
make build

echo ""
echo -e "${GREEN}==> Stopping services...${NC}"
for service in "${SERVICES[@]}"; do
    if systemctl is-active --quiet "$service"; then
        echo "  Stopping $service..."
        systemctl stop "$service"
    else
        echo "  $service is not running, skipping..."
    fi
done

echo ""
echo -e "${GREEN}==> Installing new binaries...${NC}"
cp -v bin/pgw-* /usr/local/bin/

echo ""
echo -e "${GREEN}==> Starting services...${NC}"
for service in "${SERVICES[@]}"; do
    if systemctl is-enabled --quiet "$service" 2>/dev/null; then
        echo "  Starting $service..."
        systemctl start "$service"
    else
        echo "  $service is not enabled, skipping..."
    fi
done

echo ""
echo -e "${GREEN}==> Checking service status...${NC}"
sleep 2
for service in pgw-api pgw-ui pgw-health; do
    if systemctl is-active --quiet "$service"; then
        echo -e "  ${GREEN}✓${NC} $service is running"
    else
        echo -e "  ${RED}✗${NC} $service failed to start"
    fi
done

echo ""
echo -e "${GREEN}==> Binary info:${NC}"
ls -lh /usr/local/bin/pgw-* | awk '{print "  " $9 " (" $5 ", " $6 " " $7 " " $8 ")"}'

echo ""
echo -e "${GREEN}==> Current git commit:${NC}"
git log -1 --oneline | sed 's/^/  /'

echo ""
echo -e "${GREEN}✅ Update complete!${NC}"
echo ""
echo "Verify with:"
echo "  sudo systemctl status pgw-api pgw-ui pgw-health"
echo "  curl -s http://localhost:8080/v1/proxies | jq"
