#!/bin/bash
# Script to apply forwarder binding fix to PGW servers
# Fixes routing loop issue by binding forwarders to LAN IP instead of all interfaces

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root"
   exit 1
fi

# Get LAN interface IP (you might need to adjust this)
get_lan_ip() {
    local lan_iface=$(grep "PGW_LAN_IFACE=" /etc/pgw/pgw.env 2>/dev/null | cut -d'=' -f2 || echo "ens19")
    local lan_ip=$(ip addr show $lan_iface 2>/dev/null | grep "inet " | head -1 | awk '{print $2}' | cut -d'/' -f1)
    
    if [[ -z "$lan_ip" ]]; then
        error "Could not determine LAN IP for interface $lan_iface"
        exit 1
    fi
    
    echo "$lan_ip"
}

# Main execution
main() {
    log "Starting PGW Forwarder Fix Application..."
    
    # Get LAN IP
    LAN_IP=$(get_lan_ip)
    log "Detected LAN IP: $LAN_IP"
    
    # Backup original service file
    SERVICE_FILE="/etc/systemd/system/pgw-fwd@.service"
    BACKUP_FILE="/etc/systemd/system/pgw-fwd@.service.backup.$(date +%Y%m%d_%H%M%S)"
    
    if [[ ! -f "$SERVICE_FILE" ]]; then
        error "Service file not found: $SERVICE_FILE"
        exit 1
    fi
    
    log "Backing up original service file..."
    cp "$SERVICE_FILE" "$BACKUP_FILE"
    success "Backup created: $BACKUP_FILE"
    
    # Check current binding
    current_bind=$(grep "PGW_FWD_ADDR=" "$SERVICE_FILE" | head -1)
    log "Current binding: $current_bind"
    
    if [[ $current_bind == *"$LAN_IP"* ]]; then
        warn "Fix appears to already be applied. Current binding uses LAN IP."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log "Aborted by user"
            exit 0
        fi
    fi
    
    # Stop all forwarder services
    log "Stopping all forwarder services..."
    for port in {15001..15050}; do
        systemctl stop "pgw-fwd@$port.service" 2>/dev/null || true
    done
    
    # Kill any remaining forwarder processes
    pkill -f pgw-fwd || true
    sleep 2
    
    # Update service file
    log "Updating service file binding..."
    sed -i "s|Environment=PGW_FWD_ADDR=:[^[:space:]]*|Environment=PGW_FWD_ADDR=$LAN_IP:%i|g" "$SERVICE_FILE"
    
    # Verify change
    new_bind=$(grep "PGW_FWD_ADDR=" "$SERVICE_FILE" | head -1)
    log "New binding: $new_bind"
    
    if [[ $new_bind != *"$LAN_IP"* ]]; then
        error "Failed to update service file properly"
        log "Restoring backup..."
        cp "$BACKUP_FILE" "$SERVICE_FILE"
        exit 1
    fi
    
    # Reload systemd
    log "Reloading systemd daemon..."
    systemctl daemon-reload
    
    # Start forwarder services (based on active mappings)
    log "Starting forwarder services..."
    
    # Get active ports from mappings if API is available
    active_ports=$(curl -s -H "Authorization: Bearer $(grep PGW_AGENT_TOKEN /etc/pgw/pgw.env | cut -d'=' -f2)" \
                   http://127.0.0.1:8080/v1/mappings 2>/dev/null | \
                   jq -r '.[].local_redirect_port' 2>/dev/null | sort -u || echo "")
    
    if [[ -z "$active_ports" ]]; then
        warn "Could not get active ports from API, starting default range..."
        active_ports=$(seq 15001 15017)
    fi
    
    for port in $active_ports; do
        log "Starting pgw-fwd@$port.service..."
        systemctl start "pgw-fwd@$port.service" || {
            error "Failed to start pgw-fwd@$port.service"
        }
    done
    
    # Verify services are running
    sleep 3
    log "Verifying services..."
    
    running_count=$(systemctl list-units --state=active | grep pgw-fwd@ | wc -l)
    success "$running_count forwarder services are now running"
    
    # Show binding status
    log "Current forwarder bindings:"
    netstat -tlnp | grep "$LAN_IP:" | grep pgw-fwd || {
        warn "No forwarders found binding to $LAN_IP"
    }
    
    success "Fix applied successfully!"
    log "Backup saved as: $BACKUP_FILE"
    log "To rollback: cp $BACKUP_FILE $SERVICE_FILE && systemctl daemon-reload && systemctl restart pgw-fwd@*.service"
}

# Run main function
main "$@"
