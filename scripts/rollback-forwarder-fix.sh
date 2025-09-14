#!/bin/bash
# Rollback script for forwarder binding fix
# Restores original binding configuration

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root"
   exit 1
fi

main() {
    log "Starting PGW Forwarder Fix Rollback..."
    
    SERVICE_FILE="/etc/systemd/system/pgw-fwd@.service"
    
    # Find most recent backup
    BACKUP_FILE=$(ls -t /etc/systemd/system/pgw-fwd@.service.backup.* 2>/dev/null | head -1)
    
    if [[ -z "$BACKUP_FILE" ]]; then
        error "No backup file found! Cannot rollback."
        log "Expected backup files like: /etc/systemd/system/pgw-fwd@.service.backup.YYYYMMDD_HHMMSS"
        exit 1
    fi
    
    log "Found backup: $BACKUP_FILE"
    
    # Show current vs backup binding
    current_bind=$(grep "PGW_FWD_ADDR=" "$SERVICE_FILE" 2>/dev/null || echo "NOT_FOUND")
    backup_bind=$(grep "PGW_FWD_ADDR=" "$BACKUP_FILE" 2>/dev/null || echo "NOT_FOUND")
    
    log "Current binding: $current_bind"
    log "Backup binding:  $backup_bind"
    
    if [[ "$current_bind" == "$backup_bind" ]]; then
        warn "Current configuration matches backup. No rollback needed."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log "Aborted by user"
            exit 0
        fi
    fi
    
    # Confirm rollback
    warn "This will rollback forwarder configuration to original state"
    read -p "Continue with rollback? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "Rollback cancelled by user"
        exit 0
    fi
    
    # Stop forwarder services
    log "Stopping forwarder services..."
    for port in {15001..15050}; do
        systemctl stop "pgw-fwd@$port.service" 2>/dev/null || true
    done
    pkill -f pgw-fwd || true
    
    # Create backup of current (modified) file
    current_backup="/etc/systemd/system/pgw-fwd@.service.pre-rollback.$(date +%Y%m%d_%H%M%S)"
    cp "$SERVICE_FILE" "$current_backup"
    log "Current config backed up to: $current_backup"
    
    # Restore from backup
    log "Restoring configuration from backup..."
    cp "$BACKUP_FILE" "$SERVICE_FILE"
    
    # Reload systemd
    log "Reloading systemd daemon..."
    systemctl daemon-reload
    
    # Start services
    log "Starting forwarder services..."
    active_ports=$(seq 15001 15017)  # Default range
    
    for port in $active_ports; do
        systemctl start "pgw-fwd@$port.service" 2>/dev/null || {
            warn "Failed to start pgw-fwd@$port.service"
        }
    done
    
    # Verify
    sleep 3
    running_count=$(systemctl list-units --state=active | grep pgw-fwd@ | wc -l)
    success "Rollback completed. $running_count forwarder services running."
    
    # Show current binding
    log "Restored binding:"
    grep "PGW_FWD_ADDR=" "$SERVICE_FILE"
    
    log "Current forwarder bindings:"
    ss -tlnp | grep pgw-fwd | head -5 || warn "No forwarder processes found in netstat"
    
    success "Rollback successful!"
    log "Original backup preserved: $BACKUP_FILE"
    log "Pre-rollback config saved: $current_backup"
}

main "$@"
