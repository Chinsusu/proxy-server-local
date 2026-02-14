#!/usr/bin/env bash
#
# PGW Auto-Update Script
# Triggered by GitHub webhook or manual execution
# Pulls latest code, builds, backups, deploys, and restarts services

set -euo pipefail

REPO_DIR="/opt/proxy-server-local"
BACKUP_DIR="/var/backups/pgw"
LOG_FILE="/var/log/pgw-deploy.log"
LOCK_FILE="/var/run/pgw-deploy.lock"
MAX_BACKUPS=3

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

error() {
    log "ERROR: $*"
    exit 1
}

# Prevent concurrent deployments
acquire_lock() {
    if [ -f "$LOCK_FILE" ]; then
        PID=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
        if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
            error "Deployment already in progress (PID: $PID)"
        fi
        log "WARN: Stale lock file found, removing"
        rm -f "$LOCK_FILE"
    fi
    echo $$ > "$LOCK_FILE"
    trap "rm -f '$LOCK_FILE'" EXIT
}

# Backup current binaries
backup_binaries() {
    local TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    local BACKUP_PATH="$BACKUP_DIR/$TIMESTAMP"
    
    log "Creating backup: $BACKUP_PATH"
    mkdir -p "$BACKUP_PATH"
    
    # Backup binaries
    for BIN in pgw-api pgw-agent pgw-ui pgw-fwd pgw-webhook; do
        if [ -f "/usr/local/bin/$BIN" ]; then
            cp -p "/usr/local/bin/$BIN" "$BACKUP_PATH/"
        fi
    done
    
    # Create 'latest' symlink
    ln -sfn "$BACKUP_PATH" "$BACKUP_DIR/latest"
    
    # Cleanup old backups (keep last MAX_BACKUPS)
    cd "$BACKUP_DIR"
    ls -t | grep -E '^[0-9]{8}_[0-9]{6}$' | tail -n +$((MAX_BACKUPS + 1)) | xargs -r rm -rf
    
    log "Backup complete: $(ls -lh $BACKUP_PATH | wc -l) binaries"
}

# Pull latest code
git_pull() {
    log "Pulling latest code from GitHub..."
    cd "$REPO_DIR"
    
    # Save current commit
    PREV_COMMIT=$(git rev-parse HEAD)
    
    # Pull
    git fetch origin main
    git reset --hard origin/main
    
    # Check if there were changes
    CURR_COMMIT=$(git rev-parse HEAD)
    if [ "$PREV_COMMIT" = "$CURR_COMMIT" ]; then
        log "Already up to date"
        return 1
    fi
    
    log "Updated: $PREV_COMMIT -> $CURR_COMMIT"
    log "Changes:"
    git log --oneline --no-decorate "$PREV_COMMIT..$CURR_COMMIT" | head -5 | while read line; do
        log "  $line"
    done
    
    return 0
}

# Build binaries
build_binaries() {
    log "Building binaries..."
    cd "$REPO_DIR"
    
    export PATH=/usr/local/go/bin:$PATH
    
    mkdir -p bin
    
    # Build all services
    go build -o bin/pgw-api ./cmd/api || error "Failed to build pgw-api"
    go build -o bin/pgw-agent ./cmd/agent || error "Failed to build pgw-agent"
    go build -o bin/pgw-ui ./cmd/ui || error "Failed to build pgw-ui"
    go build -o bin/pgw-fwd ./cmd/fwd || error "Failed to build pgw-fwd"
    go build -o bin/pgw-webhook ./cmd/webhook || error "Failed to build pgw-webhook"
    
    log "Build successful"
}

# Install binaries
install_binaries() {
    log "Installing binaries..."
    
    install -m 0755 "$REPO_DIR"/bin/pgw-* /usr/local/bin/
    
    log "Installation complete"
}

# Restart services
restart_services() {
    log "Restarting services..."
    
    # Reload systemd
    systemctl daemon-reload
    
    # Restart main services
    for SVC in pgw-api pgw-agent pgw-ui pgw-webhook; do
        if systemctl is-active --quiet "$SVC"; then
            log "Restarting $SVC..."
            systemctl restart "$SVC"
        else
            log "WARN: $SVC not running, starting..."
            systemctl start "$SVC" || log "WARN: Failed to start $SVC"
        fi
    done
    
    # Give services time to start
    sleep 3
    
    log "Services restarted"
}

# Health check
health_check() {
    log "Running health checks..."
    
    local FAILED=0
    
    # Check API
    if curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1; then
        log "✓ API: healthy"
    else
        log "✗ API: unhealthy"
        FAILED=1
    fi
    
    # Check Agent
    if curl -sf http://127.0.0.1:9090/health >/dev/null 2>&1; then
        log "✓ Agent: healthy"
    else
        log "✗ Agent: unhealthy"
        FAILED=1
    fi
    
    # Check UI
    if curl -sf http://127.0.0.1:8081/health >/dev/null 2>&1; then
        log "✓ UI: healthy"
    else
        log "✗ UI: unhealthy"  
        FAILED=1
    fi
    
    # Check Webhook
    if curl -sf http://127.0.0.1:9091/health >/dev/null 2>&1; then
        log "✓ Webhook: healthy"
    else
        log "✗ Webhook: unhealthy"
        FAILED=1
    fi
    
    return $FAILED
}

# Rollback to previous version
rollback() {
    log "ROLLBACK: Restoring previous binaries..."
    
    if [ ! -L "$BACKUP_DIR/latest" ]; then
        error "No backup found for rollback"
    fi
    
    local BACKUP_PATH=$(readlink -f "$BACKUP_DIR/latest")
    
    for BIN in "$BACKUP_PATH"/*; do
        local BASENAME=$(basename "$BIN")
        log "Restoring $BASENAME..."
        cp -p "$BIN" "/usr/local/bin/"
    done
    
    restart_services
    
    if health_check; then
        log "Rollback successful"
        return 0
    else
        error "Rollback failed - manual intervention required"
    fi
}

# Main deployment flow
main() {
    log "==================================="
    log "Starting PGW deployment"
    log "Triggered by: ${GIT_AUTHOR:-manual}"
    log "Commit: ${GIT_COMMIT:-unknown}"
    log "==================================="
    
    acquire_lock
    
    # Pull code
    if ! git_pull; then
        log "No changes detected, exiting"
        exit 0
    fi
    
    # Backup current state
    backup_binaries
    
    # Build new binaries
    build_binaries
    
    # Install
    install_binaries
    
    # Restart services
    restart_services
    
    # Verify health
    if health_check; then
        log "==================================="
        log "Deployment SUCCESSFUL"
        log "==================================="
        exit 0
    else
        log "Health check FAILED - initiating rollback"
        rollback
        exit 1
    fi
}

# Handle rollback command
if [ "${1:-}" = "rollback" ]; then
    log "Manual rollback requested"
    rollback
    exit 0
fi

# Run main deployment
main
