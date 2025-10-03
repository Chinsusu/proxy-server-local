#!/bin/bash
# update-all-nodes.sh - Update multiple PGW nodes simultaneously
# Usage: ./update-all-nodes.sh [nodes_file]
# If nodes_file not provided, will use nodes.txt in same directory

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NODES_FILE="${1:-nodes.txt}"
LOG_DIR="./update-logs"
PARALLEL_JOBS=5  # Number of parallel updates
SSH_TIMEOUT=300  # SSH timeout in seconds
SSH_USER="root"  # Default SSH user

# Create log directory
mkdir -p "$LOG_DIR"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         PGW Multi-Node Update Script                      ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if nodes file exists
if [ ! -f "$NODES_FILE" ]; then
    echo -e "${RED}Error: Nodes file '$NODES_FILE' not found${NC}"
    echo ""
    echo "Please create a nodes file with one node per line:"
    echo "  Format: [user@]hostname_or_ip"
    echo ""
    echo "Example nodes.txt:"
    echo "  192.168.1.10"
    echo "  root@192.168.1.11"
    echo "  admin@node3.example.com"
    echo ""
    exit 1
fi

# Read nodes from file (skip empty lines and comments)
mapfile -t NODES < <(grep -v '^\s*#' "$NODES_FILE" | grep -v '^\s*$')

if [ ${#NODES[@]} -eq 0 ]; then
    echo -e "${RED}Error: No nodes found in $NODES_FILE${NC}"
    exit 1
fi

echo -e "${GREEN}Found ${#NODES[@]} node(s) to update${NC}"
echo ""

# Display nodes
echo "Nodes to update:"
for i in "${!NODES[@]}"; do
    echo "  $((i+1)). ${NODES[$i]}"
done
echo ""

# Confirm
read -p "Continue with update? (yes/no): " -r REPLY
echo ""
if [[ ! $REPLY =~ ^[Yy](es)?$ ]]; then
    echo "Update cancelled."
    exit 0
fi

# Function to update a single node
update_node() {
    local node="$1"
    local log_file="$LOG_DIR/update-${node//[^a-zA-Z0-9]/_}-$(date +%Y%m%d_%H%M%S).log"
    
    echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} Starting update on ${YELLOW}$node${NC}" | tee -a "$log_file"
    
    {
        # SSH with timeout and execute update script
        ssh -o ConnectTimeout=10 \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            "$node" "curl -fsSL https://raw.githubusercontent.com/Chinsusu/proxy-server-local/main/update-pgw.sh | bash" 2>&1
        
        exit_code=$?
        
        if [ $exit_code -eq 0 ]; then
            echo -e "${GREEN}[$(date +%H:%M:%S)] ✓ SUCCESS${NC} $node" | tee -a "$log_file"
            return 0
        else
            echo -e "${RED}[$(date +%H:%M:%S)] ✗ FAILED${NC} $node (exit code: $exit_code)" | tee -a "$log_file"
            return 1
        fi
    } >> "$log_file" 2>&1 &
    
    return 0
}

# Track results
declare -A RESULTS
SUCCESS_COUNT=0
FAILED_COUNT=0

echo -e "${GREEN}==> Starting parallel updates (max $PARALLEL_JOBS concurrent)${NC}"
echo ""

# Update nodes with parallelism control
job_count=0
pids=()

for node in "${NODES[@]}"; do
    # Wait if we've reached max parallel jobs
    while [ ${#pids[@]} -ge $PARALLEL_JOBS ]; do
        for i in "${!pids[@]}"; do
            if ! kill -0 "${pids[$i]}" 2>/dev/null; then
                wait "${pids[$i]}"
                unset "pids[$i]"
            fi
        done
        pids=("${pids[@]}")  # Re-index array
        sleep 0.5
    done
    
    # Start update for this node
    update_node "$node" &
    pids+=($!)
    ((job_count++))
    
    sleep 0.2  # Small delay to avoid overwhelming SSH
done

# Wait for all remaining jobs
echo ""
echo -e "${YELLOW}Waiting for all updates to complete...${NC}"
for pid in "${pids[@]}"; do
    wait "$pid" || true
done

echo ""
echo -e "${GREEN}==> Verifying results...${NC}"
echo ""

# Check results from logs
for node in "${NODES[@]}"; do
    log_pattern="$LOG_DIR/update-${node//[^a-zA-Z0-9]/_}-*.log"
    latest_log=$(ls -t $log_pattern 2>/dev/null | head -1)
    
    if [ -n "$latest_log" ] && grep -q "✅ Update complete!" "$latest_log"; then
        echo -e "  ${GREEN}✓${NC} $node - SUCCESS"
        ((SUCCESS_COUNT++))
        RESULTS[$node]="SUCCESS"
    else
        echo -e "  ${RED}✗${NC} $node - FAILED"
        ((FAILED_COUNT++))
        RESULTS[$node]="FAILED"
    fi
done

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    Update Summary                          ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo -e "  Total nodes:      ${#NODES[@]}"
echo -e "  ${GREEN}Successful:       $SUCCESS_COUNT${NC}"
echo -e "  ${RED}Failed:           $FAILED_COUNT${NC}"
echo -e "  Logs directory:   $LOG_DIR"
echo ""

if [ $FAILED_COUNT -gt 0 ]; then
    echo -e "${YELLOW}Failed nodes:${NC}"
    for node in "${!RESULTS[@]}"; do
        if [ "${RESULTS[$node]}" == "FAILED" ]; then
            echo "  - $node"
            latest_log=$(ls -t "$LOG_DIR/update-${node//[^a-zA-Z0-9]/_}-*.log" 2>/dev/null | head -1)
            if [ -n "$latest_log" ]; then
                echo -e "${YELLOW}    Log: $latest_log${NC}"
                echo "    Last 5 lines:"
                tail -5 "$latest_log" | sed 's/^/      /'
            fi
            echo ""
        fi
    done
    
    echo -e "${YELLOW}Tip: Review logs in $LOG_DIR for details${NC}"
    echo ""
    exit 1
else
    echo -e "${GREEN}🎉 All nodes updated successfully!${NC}"
    echo ""
    exit 0
fi
