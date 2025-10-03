# Update Guide

## Quick Update for Deployed Nodes

### Method 1: One-liner (Recommended)

Run this command on any deployed node to update to the latest version:

```bash
curl -fsSL https://raw.githubusercontent.com/Chinsusu/proxy-server-local/main/update-pgw.sh | sudo bash
```

### Method 2: Manual Update

If you prefer manual control:

```bash
cd /opt/proxy-server-local
sudo bash update-pgw.sh
```

### Method 3: Step-by-step

```bash
cd /opt/proxy-server-local
git pull origin main
make build
sudo systemctl stop pgw-api pgw-ui pgw-health pgw-agent
sudo cp bin/pgw-* /usr/local/bin/
sudo systemctl start pgw-agent pgw-api pgw-ui pgw-health
```

## What the Update Script Does

1. ✅ Checks for uncommitted changes (stashes them if found)
2. ✅ Pulls latest code from GitHub
3. ✅ Builds new binaries
4. ✅ Stops all pgw services gracefully
5. ✅ Installs new binaries to `/usr/local/bin/`
6. ✅ Starts services back up
7. ✅ Verifies service status

## Verification After Update

Check services are running:
```bash
sudo systemctl status pgw-api pgw-ui pgw-health
```

Check current version:
```bash
cd /opt/proxy-server-local && git log -1 --oneline
```

Test API:
```bash
curl -s http://localhost:8080/v1/proxies | jq
```

Check UI:
```
http://<your-server>:8081
```

## Rollback (If Needed)

If something goes wrong, rollback to previous version:

```bash
cd /opt/proxy-server-local
git log --oneline -5  # Find the previous commit hash
git checkout <previous-commit-hash>
make build
sudo systemctl stop pgw-api pgw-ui pgw-health pgw-agent
sudo cp bin/pgw-* /usr/local/bin/
sudo systemctl start pgw-agent pgw-api pgw-ui pgw-health
```

## Automation for Multiple Nodes

### Using SSH loop:

```bash
#!/bin/bash
NODES="node1.example.com node2.example.com node3.example.com"

for node in $NODES; do
    echo "Updating $node..."
    ssh root@$node "curl -fsSL https://raw.githubusercontent.com/Chinsusu/proxy-server-local/main/update-pgw.sh | bash"
    echo "---"
done
```

### Using Ansible:

See `deploy/ansible/update-playbook.yml` (if available)

## Troubleshooting

**Services won't start:**
```bash
sudo journalctl -u pgw-api -n 50
sudo journalctl -u pgw-ui -n 50
```

**Build fails:**
```bash
# Check Go version
go version  # Should be 1.21+

# Clean build
cd /opt/proxy-server-local
rm -rf bin/
make build
```

**Git pull conflicts:**
```bash
cd /opt/proxy-server-local
git stash
git pull origin main
# Review stashed changes if needed
git stash list
```

## Multi-Node Update (Batch Update)

For updating multiple nodes simultaneously, use `update-all-nodes.sh`:

### Setup

1. Create a `nodes.txt` file with your node list:
   ```bash
   cp nodes.txt.example nodes.txt
   nano nodes.txt
   ```

2. Add your nodes (one per line):
   ```
   192.168.1.10
   192.168.1.11
   root@192.168.1.12
   admin@node4.example.com
   ```

### Usage

```bash
./update-all-nodes.sh [nodes_file]
```

If `nodes_file` is not specified, it defaults to `nodes.txt`.

### Features

- ✅ **Parallel execution**: Update up to 5 nodes simultaneously
- ✅ **Progress tracking**: Real-time status updates
- ✅ **Detailed logging**: Each node update logged separately
- ✅ **Error handling**: Continue on failure, report at end
- ✅ **Summary report**: Success/failure counts with details

### Example Output

```
╔════════════════════════════════════════════════════════════╗
║         PGW Multi-Node Update Script                      ║
╚════════════════════════════════════════════════════════════╝

Found 3 node(s) to update

Nodes to update:
  1. 192.168.1.10
  2. 192.168.1.11
  3. 192.168.1.12

Continue with update? (yes/no): yes

==> Starting parallel updates (max 5 concurrent)

[14:30:01] Starting update on 192.168.1.10
[14:30:01] Starting update on 192.168.1.11
[14:30:01] Starting update on 192.168.1.12
[14:30:45] ✓ SUCCESS 192.168.1.10
[14:30:47] ✓ SUCCESS 192.168.1.11
[14:30:50] ✓ SUCCESS 192.168.1.12

╔════════════════════════════════════════════════════════════╗
║                    Update Summary                          ║
╚════════════════════════════════════════════════════════════╝
  Total nodes:      3
  Successful:       3
  Failed:           0
  Logs directory:   ./update-logs

🎉 All nodes updated successfully!
```

### Configuration

Edit script variables to customize:

```bash
PARALLEL_JOBS=5      # Number of concurrent updates
SSH_TIMEOUT=300      # SSH timeout in seconds
SSH_USER="root"      # Default SSH user
```

### Logs

All update logs are saved in `./update-logs/` directory:
- One log file per node per update attempt
- Format: `update-<node>-<timestamp>.log`
- View logs: `ls -lt update-logs/`

### Prerequisites

- SSH key-based authentication configured for all nodes
- User has sudo permissions on all nodes
- Git and Go installed on all nodes
- `/opt/proxy-server-local` exists on all nodes

### SSH Key Setup (if needed)

```bash
# Generate SSH key (if not exists)
ssh-keygen -t ed25519 -C "pgw-admin"

# Copy to all nodes
for node in node1 node2 node3; do
    ssh-copy-id root@$node
done
```
