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
