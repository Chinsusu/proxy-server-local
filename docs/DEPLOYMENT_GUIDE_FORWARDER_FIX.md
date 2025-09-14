# Deployment Guide: Forwarder Binding Fix

## Quick Summary
This fix resolves routing loops where forwarders bind to all interfaces (including localhost) causing client connections to get redirected back to themselves.

**Fix**: Change forwarder binding from `:port` to `LAN_IP:port`

## 🚀 Automated Deployment

### Option 1: Using the Script (Recommended)
```bash
# 1. Clone/pull latest code
git pull origin main

# 2. Run the automated fix script
sudo ./scripts/apply-forwarder-fix.sh
```

The script will:
- Auto-detect your LAN IP
- Backup original service file
- Update binding configuration
- Restart all forwarder services
- Verify the fix is working

## 🔧 Manual Deployment

### Step 1: Backup Current Configuration
```bash
sudo cp /etc/systemd/system/pgw-fwd@.service /etc/systemd/system/pgw-fwd@.service.backup.$(date +%Y%m%d)
```

### Step 2: Determine Your LAN IP
```bash
# Method 1: From PGW config
LAN_IFACE=$(grep "PGW_LAN_IFACE=" /etc/pgw/pgw.env | cut -d'=' -f2)
LAN_IP=$(ip addr show $LAN_IFACE | grep "inet " | head -1 | awk '{print $2}' | cut -d'/' -f1)
echo "LAN IP: $LAN_IP"

# Method 2: Manual check
ip addr show ens19  # or your LAN interface
```

### Step 3: Stop All Forwarder Services
```bash
# Stop all forwarder instances
for port in {15001..15050}; do
    sudo systemctl stop pgw-fwd@$port.service 2>/dev/null || true
done

# Kill any remaining processes
sudo pkill -f pgw-fwd || true
```

### Step 4: Update Service Configuration
```bash
# Replace YOUR_LAN_IP with your actual LAN IP (e.g., 192.168.2.1)
sudo sed -i 's/Environment=PGW_FWD_ADDR=:%i/Environment=PGW_FWD_ADDR=YOUR_LAN_IP:%i/' /etc/systemd/system/pgw-fwd@.service

# Verify the change
grep PGW_FWD_ADDR /etc/systemd/system/pgw-fwd@.service
```

### Step 5: Reload and Restart Services
```bash
# Reload systemd
sudo systemctl daemon-reload

# Start forwarder services for active mappings
for port in {15001..15017}; do  # Adjust range based on your setup
    sudo systemctl start pgw-fwd@$port.service
done
```

### Step 6: Verify Fix
```bash
# Check services are running
systemctl list-units --state=active | grep pgw-fwd@

# Verify binding to LAN IP (replace with your LAN IP)
ss -tlnp | grep "192.168.2.1:"

# Check logs for successful connections
journalctl -u pgw-fwd@15001.service --since "5 minutes ago" | grep OK
```

## 🔍 Verification Checklist

- [ ] All required forwarder services are `active` and `running`
- [ ] Forwarders bind to LAN IP, not `:::`
- [ ] Client connections show `OK` in logs, not `failed`
- [ ] No `CONNECT 127.0.0.1:15001 failed` errors
- [ ] Backup file created successfully

## 📊 Expected Results

**Before Fix:**
```bash
ss -tlnp | grep 1500
tcp6  0  0  :::15001  :::*  LISTEN  pgw-fwd
```

**After Fix:**
```bash
ss -tlnp | grep 1500
tcp   0  0  192.168.2.1:15001  0.0.0.0:*  LISTEN  pgw-fwd
```

**Logs Before:**
```
[ERROR] CONNECT 127.0.0.1:15001 via proxy failed: proxy refused CONNECT
```

**Logs After:**
```
[INFO] 192.168.2.101:50988 -> 104.208.203.90:443 via proxy OK
```

## 🚨 Emergency Rollback

If something goes wrong:
```bash
# 1. Stop all forwarders
sudo systemctl stop pgw-fwd@*.service

# 2. Restore backup
sudo cp /etc/systemd/system/pgw-fwd@.service.backup.* /etc/systemd/system/pgw-fwd@.service

# 3. Reload and restart
sudo systemctl daemon-reload
for port in {15001..15017}; do
    sudo systemctl start pgw-fwd@$port.service
done
```

## 📋 Server Inventory Template

Use this to track deployment across multiple servers:

| Server | IP | LAN Interface | Status | Deployed | Notes |
|--------|----|--------------|---------|---------| ------|
| pgw-01 | 10.0.1.10 | ens19 | ✅ Fixed | 2025-01-14 | |
| pgw-02 | 10.0.1.11 | ens19 | ❌ Pending | | |
| pgw-03 | 10.0.1.12 | ens18 | ❌ Pending | | Different interface |

## 🔧 Troubleshooting

### Issue: Script fails to detect LAN IP
**Solution**: Edit script and set LAN_IP manually:
```bash
# In apply-forwarder-fix.sh, modify:
LAN_IP="192.168.2.1"  # Your actual LAN IP
```

### Issue: Services fail to start
**Check**: 
```bash
systemctl status pgw-fwd@15001.service
journalctl -u pgw-fwd@15001.service --no-pager
```

### Issue: Still getting routing loops
**Check**:
1. Verify nftables rules don't redirect localhost traffic
2. Ensure forwarder really binds to LAN IP only
3. Check no other services using same ports

## 📞 Support

If you encounter issues:
1. Check logs: `journalctl -u pgw-fwd@15001.service`
2. Verify network config: `ip addr show`
3. Check service file: `cat /etc/systemd/system/pgw-fwd@.service`
4. Create GitHub issue with logs and system info
