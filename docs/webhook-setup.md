# GitHub Webhook Setup Guide

This guide explains how to configure GitHub webhook for automatic deployment of proxy-server-local.

---

## Prerequisites

1. PGW system installed and running
2. Port 9091 accessible from internet (for GitHub webhooks)
3. Access to GitHub repository settings

---

## Step 1: Get Webhook Secret

On your PGW server, find the webhook secret:

```bash
grep PGW_WEBHOOK_SECRET /etc/pgw/pgw.env
```

Copy the value after `PGW_WEBHOOK_SECRET=` (it's a 48-character random string).

---

## Step 2: Configure GitHub Webhook

1. Go to your GitHub repository: https://github.com/Chinsusu/proxy-server-local
2. Click **Settings** → **Webhooks** → **Add webhook**
3. Configure:
   - **Payload URL**: `http://<your-server-ip>:9091/webhook`
     - Example: `http://192.168.1.56:9091/webhook`
   - **Content type**: `application/json`
   - **Secret**: Paste the `PGW_WEBHOOK_SECRET` value from Step 1
   - **Which events**: Select "Just the `push` event"
   - **Active**: ✅ Checked
4. Click **Add webhook**

---

## Step 3: Verify Webhook

### Test from GitHub

1. In GitHub webhook settings, scroll down to "Recent Deliveries"
2. Click **Redeliver** on any recent delivery (or push a test commit)
3. Check Response:
   - **Status**: Should be `202 Accepted`
   - **Body**: `Deployment triggered`

### Check Server Logs

On your PGW server:

```bash
# Watch webhook service logs
sudo journalctl -u pgw-webhook -f

# Watch deployment logs
tail -f /var/log/pgw-deploy.log
```

You should see:
```
[INFO] Webhook received: Chinsusu/proxy-server-local push to refs/heads/main
[INFO] Commit: abc1234 by Your Name - Commit message
[DEPLOY] Starting deployment for commit abc1234
[DEPLOY] Deployment successful
```

---

## How Auto-Deployment Works

When you push to `main` branch:

1. **GitHub sends webhook** to `:9091/webhook`
2. **Webhook service validates** HMAC signature
3. **Filters branch** — only `main` branch triggers deployment
4. **Deployment script runs:**
   ```
   └─ Lock acquired (prevents concurrent deploys)
   └─ Git pull latest code
   └─ Backup current binaries to /var/backups/pgw/
   └─ Build new binaries (all services)
   └─ Install to /usr/local/bin/
   └─ Restart services (API, Agent, UI, Webhook)
   └─ Health check verification
   └─ Rollback if health check fails
   ```
5. **Deployment completes** in ~30 seconds

---

## Manual Operations

### Manual Deployment

```bash
sudo /usr/local/bin/update-pgw.sh
```

### Rollback to Previous Version

```bash
sudo /usr/local/bin/update-pgw.sh rollback
```

### Check Deployment Status

```bash
# Check last deployment
tail -20 /var/log/pgw-deploy.log

# Check available backups
ls -lh /var/backups/pgw/
```

### Check Webhook Health

```bash
curl http://localhost:9091/health
```

---

## Firewall Configuration

**If using UFW:**
```bash
sudo ufw allow 9091/tcp comment 'PGW Webhook'
```

**If using nftables:**
```bash
sudo nft add rule inet filter input tcp dport 9091 accept comment \"PGW Webhook\"
```

**For security**, consider restricting to GitHub IPs only:
- GitHub webhook IPs: https://api.github.com/meta (check `hooks` array)

---

## Troubleshooting

### Webhook Not Triggering

1. **Check if webhook service is running:**
   ```bash
   sudo systemctl status pgw-webhook
   ```

2. **Check if port 9091 is listening:**
   ```bash
   sudo ss -tlnp | grep 9091
   ```

3. **Check firewall:**
   ```bash
   sudo ufw status | grep 9091  # or check nftables
   ```

4. **Test webhook manually:**
   ```bash
   # Generate valid signature
   SECRET=$(grep PGW_WEBHOOK_SECRET /etc/pgw/pgw.env | cut -d'=' -f2)
   PAYLOAD='{"ref":"refs/heads/main","repository":{"full_name":"Chinsusu/proxy-server-local"},"head_commit":{"id":"test123","message":"Test","author":{"name":"Test"}}}'
   SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | cut -d' ' -f2)
   
   curl -X POST http://localhost:9091/webhook \
     -H "Content-Type: application/json" \
     -H "X-Hub-Signature-256: sha256=$SIGNATURE" \
     -d "$PAYLOAD"
   ```

### Deployment Failed

1. **Check deployment logs:**
   ```bash
   tail -50 /var/log/pgw-deploy.log
   ```

2. **Check if lock file stuck:**
   ```bash
   ls -la /var/run/pgw-deploy.lock
   # If stale, remove it:
   sudo rm -f /var/run/pgw-deploy.lock
   ```

3. **Manual rollback:**
   ```bash
   sudo /usr/local/bin/update-pgw.sh rollback
   ```

### GitHub Shows Red X on Webhook

- Check GitHub webhook delivery details
- Common issues:
  - Wrong secret configured
  - Server unreachable (firewall/network)
  - Webhook service not running

---

## Security Notes

1. **Webhook secret** prevents unauthorized deployment triggers
2. **Branch filtering** ensures only `main` pushes trigger deployment
3. **Lock mechanism** prevents concurrent deployments
4. **Automatic rollback** on health check failure
5. **Backups** kept for last 3 deployments

---

## Next Steps

After webhook is configured:

1. **Test with real commit**: Push a small change to `main`
2. **Monitor deployment**: Watch logs on all servers
3. **Verify services**: Check dashboard UI after deployment
4. **Setup alerts**: Consider monitoring webhook endpoint uptime
