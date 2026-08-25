# PGW v2 Quick Ops

## Trạng thái control plane

```bash
systemctl status nftables.service systemd-sysctl.service --no-pager
systemctl status pgw-api.service pgw-agent.service pgw-ui.service pgw-health.service --no-pager
systemctl list-units --all 'pgw-fwd@*.service'
curl --fail http://127.0.0.1:9090/healthz
curl --fail http://127.0.0.1:9090/metrics
```

## Trạng thái data plane

```bash
sudo /usr/local/sbin/pgw-verify-base
nft list table inet pgw_base
nft list table inet pgw_dynamic
ss -lntp
```

Không sửa rule trực tiếp. Nếu desired/applied generation lệch, kiểm tra log
Agent và audit API; Agent sẽ reconcile/LKG theo worker queue.

## Store và log

```bash
sqlite3 /var/lib/pgw/pgw.db 'PRAGMA integrity_check;'
journalctl -u pgw-agent.service -u pgw-api.service --since '-15 min' --no-pager
journalctl -u 'pgw-fwd@*.service' --since '-15 min' --no-pager
```

Không dump credential, token hoặc ciphertext vào ticket/log. SQLite backup và
restore chỉ chạy qua lifecycle transaction khi writer đã dừng.

## Update / rollback

```bash
sudo /usr/local/sbin/pgw-release-launcher --dry-run
sudo /usr/local/sbin/pgw-release-launcher
sudo /usr/local/sbin/pgw-release-launcher --rollback /var/backups/pgw/install.XXXXXXXX
```

Không copy binary/DB thủ công và không restart instance Forwarder ngoài Agent.
Trong sự cố, bảo toàn base kill-switch và management/OOB; ưu tiên fail-close.

## Canary sau thay đổi

1. Xác minh base table và `ip_forward`.
2. Đăng nhập `https://PGW_DNS_NAME:8081/login`.
3. Với client canary, xác minh exit IP đúng proxy và destination/proxy log.
4. Xác minh client chưa mapping, UDP, IPv6 và TCP ngoài policy bị chặn.
5. Soak tối thiểu 30 phút; rollback nếu xuất hiện direct-WAN hoặc state/hash sai.
