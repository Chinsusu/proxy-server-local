# PGW v2

PGW là gateway egress fail-close cho LAN. Bảng nftables tĩnh `inet pgw_base`
chặn trực tiếp `LAN → WAN`; Agent chỉ xuất bản bảng động sau khi Forwarder đã
báo `READY=1`. Không có direct fallback khi API, Agent, Forwarder hoặc upstream
proxy lỗi.

## Kiến trúc vận hành

- SQLite `/var/lib/pgw/pgw.db` là production store. JSON chỉ là định dạng
  import/export ngoại tuyến.
- `pgw-api` quản lý domain, SQLite và secret mã hóa; không gọi nftables hay
  systemd.
- `pgw-agent` là tiến trình duy nhất quản lý bảng nftables động và các instance
  `pgw-fwd@<port>.service`.
- `pgw-fwd` chạy theo từng mapping; credential đi qua systemd credentials, không
  nằm trong argument, environment, config hoặc log.
- `pgw-ui` phục vụ HTTPS và proxy API bằng token nội bộ riêng.

Các service chạy bằng user tách biệt. Chỉ Agent có `CAP_NET_ADMIN`; quyền quản
lý Forwarder của Agent bị giới hạn bằng polkit theo unit và port.

## Build và kiểm tra

```bash
go test ./...
go vet ./...
CGO_ENABLED=0 go build ./cmd/api ./cmd/agent ./cmd/fwd ./cmd/ui ./cmd/health
bash deploy/tests/hardening_test.sh
```

Không build hoặc triển khai `cmd/webhook`; auto-update qua webhook không được
hỗ trợ.

## Cài đặt và cập nhật

Production dùng self-managed candidate đã được owner kiểm SHA-256. Không chạy
checkout với quyền root; root chỉ chạy launcher nằm trong candidate đã stage:

```bash
sudo /opt/pgw/inbox/<release>/assembly/pgw-release-launcher \
  --adopt /opt/pgw/inbox/<release>/assembly --dry-run
sudo /opt/pgw/inbox/<release>/assembly/pgw-release-launcher \
  --adopt /opt/pgw/inbox/<release>/assembly --migrate-legacy --lan ens19 --wan eth0
```

Installer khóa toàn bộ lifecycle, dừng/drain service và Forwarder trước khi
snapshot DB/runtime, publish file nguyên tử, smoke test, rồi giữ snapshot tại
`/var/backups/pgw/install.*`. Snapshot được HMAC bằng key root-only và có journal
khôi phục bền vững. Credential site-specific chỉ được import từ inbox cố định
`/etc/pgw/credential-inbox`; không truyền đường dẫn qua environment. Không chép
binary hoặc DB thủ công. Xem
[`docs/deploy.md`](docs/deploy.md) và [`docs/QUICK_OPS.md`](docs/QUICK_OPS.md).

## Tài liệu kỹ thuật

- [Kiến trúc](docs/architecture.md)
- [API](docs/api.md)
- [Coding standard](docs/CODING_STANDARDS.md)
- [Git workflow](docs/GIT_WORKFLOW.md)
- [CI](docs/CI.md)

License: AGPL-3.0.
