# Hướng dẫn triển khai

## Build & cài đặt

```bash
go build -o bin/pgw-api   ./cmd/api
go build -o bin/pgw-agent ./cmd/agent
go build -o bin/pgw-fwd   ./cmd/fwd
go build -o bin/pgw-ui    ./cmd/ui
sudo install -m 0755 bin/pgw-* /usr/local/bin/
```

## systemd units (ví dụ)

`/etc/systemd/system/pgw-api.service`

```ini
[Unit]
Description=PGW API
After=network.target

[Service]
Environment=PGW_API_ADDR=:8080
Environment=PGW_STORE=memory
# Environment=PGW_STORE=file
# Environment=PGW_STORE_PATH=/var/lib/pgw/state.json
Environment=PGW_HEALTH_INTERVAL=30s
ExecStart=/usr/local/bin/pgw-api
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/pgw-agent.service`

```ini
[Unit]
Description=PGW Agent
After=network.target pgw-api.service

[Service]
Environment=PGW_AGENT_ADDR=:9090
Environment=PGW_API_BASE=http://127.0.0.1:8080
Environment=PGW_WAN_IFACE=eth0
Environment=PGW_LAN_IFACE=ens19
ExecStart=/usr/local/bin/pgw-agent
# Nếu cần quyền nft:
# CapabilityBoundingSet=CAP_NET_ADMIN
# hoặc cấu hình sudoers cho "nft -f -" an toàn
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/pgw-fwd.service`

```ini
[Unit]
Description=PGW Forwarder
After=network.target

[Service]
Environment=PGW_FWD_ADDR=:15001
ExecStart=/usr/local/bin/pgw-fwd
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/pgw-ui.service`

```ini
[Unit]
Description=PGW UI
After=network.target pgw-api.service pgw-agent.service

[Service]
Environment=PGW_UI_ADDR=:8081
Environment=PGW_UI_API=http://127.0.0.1:8080
Environment=PGW_UI_AGENT=http://127.0.0.1:9090/agent
ExecStart=/usr/local/bin/pgw-ui
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Kích hoạt:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pgw-api pgw-agent pgw-fwd pgw-ui
```

## Kiểm tra nhanh

```bash
# UI reverse proxy tới agent
curl -sI http://127.0.0.1:8081/agent/reconcile | head -n1   # 200 OK

# Kiểm tra rule
sudo nft list table ip pgw
sudo nft list table inet pgw_filter

# Kiểm tra forwarder
ss -lntp | grep :15001
journalctl -u pgw-fwd -f
```

## Hành vi mặc định: Auto-apply, per-client port và Auto-cleanup

- Tạo mapping (POST /v1/mappings):
  - Mô hình "1 cổng forwarder ↔ 1 client": mỗi client có một cổng forwarder riêng (khác client → cổng khác; cùng client → tái sử dụng cùng cổng).
  - API tự gán cổng theo client: nếu proxy đã có cổng, tái sử dụng; nếu chưa, chọn cổng trống trong khoảng [PGW_FWD_BASE_PORT..PGW_FWD_MAX_PORT] (mặc định 15001..15999). Có thể cung cấp `local_redirect_port` nhưng sẽ bị từ chối nếu cổng đó đang thuộc client khác.
  - API ghi file cờ `/var/lib/pgw/ports/<port>`, và khi là lần đầu dùng cổng đó, API sẽ `systemctl start pgw-fwd@<port>` (best-effort). Sau đó gọi Agent `reconcile`. Khi cổng `127.0.0.1:<port>` mở và rule nft đã có, mapping được đánh dấu `APPLIED`.
  - Biến môi trường (tuỳ chọn): `PGW_FWD_BASE_PORT` và `PGW_FWD_MAX_PORT` để điều chỉnh dải cổng tự cấp.

- Xóa mapping (DELETE /v1/mappings/{id}):
  - API ghi nhận `port` của mapping trước khi xóa; sau khi xóa:
    - Nếu không còn mapping nào dùng cùng `port` đó, API sẽ xóa file cờ `/var/lib/pgw/ports/<port>` và chạy `systemctl stop pgw-fwd@<port>` (an toàn, no‑op nếu unit không tồn tại).
    - Luôn gọi Agent `reconcile` để đồng bộ nftables.

- Gợi ý kiểm tra nhanh:
  - Sau khi tạo mapping: `ls /var/lib/pgw/ports` → thấy tệp ứng với port.
  - Sau khi xóa mapping cuối cùng dùng port đó: tệp tương ứng biến mất, và `systemctl status pgw-fwd@<port>` sẽ không còn chạy (nếu dùng template unit).
  - `sudo nft list table ip pgw` và `sudo nft list table inet pgw_filter` phản ánh trạng thái mới.

## Forwarder theo cổng với systemd template (khuyến nghị)

Tạo unit mẫu `/etc/systemd/system/pgw-fwd@.service` để chạy nhiều forwarder song song, mỗi instance lắng nghe một cổng:

```ini
[Unit]
Description=PGW Forwarder instance on port %i
After=network.target

[Service]
Environment=PGW_FWD_ADDR=:%i
ExecStart=/usr/local/bin/pgw-fwd
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Khởi chạy ví dụ:

```bash
sudo systemctl enable --now pgw-fwd@15001
# Nếu có mapping khác dùng cổng khác:
sudo systemctl enable --now pgw-fwd@15002
```

Lưu ý: API sẽ dọn cờ `/var/lib/pgw/ports/<port>` và gọi `systemctl stop pgw-fwd@<port>` khi xoá mapping cuối cùng dùng cổng đó. API cũng sẽ cố gắng `systemctl start pgw-fwd@<port>` khi proxy lần đầu được gán cổng. Bạn vẫn có thể quản lý thủ công các instance nếu muốn.


Lưu ý (an toàn): Chỉ apply mapping sau khi kiểm tra health của proxy thành công (OK/DEGRADED).
Nếu health thất bại, mapping ở trạng thái FAILED và sẽ không khởi động forwarder/cấp rule.

## Authentication (JWT)

Thiết lập đăng nhập admin và bảo mật JWT qua file ENV (/etc/pgw/pgw.env):

- Bắt buộc:
  - `PGW_JWT_SECRET` — khoá ký JWT.
- Admin bootstrap (API login):
  - `PGW_ADMIN_USER` và `PGW_ADMIN_PASS_HASH` (Argon2id PHC, khuyến nghị),
    hoặc `PGW_ADMIN_PASS` (không khuyến nghị).
- Agent nội bộ:
  - (Tuỳ chọn) `PGW_AGENT_TOKEN` — token để Agent gọi API (được coi là role `agent`).

Đăng nhập API: `POST /v1/auth/login` với JSON `{username,password}` → trả về token JWT.
UI có trang `/login`, cookie `pgw_jwt` sẽ được set và tự động forward tới API.
