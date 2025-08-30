# PGW — Proxy Gateway

PGW ép toàn bộ HTTP/HTTPS (TCP 80/443) từ các **client trong LAN** đi qua **forwarder (:15001)**, forwarder sẽ dùng **upstream HTTP proxy** (có thể có user/pass) để đổi **exit IP**.  
Kiến trúc gồm 4 thành phần:

- **API** (`pgw-api`, :8080): quản lý `proxies / clients / mappings`, health-check, telemetry.
- **Agent** (`pgw-agent`, :9090/agent): sinh & apply rules **nftables** từ `mappings`.
- **Forwarder** (`pgw-fwd`, :15001): transparent CONNECT (+ ghi log SNI đã ẩn nhạy cảm).
- **UI** (`pgw-ui`, :8081): dashboard & reverse proxy (`/api/*`→API, `/agent/*`→Agent).

> Ràng buộc hiện tại: **mỗi client là 1 IP /32** (không nhận CIDR rộng hơn).

---

## Nhanh gọn để chạy thử

Yêu cầu: Go ≥ 1.21, Linux có `nft` (nftables), systemd.

```bash
# Build từng thành phần
go build -o bin/pgw-api   ./cmd/api
go build -o bin/pgw-agent ./cmd/agent
go build -o bin/pgw-fwd   ./cmd/fwd
go build -o bin/pgw-ui    ./cmd/ui

sudo install -m 0755 bin/pgw-* /usr/local/bin/

# Chạy dịch vụ (xem ví dụ systemd ở docs/deploy.md)
sudo systemctl restart pgw-api pgw-agent pgw-fwd pgw-ui
```

Mặc định địa chỉ:

* API: `http://127.0.0.1:8080`
* Agent: `http://127.0.0.1:9090/agent`
* UI: `http://127.0.0.1:8081` (proxy `/api/*` và `/agent/*`)
* Forwarder: `:15001`

---

## Cấu hình (env)

* **API**

  * `PGW_API_ADDR` (mặc định `:8080`)
  * `PGW_STORE` = `memory` (mặc định) hoặc `file`
  * `PGW_STORE_PATH` (khi `file`, ví dụ `/var/lib/pgw/state.json`)
  * `PGW_HEALTH_INTERVAL` (ví dụ `30s`)
* **Agent**

  * `PGW_AGENT_ADDR` (mặc định `:9090`)
  * `PGW_API_BASE` (mặc định `http://127.0.0.1:8080`)
  * `PGW_WAN_IFACE` (ví dụ `eth0`)
  * `PGW_LAN_IFACE` (ví dụ `ens19`)
* **Forwarder**

  * `PGW_FWD_ADDR` (mặc định `:15001`)
* **UI**

  * `PGW_UI_ADDR` (mặc định `:8081`)
  * `PGW_UI_API` (mặc định `http://127.0.0.1:8080`)
  * `PGW_UI_AGENT` (mặc định `http://127.0.0.1:9090/agent`)

---

## Luồng hoạt động

1. Tạo **proxy** (upstream) qua API/UI → health-check để có `status/latency/exit_ip`.
2. Tạo **client** (IP **/32**).
3. Tạo **mapping** client ↔ proxy.
4. Agent `/agent/reconcile` sinh rules `nft`:

   * NAT redirect TCP 80/443 từ IP client → `:15001`.
   * Chặn leak ra WAN (`oifname "eth0" drop`), chặn UDP từ client, mở DNS 53 về gateway, mở input port 15001.
5. Forwarder tiếp nhận kết nối, thực hiện CONNECT tới upstream, log (ẩn nhạy cảm).

---

## API nhanh (cURL)

```bash
API=http://127.0.0.1:8080

# Proxy
curl -s -H 'Content-Type: application/json' -d '{
  "type":"http","host":"ipv4-vt-01.resvn.net","port":24639,
  "username":"USER","password":"PASS","enabled":true
}' $API/v1/proxies | jq .

PID=$(curl -s $API/v1/proxies | jq -r '.[0].id')
curl -s -X POST $API/v1/proxies/$PID/check | jq .

# Client (chỉ /32, nếu thiếu "/32" thì API tự gắn "/32")
curl -s -H 'Content-Type: application/json' \
  -d '{"ip_cidr":"192.168.2.3/32","enabled":true}' \
  $API/v1/clients | jq .

# Mapping
CID=$(curl -s $API/v1/clients | jq -r '.[0].id')
curl -s -H 'Content-Type: application/json' \
  -d '{"client_id":"'"$CID"'","proxy_id":"'"$PID"'"}' \
  $API/v1/mappings | jq .

# Xem
curl -s $API/v1/mappings/active | jq .
```

Danh sách endpoint chi tiết: xem `docs/api.md`.

---

## Ghi chú bảo mật

* Agent cần quyền apply `nft` → chạy dưới user có quyền hoặc cấp quyền `sudo nft -f -` an toàn.
* UI reverse-proxy chỉ nên bind `127.0.0.1` hoặc đặt sau reverse-proxy bên ngoài.
* Log SNI/domain đã **ẩn bớt** thông tin nhạy cảm.
* Chặn leak ngoài WAN & UDP tại `pgw_filter`.

---

## Giới hạn hiện tại

* **Chỉ hỗ trợ client IP /32** (theo Phương án A).
* Upstream proxy loại `http`; SOCKS/HTTPS sẽ thêm sau.
* `memory store` mất dữ liệu khi restart (dùng `file` để lưu bền).

---

## Tài liệu chi tiết

* `docs/architecture.md` – Kiến trúc & rule nftables sinh ra.
* `docs/deploy.md` – Cài đặt, systemd units, biến môi trường.
* `docs/api.md` – Tài liệu API.
* `docs/ui.md` – Giao diện & reverse proxy.
* `docs/troubleshooting.md` – Lỗi thường gặp & cách xử lý.
* `docs/security.md` – Khuyến nghị bảo mật.

---

## License

MIT (tùy bạn chọn).
