# UI

- Chạy tại `:8081`
- Reverse proxy:
  - `/api/*` → `PGW_UI_API` (mặc định `http://127.0.0.1:8080`)
  - `/agent/*` → `PGW_UI_AGENT` (mặc định `http://127.0.0.1:9090/agent`)

## Tính năng
- Dashboard: thống kê, bảng Proxies (status/latency/exit_ip), bảng Mappings.
- Nút:
  - **Health All** (check tất cả proxies)
  - **Reconcile** (gọi agent)
  - **Create Proxy**, **Create Mapping**
  - **Delete Mapping**, **Delete Client** (qua API)
- Ghi nhớ tab đã chọn bằng `localStorage`.

## Khi UI "trắng"
- Thường do API dùng memory store → sau restart **trống dữ liệu**. Tạo lại proxy/client/mapping rồi **Reconcile**.
- Sai cấu hình `PGW_UI_AGENT` → `/agent/reconcile` trả 404/405 → chỉnh env và restart `pgw-ui`.
