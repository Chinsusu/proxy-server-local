# Troubleshooting

## /agent/reconcile trả 404/405
- Sai base đường dẫn. Đúng là: `PGW_UI_AGENT=http://127.0.0.1:9090/agent`
- Kiểm tra: `curl -sI http://127.0.0.1:8081/agent/reconcile`

## Rules nftables không xuất hiện
- Agent chưa chạy hoặc reconcile lỗi. Xem: `journalctl -u pgw-agent -n 200`
- Gọi lại: `curl -s http://127.0.0.1:8081/agent/reconcile`

## Windows client không ra Internet
- Đặt **Gateway** = IP máy PGW (ví dụ `192.168.2.1`) và **DNS** = IP máy PGW.
- Chỉ HTTP/HTTPS đi qua; ping bị chặn (chủ đích).
- Upstream proxy DOWN → check lại `/v1/proxies/{id}/check`.

## UI trắng/không có dữ liệu
- API memory store bị rỗng sau restart → tạo lại dữ liệu.
- Kiểm tra `PGW_UI_API` và `PGW_UI_AGENT`.

## Lỗi "delete table ... not found" khi reconcile
- Có thể bỏ qua (idempotent); script đã xử lý xóa nếu có.
