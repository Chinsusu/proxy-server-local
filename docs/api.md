# API Reference

Base: `http://127.0.0.1:8080`

> Tất cả endpoint (trừ `/v1/health` và `/v1/auth/login`) yêu cầu header `Authorization: Bearer <JWT>`.

## Health
- `GET /v1/health` → `"ok"` *(không cần auth)*

## Auth
- `POST /v1/auth/login` body: `{"Username":"admin","Password":"<pass>"}` *(không cần auth)*
  - → `200 {"token":"<JWT>","role":"admin","expires_at":"<RFC3339>"}` (JWT TTL = **12 giờ**)
  - → `401` nếu sai credentials
  - → `429` nếu vượt rate limit (5 lần thất bại / 15 phút / IP)

## Proxies
- `GET /v1/proxies` → `[]Proxy` (sắp xếp theo host, port, id)
- `POST /v1/proxies` body:
  ```json
  {"type":"http","host":"...","port":24639,"username":"...","password":"...","enabled":true}
  ```
  - `type`: `"http"` hoặc `"socks5"`
  - → `201 Proxy`
  - → `409` nếu proxy trùng (cùng host + port + username + password)
- `DELETE /v1/proxies/{id}` → `204 No Content` (cascade xóa mappings liên quan; async cleanup forwarder + nft)
- `POST /v1/proxies/{id}/check` → `{status, latency_ms, exit_ip, err}` và cập nhật telemetry vào store

## Clients
- `GET /v1/clients` → `[]Client`
- `POST /v1/clients` body:
  ```json
  {"ip_cidr":"192.168.2.3/32","enabled":true}
  ```
  Ghi chú: nếu gửi `"192.168.2.3"` sẽ tự chuyển thành `/32`; prefix `<32` sẽ trả `400`.
- `DELETE /v1/clients/{id}` → `204 No Content` (cascade xóa mappings liên quan)

## Mappings
- `GET /v1/mappings` → `[]MappingView` (kèm derived state, sắp xếp theo client IP)
  - **Được dùng bởi Agent** để lấy tất cả mappings để reconcile nftables
- `GET /v1/mappings/active` → `[]MappingView` (filtered theo `PGW_ENFORCE_HEALTH`)
  - **Được dùng bởi Forwarder** để resolve upstream proxy theo `LocalRedirectPort`
- `POST /v1/mappings` body:
  ```json
  {"client_id":"...","proxy_id":"..."}
  ```
  - API tự gán `local_redirect_port` (1 client = 1 port cố định, dải 15001–15999)
  - Health-check upstream trước khi apply; nếu fail → `state=FAILED`
  - → `409` nếu proxy đã có mapping khác
  - → `201 MappingView`
- `POST /v1/mappings/state/{id}` body: `{"state":"APPLIED|PENDING|FAILED","local_redirect_port":15001}`
  - **Chỉ dành cho Agent** gọi sau khi reconcile (role `admin` hoặc `agent`)
  - → `204 No Content`
- `DELETE /v1/mappings/{id}` → `204 No Content` (async: cleanup flag file + stop forwarder + reconcile)

## Agent (port :9090)
- `GET /agent/reconcile` — apply nft idempotent, trả `"ok"`
- `POST /agent/reconcile` — giống GET
- `HEAD /agent/reconcile` — chỉ check status (200 OK)
- `GET /agent/health` — liveness check, trả `"ok"`

> Ghi chú: UI reverse proxy `/agent/*` → `http://127.0.0.1:9090/agent` nên có thể gọi qua `http://127.0.0.1:8081/agent/reconcile`.
