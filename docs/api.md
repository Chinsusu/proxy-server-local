# API Reference

Base: `http://127.0.0.1:8080`

## Health
- `GET /v1/health` → `"ok"`

## Proxies
- `GET /v1/proxies` → `[]Proxy`
- `POST /v1/proxies` body:
  ```json
  {"type":"http","host":"...","port":24639,"username":"...","password":"...","enabled":true}
  ```
  → `201 Proxy`
- `POST /v1/proxies/{id}/check` → `{status, latency_ms, exit_ip}` và đồng thời cập nhật telemetry.

## Clients
- `GET /v1/clients` → `[]Client`
- `POST /v1/clients` body:
  ```json
  {"ip_cidr":"192.168.2.3/32","enabled":true}
  ```
  Ghi chú: nếu gửi `"192.168.2.3"` sẽ tự chuyển thành `/32`; prefix `<32` sẽ trả `400`.
- `DELETE /v1/clients/{id}` → `204 No Content` (cũng xóa mappings liên quan).

## Mappings
- `GET /v1/mappings` → `[]MappingView`
- `GET /v1/mappings/active` → `[]MappingView` (đang enabled)
- `POST /v1/mappings` body:
  ```json
  {"client_id":"...","proxy_id":"..."}
  ```
  → `201 MappingView`
- `DELETE /v1/mappings/{id}` → `204`

## Agent

Base: qua UI proxy `http://127.0.0.1:8081/agent`

- `GET /reconcile` → `ok` (apply nft idempotent)
