
# Configuration Reference

## API (`pgw-api`)
| Env Var | Mặc định | Mô tả |
|---------|---------|-------|
| `PGW_API_ADDR` | `:8080` | Listen address |
| `PGW_JWT_SECRET` | *(bắt buộc)* | Khoá ký JWT; tối thiểu 32 ký tự |
| `PGW_JWT_STRICT` | `true` | `false` để bỏ qua validation JWT secret (chỉ dành cho dev) |
| `PGW_STORE` | `memory` | `memory` hoặc `file` |
| `PGW_STORE_PATH` | `/var/lib/pgw/state.json` | Path khi dùng `file` store |
| `PGW_HEALTH_INTERVAL` | `30s` | Chu kỳ health check |
| `PGW_ADMIN_USER` | — | Username admin |
| `PGW_ADMIN_PASS_HASH` | — | Argon2id PHC hash của password admin (khuyến nghị) |
| `PGW_ADMIN_PASS` | — | Password admin dạng plain (không khuyến nghị; tự hash khi start) |
| `PGW_AGENT_TOKEN` | — | Token nội bộ cho Agent gọi API (role `agent`) |
| `PGW_FWD_BASE_PORT` | `15001` | Port thấp nhất trong dải tự cấp cho forwarder |
| `PGW_FWD_MAX_PORT` | `15999` | Port cao nhất trong dải tự cấp cho forwarder |
| `PGW_ENFORCE_HEALTH` | `false` | `true` = `/v1/mappings/active` lọc bỏ mapping `FAILED` |

## Agent (`pgw-agent`)
| Env Var | Mặc định | Mô tả |
|---------|---------|-------|
| `PGW_AGENT_ADDR` | `:9090` | Listen address |
| `PGW_API_BASE` | `http://127.0.0.1:8080` | Base URL của API |
| `PGW_WAN_IFACE` | `eth0` | Tên interface WAN |
| `PGW_LAN_IFACE` | `ens19` | Tên interface LAN |
| `PGW_AGENT_RECONCILE` | `15s` | Chu kỳ reconcile định kỳ |
| `PGW_AGENT_TOKEN` | — | Token để Agent gọi API (cùng giá trị với API) |

## Forwarder (`pgw-fwd`)
| Env Var | Mặc định | Mô tả |
|---------|---------|-------|
| `PGW_FWD_ADDR` | `192.168.2.1:<port>` | Listen address (bind vào LAN IP để tránh routing loop) |
| `PGW_API_BASE` | `http://127.0.0.1:8080` | Base URL của API |
| `PGW_AGENT_TOKEN` | — | Token để Forwarder gọi `/v1/mappings/active` |
| `PGW_FWD_DIAL_TIMEOUT` | `5s` | Timeout kết nối TCP tới upstream proxy |
| `PGW_FWD_POLL_INTERVAL` | `30s` | Chu kỳ re-resolve upstream (hot-reload) |
| `PGW_FWD_MAX_CONNS` | `8192` | Số kết nối concurrent tối đa |
| `PGW_FWD_LOG_SAMPLE` | `100` | Log 1 trong N kết nối thành công (1 = log tất cả) |
| `PGW_FWD_IDLE_TIMEOUT` | `30m` | Timeout idle cho splice connection |
| `PGW_FWD_DRAIN_TIMEOUT` | `30s` | Thời gian chờ drain connections khi shutdown |

## UI (`pgw-ui`)
| Env Var | Mặc định | Mô tả |
|---------|---------|-------|
| `PGW_UI_ADDR` | `:8081` | Listen address |
| `PGW_UI_API` | `http://127.0.0.1:8080` | Forward `/api/*` tới đây |
| `PGW_UI_AGENT` | `http://127.0.0.1:9090/agent` | Forward `/agent/*` tới đây |
| `PGW_JWT_SECRET` | *(bắt buộc)* | Khoá verify JWT (cùng giá trị với API) |

## Webhook (`pgw-webhook`)
| Env Var | Mặc định | Mô tả |
|---------|---------|-------|
| `PGW_WEBHOOK_SECRET` | *(bắt buộc)* | HMAC secret để verify GitHub webhook signatures |
| `PGW_WEBHOOK_PORT` | `9091` | Listen port |
| `PGW_WEBHOOK_DEPLOY_SCRIPT` | `/usr/local/bin/update-pgw.sh` | Script chạy khi push tới `main` |
