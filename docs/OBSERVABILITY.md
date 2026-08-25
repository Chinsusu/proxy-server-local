# Observability

PGW services write one structured JSON object per line to stdout, which is
captured by journald in the production unit. Every request log has
`timestamp`, `level`, `service`, `event`, and a validated or generated
`request_id`. Optional operational fields are bounded to `mapping_id`,
`proxy_id`, `generation`, and `reason_code`. Request bodies, query strings,
cookies, JWTs, passwords, tokens, ciphertext, credentials, and credential
paths are never logged. The shared implementation is `pkg/observability`;
services must not introduce ad-hoc log schemas.

`X-Request-ID` is accepted only as an 8--64 character ASCII identifier using
letters, digits, `_`, and `-`; all other values are replaced by a generated
opaque ID. It is returned in the response and included in the standard v2
error envelope.

## Metrics

The API exposes `/metrics` only through its already numeric-loopback API
listener. The UI uses a **separate** numeric-loopback listener, controlled by
`PGW_UI_METRICS_ADDR` (default `127.0.0.1:9091`); it is never routed through
the browser TLS ingress. `localhost`, wildcard, and non-loopback values are
rejected at startup. Scrape these endpoints locally through a node exporter,
or tunnel them explicitly; do not publish them through the management proxy.

Metric labels are deliberately bounded. No metric has client, mapping, proxy,
credential, IP address, raw path, query, or request ID labels.

| Metric | Labels |
| --- | --- |
| `pgw_http_requests_total` | `service`, `method`, `route`, `status_class` |
| `pgw_http_request_duration_seconds_sum/count` | `service`, `method`, `route`, `status_class` |
| `pgw_auth_attempts_total` | `service`, `outcome`, `reason` |
| `pgw_db_errors_total` | `service`, `reason` |
| `pgw_schema_migration_ready` | `service`, `status` |
| `pgw_agent_generation_pending/applied` | `service` |
| `pgw_agent_state` | `service`, `state` (`unknown`, `pending`, `applying`, `applied`, `verified`, `failed`, `rolled_back`) |
| `pgw_ui_proxy_requests_total` | `service`, `route`, `status_class` |

Routes are templates (`/v2/proxies/{id}`, never a raw identifier). Auth
reasons are bounded operational enums such as `authenticated`,
`invalid_credentials`, and `rate_limited`.

## Health endpoints

`/healthz` is process liveness. `/readyz` checks the SQLite control-plane
read path and returns `503` when it is unavailable. These endpoints inherit
the API loopback listener and must not be exposed directly.
