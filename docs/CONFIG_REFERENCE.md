
# Configuration Reference

Common env:
- PGW_DB_DSN: Postgres or SQLite DSN.
- PGW_NATS_URL: nats://host:port
- PGW_HEALTH_INTERVAL: default 30s
- PGW_UI_ADDR, PGW_API_ADDR: listen addresses
- PGW_AGENT_ADDR: localhost control
- PGW_FORWARDER_BASE_PORT: base for per-mapping ports (e.g., 15000)
- PGW_WAN_IFACE: eth0
- PGW_LAN_IFACE: ens19
- PGW_STRICT_OUTPUT: true|false
- PGW_JWT_SECRET: JWT signing key

Service-specific:
- API: PGW_RATE_LIMIT_LOGIN, PGW_CORS_ORIGINS
- Health: PGW_CHECK_TIMEOUT_MS, PGW_LATENCY_OK_MS, PGW_LATENCY_WARN_MS
- Agent: PGW_RECONCILE_INTERVAL=1s, PGW_ENABLE_DNS_STUB=true|false
