# PGW v2 configuration reference

Production configuration comes from `/etc/pgw/pgw.env`; secret values are not
accepted there. Units receive secrets through systemd `LoadCredential=`.

## API

| Setting | Default | Purpose |
|---|---|---|
| `PGW_API_ADDR` | `127.0.0.1:8080` | Public API listener behind UI/reverse proxy |
| `PGW_AGENT_SOCKET` | `/run/pgw/control/api-agent.sock` | Internal Agent UDS; never TCP |
| `PGW_DB_PATH` | `/var/lib/pgw/pgw.db` | SQLite production database |
| `PGW_JWT_SECRET_FILE` | systemd credential | Compatibility file fallback; owner-only regular file |
| `PGW_ADMIN_PASS_HASH_FILE` | systemd credential | Compatibility file fallback for Argon2id PHC |
| `PGW_SECRETS_KEY_FILE` | systemd credential | AES-256-GCM master key source |
| `PGW_AGENT_TOKEN_FILE` | systemd credential | Scoped API↔Agent service token |

Plaintext JWT, admin password, proxy password and service-token environment
variables are rejected. SQLite is the only production store; JSON is limited to
explicit offline import/export.

## Agent

| Setting | Default | Purpose |
|---|---|---|
| `PGW_AGENT_ADDR` | `127.0.0.1:9090` | Loopback health/metrics/scoped trigger listener |
| `PGW_AGENT_SOCKET` | `/run/pgw/control/api-agent.sock` | Desired snapshot, credential and ACK UDS |
| `PGW_LAN_IFACE` | `ens19` | LAN ingress interface |
| `PGW_WAN_IFACE` | `eth0` | WAN egress interface |
| `PGW_LAN_ADDRESS` | **required; no default** | Exact validated global IPv4 on `PGW_LAN_IFACE`; persisted by the installer and used as the concrete Forwarder data-listener address |
| `PGW_FORWARDER_RUNTIME_ROOT` | `/run/pgw/forwarders` | Agent-owned runtime/config/credential sources |
| `PGW_LKG_DIRECTORY` | `/var/lib/pgw/rules` | LKG and durable transition journal |
| `PGW_FWD_BASE_PORT` | `15001` | First permitted Forwarder instance port |
| `PGW_FWD_MAX_PORT` | `15999` | Last permitted Forwarder instance port |

Agent is the sole writer for dynamic nftables and sole manager of
`pgw-fwd@<numeric-port>.service`. API and UI cannot invoke these operations.
Agent rejects startup when `PGW_LAN_ADDRESS` is absent, wildcard, loopback,
multicast, or IPv6; it never falls back to a compiled management address.

## Forwarder

Forwarder reads non-secret JSON from
`/run/pgw/forwarders/<port>/forwarder.json`. Username/password, when configured,
arrive only as per-instance systemd credentials. Data binds the concrete LAN IP;
metrics bind `127.0.0.2:<same-port>`.

## UI and health

| Setting | Default | Purpose |
|---|---|---|
| `PGW_UI_ADDR` | `<validated LAN IPv4>:8081` | HTTPS management listener; wildcard/loopback/WAN bind forbidden |
| `PGW_UI_API` | `http://127.0.0.1:8080` | UI proxy to public API only |
| `PGW_UI_WEB_DIR` | `/usr/local/share/pgw/web` | Read-only verified asset tree |
| `PGW_HEALTH_INTERVAL` | `30s` | Health monitor interval |

UI TLS key/certificate and UI proxy identity token are systemd credentials. UI
has no route or credential to the Agent listener.

## Lifecycle

Use only the root-owned static `/usr/local/sbin/pgw-release-launcher`. Install,
update and rollback share
`/run/pgw-lifecycle.lock`; manual binary/DB replacement and webhook deployment
are unsupported.
