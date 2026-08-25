CREATE TABLE IF NOT EXISTS proxies (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL CHECK (type IN ('http', 'socks5')),
    host TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    username TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    status TEXT NOT NULL DEFAULT 'DOWN' CHECK (status IN ('OK', 'DEGRADED', 'DOWN')),
    latency_ms INTEGER,
    exit_ip TEXT NOT NULL DEFAULT '',
    last_checked_at INTEGER,
    version INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_proxies_status ON proxies(status);

CREATE TABLE IF NOT EXISTS proxy_secrets (
    proxy_id TEXT PRIMARY KEY REFERENCES proxies(id) ON DELETE CASCADE,
    envelope_version INTEGER NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS proxy_capabilities (
    proxy_id TEXT PRIMARY KEY REFERENCES proxies(id) ON DELETE CASCADE,
    supports_tcp INTEGER NOT NULL DEFAULT 1 CHECK (supports_tcp IN (0, 1)),
    supports_udp INTEGER NOT NULL DEFAULT 0 CHECK (supports_udp IN (0, 1)),
    remote_dns INTEGER NOT NULL DEFAULT 0 CHECK (remote_dns IN (0, 1)),
    probe_state TEXT NOT NULL DEFAULT 'UNKNOWN',
    probed_at INTEGER,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS proxy_health_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proxy_id TEXT NOT NULL REFERENCES proxies(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('OK', 'DEGRADED', 'DOWN')),
    latency_ms INTEGER,
    exit_ip TEXT NOT NULL DEFAULT '',
    reason_code TEXT NOT NULL DEFAULT '',
    checked_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_proxy_health_proxy_time ON proxy_health_snapshots(proxy_id, checked_at DESC);

CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY,
    ip_cidr TEXT NOT NULL UNIQUE,
    note TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    version INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS egress_policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL CHECK (kind IN ('web_only')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    version INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
INSERT OR IGNORE INTO egress_policies (id, name, kind, enabled, version, created_at, updated_at)
VALUES ('default-web-only', 'Default web-only', 'web_only', 1, 1, unixepoch() * 1000, unixepoch() * 1000);

CREATE TABLE IF NOT EXISTS mappings (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
    proxy_id TEXT NOT NULL REFERENCES proxies(id) ON DELETE RESTRICT,
    policy_id TEXT NOT NULL REFERENCES egress_policies(id) ON DELETE RESTRICT,
    local_redirect_port INTEGER NOT NULL CHECK (local_redirect_port BETWEEN 1 AND 65535),
    desired_state TEXT NOT NULL DEFAULT 'DRAFT' CHECK (desired_state IN ('DRAFT', 'ACTIVE', 'SUSPENDED', 'DELETED')),
    desired_generation INTEGER NOT NULL DEFAULT 0 CHECK (desired_generation >= 0),
    applied_generation INTEGER NOT NULL DEFAULT 0 CHECK (applied_generation >= 0),
    desired_hash TEXT NOT NULL DEFAULT '',
    applied_hash TEXT NOT NULL DEFAULT '',
    data_plane_state TEXT NOT NULL DEFAULT 'UNKNOWN' CHECK (data_plane_state IN ('VERIFIED', 'UNKNOWN', 'FAILED')),
    version INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mappings_one_active_per_client
ON mappings(client_id) WHERE desired_state = 'ACTIVE';
CREATE INDEX IF NOT EXISTS idx_mappings_desired_generation ON mappings(desired_generation);

CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    token_id TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    version INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS reconcile_states (
    node_id TEXT PRIMARY KEY,
    pending_generation INTEGER NOT NULL DEFAULT 0 CHECK (pending_generation >= 0),
    applied_generation INTEGER NOT NULL DEFAULT 0 CHECK (applied_generation >= 0),
    ruleset_hash TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'UNKNOWN',
    last_error TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    entity TEXT NOT NULL,
    entity_id TEXT NOT NULL DEFAULT '',
    payload BLOB NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_events_entity_time ON audit_events(entity, entity_id, created_at DESC);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    scope TEXT NOT NULL,
    key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    response BLOB NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    PRIMARY KEY (scope, key)
);
