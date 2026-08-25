-- Revisions bind an Agent snapshot to the exact proxy endpoint and optional
-- authentication material it will receive over the credential socket. Soft
-- deletion preserves mapping history and audit evidence while excluding
-- retired clients/proxies from public resources and future activation.
ALTER TABLE proxies ADD COLUMN proxy_revision INTEGER NOT NULL DEFAULT 1 CHECK (proxy_revision >= 1);
ALTER TABLE proxies ADD COLUMN credential_revision INTEGER NOT NULL DEFAULT 1 CHECK (credential_revision >= 1);
ALTER TABLE proxies ADD COLUMN deleted_at INTEGER;
ALTER TABLE clients ADD COLUMN deleted_at INTEGER;

CREATE INDEX IF NOT EXISTS idx_proxies_live_id ON proxies(id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_clients_live_id ON clients(id) WHERE deleted_at IS NULL;
