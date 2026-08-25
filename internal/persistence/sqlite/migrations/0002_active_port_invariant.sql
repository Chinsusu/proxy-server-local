-- A transparent listener must never have two competing ACTIVE primary
-- mappings. Draft/suspended mappings may retain a requested port for review.
CREATE UNIQUE INDEX IF NOT EXISTS idx_mappings_one_active_per_redirect_port
ON mappings(local_redirect_port) WHERE desired_state = 'ACTIVE';
