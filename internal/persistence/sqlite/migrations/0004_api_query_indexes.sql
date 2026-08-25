-- API cursor reads and Agent snapshots use these stable, low-cardinality
-- orderings. This is forward-only and does not change any public data shape.
CREATE INDEX IF NOT EXISTS idx_mappings_desired_state_id
ON mappings(desired_state, id);

CREATE INDEX IF NOT EXISTS idx_audit_events_id
ON audit_events(id);
