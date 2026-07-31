-- Index to optimize outbox retention cleanup queries for delivered and exhausted rows.

CREATE INDEX idx_event_outbox_retention ON event_outbox(created_at) WHERE delivered_at IS NOT NULL OR unparseable = true;
