-- Access-token usage tracking. Stamped on successful bearer authentication,
-- throttled in the application to at most one write per credential per five
-- minutes, so owners can spot unused tokens before revoking them.
ALTER TABLE credentials ADD COLUMN last_used_at TIMESTAMPTZ;
