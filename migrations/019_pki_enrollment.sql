-- PR-014: durable enrollment abuse-control windows. Keeping counters in
-- PostgreSQL makes limits atomic across Atom replicas and process restarts.
CREATE TABLE pki_enrollment_rate_windows (
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('entity', 'tenant')),
    scope_id UUID NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    request_count BIGINT NOT NULL CHECK (request_count > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_kind, scope_id, window_start)
);

CREATE INDEX idx_pki_enrollment_rate_windows_updated
    ON pki_enrollment_rate_windows (updated_at);

COMMENT ON TABLE pki_enrollment_rate_windows IS
    'Fixed-window counters for PR-014 per-entity and per-tenant enrollment limits';
