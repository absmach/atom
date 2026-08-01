-- Generic domain-event publishing. Purely additive: one new table, no ALTER on
-- any existing table. Safe to apply on any deployment; the feature stays a
-- no-op until an operator sets ATOM_EVENTS_AMQP_URL.

CREATE TABLE event_outbox (
    id              UUID        PRIMARY KEY,
    event           TEXT        NOT NULL,
    -- Deliberately NOT foreign keys. The outbox is an append-only record of
    -- what happened, not of what currently exists, and constraining these
    -- columns to live rows lost events two ways:
    --
    --   1. Failure events. `audit::observe_error` publishes the attempt that
    --      failed, and a common reason for failing is that the tenant in the
    --      request does not exist. An FK rejected the outbox insert too, so
    --      exactly the events a consumer most needs to see — invalid-target
    --      failures — were the ones deterministically dropped.
    --
    --   2. `ON DELETE SET NULL` silently rewrote history: purging a tenant or
    --      entity blanked the actor/tenant on every past event it appeared in,
    --      including events already delivered to the broker with those ids
    --      populated. The payload JSONB kept the original values, so the row
    --      and its own payload disagreed.
    --
    -- Keeping them unconstrained (rather than nulling ids at the call site)
    -- keeps the columns truthful about what the event carried. Nothing joins
    -- them to `tenants`/`entities`; they exist for filtering and for the
    -- publisher, and the authoritative copy travels inside `payload`.
    actor_entity_id UUID        NULL,
    tenant_id       UUID        NULL,
    payload         JSONB       NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at    TIMESTAMPTZ NULL,
    attempts        INTEGER     NOT NULL DEFAULT 0,
    last_error      TEXT        NULL,
    -- Distinguishes a structurally-invalid row (payload no longer matches
    -- DomainEventPayload, e.g. left over from an older schema_version) from a
    -- row that has simply failed to publish so far. Only the former is safe to
    -- ever stop retrying: retrying a bad deserialize can never succeed, while a
    -- publish failure may just be a broker outage that recovers, and must stay
    -- retryable no matter how long that takes.
    unparseable     BOOLEAN     NOT NULL DEFAULT false
);

CREATE INDEX idx_event_outbox_undelivered ON event_outbox(created_at) WHERE delivered_at IS NULL;

-- Optimizes outbox retention cleanup over delivered and exhausted rows.
CREATE INDEX idx_event_outbox_retention ON event_outbox(created_at) WHERE delivered_at IS NOT NULL OR (unparseable = true AND attempts >= 10);
