-- Generic domain-event publishing (see plan.md at the repo root). Purely
-- additive: one new table, no ALTER on any existing table. Safe to apply on
-- any deployment; the feature stays a no-op until an operator sets
-- ATOM_EVENTS_AMQP_URL.

CREATE TABLE event_outbox (
    id              UUID        PRIMARY KEY,
    event           TEXT        NOT NULL,
    actor_entity_id UUID        NULL REFERENCES entities(id) ON DELETE SET NULL,
    tenant_id       UUID        NULL REFERENCES tenants(id) ON DELETE SET NULL,
    payload         JSONB       NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at    TIMESTAMPTZ NULL,
    attempts        INTEGER     NOT NULL DEFAULT 0,
    last_error      TEXT        NULL
);

CREATE INDEX idx_event_outbox_undelivered ON event_outbox(created_at) WHERE delivered_at IS NULL;
