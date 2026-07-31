-- The outbox is an append-only record of what happened, so its actor/tenant
-- columns must not be constrained by what exists *now*.
--
-- Two ways the foreign keys actively lost events:
--
--   1. Failure events. `audit::observe_error` publishes the attempt that
--      failed, and a common reason for failing is that the tenant in the
--      request does not exist. The FK then rejected the outbox insert too, so
--      exactly the events a consumer most needs to see — invalid-tenant
--      failures — were the ones deterministically dropped.
--
--   2. `ON DELETE SET NULL` silently rewrote history: purging a tenant or
--      entity blanked the actor/tenant on every past event it appeared in,
--      including events already delivered to the broker with those ids
--      populated. The payload JSONB kept the original values, so the row and
--      its own payload disagreed.
--
-- Dropping the constraints (rather than nulling ids at the call site) keeps the
-- columns truthful about what the event carried. Nothing joins these columns to
-- `tenants`/`entities`; they exist for filtering and for the publisher, and the
-- authoritative copy travels inside `payload`.

ALTER TABLE event_outbox
    DROP CONSTRAINT IF EXISTS event_outbox_tenant_id_fkey,
    DROP CONSTRAINT IF EXISTS event_outbox_actor_entity_id_fkey;
