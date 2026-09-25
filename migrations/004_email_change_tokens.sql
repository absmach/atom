-- Issue #110, workstream A: dedicated verified email-change flow.
--
-- A single-use, hashed, expiring token bound to the entity, the email it saw
-- as current at request time (the confirmation transaction fails safely if
-- that has since drifted), the proposed new email, and the requesting
-- session. Mirrors `email_verification_tokens`/`password_reset_tokens`
-- (migration 001) rather than reusing either: this token authorizes a
-- *different* mutation (changing the login identifier of an already-verified
-- account) and needs its own current-email binding those tables don't carry.
CREATE TABLE email_change_tokens (
    id            UUID        PRIMARY KEY,
    entity_id     UUID        NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    -- The requesting session, kept for audit/observability. Confirmation
    -- deliberately does not require this session to still be alive — see
    -- `identity::service::confirm_email_change`.
    session_id    UUID        REFERENCES sessions(id) ON DELETE SET NULL,
    current_email TEXT        NOT NULL,
    new_email     TEXT        NOT NULL,
    secret_hash   TEXT        NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    consumed_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Looked up on every new request (to supersede prior pending ones) and on
-- every confirm attempt's cleanup sweep.
CREATE INDEX idx_email_change_tokens_entity_pending
    ON email_change_tokens(entity_id) WHERE consumed_at IS NULL;
