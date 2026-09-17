-- SQLite counterpart of migrations/004_email_change_tokens.sql (dedicated
-- verified email-change flow). Same table, index and invariants; see the
-- PostgreSQL file for the reasoning. Encodings match the rest of the SQLite
-- baseline: UUIDs are BLOBs, timestamps are TEXT.
CREATE TABLE email_change_tokens (
    id            BLOB PRIMARY KEY,
    entity_id     BLOB NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    -- The requesting session, kept for audit/observability. Confirmation
    -- deliberately does not require this session to still be alive — see
    -- `identity::service::confirm_email_change`.
    session_id    BLOB REFERENCES sessions(id) ON DELETE SET NULL,
    current_email TEXT NOT NULL,
    new_email     TEXT NOT NULL,
    secret_hash   TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    consumed_at   TEXT,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z')
);

-- Looked up on every new request (to supersede prior pending ones) and on
-- every confirm attempt's cleanup sweep.
CREATE INDEX idx_email_change_tokens_entity_pending
    ON email_change_tokens(entity_id) WHERE consumed_at IS NULL;
