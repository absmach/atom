-- SQLite counterpart of migrations/002_refresh_tokens.sql (rotating refresh
-- tokens). Same table, indexes and invariants; see the PostgreSQL file for the
-- reasoning behind the deferred self-reference and the partial unique index.

CREATE TABLE refresh_tokens (
    id                BLOB PRIMARY KEY NOT NULL
                      DEFAULT (unhex(hex(randomblob(6)) || '4' || substr(hex(randomblob(2)), 2) || substr('89AB', 1 + (random() & 3), 1) || substr(hex(randomblob(2)), 2) || hex(randomblob(6)))),
    session_id        BLOB NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    secret_hash       BLOB NOT NULL,
    family_expires_at TEXT NOT NULL,
    consumed_at       TEXT,
    revoked_at        TEXT,
    replaced_by       BLOB REFERENCES refresh_tokens(id) DEFERRABLE INITIALLY DEFERRED,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000Z'),
    CHECK (family_expires_at > created_at)
);

CREATE INDEX idx_refresh_tokens_session ON refresh_tokens(session_id);
CREATE INDEX idx_refresh_tokens_family_expiry ON refresh_tokens(family_expires_at);

CREATE UNIQUE INDEX idx_refresh_tokens_session_active ON refresh_tokens(session_id)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;
