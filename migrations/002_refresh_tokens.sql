-- Rotating refresh tokens (issue #100). A refresh token is an opaque,
-- KEK-keyed-HMAC-verified credential bound to a session, kept in its own
-- table (not `credentials`) so consumed rows can be retained until the
-- family's absolute deadline for replay detection.
--
-- A forward migration, not folded into 001_initial.sql: that file is the
-- byte-frozen v1.0.0 launch baseline (see AGENTS.md and
-- scripts/check-v1-contracts.sh) — editing it changes its checksum and
-- breaks sqlx's migrator for any database already initialized from it.

CREATE TABLE refresh_tokens (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id        UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    secret_hash       BYTEA NOT NULL,
    family_expires_at TIMESTAMPTZ NOT NULL,
    consumed_at       TIMESTAMPTZ,
    revoked_at        TIMESTAMPTZ,
    -- Deferred: rotation updates the old row's `replaced_by` before the
    -- replacement row exists (it must, to mark the old row consumed before
    -- the new one goes active — see `idx_refresh_tokens_session_active`
    -- below), so this FK can only be checked at commit, not per-statement.
    replaced_by       UUID REFERENCES refresh_tokens(id) DEFERRABLE INITIALLY DEFERRED,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (family_expires_at > created_at)
);

CREATE INDEX idx_refresh_tokens_session ON refresh_tokens(session_id);
CREATE INDEX idx_refresh_tokens_family_expiry ON refresh_tokens(family_expires_at);

-- Physical backstop for the single-active-descendant invariant: application
-- logic already enforces "at most one live token per session" transactionally
-- (consume-then-insert under a row lock), but a partial unique index turns a
-- future bug into a loud constraint violation instead of a silent fork.
CREATE UNIQUE INDEX idx_refresh_tokens_session_active ON refresh_tokens(session_id)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;
