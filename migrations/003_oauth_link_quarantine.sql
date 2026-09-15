-- Issue #110, workstream B: approval-gated remediation tooling.
--
-- Soft-disable for an `oauth_identities` link an administrator has reviewed
-- and found unjustified (a suspicious preclaim-era association — see
-- AGENTS.md) but is not yet ready to permanently delete. A quarantined link
-- is preserved for audit but can no longer authenticate or be silently
-- re-linked by a fresh OAuth callback; see
-- `identity::service::upsert_oauth_identity`.
ALTER TABLE oauth_identities
    ADD COLUMN quarantined_at TIMESTAMPTZ;

CREATE INDEX idx_oauth_identities_quarantined
    ON oauth_identities(entity_id)
    WHERE quarantined_at IS NOT NULL;
