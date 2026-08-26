-- Email identity is global and case-insensitive. All login and invitation
-- lookups already compare normalized/lower-case email addresses, so the backing
-- uniqueness invariant must use the same key.

DROP INDEX IF EXISTS idx_entity_emails_email;

CREATE UNIQUE INDEX idx_entity_emails_email
    ON entity_emails (lower(email))
    WHERE deleted_at IS NULL;
