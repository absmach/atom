-- Email identity is global and case-insensitive. All login and invitation
-- lookups already compare normalized/lower-case email addresses, so the backing
-- uniqueness invariant must use the same key.

-- Older admin-created human entities predate the canonical email table. Bring
-- valid email attributes into that table before enforcing the new invariant.
INSERT INTO entity_emails (entity_id, email, deleted_at)
SELECT e.id,
       lower(trim(e.attributes->>'email')),
       e.deleted_at
FROM entities e
LEFT JOIN entity_emails ee ON ee.entity_id = e.id
WHERE e.kind = 'human'
  AND ee.id IS NULL
  AND e.attributes->>'email' IS NOT NULL
  AND trim(e.attributes->>'email') ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$';

DROP INDEX IF EXISTS idx_entity_emails_email;

CREATE UNIQUE INDEX idx_entity_emails_email
    ON entity_emails (lower(email))
    WHERE deleted_at IS NULL;
