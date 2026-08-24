-- Tenant and authority purge must succeed even after the authority has issued
-- revocations. Migration 016 pointed certificate_revocations.issuer_id at
-- pki_authorities with ON DELETE RESTRICT, so a purge that reaches the
-- authority row is blocked and rolled back for any tenant that has ever
-- revoked a managed certificate. Migration 022 gave the ledger its own
-- durable lifetime (own expires_at, no more credential-delete cascade) so
-- revocation evidence outlives the identity rows that produced it.
--
-- Switch the FK to ON DELETE SET NULL so authority purge succeeds. Once
-- issuer_id is cleared, the row stops feeding CRL/OCSP publication (which
-- keys off issuer_id) but the fingerprint, serial, and credential_id remain
-- as immutable audit evidence. The immutability trigger is extended to allow
-- exactly one column mutation — the FK cascade clearing issuer_id — while
-- continuing to reject every other UPDATE and every DELETE.

ALTER TABLE certificate_revocations
    DROP CONSTRAINT certificate_revocations_issuer_id_fkey;

ALTER TABLE certificate_revocations
    ADD CONSTRAINT certificate_revocations_issuer_id_fkey
        FOREIGN KEY (issuer_id)
        REFERENCES pki_authorities(id)
        ON DELETE SET NULL;

CREATE OR REPLACE FUNCTION prevent_certificate_revocation_mutation()
RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF OLD.issuer_id IS NOT NULL
           AND NEW.issuer_id IS NULL
           AND NEW.credential_id             IS NOT DISTINCT FROM OLD.credential_id
           AND NEW.issuer_fingerprint_sha256 IS NOT DISTINCT FROM OLD.issuer_fingerprint_sha256
           AND NEW.serial_number             IS NOT DISTINCT FROM OLD.serial_number
           AND NEW.reason                    IS NOT DISTINCT FROM OLD.reason
           AND NEW.actor_entity_id           IS NOT DISTINCT FROM OLD.actor_entity_id
           AND NEW.revoked_at                IS NOT DISTINCT FROM OLD.revoked_at
           AND NEW.expires_at                IS NOT DISTINCT FROM OLD.expires_at
           AND NEW.created_at                IS NOT DISTINCT FROM OLD.created_at
        THEN
            RETURN NEW;
        END IF;
    END IF;

    RAISE EXCEPTION 'certificate revocation records are immutable'
        USING ERRCODE = '23514';
END;
$$ LANGUAGE plpgsql;
