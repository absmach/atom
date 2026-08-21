-- Revocation publication evidence must outlive the credential and identity
-- rows that produced it. A still-valid revoked certificate remains revoked
-- after an explicit entity/tenant purge, and its issuer keeps publishing that
-- state until the certificate expires.

DROP TRIGGER trg_certificate_revocations_immutable ON certificate_revocations;

ALTER TABLE certificate_revocations
    ADD COLUMN expires_at TIMESTAMPTZ;

UPDATE certificate_revocations r
   SET expires_at = COALESCE(c.expires_at, 'infinity'::timestamptz)
  FROM credentials c
 WHERE c.id = r.credential_id;

UPDATE certificate_revocations
   SET expires_at = 'infinity'::timestamptz
 WHERE expires_at IS NULL;

ALTER TABLE certificate_revocations
    ALTER COLUMN expires_at SET NOT NULL,
    DROP CONSTRAINT certificate_revocations_credential_id_fkey;

CREATE UNIQUE INDEX idx_certificate_revocations_issuer_serial
    ON certificate_revocations(issuer_id, serial_number)
    WHERE issuer_id IS NOT NULL;

-- PR-009's issuer-keyed state function is retained here with one additional
-- immutable value: the credential expiry copied at the revocation boundary.
CREATE OR REPLACE FUNCTION record_certificate_revocation()
RETURNS trigger AS $$
DECLARE
    event_time         TIMESTAMPTZ;
    event_reason       TEXT;
    event_actor        UUID;
    issuer_fingerprint TEXT;
BEGIN
    IF NEW.kind <> 'certificate' OR NEW.status <> 'revoked' THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.status = 'revoked' THEN
        RETURN NEW;
    END IF;

    -- Migration 011 explicitly marks pre-registry leaves. They retain local
    -- status revocation but cannot produce artifacts for an unknown issuer.
    IF NEW.issuer_id IS NULL
       AND NEW.metadata->>'issuer_migration' = 'legacy_unmanaged' THEN
        RETURN NEW;
    END IF;

    SELECT a.fingerprint_sha256
      INTO issuer_fingerprint
      FROM pki_authorities a
     WHERE a.id = NEW.issuer_id;
    IF issuer_fingerprint IS NULL THEN
        RAISE EXCEPTION 'revoked certificate % missing pki_authorities row for issuer_id %',
            NEW.id, NEW.issuer_id USING ERRCODE = '23514';
    END IF;

    event_time := COALESCE((NEW.metadata->>'revoked_at')::timestamptz, now());
    event_reason := left(
        COALESCE(NULLIF(btrim(NEW.metadata->>'revocation_reason'), ''), 'unspecified'),
        128
    );
    event_actor := NULLIF(NEW.metadata->>'revoked_by_entity_id', '')::uuid;

    INSERT INTO certificate_revocations (
        credential_id, issuer_id, issuer_fingerprint_sha256, serial_number,
        reason, actor_entity_id, revoked_at, expires_at
    ) VALUES (
        NEW.id, NEW.issuer_id, issuer_fingerprint, NEW.identifier,
        event_reason, event_actor, event_time,
        COALESCE(NEW.expires_at, 'infinity'::timestamptz)
    )
    ON CONFLICT (credential_id) DO NOTHING;

    INSERT INTO certificate_crl_state (
        issuer_id, issuer_fingerprint_sha256, crl_number, dirty
    ) VALUES (
        NEW.issuer_id, issuer_fingerprint, 0, TRUE
    )
    ON CONFLICT (issuer_id) DO UPDATE
        SET dirty = TRUE, updated_at = now();

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- The ledger no longer relies on a credential-delete cascade. Reject direct
-- updates and deletes so revocation cannot disappear before expiry.
CREATE TRIGGER trg_certificate_revocations_immutable
    BEFORE UPDATE OR DELETE ON certificate_revocations
    FOR EACH ROW EXECUTE FUNCTION prevent_certificate_revocation_mutation();
