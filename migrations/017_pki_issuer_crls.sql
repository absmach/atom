-- Issuer-keyed CRL publication state.
--
-- Every certificate_crl_state row corresponds to a managed pki_authorities
-- row via issuer_id. Any row whose fingerprint does not match a live
-- authority is orphaned by design and must be dropped before the tightening.

UPDATE certificate_crl_state s
   SET issuer_id = a.id
  FROM pki_authorities a
 WHERE s.issuer_id IS NULL
   AND a.fingerprint_sha256 = s.issuer_fingerprint_sha256;

DELETE FROM certificate_crl_state
 WHERE issuer_id IS NULL;

ALTER TABLE certificate_crl_state
    ADD COLUMN crl_sha256 TEXT;

UPDATE certificate_crl_state
   SET crl_sha256 = CASE
           WHEN crl_der IS NULL THEN NULL
           ELSE encode(digest(crl_der, 'sha256'), 'hex')
       END;

ALTER TABLE certificate_crl_state
    ALTER COLUMN issuer_id SET NOT NULL,
    DROP CONSTRAINT certificate_crl_state_pkey,
    ADD CONSTRAINT certificate_crl_state_pkey PRIMARY KEY (issuer_id),
    ADD CONSTRAINT chk_certificate_crl_state_hash CHECK (
        (crl_der IS NULL AND crl_sha256 IS NULL)
        OR (
            crl_der IS NOT NULL
            AND crl_sha256 ~ '^[0-9a-f]{64}$'
            AND crl_sha256 = encode(digest(crl_der, 'sha256'), 'hex')
        )
    );

DROP INDEX idx_certificate_crl_state_issuer;

CREATE UNIQUE INDEX idx_certificate_crl_state_fingerprint
    ON certificate_crl_state(issuer_fingerprint_sha256);

-- PR-008 owns authoritative revocation. Replacing its trigger here changes
-- only the artifact-state representation: publication is keyed by
-- pki_authorities.id, and the fingerprint stays as historical evidence.
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
        reason, actor_entity_id, revoked_at
    ) VALUES (
        NEW.id, NEW.issuer_id, issuer_fingerprint, NEW.identifier,
        event_reason, event_actor, event_time
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
