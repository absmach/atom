-- Unambiguous certificate runtime identity and issuer-scoped serials.
--
-- Application readers resolve managed credentials by fingerprint or by
-- issuer identity plus serial. Build the replacement unique index before
-- removing the old global one so the migration never exposes an
-- unconstrained serial window.

ALTER TABLE credentials
    DROP CONSTRAINT credentials_status_check;

ALTER TABLE credentials
    ADD CONSTRAINT credentials_status_check
    CHECK (
        status IN ('active', 'revoked')
        OR (kind = 'certificate' AND status = 'revocation_pending')
    );

CREATE UNIQUE INDEX idx_credentials_certificate_issuer_serial
    ON credentials(issuer_id, identifier)
    WHERE kind = 'certificate'
      AND identifier IS NOT NULL;

DROP INDEX idx_credentials_certificate_serial;
DROP INDEX idx_credentials_certificate_issuer_serial_lookup;
