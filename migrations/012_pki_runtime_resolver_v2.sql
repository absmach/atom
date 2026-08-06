-- Unambiguous certificate runtime identity and issuer-scoped serials.
--
-- Application readers in PR-011 resolve managed credentials by fingerprint or
-- issuer identity plus serial. The only serial-only compatibility reader is
-- explicitly restricted to issuer_id IS NULL, the legacy file-issuer namespace.
-- Build both replacement unique indexes before removing the old global one so
-- the migration never exposes an unconstrained serial window.

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
      AND issuer_id IS NOT NULL
      AND identifier IS NOT NULL;

CREATE UNIQUE INDEX idx_credentials_certificate_legacy_serial
    ON credentials(identifier)
    WHERE kind = 'certificate'
      AND issuer_id IS NULL
      AND identifier IS NOT NULL;

DROP INDEX idx_credentials_certificate_serial;
DROP INDEX idx_credentials_certificate_issuer_serial_lookup;
