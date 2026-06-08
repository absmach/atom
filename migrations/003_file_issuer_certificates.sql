DROP TABLE IF EXISTS certificate_authorities;

DROP TABLE IF EXISTS certificate_crl_state;

CREATE TABLE certificate_crl_state (
    issuer_fingerprint_sha256 TEXT PRIMARY KEY,
    crl_number BIGINT NOT NULL DEFAULT 0,
    crl_der BYTEA,
    this_update TIMESTAMPTZ,
    next_update TIMESTAMPTZ,
    dirty BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
