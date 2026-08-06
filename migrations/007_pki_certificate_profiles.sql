-- Stored certificate profiles and issuer artifact-discovery configuration.
--
-- Certificate shape is data.  The two global rows are conservative platform
-- ceilings; a tenant row references one of them and may only narrow it.

ALTER TABLE pki_authorities
    ADD COLUMN ocsp_url TEXT,
    ADD COLUMN ca_issuers_url TEXT,
    ADD COLUMN crl_distribution_point_url TEXT,
    ADD CONSTRAINT chk_pki_authorities_artifact_urls
    CHECK (
        (ocsp_url IS NULL
            AND ca_issuers_url IS NULL
            AND crl_distribution_point_url IS NULL)
        OR
        (ocsp_url ~ '^https?://[^[:space:]]+$'
            AND ca_issuers_url ~ '^https?://[^[:space:]]+$'
            AND crl_distribution_point_url ~ '^https?://[^[:space:]]+$')
    );

CREATE OR REPLACE FUNCTION pki_valid_san_policy(policy JSONB) RETURNS BOOLEAN AS $$
DECLARE
    san_type TEXT;
    rule JSONB;
    mode TEXT;
BEGIN
    IF jsonb_typeof(policy) <> 'object'
       OR NOT policy ?& ARRAY['dns', 'ip', 'email', 'uri']
       OR policy - ARRAY['dns', 'ip', 'email', 'uri'] <> '{}'::jsonb THEN
        RETURN false;
    END IF;

    FOREACH san_type IN ARRAY ARRAY['dns', 'ip', 'email', 'uri'] LOOP
        rule := policy -> san_type;
        mode := rule ->> 'mode';
        IF jsonb_typeof(rule) <> 'object'
           OR NOT rule ?& ARRAY['mode', 'values']
           OR rule - ARRAY['mode', 'values'] <> '{}'::jsonb
           OR jsonb_typeof(rule -> 'values') <> 'array' THEN
            RETURN false;
        END IF;

        IF san_type = 'dns' AND mode NOT IN ('deny', 'allowlist', 'entity_template') THEN
            RETURN false;
        ELSIF san_type IN ('ip', 'email') AND mode NOT IN ('deny', 'allowlist') THEN
            RETURN false;
        ELSIF san_type = 'uri' AND (mode <> 'identity' OR rule -> 'values' <> '[]'::jsonb) THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION pki_san_rule_is_subset(child JSONB, ceiling JSONB)
RETURNS BOOLEAN AS $$
DECLARE
    child_mode TEXT := child ->> 'mode';
    ceiling_mode TEXT := ceiling ->> 'mode';
BEGIN
    IF ceiling_mode = 'deny' THEN
        RETURN child_mode = 'deny';
    ELSIF ceiling_mode = 'identity' THEN
        RETURN child_mode = 'identity';
    ELSIF ceiling_mode IN ('allowlist', 'entity_template') THEN
        RETURN child_mode = 'deny'
            OR (child_mode = ceiling_mode
                AND (ceiling -> 'values') @> (child -> 'values'));
    END IF;
    RETURN false;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE TABLE certificate_profiles (
    id                         UUID        PRIMARY KEY,
    tenant_id                  UUID        REFERENCES tenants(id) ON DELETE CASCADE,
    base_profile_id            UUID        REFERENCES certificate_profiles(id) ON DELETE RESTRICT,
    name                       TEXT        NOT NULL
                                           CHECK (name ~ '^[a-z][a-z0-9_-]{0,62}$'),
    permitted_key_algorithms   JSONB       NOT NULL
                                           CHECK (jsonb_typeof(permitted_key_algorithms) = 'array'
                                               AND jsonb_array_length(permitted_key_algorithms) > 0),
    default_ttl_seconds        BIGINT      NOT NULL CHECK (default_ttl_seconds > 0),
    maximum_ttl_seconds        BIGINT      NOT NULL CHECK (maximum_ttl_seconds > 0),
    renewal_threshold_seconds  BIGINT      NOT NULL CHECK (renewal_threshold_seconds > 0),
    key_usages                 TEXT[]      NOT NULL,
    extended_key_usages        TEXT[]      NOT NULL,
    san_policy                 JSONB       NOT NULL CHECK (pki_valid_san_policy(san_policy)),
    identity_uri_template      TEXT        NOT NULL
                                           CHECK (identity_uri_template =
                                               'urn:atom:{scope}entity:{entity_id}'),
    basic_constraints          JSONB       NOT NULL
                                           CHECK (basic_constraints =
                                               '{"ca": false, "path_len": null}'::jsonb),
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_certificate_profiles_nonzero_id
        CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CONSTRAINT chk_certificate_profiles_scope
        CHECK ((tenant_id IS NULL AND base_profile_id IS NULL)
            OR (tenant_id IS NOT NULL AND base_profile_id IS NOT NULL)),
    CONSTRAINT chk_certificate_profiles_ttl
        CHECK (default_ttl_seconds <= maximum_ttl_seconds
            AND renewal_threshold_seconds <= maximum_ttl_seconds),
    CONSTRAINT chk_certificate_profiles_leaf_key_usages
        CHECK (key_usages <@ ARRAY[
            'digital_signature', 'content_commitment', 'key_encipherment',
            'data_encipherment', 'key_agreement'
        ]::TEXT[]),
    CONSTRAINT chk_certificate_profiles_extended_key_usages
        CHECK (extended_key_usages <@ ARRAY[
            'server_auth', 'client_auth', 'code_signing', 'email_protection',
            'time_stamping', 'ocsp_signing'
        ]::TEXT[])
);

CREATE UNIQUE INDEX idx_certificate_profiles_platform_name
    ON certificate_profiles(name) WHERE tenant_id IS NULL;
CREATE UNIQUE INDEX idx_certificate_profiles_tenant_name
    ON certificate_profiles(tenant_id, name) WHERE tenant_id IS NOT NULL;
CREATE INDEX idx_certificate_profiles_base ON certificate_profiles(base_profile_id);

CREATE OR REPLACE FUNCTION enforce_certificate_profile_ceiling() RETURNS trigger AS $$
DECLARE
    ceiling certificate_profiles%ROWTYPE;
    san_type TEXT;
BEGIN
    IF NEW.tenant_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT * INTO ceiling
      FROM certificate_profiles
     WHERE id = NEW.base_profile_id AND tenant_id IS NULL
     FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'tenant certificate profile requires a platform ceiling'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.name <> ceiling.name THEN
        RAISE EXCEPTION 'tenant certificate profile name must match its platform ceiling'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.default_ttl_seconds > ceiling.default_ttl_seconds
       OR NEW.maximum_ttl_seconds > ceiling.maximum_ttl_seconds
       OR NEW.renewal_threshold_seconds > ceiling.renewal_threshold_seconds THEN
        RAISE EXCEPTION 'tenant certificate profile cannot extend platform time limits'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.permitted_key_algorithms <> ceiling.permitted_key_algorithms
       OR NOT NEW.key_usages <@ ceiling.key_usages
       OR NOT NEW.extended_key_usages <@ ceiling.extended_key_usages
       OR NEW.identity_uri_template <> ceiling.identity_uri_template
       OR NEW.basic_constraints <> ceiling.basic_constraints THEN
        RAISE EXCEPTION 'tenant certificate profile exceeds platform certificate shape'
            USING ERRCODE = '23514';
    END IF;

    FOREACH san_type IN ARRAY ARRAY['dns', 'ip', 'email', 'uri'] LOOP
        IF NOT pki_san_rule_is_subset(
            NEW.san_policy -> san_type,
            ceiling.san_policy -> san_type
        ) THEN
            RAISE EXCEPTION 'tenant certificate profile widens platform SAN policy'
                USING ERRCODE = '23514';
        END IF;
    END LOOP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_certificate_profiles_ceiling
    BEFORE INSERT OR UPDATE OF tenant_id, base_profile_id, name,
        permitted_key_algorithms, default_ttl_seconds, maximum_ttl_seconds,
        renewal_threshold_seconds, key_usages, extended_key_usages, san_policy,
        identity_uri_template, basic_constraints
    ON certificate_profiles
    FOR EACH ROW EXECUTE FUNCTION enforce_certificate_profile_ceiling();

INSERT INTO certificate_profiles (
    id, name, permitted_key_algorithms, default_ttl_seconds,
    maximum_ttl_seconds, renewal_threshold_seconds, key_usages,
    extended_key_usages, san_policy, identity_uri_template, basic_constraints
) VALUES
    (
        '00000000-0000-0000-0000-000000000401',
        'client',
        '[{"algorithm":"ecdsa","sizes":[256]}]'::jsonb,
        86400, 604800, 86400,
        ARRAY['digital_signature']::TEXT[],
        ARRAY['client_auth']::TEXT[],
        '{
            "dns":{"mode":"deny","values":[]},
            "ip":{"mode":"deny","values":[]},
            "email":{"mode":"deny","values":[]},
            "uri":{"mode":"identity","values":[]}
        }'::jsonb,
        'urn:atom:{scope}entity:{entity_id}',
        '{"ca":false,"path_len":null}'::jsonb
    ),
    (
        '00000000-0000-0000-0000-000000000402',
        'server',
        '[{"algorithm":"ecdsa","sizes":[256]}]'::jsonb,
        86400, 604800, 86400,
        ARRAY['digital_signature','key_encipherment']::TEXT[],
        ARRAY['server_auth']::TEXT[],
        '{
            "dns":{"mode":"deny","values":[]},
            "ip":{"mode":"deny","values":[]},
            "email":{"mode":"deny","values":[]},
            "uri":{"mode":"identity","values":[]}
        }'::jsonb,
        'urn:atom:{scope}entity:{entity_id}',
        '{"ca":false,"path_len":null}'::jsonb
    )
ON CONFLICT (id) DO NOTHING;
