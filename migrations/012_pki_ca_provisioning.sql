-- Controlled CA provisioning state for PR-003.
--
-- A managed CA does not have certificate material while its locally generated
-- key and CSR are waiting for an offline signature.  The foundation schema
-- intentionally modelled only completed authorities; make the material
-- state-aware without weakening the constraints on active authorities.

ALTER TABLE pki_authorities
    ALTER COLUMN serial_number DROP NOT NULL,
    ALTER COLUMN fingerprint_sha256 DROP NOT NULL,
    ALTER COLUMN certificate_pem DROP NOT NULL,
    ALTER COLUMN chain_pem DROP NOT NULL,
    ALTER COLUMN not_before DROP NOT NULL,
    ALTER COLUMN not_after DROP NOT NULL,
    ADD COLUMN provisioning_mode TEXT NOT NULL DEFAULT 'imported'
        CHECK (provisioning_mode IN ('imported', 'offline', 'automated')),
    ADD COLUMN csr_pem TEXT,
    ADD COLUMN failure_reason TEXT;

ALTER TABLE pki_authorities
    ADD CONSTRAINT chk_pki_authorities_completed_material
    CHECK (
        status IN ('provisioning', 'pending_signature', 'failed')
        OR (
            serial_number IS NOT NULL
            AND fingerprint_sha256 IS NOT NULL
            AND certificate_pem IS NOT NULL
            AND chain_pem IS NOT NULL
            AND not_before IS NOT NULL
            AND not_after IS NOT NULL
        )
    ),
    ADD CONSTRAINT chk_pki_authorities_pending_csr
    CHECK (
        status NOT IN ('provisioning', 'pending_signature')
        OR (
            kind <> 'root'
            AND key_backend <> 'public_only'
            AND NULLIF(btrim(csr_pem), '') IS NOT NULL
        )
    ),
    ADD CONSTRAINT chk_pki_authorities_failure_reason
    CHECK (
        (status = 'failed' AND NULLIF(btrim(failure_reason), '') IS NOT NULL)
        OR (status <> 'failed' AND failure_reason IS NULL)
    );

-- One unfinished request per scope makes repeated calls deterministic and
-- prevents concurrent replicas from generating abandoned CA keys for the same
-- tenant or global authority role.
CREATE UNIQUE INDEX idx_pki_authorities_one_pending_tenant
    ON pki_authorities(tenant_id)
    WHERE kind = 'tenant_intermediate'
      AND status IN ('provisioning', 'pending_signature');

CREATE UNIQUE INDEX idx_pki_authorities_one_pending_global_kind
    ON pki_authorities(kind)
    WHERE tenant_id IS NULL
      AND kind IN ('platform_intermediate', 'platform_leaf_issuer')
      AND status IN ('provisioning', 'pending_signature');

-- Only one platform intermediate is selected for automated CA signing.  Older
-- versions remain addressable in retiring/retired state for chain validation.
CREATE UNIQUE INDEX idx_pki_authorities_one_active_platform_intermediate
    ON pki_authorities((true))
    WHERE kind = 'platform_intermediate' AND status = 'active';

-- CA lifecycle administration is deliberately distinct from ordinary tenant
-- or credential management.  Automated CA signing is a second, stronger
-- capability so an operator can delegate offline-CSR handling without granting
-- use of the online platform-intermediate signer.
INSERT INTO actions (name, description) VALUES
    ('pki.provision', 'Manage PKI authority provisioning and lifecycle'),
    ('pki.provision_automated', 'Use the platform CA signer for automated authority provisioning')
ON CONFLICT (name) DO NOTHING;

INSERT INTO permission_block_actions (permission_block_id, action_id)
SELECT '00000000-0000-0000-0000-000000000007', id
FROM actions
WHERE name IN ('pki.provision', 'pki.provision_automated')
ON CONFLICT DO NOTHING;
