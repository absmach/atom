# PR-007 — Issuer-Aware Certificate Renewal

## Objective

Renew existing certificates into the tenant's current active issuer while preserving history and safe rotation.

## Dependencies

PR-006.

## Scope

- Renew by exact credential identity, not ambiguous serial-only selection.
- Support CSR-based renewal and explicitly controlled generated-key renewal.
- Link new credential to previous credential in metadata or a dedicated relation.
- Issue under current active tenant issuer, including v1-to-v2 migration.
- Policy for old credential: overlap window, optional immediate revocation, and audit.
- Bound validity by current issuer and tenant policy.

## Non-goals

Bulk fleet automation and ACME.

## Acceptance criteria

- Renewal cannot cross tenant or entity.
- Old issuer may be retiring; new leaf uses active issuer.
- Expired/revoked credentials follow explicit policy and cannot bypass authorization.
- New certificate has a new serial/fingerprint and correct issuer ID.
- Both old and new credentials remain unambiguously resolvable during overlap.
- Legacy global certificate can renew into tenant issuer.

## Mandatory tests

Same-issuer renewal, rotation renewal, legacy migration, revoked/expired input, overlap, immediate revoke option, idempotent retries, and audit/outbox linkage.

## AI execution prompt

Implement exact-credential renewal and rotation migration. Do not use `certificate_by_serial` when identity can be ambiguous. Preserve old credential history and make overlap/revocation policy explicit.