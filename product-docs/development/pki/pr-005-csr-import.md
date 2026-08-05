# PR-005 — Tenant-Aware CSR Signing

## Objective

Add the first production tenant-aware leaf path using device-generated CSRs.

## Dependencies

PR-002, PR-003, and PR-004.

## Scope

- Resolve target entity and derive tenant.
- Authorize certificate management for the entity.
- Select the tenant's active issuer internally.
- Validate and canonicalize CSR using the client profile.
- Sign through the key provider.
- Verify returned certificate and chain.
- Persist credential, issuer ID, metadata, audit, and event atomically according to Atom conventions.
- Add idempotency/retry behavior for serial collisions and request retries.

## Non-goals

Generated private keys, renewal, revocation, CRL, OCSP, or resolver-v2.

## Acceptance criteria

- Caller cannot supply tenant, issuer, CA path, key reference, or privileged extensions.
- Tenant A cannot sign for Tenant B entity.
- No active issuer returns a clear fail-closed error.
- Certificate issuer and entity tenant match at service and database layers.
- Private key never enters Atom.
- Signing success followed by DB failure does not create a runtime-usable credential; reconciliation strategy is documented.
- Legacy CSR endpoint remains compatible or is explicitly versioned.

## Mandatory tests

Cross-tenant authorization, issuer unavailable, issuer expired/retiring, CSR attacks, serial collision retry, transaction rollback, duplicate request, audit/outbox, and independent chain verification.

## AI execution prompt

Implement CSR signing only. Derive tenant and issuer from stored entity state. Do not add generated-key issuance. Follow nested transaction/savepoint rules for serial retries and do not open a second pool connection.