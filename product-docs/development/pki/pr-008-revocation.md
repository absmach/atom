# PR-008 — Issuer-Aware Revocation State Machine

## Objective

Make certificate revocation immediately authoritative in Atom and ready for per-issuer CRL/OCSP publication.

## Dependencies

PR-006.

## Scope

- Revoke exact credential by ID/fingerprint or issuer plus serial.
- Add revocation reason, actor, time, and issuer metadata.
- Support entity-wide and tenant lifecycle revocation operations.
- Define active, revocation_pending if needed, revoked, and reconciliation behavior.
- Dirty only the affected issuer's artifact state.
- Ensure resolver paths deny pending/revoked immediately.

## Non-goals

CRL encoding and OCSP response generation.

## Acceptance criteria

- Serial alone is not used when multiple issuers may share it.
- Tenant A cannot revoke Tenant B credential.
- Revocation is idempotent.
- Revoked credentials cannot be renewed except through an explicit replacement policy.
- Entity/tenant suspension behavior is fail closed.
- Only affected issuer artifact state changes.
- Audit and outbox include no secrets and identify issuer/credential/reason.

## Mandatory tests

Exact lookup, duplicate serial issuers, cross-tenant denial, repeated revoke, entity-wide revoke, tenant delete/freeze, transaction failure, and resolver denial.

## AI execution prompt

Implement authoritative Atom revocation and issuer-scoped invalidation. Do not generate CRLs or OCSP yet. Eliminate ambiguous serial-only mutation paths covered by this scope.