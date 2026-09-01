# PR-011 — Certificate Runtime Resolver v2

## Status

Implemented by the PR-011 delivery branch.

## Objective

Make runtime certificate identity unambiguous and unlock safe duplicate serials across tenant issuers.

## Dependencies

PR-007, PR-008, PR-009, and PR-010.

## Scope

- Add versioned gRPC resolver accepting leaf DER/fingerprint and optionally issuer fingerprint plus serial.
- Return entity ID, tenant ID, credential ID, issuer ID, expiry, and status. A
  global entity resolves with an empty tenant and must not acquire tenant scope.
- Publish certificate lifecycle events consumers can use to invalidate cached
  resolutions, so a relying party is not forced to choose between polling and a
  long revocation lag.
- Validate tenant/entity/credential/issuer lifecycle and optional expected tenant.
- Migrate GraphQL, renewal, revocation, CRL, OCSP, and identity paths away from serial-only lookup.
- Only after all live readers are migrated, replace global serial uniqueness with issuer-plus-serial uniqueness.
- Preserve a clearly deprecated legacy resolver during transition.

## Non-goals

Relying-party adapter wiring, which belongs to PR-012.

## Acceptance criteria

- Fingerprint resolves exactly one credential.
- Issuer plus serial resolves exactly one credential.
- Same serial under two issuers is supported and tested.
- Expected tenant mismatch is denied.
- Unknown, revoked, pending, expired, disabled-issuer, inactive-entity, and frozen/deleted-tenant credentials are denied.
- No live mutation or runtime reader uses ambiguous serial-only selection.
- Database uniqueness changes only after reader migration tests pass.

## Mandatory tests

Duplicate serials, fingerprint mismatch, issuer mismatch, DER-derived fingerprint, expected tenant, all lifecycle failures, legacy compatibility, migration with existing data, and concurrency/load checks.

## AI execution prompt

Treat this as a cutover PR. Inventory every serial-only reader before changing uniqueness. Add tests proving no ambiguous path remains. Do not wire any consuming platform yet.
