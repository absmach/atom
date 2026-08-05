# PR-009 — Per-Issuer CRL Generation and Routes

## Objective

Publish standards-compliant CRLs for every issuer while retaining legacy artifacts during migration and rotation.

## Dependencies

PR-008.

## Scope

- CRL cache/state keyed by issuer ID.
- Issuer-specific route: `/certs/issuers/{issuer_id}/crl`.
- Include only certificates issued by that authority.
- Increment CRL number monotonically.
- Set thisUpdate/nextUpdate and revocation reasons.
- Sign through the authority key provider.
- Use issuer-scoped locking to avoid duplicate concurrent generation.
- Preserve old issuer CRLs until retention permits removal.

## Non-goals

Delta CRLs unless separately approved; OCSP.

## Acceptance criteria

- Revoking Tenant A certificate never changes Tenant B CRL.
- CRL signature verifies under exact issuer.
- Root/platform authorities do not expose leaf CRLs unless their role requires it.
- Retiring/retired issuer can publish CRL but cannot issue new leaves.
- Cache invalidation and regeneration survive restart.
- Legacy global route remains until documented cutover.

## Mandatory tests

Empty CRL, revoked entries, reason codes, number increment, concurrent requests, rotation old/new CRLs, expired issuer policy, cache corruption, OpenSSL verification, and cross-issuer exclusion.

## AI execution prompt

Implement issuer-specific CRLs only. Reuse key provider and exact issuer relationships. Do not dirty or scan unrelated tenants, and do not remove legacy routes prematurely.