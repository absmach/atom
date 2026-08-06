# PR-009 — Per-Issuer CRL Generation and Routes

## Status

Implemented by the PR-009 delivery branch.

## Objective

Publish standards-compliant CRLs for every issuer while retaining legacy artifacts during migration and rotation.

## Dependencies

PR-008.

## Scope

- CRL cache/state keyed by issuer ID.
- Issuer-specific route: `/certs/issuers/{issuer_id}/crl`.
- Include only certificates issued by that authority.
- Increment CRL number monotonically, **continuing from the value already
  published by the fingerprint-keyed state row for the same physical CA**.
  Restarting at 1 makes CRL numbers move backwards, which conforming verifiers
  treat as a rollback attack.
- Set thisUpdate/nextUpdate and revocation reasons taken from the stored
  revocation record rather than a fixed `unspecified`.
- Serve validator-friendly caching so a polling fleet does not take the
  regeneration lock on every fetch.
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
- CRL numbers never decrease across the state-representation cutover.
- Recorded revocation reasons appear in CRL entries.
- Legacy global route remains until documented cutover.
- CRL is documented to operators as a compliance and interoperability artifact,
  not as the platform's primary revocation control — that role belongs to short
  lifetimes plus resolver denial.

## Mandatory tests

Empty CRL, revoked entries, reason codes, number increment, concurrent requests, rotation old/new CRLs, expired issuer policy, cache corruption, OpenSSL verification, and cross-issuer exclusion.

## AI execution prompt

Implement issuer-specific CRLs only. Reuse key provider and exact issuer relationships. Do not dirty or scan unrelated tenants, and do not remove legacy routes prematurely.
