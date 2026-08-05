# PR-001 — Authority Registry Foundation

## Status

Implemented by PR #44.

## Objective

Add the persistent, typed foundation for versioned root, platform-intermediate, and tenant-intermediate authorities without changing the v1 signing runtime.

## Scope

- `pki_authorities` hierarchy, lifecycle, validity, and key-backend metadata.
- `credentials.issuer_id` linkage.
- global fingerprint uniqueness.
- tenant-to-issuer database enforcement.
- CRL-state issuer linkage.
- read-side Rust types and selectors.
- architecture and implementation documentation.

## Compatibility boundary

- v1 credentials keep `issuer_id = NULL`.
- global serial uniqueness remains while live readers use serial alone.
- current file issuer and public routes remain unchanged.

## Acceptance criteria

- Root is global and parentless.
- Platform intermediate is global and parented.
- Tenant intermediate is tenant-scoped and parented.
- Only an active tenant intermediate with a signing backend may enable leaf issuance.
- One tenant has at most one issuer enabled for new leaves.
- Non-legacy certificate issuer must match entity tenant.
- Root/platform authorities cannot be attached to leaf credentials.
- Hard tenant purge is not permanently blocked by authority rows.
- Existing v1 tests pass unchanged.
- CI format, clippy, compilation, migrations, and PostgreSQL tests pass.

## Mandatory tests

Authority shape, active issuer selection, rotation handover, fingerprint collision, serial compatibility, cross-tenant issuer rejection, root/platform leaf rejection, and tenant purge.

## Out of scope

Key generation, key encryption, CA APIs, tenant issuance, resolver changes, CRL/OCSP route changes.

## Next

Unlocks PR-002 and PR-004.