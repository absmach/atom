# PR-006 — Generated-Key Tenant Leaf Issuance

## Objective

Add one-time generated-key bootstrap using the same tenant-aware issuance pipeline.

## Dependencies

PR-005.

## Scope

- Generate leaf key using approved algorithm and secure randomness.
- Build canonical client profile.
- Sign with active tenant issuer.
- Persist certificate only; return private key once.
- Zeroize key material after response construction where possible.
- Ensure key never enters database, audit, event, tracing, or error output.
- Reuse authorization, issuer selection, verification, and transaction behavior from CSR signing.

## Non-goals

Recoverable leaf keys, escrow, downloadable historical keys, or server certificates.

## Acceptance criteria

- Private key is returned exactly once and cannot be retrieved later.
- Stored credential contains no private-key material.
- Response failures after commit are documented as non-recoverable and operationally visible without logging key data.
- Tenant isolation and issuer matching are identical to CSR signing.
- Existing generated-key clients retain an explicit migration/compatibility path.

## Mandatory tests

Successful bootstrap, response serialization, persistence inspection, log/audit/event inspection, authorization denial, cross-tenant denial, issuer failure, DB rollback, and generated key/certificate match.

## AI execution prompt

Implement generated-key bootstrap by reusing PR-005 service boundaries. Never create a reveal endpoint or persist the private key. Prove secret absence from all stored and observable outputs.