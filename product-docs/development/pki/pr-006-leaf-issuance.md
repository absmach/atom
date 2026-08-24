# PR-006 — Generated-Key Tenant Leaf Issuance

## Status

Implemented by the PR-006 delivery branch.

## Objective

Add one-time generated-key bootstrap using the same tenant-aware issuance pipeline.

## Dependencies

PR-005.

## Scope

- Generate leaf key using an algorithm permitted by the profile and secure
  randomness. The algorithm is a profile field, not a hardcoded choice: subjects
  with constrained or legacy TLS stacks do not all accept the same one.
- Build canonical client profile.
- Sign with active tenant issuer.
- Persist certificate only; return private key once.
- Zeroize key material after response construction where possible.
- Ensure key never enters database, audit, event, tracing, or error output.
- Reuse authorization, issuer selection, verification, and transaction behavior from CSR signing.
- Ship behind a flag that stays off in production deployments until PR-010
  completes. Until per-issuer CRL and OCSP exist, revoking a certificate issued by
  a tenant CA writes it into a CRL signed by a different CA, and the OCSP
  responder answers for serials its queried authority never issued. See the
  roadmap's sequencing hazard section.

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
