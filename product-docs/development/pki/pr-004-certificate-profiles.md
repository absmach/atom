# PR-004 — Canonical Certificate Profiles and PKI Core

## Objective

Extract certificate construction and validation into an Atom-owned PKI core with strict client and server profiles.

## Dependencies

PR-001. May proceed in parallel with PR-002.

## Scope

- Define canonical machine-client and optional machine-server profiles.
- Client default: `CA=false`, digital signature, `clientAuth`, canonical URI SAN.
- Server profile: explicit `serverAuth`; do not combine both by default.
- Canonical identity: `urn:atom:tenant:<tenant-id>:entity:<entity-id>`.
- CSR parser verifies signature and treats requested extensions as untrusted input.
- Centralize serial generation, validity bounding, fingerprints, issuer validation, and chain verification.
- Hide rcgen/x509-parser details behind internal types.

## Non-goals

No tenant issuance routing or public API changes.

## Acceptance criteria

- CSR cannot request CA=true, keyCertSign, cRLSign, another tenant/entity URI, arbitrary EKUs, or excessive validity.
- Intermediate SANs are never copied to leaves.
- Client certificate has clientAuth but not serverAuth.
- Server certificate is issued only through an explicit server profile and authorization path.
- Issuer constraints and validity are checked before signing.
- Generated identity is deterministic from stored tenant/entity IDs.

## Mandatory tests

Malformed CSR, invalid CSR signature, CA request, identity substitution, unsupported key algorithm/size, SAN policy, EKU separation, validity boundary, and independent OpenSSL inspection.

## AI execution prompt

Implement strict profiles and reusable PKI core only. Treat CSR as a public key container, not a policy document. Preserve current external behavior until PR-006 switches issuance.