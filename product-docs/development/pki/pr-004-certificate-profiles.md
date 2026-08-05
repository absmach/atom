# PR-004 — Certificate Profiles and PKI Core

## Objective

Extract certificate construction and validation into an Atom-owned PKI core, and
make certificate shape **stored data** rather than code.

## Dependencies

PR-001. May proceed in parallel with PR-002.

## Scope

- Define a `certificate_profiles` model holding, per profile: permitted key
  algorithms and sizes, default and maximum TTL, renewal threshold, key usages,
  extended key usages, per-SAN-type policy, the canonical identity URI template,
  and basic constraints.
- Ship platform baseline profiles: a client profile and a server profile.
- Allow tenant-scoped overrides bounded by the platform ceiling: a tenant may
  shorten a TTL, never extend it; may restrict a SAN policy, never widen it.
- Canonical identity SAN: `urn:atom:tenant:<tenant-id>:entity:<entity-id>` for
  tenant-owned subjects, `urn:atom:entity:<entity-id>` for global subjects.
  Always derived from stored state, never from request input.
- Embed **Authority Information Access** (OCSP responder URL, CA issuers URL) and
  **CRL Distribution Points** from the issuing authority's configuration.
- CSR parser verifies the signature and treats requested extensions as untrusted
  input.
- Centralize serial generation, validity bounding, fingerprints, issuer
  validation, and chain verification.
- Hide rcgen/x509-parser details behind internal types.

## Non-goals

No tenant issuance routing or public API changes. No enrollment.

## Design constraints

### Profiles are data, not branches

A downstream product's certificate requirement is expressed by a profile row. If a
requirement cannot be expressed as profile data, the profile model is missing a
field — that is not licence to add a conditional. No profile name, field, or code
path may reference a downstream product.

### Extended key usage combination is a profile decision

The client profile defaults to `clientAuth` only and the server profile to
`serverAuth` only. Combining them must remain **possible** through an explicit
profile, because mutually authenticated service-to-service mTLS legitimately needs
one certificate that is both. A hardcoded prohibition would make that use case
unimplementable. The requirement is that combination is explicit, attributable to
a profile, and never the default.

### DNS SANs are never free-form input

Once services authenticate each other by name, an unvalidated DNS SAN is an
impersonation primitive. A profile restricts DNS SANs to an allowlist or to a
template bound to the entity. The current v1 behaviour of accepting caller-supplied
`dns_names` unchecked does not survive this PR.

### Artifact discovery is part of the profile, not an afterthought

Per-issuer CRL and OCSP routes are useless if leaves do not point at them. A leaf
without AIA and CDP extensions forces every relying party to be configured by
hand.

## Acceptance criteria

- CSR cannot request `CA=true`, `keyCertSign`, `cRLSign`, another tenant/entity
  URI, arbitrary EKUs, or excessive validity.
- Intermediate SANs are never copied to leaves.
- A client certificate has `clientAuth` and not `serverAuth` under the default
  client profile.
- A combined client/server certificate is issuable only through an explicit
  profile and is never produced by default.
- A DNS SAN outside the profile's policy is rejected.
- Issued leaves carry AIA and CRL distribution point extensions resolving to the
  issuing authority's routes.
- A tenant override cannot exceed the platform TTL ceiling or widen a SAN policy.
- Generated identity is deterministic from stored tenant/entity IDs, including for
  global entities.
- Issuer constraints and validity are checked before signing.
- No profile, field, or code path names a downstream product.

## Mandatory tests

Malformed CSR, invalid CSR signature, CA request, identity substitution,
unsupported key algorithm/size, SAN policy including DNS allowlist and template
violation, EKU separation and explicit combination, TTL ceiling enforcement on
tenant override, AIA/CDP presence and correctness, validity boundary, global-entity
identity URI, and independent OpenSSL inspection of every profile.

## AI execution prompt

Implement stored profiles and a reusable PKI core. Treat a CSR as a public key
container, not a policy document. Make every certificate-shape decision a profile
field rather than a conditional, and keep downstream product vocabulary out of the
model entirely. Preserve current external behavior until PR-006 switches issuance.
