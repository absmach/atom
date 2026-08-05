# PR-000 — v1 Certificate Correctness Hotfixes

## Objective

Fix defects in the live v1 certificate runtime that make Atom's published PKI
artifacts unverifiable or unusable by standard clients. These are present today,
independent of the multi-tenant work, and every later PR inherits them.

## Dependencies

None. This PR is deliberately orderable before or alongside PR-001 and does not
touch the authority registry.

## Scope

### 1. OCSP signature algorithm must match the signing key

`ocsp_response` signs with the loaded issuer key but hardcodes the response
algorithm identifier to `sha256WithRSAEncryption`. When the mounted CA key is
ECDSA — the common choice for machine PKI — the response carries an ECDSA
signature labelled as RSA, and every conforming client rejects it. The defect is
invisible in deployments whose CA happens to be RSA, which includes the repository's
development CA.

Required: derive the algorithm identifier from the issuer key algorithm, and
reject at startup any issuer whose key algorithm the OCSP responder cannot
represent.

### 2. Revocation reasons must reach CRL and OCSP

Revocation reason is captured in credential metadata and then discarded: CRL
entries are written with `unspecified` and OCSP revoked responses likewise. A
relying party can never distinguish a routine decommission from a key compromise.

Required: map the stored reason to the CRL entry reason code and the OCSP
`RevokedInfo` reason, with an explicit default when no reason was recorded.

### 3. OCSP nonce handling

The responder ignores the request nonce and sets no response extensions. Clients
that send a nonce cannot bind the response to their request.

Required: echo the nonce when present, and document the policy when absent.

### 4. CRL responses must be cacheable

Every CRL fetch opens a transaction and takes an advisory lock before returning
cached bytes. A fleet polling the CRL serialises on that lock.

Required: serve validator-friendly caching headers derived from `thisUpdate` and
`nextUpdate`, and return a not-modified response when the client already holds the
current CRL.

## Non-goals

Per-issuer routes, issuer-aware lookup, certificate profiles, AIA/CDP extensions,
and anything touching the authority registry. Those belong to their numbered PRs.

## Acceptance criteria

- OCSP responses verify with an independent client against both an ECDSA and an
  RSA issuer.
- An issuer key algorithm the responder cannot represent fails at startup, not at
  request time.
- CRL and OCSP report the recorded revocation reason.
- A nonce sent by a client is present in the response.
- Repeated CRL fetches do not take the regeneration lock when the cached CRL is
  current.
- No change to certificate issuance, storage, or authorization behaviour.

## Mandatory tests

OpenSSL verification of OCSP responses under ECDSA and RSA issuers, reason-code
round trip through CRL and OCSP, nonce echo and absence, cache revalidation
behaviour, and concurrent CRL fetch behaviour.

## Rollback

Each item is independently revertible. No schema change, no API contract change.

## AI execution prompt

Fix only the listed defects in the existing v1 certificate service. Do not
introduce the authority registry, profiles, or issuer-scoped routes. Prove each
fix with an independent implementation rather than a self-consistent round trip
through the same library.
