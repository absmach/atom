# PR-010 — Per-Issuer OCSP

## Status

Implemented by the PR-010 delivery branch.

## Objective

Provide standards-compliant OCSP good, revoked, and unknown responses for tenant issuers.

## Dependencies

PR-008 and preferably PR-009.

## Scope

- Route: `POST /certs/issuers/{issuer_id}/ocsp`.
- Parse request CertID and verify it targets the route issuer.
- Resolve certificate by issuer plus serial.
- Return good, revoked with time/reason, or unknown.
- Sign with issuer or approved delegated responder certificate, using an
  algorithm identifier **derived from the signing key** rather than a constant.
- Report the recorded revocation reason rather than a fixed `unspecified`.
- Define producedAt, thisUpdate, nextUpdate, nonce policy, caching, and error responses.
- Retain old issuer OCSP during rotation/retention.

## Non-goals

General-purpose public OCSP service or unsupported hash algorithms without review.

## Acceptance criteria

- Same serial under another issuer cannot affect response; a serial the queried
  authority did not issue returns `unknown`, never `good` or `revoked`.
- Responses verify with an independent client under every supported issuer key
  algorithm, not only the one used in development.
- Unknown issuer/serial fails according to RFC behavior without leaking tenant data.
- Revocation status matches Atom database immediately.
- Signer authorization and responder certificate chain verify independently.
- Malformed requests cannot panic or cause excessive allocation.
- Legacy OCSP compatibility is documented.

## Mandatory tests

Good, revoked, unknown, wrong issuer, duplicate serial issuers, malformed DER, unsupported hash, nonce behavior, replay/cache times, delegated responder if used, and OpenSSL/independent client verification.

## AI execution prompt

Implement OCSP conservatively using maintained ASN.1 types. Avoid hand-written DER unless unavoidable and reviewed. Never resolve by serial alone.
