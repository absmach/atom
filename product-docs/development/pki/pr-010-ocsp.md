# PR-010 — Per-Issuer OCSP

## Objective

Provide standards-compliant OCSP good, revoked, and unknown responses for tenant issuers.

## Dependencies

PR-008 and preferably PR-009.

## Scope

- Route: `POST /certs/issuers/{issuer_id}/ocsp`.
- Parse request CertID and verify it targets the route issuer.
- Resolve certificate by issuer plus serial.
- Return good, revoked with time/reason, or unknown.
- Sign with issuer or approved delegated responder certificate.
- Define producedAt, thisUpdate, nextUpdate, nonce policy, caching, and error responses.
- Retain old issuer OCSP during rotation/retention.

## Non-goals

General-purpose public OCSP service or unsupported hash algorithms without review.

## Acceptance criteria

- Same serial under another issuer cannot affect response.
- Unknown issuer/serial fails according to RFC behavior without leaking tenant data.
- Revocation status matches Atom database immediately.
- Signer authorization and responder certificate chain verify independently.
- Malformed requests cannot panic or cause excessive allocation.
- Legacy OCSP compatibility is documented.

## Mandatory tests

Good, revoked, unknown, wrong issuer, duplicate serial issuers, malformed DER, unsupported hash, nonce behavior, replay/cache times, delegated responder if used, and OpenSSL/independent client verification.

## AI execution prompt

Implement OCSP conservatively using maintained ASN.1 types. Avoid hand-written DER unless unavoidable and reviewed. Never resolve by serial alone.