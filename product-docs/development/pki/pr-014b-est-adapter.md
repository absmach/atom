# PR-014b — EST Adapter

## Status

Specified, not scheduled. Build on the trigger condition below.

## Trigger condition

The first consumer that requires certificate enrollment from vendor or third-party
firmware without writing an Atom-specific client.

Until then this remains unbuilt on purpose. A protocol with no caller is an
untested public surface, and PR-014's native adapter already covers the in-house
consumers.

## Objective

Expose Atom enrollment over EST (RFC 7030) so standards-based clients can enroll
and re-enroll without Atom-specific code.

## Dependencies

PR-014, whose adapter boundary this attaches to. If implementing this PR requires
changing enrollment logic rather than adding an adapter, PR-014's boundary was
wrong and that is the defect to fix first.

## Why EST rather than ACME

Recorded in PR-014's transport decision. In short: EST's authentication model is
already Atom's — an existing credential to bootstrap, the current certificate to
renew — with no account, order, challenge, or nonce state, and no assumption that
identity is a DNS name.

## Scope

- `/.well-known/est/cacerts` — the trust anchors and chain for the requesting
  scope, as a certs-only PKCS#7.
- `/.well-known/est/simpleenroll` — PKCS#10 in, PKCS#7 out, authenticated with an
  existing Atom credential over HTTP authentication.
- `/.well-known/est/simplereenroll` — same, authenticated by the client
  certificate being replaced.
- `/.well-known/est/serverkeygen` — mapped onto Atom's generated-key issuance,
  returning the certificate and the one-time private key.
- `/.well-known/est/csrattrs` — advertise the attributes the applicable profile
  expects, so a client can build a conforming CSR.
- Content type, base64 transfer encoding, and error handling per RFC 7030.
- Path scoping so a request resolves to the correct issuer without the client
  naming one.

## Non-goals

Certificate-less TLS-SRP authentication, EST over CoAP, and any EST operation not
listed above.

## Design constraints

- Use a maintained CMS implementation to build the degenerate certs-only PKCS#7.
  Hand-rolled DER for this structure is a recurring source of interoperability
  defects and is not acceptable without explicit cryptographic review.
- The adapter translates protocol to the enrollment service and back. It performs
  no authorization, issuer selection, or profile logic of its own.
- `/cacerts` must agree with the trust bundle published by PR-003 — one source of
  truth, two representations.
- The issuer is still derived from the authenticated subject's tenant scope. EST
  offers no way for a client to select one and must not acquire one.

## Acceptance criteria

- A standard EST client enrolls and re-enrolls against Atom with no
  Atom-specific configuration beyond the URL and its credential.
- Certificates issued over EST are byte-for-byte equivalent in profile, issuer,
  and identity to those issued over the native adapter for the same subject.
- `simplereenroll` accepts only the certificate being replaced, and rejects an
  expired or revoked one.
- A client cannot select an issuer, tenant, or profile.
- `/cacerts` output matches the published trust bundle.
- Malformed PKCS#10, oversized bodies, and invalid base64 fail cheaply.
- No enrollment logic was added to the adapter.

## Mandatory tests

Interoperability against at least one independent EST client implementation,
enroll and re-enroll flows, expired and revoked re-enrollment rejection,
`serverkeygen` key handling and one-time delivery, `csrattrs` correctness against
the profile, `/cacerts` agreement with the trust bundle, cross-tenant attempts,
malformed input, and parity of issued certificates with the native adapter.

## AI execution prompt

Implement an EST adapter over the existing enrollment service. Add no enrollment
logic. Use a maintained CMS library for PKCS#7 construction. Prove interoperability
with an independent client rather than round-tripping through your own encoder.
