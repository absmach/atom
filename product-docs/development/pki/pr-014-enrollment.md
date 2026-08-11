# PR-014 — Subject Enrollment and Re-Enrollment

Implemented by the PR-014 delivery branch.

## Objective

Let a subject obtain and replace its own certificate without an operator in the
loop. This is the difference between a CA and a usable certificate platform: the
management API covers provisioning *for* a subject, and nothing today covers a
subject provisioning *itself*.

## Dependencies

PR-006 for issuance, PR-007 for renewal semantics. May be specified in parallel
but must not merge before them.

---

## Transport decision

**Decided: an Atom-native enrollment interface is the normative transport. EST is
specified separately as PR-014b and built on demand. ACME and SCEP are rejected.**

The work behind every option is identical — authenticate the subject, derive the
entity, derive the issuer from the entity's tenant scope, apply the profile, sign,
persist, audit. Protocol choice therefore selects an *adapter*, not an
architecture, provided the adapter boundary is real. Enforcing that boundary is an
acceptance criterion below precisely so this decision stays cheap to revisit.

### Native — normative

A small authenticated endpoint accepting a CSR and returning the certificate and
chain, authenticated with any existing Atom credential, or with the certificate
being replaced.

Chosen because the first and most demanding consumers are internal services doing
service-to-service mTLS on short lifetimes. They are in-house, they renew
aggressively, and a standard protocol buys them nothing but a state machine. The
native interface is also the substrate every other adapter sits on, so it is built
either way.

It additionally carries what no standard protocol exposes: the profile's renewal
threshold, so a subject learns when to come back instead of guessing.

### EST (RFC 7030) — PR-014b, built on demand

EST is the correct standard for this problem and its auth model matches the
requirements exactly: HTTP authentication for first enrollment, client certificate
for re-enrollment, no session state. `/serverkeygen` maps onto Atom's generated-key
issuance and `/csrattrs` can advertise profile requirements.

It is deferred rather than rejected because no consumer needs it yet — current
device fleets are provisioned through their platform's own bootstrap service, not
by firmware speaking EST. Building a protocol with no caller produces an untested
surface.

**Trigger condition:** the first consumer that requires certificate enrollment from
vendor or third-party firmware without writing an Atom-specific client. On that
trigger, implement PR-014b; do not extend this PR.

### ACME (RFC 8555) — rejected

ACME has by far the largest client ecosystem, which is a real and tempting
advantage. It is rejected because the mismatch is structural rather than
cosmetic:

- ACME's model is *prove control of an identifier*, where identifiers are DNS
  names or IP addresses. Atom's model is *authenticate as an entity*. External
  Account Binding can attach an Atom credential to an ACME account, but the order
  still carries an identifier type that stock clients neither produce nor accept
  for an entity-scoped identity.
- The ecosystem advantage is therefore mostly illusory here: the clients that make
  ACME attractive assume DNS validation and would need Atom-specific behaviour
  anyway.
- The server-side cost is the full state machine — accounts, orders,
  authorizations, challenges, nonces, JWS — for a benefit that does not survive
  the identifier mismatch.

`device-attest-01` is the nearest fit and remains a draft with few
implementations. Revisit only if it stabilises *and* a consumer already operates
ACME clients.

### SCEP (RFC 8894) — rejected

Shared challenge-password enrollment, still common in MDM and network equipment.
Rejected because it earns its place only when onboarding devices that speak
nothing else, and no such fleet is in scope. Its auth model is also a step
backwards from reusing Atom credentials.

---

## Prerequisite: client-certificate termination

Re-enrollment authenticates with the certificate being replaced, over mTLS. Atom
does not currently terminate client TLS on any subject-facing listener — GraphQL
is bearer-token and the gRPC TLS is server-side only.

This PR therefore includes a listener that requests and verifies client
certificates **in process**, against Atom's own trust bundle, and maps the verified
peer certificate to a credential through the resolver.

A reverse proxy that verifies the certificate and forwards the result in a header
is explicitly not acceptable: anything able to reach that port can then forge any
identity. If a proxy terminates TLS for operational reasons, it must forward the
full peer certificate over an authenticated channel and Atom must verify it again.

This is protocol-independent work — native, EST, and ACME all require it — and is
likely the largest single piece of the PR. Decide and record whether the listener
is a dedicated port, and whether the enrollment surface is public or internal.

---

## Scope

- **First enrollment.** The caller authenticates with an existing Atom credential
  for the target entity — access token, shared key, or another already-trusted
  credential — and submits a CSR. Atom derives the entity from the authenticated
  credential, derives the issuer from that entity's tenant scope, applies the
  profile, and returns the certificate and chain. There is no separate join-token
  system; reusing Atom credentials for bootstrap is the design.
- **Re-enrollment.** The caller authenticates with the certificate being replaced,
  over mTLS, and submits a new CSR. No operator, no second credential. This is
  what makes short-lived certificates operable.
- **Self-scope only.** An enrolling subject may only enroll for itself. A caller
  acting for another entity uses the management API and is authorized against that
  entity as normal.
- **Adapter boundary.** One internal enrollment service; the native interface is a
  thin adapter over it. No enrollment logic — authentication mapping, entity
  derivation, issuer selection, profile application, persistence — may live in the
  adapter.
- **Renewal guidance.** Responses carry the profile's renewal threshold so a
  subject knows when to return.
- Client-certificate termination as described above.
- Rate limiting and abuse controls per entity and per tenant.
- Audit and outbox events distinguishing first enrollment from re-enrollment.

## Non-goals

EST, ACME, and SCEP adapters. Bulk fleet provisioning, hardware attestation, and
device onboarding UX. Each may be proposed as a later numbered PR; none may be
smuggled in here.

## Design constraints

- Enrollment authenticates the subject and authorizes against the target entity;
  it never becomes a second authorization model.
- Re-enrollment must accept a certificate that is valid but close to expiry, and
  must reject one that is expired, revoked, or issued to an inactive entity. The
  recovery path for an expired subject is first enrollment with a non-certificate
  credential, and that path must exist and be documented.
- Renewal thresholds come from the profile, not a global constant.
- The enrollment endpoint is a public network surface taking cryptographic input.
  Malformed input must fail cheaply and must not allocate unboundedly. TLS
  handshakes and established connections have deadlines; shutdown tracks and
  drains connection tasks for a bounded interval.
- Durable rate-limit windows are removed with entity and tenant purge, so deleted
  one-time subjects cannot leave unbounded counter rows.
- The adapter boundary is verified by review, not by intent: a reviewer must be
  able to describe how a second adapter would attach without touching enrollment
  logic.

## Acceptance criteria

- A subject holding only a non-certificate Atom credential can obtain its first
  certificate.
- A subject holding a valid certificate can replace it using only that
  certificate, over a listener that verified the certificate in process.
- A forged or proxy-asserted client identity is rejected; no header or metadata
  field can substitute for a verified peer certificate.
- A subject cannot enroll for another entity, in its own tenant or another.
- Expired, revoked, inactive-entity, frozen-tenant, and unknown subjects are
  denied.
- The issued certificate is identical in profile and issuer to one issued through
  the management API for the same entity.
- Responses carry the renewal threshold from the certificate's profile.
- Enrollment and re-enrollment are distinguishable in audit and events.
- Native adapter denials and service failures use the same error-observation path
  as other certificate transports, including a missing verified peer.
- Rate limits are enforced and observable.
- Enrollment logic sits behind an adapter boundary, with no protocol-specific
  behaviour below it and no enrollment behaviour above it.
- No consumer-specific concept appears in the interface or the stored data.

## Mandatory tests

First enrollment per credential kind, re-enrollment over mTLS, forged-peer and
header-injection rejection, self-scope violation, expired-certificate
re-enrollment rejection plus documented recovery, cross-tenant attempts, global
entity enrollment against the platform leaf issuer, malformed and oversized CSR
input, rate-limit behaviour, profile application parity with the management API,
renewal-threshold correctness, bounded handshake/connection shutdown behaviour,
purge cleanup for durable counters, error observation, and independent
verification of the issued chain.

## AI execution prompt

Implement subject-driven enrollment behind an adapter boundary, with the native
adapter only. Derive the entity from the authenticated credential, never from the
request body. Verify client certificates in process; never trust a proxy-asserted
identity. Reuse the PR-005/PR-006 issuance pipeline rather than building a second
one, and keep the interface free of any downstream product's vocabulary. Do not
implement EST, ACME, or SCEP.
