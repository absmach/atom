# PR-012 — Relying-Party Certificate Authentication Integration

## Objective

Define and deliver the integration contract for services that terminate mTLS
outside Atom and authenticate peers against Atom's certificate identity.

This work lives in the consuming repositories. Atom's side is delivered by PR-011;
what this PR owns is the contract those consumers implement, the reference
integration, and the removal of any legacy certificate-service assumptions.

## Dependencies

PR-011, PR-014, and access to the consuming repositories.

## Scope

- Extract the peer leaf DER, fingerprint, and issuer data from the TLS termination
  path.
- Choose and implement a verification tier per integration (see below).
- Compare the tenant Atom resolves against the tenant scope the caller is
  requesting, before authorization.
- Call normal Atom authorization for the operation being performed.
- Define caching with a bounded TTL and event-driven invalidation.
- Remove or deprecate legacy certificate-service integrations.
- Add operational metrics and defined failure behavior.

## Verification tiers

Every integration must declare which tier it uses and why.

**Offline verification** — validate the chain against the trust bundle and read
the canonical Atom identity URI SAN. No call to Atom per connection. Appropriate
for high-rate mutually authenticated service-to-service traffic on ephemeral
certificates, where the short lifetime is the revocation control. This keeps Atom
out of the data path.

**Resolver verification** — call Atom's certificate resolver for authoritative
status. Appropriate for standard and long-tier subjects where revocation freshness
matters more than handshake cost, and on cache misses in any tier.

## Caching and invalidation

Caching a resolver result caches an authorization-relevant fact, so:

- TTL is bounded and documented;
- invalidation is driven by Atom's certificate lifecycle events through the
  outbox, not by polling;
- an integration that cannot consume events uses a TTL short enough that its
  revocation lag is acceptable, and states that lag explicitly.

## Failure behavior

Atom unreachable is **fail closed** unless a reviewed bounded-cache policy applies.
The integration documents its recovery-time expectation, because short certificate
lifetimes combined with a mandatory resolver make Atom's availability a fleet-wide
dependency.

## Non-goals

Changing a consumer's own subject, topic, or resource design, or its authorization
semantics beyond certificate identity.

## Acceptance criteria

- A certificate from one tenant cannot authenticate to another tenant's scope
  despite a common root of trust.
- A certificate issued to a global entity authenticates as a global entity and
  does not acquire tenant scope.
- Unknown, revoked, expired, inactive-entity, and frozen-tenant credentials are
  denied before session establishment.
- Atom outage behavior is explicitly fail closed unless a reviewed bounded cache
  policy applies.
- Certificate identity maps to the correct Atom entity.
- Revocation propagates to the integration within its documented lag.
- Existing non-certificate authentication paths are unaffected.
- No legacy certificate service is required for migrated deployments.
- The trust bundle is consumed from Atom's published endpoint and refreshes when
  new authorities appear.

## Mandatory tests

Per-protocol authentication paths as applicable, cross-tenant attack,
global-entity authentication, revoked-session policy, resolver timeout, cache
expiry and event-driven invalidation, certificate rotation mid-session, trust
bundle refresh after tenant CA provisioning, authorization denial, and load
behavior at expected connection rates.

## AI execution prompt

Implement certificate authentication integration only. Do not infer tenant from
the certificate subject alone; trust Atom's verified resolution and compare it
with the scope being requested. Declare the verification tier explicitly and
preserve existing authorization semantics.
