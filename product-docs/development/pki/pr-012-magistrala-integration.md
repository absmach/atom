# PR-012 — Magistrala Certificate Authentication Integration

## Objective

Replace old certificate-service assumptions in Magistrala with Atom resolver-v2 and tenant/domain enforcement.

## Dependencies

PR-011 and the corresponding Magistrala integration branch/repository access.

## Scope

- Extract peer leaf DER/fingerprint and issuer data from TLS termination path.
- Call Atom CertificateService resolver v2.
- Compare returned tenant ID with requested Magistrala domain before session acceptance.
- Call normal Atom authorization for publish, subscribe, read, write, or execute.
- Define caching with revocation-safe TTL/invalidation.
- Remove or deprecate old certs client/service integration.
- Add operational metrics and failure behavior.

## Non-goals

Changing MQTT subject design or unrelated Magistrala authorization semantics.

## Acceptance criteria

- Tenant A certificate cannot authenticate to Tenant B domain despite common root trust.
- Unknown/revoked/expired/frozen credentials are denied before session establishment.
- Atom outage behavior is explicitly fail closed unless a reviewed bounded cache policy applies.
- Certificate identity maps to the correct Atom entity.
- Existing non-certificate authentication paths are unaffected.
- Old certs service is no longer required for migrated deployments.

## Mandatory tests

MQTT/HTTP/WS paths as applicable, cross-tenant domain attack, revoked active session policy, resolver timeout, cache expiry, certificate rotation, authorization denial, and load behavior.

## AI execution prompt

Implement only certificate authentication integration. Do not infer tenant from CN alone; trust Atom's verified resolution and compare it with the requested domain. Preserve existing topic authorization.