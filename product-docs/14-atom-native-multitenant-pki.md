# Atom-Native Multi-Tenant PKI

## Status: Foundation draft
## Date: 2026-08-05

This document defines the direction for replacing Atom's single file issuer with
an Atom-native, multi-tenant PKI. It supersedes neither the active v1 certificate
runtime nor its file-issuer deployment contract until the later implementation
phases described here are merged.

The architectural decision is:

- Atom remains the single certificate control plane and credential source of truth.
- Atom does not depend on OpenBao or a standalone certificate service.
- The production root private key stays offline and is never loaded by the Atom API.
- Each tenant has its own versioned intermediate CA.
- Global entities are served by one platform leaf issuer.
- Leaf-issuing CAs use `pathLenConstraint = 0`.
- CA private-key access is behind a signer/key-provider boundary.
- Certificate identity is leaf fingerprint, or issuer plus serial; serial alone is not globally unique.
- The existing global file issuer remains a legacy-compatible mode during migration.

---

## Why Atom Owns This

Atom is not adding a CA because a CA is missing. A certificate is a projection of
an identity into an offline-verifiable format, and Atom already owns the identity:
entity, tenant, status, credential lifecycle, authorization, and audit. Two
properties follow from that ownership and are the reason not to bolt on a
standalone CA:

- **Revocation is identity state.** Disabling an entity or freezing a tenant
  invalidates its certificates through the same path that invalidates its tokens.
  No CRL propagation delay, no second lifecycle to reconcile.
- **Bootstrap is already solved.** The hard problem for any workload PKI is how a
  new subject proves who it is before it holds a certificate. Atom entities
  already hold passwords, shared keys, and access tokens, so the first
  certificate is an ordinary authenticated operation rather than a static join
  token.

Anything that does not benefit from those two properties does not belong in Atom
PKI.

---

## Scope

Atom PKI is a focused private CA for Atom-managed identities. It provides:

- root and intermediate CA metadata;
- tenant intermediate and platform leaf issuer provisioning and import;
- generated leaf issuance and CSR signing;
- certificate enrollment, renewal, and revocation;
- certificate profiles;
- issuer-specific CA chains, CRLs, and OCSP;
- trust anchor distribution;
- issuer rotation and retirement;
- certificate-to-entity resolution;
- authorization, tenant isolation, durable audit, and lifecycle events.

### Out of scope

The following are excluded by decision, not by omission. Adding any of them
requires an architecture review that revisits this document:

- general secret storage: key/value secrets, dynamic database credentials,
  transit encryption;
- PKI-as-a-service: caller-chosen issuers, arbitrary roles, wildcard SAN policy,
  signing for subjects Atom does not know;
- public/WebPKI issuance, public-domain ACME, or certificate transparency
  participation;
- code signing, document signing, and timestamping;
- an SSH certificate authority;
- key escrow or recovery of an issued leaf private key.

### The boundary rule

> **Atom never issues a certificate for a subject that is not an Atom entity.**

Every requested certificate resolves to a stored entity whose tenant, status, and
authorization Atom evaluates. This single rule is what keeps a focused identity
CA from drifting into a general-purpose PKI product, and it is the first thing to
check when a new feature request arrives.

---

## Consumer Neutrality

Atom PKI serves several internal platforms — an IoT platform, a message queue
doing service-to-service mTLS, and other internal services. None of their
concepts may appear in Atom.

Rules:

- **No consumer vocabulary in Atom.** No domain, channel, topic, device-class,
  broker, or product names in schema, code, configuration, API fields, or profile
  names. Atom's vocabulary is entity, tenant, credential, authority, profile.
- **One identity format.** Atom emits `urn:atom:tenant:<tenant-id>:entity:<entity-id>`
  as a URI SAN. Consumers map that to their own concepts; Atom does not learn what
  they mapped it to. Global entities use `urn:atom:entity:<entity-id>`.
- **Consumer data lives in `attributes.<consumer>`**, consistent with the rest of
  Atom's entity model.
- **Differences are expressed as profile rows, not code branches.** If a
  consumer's requirement cannot be expressed as profile data, that is a signal the
  profile model is missing a field — not a licence to add a conditional.

A useful test: if a reviewer can tell which downstream product a PKI code path
was written for, the abstraction is wrong.

---

## Trust Hierarchies

### Manual tenant provisioning

```text
Offline Root CA
├── Tenant A Intermediate CA (pathLen=0)
├── Tenant B Intermediate CA (pathLen=0)
└── Platform Leaf Issuer     (pathLen=0)
```

The Atom signer generates a tenant intermediate key and CSR. An offline operator
signs the CSR with the root and imports the signed certificate. The root key never
enters Atom.

### Automated tenant provisioning

```text
Offline Root CA
├── Atom Platform Intermediate CA   (signs CAs, never leaves)
│   ├── Tenant A Intermediate CA    (leaves, tenant A)
│   └── Tenant B Intermediate CA    (leaves, tenant B)
└── Platform Leaf Issuer            (leaves, global entities)
```

The offline root signs the platform intermediate once. A separately authorized
CA-provisioning operation uses that platform intermediate to sign tenant CA CSRs.
The platform intermediate is not a leaf issuer.

The direct-root hierarchy is appropriate for a small, manually provisioned set of
tenants. The platform-intermediate hierarchy is appropriate when tenant creation
must be automated.

### Global entities

Not every Atom entity has a tenant. Internal services, platform workloads, and
global human entities have `tenant_id IS NULL`, and service-to-service mTLS
between internal components is exactly this case. They are served by a **platform
leaf issuer**: a global, parented, leaf-signing authority.

It is deliberately a distinct authority kind from the platform intermediate. The
authority that signs CAs and the authority that signs everyday workload
certificates hold different keys, so compromising the high-volume online signer
does not yield the ability to mint new CAs.

The one-active-issuer rule applies to it exactly as it does per tenant: at most
one platform leaf issuer may be enabled for new issuance, with older versions
retained in `retiring`/`retired` state.

---

## Certificate Lifetime Tiers

Atom's core authorization promise is that decisions are online and revocation is
immediate. A certificate is an offline bearer proof, so a long-lived certificate
weakens that promise for exactly as long as it remains valid. Lifetime is
therefore a first-class policy decision, not a configuration afterthought.

| Tier | Subjects | Typical TTL | Renewal | Revocation depends on |
|---|---|---|---|---|
| Ephemeral | internal services, service-to-service mTLS | 1–24 h | automatic, authenticated by the current certificate | expiry |
| Standard | gateways, connected devices | 7–90 d | automatic while the subject is online | resolver and OCSP |
| Long | constrained or intermittently offline devices | 1–3 y | manual re-enrollment | resolver, mandatory |

Consequences that the implementation must honour:

- **Renewal automation is foundational, not optional.** The ephemeral tier cannot
  exist without it, and the standard tier becomes an outage waiting for a date.
  Renewal starts at roughly half of the certificate lifetime so that a subject has
  several attempts before expiry.
- **A profile declares its tier.** TTL ceilings, renewal thresholds, and whether
  automatic renewal is expected are profile fields.
- **The long tier is a liability, and its size is a design input.** The more
  long-lived certificates a deployment issues, the more it depends on the
  resolver being reachable.

---

## Revocation Strategy

Revocation has two independent mechanisms and they carry different weight.

**Atom's resolver is the control.** A revoked, expired, or entity-disabled
credential is denied at resolution time, immediately, with no publication delay.

**CRL and OCSP are compliance and interoperability artifacts.** They exist because
standard tooling, auditors, and third-party verifiers expect them. They are not
the mechanism the platform's security depends on, for a structural reason: a
large fleet produces a CRL whose size grows with the number of revoked
certificates, regenerated from and served out of Postgres. That does not scale to
fleet-wide revocation events and never has for anyone.

The practical revocation strategy is therefore **short lifetimes plus resolver
denial**, with CRL and OCSP published correctly for the parties that require them.

This ranking must be stated in operator documentation. An operator who believes
CRL propagation is the primary control will size TTLs wrongly.

---

## Certificate Profiles

Profiles are **data**, not code. A profile is a stored row describing what a
certificate of that kind looks like:

```text
name
key_algorithms[]            -- permitted subject key algorithms and sizes
ttl_default, ttl_max        -- bounded by the platform ceiling
renewal_threshold           -- fraction of lifetime after which renewal is due
key_usages[]
extended_key_usages[]
san_policy                  -- per SAN type: derived | allowlist | template | deny
identity_uri_template       -- canonical Atom identity SAN
basic_constraints           -- always CA=false for leaves
```

Platform-defined baseline profiles ship with Atom. A tenant may hold overrides,
but only within the platform ceiling: a tenant can shorten a TTL, never extend it,
and can restrict a SAN policy, never widen it.

### Extended key usage

The default client profile carries `clientAuth` only, and the default server
profile carries `serverAuth` only. **Combining them is a profile decision, not a
prohibition.** Mutually authenticated service-to-service mTLS legitimately needs a
single certificate that is both client and server, and a hardcoded ban would make
that use case unimplementable. The requirement is that combination is explicit,
attributable to a profile, and never the default.

### Subject alternative names

The canonical Atom identity URI SAN is always present and always derived from
stored state. Any other SAN is subject to profile policy, and **DNS SANs must
never be free-form caller input**: once services authenticate each other by name,
an unvalidated DNS SAN is an impersonation primitive. Profiles restrict DNS SANs
to an allowlist or a template bound to the entity.

### CSR handling

A CSR is an input public key, not a policy document. Atom verifies its signature
and then applies the profile. The CSR cannot select `CA=true`, `keyCertSign`,
`cRLSign`, another tenant or entity identity, arbitrary EKUs or extensions, an
issuer, or validity beyond platform and issuer limits.

Device-generated CSR issuance is preferred because the leaf private key never
enters Atom. Generated-key bootstrap returns the private key once and stores only
the certificate credential.

---

## Enrollment

Issuance through the authenticated management API covers operator and
service-mediated provisioning. It does not cover a subject enrolling itself,
which is what fleets and workloads actually do.

Requirements:

- **First enrollment** authenticates with an existing Atom credential for the
  target entity — access token, shared key, or another already-trusted credential.
  There is no separate join-token system; reusing Atom credentials is the point.
- **Re-enrollment** authenticates with the certificate being replaced, over mTLS,
  with no operator and no second credential. This is what makes the ephemeral
  tier operable.
- **A subject may only enroll for itself.** Enrollment never accepts a target
  entity chosen by the caller when the caller is the subject.
- **Transport is an adapter over one enrollment service.** Authentication mapping,
  entity derivation, issuer selection, profile application, and persistence live
  in the service; a protocol adapter only translates. The verbs are `enroll`,
  `re-enroll`, and `revoke`, and they are consumer-neutral.

The normative transport is an **Atom-native interface**. **EST** (RFC 7030) is
specified as an adapter to build when a consumer needs standards-based enrollment
from firmware that cannot carry Atom-specific code. **ACME** is rejected: its model
is proving control of a DNS identifier, Atom's is authenticating as an entity, and
External Account Binding does not close that gap — stock clients would still need
Atom-specific behaviour, leaving only the state machine's cost. **SCEP** is
rejected as legacy-fleet onboarding that is not in scope. Rationale is recorded in
the PR-014 transport decision.

Re-enrollment requires Atom to terminate and verify client certificates **in
process**. A proxy that verifies a certificate and forwards the result in a header
is not acceptable: anything able to reach that port could then forge an identity.

Whether a downstream platform's own provisioning service acts as a registration
authority instead of subjects enrolling directly is that platform's decision. Atom
supports both by authenticating whoever calls it and authorizing against the
target entity.

---

## Service Boundary

The public Atom process owns:

- caller authentication;
- target-entity lookup;
- target tenant derivation;
- authorization;
- certificate profiles and request validation;
- CA and certificate lifecycle state;
- audit and event publication;
- runtime certificate resolution.

Private-key operations use an internal interface:

```text
Atom API
  -> authorize and derive tenant
  -> select issuer from the subject's tenant scope
  -> canonicalize certificate profile
  -> internal signer/key provider
  -> verify signed artifact
  -> commit credential + audit/event
```

The first implementation may use an in-process encrypted-database provider. The
interface must also permit a later `atom-pki-signer` process, PKCS#11/HSM, or KMS
without changing the public certificate APIs.

No request may supply a raw key reference, CA path, or arbitrary issuer. Atom
selects the issuer from the target entity's tenant scope.

### Atom's own transport certificate

Atom's own TLS server certificate must come from outside Atom's PKI —
deployment-provided, like any other service's bootstrap material.

This is not a stylistic preference. Subjects authenticate to Atom in order to
obtain and renew certificates. If Atom's own certificate were issued by Atom, an
expired or failed rotation would leave a service that nothing can reach and that
therefore cannot renew anything, including itself. The dependency must point
outward.

---

## Authority Registry

`pki_authorities` stores public CA metadata, lifecycle state, hierarchy, and an
opaque private-key backend reference.

Kinds:

```text
root                    -- trust anchor, offline key, parentless
platform_intermediate   -- signs tenant CAs, never leaves
platform_leaf_issuer    -- signs leaves for global entities
tenant_intermediate     -- signs leaves for exactly one tenant
```

Statuses:

```text
provisioning
pending_signature
active
retiring
retired
revoked
expired
failed
```

Key backends:

```text
public_only
encrypted_database
pkcs11
kms
```

There is deliberately **no file backend**. A CA key path stored in a database row
is a key location chosen by whoever can write that row, which is the
caller-selected key reference the architecture forbids. The legacy file issuer
remains outside the registry as the `issuer_id = NULL` namespace and is retired by
renewal, not by import.

Static database invariants include:

- a root is global and parentless;
- a platform intermediate is global, parented by a root, and never issues leaves;
- a platform leaf issuer is global and parented;
- a tenant intermediate belongs to exactly one tenant and is parented;
- only a root or platform intermediate may parent another authority;
- a child authority's validity falls inside its parent's validity window;
- only an active leaf-issuing authority with a signing backend may issue leaves;
- one tenant has at most one authority enabled for new leaf issuance, and at most
  one platform leaf issuer is enabled globally;
- a tenant-owned entity's certificate references only its own tenant's
  intermediate; a global entity's certificate references only the platform leaf
  issuer;
- an entity's tenant cannot change while it holds issuer-bound certificates;
- old issuer versions remain addressable while certificates issued by them exist;
- encrypted key material and external key references are mutually exclusive.

The registry never stores a plaintext CA private key.

### Deletion semantics

Certificate credentials reference their authority with `ON DELETE RESTRICT`. The
credentials issued by an authority are the rows its CRL is built from and the
record of what it ever attested to; deleting a CA row must not silently take them
with it. Removing an authority is an explicit ordered operation — delete the
credentials, then the authority — so an accidental or malicious authority delete
fails loudly instead of erasing revocation history.

CRL cache state may cascade, because it is regenerable.

---

## Private-Key Custody

### Offline root

A production root row normally uses `key_backend = public_only`. Atom stores the
root certificate and fingerprint, not the root private key.

### Encrypted database provider

The initial software signer uses envelope encryption:

```text
random per-authority DEK
  -> encrypts the CA private key

operator-supplied CA KEK
  -> wraps the DEK
```

The CA KEK must be separate from JWT signing-key and normal credential encryption
configuration. Associated data binds ciphertext to:

```text
authority_id || tenant_id || version
```

A signer decrypts only the selected CA key for the duration of one operation and
zeroizes plaintext key material afterward. It must never preload every tenant key
at startup.

Key material — including wrapped material — must not appear in `Debug`, `Display`,
serde output, GraphQL types, audit details, events, tracing spans, or errors. A
type holding key columns implements its own redacting `Debug` rather than deriving
one.

### External signer providers

PKCS#11 and KMS providers store only an opaque key reference in Atom. The private
key never leaves the provider.

---

## Public Artifacts and Discovery

### Issuer-specific routes

```text
GET  /certs/issuers/{issuer_id}/ca-chain.pem
GET  /certs/issuers/{issuer_id}/crl
POST /certs/issuers/{issuer_id}/ocsp
```

The current global routes remain available for the legacy file issuer during the
migration period.

### Leaves must carry their own discovery pointers

Every issued leaf embeds, from the issuing authority's own configuration:

- **Authority Information Access** — the OCSP responder URL and the CA issuers URL;
- **CRL Distribution Points** — the issuing authority's CRL URL.

Without these extensions, a standard verifier cannot find the revocation data Atom
publishes, and every relying party has to be configured by hand. Per-issuer routes
without per-issuer discovery pointers are decorative.

### Trust anchor distribution

A relying party that terminates mTLS needs the trust anchors as a file it can
load, and needs to notice when the set changes — for instance when a tenant CA is
provisioned or rotated.

Atom therefore publishes an aggregated, versioned trust bundle containing the
active anchors and per-issuer chains, cacheable and revalidatable so consumers can
poll cheaply. Requiring every consumer to assemble N per-issuer chains and
discover new tenants for itself is not an acceptable substitute.

---

## Certificate Identity and Storage

Independent CAs may issue the same serial number. Therefore:

```text
unique certificate identity = issuer_id + normalized serial_number
preferred runtime identity  = leaf DER SHA-256 fingerprint
```

Certificate credentials carry `issuer_id`. The legacy v1 file issuer uses
`issuer_id = NULL` and retains its existing global serial namespace during
migration.

The runtime resolver must eventually accept the leaf fingerprint or full leaf DER
and return:

```text
entity_id
tenant_id
credential_id
issuer_id
expires_at
status
```

It verifies certificate status, expiry, issuer status, entity status, tenant
status, fingerprint, and an optional expected tenant.

### Storage shape

Certificates are stored as credential rows with certificate attributes in
`metadata`, including a unique index over the fingerprint expression. This is
correct at current volume and is not the right shape indefinitely: a large device
fleet stores millions of PEM blobs in a JSONB column with an expression index over
it.

The threshold for moving certificates to a dedicated table with typed columns must
be identified and written down before a deployment approaches it, not discovered
afterwards.

---

## Verification Tiers for Relying Parties

Not every relying party should call Atom on every connection.

**Offline verification** — chain validation plus the canonical identity URI SAN,
with no call to Atom. Appropriate for high-rate, mutually authenticated
service-to-service traffic using ephemeral certificates, where the short lifetime
is the revocation control. This keeps Atom out of the data path.

**Resolver verification** — a call to Atom's certificate resolver for authoritative
status. Appropriate for standard and long-tier subjects, where revocation
freshness matters more than handshake cost, and on cache misses.

Every consumer integration must state which tier it uses, and:

- caching, if any, has a bounded TTL and an invalidation path driven by Atom's
  certificate lifecycle events rather than polling;
- behaviour when Atom is unreachable is explicitly **fail closed**, unless a
  reviewed bounded-cache policy applies;
- the resolved tenant is compared against the tenant scope the caller is
  requesting, before authorization.

### Availability coupling

Short lifetimes and a mandatory resolver both make Atom's availability a fleet-wide
dependency. An Atom outage longer than the renewal window prevents reconnection.
Deployments must size the renewal threshold against their target recovery time,
and re-enrollment after expiry must have a path that does not require a valid
certificate.

---

## Rotation

Issuer rotation is an explicit handover, for a tenant intermediate or the platform
leaf issuer alike:

```text
1. Create issuer v2 in provisioning state.
2. Produce/import its signed CA certificate and verify the chain.
3. Set v1 to retiring and disable new issuance.
4. Set v2 active and enable new issuance.
5. Issue all new and renewed leaves under v2.
6. Continue serving v1 chain, CRL, and OCSP.
7. Retire v1 only after its last leaf expires plus the retention window.
```

The database permits multiple historical authority versions but enforces one
issuer enabled for new leaves per scope.

CRL numbering must carry across a rotation of the *state representation*: when
issuer-keyed CRL state replaces fingerprint-keyed state for the same physical CA,
the CRL number continues from the last published value. Restarting at 1 makes CRL
numbers move backwards, which conforming verifiers treat as a rollback attack.

---

## Migration

1. Represent the existing v1 file issuer as the legacy `issuer_id = NULL` namespace.
2. Add the authority registry and issuer-aware uniqueness without changing v1 signing.
3. Add a Rust signer/key-provider abstraction.
4. Add root, platform, and tenant CA provisioning lifecycle.
5. Route new leaf issuance through the subject's issuer scope.
6. Add issuer-aware runtime resolution and public artifacts.
7. Renew legacy certificates into tenant and platform issuers.
8. Retire the global issuer only after the last legacy leaf expires.

Legacy certificates migrate by **renewal**, never by rewriting issued
certificates.

---

## Foundation PR Boundary

The first PR is deliberately additive. It provides:

- `pki_authorities` schema and static security constraints;
- issuer linkage on certificate credentials;
- issuer-plus-serial and fingerprint uniqueness;
- issuer linkage for CRL state;
- typed Rust authority domain models;
- read-side repository selectors;
- integration tests for tenant isolation and rotation invariants.

It does not yet:

- store or generate CA private keys;
- change the current file issuer;
- expose CA-management APIs;
- change leaf issuance or runtime resolution;
- change public CRL/OCSP routes.

Keeping this boundary small allows the authority model and key-custody contract to
be reviewed before signing privileges are introduced.
