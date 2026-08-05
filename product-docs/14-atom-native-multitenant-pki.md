# Atom-Native Multi-Tenant PKI

## Status: Foundation draft
## Date: 2026-08-05

This document defines the direction for replacing Atom's single file issuer with
an Atom-native, multi-tenant PKI. It supersedes neither the active v1 certificate
runtime nor its file-issuer deployment contract until the later implementation
phases described here are merged.

The architectural decision is:

- Atom remains the single certificate control plane and credential source of truth.
- Atom does not depend on OpenBao or a standalone Magistrala certificate service.
- The production root private key stays offline and is never loaded by the Atom API.
- Each tenant has its own versioned intermediate CA.
- Tenant intermediate CAs issue only leaf credentials and use `pathLenConstraint = 0`.
- CA private-key access is behind a signer/key-provider boundary.
- Certificate identity is leaf fingerprint, or issuer plus serial; serial alone is not globally unique.
- The existing global file issuer remains a legacy-compatible mode during migration.

---

## Scope

Atom PKI is a focused private CA for Atom-managed machine identities. It provides:

- root and intermediate CA metadata;
- tenant intermediate provisioning and import;
- generated leaf issuance and CSR signing;
- certificate renewal and revocation;
- issuer-specific CA chains, CRLs, and OCSP;
- issuer rotation and retirement;
- certificate-to-entity resolution;
- authorization, tenant isolation, and durable audit.

Atom PKI is not a general secrets manager and does not attempt to reproduce the
full feature surface of OpenBao or Vault.

---

## Trust Hierarchies

### Manual tenant provisioning

```text
Offline Root CA
├── Tenant A Intermediate CA (pathLen=0)
├── Tenant B Intermediate CA (pathLen=0)
└── Tenant C Intermediate CA (pathLen=0)
```

The Atom signer generates a tenant intermediate key and CSR. An offline operator
signs the CSR with the root and imports the signed certificate. The root key never
enters Atom.

### Automated tenant provisioning

```text
Offline Root CA
└── Atom Platform Intermediate CA
    ├── Tenant A Intermediate CA (pathLen=0)
    ├── Tenant B Intermediate CA (pathLen=0)
    └── Tenant C Intermediate CA (pathLen=0)
```

The offline root signs the platform intermediate once. A separately authorized
CA-provisioning operation uses that platform intermediate to sign tenant CA CSRs.
The platform intermediate is not a leaf issuer.

The direct-root hierarchy is appropriate for a small, manually provisioned set of
tenants. The platform-intermediate hierarchy is appropriate when tenant creation
must be automated.

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
  -> select active tenant authority
  -> canonicalize certificate profile
  -> internal signer/key provider
  -> verify signed artifact
  -> commit credential + audit/event
```

The first implementation may use an in-process encrypted-database provider. The
interface must also permit a later `atom-pki-signer` process, PKCS#11/HSM, or KMS
without changing the public certificate APIs.

No request may supply a raw key reference, CA path, or arbitrary issuer. Atom
selects the issuer from the target entity's `tenant_id`.

---

## Authority Registry

`pki_authorities` stores public CA metadata, lifecycle state, hierarchy, and an
opaque private-key backend reference.

Kinds:

```text
root
platform_intermediate
tenant_intermediate
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
file
pkcs11
kms
```

Static database invariants include:

- a root is global and parentless;
- a platform intermediate is global and has a parent;
- a tenant intermediate belongs to exactly one tenant and has a parent;
- only an active tenant intermediate with a signing backend may issue leaves;
- one tenant has at most one authority enabled for new leaf issuance;
- old issuer versions remain addressable while certificates issued by them exist;
- encrypted key material and external key references are mutually exclusive.

The registry never stores a plaintext CA private key.

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

### External signer providers

PKCS#11 and KMS providers store only an opaque key reference in Atom. The private
key never leaves the provider.

---

## Leaf Certificate Profile

The default Atom machine-client profile is fixed by the platform:

```text
BasicConstraints: CA=false
KeyUsage: digitalSignature
ExtendedKeyUsage: clientAuth
URI SAN: urn:atom:tenant:<tenant-id>:entity:<entity-id>
```

A separate server profile may add `serverAuth`; client and server usage must not
be combined by default.

A CSR is an input public key, not a policy document. Atom verifies its signature
and then forces the canonical profile. The CSR cannot select:

- `CA=true`;
- `keyCertSign` or `cRLSign`;
- another tenant or entity identity;
- arbitrary EKUs or custom extensions;
- an issuer;
- validity beyond platform or issuer limits.

Device-generated CSR issuance is preferred because the leaf private key never
enters Atom. Generated-key bootstrap returns the private key once and stores only
the certificate credential.

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
```

It verifies certificate status, expiry, issuer status, entity status, tenant
status, fingerprint, and an optional expected tenant. Magistrala must compare the
resolved tenant with the domain being accessed before calling normal Atom
authorization.

---

## Rotation

Tenant issuer rotation is an explicit handover:

```text
1. Create tenant CA v2 in provisioning state.
2. Produce/import its signed CA certificate and verify the chain.
3. Set v1 to retiring and disable new issuance.
4. Set v2 active and enable new issuance.
5. Issue all new and renewed leaves under v2.
6. Continue serving v1 chain, CRL, and OCSP.
7. Retire v1 only after its last leaf expires plus the retention window.
```

The database permits multiple historical authority versions but enforces one
issuer enabled for new leaves per tenant.

---

## Revocation, CRL, and OCSP

Revocation state belongs to the certificate credential and its issuer. CRL cache
state is issuer-specific; revoking one tenant certificate must not dirty every
other tenant CRL.

Issuer-specific public routes will replace the global v1 artifact assumption:

```text
GET  /certs/issuers/{issuer_id}/ca-chain.pem
GET  /certs/issuers/{issuer_id}/crl
POST /certs/issuers/{issuer_id}/ocsp
```

The current global routes remain available for the legacy file issuer during the
migration period.

Runtime services do not have to wait for CRL or OCSP publication. Atom's direct
certificate resolver denies a revoked or revocation-pending credential
immediately.

---

## Migration

1. Represent the existing v1 file issuer as the legacy `issuer_id = NULL` namespace.
2. Add the authority registry and issuer-aware uniqueness without changing v1 signing.
3. Add a Rust signer/key-provider abstraction.
4. Add root/platform/tenant CA provisioning lifecycle.
5. Route new leaf issuance through the target tenant's active authority.
6. Add issuer-aware runtime resolution and public artifacts.
7. Renew legacy certificates into tenant issuers.
8. Retire the global issuer only after the last legacy leaf expires.

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
