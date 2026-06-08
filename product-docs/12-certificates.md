# Atom Certificates

## Status: Active v1
## Date: 2026-06-07

This document defines Atom-native certificate credentials. Magistrala's certs service is a reference for capabilities, not a service boundary. Atom owns certificate lifecycle, revocation state, public PKI endpoints, and runtime certificate identity lookup.

---

## Architecture Summary

Atom issues certificates from operator-supplied CA files.

- Atom does not generate a root CA or intermediate CA.
- Atom does not store CA certificates or CA private keys in Postgres.
- Atom loads issuer CA files once during startup and keeps the parsed issuer in process memory.
- Atom issues generated certificates or signs CSRs for Atom entities.
- Issued leaf certificates are stored as Atom credentials, so listing, authorization, revocation, and audit stay in the normal Atom credential model.
- Generated leaf private keys are shown once and are never stored; CSR private keys never enter Atom.
- Public PKI artifacts are served by Atom through CA chain, CRL, and OCSP endpoints.
- Runtime services extract the client certificate serial and optional fingerprint during mTLS and ask Atom gRPC to resolve that certificate to an active entity.
- There is no OpenBao dependency, no standalone Magistrala certs service, and no legacy Magistrala certificate storage boundary.

v1 uses one global file issuer for the Atom instance. Per-tenant issuer selection and trust-only `file_trust` mode are out of scope.

---

## Issuer Modes

Atom supports only issuer-capable file modes in v1.

### `file_intermediate_issuer`

Recommended for production.

Required files:

- `ATOM_CERTS_ROOT_CA_CERT_PATH`
- `ATOM_CERTS_INTERMEDIATE_CA_CERT_PATH`
- `ATOM_CERTS_INTERMEDIATE_CA_KEY_PATH`

Atom signs leaf certificates, CRLs, and OCSP responses with the intermediate private key. The public CA chain is published as `intermediate + root`.

### `file_root_issuer`

Supported for local/dev or deployments where only root CA material exists.

Required files:

- `ATOM_CERTS_ROOT_CA_CERT_PATH`
- `ATOM_CERTS_ROOT_CA_KEY_PATH`

Atom signs directly with the root private key. The public CA chain is published as `root`.

This mode is less safe for production because the root private key is mounted into Atom. Prefer `file_intermediate_issuer` so the root private key can stay offline.

---

## Startup Validation

When `ATOM_CERTS_ENABLED=true`, Atom fails startup if issuer files are missing, unreadable, malformed, expired, mismatched, or invalid for the selected mode.

Validation includes:

- required path variables are set for the selected mode;
- issuer certificate is CA-capable;
- issuer certificate key usage allows certificate and CRL signing when key usage is present;
- private key public component matches the issuer certificate;
- root issuer is self-signed in `file_root_issuer`;
- intermediate issuer is signed by the configured root certificate in `file_intermediate_issuer`;
- leaf default/max TTL configuration cannot request a certificate beyond issuer validity during issuance.

File contents are read once at startup. Requests do not reread private key files.

Example production config:

```text
ATOM_CERTS_ENABLED=true
ATOM_CERTS_CA_MODE=file_intermediate_issuer
ATOM_CERTS_ROOT_CA_CERT_PATH=/certs/root-ca.crt
ATOM_CERTS_INTERMEDIATE_CA_CERT_PATH=/certs/intermediate-ca.crt
ATOM_CERTS_INTERMEDIATE_CA_KEY_PATH=/certs/intermediate-ca.key
ATOM_CERTS_LEAF_DEFAULT_TTL_SECS=2592000
ATOM_CERTS_LEAF_MAX_TTL_SECS=2592000
```

Example local/dev root issuer config:

```text
ATOM_CERTS_ENABLED=true
ATOM_CERTS_CA_MODE=file_root_issuer
ATOM_CERTS_ROOT_CA_CERT_PATH=/certs/root-ca.crt
ATOM_CERTS_ROOT_CA_KEY_PATH=/certs/root-ca.key
```

---

## Model

A certificate credential belongs to an Atom entity and is stored in `credentials` with:

- `kind = certificate`
- `identifier = normalized certificate serial number`
- `secret_hash = null`
- `entity_id = owner entity id`
- `expires_at = certificate not-after timestamp`
- `metadata` containing certificate PEM, subject, SANs, issuer kind, issuer subject, issuer serial number, issuer DER SHA-256 fingerprint, leaf DER SHA-256 fingerprint, validity, revocation time, and revocation reason.

Issued leaf private keys are never stored. When Atom generates a leaf keypair, the private key is returned once in the issuance response.

---

## Storage and Retrieval

Atom stores issued certificate state in Postgres.

| Table | Purpose |
|---|---|
| `credentials` | Issued leaf certificates. Certificate rows use `kind = certificate`; `identifier` is the normalized serial number; `metadata` stores the certificate PEM and certificate attributes. |
| `certificate_crl_state` | Cached CRL state keyed by `issuer_fingerprint_sha256`: CRL number, cached CRL DER, `thisUpdate`, `nextUpdate`, dirty flag, and update timestamp. |
| `entities` | Owner/subject entity for issued certificates through `credentials.entity_id`. |
| `actions` and `action_applicability` | Authorization metadata for credential `read`, `manage`, `rotate`, and `revoke`. |

There is no `certificate_authorities` table in v1 file issuer mode. CA files are deployment inputs, not database records.

An issued certificate PEM is retrievable after issuance through GraphQL:

- `certificate(serialNumber)` returns one certificate.
- `certificates(entityId, tenantId, status)` lists matching certificates.
- `caChain` returns the public CA chain.

The same public CA material is available through `GET /certs/ca-chain`. CRL and OCSP material are available through `GET /certs/crl` and `POST /certs/ocsp`.

Generated leaf private keys are not retrievable after issuance. Atom returns the generated leaf private key once as `privateKeyPem`; after that, Atom keeps only the certificate record. CSR-issued certificates never expose a private key to Atom, so there is no private key to return.

Useful operational queries:

```sql
-- List issued certificate credentials.
SELECT id,
       entity_id,
       identifier AS serial_number,
       status,
       expires_at,
       metadata->>'issuer_kind' AS issuer_kind,
       metadata->>'issuer_fingerprint_sha256' AS issuer_fingerprint_sha256,
       metadata->>'fingerprint_sha256' AS fingerprint_sha256
FROM credentials
WHERE kind = 'certificate'
ORDER BY created_at DESC;

-- Retrieve one issued certificate PEM by serial number.
SELECT metadata->>'certificate_pem' AS certificate_pem
FROM credentials
WHERE kind = 'certificate'
  AND identifier = '<serial-number>';

-- Inspect cached CRL state per mounted issuer.
SELECT issuer_fingerprint_sha256,
       crl_number,
       this_update,
       next_update,
       dirty
FROM certificate_crl_state;
```

---

## Lifecycle

Atom supports:

- generated certificate issuance for an entity;
- CSR signing for an entity;
- certificate listing and viewing;
- renewal by serial number;
- serial revocation;
- entity-wide certificate revocation;
- CA chain publication;
- CRL publication;
- OCSP responses;
- runtime serial-to-entity lookup.

Renewal creates a new certificate and serial number. The old certificate remains valid until expiry unless the caller requests old-certificate revocation.

CSR signing verifies the CSR and signs the CSR public key. Atom does not store or return a private key for CSR-issued certificates.

CSR-issued certificates are forced to non-CA leaf certificates with `digitalSignature` key usage and `clientAuth` extended key usage. Atom does not trust CSR CA/basic-constraint requests.

Requested TTL values above `ATOM_CERTS_LEAF_MAX_TTL_SECS` are rejected. Atom also rejects issuance when requested leaf validity would exceed the loaded issuer certificate validity. Generated leaf certificates use a five-minute negative `notBefore` skew to tolerate small clock differences.

Certificate serial numbers are normalized lowercase hex. Atom retries serial generation on unique collisions.

Certificate fingerprints are SHA-256 over certificate DER, not over PEM text.

---

## Interfaces

GraphQL management APIs expose:

- `certificates`
- `certificate`
- `caChain`
- `issueCertificate`
- `issueCertificateFromCsr`
- `renewCertificate`
- `revokeCertificate`
- `revokeEntityCertificates`

Public PKI endpoints expose standard unauthenticated artifacts:

- `GET /certs/ca-chain`
- `GET /certs/crl`
- `POST /certs/ocsp`

Runtime services use Atom gRPC:

- `CertificateService.ResolveCertificate`
- `CertificateService.RevokeEntityCertificates`

HTTP GraphQL remains bearer-token based. Client TLS termination and certificate extraction are handled by the runtime service, which then asks Atom to resolve the serial and optional fingerprint.

Runtime certificate lookup is authorization-gated. A caller of `ResolveCertificate` must authenticate to Atom and hold `authz.check` on the resolved certificate tenant or platform.

---

## Authorization

Certificate operations use Atom credential authorization:

- Issue: credential `manage` on the target entity.
- View/list: credential `read` or `manage`.
- Renew: exact credential `rotate` or `manage`; target entity credential `manage` also allows it.
- Revoke: exact credential `revoke` or `manage`; target entity credential `manage` also allows it.
- Runtime resolve: `authz.check` on the resolved tenant or platform.
- CA chain, CRL, and OCSP are public.

Credential authority follows the target entity's `tenant_id`, not tenant membership. Tenant admins may manage certificates only for tenant-owned entities in their tenant unless explicit platform policy delegates authority.

The GraphQL certificate list supports optional `entityId`, `tenantId`, and `status` filters. Platform readers/managers can list globally; tenant readers/managers can list tenant-owned certificate credentials.

---

## Revocation, CRL, and OCSP

Revocation updates the credential status to `revoked`, writes revocation metadata, and marks CRL state dirty.

Atom issues the CRL for the loaded file issuer because Atom owns the issued leaf certificate records and their revocation state. The external CA operator owns the root/intermediate CA material and any upstream CA revocation outside Atom.

CRL responses are DER-encoded and cached in Postgres per issuer fingerprint. Atom regenerates the CRL only when:

- a certificate was revoked;
- entity-wide revocation changed certificate state;
- the cached CRL is missing;
- the cached CRL reached `nextUpdate`;
- mounted issuer files changed and Atom restarted with a different issuer fingerprint.

CRL regeneration uses a Postgres advisory transaction lock so concurrent Atom replicas do not race CRL numbers.

OCSP responses validate the request issuer name/key hashes against the loaded file issuer. Requests with mismatched issuer hashes return `unknown` for that certificate. Malformed OCSP requests receive DER OCSP non-success responses rather than JSON API errors.

---

## Rotation and Limits

CA rotation beyond replacing the active mounted issuer files is not part of v1.

If mounted issuer files are replaced, Atom must be restarted to load the new issuer. CRL cache entries are separated by issuer fingerprint, and new certificates include the new issuer metadata. Operators must keep old CA material and trust chains available long enough for previously issued certificates and CRLs to remain externally verifiable.

v1 does not support:

- per-tenant CA selection;
- trust-only CA bundles with no issuer private key;
- HSM/KMS-backed CA custody;
- automatic root/intermediate generation;
- CA private key storage in Postgres.

---

## Magistrala Alignment

Magistrala clients may authenticate with Atom API keys or Atom certificates. Former Magistrala certificate service behavior is moved into Atom:

- certificate issuance and CSR signing happen in Atom;
- revocation state lives in Atom credentials;
- CRL and OCSP are served by Atom;
- runtime services resolve certificate serials through Atom gRPC.

Magistrala should not run a separate certs service or OpenBao deployment for Atom-owned identity.
