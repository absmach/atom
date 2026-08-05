# Atom-Native PKI Test Plan

## Test principles

PKI tests must prove tenant isolation, cryptographic correctness, lifecycle behavior, backward compatibility, and failure safety. Happy-path issuance alone is insufficient.

## Layers

### Unit tests

Cover:

- authority hierarchy validation;
- status transitions;
- profile construction;
- CSR normalization and rejected extensions;
- validity calculations;
- serial normalization;
- issuer selection;
- key-provider error mapping;
- zeroization wrappers where testable;
- CRL and OCSP status mapping.

### PostgreSQL integration tests

Cover:

- one active leaf issuer per tenant, and one active platform leaf issuer globally;
- authority version uniqueness;
- entity/issuer scope equality, for tenant-owned and global entities;
- parent-kind rejection and parent/child validity containment;
- root/platform-intermediate issuer rejection for leaf credentials;
- authority deletion blocked while its certificates exist;
- entity tenant reassignment blocked while issuer-bound certificates exist;
- credential fingerprint uniqueness;
- legacy `issuer_id = NULL` behavior;
- serial uniqueness before resolver-v2 cutover;
- issuer-plus-serial uniqueness after cutover;
- tenant hard purge and retention behavior;
- transaction rollback on signing/persistence failure;
- concurrent rotation attempts.

### API and authorization tests

For GraphQL/gRPC/public routes verify:

- unauthenticated denial;
- caller lacks credential management permission;
- caller from tenant A targets tenant B entity;
- caller cannot submit issuer/key backend/path;
- tenant inactive/frozen/deleted;
- entity inactive/suspended/deleted;
- issuer provisioning/retiring/expired/revoked;
- audit and outbox outcome.

### Cryptographic interoperability

Use OpenSSL or another independent implementation to verify:

- complete chain;
- tenant CA and platform leaf issuer `CA=true`, `keyCertSign`, `cRLSign`, `pathLen=0`;
- leaf `CA=false`;
- client leaf contains `clientAuth` only by default;
- a combined client/server leaf is produced only from an explicit profile;
- URI SAN contains canonical tenant and entity IDs, or the global form;
- AIA and CRL distribution point extensions resolve to the issuing authority's routes;
- certificate signature and validity;
- CSR signature verification;
- CRL signature, number, update times, reason codes, and revoked serial;
- OCSP good/revoked/unknown responses, reason codes, nonce, and signature **under
  every supported issuer key algorithm** — an algorithm identifier that does not
  match the signing key produces responses that verify only by accident.

### Runtime tests

Verify:

- fingerprint resolves exact credential;
- issuer plus serial resolves exact credential;
- duplicate serial across two issuers never cross-resolves;
- expected tenant mismatch is denied;
- revocation-pending and revoked are denied immediately;
- old issuer certificates remain valid during rotation;
- retired issuer cannot issue new leaves;
- a global entity resolves with no tenant and does not acquire tenant scope;
- a relying party's tenant-scope mismatch is denied before authorization;
- a subject can re-enroll using only the certificate being replaced;
- an expired subject cannot re-enroll and follows the documented recovery path;
- a certificate entering its renewal window emits exactly one event per window,
  across restarts and concurrent replicas.

### Failure-injection tests

Simulate:

- key provider unavailable;
- KEK missing or wrong;
- corrupted encrypted key blob;
- signer timeout;
- database failure after signing;
- process restart during provisioning or rotation;
- duplicate serial retry;
- clock skew around validity boundaries;
- CRL/OCSP generation failure;
- HSM/KMS throttling or unavailable key.

## Required fixtures

Maintain deterministic public certificate fixtures only. Never commit production or reusable private keys. Test private keys must be generated per test or clearly marked non-production fixtures.

Required scenarios:

- legacy global issuer and leaf;
- root plus platform intermediate plus tenant A/B intermediates plus platform leaf issuer;
- an ECDSA issuer and an RSA issuer, so algorithm-identifier defects cannot hide
  behind a single development CA;
- tenant A issuer v1 and v2 rotation;
- same serial under tenant A and tenant B issuers;
- a global entity and its certificate;
- revoked and expired leaves;
- malformed and privilege-escalating CSRs.

## Performance checks

Measure:

- issuance latency excluding external HSM/KMS variance;
- resolver latency under expected connection volume;
- CRL generation with representative revocation counts;
- startup behavior with many tenant authorities;
- memory behavior proving all tenant keys are not decrypted/preloaded.

Performance thresholds must be documented in the implementing PR rather than guessed globally.

## Regression rule

No PR may relax a foundation invariant until its replacement lookup/API path is merged and regression tests prove both legacy and new behavior during the transition.