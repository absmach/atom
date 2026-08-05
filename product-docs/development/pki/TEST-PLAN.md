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

- one active leaf issuer per tenant;
- authority version uniqueness;
- entity/issuer tenant equality;
- root/platform issuer rejection for leaf credentials;
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
- tenant CA `CA=true`, `keyCertSign`, `cRLSign`, `pathLen=0`;
- leaf `CA=false`;
- client leaf contains `clientAuth` only by default;
- URI SAN contains canonical tenant and entity IDs;
- certificate signature and validity;
- CSR signature verification;
- CRL signature, number, update times, and revoked serial;
- OCSP good/revoked/unknown responses and signature.

### Runtime tests

Verify:

- fingerprint resolves exact credential;
- issuer plus serial resolves exact credential;
- duplicate serial across two issuers never cross-resolves;
- expected tenant mismatch is denied;
- revocation-pending and revoked are denied immediately;
- old issuer certificates remain valid during rotation;
- retired issuer cannot issue new leaves;
- Magistrala domain mismatch is denied before authorization.

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
- root plus platform plus tenant A/B intermediates;
- tenant A issuer v1 and v2 rotation;
- same serial under tenant A and tenant B issuers;
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