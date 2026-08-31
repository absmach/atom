# AI-Assisted PKI Development Guidelines

These rules apply to human developers, coding agents, and review agents.

## Before coding

The agent must read the architecture PRD, roadmap, this file, the selected PR specification, the repository `AGENTS.md`, and existing certificate tests. It must inspect the current implementation because file names and interfaces may have changed after this document was written.

## Allowed behavior

- Implement only the selected PR scope.
- Refactor locally when required to create the specified boundary.
- Add tests, documentation, metrics, and error handling needed by the acceptance criteria.
- Propose an architecture-document update when facts found in code contradict the plan.

## Forbidden behavior

The agent must never:

- add OpenBao, Vault, or another external PKI as a hidden dependency;
- recreate `absmach/certs` as an independent source of truth;
- store or log plaintext CA private keys;
- place the production root private key in Atom configuration, database, container, or runtime memory;
- accept issuer IDs, CA paths, key references, tenant identities, CA constraints, or privileged EKUs directly from untrusted requests;
- trust CSR extensions as policy;
- combine `clientAuth` and `serverAuth` by default, or hardcode a rule that makes an explicit combined profile impossible — mutually authenticated service-to-service mTLS legitimately needs one;
- accept a free-form DNS SAN from a caller;
- name a downstream product in schema, code, configuration, API fields, profile names, or tests;
- express a consumer-specific requirement as a code branch instead of profile data;
- issue a certificate for a subject that is not an Atom entity;
- delete an authority row in a way that removes the certificates it issued;
- trust a proxy-asserted client identity in place of a client certificate the process verified itself;
- put enrollment logic inside a protocol adapter, or protocol handling inside the enrollment service;
- identify a certificate globally by serial alone after duplicate issuer serials are enabled;
- weaken an existing database constraint without first migrating all dependent readers and adding regression tests;
- use a second pool connection while a transaction is open;
- publish an event outside the mutation transaction when Atom conventions require an outbox row;
- modify unrelated authorization behavior;
- add TODO-only implementations or mock production cryptography;
- suppress failing tests or reduce test coverage to make CI pass.

## Cryptographic rules

- Use maintained libraries already approved by the project where possible.
- Keep library-specific types behind Atom-owned interfaces.
- Validate issuer certificate constraints before signing; do not assume the signing library enforces them.
- Use cryptographically secure randomness for keys, serials, nonces, and DEKs.
- Zeroize plaintext private-key buffers where the chosen types permit it.
- Never include secrets in `Debug`, `Display`, serde output, GraphQL types, audit details, events, or tracing spans.
- Fail closed when issuer state, tenant state, key backend, validity, or chain verification is uncertain.

## Consumer-neutrality rules

Atom PKI serves several internal platforms. None of their concepts may enter Atom.

- Atom's vocabulary is entity, tenant, credential, authority, profile.
- Atom emits `urn:atom:tenant:<tenant-id>:entity:<entity-id>`, or
  `urn:atom:entity:<entity-id>` for a global entity. Consumers map that to their
  own concepts; Atom does not learn what they mapped it to.
- Consumer-specific data belongs in `attributes.<consumer>`.
- A consumer's certificate requirement is a profile row. If it cannot be expressed
  as profile data, the profile model is missing a field — propose the field.

Review test: if a reviewer can tell which downstream product a PKI code path was
written for, the abstraction is wrong.

## Multi-tenancy rules

- Resolve the target entity first.
- Derive the tenant scope from the stored entity; `tenant_id IS NULL` is a valid
  scope meaning a global entity, not an error.
- Authorize against that entity and tenant.
- Resolve the active issuer from the derived scope through the shared selector,
  not by branching at the call site.
- Verify the authority matches the subject's scope: a tenant intermediate for the
  same tenant, or the platform leaf issuer for a global entity.
- Persist the issuer relationship in the same transaction as the certificate credential.
- Add database-level protection for invariants that imports or operator SQL could otherwise bypass.

## Compatibility rules

- Existing v1 credentials use `issuer_id = NULL` until migrated.
- Keep global serial uniqueness while any live reader resolves by serial alone.
- Do not remove global PKI artifact routes until issuer-specific routes and migration are complete.
- Do not silently change existing GraphQL or gRPC contracts; version or deprecate explicitly.

## Agent completion report

Every coding-agent response must state:

- files changed;
- acceptance criteria satisfied;
- commands/tests run and results;
- migrations added or changed;
- compatibility impact;
- security assumptions;
- unresolved risks or criteria not completed.

The agent must not claim success when it did not execute the relevant tests.