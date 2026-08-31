# PKI Definition of Done

A PKI PR is ready for merge only when every applicable item is complete.

## Scope and design

- The implementation matches one numbered PR specification.
- Dependencies are merged.
- Out-of-scope work is not included.
- The capability falls inside the PRD's scope section, or product review has approved widening it.
- No downstream product's vocabulary appears in schema, code, configuration, API fields, profile names, or tests.
- Consumer-specific behavior is expressed as profile data, not as a code branch.
- Architecture changes are reflected in the PRD and roadmap.
- Security-sensitive decisions are explained in the PR description.

## Code quality

- `cargo fmt --all -- --check` passes.
- `cargo clippy --all-targets --all-features -- -D warnings` passes using the repository's supported invocation.
- All test binaries compile.
- No new unsafe code without explicit review.
- No plaintext secret appears in logs, errors, serialization, fixtures, or snapshots.
- Library-specific crypto types do not leak across the intended abstraction boundary.

## Database and migration

- Migration applies to an empty database.
- Migration applies to a database containing representative legacy certificates.
- Existing migrations are not rewritten after release unless repository policy explicitly permits it.
- New uniqueness, FK, trigger, purge, and cascade behavior has integration coverage.
- Roll-forward recovery is documented if SQL migration rollback is not supported.
- Tenant purge and retention semantics are tested.

## Functional testing

- Unit tests cover domain invariants and failure states.
- PostgreSQL integration tests cover tenant isolation.
- Cross-tenant negative tests exist.
- Legacy compatibility tests exist where behavior is retained.
- Rotation or lifecycle transitions are tested when relevant.
- API/gRPC contracts and generated docs are updated when changed.
- External interoperability tests are included for X.509, CRL, or OCSP changes.

## Security testing

- Caller cannot choose another tenant's issuer.
- A global entity is issued only by the platform leaf issuer, and a tenant-owned entity only by its own tenant intermediate.
- Root and platform intermediate cannot issue leaves through normal leaf APIs.
- Deleting an authority cannot delete the certificates it issued.
- CSR cannot elevate constraints or identity.
- Expired, revoked, disabled, unknown, or mismatched authorities fail closed.
- Error paths do not leak private key material.
- Concurrency tests cover one-active-issuer and rotation handover where applicable.

## Operations

- Configuration variables are documented.
- Startup validation fails clearly for missing or invalid key configuration.
- Metrics and structured logs expose operation outcome without secrets.
- Backup, restore, rotation, and incident behavior are updated when relevant.
- No deployment requires OpenBao.

## Documentation and review

- The relevant PR specification is marked implemented or updated with deviations.
- Public/operator documentation is updated.
- CI is green.
- Required security/database/integration reviewers have approved.
- Review comments are resolved with code or documented rationale.

## Merge evidence

The PR description must include exact test commands and results, migration impact, backward-compatibility statement, and the next roadmap PR unlocked by the merge.