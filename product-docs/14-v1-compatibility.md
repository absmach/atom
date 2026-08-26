# v1 compatibility contract

## Status: Release gate

Atom v1 freezes its external API at tag `v1.0.0`. The canonical contract
artifacts are:

- `apidocs/openapi.yaml` for the mounted HTTP routes and DTOs;
- `apidocs/graphql-schema.graphql` for the complete GraphQL type system;
- `proto/atom/v1/atom.proto` for Atom's gRPC services.

After `v1.0.0`, those v1 artifacts are immutable. Bug fixes may change an
implementation only when accepted requests, response shapes, status/error
semantics, authentication requirements, field and enum meanings, and stored
data meanings remain compatible. A necessary contract change belongs in a new
versioned API rather than an edit to v1.

The password-reset request contains only `email`. Atom always constructs its
link from `ATOM_PASSWORD_RESET_REDIRECT`; callers cannot select a redirect.
The removed legacy `CertificateService.ResolveCertificate` RPC is not part of
v1. Consumers use `ResolveCertificateV2`.

## Database upgrade boundary

The oldest supported in-place upgrade to v1 is `v0.50.0`. Earlier database
releases are not a supported direct upgrade source. Move their data into a
clean, v0.50-compatible database through a separately qualified export/import
process before upgrading to v1.

The four migrations shipped by v0.50.0 are pinned in
`api/v1/migrations-v0.50.0.sha384`. CI verifies those exact checksums. Once
`v1.0.0` is tagged, `scripts/check-v1-contracts.sh` also rejects edits or
deletions of every SQL migration present in that tag while allowing new,
forward-only migrations.

Persisted enum strings, action names, object/scope encodings, ABAC condition
syntax, bootstrap YAML fields, custom endpoint definitions, and event envelope
semantics are storage or integration contracts. Evolving one requires a new
migration and, where readers and writers can overlap during rollout, a
compatible expand/backfill/contract sequence. Never rewrite an applied
migration.

## Release verification

Before tagging v1:

1. Run the API documentation workflow and `scripts/check-v1-contracts.sh`.
2. Upgrade a populated v0.50.0 database and run all DB-gated tests.
3. Run the same release image against a fresh database.
4. Complete PKCS#11 recovery, PKI smoke, and image-build jobs at the exact tag
   commit.

After tagging, CI compares the three API artifacts to `v1.0.0`, runs Buf's
breaking-change detector, and checks every released migration for immutability.
