# PR-001 — Authority Registry Foundation

## Status

Implemented by PR #44. **Required corrections outstanding** — see below. They are
schema-level and this migration is unreleased, so they are applied in place rather
than deferred to a follow-up migration.

## Objective

Add the persistent, typed foundation for versioned root, platform-intermediate,
platform-leaf-issuer, and tenant-intermediate authorities without changing the v1
signing runtime.

## Scope

- `pki_authorities` hierarchy, lifecycle, validity, and key-backend metadata.
- `credentials.issuer_id` linkage.
- global fingerprint uniqueness.
- issuer-scope database enforcement for tenant-owned and global subjects.
- CRL-state issuer linkage.
- read-side Rust types and selectors.
- architecture and implementation documentation.

## Compatibility boundary

- v1 credentials keep `issuer_id = NULL`.
- global serial uniqueness remains while live readers use serial alone.
- current file issuer and public routes remain unchanged.

## Required corrections

Each item states the defect, why it matters, and the required end state.

### 1. Certificate credentials must not cascade from their authority

`credentials.issuer_id` currently uses `ON DELETE CASCADE`. Deleting one authority
row therefore deletes every certificate credential it issued — the same rows its
CRL is built from and the record of what it ever attested to. The CA-management
API arriving in PR-003 makes authority deletion reachable from application code,
so this is not a theoretical operator-SQL hazard.

Required: `ON DELETE RESTRICT`, plus an explicit ordered deletion in hard tenant
purge (credentials, then authorities, then the tenant) so the existing acceptance
criterion "hard tenant purge is not permanently blocked by authority rows"
continues to hold. Relying on cascade ordering between sibling FK paths is not
sufficient; the order must be explicit in `purge_tenant_with_audit`.

CRL cache state may keep `ON DELETE CASCADE` — it is a regenerable cache, and the
authority is already protected by the credential RESTRICT.

### 2. Entity tenant reassignment must not orphan the issuer binding

`trg_credentials_certificate_issuer_tenant` fires only on writes to `credentials`.
`entities.tenant_id` is updatable, so moving an entity between tenants leaves its
certificates pointing at a foreign tenant's issuer with no write to notice — the
isolation invariant is silently violated after the fact.

Required: a `BEFORE UPDATE OF tenant_id` trigger on `entities` that rejects the
change while the entity holds any certificate credential with a non-null
`issuer_id`. A certificate binds an identity to a tenant; changing the tenant
invalidates that binding, so the certificates are revoked first and the move
follows.

### 3. Global entities need a leaf issuer

The current constraint set requires a non-legacy certificate's subject to have a
tenant and its issuer to be a `tenant_intermediate`. Entities with
`tenant_id IS NULL` — internal services, platform workloads, global human
entities — therefore cannot hold a non-legacy certificate at all. Internal
service-to-service mTLS is precisely this case, so the model as written excludes
one of its primary consumers and contradicts the plan to retire the global file
issuer.

Required: a fourth authority kind `platform_leaf_issuer` — global, parented,
leaf-issuing — with:

- the scope CHECK extended to permit it;
- the leaf-issuance CHECK permitting `tenant_intermediate` and
  `platform_leaf_issuer`, and still never a root or platform intermediate;
- a partial unique index enforcing at most one enabled platform leaf issuer
  globally (a partial unique index on `tenant_id` cannot express this, because
  NULLs do not collide);
- the issuer-scope trigger extended so a global entity's certificate must
  reference the platform leaf issuer, and a tenant-owned entity's must reference
  its own tenant intermediate;
- a matching read-side selector, so issuance resolves the issuer from the
  subject's tenant scope through one function rather than branching at call sites.

It is a separate kind from `platform_intermediate` on purpose: the key that signs
tenant CAs must not also be the high-volume key that signs workload leaves.

### 4. Hierarchy rules that a row-local CHECK cannot express

Nothing currently prevents a `tenant_intermediate` from being parented by another
`tenant_intermediate`, which breaks the `pathLen=0` intent at the data layer, and
nothing prevents a child CA from outliving its parent — certificates that stop
verifying the day the parent expires.

Required: a `BEFORE INSERT OR UPDATE` trigger on `pki_authorities` enforcing that
the parent is a root or platform intermediate, that a platform intermediate is
parented by a root, and that the child's validity window falls inside the parent's.

### 5. Remove the `file` key backend

A CA key path stored in a database row is a key location chosen by whoever can
write that row — the caller-selected key reference the architecture forbids. It
also has no user: the legacy file issuer stays outside the registry as the
`issuer_id = NULL` namespace and is retired by renewal, not by import.

Required: drop `file` from the `key_backend` CHECK, from the key-storage CHECK,
and from `AuthorityKeyBackend`. Development deployments use `encrypted_database`
with a development KEK once PR-002 lands; until then no registry row can sign.

### 6. `AuthorityRecord` must not derive `Debug`

The struct holds `encrypted_private_key`, `wrapped_dek`, and their nonces. A
derived `Debug` prints all of it into any log line, span, or error that formats a
record — the DoD rule that key material never reaches observable output is
violated by the foundation itself.

Required: a hand-written `Debug` that reports presence rather than bytes for every
key-material column.

## Acceptance criteria

- Root is global and parentless.
- Platform intermediate is global, parented by a root, and cannot issue leaves.
- Platform leaf issuer is global, parented, and issues leaves only for entities
  with no tenant.
- Tenant intermediate is tenant-scoped and parented.
- Only a root or platform intermediate may parent an authority.
- A child authority's validity falls inside its parent's validity window.
- Only an active leaf-issuing authority with a signing backend may enable leaf
  issuance.
- One tenant has at most one issuer enabled for new leaves; at most one platform
  leaf issuer is enabled globally.
- A tenant-owned entity's non-legacy certificate matches its tenant's
  intermediate; a global entity's matches the platform leaf issuer.
- An entity holding issuer-bound certificates cannot change tenant.
- Root and platform intermediates cannot be attached to leaf credentials.
- Deleting an authority that still has certificate credentials fails.
- Hard tenant purge succeeds and is not permanently blocked by authority rows.
- No `file` key backend exists in schema or Rust.
- No key material appears in `Debug` output.
- Existing v1 tests pass unchanged.
- CI format, clippy, compilation, migrations, and PostgreSQL tests pass.

## Mandatory tests

Authority shape per kind, parent-kind rejection, validity containment rejection,
active issuer selection for tenant and global scope, rotation handover,
one-enabled platform leaf issuer, fingerprint collision, serial compatibility,
cross-tenant issuer rejection, global-entity issuer rejection, root/platform leaf
rejection, authority delete blocked by credentials, entity tenant-move rejection,
and tenant purge.

## Out of scope

Key generation, key encryption, CA APIs, tenant issuance, resolver changes,
CRL/OCSP route changes, certificate profiles, enrollment.

## Next

Unlocks PR-002 and PR-004.
