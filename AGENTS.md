# Atom — Identity & Authorization Service

Lightweight replacement for Keycloak — single Rust binary, single Postgres database. Built for Magistrala IoT platform but generic enough for any cloud-native system.

## Stack

- **Language:** Rust (edition 2021)
- **HTTP framework:** Axum 0.7
- **APIs:** GraphQL (async-graphql `=7.2.1`, depth/complexity/introspection limits) + gRPC (Tonic 0.12 + tonic-health). The legacy tenant Axum handlers are **unmounted** (see `routes.rs`); the dead authz REST handler module has been removed.
- **Database:** PostgreSQL via sqlx 0.8.6 (dynamic `query`/`query_as`; the `macros` feature is enabled only for `migrate!` — query macros are not used, so no compile-time DB is required)
- **Auth:** argon2 (password/API-key hashing); **ES256** JWTs via `p256` with `kid` rotation + JWKS (tokens carry identity/session, never permissions)
- **PKI:** `rcgen`/`ring`/`ocsp`/`x509-parser` (certificate issuance, CSR, renewal, CRL, OCSP)
- **Runtime:** Tokio (full features)
- **Testing:** `cargo test`; DB-gated integration tests in `tests/` are `#[ignore]` and run in CI against Postgres with `--include-ignored`

## Project Layout

```
src/
  main.rs              — startup: config, DB pool, migrations, admin bootstrap, router
  config.rs            — Config struct, reads env vars (incl. ADMIN_ENTITY_ID, ADMIN_SECRET)
  state.rs             — AppState (pool + config), cloned into every handler
  routes.rs            — live router: GraphQL, gRPC, auth/session REST, custom endpoints,
  │                       JWKS, health/live, health/ready, cert artifacts (rate-limit + CORS layers)
  error.rs             — AppError enum → HTTP responses; db_err() helper
  audit.rs             — fire-and-forget audit_logs writer; never fails the caller
  auth.rs              — ES256 verify, Bearer/cookie extraction, AuthContext extractor;
  │                       control-plane gates: has_capability_in_scope / require_any_capability /
  │                       require_read_access (over the canonical grant expansion);
  │                       RequireManage extractor + has_global_manage() helper
  keys.rs              — ES256 signing keys (primary/standby/retired), encryption at rest
  grpc.rs              — Tonic services: AuthService, AuthzService.Check, CertificateService
  graphql/             — schema + per-domain resolvers (the live admin/API surface)
  db.rs                — pool creation (configurable pool)
  models/
  │  enums.rs          — typed domain enums: EntityKind, EntityStatus, CredentialKind,
  │                       CredentialStatus, SubjectKind, GrantKind, ScopeKind, Effect,
  │                       AuditOutcome — all derive sqlx::Type + serde
  │  entity.rs, group.rs, resource.rs, role.rs, capability.rs,
  │  session.rs, token.rs, policy.rs — domain structs using the typed enums
  identity/
  │  mod.rs
  │  handlers.rs       — Axum handlers for auth + identity endpoints
  │  service.rs        — business logic; writes auth.login audit events
  │  repo.rs           — sqlx queries
  authz/
     mod.rs
     engine.rs         — PDP: batch-loads role capabilities, evaluates RBAC/ABAC,
     │                    deny-overrides-allow; unit-tested in #[cfg(test)]
     repo.rs           — sqlx queries; effective_grants_for_subject() wraps the
                          canonical subject_effective_grants() SQL function, shared
                          by the PDP and every authorized-listing reader
migrations/
  001_initial.sql      — full schema + action seeds and bootstrap access data
```

## Architecture Patterns

- **Layered:** handler → service/engine → repo. Handlers only do HTTP concerns; business logic lives in service/engine; repo only does DB.
- **AppState** is cheaply cloned (Arc internally via pool) and injected via Axum's `State` extractor.
- **Error handling:** `AppError` is the single error type across all layers. `db_err()` converts `RowNotFound` to `AppError::NotFound`. Postgres unique-violation (code 23505) maps to 409.
- **Typed enums:** all constrained domain fields (`EntityKind`, `Effect`, `ScopeKind`, etc.) are Rust enums deriving `sqlx::Type` + serde. Invalid values are rejected at deserialization — no manual validators in handlers.
- **No special user type:** every principal is an `Entity` with a `kind` field.
- **Online authorization:** tokens carry no permissions; every authz check (GraphQL `authzCheck` / gRPC `AuthzService.Check`) hits the DB, so revocation and policy changes take effect immediately.
- **One canonical grant expansion:** the `subject_effective_grants(uuid)` SQL function (in migration `001`) is the single "what does this subject hold" expansion for the *runtime* path. The PDP (`engine::evaluate`), `explain`, and the control-plane gates consume it through `repo::effective_grants_for_subject`; the authorized-listing readers (`authorized_object_ids` for entity/resource/group) select from it directly and filter candidates with the shared `grant_scope_matches(...)` SQL predicate, which mirrors the PDP's Rust `scope_values_match` (a parity test pins them together). The scope_mode→(scope_kind, scope_ref) mapping lives once in the `permission_block_scopes` view. Group membership is resolved recursively; each grant carries its own scope/effect/conditions. Do not reintroduce a per-reader flattener or a parallel listing evaluator. Every *subject-forward decision/visibility* reader is now on the canonical expansion: the entity/resource/group authorized listers, the tenant-listing visibility filter (`tenants::repo::list_tenants`), and the audit tenant-scoping filter (`tenant_ids_for_action_on_object_kind`). `effective_access_edges()` survives only where the canonical subject-forward expansion does not fit: the **reverse** assignment-time guardrail validators in `guardrails.rs` (which resolve role/group → affected subjects, the opposite direction), the **policy-object lookups** in `authz/repo.rs` (id → object kind / owning tenant, using the edge view as a convenience over `direct_policies`+`role_assignments`), and the **assignment-metadata** listers (`subject_role_assignments`, which list raw assignments, not effective access). Do not route a subject's effective-access decision through `effective_access_edges()`.
- **Audit log:** `audit::write()` is fire-and-forget — it logs failures but never propagates them to the caller. Called from service (login) and handlers (logout, credential ops, authz check).

## Authorization Model (PDP)

Atom's current product model is:

```text
Action = atomic operation
Action Applicability = where an action is valid
Permission Block = scope + actions + effect + conditions
Role = named collection of Permission Blocks
Role Assignment = subject gets a Role
Direct Policy = subject gets one Permission Block directly
```

Action naming is hybrid:
- real stored objects use generic actions, for example `read` on `audit_log`, `manage` or `revoke` on `credential`, `create` or `manage` on `tenant`, and `rotate` on `signing_key`;
- scoped access administration keeps explicit actions: `role.manage` manages roles for a Permission Block scope, and `policy.manage` adds/removes assignments for that scope;
- operation checks keep operation names such as `authz.check`.

Evaluation order in `authz/engine.rs` (`evaluate` and `explain` share one context loader, `load_decision_context`):
1. Load entity (must be active) and protected object; deny if the object's tenant is not active.
2. Resolve action by name and validate it through action applicability.
3. Build the canonical grant expansion (`effective_grants_for_subject`) — direct policies + role-linked blocks, group inheritance resolved recursively, each grant carrying its own scope/effect/conditions. One batched query, no per-binding round-trips.
4. For each grant: check assignment tenant boundary, block scope, action coverage, then ABAC conditions.
5. **First DENY match → return denied immediately.**
6. Any ALLOW match → allowed; otherwise → default deny.

ABAC conditions: flat JSON object, keys are dot-paths (`entity.*`, `resource.*`, `object.*`, `tenant.*`, `context.*`), all entries ANDed. Operators: literal equality plus `eq`/`neq`/`in`/`contains`/`gt`/`gte`/`lt`/`lte` (numbers and RFC-3339 timestamps). Empty `{}` always matches; **missing paths, unknown operators, and a non-object `conditions` value all fail closed.**

## Self-Authorization

The live GraphQL/gRPC surface wraps the PDP with imperative **control-plane gates** — administrative preconditions, not object-level decisions:

**Scope gates** (`auth.rs`) — `has_capability_in_scope` / `require_any_capability` / `require_read_access` evaluate the canonical grant expansion in memory: they honour the block's own scope and effect and resolve groups recursively. They **fail closed on ABAC conditions** (several callers use a gate as the final decision, e.g. `createEntity`, which has no object to re-check): only an *unconditional* allow satisfies a gate, and *any* matching deny — conditional or not — blocks it. Object-specific authorization must still call the PDP, which evaluates the conditions the gate ignores.

**`RequireManage` extractor + `has_global_manage`** (`auth.rs`) — still used by some GraphQL resolvers; checks whether the caller holds a platform-scoped `manage` allow (directly or via a role).

**Admin bootstrap** — migration `001_initial.sql` seeds:
- Entity `00000000-0000-0000-0000-000000000001` (`atom-admin`)
- Role `00000000-0000-0000-0000-000000000002` (`atom-admin`) with all seeded actions
- Role assignment: admin entity → admin role

Set `ADMIN_SECRET` on first boot to create the password credential for `atom-admin`. Subsequent restarts with the same env var are no-ops (credential already exists). To change the admin password, revoke the old credential via the API, then restart with the new secret.

## Database

- All PKs are UUIDs (`gen_random_uuid()` via pgcrypto).
- `entities` and `groups` have a composite unique index on `(name, tenant_id)` — name uniqueness is per-tenant.
- `actions` unique on `name`; `action_applicability` defines valid object kind/type pairs.
- Migrations are embedded in the binary at compile time via `sqlx::migrate!("./migrations")` and run automatically on startup (no runtime CWD dependency). New migrations go in `migrations/NNN_<name>.sql`; adding one requires a rebuild.
- **Soft delete:** entities, groups, roles, resources, and tenants carry a `deleted_at`/`deleted_by` tombstone. Delete mutations set the tombstone (they do not hard-`DELETE`) and fire immediate side effects (entity delete also marks `status = inactive` and revokes its credentials + sessions; tenant delete marks `status = deleted` and revokes child sessions). Group/role/resource soft delete leaves `status` unchanged. Every read/authz/listing/login query still filters `deleted_at IS NULL` — a new query over these tables must include it unless it intentionally exposes tombstones behind an admin-only deleted filter. Name/alias unique indexes are partial (`WHERE deleted_at IS NULL`) so names free on delete. Authorized listings also exclude objects whose owning tenant is not `active` (a soft-deleted/frozen/inactive tenant), matching the PDP's tenant-lifecycle deny. Physical removal is the `purge` background job (`src/purge.rs`, `ATOM_PURGE_*`, disabled by default) or the explicit admin `purge{Entity,Group,Resource,Role,Tenant}` mutations; all reuse FK cascades — tenant-owned groups/roles/resources are `ON DELETE CASCADE` (not `SET NULL`) so purging a tenant removes them rather than turning them into global rows. The per-type purge mutations physically delete a row that is **already soft-deleted** (they require `deleted_at IS NOT NULL` and refuse a live row), bypass the retention window, are **platform-admin only** and audit-logged (`*.purge` events), and are irreversible; `purgeRole` additionally GCs permission blocks left orphaned by the removal, mirroring the background job's `purge_roles`. Because `permission_blocks.object_id`, `direct_policies.subject_id`, and `role_assignments.subject_id` are bare UUIDs with **no foreign key**, every physical-removal path also deletes the authz rows that reference a purged id — object-scoped blocks granting access *on* it (which cascade to their actions, role links, and direct policies) and the direct policies / role assignments granting *to* it — through one canonical helper, `authz::repo::purge_authz_references_for_ids`, fed the full set of doomed UUIDs. All paths share it: the explicit `purge{Entity,Resource,Group,Role}` mutations (entity purge also folds in its cascaded credential ids; role purge covers the role *as an object*), `purgeTenant` and the background retention job (both first collect the tenant + all cascaded children — entities, their credentials, groups, roles, resources — via `tenants::repo::tenant_purge_object_ids`, then run the cleanup). A direct policy / role assignment is itself a protected object (`object_kind = 'policy'`, keyed by its row id), and it gets removed by many paths — direct/bulk delete and FK cascade from tenants, roles, and permission_blocks — so app-level capture at each call site is incomplete. Instead a DB trigger (`purge_blocks_targeting_policy`, defined in `migrations/001_initial.sql`) enforces the invariant: an `AFTER DELETE` trigger on `direct_policies`/`role_assignments` deletes `permission_blocks WHERE object_id = OLD.id` whenever a policy row is removed by **any** means (row-level triggers fire on cascade-deleted rows too); deleting those blocks cascades to the policies referencing them, re-firing the trigger to a fixpoint. So no dangling grant survives any purge, policy delete, member removal, or cascade — no application code needs to special-case the policy-object kind.
- **Restore (undelete):** while a row is still tombstoned (i.e. not yet purged), the `restore{Entity,Group,Resource,Role,Tenant}` mutations reverse the soft delete by clearing `deleted_at`/`deleted_by` (entity/tenant also re-set `status = active`; a restored role's permission blocks survived the delete, so its grants resume in the PDP immediately). The retention window is enforced implicitly — a purged row is gone, so anything still tombstoned is restorable. Restore is **platform-admin only** (`manage` on `Scope::Platform`) and audit-logged (`*.restore` events), because reinstating an identity/role/group re-grants the access it carried. Credential handling differs by scope: **`restoreEntity` keeps the entity's own credentials and sessions revoked** (an individual delete is a targeted removal, so recovery requires credential re-issue / password reset), whereas **`restoreTenant` reactivates the non-certificate child credentials** that *that* delete revoked — identified by the `tenant_deleted` revocation marker stamped in `credentials.metadata` — so members can sign in again with their existing passwords/API keys and the tenant is operational. Two guards keep that marker authoritative: tenant restore reactivates only credentials of children that are **not themselves individually soft-deleted** (`entities.deleted_at IS NULL`), so a child deleted after the tenant still requires `restoreEntity` + re-issue; and any later revocation **overwrites the provenance** — an explicit `revoke_credential` re-stamps `revocation_reason = 'manual'`, so a deliberate admin revocation is never resurrected by a subsequent tenant restore. Certificates stay revoked in both cases (their revocation is published via the CRL and cannot be safely undone — re-issue is required), and sessions stay revoked so a fresh login is required. Restore fails with a conflict if the name/alias/email was re-taken by a live row during the window (the partial unique index raises; mapped via `error::restore_conflict`), or if the row's owning tenant is still soft-deleted (restore the tenant first — restoring a tenant un-hides its children automatically since they were never individually tombstoned).
- GIN indexes on `attributes` JSONB columns in `entities` and `resources`.

## API Key Format

`atom_<32-hex-credential-id>_<64-hex-secret>`

The credential ID is embedded in the key for O(1) lookup without a full-table scan. Secret is argon2-hashed; shown only once on creation.

## Rust Patterns & Conventions

### Error handling
- Use `?` for propagation throughout. At external boundaries (DB, JWT, argon2) convert with `.map_err(|e| AppError::...)` or `db_err()`.
- Never `unwrap()` in non-test code unless the invariant is truly compiler-provable. Use `expect("reason")` only when you can justify why it can't fail.
- `anyhow` is for `main` and startup code only. All library/handler code uses `AppError`.

### Enums and exhaustive matching
- Never use a `_` wildcard catch-all when matching on project enums (`Effect`, `ScopeKind`, `GrantKind`, etc.). The compiler will catch unhandled variants when new ones are added — that's the point.
- Wildcard is acceptable only for third-party or `std` error/status types where exhaustiveness isn't a goal.

### Borrowing
- Prefer `&str` over `&String` and `&[T]` over `&Vec<T>` in function signatures unless you need ownership.
- Avoid `.clone()` in hot paths (request handling, PDP evaluation). Clone is fine at startup and in tests.

### Iterators over loops
- Prefer `.iter().filter().map().collect()` chains over `for` loops with `push`. Use `for` only when side effects or early returns make a chain unreadable.
- `.collect::<HashSet<_>>()` then `.into_iter().collect::<Vec<_>>()` is the idiomatic dedup pattern (used in engine for role_ids).

### Async
- Never call blocking I/O inside an async function without `tokio::task::spawn_blocking`. DB calls via sqlx are non-blocking by design.
- Fire-and-forget tasks (e.g. audit writes that don't need a result) can use `.await` inline — `tokio::spawn` is only warranted when the work must outlive the request or truly run concurrently.

### Derives — conventional ordering
```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
```
Order: `Debug`, `Clone`, `Copy` (if applicable), `PartialEq`, `Eq`, `Hash` (if applicable), then serde, then sqlx/axum traits.

### Tests
- Unit tests go in a `#[cfg(test)] mod tests` block in the same file as the code under test.
- Integration tests that need a real DB go in `tests/` and require `DATABASE_URL` to be set; add a `#[ignore]` attribute if you want `cargo test` to skip them by default.
- Use `insta::assert_json_snapshot!` for JSON response assertions.
- Never assert on exact `Uuid` or timestamp values — assert on structure and relevant fields only.

### Clippy
Run before committing:
```bash
cargo clippy -- -D warnings
cargo fmt --check
```

## Development

```bash
# Start Postgres only (Docker), for host `cargo run`
make db

# Run (auto-applies migrations)
cargo run

# Type check only
cargo check

# Run unit tests (no DB required)
cargo test

# Run the DB-gated tests too (needs DATABASE_URL)
cargo test -- --include-ignored

# Lint
cargo clippy -- -D warnings
cargo fmt --check
```

Environment variables: copy `.env.example` to `.env`. Required: `DATABASE_URL`. Signing uses ES256 keys bootstrapped/loaded at startup (optionally encrypted at rest via `ATOM_KEY_ENCRYPTION_KEY`) — there is no `JWT_SECRET`.

Optional: `ADMIN_SECRET` — if set, bootstraps the admin entity's password on first boot.
Optional: `ADMIN_ENTITY_ID` — override the seeded admin UUID (default `00000000-0000-0000-0000-000000000001`).

The runtime is production-hardened: configurable DB pool, five-category IP rate limiter, GraphQL depth/complexity/introspection limits (introspection **off** by default — opt in with `ATOM_GRAPHQL_INTROSPECTION_ENABLED=true`), per-route body limits, signing-key encryption at rest, audit retention, a `/health/ready` readiness probe, and graceful shutdown on SIGINT/SIGTERM (both the HTTP and gRPC servers drain in-flight requests before exit).

## Metrics

Prometheus metrics are exposed at `GET /metrics` (text exposition). All metric
emission goes through the `crate::metrics` façade — domain code calls semantic
functions (`record_decision`, `record_audit_failure`, `record_rate_limit_rejection`)
and never imports the `metrics` crate. The backend (`metrics` facade +
`metrics-exporter-prometheus`) is confined to `src/metrics.rs` behind the
`metrics` cargo feature (in `default`).

Two off switches:
- **Runtime:** `ATOM_METRICS_ENABLED=false` skips the recorder install and does
  not mount `/metrics`; the façade calls fall through to the global no-op recorder.
- **Compile-time (zero cost):** build with `--no-default-features` — the façade
  compiles to inlined no-ops and the metrics crates are not linked.

Series (v1): `atom_authz_decision_duration_seconds` (histogram, label `result`),
`atom_audit_write_failures_total`, `atom_rate_limit_rejections_total` (label
`category`), `atom_db_pool_connections` (gauge, label `state`). No tenant/entity/IP
labels — cardinality is kept bounded. Per-check query count is deliberately not a
metric (would require threading a counter through every repo call); the pool gauges
cover capacity instead.

**Security:** `/metrics` is unauthenticated by design and exposes internal
operational data. It **must** be network-restricted to the scraper (firewall,
service mesh, or a private network). Do not expose it publicly. Swapping the
Prometheus pull exporter for an OTLP push exporter later is an `init`/`render`
change in `src/metrics.rs` only — call sites do not move.

## Key Invariants

- DENY always overrides ALLOW — never change this without explicit discussion.
- Default deny — no matching allow policy means denied.
- `db_err()` must be used when converting sqlx errors in repo functions so `RowNotFound` maps correctly.
- API keys are one-time reveal — the plaintext secret is never stored; once the creation response is sent it cannot be recovered.
- No `PUT /groups/:id` — groups are immutable after creation (name/tenant change would break policy references).
- Enum variants must stay in sync with DB CHECK constraints — changing a variant's serialized name is a schema-breaking change requiring a migration.
- `audit::write()` must never be `?`-propagated — it is always fire-and-forget to avoid blocking auth decisions on audit failures.
- `subject_effective_grants(uuid)` (in migration `001`) is the one canonical grant expansion for the runtime path — the PDP, `explain`, the control-plane gates, and the authorized-listing readers all consume it (the listers add the shared `grant_scope_matches` SQL predicate, which mirrors the PDP's Rust scope matching). Do not add a second flattener, a per-listing-reader role expansion, or a parallel listing evaluator. The tenant-listing visibility filter and the audit tenant-scoping filter are on the canonical expansion too. `effective_access_edges()` is now confined to readers the subject-forward expansion cannot serve: the reverse assignment-time guardrail validators (`guardrails.rs`), the policy-object id→kind/tenant lookups, and the assignment-metadata listers. Never route a subject's effective-access decision through it.
- Role-linked permission blocks carry their own effect and conditions through expansion — a role-linked deny must override, and a role-linked conditional must stay conditional. Never re-flatten role edges to a hard-coded `allow`/`{}`.
- Permission blocks are shared and immutable: never `DELETE FROM permission_blocks` by role. Unlink the role's links, then GC only blocks left unreferenced (`unlink_role_blocks_and_gc`).
