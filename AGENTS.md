# Atom — Identity & Authorization Service

Lightweight replacement for Keycloak — single Rust binary, single Postgres database. Built for Magistrala IoT platform but generic enough for any cloud-native system.

## Stack

- **Language:** Rust (edition 2021)
- **HTTP framework:** Axum 0.7
- **APIs:** GraphQL (async-graphql `=7.2.1`, depth/complexity/introspection limits) + gRPC (Tonic 0.12 + tonic-health). The REST handlers under `authz/` and `tenants/` are compiled but **unmounted** (see `routes.rs`).
- **Database:** PostgreSQL via sqlx 0.8.6 (dynamic `query`/`query_as`; macros off)
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
     handlers.rs       — Axum handlers; capabilities + policy endpoints use RequireManage
     engine.rs         — PDP: batch-loads role capabilities, evaluates RBAC/ABAC,
     │                    deny-overrides-allow; unit-tested in #[cfg(test)]
     repo.rs           — sqlx queries; capability_ids_for_roles() batch-loads by role array
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
- **One canonical grant expansion:** `repo::effective_grants_for_subject` is the single reader of "what does this subject hold" for the *runtime* path — the PDP (`engine::evaluate`), `explain`, and the control-plane gates all consume it. Group membership is resolved recursively; each grant carries its own scope/effect/conditions. Do not reintroduce a second flattener. (The assignment-time guardrail validators in `guardrails.rs` still read `effective_access_edges()` with their own recursive group CTE — folding them onto the canonical expansion is tracked future work, not yet done.)
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
- Migrations run automatically on startup via a runtime `sqlx::migrate::Migrator` over `./migrations` (CWD-dependent; embedding via `sqlx::migrate!` is a tracked TODO). New migrations go in `migrations/NNN_<name>.sql`.
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

The runtime is production-hardened: configurable DB pool, five-category IP rate limiter, GraphQL depth/complexity/introspection limits (introspection **off** by default — opt in with `ATOM_GRAPHQL_INTROSPECTION_ENABLED=true`), per-route body limits, signing-key encryption at rest, audit retention, and a `/health/ready` readiness probe.

## Key Invariants

- DENY always overrides ALLOW — never change this without explicit discussion.
- Default deny — no matching allow policy means denied.
- `db_err()` must be used when converting sqlx errors in repo functions so `RowNotFound` maps correctly.
- API keys are one-time reveal — the plaintext secret is never stored; once the creation response is sent it cannot be recovered.
- No `PUT /groups/:id` — groups are immutable after creation (name/tenant change would break policy references).
- Enum variants must stay in sync with DB CHECK constraints — changing a variant's serialized name is a schema-breaking change requiring a migration.
- `audit::write()` must never be `?`-propagated — it is always fire-and-forget to avoid blocking auth decisions on audit failures.
- `effective_grants_for_subject` is the one canonical grant expansion for the runtime path — the PDP, `explain`, and the control-plane gates all read it. Do not add a second flattener or reintroduce per-binding role lookups. (Assignment-time guardrails still read `effective_access_edges()`; converging them is future work.)
- Role-linked permission blocks carry their own effect and conditions through expansion — a role-linked deny must override, and a role-linked conditional must stay conditional. Never re-flatten role edges to a hard-coded `allow`/`{}`.
- Permission blocks are shared and immutable: never `DELETE FROM permission_blocks` by role. Unlink the role's links, then GC only blocks left unreferenced (`unlink_role_blocks_and_gc`).
