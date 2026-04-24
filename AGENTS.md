# Atom — Identity & Authorization Service

Lightweight replacement for Keycloak — single Rust binary, single Postgres database. Built for Magistrala IoT platform but generic enough for any cloud-native system.

## Stack

- **Language:** Rust (edition 2021)
- **HTTP framework:** Axum 0.7
- **Database:** PostgreSQL via sqlx 0.7 (dynamic queries; `query_as` with `FromRow`)
- **Auth:** argon2 (password/API key hashing), jsonwebtoken (HS256 JWTs)
- **Runtime:** Tokio (full features)
- **Testing:** `cargo test` (unit tests in-module); `insta` available for snapshot tests

## Project Layout

```
src/
  main.rs              — startup: config, DB pool, migrations, admin bootstrap, router
  config.rs            — Config struct, reads env vars (incl. ADMIN_ENTITY_ID, ADMIN_SECRET)
  state.rs             — AppState (pool + config), cloned into every handler
  routes.rs            — single router wiring all handlers
  error.rs             — AppError enum → HTTP responses; db_err() helper
  audit.rs             — fire-and-forget audit_logs writer; never fails the caller
  auth.rs              — JWT encode/decode, Bearer extraction, AuthContext extractor,
  │                       RequireManage extractor, has_global_manage() helper
  db.rs                — pool creation
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
  001_initial.sql      — full schema + capability seeds
  002_admin_seed.sql   — admin entity (UUID …0001) + admin role (…0002) + binding
```

## Architecture Patterns

- **Layered:** handler → service/engine → repo. Handlers only do HTTP concerns; business logic lives in service/engine; repo only does DB.
- **AppState** is cheaply cloned (Arc internally via pool) and injected via Axum's `State` extractor.
- **Error handling:** `AppError` is the single error type across all layers. `db_err()` converts `RowNotFound` to `AppError::NotFound`. Postgres unique-violation (code 23505) maps to 409.
- **Typed enums:** all constrained domain fields (`EntityKind`, `Effect`, `ScopeKind`, etc.) are Rust enums deriving `sqlx::Type` + serde. Invalid values are rejected at deserialization — no manual validators in handlers.
- **No special user type:** every principal is an `Entity` with a `kind` field.
- **Online authorization:** tokens carry no permissions; every `POST /authz/check` hits the DB.
- **Audit log:** `audit::write()` is fire-and-forget — it logs failures but never propagates them to the caller. Called from service (login) and handlers (logout, credential ops, authz check).

## Authorization Model (PDP)

Evaluation order in `authz/engine.rs`:
1. Load entity (must be active) and resource.
2. Resolve capability by action name (matched against resource kind or NULL=all).
3. Load all `policy_bindings` where `subject_id` is the entity directly **or** any group the entity belongs to.
4. **Batch-load** all role capabilities in a single `ANY($1::uuid[])` query — no per-binding round-trips.
5. For each binding: check scope, check grant covers the capability (direct cap or via role), evaluate ABAC conditions.
6. **First DENY match → return denied immediately.**
7. Any ALLOW match → allowed; otherwise → denied.

ABAC conditions: flat JSON object, keys are dot-paths (`entity.attributes.x`, `resource.attributes.y`, `context.z`), values must match exactly (AND logic). Empty `{}` means no conditions — always matches.

## Self-Authorization

Management endpoints are protected by two mechanisms:

**`RequireManage` extractor** (`auth.rs`) — used on `POST/DELETE /capabilities` and `POST/DELETE /policies`. Runs a single DB query (`has_global_manage`) that checks whether the caller holds an `allow` + `scope=all` binding covering the `manage` capability (directly or via a role). Returns 403 otherwise.

**Self-delete check** in `DELETE /entities/:id` — the entity may delete itself; deleting any other entity requires `has_global_manage`.

**Admin bootstrap** — migration `002` seeds:
- Entity `00000000-0000-0000-0000-000000000001` (`atom-admin`)
- Role `00000000-0000-0000-0000-000000000002` (`atom-admin`) with all seeded capabilities
- Policy binding: admin entity → admin role → scope `all`

Set `ADMIN_SECRET` on first boot to create the password credential for `atom-admin`. Subsequent restarts with the same env var are no-ops (credential already exists). To change the admin password, revoke the old credential via the API, then restart with the new secret.

## Database

- All PKs are UUIDs (`gen_random_uuid()` via pgcrypto).
- `entities` and `groups` have a composite unique index on `(name, tenant_id)` — name uniqueness is per-tenant.
- `capabilities` unique on `(name, resource_kind)` — `resource_kind = NULL` means applies to all kinds.
- Migrations run automatically on startup via `sqlx::migrate!("./migrations")`. New migrations go in `migrations/NNN_<name>.sql`.
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
# Start Postgres only
docker-compose up postgres -d

# Run (auto-applies migrations)
cargo run

# Type check only
cargo check

# Run unit tests (no DB required)
cargo test

# Lint
cargo clippy -- -D warnings

# Live reload (requires cargo-watch)
cargo watch -x run
```

Environment variables: copy `.env.example` to `.env`. Required: `DATABASE_URL`, `JWT_SECRET` (32+ chars).

Optional: `ADMIN_SECRET` — if set, bootstraps the admin entity's password on first boot.
Optional: `ADMIN_ENTITY_ID` — override the seeded admin UUID (default `00000000-0000-0000-0000-000000000001`).

## Key Invariants

- DENY always overrides ALLOW — never change this without explicit discussion.
- Default deny — no matching allow policy means denied.
- `db_err()` must be used when converting sqlx errors in repo functions so `RowNotFound` maps correctly.
- API keys are one-time reveal — the plaintext secret is never stored; once the creation response is sent it cannot be recovered.
- No `PUT /groups/:id` — groups are immutable after creation (name/tenant change would break policy references).
- Enum variants must stay in sync with DB CHECK constraints — changing a variant's serialized name is a schema-breaking change requiring a migration.
- `audit::write()` must never be `?`-propagated — it is always fire-and-forget to avoid blocking auth decisions on audit failures.
- The `capability_ids_for_roles` batch query must be called before the binding loop in `engine::evaluate` — do not reintroduce per-binding role lookups.
