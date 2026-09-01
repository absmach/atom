# Atom

Atom is a lightweight identity and authorization service for cloud-native and
edge systems. It provides authentication, multi-tenant authorization, audit,
and managed PKI from one Rust binary backed by PostgreSQL.

Atom is built for the [Magistrala](https://github.com/absmach/magistrala) IoT
platform, but its APIs and authorization model are product-neutral.

## Features

- Entity identities for people, devices, services, workloads, and applications
- Password, shared-key, access-token, OAuth/OIDC, and certificate authentication
- Online RBAC and ABAC decisions with deny-overrides-allow semantics
- Tenant, object, object-type, group, and platform authorization scopes
- GraphQL management API and gRPC runtime APIs
- Certificate issuance, renewal, revocation, CRL, OCSP, and EST enrollment
- Transactional domain-event outbox and persisted audit trail
- Optional Redis acceleration without caching authorization decisions
- Health, readiness, metrics, rate limiting, and graceful shutdown

## Documentation

The complete documentation is available at
[absmach.eu/docs/atom](https://www.absmach.eu/docs/atom/).

- [Quick start](https://www.absmach.eu/docs/atom/quickstart/)
- [Architecture](https://www.absmach.eu/docs/atom/architecture/)
- [Authentication](https://www.absmach.eu/docs/atom/authentication/)
- [Access control](https://www.absmach.eu/docs/atom/access-control/)
- [Operations](https://www.absmach.eu/docs/atom/operations/)
- [API endpoints](https://www.absmach.eu/docs/atom/endpoints/)

Machine-readable and generated API contracts are kept in [`apidocs`](apidocs).
The documentation website source is in [`docs`](docs).

## Quick start

Requirements:

- Docker with Compose support
- GNU Make

Start PostgreSQL, Atom, and the Atom UI:

```bash
make up
```

On first use, `make up` creates `.env` from `.env.example` and starts the local
stack with development-only credentials.

| Service | URL |
| --- | --- |
| Atom UI | <http://localhost:3005> |
| GraphQL | <http://localhost:8080/graphql> |
| Readiness | <http://localhost:8080/health/ready> |
| gRPC | `localhost:8081` |

The demo administrator credentials are:

```text
identifier: admin
secret: 12345678
```

These defaults are for local development only. Replace every secret and
encryption key before using Atom in a shared or production environment.

Stop the stack with:

```bash
make down
```

See the [quick-start guide](https://www.absmach.eu/docs/atom/quickstart/) for
host development, certificate setup, custom ports, and troubleshooting.

## Development

Start only PostgreSQL and run Atom on the host:

```bash
make db
cargo run
```

Run the standard checks:

```bash
cargo fmt --all --check
cargo clippy --locked -- -D warnings
cargo test --locked
```

Database-backed integration tests require `DATABASE_URL`:

```bash
cargo test --locked -- --include-ignored
```

Build and test the UI:

```bash
cd ui
pnpm install --frozen-lockfile
pnpm lint
pnpm test
pnpm build
```

Build the documentation website:

```bash
cd docs
pnpm install --frozen-lockfile
pnpm build
```

## API contracts

Atom treats its public API and released migrations as compatibility surfaces.
Do not edit released migrations or frozen v1 contracts in place.

```bash
make proto
make proto-lint
make proto-check
bash scripts/check-v1-contracts.sh
```

The canonical artifacts are:

- [`apidocs/openapi.yaml`](apidocs/openapi.yaml)
- [`apidocs/graphql-schema.graphql`](apidocs/graphql-schema.graphql)
- [`proto/atom/v1/atom.proto`](proto/atom/v1/atom.proto)

## Repository layout

| Path | Purpose |
| --- | --- |
| `src/` | Rust service implementation |
| `ui/` | Optional Atom administration UI |
| `docs/` | Documentation website and archived design history |
| `api/` and `apidocs/` | Versioned and generated API contract artifacts |
| `config/` | Demo and example bootstrap/callout configuration |
| `examples/` | Runnable integrations, demos, and API collections |
| `migrations/` | Immutable PostgreSQL migrations |
| `proto/` | Atom-owned and vendored protobuf contracts |
| `scripts/` | Validation and maintenance scripts |
| `tests/` | Database-backed integration and contract tests |

## Security

Atom defaults to online authorization: identity tokens contain no permissions,
and policy changes take effect without waiting for token expiry. Production
deployments must use strong encryption keys, secure PostgreSQL, TLS or a trusted
service mesh, and network restrictions around administrative and metrics
endpoints. See the [documentation](https://www.absmach.eu/docs/atom/) for the
full deployment and security requirements.
