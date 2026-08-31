# Atom UI

The optional administration interface for Atom. It is a Next.js application
that uses Atom's GraphQL API for identity, authorization, audit, and PKI
management.

## Development

Start Atom first, then run:

```bash
pnpm install --frozen-lockfile
ATOM_GRAPHQL_URL=http://localhost:8080/graphql pnpm dev
```

Open <http://localhost:3000>.

## Validation

```bash
pnpm lint
pnpm test
pnpm build
```

The production container is built from [`Dockerfile`](Dockerfile). The root
Compose stack starts the published UI profile with `make up`.
