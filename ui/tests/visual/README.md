# PKI visual walkthrough

Opens a real browser and steps through the full PKI flow end-to-end so a human can watch:

1. Login via the UI form
2. Open the GraphQL Playground, prove the schema loaded, search a mutation
3. Visit `/pki/authorities`, click the tenant intermediate we seeded
4. Authority detail — PEM viewer, publication URLs
5. Visit `/pki/certificates`, click the leaf we seeded
6. Certificate detail — revoke via the reason picker
7. Confirm the certificate flips to "revoked"
8. Walk each tab of `/pki/actions` so the operator surface is visible

## Prerequisites

- `make up` has the compose stack live (Postgres, atom `:18080`, atom-ui `:3006`). The trust anchor (`ATOM_PKI_ROOT_CERT_PATH` + `ATOM_PKI_PLATFORM_INTERMEDIATE_{CERT,KEY}_PATH`) is bootstrapped by `make pki-material`, which `make up` runs automatically.
- `openssl` on `PATH` (for the device CSR the walkthrough issues in step 6).
- Node 20+ and `pnpm` (via `corepack enable`).
- Playwright Chromium browser installed.

## Run it

From the `ui/` directory:

```bash
# One-time setup:
pnpm install --frozen-lockfile
pnpm exec playwright install chromium

# Every run:
pnpm exec playwright test \
  --config=tests/visual/pki-visual.config.ts \
  tests/visual/pki-walkthrough.spec.ts
```

A Chromium window opens. Watch the top-right green banner for step labels.

## Overrides

Env vars the spec / config respect:

| Var | Default | Purpose |
|---|---|---|
| `UI_URL` | `http://localhost:3006` | Atom UI base URL |
| `ATOM_BACKEND_URL` | `http://localhost:18080` | Atom GraphQL / HTTP |
| `ATOM_ADMIN_IDENTIFIER` | `admin` | Admin login |
| `ATOM_ADMIN_SECRET` | *(read from repo `.env`)* | Admin password |
| `PW_HEADLESS` | *(unset — headed)* | Set to `1` for headless CI-style runs |
| `PW_SLOWMO_MS` | `350` | Millisecond delay between actions |
| `PW_VIEWPORT_WIDTH` / `_HEIGHT` | `1400` / `900` | Browser window size |

## Notes

- Root + platform intermediate are **config-only**. The walkthrough only verifies they exist as active rows and fails clearly if they don't — bootstrap them via `make pki-material` (or set the three `ATOM_PKI_*_PATH` env vars manually and restart atom).
- The walkthrough is a "leaves visible residue" test — tenants, entities, and issued certs stay in the DB. Fine for demos, not for repeated CI.
