# PKI UI — shipped work + open follow-ups

Tracks what the PKI release actually shipped in the Atom UI and what remains for future work.

The PKI backend stays authoritative; every UI action here calls the same GraphQL mutations documented in [pr-014-enrollment.md](pr-014-enrollment.md), [pr-013-hsm-kms-support.md](pr-013-hsm-kms-support.md), and the rest of the pr-* set. UI is a thin client.

## What shipped in this PR

### GraphQL Explorer (Playground)
- Auto-loads the schema on mount, surfaces introspection errors inline.
- Sidebar **Operations** panel: every query and mutation, grouped by domain (PKI Authorities, Certificates, Tenants, Entities, Authorization, Identity & Sessions, Groups, Resources, Audit & Health, Other). Search filters across name + description. Click any entry to load a runnable template with arg stubs and inline arg-type hints.
- Sidebar **Types** panel (renamed from Schema): OBJECT / INPUT_OBJECT / ENUM / SCALAR reference.
- Sidebar **Starter Operations**: unchanged curated queries.
- Docs: [graphql-explorer.md](../graphql-explorer.md).

Files:
- [app/components/playground/graphql-playground.tsx](../../../app/components/playground/graphql-playground.tsx)
- [app/app/(admin)/playground/page.tsx](../../../app/app/(admin)/playground/page.tsx)

### Certificates section under `/pki/*`
- Nav group **PKI** added to the admin sidebar with three entries: Authorities, Certificates, PKI Actions.
- `/pki/authorities` — list every managed CA (root, platform intermediate, platform leaf issuer, tenant intermediates) with tenant filter. Uses `pkiAuthorities`.
- `/pki/certificates` — list every issued leaf cert with tenant filter. Uses `certificates`. Delete row → `revokeCertificateV2` with reason `unspecified`.
- `/pki/actions` — six-tab form panel (Import Root and Import Signed CA tabs were subsequently removed; both anchors are now config-only via `ATOM_PKI_ROOT_CERT_PATH` / `ATOM_PKI_PLATFORM_INTERMEDIATE_{CERT,KEY}_PATH`):
  - **Provision Tenant CA** — one-click `provisionTenantAuthorityAutomatically`.
  - **Issue Certificate** — file-upload CSR + TTL + auto-generated idempotency key + `issueCertificateFromCsrV2`.
  - **Revoke Certificate** — credential ID + RFC 5280 reason dropdown + `revokeCertificateV2`.
  - **Retire Authority** — two-step `beginAuthorityRetirement` → `completeAuthorityRetirement` with a safety checkbox.

Shared components:
- [app/components/pki/badges.tsx](../../../app/components/pki/badges.tsx) — `AuthorityStatusBadge`, `AuthorityKindBadge`, `CertificateStatusBadge`.
- [app/components/pki/pem-viewer.tsx](../../../app/components/pki/pem-viewer.tsx) — copyable + downloadable PEM view.

## Phase 1 additions (just shipped)

- **Authority detail** — `app/(admin)/pki/authorities/[id]/page.tsx`. Renders Identity, Lifecycle, Publication URLs (clickable), Certificate PEM, and Chain PEM via `PemViewer`. Backend gained `ocspUrl`, `caIssuersUrl`, `crlDistributionPointUrl`, `updatedAt` on the GraphQL `Authority` type.
- **Certificate detail** — `app/(admin)/pki/certificates/[credentialId]/page.tsx`. Renders Identity (entity, tenant, issuer, profile, DNS SAN, IP SAN, fingerprint), Lifecycle (expires, issued, revocation reason/time when revoked), Subject JSON, Certificate PEM. Includes a **Revoke** button.
- **Rich revoke** — `app/components/pki/revoke-certificate-button.tsx`. shadcn `AlertDialog` with the full RFC 5280 reason dropdown, calls `revokeCertificateV2`, refreshes the page on success.
- **Tenant-scoped certs** — `app/(admin)/tenants/[id]/certificates/page.tsx`. Same `CrudWorkspace` bound to the pinned tenantId from the route. Access is still gated by the `(admin)` layout today; opening up to tenant admins is the follow-up below.
- **CSR parse preview** — Issue Certificate tab now decodes the pasted CSR in-browser with `@peculiar/x509`, shows subject / public-key algorithm / SAN DNS before submit. Invalid PEM surfaces a red error banner.
- **Playwright smoke** — `app/tests/e2e/pki.spec.ts`. Verifies PKI Actions renders all six tabs and the reason dropdown; verifies the Playground Operations panel auto-loads and search filters live. Route sweep in `admin-shell.spec.ts` extended with `/pki/*`.

## Phase 2 additions (just shipped)

- **Import Root PEM preview** — parses the pasted root PEM in-browser via `@peculiar/x509` and previews subject / issuer / serial / not-before / not-after before submission.
- **Bulk Revoke tab** — matches the actual `bulkRevokeCertificates` schema (scope selectors: tenant / issuer / principal group + reason + batch limit) with an explicit safety checkbox that names the reason.
- **Generate & Issue tab** — WebCrypto (`ECDSA_P256` or `RSA_2048`) generates a keypair in the browser, `@peculiar/x509` produces a PKCS#10 CSR, the CSR is submitted for issuance, and the freshly-generated private key is offered as a one-time download (never sent server-side). SAN DNS entries deferred — use "Issue from CSR" for those.
- **Retire Authority wizard** — 4-step flow: **Impact** (explains the effect) → **Confirm** (target ID + explicit "I have a replacement" checkbox) → **Begin** → **Complete**, with status badges surfacing the authority's real state between steps.
- **Tenant-admin surface** — confirmed to work as-is: [app/(admin)/layout.tsx](../../../app/app/(admin)/layout.tsx) only enforces session validity (not platform-admin scope). Per-operation authorization is enforced backend-side by the GraphQL resolvers. Any authenticated tenant admin can navigate to `/tenants/[id]/certificates`; operations they cannot perform surface a Forbidden GraphQL error.

## Nothing remaining

Everything in the PR is shipped, typechecked, and lint-clean. If new gaps surface during smoke testing, add them here as new items rather than reviving deferred sections.

## Architectural follow-up

### Surface PKI HTTP endpoints as protected built-in API Endpoints
Atom has an existing "API Endpoints" concept (see `app/app/(admin)/endpoints`). The PKI ships several public HTTP endpoints that today live outside that registry:

- `GET /certs/ca-chain`
- `GET /certs/trust-bundle.pem`
- `GET /certs/issuers/:issuer_id/crl` (and legacy `/certs/crl`)
- `POST /certs/issuers/:issuer_id/ocsp` (and legacy `/certs/ocsp`)
- `POST /pki/enroll` / `POST /pki/reenroll`
- `GET/POST /.well-known/est/*`

**Proposal.** Register these as built-in `api_endpoints` rows during migration so:
- Operators discover them in the same UI they use for user-defined endpoints.
- They're visible to authz decisions and audit tooling.
- A `built_in = TRUE` column marks them non-deletable so nobody can accidentally drop the routes an issued certificate depends on.

**Blast radius.** Migration + one seed of ~10 rows + a `DELETE` trigger that rejects rows where `built_in = TRUE`. UI changes only cosmetic (badge saying "built-in, not deletable").

## Files touched in this PR

```
+ app/app/(admin)/pki/authorities/page.tsx
+ app/app/(admin)/pki/certificates/page.tsx
+ app/app/(admin)/pki/actions/page.tsx
+ app/components/pki/badges.tsx
+ app/components/pki/pem-viewer.tsx
+ app/components/pki/pki-actions-panel.tsx
M app/components/playground/graphql-playground.tsx
M app/components/app-shell/app-shell.tsx
M app/lib/crud/resources.ts
+ product-docs/development/graphql-explorer.md
M product-docs/development/pki/UI-FOLLOWUP-TODO.md
```
