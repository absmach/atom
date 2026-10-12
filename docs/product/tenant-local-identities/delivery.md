# Delivery: tenant-local identities

Status: Draft architecture-stage plan for [#99](https://github.com/absmach/atom/issues/99).
Owner: @arvindh123; review: Atom maintainers and authentication/security before activation.
[PRD](prd.md) and [RFC](../../rfcs/tenant-local-identities.md) are the source of truth.
Stage IDs are planning identifiers, not created GitHub issues.

## Branch contract and first PR

Integration: feature/tenant-local-identities, initially from current main.
Ticket branches start from latest integration and target it. Stage 001 uses
codex/tenant-local-identity-contracts. Only final stabilization targets main.
Intermediate PRs must not close #99 or enable incomplete runtime behavior.

Stage 001 contains these documents and adds integration to existing Rust, API and
frontend PR workflow filters. Runtime, schema, migration and API behavior are unchanged.
Validate documents, references, traceability and workflow filters; do not report
future security tests as passing.

## Shared implementation contract

- Human owner/reviewer: issue assignee @arvindh123 / Atom maintainers. Owner selects
  a security reviewer before activation. Agents implement only assigned stages,
  without autonomous merging or feature activation.
- Read current repository instructions and rebase onto integration. Paths below
  were checked at 775a326; inspect intervening changes before editing.
- Every PR includes behavior tests, FR/NFR mapping, validation results and API/
  migration/rollback notes (explicitly none where appropriate).
- Use current native DB adapters, paired migrations and canonical authz. Preserve
  lifecycle filters, deny precedence, outbox rules and single-connection safety.
- Keep local provisioning unavailable until all readers/guards and final tests land.
  Stage 002 retains old uniqueness; activation/index relaxation belongs to 013.
- Intermediate PR text uses "Refs #99; ATOM-TLI-NNN". Only actual published leaf
  issues get closing keywords; never pretend a stage ID is an issue number.
  The accepted stabilization PR can close #99.

## Stages and dependencies

All stages inherit NFR-1 through NFR-4. Each row defines scope/output and minimum
proof. Split broad stages into focused PRs when needed, all still gated off;
do not ship a temporarily unguarded transport.

| Stage | Depends on | Scope and verified starting points | Acceptance / exclusions |
|---|---|---|---|
| 001 Architecture/contracts | — | PRD, RFC, plan and integration CI. | Answer six #99 decisions, equal-password semantics, staged indexes and rollback. No runtime feature. |
| 002 Schema/model | 001 | src/models/{enums,entity,tenant,session}.rs; migrations/ and migrations/sqlite/. | FR-1/2: deterministic backfill, invalid combinations/NULL uniqueness tested on both DBs. Retain old indexes, no activation. |
| 003 Identity lookup | 002 | src/identity/{service,repo}.rs; shared resolved-context validation. | FR-1/2: email/name/UUID/alias/credential, tombstones/ambiguity; no local lookup via legacy fallback. |
| 004 Signup/verification | 003 | src/identity/{service,handlers}.rs, src/models/session.rs, src/tenants/repo.rs. | FR-3/5: atomic enrollment, race/fault/no-op proof, verification/resend binding, server role, generic public response. No client role/redirect. |
| 005 Login/session/refresh | 003 | src/auth.rs, src/identity/{service,refresh_tokens}.rs, src/models/{session,refresh_token}.rs, src/grpc.rs, src/cache/. | FR-4: platform selector, session/JWT home parity, refresh/revoke, old-token rejection; legacy compatibility. No permissions in JWTs. |
| 006 Recovery/credentials | 004, 005 | src/identity/{service,access_tokens}.rs, src/auth.rs, src/certs/, src/broker_auth/. | FR-5: reset/email-change/setup and credential operations reject mismatch; preserve managed ownership and revocation. Include cert/broker mapping, no hash copying. |
| 007 Invitations/membership | 003, 004, 005 | src/tenants/{repo,email}.rs, src/graphql/tenants.rs, src/models/tenant.rs. | FR-6: local identity/role, mailbox proof, expiry/revoke/replay, suspension/removal; no event on membership no-op. |
| 008 OAuth/OIDC | 003, 004, 005 | src/identity/{service,oauth_github,oauth_apple}.rs, src/config.rs, migration 006. | FR-7: tenant/provider/client/issuer/subject binding; state/nonce/PKCE/exchange tampering, verified local linking. No arbitrary discovery/redirect. |
| 009 Authorization | 003, 005 | src/{auth,guardrails}.rs, src/authz/, authorized listers, src/graphql/, src/grpc.rs, src/bootstrap.rs. | FR-1/8: mutation/runtime home boundaries including recursive groups, role blocks and platform scope; keep platform admin and legacy machines; one-connection tests. |
| 010 Lifecycle | 006, 007, 009 | src/tenants/repo.rs, src/identity/repo.rs, src/purge.rs, src/authz/repo.rs. | FR-9: freeze/delete races, restore provenance, individually deleted children, purge references; no revived cert/session. |
| 011 Migration tooling | 002–010 | New operator entry point/checkpoints using current identity/tenant transactions and canonical cleanup. | FR-10: dry-run no writes, deterministic mapping/conflicts, interruption/retry, freshness, fenced cutover, cache/session invalidation, rollback boundary. No activation yet. |
| 012 Contracts/bootstrap/docs | 004–010 | api/v1/, apidocs/, proto/atom/v1/, src/bootstrap.rs, config/examples/bootstrap.yaml, docs/content/docs/. | FR-11: generated contracts, protected profile config, migration/runbook guidance. Earlier PRs update their own contracts; this reconciles all surfaces. Atomic work stays external. |
| 013 End-to-end/activation | 011, 012 | New suites using tests/common/ and src/db/testing.rs; final uniqueness/activation migration. | All FR/NFR: two-backend/transport tampering, upgrade/downgrade fence, independent accounts, lifecycle, migration, cache and Atom-only portability. Evidence before activation/stabilization. |

These are capability stages, not a claim that thirteen agent-sized GitHub leaves
already exist. Credential/guardrail work may need independently testable family/
transport leaves. Stage owners must define exact leaf acceptance before dispatch.

## Validation

Existing root commands:

~~~sh
cargo fmt --check
cargo clippy --locked -- -D warnings
cargo test --locked
bash scripts/check-db-boundary.sh
bash scripts/check-v1-contracts.sh
python scripts/test-v1-contracts.py
~~~

Database changes use the fresh-database-per-binary procedure in
.github/workflows/rust.yml. Running --include-ignored alone does not provision its
Redis, PKCS#11, EST or other prerequisites.

For a focused new suite, use disposable PostgreSQL with DATABASE_URL and
"cargo test --test <suite> -- --include-ignored --test-threads=1", then repeat with
ATOM_TEST_BACKEND=sqlite and a distinct ATOM_TEST_SQLITE_PATH. The placeholder is
not a claim a future test file exists. Run cache-on/off where relevant.

Extend existing tests as appropriate:

- tests/m15_signup.rs, m23_authenticate_credential.rs, m24_invitation_errors.rs.
- tests/m51_refresh_tokens.rs, m51_self_profile_update.rs, m52_email_change.rs.
- tests/m8_guardrails.rs, m16_authorized_listing.rs, m19_tenant_listing.rs.
- tests/m21_soft_delete.rs, m22_restore.rs, m25_cache_invalidation.rs.
- tests/m25_event_outbox.rs, m26_audit_event_publishing.rs, api_contract.rs.

Assert generated identifier relationships and outcome/structure, not literal
UUIDs/timestamps. Include races/rollback, not tests merely mirroring implementation.

## Publication manifest and review gate

Repository: absmach/atom. Initiative: tenant-local-identities. Existing Epic: #99.
This PR publishes only stage-001 documents and CI filters. It creates/changes no
child issues, labels, milestones or Projects. Future issue publication needs a
concrete manifest if requested.

Artifacts (Draft): PRD with 11 FR + 4 NFR; RFC covering architecture, security,
compatibility, migration, observability and rollback; delivery and acceptance plan.
Proposed hierarchy: #99 -> capability stages 002–013 -> focused leaves where needed,
using native GitHub sub-issues when published. Dependencies are acyclic; 013 owns
final proof. No new label/milestone taxonomy is proposed.

The RFC proposes all six decisions from #99: explicit scope, DB mode, additive
platform login, fresh password setup migration, policy-based platform machine
access, and protected app-profile references. Stage-001 review accepts or amends
them. Opening this PR implies neither architectural approval nor feature completion.
