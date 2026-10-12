# Tenant-local human identities

Status: Draft for architecture review (ATOM-TLI-001); not implemented.
Accountable owner: @arvindh123 (assignee of [issue #99](https://github.com/absmach/atom/issues/99)).
Review: Atom maintainers, with authentication/security review before activation.

This is the product contract for #99. The [RFC](../../rfcs/tenant-local-identities.md)
records proposed decisions; the [delivery plan](delivery.md) maps requirements to
staged PRs. Merging the architecture PR does not complete #99.

## Problem and outcome

One Atomic finished app maps to one Atom tenant. Public human signup currently
creates a global entity. App membership is not an independent login identity.
A person using the same email in two apps needs separate entity IDs, credentials,
verification, recovery, sessions, provider links, grants and lifecycle.

Target users are finished-app users, tenant administrators, platform operators and
developers integrating Atom. Platform administrators and Atomic collaborators stay
distinct from finished-app users. Atom must work without Atomic/Phoenix in the
runtime path. Existing global-mode tenants retain supported behavior until an
operator explicitly migrates them.

## Non-goals

- Cross-app SSO, shared credentials or automatic cross-tenant account linking.
- A new EntityKind; app users remain human.
- An organization/group containing multiple apps and reusable app users. The older
  comment on #99 describes a separate need; it must not weaken the current isolation contract.
- Changing the canonical grant expansion or putting permissions in JWTs.
- Copying passwords, password hashes, keys, certificates or sessions at migration.
- Implementing Atomic provisioning changes in this repository.

## Journeys and error behavior

1. A user signs up in active, open-enrollment App A. Atom creates one local human,
   password, verification state, membership and configured Member role atomically.
   Repeating/racing signup cannot create another live identity or replace its
   password. Public acknowledgement does not disclose account existence.
2. The user signs up in B with the same email, receiving a distinct entity. Resetting
   A's password or changing A's email leaves B's identity unchanged.
3. An invitee accepts a valid B invitation. Its stored tenant selects the namespace;
   an A or global identity is never silently reused. Invalid/expired/revoked
   invitations mutate nothing; repeated acceptance is a no-op.
4. An operator migrates a legacy app after dry-run conflict review. Users receive
   tenant-specific setup; cutover fences old membership access and revokes affected
   old sessions. Retrying resumes the same mapping, not duplicate identities.

If independently enrolled A and B identities use identical email/password strings,
logging into B with those strings authenticates B against B's password record.
Password text cannot reveal its origin. Prove isolation through independent records
and password changes, and rejection of A's credential IDs, entity IDs, sessions and
tokens in B; do not prohibit coincidentally equal user-chosen passwords.

## Requirements and traceability

Stage numbers below refer to ATOM-TLI-NNN. Stage 013 owns final end-to-end proof for
every row, including all backends/transports, not just unit-level acceptance.

| ID | Observable requirement | Acceptance evidence | Stage |
|---|---|---|---|
| FR-1 | Persist scope and mode; local identities have one immutable home tenant. | Invalid combinations/moves rejected on both DBs; existing global tenants preserve behavior. | 002, 003, 009 |
| FR-2 | Live normalized email is unique per local tenant and in the legacy/platform namespace. | Same email in A/B succeeds, concurrent duplicate in A creates one identity, no lookup fallback crosses namespaces. | 002, 003 |
| FR-3 | Signup validates tenant enrollment and atomically creates identity, password, verification, membership and server-selected role. | Injected failure yields no partial enrollment/success event; races/idempotency and client role-injection tests. | 004 |
| FR-4 | Login, session, JWT and refresh family enforce home tenant. | Missing/wrong context, inactive tenant and revoked session fail; refresh cannot change home. | 005 |
| FR-5 | Verification, recovery, email change and credential administration enforce home tenant. | A's tokens fail in B; reset/change/revoke in A leaves B unchanged; generic public responses. | 006 |
| FR-6 | Invitations and membership lifecycle operate only on the invitation tenant's local identity. | Foreign identity/role, expired/revoked/replayed invitation and suspension/removal tests; no event on no-op. | 007 |
| FR-7 | OAuth/OIDC links, state and exchange are tenant-bound. | One external account enrolls independently in A/B; state/issuer/client/subject/code substitution fails. | 008 |
| FR-8 | Guards, PDP, listings and admin operations reject local cross-tenant access. | Direct/role/recursive-group/platform grants cannot escape home; authorized platform administration still works. | 009 |
| FR-9 | Freeze/delete/restore/purge preserve existing lifecycle rules within home. | Manual revocation survives restore; certs/sessions stay revoked; purge cleans children and authz references. | 010 |
| FR-10 | Migration is explicit, observable, resumable and idempotent. | Dry run writes nothing; retry preserves mappings; no secret copying; cutover/rollback demonstrated. | 011 |
| FR-11 | REST/auth, GraphQL, applicable gRPC, bootstrap and docs agree. | Transport parity, additive contract checks, bootstrap rejection and fresh Atom-only portability tests. | 012, 013 |
| NFR-1 | Preserve transactional success events, non-fatal compliance audit and single-connection safety. | Rollback emits no success; audit failure cannot undo mutation; max-connections=1 completes. | 004–011, 013 |
| NFR-2 | PostgreSQL and SQLite expose identical isolation behavior. | Paired forward-only migrations, parity checks and identical integration scenarios. | 002–013 |
| NFR-3 | Preserve v1 behavior for unmigrated tenants; incomplete local flows stay unavailable. | Frozen-contract and legacy regressions pass; no activation before all guards/readers/tests land. | 002, 005, 012, 013 |
| NFR-4 | Do not leak sibling account existence or secrets. | Equivalent public status/body categories; no secret material in logs/reports, no identity metric labels. | 003–008, 011, 013 |

## Acceptance and release

Test two local tenants, one legacy tenant, global humans and machines, equal
normalized emails, nested groups and stale cached grants. Run both cache-enabled
and cache-disabled paths on both databases. Local login must return the intended
tenant's entity, including the equal-password case.

Targets: zero successful cross-tenant attacks in the adversarial matrix; zero
duplicate live identities in concurrent enrollment; zero copied credential/session
records at migration; no legacy-suite regressions. These are release-test targets,
not production measurements. Stage 013 records evidence; @arvindh123 accepts it
before stabilization. Existing latency targets are unchanged; measure representative
login/PDP latency and query counts before/after and review regressions.

Use the [validation procedure](delivery.md#validation). Do not close #99 or enable
local mode until every requirement and issue acceptance criterion has evidence.

## Constraints, risks and ownership

- Atomic must explicitly provision local app tenants after Atom supports them.
  That separate repository integration is required for Atomic rollout.
- Rebase each stage against database adapter changes; implement through current
  repository boundaries and native adapters, not new runtime SQL translation.
- Old binaries/readers are unsafe after local state exists. The RFC requires a
  cutover fence and minimum compatible application-version check.
- Existing tenant-owned machines may legitimately cross tenants. Do not reinterpret
  them as isolated users during additive schema deployment.
- The owner reviews the RFC choices at stage 001. Later namespace, authority,
  compatibility or rollback changes require an RFC amendment.

Stage 001 changes no runtime or schema behavior. Its only executable change adds
the integration branch to existing PR workflow filters.
