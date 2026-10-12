# RFC: Tenant-local identity contracts (ATOM-TLI-001)

Status: Draft; proposed decisions for maintainer review, not deployed behavior.
Owner: @arvindh123. Review: Atom maintainers and authentication/security.
Related: [#99](https://github.com/absmach/atom/issues/99),
[PRD](../product/tenant-local-identities/prd.md),
[delivery](../product/tenant-local-identities/delivery.md).

## Current state

Inspected main baseline: 775a32627d9c0ce4b52cd536cfea198c623b530c.

- src/identity/service.rs::write_signup_human inserts a human with NULL tenant_id;
  resolve_login_identity supports legacy identifier fallback.
- src/models/session.rs::SignupRequest lacks tenant selection. Login has optional
  tenant ID/alias; Session does not snapshot a home tenant.
- migrations/001_initial.sql ends with global live lower(email) uniqueness.
  migrations/sqlite/ contains the paired SQLite baseline.
- src/auth.rs and api/v1/jwt-contract.json already use tid for identity tenant.
  Preserve its v1 meaning, type and nullability.
- src/identity/refresh_tokens.rs ties opaque refresh families to sessions.
- OAuth includes Google, GitHub and Apple; migration 006 adds client binding.
- Self-service email change is limited to global humans and covered by
  tests/m52_email_change.rs.
- api/v1/ and scripts/check-v1-contracts.sh freeze current public contracts.

All following contracts are future behavior. This PR alters no API, runtime code,
or baseline migration. Implement future DB work through the current repository
abstraction and private native adapters required by project instructions; rebase
against ongoing adapter changes rather than extending legacy SQL translation.

## Decisions

### D1. Store scope explicitly; distinguish ownership from isolation

Use exhaustive IdentityScope (platform, tenant) and TenantIdentityMode (global,
tenant_local), stored in DB columns, not attributes. Platform scope requires NULL
entity tenant_id; tenant scope requires a real tenant. Kind remains independent.
Enforce consistency in both databases and shared service validation.

An isolated identity has tenant scope and a home tenant in tenant_local mode.
Scope alone must not change existing cross-tenant authorization. Legacy tenant-owned
machines/humans in global tenants keep their current behavior until explicitly
migrated. Global describes legacy tenant mode, not necessarily NULL entity ownership.

Backfill NULL ownership to platform and non-NULL to tenant; existing tenants remain
global. Report missing/deleted owners and incompatible assignments before migration.
Do not infer app users from email or change their kind. Once isolated, normal
mutations cannot move home, change to platform scope, or change kind to escape the
boundary.

### D2. Database tenant mode is authoritative

Generic Atom tenant creation retains global as the compatibility default. Atomic
must explicitly request tenant_local for new app tenants. A deployment availability
gate can disable local functionality, but cannot override DB mode or fall back to
global authentication for a local tenant. Disabled/incomplete local paths fail closed.

Only platform-authorized provisioning/migration selects or transitions mode.
Ordinary tenant metadata updates cannot toggle it. Populated tenants require the
migration protocol, not a one-field update. Local-to-global changes are unsupported
once local identities are active.

### D3. Resolve namespace before identifier lookup

Use an exhaustive internal context: platform, legacy tenant or local tenant.
Resolve UUID/alias to a DB tenant; reject both supplied together, malformed selectors
and ineligible tenants. Store UUIDs, never mutable aliases, in tokens and links.

A public selector requests a namespace; it is not authorization. Validate against
server-owned app configuration when an app binding exists, rejecting conflicting
path/body/header selectors. Do not infer a trusted app from arbitrary Host, Origin,
forwarded headers or attributes. Without an app binding, an explicit valid selector
chooses the namespace; credentials and enrollment policy still control admission.

Local lookup is exact (home tenant, scope, normalized identifier). Apply it to email,
UUID, name, alias, external ID and credential ID; no global/attribute-email fallback.
Legacy fallback stays only in legacy flows and always excludes isolated identities,
even if the identifier is unique. Unqualified login cannot discover a local account.

Share resolved-context validation across transports, internal services, bootstrap,
refresh, broker credential lookup and certificate identity mapping.

### D4. Preserve legacy entry points; add explicit platform selection

Proposed additive wire contract: identity_scope="platform" on POST /auth/login
selects only platform entities and rejects a simultaneous tenant selector. Add the
equivalent optional enum to applicable GraphQL/gRPC inputs without renumbering
protobuf fields. Unknown enum values and contradictory inputs fail as bad requests.

Unqualified login preserves legacy non-isolated behavior. Tenant ID/alias requests
use the selected tenant's mode. Local login requires exactly one tenant selector;
never scan emails, credentials or memberships to guess the home.

Signup, resend-verification and password-reset request gain optional tenant_id /
tenant_alias inputs. Unqualified legacy requests address only the legacy namespace.
Server-owned enrollment settings choose whether signup is open and the tenant's
Member role; no client role input. Closed enrollment never reveals email existence.

Token-consuming verification/reset/email-change/invitation endpoints derive home
from immutable stored token state. Optional app context must match. Authenticated
self-service derives home from the session, never a browser override.

Keep generic transport error categories consistent with AppError. Every owning PR
must update generated contracts and prove backward compatibility; optional fields
do not authorize changing existing unqualified v1 behavior.

### D5. Namespace uniqueness without an unsafe rollout gap

Canonical email rows need an enforced entity-consistent namespace: NULL for legacy
identities (including unmigrated tenant-owned identities), home UUID for isolated
identities. Use separate partial live unique indexes for the NULL namespace and
(namespace, lower(email)); NULL must not allow duplicate platform emails. Apply
existing normalization, not provider-specific plus/dot rewriting.

Enforce namespace/entity consistency on every writer and migration, including DB
constraints/triggers appropriate to each backend. Public validation alone is insufficient.
Provider links need namespace, provider/issuer identity, client binding and provider
subject. Preserve migration 006's client binding. Foreign namespace/entity combinations
must fail; one provider account may enroll independently in A and B.

Stage 002 adds/backfills state while retaining the stricter global email/provider
indexes. Local tenants are not enabled yet. Relax the old indexes only in an
activation migration after every reader/writer is namespace-aware and old binaries
are fenced out. Dropping uniqueness while unqualified fetch_optional readers remain
would create ambiguous identity selection.

### D6. Sessions and every credential inherit immutable home

Persist session identity scope/home at issuance, including refresh-family parent
sessions. Local session home, entity home, JWT tid, request target tenant and app
binding must agree. Recheck online lifecycle/revocation and admission state. New
context must participate in cache keys/snapshots or use versioning/invalidation at
cutover; an old global cache result cannot satisfy a local lookup.

Retain existing sub/sid/tid JWT claims, with a required non-NULL tid for local
identities and NULL for platform identities. Old tokens without local context cannot
be promoted to local sessions. No permissions in JWTs. Refresh keeps the original
home and rechecks revocation, lifecycle and membership eligibility. Logout,
introspection and session list/revoke follow the same boundary.

Access/shared keys and certificates resolve owner/home before authorization.
Requests without an explicit target derive home from the authenticated identity;
object-addressed requests resolve the object's owning tenant. Foreign targets fail
even if a grant otherwise permits access. Apply the check to creation, rotation,
replacement, revoke, list and reveal.

Keep the broker wire contract unchanged. Local identifier login needs a qualified
request or configured trusted binding; never guess a home across tenants. Broker
topic allow patterns cannot bypass the local home boundary.

### D7. Recovery, invitations and OAuth carry namespace state

Verification, reset, setup and email-change tokens are single-use, expiring and
bound to entity + home. Recheck lifecycle and captured identity state at consumption.
Preserve recent-session email-change requirements, managed-by guards, reset/change
token invalidation and session revocation. A reset in A cannot consume B's tokens.

Local signup/recovery/resend return the same generic accepted category for existing
and new eligible emails. Duplicate signup never changes credentials or assigns a
different role. Bound resends with rate limits. Malformed input may fail before
lookup; authenticated admin conflicts can remain explicit. Avoid existence-dependent
fast paths, without claiming perfectly identical timing.

Invitation home and role come from the stored invitation. Accept only into that
tenant; prove mailbox/identity for an existing local account. A global session
alone cannot authorize acceptance. Invalid/revoked/expired tokens mutate nothing;
repeated acceptance publishes no new membership event. Invites cannot silently
reactivate suspended or individually deleted identities.

OAuth start selects server-approved namespace/provider configuration. Bind a random
high-entropy state token to server-side state carrying home, issuer/provider, client,
nonce, PKCE and approved return destination. Callback/exchange consume it once;
browser parameters cannot replace the bindings. Keep signature, issuer, audience and
provider-specific verified-email checks. Auto-link only verified canonical email
in the same namespace under the relevant locks. Never cross-link tenants.

### D8. App profiles are server-owned

Store enrollment settings and approved mail/provider profile references in protected
tenant configuration. Deployment-owned profiles define allowed providers, issuer/client,
templates and exact redirect destinations; secrets come from deployment secret sources.
Tenant admins cannot supply arbitrary discovery URLs, SMTP settings or redirects.
Platform operators approve references; bootstrap uses references, not reusable secrets.
Missing local profiles fail closed, without sibling/global fallback. Legacy config
remains the legacy default. A new secrets-management UI is not part of this feature.

### D9. Home is a precondition for permission evaluation

Reject isolated subjects in foreign memberships, assignments, policies and principal/
object groups. Validate inherited groups and permission-block scope, not just role
ownership or assignment tenant. Revalidate group/role-block changes too.

Enforce home at PDP, control-plane gates and authorized listings, including existing
or directly inserted invalid grants. Preserve canonical expansion, deny-overrides and
ABAC; do not add a separate evaluator. Platform admins with explicit authority can
manage local identities without becoming app users or gaining implicit impersonation.

Platform service/workload/device/application entities may cross tenants only through
explicit policies; kind alone grants nothing. Local machines obey local boundaries.
Legacy tenant-owned machines keep behavior until explicit migration and appear in
conflict reports if their grants cannot migrate.

Local membership suspension/removal blocks new and existing authentication until
explicitly restored. Entity status alone is insufficient; refresh and authorization
must check admission state.

## Migration, deployment and rollback

1. Add typed state and paired forward-only migrations, preserving defaults and old
   indexes. Never edit applied baseline 001. Keep local provisioning disabled.
2. Ship all namespace-aware readers/writers, guards, tokens, caches and lifecycle
   behavior. Deploy compatible binaries only, then apply activation migration/gate.
   Record a minimum compatible version; startup must reject unsafe downgrades after
   local state exists. A default-on flag cannot substitute for complete enforcement.
3. Dry-run a tenant with a stable migration ID. Report source-to-local mappings,
   email conflicts, absent/unverified addresses, foreign grants, managed config and
   non-human exceptions. Identifiers/counts are sufficient; never export secrets.
   Ambiguity blocks cutover; never silently link accounts or widen permissions.
4. Materialize distinct local entities using unique migration keys and resumable
   checkpoints. Copy reviewed profile data and tenant-valid assignments only.
   Do not copy hashes, keys, certificates or active sessions. Re-establish verification
   through tenant-specific setup or verified provider enrollment.
5. Fence tenant writes at cutover, check report freshness, atomically transition
   mappings/mode/admission, revoke affected old sessions/refresh families and invalidate
   caches. Deliver setup after commit. Shared global sessions may be logged out of
   other legacy apps as an explicit consequence. Preserve global identities/credentials
   for other tenants; old app membership grants cannot retain migrated app-user access.
6. Before activation, abandon staged rows safely while preserving the legacy mapping.
   After local identities/credentials/grants are active, do not flip mode back or run
   old binaries. Disable admission and roll forward with a compatible fix. Restoring
   a backup requires an operator-led outage and reconciliation of all newer writes;
   it is not a lossless rollback.

Delete/restore/purge reuse canonical paths. Individual restore keeps credentials
revoked; tenant restore respects tenant_deleted provenance, excludes individually
deleted children, and never revives later manual revocations, certs or sessions.

## Failures, privacy and observability

| Failure/threat | Required response |
|---|---|
| Selector, foreign object or token substitution | Reject before mutation; generic public error; correlate IDs without disclosing sibling accounts. |
| Concurrent signup/acceptance | One complete enrollment; replay cannot replace credentials or emit duplicate membership events. |
| Freeze/removal during login/refresh | Recheck admission using existing coordination order; no usable new session after the lifecycle fence. |
| Stale global cache entry | Namespace/version separation and invalidation; no cross-namespace fallback. |
| Mutation/outbox failure | Roll back together; safe retry. Compliance audit failure after commit remains non-fatal. |
| Mail failure after commit | Durable account remains; rate-limited tenant-bound resend, not another enrollment. |
| Interrupted migration/config drift | Persist stage/checkpoint; revalidate and resume the same mapping or stop before cutover. |
| Incorrect app profile | Fail closed; platform operator repairs reference, no global fallback. |

Reuse existing audit/outbox event names and compatible details; new names require
the frozen-contract process. Transport supplies correlation metadata when supported.
Success events commit with mutations; errors are observed only on failure.
Compliance audit retains its non-fatal semantics. No foreign keys from outbox
history to live objects.

Record migration ID, stage, counts and error categories. Reuse semantic metrics
with bounded labels, not email/tenant/token IDs. Operators inspect denial/error
spikes after cutover and disable admission on unexplained cross-tenant successes
or inconsistent mappings. Keep existing pre-hash rate limits. Namespace indexes
must support bounded lookup; inspect query plans on both DBs and measure latency.

## Validation and alternatives

The [PRD matrix](../product/tenant-local-identities/prd.md#requirements-and-traceability)
and [delivery checks](../product/tenant-local-identities/delivery.md#validation) are
the acceptance contract. Cover equal-password independent accounts, all credential
types, refresh replay, OAuth substitution, brokers, recursive groups, listings,
lifecycle races, one-connection safety, interrupted migration and stale caches.
Prove fresh Atom-only operation on both databases and preserve legacy suites.

Rejected alternatives: derived scope alone (less explicit contract), deployment-only
mode (no per-tenant rollout), global identities plus memberships (shared credentials),
hash copying (shared initial material), mandatory tenant context on all legacy
logins (breaks clients), early global-index removal (ambiguous lookup).

These choices are proposals for stage-001 review. Later namespace, authority,
compatibility or rollback changes require an RFC amendment. Configuration approval
and migration gates impose deliberate operational work for enforceable isolation.
