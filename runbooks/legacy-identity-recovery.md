# Legacy identity recovery runbook

Issue [#110](https://github.com/absmach/atom/issues/110), workstream B. This
runbook is the operator-facing half of that workstream: how to use the
dry-run report and the remediation mutations together, safely.

**Scope.** This procedure repairs identity-state drift that predates PR
#109 and the verified email-change flow (#115) — rows where `entity_emails`,
`credentials`, `oauth_identities`, or `entities.attributes.email` disagree
with each other. It does not cover ordinary user-initiated recovery (a user
who still controls their mailbox should use `/auth/email/change/request` or
the password-reset flow, not this runbook).

**Access required.** Every query and mutation described here is
platform-admin only (`manage` on `Scope::Platform`, via GraphQL). If you
cannot see `legacyUnverifiedEmails` in the schema, you don't have it.

## The governing rule

**Never mark an email verified, or trust an OAuth link, merely because a row
exists.** Every action below requires you to first establish *why* it's
safe — an existing verification token that was actually consumed, a valid
emailed invitation token, a verified IdP claim through the hardened linking
path (`identity::service::upsert_oauth_identity`), or evidence you can point
to in writing. If you can't articulate the evidence, don't act — leave the
row for a later pass and say why in your own tracking, not Atom's.

Local development's `ATOM_ALLOW_UNVERIFIED_EMAIL_LOGIN` bypass is a
convenience for *logging in*, nothing else. An address let through it is
**not** trusted for OAuth auto-linking, invitation discovery, or as evidence
for anything in this runbook — treat a dev database exactly like production
when following this procedure.

## Step 1 — back up

Take a database snapshot (or confirm your existing backup/PITR window covers
the moment you're about to start) before making any mutation. Every
mutation below is scoped to one row and individually reversible in principle,
but a snapshot is the only *unconditional* rollback boundary — see
"Rollback boundaries" below for what each mutation can and cannot undo on
its own.

## Step 2 — run the dry-run report

Four read-only, paginated queries, each also accepting `entityId` to narrow
to one account once you're investigating a specific finding:

```graphql
{
  legacyUnverifiedEmails(limit: 50) {
    entityId email entityKind entityStatus emailCreatedAt
    pendingTokens { verification passwordReset emailChange invitation }
  }
  legacyCredentialIdentifierMismatches(limit: 50) {
    entityId credentialId identifier canonicalEmail canonicalVerifiedAt
    pendingTokens { verification passwordReset emailChange invitation }
  }
  legacyOauthEmailMismatches(limit: 50) {
    entityId provider subject oauthEmail oauthEmailVerified
    canonicalEmail canonicalVerifiedAt
    pendingTokens { verification passwordReset emailChange invitation }
  }
  legacyAttributesEmailMismatches(limit: 50) {
    entityId attributesEmail canonicalEmail canonicalVerifiedAt
    pendingTokens { verification passwordReset emailChange invitation }
  }
}
```

Page through with `limit`/`offset` until each list is empty. Nothing here
mutates any row — safe to run as often as you like, from any environment
with read access to a replica.

## Step 3 — triage each row

For every row, check `pendingTokens` **first**:

- `verification > 0` or `emailChange > 0` or `invitation > 0` — a
  self-service path is already in flight. The right action is usually to
  wait or nudge the user to finish it (resend a link, point them at the
  pending invitation), not to remediate administratively.
- `passwordReset > 0` alone doesn't resolve an unverified email — password
  reset doesn't touch `verified_at`.
- All zero — no self-service path is currently available; this is the
  population administrative recovery actually exists for.

## Step 4 — remediate

Every mutation below targets exactly one row (there is no bulk "fix
everything" entry point — that's deliberate) and is **idempotent**: calling
it again after it already took effect is a safe no-op, so a resumed or
re-run pass never fails on rows you already handled.

### Unverified email (`legacyUnverifiedEmails` / credential or attributes mismatches with no verified canonical email)

```graphql
mutation {
  recordAdministratorAssistedEmailVerification(
    entityId: "<entity-id>"
    evidence: "<what you checked, where, and when — this is stored verbatim in audit_logs>"
  )
}
```

`evidence` is required and non-empty — write enough that a later reviewer
can independently judge whether the recovery was justified (a ticket
number and what was confirmed against it is the minimum bar). This does not
touch `credentials.identifier` or `attributes.email` — re-run the report
after, and if a credential-identifier or attributes mismatch remains for the
same entity, that's a separate, still-open finding (see below).

Credential-identifier and `attributes.email` mismatches have no dedicated
remediation mutation in this PR: they're either resolved by the user running
`/auth/email/change/request` → `/auth/email/change/confirm` themselves (which
atomically fixes both), or by an administrator using the existing
`updateEntity`/credential-management GraphQL surface with the ordinary
audit trail that already provides.

### Suspicious OAuth link (`legacyOauthEmailMismatches`)

Decide **quarantine** vs **revoke**:

- **Quarantine** (reversible in principle, preserves the row) when you're not
  yet certain — the link stops authenticating and can't be silently
  refreshed by a fresh OAuth callback, but the row and its history survive
  for further investigation.
- **Revoke** (permanent) once you've confirmed the link was never authorized
  by the account owner, or quarantine has sat long enough that you're ready
  to close it out.

```graphql
mutation {
  quarantineOauthLink(
    entityId: "<entity-id>", provider: "<provider>", subject: "<subject>"
    reason: "<why this link is suspicious, and what you checked>"
  )
}

mutation {
  revokeOauthLink(
    entityId: "<entity-id>", provider: "<provider>", subject: "<subject>"
    reason: "<why this is being permanently removed>"
  )
}
```

`provider`/`subject` come straight off the report row. `reason` is required
for both, stored verbatim in `audit_logs`, same evidentiary bar as above.

## Step 5 — verify

Re-run the Step 2 query for the specific `entityId` you just touched. A
successfully remediated row disappears from its list — that's the
post-run verification signal. Cross-check `audit_logs` (`entityAuditLogs`)
for the `entity.update` event carrying the `field`/`evidence`/`reason` you
recorded, if you need a paper trail beyond what the mutation's success
already tells you.

## Rollback boundaries

- `recordAdministratorAssistedEmailVerification` has no mutation to reverse
  it — undoing a wrongly-recorded verification means restoring from the
  Step 1 backup, or a direct, individually-reviewed database update.
- `quarantineOauthLink` has no `unquarantineOauthLink` mutation yet — reversing
  it is a direct `UPDATE oauth_identities SET quarantined_at = NULL WHERE ...`
  by someone empowered to make that call, treated with the same evidentiary
  bar as quarantining it in the first place.
- `revokeOauthLink` is a hard delete. It cannot be undone by Atom at all —
  the user must complete OAuth again, which itself requires their canonical
  email to already be verified.

None of this is destructive to anything *other* than the single targeted
row, and every action is audited — but "audited" is not "reversible."
Treat the Step 1 backup as the real undo button for anything this runbook
doesn't give you a mutation to reverse.
