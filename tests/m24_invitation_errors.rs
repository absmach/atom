//! DB-gated tests for tenant invitation state-specific errors.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m24_invitation_errors -- --ignored
//! ```

mod common;

use atom::{
    error::AppError,
    models::{
        enums::InvitationState,
        tenant::{CreateTenantInvitation, ListTenantInvitations},
    },
    tenants::repo as tenant_repo,
};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

async fn make_entity(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO entities (id, kind, name, status) VALUES ($1, 'human', $2, 'active')")
        .bind(id)
        .bind(name)
        .execute(pool)
        .await
        .expect("insert entity");
    id
}

async fn make_tenant(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(name)
        .execute(pool)
        .await
        .expect("insert tenant");
    id
}

async fn add_email(pool: &PgPool, entity_id: Uuid, email: &str) {
    sqlx::query(
        "INSERT INTO entity_emails (id, entity_id, email, verified_at) VALUES ($1, $2, $3, now())",
    )
    .bind(Uuid::new_v4())
    .bind(entity_id)
    .bind(email)
    .execute(pool)
    .await
    .expect("insert entity email");
}

async fn add_unverified_email(pool: &PgPool, entity_id: Uuid, email: &str) {
    sqlx::query("INSERT INTO entity_emails (id, entity_id, email) VALUES ($1, $2, $3)")
        .bind(Uuid::new_v4())
        .bind(entity_id)
        .bind(email)
        .execute(pool)
        .await
        .expect("insert unverified entity email");
}

async fn insert_user_invitation(
    pool: &PgPool,
    tenant_id: Uuid,
    inviter_id: Uuid,
    invitee_id: Uuid,
) -> Uuid {
    sqlx::query_scalar(
        r#"INSERT INTO tenant_invitations
             (id, tenant_id, invitee_user_id, invited_by, expires_at)
           VALUES ($1, $2, $3, $4, now() + interval '1 hour')
           RETURNING id"#,
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(invitee_id)
    .bind(inviter_id)
    .fetch_one(pool)
    .await
    .expect("insert invitation")
}

async fn create_email_invitation(
    pool: &PgPool,
    tenant_id: Uuid,
    inviter_id: Uuid,
    email: &str,
) -> (Uuid, String) {
    let created = tenant_repo::create_invitation(
        pool,
        tenant_id,
        inviter_id,
        CreateTenantInvitation {
            invitee_user_id: None,
            invitee_email: Some(email.to_string()),
            role_id: None,
            resend: false,
            redirect_url: None,
        },
        3600,
    )
    .await
    .expect("create invitation");
    (
        created.invitation.id,
        created.token.expect("email invitation token"),
    )
}

async fn set_invitation_state(pool: &PgPool, invitation_id: Uuid, state: &str) {
    let query = match state {
        "accepted" => "UPDATE tenant_invitations SET accepted_at = now() WHERE id = $1",
        "rejected" => "UPDATE tenant_invitations SET rejected_at = now() WHERE id = $1",
        "revoked" => "UPDATE tenant_invitations SET revoked_at = now() WHERE id = $1",
        "expired" => {
            "UPDATE tenant_invitations SET expires_at = now() - interval '1 hour' WHERE id = $1"
        }
        _ => panic!("unknown invitation state {state}"),
    };
    sqlx::query(query)
        .bind(invitation_id)
        .execute(pool)
        .await
        .expect("set invitation state");
}

fn assert_err_contains<T>(result: Result<T, AppError>, expected: &str) {
    match result {
        Ok(_) => panic!("expected error containing {expected}"),
        Err(err) => {
            let message = err.to_string();
            assert!(
                message.contains(expected),
                "expected error containing {expected}, got {message}"
            );
        }
    }
}

fn unknown_invitation_token() -> String {
    format!("atomi_{}_{}", Uuid::new_v4().simple(), "ab".repeat(32))
}

fn replace_token_secret(token: &str) -> String {
    let (prefix, _) = token.rsplit_once('_').expect("token has secret");
    format!("{prefix}_{}", "cd".repeat(32))
}

#[tokio::test]
#[ignore]
async fn direct_invitation_accept_reports_state_specific_errors() {
    let pool = common::pool().await;
    let inviter = make_entity(&pool, &format!("inviter-{}", Uuid::new_v4())).await;
    let invitee = make_entity(&pool, &format!("invitee-{}", Uuid::new_v4())).await;

    for (state, expected) in [
        ("accepted", "invitation already accepted"),
        ("rejected", "invitation already rejected"),
        ("revoked", "invitation already revoked"),
        ("expired", "invitation expired"),
    ] {
        let tenant = make_tenant(&pool, &format!("invitation-{state}-{}", Uuid::new_v4())).await;
        let invitation = insert_user_invitation(&pool, tenant, inviter, invitee).await;
        set_invitation_state(&pool, invitation, state).await;

        assert_err_contains(
            tenant_repo::accept_invitation(&pool, tenant, invitee).await,
            expected,
        );
    }

    let tenant = make_tenant(&pool, &format!("invitation-missing-{}", Uuid::new_v4())).await;
    assert_err_contains(
        tenant_repo::accept_invitation(&pool, tenant, invitee).await,
        "tenant invitation not found",
    );
}

#[tokio::test]
#[ignore]
async fn invitation_token_accept_reports_state_specific_errors() {
    let pool = common::pool().await;
    let inviter = make_entity(&pool, &format!("token-inviter-{}", Uuid::new_v4())).await;
    let invitee = make_entity(&pool, &format!("token-invitee-{}", Uuid::new_v4())).await;
    let email = format!("invitee-{}@example.test", Uuid::new_v4());
    add_email(&pool, invitee, &email).await;

    for (state, expected) in [
        ("accepted", "invitation already accepted"),
        ("rejected", "invitation already rejected"),
        ("revoked", "invitation already revoked"),
        ("expired", "invitation expired"),
    ] {
        let tenant = make_tenant(&pool, &format!("token-{state}-{}", Uuid::new_v4())).await;
        let (invitation, token) = create_email_invitation(&pool, tenant, inviter, &email).await;
        set_invitation_state(&pool, invitation, state).await;

        assert_err_contains(
            tenant_repo::accept_invitation_token(&pool, &token, invitee).await,
            expected,
        );
    }

    assert_err_contains(
        tenant_repo::accept_invitation_token(&pool, &unknown_invitation_token(), invitee).await,
        "invitation not found",
    );

    let invalid_tenant = make_tenant(&pool, &format!("token-invalid-{}", Uuid::new_v4())).await;
    let (_, valid_token) = create_email_invitation(&pool, invalid_tenant, inviter, &email).await;
    assert_err_contains(
        tenant_repo::accept_invitation_token(&pool, &replace_token_secret(&valid_token), invitee)
            .await,
        "invalid invitation token",
    );

    let wrong_user_tenant =
        make_tenant(&pool, &format!("token-wrong-user-{}", Uuid::new_v4())).await;
    let (_, token) = create_email_invitation(&pool, wrong_user_tenant, inviter, &email).await;
    let other = make_entity(&pool, &format!("token-other-{}", Uuid::new_v4())).await;
    assert_err_contains(
        tenant_repo::accept_invitation_token(&pool, &token, other).await,
        "invitation does not belong to this user",
    );
}

#[tokio::test]
#[ignore]
async fn email_invitation_token_proves_and_records_address_ownership() {
    let pool = common::pool().await;
    let inviter = make_entity(&pool, &format!("verified-inviter-{}", Uuid::new_v4())).await;
    let claimant = make_entity(&pool, &format!("verified-claimant-{}", Uuid::new_v4())).await;
    let email = format!("verified-{}@example.test", Uuid::new_v4());
    add_unverified_email(&pool, claimant, &email).await;
    let tenant = make_tenant(&pool, &format!("verified-tenant-{}", Uuid::new_v4())).await;
    let (invitation_id, token) = create_email_invitation(&pool, tenant, inviter, &email).await;

    let bound_invitee: Option<Uuid> =
        sqlx::query_scalar("SELECT invitee_user_id FROM tenant_invitations WHERE id = $1")
            .bind(invitation_id)
            .fetch_one(&pool)
            .await
            .expect("invitation binding");
    assert_eq!(
        bound_invitee, None,
        "an unverified address must not bind an invitation to an entity"
    );

    let hidden = tenant_repo::list_user_invitations(
        &pool,
        claimant,
        ListTenantInvitations {
            limit: 100,
            offset: 0,
            state: Some(InvitationState::Pending),
        },
    )
    .await
    .expect("list invitations for unverified address");
    assert_eq!(hidden.total, 0);
    assert!(hidden.items.is_empty());

    assert_err_contains(
        tenant_repo::accept_invitation(&pool, tenant, claimant).await,
        "tenant invitation not found",
    );
    assert_err_contains(
        tenant_repo::accept_invitation_token(&pool, &replace_token_secret(&token), claimant).await,
        "invalid invitation token",
    );
    let still_unverified: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT verified_at FROM entity_emails WHERE entity_id = $1")
            .bind(claimant)
            .fetch_one(&pool)
            .await
            .expect("verification state after invalid token");
    assert!(still_unverified.is_none());

    let accepted_tenant = tenant_repo::accept_invitation_token(&pool, &token, claimant)
        .await
        .expect("mailbox token proves the claimant owns the address");
    assert_eq!(accepted_tenant, tenant);

    let verified_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT verified_at FROM entity_emails WHERE entity_id = $1")
            .bind(claimant)
            .fetch_one(&pool)
            .await
            .expect("verification timestamp after token acceptance");
    assert!(verified_at.is_some());

    let accepted_by: Option<Uuid> = sqlx::query_scalar(
        "SELECT accepted_by FROM tenant_invitations WHERE id = $1 AND invitee_user_id = $2",
    )
    .bind(invitation_id)
    .bind(claimant)
    .fetch_one(&pool)
    .await
    .expect("accepted invitation binding");
    assert_eq!(accepted_by, Some(claimant));

    let second_tenant =
        make_tenant(&pool, &format!("verified-second-tenant-{}", Uuid::new_v4())).await;
    let (second_invitation_id, _) =
        create_email_invitation(&pool, second_tenant, inviter, &email).await;

    let visible = tenant_repo::list_user_invitations(
        &pool,
        claimant,
        ListTenantInvitations {
            limit: 100,
            offset: 0,
            state: Some(InvitationState::Pending),
        },
    )
    .await
    .expect("list invitations for verified address");
    assert_eq!(visible.total, 1);
    assert_eq!(visible.items.len(), 1);
    assert_eq!(visible.items[0].id, second_invitation_id);

    tenant_repo::accept_invitation(&pool, second_tenant, claimant)
        .await
        .expect("verified address accepts invitation");
}

#[tokio::test]
#[ignore]
async fn email_invitation_acceptance_works_with_a_single_connection_pool() {
    let setup_pool = common::pool().await;
    let inviter = make_entity(
        &setup_pool,
        &format!("single-connection-inviter-{}", Uuid::new_v4()),
    )
    .await;
    let invitee = make_entity(
        &setup_pool,
        &format!("single-connection-invitee-{}", Uuid::new_v4()),
    )
    .await;
    let email = format!("single-connection-{}@example.test", Uuid::new_v4());
    add_email(&setup_pool, invitee, &email).await;
    let tenant = make_tenant(
        &setup_pool,
        &format!("single-connection-tenant-{}", Uuid::new_v4()),
    )
    .await;
    let (_, token) = create_email_invitation(&setup_pool, tenant, inviter, &email).await;
    drop(setup_pool);

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("connect single-connection pool");

    let accepted_tenant = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tenant_repo::accept_invitation_token(&pool, &token, invitee),
    )
    .await
    .expect("accept must not wait for a second pool connection")
    .expect("accept email invitation");
    assert_eq!(accepted_tenant, tenant);
}

#[tokio::test]
#[ignore]
async fn reject_and_revoke_invitation_report_state_specific_errors() {
    let pool = common::pool().await;
    let inviter = make_entity(&pool, &format!("rr-inviter-{}", Uuid::new_v4())).await;
    let invitee = make_entity(&pool, &format!("rr-invitee-{}", Uuid::new_v4())).await;

    let missing_tenant = make_tenant(&pool, &format!("rr-missing-{}", Uuid::new_v4())).await;
    assert_err_contains(
        tenant_repo::reject_invitation(&pool, missing_tenant, invitee).await,
        "tenant invitation not found",
    );

    let accepted_tenant = make_tenant(&pool, &format!("rr-accepted-{}", Uuid::new_v4())).await;
    let accepted = insert_user_invitation(&pool, accepted_tenant, inviter, invitee).await;
    set_invitation_state(&pool, accepted, "accepted").await;
    assert_err_contains(
        tenant_repo::reject_invitation(&pool, accepted_tenant, invitee).await,
        "invitation already accepted",
    );

    let revoked_tenant = make_tenant(&pool, &format!("rr-revoked-{}", Uuid::new_v4())).await;
    let revoked = insert_user_invitation(&pool, revoked_tenant, inviter, invitee).await;
    set_invitation_state(&pool, revoked, "revoked").await;
    assert_err_contains(
        tenant_repo::revoke_invitation_by_id(&pool, revoked_tenant, revoked).await,
        "invitation already revoked",
    );

    assert_err_contains(
        tenant_repo::revoke_invitation_by_id(&pool, revoked_tenant, Uuid::new_v4()).await,
        "tenant invitation not found",
    );
}

#[tokio::test]
#[ignore]
async fn reinviting_existing_invitee_keeps_the_emailed_token_valid() {
    let pool = common::pool().await;
    let inviter = make_entity(&pool, &format!("reinvite-inviter-{}", Uuid::new_v4())).await;
    let invitee = make_entity(&pool, &format!("reinvite-invitee-{}", Uuid::new_v4())).await;
    let email = format!("reinvite-{}@example.test", Uuid::new_v4());
    add_email(&pool, invitee, &email).await;
    let tenant = make_tenant(&pool, &format!("reinvite-tenant-{}", Uuid::new_v4())).await;

    let (first_id, _first_token) = create_email_invitation(&pool, tenant, inviter, &email).await;
    // Inviting the same person again for the same tenant hits create_invitation's
    // UPDATE branch (there's already a row matching on invitee_email), reusing
    // that row's id rather than inserting a new one.
    let (second_id, second_token) = create_email_invitation(&pool, tenant, inviter, &email).await;
    assert_eq!(
        first_id, second_id,
        "re-inviting the same person should reuse their existing invitation row"
    );

    // The freshly emailed (second) token must resolve to that row.
    let accepted_tenant = tenant_repo::accept_invitation_token(&pool, &second_token, invitee)
        .await
        .expect("accept the just-sent invitation token");
    assert_eq!(accepted_tenant, tenant);

    // The superseded first token pointed at the same row id but an old
    // secret, so it now fails signature verification rather than the row
    // itself being unreachable — a stale link errors clearly instead of
    // reporting "invitation not found" for a link that was never sent.
    let inviter2 = make_entity(&pool, &format!("reinvite-inviter2-{}", Uuid::new_v4())).await;
    let invitee2 = make_entity(&pool, &format!("reinvite-invitee2-{}", Uuid::new_v4())).await;
    let email2 = format!("reinvite2-{}@example.test", Uuid::new_v4());
    add_email(&pool, invitee2, &email2).await;
    let tenant2 = make_tenant(&pool, &format!("reinvite-tenant2-{}", Uuid::new_v4())).await;
    let (_, stale_token) = create_email_invitation(&pool, tenant2, inviter2, &email2).await;
    let (_, _fresh_token) = create_email_invitation(&pool, tenant2, inviter2, &email2).await;
    assert_err_contains(
        tenant_repo::accept_invitation_token(&pool, &stale_token, invitee2).await,
        "invalid invitation token",
    );
}

#[tokio::test]
#[ignore]
async fn expired_invitations_are_excluded_from_the_pending_filter() {
    let pool = common::pool().await;
    let inviter = make_entity(&pool, &format!("expiry-inviter-{}", Uuid::new_v4())).await;
    let invitee = make_entity(&pool, &format!("expiry-invitee-{}", Uuid::new_v4())).await;
    let tenant = make_tenant(&pool, &format!("expiry-tenant-{}", Uuid::new_v4())).await;

    let still_pending = insert_user_invitation(&pool, tenant, inviter, invitee).await;
    let other_invitee = make_entity(&pool, &format!("expiry-invitee2-{}", Uuid::new_v4())).await;
    let expired = insert_user_invitation(&pool, tenant, inviter, other_invitee).await;
    set_invitation_state(&pool, expired, "expired").await;

    let pending = tenant_repo::list_tenant_invitations(
        &pool,
        tenant,
        ListTenantInvitations {
            limit: 100,
            offset: 0,
            state: Some(InvitationState::Pending),
        },
    )
    .await
    .expect("list pending invitations");

    assert_eq!(
        pending.total, 1,
        "expired invitation must not count toward the pending total"
    );
    assert_eq!(
        pending.items.len(),
        1,
        "expired invitation must not appear in the pending list"
    );
    assert_eq!(pending.items[0].id, still_pending);
    assert!(
        pending.items.iter().all(|item| item.id != expired),
        "expired invitation leaked into the pending list"
    );

    let user_pending = tenant_repo::list_user_invitations(
        &pool,
        other_invitee,
        ListTenantInvitations {
            limit: 100,
            offset: 0,
            state: Some(InvitationState::Pending),
        },
    )
    .await
    .expect("list user's pending invitations");
    assert_eq!(
        user_pending.total, 0,
        "the expired invitee's own pending list must not include it either"
    );
    assert!(user_pending.items.is_empty());
}
