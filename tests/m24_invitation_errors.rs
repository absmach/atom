//! DB-gated tests for tenant invitation state-specific errors.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m24_invitation_errors -- --ignored
//! ```

mod common;

use atom::{error::AppError, models::tenant::CreateTenantInvitation, tenants::repo as tenant_repo};
use sqlx::PgPool;
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
