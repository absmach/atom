use async_graphql::{Context, Object, Result, ID};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    auth::AuthContext,
    error::{db_err, AppError},
    identity::profile_repo,
    models::profile::{
        CreateProfile, CreateProfileVersion, ListProfiles, UpdateProfile, UpdateProfileVersion,
    },
    state::AppState,
};

use super::{
    auth::{gql_error, require_auth, require_list_access, scope_for_tenant},
    types::{
        parse_id, parse_optional_id, CreateProfileInput, CreateProfileVersionInput, Profile,
        ProfileList, ProfileVersion, UpdateProfileInput, UpdateProfileVersionInput,
    },
};

#[derive(Default)]
pub struct ProfileQuery;

#[Object]
impl ProfileQuery {
    #[allow(clippy::too_many_arguments)]
    async fn profiles(
        &self,
        ctx: &Context<'_>,
        object_kind: Option<String>,
        kind: Option<String>,
        tenant_id: Option<ID>,
        status: Option<String>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<ProfileList> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(tenant_id, "tenantId")?;
        require_list_access(&state.pool, &auth, tenant_id).await?;
        let list = profile_repo::list_profiles(
            &state.pool,
            ListProfiles {
                tenant_id,
                object_kind,
                kind,
                key: None,
                status,
                limit: limit.map(i64::from).unwrap_or(20),
                offset: offset.map(i64::from).unwrap_or(0),
            },
        )
        .await
        .map_err(gql_error)?;

        Ok(ProfileList {
            items: list.items.into_iter().map(Profile::from).collect(),
            total: list.total,
        })
    }

    async fn profile(&self, ctx: &Context<'_>, id: ID) -> Result<Profile> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        require_profile_target_access(
            &state.pool,
            &auth,
            profile_tenant_target(&state.pool, id)
                .await
                .map_err(gql_error)?,
            id,
            "profile",
            &["read", "manage"],
        )
        .await
        .map_err(gql_error)?;
        let profile = profile_repo::get_profile(&state.pool, id)
            .await
            .map_err(gql_error)?;
        Ok(profile.into())
    }

    async fn profile_versions(
        &self,
        ctx: &Context<'_>,
        profile_id: ID,
    ) -> Result<Vec<ProfileVersion>> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let profile_id = parse_id(profile_id, "profileId")?;
        require_profile_target_access(
            &state.pool,
            &auth,
            profile_tenant_target(&state.pool, profile_id)
                .await
                .map_err(gql_error)?,
            profile_id,
            "profile",
            &["read", "manage"],
        )
        .await
        .map_err(gql_error)?;
        let versions = profile_repo::list_profile_versions(&state.pool, profile_id)
            .await
            .map_err(gql_error)?;
        Ok(versions.into_iter().map(ProfileVersion::from).collect())
    }
}

#[derive(Default)]
pub struct ProfileMutation;

#[Object]
impl ProfileMutation {
    async fn create_profile(
        &self,
        ctx: &Context<'_>,
        input: CreateProfileInput,
    ) -> Result<Profile> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let tenant_id = parse_optional_id(input.tenant_id, "tenantId")?;
        let result = async {
            crate::auth::require_any_capability(
                &state.pool,
                &auth,
                &[
                    ("manage", scope_for_tenant(tenant_id)),
                    ("write", scope_for_tenant(tenant_id)),
                ],
            )
            .await?;
            profile_repo::create_profile_with_audit(
                &state.pool,
                state.config.events.enabled(),
                Some(auth.entity_id),
                CreateProfile {
                    tenant_id,
                    object_kind: input.object_kind,
                    kind: input.kind,
                    key: input.key,
                    display_name: input.display_name,
                    description: input.description,
                    status: input.status,
                },
            )
            .await
        }
        .await;

        if let Err(ref err) = result {
            crate::audit::observe_error(
                &state.pool,
                state.config.events.enabled(),
                &crate::audit::AuditMeta {
                    actor_entity_id: Some(auth.entity_id),
                    tenant_id,
                    target_kind: "profile",
                    target_id: None,
                    event: "profile.create",
                },
                &json!({}),
                err,
            )
            .await;
        }

        result.map(Into::into).map_err(gql_error)
    }

    async fn create_profile_version(
        &self,
        ctx: &Context<'_>,
        profile_id: ID,
        input: CreateProfileVersionInput,
    ) -> Result<ProfileVersion> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let profile_id = parse_id(profile_id, "profileId")?;
        let target = profile_tenant_target(&state.pool, profile_id)
            .await
            .map_err(gql_error)?;
        let tenant_id = target.flatten();
        let result = async {
            require_profile_target_access(
                &state.pool,
                &auth,
                target,
                profile_id,
                "profile",
                &["manage", "write"],
            )
            .await?;
            profile_repo::create_profile_version_with_audit(
                &state.pool,
                state.config.events.enabled(),
                Some(auth.entity_id),
                tenant_id,
                profile_id,
                CreateProfileVersion {
                    version: input.version,
                    json_schema: input.json_schema.unwrap_or_else(|| json!({})),
                    ui_schema: input.ui_schema.unwrap_or_else(|| json!({})),
                    status: input.status,
                },
            )
            .await
        }
        .await;

        if let Err(ref err) = result {
            crate::audit::observe_error(
                &state.pool,
                state.config.events.enabled(),
                &crate::audit::AuditMeta {
                    actor_entity_id: Some(auth.entity_id),
                    tenant_id,
                    target_kind: "profile_version",
                    target_id: None,
                    event: "profile_version.create",
                },
                &json!({ "profile_id": profile_id }),
                err,
            )
            .await;
        }

        result.map(Into::into).map_err(gql_error)
    }

    async fn update_profile(
        &self,
        ctx: &Context<'_>,
        id: ID,
        input: UpdateProfileInput,
    ) -> Result<Profile> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let target = profile_tenant_target(&state.pool, id)
            .await
            .map_err(gql_error)?;
        let tenant_id = target.flatten();
        validate_profile_status(input.status.as_deref())?;

        let result = async {
            require_profile_target_access(
                &state.pool,
                &auth,
                target,
                id,
                "profile",
                &["manage", "write"],
            )
            .await?;
            profile_repo::update_profile_with_audit(
                &state.pool,
                state.config.events.enabled(),
                Some(auth.entity_id),
                id,
                UpdateProfile {
                    display_name: input.display_name,
                    description: input.description,
                    status: input.status,
                },
            )
            .await
        }
        .await;

        if let Err(ref err) = result {
            crate::audit::observe_error(
                &state.pool,
                state.config.events.enabled(),
                &crate::audit::AuditMeta {
                    actor_entity_id: Some(auth.entity_id),
                    tenant_id,
                    target_kind: "profile",
                    target_id: Some(id),
                    event: "profile.update",
                },
                &json!({}),
                err,
            )
            .await;
        }

        result.map(Into::into).map_err(gql_error)
    }

    // Status only — see UpdateProfileVersionInput for why jsonSchema/uiSchema
    // are not editable here.
    async fn update_profile_version(
        &self,
        ctx: &Context<'_>,
        id: ID,
        input: UpdateProfileVersionInput,
    ) -> Result<ProfileVersion> {
        let auth = require_auth(ctx)?;
        let state = ctx.data::<AppState>()?;
        let id = parse_id(id, "id")?;
        let target = profile_version_tenant_target(&state.pool, id)
            .await
            .map_err(gql_error)?;
        let tenant_id = target.and_then(|(_, tenant_id)| tenant_id);
        let profile_id = target.map(|(profile_id, _)| profile_id);
        validate_profile_version_status(input.status.as_deref())?;

        let result = async {
            require_profile_target_access(
                &state.pool,
                &auth,
                target.map(|(_, tenant_id)| tenant_id),
                id,
                "profile version",
                &["manage", "write"],
            )
            .await?;
            profile_repo::update_profile_version_with_audit(
                &state.pool,
                state.config.events.enabled(),
                Some(auth.entity_id),
                tenant_id,
                id,
                UpdateProfileVersion {
                    json_schema: None,
                    ui_schema: None,
                    status: input.status,
                },
            )
            .await
        }
        .await;

        if let Err(ref err) = result {
            crate::audit::observe_error(
                &state.pool,
                state.config.events.enabled(),
                &crate::audit::AuditMeta {
                    actor_entity_id: Some(auth.entity_id),
                    tenant_id,
                    target_kind: "profile_version",
                    target_id: Some(id),
                    event: "profile_version.update",
                },
                &json!({ "profile_id": profile_id }),
                err,
            )
            .await;
        }

        result.map(Into::into).map_err(gql_error)
    }
}

/// Resolve only the tenant boundary needed for the non-exact profile gate.
/// The caller must pass the outer `Option` to `require_profile_target_access`
/// before returning a row or a not-found error, so an unauthorized caller
/// cannot distinguish a missing id from a profile in another tenant.
async fn profile_tenant_target(
    pool: &PgPool,
    id: Uuid,
) -> std::result::Result<Option<Option<Uuid>>, AppError> {
    sqlx::query_scalar("SELECT tenant_id FROM profiles WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)
}

async fn profile_version_tenant_target(
    pool: &PgPool,
    id: Uuid,
) -> std::result::Result<Option<(Uuid, Option<Uuid>)>, AppError> {
    sqlx::query_as(
        r#"SELECT version.profile_id, profile.tenant_id
           FROM profile_versions version
           JOIN profiles profile ON profile.id = version.profile_id
           WHERE version.id = $1"#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

async fn require_profile_target_access(
    pool: &PgPool,
    auth: &AuthContext,
    target: Option<Option<Uuid>>,
    id: Uuid,
    label: &str,
    actions: &[&str],
) -> std::result::Result<Option<Uuid>, AppError> {
    let tenant_id = target.flatten();
    let scope = scope_for_tenant(tenant_id);
    let checks = actions
        .iter()
        .map(|action| (*action, scope))
        .collect::<Vec<_>>();
    crate::auth::require_any_capability(pool, auth, &checks).await?;
    if target.is_none() {
        return Err(AppError::not_found(format!("{label} {id} not found")));
    }
    Ok(tenant_id)
}

fn validate_profile_status(status: Option<&str>) -> Result<()> {
    match status {
        Some("active" | "deprecated" | "disabled") | None => Ok(()),
        Some(_) => Err(async_graphql::Error::new(
            "status must be active, deprecated, or disabled",
        )),
    }
}

fn validate_profile_version_status(status: Option<&str>) -> Result<()> {
    match status {
        Some("draft" | "active" | "deprecated" | "disabled") | None => Ok(()),
        Some(_) => Err(async_graphql::Error::new(
            "status must be draft, active, deprecated, or disabled",
        )),
    }
}
