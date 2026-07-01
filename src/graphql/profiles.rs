use async_graphql::{Context, Object, Result, ID};
use serde_json::json;

use crate::{
    identity::profile_repo,
    models::profile::{CreateProfile, CreateProfileVersion, ListProfiles, UpdateProfile},
    state::AppState,
};

use super::{
    auth::{gql_error, require_auth, require_list_access, require_read_access, scope_for_tenant},
    types::{
        parse_id, parse_optional_id, CreateProfileInput, CreateProfileVersionInput, Profile,
        ProfileList, ProfileVersion, UpdateProfileInput,
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
        let profile = profile_repo::get_profile(&state.pool, id)
            .await
            .map_err(gql_error)?;
        require_read_access(&state.pool, &auth, profile.tenant_id, id).await?;
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
        let profile = profile_repo::get_profile(&state.pool, profile_id)
            .await
            .map_err(gql_error)?;
        require_read_access(&state.pool, &auth, profile.tenant_id, profile_id).await?;
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
            profile_repo::create_profile(
                &state.pool,
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

        crate::audit::observe_result(
            crate::audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id,
                target_kind: "profile",
                target_id: result.as_ref().ok().map(|p| p.id),
                event: "profile.create",
            },
            json!({}),
            &result,
        );

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
        let profile = profile_repo::get_profile(&state.pool, profile_id)
            .await
            .map_err(gql_error)?;
        let result = async {
            crate::auth::require_any_capability(
                &state.pool,
                &auth,
                &[
                    ("manage", scope_for_tenant(profile.tenant_id)),
                    ("write", scope_for_tenant(profile.tenant_id)),
                ],
            )
            .await?;
            profile_repo::create_profile_version(
                &state.pool,
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

        crate::audit::observe_result(
            crate::audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: profile.tenant_id,
                target_kind: "profile_version",
                target_id: result.as_ref().ok().map(|v| v.id),
                event: "profile_version.create",
            },
            json!({ "profile_id": profile_id }),
            &result,
        );

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
        let existing = profile_repo::get_profile(&state.pool, id)
            .await
            .map_err(gql_error)?;
        validate_profile_status(input.status.as_deref())?;

        let result = async {
            crate::auth::require_any_capability(
                &state.pool,
                &auth,
                &[
                    ("manage", scope_for_tenant(existing.tenant_id)),
                    ("write", scope_for_tenant(existing.tenant_id)),
                ],
            )
            .await?;
            profile_repo::update_profile(
                &state.pool,
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

        crate::audit::observe_result(
            crate::audit::AuditMeta {
                actor_entity_id: Some(auth.entity_id),
                tenant_id: existing.tenant_id,
                target_kind: "profile",
                target_id: Some(id),
                event: "profile.update",
            },
            json!({}),
            &result,
        );

        result.map(Into::into).map_err(gql_error)
    }
}

fn validate_profile_status(status: Option<&str>) -> Result<()> {
    match status {
        Some("active" | "deprecated" | "disabled") | None => Ok(()),
        Some(_) => Err(async_graphql::Error::new(
            "status must be active, deprecated, or disabled",
        )),
    }
}
