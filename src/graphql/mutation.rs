use async_graphql::MergedObject;

#[derive(MergedObject, Default)]
pub struct MutationRoot(
    super::auth::AuthMutation,
    super::tenants::TenantMutation,
    super::profiles::ProfileMutation,
    super::entities::EntityMutation,
    super::resources::ResourceMutation,
    super::api_endpoints::ApiEndpointMutation,
    super::groups::GroupMutation,
    super::credentials::CredentialMutation,
    super::policies::PolicyMutation,
    super::authz::AuthzMutation,
);

pub fn mutation_root() -> MutationRoot {
    MutationRoot::default()
}
