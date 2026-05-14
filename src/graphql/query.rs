use async_graphql::MergedObject;

#[derive(MergedObject, Default)]
pub struct QueryRoot(
    super::auth::AuthQuery,
    super::tenants::TenantQuery,
    super::profiles::ProfileQuery,
    super::entities::EntityQuery,
    super::resources::ResourceQuery,
    super::api_endpoints::ApiEndpointQuery,
    super::groups::GroupQuery,
    super::credentials::CredentialQuery,
    super::policies::PolicyQuery,
    super::admin::AdminQuery,
);
