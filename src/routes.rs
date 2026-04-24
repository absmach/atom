use axum::{
    routing::{delete, get, post},
    Router,
};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use crate::{
    authz::handlers as authz,
    identity::handlers as identity,
    keys,
    state::AppState,
};

pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        // JWKS — unauthenticated, consumed by external verifiers
        .route("/.well-known/jwks.json", get(keys::jwks))
        // Health
        .route("/health", get(identity::health))
        // Auth
        .route("/auth/login", post(identity::login))
        .route("/auth/logout", post(identity::logout))
        .route("/auth/sessions/:id", get(identity::get_session))
        .route("/auth/keys/rotate", post(keys::rotate_keys))
        // Entities
        .route("/entities", get(identity::list_entities).post(identity::create_entity))
        .route(
            "/entities/:id",
            get(identity::get_entity)
                .put(identity::update_entity)
                .delete(identity::delete_entity),
        )
        // Credentials
        .route(
            "/entities/:id/credentials/password",
            post(identity::create_password),
        )
        .route(
            "/entities/:id/credentials/api-keys",
            post(identity::create_api_key),
        )
        .route(
            "/entities/:id/credentials",
            get(identity::list_credentials),
        )
        .route(
            "/entities/:entity_id/credentials/:cred_id",
            delete(identity::revoke_credential),
        )
        // Groups (on entity)
        .route("/entities/:id/groups", get(identity::get_entity_groups))
        // Ownerships
        .route(
            "/entities/:id/owned",
            get(identity::list_owned).post(identity::add_ownership),
        )
        .route(
            "/entities/:owner_id/owned/:owned_id",
            delete(identity::remove_ownership),
        )
        // Groups
        .route("/groups", get(identity::list_groups).post(identity::create_group))
        .route(
            "/groups/:id",
            get(identity::get_group).delete(identity::delete_group),
        )
        .route(
            "/groups/:id/members",
            get(identity::list_group_members).post(identity::add_group_member),
        )
        .route(
            "/groups/:group_id/members/:entity_id",
            delete(identity::remove_group_member),
        )
        // Resources
        .route("/resources", get(authz::list_resources).post(authz::create_resource))
        .route(
            "/resources/:id",
            get(authz::get_resource)
                .put(authz::update_resource)
                .delete(authz::delete_resource),
        )
        // Roles
        .route("/roles", get(authz::list_roles).post(authz::create_role))
        .route(
            "/roles/:id",
            get(authz::get_role).delete(authz::delete_role),
        )
        .route(
            "/roles/:id/capabilities",
            get(authz::get_role_capabilities).post(authz::add_role_capability),
        )
        .route(
            "/roles/:role_id/capabilities/:cap_id",
            delete(authz::remove_role_capability),
        )
        // Capabilities
        .route(
            "/capabilities",
            get(authz::list_capabilities).post(authz::create_capability),
        )
        .route(
            "/capabilities/:id",
            get(authz::get_capability).delete(authz::delete_capability),
        )
        // Policy Bindings
        .route(
            "/policies",
            get(authz::list_policies).post(authz::create_policy),
        )
        .route(
            "/policies/:id",
            get(authz::get_policy).delete(authz::delete_policy),
        )
        // Authorization check (PDP)
        .route("/authz/check", post(authz::check))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(cors)
}
