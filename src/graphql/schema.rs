use async_graphql::{EmptySubscription, Schema};

use crate::state::AppState;

use super::{
    mutation::{mutation_root, MutationRoot},
    query::QueryRoot,
};

pub type AtomSchema = Schema<QueryRoot, MutationRoot, EmptySubscription>;

pub fn build_schema(state: AppState) -> AtomSchema {
    Schema::build(QueryRoot::default(), mutation_root(), EmptySubscription)
        .data(state)
        .finish()
}

#[cfg(test)]
mod tests {
    use async_graphql::Request;
    use serde_json::Value;
    use sqlx::postgres::PgPoolOptions;
    use std::collections::BTreeSet;

    use crate::{
        config::{Config, ADMIN_ENTITY_ID},
        keys::{ActiveKeys, LoadedKey},
        state::AppState,
    };

    use super::build_schema;

    #[tokio::test]
    async fn health_query_returns_ok() {
        let schema = build_schema(test_state());

        let response = schema.execute(Request::new("{ health }")).await;

        assert!(response.errors.is_empty(), "{:?}", response.errors);
        assert_eq!(
            response.data.into_json().unwrap(),
            serde_json::json!({"health": "ok"})
        );
    }

    #[tokio::test]
    async fn protected_queries_require_authentication_before_db_access() {
        let schema = build_schema(test_state());

        let response = schema
            .execute(Request::new(
                r#"
                {
                  entities {
                    total
                  }
                }
                "#,
            ))
            .await;

        assert!(!response.errors.is_empty());
        assert!(response.errors[0]
            .message
            .contains("missing authentication"));
    }

    #[tokio::test]
    async fn unsupported_login_kind_returns_clear_error() {
        let schema = build_schema(test_state());

        let response = schema
            .execute(Request::new(
                r#"
                mutation {
                  login(input: {
                    identifier: "atom-admin",
                    secret: "change-me",
                    kind: "api_key"
                  }) {
                    token
                  }
                }
                "#,
            ))
            .await;

        assert!(!response.errors.is_empty());
        assert!(response.errors[0]
            .message
            .contains("unsupported credential kind: api_key"));
    }

    #[tokio::test]
    async fn schema_exposes_generic_atom_operations_only() {
        let schema = build_schema(test_state());

        let response = schema
            .execute(Request::new(
                r#"
                {
                  __schema {
                    queryType {
                      fields {
                        name
                      }
                    }
                    mutationType {
                      fields {
                        name
                      }
                    }
                  }
                }
                "#,
            ))
            .await;

        assert!(response.errors.is_empty(), "{:?}", response.errors);
        let data = response.data.into_json().expect("json data");
        let query_fields = field_names(&data["__schema"]["queryType"]["fields"]);
        let mutation_fields = field_names(&data["__schema"]["mutationType"]["fields"]);

        for name in [
            "health",
            "session",
            "tenants",
            "tenant",
            "profiles",
            "profile",
            "profileVersions",
            "entities",
            "entity",
            "resources",
            "resource",
            "groups",
            "group",
            "groupMembers",
            "entityGroups",
            "credentials",
            "ownedEntities",
            "roles",
            "role",
            "capabilities",
            "capability",
            "policies",
            "policy",
            "auditLogs",
            "entityAuditLogs",
            "orphanPolicies",
            "unprotectedResources",
            "expiringCredentials",
        ] {
            assert!(query_fields.contains(name), "missing query field {name}");
        }

        for name in [
            "login",
            "logout",
            "createTenant",
            "updateTenant",
            "deleteTenant",
            "enableTenant",
            "disableTenant",
            "freezeTenant",
            "createProfile",
            "createProfileVersion",
            "createEntity",
            "createResource",
            "updateResource",
            "deleteResource",
            "createGroup",
            "deleteGroup",
            "addGroupMember",
            "removeGroupMember",
            "createPassword",
            "createApiKey",
            "revokeCredential",
            "addOwnership",
            "removeOwnership",
            "createRole",
            "deleteRole",
            "addRoleCapability",
            "removeRoleCapability",
            "createCapability",
            "deleteCapability",
            "createPolicy",
            "deletePolicy",
            "authzCheck",
            "authzExplain",
            "authzBulkCheck",
        ] {
            assert!(
                mutation_fields.contains(name),
                "missing mutation field {name}"
            );
        }

        for suffix in ["Domain", "Client", "Channel"] {
            let name = format!("create{suffix}");
            assert!(
                !query_fields.contains(&name),
                "unexpected query field {name}"
            );
            assert!(
                !mutation_fields.contains(&name),
                "unexpected mutation field {name}"
            );
        }
    }

    #[tokio::test]
    async fn schema_enum_values_match_atom_storage_values() {
        let schema = build_schema(test_state());

        let response = schema
            .execute(Request::new(
                r#"
                {
                  entityKind: __type(name: "EntityKind") { enumValues { name } }
                  entityStatus: __type(name: "EntityStatus") { enumValues { name } }
                  tenantStatus: __type(name: "TenantStatus") { enumValues { name } }
                  subjectKind: __type(name: "SubjectKind") { enumValues { name } }
                  grantKind: __type(name: "GrantKind") { enumValues { name } }
                  scopeKind: __type(name: "ScopeKind") { enumValues { name } }
                  effect: __type(name: "Effect") { enumValues { name } }
                  credentialKind: __type(name: "CredentialKind") { enumValues { name } }
                  auditOutcome: __type(name: "AuditOutcome") { enumValues { name } }
                }
                "#,
            ))
            .await;

        assert!(response.errors.is_empty(), "{:?}", response.errors);
        let data = response.data.into_json().expect("json data");

        assert_eq!(
            enum_names(&data, "entityKind"),
            set(&["human", "device", "service", "workload", "application"])
        );
        assert_eq!(
            enum_names(&data, "entityStatus"),
            set(&["active", "inactive", "suspended"])
        );
        assert_eq!(
            enum_names(&data, "tenantStatus"),
            set(&["active", "inactive", "frozen", "deleted"])
        );
        assert_eq!(enum_names(&data, "subjectKind"), set(&["entity", "group"]));
        assert_eq!(enum_names(&data, "grantKind"), set(&["capability", "role"]));
        assert_eq!(
            enum_names(&data, "scopeKind"),
            set(&["platform", "tenant", "object_kind", "object_type", "object"])
        );
        assert_eq!(enum_names(&data, "effect"), set(&["allow", "deny"]));
        assert_eq!(
            enum_names(&data, "credentialKind"),
            set(&["password", "api_key", "certificate"])
        );
        assert_eq!(
            enum_names(&data, "auditOutcome"),
            set(&["allow", "deny", "error"])
        );
    }

    fn test_state() -> AppState {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://atom:atom@localhost/atom_test")
            .expect("create lazy test pool");
        let config = Config {
            database_url: "postgres://atom:atom@localhost/atom_test".into(),
            listen_addr: "127.0.0.1:0".into(),
            grpc_addr: "127.0.0.1:0".into(),
            jwt_expiry_secs: 3600,
            admin_entity_id: ADMIN_ENTITY_ID,
            admin_secret: None,
        };
        let primary = LoadedKey {
            kid: "test".into(),
            public_key_pem: String::new(),
            private_key_pem: String::new(),
            x_b64: String::new(),
            y_b64: String::new(),
        };
        AppState::new(
            pool,
            config,
            ActiveKeys {
                primary,
                standby: None,
            },
        )
    }

    fn field_names(value: &Value) -> BTreeSet<String> {
        value
            .as_array()
            .expect("field array")
            .iter()
            .map(|field| field["name"].as_str().expect("field name").to_string())
            .collect()
    }

    fn enum_names(data: &Value, type_name: &str) -> BTreeSet<String> {
        data[type_name]["enumValues"]
            .as_array()
            .expect("enum values")
            .iter()
            .map(|value| value["name"].as_str().expect("enum value name").to_string())
            .collect()
    }

    fn set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }
}
