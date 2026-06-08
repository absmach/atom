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
    async fn login_response_exposes_email_verification_fields() {
        let schema = build_schema(test_state());

        let response = schema
            .execute(Request::new(
                r#"
                {
                  __type(name: "LoginResponse") {
                    fields {
                      name
                    }
                  }
                }
                "#,
            ))
            .await;

        assert!(response.errors.is_empty(), "{:?}", response.errors);
        let data = response.data.into_json().expect("json data");
        let fields = field_names(&data["__type"]["fields"]);
        assert!(fields.contains("emailVerified"));
        assert!(fields.contains("verificationRequired"));
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
            "apiEndpoints",
            "apiEndpoint",
            "apiEndpointExecutions",
            "groups",
            "group",
            "objectGroups",
            "principalGroups",
            "groupMembers",
            "entityGroups",
            "credentials",
            "caChain",
            "certificates",
            "certificate",
            "ownedEntities",
            "authorizedObjectIds",
            "roles",
            "role",
            "actions",
            "action",
            "actionApplicability",
            "permissionBlocks",
            "permissionBlock",
            "roleAssignments",
            "directPolicies",
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
            "signup",
            "createTenant",
            "updateTenant",
            "deleteTenant",
            "enableTenant",
            "disableTenant",
            "freezeTenant",
            "removeTenantMember",
            "createProfile",
            "createProfileVersion",
            "createEntity",
            "addEntityToObjectGroup",
            "removeEntityFromObjectGroup",
            "setEntityParentGroup",
            "clearEntityParentGroup",
            "createResource",
            "updateResource",
            "addResourceToObjectGroup",
            "removeResourceFromObjectGroup",
            "setResourceParentGroup",
            "clearResourceParentGroup",
            "deleteResource",
            "createApiEndpoint",
            "updateApiEndpoint",
            "enableApiEndpoint",
            "disableApiEndpoint",
            "createGroup",
            "createObjectGroup",
            "createPrincipalGroup",
            "setObjectGroupParent",
            "removeObjectGroupParent",
            "deleteGroup",
            "addGroupMember",
            "removeGroupMember",
            "createPassword",
            "createApiKey",
            "revokeCredential",
            "issueCertificate",
            "issueCertificateFromCsr",
            "renewCertificate",
            "revokeCertificate",
            "revokeEntityCertificates",
            "addOwnership",
            "removeOwnership",
            "createRole",
            "deleteRole",
            "replaceRolePermissionBlocks",
            "createAction",
            "updateAction",
            "deleteAction",
            "addActionApplicability",
            "removeActionApplicability",
            "createPermissionBlock",
            "deletePermissionBlock",
            "createRoleAssignment",
            "deleteRoleAssignment",
            "createDirectPolicy",
            "deleteDirectPolicy",
            "authzCheck",
            "authzExplain",
            "authzBulkCheck",
        ] {
            assert!(
                mutation_fields.contains(name),
                "missing mutation field {name}"
            );
        }

        for name in [
            "apiTemplates",
            "apiTemplate",
            "capabilities",
            "capability",
            "policies",
            "policy",
            "roleCapabilities",
            "rolePolicies",
            "subjectRoleAssignments",
        ] {
            assert!(
                !query_fields.contains(name),
                "unexpected query field {name}"
            );
        }

        for name in [
            "createApiTemplate",
            "updateApiTemplate",
            "disableApiTemplate",
            "addRoleCapability",
            "removeRoleCapability",
            "addCompositeRoleChild",
            "removeCompositeRoleChild",
            "replaceCompositeRoleChildren",
            "assignRoleToEntity",
            "assignRoleToPrincipalGroup",
            "removeAssignment",
            "removeRoleAssignment",
            "createCapability",
            "deleteCapability",
            "createPolicy",
            "deletePolicy",
        ] {
            assert!(
                !mutation_fields.contains(name),
                "unexpected mutation field {name}"
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
    async fn api_endpoint_schema_is_self_contained() {
        let schema = build_schema(test_state());

        let response = schema
            .execute(Request::new(
                r#"
                {
                  endpointType: __type(name: "ApiEndpoint") {
                    fields { name }
                  }
                  createInput: __type(name: "CreateApiEndpointInput") {
                    inputFields { name }
                  }
                  updateInput: __type(name: "UpdateApiEndpointInput") {
                    inputFields { name }
                  }
                  templateType: __type(name: "ApiTemplate") {
                    name
                  }
                }
                "#,
            ))
            .await;

        assert!(response.errors.is_empty(), "{:?}", response.errors);
        let data = response.data.into_json().expect("json data");
        let endpoint_fields = field_names(&data["endpointType"]["fields"]);
        assert!(endpoint_fields.contains("operationKind"));
        assert!(endpoint_fields.contains("graphql"));
        assert!(!endpoint_fields.contains("templateId"));

        let create_fields = field_names(&data["createInput"]["inputFields"]);
        assert!(create_fields.contains("operationKind"));
        assert!(create_fields.contains("graphql"));
        assert!(!create_fields.contains("templateId"));

        let update_fields = field_names(&data["updateInput"]["inputFields"]);
        assert!(update_fields.contains("operationKind"));
        assert!(update_fields.contains("graphql"));
        assert!(!update_fields.contains("templateId"));
        assert!(data["templateType"].is_null());
    }

    #[tokio::test]
    async fn roles_query_exposes_derived_kind_filter() {
        let schema = build_schema(test_state());

        let response = schema
            .execute(Request::new(
                r#"
                {
                  __schema {
                    queryType {
                      fields {
                        name
                        args { name }
                      }
                    }
                  }
                }
                "#,
            ))
            .await;

        assert!(response.errors.is_empty(), "{:?}", response.errors);
        let data = response.data.into_json().expect("json data");
        let query_fields = data["__schema"]["queryType"]["fields"]
            .as_array()
            .expect("query fields");
        let roles_field = query_fields
            .iter()
            .find(|field| field["name"].as_str() == Some("roles"))
            .expect("roles field");
        let arg_names = field_names(&roles_field["args"]);

        assert!(arg_names.contains("derivedKind"));
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
            jwt_issuer: "http://localhost:8080".to_string(),
            jwt_audience: "magistrala".to_string(),
            admin_entity_id: ADMIN_ENTITY_ID,
            admin_secret: None,
            service_secret: None,
            service_entity_id: crate::config::SERVICE_ENTITY_ID,
            signup_enabled: false,
            dev_allow_unverified_email_login: false,
            public_base_url: "http://localhost:8080".into(),
            cors_allowed_origins: vec!["http://localhost:8080".into()],
            auth_cookie_secure: false,
            auth_cookie_domain: None,
            email_verification_redirect: "http://localhost:8080/auth/email/verify".into(),
            password_reset_redirect: "http://localhost:8080/reset-password".into(),
            invitation_redirect: "http://localhost:8080/invitations/accept".into(),
            oauth_success_redirect: "http://localhost:8080".into(),
            oauth_error_redirect: "http://localhost:8080".into(),
            oidc_providers: vec![],
            smtp: None,
            email_verification_expiry_secs: 86_400,
            invitation_expiry_secs: 604_800,
            oauth_state_expiry_secs: 600,
            auth_exchange_code_expiry_secs: 300,
            certs_enabled: false,
            certs_ca_mode: crate::config::CertsCaMode::FileIntermediateIssuer,
            certs_root_ca_cert_path: None,
            certs_intermediate_ca_cert_path: None,
            certs_intermediate_ca_key_path: None,
            certs_root_ca_key_path: None,
            certs_leaf_default_ttl_secs: 2_592_000,
            certs_leaf_max_ttl_secs: 2_592_000,
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
            None,
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
