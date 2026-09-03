use async_graphql::{EmptySubscription, Schema};

use crate::state::AppState;

use super::{
    callout_ext::CalloutExtensionFactory,
    mutation::{mutation_root, MutationRoot},
    query::QueryRoot,
};

pub type AtomSchema = Schema<QueryRoot, MutationRoot, EmptySubscription>;

/// Deterministic GraphQL type-system contract used by the checked-in v1 SDL.
/// Runtime-only limits and extensions do not affect the schema shape.
pub fn schema_sdl() -> String {
    Schema::build(QueryRoot::default(), mutation_root(), EmptySubscription)
        .finish()
        .sdl()
}

pub fn build_schema(state: AppState) -> AtomSchema {
    let limits = state.config.graphql_limits;
    let builder = Schema::build(QueryRoot::default(), mutation_root(), EmptySubscription)
        .limit_depth(limits.max_depth)
        .limit_complexity(limits.max_complexity)
        .extension(CalloutExtensionFactory)
        .data(state)
        .disable_suggestions();
    if limits.introspection_enabled {
        builder.finish()
    } else {
        builder.disable_introspection().finish()
    }
}

#[cfg(test)]
mod tests {
    use async_graphql::Request;
    use serde_json::Value;
    use sqlx::postgres::PgPoolOptions;
    use std::collections::BTreeSet;

    use crate::{
        config::Config,
        keys::{ActiveKeys, LoadedKey},
        state::AppState,
    };

    use super::{build_schema, schema_sdl};

    #[test]
    fn checked_in_graphql_schema_matches_runtime_types() {
        assert_eq!(
            format!("{}\n", schema_sdl()),
            include_str!("../../apidocs/graphql-schema.graphql"),
            "GraphQL schema drifted; run `cargo run --example export-graphql-schema -- \
             apidocs/graphql-schema.graphql` and review the API change"
        );
    }

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
    async fn tenant_invitation_exposes_invitee_name() {
        let schema = build_schema(test_state());

        let response = schema
            .execute(Request::new(
                r#"
                {
                  __type(name: "TenantInvitation") {
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
        assert!(fields.contains("inviteeName"));
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
                      fields(includeDeprecated: true) {
                        name
                      }
                    }
                    mutationType {
                      fields(includeDeprecated: true) {
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
            "certificates",
            "certificate",
            "ownedEntities",
            "authorizedObjectIds",
            "roles",
            "role",
            "actions",
            "action",
            "actionApplicability",
            "actionAssignmentRules",
            "permissionBlocks",
            "permissionBlock",
            "roleAssignments",
            "directPolicies",
            "auditLogs",
            "entityAuditLogs",
            "orphanPolicies",
            "expiringCredentials",
            "systemStatus",
            "signingKeys",
        ] {
            assert!(query_fields.contains(name), "missing query field {name}");
        }

        for name in [
            "login",
            "logout",
            "refreshSession",
            "signup",
            "createTenant",
            "updateTenant",
            "deleteTenant",
            "enableTenant",
            "disableTenant",
            "freezeTenant",
            "addTenantMember",
            "removeTenantMember",
            "createProfile",
            "createProfileVersion",
            "createEntity",
            "addEntityToObjectGroup",
            "removeEntityFromObjectGroup",
            "clearEntityObjectGroups",
            "createResource",
            "updateResource",
            "addResourceToObjectGroup",
            "removeResourceFromObjectGroup",
            "clearResourceObjectGroups",
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
            "createAccessToken",
            "replaceAccessTokenPermissions",
            "revokeAccessToken",
            "createSharedKey",
            "revealSharedKey",
            "revokeCredential",
            "issueGeneratedCertificateV2",
            "issueCertificateFromCsrV2",
            "renewCertificateFromCsrV2",
            "renewGeneratedCertificateV2",
            "revokeCertificateV2",
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
            "createActionAssignmentRule",
            "deleteActionAssignmentRule",
            "createPermissionBlock",
            "deletePermissionBlock",
            "createRoleAssignment",
            "deleteRoleAssignment",
            "createDirectPolicy",
            "deleteDirectPolicy",
            "authzCheck",
            "authzExplain",
            "authzBulkCheck",
            "rotateSigningKeys",
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
            "unprotectedResources",
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

    /// `entities`, `groups` and `resources` all carry a JSONB `attributes`
    /// column, so all three should expose the same containment filter under
    /// the same name and type.
    #[tokio::test]
    async fn entity_group_and_resource_queries_expose_attributes_contains_filter() {
        let schema = build_schema(test_state());

        let response = schema
            .execute(Request::new(
                r#"
                {
                  __schema {
                    queryType {
                      fields {
                        name
                        args {
                          name
                          type { name }
                        }
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

        for name in ["entities", "groups", "resources"] {
            let field = query_fields
                .iter()
                .find(|field| field["name"].as_str() == Some(name))
                .unwrap_or_else(|| panic!("missing query field {name}"));
            let filter = field["args"]
                .as_array()
                .expect("args")
                .iter()
                .find(|arg| arg["name"].as_str() == Some("attributesContains"))
                .unwrap_or_else(|| panic!("{name} is missing the attributesContains filter"));
            assert_eq!(
                filter["type"]["name"].as_str(),
                Some("JSON"),
                "{name}.attributesContains must be an optional JSON object"
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
                  effect: __type(name: "Effect") { enumValues { name } }
                  credentialKind: __type(name: "CredentialKind") { enumValues { name } }
                  auditOutcome: __type(name: "AuditOutcome") { enumValues { name } }
                  assignmentRuleDecision: __type(name: "ActionAssignmentRuleDecision") { enumValues { name } }
                  createAssignmentRuleDecision: __type(name: "CreateActionAssignmentRuleDecision") { enumValues { name } }
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
            set(&["password", "access_token", "certificate", "shared_key"])
        );
        assert_eq!(
            enum_names(&data, "auditOutcome"),
            set(&["allow", "deny", "error"])
        );
        assert_eq!(
            enum_names(&data, "assignmentRuleDecision"),
            set(&["allow", "deny", "require_override"])
        );
        assert_eq!(
            enum_names(&data, "createAssignmentRuleDecision"),
            set(&["allow", "deny"])
        );
    }

    /// The exclusion is surprising unless it is written down where a caller
    /// reads it, so the field description is part of the deliverable, not a
    /// nicety: `directPolicies(objectId:)` returns policies *naming* the
    /// object, never everyone who can reach it.
    #[tokio::test]
    async fn direct_policies_documents_that_the_object_filter_is_not_effective_access() {
        let schema = build_schema(test_state());

        let response = schema
            .execute(Request::new(
                r#"
                {
                  __schema {
                    queryType {
                      fields {
                        name
                        description
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
        let field = data["__schema"]["queryType"]["fields"]
            .as_array()
            .expect("field array")
            .iter()
            .find(|field| field["name"] == "directPolicies")
            .expect("directPolicies field")
            .clone();

        let args = field_names(&field["args"]);
        for arg in ["objectId", "objectKind", "objectType"] {
            assert!(args.contains(arg), "missing {arg} argument");
        }

        let description = field["description"]
            .as_str()
            .expect("directPolicies must carry a field description");
        for excluded in ["platform", "tenant", "object_kind", "object_type"] {
            assert!(
                description.contains(excluded),
                "the description must name the excluded {excluded} scope"
            );
        }
        assert!(
            description.contains("not effective access"),
            "the description must say the result is not effective access"
        );
    }

    fn test_state() -> AppState {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://atom:atom@localhost/atom_test")
            .expect("create lazy test pool");
        let mut config = Config::for_tests();
        // These tests introspect the schema (__schema/__type), which is disabled
        // by default; turn it on for the test schema.
        config.graphql_limits.introspection_enabled = true;
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
