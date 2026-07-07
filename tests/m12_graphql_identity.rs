//! GraphQL generic identity operation tests.
//!
//! Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m12_graphql_identity -- --ignored
//! ```

mod common;

use async_graphql::Request;
use atom::{
    auth::{authenticate_token, AuthContext},
    config::Config,
    graphql::build_schema,
    identity::service as identity_service,
    keys::{ActiveKeys, LoadedKey},
    models::enums::{CredentialKind, CredentialStatus},
    state::AppState,
};
use sqlx::PgPool;
use uuid::Uuid;

fn state(pool: PgPool) -> AppState {
    let config = Config::for_tests();
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

fn authed(query: impl Into<String>) -> Request {
    Request::new(query).data(AuthContext {
        entity_id: common::admin_id(),
        tenant_id: None,
        session_id: None,
        ..Default::default()
    })
}

fn authed_as(entity_id: Uuid, query: impl Into<String>) -> Request {
    Request::new(query).data(AuthContext {
        entity_id,
        tenant_id: None,
        session_id: None,
        ..Default::default()
    })
}

fn authed_scoped(
    entity_id: Uuid,
    ceiling: atom::authz::repo::CredentialCeiling,
    query: impl Into<String>,
) -> Request {
    authed_scoped_with_credential(entity_id, Uuid::new_v4(), ceiling, query)
}

/// Like `authed_scoped`, but with the real credential id — required by the
/// ceiling-aware listing surfaces, which re-read the ceiling rows by credential.
fn authed_scoped_with_credential(
    entity_id: Uuid,
    credential_id: Uuid,
    ceiling: atom::authz::repo::CredentialCeiling,
    query: impl Into<String>,
) -> Request {
    Request::new(query).data(AuthContext {
        entity_id,
        tenant_id: None,
        session_id: None,
        credential_id: Some(credential_id),
        scoped: true,
        ceiling: Some(std::sync::Arc::new(ceiling)),
        ..Default::default()
    })
}

async fn entity(pool: &PgPool, kind: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO entities (id, kind, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(id)
        .bind(kind)
        .bind(format!("graphql-identity-{kind}-{id}"))
        .execute(pool)
        .await
        .expect("insert entity");
    id
}

#[tokio::test]
#[ignore]
async fn create_group_returns_group() {
    let pool = common::pool().await;
    let schema = build_schema(state(pool));
    let name = format!("graphql-group-{}", Uuid::new_v4());

    let missing_type = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createGroup(input: {{
                name: "{name}-missing"
              }}) {{
                id
              }}
            }}
            "#
        )))
        .await;
    assert!(
        missing_type
            .errors
            .iter()
            .any(|err| err.message.contains("groupType is required")),
        "{:?}",
        missing_type.errors
    );

    let response = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createGroup(input: {{
                name: "{name}",
                groupType: "object",
                description: "GraphQL group"
              }}) {{
                id
                name
                groupType
                tenantId
                description
              }}
            }}
            "#
        )))
        .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let group = &response.data.into_json().expect("json data")["createGroup"];
    assert_eq!(group["name"], name);
    assert_eq!(group["groupType"], "object");
    assert_eq!(group["description"], "GraphQL group");
    assert!(group["id"].as_str().is_some());
}

#[tokio::test]
#[ignore]
async fn add_and_remove_group_member() {
    let pool = common::pool().await;
    let member_id = entity(&pool, "device").await;
    let schema = build_schema(state(pool));
    let name = format!("graphql-members-{}", Uuid::new_v4());

    let created = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createPrincipalGroup(input: {{ name: "{name}" }}) {{
                id
              }}
            }}
            "#
        )))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);
    let group_id = created.data.into_json().expect("json data")["createPrincipalGroup"]["id"]
        .as_str()
        .expect("group id")
        .to_owned();

    let added = schema
        .execute(authed(format!(
            r#"
            mutation {{
              addGroupMember(groupId: "{group_id}", entityId: "{member_id}")
            }}
            "#
        )))
        .await;
    assert!(added.errors.is_empty(), "{:?}", added.errors);
    assert_eq!(
        added.data.into_json().expect("json data")["addGroupMember"],
        true
    );

    let listed = schema
        .execute(authed(format!(
            r#"
            {{
              groupMembers(groupId: "{group_id}") {{
                id
              }}
              entityGroups(entityId: "{member_id}")
            }}
            "#
        )))
        .await;
    assert!(listed.errors.is_empty(), "{:?}", listed.errors);
    let data = listed.data.into_json().expect("json data");
    assert!(data["groupMembers"]
        .as_array()
        .expect("members")
        .iter()
        .any(|item| item["id"] == member_id.to_string()));
    assert!(data["entityGroups"]
        .as_array()
        .expect("groups")
        .iter()
        .any(|id| id == group_id.as_str()));

    let removed = schema
        .execute(authed(format!(
            r#"
            mutation {{
              removeGroupMember(groupId: "{group_id}", entityId: "{member_id}")
            }}
            "#
        )))
        .await;
    assert!(removed.errors.is_empty(), "{:?}", removed.errors);
    assert_eq!(
        removed.data.into_json().expect("json data")["removeGroupMember"],
        true
    );
}

#[tokio::test]
#[ignore]
async fn create_access_token_returns_secret_once_and_credentials_list_contains_it() {
    let pool = common::pool().await;
    let entity_id = entity(&pool, "service").await;
    let schema = build_schema(state(pool));

    // Admin mints a token for the service entity (delegated) — admin holds global
    // manage, so this is the sole credential-provisioning path now that the
    // dedicated API-key surface is gone.
    let created = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createAccessToken(input: {{
                name: "GraphQL provisioning token"
                subjectId: "{entity_id}"
                permissions: [{{ actions: ["read"], scopeMode: "platform" }}]
              }}) {{
                credentialId
                token
                expiresAt
              }}
            }}
            "#
        )))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);
    let api_key = &created.data.into_json().expect("json data")["createAccessToken"];
    let credential_id = api_key["credentialId"]
        .as_str()
        .expect("credential id")
        .to_owned();
    assert!(api_key["token"]
        .as_str()
        .is_some_and(|token| token.starts_with("atom_")));

    let listed = schema
        .execute(authed(format!(
            r#"
            {{
              credentials(entityId: "{entity_id}") {{
                items {{
                  id
                  kind
                  status
                  identifier
                }}
                total
              }}
            }}
            "#
        )))
        .await;
    assert!(listed.errors.is_empty(), "{:?}", listed.errors);
    let credentials = listed.data.into_json().expect("json data")["credentials"]["items"]
        .as_array()
        .expect("credentials")
        .clone();
    assert!(credentials.iter().any(|credential| {
        credential["id"] == credential_id
            && credential["kind"] == "access_token"
            && credential["status"] == "active"
    }));
}

#[tokio::test]
#[ignore]
async fn access_tokens_are_self_scoped_with_permission_ceiling() {
    let pool = common::pool().await;
    let owner_id = entity(&pool, "human").await;
    let other_id = entity(&pool, "human").await;
    let auth_state = state(pool.clone());
    let schema = build_schema(state(pool.clone()));
    let name = format!("graphql-token-{}", Uuid::new_v4());

    // Self-service creation requires a permission ceiling.
    let empty = schema
        .execute(authed_as(
            owner_id,
            format!(
                r#"mutation {{ createAccessToken(input: {{ name: "{name}-empty", permissions: [] }}) {{ credentialId }} }}"#
            ),
        ))
        .await;
    assert!(!empty.errors.is_empty());
    assert!(empty.errors[0].message.contains("at least one permission"));

    let created = schema
        .execute(authed_as(
            owner_id,
            format!(
                r#"
                mutation {{
                  createAccessToken(input: {{
                    name: "{name}",
                    description: "CLI access",
                    expiresAt: "2999-01-01T00:00:00Z",
                    permissions: [
                      {{ actions: ["read"], scopeMode: "object_kind", objectKind: "entity" }}
                    ]
                  }}) {{
                    credentialId
                    token
                    name
                    description
                  }}
                }}
                "#
            ),
        ))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);
    let created_json = created.data.into_json().expect("json data");
    let pat = &created_json["createAccessToken"];
    let credential_id = pat["credentialId"]
        .as_str()
        .expect("credential id")
        .parse::<Uuid>()
        .expect("credential uuid");
    let token = pat["token"].as_str().expect("token").to_owned();
    assert!(token.starts_with("atom_"));
    assert_eq!(pat["name"], name);

    let (kind, scoped, status): (CredentialKind, bool, CredentialStatus) =
        sqlx::query_as("SELECT kind, scoped, status FROM credentials WHERE id = $1")
            .bind(credential_id)
            .fetch_one(&pool)
            .await
            .expect("credential row");
    assert_eq!(kind, CredentialKind::AccessToken);
    assert!(scoped);
    assert_eq!(status, CredentialStatus::Active);

    let limit_actions: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM credential_permission_limits l
           JOIN credential_permission_limit_actions la ON la.limit_id = l.id
           WHERE l.credential_id = $1"#,
    )
    .bind(credential_id)
    .fetch_one(&pool)
    .await
    .expect("limit count");
    assert_eq!(limit_actions, 1);

    // Owner sees the token with its permission summary; the secret is not listed.
    let owner_listed = schema
        .execute(authed_as(
            owner_id,
            r#"{ accessTokens { items { credentialId name status scoped permissions { actions scopeMode objectKind } } total } }"#,
        ))
        .await;
    assert!(owner_listed.errors.is_empty(), "{:?}", owner_listed.errors);
    let owner_json = owner_listed.data.into_json().expect("json data");
    let listed = owner_json["accessTokens"]["items"]
        .as_array()
        .expect("token list")
        .iter()
        .find(|item| item["credentialId"] == credential_id.to_string())
        .expect("listed token")
        .clone();
    assert_eq!(listed["scoped"], true);
    assert_eq!(listed["permissions"][0]["actions"][0], "read");
    assert_eq!(listed["permissions"][0]["objectKind"], "entity");
    assert!(!listed.as_object().unwrap().contains_key("token"));

    // Self-scoped: a different entity sees none of the owner's tokens.
    let other_listed = schema
        .execute(authed_as(
            other_id,
            r#"{ accessTokens { items { credentialId } total } }"#,
        ))
        .await;
    assert_eq!(
        other_listed.data.into_json().expect("json data")["accessTokens"]["total"],
        0
    );

    let authenticated = authenticate_token(&auth_state, &token)
        .await
        .expect("token authenticates");
    assert_eq!(authenticated.entity_id, owner_id);
    assert!(authenticated.session_id.is_none());

    // A caller without credential-management authority over the owner cannot
    // revoke (delegated revoke requires `manage` on the owner or its tenant).
    let other_revoke = schema
        .execute(authed_as(
            other_id,
            format!(r#"mutation {{ revokeAccessToken(credentialId: "{credential_id}") }}"#),
        ))
        .await;
    assert!(!other_revoke.errors.is_empty());

    let owner_revoke = schema
        .execute(authed_as(
            owner_id,
            format!(r#"mutation {{ revokeAccessToken(credentialId: "{credential_id}") }}"#),
        ))
        .await;
    assert!(owner_revoke.errors.is_empty(), "{:?}", owner_revoke.errors);
    assert!(authenticate_token(&auth_state, &token).await.is_err());
}

/// The PDP intersects a scoped token's ceiling with the owner's live grants:
/// the owner can read+manage the object, but a read-only token cannot manage it,
/// and removing the owner's grant drops the token's access entirely.
#[tokio::test]
#[ignore]
async fn access_token_ceiling_intersects_owner_grants() {
    use atom::authz::{engine, repo as authz_repo};
    use atom::models::policy::AuthzRequest;

    let pool = common::pool().await;
    let owner_id = entity(&pool, "human").await;
    let object_id = entity(&pool, "device").await;

    // Owner gets read+manage on the object via a direct policy permission block.
    let block_id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO permission_blocks (id, scope_mode, object_id, effect)
           VALUES ($1, 'object', $2, 'allow')"#,
    )
    .bind(block_id)
    .bind(object_id)
    .execute(&pool)
    .await
    .expect("insert block");
    for action in ["read", "manage"] {
        sqlx::query(
            r#"INSERT INTO permission_block_actions (permission_block_id, action_id)
               SELECT $1, id FROM actions WHERE name = $2"#,
        )
        .bind(block_id)
        .bind(action)
        .execute(&pool)
        .await
        .expect("insert block action");
    }
    sqlx::query(
        r#"INSERT INTO direct_policies (subject_kind, subject_id, permission_block_id)
           VALUES ('entity', $1, $2)"#,
    )
    .bind(owner_id)
    .bind(block_id)
    .execute(&pool)
    .await
    .expect("insert direct policy");

    // A read-only access token for the owner.
    let token = identity_service::create_access_token(
        &pool,
        &Default::default(),
        owner_id,
        atom::models::token::CreateAccessToken {
            name: "reader".into(),
            description: None,
            expires_at: None,
            permissions: vec![atom::models::token::AccessTokenPermission {
                actions: vec!["read".into()],
                scope_mode: "object".into(),
                tenant_id: None,
                object_kind: None,
                object_type: None,
                object_id: Some(object_id),
                conditions: None,
            }],
        },
        true,
    )
    .await
    .expect("create access token");
    let ceiling = authz_repo::load_credential_ceiling(&pool, token.credential_id)
        .await
        .expect("load ceiling");

    let read_req = AuthzRequest {
        subject_id: owner_id,
        action: "read".into(),
        resource_id: None,
        object_kind: Some("entity".into()),
        object_id: Some(object_id),
        context: serde_json::Value::Null,
    };
    let manage_req = AuthzRequest {
        subject_id: owner_id,
        action: "manage".into(),
        resource_id: None,
        object_kind: Some("entity".into()),
        object_id: Some(object_id),
        context: serde_json::Value::Null,
    };

    // Owner alone can do both.
    assert!(
        engine::evaluate_with_ceiling(&pool, &read_req, None)
            .await
            .unwrap()
            .allowed
    );
    assert!(
        engine::evaluate_with_ceiling(&pool, &manage_req, None)
            .await
            .unwrap()
            .allowed
    );

    // Through the read-only token: read allowed, manage denied by the ceiling.
    assert!(
        engine::evaluate_with_ceiling(&pool, &read_req, Some(&ceiling))
            .await
            .unwrap()
            .allowed
    );
    assert!(
        !engine::evaluate_with_ceiling(&pool, &manage_req, Some(&ceiling))
            .await
            .unwrap()
            .allowed
    );

    // Control-plane gate path is capped too: a scoped token's AuthContext denies
    // a manage gate its ceiling omits, even though the owner can manage.
    let scoped_auth = atom::auth::AuthContext {
        entity_id: owner_id,
        scoped: true,
        ceiling: Some(std::sync::Arc::new(ceiling.clone())),
        ..Default::default()
    };
    assert!(atom::auth::has_capability_in_scope(
        &pool,
        &scoped_auth,
        "read",
        atom::auth::Scope::Object(object_id),
    )
    .await
    .unwrap());
    assert!(!atom::auth::has_capability_in_scope(
        &pool,
        &scoped_auth,
        "manage",
        atom::auth::Scope::Object(object_id),
    )
    .await
    .unwrap());

    // Remove the owner's grant: the token's access disappears immediately.
    sqlx::query("DELETE FROM direct_policies WHERE subject_id = $1")
        .bind(owner_id)
        .execute(&pool)
        .await
        .expect("delete policy");
    assert!(
        !engine::evaluate_with_ceiling(&pool, &read_req, Some(&ceiling))
            .await
            .unwrap()
            .allowed
    );
}

#[tokio::test]
#[ignore]
async fn scoped_token_cannot_manage_credentials_or_escalate_self_check() {
    use atom::authz::repo as authz_repo;

    let pool = common::pool().await;
    let owner = entity(&pool, "human").await;
    let object = entity(&pool, "device").await;
    let schema = build_schema(state(pool.clone()));

    // Owner holds read+manage on the object.
    let block_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO permission_blocks (id, scope_mode, object_id, effect) VALUES ($1, 'object', $2, 'allow')",
    )
    .bind(block_id)
    .bind(object)
    .execute(&pool)
    .await
    .expect("block");
    for action in ["read", "manage"] {
        sqlx::query(
            "INSERT INTO permission_block_actions (permission_block_id, action_id) SELECT $1, id FROM actions WHERE name = $2",
        )
        .bind(block_id)
        .bind(action)
        .execute(&pool)
        .await
        .expect("block action");
    }
    sqlx::query(
        "INSERT INTO direct_policies (subject_kind, subject_id, permission_block_id) VALUES ('entity', $1, $2)",
    )
    .bind(owner)
    .bind(block_id)
    .execute(&pool)
    .await
    .expect("policy");

    // A second readable object outside the token ceiling: the owner's authorized
    // set is {object, second_object}, the ceiling covers only {object}.
    let second_object = entity(&pool, "device").await;
    let second_block_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO permission_blocks (id, scope_mode, object_id, effect) VALUES ($1, 'object', $2, 'allow')",
    )
    .bind(second_block_id)
    .bind(second_object)
    .execute(&pool)
    .await
    .expect("second block");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) SELECT $1, id FROM actions WHERE name = 'read'",
    )
    .bind(second_block_id)
    .execute(&pool)
    .await
    .expect("second block action");
    sqlx::query(
        "INSERT INTO direct_policies (subject_kind, subject_id, permission_block_id) VALUES ('entity', $1, $2)",
    )
    .bind(owner)
    .bind(second_block_id)
    .execute(&pool)
    .await
    .expect("second policy");

    // Owner mints a read-only access token for itself (unscoped session).
    let created = schema
        .execute(authed_as(
            owner,
            format!(
                r#"mutation {{ createAccessToken(input: {{ name: "ro", permissions: [{{ actions: ["read"], scopeMode: "object", objectId: "{object}" }}] }}) {{ credentialId }} }}"#
            ),
        ))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);
    let cred_id = created.data.into_json().expect("json")["createAccessToken"]["credentialId"]
        .as_str()
        .expect("id")
        .parse::<Uuid>()
        .expect("uuid");
    let ceiling = authz_repo::load_credential_ceiling(&pool, cred_id)
        .await
        .expect("ceiling");

    // Finding 1: a scoped token cannot mint, widen, or revoke tokens.
    let mint = schema
        .execute(authed_scoped(
            owner,
            ceiling.clone(),
            format!(
                r#"mutation {{ createAccessToken(input: {{ name: "wider", permissions: [{{ actions: ["manage"], scopeMode: "object", objectId: "{object}" }}] }}) {{ credentialId }} }}"#
            ),
        ))
        .await;
    assert!(!mint.errors.is_empty(), "scoped token must not mint tokens");
    let widen = schema
        .execute(authed_scoped(
            owner,
            ceiling.clone(),
            format!(
                r#"mutation {{ replaceAccessTokenPermissions(credentialId: "{cred_id}", permissions: [{{ actions: ["manage"], scopeMode: "object", objectId: "{object}" }}]) }}"#
            ),
        ))
        .await;
    assert!(
        !widen.errors.is_empty(),
        "scoped token must not widen ceilings"
    );
    // Ceiling rows unchanged (still read-only).
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT a.name FROM credential_permission_limits l JOIN credential_permission_limit_actions la ON la.limit_id = l.id JOIN actions a ON a.id = la.action_id WHERE l.credential_id = $1",
    )
    .bind(cred_id)
    .fetch_all(&pool)
    .await
    .expect("actions");
    assert_eq!(actions, vec!["read".to_string()]);

    // Finding 2: self authzCheck via the scoped token returns the token-limited
    // answer — read allowed, manage denied — despite the owner holding manage.
    let read = schema
        .execute(authed_scoped(
            owner,
            ceiling.clone(),
            format!(
                r#"mutation {{ authzCheck(input: {{ subjectId: "{owner}", action: "read", objectKind: "entity", objectId: "{object}" }}) {{ allowed }} }}"#
            ),
        ))
        .await;
    assert!(read.errors.is_empty(), "{:?}", read.errors);
    assert_eq!(
        read.data.into_json().expect("json")["authzCheck"]["allowed"],
        true
    );

    let manage = schema
        .execute(authed_scoped(
            owner,
            ceiling.clone(),
            format!(
                r#"mutation {{ authzCheck(input: {{ subjectId: "{owner}", action: "manage", objectKind: "entity", objectId: "{object}" }}) {{ allowed }} }}"#
            ),
        ))
        .await;
    assert!(manage.errors.is_empty(), "{:?}", manage.errors);
    assert_eq!(
        manage.data.into_json().expect("json")["authzCheck"]["allowed"],
        false,
        "scoped token self-check must reflect the ceiling, not owner authority"
    );

    // authzExplain must apply the ceiling too (engine level: the GraphQL surface
    // gates explain behind platform-manage, which a narrow ceiling cannot pass).
    // The owner holds manage, but the read-only ceiling denies it and no matched
    // binding leaks — otherwise a scoped caller gets a misleading "allowed".
    let scoped_owner_auth = atom::auth::AuthContext {
        entity_id: owner,
        scoped: true,
        ceiling: Some(std::sync::Arc::new(ceiling.clone())),
        ..Default::default()
    };
    let explain_manage = atom::authz::engine::explain(
        &pool,
        &atom::models::policy::AuthzRequest {
            subject_id: owner,
            action: "manage".into(),
            resource_id: None,
            object_kind: Some("entity".into()),
            object_id: Some(object),
            context: serde_json::Value::Null,
        },
        &scoped_owner_auth,
    )
    .await
    .expect("explain");
    assert!(
        !explain_manage.allowed,
        "explain must apply the scoped-token ceiling"
    );
    assert_eq!(
        explain_manage.reason,
        "denied by access token permission ceiling"
    );
    assert!(
        explain_manage.matched_binding.is_none(),
        "capped explain must not expose a matched binding"
    );

    // Authorized listing is ceiling-aware: the session sees the owner's full
    // set, the scoped token sees only what its ceiling covers.
    let session_listed = schema
        .execute(authed_as(
            owner,
            format!(
                r#"{{ authorizedObjectIds(input: {{ subjectId: "{owner}", action: "read", objectKind: "entity" }}) {{ ids total }} }}"#
            ),
        ))
        .await;
    assert!(
        session_listed.errors.is_empty(),
        "{:?}",
        session_listed.errors
    );
    let session_json = session_listed.data.into_json().expect("json");
    assert_eq!(
        session_json["authorizedObjectIds"]["total"], 2,
        "owner session must list both readable objects"
    );

    let scoped_listed = schema
        .execute(authed_scoped_with_credential(
            owner,
            cred_id,
            ceiling.clone(),
            format!(
                r#"{{ authorizedObjectIds(input: {{ subjectId: "{owner}", action: "read", objectKind: "entity" }}) {{ ids total }} }}"#
            ),
        ))
        .await;
    assert!(
        scoped_listed.errors.is_empty(),
        "{:?}",
        scoped_listed.errors
    );
    let scoped_json = scoped_listed.data.into_json().expect("json");
    assert_eq!(
        scoped_json["authorizedObjectIds"]["ids"],
        serde_json::json!([object.to_string()]),
        "scoped token listing must be capped to the ceiling"
    );

    // The generic entity listing applies the same cap.
    let scoped_entities = schema
        .execute(authed_scoped_with_credential(
            owner,
            cred_id,
            ceiling.clone(),
            r#"{ entities { total } }"#,
        ))
        .await;
    assert!(
        scoped_entities.errors.is_empty(),
        "{:?}",
        scoped_entities.errors
    );
    assert_eq!(
        scoped_entities.data.into_json().expect("json")["entities"]["total"],
        1,
        "entity listing through a scoped token must be ceiling-capped"
    );

    // Surfaces outside the ceiling return empty sets, not errors.
    for (query, path) in [
        (r#"{ resources { total } }"#, "resources"),
        (r#"{ groups { total } }"#, "groups"),
    ] {
        let listed = schema
            .execute(authed_scoped_with_credential(
                owner,
                cred_id,
                ceiling.clone(),
                query,
            ))
            .await;
        assert!(listed.errors.is_empty(), "{query}: {:?}", listed.errors);
        assert_eq!(
            listed.data.into_json().expect("json")[path]["total"],
            0,
            "{path} must be empty under an entity-only ceiling"
        );
    }

    // Tenant visibility is ceiling-aware too: an entity-only ceiling yields an
    // empty tenant list, not an error.
    let tenants = schema
        .execute(authed_scoped_with_credential(
            owner,
            cred_id,
            ceiling.clone(),
            r#"{ tenants { total } }"#,
        ))
        .await;
    assert!(tenants.errors.is_empty(), "{:?}", tenants.errors);
    assert_eq!(
        tenants.data.into_json().expect("json")["tenants"]["total"],
        0,
        "tenant visibility must be empty under an entity-only ceiling"
    );
}

#[tokio::test]
#[ignore]
async fn replace_access_token_permissions_is_owner_only_and_non_empty() {
    let pool = common::pool().await;
    let owner_id = entity(&pool, "human").await;
    let other_id = entity(&pool, "human").await;
    let schema = build_schema(state(pool.clone()));

    let created = schema
        .execute(authed_as(
            owner_id,
            r#"
            mutation {
              createAccessToken(input: {
                name: "editable",
                permissions: [{ actions: ["read"], scopeMode: "object_kind", objectKind: "entity" }]
              }) { credentialId }
            }
            "#,
        ))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);
    let credential_id = created.data.into_json().expect("json")["createAccessToken"]
        ["credentialId"]
        .as_str()
        .expect("credential id")
        .to_owned();

    // A different entity without credential-management authority over the
    // owner cannot edit it (delegated replace requires `manage` on the owner).
    let other = schema
        .execute(authed_as(
            other_id,
            format!(
                r#"
                mutation {{
                  replaceAccessTokenPermissions(
                    credentialId: "{credential_id}",
                    permissions: [{{ actions: ["manage"], scopeMode: "object_kind", objectKind: "entity" }}]
                  )
                }}
                "#
            ),
        ))
        .await;
    assert!(!other.errors.is_empty());

    // Empty permissions are rejected.
    let empty = schema
        .execute(authed_as(
            owner_id,
            format!(
                r#"mutation {{ replaceAccessTokenPermissions(credentialId: "{credential_id}", permissions: []) }}"#
            ),
        ))
        .await;
    assert!(!empty.errors.is_empty());
    assert!(empty.errors[0].message.contains("at least one permission"));

    // Owner replaces read → manage; the stored ceiling reflects the new action.
    let replaced = schema
        .execute(authed_as(
            owner_id,
            format!(
                r#"
                mutation {{
                  replaceAccessTokenPermissions(
                    credentialId: "{credential_id}",
                    permissions: [{{ actions: ["manage"], scopeMode: "object_kind", objectKind: "entity" }}]
                  )
                }}
                "#
            ),
        ))
        .await;
    assert!(replaced.errors.is_empty(), "{:?}", replaced.errors);

    let actions: Vec<String> = sqlx::query_scalar(
        r#"SELECT a.name
           FROM credential_permission_limits l
           JOIN credential_permission_limit_actions la ON la.limit_id = l.id
           JOIN actions a ON a.id = la.action_id
           WHERE l.credential_id = $1"#,
    )
    .bind(credential_id.parse::<Uuid>().expect("uuid"))
    .fetch_all(&pool)
    .await
    .expect("limit actions");
    assert_eq!(actions, vec!["manage".to_string()]);
}

#[tokio::test]
#[ignore]
async fn shared_key_can_be_created_revealed_and_used_for_authentication() {
    let pool = common::pool().await;
    let device_id = entity(&pool, "device").await;
    let human_id = entity(&pool, "human").await;
    let schema = build_schema(state(pool.clone()));

    let rejected = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createSharedKey(entityId: "{human_id}", input: {{}}) {{
                credentialId
              }}
            }}
            "#
        )))
        .await;
    assert!(!rejected.errors.is_empty());
    assert!(rejected.errors[0]
        .message
        .contains("cannot be created for human entities"));

    let direct_human_insert = sqlx::query(
        "INSERT INTO credentials (entity_id, kind, secret_hash) VALUES ($1, 'shared_key', 'hash')",
    )
    .bind(human_id)
    .execute(&pool)
    .await;
    let db_err = direct_human_insert
        .expect_err("DB constraint should reject shared_key credentials for human entities")
        .into_database_error()
        .expect("database error");
    assert_eq!(db_err.code().as_deref(), Some("23514"));

    let created = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createSharedKey(entityId: "{device_id}", input: {{
                description: "Provisioning key"
              }}) {{
                credentialId
                key
                expiresAt
              }}
            }}
            "#
        )))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);
    let created_json = created.data.into_json().expect("json data");
    let shared_key = &created_json["createSharedKey"];
    let credential_id = shared_key["credentialId"]
        .as_str()
        .expect("credential id")
        .to_owned();
    let key = shared_key["key"].as_str().expect("shared key").to_owned();
    assert!(key.starts_with("atom_shared_"));

    let (hash, metadata, ciphertext, lookup_hash): (
        String,
        serde_json::Value,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    ) = sqlx::query_as(
        "SELECT secret_hash, metadata, secret_ciphertext, secret_lookup_hash FROM credentials WHERE id = $1",
    )
    .bind(credential_id.parse::<Uuid>().expect("credential uuid"))
    .fetch_one(&pool)
    .await
    .expect("credential row");
    assert_ne!(hash, key);
    // The plaintext key is never persisted; only the envelope-encrypted copy is.
    assert!(metadata.get("shared_key").is_none());
    let ciphertext = ciphertext.expect("secret ciphertext stored");
    assert!(!ciphertext.windows(key.len()).any(|w| w == key.as_bytes()));
    assert_eq!(lookup_hash.expect("lookup hash stored").len(), 32);

    let device_kind_change = sqlx::query("UPDATE entities SET kind = 'human' WHERE id = $1")
        .bind(device_id)
        .execute(&pool)
        .await;
    let db_err = device_kind_change
        .expect_err("DB constraint should reject changing a shared-key device to non-device")
        .into_database_error()
        .expect("database error");
    assert_eq!(db_err.code().as_deref(), Some("23514"));

    let listed = schema
        .execute(authed(format!(
            r#"
            {{
              credentials(entityId: "{device_id}") {{
                items {{
                  id
                  kind
                  status
                  identifier
                }}
                total
              }}
            }}
            "#
        )))
        .await;
    assert!(listed.errors.is_empty(), "{:?}", listed.errors);
    let credentials = listed.data.into_json().expect("json data")["credentials"]["items"]
        .as_array()
        .expect("credentials")
        .clone();
    assert!(credentials.iter().any(|credential| {
        credential["id"] == credential_id
            && credential["kind"] == "shared_key"
            && credential["status"] == "active"
            && credential["identifier"].is_null()
    }));

    let revealed = schema
        .execute(authed(format!(
            r#"
            mutation {{
              revealSharedKey(entityId: "{device_id}", credentialId: "{credential_id}") {{
                credentialId
                key
              }}
            }}
            "#
        )))
        .await;
    assert!(revealed.errors.is_empty(), "{:?}", revealed.errors);
    assert_eq!(
        revealed.data.into_json().expect("json data")["revealSharedKey"]["key"],
        key
    );

    // Revealing secret material must leave a durable compliance record.
    let reveal_audit: serde_json::Value = sqlx::query_scalar(
        "SELECT details FROM audit_logs WHERE event = 'credential.reveal' \
         AND target_id = $1 AND outcome = 'allow' ORDER BY created_at DESC LIMIT 1",
    )
    .bind(device_id)
    .fetch_one(&pool)
    .await
    .expect("credential.reveal audit row");
    assert_eq!(reveal_audit["kind"], serde_json::json!("shared_key"));
    assert_eq!(
        reveal_audit["credential_id"],
        serde_json::json!(credential_id)
    );

    let password_kind_rejected = identity_service::authenticate_credential_in_tenant(
        &pool,
        &Config::for_tests(),
        &device_id.to_string(),
        &key,
        None,
        CredentialKind::Password,
    )
    .await
    .expect_err("shared key must not authenticate as password");
    assert!(password_kind_rejected
        .to_string()
        .contains("invalid credentials"));

    let authenticated = identity_service::authenticate_credential_in_tenant(
        &pool,
        &Config::for_tests(),
        &device_id.to_string(),
        &key,
        None,
        CredentialKind::SharedKey,
    )
    .await
    .expect("authenticate shared key");
    assert_eq!(authenticated.entity_id, device_id);
    assert_eq!(authenticated.credential_id.to_string(), credential_id);
    assert_eq!(
        authenticated.kind,
        atom::models::enums::CredentialKind::SharedKey
    );

    // Tampering with the stored ciphertext must surface as an unrecoverable key
    // rather than returning a wrong secret.
    sqlx::query(
        r#"UPDATE credentials
           SET secret_ciphertext = decode(md5(random()::text), 'hex')
           WHERE id = $1"#,
    )
    .bind(credential_id.parse::<Uuid>().expect("credential uuid"))
    .execute(&pool)
    .await
    .expect("corrupt shared key ciphertext");

    let lost_key = schema
        .execute(authed(format!(
            r#"
            mutation {{
              revealSharedKey(entityId: "{device_id}", credentialId: "{credential_id}") {{
                key
              }}
            }}
            "#
        )))
        .await;
    assert!(!lost_key.errors.is_empty());
    assert!(lost_key.errors[0]
        .message
        .contains("could not retrieve the shared key"));
}

#[tokio::test]
#[ignore]
async fn arbitrary_shared_key_uses_indexed_lookup_and_explicit_kind() {
    let pool = common::pool().await;
    let device_id = entity(&pool, "device").await;
    let schema = build_schema(state(pool.clone()));
    let manual_key = format!("manual-device-key-{}", Uuid::new_v4());

    let created = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createSharedKey(entityId: "{device_id}", input: {{
                key: "{manual_key}",
                description: "Imported provisioning key"
              }}) {{
                credentialId
                key
              }}
            }}
            "#
        )))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);
    let created_json = created.data.into_json().expect("json data");
    let credential_id = created_json["createSharedKey"]["credentialId"]
        .as_str()
        .expect("credential id")
        .to_owned();
    assert_eq!(created_json["createSharedKey"]["key"], manual_key);

    let (stored_hash, lookup_hash, metadata): (String, Option<Vec<u8>>, serde_json::Value) =
        sqlx::query_as(
            "SELECT secret_hash, secret_lookup_hash, metadata FROM credentials WHERE id = $1",
        )
        .bind(credential_id.parse::<Uuid>().expect("credential uuid"))
        .fetch_one(&pool)
        .await
        .expect("credential row");
    assert_ne!(stored_hash, manual_key);
    assert_eq!(lookup_hash.expect("lookup hash stored").len(), 32);
    assert!(metadata.get("shared_key").is_none());

    let authenticated = identity_service::authenticate_credential_in_tenant(
        &pool,
        &Config::for_tests(),
        &device_id.to_string(),
        &manual_key,
        None,
        CredentialKind::SharedKey,
    )
    .await
    .expect("authenticate arbitrary shared key");
    assert_eq!(authenticated.entity_id, device_id);
    assert_eq!(authenticated.credential_id.to_string(), credential_id);

    let wrong_kind = identity_service::authenticate_credential_in_tenant(
        &pool,
        &Config::for_tests(),
        &device_id.to_string(),
        &manual_key,
        None,
        CredentialKind::Password,
    )
    .await
    .expect_err("shared key must not authenticate as password");
    assert!(wrong_kind.to_string().contains("invalid credentials"));
}

#[tokio::test]
#[ignore]
async fn shared_key_works_for_non_device_machine_entities() {
    let pool = common::pool().await;
    let service_id = entity(&pool, "service").await;
    let schema = build_schema(state(pool.clone()));

    let created = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createSharedKey(entityId: "{service_id}", input: {{}}) {{
                credentialId
                key
              }}
            }}
            "#
        )))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);
    let created_json = created.data.into_json().expect("json data");
    let credential_id = created_json["createSharedKey"]["credentialId"]
        .as_str()
        .expect("credential id")
        .to_owned();
    let key = created_json["createSharedKey"]["key"]
        .as_str()
        .expect("shared key")
        .to_owned();

    let revealed = schema
        .execute(authed(format!(
            r#"
            mutation {{
              revealSharedKey(entityId: "{service_id}", credentialId: "{credential_id}") {{
                key
              }}
            }}
            "#
        )))
        .await;
    assert!(revealed.errors.is_empty(), "{:?}", revealed.errors);
    assert_eq!(
        revealed.data.into_json().expect("json data")["revealSharedKey"]["key"],
        key
    );

    let authenticated = identity_service::authenticate_credential_in_tenant(
        &pool,
        &Config::for_tests(),
        &service_id.to_string(),
        &key,
        None,
        CredentialKind::SharedKey,
    )
    .await
    .expect("authenticate shared key for service entity");
    assert_eq!(authenticated.entity_id, service_id);
    assert_eq!(
        authenticated.kind,
        atom::models::enums::CredentialKind::SharedKey
    );
}

#[tokio::test]
#[ignore]
async fn add_and_remove_ownership() {
    let pool = common::pool().await;
    let owner_id = entity(&pool, "human").await;
    let owned_id = entity(&pool, "device").await;
    let schema = build_schema(state(pool));

    let added = schema
        .execute(authed(format!(
            r#"
            mutation {{
              addOwnership(ownerId: "{owner_id}", ownedId: "{owned_id}", relation: "manages") {{
                ownerId
                ownedId
                relation
              }}
            }}
            "#
        )))
        .await;
    assert!(added.errors.is_empty(), "{:?}", added.errors);
    let ownership = &added.data.into_json().expect("json data")["addOwnership"];
    assert_eq!(ownership["ownerId"], owner_id.to_string());
    assert_eq!(ownership["ownedId"], owned_id.to_string());
    assert_eq!(ownership["relation"], "manages");

    let listed = schema
        .execute(authed(format!(
            r#"
            {{
              ownedEntities(ownerId: "{owner_id}") {{
                id
              }}
            }}
            "#
        )))
        .await;
    assert!(listed.errors.is_empty(), "{:?}", listed.errors);
    assert!(listed.data.into_json().expect("json data")["ownedEntities"]
        .as_array()
        .expect("owned entities")
        .iter()
        .any(|entity| entity["id"] == owned_id.to_string()));

    let removed = schema
        .execute(authed(format!(
            r#"
            mutation {{
              removeOwnership(ownerId: "{owner_id}", ownedId: "{owned_id}")
            }}
            "#
        )))
        .await;
    assert!(removed.errors.is_empty(), "{:?}", removed.errors);
    assert_eq!(
        removed.data.into_json().expect("json data")["removeOwnership"],
        true
    );
}

/// Delegated minting: `createAccessToken(subjectId:)` lets an unscoped caller with
/// `manage` on the target mint a token *owned by the target*. A caller without
/// manage, and a scoped caller (even one holding manage), are both refused; a
/// missing target is not found. The ceiling is never validated against the
/// target's grants here — it is capped at evaluation time.
#[tokio::test]
#[ignore]
async fn delegated_access_token_mint_requires_manage_and_unscoped_caller() {
    use atom::authz::repo::CredentialCeiling;

    let pool = common::pool().await;
    let manager = entity(&pool, "human").await;
    let target = entity(&pool, "service").await;
    let outsider = entity(&pool, "human").await;
    let object = entity(&pool, "device").await;
    let schema = build_schema(state(pool.clone()));

    // `manager` holds manage on the target so it may manage the target's credentials.
    let block_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO permission_blocks (id, scope_mode, object_id, effect) VALUES ($1, 'object', $2, 'allow')",
    )
    .bind(block_id)
    .bind(target)
    .execute(&pool)
    .await
    .expect("block");
    sqlx::query(
        "INSERT INTO permission_block_actions (permission_block_id, action_id) SELECT $1, id FROM actions WHERE name = 'manage'",
    )
    .bind(block_id)
    .execute(&pool)
    .await
    .expect("block action");
    sqlx::query(
        "INSERT INTO direct_policies (subject_kind, subject_id, permission_block_id) VALUES ('entity', $1, $2)",
    )
    .bind(manager)
    .bind(block_id)
    .execute(&pool)
    .await
    .expect("policy");

    let mint_query = |subject: Uuid, name: &str| {
        format!(
            r#"mutation {{ createAccessToken(input: {{ name: "{name}", subjectId: "{subject}", permissions: [{{ actions: ["read"], scopeMode: "object", objectId: "{object}" }}] }}) {{ credentialId }} }}"#
        )
    };

    // Manager mints a token owned by the target.
    let ok = schema
        .execute(authed_as(manager, mint_query(target, "svc-token")))
        .await;
    assert!(ok.errors.is_empty(), "{:?}", ok.errors);
    let cred_id = ok.data.into_json().expect("json")["createAccessToken"]["credentialId"]
        .as_str()
        .expect("id")
        .parse::<Uuid>()
        .expect("uuid");
    // Credential is owned by the target, and scoped.
    let (owner, scoped): (Uuid, bool) =
        sqlx::query_as("SELECT entity_id, scoped FROM credentials WHERE id = $1")
            .bind(cred_id)
            .fetch_one(&pool)
            .await
            .expect("credential");
    assert_eq!(owner, target, "delegated token must be owned by the target");
    assert!(scoped);

    // A caller without manage on the target is forbidden.
    let denied = schema
        .execute(authed_as(outsider, mint_query(target, "nope")))
        .await;
    assert!(
        !denied.errors.is_empty(),
        "caller without manage must not mint for another subject"
    );

    // A scoped caller is refused even though it holds manage on the target.
    let scoped_denied = schema
        .execute(authed_scoped(
            manager,
            CredentialCeiling { entries: vec![] },
            mint_query(target, "scoped-nope"),
        ))
        .await;
    assert!(
        !scoped_denied.errors.is_empty(),
        "scoped caller must not mint delegated tokens"
    );

    // A missing target is not found.
    let missing = schema
        .execute(authed_as(manager, mint_query(Uuid::new_v4(), "ghost")))
        .await;
    assert!(
        !missing.errors.is_empty(),
        "delegated mint for a missing subject must fail"
    );
}

/// The unscoped contract (`scoped: false`, empty `permissions`): the token carries
/// the owner's full live grants with no ceiling — the provisioning path used by
/// Magistrala service tokens. Admin (seeded platform `manage`) delegated-mints for
/// a service entity; a ceiling is never written and the auth layer imposes no cap.
/// Unscoped tokens may not carry permissions, and a scoped caller may not mint one.
#[tokio::test]
#[ignore]
async fn unscoped_access_token_carries_owner_authority() {
    use atom::authz::repo::CredentialCeiling;

    let pool = common::pool().await;
    let owner = entity(&pool, "service").await;
    let app_state = state(pool.clone());
    let schema = build_schema(state(pool.clone()));

    let created = schema
        .execute(authed(format!(
            r#"mutation {{ createAccessToken(input: {{ name: "svc", subjectId: "{owner}", scoped: false, permissions: [] }}) {{ credentialId token }} }}"#
        )))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);
    let json = created.data.into_json().expect("json");
    let cred_id = json["createAccessToken"]["credentialId"]
        .as_str()
        .expect("id")
        .parse::<Uuid>()
        .expect("uuid");
    let token = json["createAccessToken"]["token"]
        .as_str()
        .expect("token")
        .to_string();

    // Persisted unscoped, with zero ceiling rows.
    let scoped: bool = sqlx::query_scalar("SELECT scoped FROM credentials WHERE id = $1")
        .bind(cred_id)
        .fetch_one(&pool)
        .await
        .expect("scoped");
    assert!(!scoped, "token must persist as unscoped");
    let ceiling_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM credential_permission_limits WHERE credential_id = $1",
    )
    .bind(cred_id)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(ceiling_rows, 0, "unscoped token must have no ceiling rows");

    // Auth layer imposes no ceiling — evaluation uses the owner's full live grants.
    let ctx = authenticate_token(&app_state, &token).await.expect("auth");
    assert_eq!(ctx.entity_id, owner);
    assert!(!ctx.scoped);
    assert!(ctx.ceiling.is_none());

    // An unscoped request may not carry a ceiling.
    let bad = schema
        .execute(authed(format!(
            r#"mutation {{ createAccessToken(input: {{ name: "bad", subjectId: "{owner}", scoped: false, permissions: [{{ actions: ["read"], scopeMode: "platform" }}] }}) {{ credentialId }} }}"#
        )))
        .await;
    assert!(
        !bad.errors.is_empty(),
        "unscoped token must not carry permissions"
    );

    // A scoped caller may not mint an unscoped token (credential-management gate
    // rejects scoped callers).
    let scoped_caller = schema
        .execute(authed_scoped(
            owner,
            CredentialCeiling { entries: vec![] },
            r#"mutation { createAccessToken(input: { name: "esc", scoped: false, permissions: [] }) { credentialId } }"#,
        ))
        .await;
    assert!(
        !scoped_caller.errors.is_empty(),
        "scoped caller must not mint an unscoped token"
    );
}

/// Access tokens minted without a deployment KEK fall back to the argon2
/// verifier (no `secret_lookup_hash`); authentication must still work — and a
/// KEK-minted token must carry the keyed HMAC digest instead of an argon2 hash.
#[tokio::test]
#[ignore]
async fn access_token_verifier_hmac_and_argon2_fallback() {
    let pool = common::pool().await;
    let owner = entity(&pool, "service").await;
    let app_state = state(pool.clone());

    let request = || atom::models::token::CreateAccessToken {
        name: "verifier".into(),
        description: None,
        expires_at: None,
        permissions: vec![],
    };

    // No KEK at mint time → argon2 fallback row; still authenticates.
    let fallback = identity_service::create_access_token(
        &pool,
        &atom::config::SigningKeyConfig::default(),
        owner,
        request(),
        false,
    )
    .await
    .expect("mint without KEK");
    let (hash, lookup): (Option<String>, Option<Vec<u8>>) =
        sqlx::query_as("SELECT secret_hash, secret_lookup_hash FROM credentials WHERE id = $1")
            .bind(fallback.credential_id)
            .fetch_one(&pool)
            .await
            .expect("row");
    assert!(hash.is_some(), "no-KEK mint must store an argon2 hash");
    assert!(
        lookup.is_none(),
        "no-KEK mint must not store a keyed digest"
    );
    let ctx = authenticate_token(&app_state, &fallback.token)
        .await
        .expect("argon2 fallback token authenticates");
    assert_eq!(ctx.entity_id, owner);

    // KEK present at mint time → keyed HMAC digest, no argon2 hash.
    let hmac_minted = identity_service::create_access_token(
        &pool,
        &app_state.config.signing_keys,
        owner,
        request(),
        false,
    )
    .await
    .expect("mint with KEK");
    let (hash, lookup): (Option<String>, Option<Vec<u8>>) =
        sqlx::query_as("SELECT secret_hash, secret_lookup_hash FROM credentials WHERE id = $1")
            .bind(hmac_minted.credential_id)
            .fetch_one(&pool)
            .await
            .expect("row");
    assert!(hash.is_none(), "KEK mint must not store an argon2 hash");
    assert!(lookup.is_some(), "KEK mint must store the keyed digest");
    let ctx = authenticate_token(&app_state, &hmac_minted.token)
        .await
        .expect("hmac token authenticates");
    assert_eq!(ctx.entity_id, owner);

    // Wrong secret with a valid credential id is rejected without leaking state.
    let mut forged = hmac_minted.token.clone();
    let flipped = if forged.ends_with('0') { "1" } else { "0" };
    forged.truncate(forged.len() - 1);
    forged.push_str(flipped);
    let err = authenticate_token(&app_state, &forged)
        .await
        .expect_err("forged secret must fail");
    assert!(format!("{err:?}").contains("invalid api key"));
}

/// A token whose `expiresAt` is already in the past would be born dead; creation
/// must reject it up front instead of minting a credential that can never
/// authenticate.
#[tokio::test]
#[ignore]
async fn create_access_token_rejects_past_expiry() {
    let pool = common::pool().await;
    let schema = build_schema(state(pool.clone()));

    let resp = schema
        .execute(authed(
            r#"mutation { createAccessToken(input: { name: "dead", expiresAt: "2020-01-01T00:00:00Z", permissions: [{ actions: ["read"], scopeMode: "platform" }] }) { credentialId } }"#,
        ))
        .await;
    assert!(!resp.errors.is_empty(), "past expiry must be rejected");
    assert!(
        resp.errors[0].message.contains("future"),
        "unexpected error: {}",
        resp.errors[0].message
    );
}

/// A delegated mint is audited under the token owner's tenant, so the event is
/// visible in that tenant's audit trail even when the minting admin is
/// platform-scoped (NULL tenant).
#[tokio::test]
#[ignore]
async fn delegated_mint_audit_row_carries_owner_tenant() {
    let pool = common::pool().await;
    let tenant_id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1, $2, 'active')")
        .bind(tenant_id)
        .bind(format!("audit-tenant-{tenant_id}"))
        .execute(&pool)
        .await
        .expect("tenant");
    let owner = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, kind, name, status, tenant_id) VALUES ($1, 'service', $2, 'active', $3)",
    )
    .bind(owner)
    .bind(format!("audit-owner-{owner}"))
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("entity");
    let schema = build_schema(state(pool.clone()));

    let resp = schema
        .execute(authed(format!(
            r#"mutation {{ createAccessToken(input: {{ name: "svc", subjectId: "{owner}", permissions: [{{ actions: ["read"], scopeMode: "tenant", tenantId: "{tenant_id}" }}] }}) {{ credentialId }} }}"#
        )))
        .await;
    assert!(resp.errors.is_empty(), "{:?}", resp.errors);
    let cred_id = resp.data.into_json().expect("json")["createAccessToken"]["credentialId"]
        .as_str()
        .expect("id")
        .parse::<Uuid>()
        .expect("uuid");

    let audit_tenant: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT tenant_id FROM audit_logs
           WHERE target_id = $1 AND event = 'credential.create'
           ORDER BY created_at DESC LIMIT 1"#,
    )
    .bind(cred_id)
    .fetch_one(&pool)
    .await
    .expect("audit row");
    assert_eq!(
        audit_tenant,
        Some(tenant_id),
        "delegated mint must be audited under the owner's tenant"
    );
}

/// A token minted without a KEK (argon2 verifier) upgrades to the keyed HMAC
/// digest on its first successful authentication once a KEK is configured, and
/// the upgraded row keeps authenticating.
#[tokio::test]
#[ignore]
async fn argon2_access_token_upgrades_to_hmac_on_use() {
    let pool = common::pool().await;
    let owner = entity(&pool, "service").await;
    // `Config::for_tests()` carries a deterministic KEK.
    let app_state = state(pool.clone());

    let minted = identity_service::create_access_token(
        &pool,
        &atom::config::SigningKeyConfig::default(),
        owner,
        atom::models::token::CreateAccessToken {
            name: "upgrade".into(),
            description: None,
            expires_at: None,
            permissions: vec![],
        },
        false,
    )
    .await
    .expect("mint without KEK");

    let ctx = authenticate_token(&app_state, &minted.token)
        .await
        .expect("argon2 token authenticates");
    assert_eq!(ctx.entity_id, owner);

    let (hash, lookup): (Option<String>, Option<Vec<u8>>) =
        sqlx::query_as("SELECT secret_hash, secret_lookup_hash FROM credentials WHERE id = $1")
            .bind(minted.credential_id)
            .fetch_one(&pool)
            .await
            .expect("row");
    assert!(
        lookup.is_some(),
        "first use with a KEK must store the keyed digest"
    );
    assert!(
        hash.is_none(),
        "the argon2 hash must be dropped after the upgrade"
    );

    let ctx = authenticate_token(&app_state, &minted.token)
        .await
        .expect("upgraded token authenticates");
    assert_eq!(ctx.entity_id, owner);
}

/// Successful bearer authentication stamps `last_used_at` (surfaced as
/// `lastUsedAt` in the owner's token listing); a repeat inside the five-minute
/// throttle window must not advance the stamp.
#[tokio::test]
#[ignore]
async fn access_token_authentication_stamps_last_used_at() {
    let pool = common::pool().await;
    let owner = entity(&pool, "service").await;
    let app_state = state(pool.clone());

    let minted = identity_service::create_access_token(
        &pool,
        &app_state.config.signing_keys,
        owner,
        atom::models::token::CreateAccessToken {
            name: "usage".into(),
            description: None,
            expires_at: None,
            permissions: vec![],
        },
        false,
    )
    .await
    .expect("mint");

    let last_used = |pool: PgPool, id: Uuid| async move {
        sqlx::query_scalar::<_, Option<chrono::DateTime<chrono::Utc>>>(
            "SELECT last_used_at FROM credentials WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("credential row")
    };

    assert!(
        last_used(pool.clone(), minted.credential_id)
            .await
            .is_none(),
        "an unused token has no usage stamp"
    );

    authenticate_token(&app_state, &minted.token)
        .await
        .expect("authenticate");
    let stamped = last_used(pool.clone(), minted.credential_id)
        .await
        .expect("first use must stamp last_used_at");

    authenticate_token(&app_state, &minted.token)
        .await
        .expect("authenticate again");
    let second = last_used(pool.clone(), minted.credential_id).await;
    assert_eq!(
        second,
        Some(stamped),
        "a repeat within the throttle window must not advance the stamp"
    );

    // The owner-facing listing surfaces the stamp.
    let schema = build_schema(state(pool.clone()));
    let listed = schema
        .execute(authed_as(
            owner,
            "query { accessTokens { items { credentialId lastUsedAt } } }",
        ))
        .await;
    assert!(listed.errors.is_empty(), "{:?}", listed.errors);
    let json = listed.data.into_json().expect("json");
    let item = json["accessTokens"]["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|t| t["credentialId"] == minted.credential_id.to_string().as_str())
        .cloned()
        .expect("token listed");
    assert!(
        item["lastUsedAt"].is_string(),
        "lastUsedAt must be surfaced in the listing"
    );
}

/// Admin lifecycle parity for delegated tokens: the unscoped admin who holds
/// `manage` on the owner can list the owner's tokens (ceiling included),
/// replace the ceiling, and revoke — while an unrelated caller and a scoped
/// caller are refused. Audit rows carry `delegated: true`.
#[tokio::test]
#[ignore]
async fn admin_lists_and_manages_delegated_tokens() {
    use atom::authz::repo::CredentialCeiling;

    let pool = common::pool().await;
    let owner = entity(&pool, "service").await;
    let outsider = entity(&pool, "human").await;
    let schema = build_schema(state(pool.clone()));

    // Admin (seeded platform manage) delegated-mints a scoped token.
    let created = schema
        .execute(authed(format!(
            r#"mutation {{ createAccessToken(input: {{ name: "svc", subjectId: "{owner}", permissions: [{{ actions: ["read"], scopeMode: "object_kind", objectKind: "resource" }}] }}) {{ credentialId }} }}"#
        )))
        .await;
    assert!(created.errors.is_empty(), "{:?}", created.errors);
    let cred_id = created.data.into_json().expect("json")["createAccessToken"]["credentialId"]
        .as_str()
        .expect("id")
        .to_owned();

    // Delegated listing returns the token with its ceiling.
    let list_query = format!(
        r#"query {{ accessTokens(subjectId: "{owner}") {{ items {{ credentialId name scoped permissions {{ actions scopeMode objectKind }} }} total }} }}"#
    );
    let listed = schema.execute(authed(list_query.clone())).await;
    assert!(listed.errors.is_empty(), "{:?}", listed.errors);
    let json = listed.data.into_json().expect("json");
    let item = json["accessTokens"]["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|t| t["credentialId"] == cred_id.as_str())
        .cloned()
        .expect("delegated token listed for the admin");
    assert_eq!(item["scoped"], true);
    assert_eq!(item["permissions"][0]["objectKind"], "resource");

    // An unrelated caller and a scoped caller are refused.
    let denied = schema
        .execute(authed_as(outsider, list_query.clone()))
        .await;
    assert!(
        !denied.errors.is_empty(),
        "caller without manage must not list another subject's tokens"
    );
    let scoped_denied = schema
        .execute(authed_scoped(
            common::admin_id(),
            CredentialCeiling { entries: vec![] },
            list_query,
        ))
        .await;
    assert!(
        !scoped_denied.errors.is_empty(),
        "a scoped caller must not list another subject's tokens"
    );

    // Admin replaces the delegated token's ceiling.
    let replace_mutation = format!(
        r#"mutation {{ replaceAccessTokenPermissions(credentialId: "{cred_id}", permissions: [{{ actions: ["read"], scopeMode: "platform" }}]) }}"#,
    );
    let replaced = schema.execute(authed(replace_mutation.clone())).await;
    assert!(replaced.errors.is_empty(), "{:?}", replaced.errors);
    let scope_modes: Vec<String> = sqlx::query_scalar(
        "SELECT scope_mode FROM credential_permission_limits WHERE credential_id = $1",
    )
    .bind(cred_id.parse::<Uuid>().expect("uuid"))
    .fetch_all(&pool)
    .await
    .expect("limits");
    assert_eq!(scope_modes, vec!["platform".to_string()]);

    // An unrelated caller cannot replace or revoke it.
    let outsider_replace = schema.execute(authed_as(outsider, replace_mutation)).await;
    assert!(
        !outsider_replace.errors.is_empty(),
        "caller without manage must not replace another subject's ceiling"
    );
    let outsider_revoke = schema
        .execute(authed_as(
            outsider,
            format!(r#"mutation {{ revokeAccessToken(credentialId: "{cred_id}") }}"#),
        ))
        .await;
    assert!(
        !outsider_revoke.errors.is_empty(),
        "caller without manage must not revoke another subject's token"
    );

    // Admin revokes it; the audit row is delegated and stamped for the owner.
    let revoked = schema
        .execute(authed(format!(
            r#"mutation {{ revokeAccessToken(credentialId: "{cred_id}") }}"#
        )))
        .await;
    assert!(revoked.errors.is_empty(), "{:?}", revoked.errors);
    let status: String = sqlx::query_scalar("SELECT status FROM credentials WHERE id = $1")
        .bind(cred_id.parse::<Uuid>().expect("uuid"))
        .fetch_one(&pool)
        .await
        .expect("credential");
    assert_eq!(status, "revoked");
    let delegated: serde_json::Value = sqlx::query_scalar(
        r#"SELECT details FROM audit_logs
           WHERE target_id = $1 AND event = 'credential.revoke'
           ORDER BY created_at DESC LIMIT 1"#,
    )
    .bind(cred_id.parse::<Uuid>().expect("uuid"))
    .fetch_one(&pool)
    .await
    .expect("audit row");
    assert_eq!(delegated["delegated"], true);
}

/// The token listing filters by status and paginates with a full filtered
/// `total`, so revoked tokens do not pile into the default view forever.
#[tokio::test]
#[ignore]
async fn access_tokens_listing_filters_and_paginates() {
    let pool = common::pool().await;
    let owner = entity(&pool, "service").await;
    let app_state = state(pool.clone());
    let schema = build_schema(state(pool.clone()));

    let mut cred_ids = Vec::new();
    for name in ["one", "two", "three"] {
        let minted = identity_service::create_access_token(
            &pool,
            &app_state.config.signing_keys,
            owner,
            atom::models::token::CreateAccessToken {
                name: name.into(),
                description: None,
                expires_at: None,
                permissions: vec![],
            },
            false,
        )
        .await
        .expect("mint");
        cred_ids.push(minted.credential_id);
    }
    identity_service::revoke_access_token(&pool, owner, cred_ids[0])
        .await
        .expect("revoke");

    let list = |args: &str| {
        let query =
            format!(r#"query {{ accessTokens{args} {{ items {{ credentialId }} total }} }}"#);
        schema.execute(authed_as(owner, query))
    };

    let active = list(r#"(status: "active")"#).await;
    assert!(active.errors.is_empty(), "{:?}", active.errors);
    let json = active.data.into_json().expect("json");
    assert_eq!(json["accessTokens"]["total"], 2);
    assert_eq!(
        json["accessTokens"]["items"]
            .as_array()
            .expect("items")
            .len(),
        2
    );

    let revoked = list(r#"(status: "revoked")"#).await;
    let json = revoked.data.into_json().expect("json");
    assert_eq!(json["accessTokens"]["total"], 1);
    assert_eq!(
        json["accessTokens"]["items"][0]["credentialId"],
        cred_ids[0].to_string().as_str()
    );

    let all = list("").await;
    let json = all.data.into_json().expect("json");
    assert_eq!(json["accessTokens"]["total"], 3);

    let page = list("(limit: 1, offset: 1)").await;
    let json = page.data.into_json().expect("json");
    assert_eq!(json["accessTokens"]["total"], 3, "total spans all pages");
    assert_eq!(
        json["accessTokens"]["items"]
            .as_array()
            .expect("items")
            .len(),
        1
    );

    let invalid = list(r#"(status: "nonsense")"#).await;
    assert!(
        !invalid.errors.is_empty(),
        "an unknown status filter must be rejected"
    );
}
