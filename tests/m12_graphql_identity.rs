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
async fn create_api_key_returns_secret_once_and_credentials_list_contains_it() {
    let pool = common::pool().await;
    let entity_id = entity(&pool, "service").await;
    let schema = build_schema(state(pool));

    let created = schema
        .execute(authed(format!(
            r#"
            mutation {{
              createApiKey(entityId: "{entity_id}", input: {{
                description: "GraphQL API key"
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
    let api_key = &created.data.into_json().expect("json data")["createApiKey"];
    let credential_id = api_key["credentialId"]
        .as_str()
        .expect("credential id")
        .to_owned();
    assert!(api_key["key"]
        .as_str()
        .is_some_and(|key| key.starts_with("atom_")));

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

    // Revoke is owner-only.
    let other_revoke = schema
        .execute(authed_as(
            other_id,
            format!(r#"mutation {{ revokeAccessToken(credentialId: "{credential_id}") }}"#),
        ))
        .await;
    assert!(!other_revoke.errors.is_empty());
    assert!(other_revoke.errors[0]
        .message
        .contains("access token not found"));

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
        engine::evaluate(&pool, &read_req, None)
            .await
            .unwrap()
            .allowed
    );
    assert!(
        engine::evaluate(&pool, &manage_req, None)
            .await
            .unwrap()
            .allowed
    );

    // Through the read-only token: read allowed, manage denied by the ceiling.
    assert!(
        engine::evaluate(&pool, &read_req, Some(&ceiling))
            .await
            .unwrap()
            .allowed
    );
    assert!(
        !engine::evaluate(&pool, &manage_req, Some(&ceiling))
            .await
            .unwrap()
            .allowed
    );

    // Remove the owner's grant: the token's access disappears immediately.
    sqlx::query("DELETE FROM direct_policies WHERE subject_id = $1")
        .bind(owner_id)
        .execute(&pool)
        .await
        .expect("delete policy");
    assert!(
        !engine::evaluate(&pool, &read_req, Some(&ceiling))
            .await
            .unwrap()
            .allowed
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

    // A different entity cannot edit it.
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
    assert!(other.errors[0].message.contains("access token not found"));

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
