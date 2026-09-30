//! File storage: upload, download, authorization, signed URLs, content safety,
//! limits, quota, replacement and the blob deletion queue, through the HTTP
//! routes and the in-memory blob store.
//!
//! The deletion worker claims every due key in the database, so these tests
//! assume one test at a time, as CI runs them. Run with:
//! ```bash
//! DATABASE_URL=postgres://... cargo test --test m53_file_storage -- --ignored --test-threads=1
//! ATOM_TEST_BACKEND=sqlite cargo test --test m53_file_storage -- --ignored --test-threads=1
//! ```

mod common;

use std::sync::Arc;

use atom::{
    auth::encode_jwt,
    authz::{repo as authz_repo, resources as resource_repo},
    config::{Config, SecretBytes},
    db::Database,
    files::worker,
    identity::repo as identity_repo,
    keys::{self, ActiveKeys},
    models::{
        enums::{Effect, SubjectKind},
        policy::{CreatePermissionBlock, CreateRoleAssignment},
        resource::UpdateResource,
        role::CreateRole,
    },
    routes::create_router,
    state::AppState,
    storage::{memory::MemoryBlobStore, StorageResolver},
};
use axum::{
    body::{to_bytes, Body},
    http::{header, Request, Response, StatusCode},
    Router,
};
use futures_util::StreamExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRpretend-image-data";
const BASE: &str = "http://localhost:8080";

struct Harness {
    pool: Database,
    state: AppState,
    store: Arc<MemoryBlobStore>,
    keys: ActiveKeys,
}

impl Harness {
    async fn new(configure: impl FnOnce(&mut Config)) -> Self {
        let pool = common::pool().await;
        let keys = keys::rotate(&pool, &Config::for_tests().signing_keys)
            .await
            .expect("rotate test signing key");
        let mut config = Config::for_tests();
        config.storage.backend = Some("memory".into());
        config.signing_keys.key_encryption_key = Some(SecretBytes::new(vec![7; 32]).unwrap());
        configure(&mut config);
        // Tests run one at a time; each starts with an empty deletion queue.
        atom::db::query("DELETE FROM blob_deletions")
            .execute(&pool)
            .await
            .expect("clear queue");
        let store = Arc::new(MemoryBlobStore::default());
        let state = AppState::new(pool.clone(), config, keys.clone(), None)
            .with_storage(StorageResolver::new(store.clone(), None));
        Self {
            pool,
            state,
            store,
            keys,
        }
    }

    fn app(&self) -> Router {
        create_router(self.state.clone())
    }

    async fn token(&self, entity_id: Uuid, tenant_id: Option<Uuid>) -> String {
        let session = identity_repo::create_session(&self.pool, entity_id, 3600)
            .await
            .expect("create session");
        encode_jwt(
            entity_id,
            session.id,
            tenant_id,
            &self.keys.primary,
            3600,
            BASE,
            "magistrala",
        )
        .expect("encode jwt")
    }

    async fn admin(&self) -> String {
        self.token(common::admin_id(), None).await
    }

    async fn send(&self, request: Request<Body>) -> Response<Body> {
        self.app().oneshot(request).await.expect("request")
    }

    async fn upload(
        &self,
        token: &str,
        query: &str,
        content_type: &str,
        bytes: &[u8],
    ) -> Response<Body> {
        self.send(
            Request::post(format!("/files{query}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, content_type)
                .body(Body::from(bytes.to_vec()))
                .unwrap(),
        )
        .await
    }

    async fn uploaded(&self, token: &str, query: &str, bytes: &[u8]) -> Value {
        let response = self.upload(token, query, "image/png", bytes).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        json_body(response).await
    }

    async fn get(&self, path: &str, token: Option<&str>) -> Response<Body> {
        let mut request = Request::get(path);
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        self.send(request.body(Body::empty()).unwrap()).await
    }

    async fn queued(&self) -> i64 {
        atom::db::query_scalar("SELECT COUNT(*) FROM blob_deletions")
            .fetch_one(&self.pool)
            .await
            .expect("count queue")
    }
}

async fn json_body(response: Response<Body>) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json body")
}

async fn raw_body(response: Response<Body>) -> Vec<u8> {
    to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body")
        .to_vec()
}

fn header_of(response: &Response<Body>, name: header::HeaderName) -> &str {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
}

fn id_of(file: &Value) -> Uuid {
    file["id"].as_str().unwrap().parse().unwrap()
}

/// A tenant and an entity in it holding `actions` across the tenant.
async fn tenant_member(pool: &Database, actions: &[&str]) -> (Uuid, Uuid) {
    let tenant_id = Uuid::new_v4();
    atom::db::query("INSERT INTO tenants (id, name, status) VALUES ($1, $2, 'active')")
        .bind(tenant_id)
        .bind(format!("files-tenant-{tenant_id}"))
        .execute(pool)
        .await
        .expect("insert tenant");
    let entity_id = Uuid::new_v4();
    atom::db::query(
        "INSERT INTO entities (id, kind, name, tenant_id, status) VALUES ($1, 'human', $2, $3, 'active')",
    )
    .bind(entity_id)
    .bind(format!("files-member-{entity_id}"))
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("insert entity");
    if actions.is_empty() {
        return (tenant_id, entity_id);
    }

    let mut action_ids = Vec::new();
    for action in actions {
        let id: Uuid = atom::db::query_scalar("SELECT id FROM actions WHERE name = $1")
            .bind(*action)
            .fetch_one(pool)
            .await
            .expect("seeded action");
        action_ids.push(id);
    }
    let role = authz_repo::create_role(
        pool,
        CreateRole {
            name: format!("files-role-{entity_id}"),
            tenant_id: Some(tenant_id),
            description: None,
        },
    )
    .await
    .expect("create role");
    let block = authz_repo::create_permission_block(
        pool,
        CreatePermissionBlock {
            tenant_id: Some(tenant_id),
            scope_mode: "tenant".into(),
            object_kind: None,
            object_type: None,
            object_id: None,
            group_id: None,
            effect: Effect::Allow,
            conditions: json!({}),
            action_ids,
        },
    )
    .await
    .expect("create block");
    authz_repo::replace_role_permission_block_links(pool, role.id, &[block.id])
        .await
        .expect("link block");
    authz_repo::create_role_assignment(
        pool,
        CreateRoleAssignment {
            tenant_id: Some(tenant_id),
            subject_kind: SubjectKind::Entity,
            subject_id: entity_id,
            role_id: role.id,
        },
    )
    .await
    .expect("assign role");
    (tenant_id, entity_id)
}

#[tokio::test]
#[ignore]
async fn upload_and_download_round_trip() {
    let h = Harness::new(|_| {}).await;
    let token = h.admin().await;

    // Declared JPEG, bytes are PNG: stored as what the bytes are.
    let response = h.upload(&token, "?name=photo.png", "image/jpeg", PNG).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let file = json_body(response).await;
    assert_eq!(file["content_type"], "image/png");
    assert_eq!(file["size_bytes"], PNG.len());
    assert_eq!(file["name"], "photo.png");
    assert_eq!(file["owner_id"], common::admin_id().to_string());
    assert_eq!(
        file["url"],
        format!("{BASE}/files/{}", file["id"].as_str().unwrap())
    );
    assert!(file.get("storage_key").is_none());
    assert_eq!(h.store.len(), 1);
    assert_eq!(
        h.queued().await,
        0,
        "a committed upload leaves nothing queued"
    );

    let path = format!("/files/{}", id_of(&file));
    let response = h.get(&path, Some(&token)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(header_of(&response, header::CONTENT_TYPE), "image/png");
    assert_eq!(
        header_of(&response, header::X_CONTENT_TYPE_OPTIONS),
        "nosniff"
    );
    assert_eq!(
        header_of(&response, header::CACHE_CONTROL),
        "private, no-store"
    );
    assert!(header_of(&response, header::CONTENT_DISPOSITION).starts_with("inline"));
    let etag = header_of(&response, header::ETAG).to_string();
    assert_eq!(etag, format!("\"{}\"", file["sha256"].as_str().unwrap()));
    assert_eq!(raw_body(response).await, PNG);

    let response = h
        .send(
            Request::get(&path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::IF_NONE_MATCH, &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);

    let response = h
        .send(
            Request::get(&path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::RANGE, "bytes=1-3")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        header_of(&response, header::CONTENT_RANGE),
        format!("bytes 1-3/{}", PNG.len())
    );
    assert_eq!(raw_body(response).await, &PNG[1..4]);

    let response = h
        .get(&format!("/files/{}", Uuid::new_v4()), Some(&token))
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore]
async fn public_files_are_readable_anonymously_and_private_ones_are_not() {
    let h = Harness::new(|_| {}).await;
    let token = h.admin().await;
    let private = h.uploaded(&token, "", PNG).await;
    let public = h.uploaded(&token, "?public=true", PNG).await;

    let response = h.get(&format!("/files/{}", id_of(&private)), None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = h.get(&format!("/files/{}", id_of(&public)), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        header_of(&response, header::CACHE_CONTROL),
        "public, max-age=300"
    );
}

#[tokio::test]
#[ignore]
async fn signed_urls_open_one_file_until_they_expire() {
    let h = Harness::new(|_| {}).await;
    let token = h.admin().await;
    let file = h.uploaded(&token, "", PNG).await;
    let other = h.uploaded(&token, "", PNG).await;

    let response = h
        .send(
            Request::post(format!("/files/{}/signed-url", id_of(&file)))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"expires_in":60}"#))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let signed = json_body(response).await;
    let url = signed["url"]
        .as_str()
        .unwrap()
        .strip_prefix(BASE)
        .unwrap()
        .to_string();

    let response = h.get(&url, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        header_of(&response, header::CACHE_CONTROL),
        "private, no-store"
    );
    assert_eq!(raw_body(response).await, PNG);

    let query = url.split_once('?').unwrap().1;
    let response = h
        .get(&format!("/files/{}?{query}", id_of(&other)), None)
        .await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "a link opens only its own file"
    );

    let tampered = url.replace("expires=", "expires=1");
    let response = h.get(&tampered, None).await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "the expiry is signed"
    );

    let signature = query.split_once("signature=").unwrap().1;
    let expired = format!("/files/{}?expires=1&signature={signature}", id_of(&file));
    let response = h.get(&expired, None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    for expires_in in [0, 3601] {
        let response = h
            .send(
                Request::post(format!("/files/{}/signed-url", id_of(&file)))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(r#"{{"expires_in":{expires_in}}}"#)))
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
#[ignore]
async fn tenant_permissions_govern_files() {
    let h = Harness::new(|_| {}).await;
    let (tenant_id, writer) = tenant_member(&h.pool, &["write", "read"]).await;
    let (reader_tenant, reader) = tenant_member(&h.pool, &["read"]).await;
    let (outsider_tenant, outsider) = tenant_member(&h.pool, &[]).await;
    let writer_token = h.token(writer, Some(tenant_id)).await;
    let reader_token = h.token(reader, Some(reader_tenant)).await;
    let outsider_token = h.token(outsider, Some(outsider_tenant)).await;

    // Without `tenant_id`, a file goes to the uploader's tenant.
    let file = h.uploaded(&writer_token, "", PNG).await;
    assert_eq!(file["tenant_id"], tenant_id.to_string());
    let path = format!("/files/{}", id_of(&file));

    assert_eq!(
        h.get(&path, Some(&writer_token)).await.status(),
        StatusCode::OK
    );
    // `reader` reads in another tenant, not this one.
    assert_eq!(
        h.get(&path, Some(&reader_token)).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        h.get(&path, Some(&outsider_token)).await.status(),
        StatusCode::FORBIDDEN
    );

    let response = h
        .upload(
            &outsider_token,
            &format!("?tenant_id={tenant_id}"),
            "image/png",
            PNG,
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Writing is not deleting.
    let response = h
        .send(
            Request::delete(&path)
                .header(header::AUTHORIZATION, format!("Bearer {writer_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = h
        .send(
            Request::put(&path)
                .header(header::AUTHORIZATION, format!("Bearer {writer_token}"))
                .body(Body::from(PNG.to_vec()))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore]
async fn content_is_checked_and_unsafe_types_are_attachments() {
    let h = Harness::new(|config| {
        config.storage.allowed_types.push("image/svg+xml".into());
    })
    .await;
    let token = h.admin().await;

    let response = h
        .upload(&token, "", "image/png", b"<html><script>alert(1)</script>")
        .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "bytes disagree with the declared type"
    );
    let response = h
        .upload(&token, "", "text/html", b"<html><script>alert(1)</script>")
        .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "type not allowed"
    );
    assert_eq!(h.store.len(), 0);

    let svg = br#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#;
    let response = h
        .upload(&token, "?name=logo.svg", "image/svg+xml", svg)
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let file = json_body(response).await;
    let response = h
        .get(&format!("/files/{}", id_of(&file)), Some(&token))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        header_of(&response, header::CONTENT_DISPOSITION),
        "attachment; filename*=UTF-8''logo.svg"
    );
    assert_eq!(
        header_of(&response, header::CONTENT_SECURITY_POLICY),
        "sandbox"
    );
    assert_eq!(
        header_of(&response, header::X_CONTENT_TYPE_OPTIONS),
        "nosniff"
    );
}

#[tokio::test]
#[ignore]
async fn oversized_uploads_are_refused_while_streaming() {
    let h = Harness::new(|config| config.storage.max_file_bytes = 64).await;
    let token = h.admin().await;
    let big = [PNG, &[0u8; 100]].concat();

    // Announced length.
    let response = h
        .send(
            Request::post("/files")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "image/png")
                .header(header::CONTENT_LENGTH, big.len())
                .body(Body::from(big.clone()))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(h.queued().await, 0, "refused before anything was written");

    // No length: counted while streaming.
    let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
        big.chunks(16).map(|chunk| Ok(chunk.to_vec())).collect();
    let response = h
        .send(
            Request::post("/files")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "image/png")
                .body(Body::from_stream(futures_util::stream::iter(chunks)))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(h.store.len(), 0);
    assert_eq!(
        h.queued().await,
        1,
        "the abandoned key is left for the worker"
    );
}

#[tokio::test]
#[ignore]
async fn the_tenant_quota_holds_under_concurrent_uploads() {
    let quota = (PNG.len() * 3) as u64;
    let h = Harness::new(|config| config.storage.tenant_quota_bytes = Some(quota)).await;
    let token = h.admin().await;
    let (tenant_id, _) = tenant_member(&h.pool, &[]).await;
    let query = format!("?tenant_id={tenant_id}");

    let uploads = (0..6).map(|_| h.upload(&token, &query, "image/png", PNG));
    let statuses: Vec<StatusCode> = futures_util::future::join_all(uploads)
        .await
        .iter()
        .map(|response| response.status())
        .collect();
    let created = statuses
        .iter()
        .filter(|status| **status == StatusCode::CREATED)
        .count();
    let refused = statuses
        .iter()
        .filter(|status| **status == StatusCode::PAYLOAD_TOO_LARGE)
        .count();
    assert_eq!((created, refused), (3, 3), "{statuses:?}");
}

#[tokio::test]
#[ignore]
async fn replaced_and_purged_bytes_are_deleted_by_the_worker() {
    let h = Harness::new(|config| config.storage.deletion_grace_secs = 0).await;
    let token = h.admin().await;
    let file = h.uploaded(&token, "", PNG).await;
    let id = id_of(&file);
    let path = format!("/files/{id}");

    let replacement = [PNG, b"-v2"].concat();
    let response = h
        .send(
            Request::put(&path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(replacement.clone()))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let replaced = json_body(response).await;
    assert_ne!(replaced["sha256"], file["sha256"]);
    assert_eq!(replaced["id"], file["id"]);
    assert_eq!(h.store.len(), 2);
    assert_eq!(h.queued().await, 1, "the replaced key is queued");

    let summary = worker::delete_due(&h.state).await.expect("deletion pass");
    assert_eq!(summary.deleted, 1);
    assert_eq!(h.store.len(), 1);
    assert_eq!(
        raw_body(h.get(&path, Some(&token)).await).await,
        replacement
    );

    // A client cannot redirect the file through its attributes.
    resource_repo::update_resource(
        &h.pool,
        id,
        UpdateResource {
            name: None,
            alias: None,
            attributes: Some(json!({ "storage_key": "_platform/elsewhere" })),
        },
    )
    .await
    .expect("update attributes");
    assert_eq!(
        raw_body(h.get(&path, Some(&token)).await).await,
        replacement
    );

    // Soft delete keeps the bytes; restore brings the file back.
    let response = h
        .send(
            Request::delete(&path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        h.get(&path, Some(&token)).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(h.queued().await, 0);
    resource_repo::restore_resource(&h.pool, id, Some(common::admin_id()))
        .await
        .expect("restore");
    assert_eq!(h.get(&path, Some(&token)).await.status(), StatusCode::OK);

    // Purge removes the row, which queues the bytes.
    resource_repo::delete_resource(&h.pool, id, Some(common::admin_id()))
        .await
        .expect("soft delete");
    resource_repo::purge_resource(&h.pool, id)
        .await
        .expect("purge");
    assert_eq!(h.queued().await, 1);
    let summary = worker::delete_due(&h.state).await.expect("deletion pass");
    assert_eq!(summary.deleted, 1);
    assert_eq!(h.store.len(), 0);
    assert_eq!(h.queued().await, 0);
}

#[tokio::test]
#[ignore]
async fn a_tenant_purge_queues_its_files() {
    let h = Harness::new(|config| config.storage.deletion_grace_secs = 0).await;
    let token = h.admin().await;
    let (tenant_id, _) = tenant_member(&h.pool, &[]).await;
    for _ in 0..2 {
        h.uploaded(&token, &format!("?tenant_id={tenant_id}"), PNG)
            .await;
    }
    assert_eq!(h.store.len(), 2);

    atom::tenants::repo::soft_delete_tenant(&h.pool, tenant_id, Some(common::admin_id()))
        .await
        .expect("soft delete tenant");
    atom::tenants::repo::purge_tenant(&h.pool, tenant_id)
        .await
        .expect("purge tenant");
    let summary = worker::delete_due(&h.state).await.expect("deletion pass");
    assert_eq!(summary.deleted, 2);
    assert_eq!(h.store.len(), 0);
}

#[tokio::test]
#[ignore]
async fn uploads_outlasting_the_grace_period_are_not_committed() {
    // Grace 0: the key an upload queued is due at once, as if the upload had
    // taken longer than the grace period. The worker claims it here before the
    // upload commits, so the upload must fail rather than refer to bytes that
    // are being deleted.
    let h = Harness::new(|config| config.storage.deletion_grace_secs = 0).await;
    let token = h.admin().await;

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let gated = futures_util::stream::once(async { Ok::<_, std::io::Error>(PNG.to_vec()) }).chain(
        futures_util::stream::once(async move {
            rx.await.ok();
            Ok::<_, std::io::Error>(b"-tail".to_vec())
        }),
    );
    let request = Request::post("/files")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "image/png")
        .body(Body::from_stream(gated))
        .unwrap();
    let app = h.app();
    let upload = tokio::spawn(async move { app.oneshot(request).await.expect("request") });

    // Wait until the upload has queued its key, then claim it.
    loop {
        if h.queued().await == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    worker::delete_due(&h.state).await.expect("deletion pass");
    tx.send(()).unwrap();

    let response = upload.await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    // The bytes landed after the worker's delete; the key is queued again.
    assert_eq!(h.store.len(), 1);
    assert_eq!(h.queued().await, 1);
    worker::delete_due(&h.state).await.expect("deletion pass");
    assert_eq!(h.store.len(), 0);
}

#[tokio::test]
#[ignore]
async fn file_routes_are_absent_without_storage() {
    let pool = common::pool().await;
    let keys = keys::rotate(&pool, &Config::for_tests().signing_keys)
        .await
        .expect("rotate test signing key");
    let app = create_router(AppState::new(pool, Config::for_tests(), keys, None));
    let response = app
        .oneshot(
            Request::get(format!("/files/{}", Uuid::new_v4()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
