//! Files: resources of kind `file` whose bytes live in the deployment's
//! [`BlobStore`](crate::storage::BlobStore).
//!
//! A file's tenant, owner, groups, attributes, soft delete, audit and events
//! are its resource's. What only the server may set -- above all where its
//! bytes are stored -- is in `file_objects` ([`repo`]), out of reach of
//! `updateResource`.
//!
//! The store is outside every database transaction, so bytes are never
//! deleted inline. Every write of new bytes queues its own key for deletion
//! before writing it, and takes it off the queue in the transaction that
//! starts referring to it; every row that stops referring to a key queues it
//! (a trigger, so purges and cascades are covered). The [`worker`] deletes
//! queued keys once they are older than the grace period. Whatever fails in
//! between, bytes nothing refers to are collected and bytes something refers
//! to are kept.

pub mod handlers;
pub(crate) mod repo;
mod signing;
mod sniff;
pub mod worker;

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures_util::{stream, StreamExt};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    audit,
    auth::{require_any_capability, scope_for_tenant, AuthContext, Scope},
    authz::resources as resource_repo,
    error::{db_err, AppError},
    models::{
        enums::AuditOutcome,
        resource::{CreateResource, Resource},
    },
    state::AppState,
    storage::{BlobError, BlobKey, BlobMeta, ByteStream, PutMeta},
};
use repo::NewFileObject;

/// The resource kind of a file.
pub const FILE_KIND: &str = "file";

/// The server-owned facts about a file's current bytes.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct FileObject {
    pub resource_id: Uuid,
    pub tenant_id: Option<Uuid>,
    #[serde(skip)]
    pub storage_key: String,
    pub size_bytes: i64,
    pub content_type: String,
    pub sha256: String,
    pub public: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// What a caller says about a new file; the bytes say the rest.
#[derive(Debug, Default)]
pub struct NewUpload {
    pub tenant_id: Option<Uuid>,
    pub name: Option<String>,
    pub alias: Option<String>,
    pub owner_id: Option<Uuid>,
    pub public: bool,
}

/// Bytes written to the store and not yet referred to by any row.
struct Written {
    key: BlobKey,
    size: i64,
    content_type: String,
    sha256: String,
}

/// Counts and hashes an upload as it streams through, and stops it at the
/// size limit without buffering it.
struct Tally {
    size: u64,
    digest: ring::digest::Context,
    over_limit: bool,
}

/// The URL a file is downloaded from.
pub fn file_url(state: &AppState, id: Uuid) -> String {
    format!(
        "{}/files/{id}",
        state.config.public_base_url.trim_end_matches('/')
    )
}

/// Reads until `min` bytes are in hand (or the body ends), so the type can be
/// sniffed before anything is written, and returns them with a stream that
/// yields the whole body again.
async fn peek(mut body: ByteStream, min: usize) -> Result<(Vec<u8>, ByteStream), AppError> {
    let mut head: Vec<Bytes> = Vec::new();
    let mut seen = 0;
    while seen < min {
        match body.next().await {
            Some(chunk) => {
                let chunk = chunk.map_err(|err| AppError::bad_request(err.to_string()))?;
                seen += chunk.len();
                head.push(chunk);
            }
            None => break,
        }
    }
    let prefix: Vec<u8> = head
        .iter()
        .flat_map(|chunk| chunk.iter().copied())
        .take(min)
        .collect();
    let replay = stream::iter(head.into_iter().map(Ok)).chain(body).boxed();
    Ok((prefix, replay))
}

/// Streams `body` into a fresh key under the file's prefix. The key is queued
/// for deletion first, so if nothing ever refers to it the worker removes it.
async fn write_bytes(
    state: &AppState,
    tenant_id: Option<Uuid>,
    file_id: Uuid,
    declared_type: Option<&str>,
    body: ByteStream,
) -> Result<Written, AppError> {
    let config = &state.config.storage;
    let store = state.storage.for_tenant(tenant_id).await?;
    let key = state
        .storage
        .tenant_prefix(tenant_id)
        .join(&file_id.simple().to_string())
        .and_then(|key| key.join(&Uuid::new_v4().simple().to_string()))?;

    let (head, body) = peek(body, sniff::SNIFF_BYTES).await?;
    let content_type = sniff::resolve(&head, declared_type, &config.allowed_types)?;

    repo::queue_upload(state.pool(), key.as_str(), tenant_id).await?;

    let max = config.max_file_bytes;
    let tally = Arc::new(Mutex::new(Tally {
        size: 0,
        digest: ring::digest::Context::new(&ring::digest::SHA256),
        over_limit: false,
    }));
    let counted = {
        let tally = Arc::clone(&tally);
        body.map(move |chunk| {
            let chunk = chunk?;
            let mut tally = tally.lock().expect("upload tally poisoned");
            tally.size += chunk.len() as u64;
            if tally.size > max {
                tally.over_limit = true;
                return Err(BlobError::Body("file too large".into()));
            }
            tally.digest.update(&chunk);
            Ok(chunk)
        })
        .boxed()
    };

    let written = store
        .put(
            &key,
            counted,
            PutMeta {
                content_type: Some(content_type.clone()),
            },
        )
        .await;
    // Read under the lock rather than unwrapped: an adapter need not have
    // dropped the body by the time `put` returns.
    let (sent, over_limit, digest) = {
        let tally = tally.lock().expect("upload tally poisoned");
        (tally.size, tally.over_limit, tally.digest.clone().finish())
    };
    if over_limit {
        return Err(AppError::payload_too_large(format!(
            "files are limited to {max} bytes"
        )));
    }
    let BlobMeta { size, .. } = written?;
    if size != sent {
        return Err(AppError::Internal(anyhow::anyhow!(
            "storage recorded {size} bytes of {sent} sent"
        )));
    }

    Ok(Written {
        key,
        size: i64::try_from(size).map_err(|_| AppError::payload_too_large("file too large"))?,
        content_type,
        sha256: hex::encode(digest),
    })
}

/// Refuses a write that would take the tenant past its quota. Called with the
/// tenant row locked, so concurrent uploads are counted one after another.
async fn check_quota(
    state: &AppState,
    tx: &mut crate::db::DbTransaction<'_>,
    tenant_id: Option<Uuid>,
    added: i64,
) -> Result<(), AppError> {
    let (Some(quota), Some(tenant_id)) = (state.config.storage.tenant_quota_bytes, tenant_id)
    else {
        return Ok(());
    };
    let used = repo::tenant_usage_in_tx(tx, tenant_id).await?;
    if used.saturating_add(added) > i64::try_from(quota).unwrap_or(i64::MAX) {
        return Err(AppError::payload_too_large(
            "the tenant's file storage quota is used up",
        ));
    }
    Ok(())
}

/// Takes the written key off the deletion queue in `tx`, the transaction that
/// will refer to it. If the worker already claimed it, the upload outlasted
/// the grace period: the worker may have deleted the key before the last bytes
/// landed, so nothing may refer to it, and it is queued again (after `tx` is
/// rolled back, which SQLite's single writer needs) so those bytes go too.
async fn claim_written<'t>(
    state: &AppState,
    mut tx: crate::db::DbTransaction<'t>,
    written: &Written,
    tenant_id: Option<Uuid>,
) -> Result<crate::db::DbTransaction<'t>, AppError> {
    if repo::unqueue_in_tx(&mut tx, written.key.as_str()).await? {
        return Ok(tx);
    }
    drop(tx);
    repo::queue_upload(state.pool(), written.key.as_str(), tenant_id).await?;
    Err(AppError::service_unavailable(
        "the upload took longer than the storage grace period; retry it",
    ))
}

fn file_details(file: &FileObject) -> serde_json::Value {
    serde_json::json!({
        "kind": FILE_KIND,
        "size_bytes": file.size_bytes,
        "content_type": file.content_type,
        "public": file.public,
    })
}

/// Creates a file from an upload. The caller needs `manage` or `write` in the
/// tenant, as for any resource.
pub async fn upload(
    state: &AppState,
    auth: &AuthContext,
    req: NewUpload,
    declared_type: Option<&str>,
    body: ByteStream,
) -> Result<(Resource, FileObject), AppError> {
    let tenant_scope = scope_for_tenant(req.tenant_id);
    require_any_capability(
        state.pool(),
        auth,
        &[("manage", tenant_scope), ("write", tenant_scope)],
    )
    .await?;

    let id = Uuid::new_v4();
    let written = write_bytes(state, req.tenant_id, id, declared_type, body).await?;

    let mut tx = state.pool().begin().await.map_err(db_err)?;
    let resource = resource_repo::insert_resource_in_tx(
        &mut tx,
        CreateResource {
            id: Some(id),
            kind: FILE_KIND.to_string(),
            name: req.name,
            alias: req.alias,
            tenant_id: req.tenant_id,
            owner_id: req.owner_id.or(Some(auth.entity_id)),
            attributes: serde_json::Value::Null,
        },
    )
    .await?;
    check_quota(state, &mut tx, req.tenant_id, written.size).await?;
    let mut tx = claim_written(state, tx, &written, req.tenant_id).await?;
    let file = repo::insert_in_tx(
        &mut tx,
        &NewFileObject {
            resource_id: id,
            tenant_id: req.tenant_id,
            storage_key: written.key.as_str(),
            size_bytes: written.size,
            content_type: &written.content_type,
            sha256: &written.sha256,
            public: req.public,
        },
    )
    .await?;

    let meta = audit::AuditMeta {
        actor_entity_id: Some(auth.entity_id),
        tenant_id: resource.tenant_id,
        target_kind: "resource",
        target_id: Some(id),
        event: "resource.create",
    };
    let mut details = file_details(&file);
    details["name"] = serde_json::json!(resource.name);
    details["alias"] = serde_json::json!(resource.alias);
    audit::commit_with_observation(tx, state.config.events.enabled(), &meta, &details).await?;
    Ok((resource, file))
}

/// The live file `id`, with its resource.
async fn find(state: &AppState, id: Uuid) -> Result<(Resource, FileObject), AppError> {
    let file = repo::get(state.pool(), id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("file {id} not found")))?;
    let resource = resource_repo::get_resource(state.pool(), id).await?;
    Ok((resource, file))
}

async fn require_on_file(
    state: &AppState,
    auth: &AuthContext,
    action: &str,
    file: &FileObject,
) -> Result<(), AppError> {
    require_any_capability(
        state.pool(),
        auth,
        &[
            (action, Scope::Object(file.resource_id)),
            ("manage", Scope::Object(file.resource_id)),
            (action, scope_for_tenant(file.tenant_id)),
            ("manage", scope_for_tenant(file.tenant_id)),
        ],
    )
    .await
}

/// Replaces a file's bytes (`write` on the file). Its id, and so its URL,
/// stay; its ETag changes.
pub async fn replace(
    state: &AppState,
    auth: &AuthContext,
    id: Uuid,
    declared_type: Option<&str>,
    body: ByteStream,
) -> Result<(Resource, FileObject), AppError> {
    let (_, existing) = find(state, id).await?;
    require_on_file(state, auth, "write", &existing).await?;
    let written = write_bytes(state, existing.tenant_id, id, declared_type, body).await?;

    let mut tx = state.pool().begin().await.map_err(db_err)?;
    let tenant_id = resource_repo::lock_live_resource_in_tx(&mut tx, id).await?;
    let current = repo::get_in_tx(&mut tx, id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("file {id} not found")))?;
    check_quota(state, &mut tx, tenant_id, written.size - current.size_bytes).await?;
    let mut tx = claim_written(state, tx, &written, tenant_id).await?;
    let file = repo::replace_blob_in_tx(
        &mut tx,
        id,
        &NewFileObject {
            resource_id: id,
            tenant_id,
            storage_key: written.key.as_str(),
            size_bytes: written.size,
            content_type: &written.content_type,
            sha256: &written.sha256,
            public: current.public,
        },
    )
    .await?;
    resource_repo::touch_resource_in_tx(&mut tx, id).await?;

    let mut details = file_details(&file);
    details["updated_fields"] = serde_json::json!(["content"]);
    let event = audit::AuditEvent {
        actor_entity_id: Some(auth.entity_id),
        tenant_id,
        target_kind: Some("resource"),
        target_id: Some(id),
        event: "resource.update",
        outcome: AuditOutcome::Allow,
        details,
    };
    audit::commit_with_audit(state.pool(), tx, state.config.events.enabled(), &event).await?;
    let resource = resource_repo::get_resource(state.pool(), id).await?;
    Ok((resource, file))
}

/// Soft-deletes a file (`delete` on the file). Its bytes stay, so a restore
/// brings it back; they go when the resource is purged.
pub async fn delete(state: &AppState, auth: &AuthContext, id: Uuid) -> Result<(), AppError> {
    let (_, file) = find(state, id).await?;
    require_on_file(state, auth, "delete", &file).await?;
    resource_repo::delete_resource_with_audit(
        state.pool(),
        state.config.events.enabled(),
        Some(auth.entity_id),
        id,
        Some(auth.entity_id),
    )
    .await
}

/// How a download proved it may read the file.
pub enum Access<'a> {
    Session(&'a AuthContext),
    Signed { expires: i64, signature: &'a str },
    Anonymous,
}

/// An open download.
pub struct Download {
    pub resource: Resource,
    pub file: FileObject,
    pub range: Option<std::ops::Range<u64>>,
    pub body: ByteStream,
}

/// Checks that `access` may read file `id` and returns it, without its bytes.
pub async fn authorize_read(
    state: &AppState,
    id: Uuid,
    access: Access<'_>,
) -> Result<(Resource, FileObject), AppError> {
    let (resource, file) = find(state, id).await?;
    if file.public {
        return Ok((resource, file));
    }
    match access {
        Access::Session(auth) => {
            crate::auth::require_read_access(state.pool(), auth, file.tenant_id, id).await?;
        }
        Access::Signed { expires, signature } => {
            if !signing::verify(state, id, expires, signature, Utc::now().timestamp()) {
                return Err(AppError::unauthorized("the link is invalid or has expired"));
            }
        }
        Access::Anonymous => return Err(AppError::unauthorized("missing authentication")),
    }
    Ok((resource, file))
}

/// Opens the bytes of a file [`authorize_read`] returned, or part of them.
pub async fn open(
    state: &AppState,
    resource: Resource,
    file: FileObject,
    range: Option<std::ops::Range<u64>>,
) -> Result<Download, AppError> {
    let store = state.storage.for_tenant(file.tenant_id).await?;
    let key = BlobKey::parse(file.storage_key.clone())?;
    let (_, body) = store.get(&key, range.clone()).await?;
    Ok(Download {
        resource,
        file,
        range,
        body,
    })
}

/// A download link for file `id` that works without a session until it
/// expires. Issuing one needs `read` on the file.
pub async fn signed_url(
    state: &AppState,
    auth: &AuthContext,
    id: Uuid,
    expires_in: u64,
) -> Result<(String, DateTime<Utc>), AppError> {
    let max = state.config.storage.signed_url_max_ttl_secs;
    if expires_in == 0 || expires_in > max {
        return Err(AppError::bad_request(format!(
            "expires_in must be between 1 and {max} seconds"
        )));
    }
    authorize_read(state, id, Access::Session(auth)).await?;
    let expires_at = Utc::now() + chrono::Duration::seconds(expires_in as i64);
    let expires = expires_at.timestamp();
    let signature = signing::sign(state, id, expires)?;
    Ok((
        format!(
            "{}?expires={expires}&signature={signature}",
            file_url(state, id)
        ),
        expires_at,
    ))
}
