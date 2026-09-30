//! Object storage for file bytes, behind Atom's own interface.
//!
//! Everything above this module -- the file service, its HTTP handlers, the
//! deletion worker -- depends only on [`BlobStore`] and the types beside it.
//! No provider SDK type crosses this boundary, so a provider is added by
//! writing an adapter (a module implementing [`BlobStore`], ideally behind a
//! Cargo feature) and passing [`conformance`], without touching domain code.
//!
//! Adapters:
//!
//! - [`memory::MemoryBlobStore`] -- in-process, always compiled; for tests and
//!   for proving the domain does not depend on a provider.
//! - `object_store` (feature `storage-object-store`) -- the
//!   [`object_store`](https://crates.io/crates/object_store) crate: local
//!   filesystem, and with `storage-s3`/`storage-gcs`/`storage-azure` S3 and
//!   S3-compatible stores (MinIO, R2, SeaweedFS, B2, Wasabi), Google Cloud
//!   Storage and Azure Blob.
//!
//! [`StorageResolver`] hands out the store for a tenant. Today every tenant
//! gets the deployment's store; the resolver is where a tenant's own bucket
//! would be chosen, so no caller may assume one global store.

use std::{fmt, ops::Range, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures_util::stream::BoxStream;
use uuid::Uuid;

use crate::{config::StorageConfig, error::AppError};

pub mod conformance;
pub mod memory;
#[cfg(feature = "storage-object-store")]
mod object_store_adapter;

/// A stream of bytes crossing the storage boundary, in either direction.
pub type ByteStream = BoxStream<'static, Result<Bytes, BlobError>>;

/// Where a blob lives in a store: `/`-separated segments of ASCII letters,
/// digits, `.`, `_` and `-`. No empty segments, no `.`/`..`, no leading or
/// trailing `/` -- so a key can never name something outside its prefix on
/// any backend, the local filesystem included.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlobKey(String);

impl BlobKey {
    pub fn parse(value: impl Into<String>) -> Result<Self, BlobError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= 1024
            && value.split('/').all(|segment| {
                !segment.is_empty()
                    && segment != "."
                    && segment != ".."
                    && segment
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            });
        if valid {
            Ok(Self(value))
        } else {
            Err(BlobError::InvalidKey(value))
        }
    }

    /// This key with `segment` (itself one or more valid segments) appended.
    pub fn join(&self, segment: &str) -> Result<Self, BlobError> {
        Self::parse(format!("{}/{segment}", self.0))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True when `self` is `prefix` or lies beneath it.
    pub fn starts_with(&self, prefix: &BlobKey) -> bool {
        self.0 == prefix.0
            || (self.0.starts_with(&prefix.0)
                && self.0.as_bytes().get(prefix.0.len()) == Some(&b'/'))
    }
}

impl fmt::Display for BlobKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a caller tells the store about a blob it writes.
#[derive(Debug, Clone, Default)]
pub struct PutMeta {
    pub content_type: Option<String>,
}

/// What a store reports about a blob it holds.
#[derive(Debug, Clone)]
pub struct BlobMeta {
    pub key: BlobKey,
    pub size: u64,
    pub last_modified: Option<DateTime<Utc>>,
}

/// What an adapter can do beyond the required operations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Capabilities {
    /// [`BlobStore::presign_get`] returns a provider URL.
    pub presign: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("blob {0} not found")]
    NotFound(String),
    #[error("invalid blob key {0:?}")]
    InvalidKey(String),
    #[error("range {0:?} is not satisfiable")]
    InvalidRange(Range<u64>),
    /// The body stream a caller supplied failed; the write is abandoned.
    #[error("upload interrupted: {0}")]
    Body(String),
    #[error("{0} is not supported by this storage backend")]
    Unsupported(&'static str),
    /// The backend could not be reached or refused the request.
    #[error("storage backend error: {0}")]
    Backend(String),
}

impl From<BlobError> for AppError {
    /// The one place storage errors become API errors. Backend detail is
    /// logged, never returned: it can name buckets, endpoints and accounts.
    fn from(err: BlobError) -> Self {
        match err {
            BlobError::NotFound(_) => AppError::not_found("file not found"),
            BlobError::InvalidRange(_) => {
                AppError::bad_request("requested range is not satisfiable")
            }
            BlobError::Body(message) => {
                AppError::bad_request(format!("upload interrupted: {message}"))
            }
            BlobError::InvalidKey(_) | BlobError::Unsupported(_) | BlobError::Backend(_) => {
                tracing::error!(error = %err, "file storage failed");
                AppError::ServiceUnavailable("file storage is unavailable".into())
            }
        }
    }
}

/// A place to keep bytes. Implementations must be safe to share across tasks
/// and must pass [`conformance::run`].
#[async_trait]
pub trait BlobStore: Send + Sync + 'static {
    /// A short, log-safe name for the backend (`"memory"`, `"s3"`, ...).
    fn name(&self) -> &'static str;

    fn capabilities(&self) -> Capabilities {
        Capabilities::default()
    }

    /// Writes `body` under `key`, replacing anything there. A failed body
    /// stream must leave no partial blob visible under `key`.
    async fn put(
        &self,
        key: &BlobKey,
        body: ByteStream,
        meta: PutMeta,
    ) -> Result<BlobMeta, BlobError>;

    /// Reads a blob, or `range` of it (`start..end`, end exclusive).
    async fn get(
        &self,
        key: &BlobKey,
        range: Option<Range<u64>>,
    ) -> Result<(BlobMeta, ByteStream), BlobError>;

    async fn head(&self, key: &BlobKey) -> Result<BlobMeta, BlobError>;

    /// Removes a blob. Removing one that does not exist is not an error:
    /// deletion is retried, and a retry must not fail on its own success.
    async fn delete(&self, key: &BlobKey) -> Result<(), BlobError>;

    /// Removes every blob under `prefix`, returning how many were removed.
    async fn delete_prefix(&self, prefix: &BlobKey) -> Result<u64, BlobError>;

    /// A time-limited URL the provider itself serves. Optional; see
    /// [`Capabilities::presign`].
    async fn presign_get(
        &self,
        _key: &BlobKey,
        _ttl: std::time::Duration,
    ) -> Result<url::Url, BlobError> {
        Err(BlobError::Unsupported("presigned URLs"))
    }
}

/// Hands out the store a tenant's files live in.
#[derive(Clone, Default)]
pub struct StorageResolver {
    store: Option<Arc<dyn BlobStore>>,
    prefix: Option<BlobKey>,
}

impl fmt::Debug for StorageResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageResolver")
            .field("backend", &self.store.as_ref().map(|store| store.name()))
            .field("prefix", &self.prefix)
            .finish()
    }
}

impl StorageResolver {
    /// No storage: file endpoints answer 404.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Every tenant's files in `store`, under `prefix` when one is given.
    pub fn new(store: Arc<dyn BlobStore>, prefix: Option<BlobKey>) -> Self {
        Self {
            store: Some(store),
            prefix,
        }
    }

    pub fn enabled(&self) -> bool {
        self.store.is_some()
    }

    /// The store for `tenant_id`'s files.
    pub async fn for_tenant(
        &self,
        _tenant_id: Option<Uuid>,
    ) -> Result<Arc<dyn BlobStore>, AppError> {
        self.store
            .clone()
            .ok_or_else(|| AppError::not_found("file storage is not enabled"))
    }

    /// Writes, reads back and deletes a small object under `<prefix>/_probe`,
    /// proving the deployment's store is reachable with the access files
    /// need. Nothing to check when storage is off.
    pub async fn check_writable(&self) -> Result<(), BlobError> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let probe = BlobKey::parse("_probe")?.join(&Uuid::new_v4().simple().to_string())?;
        let key = match &self.prefix {
            Some(prefix) => prefix.join(probe.as_str())?,
            None => probe,
        };
        let body = Bytes::from_static(b"atom storage probe");
        store
            .put(&key, once(body.clone()), PutMeta::default())
            .await?;
        let (_, stream) = store.get(&key, None).await?;
        let read = collect(stream).await;
        store.delete(&key).await?;
        if read? != body {
            return Err(BlobError::Backend(
                "the probe object read back differently".into(),
            ));
        }
        Ok(())
    }

    /// Where `tenant_id`'s files live within its store: `<prefix>/<tenant>`,
    /// with `_platform` for files that belong to no tenant. Everything a
    /// tenant stores is under this key, so it is what export, migration and
    /// tenant purge operate on.
    pub fn tenant_prefix(&self, tenant_id: Option<Uuid>) -> BlobKey {
        let tenant =
            tenant_id.map_or_else(|| "_platform".to_string(), |id| id.simple().to_string());
        match &self.prefix {
            Some(prefix) => prefix.join(&tenant).expect("a UUID is a valid key segment"),
            None => BlobKey::parse(tenant).expect("a UUID is a valid key segment"),
        }
    }
}

/// Builds the deployment's storage from configuration. `None` when storage is
/// off. Provider settings are read by the adapter that owns them, so they
/// never sit in [`crate::config::Config`] where `Debug` could print them.
pub fn build(config: &StorageConfig) -> anyhow::Result<StorageResolver> {
    let Some(backend) = config.backend.as_deref() else {
        return Ok(StorageResolver::disabled());
    };
    let prefix = config
        .prefix
        .as_deref()
        .map(BlobKey::parse)
        .transpose()
        .map_err(|err| anyhow::anyhow!("ATOM_STORAGE_PREFIX: {err}"))?;
    let store: Arc<dyn BlobStore> = match backend {
        "memory" => Arc::new(memory::MemoryBlobStore::default()),
        #[cfg(feature = "storage-object-store")]
        other => object_store_adapter::from_env(other)?,
        #[cfg(not(feature = "storage-object-store"))]
        other => anyhow::bail!(
            "ATOM_STORAGE_BACKEND={other} needs an adapter this build does not include; \
             rebuild with the matching storage-* feature"
        ),
    };
    tracing::info!(backend = store.name(), "file storage enabled");
    Ok(StorageResolver::new(store, prefix))
}

/// Collects a [`ByteStream`] into memory. For tests and small reads only.
pub async fn collect(mut stream: ByteStream) -> Result<Vec<u8>, BlobError> {
    use futures_util::StreamExt;
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        out.extend_from_slice(&chunk?);
    }
    Ok(out)
}

/// A [`ByteStream`] of one chunk.
pub fn once(bytes: impl Into<Bytes>) -> ByteStream {
    Box::pin(futures_util::stream::once(std::future::ready(Ok(
        bytes.into()
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_cannot_escape_their_prefix() {
        for bad in [
            "", "/a", "a/", "a//b", "a/../b", "..", ".", "a/b c", "a\\b", "é",
        ] {
            assert!(BlobKey::parse(bad).is_err(), "{bad:?}");
        }
        let key = BlobKey::parse("files/0123abcd/obj-1.v2").unwrap();
        assert_eq!(key.as_str(), "files/0123abcd/obj-1.v2");
        assert!(key.starts_with(&BlobKey::parse("files/0123abcd").unwrap()));
        assert!(!key.starts_with(&BlobKey::parse("files/0123").unwrap()));
    }

    #[test]
    fn a_tenant_owns_one_prefix() {
        let resolver = StorageResolver::new(
            Arc::new(memory::MemoryBlobStore::default()),
            Some(BlobKey::parse("atom").unwrap()),
        );
        let tenant = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        assert_eq!(
            resolver.tenant_prefix(Some(tenant)).as_str(),
            "atom/11111111222233334444555555555555"
        );
        assert_eq!(resolver.tenant_prefix(None).as_str(), "atom/_platform");
    }

    #[tokio::test]
    async fn the_startup_probe_leaves_nothing_behind() {
        let store = Arc::new(memory::MemoryBlobStore::default());
        let resolver = StorageResolver::new(store.clone(), Some(BlobKey::parse("atom").unwrap()));
        resolver.check_writable().await.expect("probe");
        assert!(store.is_empty());
        StorageResolver::disabled()
            .check_writable()
            .await
            .expect("nothing to probe");
    }

    #[tokio::test]
    async fn the_memory_adapter_passes_the_conformance_suite() {
        conformance::run(&memory::MemoryBlobStore::default()).await;
    }
}
