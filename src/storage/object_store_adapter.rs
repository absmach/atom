//! [`BlobStore`] over the [`object_store`] crate: the local filesystem, and
//! with the `storage-s3`/`storage-gcs`/`storage-azure` features S3 and
//! S3-compatible stores, Google Cloud Storage and Azure Blob.
//!
//! Nothing from `object_store` leaves this module. Its settings are read here
//! from `ATOM_STORAGE_*` variables, after the provider's own standard
//! environment (`AWS_*`, `GOOGLE_*`, `AZURE_*`), so instance roles and
//! workload identity work without Atom-specific configuration.

use std::{ops::Range, sync::Arc};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures_util::{StreamExt, TryStreamExt};
use object_store::{
    path::Path, GetOptions, GetRange, ObjectStore, ObjectStoreExt, PutPayload, WriteMultipart,
};

use super::{BlobError, BlobKey, BlobMeta, BlobStore, ByteStream, PutMeta};

/// Below this, a blob is written in one request; above it, as a multipart
/// upload. It is also the part size: S3's minimum for every part but the last.
const PART_BYTES: usize = 5 * 1024 * 1024;
/// Parts in flight at once during a multipart upload.
const PARTS_IN_FLIGHT: usize = 4;

pub struct ObjectStoreBlobStore {
    name: &'static str,
    store: Arc<dyn ObjectStore>,
}

impl ObjectStoreBlobStore {
    pub fn new(name: &'static str, store: Arc<dyn ObjectStore>) -> Self {
        Self { name, store }
    }
}

/// Builds the adapter for `ATOM_STORAGE_BACKEND=<backend>`.
pub fn from_env(backend: &str) -> anyhow::Result<Arc<dyn BlobStore>> {
    let adapter = match backend {
        "local" => {
            let path = required("ATOM_STORAGE_LOCAL_PATH")?;
            std::fs::create_dir_all(&path)
                .map_err(|err| anyhow::anyhow!("ATOM_STORAGE_LOCAL_PATH {path}: {err}"))?;
            let store = object_store::local::LocalFileSystem::new_with_prefix(&path)
                .map_err(|err| anyhow::anyhow!("ATOM_STORAGE_LOCAL_PATH {path}: {err}"))?;
            ObjectStoreBlobStore::new("local", Arc::new(store))
        }
        #[cfg(feature = "storage-s3")]
        "s3" => {
            let mut builder = object_store::aws::AmazonS3Builder::from_env()
                .with_bucket_name(required("ATOM_STORAGE_S3_BUCKET")?);
            if let Some(region) = optional("ATOM_STORAGE_S3_REGION") {
                builder = builder.with_region(region);
            }
            if let Some(endpoint) = optional("ATOM_STORAGE_S3_ENDPOINT") {
                builder = builder.with_endpoint(endpoint);
            }
            if let Some(key) = optional("ATOM_STORAGE_S3_ACCESS_KEY_ID") {
                builder = builder.with_access_key_id(key);
            }
            if let Some(secret) = optional("ATOM_STORAGE_S3_SECRET_ACCESS_KEY") {
                builder = builder.with_secret_access_key(secret);
            }
            // MinIO and SeaweedFS are commonly reached over plain HTTP inside
            // a private network, and address buckets by path.
            builder = builder
                .with_allow_http(flag("ATOM_STORAGE_S3_ALLOW_HTTP")?)
                .with_virtual_hosted_style_request(flag("ATOM_STORAGE_S3_VIRTUAL_HOSTED")?);
            ObjectStoreBlobStore::new("s3", Arc::new(builder.build()?))
        }
        #[cfg(feature = "storage-gcs")]
        "gcs" => {
            let mut builder = object_store::gcp::GoogleCloudStorageBuilder::from_env()
                .with_bucket_name(required("ATOM_STORAGE_GCS_BUCKET")?);
            if let Some(path) = optional("ATOM_STORAGE_GCS_SERVICE_ACCOUNT_PATH") {
                builder = builder.with_service_account_path(path);
            }
            ObjectStoreBlobStore::new("gcs", Arc::new(builder.build()?))
        }
        #[cfg(feature = "storage-azure")]
        "azure" => {
            let mut builder = object_store::azure::MicrosoftAzureBuilder::from_env()
                .with_account(required("ATOM_STORAGE_AZURE_ACCOUNT")?)
                .with_container_name(required("ATOM_STORAGE_AZURE_CONTAINER")?);
            if let Some(key) = optional("ATOM_STORAGE_AZURE_ACCESS_KEY") {
                builder = builder.with_access_key(key);
            }
            ObjectStoreBlobStore::new("azure", Arc::new(builder.build()?))
        }
        other => anyhow::bail!(
            "unknown ATOM_STORAGE_BACKEND {other:?}: expected memory, local{}{}{}",
            if cfg!(feature = "storage-s3") {
                ", s3"
            } else {
                ""
            },
            if cfg!(feature = "storage-gcs") {
                ", gcs"
            } else {
                ""
            },
            if cfg!(feature = "storage-azure") {
                ", azure"
            } else {
                ""
            },
        ),
    };
    Ok(Arc::new(adapter))
}

fn required(name: &str) -> anyhow::Result<String> {
    optional(name).ok_or_else(|| anyhow::anyhow!("{name} must be set for this storage backend"))
}

fn optional(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn flag(name: &str) -> anyhow::Result<bool> {
    match optional(name).as_deref() {
        None => Ok(false),
        Some("true" | "1" | "yes") => Ok(true),
        Some("false" | "0" | "no") => Ok(false),
        Some(other) => anyhow::bail!("{name} must be true or false, not {other:?}"),
    }
}

fn path(key: &BlobKey) -> Result<Path, BlobError> {
    Path::parse(key.as_str()).map_err(|_| BlobError::InvalidKey(key.to_string()))
}

fn backend(err: object_store::Error) -> BlobError {
    match err {
        object_store::Error::NotFound { path, .. } => BlobError::NotFound(path),
        other => BlobError::Backend(other.to_string()),
    }
}

fn meta(key: &BlobKey, object: &object_store::ObjectMeta) -> BlobMeta {
    BlobMeta {
        key: key.clone(),
        size: object.size,
        last_modified: Some(object.last_modified),
    }
}

#[async_trait]
impl BlobStore for ObjectStoreBlobStore {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn put(
        &self,
        key: &BlobKey,
        mut body: ByteStream,
        _meta: PutMeta,
    ) -> Result<BlobMeta, BlobError> {
        let location = path(key)?;

        // Buffer up to one part. A body that ends within it -- a photo, most
        // documents -- is written in a single request.
        let mut head = BytesMut::new();
        let mut rest = None;
        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            head.extend_from_slice(&chunk);
            if head.len() >= PART_BYTES {
                rest = Some(());
                break;
            }
        }

        if rest.is_none() {
            let size = head.len() as u64;
            self.store
                .put(&location, PutPayload::from(head.freeze()))
                .await
                .map_err(backend)?;
            return Ok(BlobMeta {
                key: key.clone(),
                size,
                last_modified: None,
            });
        }

        let upload = self.store.put_multipart(&location).await.map_err(backend)?;
        let mut writer = WriteMultipart::new_with_chunk_size(upload, PART_BYTES);
        let mut size = head.len() as u64;
        writer.write(&head);
        drop(head);
        while let Some(chunk) = body.next().await {
            let chunk: Bytes = match chunk {
                Ok(chunk) => chunk,
                Err(err) => {
                    // Abort so no partial object is ever completed.
                    let _ = writer.abort().await;
                    return Err(err);
                }
            };
            if let Err(err) = writer.wait_for_capacity(PARTS_IN_FLIGHT).await {
                let _ = writer.abort().await;
                return Err(backend(err));
            }
            size += chunk.len() as u64;
            writer.write(&chunk);
        }
        writer.finish().await.map_err(backend)?;
        Ok(BlobMeta {
            key: key.clone(),
            size,
            last_modified: None,
        })
    }

    async fn get(
        &self,
        key: &BlobKey,
        range: Option<Range<u64>>,
    ) -> Result<(BlobMeta, ByteStream), BlobError> {
        let options = GetOptions {
            range: range.map(GetRange::Bounded),
            ..GetOptions::default()
        };
        let result = self
            .store
            .get_opts(&path(key)?, options)
            .await
            .map_err(backend)?;
        let meta = meta(key, &result.meta);
        let stream = result.into_stream().map_err(backend).boxed();
        Ok((meta, stream))
    }

    async fn head(&self, key: &BlobKey) -> Result<BlobMeta, BlobError> {
        let object = self.store.head(&path(key)?).await.map_err(backend)?;
        Ok(meta(key, &object))
    }

    async fn delete(&self, key: &BlobKey) -> Result<(), BlobError> {
        match self.store.delete(&path(key)?).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(err) => Err(backend(err)),
        }
    }

    async fn delete_prefix(&self, prefix: &BlobKey) -> Result<u64, BlobError> {
        // `list` is segment-based: `a/tenant` never lists `a/tenant-b/...`.
        let listed: Vec<Path> = self
            .store
            .list(Some(&path(prefix)?))
            .map_ok(|object| object.location)
            .try_collect()
            .await
            .map_err(backend)?;
        let count = listed.len() as u64;
        let locations = futures_util::stream::iter(listed.into_iter().map(Ok)).boxed();
        self.store
            .delete_stream(locations)
            .try_for_each(|_| async { Ok(()) })
            .await
            .or_else(|err| match err {
                object_store::Error::NotFound { .. } => Ok(()),
                other => Err(backend(other)),
            })?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_local_adapter_passes_the_conformance_suite() {
        let dir =
            std::env::temp_dir().join(format!("atom-storage-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = ObjectStoreBlobStore::new(
            "local",
            Arc::new(object_store::local::LocalFileSystem::new_with_prefix(&dir).unwrap()),
        );
        super::super::conformance::run(&store).await;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn the_in_memory_object_store_passes_the_conformance_suite() {
        let store = ObjectStoreBlobStore::new(
            "object-store-memory",
            Arc::new(object_store::memory::InMemory::new()),
        );
        super::super::conformance::run(&store).await;
    }

    /// Runs against a real S3-compatible store (such as MinIO) when
    /// `ATOM_TEST_S3_BUCKET` and the usual `ATOM_STORAGE_S3_*` settings are
    /// set, and passes without one: the DB-gated CI jobs run ignored tests but
    /// provision no object store.
    #[cfg(feature = "storage-s3")]
    #[tokio::test]
    #[ignore]
    async fn the_s3_adapter_passes_the_conformance_suite() {
        let Ok(bucket) = std::env::var("ATOM_TEST_S3_BUCKET") else {
            eprintln!("ATOM_TEST_S3_BUCKET is not set; skipping the S3 conformance suite");
            return;
        };
        std::env::set_var("ATOM_STORAGE_S3_BUCKET", bucket);
        let store = from_env("s3").expect("configure s3");
        super::super::conformance::run(store.as_ref()).await;
    }
}
