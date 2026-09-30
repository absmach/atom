//! An in-process [`BlobStore`]. Always compiled, with no provider dependency:
//! tests use it, and it is the proof that nothing above the storage boundary
//! needs a real provider. Not for production -- it forgets on restart.

use std::{collections::BTreeMap, ops::Range, sync::Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use futures_util::StreamExt;

use super::{BlobError, BlobKey, BlobMeta, BlobStore, ByteStream, PutMeta};

#[derive(Default)]
pub struct MemoryBlobStore {
    blobs: Mutex<BTreeMap<BlobKey, (Bytes, BlobMeta)>>,
}

impl MemoryBlobStore {
    /// How many blobs it holds. For tests.
    pub fn len(&self) -> usize {
        self.blobs.lock().expect("memory store lock").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl BlobStore for MemoryBlobStore {
    fn name(&self) -> &'static str {
        "memory"
    }

    async fn put(
        &self,
        key: &BlobKey,
        mut body: ByteStream,
        _meta: PutMeta,
    ) -> Result<BlobMeta, BlobError> {
        // Collected first and stored only once complete, so a failed body
        // leaves no partial blob -- the same guarantee a multipart upload gives.
        let mut data = Vec::new();
        while let Some(chunk) = body.next().await {
            data.extend_from_slice(&chunk?);
        }
        let meta = BlobMeta {
            key: key.clone(),
            size: data.len() as u64,
            last_modified: Some(Utc::now()),
        };
        self.blobs
            .lock()
            .expect("memory store lock")
            .insert(key.clone(), (Bytes::from(data), meta.clone()));
        Ok(meta)
    }

    async fn get(
        &self,
        key: &BlobKey,
        range: Option<Range<u64>>,
    ) -> Result<(BlobMeta, ByteStream), BlobError> {
        let (data, meta) = self
            .blobs
            .lock()
            .expect("memory store lock")
            .get(key)
            .cloned()
            .ok_or_else(|| BlobError::NotFound(key.to_string()))?;
        let data = match range {
            None => data,
            Some(range) if range.start <= range.end && range.end <= meta.size => {
                data.slice(range.start as usize..range.end as usize)
            }
            Some(range) => return Err(BlobError::InvalidRange(range)),
        };
        Ok((meta, super::once(data)))
    }

    async fn head(&self, key: &BlobKey) -> Result<BlobMeta, BlobError> {
        self.blobs
            .lock()
            .expect("memory store lock")
            .get(key)
            .map(|(_, meta)| meta.clone())
            .ok_or_else(|| BlobError::NotFound(key.to_string()))
    }

    async fn delete(&self, key: &BlobKey) -> Result<(), BlobError> {
        self.blobs.lock().expect("memory store lock").remove(key);
        Ok(())
    }

    async fn delete_prefix(&self, prefix: &BlobKey) -> Result<u64, BlobError> {
        let mut blobs = self.blobs.lock().expect("memory store lock");
        let before = blobs.len();
        blobs.retain(|key, _| !key.starts_with(prefix));
        Ok((before - blobs.len()) as u64)
    }
}
