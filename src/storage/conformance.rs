//! The contract every [`BlobStore`] adapter must meet, as a test suite.
//!
//! Adding a provider means implementing the trait and calling [`run`] from
//! the adapter's tests against a real (or emulated) instance. The suite writes
//! only under a fresh random prefix and removes what it wrote.

use bytes::Bytes;
use futures_util::stream;
use uuid::Uuid;

use super::{collect, once, BlobError, BlobKey, BlobStore, ByteStream, PutMeta};

/// Runs every check against `store`. Panics on the first failure.
pub async fn run(store: &dyn BlobStore) {
    let root = BlobKey::parse(format!("conformance-{}", Uuid::new_v4().simple())).unwrap();

    round_trip(store, &root).await;
    chunked_writes_are_joined(store, &root).await;
    overwrite_replaces(store, &root).await;
    ranges(store, &root).await;
    missing_keys(store, &root).await;
    failed_body_leaves_nothing(store, &root).await;
    delete_is_idempotent(store, &root).await;
    prefix_delete_is_scoped(store, &root).await;

    store
        .delete_prefix(&root)
        .await
        .expect("clean up the suite's prefix");
}

fn key(root: &BlobKey, name: &str) -> BlobKey {
    root.join(name).unwrap()
}

async fn round_trip(store: &dyn BlobStore, root: &BlobKey) {
    let key = key(root, "round-trip");
    let meta = store
        .put(
            &key,
            once(&b"hello, world"[..]),
            PutMeta {
                content_type: Some("text/plain".into()),
            },
        )
        .await
        .expect("put");
    assert_eq!(
        meta.size,
        12,
        "{}: put reports the size written",
        store.name()
    );
    assert_eq!(store.head(&key).await.expect("head").size, 12);
    let (meta, body) = store.get(&key, None).await.expect("get");
    assert_eq!(meta.size, 12);
    assert_eq!(collect(body).await.expect("read"), b"hello, world");
}

async fn chunked_writes_are_joined(store: &dyn BlobStore, root: &BlobKey) {
    let key = key(root, "chunked");
    // Larger than any single buffer an adapter is likely to use, so a
    // streaming adapter exercises more than one part.
    let chunk = Bytes::from(vec![7u8; 1024 * 1024]);
    let body: ByteStream = Box::pin(stream::iter((0..9).map(move |_| Ok(chunk.clone()))));
    store
        .put(&key, body, PutMeta::default())
        .await
        .expect("chunked put");
    let (meta, body) = store.get(&key, None).await.expect("get");
    assert_eq!(meta.size, 9 * 1024 * 1024);
    let data = collect(body).await.expect("read");
    assert_eq!(data.len(), 9 * 1024 * 1024);
    assert!(data.iter().all(|b| *b == 7));
}

async fn overwrite_replaces(store: &dyn BlobStore, root: &BlobKey) {
    let key = key(root, "overwrite");
    store
        .put(&key, once(&b"first"[..]), PutMeta::default())
        .await
        .unwrap();
    store
        .put(&key, once(&b"second!"[..]), PutMeta::default())
        .await
        .unwrap();
    let (meta, body) = store.get(&key, None).await.unwrap();
    assert_eq!(meta.size, 7);
    assert_eq!(collect(body).await.unwrap(), b"second!");
}

async fn ranges(store: &dyn BlobStore, root: &BlobKey) {
    let key = key(root, "ranges");
    store
        .put(&key, once(&b"0123456789"[..]), PutMeta::default())
        .await
        .unwrap();
    let (_, body) = store.get(&key, Some(2..5)).await.expect("ranged get");
    assert_eq!(collect(body).await.unwrap(), b"234");
    let (_, body) = store.get(&key, Some(9..10)).await.expect("last byte");
    assert_eq!(collect(body).await.unwrap(), b"9");
}

async fn missing_keys(store: &dyn BlobStore, root: &BlobKey) {
    let key = key(root, "never-written");
    assert!(
        matches!(store.head(&key).await, Err(BlobError::NotFound(_))),
        "{}: head",
        store.name()
    );
    assert!(
        matches!(store.get(&key, None).await, Err(BlobError::NotFound(_))),
        "{}: get",
        store.name()
    );
}

async fn failed_body_leaves_nothing(store: &dyn BlobStore, root: &BlobKey) {
    let key = key(root, "failed-body");
    let body: ByteStream = Box::pin(stream::iter(vec![
        Ok(Bytes::from_static(b"partial")),
        Err(BlobError::Body("client went away".into())),
    ]));
    assert!(store.put(&key, body, PutMeta::default()).await.is_err());
    assert!(
        matches!(store.head(&key).await, Err(BlobError::NotFound(_))),
        "{}: a failed upload must not leave a blob behind",
        store.name()
    );
}

async fn delete_is_idempotent(store: &dyn BlobStore, root: &BlobKey) {
    let key = key(root, "deleted");
    store
        .put(&key, once(&b"x"[..]), PutMeta::default())
        .await
        .unwrap();
    store.delete(&key).await.expect("delete");
    assert!(matches!(
        store.head(&key).await,
        Err(BlobError::NotFound(_))
    ));
    store
        .delete(&key)
        .await
        .expect("deleting a missing blob succeeds");
}

async fn prefix_delete_is_scoped(store: &dyn BlobStore, root: &BlobKey) {
    let tenant = key(root, "tenant-a");
    let sibling = key(root, "tenant-ab");
    for name in ["one", "two/three"] {
        store
            .put(
                &tenant.join(name).unwrap(),
                once(&b"x"[..]),
                PutMeta::default(),
            )
            .await
            .unwrap();
    }
    store
        .put(
            &sibling.join("kept").unwrap(),
            once(&b"x"[..]),
            PutMeta::default(),
        )
        .await
        .unwrap();

    assert_eq!(
        store.delete_prefix(&tenant).await.expect("prefix delete"),
        2
    );
    assert!(matches!(
        store.head(&tenant.join("one").unwrap()).await,
        Err(BlobError::NotFound(_))
    ));
    assert!(
        store.head(&sibling.join("kept").unwrap()).await.is_ok(),
        "{}: a prefix delete must stop at a segment boundary",
        store.name()
    );
}
