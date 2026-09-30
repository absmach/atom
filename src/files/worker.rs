//! Deletes queued blobs from the store once they are older than the grace
//! period. The grace period covers uploads still streaming: their own key is
//! queued while they write it, and they take it off the queue when they
//! commit.

use chrono::Utc;

use super::repo::{self, QueuedBlob};
use crate::{error::AppError, state::AppState, storage::BlobKey};

/// What one pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DeletionSummary {
    pub deleted: usize,
    pub failed: usize,
}

pub fn spawn_blob_deletion_with_shutdown(
    state: AppState,
    shutdown: tokio_util::sync::CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    if !state.storage.enabled() {
        return None;
    }
    let interval_secs = state.config.storage.deletion_interval_secs;
    let tasks = state.background_tasks.clone();
    Some(tasks.spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => break,
                _ = interval.tick() => {}
            }
            match delete_due(&state).await {
                Ok(summary) if summary.deleted > 0 || summary.failed > 0 => {
                    tracing::info!(
                        deleted = summary.deleted,
                        failed = summary.failed,
                        "blob deletion pass"
                    );
                }
                Ok(_) => {}
                Err(err) => tracing::warn!(error = %err, "blob deletion pass failed"),
            }
        }
    }))
}

/// One pass: claims due keys and deletes their bytes, putting back any whose
/// deletion failed.
pub async fn delete_due(state: &AppState) -> Result<DeletionSummary, AppError> {
    let config = &state.config.storage;
    let cutoff = Utc::now()
        - chrono::Duration::seconds(i64::try_from(config.deletion_grace_secs).unwrap_or(i64::MAX));
    let mut summary = DeletionSummary::default();
    for blob in repo::claim_due(state.pool(), cutoff, config.deletion_batch).await? {
        match delete_one(state, &blob).await {
            Ok(()) => summary.deleted += 1,
            Err(err) => {
                summary.failed += 1;
                tracing::warn!(key = %blob.storage_key, attempts = blob.attempts + 1, error = %err, "blob deletion failed");
                repo::requeue(state.pool(), &blob, &err.to_string()).await?;
            }
        }
    }
    Ok(summary)
}

async fn delete_one(state: &AppState, blob: &QueuedBlob) -> Result<(), AppError> {
    // Keys are never reused, so a referenced key is one a restore or a
    // failed-then-retried commit still needs; it is dropped from the queue.
    if repo::referenced(state.pool(), &blob.storage_key).await? {
        return Ok(());
    }
    let Ok(key) = BlobKey::parse(blob.storage_key.clone()) else {
        tracing::warn!(key = %blob.storage_key, "dropping an invalid key from the deletion queue");
        return Ok(());
    };
    let store = state.storage.for_tenant(blob.tenant_id).await?;
    store.delete(&key).await?;
    Ok(())
}
