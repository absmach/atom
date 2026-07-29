//! The single orchestration primitive every security-sensitive mutation goes
//! through: establish the barrier on the affected cache keys, run the
//! Postgres mutation, then clear the barrier — regardless of the mutation's
//! outcome. See `src/cache/mod.rs` for the consistency model this
//! implements.
//!
//! Callers determine *which* keys are affected (a single subject, or an
//! enumerated set — see `authz::repo::affected_subject_ids_for_role` /
//! `affected_subject_ids_for_group`) before calling this; the enumeration
//! itself is domain SQL and does not belong here.

use std::future::Future;

use super::{CacheCategory, CacheClient};
use crate::error::AppError;

/// Runs `mutate` guarded by a cache barrier on `keys`. With caching disabled
/// (`cache: None`) this is a pure passthrough to `mutate`, byte-identical to
/// not having a cache at all.
///
/// If establishing the barrier fails while caching is enabled, the mutation
/// is refused (`mutate` is never called) rather than committing a Postgres
/// change the cache cannot be told about — see the module-level consistency
/// model in `src/cache/mod.rs`.
pub async fn guarded_mutation<T, F, Fut>(
    cache: Option<&CacheClient>,
    category: CacheCategory,
    keys: &[String],
    mutate: F,
) -> Result<T, AppError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T, AppError>>,
{
    let Some(cache) = cache else {
        return mutate().await;
    };

    cache.begin(category, keys).await?;
    let result = mutate().await;
    cache.end(category, keys).await;
    result
}

/// Like [`guarded_mutation`], for a mutation whose effects span more than one
/// cache category in a single Postgres transaction — e.g. tenant restore,
/// which both flips the tenant's own status and reactivates a set of
/// credentials. Establishes a barrier on every `(category, keys)` group
/// before running `mutate`; if a later group's barrier can't be established,
/// the ones already established are cleared immediately (rather than left to
/// self-heal on their barrier TTL) before the mutation is refused. Every
/// established group is cleared after `mutate` regardless of outcome.
pub async fn guarded_multi_mutation<T, F, Fut>(
    cache: Option<&CacheClient>,
    groups: &[(CacheCategory, &[String])],
    mutate: F,
) -> Result<T, AppError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T, AppError>>,
{
    let Some(cache) = cache else {
        return mutate().await;
    };

    let mut established = Vec::with_capacity(groups.len());
    for &(category, keys) in groups {
        match cache.begin(category, keys).await {
            Ok(()) => established.push((category, keys)),
            Err(err) => {
                for (category, keys) in established {
                    cache.end(category, keys).await;
                }
                return Err(err);
            }
        }
    }

    let result = mutate().await;
    for (category, keys) in established {
        cache.end(category, keys).await;
    }
    result
}

/// Establishes a barrier on every `(category, keys)` group, in order. Used by
/// callers that already hold an open `Transaction` across their own
/// lock/enumerate/mutate/commit sequence (so the barrier can't be established
/// via a `FnOnce` closure the way [`guarded_mutation`]/[`guarded_multi_mutation`]
/// do — a closure can't cleanly borrow `&mut Transaction` across an await
/// point on stable Rust). If a later group's barrier can't be established, the
/// ones already established are cleared immediately rather than left to
/// self-heal on their barrier TTL. Pair with [`end_all`], called
/// unconditionally after the mutation regardless of outcome.
pub async fn begin_all(
    cache: &CacheClient,
    groups: &[(CacheCategory, &[String])],
) -> Result<(), AppError> {
    let mut established = Vec::with_capacity(groups.len());
    for &(category, keys) in groups {
        match cache.begin(category, keys).await {
            Ok(()) => established.push((category, keys)),
            Err(err) => {
                for (category, keys) in established {
                    cache.end(category, keys).await;
                }
                return Err(err);
            }
        }
    }
    Ok(())
}

/// Clears the barrier on every `(category, keys)` group established by a
/// prior [`begin_all`] call. Always best-effort, mirroring [`CacheClient::end`].
pub async fn end_all(cache: &CacheClient, groups: &[(CacheCategory, &[String])]) {
    for &(category, keys) in groups {
        cache.end(category, keys).await;
    }
}
