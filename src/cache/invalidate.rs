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

use std::{future::Future, pin::Pin};

use sqlx::{PgPool, Postgres, Transaction};

use super::{CacheCategory, CacheClient, CacheLease};
use crate::error::{db_err, AppError};

/// A boxed future borrowing the transaction it runs on — what
/// [`guarded_tx_mutation`]'s closures return. Stable Rust has no async
/// closures, so a closure that awaits while holding `&mut Transaction` has to
/// spell the borrow out by hand; call sites write `|tx| Box::pin(f(tx, ..))`.
pub type TxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, AppError>> + Send + 'a>>;

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

    let lease = cache.begin(category, keys).await?;
    let result = mutate().await;
    cache.end(lease).await;
    result
}

/// [`guarded_mutation`] for a mutation whose affected keys can only be
/// determined *under the locks the mutation itself takes* — every
/// group-closure and role mutation, where the set of affected `grants` keys
/// is the enumerated member set and a concurrent membership change would
/// otherwise slip past the enumeration (see
/// `authz::repo::lock_group_closures_and_collect_member_ids`).
///
/// Opens the transaction, runs `collect_keys` on it (which locks and
/// enumerates), establishes the barrier on what it returned, runs `mutate` on
/// the same transaction, commits, and clears the barrier — in that order,
/// regardless of outcome. That ordering is the whole point of the helper: the
/// barrier must be established after the lock (so the enumeration is
/// complete) and cleared after the commit (so no reader repopulates from
/// pre-commit state), and every call site previously re-derived it by hand.
///
/// Callers hold the `None` cache case themselves, since the uncached
/// fallback is a different repo function per call site rather than the same
/// one — usually the non-`_in_tx` variant that opens its own transaction.
pub async fn guarded_tx_mutation<T, K, M, S>(
    cache: &CacheClient,
    category: CacheCategory,
    pool: &PgPool,
    collect_keys: K,
    mutate: M,
    on_success: S,
) -> Result<T, AppError>
where
    K: for<'a> FnOnce(&'a mut Transaction<'static, Postgres>) -> TxFuture<'a, Vec<String>>,
    M: for<'a> FnOnce(&'a mut Transaction<'static, Postgres>) -> TxFuture<'a, T>,
    S: FnOnce(&T),
{
    let mut tx = pool.begin().await.map_err(db_err)?;
    let keys = collect_keys(&mut tx).await?;
    let lease = cache.begin(category, &keys).await?;
    let outcome = mutate(&mut tx).await;
    let outcome = match outcome {
        Ok(value) => {
            let result = crate::audit::commit_observed_with_cache(tx, cache, lease, value).await;
            if let Ok(ref value) = result {
                on_success(value);
            }
            result
        }
        Err(err) => {
            cache.end(lease).await;
            Err(err)
        }
    };
    outcome
}

/// Establishes a barrier on every `(category, keys)` group, in order. Used by
/// callers that already hold an open `Transaction` across their own
/// lock/enumerate/mutate/commit sequence (so the barrier can't be established
/// via a `FnOnce` closure the way [`guarded_mutation`] does). Prefer
/// [`guarded_tx_mutation`] for the single-category case it covers; `begin_all`
/// remains for mutations spanning several categories on one transaction.
///
/// If a later group's barrier can't be established, cleanup is attempted for
/// every requested group. Exact-token cleanup is a no-op where BEGIN did not
/// execute, and prevents an ambiguous timeout from leaving an avoidable
/// permanent barrier. Pair with [`end_all`], called unconditionally after the
/// mutation regardless of outcome.
pub async fn begin_all(
    cache: &CacheClient,
    groups: &[(CacheCategory, &[String])],
) -> Result<Vec<CacheLease>, AppError> {
    let mut established = Vec::with_capacity(groups.len());
    for &(category, keys) in groups {
        match cache.begin(category, keys).await {
            Ok(lease) => established.push(lease),
            Err(err) => {
                for lease in established {
                    cache.end(lease).await;
                }
                return Err(err);
            }
        }
    }
    Ok(established)
}

/// Clears the barrier on every `(category, keys)` group established by a
/// prior [`begin_all`] call. Always best-effort, mirroring [`CacheClient::end`].
pub async fn end_all(cache: &CacheClient, leases: Vec<CacheLease>) {
    for lease in leases {
        cache.end(lease).await;
    }
}
