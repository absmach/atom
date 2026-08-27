//! Redis-backed cache for AuthN/AuthZ decision *inputs* (never decisions
//! themselves — see `src/authz/engine.rs` and `src/auth.rs` for what actually
//! decides allow/deny). Postgres remains the sole source of truth.
//!
//! # Consistency model
//!
//! Every cached entry is a Redis hash with three fields: `v` (an integer
//! version, bumped on every mutation that can affect the entry), `dirty` (an
//! integer *nesting counter* — above zero while one or more mutations are in
//! flight, zero or absent otherwise), and `p` (the serialized payload,
//! present only when the entry holds a valid value).
//!
//! Three primitives, each a small atomic Lua script, implement a per-key
//! mutation barrier that prevents four races that a plain cache-aside +
//! post-commit `DEL` cannot: a read started *before* a mutation repopulating
//! the cache with stale data after the mutation's invalidation ran, a read
//! started *during* the mutation's dirty window doing the same once the
//! mutation finishes, a lost invalidation silently resurrecting a revoked
//! value, and — the reason `dirty` is a counter rather than a flag — two
//! overlapping mutations on the same key finishing at different times:
//!
//! - `begin` — called before a security-sensitive Postgres mutation.
//!   Increments the version and the dirty counter, clears any payload, and
//!   bounds the barrier itself with an expiry so a lost `end` call self-heals
//!   rather than leaving the entry dirty forever.
//! - `end` — called after the mutation (success or failure). Bumps the
//!   version *again*, decrements the dirty counter, and clears any payload —
//!   the next reader does a clean reload. The second version bump (beyond the
//!   one `begin` already did) is what closes the dirty-window race below — it
//!   is not merely decrementing a counter.
//! - `try_populate` — called by a cache-miss read after it finishes loading
//!   from Postgres. Writes the payload only if the dirty counter is zero and
//!   the version still matches what the reader observed before it started
//!   loading; otherwise the write is silently discarded.
//!
//! The dirty-window race the version's second bump defeats (found by external
//! review, 2026-07-29 — the original `end` only cleared `dirty`, without
//! re-bumping the version): a reader's `lookup` can land *while* a mutation is
//! mid-flight (`dirty > 0`), observe the *post-`begin`* version, then proceed
//! to load from Postgres — possibly reading the pre-mutation state, since the
//! mutation's own Postgres write may not have committed yet. If `end` only
//! cleared `dirty` without moving the version again, that reader's later
//! `try_populate` call, run after `end`, would find the version *unchanged*
//! since the moment it was observed and would succeed — re-caching a stale
//! value for the mutation's category for a full TTL, exactly during a
//! revoke/policy-change race. Bumping the version in `end` too means any
//! version a reader could have observed during the dirty window is
//! guaranteed stale by the time `end` finishes, so `try_populate` always
//! rejects it — whether it runs while still dirty (rejected by the `dirty`
//! check) or after `end` (rejected by the version check).
//!
//! The overlapping-mutations race a counter (rather than a `0`/`1` flag)
//! defeats (also found by external review, 2026-07-29): if two
//! security-sensitive mutations both touch the same key — say, two role
//! changes affecting the same subject's `grants` entry — and a boolean `dirty`
//! flag is unconditionally cleared by whichever mutation's `end` runs first,
//! a reader landing after that first `end` but before the *second* mutation's
//! commit sees a clean, non-dirty entry and can `try_populate` a payload
//! loaded from the pre-second-mutation database state. That entry is wrong
//! the instant the second mutation commits, and if the second mutation's own
//! `end` is ever delayed or lost, nothing else corrects it before the TTL.
//! Making `dirty` a nesting counter — incremented by every `begin`,
//! decremented by every `end` — means the barrier only reads as clean once
//! *every* overlapping mutation on the key has called `end`, so a reader can
//! never land in the gap between one mutation's `end` and another's commit.
//!
//! Reads never depend on Redis being reachable: any error (timeout,
//! connection failure, corrupt payload) is treated as a miss and falls
//! through to the caller's Postgres loader. `begin` is the one exception —
//! while caching is enabled, a `begin` failure refuses the mutation rather
//! than committing a change the cache cannot be told about (see
//! `src/cache/invalidate.rs`).

pub mod entries;
pub mod invalidate;
pub mod keys;

use std::{future::Future, time::Duration};

use deadpool_redis::{Config as PoolConfig, Pool, Runtime};
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

use crate::{
    config::{CacheConfig, CacheTtlConfig},
    error::AppError,
    metrics,
};

/// Keys are chunked so a single Lua invocation never touches an unbounded
/// number of hash keys in one round trip.
const BULK_CHUNK_SIZE: usize = 500;

const BEGIN_SCRIPT_SRC: &str = r#"
local ttl_ms = ARGV[1]
for i, key in ipairs(KEYS) do
  redis.call('HINCRBY', key, 'v', 1)
  redis.call('HINCRBY', key, 'dirty', 1)
  redis.call('HDEL', key, 'p')
  redis.call('PEXPIRE', key, ttl_ms)
end
return 1
"#;

// Re-applies `PEXPIRE` for the same reason `begin` sets it: `HINCRBY`
// recreates a key that has already expired, and a recreated barrier entry
// with no TTL would never be reclaimed. An `end` that lands after its own
// barrier expired (a long mutation, or a bulk invalidation chunking through
// many keys) would otherwise leak an immortal hash per key.
//
// `dirty` is a nesting counter, not a flag: `begin` increments it, `end`
// decrements it, and only 0 means "no mutation is still in flight" — see the
// module docs for why two overlapping mutations on the same key need this.
// The clamp back to 0 below guards against `dirty` drifting negative if `end`
// is ever called without a matching `begin` (should not happen, but a
// negative counter would otherwise require one *extra* `begin` to dig back
// out of before the barrier could ever be seen as dirty again).
//
// `HDEL p` is defensive rather than load-bearing: `begin` already cleared the
// payload, and `try_populate` refuses to write while dirty. It costs one call
// and guarantees that whatever happened to the key in between — including a
// reader repopulating it against a barrier that was destroyed out from under
// this mutation — the entry is left without a payload for the next reader to
// reload cleanly, which is what `end`'s contract has always claimed.
const END_SCRIPT_SRC: &str = r#"
local ttl_ms = ARGV[1]
for i, key in ipairs(KEYS) do
  redis.call('HINCRBY', key, 'v', 1)
  local remaining = redis.call('HINCRBY', key, 'dirty', -1)
  if remaining < 0 then
    redis.call('HSET', key, 'dirty', 0)
  end
  redis.call('HDEL', key, 'p')
  redis.call('PEXPIRE', key, ttl_ms)
end
return 1
"#;

const TRY_POPULATE_SCRIPT_SRC: &str = r#"
local v = redis.call('HGET', KEYS[1], 'v')
if v == false then v = '0' end
local dirty = tonumber(redis.call('HGET', KEYS[1], 'dirty')) or 0
if dirty > 0 or v ~= ARGV[1] then
  return 'stale'
end
redis.call('HSET', KEYS[1], 'p', ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return 'applied'
"#;

// Discards a corrupt payload without touching the barrier fields. Guarded by
// exactly the same version/dirty check as `try_populate`, and for the same
// reason: an unconditional `DEL` of the whole hash would take `v` and `dirty`
// with it, destroying an in-flight mutation's barrier. The next reader would
// then see an absent key, observe version 0, load pre-commit state, and
// populate it successfully — the barrier's whole purpose, defeated by a
// cleanup path.
const DISCARD_SCRIPT_SRC: &str = r#"
local v = redis.call('HGET', KEYS[1], 'v')
if v == false then v = '0' end
local dirty = tonumber(redis.call('HGET', KEYS[1], 'dirty')) or 0
if dirty > 0 or v ~= ARGV[1] then
  return 'skipped'
end
redis.call('HDEL', KEYS[1], 'p')
return 'discarded'
"#;

/// Fixed, low-cardinality label for cache metrics and log lines. Never an ID,
/// action name, or arbitrary string — see `src/metrics.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheCategory {
    Session,
    EntityStatus,
    TenantStatus,
    Credential,
    CredentialCeiling,
    Grants,
}

impl CacheCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::EntityStatus => "entity_status",
            Self::TenantStatus => "tenant_status",
            Self::Credential => "credential",
            Self::CredentialCeiling => "credential_ceiling",
            Self::Grants => "grants",
        }
    }

    /// The configured entry TTL for this category — resolved here, once, so
    /// callers never need to thread a `Duration` through read/write-path call
    /// sites themselves.
    fn ttl(self, cfg: &CacheTtlConfig) -> Duration {
        let secs = match self {
            Self::Session => cfg.session_secs,
            Self::EntityStatus => cfg.entity_status_secs,
            Self::TenantStatus => cfg.tenant_status_secs,
            Self::Credential => cfg.credential_secs,
            Self::CredentialCeiling => cfg.credential_ceiling_secs,
            Self::Grants => cfg.grants_secs,
        };
        Duration::from_secs(secs)
    }
}

/// The outcome of a cache read: a valid, non-dirty entry, or a miss carrying
/// the version a subsequent `try_populate` must present unchanged to write
/// successfully. `Unavailable` means the read itself failed (timeout,
/// connection error) — callers must fall through to Postgres and must not
/// attempt to populate afterward (the write would just fail too).
#[derive(Debug)]
pub enum Lookup<T> {
    Hit(T),
    Miss { version: i64 },
    Unavailable,
}

/// One key's unparsed entry from [`CacheClient::lookup_many`]. Opaque by
/// design — [`CacheClient::decode`] is the only way to read it, so the
/// dirty-bit and version handling can't be reimplemented per call site.
#[derive(Debug)]
pub struct RawLookup {
    /// `None` when the read itself failed, which `decode` maps to
    /// `Lookup::Unavailable`.
    version: Option<i64>,
    /// `None` for an absent *or* dirty entry — both are misses, and a dirty
    /// entry's payload must never be served.
    payload: Option<Vec<u8>>,
}

impl Default for RawLookup {
    /// An unavailable entry — the safe reading of a result that never arrived.
    fn default() -> Self {
        Self::unavailable()
    }
}

impl RawLookup {
    fn unavailable() -> Self {
        Self {
            version: None,
            payload: None,
        }
    }

    fn from_fields(fields: (Option<i64>, Option<i64>, Option<Vec<u8>>)) -> Self {
        let (version, dirty, payload) = fields;
        // `dirty` is a nesting counter (see `BEGIN_SCRIPT_SRC`/`END_SCRIPT_SRC`):
        // any value above zero means at least one overlapping mutation on this
        // key is still in flight.
        let is_dirty = dirty.unwrap_or(0) > 0;
        Self {
            version: Some(version.unwrap_or(0)),
            payload: payload.filter(|_| !is_dirty),
        }
    }
}

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("cache operation timed out")]
    Timeout,
    #[error("cache pool error: {0}")]
    Pool(#[from] deadpool_redis::PoolError),
    #[error("cache redis error: {0}")]
    Redis(#[from] redis::RedisError),
}

#[derive(Debug)]
pub struct CacheClient {
    pool: Pool,
    op_timeout: Duration,
    ttl: CacheTtlConfig,
    begin_script: redis::Script,
    end_script: redis::Script,
    try_populate_script: redis::Script,
    discard_script: redis::Script,
}

impl CacheClient {
    /// Builds the client and its connection pool *without* contacting Redis.
    ///
    /// An error here is a configuration error — an unparseable URL, an invalid
    /// pool size — never a transient outage, so callers should treat it as
    /// fatal. Reachability is a separate, retryable concern: see
    /// [`Self::probe`] and `main::init_cache`.
    pub fn build(cfg: &CacheConfig) -> anyhow::Result<Self> {
        let pool_cfg = PoolConfig::from_url(&cfg.redis_url);
        let mut pool_builder = pool_cfg
            .builder()
            .map_err(|e| anyhow::anyhow!("invalid ATOM_CACHE_REDIS_URL: {e}"))?;
        pool_builder = pool_builder.max_size(cfg.pool_max_size as usize);
        let pool = pool_builder
            .runtime(Runtime::Tokio1)
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build cache pool: {e}"))?;

        Ok(Self {
            pool,
            op_timeout: Duration::from_millis(cfg.op_timeout_ms),
            ttl: cfg.ttl,
            begin_script: redis::Script::new(BEGIN_SCRIPT_SRC),
            end_script: redis::Script::new(END_SCRIPT_SRC),
            try_populate_script: redis::Script::new(TRY_POPULATE_SCRIPT_SRC),
            discard_script: redis::Script::new(DISCARD_SCRIPT_SRC),
        })
    }

    /// One-shot reachability check with a single `PING`, bounded by
    /// `connect_timeout_ms`.
    pub async fn probe(&self, connect_timeout_ms: u64) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_millis(connect_timeout_ms), self.ping())
            .await
            .map_err(|_| anyhow::anyhow!("cache connect timed out"))?
            .map_err(|e| anyhow::anyhow!("cache connect failed: {e}"))
    }

    /// [`build`](Self::build) plus a [`probe`](Self::probe) — fails unless
    /// Redis is reachable right now.
    pub async fn connect(cfg: &CacheConfig) -> anyhow::Result<Self> {
        let client = Self::build(cfg)?;
        client.probe(cfg.connect_timeout_ms).await?;
        Ok(client)
    }

    pub async fn ping(&self) -> Result<(), CacheError> {
        let mut conn = self.get_conn().await?;
        tokio::time::timeout(
            self.op_timeout,
            redis::cmd("PING").query_async::<String>(&mut conn),
        )
        .await
        .map_err(|_| CacheError::Timeout)?
        .map_err(CacheError::from)?;
        Ok(())
    }

    async fn get_conn(&self) -> Result<deadpool_redis::Connection, CacheError> {
        tokio::time::timeout(self.op_timeout, self.pool.get())
            .await
            .map_err(|_| CacheError::Timeout)?
            .map_err(CacheError::from)
    }

    /// Single-key read. Never errors outward — a failure of any kind becomes
    /// `Lookup::Unavailable`.
    pub async fn lookup<T: DeserializeOwned>(
        &self,
        category: CacheCategory,
        key: &str,
    ) -> Lookup<T> {
        let raw = self
            .lookup_many(std::slice::from_ref(&key))
            .await
            .pop()
            .unwrap_or_else(RawLookup::unavailable);
        self.decode(category, key, raw).await
    }

    /// Reads every key in one pipelined round trip on a single pooled
    /// connection, returning one [`RawLookup`] per key, in order.
    ///
    /// The auth hot path reads up to three keys before any request work
    /// starts; issued one at a time that is three pool acquisitions and three
    /// serial round trips, each bounded by `op_timeout`. Use this wherever the
    /// keys have no data dependency on each other, then [`Self::decode`] each
    /// result into its own type. Metrics are recorded by `decode`, not here,
    /// so one batch can span several categories.
    ///
    /// Always returns exactly `keys.len()` entries; a transport failure yields
    /// unavailable entries rather than a short vector.
    pub async fn lookup_many(&self, keys: &[&str]) -> Vec<RawLookup> {
        if keys.is_empty() {
            return Vec::new();
        }
        let unavailable = || keys.iter().map(|_| RawLookup::unavailable()).collect();

        let mut conn = match self.get_conn().await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::warn!(error = %err, "cache lookup unavailable");
                return unavailable();
            }
        };

        let mut pipe = redis::pipe();
        for key in keys {
            pipe.cmd("HMGET").arg(*key).arg("v").arg("dirty").arg("p");
        }
        let result = tokio::time::timeout(
            self.op_timeout,
            pipe.query_async::<Vec<(Option<i64>, Option<i64>, Option<Vec<u8>>)>>(&mut conn),
        )
        .await;

        match result {
            Ok(Ok(rows)) if rows.len() == keys.len() => {
                rows.into_iter().map(RawLookup::from_fields).collect()
            }
            Ok(Ok(rows)) => {
                tracing::warn!(
                    expected = keys.len(),
                    got = rows.len(),
                    "cache pipelined lookup returned an unexpected row count"
                );
                unavailable()
            }
            Ok(Err(err)) => {
                tracing::warn!(error = %err, "cache lookup failed");
                unavailable()
            }
            Err(_) => {
                tracing::warn!("cache lookup timed out");
                unavailable()
            }
        }
    }

    /// Parses one [`lookup_many`](Self::lookup_many) result into a typed
    /// [`Lookup`], recording the read in the per-category metrics. A corrupt
    /// payload is deleted and reported as a miss, exactly as in `lookup`.
    pub async fn decode<T: DeserializeOwned>(
        &self,
        category: CacheCategory,
        key: &str,
        raw: RawLookup,
    ) -> Lookup<T> {
        let Some(version) = raw.version else {
            metrics::record_cache_lookup(category.as_str(), "error");
            return Lookup::Unavailable;
        };
        let Some(payload) = raw.payload else {
            metrics::record_cache_lookup(category.as_str(), "miss");
            return Lookup::Miss { version };
        };
        match rmp_serde::from_slice::<T>(&payload) {
            Ok(value) => {
                metrics::record_cache_lookup(category.as_str(), "hit");
                Lookup::Hit(value)
            }
            Err(err) => {
                tracing::warn!(category = category.as_str(), error = %err, "cache payload corrupt; discarding");
                self.discard_payload(key, version).await;
                metrics::record_cache_lookup(category.as_str(), "miss");
                Lookup::Miss { version }
            }
        }
    }

    /// Clears a corrupt payload field, leaving the barrier (`v`/`dirty`)
    /// intact, and only while the entry is still at `observed_version` and not
    /// dirty. Best-effort: a failure just leaves the corrupt payload for the
    /// next reader to trip over and re-attempt.
    async fn discard_payload(&self, key: &str, observed_version: i64) {
        let Ok(mut conn) = self.get_conn().await else {
            return;
        };
        let _ = tokio::time::timeout(
            self.op_timeout,
            self.discard_script
                .key(key)
                .arg(observed_version)
                .invoke_async::<String>(&mut conn),
        )
        .await;
    }

    /// Best-effort conditional write following a cache-miss load. Discarded
    /// silently if the entry became dirty or its version moved on since the
    /// caller observed `expected_version` — see the module docs.
    pub async fn try_populate<T: Serialize>(
        &self,
        category: CacheCategory,
        key: &str,
        expected_version: i64,
        value: &T,
    ) {
        let Ok(payload) = rmp_serde::to_vec(value) else {
            tracing::warn!(
                category = category.as_str(),
                "cache payload serialize failed"
            );
            metrics::record_cache_populate(category.as_str(), "error");
            return;
        };
        let mut conn = match self.get_conn().await {
            Ok(conn) => conn,
            Err(_) => {
                metrics::record_cache_populate(category.as_str(), "error");
                return;
            }
        };
        let ttl = category.ttl(&self.ttl);
        let outcome = tokio::time::timeout(
            self.op_timeout,
            self.try_populate_script
                .key(key)
                .arg(expected_version)
                .arg(payload)
                .arg(ttl.as_millis() as i64)
                .invoke_async::<String>(&mut conn),
        )
        .await;
        // The script distinguishes `applied` from `stale` (barrier dirty, or
        // the version moved since the caller's `lookup`). Both are normal, but
        // only the split tells an operator whether a zero hit rate means "cold"
        // or "every write is being rejected" — so it is recorded, not dropped.
        match outcome {
            Ok(Ok(result)) => {
                let outcome = if result == "applied" {
                    "applied"
                } else {
                    "stale"
                };
                metrics::record_cache_populate(category.as_str(), outcome);
            }
            Ok(Err(err)) => {
                tracing::warn!(category = category.as_str(), error = %err, "cache populate failed");
                metrics::record_cache_populate(category.as_str(), "error");
            }
            Err(_) => {
                tracing::warn!(category = category.as_str(), "cache populate timed out");
                metrics::record_cache_populate(category.as_str(), "error");
            }
        }
    }

    /// Cache-aside read with a fallback loader: a hit returns immediately, a
    /// miss loads via `loader` and best-effort populates the cache, and an
    /// unavailable cache falls straight through to `loader`.
    pub async fn get_or_load<T, F, Fut>(
        &self,
        category: CacheCategory,
        key: &str,
        loader: F,
    ) -> Result<T, AppError>
    where
        T: Serialize + DeserializeOwned,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, AppError>>,
    {
        match self.lookup::<T>(category, key).await {
            Lookup::Hit(value) => Ok(value),
            Lookup::Miss { version } => {
                let value = loader().await?;
                self.try_populate(category, key, version, &value).await;
                Ok(value)
            }
            Lookup::Unavailable => loader().await,
        }
    }

    /// Increments `keys`' dirty counter before a security-sensitive Postgres
    /// mutation — safe to call while another mutation on the same key is
    /// already in flight, since the counter (not a flag) is what lets `end`
    /// tell "this mutation is done" apart from "every overlapping mutation on
    /// this key is done" (see module docs). **Fails the caller** if the
    /// barrier cannot be established (Redis unreachable/timeout) — see module
    /// docs and `src/cache/invalidate.rs`. A no-op that always succeeds when
    /// `keys` is empty.
    pub async fn begin(&self, category: CacheCategory, keys: &[String]) -> Result<(), AppError> {
        if keys.is_empty() {
            return Ok(());
        }
        let barrier_ttl = barrier_ttl(category.ttl(&self.ttl));
        // One connection for every chunk, not one per chunk: a bulk
        // invalidation re-acquiring from the pool per 500 keys competes with
        // the request path for connections while already holding Postgres row
        // locks.
        let mut conn = self.get_conn().await.map_err(|err| {
            tracing::warn!(category = category.as_str(), error = %err, "cache begin: connection unavailable");
            metrics::record_cache_invalidation(category.as_str(), "error");
            AppError::service_unavailable("cache unavailable; refusing security-sensitive mutation")
        })?;
        for chunk in keys.chunks(BULK_CHUNK_SIZE) {
            let mut invocation = self.begin_script.prepare_invoke();
            for key in chunk {
                invocation.key(key);
            }
            invocation.arg(barrier_ttl.as_millis() as i64);

            let outcome =
                tokio::time::timeout(self.op_timeout, invocation.invoke_async::<i64>(&mut conn))
                    .await;
            match outcome {
                Ok(Ok(_)) => {}
                Ok(Err(err)) => {
                    tracing::warn!(category = category.as_str(), error = %err, "cache begin failed");
                    metrics::record_cache_invalidation(category.as_str(), "error");
                    return Err(AppError::service_unavailable(
                        "cache unavailable; refusing security-sensitive mutation",
                    ));
                }
                Err(_) => {
                    tracing::warn!(category = category.as_str(), "cache begin timed out");
                    metrics::record_cache_invalidation(category.as_str(), "error");
                    return Err(AppError::service_unavailable(
                        "cache unavailable; refusing security-sensitive mutation",
                    ));
                }
            }
        }
        metrics::record_cache_invalidation(category.as_str(), "ok");
        Ok(())
    }

    /// Bumps the version and decrements the dirty counter on `keys` after the
    /// mutation (success or failure) — the entry only reads as clean once
    /// every overlapping `begin` on the key has been matched by an `end`.
    /// Always best-effort — never fails the caller. Left dirty entries
    /// self-heal once the barrier TTL set by `begin` expires. The version
    /// bump (not just the dirty decrement) is what stops a reader whose
    /// `lookup` landed during the dirty window from repopulating a stale
    /// value afterward — see the module docs.
    pub async fn end(&self, category: CacheCategory, keys: &[String]) {
        if keys.is_empty() {
            return;
        }
        let barrier_ttl = barrier_ttl(category.ttl(&self.ttl));
        // One connection for every chunk — see `begin`.
        let mut conn = match self.get_conn().await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::warn!(category = category.as_str(), error = %err, "cache end: connection unavailable");
                metrics::record_cache_invalidation(category.as_str(), "error");
                return;
            }
        };
        for chunk in keys.chunks(BULK_CHUNK_SIZE) {
            let mut invocation = self.end_script.prepare_invoke();
            for key in chunk {
                invocation.key(key);
            }
            invocation.arg(barrier_ttl.as_millis() as i64);
            let outcome =
                tokio::time::timeout(self.op_timeout, invocation.invoke_async::<i64>(&mut conn))
                    .await;
            match outcome {
                Ok(Ok(_)) => metrics::record_cache_invalidation(category.as_str(), "ok"),
                Ok(Err(err)) => {
                    tracing::warn!(category = category.as_str(), error = %err, "cache end failed");
                    metrics::record_cache_invalidation(category.as_str(), "error");
                }
                Err(_) => {
                    tracing::warn!(category = category.as_str(), "cache end timed out");
                    metrics::record_cache_invalidation(category.as_str(), "error");
                }
            }
        }
    }
}

/// The barrier key's own expiry: long enough to comfortably outlast any
/// realistic Postgres mutation + `end` call, so a lost `end` self-heals by
/// the whole entry expiring outright rather than staying dirty forever.
///
/// Saturating rather than `*`: `Duration`'s multiplication panics on
/// overflow, and this runs inside `begin`/`end` — on the mutation path, long
/// after a nonsensically large `ATOM_CACHE_TTL_*` would have been accepted at
/// startup. `cache_from_env` bounds those values, so this is belt-and-braces.
fn barrier_ttl(entry_ttl: Duration) -> Duration {
    entry_ttl.saturating_mul(5)
}

/// `get_or_load`, but tolerant of caching being disabled entirely — the
/// common entry point for read paths, so call sites don't need to branch on
/// `Option<&CacheClient>` themselves.
pub async fn cached_or_load<T, F, Fut>(
    cache: Option<&CacheClient>,
    category: CacheCategory,
    key: &str,
    loader: F,
) -> Result<T, AppError>
where
    T: Serialize + DeserializeOwned,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T, AppError>>,
{
    match cache {
        Some(cache) => cache.get_or_load(category, key, loader).await,
        None => loader().await,
    }
}

/// Redis-gated unit tests for the cache mechanism itself — key formatting,
/// serialization round trips, and the barrier primitives in isolation from
/// any AuthN/AuthZ call site. Requires `ATOM_TEST_REDIS_URL`; run with
/// `ATOM_TEST_REDIS_URL=redis://... cargo test -- --ignored`.
#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct Payload {
        value: String,
    }

    async fn test_client() -> CacheClient {
        let url = std::env::var("ATOM_TEST_REDIS_URL")
            .expect("ATOM_TEST_REDIS_URL must be set for cache-gated tests");
        let cfg = CacheConfig {
            enabled: true,
            redis_url: url,
            ..CacheConfig::default()
        };
        CacheClient::connect(&cfg)
            .await
            .expect("connect to test redis")
    }

    fn unique_key(label: &str) -> String {
        format!("atom:v1:test:{label}:{}", Uuid::new_v4())
    }

    /// Drives `main.rs`'s fail-fast-vs-degrade startup branching: `connect`
    /// must return `Err` (not hang, not panic) against an unreachable Redis,
    /// bounded by `connect_timeout_ms`. No live Redis needed — this
    /// deliberately never reaches one — so it runs in default `cargo test`.
    #[tokio::test]
    async fn connect_fails_against_an_unreachable_redis() {
        let cfg = CacheConfig {
            enabled: true,
            redis_url: "redis://127.0.0.1:1/0".into(),
            connect_timeout_ms: 200,
            op_timeout_ms: 50,
            ..CacheConfig::default()
        };
        let result = CacheClient::connect(&cfg).await;
        assert!(
            result.is_err(),
            "connect must fail against an unreachable redis, not hang or succeed"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn ping_succeeds_against_reachable_redis() {
        let client = test_client().await;
        client.ping().await.expect("ping");
    }

    #[tokio::test]
    #[ignore]
    async fn lookup_on_absent_key_is_a_clean_miss_at_version_zero() {
        let client = test_client().await;
        let key = unique_key("lookup-miss");
        match client.lookup::<Payload>(CacheCategory::Grants, &key).await {
            Lookup::Miss { version } => assert_eq!(version, 0),
            other => panic!("expected a clean miss, got {other:?}"),
        }
    }

    #[tokio::test]
    #[ignore]
    async fn try_populate_then_lookup_round_trips_the_payload() {
        let client = test_client().await;
        let key = unique_key("roundtrip");
        let value = Payload {
            value: "hello".into(),
        };

        let version = match client.lookup::<Payload>(CacheCategory::Grants, &key).await {
            Lookup::Miss { version } => version,
            other => panic!("expected miss before populate, got {other:?}"),
        };
        client
            .try_populate(CacheCategory::Grants, &key, version, &value)
            .await;

        match client.lookup::<Payload>(CacheCategory::Grants, &key).await {
            Lookup::Hit(got) => assert_eq!(got, value),
            other => panic!("expected a hit after populate, got {other:?}"),
        }
    }

    #[tokio::test]
    #[ignore]
    async fn corrupt_payload_is_discarded_without_destroying_the_barrier() {
        let client = test_client().await;
        let key = unique_key("corrupt");

        // Write a payload that isn't a validly-encoded `Payload` directly
        // into the hash, bypassing `try_populate`, to simulate corruption.
        let mut conn = client.get_conn().await.expect("conn");
        let _: () = redis::cmd("HSET")
            .arg(&key)
            .arg("v")
            .arg(1)
            .arg("p")
            .arg("not a valid payload")
            .query_async(&mut conn)
            .await
            .expect("seed corrupt payload");

        match client.lookup::<Payload>(CacheCategory::Grants, &key).await {
            Lookup::Miss { .. } => {}
            other => panic!("expected corrupt payload to be a miss, got {other:?}"),
        }

        // The corrupt payload must be gone so the next lookup doesn't repeat
        // the same deserialize failure — but *only* the payload. Deleting the
        // whole hash would take `v`/`dirty` with it, and a concurrent
        // mutation's barrier along with them.
        let (version, payload): (Option<i64>, Option<Vec<u8>>) = redis::cmd("HMGET")
            .arg(&key)
            .arg("v")
            .arg("p")
            .query_async(&mut conn)
            .await
            .expect("read back barrier fields");
        assert!(
            payload.is_none(),
            "corrupt payload should have been cleared"
        );
        assert_eq!(
            version,
            Some(1),
            "the version must survive: it is what a concurrent mutation's barrier rests on"
        );
    }

    /// The reason [`DISCARD_SCRIPT_SRC`] is version-guarded: a corrupt-payload
    /// cleanup racing a mutation must not clear the barrier that mutation just
    /// established, or a reader could repopulate pre-commit state over it.
    #[tokio::test]
    #[ignore]
    async fn corrupt_payload_cleanup_leaves_a_concurrent_barrier_intact() {
        let client = test_client().await;
        let key = unique_key("corrupt-vs-barrier");
        let keys = vec![key.clone()];

        let mut conn = client.get_conn().await.expect("conn");
        let _: () = redis::cmd("HSET")
            .arg(&key)
            .arg("v")
            .arg(1)
            .arg("p")
            .arg("not a valid payload")
            .query_async(&mut conn)
            .await
            .expect("seed corrupt payload");

        // A mutation opens its barrier *after* the reader observed version 1.
        client
            .begin(CacheCategory::Grants, &keys)
            .await
            .expect("begin");

        // The reader's cleanup now fires against its stale observed version.
        client.discard_payload(&key, 1).await;

        let dirty: Option<String> = redis::cmd("HGET")
            .arg(&key)
            .arg("dirty")
            .query_async(&mut conn)
            .await
            .expect("read dirty");
        assert_eq!(
            dirty.as_deref(),
            Some("1"),
            "the in-flight mutation's barrier must survive a late corrupt-payload cleanup"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn try_populate_rejects_a_stale_version() {
        let client = test_client().await;
        let key = unique_key("stale-version");
        let keys = vec![key.clone()];

        // A concurrent mutation bumps the version between the reader's
        // initial lookup and its populate attempt.
        client
            .begin(CacheCategory::Grants, &keys)
            .await
            .expect("begin");
        client.end(CacheCategory::Grants, &keys).await;

        // The reader observed version 0 (before the mutation) and now tries
        // to populate with that stale value.
        let stale_value = Payload {
            value: "stale".into(),
        };
        client
            .try_populate(CacheCategory::Grants, &key, 0, &stale_value)
            .await;

        // Must still be a miss — the stale write was discarded.
        match client.lookup::<Payload>(CacheCategory::Grants, &key).await {
            Lookup::Miss { .. } => {}
            Lookup::Hit(got) => panic!("stale write should have been rejected, got {got:?}"),
            other => panic!("unexpected lookup outcome: {other:?}"),
        }
    }

    #[tokio::test]
    #[ignore]
    async fn dirty_entry_is_never_served_as_a_hit() {
        let client = test_client().await;
        let key = unique_key("dirty");
        let keys = vec![key.clone()];

        let version = match client.lookup::<Payload>(CacheCategory::Grants, &key).await {
            Lookup::Miss { version } => version,
            other => panic!("expected miss, got {other:?}"),
        };
        let value = Payload {
            value: "before-mutation".into(),
        };
        client
            .try_populate(CacheCategory::Grants, &key, version, &value)
            .await;
        // Confirm it's actually cached before dirtying it.
        assert!(matches!(
            client.lookup::<Payload>(CacheCategory::Grants, &key).await,
            Lookup::Hit(_)
        ));

        // `begin` marks it dirty and clears the payload without an `end`.
        client
            .begin(CacheCategory::Grants, &keys)
            .await
            .expect("begin");

        match client.lookup::<Payload>(CacheCategory::Grants, &key).await {
            Lookup::Miss { .. } => {}
            Lookup::Hit(got) => panic!("dirty entry served as a hit: {got:?}"),
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[tokio::test]
    #[ignore]
    async fn bulk_begin_and_end_cover_every_key_in_one_round_trip() {
        let client = test_client().await;
        let keys: Vec<String> = (0..5).map(|i| unique_key(&format!("bulk-{i}"))).collect();

        client
            .begin(CacheCategory::Grants, &keys)
            .await
            .expect("begin");
        for key in &keys {
            let (_, dirty, _): (Option<i64>, Option<String>, Option<Vec<u8>>) = redis::cmd("HMGET")
                .arg(key)
                .arg("v")
                .arg("dirty")
                .arg("p")
                .query_async(&mut client.get_conn().await.expect("conn"))
                .await
                .expect("hmget");
            assert_eq!(
                dirty.as_deref(),
                Some("1"),
                "key {key} should be dirty after begin"
            );
        }

        client.end(CacheCategory::Grants, &keys).await;
        for key in &keys {
            let (_, dirty, _): (Option<i64>, Option<String>, Option<Vec<u8>>) = redis::cmd("HMGET")
                .arg(key)
                .arg("v")
                .arg("dirty")
                .arg("p")
                .query_async(&mut client.get_conn().await.expect("conn"))
                .await
                .expect("hmget");
            assert_eq!(
                dirty.as_deref(),
                Some("0"),
                "key {key} should be clean after end"
            );
        }
    }

    #[tokio::test]
    #[ignore]
    async fn get_or_load_hits_cache_on_second_call_without_invoking_loader() {
        let client = test_client().await;
        let key = unique_key("get-or-load");
        let calls = std::sync::atomic::AtomicUsize::new(0);

        let first: Payload = client
            .get_or_load(CacheCategory::Grants, &key, || {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async {
                    Ok(Payload {
                        value: "loaded".into(),
                    })
                }
            })
            .await
            .expect("first load");
        assert_eq!(first.value, "loaded");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

        let second: Payload = client
            .get_or_load(CacheCategory::Grants, &key, || {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async {
                    Ok(Payload {
                        value: "should-not-be-called".into(),
                    })
                }
            })
            .await
            .expect("second load");
        assert_eq!(
            second.value, "loaded",
            "second call must be served from cache"
        );
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "loader must not run again on a cache hit"
        );
    }

    /// The test that actually validates the consistency model, not just its
    /// individual primitives: a reader that captured a version *before* a
    /// concurrent mutation must not be able to repopulate the cache with its
    /// now-stale result *after* the mutation commits and clears the barrier.
    /// This is the exact race described in `src/cache/mod.rs`'s module docs.
    #[tokio::test]
    #[ignore]
    async fn stale_reader_cannot_repopulate_after_a_concurrent_mutation_completes() {
        let client = test_client().await;
        let key = unique_key("race");
        let keys = vec![key.clone()];

        // Reader observes the version before any mutation has happened.
        let observed_version = match client.lookup::<Payload>(CacheCategory::Grants, &key).await {
            Lookup::Miss { version } => version,
            other => panic!("expected initial miss, got {other:?}"),
        };

        // A concurrent mutation runs to completion while the reader's
        // (simulated) Postgres load is still in flight: begin bumps the
        // version and marks dirty, then end clears dirty after the mutation
        // commits.
        client
            .begin(CacheCategory::Grants, &keys)
            .await
            .expect("begin");
        client.end(CacheCategory::Grants, &keys).await;

        // The reader's stale load now finishes and attempts to populate with
        // the version it observed *before* the mutation.
        let stale_value = Payload {
            value: "STALE — must never be visible".into(),
        };
        client
            .try_populate(CacheCategory::Grants, &key, observed_version, &stale_value)
            .await;

        // The cache must not have been poisoned with the stale value — the
        // next reader must see a clean miss (correctness bound: even though
        // the mutation revealed no new payload of its own, the stale write
        // must never have applied), never the disallowed value.
        match client.lookup::<Payload>(CacheCategory::Grants, &key).await {
            Lookup::Hit(got) => assert_ne!(
                got, stale_value,
                "stale reader was able to poison the cache after a concurrent mutation"
            ),
            Lookup::Miss { .. } => {}
            Lookup::Unavailable => panic!("cache should be reachable in this test"),
        }
    }

    /// Regression test for a review finding: the test above only covers a
    /// reader whose `lookup` landed *before* `begin` ran (a version `begin`
    /// then bumps past). It does not cover a reader whose `lookup` lands
    /// *during* the dirty window itself (after `begin`, before `end`) — that
    /// reader observes the *post-`begin`* version, and if `end` only cleared
    /// `dirty` without bumping the version again, that same version would
    /// still match after `end`, so `try_populate` would wrongly accept a
    /// value the reader may have loaded from Postgres before the mutation's
    /// own write committed. This is the actual scenario the review
    /// described: "a reader that starts during a mutation" — not one that
    /// started before it.
    #[tokio::test]
    #[ignore]
    async fn stale_reader_cannot_repopulate_during_the_mutations_dirty_window() {
        let client = test_client().await;
        let key = unique_key("dirty-window-race");
        let keys = vec![key.clone()];

        // The mutation begins — the key is now dirty.
        client
            .begin(CacheCategory::Grants, &keys)
            .await
            .expect("begin");

        // A reader's `lookup` lands *while the mutation is still in
        // flight* — this is the case the previous test didn't cover.
        let dirty_window_version = match client.lookup::<Payload>(CacheCategory::Grants, &key).await
        {
            Lookup::Miss { version } => version,
            other => panic!("expected a miss while dirty, got {other:?}"),
        };

        // The mutation finishes — `end` clears dirty (and, with the fix,
        // bumps the version again).
        client.end(CacheCategory::Grants, &keys).await;

        // The reader's (simulated) Postgres load — possibly stale, since it
        // may have run before the mutation's own write committed — finishes
        // and attempts to populate using the version it observed *during*
        // the dirty window.
        let stale_value = Payload {
            value: "STALE — read during the dirty window, must never be visible".into(),
        };
        client
            .try_populate(
                CacheCategory::Grants,
                &key,
                dirty_window_version,
                &stale_value,
            )
            .await;

        match client.lookup::<Payload>(CacheCategory::Grants, &key).await {
            Lookup::Hit(got) => assert_ne!(
                got, stale_value,
                "a reader that started during the mutation's dirty window was able to poison \
                 the cache once the mutation completed — this is exactly the P1 the barrier \
                 model exists to prevent, and means `end` isn't invalidating a dirty-window \
                 read's captured version"
            ),
            Lookup::Miss { .. } => {}
            Lookup::Unavailable => panic!("cache should be reachable in this test"),
        }
    }

    /// Regression test for a review finding: the two tests above only cover a
    /// single mutation on a key. When *two* security-sensitive mutations
    /// overlap on the same key — e.g. two role changes affecting the same
    /// subject's `grants` entry — a `dirty` field that is a flag rather than
    /// a nesting counter is unconditionally cleared by whichever mutation's
    /// `end` runs first, even though the second mutation is still in flight.
    /// A reader landing in that gap sees a clean, non-dirty entry and can
    /// `try_populate` a payload loaded before the second mutation's own
    /// commit — wrong the instant that commit lands, and never corrected if
    /// the second mutation's own `end` is ever delayed or lost.
    #[tokio::test]
    #[ignore]
    async fn dirty_barrier_stays_up_until_every_overlapping_mutation_ends() {
        let client = test_client().await;
        let key = unique_key("overlapping-mutations");
        let keys = vec![key.clone()];

        // Two mutations both touch this key concurrently — M1 begins first,
        // then M2 begins while M1 is still in flight.
        client
            .begin(CacheCategory::Grants, &keys)
            .await
            .expect("M1 begin");
        client
            .begin(CacheCategory::Grants, &keys)
            .await
            .expect("M2 begin");

        // M1 finishes first. With a flag (not a counter), this would clear
        // `dirty` outright even though M2 hasn't committed yet.
        client.end(CacheCategory::Grants, &keys).await;

        // A reader lands in the gap between M1's `end` and M2's commit. The
        // barrier must still read as dirty — M2 is still in flight — so this
        // must be a miss, not a hit, and the version it observes here must
        // never successfully populate the cache.
        let gap_version = match client.lookup::<Payload>(CacheCategory::Grants, &key).await {
            Lookup::Miss { version } => version,
            other => panic!(
                "expected a miss while M2 is still in flight (M1's end must not have cleared \
                 the barrier), got {other:?}"
            ),
        };
        let stale_value = Payload {
            value: "STALE — read while a second overlapping mutation was still in flight".into(),
        };
        client
            .try_populate(CacheCategory::Grants, &key, gap_version, &stale_value)
            .await;
        match client.lookup::<Payload>(CacheCategory::Grants, &key).await {
            Lookup::Hit(got) => assert_ne!(
                got, stale_value,
                "a reader landing between M1's `end` and M2's commit was able to poison the \
                 cache — this means `dirty` is being treated as a flag instead of a nesting \
                 counter, so the first of two overlapping mutations to finish clears the \
                 barrier the second one still needs"
            ),
            Lookup::Miss { .. } => {}
            Lookup::Unavailable => panic!("cache should be reachable in this test"),
        }

        // M2 finishes. Only now should the barrier be fully clear.
        client.end(CacheCategory::Grants, &keys).await;
        let clean_version = match client.lookup::<Payload>(CacheCategory::Grants, &key).await {
            Lookup::Miss { version } => version,
            other => {
                panic!("expected a clean miss once every overlapping mutation ended, got {other:?}")
            }
        };
        let fresh_value = Payload {
            value: "fresh, post-M2 value".into(),
        };
        client
            .try_populate(CacheCategory::Grants, &key, clean_version, &fresh_value)
            .await;
        assert!(
            matches!(
                client.lookup::<Payload>(CacheCategory::Grants, &key).await,
                Lookup::Hit(got) if got == fresh_value
            ),
            "once every overlapping mutation has called `end`, the barrier must clear and a \
             fresh populate must succeed"
        );
    }
}
