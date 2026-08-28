//! Redis-backed cache for AuthN/AuthZ decision *inputs* (never decisions
//! themselves — see `src/authz/engine.rs` and `src/auth.rs` for what actually
//! decides allow/deny). Postgres remains the sole source of truth.
//!
//! # Consistency model
//!
//! Every cached entry is a Redis hash with `v` (an integer
//! version, bumped on every mutation that can affect the entry), `dirty` (an
//! integer *nesting counter* — above zero while one or more mutations are in
//! flight, zero or absent otherwise), and `p` (the serialized payload,
//! present only when the entry holds a valid value). Each in-flight mutation
//! also owns a unique `lease:<uuid>` field. The physical Redis key is the
//! deployment namespace followed by the stable logical `atom:v1:` key.
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
//!   creates a persistent exact-token barrier. A dropped or crashed mutation
//!   intentionally leaves that key permanently dirty, forcing safe Postgres
//!   fallback until operator repair.
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
//! the instant the second mutation commits. Exact persistent tokens keep the
//! entry dirty if either mutation's own `end` is delayed or lost.
//! Making `dirty` a nesting counter — incremented by every `begin`,
//! decremented by every `end` — means the barrier only reads as clean once
//! *every* overlapping mutation on the key has called `end`, so a reader can
//! never land in the gap between one mutation's `end` and another's commit.
//!
//! Reads never depend on Redis being reachable: any error (timeout,
//! connection failure, corrupt payload) is treated as a miss and falls
//! through to the caller's Postgres loader. `begin` is the one exception —
//! while caching is in prepare or enabled mode, a `begin` failure refuses the mutation rather
//! than committing a change the cache cannot be told about (see
//! `src/cache/invalidate.rs`).
//!
//! Persistent dirty tokens require one dedicated, non-clustered, non-replicated
//! Redis primary with persistence disabled and `maxmemory-policy=noeviction`.
//! The client verifies that topology at startup/readiness. Each process also
//! remembers one persistent random namespace-incarnation marker. Every lookup,
//! populate, begin, end, and corrupt-payload discard verifies that marker
//! atomically; missing/mismatched state permanently latches the process unsafe
//! until restart. Observing an unsafe Redis configuration, or an END whose exact
//! lease disappeared, replaces the marker with a reserved poison value so every
//! process fails closed. A new/empty namespace is initialized only with the
//! explicit one-startup `ATOM_CACHE_INITIALIZE_NAMESPACE=true` switch. Redis
//! restart/state loss, poison recovery, or abandoned-token repair requires
//! traffic stopped and every Atom process and in-flight request terminated or
//! fully drained before that switch is used.

pub mod entries;
pub mod invalidate;
pub mod keys;

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, OnceLock,
    },
    time::Duration,
};

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

const POISONED_INCARNATION_PREFIX: &str = "poisoned:";

// The namespace incarnation is deliberately initialized only through the
// explicit one-startup switch. A process remembers the marker it first saw;
// every data-plane script compares that exact value before reading or writing
// anything. Redis replacement/FLUSHDB therefore rejects an old in-flight
// reader instead of letting it populate the fresh namespace.
const INIT_OR_VERIFY_INCARNATION_SCRIPT_SRC: &str = r#"
local function marker_valid(value)
  if value == false or #value ~= 36 then return false end
  if string.sub(value, 9, 9) ~= '-' or string.sub(value, 14, 14) ~= '-' or string.sub(value, 19, 19) ~= '-' or string.sub(value, 24, 24) ~= '-' then return false end
  local compact = string.gsub(value, '-', '')
  return #compact == 32 and string.match(compact, '^[0-9a-f]+$') ~= nil
end

local function epoch_valid(value)
  if value == false then return false end
  if value == '0' then return true end
  if string.match(value, '^[1-9][0-9]*$') == nil then return false end
  if #value < 19 then return true end
  if #value > 19 then return false end
  return value <= '9223372036854775807'
end

local marker = redis.call('GET', KEYS[1])
local epoch = redis.call('GET', KEYS[2])
local expected = ARGV[1]
local marker_ok = marker_valid(marker) and redis.call('PTTL', KEYS[1]) == -1
local epoch_ok = epoch_valid(epoch) and redis.call('PTTL', KEYS[2]) == -1

if expected ~= '' then
  if marker == expected and marker_ok and epoch_ok then return {1, marker} end
  return {0, ''}
end

if marker ~= false then
  if not marker_ok or not epoch_ok then return {-1, ''} end
  return {1, marker}
end

-- Initialization is permitted only for a genuinely empty namespace. A
-- missing marker with a surviving epoch means the generation was damaged or
-- globally fenced through the poison fallback. Reusing that epoch would let
-- an initializer erase evidence that other Atom processes may still hold
-- reads or mutations from the old generation.
if epoch ~= false then return {-1, ''} end
if ARGV[2] ~= '1' then return {-2, ''} end

local candidate = ARGV[3]
redis.call('SET', KEYS[1], candidate)
redis.call('SET', KEYS[2], 0)
redis.call('PERSIST', KEYS[1])
redis.call('PERSIST', KEYS[2])
return {2, candidate}
"#;

const LOOKUP_SCRIPT_SRC: &str = r#"
local function epoch_valid(value)
  if value == false then return false end
  if value == '0' then return true end
  if string.match(value, '^[1-9][0-9]*$') == nil then return false end
  if #value < 19 then return true end
  if #value > 19 then return false end
  return value <= '9223372036854775807'
end

local marker = redis.call('GET', KEYS[1])
local epoch = redis.call('GET', KEYS[2])
if marker ~= ARGV[1] or redis.call('PTTL', KEYS[1]) ~= -1 or not epoch_valid(epoch) or redis.call('PTTL', KEYS[2]) ~= -1 then
  return {'incarnation_mismatch', 0, {}}
end

local rows = {}
for i = 3, #KEYS do
  local fields = redis.call('HMGET', KEYS[i], 'v', 'dirty', 'p', 'i')
  if fields[4] ~= ARGV[1] then
    rows[#rows + 1] = {false, false, false}
  else
    rows[#rows + 1] = {fields[1], fields[2], fields[3]}
  end
end
return {'ok', epoch, rows}
"#;

const BEGIN_SCRIPT_SRC: &str = r#"
local function epoch_valid(value)
  if value == false then return false end
  if value == '0' then return true end
  if string.match(value, '^[1-9][0-9]*$') == nil then return false end
  if #value < 19 then return true end
  if #value > 19 then return false end
  return value <= '9223372036854775807'
end

local expected = ARGV[1]
local lease = ARGV[2]
local epoch = redis.call('GET', KEYS[2])
if redis.call('GET', KEYS[1]) ~= expected or redis.call('PTTL', KEYS[1]) ~= -1 or not epoch_valid(epoch) or redis.call('PTTL', KEYS[2]) ~= -1 then
  return 0
end
redis.call('INCR', KEYS[2])
redis.call('PERSIST', KEYS[2])
for i = 3, #KEYS do
  local key = KEYS[i]
  if redis.call('HGET', key, 'i') ~= expected then
    redis.call('DEL', key)
    redis.call('HSET', key, 'i', expected)
  end
  if redis.call('HSETNX', key, lease, 1) == 1 then
    redis.call('HINCRBY', key, 'v', 1)
    redis.call('HINCRBY', key, 'dirty', 1)
  end
  redis.call('HDEL', key, 'p')
  redis.call('PERSIST', key)
end
return 1
"#;

// The namespace-wide persistent epoch prevents ABA when a clean per-entry hash
// expires: every begin/end moves the epoch, so an old reader can never populate
// using a pre-mutation epoch even if its local version returns to zero.
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
local function epoch_valid(value)
  if value == false then return false end
  if value == '0' then return true end
  if string.match(value, '^[1-9][0-9]*$') == nil then return false end
  if #value < 19 then return true end
  if #value > 19 then return false end
  return value <= '9223372036854775807'
end

local expected = ARGV[1]
local ttl_ms = ARGV[2]
local lease = ARGV[3]
local poison = ARGV[4]
local epoch = redis.call('GET', KEYS[2])
if redis.call('GET', KEYS[1]) ~= expected or redis.call('PTTL', KEYS[1]) ~= -1 or not epoch_valid(epoch) or redis.call('PTTL', KEYS[2]) ~= -1 then
  return 0
end
for i = 3, #KEYS do
  if redis.call('HGET', KEYS[i], 'i') ~= expected or redis.call('HEXISTS', KEYS[i], lease) == 0 then
    redis.call('SET', KEYS[1], poison)
    return -1
  end
end
redis.call('INCR', KEYS[2])
redis.call('PERSIST', KEYS[2])
for i = 3, #KEYS do
  local key = KEYS[i]
  redis.call('HINCRBY', key, 'v', 1)
  if redis.call('HDEL', key, lease) == 1 then
    local remaining = redis.call('HINCRBY', key, 'dirty', -1)
    if remaining < 0 then
      redis.call('HSET', key, 'dirty', 0)
    end
  end
  redis.call('HDEL', key, 'p')
  local dirty = tonumber(redis.call('HGET', key, 'dirty')) or 0
  if dirty > 0 then redis.call('PERSIST', key)
  else redis.call('PEXPIRE', key, ttl_ms) end
end
return 1
"#;

// Cleanup after an ambiguous/partial BEGIN cannot use strict END: some keys
// may never have received this lease. It consumes only exact leases that are
// present in the still-matching incarnation and otherwise does nothing.
const CLEANUP_SCRIPT_SRC: &str = r#"
local function epoch_valid(value)
  if value == false then return false end
  if value == '0' then return true end
  if string.match(value, '^[1-9][0-9]*$') == nil then return false end
  if #value < 19 then return true end
  if #value > 19 then return false end
  return value <= '9223372036854775807'
end

local expected = ARGV[1]
local ttl_ms = ARGV[2]
local lease = ARGV[3]
local epoch = redis.call('GET', KEYS[2])
if redis.call('GET', KEYS[1]) ~= expected or redis.call('PTTL', KEYS[1]) ~= -1 or not epoch_valid(epoch) or redis.call('PTTL', KEYS[2]) ~= -1 then
  return 0
end
local cleaned = 0
for i = 3, #KEYS do
  local key = KEYS[i]
  if redis.call('HGET', key, 'i') == expected and redis.call('HDEL', key, lease) == 1 then
    redis.call('HINCRBY', key, 'v', 1)
    local remaining = redis.call('HINCRBY', key, 'dirty', -1)
    if remaining < 0 then redis.call('HSET', key, 'dirty', 0) end
    redis.call('HDEL', key, 'p')
    if remaining > 0 then redis.call('PERSIST', key)
    else redis.call('PEXPIRE', key, ttl_ms) end
    cleaned = cleaned + 1
  end
end
if cleaned > 0 then
  redis.call('INCR', KEYS[2])
  redis.call('PERSIST', KEYS[2])
end
return 1
"#;

const TRY_POPULATE_SCRIPT_SRC: &str = r#"
local function epoch_valid(value)
  if value == false then return false end
  if value == '0' then return true end
  if string.match(value, '^[1-9][0-9]*$') == nil then return false end
  if #value < 19 then return true end
  if #value > 19 then return false end
  return value <= '9223372036854775807'
end

local expected = ARGV[1]
local epoch = redis.call('GET', KEYS[3])
if redis.call('GET', KEYS[2]) ~= expected or redis.call('PTTL', KEYS[2]) ~= -1 or not epoch_valid(epoch) or redis.call('PTTL', KEYS[3]) ~= -1 then
  return 'incarnation_mismatch'
end
local entry_incarnation = redis.call('HGET', KEYS[1], 'i')
local v = false
local dirty = 0
if entry_incarnation == expected then
  v = redis.call('HGET', KEYS[1], 'v')
  dirty = tonumber(redis.call('HGET', KEYS[1], 'dirty')) or 0
end
if v == false then v = '0' end
if dirty > 0 or v ~= ARGV[2] or epoch ~= ARGV[3] then
  return 'stale'
end
if entry_incarnation ~= expected then redis.call('DEL', KEYS[1]) end
redis.call('HSET', KEYS[1], 'i', expected, 'p', ARGV[4])
redis.call('PEXPIRE', KEYS[1], ARGV[5])
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
local function epoch_valid(value)
  if value == false then return false end
  if value == '0' then return true end
  if string.match(value, '^[1-9][0-9]*$') == nil then return false end
  if #value < 19 then return true end
  if #value > 19 then return false end
  return value <= '9223372036854775807'
end

local expected = ARGV[1]
local epoch = redis.call('GET', KEYS[3])
if redis.call('GET', KEYS[2]) ~= expected or redis.call('PTTL', KEYS[2]) ~= -1 or not epoch_valid(epoch) or redis.call('PTTL', KEYS[3]) ~= -1 then
  return 'incarnation_mismatch'
end
if redis.call('HGET', KEYS[1], 'i') ~= expected then return 'skipped' end
local v = redis.call('HGET', KEYS[1], 'v')
if v == false then v = '0' end
local dirty = tonumber(redis.call('HGET', KEYS[1], 'dirty')) or 0
if dirty > 0 or v ~= ARGV[2] then
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
    Miss { version: i64, epoch: i64 },
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
    epoch: i64,
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
            epoch: 0,
        }
    }

    fn from_fields(fields: (Option<i64>, Option<i64>, Option<Vec<u8>>), epoch: i64) -> Self {
        let (version, dirty, payload) = fields;
        // `dirty` is a nesting counter (see `BEGIN_SCRIPT_SRC`/`END_SCRIPT_SRC`):
        // any value above zero means at least one overlapping mutation on this
        // key is still in flight.
        let is_dirty = dirty.unwrap_or(0) > 0;
        Self {
            version: Some(version.unwrap_or(0)),
            payload: payload.filter(|_| !is_dirty),
            epoch,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RedisSafetySnapshot {
    maxmemory_policy: String,
    save: Option<String>,
    appendonly: Option<String>,
    cluster_enabled: Option<String>,
    role: Option<String>,
    connected_replicas: Option<u64>,
}

impl RedisSafetySnapshot {
    fn validate_topology(&self) -> Result<(), CacheError> {
        let mut violations = Vec::new();
        if self.save.as_deref() != Some("") {
            violations.push("RDB snapshots must be disabled (`save \"\"`)".to_string());
        }
        if self.appendonly.as_deref() != Some("no") {
            violations.push("AOF must be disabled (`appendonly no`)".to_string());
        }
        if self.cluster_enabled.as_deref() != Some("no") {
            violations.push("Redis Cluster must be disabled".to_string());
        }
        if self.role.as_deref() != Some("master") {
            violations.push("the endpoint must be the Redis primary".to_string());
        }
        if self.connected_replicas != Some(0) {
            violations.push("Redis replicas and automatic failover are unsupported".to_string());
        }
        if violations.is_empty() {
            Ok(())
        } else {
            Err(CacheError::Topology(violations.join("; ")))
        }
    }
}

fn redis_info_value<'a>(info: &'a str, key: &str) -> Option<&'a str> {
    info.lines().find_map(|line| {
        let (field, value) = line.trim_end_matches('\r').split_once(':')?;
        (field == key).then_some(value)
    })
}

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("cache requires Redis maxmemory-policy=noeviction, got {0}")]
    EvictionPolicy(String),
    #[error("cache requires a dedicated ephemeral standalone Redis primary: {0}")]
    Topology(String),
    #[error("cache namespace has not been initialized; fully drain the Atom fleet, then start one process with ATOM_CACHE_INITIALIZE_NAMESPACE=true")]
    NamespaceUninitialized,
    #[error("cache namespace incarnation or mutation epoch is missing, malformed, or expiring; full fleet drain and namespace reinitialization are required")]
    NamespaceInvalid,
    #[error("cache namespace incarnation changed after startup; this process is permanently unsafe until restart")]
    IncarnationChanged,
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
    namespace: String,
    reads_enabled: bool,
    initialize_namespace: bool,
    incarnation: Arc<OnceLock<String>>,
    incarnation_unsafe: Arc<AtomicBool>,
    init_or_verify_incarnation_script: redis::Script,
    lookup_script: redis::Script,
    begin_script: redis::Script,
    end_script: redis::Script,
    cleanup_script: redis::Script,
    try_populate_script: redis::Script,
    discard_script: redis::Script,
    eviction_safe: Arc<AtomicBool>,
}

#[derive(Debug)]
pub struct CacheLease {
    category: CacheCategory,
    logical_keys: Vec<String>,
    redis_keys: Vec<String>,
    lease_field: String,
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
            namespace: cfg.namespace.clone(),
            reads_enabled: cfg.mode.reads_enabled(),
            initialize_namespace: cfg.initialize_namespace,
            incarnation: Arc::new(OnceLock::new()),
            incarnation_unsafe: Arc::new(AtomicBool::new(false)),
            init_or_verify_incarnation_script: redis::Script::new(
                INIT_OR_VERIFY_INCARNATION_SCRIPT_SRC,
            ),
            lookup_script: redis::Script::new(LOOKUP_SCRIPT_SRC),
            begin_script: redis::Script::new(BEGIN_SCRIPT_SRC),
            end_script: redis::Script::new(END_SCRIPT_SRC),
            cleanup_script: redis::Script::new(CLEANUP_SCRIPT_SRC),
            try_populate_script: redis::Script::new(TRY_POPULATE_SCRIPT_SRC),
            discard_script: redis::Script::new(DISCARD_SCRIPT_SRC),
            eviction_safe: Arc::new(AtomicBool::new(false)),
        })
    }

    /// The physical Redis key for a logical v1 cache key. Public for
    /// diagnostics and black-box integration tests; application code should
    /// continue to pass logical keys to the cache APIs.
    pub fn redis_key(&self, logical_key: &str) -> String {
        format!("{}:{logical_key}", self.namespace)
    }

    pub fn epoch_key(&self) -> String {
        format!("{}:atom:v1:mutation_epoch", self.namespace)
    }

    pub fn incarnation_key(&self) -> String {
        format!("{}:atom:v1:incarnation", self.namespace)
    }

    fn expected_incarnation(&self) -> Result<&str, CacheError> {
        if self.incarnation_unsafe.load(Ordering::Acquire) {
            return Err(CacheError::IncarnationChanged);
        }
        self.incarnation
            .get()
            .map(String::as_str)
            .ok_or(CacheError::NamespaceUninitialized)
    }

    fn latch_incarnation_unsafe(&self, operation: &'static str) {
        if !self.incarnation_unsafe.swap(true, Ordering::AcqRel) {
            tracing::error!(
                operation,
                namespace = %self.namespace,
                "cache namespace was globally fenced or its incarnation changed; permanently disabling cache reads and protected mutations until process restart"
            );
        }
    }

    async fn read_redis_safety(
        &self,
        conn: &mut deadpool_redis::Connection,
    ) -> Result<RedisSafetySnapshot, CacheError> {
        let config = tokio::time::timeout(
            self.op_timeout,
            redis::cmd("CONFIG")
                .arg("GET")
                .arg("maxmemory-policy")
                .arg("save")
                .arg("appendonly")
                .arg("cluster-enabled")
                .query_async::<HashMap<String, String>>(&mut *conn),
        )
        .await
        .map_err(|_| CacheError::Timeout)??;
        let replication = tokio::time::timeout(
            self.op_timeout,
            redis::cmd("INFO")
                .arg("replication")
                .query_async::<String>(&mut *conn),
        )
        .await
        .map_err(|_| CacheError::Timeout)??;

        Ok(RedisSafetySnapshot {
            maxmemory_policy: config
                .get("maxmemory-policy")
                .cloned()
                .unwrap_or_else(|| "missing".to_string()),
            save: config.get("save").cloned(),
            appendonly: config.get("appendonly").cloned(),
            cluster_enabled: config.get("cluster-enabled").cloned(),
            role: redis_info_value(&replication, "role").map(str::to_string),
            connected_replicas: redis_info_value(&replication, "connected_slaves")
                .or_else(|| redis_info_value(&replication, "connected_replicas"))
                .and_then(|value| value.parse::<u64>().ok()),
        })
    }

    async fn poison_namespace(
        &self,
        conn: &mut deadpool_redis::Connection,
        operation: &'static str,
        reason: &str,
    ) {
        let poison = format!("{POISONED_INCARNATION_PREFIX}{}", uuid::Uuid::new_v4());
        let set_result = tokio::time::timeout(
            self.op_timeout,
            redis::cmd("SET")
                .arg(self.incarnation_key())
                .arg(&poison)
                .query_async::<()>(&mut *conn),
        )
        .await;
        let globally_fenced = matches!(set_result, Ok(Ok(())));
        if !globally_fenced {
            // `DEL` remains permitted under Redis OOM handling. A missing
            // marker is also fail-closed for every running process and every
            // non-initializer; the reserved poison value is preferred because
            // even an accidentally enabled initializer cannot replace it.
            let deleted = tokio::time::timeout(
                self.op_timeout,
                redis::cmd("DEL")
                    .arg(self.incarnation_key())
                    .query_async::<u64>(&mut *conn),
            )
            .await;
            if !matches!(deleted, Ok(Ok(_))) {
                tracing::error!(
                    operation,
                    namespace = %self.namespace,
                    reason,
                    "failed to persist or delete the unsafe cache incarnation marker; peer fencing could not be confirmed"
                );
            }
        }
        tracing::error!(
            operation,
            namespace = %self.namespace,
            reason,
            globally_fenced,
            "cache namespace declared unsafe; full fleet drain and fresh namespace initialization are required"
        );
        self.latch_incarnation_unsafe(operation);
    }

    async fn initialize_or_verify_incarnation(
        &self,
        conn: &mut deadpool_redis::Connection,
    ) -> Result<(), CacheError> {
        if self.incarnation_unsafe.load(Ordering::Acquire) {
            return Err(CacheError::IncarnationChanged);
        }

        let expected = self.incarnation.get().map(String::as_str).unwrap_or("");
        let candidate = uuid::Uuid::new_v4().to_string();
        let (status, observed) = tokio::time::timeout(
            self.op_timeout,
            self.init_or_verify_incarnation_script
                .key(self.incarnation_key())
                .key(self.epoch_key())
                .arg(expected)
                .arg(if self.initialize_namespace { "1" } else { "0" })
                .arg(candidate)
                .invoke_async::<(i64, String)>(&mut *conn),
        )
        .await
        .map_err(|_| CacheError::Timeout)??;

        match status {
            1 | 2 if expected.is_empty() => {
                if self.incarnation.set(observed).is_err() {
                    // A concurrent readiness probe may have won the OnceLock.
                    // Both probes read through the same atomic script, so the
                    // winner must have remembered the same marker.
                    let remembered = self
                        .incarnation
                        .get()
                        .expect("OnceLock set failed only when a value exists");
                    let (verify_status, _): (i64, String) = tokio::time::timeout(
                        self.op_timeout,
                        self.init_or_verify_incarnation_script
                            .key(self.incarnation_key())
                            .key(self.epoch_key())
                            .arg(remembered)
                            .arg("0")
                            .arg("")
                            .invoke_async(&mut *conn),
                    )
                    .await
                    .map_err(|_| CacheError::Timeout)??;
                    if verify_status != 1 {
                        self.latch_incarnation_unsafe("probe");
                        return Err(CacheError::IncarnationChanged);
                    }
                }
                Ok(())
            }
            1 | 2 => Ok(()),
            -2 => Err(CacheError::NamespaceUninitialized),
            -1 => Err(CacheError::NamespaceInvalid),
            _ if expected.is_empty() => Err(CacheError::NamespaceInvalid),
            _ => {
                self.latch_incarnation_unsafe("probe");
                Err(CacheError::IncarnationChanged)
            }
        }
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
        if self.incarnation_unsafe.load(Ordering::Acquire) {
            return Err(CacheError::IncarnationChanged);
        }
        let mut conn = self.get_conn().await?;
        tokio::time::timeout(
            self.op_timeout,
            redis::cmd("PING").query_async::<String>(&mut conn),
        )
        .await
        .map_err(|_| CacheError::Timeout)?
        .map_err(CacheError::from)?;
        let safety = match self.read_redis_safety(&mut conn).await {
            Ok(safety) => safety,
            Err(err) => {
                self.eviction_safe.store(false, Ordering::Release);
                return Err(err);
            }
        };
        if safety.maxmemory_policy != "noeviction" {
            self.eviction_safe.store(false, Ordering::Release);
            let err = CacheError::EvictionPolicy(safety.maxmemory_policy.clone());
            self.poison_namespace(&mut conn, "redis_safety", &err.to_string())
                .await;
            return Err(err);
        }
        if let Err(err) = safety.validate_topology() {
            self.eviction_safe.store(false, Ordering::Release);
            self.poison_namespace(&mut conn, "redis_safety", &err.to_string())
                .await;
            return Err(err);
        }
        self.initialize_or_verify_incarnation(&mut conn).await?;
        self.eviction_safe.store(true, Ordering::Release);
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

    /// Reads every key in one atomic Lua round trip on a single pooled
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
        if !self.eviction_safe.load(Ordering::Acquire)
            || self.incarnation_unsafe.load(Ordering::Acquire)
        {
            return unavailable();
        }
        // Prepare mode deliberately exercises every writer-side barrier while
        // keeping all readers on Postgres. This is what makes the prepare ->
        // enabled rolling transition safe.
        if !self.reads_enabled {
            return unavailable();
        }
        let expected_incarnation = match self.expected_incarnation() {
            Ok(incarnation) => incarnation,
            Err(_) => return unavailable(),
        };
        let redis_keys: Vec<String> = keys.iter().map(|key| self.redis_key(key)).collect();

        let mut conn = match self.get_conn().await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::warn!(error = %err, "cache lookup unavailable");
                return unavailable();
            }
        };

        let mut invocation = self.lookup_script.prepare_invoke();
        invocation.key(self.incarnation_key()).key(self.epoch_key());
        for key in &redis_keys {
            invocation.key(key);
        }
        invocation.arg(expected_incarnation);
        let result = tokio::time::timeout(
            self.op_timeout,
            invocation.invoke_async::<(
                String,
                i64,
                Vec<(Option<i64>, Option<i64>, Option<Vec<u8>>)>,
            )>(&mut conn),
        )
        .await;

        match result {
            Ok(Ok((status, epoch, rows))) if status == "ok" && rows.len() == keys.len() => rows
                .into_iter()
                .map(|fields| RawLookup::from_fields(fields, epoch))
                .collect(),
            Ok(Ok((status, _, _))) if status == "incarnation_mismatch" => {
                self.latch_incarnation_unsafe("lookup");
                unavailable()
            }
            Ok(Ok((_, _, rows))) => {
                tracing::warn!(
                    expected = keys.len(),
                    got = rows.len(),
                    "cache batched lookup returned an unexpected row count"
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
            return Lookup::Miss {
                version,
                epoch: raw.epoch,
            };
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
                Lookup::Miss {
                    version,
                    epoch: raw.epoch,
                }
            }
        }
    }

    /// Clears a corrupt payload field, leaving the barrier (`v`/`dirty`)
    /// intact, and only while the entry is still at `observed_version` and not
    /// dirty. Best-effort: a failure just leaves the corrupt payload for the
    /// next reader to trip over and re-attempt.
    async fn discard_payload(&self, key: &str, observed_version: i64) {
        let Ok(expected_incarnation) = self.expected_incarnation() else {
            return;
        };
        let Ok(mut conn) = self.get_conn().await else {
            return;
        };
        let outcome = tokio::time::timeout(
            self.op_timeout,
            self.discard_script
                .key(self.redis_key(key))
                .key(self.incarnation_key())
                .key(self.epoch_key())
                .arg(expected_incarnation)
                .arg(observed_version)
                .invoke_async::<String>(&mut conn),
        )
        .await;
        if matches!(outcome, Ok(Ok(ref result)) if result == "incarnation_mismatch") {
            self.latch_incarnation_unsafe("discard");
        }
    }

    /// Best-effort conditional write following a cache-miss load. Discarded
    /// silently if the entry became dirty or its version moved on since the
    /// caller observed `expected_version` — see the module docs.
    pub async fn try_populate<T: Serialize>(
        &self,
        category: CacheCategory,
        key: &str,
        expected_version: i64,
        expected_epoch: i64,
        value: &T,
    ) {
        let expected_incarnation = match self.expected_incarnation() {
            Ok(incarnation) => incarnation,
            Err(_) => {
                metrics::record_cache_populate(category.as_str(), "error");
                return;
            }
        };
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
                .key(self.redis_key(key))
                .key(self.incarnation_key())
                .key(self.epoch_key())
                .arg(expected_incarnation)
                .arg(expected_version)
                .arg(expected_epoch)
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
                let outcome = match result.as_str() {
                    "applied" => "applied",
                    "incarnation_mismatch" => {
                        self.latch_incarnation_unsafe("populate");
                        "error"
                    }
                    _ => "stale",
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
            Lookup::Miss { version, epoch } => {
                let value = loader().await?;
                self.try_populate(category, key, version, epoch, &value)
                    .await;
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
    pub async fn begin(
        &self,
        category: CacheCategory,
        keys: &[String],
    ) -> Result<CacheLease, AppError> {
        let expected_incarnation = self.expected_incarnation().map_err(|err| {
            tracing::warn!(category = category.as_str(), error = %err, "cache begin refused");
            AppError::service_unavailable(
                "cache namespace is not safe; refusing security-sensitive mutation",
            )
        })?;
        if keys.is_empty() {
            return Ok(CacheLease {
                category,
                logical_keys: Vec::new(),
                redis_keys: Vec::new(),
                lease_field: format!("lease:{}", uuid::Uuid::new_v4()),
            });
        }
        if !self.eviction_safe.load(Ordering::Acquire) {
            return Err(AppError::service_unavailable(
                "cache noeviction policy is not verified; refusing security-sensitive mutation",
            ));
        }
        let lease_field = format!("lease:{}", uuid::Uuid::new_v4());
        // One logical key must own this lease exactly once. Without this
        // stable deduplication, a duplicate straddling the 500-key chunk
        // boundary is consumed by the first END chunk and appears to be a lost
        // exact lease in the later chunk, globally poisoning a healthy
        // namespace.
        let mut seen = HashSet::with_capacity(keys.len());
        let logical_keys: Vec<String> = keys
            .iter()
            .filter(|key| seen.insert(key.as_str()))
            .cloned()
            .collect();
        let redis_keys: Vec<String> = logical_keys.iter().map(|key| self.redis_key(key)).collect();
        // One connection for every chunk, not one per chunk: a bulk
        // invalidation re-acquiring from the pool per 500 keys competes with
        // the request path for connections while already holding Postgres row
        // locks.
        let mut conn = self.get_conn().await.map_err(|err| {
            tracing::warn!(category = category.as_str(), error = %err, "cache begin: connection unavailable");
            metrics::record_cache_invalidation(category.as_str(), "error");
            AppError::service_unavailable("cache unavailable; refusing security-sensitive mutation")
        })?;
        for chunk in redis_keys.chunks(BULK_CHUNK_SIZE) {
            let mut invocation = self.begin_script.prepare_invoke();
            invocation.key(self.incarnation_key()).key(self.epoch_key());
            for key in chunk {
                invocation.key(key);
            }
            invocation.arg(expected_incarnation).arg(&lease_field);

            let outcome =
                tokio::time::timeout(self.op_timeout, invocation.invoke_async::<i64>(&mut conn))
                    .await;
            match outcome {
                Ok(Ok(1)) => {}
                Ok(Ok(_)) => {
                    self.latch_incarnation_unsafe("begin");
                    metrics::record_cache_invalidation(category.as_str(), "error");
                    return Err(AppError::service_unavailable(
                        "cache namespace incarnation changed; refusing security-sensitive mutation",
                    ));
                }
                Ok(Err(err)) => {
                    tracing::warn!(category = category.as_str(), error = %err, "cache begin failed");
                    metrics::record_cache_invalidation(category.as_str(), "error");
                    self.cleanup_partial_begin(category, &mut conn, &redis_keys, &lease_field)
                        .await;
                    return Err(AppError::service_unavailable(
                        "cache unavailable; refusing security-sensitive mutation",
                    ));
                }
                Err(_) => {
                    tracing::warn!(category = category.as_str(), "cache begin timed out");
                    metrics::record_cache_invalidation(category.as_str(), "error");
                    self.cleanup_partial_begin(category, &mut conn, &redis_keys, &lease_field)
                        .await;
                    return Err(AppError::service_unavailable(
                        "cache unavailable; refusing security-sensitive mutation",
                    ));
                }
            }
        }
        metrics::record_cache_invalidation(category.as_str(), "ok");
        Ok(CacheLease {
            category,
            logical_keys,
            redis_keys,
            lease_field,
        })
    }

    /// Bumps the version and decrements the dirty counter on `keys` after the
    /// mutation (success or failure) — the entry only reads as clean once
    /// every overlapping `begin` on the key has been matched by an `end`.
    /// Always best-effort — never fails the caller. A failed `end` deliberately
    /// leaves a persistent dirty token and forces Postgres fallback. The version
    /// bump (not just the dirty decrement) is what stops a reader whose
    /// `lookup` landed during the dirty window from repopulating a stale
    /// value afterward — see the module docs.
    pub async fn end(&self, lease: CacheLease) {
        if lease.logical_keys.is_empty() {
            return;
        }
        let category = lease.category;
        let expected_incarnation = match self.expected_incarnation() {
            Ok(incarnation) => incarnation,
            Err(err) => {
                tracing::error!(category = category.as_str(), error = %err, "cache end refused");
                metrics::record_cache_invalidation(category.as_str(), "error");
                return;
            }
        };
        let poison = format!("{POISONED_INCARNATION_PREFIX}{}", uuid::Uuid::new_v4());
        // One connection for every chunk — see `begin`.
        let mut conn = match self.get_conn().await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::warn!(category = category.as_str(), error = %err, "cache end: connection unavailable");
                metrics::record_cache_invalidation(category.as_str(), "error");
                return;
            }
        };
        for chunk in lease.redis_keys.chunks(BULK_CHUNK_SIZE) {
            let mut invocation = self.end_script.prepare_invoke();
            invocation.key(self.incarnation_key()).key(self.epoch_key());
            for key in chunk {
                invocation.key(key);
            }
            invocation
                .arg(expected_incarnation)
                .arg(category.ttl(&self.ttl).as_millis() as i64)
                .arg(&lease.lease_field)
                .arg(&poison);
            let outcome =
                tokio::time::timeout(self.op_timeout, invocation.invoke_async::<i64>(&mut conn))
                    .await;
            match outcome {
                Ok(Ok(1)) => metrics::record_cache_invalidation(category.as_str(), "ok"),
                Ok(Ok(_)) => {
                    self.latch_incarnation_unsafe("end");
                    metrics::record_cache_invalidation(category.as_str(), "error");
                    break;
                }
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

    async fn cleanup_partial_begin(
        &self,
        category: CacheCategory,
        conn: &mut deadpool_redis::Connection,
        redis_keys: &[String],
        lease_field: &str,
    ) {
        let Ok(expected_incarnation) = self.expected_incarnation() else {
            return;
        };
        for chunk in redis_keys.chunks(BULK_CHUNK_SIZE) {
            let mut invocation = self.cleanup_script.prepare_invoke();
            invocation.key(self.incarnation_key()).key(self.epoch_key());
            for key in chunk {
                invocation.key(key);
            }
            invocation
                .arg(expected_incarnation)
                .arg(category.ttl(&self.ttl).as_millis() as i64)
                .arg(lease_field);
            let _ =
                tokio::time::timeout(self.op_timeout, invocation.invoke_async::<i64>(&mut *conn))
                    .await;
        }
    }
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
    use std::collections::BTreeMap;

    use crate::{
        authz::repo::{CredentialCeiling, EffectiveGrant},
        cache::entries::{
            CredentialCacheEntry, EntityStatusCacheEntry, SessionCacheEntry, TenantStatusCacheEntry,
        },
        config::CacheMode,
        models::enums::{CredentialStatus, Effect, EntityStatus, ScopeKind, TenantStatus},
    };
    use chrono::{TimeZone, Utc};
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct Payload {
        value: String,
    }

    fn test_config(namespace: String, initialize_namespace: bool) -> CacheConfig {
        let url = std::env::var("ATOM_TEST_REDIS_URL")
            .expect("ATOM_TEST_REDIS_URL must be set for cache-gated tests");
        CacheConfig {
            mode: CacheMode::Enabled,
            redis_url: url,
            namespace,
            initialize_namespace,
            ..CacheConfig::default()
        }
    }

    async fn test_client() -> CacheClient {
        let cfg = test_config(format!("unit-{}", Uuid::new_v4()), true);
        CacheClient::connect(&cfg)
            .await
            .expect("connect to test redis")
    }

    fn unique_key(label: &str) -> String {
        format!("atom:v1:test:{label}:{}", Uuid::new_v4())
    }

    fn safe_redis_snapshot() -> RedisSafetySnapshot {
        RedisSafetySnapshot {
            maxmemory_policy: "noeviction".into(),
            save: Some(String::new()),
            appendonly: Some("no".into()),
            cluster_enabled: Some("no".into()),
            role: Some("master".into()),
            connected_replicas: Some(0),
        }
    }

    fn insert_wire<T: Serialize>(values: &mut BTreeMap<String, String>, name: &str, value: &T) {
        values.insert(
            name.to_string(),
            hex::encode(rmp_serde::to_vec(value).expect("serialize golden value")),
        );
    }

    fn current_v1_cache_wire_values() -> BTreeMap<String, String> {
        let mut values = BTreeMap::new();
        let nil = Uuid::nil();
        let id1 = Uuid::from_u128(1);
        let id2 = Uuid::from_u128(2);
        let id3 = Uuid::from_u128(3);
        let id4 = Uuid::from_u128(4);
        let id5 = Uuid::from_u128(5);
        let at = Utc
            .timestamp_opt(1_700_000_000, 123_456_789)
            .single()
            .expect("time");
        let later = Utc
            .timestamp_opt(1_800_000_000, 987_654_321)
            .single()
            .expect("later time");

        insert_wire(
            &mut values,
            "payload.session.some",
            &SessionCacheEntry {
                entity_id: nil,
                revoked_at: Some(at),
                expires_at: later,
            },
        );
        insert_wire(
            &mut values,
            "payload.session.none",
            &SessionCacheEntry {
                entity_id: id1,
                revoked_at: None,
                expires_at: at,
            },
        );
        insert_wire(
            &mut values,
            "payload.entity_status.tenant",
            &EntityStatusCacheEntry {
                status: EntityStatus::Suspended,
                tenant_id: Some(id2),
            },
        );
        insert_wire(
            &mut values,
            "payload.entity_status.global",
            &EntityStatusCacheEntry {
                status: EntityStatus::Active,
                tenant_id: None,
            },
        );
        insert_wire(
            &mut values,
            "payload.tenant_status",
            &TenantStatusCacheEntry {
                status: TenantStatus::Frozen,
            },
        );
        insert_wire(
            &mut values,
            "payload.credential.full",
            &CredentialCacheEntry {
                entity_id: id1,
                status: CredentialStatus::RevocationPending,
                secret_hash: Some("argon".into()),
                secret_lookup_hash: Some(vec![0, 1, 2, 127, 128, 255]),
                expires_at: Some(at),
                scoped: true,
            },
        );
        insert_wire(
            &mut values,
            "payload.credential.none",
            &CredentialCacheEntry {
                entity_id: id2,
                status: CredentialStatus::Active,
                secret_hash: None,
                secret_lookup_hash: None,
                expires_at: None,
                scoped: false,
            },
        );

        let role_grant = EffectiveGrant {
            assignment_id: nil,
            block_id: id1,
            role_id: Some(id2),
            role_name: Some("operator".into()),
            via: "group:parent -> child".into(),
            tenant_boundary: Some(id3),
            scope_kind: ScopeKind::GroupTreeObjectType,
            scope_ref: Some(format!("{id4}:resource:channel")),
            capability_id: id5,
            effect: Effect::Deny,
            conditions: serde_json::json!({
                "context.ip": {"in": ["192.0.2.1", "2001:db8::1"]},
                "entity.risk": {"gte": 7},
                "sentinel": [true, null, "v1"]
            }),
        };
        let direct_grant = EffectiveGrant {
            assignment_id: id5,
            block_id: id4,
            role_id: None,
            role_name: None,
            via: "direct".into(),
            tenant_boundary: None,
            scope_kind: ScopeKind::Platform,
            scope_ref: None,
            capability_id: id3,
            effect: Effect::Allow,
            conditions: serde_json::json!({}),
        };
        insert_wire(&mut values, "payload.effective_grant.role", &role_grant);
        insert_wire(&mut values, "payload.effective_grant.direct", &direct_grant);
        insert_wire(
            &mut values,
            "payload.grants",
            &vec![role_grant.clone(), direct_grant.clone()],
        );
        insert_wire(
            &mut values,
            "payload.credential_ceiling",
            &CredentialCeiling {
                entries: vec![direct_grant],
            },
        );

        for (name, value) in [
            ("active", EntityStatus::Active),
            ("inactive", EntityStatus::Inactive),
            ("suspended", EntityStatus::Suspended),
        ] {
            insert_wire(&mut values, &format!("enum.entity_status.{name}"), &value);
        }
        for (name, value) in [
            ("active", TenantStatus::Active),
            ("inactive", TenantStatus::Inactive),
            ("frozen", TenantStatus::Frozen),
            ("deleted", TenantStatus::Deleted),
        ] {
            insert_wire(&mut values, &format!("enum.tenant_status.{name}"), &value);
        }
        for (name, value) in [
            ("active", CredentialStatus::Active),
            ("revocation_pending", CredentialStatus::RevocationPending),
            ("revoked", CredentialStatus::Revoked),
        ] {
            insert_wire(
                &mut values,
                &format!("enum.credential_status.{name}"),
                &value,
            );
        }
        for (name, value) in [
            ("platform", ScopeKind::Platform),
            ("tenant", ScopeKind::Tenant),
            ("object_kind", ScopeKind::ObjectKind),
            ("object_type", ScopeKind::ObjectType),
            ("object", ScopeKind::Object),
            ("group_object_type", ScopeKind::GroupObjectType),
            ("group_tree_object_type", ScopeKind::GroupTreeObjectType),
            ("group_child_kind", ScopeKind::GroupChildKind),
            ("group_descendant_kind", ScopeKind::GroupDescendantKind),
        ] {
            insert_wire(&mut values, &format!("enum.scope_kind.{name}"), &value);
        }
        for (name, value) in [("allow", Effect::Allow), ("deny", Effect::Deny)] {
            insert_wire(&mut values, &format!("enum.effect.{name}"), &value);
        }
        values
    }

    #[test]
    fn v1_cache_messagepack_bytes_match_frozen_goldens() {
        let expected: BTreeMap<String, String> =
            serde_json::from_str(include_str!("../../api/v1/cache-wire-v1.json"))
                .expect("parse frozen v1 cache wire fixture");
        let actual = current_v1_cache_wire_values();
        if expected.is_empty() {
            eprintln!(
                "{}",
                serde_json::to_string_pretty(&actual).expect("render cache wire fixture")
            );
        }
        assert_eq!(actual, expected);
    }

    #[test]
    fn v1_redis_topology_rejects_every_rollback_source() {
        safe_redis_snapshot()
            .validate_topology()
            .expect("supported topology");

        let unsafe_cases: &[(&str, fn(&mut RedisSafetySnapshot))] = &[
            ("RDB snapshots", |snapshot: &mut RedisSafetySnapshot| {
                snapshot.save = Some("3600 1".into())
            }),
            ("AOF", |snapshot: &mut RedisSafetySnapshot| {
                snapshot.appendonly = Some("yes".into())
            }),
            ("Redis Cluster", |snapshot: &mut RedisSafetySnapshot| {
                snapshot.cluster_enabled = Some("yes".into())
            }),
            ("primary", |snapshot: &mut RedisSafetySnapshot| {
                snapshot.role = Some("slave".into())
            }),
            ("replicas", |snapshot: &mut RedisSafetySnapshot| {
                snapshot.connected_replicas = Some(1)
            }),
        ];
        for (expected, mutate) in unsafe_cases {
            let mut snapshot = safe_redis_snapshot();
            mutate(&mut snapshot);
            let err = snapshot
                .validate_topology()
                .expect_err("rollback-capable topology must be rejected");
            assert!(
                err.to_string().contains(expected),
                "unexpected error: {err}"
            );
        }
    }

    #[test]
    fn v1_cache_contract_matches_runtime_keys_and_positional_dtos() {
        let contract = include_str!("../../api/v1/cache-contract.md");
        let id = Uuid::nil();
        for (key, expected, pattern) in [
            (
                keys::session(id),
                "atom:v1:session:00000000-0000-0000-0000-000000000000",
                "atom:v1:session:<session-uuid>",
            ),
            (
                keys::entity_status(id),
                "atom:v1:entity_status:00000000-0000-0000-0000-000000000000",
                "atom:v1:entity_status:<entity-uuid>",
            ),
            (
                keys::tenant_status(id),
                "atom:v1:tenant_status:00000000-0000-0000-0000-000000000000",
                "atom:v1:tenant_status:<tenant-uuid>",
            ),
            (
                keys::credential(id),
                "atom:v1:credential:00000000-0000-0000-0000-000000000000",
                "atom:v1:credential:<credential-uuid>",
            ),
            (
                keys::cred_ceiling(id),
                "atom:v1:cred_ceiling:00000000-0000-0000-0000-000000000000",
                "atom:v1:cred_ceiling:<credential-uuid>",
            ),
            (
                keys::grants(id),
                "atom:v1:grants:00000000-0000-0000-0000-000000000000",
                "atom:v1:grants:<subject-uuid>",
            ),
        ] {
            assert_eq!(key, expected);
            assert!(contract.contains(pattern), "contract missing {pattern}");
        }
        let cfg = CacheConfig {
            mode: CacheMode::Enabled,
            redis_url: "redis://127.0.0.1:1/0".into(),
            namespace: "contract-deployment".into(),
            ..CacheConfig::default()
        };
        let client = CacheClient::build(&cfg).expect("contract cache client");
        assert_eq!(
            client.epoch_key(),
            "contract-deployment:atom:v1:mutation_epoch"
        );
        assert!(contract.contains("<ATOM_CACHE_NAMESPACE>:atom:v1:mutation_epoch"));
        assert_eq!(
            client.incarnation_key(),
            "contract-deployment:atom:v1:incarnation"
        );
        assert!(contract.contains("<ATOM_CACHE_NAMESPACE>:atom:v1:incarnation"));

        let at = Utc.timestamp_opt(1_700_000_000, 0).single().expect("time");
        let later = Utc.timestamp_opt(1_800_000_000, 0).single().expect("time");
        let other_id = Uuid::from_u128(1);
        let session = SessionCacheEntry {
            entity_id: id,
            revoked_at: Some(at),
            expires_at: later,
        };
        let entity = EntityStatusCacheEntry {
            status: EntityStatus::Suspended,
            tenant_id: Some(other_id),
        };
        let tenant = TenantStatusCacheEntry {
            status: TenantStatus::Inactive,
        };
        let credential = CredentialCacheEntry {
            entity_id: id,
            status: CredentialStatus::RevocationPending,
            secret_hash: Some("argon".into()),
            secret_lookup_hash: Some(vec![1, 2, 3]),
            expires_at: Some(at),
            scoped: true,
        };
        let session_wire: (Uuid, Option<chrono::DateTime<Utc>>, chrono::DateTime<Utc>) =
            rmp_serde::from_slice(&rmp_serde::to_vec(&session).expect("session"))
                .expect("session positions");
        assert_eq!(session_wire, (id, Some(at), later));
        let entity_wire: (EntityStatus, Option<Uuid>) =
            rmp_serde::from_slice(&rmp_serde::to_vec(&entity).expect("entity"))
                .expect("entity positions");
        assert_eq!(entity_wire, (EntityStatus::Suspended, Some(other_id)));
        let tenant_wire: (TenantStatus,) =
            rmp_serde::from_slice(&rmp_serde::to_vec(&tenant).expect("tenant"))
                .expect("tenant positions");
        assert_eq!(tenant_wire, (TenantStatus::Inactive,));
        let credential_wire: (
            Uuid,
            CredentialStatus,
            Option<String>,
            Option<Vec<u8>>,
            Option<chrono::DateTime<Utc>>,
            bool,
        ) = rmp_serde::from_slice(&rmp_serde::to_vec(&credential).expect("credential"))
            .expect("credential positions");
        assert_eq!(
            credential_wire,
            (
                id,
                CredentialStatus::RevocationPending,
                Some("argon".into()),
                Some(vec![1, 2, 3]),
                Some(at),
                true,
            )
        );

        let grant = EffectiveGrant {
            assignment_id: id,
            block_id: Uuid::from_u128(2),
            role_id: Some(Uuid::from_u128(3)),
            role_name: Some("operator".into()),
            via: "group:path".into(),
            tenant_boundary: Some(Uuid::from_u128(4)),
            scope_kind: ScopeKind::Tenant,
            scope_ref: Some("scope-ref".into()),
            capability_id: Uuid::from_u128(5),
            effect: Effect::Deny,
            conditions: serde_json::json!({"sentinel": 7}),
        };
        type GrantWire = (
            Uuid,
            Uuid,
            Option<Uuid>,
            Option<String>,
            String,
            Option<Uuid>,
            ScopeKind,
            Option<String>,
            Uuid,
            Effect,
            serde_json::Value,
        );
        let expected_grant: GrantWire = (
            id,
            Uuid::from_u128(2),
            Some(Uuid::from_u128(3)),
            Some("operator".into()),
            "group:path".into(),
            Some(Uuid::from_u128(4)),
            ScopeKind::Tenant,
            Some("scope-ref".into()),
            Uuid::from_u128(5),
            Effect::Deny,
            serde_json::json!({"sentinel": 7}),
        );
        let grant_bytes = rmp_serde::to_vec(&grant).expect("grant");
        let positional: GrantWire = rmp_serde::from_slice(&grant_bytes).expect("grant positions");
        assert_eq!(positional, expected_grant);
        let ceiling = CredentialCeiling {
            entries: vec![grant],
        };
        let ceiling_positional: (Vec<GrantWire>,) =
            rmp_serde::from_slice(&rmp_serde::to_vec(&ceiling).expect("ceiling"))
                .expect("ceiling positions");
        assert_eq!(ceiling_positional, (vec![expected_grant],));
    }

    /// Drives `main.rs`'s fail-fast-vs-degrade startup branching: `connect`
    /// must return `Err` (not hang, not panic) against an unreachable Redis,
    /// bounded by `connect_timeout_ms`. No live Redis needed — this
    /// deliberately never reaches one — so it runs in default `cargo test`.
    #[tokio::test]
    async fn connect_fails_against_an_unreachable_redis() {
        let cfg = CacheConfig {
            mode: CacheMode::Enabled,
            redis_url: "redis://127.0.0.1:1/0".into(),
            namespace: "unit-unreachable".into(),
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
    async fn malformed_epoch_values_fail_readiness() {
        for malformed in ["1.5", "1e3", "-1", "+1", "01", "nan", "9223372036854775808"] {
            let namespace = format!("unit-malformed-epoch-{}", Uuid::new_v4());
            let client = CacheClient::connect(&test_config(namespace, true))
                .await
                .expect("initialize namespace");
            let _: () = redis::cmd("SET")
                .arg(client.epoch_key())
                .arg(malformed)
                .query_async(&mut client.get_conn().await.expect("conn"))
                .await
                .expect("write malformed epoch");

            assert!(
                matches!(client.ping().await, Err(CacheError::IncarnationChanged)),
                "epoch {malformed:?} must fail readiness and permanently latch the process unsafe"
            );
        }
    }

    #[tokio::test]
    #[ignore]
    async fn empty_namespace_requires_explicit_initialization() {
        let namespace = format!("unit-uninitialized-{}", Uuid::new_v4());
        let cfg = test_config(namespace, false);
        let err = CacheClient::connect(&cfg)
            .await
            .expect_err("an empty namespace must never initialize implicitly");
        assert!(
            err.to_string().contains("ATOM_CACHE_INITIALIZE_NAMESPACE"),
            "unexpected initialization error: {err}"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn initializer_rejects_a_missing_marker_when_the_epoch_survives() {
        let namespace = format!("unit-damaged-namespace-{}", Uuid::new_v4());
        let first = CacheClient::connect(&test_config(namespace.clone(), true))
            .await
            .expect("initialize namespace");
        let mut conn = first.get_conn().await.expect("conn");
        let _: () = redis::cmd("DEL")
            .arg(first.incarnation_key())
            .query_async(&mut conn)
            .await
            .expect("remove only the incarnation marker");
        let epoch_exists: bool = redis::cmd("EXISTS")
            .arg(first.epoch_key())
            .query_async(&mut conn)
            .await
            .expect("check surviving epoch");
        assert!(
            epoch_exists,
            "the test must preserve the old generation epoch"
        );
        drop(conn);

        let err = CacheClient::connect(&test_config(namespace, true))
            .await
            .expect_err("an initializer must not repair a partially lost generation");
        assert!(
            err.to_string().contains("namespace incarnation"),
            "unexpected damaged-namespace error: {err}"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn later_process_joins_existing_incarnation_without_initializer() {
        let namespace = format!("unit-join-{}", Uuid::new_v4());
        let initializer = CacheClient::connect(&test_config(namespace.clone(), true))
            .await
            .expect("initialize namespace");
        let joining = CacheClient::connect(&test_config(namespace, false))
            .await
            .expect("join initialized namespace");
        assert_eq!(initializer.incarnation.get(), joining.incarnation.get());
    }

    /// Namespace-local equivalent of FLUSHDB followed by Redis replacement:
    /// removing the marker, epoch, and entry keys is enough to reproduce the
    /// state-loss race without disrupting other parallel tests sharing Redis.
    #[tokio::test]
    #[ignore]
    async fn old_reader_cannot_populate_after_namespace_flush_and_replacement() {
        let namespace = format!("unit-replacement-{}", Uuid::new_v4());
        let cfg = test_config(namespace, true);
        let old_client = CacheClient::connect(&cfg).await.expect("old client");
        let key = unique_key("replacement-reader");
        let (version, epoch) = match old_client
            .lookup::<Payload>(CacheCategory::Grants, &key)
            .await
        {
            Lookup::Miss { version, epoch } => (version, epoch),
            other => panic!("expected old-generation miss, got {other:?}"),
        };

        let mut conn = old_client.get_conn().await.expect("conn");
        let _: () = redis::cmd("DEL")
            .arg(old_client.incarnation_key())
            .arg(old_client.epoch_key())
            .arg(old_client.redis_key(&key))
            .query_async(&mut conn)
            .await
            .expect("simulate namespace flush");
        drop(conn);

        let new_client = CacheClient::connect(&cfg)
            .await
            .expect("initialize replacement namespace");
        assert_ne!(
            old_client.incarnation.get(),
            new_client.incarnation.get(),
            "a replacement must receive a new incarnation"
        );

        let stale = Payload {
            value: "loaded before Redis replacement".into(),
        };
        old_client
            .try_populate(CacheCategory::Grants, &key, version, epoch, &stale)
            .await;
        assert!(
            old_client.incarnation_unsafe.load(Ordering::Acquire),
            "the old client must permanently latch unsafe on marker mismatch"
        );
        assert!(matches!(
            old_client
                .lookup::<Payload>(CacheCategory::Grants, &key)
                .await,
            Lookup::Unavailable
        ));
        assert!(old_client
            .begin(CacheCategory::Grants, std::slice::from_ref(&key))
            .await
            .is_err());
        assert!(matches!(
            old_client.ping().await,
            Err(CacheError::IncarnationChanged)
        ));

        let (new_version, new_epoch) = match new_client
            .lookup::<Payload>(CacheCategory::Grants, &key)
            .await
        {
            Lookup::Miss { version, epoch } => (version, epoch),
            other => panic!("replacement must start cold, got {other:?}"),
        };
        let fresh = Payload {
            value: "loaded after replacement".into(),
        };
        new_client
            .try_populate(CacheCategory::Grants, &key, new_version, new_epoch, &fresh)
            .await;
        match new_client
            .lookup::<Payload>(CacheCategory::Grants, &key)
            .await
        {
            Lookup::Hit(got) => assert_eq!(got, fresh),
            other => panic!("replacement client should populate normally, got {other:?}"),
        }
    }

    #[tokio::test]
    #[ignore]
    async fn restored_marker_does_not_clear_the_per_process_unsafe_latch() {
        let client = test_client().await;
        let key = unique_key("restored-marker");
        let remembered = client
            .incarnation
            .get()
            .expect("connected client remembers incarnation")
            .clone();
        let mut conn = client.get_conn().await.expect("conn");
        let _: () = redis::cmd("DEL")
            .arg(client.incarnation_key())
            .query_async(&mut conn)
            .await
            .expect("delete marker");

        assert!(matches!(
            client.lookup::<Payload>(CacheCategory::Grants, &key).await,
            Lookup::Unavailable
        ));
        let _: () = redis::cmd("SET")
            .arg(client.incarnation_key())
            .arg(remembered)
            .query_async(&mut conn)
            .await
            .expect("restore marker");
        assert!(matches!(
            client.ping().await,
            Err(CacheError::IncarnationChanged)
        ));
        assert!(client
            .begin(CacheCategory::Grants, std::slice::from_ref(&key))
            .await
            .is_err());
    }

    #[tokio::test]
    #[ignore]
    async fn end_latches_unsafe_when_redis_is_replaced_mid_mutation() {
        let namespace = format!("unit-end-replacement-{}", Uuid::new_v4());
        let cfg = test_config(namespace, true);
        let old_client = CacheClient::connect(&cfg).await.expect("old client");
        let key = unique_key("replacement-writer");
        let lease = old_client
            .begin(CacheCategory::Grants, std::slice::from_ref(&key))
            .await
            .expect("begin old-generation mutation");
        let mut conn = old_client.get_conn().await.expect("conn");
        let _: () = redis::cmd("DEL")
            .arg(old_client.incarnation_key())
            .arg(old_client.epoch_key())
            .arg(old_client.redis_key(&key))
            .query_async(&mut conn)
            .await
            .expect("simulate namespace replacement");
        drop(conn);
        let _new_client = CacheClient::connect(&cfg)
            .await
            .expect("initialize replacement namespace");

        old_client.end(lease).await;
        assert!(old_client.incarnation_unsafe.load(Ordering::Acquire));
        assert!(matches!(
            old_client.ping().await,
            Err(CacheError::IncarnationChanged)
        ));
    }

    #[tokio::test]
    #[ignore]
    async fn missing_end_lease_globally_poisons_every_client_and_initializer() {
        let namespace = format!("unit-end-poison-{}", Uuid::new_v4());
        let first = CacheClient::connect(&test_config(namespace.clone(), true))
            .await
            .expect("first client");
        let peer = CacheClient::connect(&test_config(namespace.clone(), false))
            .await
            .expect("peer client");
        let key = unique_key("lost-end-lease");
        let lease = first
            .begin(CacheCategory::Grants, std::slice::from_ref(&key))
            .await
            .expect("begin mutation");

        // Reproduce the dangerous allkeys-eviction race: the dirty hash is
        // lost, then a reader recreates a clean payload from pre-commit
        // Postgres state while the mutation is still in flight.
        let stale = Payload {
            value: "pre-commit stale value".into(),
        };
        let payload = rmp_serde::to_vec(&stale).expect("serialize stale payload");
        let incarnation = first
            .incarnation
            .get()
            .expect("remembered incarnation")
            .clone();
        let mut conn = first.get_conn().await.expect("conn");
        let _: () = redis::cmd("DEL")
            .arg(first.redis_key(&key))
            .query_async(&mut conn)
            .await
            .expect("evict dirty hash");
        let _: () = redis::cmd("HSET")
            .arg(first.redis_key(&key))
            .arg("i")
            .arg(incarnation)
            .arg("v")
            .arg(0)
            .arg("dirty")
            .arg(0)
            .arg("p")
            .arg(payload)
            .query_async(&mut conn)
            .await
            .expect("repopulate stale hash without the exact lease");
        drop(conn);

        first.end(lease).await;
        assert!(first.incarnation_unsafe.load(Ordering::Acquire));
        assert!(matches!(
            peer.lookup::<Payload>(CacheCategory::Grants, &key).await,
            Lookup::Unavailable
        ));
        assert!(peer.incarnation_unsafe.load(Ordering::Acquire));

        let marker: String = redis::cmd("GET")
            .arg(first.incarnation_key())
            .query_async(&mut first.get_conn().await.expect("conn"))
            .await
            .expect("poisoned marker");
        assert!(marker.starts_with(POISONED_INCARNATION_PREFIX));
        let err = CacheClient::connect(&test_config(namespace, true))
            .await
            .expect_err("even an initializer must reject a poisoned generation");
        assert!(
            err.to_string().contains("namespace incarnation"),
            "unexpected poison error: {err}"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn lookup_on_absent_key_is_a_clean_miss_at_version_zero() {
        let client = test_client().await;
        let key = unique_key("lookup-miss");
        match client.lookup::<Payload>(CacheCategory::Grants, &key).await {
            Lookup::Miss { version, epoch } => assert_eq!((version, epoch), (0, 0)),
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

        let (version, epoch) = match client.lookup::<Payload>(CacheCategory::Grants, &key).await {
            Lookup::Miss { version, epoch } => (version, epoch),
            other => panic!("expected miss before populate, got {other:?}"),
        };
        client
            .try_populate(CacheCategory::Grants, &key, version, epoch, &value)
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
        let redis_key = client.redis_key(&key);
        let incarnation = client
            .incarnation
            .get()
            .expect("connected client remembers incarnation");
        let _: () = redis::cmd("HSET")
            .arg(&redis_key)
            .arg("i")
            .arg(incarnation)
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
            .arg(&redis_key)
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
        let redis_key = client.redis_key(&key);
        let incarnation = client
            .incarnation
            .get()
            .expect("connected client remembers incarnation");
        let _: () = redis::cmd("HSET")
            .arg(&redis_key)
            .arg("i")
            .arg(incarnation)
            .arg("v")
            .arg(1)
            .arg("p")
            .arg("not a valid payload")
            .query_async(&mut conn)
            .await
            .expect("seed corrupt payload");

        // A mutation opens its barrier *after* the reader observed version 1.
        let _lease = client
            .begin(CacheCategory::Grants, &keys)
            .await
            .expect("begin");

        // The reader's cleanup now fires against its stale observed version.
        client.discard_payload(&key, 1).await;

        let dirty: Option<String> = redis::cmd("HGET")
            .arg(&redis_key)
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
        let lease = client
            .begin(CacheCategory::Grants, &keys)
            .await
            .expect("begin");
        client.end(lease).await;
        let redis_key = client.redis_key(&key);
        let (version_after, epoch_after, epoch_ttl): (Option<i64>, Option<i64>, i64) = {
            let mut conn = client.get_conn().await.expect("conn");
            let version = redis::cmd("HGET")
                .arg(&redis_key)
                .arg("v")
                .query_async(&mut conn)
                .await
                .expect("version after mutation");
            let epoch_key = client.epoch_key();
            let epoch = redis::cmd("GET")
                .arg(&epoch_key)
                .query_async(&mut conn)
                .await
                .expect("epoch after mutation");
            let ttl = redis::cmd("PTTL")
                .arg(&epoch_key)
                .query_async(&mut conn)
                .await
                .expect("epoch ttl");
            let _: () = redis::cmd("DEL")
                .arg(&redis_key)
                .query_async(&mut conn)
                .await
                .expect("simulate clean hash expiry");
            (version, epoch, ttl)
        };
        assert!(version_after.unwrap_or_default() > 0);
        assert!(epoch_after.unwrap_or_default() > 0);
        assert_eq!(epoch_ttl, -1, "namespace mutation epoch must never expire");

        // The reader observed version 0 (before the mutation) and now tries
        // to populate with that stale value.
        let stale_value = Payload {
            value: "stale".into(),
        };
        client
            .try_populate(CacheCategory::Grants, &key, 0, 0, &stale_value)
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

        let (version, epoch) = match client.lookup::<Payload>(CacheCategory::Grants, &key).await {
            Lookup::Miss { version, epoch } => (version, epoch),
            other => panic!("expected miss, got {other:?}"),
        };
        let value = Payload {
            value: "before-mutation".into(),
        };
        client
            .try_populate(CacheCategory::Grants, &key, version, epoch, &value)
            .await;
        // Confirm it's actually cached before dirtying it.
        assert!(matches!(
            client.lookup::<Payload>(CacheCategory::Grants, &key).await,
            Lookup::Hit(_)
        ));

        // `begin` marks it dirty and clears the payload without an `end`.
        let _lease = client
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

        let lease = client
            .begin(CacheCategory::Grants, &keys)
            .await
            .expect("begin");
        for key in &keys {
            let (_, dirty, _): (Option<i64>, Option<String>, Option<Vec<u8>>) = redis::cmd("HMGET")
                .arg(client.redis_key(key))
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

        client.end(lease).await;
        for key in &keys {
            let (_, dirty, _): (Option<i64>, Option<String>, Option<Vec<u8>>) = redis::cmd("HMGET")
                .arg(client.redis_key(key))
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
    async fn duplicate_key_across_bulk_chunks_owns_one_exact_lease() {
        let client = test_client().await;
        let mut keys: Vec<String> = (0..=BULK_CHUNK_SIZE)
            .map(|i| unique_key(&format!("dedup-{i}")))
            .collect();
        keys.push(keys[0].clone());

        let lease = client
            .begin(CacheCategory::Grants, &keys)
            .await
            .expect("begin deduplicated bulk mutation");
        assert_eq!(lease.logical_keys.len(), BULK_CHUNK_SIZE + 1);
        assert_eq!(lease.redis_keys.len(), BULK_CHUNK_SIZE + 1);
        client.end(lease).await;

        assert!(!client.incarnation_unsafe.load(Ordering::Acquire));
        let dirty: Option<i64> = redis::cmd("HGET")
            .arg(client.redis_key(&keys[0]))
            .arg("dirty")
            .query_async(&mut client.get_conn().await.expect("conn"))
            .await
            .expect("dirty after deduplicated end");
        assert_eq!(dirty, Some(0));
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
        let (observed_version, observed_epoch) =
            match client.lookup::<Payload>(CacheCategory::Grants, &key).await {
                Lookup::Miss { version, epoch } => (version, epoch),
                other => panic!("expected initial miss, got {other:?}"),
            };

        // A concurrent mutation runs to completion while the reader's
        // (simulated) Postgres load is still in flight: begin bumps the
        // version and marks dirty, then end clears dirty after the mutation
        // commits.
        let lease = client
            .begin(CacheCategory::Grants, &keys)
            .await
            .expect("begin");
        client.end(lease).await;

        // The reader's stale load now finishes and attempts to populate with
        // the version it observed *before* the mutation.
        let stale_value = Payload {
            value: "STALE — must never be visible".into(),
        };
        client
            .try_populate(
                CacheCategory::Grants,
                &key,
                observed_version,
                observed_epoch,
                &stale_value,
            )
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
        let lease = client
            .begin(CacheCategory::Grants, &keys)
            .await
            .expect("begin");

        // A reader's `lookup` lands *while the mutation is still in
        // flight* — this is the case the previous test didn't cover.
        let (dirty_window_version, dirty_window_epoch) =
            match client.lookup::<Payload>(CacheCategory::Grants, &key).await {
                Lookup::Miss { version, epoch } => (version, epoch),
                other => panic!("expected a miss while dirty, got {other:?}"),
            };

        // The mutation finishes — `end` clears dirty (and, with the fix,
        // bumps the version again).
        client.end(lease).await;

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
                dirty_window_epoch,
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
        let lease_1 = client
            .begin(CacheCategory::Grants, &keys)
            .await
            .expect("M1 begin");
        let lease_2 = client
            .begin(CacheCategory::Grants, &keys)
            .await
            .expect("M2 begin");

        // M1 finishes first. With a flag (not a counter), this would clear
        // `dirty` outright even though M2 hasn't committed yet.
        client.end(lease_1).await;
        let redis_key = client.redis_key(&key);
        let ttl_while_dirty: i64 = redis::cmd("PTTL")
            .arg(&redis_key)
            .query_async(&mut client.get_conn().await.expect("conn"))
            .await
            .expect("dirty ttl");
        assert_eq!(
            ttl_while_dirty, -1,
            "remaining token must keep key persistent"
        );

        // A reader lands in the gap between M1's `end` and M2's commit. The
        // barrier must still read as dirty — M2 is still in flight — so this
        // must be a miss, not a hit, and the version it observes here must
        // never successfully populate the cache.
        let (gap_version, gap_epoch) =
            match client.lookup::<Payload>(CacheCategory::Grants, &key).await {
                Lookup::Miss { version, epoch } => (version, epoch),
                other => panic!(
                    "expected a miss while M2 is still in flight (M1's end must not have cleared \
                 the barrier), got {other:?}"
                ),
            };
        let stale_value = Payload {
            value: "STALE — read while a second overlapping mutation was still in flight".into(),
        };
        client
            .try_populate(
                CacheCategory::Grants,
                &key,
                gap_version,
                gap_epoch,
                &stale_value,
            )
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
        client.end(lease_2).await;
        let ttl_when_clean: i64 = redis::cmd("PTTL")
            .arg(&redis_key)
            .query_async(&mut client.get_conn().await.expect("conn"))
            .await
            .expect("clean ttl");
        assert!(
            ttl_when_clean > 0,
            "clean entry hash should regain bounded TTL"
        );
        let (clean_version, clean_epoch) = match client
            .lookup::<Payload>(CacheCategory::Grants, &key)
            .await
        {
            Lookup::Miss { version, epoch } => (version, epoch),
            other => {
                panic!("expected a clean miss once every overlapping mutation ended, got {other:?}")
            }
        };
        let fresh_value = Payload {
            value: "fresh, post-M2 value".into(),
        };
        client
            .try_populate(
                CacheCategory::Grants,
                &key,
                clean_version,
                clean_epoch,
                &fresh_value,
            )
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

    #[tokio::test]
    #[ignore]
    async fn dropped_lease_remains_dirty_without_expiry() {
        let client = test_client().await;
        let key = unique_key("drop-persists");
        let keys = vec![key.clone()];
        let redis_key = client.redis_key(&key);
        let lease = client
            .begin(CacheCategory::Grants, &keys)
            .await
            .expect("begin");

        drop(lease);
        tokio::time::sleep(Duration::from_millis(700)).await;
        let dirty: Option<i64> = redis::cmd("HGET")
            .arg(&redis_key)
            .arg("dirty")
            .query_async(&mut client.get_conn().await.expect("conn"))
            .await
            .expect("dirty after drop");
        assert_eq!(dirty, Some(1), "dropped token must remain dirty");
        let ttl: i64 = redis::cmd("PTTL")
            .arg(&redis_key)
            .query_async(&mut client.get_conn().await.expect("conn"))
            .await
            .expect("ttl after drop");
        assert_eq!(ttl, -1, "dirty barrier must have no expiry");
    }
}
