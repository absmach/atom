# Generic Domain-Event Publishing for Atom

## 1. Title

**Generic, Optional, Broker-Backed Domain-Event Publishing for Atom**

Branch: `at-37-events`. This document reflects the **implemented** design, not a proposal — the feature described here is built, tested, and merged into this branch. It replaces an earlier draft of this same document that proposed usage quotas and quota enforcement *inside* Atom; that direction was explicitly rejected by the team (see §2) and nothing from it remains in the codebase.

## 2. Executive summary and origin

Atom needed a way to let external systems (a billing service is the motivating example) react to the CRUD operations Atom already performs, without Atom taking on any billing/quota/usage-limit responsibility itself. This requirement was clarified over a team discussion (Dušan, Arvindh, sammy oina) that produced three settled decisions this implementation follows exactly:

1. **No usage quotas or limits in Atom.** ("we will not add usage quota in Atom directly" — Dušan). Any pre-operation limit check (e.g. "is this tenant within its plan's entity count") is a separate, external concern — either the consumer's own logic or a separate callback/webhook mechanism outside this feature's scope.
2. **Events are async and fire-and-forget from Atom's side.** ("In events approach, ATOM dont care, it fires the event and forget. The billing need to take care rest." — Arvindh). Atom's job ends at reliable delivery of a notification; it has no opinion on what the consumer does with it.
3. **Publish everything, to a broker, optionally.** The team settled on: publish *all* events (not just CRUD, not filtered by category — "We will publish all events for the time being" — user), over **AMQP** specifically ("we use AMQP for events, so broker does not have to be FMQ" — Dušan), with the broker connection **built into Atom and gated purely by configuration** ("Atom stores events and broadcasts them to FMQ optionally" — Dušan; "if a broker is not configured events are simply not published, so users who don't need this feature can keep their deployment simple" — sammy oina).

A prior draft of this feature (still visible in git history on this branch, since abandoned mid-implementation) built a full quota-policy/usage-counter/enforcement system inside Atom. That work was discarded once the above was clarified; only its transactional-outbox and pluggable-publisher mechanics were reusable, and both were rebuilt from scratch against the corrected scope described here.

## 3. Goals

- Every operation Atom already records via its existing audit mechanism (`src/audit.rs`) is optionally mirrored to an AMQP broker as a generic domain event.
- Publishing is reliable in the at-least-once sense: a broker outage or a transient publish failure must not lose an event, and must not block or fail the underlying mutation.
- The feature is entirely optional and off by default: an operator who never sets an AMQP URL sees zero behavior change and zero extra database writes.
- No event-category filtering in this version — every audit-worthy event is eligible for publishing when the feature is enabled (the team's explicit "publish all events for the time being" instruction).
- The broker integration is generic (standard AMQP 0-9-1, via the `lapin` crate) — Atom does not depend on FluxMQ, Magistrala, or any other Abstract Machines product to use this feature.

## 4. Non-goals

- No quota policies, usage counters, or enforcement of any kind inside Atom.
- No billing, subscription, plan, price, invoice, or payment vocabulary anywhere in Atom's code, schema, or event payloads.
- No pre-operation callback/webhook mechanism — that is a distinct, separately-owned effort (Arvindh: "working on ATOM config, to have callback as config") and is not part of this feature.
- No event-type filtering/allowlisting in v1 — deferred until there's a concrete need (see §14).
- No changes to what gets persisted in `audit_logs` — the existing two-channel audit system (`write` vs. `observe_result` vs. `write_hot_path`) is unchanged in its DB-persistence behavior; this feature only adds a second, independent effect (event enqueue) alongside it.

## 5. Existing implementation findings (confirmed before building)

These were confirmed by direct inspection of the repository before any code was written:

- **No prior event/broker/outbox infrastructure existed.** No message-broker client crate, no outbox table, no webhook delivery code anywhere in `src/` or `migrations/`.
- **Atom's audit system is not a single, uniform mechanism.** `src/audit.rs` has three entry points, and critically, they are *not* interchangeable:
  - `write(pool, event)` — 38 call sites — persists to the `audit_logs` table.
  - `observe_result(meta, details, result)` — 42 call sites — **stdout/tracing only, never persisted to `audit_logs`**. This includes `resource.create` (`src/graphql/resources.rs`), `tenant.create` (`src/graphql/tenants.rs`), and `group.create` (`src/graphql/groups.rs`) — i.e. exactly the create operations an external consumer is most likely to care about.
  - `write_hot_path(pool, policy, kind, event)` — 4 call sites — conditionally persists, used for high-volume auth/authz checks, suppressing `Allow` outcomes by default.
  - This finding directly shaped the design: hooking event publishing only into the DB-persisted path (`write`) would have silently dropped nearly half of all audit-worthy operations. See §9 decision record.
- **Atom's audit writes are not transactionally atomic with the mutations they record.** Mutation repo functions (e.g. `authz::repo::create_resource`) open and commit their own transaction; the subsequent audit call runs afterward on a separate connection. This is a pre-existing, accepted characteristic of the audit system, not something this feature introduced or needed to fix — see §9.
- **The codebase has a clear precedent for optional, config-gated background features**: `AuditRetentionConfig`/`PurgeConfig` (`src/config.rs`) both use an `enabled: bool` (or, as adopted here, presence-of-config) pattern, with a `tokio::spawn`-based background loop (`audit::spawn_retention_cleanup`, `purge::spawn_purge_cleanup`) that simply doesn't start when disabled. This is the exact template this feature's outbox poller follows.
- **`src/metrics.rs`'s facade-over-swappable-backend pattern** (semantic functions call into a `#[cfg(feature = "metrics")]`-gated backend, compiling to no-ops otherwise) was the template for this feature's `EventPublisher` trait — a generic interface with a dependency-free default (`LogPublisher`) and a real backend (`AmqpPublisher`) selected purely by runtime configuration, not a compile-time feature flag (since broker configuration is a per-deployment, not per-binary, decision).
- **No existing dependency provided AMQP support.** `lapin` (the standard async Rust AMQP 0-9-1 client) was added as a new, genuinely new dependency — justified because the team explicitly named AMQP as the protocol to use, not merely inferred.

## 6. Architecture

```
Any existing mutation call site (84 of them, across src/graphql/*, src/identity/*,
src/certs/graphql.rs, src/grpc.rs) — UNCHANGED, still calls:

    audit::write(pool, events_enabled, event)
    audit::observe_result(pool, events_enabled, meta, details, &result)   [now async]
    audit::write_hot_path(pool, policy, events_enabled, kind, event)

                          │
                          ▼
              src/audit.rs (single choke point)
       ┌──────────────────┴───────────────────┐
       │ log_audit_event()  — stdout, unchanged │
       │ audit_logs INSERT  — write() only,     │
       │                      unchanged          │
       │ events::enqueue()  — NEW, all three     │
       │                      entry points        │
       └──────────────────┬───────────────────┘
                          │ (no-op if !events_enabled)
                          ▼
              event_outbox table (Postgres)
                          │
                          │ background poller, tokio::spawn,
                          │ advisory-locked batch delivery
                          ▼
              EventPublisher trait (src/events/publisher.rs)
       ┌──────────────────┴────────────────────────┐
       │ LogPublisher (default, no broker)          │
       │ AmqpPublisher (lapin, default exchange +   │
       │   one fixed routing key, optional mTLS)    │
       └─────────────────────────────────────────────┘
```

Every mutation call site's existing audit call is the *only* integration point — no new logic was added at any of the 84 call sites beyond passing one additional `bool` (whether events are enabled) into the same function they already called. All new logic lives in `src/audit.rs` (the enqueue trigger) and `src/events/` (everything else).

`AmqpPublisher` publishes every event to the **default exchange** (`exchange: ""`) with **one fixed, configurable routing key** — not a custom topic exchange with per-event-type routing keys, which is what an earlier iteration of this design used. This changed after inspecting a real integration contract a broker operator may impose (§9, DR-7): some deployments (FluxMQ's "Internal AMQP Local Principals" feature is the concrete example encountered) grant Atom publish access to exactly one pre-provisioned queue via the default exchange and refuse any topology mutation (exchange/queue declare, bind) outright. Publishing to the default exchange with a fixed routing key requires no topology declaration at all and is standard AMQP 0-9-1 that behaves identically against any compliant broker — consumers distinguish event types using the payload's own `event` field, not AMQP routing. `AmqpPublisher::connect` still declares a custom exchange when `EventsConfig.amqp_exchange` is non-empty, for deployments that prefer topic-exchange routing and grant Atom the topology permissions to do so.

## 7. Responsibility boundaries

| Responsibility | Owner |
|---|---|
| Detecting that an operation happened | Atom (`src/audit.rs`, unchanged) |
| Deciding whether to persist to `audit_logs` | Atom (unchanged — `write` vs `observe_result` vs `write_hot_path`, exactly as before) |
| Deciding whether to enqueue a domain event | Atom, gated purely by `EventsConfig::enabled()` (presence of an AMQP URL) |
| Reliable at-least-once delivery to the broker | Atom (`event_outbox` + poller + `EventPublisher`) |
| Deciding what to do with a received event | **External system** — entirely out of scope |
| Pre-operation limit/quota checks | **External system**, via a separate mechanism not built here |
| Billing, invoicing, payment | **External system** — Atom has no vocabulary for any of this |

## 8. Event contract

Defined in `src/events/mod.rs` as `DomainEventPayload`, deliberately mirroring `audit::AuditEvent`'s shape rather than inventing a parallel model:

```rust
pub struct DomainEventPayload {
    pub schema_version: u32,        // starts at 1
    pub event_id: Uuid,             // idempotency key, stable across redelivery
    pub event: String,              // e.g. "resource.create", "tenant.delete" — Atom's existing audit event names, unfiltered
    pub occurred_at: DateTime<Utc>,
    pub source: String,             // "atom"
    pub actor_entity_id: Option<Uuid>,
    pub tenant_id: Option<Uuid>,
    pub target_kind: Option<String>,
    pub target_id: Option<Uuid>,
    pub outcome: String,            // "allow" | "deny" | "error"
    pub details: serde_json::Value, // whatever the audit call site already put in `details`
    pub request_id: Option<String>, // reserved; not populated (no request-id propagation exists in Atom yet)
}
```

Example (as actually produced by `resource.create`):
```json
{
  "schema_version": 1,
  "event_id": "0b0a5e4a-8f2b-4a3e-9b8a-2c9e2b6a7d11",
  "event": "resource.create",
  "occurred_at": "2026-07-30T14:03:22.501Z",
  "source": "atom",
  "actor_entity_id": "3f9c1e2a-...",
  "tenant_id": "a1b2c3d4-...",
  "target_kind": "resource",
  "target_id": "9d8e7f6a-...",
  "outcome": "allow",
  "details": {"kind": "channel"},
  "request_id": null
}
```

No billing/usage/quota vocabulary appears anywhere in this contract — deliberately, since Atom has no concept of any of it.

## 9. Decision records

**DR-1: Hook into all three audit functions, not just the DB-persisted one.**
- *Context*: §5 found that `observe_result` (42 call sites, including most creates) never reaches `audit_logs`.
- *Options*: (a) publish only from `write`/`write_hot_path` (simple, but misses ~half of all operations); (b) extend all three functions, including making `observe_result` async so it can reach the database.
- *Selected*: (b).
- *Rationale*: "publish all events" cannot be satisfied by (a) — it would silently exclude `resource.create`, `tenant.create`, `group.create`, and others. (b) required a mechanical but wide-reaching signature change (see DR-2) and making `observe_result` `async` (it previously wasn't), which in turn required adding `.await` at all 42 of its call sites.
- *Consequences*: `observe_result`'s signature and every call site changed. This was the single largest mechanical change in the implementation, verified compiler-error-by-compiler-error (each of the 84 sites was a type error until fixed, so none could be silently missed).

**DR-2: `pool: &PgPool` + `events_enabled: bool`, not `state: &AppState`.**
- *Context*: The natural-seeming choice was to have `audit::write`/`observe_result`/`write_hot_path` take `&AppState` (already a dependency of `audit.rs` via `spawn_retention_cleanup`), reading `state.config.events.enabled()` internally.
- *Options*: (a) change all three functions to take `&AppState`; (b) keep `pool: &PgPool` and add one plain `events_enabled: bool` parameter.
- *Selected*: (b).
- *Rationale*: While drafting (a), a real call site was found — `audit_authz_check`/`audit_authz_explain` in `src/graphql/authz.rs`, part of the authz PDP path — that deliberately takes only `pool: &sqlx::PgPool` and `audit_policy: AuditPolicyConfig`, not `AppState`, because the authz engine's core evaluation logic is intentionally transport/state-agnostic. Forcing `&AppState` there would have cascaded an inappropriate dependency into architecturally unrelated code. A plain `bool` has no such cost — it was trivially derivable everywhere (`state.config.events.enabled()`, `cfg.events.enabled()`, or threaded through as one more parameter on the rare helper function that needed it).
- *Consequences*: Two small helper functions (`audit_authz_check`, `audit_authz_explain` in `graphql/authz.rs`; `audit_action_assignment_rule` in `graphql/policies.rs`) gained an explicit `events_enabled: bool` parameter, passed through from their callers.
- *Follow-up*: none; this shape has proven sufficient everywhere in the codebase.

**DR-3: Reliability matches the existing audit system's consistency level, not stricter.**
- *Context*: §5 found audit writes are not atomic with their triggering mutation today.
- *Options*: (a) make the event-outbox insert atomic with the *originating mutation* (would require threading a shared transaction through every repo function — a much larger, riskier change); (b) match the existing precedent — the outbox insert and the `audit_logs` insert happen together, in one transaction, inside `audit::write`, but neither is atomic with the mutation that preceded the audit call.
- *Selected*: (b).
- *Rationale*: There is no counting/enforcement requirement (unlike the abandoned quota design) that would justify the cost and risk of (a). Matching the existing, already-accepted audit consistency level keeps the change scoped to `src/audit.rs` and `src/events/` only.
- *Consequences*: A crash between a mutation committing and the subsequent audit/event call has always been able to lose the audit record in this codebase; this feature doesn't change that window, and inherits it for events too. Documented, not hidden.

**DR-4: Transactional outbox, not direct publish.**
- *Context*: standard reliable-delivery question.
- *Options*: (a) call the publisher directly from `audit::write`/`observe_result`; (b) write to an `event_outbox` table (in the same transaction as the `audit_logs` insert, where applicable) and deliver asynchronously via a background poller.
- *Selected*: (b).
- *Rationale*: (a) would make every mutation's latency and success depend on a broker's availability — unacceptable for a generic platform component. (b) means a broker outage only delays delivery; nothing is lost (rows stay in `event_outbox` until delivered) and nothing about the mutation's behavior changes.
- *Consequences*: at-least-once delivery, not exactly-once — a crash between a successful publish and the `delivered_at` UPDATE redelivers the same `event_id`. Consumers must deduplicate on `event_id`.

**DR-5: Broker integration lives inside Atom's core, config-gated — not a separate relay.**
- *Context*: the team explicitly discussed this trade-off (Dušan: "Atom stores events and broadcasts them to FMQ optionally"; sammy: "if a broker is not configured events are simply not published").
- *Options*: (a) ship only the generic outbox + trait in Atom, with any real broker push implemented as a wholly separate, optional relay process; (b) ship a real AMQP publisher (`AmqpPublisher`, using `lapin`) inside Atom's core, active only when `ATOM_EVENTS_AMQP_URL` is configured.
- *Selected*: (b), per explicit team direction.
- *Rationale*: The team preferred single-process operational simplicity over maximal decoupling, provided the feature is a true no-op when unconfigured — which it is (see §11).
- *Consequences*: Atom's `Cargo.toml` now has a real dependency on `lapin`. This is deliberately scoped down to only the AMQP-related features needed (see §13 for a dependency-conflict this required resolving).

**DR-6: No event-type filtering in v1.**
- *Context*: earlier discussion (before the user's final clarification) considered a configurable allow/deny list of event categories (e.g. excluding auth/authz noise).
- *Options*: (a) build a configurable filter; (b) publish everything unconditionally when enabled, relying on `write_hot_path`'s *existing* suppression of high-volume `Allow` auth/authz outcomes to naturally keep the worst noise out.
- *Selected*: (b), per explicit user instruction ("We will publish all events for the time being").
- *Rationale*: simplest correct thing that satisfies the stated requirement; a filter can be added later without any structural change (the `event` field is a free string already).
- *Follow-up*: flagged as open work in §14 if a real deployment finds the volume or content unsuitable.

**DR-7: Default exchange + one fixed routing key, not a custom topic exchange with per-event routing.**
- *Context*: the original `AmqpPublisher` declared a custom durable topic exchange and used each event's own name (e.g. `resource.create`) as the routing key, so a consumer could bind with a wildcard pattern. After the initial implementation, inspection of a real production integration contract — FluxMQ's "Internal AMQP Local Principals" feature (`docs/deployment/internal-amqp-local-principals.md` in the FluxMQ repo, authored by the same team building Atom's billing integration) — showed this doesn't match how a real deployment may grant Atom broker access at all: local principals may publish only to **exactly one** `(exchange, routing_key)` pair (`exchange: ""`, one fixed routing key), cannot declare or bind any topology, and any attempt to do so is refused with AMQP `403`.
- *Options*: (a) keep the custom-topic-exchange design and treat FluxMQ's contract as something Atom simply can't satisfy without a broker-specific carve-out; (b) redesign `AmqpPublisher` to publish every event to the default exchange with one fixed, configurable routing key, matching the restrictive contract, and rely on the payload's own `event` field for consumer-side filtering.
- *Selected*: (b).
- *Rationale*: publishing to the default exchange with a fixed routing key is *more* generic, not less — it's plain AMQP 0-9-1 with no topology assumptions, works identically against RabbitMQ (verified, `tests/m27_live_amqp_delivery.rs`) and FluxMQ's local-principal listener (verified, `tests/m28_amqp_mtls_local_principal.rs`), and doesn't require the broker to grant Atom any exchange/queue-management permission at all — a strictly smaller trust footprint than the topic-exchange design needed. The per-event routing key the old design relied on for consumer-side filtering was solving a problem the payload's own `event` field already solves.
- *Consequences*: `EventsConfig` gained `amqp_routing_key: String` (default `"atom.events"`) and `amqp_exchange` defaults to `""` (empty = default exchange, meaning `AmqpPublisher::connect` skips exchange declaration entirely). A non-empty `amqp_exchange` still declares a custom topic exchange for deployments that grant that permission and prefer per-event routing at the AMQP layer, but every publish still uses the one fixed `amqp_routing_key`, not `event.event` — a deployment wanting topic-exchange-style per-event routing today would need a config-level change to this behavior, not just a config value; not built, since no concrete need for it has arisen (see §15).
- *Follow-up*: none currently; revisit if a real consumer needs AMQP-layer routing by event type rather than payload-field filtering.

**DR-8: Optional mTLS client-certificate support, mirroring the existing `GrpcTlsConfig` pattern.**
- *Context*: FluxMQ's local-principal contract requires a client TLS certificate (with a specific URI SAN) plus a SASL username/secret — not just a plain `amqp://` URL.
- *Options*: (a) support only plain/SASL-only AMQP connections, leaving mTLS brokers unsupported; (b) add optional client-cert/key/CA-bundle config, mirroring `GrpcTlsConfig`'s existing shape (`src/config.rs`) exactly, and load it into `lapin`'s `OwnedTLSConfig`/`OwnedIdentity::PKCS8`.
- *Selected*: (b).
- *Rationale*: mTLS client-certificate authentication is standard AMQPS, not a FluxMQ-specific mechanism (RabbitMQ supports the identical combination) — supporting it is a generic capability, not broker-specific coupling. `Atom` already has an established config pattern (`GrpcTlsConfig`) for exactly this shape (cert/key/CA paths, all optional), so this reuses precedent rather than inventing one.
- *Consequences*: `EventsConfig` gained `amqp_tls_client_cert_path`, `amqp_tls_client_key_path` (must be set together or not at all — validated in `events_from_env`), and `amqp_tls_ca_path` (independent, verifies the broker's server certificate). None of these require Atom's code to know anything about "local principals," SPIFFE URIs, or FluxMQ's internal-listener concept — those are pure configuration values a deployment supplies.
- *Follow-up*: none.

### Two Rust-dependency bugs found and fixed while building the live mTLS test

Both were discovered only because the mTLS test was actually run against a real broker rather than mocked — recorded here since they're non-obvious and would silently resurface if the `lapin`/`rustls` dependency versions or feature flags are ever changed:

1. **A rustls-side connector bug when no root-store feature is enabled.** With `lapin` pinned to `default-features = false, features = ["default-runtime", "rustls--ring"]` (chosen to avoid the dual-crypto-provider conflict — see the original `plan.md` file-by-file section, since renamed §13.1 below), the underlying `tcp-stream` crate's Rustls connector (`RustlsConnectorConfig::default()`, used when none of `rustls-native-certs`/`rustls-webpki-roots-certs`/`rustls-platform-verifier` are enabled) produced a connector that silently failed the TLS handshake — the client sent non-TLS bytes on the wire (confirmed via FluxMQ's server log: `"tls: first record does not look like a TLS handshake"`) and then hung indefinitely rather than erroring. Verified server-side correctness independently first with `openssl s_client` (clean mTLS handshake, `Verification: OK`) before concluding the bug was client-side. **Fix**: added the `rustls-webpki-roots-certs` feature to `lapin` in `Cargo.toml`, giving the connector a valid (if unused, since a custom CA is always supplied via `EventsConfig.amqp_tls_ca_path`) root store to build from.
2. **`AmqpPublisher::publish` was not actually waiting for a broker acknowledgment.** The original code called `channel.basic_publish(...).await?.await?`, awaiting the returned `PublisherConfirm`, but never called `channel.confirm_select(...)` first. Without confirm mode enabled, a `PublisherConfirm` resolves once the publish frame is sent, not once the broker accepts or rejects it — an ACL-denied or unroutable publish looked identical to a successful one. Caught by `tests/m28_amqp_mtls_local_principal.rs`'s negative test (publishing to a routing key the local principal isn't granted): FluxMQ correctly closed the connection with `publish_acl_mismatch`, but the test's `.publish()` call still returned `Ok`. **Fix**: `AmqpPublisher::connect` now calls `channel.confirm_select(ConfirmSelectOptions::default()).await?` once, right after creating the channel, making every subsequent publish's confirmation a real broker acknowledgment.

## 10. Counting/enforcement — explicitly absent

There is no counting, no limit, no enforcement anywhere in this feature. This section exists only to state plainly, for anyone reviewing this document after the fact, that the original plan's `quota_policies`/`usage_counters`/`check_and_record_quota` design was fully discarded and none of it exists in the current codebase. Searching the repository for `quota`, `usage_counter`, or `QuotaExceeded` should return nothing.

## 11. Configuration and backward compatibility

`EventsConfig` (`src/config.rs`), a field on `Config.events`:

```rust
pub struct EventsConfig {
    pub amqp_url: Option<String>,       // ATOM_EVENTS_AMQP_URL — None = feature fully off
    pub amqp_exchange: String,          // ATOM_EVENTS_AMQP_EXCHANGE, default "" (the default exchange — see DR-7)
    pub amqp_routing_key: String,       // ATOM_EVENTS_AMQP_ROUTING_KEY, default "atom.events" — used for every publish
    pub amqp_tls_client_cert_path: Option<String>, // ATOM_EVENTS_AMQP_TLS_CLIENT_CERT_PATH — mTLS, must pair with the key path
    pub amqp_tls_client_key_path: Option<String>,  // ATOM_EVENTS_AMQP_TLS_CLIENT_KEY_PATH
    pub amqp_tls_ca_path: Option<String>,           // ATOM_EVENTS_AMQP_TLS_CA_PATH — verifies the broker's server cert
    pub outbox_poll_interval_secs: u64, // ATOM_EVENTS_OUTBOX_POLL_INTERVAL_SECS, default 5
    pub outbox_batch_size: i64,         // ATOM_EVENTS_OUTBOX_BATCH_SIZE, default 100
    pub outbox_max_attempts: i32,       // ATOM_EVENTS_OUTBOX_MAX_ATTEMPTS, default 10 (not yet enforced — see §15)
}
impl EventsConfig {
    pub fn enabled(&self) -> bool { self.amqp_url.is_some() }
}
```

The two TLS path fields are validated as a pair in `events_from_env()` — set together or not at all; `amqp_tls_ca_path` is independent of them (a deployment could verify the broker's cert without presenting a client cert, or vice versa, though FluxMQ's local-principal contract requires both together in practice).

Enablement is **presence-based**, not a redundant separate flag — matching `certificate_issuer: Option<Arc<CertificateIssuer>>` and `grpc_tls: Option<GrpcTlsConfig>`'s existing style in this codebase.

Backward compatibility, verified by test (`tests/m26_audit_event_publishing.rs::no_event_outbox_rows_are_written_when_events_are_not_configured`):
- No `ATOM_EVENTS_AMQP_URL` (the default) → `EventsConfig::enabled()` is `false` → `events::enqueue` returns immediately with no query at all → zero new database writes, zero new behavior for any existing deployment.
- `spawn_event_publisher` (the background poller) does not spawn a task at all when disabled.
- The `event_outbox` migration (`migrations/004_event_outbox.sql`) is purely additive — one new table, no `ALTER` on any existing table — so it applies cleanly to any existing Atom database regardless of whether the feature is ever turned on.

## 12. Database schema

One new migration, `migrations/004_event_outbox.sql`:

```sql
CREATE TABLE event_outbox (
    id              UUID        PRIMARY KEY,
    event           TEXT        NOT NULL,
    actor_entity_id UUID        NULL REFERENCES entities(id) ON DELETE SET NULL,
    tenant_id       UUID        NULL REFERENCES tenants(id) ON DELETE SET NULL,
    payload         JSONB       NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at    TIMESTAMPTZ NULL,
    attempts        INTEGER     NOT NULL DEFAULT 0,
    last_error      TEXT        NULL
);
CREATE INDEX idx_event_outbox_undelivered ON event_outbox(created_at) WHERE delivered_at IS NULL;
```

Unlike the abandoned draft, `event` has no `CHECK` constraint restricting it to a fixed set of values — per DR-6, every audit event name is a valid, publishable event.

## 13. File-by-file summary of what changed

| File | Change |
|---|---|
| `src/events/mod.rs` (**new**) | `DomainEventPayload`, `enqueue()` (the outbox-insert primitive, no-op when disabled), `spawn_event_publisher()` (background poller, modeled on `audit::spawn_retention_cleanup`/`purge::spawn_purge_cleanup`, advisory-locked via `EVENT_OUTBOX_ADVISORY_LOCK_ID`), `deliver_outbox_batch()` (public, so tests can drive delivery deterministically). |
| `src/events/publisher.rs` (**new**) | `EventPublisher` trait, `PublishError`, `LogPublisher` (default, traces and always succeeds), `AmqpPublisher` (real `lapin`-backed implementation: connects with `enable_auto_recover()`, enables publisher confirms via `confirm_select` (§9's second bugfix), optionally loads an mTLS client identity + CA bundle into `OwnedTLSConfig`, declares a custom topic exchange only when `amqp_exchange` is non-empty, and publishes every event to one fixed `(exchange, routing_key)` target per DR-7). |
| `src/audit.rs` | `write`, `observe_result`, `write_hot_path` all gained an `events_enabled: bool` parameter and now also call `events::enqueue`. `observe_result` changed from sync to `async`. `write`'s DB insert and the event enqueue now share one transaction. |
| `src/config.rs` | New `EventsConfig` struct (routing key + optional mTLS fields, DR-7/DR-8) + `events_from_env()`, wired into `Config`. |
| `src/state.rs` | New `AppState.event_publisher: Option<Arc<dyn EventPublisher>>` field (`None` by default) + `with_event_publisher()` builder, since connecting to AMQP is async and `AppState::new` is not. |
| `src/main.rs` | If `cfg.events.amqp_url` is set, connects `AmqpPublisher` and attaches it via `with_event_publisher`; always calls `events::spawn_event_publisher(state.clone())` (a no-op if disabled). |
| `src/metrics.rs` | Added `record_outbox_publish_failure()` / `atom_quota_outbox_publish_failures_total`-equivalent counter (named for events, following the existing feature-gated facade pattern). |
| `src/lib.rs` | `pub mod events;` added (alphabetically placed). |
| `Cargo.toml` | Added `lapin`, pinned to `default-features = false, features = ["default-runtime", "rustls--ring", "rustls-webpki-roots-certs"]` — see §13.1 below for why (two separate fixes: the crypto-provider conflict, and a silent-TLS-handshake-failure bug). |
| `src/graphql/*.rs`, `src/identity/{service,handlers}.rs`, `src/certs/graphql.rs`, `src/grpc.rs` | All 84 existing `audit::write`/`observe_result`/`write_hot_path` call sites updated to pass the additional `events_enabled` argument (and, for `observe_result` callers, `.await` added). Three small local helper functions (`audit_authz_check`, `audit_authz_explain`, `audit_action_assignment_rule`) gained an `events_enabled: bool` parameter threaded from their callers. No business logic changed at any of these sites. |
| `migrations/004_event_outbox.sql` (**new**) | The `event_outbox` table (§12). |
| `tests/m25_event_outbox.rs` (**new**) | Outbox delivery mechanics: exactly-once marking, redelivery-with-same-id after a simulated failure, arbitrary event names all delivered (proving DR-6's no-filtering choice), no-op on an empty queue. |
| `tests/m26_audit_event_publishing.rs` (**new**) | The feature's core correctness proof: `resource.create` (never DB-audited) still produces an `event_outbox` row when enabled, and produces none when disabled. |
| `tests/m27_live_amqp_delivery.rs` (**new**) | Full round-trip proof against a real, plain (no TLS) AMQP broker (verified against RabbitMQ): connects the real `AmqpPublisher`, publishes to the default exchange with a fixed routing key, and consumes the exact payload back off the matching queue. |
| `tests/m28_amqp_mtls_local_principal.rs` (**new**) | Full round-trip proof against FluxMQ's "Internal AMQP Local Principals" contract specifically: mTLS + SASL connection succeeds and is authenticated (verified via FluxMQ's admin API `/api/v1/stats`), a publish to the exactly-granted `(default exchange, routing key)` target succeeds, and a publish to any other routing key is denied (`403`, verified via `.publish()` returning `Err` — this is the test that caught the missing `confirm_select` bug in §9). |
| `tests/m7_audit.rs`, `tests/m12_graphql_identity.rs` | Mechanically updated for the new `audit::*` signatures (m7) and one unrelated pre-existing clippy lint fixed in passing (m12, a redundant `..Default::default()`). |

### 13.1 Dependency issues this work surfaced and fixed

Two separate `lapin`/`rustls` issues were found and fixed — the first while adding the dependency, the second only once the live mTLS test was actually run (see §9's decision records for the second bug's full context, since it doubles as a decision record — a wrong publish silently looked successful):

1. **Dual crypto-provider conflict.** Adding `lapin` with its default features introduced a second Rustls cryptography backend (`aws-lc-rs`, pulled in transitively via `lapin → amq-protocol-tcp → tcp-stream → rustls-connector`) alongside the one this codebase already used (`ring`, via `sqlx`'s `runtime-tokio-rustls` feature and `reqwest`/`hyper-rustls`). With both active, Rustls could no longer auto-select a `CryptoProvider`, and two existing, unrelated gRPC TLS unit tests started failing at runtime (`Could not automatically determine the process-level CryptoProvider`). **Fixed** by pinning `lapin`'s features explicitly to `rustls--ring` instead of bare `rustls`, aligning it with the project's existing backend choice. Confirmed via `cargo tree -e features -i rustls` that only the `ring` feature was requested afterward, and the previously-failing tests passed again.
2. **Silent TLS handshake failure with no root-store feature enabled.** After the fix above, `lapin` had `default-features = false, features = ["default-runtime", "rustls--ring"]` — no root-store-building feature (`rustls-native-certs`/`rustls-webpki-roots-certs`/`rustls-platform-verifier`). `tcp-stream`'s Rustls connector falls back to `RustlsConnectorConfig::default()` in that case, which produced a connector that failed silently: the client sent non-TLS bytes on the wire (confirmed via FluxMQ's server log, `"tls: first record does not look like a TLS handshake"`), then hung indefinitely instead of erroring — even with `enable_auto_recover()` removed and an explicit `rustls::crypto::ring::default_provider().install_default()` call added, ruling out both retry-loop and crypto-provider-registration explanations. Verified the server side was correct independently first, with `openssl s_client` (clean mTLS handshake, `Verification: OK`) using the same generated PKI, before concluding the bug was client-side. **Fixed** by adding the `rustls-webpki-roots-certs` feature to `lapin`, giving the connector a valid root store to build from (unused in practice, since a custom CA is always supplied via `amqp_tls_ca_path`, but apparently required for the connector to construct a working TLS config at all).

## 14. Testing strategy (as implemented)

- **Unit tests** (`src/events/mod.rs`, `src/events/publisher.rs`): payload contract shape, `LogPublisher` always succeeds including on an empty batch.
- **Outbox mechanics** (`tests/m25_event_outbox.rs`, DB-gated): delivered-exactly-once, no redelivery of already-delivered rows, failed delivery is retried with the *same* `event_id` (at-least-once, not exactly-once, not duplicate-with-new-id), arbitrary/mixed event names are all delivered with no filtering, empty-queue is a harmless no-op. Each test truncates `event_outbox` first — the table has no other test-isolation mechanism (unlike other tables, which existing tests scope by generated IDs), so this was necessary once tests ran in a shared database.
- **The core correctness proof** (`tests/m26_audit_event_publishing.rs`): explicitly demonstrates that `resource.create` — an `observe_result`-channeled operation that is *never* written to `audit_logs` — still produces an `event_outbox` row when publishing is enabled, and produces none when it's disabled. This is the test that would have failed under the rejected "hook only into `write`" design (DR-1).
- **Live broker round-trips** (`tests/m27_live_amqp_delivery.rs` against RabbitMQ, `tests/m28_amqp_mtls_local_principal.rs` against a locally-built FluxMQ with its internal mTLS listener configured): both prove real wire delivery, not just "the publish call returned `Ok`" — the RabbitMQ test consumes the exact payload back off a queue; the FluxMQ test verifies authentication and message receipt via FluxMQ's own admin API and additionally proves the publish ACL is enforced (a wrong routing key is denied). Neither runs in normal CI (both require a live broker); see each file's module doc comment for local setup steps.
- **Regression**: the full existing test suite (all `#[ignore]`d integration tests plus the unit suite) passes unmodified in behavior — verified by running everything, not just the new files, matching this repository's actual CI convention (`.github/workflows/rust.yml`'s `cargo test -- --include-ignored --test-threads=1`).
- **Environment note**: DB-gated tests must run against a database whose `signing_keys` table either doesn't exist yet or was bootstrapped under the same test KEK `Config::for_tests()` uses (`vec![7u8; 32]`). A database shared with a live, separately-configured Atom deployment (e.g. a docker-compose stack with its own generated KEK) will fail unrelated to this feature; use a dedicated test database.

## 15. Open questions / future work

- **Dead-letter handling**: `event_outbox` rows that repeatedly fail to publish stay undelivered indefinitely; `EventsConfig.outbox_max_attempts` is defined but not yet enforced (no row is ever given up on). Worth revisiting once a real broker outage pattern is observed.
- **Event-type filtering** (DR-6): if a real consumer needs to exclude noisy categories, add a config-driven filter in `events::enqueue` — the `event` string is already a stable, matchable value, so this requires no schema change.
- **AMQP-layer per-event routing** (DR-7): the current design always publishes with one fixed routing key, relying on consumers to filter by the payload's own `event` field. If a real deployment wants AMQP-layer routing by event type instead (and grants Atom the exchange/queue permissions that requires), `AmqpPublisher` would need a mode that uses `event.event` as the routing key when a custom exchange is configured — not built, no concrete need yet.
- **Request/correlation ID propagation**: `DomainEventPayload.request_id` is defined but always `null` — no request-ID propagation exists anywhere in Atom today. Out of scope for this feature to add.
- **The pre-operation callback/webhook mechanism** Arvindh is building separately is complementary to this feature (callback = synchronous pre-check, events = async post-notification) but is not designed or implemented here — coordinate with that work before assuming both exist together in a deployment.
- **Schema compatibility with any existing external consumer** (e.g. amdm's `billing/events` package, referenced in the originating Slack thread) was not verified against this implementation — that repository was not accessible during this work. Confirm the payload shape in §8 is workable for any existing consumer before wiring one up in production.
- **Reconnection behavior with mTLS under `enable_auto_recover()`** was not specifically stress-tested (e.g. killing and restarting the broker mid-session) — worth a dedicated test if connection stability against a real broker over long uptimes becomes a concern.

## 16. Definition of done

- [x] Every existing audit call site (84) publishes an event when configured, with no behavior change when not.
- [x] `resource.create`-class operations (never DB-audited) are proven to still produce events.
- [x] No quota/usage/billing vocabulary remains anywhere in the codebase.
- [x] Full existing test suite passes unmodified in behavior.
- [x] `cargo clippy --all-targets -- -D warnings` is clean.
- [x] A real, generic AMQP publisher exists and is config-gated, off by default.
- [x] Migration is additive-only and safe on any existing deployment.
- [x] Verified end-to-end against a real broker with no TLS (RabbitMQ) — publish and consumer-side receipt both proven.
- [x] Verified end-to-end against FluxMQ's actual "Internal AMQP Local Principals" contract (mTLS + SASL, default exchange, fixed routing key, ACL enforcement) — the sanctioned production integration path, not just a generic broker.
- [ ] Payload compatibility with any specific downstream consumer (e.g. amdm) — explicitly not verified; see §15.
