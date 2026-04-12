# Changelog

## 0.3.0 (2026-04-12)

### Added

- **Daemon CLI commands**: `add-acl`, `list-acl`, `remove-acl`, `invite`
  (passkey enrollment), and `import-secrets` — full management without
  needing standalone binaries
- **Deployment mode indicator**: Dashboard shows "Daemon" badge and hides
  the service topology panel (irrelevant when all services are in-process)
- **Background tasks in daemon**: Session cleanup, stats flushing (10s),
  and time-series bucket cleanup (1h) — stats now persist across restarts
- **Auto-rebuild UI assets**: `build.rs` detects stale `dist/` and runs
  `npm run build:web` automatically during `cargo build`
- **Shared CLI module** (`webvh-common::server::cli`): ACL and passkey
  invite logic consolidated into one place, used by all 4 binaries

### Changed

- **Daemon store layout** (breaking): Consolidated from 4 separate stores
  (`server_store`, `control_store`, `watcher_store`, `witness_store`) to 2
  (`store` for primary, `witness_store` for witness). Config must be updated.
- **Daemon routing**: Control plane merged at root so the UI's `/api/`
  requests work without path prefix issues. Server contributes only
  public DID-serving routes (`.well-known` + fallback).
- **Shared task functions**: `flush_stats_to_store` and `cleanup_old_buckets`
  moved from `webvh-control` to `webvh-common::server::tasks` for reuse
- **Feature flag control**: Daemon sub-crate dependencies use
  `default-features = false` so `--no-default-features` works correctly
- **`/api/health` route**: Moved into the control plane router (was
  registered ad-hoc in `server.rs`, missing in daemon mode)

### Fixed

- DID resolution in daemon mode (server and control now share one store)
- Passkey login returning "authentication failed" silently — added warn
  logging to `require_webauthn` and empty-passkeys checks
- UI returning "Expected JSON but got text/html" — API routes now reachable
  at `/api/` in daemon mode
- Daemon fallback using `Extension` which axum doesn't apply to fallback
  handlers — replaced with closure capture
- Stats collector not seeded on daemon restart — dashboard totals now
  match per-DID sums after restart
- `Role::from_str` changed to `FromStr` trait impl (clippy)
- All clippy warnings resolved across workspace

## 0.2.0 (2026-04-12)

### Added

- **import-secrets CLI command**: Cold-start bootstrap support for importing
  signing keys from file, enabling automated provisioning without interactive
  setup
- **VTA integration redesign**: Unified startup flow with local caching via
  `VtaCache`, replacing the previous bundle-paste workflow with direct VTA
  connection
- **Time-series tracking**: Control plane now records per-DID usage over time
  with batched flush via the unified `StatsCollector`
- **Cold-start bootstrap documentation**: Complete flow documentation for VTA,
  mediator, and webvh-server bootstrap scenarios
- **webvh-daemon feature flags**: Forward `aws-secrets`, `gcp-secrets`,
  `metrics`, `store-redis`, `store-dynamodb`, `store-firestore`, and
  `store-cosmosdb` feature flags to sub-crates

### Fixed

- DIDComm session restore for setup wizard VTA authentication
- `SessionStore::connect()` now passes `None` for DIDComm transport correctly
- DID list shows actual resolve counts from per-DID stats instead of aggregates
- Server restart now accepts `seq=0` and shows empty chart message in UI
- Store integrity check skips non-JSON keys (`owner:`, `refresh:`, `ts:`)

### Changed

- `StatsCollector` refactored to unified batched flush architecture
- `vta-sdk` dependency switched from crates.io release to git nightly branch
  with `integration` feature

## 0.1.0 (2026-03-31)

First production-hardened release. Major improvements across all services in
security, performance, scalability, and operational readiness.

### Breaking Changes

- **affinidi-messaging-didcomm 0.13 migration**: `Message.type_` renamed to
  `Message.typ`; `pack_signed` and `unpack_string` replaced with new sync APIs
- **StatsSyncPayload**: Now carries per-DID deltas instead of aggregate totals;
  includes monotonic sequence number for idempotency
- **Stats persistence removed from webvh-server**: Stats are in-memory only;
  control plane is the single source of truth
- **DID delete is now soft-delete**: Content preserved for 30-day recovery
  period; hard delete happens via cleanup thread

### New Features

#### webvh-common (0.1.0)
- `StatsCollector`: Simplified to per-DID delta tracking with `drain_for_sync()`
  and `record_deltas()` for control plane ingestion
- `ServiceAuth` extractor for service-role-only endpoints
- `Role::Service` ACL role for service accounts
- `DidDocumentOptions`: DID documents now support `keyAgreement` (X25519) and
  `DIDCommMessaging` service endpoints
- `ContentCache`: In-memory TTL cache with Arc-based zero-copy reads
- `didcomm_unpack`: JWS unpacking with DID resolution and message freshness
  validation (5-minute window)
- Prometheus metrics module (behind `metrics` feature flag)
- Session `token_id` (jti) for JWT revocation on refresh
- Store `verify_integrity()` method for startup corruption detection
- `QuotaIndex` for O(1) per-owner DID count and size tracking
- Input bounds validation (DID length, path length)
- Error sanitization — 4xx responses no longer leak internal DIDs/paths

#### webvh-server (0.1.0)
- Multi-threaded REST executor (4 Tokio workers)
- DID resolution cache with TTL and write-through invalidation
- Per-DID stats sync to control plane (delta-based, no double-counting)
- Background control plane registration with retry and circuit breaker
- `recreate-did` CLI command for DID regeneration with config update
- `recover-did` CLI command for soft-delete recovery
- DID list pagination (`?limit=N&offset=M`)
- Rate limiting on auth challenge endpoint (10 pending per DID)
- DIDComm mediator discovery from VTA DID document
- Audit logging (`audit=true` field on security-critical events)
- Shutdown timeout (30s) on thread joins
- Store integrity check on startup

#### webvh-control (0.1.0)
- Per-DID stats storage with in-memory collector and periodic flush
- Stats sync authentication (ACL validation on incoming payloads)
- Stats idempotency (sequence number deduplication)
- Parallel health checks (tokio::spawn instead of sequential)
- Per-DID stats and timeseries API endpoints
- `ServiceAuth`-protected register-service endpoint
- DID list pagination
- Soft-delete recovery endpoint (`POST /api/recover/{mnemonic}`)

#### webvh-witness (0.1.0)
- Multi-threaded REST executor
- DIDComm API migration (0.13)

#### webvh-watcher (0.1.0)
- HTTP trace logging reduced to DEBUG level

#### webvh-daemon (0.1.0)
- Aligned with webvh-server AppState changes (cache, signing key)

### Security
- Session fixation prevention via JWT `jti` rotation on refresh
- DIDComm message freshness validation (rejects messages >5 min old)
- Input bounds: DID length capped at 512 bytes
- Auth challenge rate limiting (max 10 pending per DID)
- Stats sync endpoint authenticated against ACL
- Error responses sanitized (no internal DID/path leakage)
- Fjall batch errors logged instead of silently dropped

### Performance
- DID resolution cache reduces store load by ~80% for stable DIDs
- O(1) quota checks via `QuotaIndex` (was O(n) prefix scan)
- Incremental DID count tracking (was O(n) periodic scan)
- Arc-based cache entries avoid cloning large documents
- Empty stats syncs skipped (zero cost when idle)
- DID list pagination prevents unbounded response materialization

### Operations
- Prometheus metrics endpoint (`GET /metrics`, `metrics` feature flag)
- Configuration validation on load (auth TTLs, URL format, DID format)
- Structured audit logging for DID and auth operations
- HTTP trace logging moved to DEBUG level (reduces log noise)
- DID store status logged at startup (count, paths)
- Graceful shutdown with 30s timeout

### Dependencies
- `affinidi-messaging-didcomm` 0.12 → 0.13
- `vta-sdk` switched from local path to crates.io (0.2.x)
- `prometheus` 0.13 (optional, behind `metrics` feature)
