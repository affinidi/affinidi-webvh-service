# Changelog

## [Unreleased]

## 0.6.0 (2026-04-24)

### Added
- **webvh-control**: Web UI for creating enrollment invites. The Access
  Control page now has an "Invite by Link" card that generates an
  enrollment URL for a given DID and role, removing the need to drop to
  the `webvh-control invite` CLI to onboard new users. The invitee opens
  the link, registers a passkey, and is added to the ACL automatically.

### Changed
- **webvh-ui**: Login page "need access?" section no longer surfaces the
  CLI command — it now instructs users to request an invite link from an
  admin, matching the new web-based flow.
- **MSRV**: raised from 1.91.0 to 1.94.0. Required by the updated
  affinidi-tdk / affinidi-messaging / affinidi-secrets-resolver /
  affinidi-data-integrity stacks, all of which declared 1.94+ in their
  latest releases.
- **Witness proof signing**: migrated to the new async `Signer`-based API
  in affinidi-data-integrity 0.6. The `WitnessSigner` trait is now async
  (returns a `BoxFuture`) — any external signer implementations must be
  updated accordingly.
- **CosmosDB store**: migrated to azure_data_cosmos 0.32's required
  `RoutingStrategy` parameter and the now-async `container_client()`.
  Region is configurable via new `store.cosmosdb_region` setting (env:
  `*_STORE_COSMOSDB_REGION`), accepting any Azure region name — display
  form (`"West US 2"`) or normalized (`"westus2"`). Defaults to
  `"eastus"` when unset.

### Dependencies
- affinidi-tdk 0.6.3 → 0.6.5
- affinidi-tdk-common 0.5.0 → 0.5.2
- affinidi-messaging-didcomm 0.13.1 → 0.13.2
- affinidi-messaging-didcomm-service 0.2.1 → 0.2.2
- affinidi-messaging-sdk 0.16.3 → 0.16.4
- affinidi-secrets-resolver 0.5.3 → 0.5.5
- affinidi-did-resolver-cache-sdk 0.8.4 → 0.8.6
- affinidi-data-integrity 0.3 → 0.6 (breaking API — see note above)
- firestore 0.47 → 0.48
- azure_core 0.32 → 0.34 (pinned to match azure_data_cosmos 0.32)
- azure_data_cosmos 0.31 → 0.32 (breaking API)
- redis 1.0 → 1.2 (breaking `AsyncIter::next_item` now returns
  `Option<RedisResult<T>>`)
- aws-sdk-* and aws-config patch bumps (1.8.x → 1.8.16)
- didwebvh-rs 0.4.2 → 0.5.0 (transitive)

## 0.5.0 (2026-04-13)

### Added
- **webvh-server**: DIDComm-based server registration with control plane,
  replacing HTTP-based registration. Servers now authenticate and register
  via DIDComm messages over a persistent websocket connection.
- **webvh-server**: DIDComm health ping/pong replaces HTTP health checks,
  providing reliable liveness monitoring over the existing DIDComm channel.
- **webvh-server**: `list-dids` and `remove-did` CLI commands for managing
  DIDs directly from the server command line.
- **webvh-control**: Consolidated VTA provisioning protocol — the control
  plane now handles the full DIDComm VTA flow (did/request, did/publish)
  for all registered servers.
- **webvh-control**: Auto-adds its own DID to server ACL on registration,
  enabling seamless DID sync without manual ACL configuration.
- **webvh-common**: Shared DIDComm message type constants for health,
  stats, and DID sync protocols.

### Changed
- **webvh-server**: Management routes removed from server edge nodes.
  All DID management is now done through the control plane; servers are
  read-only edge nodes that serve DID documents.
- **webvh-server**: Single DIDComm connection per service using
  `DIDCommService` v0.2.0, replacing per-operation connections.
- **webvh-server**: Setup wizard simplified for read-only edge node role —
  asks only for DID hosting URL instead of full server configuration.
- **webvh-server**: DID path derived from URL instead of hardcoded
  `.well-known`, supporting flexible DID hosting configurations.
- **webvh-control**: DIDComm service and handlers restructured for
  improved message routing and handler visibility.
- **webvh-daemon**: DIDComm config flag now read from `[features]` section.
  HTTP server starts before DIDComm to avoid self-resolution race condition.

### Fixed
- **webvh-server**: Always serve HTTP for public DID resolution regardless
  of `rest_api` flag — DID documents must remain publicly accessible.
- **webvh-server**: Websocket connection established before sending
  registration message, preventing message loss.
- **webvh-control**: DID sync and stats flow now works reliably between
  control plane and registered servers.
- **webvh-control**: DIDComm service properly visible to route handlers.
- Improved DIDComm error logging across all services.

### Performance
- Suppressed noisy health-ping/pong and stats-ack request logs to reduce
  log volume in production.

### Dependencies
- `affinidi-messaging-didcomm-service` 0.1 → 0.2

## 0.4.2 (2026-04-13)

### Added
- **webvh-daemon**: Full parity with standalone webvh-server + webvh-control.
  The daemon now includes all lifecycle management that was previously only
  available in standalone mode:
  - Background storage task: session cleanup, DID cleanup, stats flush to
    persistent store, and service health checks
  - Auto-bootstrap of root DID on startup when `public_url` is configured
  - Stats collector seeded from persisted store (stats survive restarts)
  - Registry seeding from static config on startup
  - DIDComm support via new `didcomm` config field — inbound listener for VTA
    integration and outbound ATM for sync push messages
  - Ordered shutdown: DIDComm → HTTP → storage flush → persist
- **webvh-daemon**: New CLI commands from webvh-server: `bootstrap-did`,
  `recreate-did`, `recover-did`, `load-did`, `import-secrets`, `backup`,
  `restore`
- **webvh-daemon**: DID store integrity check on startup

### Fixed
- **webvh-daemon**: fjall `Locked` error on startup — server, watcher, and
  control all share the same store path but each opened it independently.
  Stores are now opened once and shared.
- **webvh-daemon**: Enrollment invite URLs returned 404 — the control plane
  was nested at `/control` but enrollment URLs pointed to `/enroll`. Control
  plane is now merged at root so URLs work identically in daemon and
  standalone modes.
- **webvh-daemon**: DID resolve stats were not recorded — the server's
  stats collector was `None`. Now a shared `Arc<StatsCollector>` is used by
  both server and control plane.
- **webvh-daemon**: HTTP client had no timeouts — now uses 30s request /
  10s connect timeouts matching standalone server.
- **webvh-control**: Time-series graphs showed zero — `flush_stats_to_store`
  wrote aggregate totals but never wrote time-series bucket entries
  (`ts:{mnemonic}:{epoch}`). Now writes per-DID and server-wide (`_all`)
  5-minute buckets on each flush cycle. This fix applies to both daemon
  and standalone control plane modes.

### Changed
- **webvh-server**: `start_didcomm_service` is now `pub` for daemon reuse.
- **webvh-control**: `flush_stats_to_store`, `run_health_checks`, and
  `seed_registry` are now `pub` for daemon reuse.

## 0.4.1 (2026-04-13)

### Added
- **webvh-daemon**: Restore unified CLI management commands (`add-acl`,
  `list-acl`, `remove-acl`, `invite`) so operators can manage ACLs and create
  passkey enrollment invites directly from the daemon binary without needing to
  run `webvh-control` separately.

## 0.4.0 (2026-04-13)

### Added
- **webvh-server**: Restore `import-secrets` CLI command for importing server
  secrets from a VTA secrets bundle or individual multibase-encoded keys. This
  is required for cold-start bootstrap scenarios where no VTA service is running.

## 0.3.0 (2026-04-12)

### Changed
- Simplified architecture: removed shared CLI module, VTA-cache layer, and
  background task infrastructure from webvh-common
- Each service binary now owns its CLI directly instead of delegating to
  `webvh-common::server::cli`
- Switched from local-path `vta-sdk` to crates.io published version (0.3.x)

### Removed
- `webvh-common::server::cli` module (CLI logic moved into each binary)
- `webvh-common::server::vta_cache` module (VTA key refresh on startup removed)
- `import-secrets` CLI command from webvh-server (restored in 0.4.0)

## 0.2.0 (2026-04-08)

### Changed
- Version bump release for crates.io publishing

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
